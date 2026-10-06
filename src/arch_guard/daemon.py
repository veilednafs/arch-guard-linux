from __future__ import annotations

from pathlib import Path

from arch_guard.correlator import SSHCorrelator
from arch_guard.dispatcher import EventDispatcher
from arch_guard.faillock import FaillockDetector
from arch_guard.live_runtime import LiveRuntimeCoordinator
from arch_guard.live_supervisor import (
    LiveSource,
    LiveSupervisor,
)
from arch_guard.network_correlator import NetworkScanCorrelator
from arch_guard.network_pipeline import NetworkPipeline
from arch_guard.pipeline import SSHPipeline
from arch_guard.runtime import ArchGuardRuntime
from arch_guard.suricata_pipeline import SuricataPipeline
from arch_guard.tailscale_scan import TailscaleScanDetector


def build_sources(
    config,
    *,
    enable_tailscale_scan: bool = False,
) -> list[LiveSource]:

    sources: list[LiveSource] = []

    if config.ssh.enabled:
        sources.append(
            LiveSource(
                name="ssh-journal",
                kind="ssh",
                command=(
                    "journalctl",
                    "-f",
                    "-n",
                    "0",
                    "-o",
                    "json",
                    "-u",
                    str(
                        config.ssh.service
                    ),
                ),
            )
        )

    if config.network.enabled:
        sources.append(
            LiveSource(
                name="kernel-network",
                kind="network",
                command=(
                    "journalctl",
                    "-f",
                    "-n",
                    "0",
                    "-o",
                    "json",
                    "-k",
                ),
            )
        )

    if config.suricata.enabled:
        for index, eve_file in enumerate(
            config.suricata.eve_files
        ):
            sources.append(
                LiveSource(
                    name=(
                        "suricata-eve-"
                        f"{index}"
                    ),
                    kind="suricata",
                    command=(
                        "tail",
                        "-n",
                        "0",
                        "-F",
                        str(eve_file),
                    ),
                )
            )

    tailscale_enabled = (
        enable_tailscale_scan
        or config.tailscale_scan.enabled
    )

    if tailscale_enabled:
        sources.append(
            LiveSource(
                name="tailscale-scan",
                kind="tailscale_scan",
                command=(
                    "tcpdump",
                    "-l",
                    "-nn",
                    "-i",
                    "lo",
                    (
                        "tcp[tcpflags] & "
                        "(tcp-syn|tcp-ack) "
                        "== tcp-syn"
                    ),
                ),
            )
        )

    return sources


def build_coordinator(
    config,
    runtime: ArchGuardRuntime,
) -> LiveRuntimeCoordinator:
    """
    Config dosyasındaki davranış ayarlarını gerçek
    pipeline nesnelerine bağlayan tek fabrika noktası.
    """

    ssh_correlator = (
        SSHCorrelator.from_config(
            config.ssh
        )
    )

    network_correlator = (
        NetworkScanCorrelator.from_config(
            config.network
        )
    )

    ssh_pipeline = SSHPipeline(
        correlator=ssh_correlator,
        lock_detector=FaillockDetector(),
    )

    network_pipeline = NetworkPipeline(
        correlator=network_correlator,
    )

    suricata_pipeline = SuricataPipeline(
        profile="default",
        dedup_seconds=(
            config.suricata.dedup_seconds
        ),
    )

    tailscale_scan_detector = TailscaleScanDetector(
        window=config.tailscale_scan.window,
        threshold=config.tailscale_scan.threshold,
        cooldown=config.tailscale_scan.cooldown,
    )

    return LiveRuntimeCoordinator(
        runtime,
        ssh_pipeline=ssh_pipeline,
        network_pipeline=network_pipeline,
        suricata_pipeline=suricata_pipeline,
        tailscale_scan_detector=tailscale_scan_detector,
    )


def run_daemon(
    config,
    *,
    enable_tailscale_scan: bool = False,
) -> int:

    dispatcher = EventDispatcher(
        event_log=Path(
            config.paths.event_log
        ),
        incident_dir=Path(
            config.paths.incident_dir
        ),
    )

    runtime = ArchGuardRuntime(
        dispatcher
    )

    coordinator = build_coordinator(
        config,
        runtime,
    )

    sources = build_sources(
        config,
        enable_tailscale_scan=(
            enable_tailscale_scan
        ),
    )

    if not sources:
        raise RuntimeError(
            "Etkin sensör bulunamadı."
        )

    supervisor = LiveSupervisor(
        coordinator,
        sources=sources,
    )

    print(
        "Arch Guard runtime başladı."
    )

    print(
        "Etkin kaynaklar:"
    )

    for source in sources:
        print(
            f"  - {source.name}"
        )

    supervisor.run()

    return 0
