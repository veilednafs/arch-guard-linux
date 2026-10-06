from __future__ import annotations

import time

from dataclasses import dataclass
from datetime import datetime

from arch_guard.faillock import (
    FaillockDetector,
)
from arch_guard.journal import (
    parse_journal_line,
)
from arch_guard.network_pipeline import (
    NetworkPipeline,
)
from arch_guard.pipeline import (
    SSHPipeline,
)
from arch_guard.policy import apply_policy
from arch_guard.runtime import (
    ArchGuardRuntime,
)
from arch_guard.suricata_pipeline import (
    SuricataPipeline,
)
from arch_guard.tailscale_scan import (
    TailscaleScanDetector,
)


@dataclass(slots=True)
class LiveStats:
    ssh_lines: int = 0
    network_lines: int = 0
    suricata_lines: int = 0
    tailscale_lines: int = 0

    ssh_events: int = 0
    network_events: int = 0
    suricata_events: int = 0
    tailscale_events: int = 0


def journal_timestamp(
    value: float | None,
) -> str | None:

    if value is None:
        return None

    return (
        datetime
        .fromtimestamp(value)
        .astimezone()
        .isoformat(
            timespec="microseconds"
        )
    )


class LiveRuntimeCoordinator:
    """
    Canlı kaynak satırlarını mevcut pipeline'lara bağlar.

    Burada subprocess/tail/journalctl yönetimi yoktur.
    Bu sınıf yalnız satır -> pipeline -> runtime bağlantısıdır.
    """

    def __init__(
        self,
        runtime: ArchGuardRuntime,
        *,
        ssh_pipeline: SSHPipeline | None = None,
        network_pipeline: NetworkPipeline | None = None,
        suricata_pipeline: SuricataPipeline | None = None,
        tailscale_scan_detector: TailscaleScanDetector | None = None,
    ):
        self.runtime = runtime

        self.ssh_pipeline = (
            ssh_pipeline
            if ssh_pipeline is not None
            else SSHPipeline(
                lock_detector=FaillockDetector()
            )
        )

        self.network_pipeline = (
            network_pipeline
            if network_pipeline is not None
            else NetworkPipeline()
        )

        self.suricata_pipeline = (
            suricata_pipeline
            if suricata_pipeline is not None
            else SuricataPipeline(
                profile="default"
            )
        )

        self.tailscale_scan_detector = (
            tailscale_scan_detector
            if tailscale_scan_detector is not None
            else TailscaleScanDetector()
        )

        self.stats = LiveStats()

    def process_ssh_line(
        self,
        line: str,
    ) -> int:

        self.stats.ssh_lines += 1

        record = parse_journal_line(
            line
        )

        if record is None:
            return 0

        now = (
            record.timestamp
            if record.timestamp is not None
            else time.time()
        )

        events = (
            self.ssh_pipeline
            .process_message(
                record.message,
                now=now,
                event_timestamp=journal_timestamp(
                    record.timestamp
                ),
            )
        )

        for event in events:
            self.runtime.emit_prepared(
                event,
                sensor="ssh",
            )

        self.stats.ssh_events += len(
            events
        )

        return len(events)

    def process_network_line(
        self,
        line: str,
    ) -> int:

        self.stats.network_lines += 1

        record = parse_journal_line(
            line
        )

        if record is None:
            return 0

        now = (
            record.timestamp
            if record.timestamp is not None
            else time.time()
        )

        events = (
            self.network_pipeline
            .process_message(
                record.message,
                now=now,
                event_timestamp=journal_timestamp(
                    record.timestamp
                ),
            )
        )

        for event in events:
            self.runtime.emit_prepared(
                event,
                sensor="network",
            )

        self.stats.network_events += len(
            events
        )

        return len(events)

    def process_suricata_line(
        self,
        line: str,
        *,
        now: float | None = None,
    ) -> int:

        self.stats.suricata_lines += 1

        events = (
            self.suricata_pipeline
            .process_line(
                line,
                now=(
                    time.time()
                    if now is None
                    else now
                ),
            )
        )

        for event in events:
            self.runtime.emit_prepared(
                event,
                sensor="suricata",
            )

        self.stats.suricata_events += len(
            events
        )

        return len(events)

    def process_tailscale_scan_line(
        self,
        line: str,
        *,
        now: float | None = None,
    ) -> int:

        self.stats.tailscale_lines += 1

        events = (
            self.tailscale_scan_detector
            .process_line(
                line,
                now=now,
            )
        )

        prepared = []

        for event in events:
            prepared.append(
                apply_policy(
                    event
                )
            )

        for event in prepared:
            self.runtime.emit_prepared(
                event,
                sensor="tailscale_scan",
            )

        self.stats.tailscale_events += len(
            prepared
        )

        return len(
            prepared
        )

