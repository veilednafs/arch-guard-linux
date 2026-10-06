import unittest

from pathlib import Path
from types import SimpleNamespace

from arch_guard.daemon import (
    build_sources,
)


def config(
    *,
    ssh=True,
    network=True,
    suricata=True,
):
    return SimpleNamespace(
        paths=SimpleNamespace(
            event_log=Path(
                "/tmp/events.jsonl"
            ),
            incident_dir=Path(
                "/tmp/incidents"
            ),
        ),
        ssh=SimpleNamespace(
            enabled=ssh,
            service="sshd.service",
        ),
        network=SimpleNamespace(
            enabled=network,
        ),
        tailscale_scan=SimpleNamespace(
            enabled=False,
            window=10,
            threshold=25,
            cooldown=60,
        ),
        suricata=SimpleNamespace(
            enabled=suricata,
            eve_files=[
                "/var/log/suricata/eve.json"
            ],
        ),
    )


class DaemonTests(
    unittest.TestCase
):

    def test_default_sources(self):
        sources = build_sources(
            config()
        )

        self.assertEqual(
            [
                source.kind
                for source in sources
            ],
            [
                "ssh",
                "network",
                "suricata",
            ],
        )

    def test_tailscale_is_opt_in(self):
        sources = build_sources(
            config(),
            enable_tailscale_scan=True,
        )

        self.assertEqual(
            sources[-1].kind,
            "tailscale_scan",
        )

    def test_disabled_sensor_removed(self):
        sources = build_sources(
            config(
                ssh=False,
                network=False,
                suricata=True,
            )
        )

        self.assertEqual(
            len(sources),
            1,
        )

        self.assertEqual(
            sources[0].kind,
            "suricata",
        )

    def test_multiple_eve_files(self):
        cfg = config()

        cfg.suricata.eve_files = [
            "/tmp/a.json",
            "/tmp/b.json",
        ]

        sources = build_sources(
            cfg
        )

        suricata = [
            source
            for source in sources
            if source.kind
            == "suricata"
        ]

        self.assertEqual(
            len(suricata),
            2,
        )


if __name__ == "__main__":
    unittest.main()


class DaemonConfigWiringTests(
    unittest.TestCase
):

    def test_pipeline_settings_come_from_config(self):
        from unittest.mock import (
            ANY,
            patch,
        )

        from arch_guard.daemon import (
            build_coordinator,
        )

        cfg = config()

        cfg.ssh.brute_force_window = 91
        cfg.ssh.high_threshold = 4
        cfg.ssh.critical_threshold = 7

        cfg.network.port_scan_window = 19
        cfg.network.port_scan_threshold = 11
        cfg.network.cooldown = 123

        cfg.suricata.dedup_seconds = 47

        runtime = object()

        with (
            patch(
                "arch_guard.daemon."
                "SSHCorrelator.from_config",
                return_value="ssh-correlator",
            ) as ssh_from_config,

            patch(
                "arch_guard.daemon."
                "NetworkScanCorrelator.from_config",
                return_value="network-correlator",
            ) as network_from_config,

            patch(
                "arch_guard.daemon.SSHPipeline",
                return_value="ssh-pipeline",
            ) as ssh_pipeline,

            patch(
                "arch_guard.daemon.NetworkPipeline",
                return_value="network-pipeline",
            ) as network_pipeline,

            patch(
                "arch_guard.daemon.SuricataPipeline",
                return_value="suricata-pipeline",
            ) as suricata_pipeline,

            patch(
                "arch_guard.daemon.LiveRuntimeCoordinator",
                return_value="coordinator",
            ) as coordinator,
        ):
            result = build_coordinator(
                cfg,
                runtime,
            )

        self.assertEqual(
            result,
            "coordinator",
        )

        ssh_from_config.assert_called_once_with(
            cfg.ssh
        )

        network_from_config.assert_called_once_with(
            cfg.network
        )

        ssh_pipeline.assert_called_once_with(
            correlator="ssh-correlator",
            lock_detector=ANY,
        )

        network_pipeline.assert_called_once_with(
            correlator="network-correlator",
        )

        suricata_pipeline.assert_called_once_with(
            profile="default",
            dedup_seconds=47,
        )

        coordinator.assert_called_once_with(
            runtime,
            ssh_pipeline="ssh-pipeline",
            network_pipeline="network-pipeline",
            suricata_pipeline="suricata-pipeline",
            tailscale_scan_detector=ANY,
        )
