import unittest

from pathlib import Path
from types import SimpleNamespace

from arch_guard.daemon import (
    build_coordinator,
)
from arch_guard.dispatcher import (
    EventDispatcher,
)
from arch_guard.runtime import (
    ArchGuardRuntime,
)


class RuntimeConfigValueTests(
    unittest.TestCase
):

    def test_non_default_values_reach_real_objects(self):

        config = SimpleNamespace(
            ssh=SimpleNamespace(
                enabled=True,
                service="sshd.service",
                brute_force_window=91,
                high_threshold=4,
                critical_threshold=7,
            ),

            network=SimpleNamespace(
                enabled=True,
                port_scan_window=19,
                port_scan_threshold=11,
                cooldown=123,
            ),

            tailscale_scan=SimpleNamespace(
                enabled=True,
                window=17,
                threshold=31,
                cooldown=88,
            ),

            suricata=SimpleNamespace(
                enabled=True,
                eve_files=[
                    "/tmp/eve.json"
                ],
                dedup_seconds=47,
            ),
        )

        dispatcher = EventDispatcher(
            event_log=Path(
                "/tmp/arch-guard-config-test.jsonl"
            ),
            incident_dir=Path(
                "/tmp/arch-guard-config-test-incidents"
            ),
        )

        runtime = ArchGuardRuntime(
            dispatcher
        )

        coordinator = build_coordinator(
            config,
            runtime,
        )

        ssh = (
            coordinator
            .ssh_pipeline
            .correlator
        )

        network = (
            coordinator
            .network_pipeline
            .correlator
        )

        self.assertEqual(
            ssh.window,
            91,
        )

        self.assertEqual(
            ssh.high_threshold,
            4,
        )

        self.assertEqual(
            ssh.critical_threshold,
            7,
        )

        self.assertEqual(
            network.window,
            19,
        )

        self.assertEqual(
            network.threshold,
            11,
        )

        self.assertEqual(
            network.cooldown,
            123,
        )

        dedup = (
            coordinator
            .suricata_pipeline
            .deduplicator
        )

        # SuricataDeduplicator'ın public davranışını
        # iç attribute adına bağımlı olmadan test ediyoruz:
        event = {
            "sensor_profile":
                "default",

            "signature_id":
                123,

            "flow_id":
                456,

            "protocol":
                "TCP",

            "source_ip":
                "198.51.100.10",

            "source_port":
                443,

            "destination_ip":
                "192.0.2.10",

            "destination_port":
                55000,
        }

        self.assertTrue(
            dedup.accept(
                event,
                now=100.0,
            )
        )

        self.assertFalse(
            dedup.accept(
                event,
                now=146.0,
            )
        )

        self.assertTrue(
            dedup.accept(
                event,
                now=148.0,
            )
        )


if __name__ == "__main__":
    unittest.main()


class TailscaleRuntimeConfigTests(
    unittest.TestCase
):

    def test_tailscale_values_reach_detector(self):
        from unittest.mock import patch

        from arch_guard.daemon import build_coordinator

        config = SimpleNamespace(
            ssh=SimpleNamespace(
                enabled=True,
                service="sshd.service",
                brute_force_window=60,
                high_threshold=3,
                critical_threshold=5,
            ),
            network=SimpleNamespace(
                enabled=True,
                port_scan_window=10,
                port_scan_threshold=6,
                cooldown=60,
            ),
            tailscale_scan=SimpleNamespace(
                enabled=True,
                window=17,
                threshold=31,
                cooldown=88,
            ),
            suricata=SimpleNamespace(
                enabled=True,
                eve_files=["/tmp/eve.json"],
                dedup_seconds=30,
            ),
        )

        dispatcher = EventDispatcher(
            event_log=Path(
                "/tmp/arch-guard-ts-config.jsonl"
            ),
            incident_dir=Path(
                "/tmp/arch-guard-ts-config-incidents"
            ),
        )

        runtime = ArchGuardRuntime(
            dispatcher
        )

        coordinator = build_coordinator(
            config,
            runtime,
        )

        detector = (
            coordinator
            .tailscale_scan_detector
        )

        self.assertEqual(
            detector.window,
            17,
        )

        self.assertEqual(
            detector.threshold,
            31,
        )

        self.assertEqual(
            detector.cooldown,
            88,
        )
