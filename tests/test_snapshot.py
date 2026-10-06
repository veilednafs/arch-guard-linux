import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch

from arch_guard.incident import (
    create_incident_if_needed,
)
from arch_guard.snapshot import (
    render_text,
    safe_name,
    write_snapshot,
)


class SnapshotTests(unittest.TestCase):

    def test_safe_name(self):
        self.assertEqual(
            safe_name(
                "ssh / weird:event"
            ),
            "ssh_weird_event",
        )

    def test_suppressed_event_gets_no_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            result = create_incident_if_needed(
                {
                    "event":
                        "suricata_alert",

                    "severity":
                        "HIGH",

                    "snapshot":
                        False,
                },
                incident_dir=Path(td),
            )

            self.assertIsNone(
                result
            )

            self.assertEqual(
                list(
                    Path(td).iterdir()
                ),
                [],
            )

    def test_snapshot_files_created(self):
        fake_report = {
            "generated":
                "2026-10-06T20:00:00+03:00",

            "trigger": {
                "event":
                    "network_port_scan",

                "severity":
                    "CRITICAL",

                "source_ip":
                    "192.0.2.50",
            },

            "tailscale": {
                "available":
                    False,

                "self":
                    {},

                "peers":
                    [],
            },

            "listeners":
                [],

            "established":
                [],

            "interfaces":
                [],

            "neighbours":
                [],

            "recent_ssh":
                [],

            "nftables":
                "",
        }

        with tempfile.TemporaryDirectory() as td:
            with patch(
                "arch_guard.snapshot.collect_snapshot",
                return_value=fake_report,
            ):
                paths = write_snapshot(
                    fake_report[
                        "trigger"
                    ],
                    Path(td),
                )

            self.assertEqual(
                len(paths),
                2,
            )

            for path in paths:
                self.assertTrue(
                    path.exists()
                )

                self.assertEqual(
                    path.stat().st_mode
                    & 0o777,
                    0o640,
                )

    def test_render_has_no_legacy_machine_name(self):
        report = {
            "generated":
                "2026-10-06",

            "trigger": {
                "event":
                    "test",

                "severity":
                    "HIGH",
            },

            "tailscale": {
                "available":
                    False,

                "self":
                    {},

                "peers":
                    [],
            },

            "listeners":
                [],

            "established":
                [],

            "neighbours":
                [],

            "recent_ssh":
                [],

            "nftables":
                "",
        }

        text = render_text(
            report
        )

        self.assertNotIn(
            "OLD-HOSTNAME",
            text,
        )

        self.assertNotIn(
            "old-local-user",
            text,
        )

    def test_tailscale_ids_not_rendered(self):
        report = {
            "generated":
                "2026-10-06",

            "trigger": {
                "event":
                    "test",

                "severity":
                    "HIGH",
            },

            "tailscale": {
                "available":
                    True,

                "self": {
                    "hostname":
                        "host",

                    "os":
                        "linux",

                    "tailscale_ips":
                        ["100.64.0.1"],

                    "online":
                        True,
                },

                "peers": [
                    {
                        "hostname":
                            "phone",

                        "os":
                            "android",

                        "tailscale_ips":
                            ["100.64.0.2"],

                        "online":
                            True,

                        "active":
                            True,
                    }
                ],
            },

            "listeners":
                [],

            "established":
                [],

            "neighbours":
                [],

            "recent_ssh":
                [],

            "nftables":
                "",
        }

        text = render_text(
            report
        )

        self.assertNotIn(
            "user_id",
            text,
        )

        self.assertNotIn(
            "node_key",
            text,
        )


if __name__ == "__main__":
    unittest.main()
