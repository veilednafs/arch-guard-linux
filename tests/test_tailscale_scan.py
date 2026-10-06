import json
import unittest

from types import SimpleNamespace

from arch_guard.notifier import (
    render_notification,
)
from arch_guard.policy import (
    apply_policy,
)
from arch_guard.tailscale_scan import (
    COOLDOWN_SECONDS,
    THRESHOLD,
    WINDOW_SECONDS,
    TailscaleScanDetector,
    parse_loopback_syn,
    tailscale_identity,
)


class TailscaleScanTests(
    unittest.TestCase
):

    def test_legacy_defaults(self):
        self.assertEqual(
            WINDOW_SECONDS,
            10,
        )

        self.assertEqual(
            THRESHOLD,
            25,
        )

        self.assertEqual(
            COOLDOWN_SECONDS,
            60,
        )

    def test_parse_loopback_syn(self):
        event = parse_loopback_syn(
            "IP 127.0.0.1.41000 > "
            "127.0.0.1.65000: "
            "Flags [S], seq 1"
        )

        self.assertIsNotNone(
            event
        )

        self.assertEqual(
            event.source_port,
            41000,
        )

        self.assertEqual(
            event.destination_port,
            65000,
        )

    def test_non_syn_ignored(self):
        self.assertIsNone(
            parse_loopback_syn(
                "IP 127.0.0.1.41000 > "
                "127.0.0.1.65000: "
                "Flags [S.]"
            )
        )

    def test_threshold_25_unique_ports(self):
        detector = (
            TailscaleScanDetector(
                identity_resolver=lambda: {
                    "device":
                        "phone",

                    "source_ip":
                        "100.64.0.20",

                    "platform":
                        "android",

                    "identity_scope":
                        "unique_active_peer",

                    "attribution_confidence":
                        "heuristic",
                }
            )
        )

        output = []

        for index in range(25):
            output = detector.process_line(
                (
                    "IP 127.0.0.1.40000 > "
                    f"127.0.0.1.{65000 + index}: "
                    "Flags [S], seq 1"
                ),
                now=100.0 + (
                    index * 0.1
                ),
            )

        self.assertEqual(
            len(output),
            1,
        )

        event = output[0]

        self.assertEqual(
            event["unique_ports"],
            25,
        )

        self.assertEqual(
            event[
                "attribution_confidence"
            ],
            "heuristic",
        )

    def test_duplicate_port_does_not_reach_threshold(self):
        detector = (
            TailscaleScanDetector(
                identity_resolver=lambda: {}
            )
        )

        output = []

        for index in range(40):
            output = detector.process_line(
                (
                    "IP 127.0.0.1.40000 > "
                    "127.0.0.1.65000: "
                    "Flags [S], seq 1"
                ),
                now=100.0 + (
                    index * 0.1
                ),
            )

        self.assertEqual(
            output,
            [],
        )

    def test_cooldown(self):
        detector = (
            TailscaleScanDetector(
                threshold=2,
                cooldown=60,
                identity_resolver=lambda: {},
            )
        )

        detector.process_line(
            "IP 127.0.0.1.1 > "
            "127.0.0.1.1000: Flags [S]",
            now=100.0,
        )

        first = detector.process_line(
            "IP 127.0.0.1.1 > "
            "127.0.0.1.1001: Flags [S]",
            now=101.0,
        )

        second = detector.process_line(
            "IP 127.0.0.1.1 > "
            "127.0.0.1.1002: Flags [S]",
            now=102.0,
        )

        self.assertEqual(
            len(first),
            1,
        )

        self.assertEqual(
            second,
            [],
        )

    def test_unique_active_peer_is_heuristic(self):

        data = {
            "Peer": {
                "node-a": {
                    "HostName":
                        "phone",

                    "OS":
                        "android",

                    "Online":
                        True,

                    "Active":
                        True,

                    "TailscaleIPs":
                        ["100.64.0.20"],

                    "ID":
                        "private-node-id",

                    "UserID":
                        12345,
                },

                "node-b": {
                    "HostName":
                        "tablet",

                    "OS":
                        "android",

                    "Online":
                        True,

                    "Active":
                        False,

                    "TailscaleIPs":
                        ["100.64.0.21"],
                },
            }
        }

        def runner(
            *args,
            **kwargs,
        ):
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    data
                ),
                stderr="",
            )

        identity = tailscale_identity(
            binary="/usr/bin/tailscale",
            runner=runner,
        )

        self.assertEqual(
            identity["device"],
            "phone",
        )

        self.assertEqual(
            identity[
                "attribution_confidence"
            ],
            "heuristic",
        )

        self.assertNotIn(
            "ID",
            identity,
        )

        self.assertNotIn(
            "UserID",
            identity,
        )

        self.assertNotIn(
            "node_id",
            identity,
        )

        self.assertNotIn(
            "user_id",
            identity,
        )

    def test_ambiguous_peers_are_not_invented(self):

        data = {
            "Peer": {
                "a": {
                    "HostName":
                        "one",

                    "Online":
                        True,

                    "Active":
                        False,

                    "TailscaleIPs":
                        ["100.64.0.1"],
                },

                "b": {
                    "HostName":
                        "two",

                    "Online":
                        True,

                    "Active":
                        False,

                    "TailscaleIPs":
                        ["100.64.0.2"],
                },
            }
        }

        def runner(
            *args,
            **kwargs,
        ):
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    data
                ),
                stderr="",
            )

        identity = tailscale_identity(
            binary="/usr/bin/tailscale",
            runner=runner,
        )

        self.assertEqual(
            identity["device"],
            "ambiguous",
        )

        self.assertEqual(
            identity["source_ip"],
            "unknown",
        )

        self.assertEqual(
            identity[
                "attribution_confidence"
            ],
            "none",
        )

    def test_policy(self):
        event = apply_policy(
            {
                "event":
                    "tailscale_port_scan",

                "severity":
                    "HIGH",
            }
        )

        self.assertTrue(
            event["notify"]
        )

        self.assertFalse(
            event["snapshot"]
        )

    def test_notification(self):
        notification = (
            render_notification(
                {
                    "event":
                        "tailscale_port_scan",

                    "severity":
                        "HIGH",

                    "notify":
                        True,

                    "device":
                        "phone",

                    "source_ip":
                        "100.64.0.20",

                    "platform":
                        "android",

                    "attribution_confidence":
                        "heuristic",

                    "ports":
                        list(
                            range(
                                65000,
                                65025,
                            )
                        ),

                    "unique_ports":
                        25,

                    "window_seconds":
                        10,
                }
            )
        )

        self.assertEqual(
            notification.title,
            "ARCH GUARD — TAILSCALE PORT SCAN",
        )

        self.assertIn(
            "Kimlik güveni: heuristic",
            notification.body,
        )


if __name__ == "__main__":
    unittest.main()
