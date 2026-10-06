import json
import unittest

from arch_guard.network_identity import (
    classify_source_ip,
    resolve_network_identity,
)


class NetworkIdentityTests(unittest.TestCase):

    def test_public_ip_classification(self):
        self.assertEqual(
            classify_source_ip(
                "1.1.1.1"
            ),
            "public",
        )

    def test_tailscale_classification(self):
        self.assertEqual(
            classify_source_ip(
                "100.64.10.20"
            ),
            "tailscale",
        )

    def test_direct_lan_mac(self):
        route = json.dumps(
            [
                {
                    "dst":
                        "192.168.1.50",
                    "dev":
                        "wlan-test",
                    "prefsrc":
                        "192.168.1.10",
                }
            ]
        )

        neighbor = json.dumps(
            [
                {
                    "dst":
                        "192.168.1.50",
                    "dev":
                        "wlan-test",
                    "lladdr":
                        "aa:bb:cc:dd:ee:ff",
                    "state":
                        ["REACHABLE"],
                }
            ]
        )

        result = resolve_network_identity(
            source_ip="192.168.1.50",
            route_json=route,
            neighbor_json=neighbor,
        )

        self.assertEqual(
            result.source_scope,
            "lan_direct",
        )

        self.assertEqual(
            result.source_mac,
            "aa:bb:cc:dd:ee:ff",
        )

        self.assertEqual(
            result.attribution_confidence,
            "neighbor",
        )

    def test_public_never_gets_gateway_mac(self):
        route = json.dumps(
            [
                {
                    "dst":
                        "1.1.1.1",
                    "gateway":
                        "192.168.1.1",
                    "dev":
                        "wlan-test",
                }
            ]
        )

        # Bilerek gateway neighbor kaydı veriyoruz.
        # Bu MAC uzak public IP'ye yazılmamalı.
        neighbor = json.dumps(
            [
                {
                    "dst":
                        "192.168.1.1",
                    "lladdr":
                        "11:22:33:44:55:66",
                    "state":
                        ["REACHABLE"],
                }
            ]
        )

        result = resolve_network_identity(
            source_ip="1.1.1.1",
            route_json=route,
            neighbor_json=neighbor,
        )

        self.assertEqual(
            result.source_scope,
            "remote_public",
        )

        self.assertIsNone(
            result.source_mac
        )

    def test_private_routed_has_no_mac(self):
        route = json.dumps(
            [
                {
                    "dst":
                        "10.20.30.40",
                    "gateway":
                        "192.168.1.1",
                    "dev":
                        "wlan-test",
                }
            ]
        )

        result = resolve_network_identity(
            source_ip="10.20.30.40",
            route_json=route,
            neighbor_json="[]",
        )

        self.assertEqual(
            result.source_scope,
            "private_routed",
        )

        self.assertIsNone(
            result.source_mac
        )

    def test_failed_neighbor_has_no_mac(self):
        route = json.dumps(
            [
                {
                    "dst":
                        "192.168.1.50",
                    "dev":
                        "wlan-test",
                }
            ]
        )

        neighbor = json.dumps(
            [
                {
                    "dst":
                        "192.168.1.50",
                    "lladdr":
                        "aa:bb:cc:dd:ee:ff",
                    "state":
                        ["FAILED"],
                }
            ]
        )

        result = resolve_network_identity(
            source_ip="192.168.1.50",
            route_json=route,
            neighbor_json=neighbor,
        )

        self.assertIsNone(
            result.source_mac
        )


if __name__ == "__main__":
    unittest.main()
