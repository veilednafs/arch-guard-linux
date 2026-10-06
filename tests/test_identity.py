import json
import unittest

from arch_guard.identity import (
    choose_tailscale_peer,
    parse_tailscale_status,
    resolve_ssh_identity,
    socket_owned_by_tailscale,
)


def status_json(
    *,
    two=False,
    active=True,
):
    peers = {
        "node1": {
            "HostName": "telefon",
            "OS": "android",
            "Online": True,
            "Active": active,
            "TailscaleIPs": [
                "100.64.0.10"
            ],
        }
    }

    if two:
        peers["node2"] = {
            "HostName": "tablet",
            "OS": "android",
            "Online": True,
            "Active": False,
            "TailscaleIPs": [
                "100.64.0.11"
            ],
        }

    return json.dumps(
        {"Peer": peers}
    )


class IdentityTests(unittest.TestCase):

    def test_status_parser(self):
        peers = parse_tailscale_status(
            status_json()
        )

        self.assertEqual(
            len(peers),
            1,
        )

        self.assertEqual(
            peers[0].device,
            "telefon",
        )

    def test_unique_active_peer(self):
        peers = parse_tailscale_status(
            status_json(two=True)
        )

        result = choose_tailscale_peer(
            peers
        )

        self.assertEqual(
            result.device,
            "telefon",
        )

        self.assertEqual(
            result.confidence,
            "heuristic",
        )

    def test_ambiguous_peers(self):
        peers = parse_tailscale_status(
            status_json(
                two=True,
                active=False,
            )
        )

        result = choose_tailscale_peer(
            peers
        )

        self.assertEqual(
            result.device,
            "ambiguous",
        )

        self.assertEqual(
            result.confidence,
            "none",
        )

    def test_socket_owner(self):
        sample = (
            'ESTAB 0 0 '
            '127.0.0.1:54321 '
            '127.0.0.1:42222 '
            'users:(("tailscaled",pid=123,fd=4))'
        )

        self.assertTrue(
            socket_owned_by_tailscale(
                sample,
                54321,
            )
        )

    def test_direct_connection(self):
        result = resolve_ssh_identity(
            ssh_source_ip="192.0.2.10",
            ssh_source_port=50000,
            ss_output="",
            tailscale_status_json="{}",
        )

        self.assertEqual(
            result["transport"],
            "direct",
        )

        self.assertEqual(
            result["real_source_ip"],
            "192.0.2.10",
        )

    def test_tailscale_proxy(self):
        ss = (
            'ESTAB 0 0 '
            '127.0.0.1:54321 '
            '127.0.0.1:42222 '
            'users:(("tailscaled",pid=123,fd=4))'
        )

        result = resolve_ssh_identity(
            ssh_source_ip="127.0.0.1",
            ssh_source_port=54321,
            ss_output=ss,
            tailscale_status_json=status_json(),
        )

        self.assertEqual(
            result["transport"],
            "tailscale/userspace-proxy",
        )

        self.assertEqual(
            result["device"],
            "telefon",
        )

        self.assertEqual(
            result["attribution_confidence"],
            "heuristic",
        )


if __name__ == "__main__":
    unittest.main()
