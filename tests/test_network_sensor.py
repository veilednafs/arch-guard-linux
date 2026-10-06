import unittest

from arch_guard.sensors.network import (
    parse_nft_log_line,
)


class NetworkSensorTests(unittest.TestCase):

    def test_wlan_probe(self):
        line = (
            "AGNET_WLAN "
            "IN=wlan0 OUT= "
            "SRC=192.0.2.20 "
            "DST=192.0.2.10 "
            "PROTO=TCP "
            "SPT=51000 DPT=22 "
            "SYN"
        )

        event = parse_nft_log_line(
            line
        )

        self.assertIsNotNone(event)

        self.assertEqual(
            event["event"],
            "network_probe",
        )

        self.assertEqual(
            event["source_ip"],
            "192.0.2.20",
        )

        self.assertEqual(
            event["destination_port"],
            22,
        )

        self.assertEqual(
            event["transport"],
            "WLAN",
        )

        self.assertEqual(
            event["capture_profile"],
            "wlan",
        )

    def test_warp_probe(self):
        line = (
            "AGNET_WARP "
            "IN=warp0 OUT= "
            "SRC=198.51.100.20 "
            "DST=198.51.100.10 "
            "PROTO=TCP "
            "SPT=52000 DPT=443 "
            "SYN"
        )

        event = parse_nft_log_line(
            line
        )

        self.assertIsNotNone(event)

        self.assertEqual(
            event["transport"],
            "WARP",
        )

        self.assertEqual(
            event["capture_profile"],
            "warp",
        )

    def test_generic_probe(self):
        line = (
            "AGNET "
            "IN=eth0 OUT= "
            "SRC=203.0.113.20 "
            "DST=203.0.113.10 "
            "PROTO=TCP "
            "SPT=53000 DPT=8080 "
            "SYN"
        )

        event = parse_nft_log_line(
            line,
            timestamp=(
                "2026-10-06T19:00:00+03:00"
            ),
        )

        self.assertIsNotNone(event)

        self.assertEqual(
            event["transport"],
            "GENERIC",
        )

        self.assertEqual(
            event["timestamp"],
            "2026-10-06T19:00:00+03:00",
        )

    def test_udp_is_ignored(self):
        line = (
            "AGNET "
            "IN=eth0 "
            "SRC=192.0.2.20 "
            "DST=192.0.2.10 "
            "PROTO=UDP "
            "SPT=50000 DPT=53"
        )

        self.assertIsNone(
            parse_nft_log_line(line)
        )

    def test_missing_port_is_ignored(self):
        line = (
            "AGNET "
            "IN=eth0 "
            "SRC=192.0.2.20 "
            "DST=192.0.2.10 "
            "PROTO=TCP"
        )

        self.assertIsNone(
            parse_nft_log_line(line)
        )

    def test_unrelated_kernel_line(self):
        self.assertIsNone(
            parse_nft_log_line(
                "Linux kernel unrelated message"
            )
        )


if __name__ == "__main__":
    unittest.main()
