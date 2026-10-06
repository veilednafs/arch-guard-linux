import unittest

from arch_guard.suricata_direction import (
    REMOTE_INBOUND,
    RETURN_TRAFFIC,
    SELF_OUTBOUND,
    TRANSIT_OR_UNKNOWN,
    classify_direction,
    conntrack_original_match_text,
)


LOCAL = {
    "192.0.2.10",
}


def event(
    source_ip,
    destination_ip,
    source_port=443,
    destination_port=55000,
):
    return {
        "source_ip":
            source_ip,

        "destination_ip":
            destination_ip,

        "source_port":
            source_port,

        "destination_port":
            destination_port,

        "protocol":
            "TCP",
    }


class SuricataDirectionTests(unittest.TestCase):

    def test_self_outbound(self):
        result = classify_direction(
            event(
                "192.0.2.10",
                "198.51.100.20",
                55000,
                443,
            ),
            local_ips=LOCAL,
        )

        self.assertEqual(
            result.direction,
            SELF_OUTBOUND,
        )

        self.assertTrue(
            result.locally_initiated_flow
        )

    def test_remote_inbound(self):
        result = classify_direction(
            event(
                "198.51.100.20",
                "192.0.2.10",
            ),
            local_ips=LOCAL,
        )

        self.assertEqual(
            result.direction,
            REMOTE_INBOUND,
        )

        self.assertFalse(
            result.locally_initiated_flow
        )

    def test_return_by_conntrack(self):
        result = classify_direction(
            event(
                "198.51.100.20",
                "192.0.2.10",
            ),
            local_ips=LOCAL,
            conntrack_return=True,
        )

        self.assertEqual(
            result.direction,
            RETURN_TRAFFIC,
        )

        self.assertEqual(
            result.evidence,
            "conntrack_original_tuple",
        )

    def test_return_by_socket(self):
        result = classify_direction(
            event(
                "198.51.100.20",
                "192.0.2.10",
            ),
            local_ips=LOCAL,
            socket_return=True,
        )

        self.assertEqual(
            result.direction,
            RETURN_TRAFFIC,
        )

        self.assertEqual(
            result.evidence,
            "matching_local_socket",
        )

    def test_transit_unknown(self):
        result = classify_direction(
            event(
                "198.51.100.20",
                "203.0.113.50",
            ),
            local_ips=LOCAL,
        )

        self.assertEqual(
            result.direction,
            TRANSIT_OR_UNKNOWN,
        )

    def test_ethernet_mac_does_not_force_local(self):
        sample = event(
            "198.51.100.20",
            "203.0.113.50",
        )

        sample[
            "ethernet_source_mac"
        ] = "aa:bb:cc:dd:ee:ff"

        result = classify_direction(
            sample,
            local_ips=LOCAL,
        )

        self.assertEqual(
            result.direction,
            TRANSIT_OR_UNKNOWN,
        )

    def test_conntrack_original_tuple(self):
        sample = event(
            "198.51.100.20",
            "192.0.2.10",
            443,
            55000,
        )

        raw = (
            "tcp 6 431999 ESTABLISHED "
            "src=192.0.2.10 "
            "dst=198.51.100.20 "
            "sport=55000 "
            "dport=443 "
            "src=198.51.100.20 "
            "dst=192.0.2.10 "
            "sport=443 "
            "dport=55000"
        )

        self.assertTrue(
            conntrack_original_match_text(
                sample,
                raw,
            )
        )


if __name__ == "__main__":
    unittest.main()
