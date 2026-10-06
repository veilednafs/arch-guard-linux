import json
import unittest

from arch_guard.sensors.suricata import (
    map_suricata_severity,
    parse_eve_line,
    parse_suricata_alert,
)


def sample_alert(
    *,
    severity=2,
    sid=2100365,
):
    return {
        "timestamp":
            "2026-10-06T20:15:00+03:00",

        "event_type":
            "alert",

        "src_ip":
            "198.51.100.20",

        "src_port":
            443,

        "dest_ip":
            "192.0.2.10",

        "dest_port":
            55000,

        "proto":
            "TCP",

        "app_proto":
            "tls",

        "flow_id":
            123456,

        "community_id":
            "1:test",

        "in_iface":
            "test0",

        "ether": {
            "src_mac":
                "11:22:33:44:55:66",

            "dest_mac":
                "aa:bb:cc:dd:ee:ff",
        },

        "alert": {
            "signature_id":
                sid,

            "signature":
                "ET TEST Example Alert",

            "category":
                "Misc activity",

            "severity":
                severity,

            "action":
                "allowed",
        },
    }


class SuricataSensorTests(unittest.TestCase):

    def test_severity_mapping(self):
        self.assertEqual(
            map_suricata_severity(1),
            "CRITICAL",
        )

        self.assertEqual(
            map_suricata_severity(2),
            "HIGH",
        )

        self.assertEqual(
            map_suricata_severity(3),
            "WARNING",
        )

        self.assertEqual(
            map_suricata_severity(4),
            "INFO",
        )

    def test_non_alert_is_ignored(self):
        self.assertIsNone(
            parse_suricata_alert(
                {
                    "event_type":
                        "flow"
                }
            )
        )

    def test_alert_fields(self):
        event = parse_suricata_alert(
            sample_alert()
        )

        self.assertIsNotNone(
            event
        )

        self.assertEqual(
            event["event"],
            "suricata_alert",
        )

        self.assertEqual(
            event["severity"],
            "HIGH",
        )

        self.assertEqual(
            event["signature_id"],
            2100365,
        )

        self.assertEqual(
            event["source_ip"],
            "198.51.100.20",
        )

        self.assertEqual(
            event["destination_port"],
            55000,
        )

    def test_warp_uses_same_parser(self):
        event = parse_suricata_alert(
            sample_alert(),
            sensor_profile="warp",
        )

        self.assertEqual(
            event["sensor_profile"],
            "warp",
        )

        self.assertEqual(
            event["sensor"],
            "suricata",
        )

    def test_eve_timestamp_is_preserved(self):
        event = parse_suricata_alert(
            sample_alert()
        )

        self.assertEqual(
            event["timestamp"],
            "2026-10-06T20:15:00+03:00",
        )

    def test_ethernet_mac_not_promoted(self):
        event = parse_suricata_alert(
            sample_alert()
        )

        self.assertNotIn(
            "source_mac",
            event,
        )

        self.assertEqual(
            event[
                "ethernet_source_mac"
            ],
            "11:22:33:44:55:66",
        )

    def test_invalid_json_is_ignored(self):
        self.assertIsNone(
            parse_eve_line(
                "bu json değil"
            )
        )

        raw = json.dumps(
            sample_alert()
        )

        event = parse_eve_line(
            raw,
            sensor_profile="default",
        )

        self.assertEqual(
            event["event"],
            "suricata_alert",
        )


if __name__ == "__main__":
    unittest.main()
