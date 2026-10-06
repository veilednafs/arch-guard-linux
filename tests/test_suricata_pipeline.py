import json
import unittest

from arch_guard.suricata_pipeline import (
    SuricataPipeline,
)


def eve(
    *,
    signature="ET TEST Alert",
    sid=900001,
    severity=2,
    source_port=443,
    flow_id=100,
):
    return json.dumps(
        {
            "timestamp":
                "2026-10-06T20:30:00+03:00",

            "event_type":
                "alert",

            "src_ip":
                "198.51.100.20",

            "src_port":
                source_port,

            "dest_ip":
                "192.0.2.10",

            "dest_port":
                55000,

            "proto":
                "TCP",

            "flow_id":
                flow_id,

            "alert": {
                "signature_id":
                    sid,

                "signature":
                    signature,

                "category":
                    "Test",

                "severity":
                    severity,

                "action":
                    "allowed",
            },
        }
    )


def inbound(event):
    result = dict(event)

    result.update(
        {
            "direction":
                "REMOTE_INBOUND",

            "direction_evidence":
                "test",

            "self_originated":
                False,

            "return_traffic":
                False,

            "locally_initiated_flow":
                False,
        }
    )

    return result


def returning(event):
    result = dict(event)

    result.update(
        {
            "direction":
                "RETURN_TRAFFIC",

            "direction_evidence":
                "test",

            "self_originated":
                False,

            "return_traffic":
                True,

            "locally_initiated_flow":
                True,
        }
    )

    return result


class SuricataPipelineTests(unittest.TestCase):

    def test_remote_high_alert(self):
        pipeline = SuricataPipeline(
            direction_resolver=inbound
        )

        events = pipeline.process_line(
            eve(),
            now=0,
        )

        self.assertEqual(
            len(events),
            1,
        )

        event = events[0]

        self.assertTrue(
            event["notify"]
        )

        self.assertTrue(
            event["snapshot"]
        )

    def test_tor_return_is_suppressed(self):
        pipeline = SuricataPipeline(
            direction_resolver=returning
        )

        events = pipeline.process_line(
            eve(
                signature=(
                    "ET TOR Known Tor "
                    "Relay/Router"
                ),
                sid=2522154,
            ),
            now=0,
        )

        event = events[0]

        self.assertTrue(
            event["suppressed"]
        )

        self.assertFalse(
            event["notify"]
        )

        self.assertFalse(
            event["snapshot"]
        )

    def test_duplicate_is_dropped(self):
        pipeline = SuricataPipeline(
            direction_resolver=inbound,
            dedup_seconds=30,
        )

        self.assertEqual(
            len(
                pipeline.process_line(
                    eve(),
                    now=0,
                )
            ),
            1,
        )

        self.assertEqual(
            pipeline.process_line(
                eve(),
                now=10,
            ),
            [],
        )

        self.assertEqual(
            pipeline.duplicates_dropped,
            1,
        )

    def test_new_flow_not_deduplicated(self):
        pipeline = SuricataPipeline(
            direction_resolver=inbound,
            dedup_seconds=30,
        )

        first = pipeline.process_line(
            eve(
                source_port=443,
                flow_id=100,
            ),
            now=0,
        )

        second = pipeline.process_line(
            eve(
                source_port=444,
                flow_id=101,
            ),
            now=1,
        )

        self.assertEqual(
            len(first),
            1,
        )

        self.assertEqual(
            len(second),
            1,
        )

    def test_warp_profile_uses_same_pipeline(self):
        pipeline = SuricataPipeline(
            profile="warp",
            direction_resolver=inbound,
        )

        event = pipeline.process_line(
            eve(),
            now=0,
        )[0]

        self.assertEqual(
            event["sensor_profile"],
            "warp",
        )

    def test_non_alert_is_ignored(self):
        pipeline = SuricataPipeline(
            direction_resolver=inbound
        )

        line = json.dumps(
            {
                "event_type":
                    "flow"
            }
        )

        self.assertEqual(
            pipeline.process_line(
                line,
                now=0,
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
