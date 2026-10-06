import unittest

from arch_guard.suricata_dedup import (
    SuricataDeduplicator,
)


def event(
    *,
    profile="default",
):
    return {
        "sensor_profile":
            profile,

        "signature_id":
            1234,

        "source_ip":
            "198.51.100.20",

        "destination_ip":
            "192.0.2.10",

        "destination_port":
            443,
    }


class SuricataDedupTests(unittest.TestCase):

    def test_first_event_is_accepted(self):
        dedup = SuricataDeduplicator(
            seconds=30
        )

        self.assertTrue(
            dedup.accept(
                event(),
                now=0,
            )
        )

    def test_duplicate_inside_window_is_dropped(self):
        dedup = SuricataDeduplicator(
            seconds=30
        )

        dedup.accept(
            event(),
            now=0,
        )

        self.assertFalse(
            dedup.accept(
                event(),
                now=10,
            )
        )

    def test_after_window_is_accepted(self):
        dedup = SuricataDeduplicator(
            seconds=30
        )

        dedup.accept(
            event(),
            now=0,
        )

        self.assertTrue(
            dedup.accept(
                event(),
                now=31,
            )
        )

    def test_profiles_do_not_collide(self):
        dedup = SuricataDeduplicator(
            seconds=30
        )

        self.assertTrue(
            dedup.accept(
                event(
                    profile="default"
                ),
                now=0,
            )
        )

        self.assertTrue(
            dedup.accept(
                event(
                    profile="warp"
                ),
                now=1,
            )
        )


if __name__ == "__main__":
    unittest.main()
