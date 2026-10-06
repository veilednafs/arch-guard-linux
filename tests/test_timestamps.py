import unittest

from arch_guard.events import make_event
from arch_guard.pipeline import SSHPipeline


class TimestampTests(unittest.TestCase):

    def test_explicit_timestamp(self):
        timestamp = "2026-01-02T03:04:05+03:00"

        event = make_event(
            "test",
            "INFO",
            timestamp=timestamp,
        )

        self.assertEqual(
            event["timestamp"],
            timestamp,
        )

    def test_pipeline_preserves_journal_time(self):
        timestamp = "2026-02-03T04:05:06+03:00"

        pipeline = SSHPipeline(
            identity_resolver=lambda event: event
        )

        events = pipeline.process_message(
            "Accepted publickey for test "
            "from 192.0.2.10 port 50000 ssh2",
            now=100,
            event_timestamp=timestamp,
        )

        self.assertEqual(
            events[0]["timestamp"],
            timestamp,
        )


if __name__ == "__main__":
    unittest.main()
