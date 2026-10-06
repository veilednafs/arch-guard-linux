import json
import tempfile
import unittest

from pathlib import Path

from arch_guard.events import (
    EventWriter,
    make_event,
)


class EventTests(unittest.TestCase):

    def test_event_schema(self):
        event = make_event(
            "ssh_failure",
            "HIGH",
            sensor="ssh",
            notify=True,
            source_ip="192.0.2.10",
        )

        self.assertEqual(
            event["event"],
            "ssh_failure",
        )

        self.assertEqual(
            event["severity"],
            "HIGH",
        )

        self.assertEqual(
            event["sensor"],
            "ssh",
        )

        self.assertTrue(
            event["notify"]
        )

    def test_writer(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "events.jsonl"

            writer = EventWriter(path)

            writer.write(
                make_event(
                    "test",
                    "INFO",
                )
            )

            raw = path.read_text(
                encoding="utf-8"
            ).strip()

            obj = json.loads(raw)

            self.assertEqual(
                obj["event"],
                "test",
            )


if __name__ == "__main__":
    unittest.main()
