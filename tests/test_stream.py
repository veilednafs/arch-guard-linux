import io
import json
import tempfile
import unittest

from pathlib import Path

from arch_guard.events import EventWriter
from arch_guard.pipeline import SSHPipeline
from arch_guard.stream import process_journal_stream


class StreamTests(unittest.TestCase):

    def test_stream_writes_event(self):
        def identity_off(event):
            return dict(event)

        pipeline = SSHPipeline(
            identity_resolver=identity_off
        )

        raw = json.dumps(
            {
                "MESSAGE":
                    "Accepted publickey for test "
                    "from 192.0.2.10 "
                    "port 50000 ssh2",
                "__REALTIME_TIMESTAMP":
                    "1000000",
            }
        )

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "events.jsonl"

            stats = process_journal_stream(
                io.StringIO(raw + "\n"),
                pipeline=pipeline,
                writer=EventWriter(path),
            )

            self.assertEqual(
                stats["events"],
                1,
            )

            self.assertTrue(
                path.exists()
            )


if __name__ == "__main__":
    unittest.main()
