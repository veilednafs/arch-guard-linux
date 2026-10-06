import json
import unittest

from arch_guard.journal import parse_journal_line


class JournalTests(unittest.TestCase):

    def test_valid_record(self):
        raw = json.dumps(
            {
                "MESSAGE":
                    "Accepted publickey for test "
                    "from 192.0.2.1 "
                    "port 50000 ssh2",
                "__REALTIME_TIMESTAMP":
                    "10000000",
            }
        )

        record = parse_journal_line(
            raw
        )

        self.assertIsNotNone(record)

        self.assertEqual(
            record.timestamp,
            10.0,
        )

        self.assertIn(
            "Accepted publickey",
            record.message,
        )

    def test_invalid_record(self):
        self.assertIsNone(
            parse_journal_line(
                "bu json değil"
            )
        )


if __name__ == "__main__":
    unittest.main()
