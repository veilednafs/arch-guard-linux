import json
import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch

from arch_guard.dispatcher import EventDispatcher


class DispatcherTests(unittest.TestCase):

    def test_normal_event_is_logged(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            dispatcher = EventDispatcher(
                event_log=root / "events.jsonl",
                incident_dir=root / "incidents",
            )

            result = dispatcher.dispatch(
                {
                    "event": "ssh_auth_success",
                    "severity": "INFO",
                    "notify": True,
                    "snapshot": False,
                }
            )

            self.assertTrue(
                result.logged
            )

            self.assertFalse(
                result.incident_created
            )

            lines = (
                root
                .joinpath("events.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            )

            self.assertEqual(
                len(lines),
                1,
            )

            event = json.loads(
                lines[0]
            )

            # notify flag root tarafından tüketilmez.
            # User notifier için logda korunur.
            self.assertTrue(
                event["notify"]
            )

    def test_snapshot_false_creates_no_incident(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            dispatcher = EventDispatcher(
                event_log=root / "events.jsonl",
                incident_dir=root / "incidents",
            )

            dispatcher.dispatch(
                {
                    "event": "suricata_alert",
                    "severity": "HIGH",
                    "notify": False,
                    "snapshot": False,
                    "suppressed": True,
                }
            )

            self.assertFalse(
                (root / "incidents").exists()
            )

    def test_snapshot_true_creates_incident(self):
        fake_paths = (
            Path("/tmp/a.json"),
            Path("/tmp/a.txt"),
        )

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            dispatcher = EventDispatcher(
                event_log=root / "events.jsonl",
                incident_dir=root / "incidents",
            )

            with patch(
                "arch_guard.dispatcher.create_incident_if_needed",
                return_value=fake_paths,
            ) as mocked:

                result = dispatcher.dispatch(
                    {
                        "event": "network_port_scan",
                        "severity": "CRITICAL",
                        "notify": True,
                        "snapshot": True,
                    }
                )

            self.assertTrue(
                result.logged
            )

            self.assertTrue(
                result.incident_created
            )

            self.assertEqual(
                result.incident_paths,
                fake_paths,
            )

            mocked.assert_called_once()

    def test_notification_is_not_sent_by_dispatcher(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            dispatcher = EventDispatcher(
                event_log=root / "events.jsonl",
                incident_dir=root / "incidents",
            )

            result = dispatcher.dispatch(
                {
                    "event": "ssh_auth_success",
                    "severity": "INFO",
                    "notify": True,
                    "snapshot": False,
                }
            )

            self.assertTrue(
                result.logged
            )

            # Dispatcher'ın notifier backend'i yok.
            self.assertFalse(
                hasattr(
                    dispatcher,
                    "notifier",
                )
            )


if __name__ == "__main__":
    unittest.main()
