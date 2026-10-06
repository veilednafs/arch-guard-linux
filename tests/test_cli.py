import io
import json
import tempfile
import unittest

from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from arch_guard import __version__
from arch_guard.cli import (
    _read_events,
    main,
)


def fake_config(
    root: Path,
):
    return SimpleNamespace(
        paths=SimpleNamespace(
            event_log=(
                root
                / "events.jsonl"
            ),
            incident_dir=(
                root
                / "incidents"
            ),
        ),
        ssh=SimpleNamespace(
            enabled=True,
        ),
        network=SimpleNamespace(
            enabled=True,
        ),
        tailscale_scan=SimpleNamespace(
            enabled=False,
            window=10,
            threshold=25,
            cooldown=60,
        ),
        suricata=SimpleNamespace(
            enabled=False,
            eve_files=[],
        ),
    )


class CLITests(
    unittest.TestCase
):

    def test_version(self):
        output = io.StringIO()

        with redirect_stdout(
            output
        ):
            rc = main(
                ["version"]
            )

        self.assertEqual(
            rc,
            0,
        )

        self.assertIn(
            __version__,
            output.getvalue(),
        )

    def test_no_command_shows_help(self):
        output = io.StringIO()

        with redirect_stdout(
            output
        ):
            rc = main([])

        self.assertEqual(
            rc,
            0,
        )

        self.assertIn(
            "usage:",
            output.getvalue(),
        )

    def test_read_last_events(self):
        with tempfile.TemporaryDirectory() as td:
            path = (
                Path(td)
                / "events.jsonl"
            )

            path.write_text(
                "\n".join(
                    json.dumps(
                        {
                            "event":
                                f"event_{index}",

                            "severity":
                                "INFO",
                        }
                    )
                    for index in range(5)
                )
                + "\n",
                encoding="utf-8",
            )

            events = _read_events(
                path,
                limit=2,
                event_filter=None,
            )

            self.assertEqual(
                [
                    item["event"]
                    for item in events
                ],
                [
                    "event_3",
                    "event_4",
                ],
            )

    def test_event_filter(self):
        with tempfile.TemporaryDirectory() as td:
            path = (
                Path(td)
                / "events.jsonl"
            )

            path.write_text(
                (
                    '{"event":"one"}\n'
                    '{"event":"two"}\n'
                    '{"event":"one"}\n'
                ),
                encoding="utf-8",
            )

            events = _read_events(
                path,
                limit=20,
                event_filter="two",
            )

            self.assertEqual(
                len(events),
                1,
            )

            self.assertEqual(
                events[0]["event"],
                "two",
            )

    def test_events_command_json(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            (
                root
                / "events.jsonl"
            ).write_text(
                (
                    '{"event":"ssh_auth_success",'
                    '"severity":"INFO",'
                    '"notify":true,'
                    '"snapshot":false}\n'
                ),
                encoding="utf-8",
            )

            output = io.StringIO()

            with (
                patch(
                    "arch_guard.cli._load_config",
                    return_value=fake_config(
                        root
                    ),
                ),
                redirect_stdout(
                    output
                ),
            ):
                rc = main(
                    [
                        "events",
                        "--json",
                    ]
                )

            self.assertEqual(
                rc,
                0,
            )

            parsed = json.loads(
                output.getvalue()
            )

            self.assertEqual(
                parsed[0]["event"],
                "ssh_auth_success",
            )

    def test_status_command(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            output = io.StringIO()

            with (
                patch(
                    "arch_guard.cli._load_config",
                    return_value=fake_config(
                        root
                    ),
                ),
                patch(
                    "arch_guard.cli.config_path",
                    return_value=(
                        root
                        / "config.toml"
                    ),
                ),
                patch(
                    "arch_guard.cli._unit_state",
                    return_value="inactive",
                ),
                redirect_stdout(
                    output
                ),
            ):
                rc = main(
                    ["status"]
                )

            self.assertEqual(
                rc,
                0,
            )

            text = output.getvalue()

            self.assertIn(
                "SSH",
                text,
            )

            self.assertIn(
                "Network",
                text,
            )

            self.assertIn(
                "Suricata",
                text,
            )


if __name__ == "__main__":
    unittest.main()


class CLIRuntimeCommandsTests(
    unittest.TestCase
):

    @patch(
        "arch_guard.cli._load_config"
    )
    @patch(
        "arch_guard.cli.run_daemon"
    )
    def test_run_command(
        self,
        mocked_run,
        mocked_config,
    ):
        mocked_config.return_value = (
            object()
        )

        mocked_run.return_value = 0

        rc = main(
            [
                "run",
                "--tailscale-scan",
            ]
        )

        self.assertEqual(
            rc,
            0,
        )

        mocked_run.assert_called_once()

        self.assertTrue(
            mocked_run.call_args.kwargs[
                "enable_tailscale_scan"
            ]
        )

    @patch(
        "arch_guard.cli._load_config"
    )
    @patch(
        "arch_guard.cli.run_notifier"
    )
    def test_notify_command(
        self,
        mocked_notify,
        mocked_config,
    ):
        mocked_config.return_value = (
            SimpleNamespace(
                paths=SimpleNamespace(
                    event_log=(
                        "/tmp/events.jsonl"
                    )
                )
            )
        )

        mocked_notify.return_value = 0

        rc = main(
            ["notify"]
        )

        self.assertEqual(
            rc,
            0,
        )

        mocked_notify.assert_called_once()
