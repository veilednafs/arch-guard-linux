import json
import unittest

from types import SimpleNamespace

from arch_guard.live_runtime import (
    LiveRuntimeCoordinator,
)
from arch_guard.runtime import (
    ArchGuardRuntime,
)


class FakeDispatcher:

    def __init__(self):
        self.events = []

    def dispatch(
        self,
        event,
    ):
        self.events.append(
            dict(event)
        )

        return SimpleNamespace(
            logged=True,
            incident_created=False,
            incident_paths=None,
            errors=[],
        )


class FakePipeline:

    def __init__(
        self,
        events,
    ):
        self.events = events
        self.calls = []

    def process_message(
        self,
        message,
        *,
        now=None,
        event_timestamp=None,
    ):
        self.calls.append(
            (
                message,
                now,
                event_timestamp,
            )
        )

        return [
            dict(event)
            for event in self.events
        ]


class FakeSuricataPipeline:

    def __init__(
        self,
        events,
    ):
        self.events = events
        self.calls = []

    def process_line(
        self,
        line,
        *,
        now=None,
    ):
        self.calls.append(
            (
                line,
                now,
            )
        )

        return [
            dict(event)
            for event in self.events
        ]


class LiveRuntimeTests(
    unittest.TestCase
):

    def test_prepared_event_not_repolicied(self):
        dispatcher = FakeDispatcher()

        runtime = ArchGuardRuntime(
            dispatcher
        )

        runtime.emit_prepared(
            {
                "event":
                    "network_port_scan",

                "severity":
                    "CRITICAL",

                # Kasten farklı değerler.
                # emit_prepared bunları değiştirmemeli.
                "notify":
                    False,

                "snapshot":
                    False,
            },
            sensor="network",
        )

        event = dispatcher.events[-1]

        self.assertFalse(
            event["notify"]
        )

        self.assertFalse(
            event["snapshot"]
        )

    def test_ssh_journal_line(self):
        dispatcher = FakeDispatcher()

        runtime = ArchGuardRuntime(
            dispatcher
        )

        pipeline = FakePipeline(
            [
                {
                    "event":
                        "ssh_auth_success",

                    "severity":
                        "INFO",

                    "notify":
                        True,

                    "snapshot":
                        False,
                }
            ]
        )

        coordinator = (
            LiveRuntimeCoordinator(
                runtime,
                ssh_pipeline=pipeline,
                network_pipeline=FakePipeline(
                    []
                ),
                suricata_pipeline=FakeSuricataPipeline(
                    []
                ),
            )
        )

        line = json.dumps(
            {
                "MESSAGE":
                    "Accepted publickey for demo",

                "__REALTIME_TIMESTAMP":
                    "1791316800000000",
            }
        )

        count = (
            coordinator
            .process_ssh_line(
                line
            )
        )

        self.assertEqual(
            count,
            1,
        )

        self.assertEqual(
            len(
                dispatcher.events
            ),
            1,
        )

        self.assertEqual(
            dispatcher.events[0][
                "sensor"
            ],
            "ssh",
        )

        self.assertEqual(
            coordinator.stats.ssh_lines,
            1,
        )

        self.assertEqual(
            coordinator.stats.ssh_events,
            1,
        )

    def test_network_journal_line(self):
        dispatcher = FakeDispatcher()

        runtime = ArchGuardRuntime(
            dispatcher
        )

        pipeline = FakePipeline(
            [
                {
                    "event":
                        "network_probe",

                    "severity":
                        "WARNING",

                    "notify":
                        False,

                    "snapshot":
                        False,
                }
            ]
        )

        coordinator = (
            LiveRuntimeCoordinator(
                runtime,
                ssh_pipeline=FakePipeline(
                    []
                ),
                network_pipeline=pipeline,
                suricata_pipeline=FakeSuricataPipeline(
                    []
                ),
            )
        )

        line = json.dumps(
            {
                "MESSAGE":
                    "AGNET SRC=192.0.2.5",

                "__REALTIME_TIMESTAMP":
                    "1791316800000000",
            }
        )

        count = (
            coordinator
            .process_network_line(
                line
            )
        )

        self.assertEqual(
            count,
            1,
        )

        self.assertEqual(
            dispatcher.events[0][
                "sensor"
            ],
            "network",
        )

    def test_suricata_line(self):
        dispatcher = FakeDispatcher()

        runtime = ArchGuardRuntime(
            dispatcher
        )

        pipeline = (
            FakeSuricataPipeline(
                [
                    {
                        "event":
                            "suricata_alert",

                        "severity":
                            "HIGH",

                        "notify":
                            False,

                        "snapshot":
                            False,

                        "suppressed":
                            True,
                    }
                ]
            )
        )

        coordinator = (
            LiveRuntimeCoordinator(
                runtime,
                ssh_pipeline=FakePipeline(
                    []
                ),
                network_pipeline=FakePipeline(
                    []
                ),
                suricata_pipeline=pipeline,
            )
        )

        count = (
            coordinator
            .process_suricata_line(
                '{"event_type":"alert"}',
                now=123.0,
            )
        )

        self.assertEqual(
            count,
            1,
        )

        self.assertEqual(
            dispatcher.events[0][
                "sensor"
            ],
            "suricata",
        )

        self.assertEqual(
            coordinator.stats.suricata_events,
            1,
        )


if __name__ == "__main__":
    unittest.main()
