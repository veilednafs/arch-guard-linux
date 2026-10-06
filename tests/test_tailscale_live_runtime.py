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

    def process_message(
        self,
        message,
        *,
        now=None,
        event_timestamp=None,
    ):
        return []


class FakeSuricata:

    def process_line(
        self,
        line,
        *,
        now=None,
    ):
        return []


class FakeTailscaleDetector:

    def process_line(
        self,
        line,
        *,
        now=None,
    ):
        return [
            {
                "event":
                    "tailscale_port_scan",

                "severity":
                    "HIGH",

                "device":
                    "phone",

                "source_ip":
                    "100.64.0.20",

                "platform":
                    "android",

                "identity_scope":
                    "unique_active_peer",

                "attribution_confidence":
                    "heuristic",

                "transport":
                    "tailscale/userspace-proxy",

                "ports":
                    list(
                        range(
                            65000,
                            65025,
                        )
                    ),

                "unique_ports":
                    25,

                "window_seconds":
                    10,

                "notify":
                    False,

                "snapshot":
                    False,
            }
        ]


class TailscaleLiveRuntimeTests(
    unittest.TestCase
):

    def test_detector_enters_runtime(self):
        dispatcher = FakeDispatcher()

        runtime = ArchGuardRuntime(
            dispatcher
        )

        coordinator = (
            LiveRuntimeCoordinator(
                runtime,
                ssh_pipeline=FakePipeline(),
                network_pipeline=FakePipeline(),
                suricata_pipeline=FakeSuricata(),
                tailscale_scan_detector=FakeTailscaleDetector(),
            )
        )

        count = (
            coordinator
            .process_tailscale_scan_line(
                "tcpdump line",
                now=100.0,
            )
        )

        self.assertEqual(
            count,
            1,
        )

        self.assertEqual(
            coordinator.stats.tailscale_lines,
            1,
        )

        self.assertEqual(
            coordinator.stats.tailscale_events,
            1,
        )

        self.assertEqual(
            runtime.stats.received,
            1,
        )

        event = dispatcher.events[0]

        self.assertEqual(
            event["sensor"],
            "tailscale_scan",
        )

        self.assertTrue(
            event["notify"]
        )

        self.assertFalse(
            event["snapshot"]
        )

        self.assertEqual(
            event["attribution_confidence"],
            "heuristic",
        )


if __name__ == "__main__":
    unittest.main()
