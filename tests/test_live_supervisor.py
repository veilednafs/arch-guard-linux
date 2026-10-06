import unittest

from arch_guard.live_supervisor import (
    LiveSource,
    LiveSupervisor,
    default_sources,
)


class FakeCoordinator:

    def __init__(self):
        self.calls = []

    def process_ssh_line(
        self,
        line,
    ):
        self.calls.append(
            ("ssh", line)
        )
        return 1

    def process_network_line(
        self,
        line,
    ):
        self.calls.append(
            ("network", line)
        )
        return 2

    def process_suricata_line(
        self,
        line,
    ):
        self.calls.append(
            ("suricata", line)
        )
        return 3

    def process_tailscale_scan_line(
        self,
        line,
    ):
        self.calls.append(
            ("tailscale_scan", line)
        )
        return 4


class LiveSupervisorTests(
    unittest.TestCase
):

    def test_default_sources(self):
        sources = default_sources()

        self.assertEqual(
            [x.kind for x in sources],
            [
                "ssh",
                "network",
                "suricata",
                "tailscale_scan",
            ],
        )

        self.assertEqual(
            sources[0].command[0],
            "journalctl",
        )

        self.assertIn(
            "sshd.service",
            sources[0].command,
        )

        self.assertEqual(
            sources[2].command[0],
            "tail",
        )

    def test_dispatch_routes_ssh(self):
        coordinator = (
            FakeCoordinator()
        )

        supervisor = (
            LiveSupervisor(
                coordinator,
                sources=[],
            )
        )

        source = LiveSource(
            name="x",
            kind="ssh",
            command=("true",),
        )

        result = supervisor.dispatch_line(
            source,
            "abc",
        )

        self.assertEqual(
            result,
            1,
        )

        self.assertEqual(
            coordinator.calls,
            [("ssh", "abc")],
        )

    def test_dispatch_routes_network(self):
        coordinator = (
            FakeCoordinator()
        )

        supervisor = (
            LiveSupervisor(
                coordinator,
                sources=[],
            )
        )

        source = LiveSource(
            name="x",
            kind="network",
            command=("true",),
        )

        self.assertEqual(
            supervisor.dispatch_line(
                source,
                "abc",
            ),
            2,
        )

    def test_dispatch_routes_suricata(self):
        coordinator = (
            FakeCoordinator()
        )

        supervisor = (
            LiveSupervisor(
                coordinator,
                sources=[],
            )
        )

        source = LiveSource(
            name="x",
            kind="suricata",
            command=("true",),
        )

        self.assertEqual(
            supervisor.dispatch_line(
                source,
                "abc",
            ),
            3,
        )

    def test_dispatch_routes_tailscale(self):
        coordinator = (
            FakeCoordinator()
        )

        supervisor = (
            LiveSupervisor(
                coordinator,
                sources=[],
            )
        )

        source = LiveSource(
            name="x",
            kind="tailscale_scan",
            command=("true",),
        )

        self.assertEqual(
            supervisor.dispatch_line(
                source,
                "abc",
            ),
            4,
        )

        self.assertEqual(
            coordinator.calls[-1],
            ("tailscale_scan", "abc"),
        )


    def test_unknown_source_rejected(self):
        coordinator = (
            FakeCoordinator()
        )

        supervisor = (
            LiveSupervisor(
                coordinator,
                sources=[],
            )
        )

        source = LiveSource(
            name="x",
            kind="weird",
            command=("true",),
        )

        with self.assertRaises(
            ValueError
        ):
            supervisor.dispatch_line(
                source,
                "abc",
            )


if __name__ == "__main__":
    unittest.main()
