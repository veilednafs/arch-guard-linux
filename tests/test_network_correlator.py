import unittest

from arch_guard.events import make_event
from arch_guard.network_correlator import (
    NetworkScanCorrelator,
)
from arch_guard.policy import apply_policy


def probe(
    port: int,
    *,
    source_ip: str = "192.0.2.50",
):
    return make_event(
        "network_probe",
        "WARNING",
        sensor="nftables",
        notify=False,
        source_ip=source_ip,
        source_port=50000,
        destination_ip="192.0.2.10",
        destination_port=port,
        interface="eth0",
        transport="GENERIC",
        capture_profile="generic",
    )


class NetworkCorrelatorTests(unittest.TestCase):

    def make_correlator(self):
        return NetworkScanCorrelator(
            window=10,
            threshold=6,
            cooldown=60,
        )

    def test_below_threshold_no_scan(self):
        c = self.make_correlator()

        produced = []

        for i, port in enumerate(
            [20, 21, 22, 23, 24]
        ):
            produced.extend(
                c.process(
                    probe(port),
                    now=float(i),
                )
            )

        self.assertEqual(
            produced,
            [],
        )

    def test_six_unique_ports_trigger_scan(self):
        c = self.make_correlator()

        produced = []

        for i, port in enumerate(
            [20, 21, 22, 23, 24, 25]
        ):
            produced.extend(
                c.process(
                    probe(port),
                    now=float(i),
                )
            )

        self.assertEqual(
            len(produced),
            1,
        )

        event = produced[0]

        self.assertEqual(
            event["event"],
            "network_port_scan",
        )

        self.assertEqual(
            event["severity"],
            "CRITICAL",
        )

        self.assertEqual(
            event["unique_ports"],
            6,
        )

        self.assertEqual(
            event["ports"],
            [20, 21, 22, 23, 24, 25],
        )

    def test_duplicate_port_does_not_count_twice(self):
        c = self.make_correlator()

        produced = []

        samples = [
            20,
            20,
            21,
            22,
            23,
            24,
        ]

        for i, port in enumerate(samples):
            produced.extend(
                c.process(
                    probe(port),
                    now=float(i),
                )
            )

        self.assertEqual(
            produced,
            [],
        )

    def test_old_ports_expire_from_window(self):
        c = self.make_correlator()

        for i, port in enumerate(
            [20, 21, 22, 23, 24]
        ):
            c.process(
                probe(port),
                now=float(i),
            )

        result = c.process(
            probe(25),
            now=20.0,
        )

        self.assertEqual(
            result,
            [],
        )

    def test_cooldown_suppresses_repeat_alert(self):
        c = self.make_correlator()

        first = []

        for i, port in enumerate(
            [20, 21, 22, 23, 24, 25]
        ):
            first.extend(
                c.process(
                    probe(port),
                    now=float(i),
                )
            )

        self.assertEqual(
            len(first),
            1,
        )

        repeated = c.process(
            probe(26),
            now=6.0,
        )

        self.assertEqual(
            repeated,
            [],
        )

    def test_scan_policy_notifies(self):
        event = make_event(
            "network_port_scan",
            "CRITICAL",
            sensor="correlator",
            notify=False,
            source_ip="192.0.2.50",
            ports=[
                20,
                21,
                22,
                23,
                24,
                25,
            ],
            unique_ports=6,
        )

        event = apply_policy(
            event
        )

        self.assertTrue(
            event["notify"]
        )


if __name__ == "__main__":
    unittest.main()
