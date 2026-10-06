import unittest

from arch_guard.network_correlator import (
    NetworkScanCorrelator,
)
from arch_guard.network_listener import (
    classify_listener_output,
)
from arch_guard.network_pipeline import (
    NetworkPipeline,
)


class NetworkListenerTests(unittest.TestCase):

    def test_no_listener(self):
        info = classify_listener_output(
            "",
            22,
        )

        self.assertFalse(
            info.listening
        )

        self.assertEqual(
            info.listener_scope,
            "NO_LISTENER",
        )

    def test_loopback_listener(self):
        info = classify_listener_output(
            "LISTEN 0 128 "
            "127.0.0.1:42222 "
            "0.0.0.0:*",
            42222,
        )

        self.assertEqual(
            info.listener_scope,
            "LOOPBACK_ONLY",
        )

    def test_all_interfaces_listener(self):
        info = classify_listener_output(
            "LISTEN 0 128 "
            "0.0.0.0:8080 "
            "0.0.0.0:*",
            8080,
        )

        self.assertEqual(
            info.listener_scope,
            "ALL_INTERFACES",
        )

    def test_bound_interface_listener(self):
        info = classify_listener_output(
            "LISTEN 0 128 "
            "192.168.1.10:9000 "
            "0.0.0.0:*",
            9000,
        )

        self.assertEqual(
            info.listener_scope,
            "BOUND_INTERFACE",
        )


class NetworkPipelineTests(unittest.TestCase):

    @staticmethod
    def identity(event):
        result = dict(event)

        result.update(
            {
                "source_scope":
                    "lan_direct",
                "source_mac":
                    "aa:bb:cc:dd:ee:ff",
                "attribution_confidence":
                    "neighbor",
            }
        )

        return result

    @staticmethod
    def listener(event):
        result = dict(event)

        result.update(
            {
                "listening":
                    True,
                "listener_scope":
                    "BOUND_INTERFACE",
                "listener":
                    "test-listener",
            }
        )

        return result

    def make_pipeline(self):
        return NetworkPipeline(
            correlator=NetworkScanCorrelator(
                window=10,
                threshold=6,
                cooldown=60,
            ),
            identity_resolver=self.identity,
            listener_resolver=self.listener,
        )

    def test_probe_is_enriched(self):
        pipeline = self.make_pipeline()

        events = pipeline.process_message(
            "AGNET "
            "IN=eth0 OUT= "
            "SRC=192.0.2.50 "
            "DST=192.0.2.10 "
            "PROTO=TCP "
            "SPT=50000 DPT=22 SYN",
            now=0,
        )

        self.assertEqual(
            len(events),
            1,
        )

        event = events[0]

        self.assertEqual(
            event["event"],
            "network_probe",
        )

        self.assertEqual(
            event["source_mac"],
            "aa:bb:cc:dd:ee:ff",
        )

        self.assertEqual(
            event["listener_scope"],
            "BOUND_INTERFACE",
        )

        self.assertFalse(
            event["notify"]
        )

    def test_scan_is_derived(self):
        pipeline = self.make_pipeline()

        produced = []

        ports = [
            22,
            80,
            443,
            8080,
            8443,
            9000,
        ]

        for index, port in enumerate(
            ports
        ):
            produced.extend(
                pipeline.process_message(
                    (
                        "AGNET "
                        "IN=eth0 OUT= "
                        "SRC=192.0.2.50 "
                        "DST=192.0.2.10 "
                        "PROTO=TCP "
                        f"SPT={50000 + index} "
                        f"DPT={port} SYN"
                    ),
                    now=float(index),
                )
            )

        scans = [
            event
            for event in produced
            if event["event"]
            == "network_port_scan"
        ]

        self.assertEqual(
            len(scans),
            1,
        )

        self.assertTrue(
            scans[0]["notify"]
        )

        self.assertEqual(
            scans[0]["unique_ports"],
            6,
        )

        self.assertEqual(
            scans[0]["source_mac"],
            "aa:bb:cc:dd:ee:ff",
        )

        self.assertEqual(
            scans[0]["source_scope"],
            "lan_direct",
        )

        self.assertEqual(
            scans[0]["attribution_confidence"],
            "neighbor",
        )

    def test_unrelated_kernel_line(self):
        pipeline = self.make_pipeline()

        self.assertEqual(
            pipeline.process_message(
                "kernel: unrelated message",
                now=0,
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
