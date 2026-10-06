import unittest

from arch_guard.correlator import SSHCorrelator
from arch_guard.pipeline import SSHPipeline


class PipelineTests(unittest.TestCase):

    def make_pipeline(self):
        return SSHPipeline(
            SSHCorrelator(
                window=60,
                high_threshold=3,
                critical_threshold=5,
            )
        )

    def test_irrelevant_message(self):
        pipeline = self.make_pipeline()

        result = pipeline.process_message(
            "alakasız journal satırı",
            now=0,
        )

        self.assertEqual(
            result,
            [],
        )

    def test_success_is_notification(self):
        pipeline = self.make_pipeline()

        result = pipeline.process_message(
            "Accepted publickey for test "
            "from 192.0.2.10 port 50000 ssh2",
            now=0,
        )

        self.assertEqual(
            len(result),
            1,
        )

        self.assertEqual(
            result[0]["severity"],
            "INFO",
        )

        self.assertTrue(
            result[0]["notify"],
        )

    def test_bruteforce_is_derived(self):
        pipeline = self.make_pipeline()

        produced = []

        for i in range(3):
            produced.extend(
                pipeline.process_message(
                    "Failed password for test "
                    "from 192.0.2.20 "
                    f"port {50000 + i} ssh2",
                    now=i,
                )
            )

        brute = [
            event
            for event in produced
            if event["event"]
            == "ssh_bruteforce"
        ]

        self.assertEqual(
            len(brute),
            1,
        )

        self.assertEqual(
            brute[0]["severity"],
            "HIGH",
        )

        self.assertTrue(
            brute[0]["notify"],
        )


if __name__ == "__main__":
    unittest.main()


class IdentityPipelineTests(unittest.TestCase):

    def test_identity_resolver_is_applied(self):
        def resolver(event):
            result = dict(event)

            result.update(
                {
                    "transport":
                        "tailscale/userspace-proxy",
                    "real_source_ip":
                        "100.64.0.10",
                    "device":
                        "telefon",
                    "platform":
                        "android",
                    "identity_scope":
                        "unique_active_peer",
                    "attribution_confidence":
                        "heuristic",
                }
            )

            return result

        pipeline = SSHPipeline(
            SSHCorrelator(
                window=60,
                high_threshold=3,
                critical_threshold=5,
            ),
            identity_resolver=resolver,
        )

        result = pipeline.process_message(
            "Accepted publickey for test "
            "from 127.0.0.1 port 54321 ssh2",
            now=0,
        )

        self.assertEqual(
            len(result),
            1,
        )

        event = result[0]

        self.assertEqual(
            event["transport"],
            "tailscale/userspace-proxy",
        )

        self.assertEqual(
            event["real_source_ip"],
            "100.64.0.10",
        )

        self.assertEqual(
            event["device"],
            "telefon",
        )

        self.assertEqual(
            event["attribution_confidence"],
            "heuristic",
        )

    def test_unresolved_identity_is_preserved(self):
        def resolver(event):
            result = dict(event)

            result.update(
                {
                    "transport":
                        "tailscale/userspace-proxy",
                    "real_source_ip":
                        "unknown",
                    "device":
                        "unknown",
                    "platform":
                        "unknown",
                    "identity_scope":
                        "no_online_peers",
                    "attribution_confidence":
                        "none",
                }
            )

            return result

        pipeline = SSHPipeline(
            identity_resolver=resolver,
        )

        result = pipeline.process_message(
            "Accepted publickey for test "
            "from 127.0.0.1 port 54321 ssh2",
            now=0,
        )

        event = result[0]

        self.assertEqual(
            event["device"],
            "unknown",
        )

        self.assertEqual(
            event["attribution_confidence"],
            "none",
        )


if __name__ == "__main__":
    unittest.main()
