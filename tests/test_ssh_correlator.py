import unittest

from arch_guard.correlator import SSHCorrelator
from arch_guard.events import make_event
from arch_guard.policy import apply_policy


def failure(
    ip="192.0.2.10",
    user="test",
):
    return make_event(
        "ssh_auth_failure",
        "WARNING",
        sensor="ssh",
        ssh_source_ip=ip,
        user=user,
    )


def success(
    ip="192.0.2.10",
    user="test",
):
    return make_event(
        "ssh_auth_success",
        "INFO",
        sensor="ssh",
        ssh_source_ip=ip,
        user=user,
    )


class SSHCorrelatorTests(unittest.TestCase):

    def test_below_threshold_no_alert(self):
        c = SSHCorrelator(
            window=60,
            high_threshold=3,
            critical_threshold=5,
        )

        self.assertEqual(
            c.process(
                failure(),
                now=0,
            ),
            [],
        )

        self.assertEqual(
            c.process(
                failure(),
                now=1,
            ),
            [],
        )

    def test_high_and_critical_alert(self):
        c = SSHCorrelator(
            window=60,
            high_threshold=3,
            critical_threshold=5,
        )

        produced = []

        for index in range(5):
            produced.extend(
                c.process(
                    failure(),
                    now=index,
                )
            )

        self.assertEqual(
            len(produced),
            2,
        )

        self.assertEqual(
            produced[0]["severity"],
            "HIGH",
        )

        self.assertEqual(
            produced[0]["failure_count"],
            3,
        )

        self.assertEqual(
            produced[1]["severity"],
            "CRITICAL",
        )

        self.assertEqual(
            produced[1]["failure_count"],
            5,
        )

    def test_window_expires(self):
        c = SSHCorrelator(
            window=60,
            high_threshold=3,
            critical_threshold=5,
        )

        c.process(
            failure(),
            now=0,
        )

        c.process(
            failure(),
            now=10,
        )

        result = c.process(
            failure(),
            now=71,
        )

        self.assertEqual(
            result,
            [],
        )

    def test_success_after_failures(self):
        c = SSHCorrelator(
            window=60,
            high_threshold=3,
            critical_threshold=5,
        )

        for index in range(3):
            c.process(
                failure(
                    user=f"user{index}"
                ),
                now=index,
            )

        result = c.process(
            success(
                user="realuser"
            ),
            now=4,
        )

        self.assertEqual(
            len(result),
            1,
        )

        event = result[0]

        self.assertEqual(
            event["event"],
            "ssh_success_after_failures",
        )

        self.assertEqual(
            event["severity"],
            "HIGH",
        )

        self.assertEqual(
            event["failure_count"],
            3,
        )

        self.assertEqual(
            event["user"],
            "realuser",
        )

    def test_success_clears_history(self):
        c = SSHCorrelator(
            window=60,
            high_threshold=3,
            critical_threshold=5,
        )

        for index in range(3):
            c.process(
                failure(),
                now=index,
            )

        c.process(
            success(),
            now=4,
        )

        result = c.process(
            success(),
            now=5,
        )

        self.assertEqual(
            result,
            [],
        )

    def test_policy(self):
        successful = apply_policy(
            success()
        )

        self.assertTrue(
            successful["notify"]
        )

        failed = apply_policy(
            failure()
        )

        self.assertFalse(
            failed["notify"]
        )

        brute = apply_policy(
            make_event(
                "ssh_bruteforce",
                "HIGH",
            )
        )

        self.assertTrue(
            brute["notify"]
        )


if __name__ == "__main__":
    unittest.main()
