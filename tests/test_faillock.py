import unittest

from types import SimpleNamespace

from arch_guard.faillock import (
    FaillockDetector,
    faillock_count,
)
from arch_guard.policy import (
    apply_policy,
)
from arch_guard.notifier import (
    render_notification,
)


class FaillockTests(
    unittest.TestCase
):

    def test_count_valid_rows(self):

        def runner(
            *args,
            **kwargs,
        ):
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    "user tty 2026-01-01 V\n"
                    "user tty 2026-01-02 V\n"
                    "user tty 2026-01-03 I\n"
                ),
                stderr="",
            )

        count = faillock_count(
            "demo",
            binary="/usr/bin/faillock",
            runner=runner,
        )

        self.assertEqual(
            count,
            2,
        )

    def test_below_threshold_no_event(self):
        detector = FaillockDetector(
            counter=lambda user: 2,
            sleeper=lambda seconds: None,
        )

        output = detector.process(
            {
                "event":
                    "ssh_auth_failure",

                "user":
                    "demo",
            }
        )

        self.assertEqual(
            output,
            [],
        )

    def test_threshold_emits_once(self):
        detector = FaillockDetector(
            counter=lambda user: 3,
            sleeper=lambda seconds: None,
        )

        event = {
            "event":
                "ssh_auth_failure",

            "severity":
                "WARNING",

            "user":
                "demo",

            "source_ip":
                "192.0.2.50",
        }

        first = detector.process(
            event
        )

        second = detector.process(
            event
        )

        self.assertEqual(
            len(first),
            1,
        )

        self.assertEqual(
            second,
            [],
        )

        self.assertEqual(
            first[0]["event"],
            "ssh_account_locked",
        )

        self.assertEqual(
            first[0][
                "pam_failure_count"
            ],
            3,
        )

    def test_success_resets_latch(self):
        detector = FaillockDetector(
            counter=lambda user: 4,
            sleeper=lambda seconds: None,
        )

        failure = {
            "event":
                "ssh_auth_failure",

            "user":
                "demo",
        }

        self.assertEqual(
            len(
                detector.process(
                    failure
                )
            ),
            1,
        )

        detector.process(
            {
                "event":
                    "ssh_auth_success",

                "user":
                    "demo",
            }
        )

        self.assertEqual(
            len(
                detector.process(
                    failure
                )
            ),
            1,
        )

    def test_account_locked_policy(self):
        event = apply_policy(
            {
                "event":
                    "ssh_account_locked",

                "severity":
                    "CRITICAL",

                "user":
                    "demo",
            }
        )

        self.assertTrue(
            event["notify"]
        )

        self.assertTrue(
            event["snapshot"]
        )

    def test_account_locked_notification(self):
        notification = (
            render_notification(
                {
                    "event":
                        "ssh_account_locked",

                    "severity":
                        "CRITICAL",

                    "notify":
                        True,

                    "user":
                        "demo",

                    "source_ip":
                        "192.0.2.50",

                    "pam_failure_count":
                        3,
                }
            )
        )

        self.assertEqual(
            notification.title,
            "ARCH GUARD — ACCOUNT LOCKED",
        )

        self.assertIn(
            "Başarısız kayıt: 3",
            notification.body,
        )


if __name__ == "__main__":
    unittest.main()
