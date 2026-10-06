import json
import unittest

from arch_guard.notification_consumer import (
    NotificationConsumer,
)


class FakeBackend:

    available = True

    def __init__(self):
        self.sent = []

    def send(
        self,
        notification,
    ):
        self.sent.append(
            notification
        )
        return True


class NotificationConsumerTests(
    unittest.TestCase
):

    def test_invalid_json_ignored(self):
        consumer = NotificationConsumer(
            backend=FakeBackend()
        )

        self.assertFalse(
            consumer.process_line(
                "not-json"
            )
        )

    def test_notify_false_ignored(self):
        backend = FakeBackend()

        consumer = NotificationConsumer(
            backend=backend
        )

        sent = consumer.process_line(
            json.dumps(
                {
                    "event":
                        "network_probe",

                    "severity":
                        "WARNING",

                    "notify":
                        False,
                }
            )
        )

        self.assertFalse(
            sent
        )

        self.assertEqual(
            backend.sent,
            [],
        )

    def test_notify_true_sent(self):
        backend = FakeBackend()

        consumer = NotificationConsumer(
            backend=backend
        )

        sent = consumer.process_line(
            json.dumps(
                {
                    "event":
                        "ssh_auth_success",

                    "severity":
                        "INFO",

                    "notify":
                        True,

                    "user":
                        "demo",

                    "source_ip":
                        "192.0.2.20",
                }
            )
        )

        self.assertTrue(
            sent
        )

        self.assertEqual(
            len(
                backend.sent
            ),
            1,
        )

        self.assertEqual(
            consumer.notifications_sent,
            1,
        )


if __name__ == "__main__":
    unittest.main()
