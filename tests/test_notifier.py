import unittest

from types import SimpleNamespace

from arch_guard.notifier import (
    NotifySendBackend,
    render_notification,
)


class NotifierTests(unittest.TestCase):

    def test_notify_false_is_ignored(self):
        self.assertIsNone(
            render_notification(
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

    def test_severity_timeouts(self):
        expected = {
            "INFO": 4,
            "WARNING": 6,
            "HIGH": 8,
            "CRITICAL": 10,
        }

        for severity, timeout in expected.items():
            event = {
                "event":
                    "test_event",

                "severity":
                    severity,

                "notify":
                    True,
            }

            notification = render_notification(
                event
            )

            self.assertEqual(
                notification.timeout_seconds,
                timeout,
            )

    def test_network_remote_mac_text(self):
        notification = render_notification(
            {
                "event":
                    "network_port_scan",

                "severity":
                    "CRITICAL",

                "notify":
                    True,

                "source_ip":
                    "198.51.100.20",

                "source_mac":
                    None,

                "ports":
                    [22, 80, 443],

                "unique_ports":
                    3,

                "window_seconds":
                    10,

                "transport":
                    "WLAN",
            }
        )

        self.assertIn(
            "N/A (remote host)",
            notification.body,
        )

    def test_suricata_return_title(self):
        notification = render_notification(
            {
                "event":
                    "suricata_alert",

                "severity":
                    "HIGH",

                "notify":
                    True,

                "direction":
                    "RETURN_TRAFFIC",

                "signature":
                    "ET TEST",

                "signature_id":
                    123,

                "source_ip":
                    "198.51.100.20",

                "source_port":
                    443,

                "destination_ip":
                    "192.0.2.10",

                "destination_port":
                    55000,

                "protocol":
                    "TCP",
            }
        )

        self.assertEqual(
            notification.title,
            "ARCH GUARD — RETURN TRAFFIC IDS",
        )

    def test_backend_reuses_notification_id(self):
        calls = []

        def runner(
            command,
            **kwargs,
        ):
            calls.append(
                list(command)
            )

            return SimpleNamespace(
                returncode=0,
                stdout="42\n",
                stderr="",
            )

        backend = NotifySendBackend(
            binary="/usr/bin/notify-send",
            runner=runner,
        )

        notification = render_notification(
            {
                "event":
                    "ssh_auth_success",

                "severity":
                    "INFO",

                "notify":
                    True,

                "user":
                    "test",

                "source_ip":
                    "192.0.2.10",
            }
        )

        self.assertTrue(
            backend.send(
                notification
            )
        )

        self.assertTrue(
            backend.send(
                notification
            )
        )

        self.assertEqual(
            backend.notification_id,
            42,
        )

        self.assertNotIn(
            "-r",
            calls[0],
        )

        self.assertIn(
            "-r",
            calls[1],
        )

        index = calls[1].index(
            "-r"
        )

        self.assertEqual(
            calls[1][index + 1],
            "42",
        )

    def test_bruteforce_render(self):
        notification = render_notification(
            {
                "event":
                    "ssh_bruteforce",

                "severity":
                    "CRITICAL",

                "notify":
                    True,

                "source_ip":
                    "192.0.2.50",

                "failure_count":
                    5,

                "window_seconds":
                    60,

                "attempted_users":
                    ["admin", "root"],
            }
        )

        self.assertIn(
            "BRUTE FORCE CRITICAL",
            notification.title,
        )

        self.assertIn(
            "Deneme: 5 / 60 sn",
            notification.body,
        )


if __name__ == "__main__":
    unittest.main()
