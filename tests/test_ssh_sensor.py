import unittest

from arch_guard.sensors.ssh import parse_sshd_message


class SSHSensorTests(unittest.TestCase):

    def test_success(self):
        event = parse_sshd_message(
            "Accepted publickey for test "
            "from 127.0.0.1 port 52100 ssh2"
        )

        self.assertIsNotNone(event)
        self.assertEqual(
            event["event"],
            "ssh_auth_success",
        )
        self.assertEqual(
            event["user"],
            "test",
        )
        self.assertEqual(
            event["auth_method"],
            "publickey",
        )
        self.assertEqual(
            event["ssh_source_port"],
            52100,
        )

    def test_failure(self):
        event = parse_sshd_message(
            "Failed password for test "
            "from 192.0.2.10 port 40001 ssh2"
        )

        self.assertIsNotNone(event)
        self.assertEqual(
            event["event"],
            "ssh_auth_failure",
        )

    def test_invalid_user(self):
        event = parse_sshd_message(
            "Invalid user root2 from 192.0.2.20 port 45000"
        )

        self.assertIsNotNone(event)
        self.assertEqual(
            event["event"],
            "ssh_invalid_user",
        )
        self.assertEqual(
            event["user"],
            "root2",
        )

    def test_session_open(self):
        event = parse_sshd_message(
            "pam_unix(sshd:session): session opened "
            "for user test(uid=1000)"
        )

        self.assertIsNotNone(event)
        self.assertEqual(
            event["event"],
            "ssh_session_open",
        )

    def test_session_closed(self):
        event = parse_sshd_message(
            "pam_unix(sshd:session): session closed "
            "for user test"
        )

        self.assertIsNotNone(event)
        self.assertEqual(
            event["event"],
            "ssh_session_closed",
        )

    def test_systemd_stop_is_ignored(self):
        event = parse_sshd_message(
            "Stopped OpenSSH Daemon."
        )

        self.assertIsNone(event)

    def test_irrelevant_line(self):
        self.assertIsNone(
            parse_sshd_message(
                "Completely unrelated journal message"
            )
        )


if __name__ == "__main__":
    unittest.main()
