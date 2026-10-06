import unittest

from arch_guard.events import make_event
from arch_guard.policy import apply_policy


class IncidentPolicyTests(unittest.TestCase):

    def test_successful_ssh_is_not_incident(self):
        event = apply_policy(
            make_event(
                "ssh_auth_success",
                "INFO",
            )
        )

        self.assertTrue(
            event["notify"]
        )

        self.assertFalse(
            event["snapshot"]
        )

    def test_high_bruteforce_notifies_without_snapshot(self):
        event = apply_policy(
            make_event(
                "ssh_bruteforce",
                "HIGH",
            )
        )

        self.assertTrue(
            event["notify"]
        )

        self.assertFalse(
            event["snapshot"]
        )

    def test_critical_bruteforce_creates_snapshot(self):
        event = apply_policy(
            make_event(
                "ssh_bruteforce",
                "CRITICAL",
            )
        )

        self.assertTrue(
            event["notify"]
        )

        self.assertTrue(
            event["snapshot"]
        )

    def test_network_scan_creates_snapshot(self):
        event = apply_policy(
            make_event(
                "network_port_scan",
                "CRITICAL",
            )
        )

        self.assertTrue(
            event["notify"]
        )

        self.assertTrue(
            event["snapshot"]
        )

    def test_raw_probe_is_log_only(self):
        event = apply_policy(
            make_event(
                "network_probe",
                "WARNING",
            )
        )

        self.assertFalse(
            event["notify"]
        )

        self.assertFalse(
            event["snapshot"]
        )

    def test_success_after_failures_high(self):
        event = apply_policy(
            make_event(
                "ssh_success_after_failures",
                "HIGH",
            )
        )

        self.assertTrue(
            event["notify"]
        )

        self.assertFalse(
            event["snapshot"]
        )


if __name__ == "__main__":
    unittest.main()
