import unittest

from arch_guard.suricata_policy import (
    apply_suricata_policy,
)


def alert(
    *,
    signature="ET TEST Alert",
    sid=999999,
    severity="HIGH",
    direction="REMOTE_INBOUND",
    profile="default",
    **extra,
):
    event = {
        "event":
            "suricata_alert",

        "severity":
            severity,

        "signature":
            signature,

        "signature_id":
            sid,

        "direction":
            direction,

        "sensor_profile":
            profile,
    }

    event.update(
        extra
    )

    return event


class SuricataPolicyTests(unittest.TestCase):

    def test_remote_high_alert_notifies_and_snapshots(self):
        event = apply_suricata_policy(
            alert()
        )

        self.assertTrue(
            event["notify"]
        )

        self.assertTrue(
            event["snapshot"]
        )

        self.assertFalse(
            event["suppressed"]
        )

    def test_et_info_is_log_only(self):
        event = apply_suricata_policy(
            alert(
                signature="ET INFO Test",
                severity="WARNING",
            )
        )

        self.assertFalse(
            event["notify"]
        )

        self.assertFalse(
            event["snapshot"]
        )

        self.assertEqual(
            event["suppression_reason"],
            "et_info",
        )

    def test_return_stream_noise(self):
        event = apply_suricata_policy(
            alert(
                sid=2210044,
                direction="RETURN_TRAFFIC",
                severity="HIGH",
            )
        )

        self.assertTrue(
            event["suppressed"]
        )

        self.assertFalse(
            event["notify"]
        )

        self.assertFalse(
            event["snapshot"]
        )

    def test_warp_engine_noise(self):
        event = apply_suricata_policy(
            alert(
                sid=2210059,
                profile="warp",
                severity="HIGH",
            )
        )

        self.assertEqual(
            event["suppression_reason"],
            "warp_engine_noise",
        )

        self.assertFalse(
            event["snapshot"]
        )

    def test_tor_return_is_log_only(self):
        event = apply_suricata_policy(
            alert(
                signature=(
                    "ET TOR Known Tor Relay/Router"
                ),
                sid=2522154,
                direction="RETURN_TRAFFIC",
                severity="HIGH",
            )
        )

        self.assertTrue(
            event["suppressed"]
        )

        self.assertFalse(
            event["notify"]
        )

        self.assertFalse(
            event["snapshot"]
        )

        self.assertEqual(
            event["suppression_reason"],
            (
                "tor_locally_initiated_or_return"
            ),
        )

    def test_tor_remote_inbound_is_not_suppressed(self):
        event = apply_suricata_policy(
            alert(
                signature=(
                    "ET TOR Known Tor Relay/Router"
                ),
                sid=2522154,
                direction="REMOTE_INBOUND",
                severity="HIGH",
            )
        )

        self.assertFalse(
            event["suppressed"]
        )

        self.assertTrue(
            event["notify"]
        )

        self.assertTrue(
            event["snapshot"]
        )

    def test_tor_historical_unresolved_is_not_suppressed(self):
        event = apply_suricata_policy(
            alert(
                signature=(
                    "ET TOR Known Tor Relay/Router"
                ),
                sid=2522154,
                direction=(
                    "REMOTE_TO_LOCAL_UNRESOLVED"
                ),
                severity="HIGH",
            )
        )

        self.assertFalse(
            event["suppressed"]
        )

        self.assertTrue(
            event["notify"]
        )

    def test_tailscale_noise_requires_process_evidence(self):
        event = apply_suricata_policy(
            alert(
                signature=(
                    "ET USER_AGENTS Go HTTP Client"
                ),
                direction="SELF_OUTBOUND",
                severity="WARNING",
                tailscale_process_confirmed=True,
            )
        )

        self.assertTrue(
            event["suppressed"]
        )

        event = apply_suricata_policy(
            alert(
                signature=(
                    "ET USER_AGENTS Go HTTP Client"
                ),
                direction="SELF_OUTBOUND",
                severity="WARNING",
                tailscale_process_confirmed=False,
            )
        )

        self.assertFalse(
            event["suppressed"]
        )


if __name__ == "__main__":
    unittest.main()
