import unittest

from types import SimpleNamespace

from arch_guard.runtime import (
    ArchGuardRuntime,
)


class FakeDispatcher:

    def __init__(self):
        self.events = []

    def dispatch(
        self,
        event,
    ):
        self.events.append(
            dict(event)
        )

        return SimpleNamespace(
            logged=True,
            incident_created=(
                event.get("snapshot")
                is True
            ),
            incident_paths=None,
            errors=[],
        )


class RuntimeTests(unittest.TestCase):

    def test_ssh_policy_is_applied(self):
        dispatcher = FakeDispatcher()

        runtime = ArchGuardRuntime(
            dispatcher
        )

        runtime.emit_ssh(
            {
                "event":
                    "ssh_auth_success",

                "severity":
                    "INFO",

                "user":
                    "demo",
            }
        )

        event = dispatcher.events[-1]

        self.assertEqual(
            event["sensor"],
            "ssh",
        )

        self.assertTrue(
            event["notify"]
        )

        self.assertFalse(
            event["snapshot"]
        )

    def test_network_critical_scan_incident(self):
        dispatcher = FakeDispatcher()

        runtime = ArchGuardRuntime(
            dispatcher
        )

        result = runtime.emit_network(
            {
                "event":
                    "network_port_scan",

                "severity":
                    "CRITICAL",

                "source_ip":
                    "192.0.2.50",

                "ports":
                    [22, 80, 443, 8080, 8443, 9000],
            }
        )

        event = dispatcher.events[-1]

        self.assertTrue(
            event["notify"]
        )

        self.assertTrue(
            event["snapshot"]
        )

        self.assertTrue(
            result.incident_created
        )

    def test_suricata_return_tor_is_suppressed(self):
        dispatcher = FakeDispatcher()

        runtime = ArchGuardRuntime(
            dispatcher
        )

        runtime.emit_suricata(
            {
                "event":
                    "suricata_alert",

                "severity":
                    "HIGH",

                "sensor_profile":
                    "default",

                "direction":
                    "RETURN_TRAFFIC",

                "signature_id":
                    2522154,

                "signature":
                    "ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 155",

                "source_ip":
                    "198.51.100.20",

                "destination_ip":
                    "192.0.2.10",
            }
        )

        event = dispatcher.events[-1]

        self.assertTrue(
            event["suppressed"]
        )

        self.assertFalse(
            event["notify"]
        )

        self.assertFalse(
            event["snapshot"]
        )

    def test_suricata_remote_tor_not_suppressed(self):
        dispatcher = FakeDispatcher()

        runtime = ArchGuardRuntime(
            dispatcher
        )

        runtime.emit_suricata(
            {
                "event":
                    "suricata_alert",

                "severity":
                    "HIGH",

                "sensor_profile":
                    "default",

                "direction":
                    "REMOTE_INBOUND",

                "signature_id":
                    2522154,

                "signature":
                    "ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 155",

                "source_ip":
                    "198.51.100.20",

                "destination_ip":
                    "192.0.2.10",
            }
        )

        event = dispatcher.events[-1]

        self.assertFalse(
            event["suppressed"]
        )

        self.assertTrue(
            event["notify"]
        )

        self.assertTrue(
            event["snapshot"]
        )

    def test_generic_emit_routes_sensor(self):
        dispatcher = FakeDispatcher()

        runtime = ArchGuardRuntime(
            dispatcher
        )

        runtime.emit(
            {
                "event":
                    "network_probe",

                "severity":
                    "WARNING",
            },
            sensor="nft",
        )

        event = dispatcher.events[-1]

        self.assertEqual(
            event["sensor"],
            "network",
        )

    def test_runtime_statistics(self):
        dispatcher = FakeDispatcher()

        runtime = ArchGuardRuntime(
            dispatcher
        )

        runtime.emit_ssh(
            {
                "event":
                    "ssh_auth_success",

                "severity":
                    "INFO",
            }
        )

        runtime.emit_network(
            {
                "event":
                    "network_port_scan",

                "severity":
                    "CRITICAL",
            }
        )

        runtime.emit_suricata(
            {
                "event":
                    "suricata_alert",

                "severity":
                    "HIGH",

                "direction":
                    "RETURN_TRAFFIC",

                "signature":
                    "ET TOR TEST",

                "signature_id":
                    123,
            }
        )

        self.assertEqual(
            runtime.stats.received,
            3,
        )

        self.assertEqual(
            runtime.stats.logged,
            3,
        )

        self.assertEqual(
            runtime.stats.incidents,
            1,
        )

        self.assertEqual(
            runtime.stats.dispatch_errors,
            0,
        )

        self.assertEqual(
            runtime.stats.by_sensor,
            {
                "ssh": 1,
                "network": 1,
                "suricata": 1,
            },
        )


if __name__ == "__main__":
    unittest.main()
