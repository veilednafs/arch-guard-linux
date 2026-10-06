import tempfile
import unittest

from pathlib import Path

from arch_guard.config import load_config


class ConfigTests(unittest.TestCase):

    def test_default_values(self):
        cfg = load_config(
            Path("/tmp/arch-guard-does-not-exist.toml")
        )

        self.assertTrue(cfg.ssh.enabled)
        self.assertEqual(
            cfg.ssh.high_threshold,
            3,
        )

        self.assertEqual(
            cfg.network.port_scan_threshold,
            6,
        )

    def test_custom_config(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "config.toml"

            path.write_text(
                """
[ssh]
high_threshold = 4

[network]
""",
                encoding="utf-8",
            )

            cfg = load_config(path)

            self.assertEqual(
                cfg.ssh.high_threshold,
                4,
            )



if __name__ == "__main__":
    unittest.main()


class TailscaleConfigTests(unittest.TestCase):

    def test_tailscale_scan_defaults(self):
        from arch_guard.config import Config

        cfg = Config()

        self.assertFalse(
            cfg.tailscale_scan.enabled
        )

        self.assertEqual(
            cfg.tailscale_scan.window,
            10,
        )

        self.assertEqual(
            cfg.tailscale_scan.threshold,
            25,
        )

        self.assertEqual(
            cfg.tailscale_scan.cooldown,
            60,
        )

    def test_network_has_no_dead_interfaces_option(self):
        from arch_guard.config import NetworkConfig

        cfg = NetworkConfig()

        self.assertFalse(
            hasattr(
                cfg,
                "interfaces",
            )
        )
