import unittest

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PackagingTests(
    unittest.TestCase
):

    def read(
        self,
        relative,
    ):
        return (
            ROOT
            .joinpath(relative)
            .read_text(
                encoding="utf-8"
            )
        )

    def test_system_service_uses_packaged_cli(self):
        text = self.read(
            "packaging/systemd/"
            "arch-guard.service"
        )

        self.assertIn(
            "ExecStart=/usr/bin/arch-guard run",
            text,
        )

        self.assertNotIn(
            "/usr/local/",
            text,
        )

    def test_user_notifier_service(self):
        text = self.read(
            "packaging/systemd/"
            "arch-guard-notify.service"
        )

        self.assertIn(
            "ExecStart=/usr/bin/arch-guard notify",
            text,
        )

    def test_nft_sensor_is_passive(self):
        text = self.read(
            "packaging/nftables/"
            "arch-guard.nft"
        )

        self.assertIn(
            'log prefix "AGNET "',
            text,
        )

        rule_text = "\n".join(
            line
            for line in text.lower().splitlines()
            if not line.lstrip().startswith("#")
        )

        forbidden_verdicts = (
            "drop",
            "reject",
            "redirect",
        )

        tokens = (
            rule_text
            .replace(";", " ")
            .replace("{", " ")
            .replace("}", " ")
            .split()
        )

        for verdict in forbidden_verdicts:
            self.assertNotIn(
                verdict,
                tokens,
            )

    def test_nft_has_no_interface_hardcode(self):
        text = self.read(
            "packaging/nftables/"
            "arch-guard.nft"
        )

        for private_value in (
            "wlo1",
            "CloudflareWARP",
            "192.168.",
        ):
            self.assertNotIn(
                private_value,
                text,
            )

    def test_sysusers_group(self):
        text = self.read(
            "packaging/sysusers/"
            "arch-guard.conf"
        )

        self.assertEqual(
            text.strip(),
            "g arch-guard - -",
        )

    def test_pkgbuild_installs_units(self):
        text = self.read(
            "packaging/arch/PKGBUILD"
        )

        self.assertIn(
            "/usr/lib/systemd/system/"
            "arch-guard.service",
            text,
        )

        self.assertIn(
            "/usr/lib/systemd/user/"
            "arch-guard-notify.service",
            text,
        )

        self.assertIn(
            "backup=(",
            text,
        )

    def test_license_present(self):
        text = self.read(
            "LICENSE"
        )

        self.assertTrue(
            text.startswith(
                "MIT License"
            )
        )


if __name__ == "__main__":
    unittest.main()
