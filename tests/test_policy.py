from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from discord_bypass.policy import DomainPolicy, load_domain_suffixes, normalize_hostname


class PolicyTests(unittest.TestCase):
    def test_suffix_boundary_and_requested_discord_app(self) -> None:
        policy = DomainPolicy.defaults()
        self.assertTrue(policy.allows("discord.app"))
        self.assertTrue(policy.allows("api.discord.app"))
        self.assertTrue(policy.allows("gateway.discord.gg"))
        self.assertFalse(policy.allows("discord.app.evil.example"))
        self.assertFalse(policy.allows("notdiscord.app"))
        self.assertFalse(policy.allows("127.0.0.1"))

    def test_expandable_file_accepts_wildcard_notation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "domains.txt"
            path.write_text(
                "# comment\n*.discord.app\n.discord.gg\ndiscord.com # inline\n",
                encoding="utf-8",
            )
            self.assertEqual(
                load_domain_suffixes(path),
                ("discord.app", "discord.gg", "discord.com"),
            )

    def test_invalid_allowlist_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "domains.txt"
            path.write_text("*\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, r"domains\.txt:1"):
                load_domain_suffixes(path)

            path.write_text("com\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "top-level-only"):
                load_domain_suffixes(path)

    def test_pac_is_narrow(self) -> None:
        script = DomainPolicy(("discord.app",)).build_pac_script("127.0.0.1", 9876)
        self.assertIn('dnsDomainIs(host, ".discord.app")', script)
        self.assertIn('return "PROXY 127.0.0.1:9876"', script)
        self.assertIn('return "DIRECT"', script)
        self.assertIn('scheme !== "wss:"', script)
        self.assertNotIn("example.com", script)

    def test_normalization(self) -> None:
        self.assertEqual(normalize_hostname("Gateway.Discord.GG."), "gateway.discord.gg")
        with self.assertRaises(ValueError):
            normalize_hostname("bad..discord.gg")


if __name__ == "__main__":
    unittest.main()
