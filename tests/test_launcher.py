from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from discord_bypass.launcher import launch_discord, prepare_shadow_discord, stop_discord


class LauncherTests(unittest.TestCase):
    def test_creates_hardlinked_host_and_standalone_module_shadow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Discord" / "app-1.2.3"
            (source / "resources").mkdir(parents=True)
            package = (
                source
                / "modules"
                / "discord_desktop_core-7"
                / "discord_desktop_core"
            )
            package.mkdir(parents=True)
            executable = source / "Discord.exe"
            executable.write_bytes(b"official executable")
            module = package / "module.node"
            module.write_bytes(b"official module")
            build_info = source / "resources" / "build_info.json"
            build_info.write_text(
                '{"releaseChannel":"stable","version":"1.2.3"}',
                encoding="utf-8",
            )

            with patch.dict(os.environ, {"LOCALAPPDATA": str(root / "Local")}, clear=False):
                shadow_executable = prepare_shadow_discord(executable)
                second_result = prepare_shadow_discord(executable)

            self.assertEqual(second_result, shadow_executable)
            shadow_root = shadow_executable.parent
            shadow_info = json.loads(
                (shadow_root / "resources" / "build_info.json").read_text(encoding="utf-8")
            )
            original_info = json.loads(build_info.read_text(encoding="utf-8"))
            self.assertTrue(shadow_info["disableUpdater"])
            self.assertTrue(shadow_info["standaloneModules"])
            self.assertTrue(shadow_info["debug"])
            self.assertNotIn("disableUpdater", original_info)
            self.assertEqual(
                os.stat(executable).st_ino,
                os.stat(shadow_executable).st_ino,
            )
            self.assertEqual(
                os.stat(module).st_ino,
                os.stat(
                    shadow_root
                    / "modules"
                    / "discord_desktop_core-7"
                    / "discord_desktop_core"
                    / "module.node"
                ).st_ino,
            )
            standalone_module = (
                shadow_root
                / "resources"
                / "standalone_modules"
                / "discord_desktop_core"
                / "module.node"
            )
            self.assertEqual(standalone_module.read_bytes(), b"official module")
            self.assertNotEqual(os.stat(module).st_ino, os.stat(standalone_module).st_ino)

    def test_uses_active_module_version_from_installer_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Discord" / "app-1.2.3"
            (source / "resources").mkdir(parents=True)
            executable = source / "Discord.exe"
            executable.write_bytes(b"official executable")
            (source / "resources" / "build_info.json").write_text(
                '{"releaseChannel":"stable","version":"1.2.3"}',
                encoding="utf-8",
            )
            for version in (1, 2):
                package = (
                    source
                    / "modules"
                    / f"discord_desktop_core-{version}"
                    / "discord_desktop_core"
                )
                package.mkdir(parents=True)
                (package / "version.txt").write_text(str(version), encoding="ascii")

            database = source.parent / "installer.db"
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "CREATE TABLE key_values (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO key_values VALUES (?, ?)",
                    (
                        "host/app/stable/win/x64",
                        json.dumps(
                            [
                                {
                                    "host_version": {"version": [1, 2, 3]},
                                    "install_state": "Installed",
                                    "modules": [
                                        {
                                            "module_version": {
                                                "module": {"name": "discord_desktop_core"},
                                                "version": 1,
                                            },
                                            "install_state": "Installed",
                                        }
                                    ],
                                }
                            ]
                        ),
                    ),
                )
                connection.commit()
            finally:
                connection.close()

            with patch.dict(os.environ, {"LOCALAPPDATA": str(root / "Local")}, clear=False):
                shadow = prepare_shadow_discord(executable).parent

            selected = (
                shadow
                / "resources"
                / "standalone_modules"
                / "discord_desktop_core"
                / "version.txt"
            )
            self.assertEqual(selected.read_text(encoding="ascii"), "1")

    def test_launches_shadow_with_local_pac(self) -> None:
        executable = Path("C:/fake/Discord.exe")
        shadow = Path("C:/fake-shadow/Discord.exe")
        with patch("discord_bypass.launcher.find_discord", return_value=executable), patch(
            "discord_bypass.launcher.prepare_shadow_discord", return_value=shadow
        ), patch("discord_bypass.launcher.subprocess.Popen") as popen:
            launch_discord("http://127.0.0.1:54321/proxy.pac")
        self.assertEqual(popen.call_args.args[0][0], str(shadow))
        self.assertIn("--proxy-pac-url=http://127.0.0.1:54321/proxy.pac", popen.call_args.args[0])

    def test_external_pac_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "local DiscordBypass"):
            launch_discord("https://example.com/proxy.pac")

    def test_explicit_restart_force_stops_the_discord_process_tree(self) -> None:
        with patch("discord_bypass.launcher.subprocess.run") as run:
            stop_discord()

        arguments = run.call_args.args[0]
        self.assertEqual(arguments[:3], ["taskkill.exe", "/IM", "Discord.exe"])
        self.assertIn("/T", arguments)
        self.assertIn("/F", arguments)


if __name__ == "__main__":
    unittest.main()
