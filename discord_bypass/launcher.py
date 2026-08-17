"""Locate and launch the official Discord desktop application."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
from pathlib import Path


_CHANNELS: dict[str, tuple[str, str]] = {
    "stable": ("Discord", "Discord.exe"),
    "ptb": ("DiscordPTB", "DiscordPTB.exe"),
    "canary": ("DiscordCanary", "DiscordCanary.exe"),
}


class DiscordNotFoundError(FileNotFoundError):
    """The selected official Discord channel is not installed."""


_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_SHADOW_SCHEMA_VERSION = 2
_MODULE_DIRECTORY = re.compile(r"^(discord_[a-z0-9_]+)-(\d+)$", re.IGNORECASE)


def _reject_reparse_point(path: Path) -> os.stat_result:
    status = path.stat(follow_symlinks=False)
    if getattr(status, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise OSError(f"reparse points are not allowed in Discord install: {path}")
    return status


def _install_fingerprint(source_root: Path) -> str:
    digest = hashlib.sha256()
    digest.update(str(source_root).casefold().encode("utf-8"))
    for directory, child_directories, filenames in os.walk(source_root):
        child_directories.sort(key=str.casefold)
        filenames.sort(key=str.casefold)
        directory_path = Path(directory)
        _reject_reparse_point(directory_path)
        for filename in filenames:
            source_file = directory_path / filename
            status = _reject_reparse_point(source_file)
            relative = source_file.relative_to(source_root).as_posix()
            digest.update(relative.casefold().encode("utf-8"))
            digest.update(status.st_size.to_bytes(8, "little", signed=False))
            digest.update(status.st_mtime_ns.to_bytes(8, "little", signed=False))

    # Discord's native updater records which installed module versions are
    # active in this database. Include its metadata so a changed selection
    # cannot accidentally reuse an older standalone-module shadow.
    installer_database = source_root.parent / "installer.db"
    if installer_database.is_file():
        status = _reject_reparse_point(installer_database)
        digest.update(b"installer.db")
        digest.update(status.st_size.to_bytes(8, "little", signed=False))
        digest.update(status.st_mtime_ns.to_bytes(8, "little", signed=False))
    return digest.hexdigest()[:16]


def _database_module_versions(
    source_root: Path,
    build_info: dict[str, object],
) -> dict[str, int]:
    """Read Discord's active module mapping without modifying its database."""

    database = source_root.parent / "installer.db"
    release_channel = build_info.get("releaseChannel")
    version_text = build_info.get("version")
    if not database.is_file() or not isinstance(release_channel, str):
        return {}
    _reject_reparse_point(database)
    if not isinstance(version_text, str) or not re.fullmatch(r"\d+(?:\.\d+){2}", version_text):
        return {}

    wanted_host_version = [int(part) for part in version_text.split(".")]
    database_uri = database.resolve().as_uri() + "?mode=ro"
    try:
        connection = sqlite3.connect(database_uri, uri=True, timeout=1.0)
        try:
            rows = connection.execute(
                "SELECT value FROM key_values WHERE key LIKE ?",
                (f"host/app/{release_channel}/win/%",),
            ).fetchall()
        finally:
            connection.close()
    except (OSError, sqlite3.Error):
        return {}

    for (serialized_records,) in rows:
        try:
            records = json.loads(serialized_records)
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, dict) or record.get("install_state") != "Installed":
                continue
            host_version = record.get("host_version")
            if not isinstance(host_version, dict):
                continue
            if host_version.get("version") != wanted_host_version:
                continue

            versions: dict[str, int] = {}
            for module_record in record.get("modules", []):
                if not isinstance(module_record, dict):
                    continue
                if module_record.get("install_state") != "Installed":
                    continue
                module_version = module_record.get("module_version")
                if not isinstance(module_version, dict):
                    continue
                module = module_version.get("module")
                name = module.get("name") if isinstance(module, dict) else None
                version = module_version.get("version")
                if (
                    isinstance(name, str)
                    and re.fullmatch(r"discord_[a-z0-9_]+", name, re.IGNORECASE)
                    and isinstance(version, int)
                    and not isinstance(version, bool)
                    and version >= 0
                ):
                    versions[name.casefold()] = version
            if versions:
                return versions
    return {}


def _active_module_packages(
    source_root: Path,
    build_info: dict[str, object],
) -> dict[str, Path]:
    modules_root = source_root / "modules"
    if not modules_root.is_dir():
        raise OSError(f"Discord module directory was not found: {modules_root}")
    _reject_reparse_point(modules_root)

    discovered: dict[str, dict[int, Path]] = {}
    for version_directory in sorted(modules_root.iterdir(), key=lambda path: path.name.casefold()):
        if not version_directory.is_dir():
            continue
        _reject_reparse_point(version_directory)
        match = _MODULE_DIRECTORY.fullmatch(version_directory.name)
        if match is None:
            continue
        name = match.group(1).casefold()
        version = int(match.group(2))
        package = version_directory / name
        if package.is_dir():
            _reject_reparse_point(package)
            discovered.setdefault(name, {})[version] = package

    selected: dict[str, Path] = {}
    database_versions = _database_module_versions(source_root, build_info)
    if database_versions:
        for name, version in database_versions.items():
            try:
                selected[name] = discovered[name][version]
            except KeyError as exc:
                raise OSError(
                    f"Discord's active module is missing: {name}-{version}"
                ) from exc
    else:
        for name, versions in discovered.items():
            selected[name] = versions[max(versions)]

    if "discord_desktop_core" not in selected:
        raise OSError("Discord's installed discord_desktop_core module was not found")
    return selected


def _copy_module_package(source: Path, target: Path) -> None:
    """Copy one installed package into the writable standalone module view."""

    for directory, child_directories, filenames in os.walk(source):
        child_directories.sort(key=str.casefold)
        filenames.sort(key=str.casefold)
        source_directory = Path(directory)
        _reject_reparse_point(source_directory)
        relative_directory = source_directory.relative_to(source)
        target_directory = target / relative_directory
        target_directory.mkdir(parents=True, exist_ok=True)
        for filename in filenames:
            source_file = source_directory / filename
            _reject_reparse_point(source_file)
            shutil.copy2(source_file, target_directory / filename, follow_symlinks=False)


def _remove_temporary_shadow(path: Path, shadow_root: Path) -> None:
    resolved_path = path.resolve(strict=False)
    resolved_root = shadow_root.resolve(strict=False)
    if resolved_path.parent != resolved_root or ".tmp-" not in resolved_path.name:
        raise RuntimeError(f"refusing unsafe shadow cleanup: {resolved_path}")
    if resolved_path.exists():
        shutil.rmtree(resolved_path)


def prepare_shadow_discord(executable: Path) -> Path:
    """Create an updater-disabled hard-link view without altering Discord.

    Electron reads ``resources/build_info.json`` before starting its native
    updater. Official host files are hard-linked into a private cache. The
    installed module packages are also copied into Discord's supported
    standalone layout so the application can load without either updater.
    """

    source_executable = executable.resolve(strict=True)
    source_root = source_executable.parent
    _reject_reparse_point(source_root)
    build_info_source = source_root / "resources" / "build_info.json"
    _reject_reparse_point(build_info_source)
    try:
        build_info = json.loads(build_info_source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OSError(f"could not read Discord build metadata: {build_info_source}") from exc
    if not isinstance(build_info, dict):
        raise OSError(f"invalid Discord build metadata: {build_info_source}")
    active_modules = _active_module_packages(source_root, build_info)

    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise OSError("LOCALAPPDATA is not defined")
    cache_root = Path(local_app_data).resolve() / "DiscordBypass" / "shadow"
    channel_root = cache_root / source_root.parent.name
    if source_root.drive.casefold() != channel_root.drive.casefold():
        raise OSError("Discord shadow must be on the same volume for hard links")

    fingerprint = _install_fingerprint(source_root)
    target_root = channel_root / (
        f"{source_root.name}-s{_SHADOW_SCHEMA_VERSION}-{fingerprint}"
    )
    target_executable = target_root / source_executable.name
    ready_marker = target_root / ".discord-bypass-ready.json"
    if target_executable.is_file() and ready_marker.is_file():
        return target_executable
    if target_root.exists():
        raise OSError(f"incomplete Discord shadow exists: {target_root}")

    channel_root.mkdir(parents=True, exist_ok=True)
    temporary_root = channel_root / (
        target_root.name + f".tmp-{os.getpid()}-{secrets.token_hex(4)}"
    )
    temporary_root.mkdir()

    try:
        for directory, child_directories, filenames in os.walk(source_root):
            child_directories.sort(key=str.casefold)
            filenames.sort(key=str.casefold)
            source_directory = Path(directory)
            _reject_reparse_point(source_directory)
            relative_directory = source_directory.relative_to(source_root)
            target_directory = temporary_root / relative_directory
            target_directory.mkdir(parents=True, exist_ok=True)

            for filename in filenames:
                source_file = source_directory / filename
                _reject_reparse_point(source_file)
                relative_file = source_file.relative_to(source_root)
                target_file = temporary_root / relative_file
                if relative_file.as_posix().casefold() == "resources/build_info.json":
                    shadow_build_info = dict(build_info)
                    shadow_build_info["disableUpdater"] = True
                    shadow_build_info["standaloneModules"] = True
                    shadow_build_info["debug"] = True
                    target_file.write_text(
                        json.dumps(shadow_build_info, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8",
                    )
                else:
                    os.link(source_file, target_file, follow_symlinks=False)

        standalone_root = temporary_root / "resources" / "standalone_modules"
        standalone_root.mkdir()
        for module_name, module_source in sorted(active_modules.items()):
            _copy_module_package(module_source, standalone_root / module_name)

        (temporary_root / ".discord-bypass-ready.json").write_text(
            json.dumps(
                {
                    "schema": _SHADOW_SCHEMA_VERSION,
                    "source": str(source_root),
                    "fingerprint": fingerprint,
                    "disableUpdater": True,
                    "standaloneModules": sorted(active_modules),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        try:
            temporary_root.rename(target_root)
        except FileExistsError:
            if not (target_executable.is_file() and ready_marker.is_file()):
                raise
            _remove_temporary_shadow(temporary_root, channel_root)
        return target_executable
    except BaseException:
        _remove_temporary_shadow(temporary_root, channel_root)
        raise


def _version_key(path: Path) -> tuple[int, ...]:
    numbers = re.findall(r"\d+", path.name)
    return tuple(int(number) for number in numbers) or (0,)


def find_discord(channel: str = "stable") -> Path:
    try:
        folder_name, executable_name = _CHANNELS[channel]
    except KeyError as exc:
        raise ValueError(f"unknown Discord channel: {channel}") from exc

    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise DiscordNotFoundError("LOCALAPPDATA is not defined")
    root = Path(local_app_data) / folder_name
    if not root.is_dir():
        raise DiscordNotFoundError(f"Discord folder not found: {root}")

    candidates = [
        child / executable_name
        for child in root.glob("app-*")
        if child.is_dir() and (child / executable_name).is_file()
    ]
    if not candidates:
        raise DiscordNotFoundError(f"{executable_name} was not found below {root}")
    return max(candidates, key=lambda path: _version_key(path.parent))


def is_discord_running(channel: str = "stable") -> bool:
    _, executable_name = _CHANNELS[channel]
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    result = subprocess.run(
        ["tasklist.exe", "/FI", f"IMAGENAME eq {executable_name}", "/FO", "CSV", "/NH"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=creation_flags,
    )
    for row in csv.reader(io.StringIO(result.stdout)):
        if row and row[0].casefold() == executable_name.casefold():
            return True
    return False


def stop_discord(channel: str = "stable") -> None:
    """Stop Discord only when the caller explicitly requested a restart."""

    _, executable_name = _CHANNELS[channel]
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    subprocess.run(
        ["taskkill.exe", "/IM", executable_name, "/T"],
        check=False,
        capture_output=True,
        creationflags=creation_flags,
    )


def launch_discord(
    pac_url: str,
    *,
    channel: str = "stable",
) -> subprocess.Popen[bytes]:
    if not re.fullmatch(r"http://127\.0\.0\.1:\d{1,5}/proxy\.pac", pac_url):
        raise ValueError("PAC URL must use the local DiscordBypass endpoint")
    executable = prepare_shadow_discord(find_discord(channel))
    arguments = [
        str(executable),
        f"--proxy-pac-url={pac_url}",
        "--disable-quic",
    ]
    creation_flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    return subprocess.Popen(
        arguments,
        cwd=str(executable.parent),
        close_fds=True,
        creationflags=creation_flags,
    )
