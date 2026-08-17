"""Destination policy and proxy auto-configuration generation."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path


# Keep this list deliberately narrow. Subdomains are included automatically.
# The first three names are also present in the locally installed Discord app.
DEFAULT_DISCORD_DOMAIN_SUFFIXES: tuple[str, ...] = (
    "discord.com",
    "discord.gg",
    "discord.app",
    "discordapp.com",
    "discordapp.net",
    "discordcdn.com",
    "discord.media",
    "discord.dev",
    "discord.new",
    "discord.co",
    "discordactivities.com",
    "discordsays.com",
    "dis.gd",
)


def normalize_hostname(hostname: str) -> str:
    """Return a canonical ASCII hostname or raise ValueError."""

    hostname = hostname.strip().rstrip(".").lower()
    if not hostname or len(hostname) > 253 or "\x00" in hostname:
        raise ValueError("invalid hostname")

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("IP literals are not allowed")

    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid internationalized hostname") from exc

    labels = hostname.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or any(not (ch.isalnum() or ch == "-") for ch in label)
        for label in labels
    ):
        raise ValueError("invalid hostname label")
    return hostname


def _normalize_suffix(value: str) -> str:
    value = value.strip()
    if value.startswith("*."):
        value = value[2:]
    elif value.startswith("."):
        value = value[1:]
    suffix = normalize_hostname(value)
    if "." not in suffix:
        raise ValueError("top-level-only suffixes are not allowed")
    return suffix


def load_domain_suffixes(path: Path) -> tuple[str, ...]:
    """Load a validated, de-duplicated suffix list from a UTF-8 text file."""

    suffixes: list[str] = []
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8-sig").splitlines(), start=1
    ):
        value = raw_line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            suffix = _normalize_suffix(value)
        except ValueError as exc:
            raise ValueError(f"{path}:{line_number}: {exc}") from exc
        if suffix not in suffixes:
            suffixes.append(suffix)
    if not suffixes:
        raise ValueError(f"{path}: domain list is empty")
    return tuple(suffixes)


@dataclass(frozen=True)
class DomainPolicy:
    """Immutable hostname allowlist shared by PAC and CONNECT validation."""

    suffixes: tuple[str, ...]

    @classmethod
    def defaults(cls) -> "DomainPolicy":
        return cls(DEFAULT_DISCORD_DOMAIN_SUFFIXES)

    @classmethod
    def from_file(cls, path: Path) -> "DomainPolicy":
        return cls(load_domain_suffixes(path))

    def allows(self, hostname: str) -> bool:
        try:
            normalized = normalize_hostname(hostname)
        except ValueError:
            return False
        return any(
            normalized == suffix or normalized.endswith("." + suffix)
            for suffix in self.suffixes
        )

    def build_pac_script(self, proxy_host: str, proxy_port: int) -> str:
        return _build_pac_script(proxy_host, proxy_port, self.suffixes)


def is_discord_hostname(hostname: str) -> bool:
    """Compatibility helper using the built-in default policy."""

    return DomainPolicy.defaults().allows(hostname)


def build_pac_script(proxy_host: str, proxy_port: int) -> str:
    """Compatibility helper using the built-in default policy."""

    return DomainPolicy.defaults().build_pac_script(proxy_host, proxy_port)


def _build_pac_script(
    proxy_host: str,
    proxy_port: int,
    suffixes: tuple[str, ...],
) -> str:
    """Build a PAC file for allowlisted HTTPS and secure WebSocket traffic."""

    if proxy_host != "127.0.0.1":
        raise ValueError("the PAC proxy must stay on IPv4 loopback")
    if not 1 <= proxy_port <= 65535:
        raise ValueError("invalid proxy port")

    checks: list[str] = []
    for suffix in suffixes:
        checks.append(
            f'(host === "{suffix}" || dnsDomainIs(host, ".{suffix}"))'
        )

    condition = " ||\n      ".join(checks)
    return (
        "// Generated locally by DiscordBypass. No remote PAC is used.\n"
        "function FindProxyForURL(url, host) {\n"
        "  host = host.toLowerCase();\n"
        "  var scheme = url.substring(0, url.indexOf(\":\") + 1).toLowerCase();\n"
        "  if (scheme !== \"https:\" && scheme !== \"wss:\") {\n"
        "    return \"DIRECT\";\n"
        "  }\n"
        f"  if ({condition}) {{\n"
        f'    return "PROXY {proxy_host}:{proxy_port}";\n'
        "  }\n"
        "  return \"DIRECT\";\n"
        "}\n"
    )
