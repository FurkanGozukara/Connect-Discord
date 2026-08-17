# Connect Discord

[![Tests](https://github.com/FurkanGozukara/Connect-Discord/actions/workflows/tests.yml/badge.svg)](https://github.com/FurkanGozukara/Connect-Discord/actions/workflows/tests.yml)

Connect Discord (`DiscordBypass`) is a source-distributed, zero-package-
dependency launcher for the official Discord desktop app on Windows. It runs a
loopback-only HTTP CONNECT proxy, securely resolves an allowlist of Discord
hosts, splits the first TLS ClientHello into ordinary TCP segments, and starts
Discord with a local proxy auto-configuration (PAC) URL.

It applies the useful TLS-splitting idea behind GoodbyeDPI without installing
WinDivert or any other kernel driver. Nothing is decrypted, and no remote proxy
or VPN is used.

## Clone and run

Requirements:

- Windows 10 or 11
- The official Discord desktop application already installed
- Internet access on the first run

```powershell
git clone https://github.com/FurkanGozukara/Connect-Discord.git
cd Connect-Discord
.\start_discord.bat
```

You can also download GitHub's source ZIP, extract it, and double-click
`start_discord.bat`. Keep its console window open while using Discord.

There is no manual dependency setup. The launcher uses an existing Python 3.10+
installation when available. Otherwise, it downloads the official CPython
3.14.7 embeddable runtime from `python.org`, verifies its pinned SHA-256 hash,
and keeps it privately in `.runtime\python`. It does not install Python
system-wide or use a package manager. The download is about 12 MB and happens
only once.

For a live DNS, proxy, TLS, and certificate check, double-click `diagnose.cmd`.
It must report `Diagnostic PASSED`.

`start_discord.bat` intentionally restarts an already-running Discord process
so its per-process PAC flag takes effect. It does not modify Discord's installed
files. The first Discord launch creates a private module cache and can take a
few seconds; later launches reuse it.

## Optional shortcut installation

Run this from the cloned or extracted directory:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
```

The installer copies the readable source to
`%LOCALAPPDATA%\Programs\DiscordBypass` and creates Start Menu and desktop
shortcuts. It needs no administrator permission. If Python is absent, the first
shortcut launch prepares the same verified private runtime inside that install
directory.

## What it changes

Nothing system-wide. The program:

- listens only on a random `127.0.0.1` port;
- serves a local PAC file;
- proxies only allowlisted HTTPS and secure WebSocket (`wss://`) destinations;
- accepts only `CONNECT` to allowlisted hostnames on TCP port 443;
- obtains public IPv4 answers over certificate-validated DNS-over-HTTPS;
- launches the installed official Discord executable with `--proxy-pac-url`
  and `--disable-quic`;
- creates a private per-user view of the installed official Discord host files;
- selects active installed modules from Discord's read-only `installer.db` and
  copies them into Discord's supported standalone-module layout;
- disables host and module update checks only in that private view, so neither
  updater can bypass the PAC during startup; and
- keeps Discord's TLS encryption end to end.

It does **not** install a service, driver, certificate, firewall rule, DNS
setting, registry entry, browser extension, or system proxy. It does not ask
for administrator rights, inspect message contents, save tokens, or write
connection logs to disk.

The private Discord view is stored below
`%LOCALAPPDATA%\DiscordBypass\shadow`. Hard links keep the official signed host
EXE/DLL bytes unchanged and consume no second copy of their file data. Active
modules are copied (about 150 MB for a typical installation) because Discord
may write module data in standalone mode; this prevents writes from reaching
the official installation. The official Discord installation and profile
settings are never edited.

This Git repository and its generated source ZIP contain no third-party EXE,
DLL, driver, or other binary. Runtime module copies come only from the user's
official Discord installation. The optional private Python runtime is fetched
directly from the Python Software Foundation and verified before execution.

## Expand the domain list

Edit [`domains.txt`](domains.txt). One suffix is accepted per line:

```text
discord.app
.discord.app
*.discord.app
```

All three forms allow the bare name and its subdomains. Blank lines, inline
comments, and full-line `#` comments are supported. Entries are normalized and
validated at startup; invalid lines stop startup with a precise filename and
line number.

Keep the list narrow. Every added suffix becomes eligible for the local proxy,
although the proxy still permits HTTPS port 443 only and rejects IP literals,
private resolver answers, and SNI names outside the same list.

## Useful commands

`run_python.cmd` uses the same existing-or-private Python selection as the main
launcher:

```powershell
# Run the live check without launching Discord
.\run_python.cmd -m discord_bypass --diagnose --no-launch --verbose

# Run the proxy without launching Discord
.\run_python.cmd -m discord_bypass --no-launch

# Use Discord PTB
.\start_discord.bat --channel ptb

# Use a fixed local port or a custom allowlist
.\start_discord.bat --port 8877 --domains-file .\my-domains.txt

# Run all offline tests
.\run_python.cmd -m unittest discover -s tests -v
```

The default 12 ms split delay can be tuned with `--split-delay-ms`. Larger
values may help unusually aggressive DPI but add connection setup latency.

## Build and verify the source package

Source-package builds require Python 3.10+ already available and use only
Windows PowerShell plus Python's standard library:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_package.ps1
```

The script runs the complete offline test suite, builds
`dist\DiscordBypass-source.zip`, creates an internal `MANIFEST.sha256`, and
writes the archive hash beside the ZIP. The build itself never downloads code
or invokes a package manager.

## Uninstall

For a shortcut installation, use its Start Menu uninstall shortcut or run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  "$env:LOCALAPPDATA\Programs\DiscordBypass\uninstall.ps1"
```

For a clone or extracted ZIP, stop the launcher and delete the directory. This
also removes its optional `.runtime` folder. There are no system settings to
restore.

## Limits

- This is DPI evasion, not anonymity. Discord and your ISP still see normal
  connection metadata and your public IP address.
- The PAC covers Discord HTTPS hostnames. Voice/video normally uses direct UDP;
  if an ISP blocks Discord IP ranges or UDP itself, a local TCP splitter cannot
  repair that path.
- Discord must be launched through this tool. An instance started normally does
  not inherit the PAC setting.
- Cloudflare DNS-over-HTTPS is tried first and Quad9 is the fallback. These
  providers can observe the allowlisted DNS queries sent to them.
- ISP behavior changes. If the diagnostic succeeds but the desktop client does
  not, run with `--verbose` and check whether a required hostname is absent from
  `domains.txt`.

The design findings are in [`UPSTREAM_AUDIT.md`](UPSTREAM_AUDIT.md), exact
reference revisions are in [`UPSTREAMS.lock`](UPSTREAMS.lock), and runtime trust
details are in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
