# Upstream source audit

Review date: 2026-08-15

This is a focused static review for the design and packaging decisions in
DiscordBypass. It is not a formal proof of security. Exact revisions are pinned
in [`UPSTREAMS.lock`](UPSTREAMS.lock).

## WinDivert

Inspected revision: `97101072dbe31d744ca3429da389350a3df39e18`

- The repository contains the user-mode `WinDivert.dll` source and the
  kernel-mode `WinDivert.sys` Windows Filtering Platform driver source.
- Its MSVC build script explicitly builds the driver with `SignMode=Off`.
- GoodbyeDPI needs this driver to capture, modify, and reinject system packets.
- A local source build therefore produces an unsigned kernel driver. Normal
  Windows 10/11 driver-signing policy will not load it without weakening boot
  security or obtaining a Microsoft-accepted production signature.
- Static searches found no downloader, shell-spawn, persistence, telemetry, or
  remote-control path in the tracked WinDivert source reviewed. The expected
  privileged behavior is packet interception and driver installation.

Decision: do not compile, package, install, or load WinDivert. This avoids both
an unverifiable prebuilt driver and unsafe test-signing instructions.

## GoodbyeDPI

Inspected revision: `f593a276f9ec753889f80208c6a7c5cf455df94a`

- The tracked runtime is C source plus a resource file; its documented external
  dependency is WinDivert.
- Relevant techniques are a small HTTPS ClientHello split (default size 2), an
  optional split at the visible TLS SNI boundary, host allowlisting, QUIC
  blocking, and optional DNS redirection.
- It also implements packet-level fake TTL/checksum/sequence and reverse-order
  techniques. Those require packet interception and were intentionally not
  reproduced in a local application proxy.
- Static searches found no source path that downloads or executes remote code,
  collects user data, mines cryptocurrency, or installs unrelated persistence.
  Service installation is an explicit documented operating mode.

Decision: independently implement only the standards-compatible TCP stream
splits and hostname scoping in Python. No GoodbyeDPI source file is imported,
linked, or shipped.

## GoodbyeDPI-Turkey

Inspected revision: `8500f689bf45777b1529b50d76f04665ddd1ffac`

- The tracked repository contains an Apache-2.0 GoodbyeDPI-derived C source
  snapshot and Turkish usage/recovery documentation.
- Its guidance emphasizes DNS interference in Turkey, administrator execution,
  WinDivert-based system-wide operation, and multiple ISP-specific presets in
  release packages.
- The repository README now points users with Discord reliability problems to a
  broader SplitWire tool. That tool's documented methods add multiple external
  executables, services, tunnels, or DLL-based injection, which conflicts with
  this project's source-only and minimal-change requirements.
- Static searches of the tracked source found no downloader or telemetry path.

Decision: solve DNS poisoning locally with certificate-validated
DNS-over-HTTPS and keep the proxy scoped to editable Discord suffixes.

## Resulting trust boundary

The shipped ZIP contains readable `.py`, `.bat`, `.cmd`, `.ps1`, `.md`, and text
files only. It has no third-party executable, DLL, SYS, PYD, PYC, driver, or
embedded certificate. Python and Windows remain the only local runtime trust
dependencies. If Python 3.10+ is absent, the launcher can fetch a pinned CPython
embeddable archive from `python.org` and verifies the Python Software
Foundation's published SHA-256 before extraction. Cloudflare and Quad9 are
external encrypted DNS resolvers; Discord remains the end-to-end TLS peer.
