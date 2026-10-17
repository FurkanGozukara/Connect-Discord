# Third-party notices

The Git repository and generated source package contain no third-party
executable, DLL, kernel driver, or Python package. They use only readable
project source and Windows system components.

When Python 3.10 or newer is not already available, `start_discord.bat` can
download the official CPython 3.14.7 Windows embeddable package directly from
`python.org`. `bootstrap_python.ps1` pins and verifies the Python Software
Foundation's published SHA-256 value before extraction. The private runtime is
stored below `.runtime`, is not committed or included in the source package,
and includes CPython's own `LICENSE.txt`. No package manager or system-wide
Python installation is used.

The following source repositories were inspected as design references. Their
code is not copied, linked, imported, or shipped in the runtime package:

- WinDivert, commit `97101072dbe31d744ca3429da389350a3df39e18`, dual
  licensed LGPL-3.0-or-later or GPL-2.0.
- GoodbyeDPI, commit `f593a276f9ec753889f80208c6a7c5cf455df94a`,
  Apache-2.0. Its HTTPS fragmentation, SNI-boundary split, host allowlisting,
  and QUIC-disable concepts informed this independent Python implementation.
- GoodbyeDPI-Turkey, commit
  `8500f689bf45777b1529b50d76f04665ddd1ffac`, Apache-2.0. Its Turkey-specific
  DNS-blocking guidance informed the use of encrypted DNS-over-HTTPS.
- ByeDPI, commit `ba532298de7b28cfe854aea83d061369d13ca290`, MIT.
  Its urgent-data documentation informed the independently implemented
  `tcp-oob` strategy. No ByeDPI source is copied or shipped.

At runtime, DNS queries for allowlisted destinations go first to Cloudflare's
DNS-over-HTTPS endpoint and fall back to Quad9. TLS certificates are validated,
and bootstrap connections use their documented resolver IPs. No system DNS
setting is changed.

Discord is a trademark of Discord Inc. This project is independent and is not
affiliated with or endorsed by Discord Inc.
