# Contributing

Contributions are welcome. Keep changes narrow, auditable, and compatible with
Windows 10/11 and Python 3.10 or newer.

Before opening a pull request, run:

```powershell
.\run_python.cmd -m unittest discover -s tests -v
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_package.ps1
```

Please preserve the project's core trust boundaries:

- loopback-only listeners;
- Discord-domain allowlisting and port 443 enforcement;
- end-to-end TLS without certificate injection or decryption;
- no drivers, services, firewall rules, registry persistence, or system proxy;
- no bundled third-party binaries; and
- no collection of credentials, tokens, message contents, or telemetry.

Add or update tests for behavior changes. Explain any proposed domain additions
and any effect on the runtime trust boundary in the pull request.
