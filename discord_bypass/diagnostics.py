"""End-to-end proxy diagnostic using Python's validating TLS stack."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass


@dataclass(frozen=True)
class DiagnosticResult:
    tls_version: str
    cipher: str
    http_status_line: str


def _read_http_header(sock: socket.socket, maximum: int = 16_384) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("connection closed while reading HTTP header")
        data.extend(chunk)
        if len(data) > maximum:
            raise ConnectionError("oversized HTTP header")
    return bytes(data)


def test_discord_tls(proxy_host: str, proxy_port: int) -> DiagnosticResult:
    """Resolve, CONNECT, split, and validate a real discord.com TLS session."""

    raw_socket = socket.create_connection((proxy_host, proxy_port), timeout=15.0)
    raw_socket.settimeout(15.0)
    try:
        raw_socket.sendall(
            b"CONNECT discord.com:443 HTTP/1.1\r\n"
            b"Host: discord.com:443\r\n"
            b"Proxy-Connection: keep-alive\r\n\r\n"
        )
        response = _read_http_header(raw_socket)
        status_line = response.split(b"\r\n", 1)[0]
        if b" 200 " not in status_line:
            raise ConnectionError(status_line.decode("ascii", errors="replace"))

        context = ssl.create_default_context()
        with context.wrap_socket(raw_socket, server_hostname="discord.com") as tls_socket:
            tls_socket.settimeout(15.0)
            tls_socket.sendall(
                b"HEAD / HTTP/1.1\r\n"
                b"Host: discord.com\r\n"
                b"User-Agent: DiscordBypass-Diagnostic/0.1\r\n"
                b"Connection: close\r\n\r\n"
            )
            first_line = b""
            while not first_line.endswith(b"\r\n") and len(first_line) <= 4096:
                chunk = tls_socket.recv(1)
                if not chunk:
                    break
                first_line += chunk
            cipher = tls_socket.cipher()
            return DiagnosticResult(
                tls_socket.version() or "unknown",
                cipher[0] if cipher else "unknown",
                first_line.strip().decode("ascii", errors="replace"),
            )
    finally:
        # wrap_socket takes ownership on success; closing twice is harmless.
        raw_socket.close()
