from __future__ import annotations

import struct


def make_client_hello(hostname: str = "discord.com") -> bytes:
    host = hostname.encode("ascii")
    server_name = b"\x00" + struct.pack("!H", len(host)) + host
    server_name_list = struct.pack("!H", len(server_name)) + server_name
    sni_extension = b"\x00\x00" + struct.pack("!H", len(server_name_list)) + server_name_list

    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"  # session ID length
        + b"\x00\x02\x13\x01"  # one TLS 1.3 cipher suite
        + b"\x01\x00"  # one null compression method
        + struct.pack("!H", len(sni_extension))
        + sni_extension
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
