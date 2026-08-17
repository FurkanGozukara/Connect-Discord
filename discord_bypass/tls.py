"""Small, strict TLS ClientHello parser used only to choose split points."""

from __future__ import annotations


TLS_RECORD_HEADER_SIZE = 5
MAX_TLS_RECORD_PAYLOAD = 18_432


def _u16(data: bytes, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def _u24(data: bytes, offset: int) -> int:
    return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]


def client_hello_sni(record: bytes) -> tuple[int, str] | None:
    """Return (hostname byte offset, hostname) for a complete ClientHello record.

    This does not decrypt, modify, or retain TLS content. It only locates the
    public SNI extension so the byte stream can be split at that boundary.
    """

    if len(record) < TLS_RECORD_HEADER_SIZE + 4:
        return None
    if record[0] != 0x16 or record[1] != 0x03:
        return None

    record_length = _u16(record, 3)
    if record_length > MAX_TLS_RECORD_PAYLOAD:
        return None
    if len(record) != TLS_RECORD_HEADER_SIZE + record_length:
        return None

    handshake = TLS_RECORD_HEADER_SIZE
    if record[handshake] != 0x01:  # ClientHello
        return None
    handshake_length = _u24(record, handshake + 1)
    handshake_end = handshake + 4 + handshake_length
    if handshake_end > len(record):
        return None

    cursor = handshake + 4
    # legacy_version + random
    if cursor + 34 > handshake_end:
        return None
    cursor += 34

    if cursor + 1 > handshake_end:
        return None
    session_id_length = record[cursor]
    cursor += 1 + session_id_length

    if cursor + 2 > handshake_end:
        return None
    cipher_suites_length = _u16(record, cursor)
    cursor += 2 + cipher_suites_length

    if cursor + 1 > handshake_end:
        return None
    compression_methods_length = record[cursor]
    cursor += 1 + compression_methods_length

    if cursor + 2 > handshake_end:
        return None
    extensions_length = _u16(record, cursor)
    cursor += 2
    extensions_end = cursor + extensions_length
    if extensions_end > handshake_end:
        return None

    while cursor + 4 <= extensions_end:
        extension_type = _u16(record, cursor)
        extension_length = _u16(record, cursor + 2)
        extension_data = cursor + 4
        extension_end = extension_data + extension_length
        if extension_end > extensions_end:
            return None

        if extension_type == 0x0000:  # server_name
            if extension_data + 2 > extension_end:
                return None
            name_list_length = _u16(record, extension_data)
            name_cursor = extension_data + 2
            name_list_end = name_cursor + name_list_length
            if name_list_end > extension_end:
                return None

            while name_cursor + 3 <= name_list_end:
                name_type = record[name_cursor]
                name_length = _u16(record, name_cursor + 1)
                name_offset = name_cursor + 3
                name_end = name_offset + name_length
                if name_end > name_list_end:
                    return None
                if name_type == 0 and name_length:
                    try:
                        hostname = record[name_offset:name_end].decode("ascii")
                    except UnicodeDecodeError:
                        return None
                    return name_offset, hostname.lower()
                name_cursor = name_end

        cursor = extension_end

    return None


def fragmentation_points(record: bytes) -> tuple[list[int], str | None]:
    """Choose conservative TCP split points for the first TLS record."""

    if len(record) <= 2:
        return [], None

    points = {2}  # GoodbyeDPI's established small ClientHello split.
    parsed = client_hello_sni(record)
    hostname: str | None = None
    if parsed is not None:
        sni_offset, hostname = parsed
        if 2 < sni_offset < len(record):
            points.add(sni_offset)
        # Also separate the first hostname byte. This remains ordinary TCP and
        # improves compatibility with DPI devices that inspect segment-local SNI.
        if 2 < sni_offset + 1 < len(record):
            points.add(sni_offset + 1)

    return sorted(points), hostname
