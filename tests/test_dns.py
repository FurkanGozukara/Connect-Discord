from __future__ import annotations

import ipaddress
import struct
import unittest

from discord_bypass.dns import DnsError, build_query, parse_a_response


def _response(address: str, transaction_id: int = 0x1234) -> bytes:
    query = build_query("discord.com", transaction_id)
    header = struct.pack("!HHHHHH", transaction_id, 0x8180, 1, 1, 0, 0)
    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 120, 4)
        + ipaddress.IPv4Address(address).packed
    )
    return header + query[12:] + answer


class DnsTests(unittest.TestCase):
    def test_query_and_public_answer(self) -> None:
        query = build_query("discord.com", 0x1234)
        self.assertEqual(query[:2], b"\x12\x34")
        addresses, ttl = parse_a_response(_response("162.159.135.232"), 0x1234)
        self.assertEqual(addresses, ["162.159.135.232"])
        self.assertEqual(ttl, 120)

    def test_private_answer_is_rejected(self) -> None:
        with self.assertRaisesRegex(DnsError, "no public"):
            parse_a_response(_response("127.0.0.1"), 0x1234)

    def test_transaction_id_must_match(self) -> None:
        with self.assertRaisesRegex(DnsError, "ID mismatch"):
            parse_a_response(_response("162.159.135.232"), 0x9999)


if __name__ == "__main__":
    unittest.main()
