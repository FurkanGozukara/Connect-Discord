from __future__ import annotations

import unittest

from discord_bypass.tls import client_hello_sni, fragmentation_points
from tests.helpers import make_client_hello


class TlsTests(unittest.TestCase):
    def test_extracts_sni_and_places_splits(self) -> None:
        record = make_client_hello("gateway.discord.gg")
        parsed = client_hello_sni(record)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        offset, hostname = parsed
        self.assertEqual(hostname, "gateway.discord.gg")
        self.assertEqual(record[offset : offset + len(hostname)], hostname.encode("ascii"))

        points, fragmented_hostname = fragmentation_points(record)
        self.assertEqual(fragmented_hostname, hostname)
        self.assertEqual(points, [2, offset, offset + 1])

    def test_malformed_lengths_are_rejected(self) -> None:
        record = bytearray(make_client_hello())
        record[3:5] = b"\xff\xff"
        self.assertIsNone(client_hello_sni(bytes(record)))

    def test_non_tls_data_gets_no_sni(self) -> None:
        points, hostname = fragmentation_points(b"GET / HTTP/1.1")
        self.assertEqual(points, [2])
        self.assertIsNone(hostname)


if __name__ == "__main__":
    unittest.main()
