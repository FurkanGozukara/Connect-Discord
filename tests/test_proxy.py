from __future__ import annotations

import asyncio
import unittest

from discord_bypass.policy import DomainPolicy
from discord_bypass.proxy import ProxyProtocolError, ProxyServer, parse_connect_target
from tests.helpers import make_client_hello


class _StaticResolver:
    def resolve(self, hostname: str) -> list[str]:
        if hostname != "discord.com":
            raise OSError("unexpected test hostname")
        return ["127.0.0.1"]


class ProxyTests(unittest.IsolatedAsyncioTestCase):
    def test_connect_policy(self) -> None:
        policy = DomainPolicy(("discord.app",))
        self.assertEqual(
            parse_connect_target("api.discord.app:443", policy),
            ("api.discord.app", 443),
        )
        with self.assertRaises(ProxyProtocolError):
            parse_connect_target("example.com:443", policy)
        with self.assertRaises(ProxyProtocolError):
            parse_connect_target("discord.app:80", policy)

    async def test_pac_and_end_to_end_forwarding(self) -> None:
        await self._check_pac_and_end_to_end_forwarding("tcp")

    async def test_urgent_split_preserves_the_upstream_tls_stream(self) -> None:
        await self._check_pac_and_end_to_end_forwarding("tcp-oob")

    async def _check_pac_and_end_to_end_forwarding(self, split_mode: str) -> None:
        expected = make_client_hello("discord.com")
        received: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

        async def upstream(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            try:
                data = await reader.readexactly(len(expected))
                if not received.done():
                    received.set_result(data)
                writer.write(b"OK")
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        upstream_server = await asyncio.start_server(upstream, "127.0.0.1", 0)
        upstream_port = upstream_server.sockets[0].getsockname()[1]
        proxy = ProxyServer(
            _StaticResolver(),
            split_delay_seconds=0,
            split_mode=split_mode,
            connect_port_override=upstream_port,
            allow_private_upstream=True,
            policy=DomainPolicy(("discord.com", "discord.app")),
        )
        await proxy.start()
        try:
            pac_reader, pac_writer = await asyncio.open_connection(proxy.host, proxy.port)
            pac_writer.write(
                b"GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
            )
            await pac_writer.drain()
            pac_response = await pac_reader.read()
            self.assertIn(b"200 OK", pac_response)
            self.assertIn(b".discord.app", pac_response)
            pac_writer.close()
            await pac_writer.wait_closed()

            reader, writer = await asyncio.open_connection(proxy.host, proxy.port)
            writer.write(
                b"CONNECT discord.com:443 HTTP/1.1\r\n"
                b"Host: discord.com:443\r\n\r\n"
            )
            await writer.drain()
            response = await reader.readuntil(b"\r\n\r\n")
            self.assertIn(b"200 Connection Established", response)

            writer.write(expected)
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(received, timeout=2), expected)
            self.assertEqual(await asyncio.wait_for(reader.readexactly(2), timeout=2), b"OK")
            writer.close()
            await writer.wait_closed()
        finally:
            await proxy.stop()
            upstream_server.close()
            await upstream_server.wait_closed()


if __name__ == "__main__":
    unittest.main()
