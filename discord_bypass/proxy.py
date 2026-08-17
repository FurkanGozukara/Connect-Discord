"""Loopback-only PAC and HTTP CONNECT proxy."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import socket
from collections.abc import Awaitable

from .dns import Resolver
from .policy import DomainPolicy, normalize_hostname
from .tls import MAX_TLS_RECORD_PAYLOAD, fragmentation_points


LOGGER = logging.getLogger(__name__)
MAX_HEADER_SIZE = 16_384
COPY_BUFFER_SIZE = 65_536


class ProxyProtocolError(ValueError):
    """A malformed or disallowed local proxy request."""


def parse_connect_target(
    target: str,
    policy: DomainPolicy | None = None,
) -> tuple[str, int]:
    """Parse and validate a CONNECT authority."""

    if not target or target.startswith("["):
        raise ProxyProtocolError("IP literals are not allowed")
    hostname, separator, port_text = target.rpartition(":")
    if not separator or not hostname or not port_text.isdecimal():
        raise ProxyProtocolError("CONNECT must use hostname:port")
    port = int(port_text)
    if port != 443:
        raise ProxyProtocolError("only HTTPS port 443 is allowed")
    hostname = normalize_hostname(hostname)
    if policy is None:
        policy = DomainPolicy.defaults()
    if not policy.allows(hostname):
        raise ProxyProtocolError("destination is outside the Discord allowlist")
    return hostname, port


async def _close_writer(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    while True:
        chunk = await reader.read(COPY_BUFFER_SIZE)
        if not chunk:
            return
        writer.write(chunk)
        await writer.drain()


class ProxyServer:
    """A local proxy that can only reach allowlisted Discord HTTPS hosts."""

    def __init__(
        self,
        resolver: Resolver,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        split_delay_seconds: float = 0.012,
        max_connections: int = 256,
        connect_port_override: int | None = None,
        allow_private_upstream: bool = False,
        policy: DomainPolicy | None = None,
    ) -> None:
        if host != "127.0.0.1":
            raise ValueError("proxy must bind only to IPv4 loopback")
        if not 0 <= port <= 65535:
            raise ValueError("invalid listen port")
        if not 0 <= split_delay_seconds <= 0.25:
            raise ValueError("invalid split delay")

        self._resolver = resolver
        self.host = host
        self.port = port
        self._split_delay = split_delay_seconds
        self._semaphore = asyncio.Semaphore(max_connections)
        self._server: asyncio.AbstractServer | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._connect_port_override = connect_port_override
        self._allow_private_upstream = allow_private_upstream
        self._policy = policy or DomainPolicy.defaults()

    @property
    def pac_url(self) -> str:
        if not self.port:
            raise RuntimeError("proxy has not started")
        return f"http://{self.host}:{self.port}/proxy.pac"

    async def start(self) -> None:
        if self._server is not None:
            raise RuntimeError("proxy is already running")
        self._server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
            limit=MAX_HEADER_SIZE * 2,
            start_serving=True,
        )
        sockets = self._server.sockets or []
        if len(sockets) != 1:
            await self.stop()
            raise RuntimeError("unexpected number of listen sockets")
        self.port = int(sockets[0].getsockname()[1])
        LOGGER.info("local proxy listening at %s:%d", self.host, self.port)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)

        try:
            async with self._semaphore:
                await self._serve_request(reader, writer)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # Keep one client from terminating the proxy.
            LOGGER.debug("client connection ended: %s", exc)
        finally:
            await _close_writer(writer)
            if task is not None:
                self._tasks.discard(task)

    async def _read_header(self, reader: asyncio.StreamReader) -> bytes:
        try:
            header = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=7.0
            )
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
            raise ProxyProtocolError("incomplete or oversized HTTP header") from exc
        if len(header) > MAX_HEADER_SIZE:
            raise ProxyProtocolError("HTTP header is too large")
        return header

    async def _serve_request(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername")
        if not peer or not ipaddress.ip_address(peer[0]).is_loopback:
            raise ProxyProtocolError("non-loopback client rejected")

        client_socket = writer.get_extra_info("socket")
        if client_socket is not None:
            client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        header = await self._read_header(reader)
        try:
            first_line = header.split(b"\r\n", 1)[0].decode("ascii")
        except UnicodeDecodeError as exc:
            await self._send_error(writer, 400, "Bad Request")
            raise ProxyProtocolError("non-ASCII request line") from exc

        parts = first_line.split(" ")
        if len(parts) != 3 or parts[2] not in ("HTTP/1.0", "HTTP/1.1"):
            await self._send_error(writer, 400, "Bad Request")
            raise ProxyProtocolError("invalid request line")
        method, target, _ = parts

        if method == "GET" and target.split("?", 1)[0] == "/proxy.pac":
            await self._serve_pac(writer)
            return
        if method != "CONNECT":
            await self._send_error(writer, 405, "Method Not Allowed")
            raise ProxyProtocolError("only PAC GET and CONNECT are supported")

        try:
            hostname, port = parse_connect_target(target, self._policy)
        except ProxyProtocolError:
            await self._send_error(writer, 403, "Forbidden")
            raise

        remote_reader: asyncio.StreamReader | None = None
        remote_writer: asyncio.StreamWriter | None = None
        try:
            addresses = await asyncio.wait_for(
                asyncio.to_thread(self._resolver.resolve, hostname), timeout=12.0
            )
            remote_reader, remote_writer, remote_address = await self._connect_remote(
                addresses,
                self._connect_port_override or port,
            )
        except Exception as exc:
            await self._send_error(writer, 502, "Bad Gateway")
            LOGGER.warning("%s: secure connection failed: %s", hostname, exc)
            return

        try:
            writer.write(
                b"HTTP/1.1 200 Connection Established\r\n"
                b"Proxy-Agent: DiscordBypass\r\n\r\n"
            )
            await writer.drain()

            sni, split_count = await self._forward_first_record(
                reader,
                remote_writer,
                hostname,
            )
            LOGGER.info(
                "%s -> %s (SNI=%s, %d TCP splits)",
                hostname,
                remote_address,
                sni or "not visible",
                split_count,
            )

            relay_tasks = (
                asyncio.create_task(_pipe(reader, remote_writer)),
                asyncio.create_task(_pipe(remote_reader, writer)),
            )
            try:
                _done, pending = await asyncio.wait(
                    relay_tasks, return_when=asyncio.FIRST_COMPLETED
                )
                for pending_task in pending:
                    pending_task.cancel()
            finally:
                # The parent connection task can itself be cancelled while it
                # is waiting (for example, when --diagnose exits). Always own,
                # cancel, and retrieve both relay results before returning.
                for relay_task in relay_tasks:
                    if not relay_task.done():
                        relay_task.cancel()
                await asyncio.gather(*relay_tasks, return_exceptions=True)
        finally:
            await _close_writer(remote_writer)

    async def _connect_remote(
        self,
        addresses: list[str],
        port: int,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
        failures: list[str] = []
        for address in addresses:
            parsed = ipaddress.ip_address(address)
            if not self._allow_private_upstream and not parsed.is_global:
                failures.append(f"{address}: non-public address rejected")
                continue
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(address, port), timeout=5.0
                )
                remote_socket = writer.get_extra_info("socket")
                if remote_socket is not None:
                    remote_socket.setsockopt(
                        socket.IPPROTO_TCP, socket.TCP_NODELAY, 1
                    )
                return reader, writer, address
            except (OSError, asyncio.TimeoutError) as exc:
                failures.append(f"{address}: {exc}")
        raise OSError("; ".join(failures) or "resolver returned no addresses")

    async def _forward_first_record(
        self,
        client_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
        connect_hostname: str,
    ) -> tuple[str | None, int]:
        header = await asyncio.wait_for(client_reader.readexactly(5), timeout=10.0)
        if header[0] != 0x16 or header[1] != 0x03:
            remote_writer.write(header)
            await remote_writer.drain()
            return None, 0

        payload_length = (header[3] << 8) | header[4]
        if payload_length > MAX_TLS_RECORD_PAYLOAD:
            raise ProxyProtocolError("oversized TLS record")
        payload = await asyncio.wait_for(
            client_reader.readexactly(payload_length), timeout=10.0
        )
        record = header + payload
        points, sni = fragmentation_points(record)

        if sni is not None and not self._policy.allows(sni):
            raise ProxyProtocolError("TLS SNI is outside the Discord allowlist")

        start = 0
        for point in points:
            remote_writer.write(record[start:point])
            await remote_writer.drain()
            if self._split_delay:
                await asyncio.sleep(self._split_delay)
            start = point
        remote_writer.write(record[start:])
        await remote_writer.drain()
        return sni, len(points)

    async def _serve_pac(self, writer: asyncio.StreamWriter) -> None:
        body = self._policy.build_pac_script(self.host, self.port).encode("utf-8")
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/x-ns-proxy-autoconfig\r\n"
            b"Cache-Control: no-store, max-age=0\r\n"
            b"X-Content-Type-Options: nosniff\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Connection: close\r\n\r\n"
            + body
        )
        writer.write(response)
        await writer.drain()

    @staticmethod
    async def _send_error(
        writer: asyncio.StreamWriter,
        status: int,
        reason: str,
    ) -> None:
        body = f"{status} {reason}\n".encode("ascii")
        writer.write(
            f"HTTP/1.1 {status} {reason}\r\n".encode("ascii")
            + b"Content-Type: text/plain; charset=us-ascii\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Connection: close\r\n\r\n"
            + body
        )
        await writer.drain()
