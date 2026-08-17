"""DNS-over-HTTPS resolver with certificate validation and pinned bootstrap IPs."""

from __future__ import annotations

import http.client
import ipaddress
import secrets
import socket
import ssl
import struct
import threading
import time
from dataclasses import dataclass
from typing import Protocol

from .policy import normalize_hostname


DNS_TYPE_A = 1
DNS_CLASS_IN = 1
MAX_DNS_MESSAGE = 65_535


class Resolver(Protocol):
    def resolve(self, hostname: str) -> list[str]:
        """Resolve a hostname to validated public IP addresses."""


@dataclass(frozen=True)
class _Provider:
    name: str
    hostname: str
    path: str
    bootstrap_ips: tuple[str, ...]


_PROVIDERS = (
    _Provider(
        "Cloudflare",
        "cloudflare-dns.com",
        "/dns-query",
        ("1.1.1.1", "1.0.0.1"),
    ),
    _Provider(
        "Quad9",
        "dns.quad9.net",
        "/dns-query",
        ("9.9.9.9", "149.112.112.112"),
    ),
)


class DnsError(RuntimeError):
    """Raised when all secure resolvers fail."""


class _BootstrapHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that skips bootstrap DNS but validates the real host."""

    def __init__(
        self,
        hostname: str,
        bootstrap_ip: str,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(hostname, 443, timeout=timeout, context=context)
        self._bootstrap_ip = bootstrap_ip

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self._bootstrap_ip, self.port),
            self.timeout,
            self.source_address,
        )
        raw_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            self.sock = self._context.wrap_socket(
                raw_socket,
                server_hostname=self.host,
            )
        except BaseException:
            raw_socket.close()
            raise


def build_query(hostname: str, transaction_id: int | None = None) -> bytes:
    hostname = normalize_hostname(hostname)
    if transaction_id is None:
        transaction_id = secrets.randbits(16)
    if not 0 <= transaction_id <= 0xFFFF:
        raise ValueError("invalid DNS transaction ID")

    qname = bytearray()
    for label in hostname.split("."):
        encoded = label.encode("ascii")
        qname.append(len(encoded))
        qname.extend(encoded)
    qname.append(0)

    # Recursion desired, one question.
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    return header + bytes(qname) + struct.pack("!HH", DNS_TYPE_A, DNS_CLASS_IN)


def _skip_name(message: bytes, offset: int) -> int:
    labels_seen = 0
    while True:
        if offset >= len(message):
            raise DnsError("truncated DNS name")
        length = message[offset]
        if length & 0xC0 == 0xC0:
            if offset + 2 > len(message):
                raise DnsError("truncated DNS compression pointer")
            return offset + 2
        if length & 0xC0:
            raise DnsError("invalid DNS label")
        offset += 1
        if length == 0:
            return offset
        if length > 63 or offset + length > len(message):
            raise DnsError("invalid DNS label length")
        offset += length
        labels_seen += 1
        if labels_seen > 127:
            raise DnsError("excessive DNS labels")


def parse_a_response(message: bytes, expected_id: int) -> tuple[list[str], int]:
    """Parse public IPv4 answers and return (addresses, minimum TTL)."""

    if len(message) < 12 or len(message) > MAX_DNS_MESSAGE:
        raise DnsError("invalid DNS response size")
    transaction_id, flags, qdcount, ancount, _, _ = struct.unpack(
        "!HHHHHH", message[:12]
    )
    if transaction_id != expected_id:
        raise DnsError("DNS transaction ID mismatch")
    if not flags & 0x8000:
        raise DnsError("DNS response bit is not set")
    if flags & 0x000F:
        raise DnsError(f"DNS resolver returned RCODE {flags & 0x000F}")
    if qdcount != 1:
        raise DnsError("unexpected DNS question count")

    offset = 12
    offset = _skip_name(message, offset)
    if offset + 4 > len(message):
        raise DnsError("truncated DNS question")
    offset += 4

    addresses: list[str] = []
    minimum_ttl: int | None = None
    for _ in range(ancount):
        offset = _skip_name(message, offset)
        if offset + 10 > len(message):
            raise DnsError("truncated DNS answer")
        record_type, record_class, ttl, data_length = struct.unpack(
            "!HHIH", message[offset : offset + 10]
        )
        offset += 10
        data_end = offset + data_length
        if data_end > len(message):
            raise DnsError("truncated DNS answer data")

        if (
            record_type == DNS_TYPE_A
            and record_class == DNS_CLASS_IN
            and data_length == 4
        ):
            address = str(ipaddress.IPv4Address(message[offset:data_end]))
            if ipaddress.ip_address(address).is_global and address not in addresses:
                addresses.append(address)
                minimum_ttl = ttl if minimum_ttl is None else min(minimum_ttl, ttl)
        offset = data_end

    if not addresses:
        raise DnsError("secure DNS returned no public IPv4 address")
    return addresses, minimum_ttl or 60


class DohResolver:
    """Small thread-safe RFC 8484 resolver with a bounded in-memory cache."""

    def __init__(self, timeout: float = 5.0) -> None:
        self._timeout = timeout
        self._context = ssl.create_default_context()
        self._cache: dict[str, tuple[float, list[str]]] = {}
        self._lock = threading.Lock()

    def resolve(self, hostname: str) -> list[str]:
        hostname = normalize_hostname(hostname)
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(hostname)
            if cached is not None and cached[0] > now:
                return list(cached[1])

        failures: list[str] = []
        for provider in _PROVIDERS:
            try:
                addresses, ttl = self._query(provider, hostname)
            except (DnsError, OSError, ssl.SSLError, http.client.HTTPException) as exc:
                failures.append(f"{provider.name}: {exc}")
                continue

            # Avoid stale routing while preventing a query storm.
            cache_seconds = max(30, min(ttl, 600))
            with self._lock:
                self._cache[hostname] = (
                    time.monotonic() + cache_seconds,
                    list(addresses),
                )
                if len(self._cache) > 256:
                    oldest = min(self._cache, key=lambda key: self._cache[key][0])
                    self._cache.pop(oldest, None)
            return addresses

        raise DnsError("; ".join(failures) or "no secure DNS provider configured")

    def _query(self, provider: _Provider, hostname: str) -> tuple[list[str], int]:
        transaction_id = secrets.randbits(16)
        payload = build_query(hostname, transaction_id)
        failures: list[str] = []

        for bootstrap_ip in provider.bootstrap_ips:
            connection = _BootstrapHTTPSConnection(
                provider.hostname,
                bootstrap_ip,
                timeout=self._timeout,
                context=self._context,
            )
            try:
                connection.request(
                    "POST",
                    provider.path,
                    body=payload,
                    headers={
                        "Accept": "application/dns-message",
                        "Content-Type": "application/dns-message",
                        "User-Agent": "DiscordBypass/0.1",
                        "Connection": "close",
                    },
                )
                response = connection.getresponse()
                body = response.read(MAX_DNS_MESSAGE + 1)
                if response.status != 200:
                    raise DnsError(f"HTTP {response.status}")
                if len(body) > MAX_DNS_MESSAGE:
                    raise DnsError("oversized DNS-over-HTTPS response")
                return parse_a_response(body, transaction_id)
            except (DnsError, OSError, ssl.SSLError, http.client.HTTPException) as exc:
                failures.append(f"{bootstrap_ip}: {exc}")
            finally:
                connection.close()

        raise DnsError(", ".join(failures))
