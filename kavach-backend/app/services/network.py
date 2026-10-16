"""Small, bounded HTTP client for inspecting untrusted URLs."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import zlib
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

import aiohttp
import idna


class UnsafeTarget(ValueError):
    """The target could reach a private or unsupported network destination."""


class FetchError(ValueError):
    """The response cannot be inspected within the client's limits."""


@dataclass(frozen=True)
class FetchResult:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    # Includes the submitted URL and every followed redirect, in order.
    redirect_chain: list[str]


_INTERNAL_SUFFIXES = (".localhost", ".local", ".internal", ".home", ".lan", ".onion", ".invalid", ".test")
_TRANSITION_RANGES = tuple(
    ipaddress.ip_network(value)
    for value in (
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "2002::/16",
        "2001::/32",
    )
)


def _public_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise UnsafeTarget("The host resolved to an invalid IP address.") from exc
    if (
        not address.is_global
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
    ):
        raise UnsafeTarget("Private, local, reserved, and non-public addresses cannot be inspected.")
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            _public_address(str(address.ipv4_mapped))
            # Avoid platform-dependent handling of mapped addresses by the connector.
            raise UnsafeTarget("IPv4-mapped IPv6 addresses are not supported.")
        if any(address in network for network in _TRANSITION_RANGES):
            raise UnsafeTarget("IPv6 transition addresses are not supported.")
    return address


def _hostname(value: str) -> str:
    value = value.rstrip(".").lower()
    if not value or "%" in value:
        raise UnsafeTarget("A valid public hostname is required.")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        try:
            value = idna.encode(value, uts46=True, std3_rules=True).decode("ascii")
        except idna.IDNAError as exc:
            raise UnsafeTarget("The hostname is not a valid international domain name.") from exc
        if "." not in value or value.endswith(_INTERNAL_SUFFIXES):
            raise UnsafeTarget("Local and internal hostnames cannot be inspected.")
        return value
    _public_address(str(address))
    return str(address)


def normalize_url(url: str) -> str:
    if not isinstance(url, str) or not url or len(url) > 2048:
        raise UnsafeTarget("Enter an HTTP or HTTPS URL with at most 2048 characters.")
    url = url.strip()
    if not url or any(ord(char) <= 32 or ord(char) == 127 for char in url) or "\\" in url:
        raise UnsafeTarget("URLs may not contain whitespace, control characters, or backslashes.")
    try:
        parts = urlsplit(url)
        port = parts.port
        if parts.scheme.lower() not in {"http", "https"}:
            raise UnsafeTarget("Only HTTP and HTTPS URLs are supported.")
        if parts.username is not None or parts.password is not None:
            raise UnsafeTarget("URLs containing credentials are not supported.")
        if not parts.hostname:
            raise UnsafeTarget("The URL must include a hostname.")
        host = _hostname(parts.hostname)
        if port is not None and port not in {80, 443}:
            raise UnsafeTarget("Only ports 80 and 443 may be inspected.")
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, UnsafeTarget):
            raise
        raise UnsafeTarget("The URL is malformed.") from exc
    authority = f"[{host}]" if ":" in host else host
    if port is not None:
        authority += f":{port}"
    return urlunsplit((parts.scheme.lower(), authority, parts.path or "/", parts.query, ""))


async def resolve_public_host(hostname: str) -> list[str]:
    hostname = _hostname(hostname)
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        records = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(
                hostname,
                None,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            ),
            timeout=3,
        )
        addresses = list(dict.fromkeys(str(_public_address(record[4][0])) for record in records))
        if not addresses:
            raise OSError("The hostname has no public address records.")
        return addresses
    return [str(_public_address(str(address)))]


class _PinnedResolver(aiohttp.abc.AbstractResolver):
    def __init__(self, hostname: str, addresses: list[str]):
        self.hostname = hostname
        self.addresses = addresses

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET):
        if host.lower().rstrip(".") != self.hostname:
            raise UnsafeTarget("Unexpected hostname in HTTP connection.")
        return [
            {
                "hostname": host,
                "host": address,
                "port": port,
                "family": socket.AF_INET6 if ":" in address else socket.AF_INET,
                "proto": socket.IPPROTO_TCP,
                "flags": socket.AI_NUMERICHOST,
            }
            for address in self.addresses
        ]

    async def close(self):
        return None


async def _read_prefix(response: aiohttp.ClientResponse, max_bytes: int) -> bytes:
    encoding = response.headers.get("Content-Encoding", "identity").lower().strip()
    if encoding in {"", "identity"}:
        decoder = None
    elif encoding in {"gzip", "x-gzip"}:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif encoding == "deflate":
        decoder = zlib.decompressobj()
    else:
        raise FetchError("Unsupported response compression.")
    body = bytearray()
    raw_bytes = 0
    async for chunk in response.content.iter_chunked(16384):
        raw_bytes += len(chunk)
        remaining = max_bytes - len(body)
        try:
            decoded = decoder.decompress(chunk, remaining + 1) if decoder else chunk
        except zlib.error as exc:
            raise FetchError("Invalid compressed response.") from exc
        body.extend(decoded[:remaining])
        if len(decoded) > remaining or len(body) >= max_bytes or raw_bytes >= max_bytes:
            break
    return bytes(body)


async def safe_fetch(
    url: str,
    *,
    method: str = "GET",
    max_redirects: int = 4,
    max_bytes: int = 262144,
    timeout: float = 8,
) -> FetchResult:
    """Fetch a bounded body prefix, revalidating and pinning each redirect's DNS."""
    current = normalize_url(url)
    method = method.upper()
    if method not in {"GET", "HEAD"}:
        raise ValueError("Only GET and HEAD inspection requests are supported.")
    if not 0 <= max_redirects <= 10 or not 1 <= max_bytes <= 2 * 1024 * 1024 or not 0 < timeout <= 30:
        raise ValueError("Invalid HTTP inspection limits.")
    chain: list[str] = []
    async with asyncio.timeout(timeout):
        for hop in range(max_redirects + 1):
            parts = urlsplit(current)
            hostname = parts.hostname or ""
            addresses = await resolve_public_host(hostname)
            connector = aiohttp.TCPConnector(
                resolver=_PinnedResolver(hostname, addresses),
                use_dns_cache=False,
                force_close=True,
                limit=1,
                family=socket.AF_UNSPEC,
            )
            chain.append(current)
            async with aiohttp.ClientSession(
                connector=connector,
                trust_env=False,
                cookie_jar=aiohttp.DummyCookieJar(),
                auto_decompress=False,
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"User-Agent": "Kavach/1.0 (link safety inspection)", "Accept-Encoding": "identity"},
            ) as session:
                async with session.request(method, current, allow_redirects=False) as response:
                    headers = {key.lower(): value for key, value in response.headers.items()}
                    location = response.headers.get("Location")
                    if response.status in {301, 302, 303, 307, 308} and location:
                        target = normalize_url(urljoin(current, location))
                        # Validate even when the redirect limit has been reached.
                        await resolve_public_host(urlsplit(target).hostname or "")
                        if target in chain:
                            raise FetchError("The URL has a redirect loop.")
                        if hop == max_redirects:
                            raise FetchError("The URL exceeded the redirect limit.")
                        current = target
                        continue
                    body = b"" if method == "HEAD" else await _read_prefix(response, max_bytes)
                    return FetchResult(current, response.status, headers, body, chain)
    raise FetchError("No HTTP response was received.")
