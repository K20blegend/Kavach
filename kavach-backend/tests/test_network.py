import gzip
import socket

import pytest

from app.services import network


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/file",
        "https://user:password@example.com/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.1/",
        "https://example.com:8080/",
        "https://localhost/",
        "https://api.internal/",
        "https://example.com\\@127.0.0.1/",
        "https://example.com/\r\nHeader:value",
        "https://[64:ff9b::7f00:1]/",
        "https://[ff02::1]/",
        "https://example.com/" + "x" * 2048,
    ],
)
def test_rejects_unsupported_or_private_targets(url):
    with pytest.raises(network.UnsafeTarget):
        network.normalize_url(url)


def test_normalizes_idna_and_discards_fragment():
    assert network.normalize_url("HTTPS://Café.COM/login#token") == "https://xn--caf-dma.com/login"


@pytest.mark.asyncio
async def test_rejects_mixed_public_and_private_dns_answers(monkeypatch):
    async def getaddrinfo(*args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
        ]

    monkeypatch.setattr(network.asyncio.get_running_loop(), "getaddrinfo", getaddrinfo)
    with pytest.raises(network.UnsafeTarget):
        await network.resolve_public_host("example.com")


class Content:
    def __init__(self, chunks):
        self.chunks = chunks

    async def iter_chunked(self, size):
        for chunk in self.chunks:
            yield chunk


class Response:
    def __init__(self, status=200, headers=None, body=b"ok"):
        self.status = status
        self.headers = headers or {}
        self.content = Content([body])

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


def fake_http(monkeypatch, responses):
    state = {"connectors": [], "sessions": [], "requests": []}

    def connector(**kwargs):
        state["connectors"].append(kwargs)
        return kwargs

    class Session:
        def __init__(self, **kwargs):
            state["sessions"].append(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        def request(self, method, url, **kwargs):
            state["requests"].append((method, url, kwargs))
            return responses.pop(0)

    monkeypatch.setattr(network.aiohttp, "TCPConnector", connector)
    monkeypatch.setattr(network.aiohttp, "ClientSession", Session)
    return state


@pytest.mark.asyncio
async def test_redirects_use_new_pinned_resolution_and_no_ambient_state(monkeypatch):
    calls = []

    async def resolve(host):
        calls.append(host)
        return ["93.184.216.34"]

    monkeypatch.setattr(network, "resolve_public_host", resolve)
    state = fake_http(monkeypatch, [Response(302, {"Location": "https://other.com/final"}), Response()])
    result = await network.safe_fetch("https://example.com/")
    assert result.redirect_chain == ["https://example.com/", "https://other.com/final"]
    assert result.body == b"ok"
    assert calls == ["example.com", "other.com", "other.com"]
    for session in state["sessions"]:
        assert session["trust_env"] is False
        assert session["auto_decompress"] is False
        assert isinstance(session["cookie_jar"], network.aiohttp.DummyCookieJar)
    resolver = state["connectors"][1]["resolver"]
    pinned = await resolver.resolve("other.com", 443)
    assert pinned[0]["host"] == "93.184.216.34"
    with pytest.raises(network.UnsafeTarget):
        await resolver.resolve("unrelated.com", 443)


@pytest.mark.asyncio
async def test_redirect_into_private_network_is_blocked_before_request(monkeypatch):
    async def resolve(host):
        return ["93.184.216.34"]

    monkeypatch.setattr(network, "resolve_public_host", resolve)
    state = fake_http(monkeypatch, [Response(302, {"Location": "http://169.254.169.254/latest/meta-data"})])
    with pytest.raises(network.UnsafeTarget):
        await network.safe_fetch("https://example.com/")
    assert len(state["requests"]) == 1


@pytest.mark.asyncio
async def test_redirect_rebinding_to_private_address_is_rejected(monkeypatch):
    async def resolve(host):
        if host == "other.com":
            raise network.UnsafeTarget("Private address")
        return ["93.184.216.34"]

    monkeypatch.setattr(network, "resolve_public_host", resolve)
    state = fake_http(monkeypatch, [Response(302, {"Location": "https://other.com/"})])
    with pytest.raises(network.UnsafeTarget):
        await network.safe_fetch("https://example.com/")
    assert len(state["requests"]) == 1


@pytest.mark.asyncio
async def test_decompression_is_bounded_even_for_small_compressed_bomb():
    compressed = gzip.compress(b"A" * 1_000_000)
    response = Response(headers={"Content-Encoding": "gzip"}, body=compressed)
    assert await network._read_prefix(response, 128) == b"A" * 128


@pytest.mark.asyncio
async def test_plain_response_is_bounded():
    assert await network._read_prefix(Response(body=b"x" * 10000), 97) == b"x" * 97


@pytest.mark.asyncio
async def test_redirect_limit_applies_before_another_http_request(monkeypatch):
    async def resolve(host):
        return ["93.184.216.34"]

    monkeypatch.setattr(network, "resolve_public_host", resolve)
    state = fake_http(monkeypatch, [Response(302, {"Location": "/next"})])
    with pytest.raises(network.FetchError, match="redirect limit"):
        await network.safe_fetch("https://example.com/", max_redirects=0)
    assert len(state["requests"]) == 1
