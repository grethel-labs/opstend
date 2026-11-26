import hashlib
import hmac
import json
import socket

import pytest

from steward.adapters import notifications as n


@pytest.fixture(params=["webhook", "discord"])
def adapter(request):
    if request.param == "discord":
        return n.DiscordWebhook("https://discord.com/api/webhooks/123/abc")
    return n.SignedWebhook("https://example.com/events", "s" * 32)


def test_contract_confirmed_delivery(adapter, monkeypatch):
    monkeypatch.setattr(n, "post", lambda *a: (200, {}, b'{"id":"123"}'))
    assert adapter.version == 1
    assert adapter.send("key", {"summary": "hello"}).confirmed


@pytest.mark.parametrize(
    "status, error, permanent",
    [
        (429, "rate_limited", False),
        (503, "unavailable", False),
        (401, "rejected", True),
        (302, "rejected", True),
    ],
)
def test_contract_failure(adapter, monkeypatch, status, error, permanent):
    monkeypatch.setattr(n, "post", lambda *a: (status, {"retry-after": "3"}, b"{}"))
    result = adapter.send("key", {"summary": "hello"})
    assert not result.confirmed and result.error_class == error and result.permanent == permanent
    if status == 429:
        assert result.retry_after_s == 3


def test_contract_network_failure_hides_credentials(adapter, monkeypatch):
    def broken(*args):
        raise OSError("secret endpoint")

    monkeypatch.setattr(n, "post", broken)
    result = adapter.send("k", {"summary": "hello"})
    assert result.error_class == "unavailable" and "secret" not in repr(result)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/x",
        "https://user:pass@example.com/",
        "https://example.com:8443/",
        "https://example.com/#x",
        "https://example.com/\r\nX:bad",
        "https://example.com\\@localhost/",
    ],
)
def test_unsafe_url_rejected(url):
    with pytest.raises(n.UnsafeTarget):
        n.target(url)


@pytest.mark.parametrize(
    "ip",
    ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "fc00::1", "::ffff:127.0.0.1", "0.0.0.0"],
)
def test_private_dns_rejected_including_mixed_answers(ip, monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **kw: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)),
        ],
    )
    with pytest.raises(n.UnsafeTarget):
        n.public_addresses("example.com")


def test_connection_pins_checked_ip_and_verifies_hostname(monkeypatch):
    seen = []

    class Context:
        def wrap_socket(self, raw, *, server_hostname):
            seen.append(server_hostname)
            return raw

    monkeypatch.setattr(n.ssl, "create_default_context", Context)
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout: seen.append(addr))
    connection = n._PinnedHTTPS("example.com", "1.1.1.1")
    connection.connect()
    assert seen == [("1.1.1.1", 443), "example.com"]


def test_signature_binds_timestamp_id_and_exact_body(monkeypatch):
    monkeypatch.setattr(n.time, "time", lambda: 123)
    adapter = n.SignedWebhook("https://example.com/", "s" * 32)
    body, headers = adapter._request("event:1", {"summary": "hello"})
    expected = hmac.new(b"s" * 32, b"123." + body, hashlib.sha256).hexdigest()
    assert headers["X-Steward-Signature"] == "v1=" + expected
    assert headers["X-Steward-Timestamp"] == "123"
    assert json.loads(body)["id"] == "event:1"


def test_discord_mentions_limits_and_acknowledgment(monkeypatch):
    adapter = n.DiscordWebhook("https://discord.com/api/webhooks/123/abc")
    body, _ = adapter._request("key", {"summary": "@everyone"})
    assert json.loads(body)["allowed_mentions"] == {"parse": []}
    assert adapter.url.endswith("?wait=true")
    assert adapter.send("k", {"summary": "x" * 2001}).permanent
    monkeypatch.setattr(n, "post", lambda *a: (204, {}, b"{}"))
    assert not adapter.send("k", {"summary": "hello"}).confirmed


@pytest.mark.parametrize("ip", ["224.0.0.1", "ff02::1", "64:ff9b::7f00:1", "2002:7f00:1::1"])
def test_multicast_and_translation_addresses_are_rejected(ip, monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **kw: [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (ip, 443)),
        ],
    )
    with pytest.raises(n.UnsafeTarget):
        n.public_addresses("example.com")


def test_real_https_transport_verifies_tls_and_refuses_redirects(tmp_path, monkeypatch):
    import http.server
    import ssl
    import subprocess
    import threading

    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )
    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(302 if self.path == "/redirect" else 200)
            self.send_header("Location", "https://127.0.0.1/private")
            self.end_headers()
            self.wfile.write(b'{"accepted":true}')

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    original_connect = socket.create_connection
    original_context = ssl.create_default_context

    def connect(address, timeout):
        assert address == ("127.0.0.1", 443)
        return original_connect(("127.0.0.1", server.server_port), timeout)

    # Explicit local test transport; production DNS guards remain tested above.
    monkeypatch.setattr(n, "public_addresses", lambda host: ["127.0.0.1"])
    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(ssl, "create_default_context", lambda: original_context(cafile=str(cert)))
    try:
        adapter = n.SignedWebhook("https://localhost/events", "s" * 32)
        assert adapter.send("one", {"summary": "real TLS"}).confirmed
        redirect = n.SignedWebhook("https://localhost/redirect", "s" * 32)
        assert redirect.send("two", {"summary": "redirect"}).permanent
        assert len(received) == 2
        # Same trusted certificate with the wrong hostname must fail validation.
        wrong_host = n.SignedWebhook("https://example.com/events", "s" * 32)
        assert not wrong_host.send("three", {"summary": "TLS mismatch"}).confirmed
        assert len(received) == 2
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
