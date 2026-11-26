"""A02/A03: shared provider contract cases against loopback fake servers.

Every adapter talks real HTTP to a fake server on 127.0.0.1; nothing leaves the
machine. This proves request shape, error mapping and bounds against the fake's
dialect only - not behavior of the real providers (see the m6_ai gate spec).
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import ssl
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from inference_fakes import NOW, item, make_ledger, scope
from steward.adapters import inference as adapters
from steward.adapters.inference import (
    AnthropicProvider,
    Endpoint,
    ManagedPrivateHttpsTransport,
    OllamaCloudProvider,
    OllamaProvider,
    OpenAICompatibleProvider,
    OpenAIProvider,
    PublicHttpsTransport,
    TransportError,
    build_provider,
)
from steward.core.config import Ai
from steward.core.inference import (
    TASKS,
    InferenceError,
    InferenceService,
    Policy,
    complete_task,
    estimate_tokens,
    render_prompt,
)
from steward.core.inference_endpoint import canonical_private_https_url, public_https_url
from steward.core.inference_snapshot import build_snapshot

KEY = "sk-test-0123456789abcdefghij"
TASK = TASKS["contract.count"]
ANSWER = json.dumps({"item_count": 1, "newest_source": "controller"})
CLOUD_MODEL = "deepseek-v4.1-flash"


@pytest.mark.parametrize(
    "url",
    ["https://10.0.0.1:443", "https://172.31.2.3:8443/api/v1/", "https://192.168.1.2:1/v1.2"],
)
def test_canonical_private_https_url(url):
    assert canonical_private_https_url(url) == url.removesuffix("/")
    assert not public_https_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://10.0.0.1:443/v1",
        "HTTPS://10.0.0.1:443/v1",
        "https://10.0.0.1/v1",
        "https://10.0.0.1:0443/v1",
        "https://10.0.0.1:0/v1",
        "https://10.0.0.1:65536/v1",
        "https://010.0.0.1:443/v1",
        "https://10.1:443/v1",
        "https://[::ffff:10.0.0.1]:443/v1",
        "https://10.0.0.1.example:443/v1",
        "https://user@10.0.0.1:443/v1",
        "https://127.0.0.1:443/v1",
        "https://100.64.0.1:443/v1",
        "https://169.254.1.1:443/v1",
        "https://172.32.0.1:443/v1",
        "https://8.8.8.8:443/v1",
        "https://10.0.0.1:443/v1?",
        "https://10.0.0.1:443/v1#",
        "https://10.0.0.1:443/v1//",
        "https://10.0.0.1:443//v1",
        "https://10.0.0.1:443/v1/../v2",
        "https://10.0.0.1:443/./v1",
        "https://10.0.0.1:443/v1%2fmodels",
        "https://10.0.0.1:443/v1\n",
    ],
)
def test_private_https_rejects_noncanonical_urls(url):
    with pytest.raises(ValueError):
        canonical_private_https_url(url)


PRIVATE_BASE = "https://10.0.0.7:443/v1"


def _relay_tls_context(tmp_path, cert_ip):
    key = ec.generate_private_key(ec.SECP256R1())
    # The common name matches even for the wrong-IP case. Verification must use the IP SAN.
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "10.0.0.7")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address(cert_ip))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(pem)
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    return context, pem


@contextmanager
def _unix_relay(path, monkeypatch):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        try:
            listener.bind(str(path))
        except PermissionError:
            # The restricted runner allows socketpairs but denies bind and socket
            # metadata queries. Keep the OpenSSL handshake and I/O on native sockets.
            client, server = socket.socketpair()
            with client, server, monkeypatch.context() as patch:

                def connect(sock, address):
                    assert sock.family == socket.AF_UNIX and address == str(path)
                    os.dup2(client.fileno(), sock.fileno())
                    sock.settimeout(sock.gettimeout())
                    client.close()

                patch.setattr(socket.socket, "connect", connect)
                patch.setattr(socket.socket, "getsockopt", lambda *_: socket.SOCK_STREAM)
                patch.setattr(socket.socket, "getpeername", lambda _: "")
                yield lambda: server
        else:
            listener.listen()
            listener.settimeout(2)
            yield lambda: listener.accept()[0]


@pytest.mark.parametrize(
    "case",
    [
        "valid",
        "completion",
        "close_delimited",
        "redirect",
        "wrong_ip",
        "untrusted",
        "stall",
        "truncated",
        "truncated_unframed",
    ],
)
def test_managed_private_https_over_unix_relay(tmp_path, monkeypatch, case):
    context, pem = _relay_tls_context(tmp_path, "10.0.0.8" if case == "wrong_ip" else "10.0.0.7")
    path = tmp_path / "relay.sock"
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    transport = ManagedPrivateHttpsTransport(
        PRIVATE_BASE, path, ca_pem=None if case == "untrusted" else pem
    )
    provider = OpenAICompatibleProvider(
        PRIVATE_BASE, "test-model", api_key=KEY, transport=transport
    )
    requests = []
    failures = []
    with _unix_relay(path, monkeypatch) as accept:

        def serve():
            with accept() as conn:
                conn.settimeout(2)
                if case == "stall":
                    # Consume TLS handshake bytes without responding.
                    conn.setblocking(True)
                    while chunk := os.read(conn.fileno(), 4096):
                        requests.append(chunk)
                    return
                try:
                    with (
                        context.wrap_socket(conn, server_side=True) as tls,
                        tls.makefile("rb") as stream,
                    ):
                        request = stream.readline()
                        while (line := stream.readline()) not in (b"\r\n", b""):
                            request += line
                        requests.append(request)
                        if case == "redirect":
                            tls.sendall(
                                b"HTTP/1.1 302 Found\r\nLocation: https://10.0.0.8/v1/models\r\nContent-Length: 0\r\n\r\n"
                            )
                        else:
                            if case == "completion":
                                length = int(
                                    next(
                                        line.split(b":", 1)[1]
                                        for line in request.splitlines()
                                        if line.lower().startswith(b"content-length:")
                                    )
                                )
                                requests.append(json.loads(stream.read(length)))
                                body = b'{"choices":[{"message":{"content":"{}"},"finish_reason":"stop"}]}'
                            else:
                                body = b'{"data":[{"id":"test-model"}]}'
                            length = len(body) + (case == "truncated")
                            if case in ("close_delimited", "truncated_unframed"):
                                if case == "truncated_unframed":
                                    body = body[:-1]
                                tls.sendall(b"HTTP/1.0 200 OK\r\n\r\n" + body)
                                # Let the requester consume the TLS shutdown before the
                                # socket disappears, as the fixed relay does on EOF.
                                tls.unwrap().close()
                            else:
                                tls.sendall(
                                    f"HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n".encode()
                                    + body
                                )
                except ssl.SSLError as exc:
                    failures.append(exc)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            if case in ("valid", "close_delimited"):
                assert provider.list_models() == ["test-model"]
            elif case == "completion":
                completion = provider.complete(
                    "system", "user", schema={}, max_output_tokens=10, timeout_s=1
                )
                assert completion.text == "{}"
            else:
                with pytest.raises(InferenceError) as exc:
                    provider.list_models(timeout_s=0.15 if case == "stall" else 1)
                assert exc.value.error_class == (
                    "unsupported" if case == "redirect" else "unavailable"
                )
        finally:
            thread.join(timeout=3)
        assert not thread.is_alive()
    if case in (
        "valid",
        "completion",
        "close_delimited",
        "redirect",
        "truncated",
        "truncated_unframed",
    ):
        request, *bodies = requests
        if case == "completion":
            assert request.startswith(b"POST /v1/chat/completions HTTP/1.1\r\n")
            assert len(bodies) == 1 and bodies[0]["model"] == "test-model"
        else:
            assert request.startswith(b"GET /v1/models HTTP/1.1\r\n")
            assert not bodies
        assert b"Host: 10.0.0.7:443\r\n" in request
        assert b"Cache-Control: no-store, no-cache\r\n" in request
        assert f"Authorization: Bearer {KEY}\r\n".encode() in request
    elif case == "stall":
        assert requests and KEY.encode() not in b"".join(requests)
    else:
        assert failures and not requests


def test_managed_private_https_rejects_endpoint_and_request_overrides(tmp_path):
    transport = ManagedPrivateHttpsTransport(PRIVATE_BASE, tmp_path / "relay.sock")
    endpoint = Endpoint.from_url(PRIVATE_BASE)
    with pytest.raises(ValueError):
        OpenAICompatibleProvider(
            PRIVATE_BASE.replace(":443", ""), "test-model", transport=transport
        )
    for target, method, path, headers in [
        (Endpoint.from_url(PRIVATE_BASE.replace("443", "8443")), "GET", "/models", {}),
        (endpoint, "GET", "/models?redirect=1", {}),
        (endpoint, "GET", "/models", {"hOsT": "10.0.0.8"}),
    ]:
        with pytest.raises(TransportError) as exc:
            transport.request(target, method, path, headers, None, timeout=1)
        assert exc.value.kind == "unsafe"


def test_managed_private_https_guards_final_check_and_request_write(tmp_path, monkeypatch):
    events = []
    held = False

    @contextmanager
    def hold():
        nonlocal held
        held = True
        try:
            yield
        finally:
            held = False

    class Connection:
        def connect(self):
            assert not held
            events.append("tls")

        def request(self, *_args):
            assert held
            events.append("send")

        def getresponse(self):
            assert not held
            events.append("read")
            return self

        status = 200

        def read(self, amt):
            return b""

        def getheaders(self):
            return [("Content-Length", "0")]

        def close(self):
            assert not held

    def check():
        events.append("locked" if held else "unlocked")

    monkeypatch.setattr(adapters, "_ManagedPrivateHttpsConnection", lambda *_: Connection())
    transport = ManagedPrivateHttpsTransport(
        PRIVATE_BASE, tmp_path / "relay.sock", check_admission=check, send_guard=hold
    )
    transport.request(Endpoint.from_url(PRIVATE_BASE), "GET", "/models", {}, None, timeout=1)
    assert events == ["unlocked", "tls", "locked", "send", "read"]


# ---- fake server ----------------------------------------------------------------------


class FakeServer:
    def __init__(self):
        self.script: list[tuple[int, dict, bytes] | float] = []
        self.requests: list[dict] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _handle(self):
                length = int(self.headers.get("content-length") or 0)
                raw = self.rfile.read(length) if length else b""
                outer.requests.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                        "body": json.loads(raw) if raw else None,
                    }
                )
                step = outer.script.pop(0)
                if isinstance(step, float):  # stall past the client's timeout
                    time.sleep(step)
                    return
                status, headers, body = step
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = _handle

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class ToFake(adapters._Base):
    """Test transport: keep the adapter's real endpoint/path/headers, send to the fake."""

    def __init__(self, port):
        self.port = port

    def _connection(self, endpoint, timeout):
        fake = Endpoint("http", endpoint.host, self.port, "")
        return adapters._Pinned(fake, "127.0.0.1", timeout, tls=False)


@pytest.fixture
def server():
    fake = FakeServer()
    yield fake
    fake.close()


def jbody(obj) -> bytes:
    return json.dumps(obj).encode()


# ---- dialects ---------------------------------------------------------------------------


class Dialect:
    name = ""
    model = "test-model"
    models_field = "data"
    model_id_field = "id"

    def provider(self, port, **kw):
        raise NotImplementedError

    def ok(self, text=ANSWER, usage=(50, 10)):
        raise NotImplementedError

    def fail(self, kind):
        raise NotImplementedError

    @staticmethod
    def err(status, body, headers=None):
        return (status, headers or {}, jbody(body))


class OllamaD(Dialect):
    name = "ollama"
    model = "test-model:1b"
    models_field = "models"
    model_id_field = "name"
    chat_path = "/api/chat"

    def provider(self, port, **kw):
        return OllamaProvider(self.model, transport=ToFake(port), timeout_s=kw.pop("t", 1.0))

    def ok(self, text=ANSWER, usage=(50, 10)):
        return (
            200,
            {},
            jbody(
                {
                    "model": self.model,
                    "message": {"role": "assistant", "content": text},
                    "done": True,
                    "done_reason": "stop",
                    "prompt_eval_count": usage[0],
                    "eval_count": usage[1],
                }
            ),
        )

    def fail(self, kind):
        return {
            "auth": self.err(401, {"error": f"bad key {KEY}"}),
            "rate": self.err(429, {"error": "busy"}, {"Retry-After": "7"}),
            "server": self.err(500, {"error": "boom"}),
            "model": self.err(404, {"error": "model 'x' not found"}),
            "context": self.ok(usage=(8192, 5)),
            "truncated": (
                200,
                {},
                jbody({"message": {"content": "{"}, "done": True, "done_reason": "length"}),
            ),
            "refusal": None,
            "quota": None,
        }[kind]


class OllamaCloudD(OllamaD):
    name = "ollama-cloud-api"
    model = CLOUD_MODEL

    def provider(self, port, **kw):
        return OllamaCloudProvider(
            KEY, self.model, transport=ToFake(port), timeout_s=kw.pop("t", 1.0)
        )

    def fail(self, kind):
        if kind == "context":
            return self.err(413, {"error": KEY})
        if kind == "truncated":
            status, headers, body = self.ok()
            return status, headers, jbody({**json.loads(body), "done_reason": "length"})
        return super().fail(kind)


class OpenAID(Dialect):
    name = "openai"
    chat_path = "/v1/chat/completions"

    def provider(self, port, **kw):
        return OpenAIProvider(KEY, "test-model", transport=ToFake(port), timeout_s=kw.pop("t", 1.0))

    def ok(self, text=ANSWER, usage=(50, 10)):
        return (
            200,
            {},
            jbody(
                {
                    "model": "test-model",
                    "choices": [
                        {"message": {"role": "assistant", "content": text}, "finish_reason": "stop"}
                    ],
                    "usage": {"prompt_tokens": usage[0], "completion_tokens": usage[1]},
                }
            ),
        )

    def fail(self, kind):
        def e(status, code, typ="x", headers=None):
            return self.err(status, {"error": {"code": code, "type": typ, "message": KEY}}, headers)

        return {
            "auth": e(401, "invalid_api_key"),
            "rate": e(429, "rate_limit_exceeded", headers={"Retry-After": "7"}),
            "quota": e(429, "insufficient_quota", "insufficient_quota"),
            "server": e(503, None),
            "model": e(404, "model_not_found"),
            "context": e(400, "context_length_exceeded"),
            "truncated": (
                200,
                {},
                jbody({"choices": [{"message": {"content": "{"}, "finish_reason": "length"}]}),
            ),
            "refusal": (
                200,
                {},
                jbody(
                    {
                        "choices": [
                            {"message": {"content": None, "refusal": "no"}, "finish_reason": "stop"}
                        ],
                        "usage": {"prompt_tokens": 5, "completion_tokens": 1},
                    }
                ),
            ),
        }[kind]


class CompatD(OpenAID):
    name = "openai-compatible"
    chat_path = "/v1/chat/completions"

    def provider(self, port, **kw):
        return OpenAICompatibleProvider(
            "http://127.0.0.1:1/v1",
            "test-model",
            api_key=KEY,
            transport=ToFake(port),
            timeout_s=kw.pop("t", 1.0),
        )


class AnthropicD(Dialect):
    name = "anthropic"
    chat_path = "/v1/messages"

    def provider(self, port, **kw):
        return AnthropicProvider(
            KEY, "test-model", transport=ToFake(port), timeout_s=kw.pop("t", 1.0)
        )

    def ok(self, text=ANSWER, usage=(50, 10)):
        return (
            200,
            {},
            jbody(
                {
                    "model": "test-model",
                    "role": "assistant",
                    "content": [{"type": "text", "text": text}],
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": usage[0], "output_tokens": usage[1]},
                }
            ),
        )

    def fail(self, kind):
        def e(status, typ, message=KEY, headers=None):
            return self.err(
                status, {"type": "error", "error": {"type": typ, "message": message}}, headers
            )

        return {
            "auth": e(401, "authentication_error"),
            "rate": e(429, "rate_limit_error", headers={"retry-after": "7"}),
            "quota": e(400, "invalid_request_error", "Your credit balance is too low " + KEY),
            "server": e(529, "overloaded_error"),
            "model": e(404, "not_found_error"),
            "context": e(400, "invalid_request_error", "prompt is too long: 999999 tokens"),
            "truncated": (
                200,
                {},
                jbody(
                    {
                        "content": [{"type": "text", "text": "{"}],
                        "stop_reason": "max_tokens",
                        "usage": {"input_tokens": 5, "output_tokens": 5},
                    }
                ),
            ),
            "refusal": (
                200,
                {},
                jbody(
                    {
                        "content": [],
                        "stop_reason": "refusal",
                        "usage": {"input_tokens": 5, "output_tokens": 0},
                    }
                ),
            ),
        }[kind]


DIALECTS = [OllamaD(), OllamaCloudD(), OpenAID(), CompatD(), AnthropicD()]
ids = [d.name for d in DIALECTS]


def snapshot(n=1):
    return build_snapshot([item(f"row {i}") for i in range(n)], scope("notes"), now=NOW)


def attempt(provider, n=1):
    return complete_task(provider, TASK, snapshot(n))


def error_of(provider) -> InferenceError:
    with pytest.raises(InferenceError) as exc:
        attempt(provider)
    return exc.value


def assert_clean(exc: InferenceError):
    text = repr(exc) + str(exc) + repr(exc.args) + repr(exc.__dict__)
    assert KEY not in text and "127.0.0.1" not in text and "http" not in text


# ---- shared contract cases ----------------------------------------------------------------


@pytest.mark.parametrize("d", DIALECTS, ids=ids)
def test_success_request_shape_and_usage(d, server):
    server.script = [d.ok()]
    provider = d.provider(server.port)
    done = attempt(provider)
    assert done.data == {"item_count": 1, "newest_source": "controller"} and done.untrusted
    assert (done.usage.input_tokens, done.usage.output_tokens) == (50, 10)
    request = server.requests[0]
    assert request["method"] == "POST" and request["path"] == d.chat_path
    body = request["body"]
    assert body["model"] == d.model
    text = json.dumps(body)
    assert "untrusted data" in text and "row 0" in text  # fixed prompt + snapshot data
    assert not {"tools", "tool_choice", "functions"} & set(body)
    assert body.get("stream", False) is False
    assert KEY not in repr(provider) and "127.0.0.1" not in repr(provider)
    assert provider.health().ok and len(server.requests) == 1  # health performs no I/O


@pytest.mark.parametrize("d", DIALECTS, ids=ids)
def test_malformed_extended_and_non_json_outputs(d, server):
    for text in ("no json", ANSWER + "{}", '{"item_count": 1, "newest_source": "c", "extra": 1}'):
        server.script = [d.ok(text)]
        exc = error_of(d.provider(server.port))
        assert exc.error_class == "invalid_output" and exc.spend == "known"
        assert exc.usage.input_tokens == 50
    server.script = [(200, {}, b"<html>proxy page</html>")]
    exc = error_of(d.provider(server.port))
    assert exc.error_class == "invalid_output" and exc.spend == "unknown"


@pytest.mark.parametrize("d", DIALECTS, ids=ids)
@pytest.mark.parametrize(
    "kind, error_class, retryable, spend",
    [
        ("auth", "auth", False, "none"),
        ("rate", "rate_limited", True, "none"),
        ("server", "unavailable", True, "unknown"),
        ("model", "model_unavailable", False, "none"),
        ("context", "context_limit", False, None),
        ("truncated", "invalid_output", False, "known"),
        ("refusal", "refused", False, "known"),
        ("quota", "quota", False, "none"),
    ],
)
def test_error_mapping_is_stable_and_secret_free(
    d, kind, error_class, retryable, spend, server, request
):
    step = d.fail(kind)
    if step is None:
        pytest.skip(f"{d.name} has no {kind} case")
    server.script = [step]
    exc = error_of(d.provider(server.port))
    assert exc.error_class == error_class and exc.retryable is retryable
    if spend:
        assert exc.spend == spend
    if kind == "rate":
        assert exc.retry_after_s == 7
    assert_clean(exc)


@pytest.mark.parametrize("d", DIALECTS, ids=ids)
def test_timeout_is_ambiguous_and_retryable(d, server):
    server.script = [1.0]
    started = time.monotonic()
    exc = error_of(d.provider(server.port, t=0.3))
    assert exc.error_class == "timeout" and exc.retryable and exc.spend == "unknown"
    assert time.monotonic() - started < 0.9


@pytest.mark.parametrize("d", DIALECTS, ids=ids)
def test_redirect_is_not_followed(d, server):
    server.script = [(302, {"Location": "http://127.0.0.1:1/steal"}, b"")]
    exc = error_of(d.provider(server.port))
    assert exc.error_class == "unsupported" and exc.spend == "none"
    assert len(server.requests) == 1


@pytest.mark.parametrize("d", DIALECTS, ids=ids)
def test_response_size_is_bounded(d, server):
    server.script = [(200, {}, b"x" * (adapters.MAX_RESPONSE + 10))]
    exc = error_of(d.provider(server.port))
    assert exc.error_class == "invalid_output"


@pytest.mark.parametrize("d", DIALECTS, ids=ids)
def test_connection_refused_means_nothing_was_sent(d):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    exc = error_of(d.provider(port))
    assert exc.error_class == "unavailable" and exc.retryable and exc.spend == "none"
    assert_clean(exc)


@pytest.mark.parametrize("d", DIALECTS, ids=ids)
def test_context_limit_before_any_request(d, server):
    provider = d.provider(server.port)
    provider.max_input_bytes = 400
    exc = error_of(provider)
    assert exc.error_class == "context_limit" and exc.spend == "none" and not server.requests


@pytest.mark.parametrize("d", DIALECTS, ids=ids)
def test_service_budget_settlement_through_real_http(d, server, tmp_path):
    ledger = make_ledger(tmp_path)
    local = d.name in ("ollama", "openai-compatible")
    policy = (
        Policy(local_only=True) if local else Policy(local_only=False, share=frozenset({"status"}))
    )
    service = InferenceService(
        d.provider(server.port),
        ledger,
        policy,
        sleep=lambda s: None,
        clock=lambda: NOW,
        max_attempts=1,
    )
    run = lambda: service.run("contract.count", [item("a")], scope("notes"))  # noqa: E731
    server.script = [d.ok(usage=(70, 5))]
    assert run().ok and ledger.usage(now=NOW)["tokens"] == 75
    server.script = [d.fail("auth")]
    assert run().error_class == "auth" and ledger.usage(now=NOW)["tokens"] == 75  # released
    server.script = [d.fail("server")]
    out = run()
    assert out.error_class == "unavailable" and ledger.usage(now=NOW)["tokens"] > 75  # charged


@pytest.mark.parametrize("d", DIALECTS, ids=ids)
def test_list_models(d, server):
    body = {d.models_field: [{d.model_id_field: d.model}, {d.model_id_field: "other"}, {}]}
    server.script = [(200, {}, jbody(body))]
    models = d.provider(server.port).list_models()
    assert set(models) == {d.model, "other"} and server.requests[0]["method"] == "GET"
    server.script = [d.fail("auth")]
    with pytest.raises(InferenceError) as exc:
        d.provider(server.port).list_models()
    assert exc.value.error_class == "auth"


# ---- dialect-specific behavior ---------------------------------------------------------------


def test_ollama_options_and_no_model_management(server):
    server.script = [OllamaD().ok(), (200, {}, jbody({"models": []}))]
    provider = OllamaD().provider(server.port)
    attempt(provider)
    provider.list_models()
    chat = server.requests[0]["body"]
    assert chat["stream"] is False and chat["options"]["num_ctx"] == 8192
    assert chat["options"]["temperature"] == 0 and "maxLength" not in json.dumps(chat["format"])
    assert [r["path"] for r in server.requests] == ["/api/chat", "/api/tags"]
    assert not any("pull" in r["path"] or "create" in r["path"] for r in server.requests)


def test_ollama_cloud_fixed_requests(server):
    d = OllamaCloudD()
    server.script = [d.ok(), d.err(200, {"models": [{"name": CLOUD_MODEL}]})]
    provider = d.provider(server.port)
    assert provider.name == d.name and provider.data_class == "external"
    assert "complete.json_schema" not in provider.capabilities
    attempt(provider)
    assert provider.list_models() == [CLOUD_MODEL]
    chat, tags = server.requests
    system, user = render_prompt(TASK, snapshot())
    assert chat["body"] == {
        "model": CLOUD_MODEL,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "stream": False,
        "options": {"num_predict": TASK.max_output_tokens},
    }
    assert (chat["method"], chat["path"]) == ("POST", "/api/chat")
    assert (tags["method"], tags["path"], tags["body"]) == ("GET", "/api/tags", None)
    for request in (chat, tags):
        assert request["headers"]["host"].split(":")[0] == "ollama.com"
        assert request["headers"]["authorization"] == f"Bearer {KEY}"


@pytest.mark.parametrize("done", [False, 1, "true", None])
def test_ollama_cloud_requires_literal_done(server, done):
    d = OllamaCloudD()
    _, _, body = d.ok()
    response = json.loads(body)
    response.pop("done")
    if done is not None:
        response["done"] = done
    server.script = [d.err(200, response)]
    exc = error_of(d.provider(server.port))
    assert exc.error_class == "invalid_output" and exc.spend == "known"
    assert (exc.usage.input_tokens, exc.usage.output_tokens) == (50, 10)


def test_ollama_cloud_rejects_error_with_completed_message(server):
    d = OllamaCloudD()
    _, _, body = d.ok()
    server.script = [d.err(200, {**json.loads(body), "error": KEY})]
    exc = error_of(d.provider(server.port))
    assert exc.error_class == "invalid_output" and exc.spend == "known"
    assert (exc.usage.input_tokens, exc.usage.output_tokens) == (50, 10)
    assert_clean(exc)


@pytest.mark.parametrize(
    "reported, expected",
    [(KEY, CLOUD_MODEL), ("a" * 129, CLOUD_MODEL), ("test-alias", "test-alias")],
)
def test_ollama_cloud_reports_only_safe_model_names(server, reported, expected):
    d = OllamaCloudD()
    _, _, body = d.ok()
    server.script = [d.err(200, {**json.loads(body), "model": reported})]
    assert attempt(d.provider(server.port)).model == expected


def test_ollama_cloud_unknown_usage_charges_reservation(server, tmp_path):
    d = OllamaCloudD()
    ledger = make_ledger(tmp_path)
    policy = Policy(local_only=False, share=frozenset({"status"}))
    service = InferenceService(d.provider(server.port), ledger, policy, clock=lambda: NOW)
    server.script = [d.ok(usage=(None, False))]
    out = service.run(TASK.id, [item("a")], scope("notes"))
    assert out.ok and out.usage.input_tokens is None and out.usage.output_tokens is None
    system, user = [m["content"] for m in server.requests[0]["body"]["messages"]]
    assert ledger.usage(now=NOW)["tokens"] == estimate_tokens(system, user) + TASK.max_output_tokens


def test_ollama_cloud_forbidden_is_secret_free(server):
    d = OllamaCloudD()
    server.script = [d.err(403, {"error": f"forbidden: {KEY}"})]
    exc = error_of(d.provider(server.port))
    assert exc.error_class == "auth" and exc.spend == "none" and not exc.retryable
    assert_clean(exc)


@pytest.mark.parametrize(
    "url", ["http://192.0.2.5:11434", "https://127.0.0.1:11434", "http://example.com:11434"]
)
def test_ollama_rejects_non_loopback_endpoints(url):
    with pytest.raises(ValueError):
        OllamaProvider("m", base_url=url)


def test_loopback_transport_rejects_hosts_that_resolve_elsewhere(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.254.253.20", 11434))]
    )
    provider = OllamaProvider("m", base_url="http://localhost:11434")
    monkeypatch.setattr(
        socket, "create_connection", lambda *a, **k: pytest.fail("connected to a non-loopback host")
    )
    exc = error_of(provider)
    assert exc.error_class == "policy_denied" and exc.spend == "none"


def test_openai_official_request_shape(server):
    d = OpenAID()
    server.script = [d.ok()]
    attempt(d.provider(server.port))
    request = server.requests[0]
    assert request["headers"]["authorization"] == f"Bearer {KEY}"
    assert request["headers"]["host"].startswith("api.openai.com")
    body = request["body"]
    assert body["max_completion_tokens"] == 128 and "max_tokens" not in body
    fmt = body["response_format"]["json_schema"]
    assert fmt["strict"] is True and fmt["schema"]["additionalProperties"] is False
    assert "temperature" not in body and "maxLength" not in json.dumps(fmt)


def test_compatible_is_probed_not_assumed(server):
    d = CompatD()
    server.script = [d.ok(), (200, {}, jbody({"data": [{"id": "test-model"}]}))]
    provider = d.provider(server.port)
    attempt(provider)
    body = server.requests[0]["body"]
    assert body["max_tokens"] == 128 and "response_format" not in body
    assert provider.data_class == "local" and "complete.json_schema" not in provider.capabilities
    assert provider.probe() == {"models.list": True, "model.listed": True}
    server.script = [(404, {}, b"{}")]
    assert provider.probe() == {"models.list": False, "model.listed": False}
    external = OpenAICompatibleProvider("https://llm.example.com/v1", "m", transport=ToFake(1))
    assert external.data_class == "external" and "Authorization" not in external._headers()


def test_anthropic_request_shape_and_response_handling(server):
    d = AnthropicD()
    thinking = {
        "content": [
            {"type": "thinking", "thinking": "hmm", "signature": "s"},
            {"type": "text", "text": ANSWER[:10]},
            {"type": "text", "text": ANSWER[10:]},
        ],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 5,
            "output_tokens": 7,
            "cache_creation_input_tokens": 2,
            "cache_read_input_tokens": 3,
        },
    }
    server.script = [(200, {}, jbody(thinking))]
    done = attempt(d.provider(server.port))
    assert done.data["item_count"] == 1 and done.usage.input_tokens == 10
    request = server.requests[0]
    assert request["headers"]["x-api-key"] == KEY
    assert request["headers"]["anthropic-version"] == "2023-06-01"
    assert request["headers"]["host"].startswith("api.anthropic.com")
    body = request["body"]
    assert body["max_tokens"] == 128 and "temperature" not in body and "thinking" not in body
    assert "tools" not in body and body["messages"][0]["role"] == "user"
    for stop in ("tool_use", "pause_turn"):  # no tools were offered: reject
        server.script = [(200, {}, jbody({**thinking, "stop_reason": stop}))]
        assert error_of(d.provider(server.port)).error_class == "invalid_output"


# ---- public transport and local_only ---------------------------------------------------------


@pytest.mark.parametrize(
    "provider_type, host", [(OpenAIProvider, "api.openai.com"), (OllamaCloudProvider, "ollama.com")]
)
def test_public_transport_connects_only_to_the_checked_public_address(
    monkeypatch, provider_type, host
):
    seen = []
    resolved = []

    def fake_resolve(host, port, *args, **kwargs):
        resolved.append((host, port))
        return [(2, 1, 6, "", ("93.184.216.34", 443))]

    def fake_connect(address, timeout=None):
        seen.append(address)
        raise OSError("no network in tests")

    monkeypatch.setattr(socket, "getaddrinfo", fake_resolve)
    monkeypatch.setattr(socket, "create_connection", fake_connect)
    exc = error_of(provider_type(KEY, "m"))
    assert resolved == [(host, 443)]
    assert seen == [("93.184.216.34", 443)] and exc.spend == "none"
    assert exc.error_class == "unavailable"


@pytest.mark.parametrize(
    "address", ["10.254.253.20", "127.0.0.1", "169.254.169.254", "::1", "fc00::1"]
)
def test_public_transport_refuses_private_resolutions(monkeypatch, address):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", (address, 443))])
    monkeypatch.setattr(
        socket, "create_connection", lambda *a, **k: pytest.fail("connected to a private address")
    )
    for provider in (
        OpenAIProvider(KEY, "m"),
        AnthropicProvider(KEY, "m"),
        OllamaCloudProvider(KEY, CLOUD_MODEL),
        OpenAICompatibleProvider("https://llm.example.com/v1", "m"),
    ):
        exc = error_of(provider)
        assert exc.error_class == "policy_denied" and exc.spend == "none"


def test_public_transport_rejects_non_https_or_odd_ports():
    transport = PublicHttpsTransport()
    for endpoint in (
        Endpoint("http", "example.com", 80, ""),
        Endpoint("https", "example.com", 8443, ""),
    ):
        with pytest.raises(TransportError) as exc:
            transport.request(endpoint, "GET", "/", {}, None, timeout=1)
        assert exc.value.kind == "unsafe"


@pytest.mark.parametrize(
    "method, provider_type",
    [("anthropic", AnthropicProvider), ("ollama-cloud-api", OllamaCloudProvider)],
)
def test_local_only_makes_external_calls_impossible(monkeypatch, tmp_path, method, provider_type):
    def forbidden(*a, **k):
        pytest.fail("network access under local_only")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    ai = Ai.model_construct(  # bypass validation: the factory must refuse on its own
        provider=method, local_only=True, model="m", api_key_ref="env:K", share=["status"]
    )
    with pytest.raises(InferenceError) as exc:
        build_provider(ai, env={"K": KEY})
    assert exc.value.error_class == "policy_denied"
    cloud = provider_type(KEY, "m")
    with pytest.raises(InferenceError) as exc:
        InferenceService(
            cloud, make_ledger(tmp_path), Policy(local_only=True, share=frozenset({"status"}))
        )
    assert exc.value.error_class == "policy_denied"


def test_ollama_cloud_sharing_and_budget_before_request(server, tmp_path):
    d = OllamaCloudD()
    provider = d.provider(server.port)
    ledger = make_ledger(tmp_path, monthly={"tokens": 50})
    with pytest.raises(InferenceError) as exc:
        InferenceService(provider, ledger, Policy(local_only=False))
    assert exc.value.error_class == "policy_denied"

    policy = Policy(local_only=False, share=frozenset({"status"}))
    service = InferenceService(provider, ledger, policy, clock=lambda: NOW)
    items = [item("status row"), item("withheld log row", cls="logs")]
    out = service.run(TASK.id, items, scope("notes"))
    assert out.error_class == "budget_denied" and not server.requests

    server.script = [d.ok()]
    service = InferenceService(provider, make_ledger(tmp_path), policy, clock=lambda: NOW)
    assert service.run(TASK.id, items, scope("notes")).ok
    content = server.requests[0]["body"]["messages"][1]["content"]
    assert "status row" in content and "withheld log row" not in content
    sent = json.loads(content)
    assert sent["coverage"]["withheld_classes"] == ["logs"]


def test_factory_builds_each_provider_from_validated_config():
    env = {"K": KEY}
    local = build_provider(Ai(provider="ollama", model="m"))
    assert isinstance(local, OllamaProvider) and local.data_class == "local"
    cfg = {
        "local_only": False,
        "model": "m",
        "api_key_ref": "env:K",
        "share": ["status"],
        "budget": {"monthly": {"tokens": 100}},
    }
    assert isinstance(build_provider(Ai(provider="openai", **cfg), env=env), OpenAIProvider)
    assert isinstance(build_provider(Ai(provider="anthropic", **cfg), env=env), AnthropicProvider)
    cloud_cfg = Ai(provider="ollama-cloud-api", **{**cfg, "model": CLOUD_MODEL})
    cloud = build_provider(cloud_cfg, env=env)
    assert isinstance(cloud, OllamaCloudProvider) and cloud.model == CLOUD_MODEL
    with pytest.raises(InferenceError) as exc:
        build_provider(cloud_cfg, env={})
    assert exc.value.error_class == "auth"
    assert_clean(exc.value)
    compat = build_provider(
        Ai(provider="openai-compatible", base_url="https://llm.example.com/v1", **cfg), env=env
    )
    assert compat.data_class == "external"
    with pytest.raises(InferenceError) as exc:  # unresolved secret reference
        build_provider(Ai(provider="openai", **cfg), env={})
    assert exc.value.error_class == "auth"
    with pytest.raises(ValueError):
        build_provider(Ai())
