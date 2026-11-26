"""InferenceProvider v1 adapters for Ollama, OpenAI, Anthropic and compatible APIs.

Transports are bounded and never follow redirects or environment proxies. Local
adapters connect to loopback addresses. External transports use checked public
addresses or a fixed managed Unix relay with end-to-end TLS. Errors map to the
stable classes of `core/inference.py` and never contain
URLs, response bodies or credentials. Official API shapes were written from
provider documentation knowledge and must be re-verified by the provider gates in
`tests/integration/gates/m6_ai.md` before any acceptance claim.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import math
import os
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from pydantic import TypeAdapter, ValidationError

from ..core.config import AI_EXTERNAL_PROVIDERS, Ai, ModelName
from ..core.inference import (
    Health,
    InferenceError,
    InferenceProvider,
    RawCompletion,
    Usage,
)
from ..core.inference_endpoint import canonical_private_https_url, is_loopback_host, parse
from ..core.inference_schema import wire_schema
from ..core.secrets import SecretError, resolve
from .notifications import UnsafeTarget, public_addresses

MAX_RESPONSE = 1024 * 1024
MAX_RETRY_AFTER_S = 3600.0
OLLAMA_URL = "http://127.0.0.1:11434"
OLLAMA_CLOUD_URL = "https://ollama.com"
OLLAMA_NUM_CTX = 8192
_MODEL_NAME = TypeAdapter(ModelName)
OPENAI_BASE = "https://api.openai.com/v1"
ANTHROPIC_BASE = "https://api.anthropic.com"
ANTHROPIC_VERSION = "2023-06-01"


# ---- transports -----------------------------------------------------------------------


@dataclass(frozen=True)
class Endpoint:
    scheme: str
    host: str
    port: int
    prefix: str  # path prefix without trailing slash

    @classmethod
    def from_url(cls, url: str) -> Endpoint:
        parts = parse(url)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return cls(parts.scheme, parts.hostname or "", port, parts.path.rstrip("/"))


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes


class TransportError(Exception):
    """`kind`: connect (nothing sent), timeout / io (request may have been processed),
    too_large, unsafe."""

    def __init__(self, kind: str):
        super().__init__(kind)
        self.kind = kind


class Transport(Protocol):
    def request(
        self,
        endpoint: Endpoint,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None,
        *,
        timeout: float,
    ) -> HttpResponse: ...


class _Base:
    """Shared request/response handling; subclasses decide where the socket goes."""

    _max_response_bytes = MAX_RESPONSE
    _check_admission: Callable[[], None] | None = None

    def _connection(self, endpoint: Endpoint, timeout: float) -> http.client.HTTPConnection:
        raise NotImplementedError

    def request(self, endpoint, method, path, headers, body, *, timeout):
        deadline = time.monotonic() + timeout
        try:
            conn = self._connection(endpoint, timeout)
        except UnsafeTarget:
            raise TransportError("unsafe") from None
        except OSError:  # DNS failure: nothing was sent
            raise TransportError("connect") from None
        return self._exchange(
            conn,
            endpoint.prefix + path,
            method,
            headers,
            body,
            deadline,
            max_response_bytes=self._max_response_bytes,
            check_admission=self._check_admission,
        )

    @staticmethod
    def _exchange(
        conn,
        path,
        method,
        headers,
        body,
        deadline,
        *,
        max_response_bytes=MAX_RESPONSE,
        check_admission=None,
        send_guard=None,
    ):
        try:
            if check_admission is not None:
                check_admission()
            try:
                conn.connect()
            except TimeoutError:
                raise TransportError("connect_timeout") from None
            except (OSError, http.client.HTTPException):
                raise TransportError("connect") from None
            try:
                with send_guard() if send_guard is not None else contextlib.nullcontext():
                    if check_admission is not None:
                        check_admission()
                    conn.request(method, path, body, headers)
                response = conn.getresponse()
                data = bytearray()
                while True:
                    if time.monotonic() > deadline:
                        raise TimeoutError
                    chunk = response.read(min(65536, max_response_bytes + 1 - len(data)))
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > max_response_bytes:
                        raise TransportError("too_large")
                if time.monotonic() >= deadline:
                    raise TimeoutError
                return HttpResponse(
                    response.status, {k.lower(): v for k, v in response.getheaders()}, bytes(data)
                )
            except TimeoutError:
                raise TransportError("timeout") from None
            except (OSError, http.client.HTTPException):
                raise TransportError("io") from None
        finally:
            with contextlib.suppress(Exception):
                conn.close()


class LoopbackTransport(_Base):
    """Plain or TLS connection to loopback addresses only (local data path)."""

    def _addresses(self, endpoint: Endpoint) -> list[str]:
        if not is_loopback_host(endpoint.host):
            raise UnsafeTarget("not a loopback host")
        found = {
            row[4][0]
            for row in socket.getaddrinfo(endpoint.host, endpoint.port, type=socket.SOCK_STREAM)
        }
        if not found or not all(is_loopback_host(a) for a in found):
            raise UnsafeTarget("loopback host resolves elsewhere")
        return sorted(found)

    def _connection(self, endpoint, timeout):
        address = self._addresses(endpoint)[0]
        if endpoint.scheme == "https":
            return _Pinned(endpoint, address, timeout, tls=True)
        return _Pinned(endpoint, address, timeout, tls=False)


class PublicHttpsTransport(_Base):
    """HTTPS to a public address that was checked immediately before connecting."""

    def __init__(
        self,
        *,
        max_response_bytes: int = MAX_RESPONSE,
        check_admission: Callable[[], None] | None = None,
    ) -> None:
        self._max_response_bytes = max_response_bytes
        self._check_admission = check_admission

    def _connection(self, endpoint, timeout):
        if endpoint.scheme != "https" or endpoint.port != 443:
            raise UnsafeTarget("external endpoints must use https on port 443")
        return _Pinned(endpoint, public_addresses(endpoint.host)[0], timeout, tls=True)


class _Pinned(http.client.HTTPConnection):
    def __init__(self, endpoint: Endpoint, address: str, timeout: float, *, tls: bool):
        super().__init__(endpoint.host, endpoint.port, timeout=timeout)
        self.address, self.tls = address, tls
        self.default_port = endpoint.port  # no ":443" in the Host header

    def connect(self) -> None:
        raw = socket.create_connection((self.address, self.port), self.timeout)
        if not self.tls:
            self.sock = raw
            return
        try:
            self.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class _DeadlineSocket(socket.socket):
    """Refresh the remaining deadline before each actual socket I/O."""

    def __init__(self, deadline: float, *, fileno: int | None = None):
        super().__init__(fileno=fileno)
        self.deadline = deadline

    def _set_remaining(self) -> None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        self.settimeout(remaining)

    def connect(self, address) -> None:
        self._set_remaining()
        super().connect(address)

    def sendall(self, data, flags=0) -> None:
        self._set_remaining()
        super().sendall(data, flags)

    def recv_into(self, buffer, nbytes=0, flags=0) -> int:
        # HTTPResponse uses socket.makefile(), which reads through recv_into().
        self._set_remaining()
        return super().recv_into(buffer, nbytes, flags)


class _ManagedOllamaConnection(http.client.HTTPConnection):
    def __init__(self, endpoint: Endpoint, deadline: float):
        super().__init__(endpoint.host, endpoint.port)
        self.deadline = deadline

    def connect(self) -> None:
        self.sock = _DeadlineSocket(self.deadline)
        self.sock.connect((self.host, self.port))


class _ManagedOllamaTransport(_Base):
    """The fixed installed advice endpoint uses one deadline and no DNS."""

    def request(self, endpoint, method, path, headers, body, *, timeout):
        if endpoint != Endpoint.from_url(OLLAMA_URL) or (method, path) != ("POST", "/api/chat"):
            raise TransportError("unsafe")
        deadline = time.monotonic() + timeout
        conn = self._connection(endpoint, deadline)
        return self._exchange(conn, path, method, headers, body, deadline)

    def _connection(self, endpoint, deadline):
        return _ManagedOllamaConnection(endpoint, deadline)


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return remaining


class _DeadlineTlsSocket(ssl.SSLSocket):
    deadline: float

    def send(self, data, flags=0):
        self.settimeout(_remaining(self.deadline))
        return super().send(data, flags)

    def recv_into(self, buffer, nbytes=0, flags=0):
        self.settimeout(_remaining(self.deadline))
        return super().recv_into(buffer, nbytes, flags)


class _ManagedPrivateHttpsResponse(http.client.HTTPResponse):
    def read(self, amt=None):
        data = super().read(amt)
        # Bounded HTTPResponse.read calls otherwise return EOF for a short body.
        if amt != 0 and not data and self.length:
            raise http.client.IncompleteRead(data, self.length)
        return data


class _ManagedPrivateHttpsConnection(http.client.HTTPConnection):
    # HTTPConnection builds an origin-form request. Always include the explicit port.
    default_port = None
    response_class = _ManagedPrivateHttpsResponse

    def __init__(
        self, endpoint: Endpoint, socket_path: str, context: ssl.SSLContext, deadline: float
    ):
        super().__init__(endpoint.host, endpoint.port)
        self._socket_path = socket_path
        self._context = context
        self._deadline = deadline

    def connect(self) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as raw:
            raw.settimeout(_remaining(self._deadline))
            raw.connect(self._socket_path)
            tls = self._context.wrap_socket(
                raw,
                server_hostname=self.host,
                do_handshake_on_connect=False,
            )
        self.sock = tls
        tls.deadline = self._deadline
        tls.settimeout(_remaining(self._deadline))
        tls.do_handshake()
        _remaining(self._deadline)


class ManagedPrivateHttpsTransport(_Base):
    """Fixed OpenAI-compatible endpoint reached through an installed Unix relay."""

    def __init__(
        self,
        base_url: str,
        socket_path: str | os.PathLike[str],
        *,
        ca_pem: str | bytes | None = None,
        check_admission: Callable[[], None] | None = None,
        send_guard: Callable[[float], contextlib.AbstractContextManager[None]] | None = None,
    ):
        self._base_url = canonical_private_https_url(base_url)
        self._endpoint = Endpoint.from_url(self._base_url)
        self._check_admission = check_admission
        self._send_guard = send_guard
        self._socket_path = os.fspath(socket_path)
        if not os.path.isabs(self._socket_path) or "\x00" in self._socket_path:
            raise ValueError("invalid managed relay socket path")
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if ca_pem is None:
            self._context.load_default_certs()
        else:
            self._context.load_verify_locations(
                cadata=ca_pem.decode("ascii") if isinstance(ca_pem, bytes) else ca_pem
            )
        self._context.sslsocket_class = _DeadlineTlsSocket

    def request(self, endpoint, method, path, headers, body, *, timeout):
        if (
            endpoint != self._endpoint
            or (method, path) not in (("GET", "/models"), ("POST", "/chat/completions"))
            or any(name.lower() in ("host", "cache-control") for name in headers)
        ):
            raise TransportError("unsafe")
        if not math.isfinite(timeout) or timeout <= 0:
            raise TransportError("connect")
        deadline = time.monotonic() + timeout
        conn = _ManagedPrivateHttpsConnection(endpoint, self._socket_path, self._context, deadline)
        send_guard = self._send_guard
        response = self._exchange(
            conn,
            endpoint.prefix + path,
            method,
            {**headers, "Cache-Control": "no-store, no-cache"},
            body,
            deadline,
            check_admission=self._check_admission,
            send_guard=None if send_guard is None else lambda: send_guard(deadline),
        )
        # Older HTTPS gateways use EOF to delimit a JSON response. TLS still
        # authenticates every received record, and only a complete object may
        # succeed. HTTPResponse separately rejects short framed bodies.
        if (
            200 <= response.status < 300
            and "content-length" not in response.headers
            and "transfer-encoding" not in response.headers
            and _json_body(response.body) is None
        ):
            raise TransportError("io")
        return response


# ---- shared provider plumbing -----------------------------------------------------------


def _retry_after(headers: dict[str, str]) -> float:
    try:
        value = float(headers.get("retry-after", "0"))
    except ValueError:
        return 30.0
    return min(max(value, 0.0), MAX_RETRY_AFTER_S) if value == value else 30.0


def _json_body(data: bytes) -> dict | None:
    try:
        value = json.loads(data)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _count(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


class _HttpProvider:
    version = 1
    capabilities: tuple[str, ...] = ("complete.json", "models.list")

    def __init__(
        self,
        *,
        name: str,
        data_class: str,
        model: str,
        endpoint: Endpoint,
        transport: Transport,
        timeout_s: float = 60.0,
        max_input_bytes: int = 200_000,
    ):
        if not 0.1 <= timeout_s <= 600:
            raise ValueError("invalid timeout")
        self.name, self.data_class, self.model = name, data_class, model
        self.timeout_s, self.max_input_bytes = timeout_s, max_input_bytes
        self._endpoint, self._transport = endpoint, transport

    def __repr__(self) -> str:  # never expose endpoint or credentials
        return f"<{type(self).__name__} {self.name} model={self.model}>"

    def health(self) -> Health:
        return Health(ok=True)

    def _headers(self) -> dict[str, str]:
        return {"Content-Type": "application/json", "User-Agent": "steward/0.1"}

    def _send(self, method: str, path: str, payload: dict | None, timeout: float) -> HttpResponse:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        try:
            return self._transport.request(
                self._endpoint, method, path, self._headers(), body, timeout=timeout
            )
        except TransportError as exc:
            if exc.kind == "connect":
                raise InferenceError("unavailable", retryable=True, spend="none") from None
            if exc.kind == "connect_timeout":
                raise InferenceError("timeout", retryable=True, spend="none") from None
            if exc.kind == "unsafe":
                raise InferenceError("policy_denied", spend="none") from None
            if exc.kind == "timeout":
                raise InferenceError("timeout", retryable=True, spend="unknown") from None
            if exc.kind == "too_large":
                raise InferenceError("invalid_output", spend="unknown") from None
            raise InferenceError("unavailable", retryable=True, spend="unknown") from None

    def _checked(self, response: HttpResponse) -> dict:
        if 200 <= response.status < 300:
            data = _json_body(response.body)
            if data is None:
                raise InferenceError("invalid_output", spend="unknown")
            return data
        raise self._classify(response)

    def _classify(self, response: HttpResponse) -> InferenceError:
        status = response.status
        if status >= 500:
            return InferenceError("unavailable", retryable=True, spend="unknown")
        if status in (401, 403):
            return InferenceError("auth", spend="none")
        if status == 413:
            return InferenceError("context_limit", spend="none")
        if status == 429:
            return InferenceError(
                "rate_limited",
                retryable=True,
                retry_after_s=_retry_after(response.headers),
                spend="none",
            )
        if 300 <= status < 400:
            return InferenceError("unsupported", spend="none")  # redirects are never followed
        return InferenceError("bad_request", spend="none")

    def complete(
        self, system: str, user: str, *, schema: dict, max_output_tokens: int, timeout_s: float
    ) -> RawCompletion:
        raise NotImplementedError

    def list_models(self, timeout_s: float = 10.0) -> list[str]:
        raise NotImplementedError


# ---- Ollama ----------------------------------------------------------------------------


class _OllamaHttp(_HttpProvider):
    def _classify(self, response: HttpResponse) -> InferenceError:
        if response.status == 404:
            return InferenceError("model_unavailable", spend="none")
        return super()._classify(response)

    def _chat_payload(self, system, user) -> dict:
        return {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
        }

    def _chat(self, payload, timeout_s) -> tuple[dict, dict, Usage]:
        data = self._checked(self._send("POST", "/api/chat", payload, timeout_s))
        message = data.get("message")
        usage = Usage(_count(data.get("prompt_eval_count")), _count(data.get("eval_count")))
        if (
            not isinstance(message, dict)
            or not isinstance(message.get("content"), str)
            or data.get("done") is not True
        ):
            raise InferenceError("invalid_output", spend="known", usage=usage)
        return data, message, usage

    def list_models(self, timeout_s: float = 10.0) -> list[str]:
        data = self._checked(self._send("GET", "/api/tags", None, timeout_s))
        models = data.get("models")
        if not isinstance(models, list):
            raise InferenceError("invalid_output", spend="none")
        return sorted(
            {m["name"] for m in models if isinstance(m, dict) and isinstance(m.get("name"), str)}
        )


class OllamaProvider(_OllamaHttp):
    """Local Ollama on loopback. Never pulls or creates models: the configured model
    must already be installed (A02: no uncontrolled downloads)."""

    def __init__(
        self,
        model: str,
        *,
        base_url: str = OLLAMA_URL,
        num_ctx: int = OLLAMA_NUM_CTX,
        transport: Transport | None = None,
        timeout_s: float = 120.0,
        require_exact_model: bool = False,
    ):
        endpoint = Endpoint.from_url(base_url)
        if endpoint.scheme != "http" or not is_loopback_host(endpoint.host):
            raise ValueError("ollama endpoint must be an http loopback address")
        if not 512 <= num_ctx <= 262144:
            raise ValueError("invalid context size")
        super().__init__(
            name="ollama",
            data_class="local",
            model=model,
            endpoint=endpoint,
            transport=transport
            or (_ManagedOllamaTransport() if require_exact_model else LoopbackTransport()),
            timeout_s=timeout_s,
            max_input_bytes=int(num_ctx * 1.5),
        )
        self.num_ctx = num_ctx
        self._require_exact_model = require_exact_model

    def complete(self, system, user, *, schema, max_output_tokens, timeout_s):
        payload = {
            **self._chat_payload(system, user),
            "format": wire_schema(schema),
            "options": {
                "num_predict": max_output_tokens,
                "num_ctx": self.num_ctx,
                "temperature": 0,
                "seed": 0,
            },
        }
        data, message, usage = self._chat(payload, timeout_s)
        if self._require_exact_model and data.get("model") != self.model:
            raise InferenceError("model_unavailable", spend="known", usage=usage)
        if usage.input_tokens is not None and usage.input_tokens >= self.num_ctx:
            # Ollama truncates silently when the prompt fills the context window.
            raise InferenceError("context_limit", spend="known", usage=usage)
        if data.get("done_reason") == "length":
            raise InferenceError("invalid_output", spend="known", usage=usage)
        return RawCompletion(message["content"], usage, str(data.get("model") or self.model)[:128])


class OllamaCloudProvider(_OllamaHttp):
    """Direct Ollama Cloud API with a Bearer key and locally validated JSON output."""

    def __init__(
        self,
        api_key: str,
        model: str,
        *,
        transport: Transport | None = None,
        timeout_s: float = 60.0,
    ):
        if not api_key or not api_key.isascii() or not api_key.isprintable() or " " in api_key:
            raise ValueError("a valid API key is required")
        super().__init__(
            name="ollama-cloud-api",
            data_class="external",
            model=model,
            endpoint=Endpoint.from_url(OLLAMA_CLOUD_URL),
            transport=transport or PublicHttpsTransport(),
            timeout_s=timeout_s,
        )
        self._key = api_key

    def _headers(self) -> dict[str, str]:
        return {**super()._headers(), "Authorization": f"Bearer {self._key}"}

    def complete(self, system, user, *, schema, max_output_tokens, timeout_s):
        if len((system + user).encode()) > self.max_input_bytes:
            raise InferenceError("context_limit", spend="none")
        payload = {
            **self._chat_payload(system, user),
            "options": {"num_predict": max_output_tokens},
        }
        data, message, usage = self._chat(payload, min(timeout_s, self.timeout_s))
        text = message["content"]
        if (
            "error" in data
            or data.get("done_reason", "stop") != "stop"
            or message.get("tool_calls") not in (None, [])
            or self._key in text
        ):
            raise InferenceError("invalid_output", spend="known", usage=usage)
        model = self.model
        reported_model = data.get("model")
        if isinstance(reported_model, str) and self._key not in reported_model:
            with contextlib.suppress(ValidationError):
                model = _MODEL_NAME.validate_python(reported_model)
        return RawCompletion(text, usage, model)

    def list_models(self, timeout_s: float = 10.0) -> list[str]:
        return super().list_models(min(timeout_s, self.timeout_s))


# ---- OpenAI and OpenAI-compatible --------------------------------------------------------


class _ChatCompletions(_HttpProvider):
    official = False

    def __init__(self, *, api_key: str | None, **kw):
        super().__init__(**kw)
        self._key = api_key

    def _headers(self):
        headers = super()._headers()
        if self._key:
            headers["Authorization"] = f"Bearer {self._key}"
        return headers

    def _classify(self, response):
        body = _json_body(response.body) or {}
        error = body.get("error") if isinstance(body.get("error"), dict) else {}
        code, kind = str(error.get("code") or ""), str(error.get("type") or "")
        status = response.status
        if status == 429 and "insufficient_quota" in (code, kind):
            return InferenceError("quota", spend="none")
        if status == 400 and code == "context_length_exceeded":
            return InferenceError("context_limit", spend="none")
        if status == 404:
            if code == "model_not_found":
                return InferenceError("model_unavailable", spend="none")
            return InferenceError("unsupported", spend="none")
        return super()._classify(response)

    def _payload(self, system, user, schema, max_output_tokens) -> dict:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if self.official:
            payload["max_completion_tokens"] = max_output_tokens
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "result", "strict": True, "schema": wire_schema(schema)},
            }
        else:  # unknown servers: only the most widely implemented fields
            payload["max_tokens"] = max_output_tokens
            payload["temperature"] = 0
        return payload

    def complete(self, system, user, *, schema, max_output_tokens, timeout_s):
        payload = self._payload(system, user, schema, max_output_tokens)
        data = self._checked(self._send("POST", "/chat/completions", payload, timeout_s))
        raw_usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        usage = Usage(
            _count(raw_usage.get("prompt_tokens")), _count(raw_usage.get("completion_tokens"))
        )
        choices = data.get("choices")
        choice = choices[0] if isinstance(choices, list) and choices else None
        message = choice.get("message") if isinstance(choice, dict) else None
        if not isinstance(message, dict):
            raise InferenceError("invalid_output", spend="known", usage=usage)
        if message.get("refusal") or choice.get("finish_reason") == "content_filter":
            raise InferenceError("refused", spend="known", usage=usage)
        text = message.get("content")
        if not isinstance(text, str) or choice.get("finish_reason") not in ("stop", None):
            raise InferenceError("invalid_output", spend="known", usage=usage)
        return RawCompletion(text, usage, str(data.get("model") or self.model)[:128])

    def list_models(self, timeout_s: float = 10.0) -> list[str]:
        data = self._checked(self._send("GET", "/models", None, timeout_s))
        rows = data.get("data")
        if not isinstance(rows, list):
            raise InferenceError("unsupported", spend="none")
        return sorted(
            {r["id"] for r in rows if isinstance(r, dict) and isinstance(r.get("id"), str)}
        )


class OpenAIProvider(_ChatCompletions):
    """Official OpenAI API (fixed endpoint). Structured output is requested natively."""

    official = True
    capabilities = ("complete.json", "complete.json_schema", "models.list")

    def __init__(self, api_key: str, model: str, *, transport: Transport | None = None, **kw):
        if not api_key:
            raise ValueError("an API key is required")
        super().__init__(
            api_key=api_key,
            name="openai",
            data_class="external",
            model=model,
            endpoint=Endpoint.from_url(OPENAI_BASE),
            transport=transport or PublicHttpsTransport(),
            **kw,
        )


class OpenAICompatibleProvider(_ChatCompletions):
    """Self-hosted or third-party endpoint. Capabilities are probed, never assumed."""

    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        api_key: str | None = None,
        transport: Transport | None = None,
        **kw,
    ):
        if isinstance(transport, ManagedPrivateHttpsTransport):
            base_url = canonical_private_https_url(base_url)
            if base_url != transport._base_url:
                raise ValueError("provider URL must match the managed private HTTPS endpoint")
        endpoint = Endpoint.from_url(base_url)
        local = is_loopback_host(endpoint.host)
        super().__init__(
            api_key=api_key,
            name="openai-compatible",
            data_class="local" if local else "external",
            model=model,
            endpoint=endpoint,
            transport=transport or (LoopbackTransport() if local else PublicHttpsTransport()),
            **kw,
        )

    def probe(self, timeout_s: float = 10.0) -> dict[str, bool]:
        """Observed capabilities of the endpoint (used by the acceptance gate)."""
        try:
            models = self.list_models(timeout_s)
        except InferenceError:
            return {"models.list": False, "model.listed": False}
        return {"models.list": True, "model.listed": self.model in models}


# ---- Anthropic ------------------------------------------------------------------------


class AnthropicProvider(_HttpProvider):
    """Official Claude API (Messages). The model is always configured explicitly."""

    def __init__(self, api_key: str, model: str, *, transport: Transport | None = None, **kw):
        if not api_key:
            raise ValueError("an API key is required")
        super().__init__(
            name="anthropic",
            data_class="external",
            model=model,
            endpoint=Endpoint.from_url(ANTHROPIC_BASE),
            transport=transport or PublicHttpsTransport(),
            **kw,
        )
        self._key = api_key

    def _headers(self):
        headers = super()._headers()
        headers["x-api-key"] = self._key
        headers["anthropic-version"] = ANTHROPIC_VERSION
        return headers

    def _classify(self, response):
        body = _json_body(response.body) or {}
        error = body.get("error") if isinstance(body.get("error"), dict) else {}
        kind, message = str(error.get("type") or ""), str(error.get("message") or "").lower()
        status = response.status
        if status == 402 or kind == "billing_error" or "credit balance" in message:
            return InferenceError("quota", spend="none")
        if status == 404 or kind == "not_found_error":
            return InferenceError("model_unavailable", spend="none")
        if status == 413 or (status == 400 and ("too long" in message or "context" in message)):
            return InferenceError("context_limit", spend="none")
        if status == 529 or kind == "overloaded_error":
            return InferenceError("unavailable", retryable=True, spend="unknown")
        return super()._classify(response)

    def complete(self, system, user, *, schema, max_output_tokens, timeout_s):
        # The closed schema is part of the system text and enforced locally; native
        # structured-output parameters are intentionally not sent (shape unverified).
        payload = {
            "model": self.model,
            "max_tokens": max_output_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        data = self._checked(self._send("POST", "/v1/messages", payload, timeout_s))
        raw_usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        first = _count(raw_usage.get("input_tokens"))
        cached = [
            _count(raw_usage.get(k) or 0)
            for k in ("cache_creation_input_tokens", "cache_read_input_tokens")
        ]
        input_tokens = None if first is None or None in cached else first + sum(cached)
        usage = Usage(input_tokens, _count(raw_usage.get("output_tokens")))
        stop = data.get("stop_reason")
        if stop == "refusal":
            raise InferenceError("refused", spend="known", usage=usage)
        blocks = data.get("content")
        if stop not in ("end_turn", "stop_sequence") or not isinstance(blocks, list):
            # max_tokens (truncated), tool_use/pause_turn (no tools were offered), unknown
            raise InferenceError("invalid_output", spend="known", usage=usage)
        text = "".join(
            b["text"]
            for b in blocks
            if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str)
        )
        return RawCompletion(text, usage, str(data.get("model") or self.model)[:128])

    def list_models(self, timeout_s: float = 10.0) -> list[str]:
        data = self._checked(self._send("GET", "/v1/models?limit=1000", None, timeout_s))
        rows = data.get("data")
        if not isinstance(rows, list):
            raise InferenceError("unsupported", spend="none")
        return sorted(
            {r["id"] for r in rows if isinstance(r, dict) and isinstance(r.get("id"), str)}
        )


# ---- factory --------------------------------------------------------------------------


def build_provider(ai: Ai, *, env=None, transport: Transport | None = None) -> InferenceProvider:
    """Construct the configured provider; secrets are resolved here, by reference only.

    Refuses external providers under `local_only`, so no code path can open an
    external connection for a local-only configuration."""
    if ai.provider == "none":
        raise ValueError("no inference provider configured")
    if ai.provider != "ollama" and ai.provider not in AI_EXTERNAL_PROVIDERS:
        raise InferenceError("unsupported", spend="none")
    if ai.is_external and ai.local_only:
        raise InferenceError("policy_denied", spend="none")
    assert ai.model is not None  # enforced by the configuration model
    try:
        key = resolve(ai.api_key_ref, env) if ai.api_key_ref else None
    except SecretError:
        raise InferenceError("auth", spend="none") from None
    if ai.provider == "ollama":
        return OllamaProvider(ai.model, base_url=ai.base_url or OLLAMA_URL, transport=transport)
    if ai.provider == "ollama-cloud-api":
        try:
            return OllamaCloudProvider(key or "", ai.model, transport=transport)
        except ValueError:
            raise InferenceError("auth", spend="none") from None
    if ai.provider == "openai":
        return OpenAIProvider(key or "", ai.model, transport=transport)
    if ai.provider == "anthropic":
        return AnthropicProvider(key or "", ai.model, transport=transport)
    return OpenAICompatibleProvider(ai.base_url or "", ai.model, api_key=key, transport=transport)
