"""Notification contract v1 and bounded HTTPS transports.

DNS is resolved and checked for every connection. The TLS socket connects to
that exact checked address, retaining the original hostname for certificate
verification and SNI. Redirects and environment proxies are never followed.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import http.client
import ipaddress
import json
import math
import re
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

VERSION = 1
TIMEOUT_S = 10
MAX_RESPONSE = 16384


@dataclass(frozen=True)
class Result:
    confirmed: bool = False
    error_class: str | None = None
    retry_after_s: float = 0
    permanent: bool = False


class NotificationAdapter(Protocol):
    version: int
    capabilities: tuple[str, ...]
    input_schema: dict
    timeout_s: float

    def health(self) -> Result: ...

    def send(self, key: str, payload: dict) -> Result: ...


class UnsafeTarget(ValueError):
    pass


def target(url: str) -> tuple[str, str]:
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.port not in (None, 443)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or any(ord(c) <= 32 or ord(c) >= 127 for c in url)
            or "\\" in url
        ):
            raise UnsafeTarget("only public HTTPS targets on port 443 are allowed")
        host = parsed.hostname
        if not re.fullmatch(r"[a-zA-Z0-9.-]+", host) or host.endswith("."):
            raise UnsafeTarget("invalid hostname")
        return host, (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
    except ValueError:
        raise UnsafeTarget("invalid HTTPS target") from None


def public_addresses(host: str) -> list[str]:
    addresses = list(
        dict.fromkeys(row[4][0] for row in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM))
    )

    def permitted(value: str) -> bool:
        ip = ipaddress.ip_address(value)
        return (
            ip.is_global
            and not ip.is_multicast
            and not ip.is_reserved
            and not any(
                ip in ipaddress.ip_network(net)
                for net in (
                    "64:ff9b::/96",
                    "64:ff9b:1::/48",
                    "2002::/16",
                    "2001::/32",
                )
            )
            if ip.version == 6
            else ip.is_global and not ip.is_multicast and not ip.is_reserved
        )

    if not addresses or not all(permitted(ip) for ip in addresses):
        raise UnsafeTarget("target resolves to a non-public address")
    return addresses


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str):
        super().__init__(host, timeout=TIMEOUT_S, context=ssl.create_default_context())
        self.address = address

    def connect(self) -> None:
        raw = socket.create_connection((self.address, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def post(url: str, body: bytes, headers: dict[str, str]) -> tuple[int, dict, bytes]:
    host, path = target(url)
    addresses = public_addresses(host)
    connection = _PinnedHTTPS(host, addresses[0])
    try:
        connection.request(
            "POST",
            path,
            body,
            {
                **headers,
                "Content-Type": "application/json",
                "User-Agent": "steward/0.1",
            },
        )
        response = connection.getresponse()
        data = response.read(MAX_RESPONSE + 1)
        if len(data) > MAX_RESPONSE:
            raise ValueError("response too large")
        return response.status, {k.lower(): v for k, v in response.getheaders()}, data
    finally:
        connection.close()


def validate_message(key: str, payload: dict) -> str:
    if not isinstance(key, str) or not 1 <= len(key) <= 200 or not isinstance(payload, dict):
        raise ValueError("invalid message")
    summary = payload.get("summary")
    if not isinstance(summary, str) or not 1 <= len(summary) <= 2000:
        raise ValueError("invalid summary")
    return summary


def _result(status: int, headers: dict, data: bytes) -> Result:
    if 200 <= status < 300:
        return Result(confirmed=True)
    if status == 429:
        try:
            delay = float(headers.get("retry-after", "0"))
            with contextlib.suppress(ValueError, TypeError, AttributeError):
                delay = max(delay, float(json.loads(data).get("retry_after", 0)))
            if not math.isfinite(delay):
                delay = 60
        except (ValueError, TypeError):
            delay = 60
        return Result(error_class="rate_limited", retry_after_s=max(1, delay))
    return Result(
        error_class="unavailable" if status >= 500 else "rejected", permanent=status < 500
    )


class SignedWebhook:
    version = VERSION
    capabilities = ("notification.send", "notification.signed")
    timeout_s = TIMEOUT_S
    input_schema = {
        "type": "object",
        "required": ["summary"],
        "properties": {"summary": {"type": "string", "minLength": 1, "maxLength": 2000}},
    }

    def __init__(self, url: str, secret: str):
        target(url)
        if len(secret.encode()) < 32:
            raise ValueError("signing key must contain at least 32 bytes")
        self.url, self.secret = url, secret.encode()

    def health(self) -> Result:
        """Local configuration health only; does not send a probe notification."""
        try:
            host, _ = target(self.url)
            public_addresses(host)
            return Result(confirmed=True)
        except UnsafeTarget:
            return Result(error_class="unsafe_target", permanent=True)
        except OSError:
            return Result(error_class="unavailable")

    def _request(self, key: str, payload: dict) -> tuple[bytes, dict]:
        validate_message(key, payload)
        body = json.dumps(
            {"v": VERSION, "id": key, "payload": payload},
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        stamp = str(int(time.time()))
        signature = hmac.new(self.secret, stamp.encode() + b"." + body, hashlib.sha256).hexdigest()
        return body, {"X-Steward-Timestamp": stamp, "X-Steward-Signature": f"v1={signature}"}

    def send(self, key: str, payload: dict) -> Result:
        try:
            body, headers = self._request(key, payload)
            if len(body) > 20000:
                return Result(error_class="invalid_message", permanent=True)
            return _result(*post(self.url, body, headers))
        except UnsafeTarget:
            return Result(error_class="unsafe_target", permanent=True)
        except (OSError, http.client.HTTPException):
            return Result(error_class="unavailable")
        except (ValueError, TypeError):
            return Result(error_class="invalid_message", permanent=True)


class DiscordWebhook(SignedWebhook):
    """Discord incoming webhook: wait for acknowledgment and suppress mentions."""

    capabilities = ("notification.send", "notification.confirmed_message")

    def __init__(self, url: str):
        host, path = target(url)
        if host != "discord.com" or not re.fullmatch(
            r"/api(?:/v10)?/webhooks/[0-9]+/[A-Za-z0-9_-]+", path
        ):
            raise UnsafeTarget("expected a Discord webhook URL without query parameters")
        self.url = url + "?wait=true"

    def _request(self, key: str, payload: dict) -> tuple[bytes, dict]:
        content = validate_message(key, payload)
        if not content or len(content.encode("utf-16-le")) // 2 > 2000:
            raise ValueError("Discord content must contain 1..2000 characters")
        return json.dumps({"content": content, "allowed_mentions": {"parse": []}}).encode(), {}

    def send(self, key: str, payload: dict) -> Result:
        # Discord's wait=true must return the created message, not just a 2xx.
        try:
            body, headers = self._request(key, payload)
            status, response_headers, data = post(self.url, body, headers)
            result = _result(status, response_headers, data)
            if result.confirmed:
                message = json.loads(data)
                if not isinstance(message, dict) or not message.get("id"):
                    return Result(error_class="unconfirmed")
            return result
        except UnsafeTarget:
            return Result(error_class="unsafe_target", permanent=True)
        except (OSError, http.client.HTTPException):
            return Result(error_class="unavailable")
        except (ValueError, TypeError):
            return Result(error_class="invalid_message", permanent=True)
