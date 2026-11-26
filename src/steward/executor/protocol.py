"""Wire protocol between unprivileged components and the host executor.

One JSON request line, one JSON response line, over a Unix stream socket. The
executor identifies callers by kernel-provided peer credentials, never by
anything inside the request.
"""

from __future__ import annotations

import json
import socket
import struct
import time
import uuid
from typing import Any

PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 256 * 1024
DEFAULT_SOCKET = "/run/steward-executor/executor.sock"
REQUEST_TTL_S = 120

# Stable error classes. Clients may branch on these; messages are informational.
ERROR_CLASSES = (
    "bad_request",
    "conflict",
    "unauthorized_peer",
    "forbidden_role",
    "unknown_action",
    "policy_denied",
    "kill_switch",
    "expired",
    "replay",
    "target_busy",
    "budget_exhausted",
    "execution_failed",
    "unavailable",
    "internal",
)


def update_call_timeout(verify_timeout_s: int) -> float:
    """Client timeout for apply/rollback: fetch, capture, verify and a verified revert."""
    return float(min(1800, 600 + 2 * int(verify_timeout_s) + 120))


RETRYABLE = {"target_busy", "unavailable", "internal"}


class ExecutorError(Exception):
    def __init__(self, error_class: str, message: str, *, outcome_unknown: bool = False):
        assert error_class in ERROR_CLASSES
        super().__init__(f"{error_class}: {message}")
        self.error_class = error_class
        self.message = message
        # True when the request may have been executed (client timeout, dropped
        # connection): the caller must re-read state, never assume failure.
        self.outcome_unknown = outcome_unknown

    @property
    def retryable(self) -> bool:
        return self.error_class in RETRYABLE


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate response field")
        obj[key] = value
    return obj


def _strict_result(frame: bytes) -> dict[str, Any]:
    invalid = ExecutorError("internal", "malformed response", outcome_unknown=True)
    try:
        if not frame.endswith(b"\n") or frame.count(b"\n") != 1:
            raise ValueError("invalid frame")
        response = json.loads(frame.decode("utf-8"), object_pairs_hook=_unique_fields)
        # Reject non-finite numbers and strings that cannot be sent as UTF-8 JSON.
        json.dumps(response, allow_nan=False, ensure_ascii=False).encode("utf-8")
    except (ValueError, RecursionError):
        raise invalid from None
    if isinstance(response, dict):
        if response.keys() == {"ok", "result"} and response["ok"] is True:
            if isinstance(response["result"], dict):
                return response["result"]
        elif response.keys() == {"ok", "error_class", "message"} and response["ok"] is False:
            error_class, message = response["error_class"], response["message"]
            if error_class in ERROR_CLASSES and isinstance(message, str) and len(message) <= 500:
                raise ExecutorError(
                    error_class,
                    "peer refused request",
                    outcome_unknown=error_class in ("internal", "unavailable"),
                )
    raise invalid


def call(
    action: str,
    params: dict[str, Any] | None = None,
    *,
    socket_path: str = DEFAULT_SOCKET,
    timeout: float = 60.0,
    request_id: str | None = None,
    expected_peer_uid: int | None = None,
    strict_response: bool = False,
) -> dict[str, Any]:
    """Send one request. A pinned peer UID also makes timeout a total I/O deadline.

    The strict AI admin path bounds both frames and half-closes after writing.
    """
    deadline = None if expected_peer_uid is None else time.monotonic() + timeout

    def remaining() -> float:
        if deadline is None:
            return timeout
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise TimeoutError("request deadline exceeded")
        return seconds

    request = {
        "v": PROTOCOL_VERSION,
        "action": action,
        "params": params or {},
        "request_id": request_id or uuid.uuid4().hex,
        "expires_at": time.time() + REQUEST_TTL_S,
    }
    sending = False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(remaining())
            sock.connect(socket_path)
            if expected_peer_uid is not None:
                credentials = struct.Struct("iII")
                _, uid, _ = credentials.unpack(
                    sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, credentials.size)
                )
                if uid != expected_peer_uid:
                    raise ExecutorError("unauthorized_peer", "unexpected socket peer UID")
            data = json.dumps(request).encode() + b"\n"
            if strict_response and len(data) > MAX_MESSAGE_BYTES:
                raise ExecutorError("bad_request", "request too large")
            if deadline is not None:
                sock.settimeout(remaining())
            sending = True
            sock.sendall(data)
            if strict_response:
                sock.shutdown(socket.SHUT_WR)
            buf = b""
            while strict_response or not buf.endswith(b"\n"):
                if deadline is not None:
                    sock.settimeout(remaining())
                read_size = (
                    min(65536, MAX_MESSAGE_BYTES + 1 - len(buf)) if strict_response else 65536
                )
                chunk = sock.recv(read_size)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > MAX_MESSAGE_BYTES:
                    raise ExecutorError(
                        "internal", "response too large", outcome_unknown=strict_response
                    )
    except OSError as exc:
        if strict_response:
            raise ExecutorError("unavailable", "peer I/O failed", outcome_unknown=sending) from None
        raise ExecutorError(
            "unavailable",
            f"executor not reachable: {exc}",
            outcome_unknown=isinstance(exc, TimeoutError),
        ) from None
    if not buf.endswith(b"\n"):
        # The connection closed without a complete answer (executor killed or restarted).
        raise ExecutorError(
            "unavailable", "executor closed the connection without a response", outcome_unknown=True
        )
    if strict_response:
        return _strict_result(buf)
    try:
        response = json.loads(buf)
    except ValueError:
        raise ExecutorError("internal", "malformed response") from None
    if not isinstance(response, dict):
        raise ExecutorError("internal", "malformed response")
    if response.get("ok"):
        if expected_peer_uid is not None and not isinstance(response.get("result"), dict):
            raise ExecutorError("internal", "malformed response result")
        return response["result"]
    error_class = response.get("error_class")
    if error_class not in ERROR_CLASSES:
        error_class = "internal"
    raise ExecutorError(error_class, str(response.get("message", ""))[:500])
