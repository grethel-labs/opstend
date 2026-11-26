"""Bounded, UID-pinned transport for the inference worker's admin control."""

from __future__ import annotations

import json
import math
import socket
import socketserver
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..executor import protocol
from ..executor.protocol import ExecutorError
from . import ipc
from .ids import valid_request_id

_IO_TIMEOUT_S = 2.0
_ERROR = b'{"ok":false,"error_class":"unavailable","message":"AI admin unavailable"}\n'
MANAGED_SOCKET = "/run/steward-inference-admin/admin.sock"
CANDIDATE_SCOPE_CODE = "candidate_scope_refused"


def _validate_uid(uid: int) -> None:
    if type(uid) is not int or not 0 <= uid < 2**32 - 1:
        raise ValueError("invalid AI admin peer UID")


@dataclass(frozen=True)
class AdminPeer:
    socket_path: str
    expected_peer_uid: int

    def __post_init__(self) -> None:
        _validate_uid(self.expected_peer_uid)

    def __call__(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        try:
            return protocol.call(
                action,
                params,
                socket_path=self.socket_path,
                expected_peer_uid=self.expected_peer_uid,
                timeout=_IO_TIMEOUT_S,
                strict_response=True,
            )
        except ExecutorError as exc:
            raise ExecutorError(
                "unavailable", "AI admin unavailable", outcome_unknown=exc.outcome_unknown
            ) from None
        except (TypeError, ValueError, RecursionError):
            raise ExecutorError("unavailable", "AI admin unavailable") from None


def _read_frame(sock: socket.socket) -> bytes:
    deadline = time.monotonic() + _IO_TIMEOUT_S
    data = bytearray()
    # The strict client half-closes its write side after the frame. Wait for EOF
    # so trailing data cannot be accepted based on a recv boundary.
    while len(data) <= ipc.MAX_MESSAGE_BYTES:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        sock.settimeout(remaining)
        chunk = sock.recv(min(65536, ipc.MAX_MESSAGE_BYTES + 1 - len(data)))
        if not chunk:
            if data.endswith(b"\n") and data.count(b"\n") == 1:
                return bytes(data)
            break
        data.extend(chunk)
    raise ValueError("invalid request frame")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate request field")
        obj[key] = value
    return obj


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite request number")
    return number


def _decode_request(raw: bytes) -> dict[str, Any]:
    request = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_finite_float,
        parse_float=_finite_float,
    )
    if (
        type(request) is not dict
        or request.keys() != {"v", "action", "params", "request_id", "expires_at"}
        or type(request["v"]) is not int
        or request["v"] != protocol.PROTOCOL_VERSION
        or type(request["action"]) is not str
        or not 1 <= len(request["action"]) <= 80
        or type(request["params"]) is not dict
        or not valid_request_id(request["request_id"])
    ):
        raise ValueError("invalid request envelope")
    expiry = request["expires_at"]
    now = time.time()
    if type(expiry) not in (int, float) or not now <= expiry <= now + protocol.REQUEST_TTL_S + 5:
        raise ValueError("invalid request expiry")
    return request


class _AdminRequestHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: _AdminServer = self.server
        try:
            # The shared helper decodes uid_t with a signed integer format.
            if ipc.peer_uid(self.request) & 0xFFFFFFFF != server.admin_uid:
                return
            request = _decode_request(_read_frame(self.request))
            result = server.dispatch(request["action"], request["params"])
            response = json.dumps({"ok": True, "result": result}, allow_nan=False).encode() + b"\n"
            if len(response) > ipc.MAX_MESSAGE_BYTES:
                response = _ERROR
        except Exception:
            response = _ERROR
        try:
            self.request.settimeout(_IO_TIMEOUT_S)
            self.request.sendall(response)
        except OSError:
            pass


class _AdminServer(socketserver.UnixStreamServer):
    """Serve short control calls serially over a manager-owned listener."""

    def __init__(
        self,
        listener: socket.socket,
        admin_uid: int,
        dispatch: Callable[[str, object], dict],
    ):
        self.admin_uid = admin_uid
        self.dispatch = dispatch
        # Initialize the request loop without TCPServer's temporary socket.
        socketserver.BaseServer.__init__(self, listener.getsockname(), _AdminRequestHandler)
        self.socket = listener.dup()
