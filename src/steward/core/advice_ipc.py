"""Dedicated, UID-pinned transport for the fixed advice task."""

from __future__ import annotations

import json
import math
import os
import pwd
import re
import socket
import socketserver
import struct
import time
from array import array
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from . import ipc
from .advice import ADVICE_TASK, QUESTION_CLASS, WINDOW_S
from .inference import ERROR_CLASSES, InferenceError, InferenceService, Outcome, Task
from .inference_schema import SchemaError, validate
from .inference_snapshot import Item, Scope

VERSION = 1
MAX_REQUEST_BYTES = ipc.MAX_MESSAGE_BYTES
MAX_REPLY_BYTES = 32 * 1024
CLIENT_TIMEOUT_S = 10.0
READ_TIMEOUT_S = 2.0
WORKER_TIMEOUT_S = 8.0
MANAGED_DIRECTORY = Path("/run/steward-inference-advice")
MANAGED_ROLES = ("bot", "api")
_PRELUDE = b"\x01"
_CREDENTIALS = struct.Struct("iII")


def managed_socket_path(role: Literal["bot", "api"]) -> Path:
    if role not in MANAGED_ROLES:
        raise ValueError("invalid managed advice role")
    return MANAGED_DIRECTORY / f"{role}.sock"


MAX_ITEMS = 1024
MAX_PROJECTS = 1024
MAX_OBSERVATION_CHARS = 16384
_PROJECT = re.compile(r"[a-z][a-z0-9-]{1,30}[a-z0-9]")
_SOURCES = {"controller", "collector"}
_CLASSES = {
    ("controller", "status"): "status",
    ("controller", "backup"): "backups",
    ("collector", "event"): "vulnerabilities",
    ("operator", "question"): "status",
}
_COVERAGE_KEYS = {
    "window",
    "sources",
    "missing_sources",
    "withheld_classes",
    "oldest",
    "newest",
    "truncated",
    "omitted_size",
}


def _validate_uid(uid: int) -> None:
    if type(uid) is not int or not 0 <= uid < 2**32 - 1:
        raise ValueError("invalid advice peer UID")


def _pin(sock: socket.socket, uid: int) -> None:
    # peer_uid decodes the unsigned kernel uid_t using a signed format.
    if ipc.peer_uid(sock) & 0xFFFFFFFF != uid:
        raise PermissionError("wrong advice peer UID")


def _set_remaining(sock: socket.socket, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    sock.settimeout(remaining)


def _read_prelude(sock: socket.socket, uid: int, deadline: float) -> None:
    _set_remaining(sock, deadline)
    data, ancillary, flags, _ = sock.recvmsg(
        len(_PRELUDE), socket.CMSG_SPACE(_CREDENTIALS.size), socket.MSG_CMSG_CLOEXEC
    )
    for level, kind, payload in ancillary:
        if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
            fds = array("i")
            fds.frombytes(payload[: len(payload) // fds.itemsize * fds.itemsize])
            for fd in fds:
                os.close(fd)
    if data != _PRELUDE or flags & ~socket.MSG_CMSG_CLOEXEC or len(ancillary) != 1:
        raise PermissionError("invalid advice credential prelude")
    level, kind, payload = ancillary[0]
    if (level, kind) != (socket.SOL_SOCKET, socket.SCM_CREDENTIALS) or len(
        payload
    ) != _CREDENTIALS.size:
        raise PermissionError("invalid advice credentials")
    pid, peer_uid, _gid = _CREDENTIALS.unpack(payload)
    if pid <= 0 or peer_uid != uid:
        raise PermissionError("wrong advice worker UID")

    # The authenticated worker waits for the request. Any queued byte or EOF is invalid.
    sock.setblocking(False)
    try:
        sock.recv(1, socket.MSG_PEEK)
    except BlockingIOError:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 0)
        return
    raise PermissionError("unexpected data after advice credential prelude")


def _send_prelude(sock: socket.socket, deadline: float) -> None:
    _set_remaining(sock, deadline)
    credentials = _CREDENTIALS.pack(os.getpid(), os.getuid(), os.getgid())
    ancillary = [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, credentials)]
    if sock.sendmsg([_PRELUDE], ancillary) != len(_PRELUDE):
        raise OSError("incomplete advice credential prelude")


def _read_frame(sock: socket.socket, limit: int, deadline: float) -> bytes:
    frame = bytearray()
    while len(frame) <= limit:
        _set_remaining(sock, deadline)
        chunk = sock.recv(min(65536, limit + 1 - len(frame)))
        if not chunk:
            if frame.endswith(b"\n") and frame.count(b"\n") == 1:
                return bytes(frame[:-1])
            break
        frame.extend(chunk)
    raise ValueError("invalid advice frame")


def _encode(value: dict, limit: int) -> bytes:
    frame = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    raw = frame.encode("utf-8") + b"\n"
    if len(raw) > limit:
        raise ValueError("advice frame exceeds limit")
    return raw


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate advice field")
        obj[key] = value
    return obj


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite advice number")
    return number


def _decode(raw: bytes) -> dict:
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_finite_float,
        parse_float=_finite_float,
    )
    if type(value) is not dict or type(value.get("v")) is not int or value["v"] != VERSION:
        raise ValueError("invalid advice envelope")
    # JSON escape sequences can introduce isolated surrogates even in valid UTF-8.
    json.dumps(value, ensure_ascii=False).encode("utf-8")
    return value


def _shape(value: object, keys: set[str]) -> None:
    if type(value) is not dict or value.keys() != keys:
        raise ValueError("invalid advice object shape")


def _number(value: object) -> bool:
    # Reject booleans and integers which cannot be represented as finite floats.
    return (
        type(value) in (int, float)
        and (type(value) is float or value.bit_length() <= 1023)
        and math.isfinite(value)
    )


def _slug(value: object) -> bool:
    return type(value) is str and _PROJECT.fullmatch(value) is not None


def _labels(value: object, allowed: set[str]) -> set[str]:
    if (
        type(value) is not list
        or len(value) > len(allowed)
        or any(type(label) is not str or label not in allowed for label in value)
        or len(set(value)) != len(value)
    ):
        raise ValueError("invalid advice labels")
    return set(value)


def _scope(value: dict) -> Scope:
    _shape(value, {"projects", "host", "since", "until"})
    projects, host = value["projects"], value["host"]
    since, until = value["since"], value["until"]
    if (
        type(host) is not bool
        or type(projects) is not list
        or len(projects) > MAX_PROJECTS
        or not all(_slug(project) for project in projects)
        or len(set(projects)) != len(projects)
        or not (host or projects)
        or not (_number(since) and _number(until) and since == until - WINDOW_S)
    ):
        raise ValueError("invalid advice scope")
    return Scope(frozenset(projects), host, since, until)


def _item(value: dict, scope: Scope, expected: set[str]) -> Item:
    _shape(value, {"source", "kind", "data_class", "observed_at", "text", "project"})
    item = Item(**value)
    if (
        type(item.source) is not str
        or type(item.kind) is not str
        or type(item.data_class) is not str
        or _CLASSES.get((item.source, item.kind)) != item.data_class
        or item.source not in expected | {"operator"}
        or not _number(item.observed_at)
        or type(item.text) is not str
        or len(item.text) > MAX_OBSERVATION_CHARS
    ):
        raise ValueError("invalid advice item")
    if item.project is None:
        if not scope.host or item.kind == "backup":
            raise ValueError("invalid host item")
    elif not _slug(item.project) or item.project not in scope.projects:
        raise ValueError("item outside advice scope")
    if item.source == "operator" and (
        item.observed_at != scope.until or not 1 <= len(item.text) <= 500
    ):
        raise ValueError("invalid advice question")
    return item


def _request(value: dict) -> tuple[list[Item], Scope, tuple[str, ...], float]:
    _shape(value, {"v", "expires_at", "scope", "expected_sources", "items"})
    scope = _scope(value["scope"])
    sources = _labels(value["expected_sources"], _SOURCES)
    expiry = value["expires_at"]
    rows = value["items"]
    if (
        "controller" not in sources
        or not _number(expiry)
        or type(rows) is not list
        or not 1 <= len(rows) <= MAX_ITEMS
    ):
        raise ValueError("invalid advice request")
    items = [_item(row, scope, sources) for row in rows]
    if sum(item.source == "operator" for item in items) != 1:
        raise ValueError("expected one advice question")
    return items, scope, tuple(value["expected_sources"]), expiry


def _reply(raw: bytes, scope: Scope, expected_sources: tuple[str, ...]) -> Outcome:
    value = _decode(raw)
    if value.get("ok") is False:
        _shape(value, {"v", "ok", "error_class"})
        error = value["error_class"]
        if type(error) is not str or error not in ERROR_CLASSES:
            raise ValueError("unknown advice error class")
        return Outcome(False, error_class=error)

    _shape(value, {"v", "ok", "data", "coverage"})
    if value["ok"] is not True:
        raise ValueError("invalid advice reply")
    data = validate(value["data"], ADVICE_TASK.schema)
    coverage = value["coverage"]
    _shape(coverage, _COVERAGE_KEYS)
    window = coverage["window"]
    _shape(window, {"since", "until"})
    if not (
        _number(window["since"])
        and _number(window["until"])
        and window == {"since": scope.since, "until": scope.until}
    ):
        raise ValueError("invalid advice coverage window")
    expected = set(expected_sources)
    present = _labels(coverage["sources"], expected | {"operator"})
    missing = _labels(coverage["missing_sources"], expected)
    _labels(coverage["withheld_classes"], set(_CLASSES.values()))
    oldest, newest = coverage["oldest"], coverage["newest"]
    count, truncated = coverage["omitted_size"], coverage["truncated"]
    if (
        missing & present
        or type(count) is not int
        or not 0 <= count <= MAX_ITEMS
        or type(truncated) is not bool
        or truncated != bool(count)
        or (not truncated and expected - present != missing)
        or not (
            (not present and oldest is None and newest is None)
            or (
                present
                and _number(oldest)
                and _number(newest)
                and scope.since <= oldest <= newest <= scope.until
                and ("operator" not in present or newest == scope.until)
            )
        )
    ):
        raise ValueError("invalid advice coverage")
    return Outcome(True, data, coverage=coverage)


@dataclass(frozen=True)
class AdvicePeer:
    socket_path: str
    expected_peer_uid: int
    worker_uid: int | None = None

    def __post_init__(self) -> None:
        _validate_uid(self.expected_peer_uid)
        if self.worker_uid is not None:
            _validate_uid(self.worker_uid)
            if self.worker_uid == 0 or self.expected_peer_uid != 0:
                raise ValueError("managed advice needs a root listener and non-root worker")

    def __call__(
        self,
        task: Task,
        items: list[Item],
        scope: Scope,
        *,
        expected_sources: tuple[str, ...] = (),
        all_projects: tuple[str, ...] = (),
    ) -> Outcome:
        # Advisor masks identifiers before transport. Its catalog stays bot-local.
        if task is not ADVICE_TASK:
            return Outcome(False, error_class="bad_request")
        deadline = time.monotonic() + CLIENT_TIMEOUT_S
        try:
            if len(items) > MAX_ITEMS or len(scope.projects) > MAX_PROJECTS:
                raise ValueError("advice request exceeds count limits")
            value = {
                "v": VERSION,
                "expires_at": deadline,
                "scope": {
                    "projects": sorted(scope.projects),
                    "host": scope.host,
                    "since": scope.since,
                    "until": scope.until,
                },
                "items": [asdict(item) for item in items],
                "expected_sources": list(expected_sources),
            }
            _request(value)
            request = _encode(value, MAX_REQUEST_BYTES)
        except (ValueError, TypeError, RecursionError):
            return Outcome(False, error_class="bad_request")

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                if self.worker_uid is not None:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                _set_remaining(sock, deadline)
                sock.connect(self.socket_path)
                _pin(sock, self.expected_peer_uid)
                if self.worker_uid is not None:
                    prelude_deadline = min(deadline, time.monotonic() + READ_TIMEOUT_S)
                    _read_prelude(sock, self.worker_uid, prelude_deadline)
                _set_remaining(sock, deadline)
                sock.sendall(request)
                sock.shutdown(socket.SHUT_WR)
                raw = _read_frame(sock, MAX_REPLY_BYTES, deadline)
            outcome = _reply(raw, scope, expected_sources)
            if time.monotonic() >= deadline:
                raise TimeoutError
            return outcome
        except TimeoutError:
            return Outcome(False, error_class="timeout")
        except (OSError, TypeError, ValueError, RecursionError, SchemaError):
            error = "timeout" if time.monotonic() >= deadline else "unavailable"
            return Outcome(False, error_class=error)


def managed_advice_peer(role: Literal["bot", "api"]) -> AdvicePeer:
    path = managed_socket_path(role)
    worker = pwd.getpwnam("steward-inference")
    if not 0 < worker.pw_uid < 2**32 - 1:
        raise PermissionError("invalid managed inference identity")
    return AdvicePeer(str(path), expected_peer_uid=0, worker_uid=worker.pw_uid)


def _failure(error_class: str) -> dict:
    return {"v": VERSION, "ok": False, "error_class": error_class}


class _AdviceRequestHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: AdviceServer = self.server
        sock = self.request
        read_deadline = time.monotonic() + READ_TIMEOUT_S
        try:
            _pin(sock, server.bot_uid)
            if server.managed:
                _send_prelude(sock, read_deadline)
        except OSError:
            return
        deadline = read_deadline
        try:
            raw = _read_frame(sock, MAX_REQUEST_BYTES, read_deadline)
            deadline = time.monotonic() + WORKER_TIMEOUT_S
            items, scope, sources, expiry = _request(_decode(raw))
            deadline = min(deadline, expiry)
            if time.monotonic() >= deadline:
                return
        except TimeoutError:
            return
        except (ValueError, RecursionError):
            response = _failure("bad_request")
        except OSError:
            return
        else:
            response = server.answer(items, scope, sources, deadline)

        try:
            raw = _encode(response, MAX_REPLY_BYTES)
        except (ValueError, TypeError, RecursionError):
            raw = _encode(_failure("invalid_output"), MAX_REPLY_BYTES)
        try:
            _set_remaining(sock, deadline)
            sock.sendall(raw)
        except OSError:
            pass


class AdviceServer(socketserver.UnixStreamServer):
    """Serial request loop on a dedicated listener supplied at trusted startup."""

    def __init__(
        self,
        listener: socket.socket,
        bot_uid: int,
        inference: InferenceService,
    ):
        self.inference = inference
        self._init_listener(listener, bot_uid, managed=False)

    def _init_listener(self, listener: socket.socket, caller_uid: int, *, managed: bool) -> None:
        _validate_uid(caller_uid)
        if (
            listener.family != socket.AF_UNIX
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
            or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        ):
            raise ValueError("invalid advice listener")
        self.bot_uid = caller_uid
        self.managed = managed
        socketserver.BaseServer.__init__(self, listener.getsockname(), _AdviceRequestHandler)
        # Trusted startup sets the backlog and establishes the listener's peer credentials.
        self.socket = listener.dup()

    def _run(
        self, items: list[Item], scope: Scope, sources: tuple[str, ...], deadline: float
    ) -> Outcome:
        classes = self.inference.policy.check(self.inference.providers[0])
        if classes is not None and QUESTION_CLASS not in classes:
            return Outcome(False, error_class="policy_denied")
        return self.inference.run(
            ADVICE_TASK, items, scope, expected_sources=sources, deadline=deadline
        )

    def answer(
        self, items: list[Item], scope: Scope, sources: tuple[str, ...], deadline: float
    ) -> dict:
        try:
            outcome = self._run(items, scope, sources, deadline)
            if outcome.ok:
                return {
                    "v": VERSION,
                    "ok": True,
                    "data": outcome.data,
                    "coverage": {key: outcome.coverage[key] for key in _COVERAGE_KEYS},
                }
            return _failure(outcome.error_class or "unavailable")
        except InferenceError as exc:
            return _failure(exc.error_class)
        except Exception:  # noqa: BLE001 - transport may only expose stable error classes
            return _failure("unavailable")


class ManagedAdviceServer(AdviceServer):
    def __init__(
        self,
        listener: socket.socket,
        caller_uid: int,
        run: Callable[[list[Item], Scope, tuple[str, ...], float], Outcome],
    ):
        self._run_advice = run
        self._init_listener(listener, caller_uid, managed=True)

    def _run(
        self, items: list[Item], scope: Scope, sources: tuple[str, ...], deadline: float
    ) -> Outcome:
        return self._run_advice(items, scope, sources, deadline)
