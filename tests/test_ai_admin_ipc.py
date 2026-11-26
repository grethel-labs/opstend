"""AI admin transport checks with real Linux Unix stream sockets."""

from __future__ import annotations

import errno
import json
import os
import socket
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import pytest

from steward import inference_worker
from steward.core.ai_admin_ipc import AdminPeer
from steward.core.ipc import MAX_MESSAGE_BYTES
from steward.executor.protocol import ExecutorError


def encode(obj):
    return json.dumps(obj).encode() + b"\n"


def request(method="view", payload=None, **fields):
    return {
        "v": 1,
        "action": method,
        "params": {} if payload is None else payload,
        "request_id": "a" * 32,
        "expires_at": time.time() + 30,
    } | fields


@pytest.fixture
def managed_listener():
    # Linux limits sockaddr_un paths to 107 bytes.
    with TemporaryDirectory(prefix="w29-", dir="/tmp") as directory:
        path = Path(directory) / "admin.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path))
            path.chmod(0o660)
            listener.listen()
            listener.settimeout(5)
            yield listener, path


@pytest.fixture
def backend_state(tmp_path):
    state = tmp_path / "inference"
    state.mkdir(mode=0o700)
    return state


@pytest.fixture
def trust_listener_parent(managed_listener, monkeypatch):
    _, path = managed_listener
    assert not inference_worker._trusted_directory(path.parent)
    monkeypatch.setattr(
        inference_worker, "_trusted_directory", lambda parent: parent == path.parent
    )


@pytest.fixture
def make_server(managed_listener, backend_state, trust_listener_parent):
    listener, path = managed_listener

    def make(**overrides):
        options = {
            "socket_path": path,
            "state_dir": backend_state,
            "admin_uid": os.geteuid(),
            "read_policy": lambda: None,
        }
        return inference_worker.make_admin_server(listener, **(options | overrides))

    return make


@contextmanager
def serving(server):
    with ThreadPoolExecutor(max_workers=1) as pool:
        running = pool.submit(server.serve_forever, poll_interval=0.01)
        try:
            yield
        finally:
            server.shutdown()
            server.server_close()
            running.result(timeout=5)


@pytest.fixture
def admin_peer(managed_listener, make_server):
    _, path = managed_listener
    with serving(make_server()):
        yield AdminPeer(str(path), os.geteuid())


def raw_exchange(path, frame):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(3)
        client.connect(str(path))
        client.sendall(frame)
        client.shutdown(socket.SHUT_WR)
        with client.makefile("rb") as reader:
            return reader.readline(MAX_MESSAGE_BYTES + 1)


def test_adopts_only_matching_listening_socket_and_preserves_manager_path(
    managed_listener,
    backend_state,
    make_server,
):
    listener, path = managed_listener
    before = path.stat()
    with pytest.raises((ValueError, OSError)):
        make_server(socket_path=path.with_name("other.sock"))
    with (
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as unbound,
        pytest.raises((ValueError, OSError)),
    ):
        inference_worker.make_admin_server(
            unbound, socket_path=path, state_dir=backend_state, admin_uid=os.geteuid()
        )
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as duplicate:
        with pytest.raises(OSError) as failure:
            duplicate.bind(str(path))
        assert failure.value.errno == errno.EADDRINUSE

    with serving(make_server()):
        result = AdminPeer(str(path), os.geteuid())("view", {})
        assert all(option["runtime_enabled"] is False for option in result["body"]["options"])

    after = path.stat()
    assert (after.st_ino, after.st_mode, after.st_uid, after.st_gid) == (
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_gid,
    )
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(str(path))
        accepted, _ = listener.accept()
        accepted.close()


def test_rejects_untrusted_parent_before_opening_state(managed_listener, backend_state):
    listener, path = managed_listener
    with pytest.raises((ValueError, OSError)):
        inference_worker.make_admin_server(
            listener, socket_path=path, state_dir=backend_state, admin_uid=os.geteuid()
        )
    assert path.is_socket()
    assert list(backend_state.iterdir()) == []


def test_rejects_nonprivate_backend_before_opening_stores(make_server, backend_state):
    backend_state.chmod(0o755)
    with pytest.raises((ValueError, OSError)):
        make_server()
    assert list(backend_state.iterdir()) == []


@pytest.mark.parametrize("pid,fds", [("0", "1"), (None, "1"), ("self", "2"), ("self", None)])
def test_managed_admin_rejects_invalid_systemd_envelope(monkeypatch, pid, fds):
    for name, value in (("LISTEN_PID", pid), ("LISTEN_FDS", fds)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, str(os.getpid()) if value == "self" else value)
    with pytest.raises(ValueError):
        inference_worker._serve_managed_admin()


@pytest.mark.parametrize("owner,mode", [(0, 0o660), (17, 0o660), (0, 0o666)])
def test_managed_admin_uses_fd_three_and_actual_api_uid(
    managed_listener, backend_state, trust_listener_parent, monkeypatch, owner, mode
):
    listener, path = managed_listener
    path.chmod(mode)
    actual_lstat = Path.lstat
    actual_socket = socket.socket
    accounts = {
        "steward-api": SimpleNamespace(pw_uid=1001, pw_gid=1004),
        "steward-inference": SimpleNamespace(pw_uid=1002),
        "steward-ai": SimpleNamespace(pw_uid=1003),
    }
    seen = {}

    def lstat(target):
        info = actual_lstat(target)
        if target == path:
            return SimpleNamespace(st_mode=info.st_mode, st_uid=owner, st_gid=1004)
        if target == backend_state:
            return SimpleNamespace(st_mode=info.st_mode, st_uid=1002)
        return info

    def socket_factory(*args, **kwargs):
        if "fileno" in kwargs:
            seen["fd"] = kwargs["fileno"]
            duplicate = listener.dup()
            duplicate.set_inheritable(True)
            seen["listener"] = duplicate
            return duplicate
        return actual_socket(*args, **kwargs)

    def serve(server):
        assert not seen["listener"].get_inheritable()
        seen["admin_uid"] = server.admin_uid
        assert server.socket.getsockname() == str(path)

    monkeypatch.setenv("LISTEN_PID", str(os.getpid()))
    monkeypatch.setenv("LISTEN_FDS", "1")
    monkeypatch.setattr(inference_worker, "MANAGED_SOCKET", str(path))
    monkeypatch.setattr(inference_worker, "STATE_DIR", backend_state)
    monkeypatch.setattr(inference_worker.pwd, "getpwnam", accounts.__getitem__)
    monkeypatch.setattr(os, "getuid", lambda: 1002)
    monkeypatch.setattr(os, "geteuid", lambda: 1002)
    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(socket, "socket", socket_factory)
    monkeypatch.setattr(inference_worker._AdminServer, "serve_forever", serve)
    if (owner, mode) == (0, 0o660):
        inference_worker._serve_managed_admin()
        assert seen["fd"] == 3
        assert seen["admin_uid"] == 1001
        assert path.is_socket()
    else:
        with pytest.raises(PermissionError):
            inference_worker._serve_managed_admin()
        assert not seen


@pytest.mark.parametrize("uids", [(0, 2, 3), (1, 2, 1), (2, 2, 3), (1, 3, 2)])
def test_managed_admin_requires_distinct_actual_service_uids(monkeypatch, uids):
    accounts = dict(zip(("steward-api", "steward-inference", "steward-ai"), uids, strict=True))
    monkeypatch.setattr(
        inference_worker.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=accounts[name])
    )
    monkeypatch.setattr(os, "getuid", lambda: 2)
    monkeypatch.setattr(os, "geteuid", lambda: 2)
    with pytest.raises(PermissionError):
        inference_worker._managed_admin_uid()


def test_client_sends_no_request_to_wrong_kernel_uid(managed_listener):
    listener, path = managed_listener
    peer = AdminPeer(str(path), os.geteuid() + 1)
    with pytest.raises(ExecutorError):
        peer("view", {})
    conn, _ = listener.accept()
    with conn:
        conn.settimeout(1)
        assert conn.recv(1) == b""


def test_server_checks_kernel_uid_before_waiting_for_a_request(managed_listener, make_server):
    _, path = managed_listener
    with (
        serving(make_server(admin_uid=os.geteuid() + 1)),
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client,
    ):
        client.connect(str(path))
        client.settimeout(0.5)
        # With no body sent, the server must already refuse the connection.
        with client.makefile("rb") as reader:
            line = reader.readline()
        if line:
            assert json.loads(line)["error_class"] == "unauthorized_peer"


@pytest.mark.parametrize(
    ("action", "params"),
    [
        ("unknown", {}),
        ("advice.answer", {}),
        ("run_once", {}),
        ("view", {"extra": True}),
        ("auto", {"key": "test-key-01", "body": {}}),
        ("auto", {"key": "test-key-01", "body": {"enabled": True, "extra": True}}),
        ("auto", {"key": "test-key-01", "body": {"enabled": 1}}),
        ("scan", {"key": "test-key-01", "body": {"extra": True}}),
        ("scan", {"key": ["test-key-01"], "body": {}}),
        ("scan", {"body": {}}),
    ],
)
def test_rejects_unregistered_actions_and_bad_typed_bodies(admin_peer, action, params):
    with pytest.raises(ExecutorError):
        admin_peer(action, params)
    assert admin_peer("view", {})["body"]["requests"] == []


@pytest.mark.parametrize(
    "fields",
    [
        {"v": True},
        {"v": 2},
        {"v": 1.0},
        {"action": 17},
        {"params": []},
        {"request_id": ""},
        {"expires_at": float("inf")},
        {"expires_at": 0},
        {"peer_uid": 0},
    ],
)
def test_server_rejects_bad_outer_request_envelope(admin_peer, managed_listener, fields):
    _, path = managed_listener
    frame = encode(request("scan", {"key": "test-key-01", "body": {}}, **fields))
    result = json.loads(raw_exchange(path, frame))
    assert result["ok"] is False
    assert admin_peer("view", {})["body"]["requests"] == []


def test_request_frame_exact_cap_overflow_and_missing_newline(admin_peer, managed_listener):
    _, path = managed_listener
    frame = encode(request())
    exact = frame[:-1].ljust(MAX_MESSAGE_BYTES - 1) + b"\n"
    assert json.loads(raw_exchange(path, exact))["ok"] is True
    assert json.loads(raw_exchange(path, exact[:-1] + b" \n"))["ok"] is False

    scan = encode(request("scan", {"key": "test-key-01", "body": {}}))
    truncated = raw_exchange(path, scan[:-1])
    if truncated:
        assert json.loads(truncated)["ok"] is False
    assert admin_peer("view", {})["body"]["requests"] == []


def test_complete_request_with_trailing_bytes_is_never_dispatched(admin_peer, managed_listener):
    _, path = managed_listener
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(str(path))
        client.sendall(encode(request("scan", {"key": "test-key-01", "body": {}})))
        client.settimeout(0.1)
        with pytest.raises(TimeoutError):
            client.recv(1)
        client.settimeout(3)
        client.sendall(b"trailing bytes")
        client.shutdown(socket.SHUT_WR)
        with client.makefile("rb") as reader:
            assert json.loads(reader.readline())["ok"] is False
    assert admin_peer("view", {})["body"]["requests"] == []


@pytest.mark.parametrize(
    "chunks",
    [
        pytest.param((b'\n{"ok":true,"result":{}}',), id="leading-newline-without-terminator"),
        pytest.param((b'{"ok":true,"result":{}}\n', b"trailing bytes"), id="trailing-bytes"),
    ],
)
def test_standard_client_rejects_malformed_reply_before_http_validation(managed_listener, chunks):
    listener, path = managed_listener

    def reply():
        connection, _ = listener.accept()
        with connection, connection.makefile("rb") as reader:
            connection.settimeout(3)
            assert json.loads(reader.read())["action"] == "view"
            for chunk in chunks:
                connection.sendall(chunk)

    with ThreadPoolExecutor(max_workers=1) as pool:
        replied = pool.submit(reply)
        with pytest.raises(ExecutorError):
            AdminPeer(str(path), os.geteuid())("view", {})
        replied.result(timeout=5)


def test_oversized_request_is_not_sent_by_client(managed_listener):
    listener, path = managed_listener
    with pytest.raises(ExecutorError):
        AdminPeer(str(path), os.geteuid())("view", {"extra": "x" * MAX_MESSAGE_BYTES})
    listener.settimeout(0.05)
    try:
        conn, _ = listener.accept()
    except TimeoutError:
        return
    with conn:
        conn.settimeout(1)
        assert conn.recv(1) == b""


def test_oversized_view_returns_bounded_failure_without_truncating_state(
    admin_peer,
    managed_listener,
    backend_state,
):
    _, path = managed_listener
    with closing(sqlite3.connect(backend_state / "sources.db")) as db, db:
        db.execute(
            "INSERT INTO sources (id, url, parser, host, grp, state, origin, added_at, note) "
            "VALUES ('fixture', 'https://example.org/p', 'json_comparison_v1', "
            "'example.org', 'example.org', 'active', 'operator', 0, ?)",
            ("x" * MAX_MESSAGE_BYTES,),
        )

    response = raw_exchange(path, encode(request()))
    assert len(response) <= MAX_MESSAGE_BYTES
    assert response.endswith(b"\n")
    assert json.loads(response)["ok"] is False
    with pytest.raises(ExecutorError):
        admin_peer("view", {})
    with closing(sqlite3.connect(backend_state / "sources.db")) as db:
        assert db.execute("SELECT length(note) FROM sources").fetchone() == (MAX_MESSAGE_BYTES,)


def test_client_times_out_waiting_for_a_silent_matching_peer(managed_listener):
    listener, path = managed_listener
    with ThreadPoolExecutor(max_workers=1) as pool:
        operation = pool.submit(AdminPeer(str(path), os.geteuid()), "view", {})
        conn, _ = listener.accept()
        with conn, conn.makefile("rb") as reader:
            conn.settimeout(5)
            assert json.loads(reader.readline())["action"] == "view"
            with pytest.raises(ExecutorError) as failure:
                operation.result(timeout=5)
            assert failure.value.outcome_unknown is True
