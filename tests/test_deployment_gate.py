import errno
import json
import os
import shutil
import socket
import struct
import subprocess
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest

from steward.core.group_checkpoint import DeploymentFence
from steward.executor import deployment_gate as gate
from steward.executor import deployment_launcher as launcher

IDENTITY = gate.Identity("a" * 32, "b" * 32, "12345678-1234-1234-1234-123456789abc")
FENCE = DeploymentFence(
    operation_id=IDENTITY.operation_id, base_revision="c" * 64, desired_revision="d" * 64
)


@pytest.fixture
def channel():
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with client, server:
        client.settimeout(0.2)
        server.settimeout(0.2)
        try:
            (pidfd,) = struct.unpack(
                "=i", server.getsockopt(socket.SOL_SOCKET, gate.SO_PEERPIDFD, 4)
            )
        except OSError as error:
            if error.errno in {errno.EINVAL, errno.ENOPROTOOPT}:
                pytest.skip("kernel has no SO_PEERPIDFD")
            raise
        os.close(pidfd)
        yield client, server


def prepare_admission(monkeypatch, tmp_path):
    pid = os.getpid()
    membership = tmp_path / str(pid) / "cgroup"
    membership.parent.mkdir()
    monkeypatch.setattr(gate, "PROC", tmp_path)
    monkeypatch.setattr(gate.application_boot, "read_deployment_fence", lambda: FENCE)
    starts = []

    def start(identity, scope, pidfd, lock_fd):
        assert lock_fd == 123
        assert scope.startswith(IDENTITY.scope_prefix) and scope.endswith(".scope")
        assert f"Pid:\t{pid}\n" in (Path("/proc/self/fdinfo") / str(pidfd)).read_text()
        starts.append(scope)
        membership.write_text(f"0::/{identity.slice}/{scope}\n")

    monkeypatch.setattr(gate, "start_scope", start)
    return starts


def send_identity(connection, **fields):
    connection.sendall(json.dumps({**asdict(IDENTITY), **fields}).encode() + b"\n")


def test_admit_kernel_peer_with_exact_identity_and_cgroup(channel, monkeypatch, tmp_path):
    starts = prepare_admission(monkeypatch, tmp_path)
    client, server = channel
    send_identity(client)
    gate.admit(server, gate.Record(IDENTITY, os.geteuid()), FENCE, 123)

    assert client.recv(16) == gate.ACK
    assert len(starts) == 1


@pytest.mark.parametrize(
    "fields",
    [
        {"operation_id": "e" * 32},
        {"run_id": "E" * 32},
        {"boot_id": "12345678-1234-1234-1234-123456789abd"},
        {"command": "echo test"},
    ],
)
def test_admit_rejects_wrong_and_unexpected_fields(channel, monkeypatch, tmp_path, fields):
    starts = prepare_admission(monkeypatch, tmp_path)
    client, server = channel
    send_identity(client, **fields)
    with pytest.raises((gate.GateError, TypeError)):
        gate.admit(server, gate.Record(IDENTITY, os.geteuid()), FENCE, 123)
    assert starts == []


def test_admit_rejects_wrong_uid_before_reading(channel, monkeypatch, tmp_path):
    starts = prepare_admission(monkeypatch, tmp_path)
    _, server = channel
    with pytest.raises(gate.GateError, match="unauthorized"):
        gate.admit(server, gate.Record(IDENTITY, os.geteuid() + 1), FENCE, 123)
    assert starts == []


def test_admit_rejects_changed_revision_after_attach(channel, monkeypatch, tmp_path):
    starts = prepare_admission(monkeypatch, tmp_path)
    before_and_after = iter([FENCE, FENCE.model_copy(update={"desired_revision": "e" * 64})])
    monkeypatch.setattr(
        gate.application_boot, "read_deployment_fence", lambda: next(before_and_after)
    )
    client, server = channel
    send_identity(client)
    with pytest.raises(gate.GateError, match="changed during admission"):
        gate.admit(server, gate.Record(IDENTITY, os.geteuid()), FENCE, 123)
    assert len(starts) == 1
    with pytest.raises(TimeoutError):
        client.recv(16)


def test_rejects_wrong_scope(monkeypatch, tmp_path):
    pid = os.getpid()
    directory = tmp_path / str(pid)
    directory.mkdir()
    (directory / "cgroup").write_text("0::/different.slice/command.scope\n")
    monkeypatch.setattr(gate, "PROC", tmp_path)
    ticks = iter([0, 3])
    monkeypatch.setattr(gate, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
    pidfd = os.pidfd_open(pid)
    try:
        with pytest.raises(gate.GateError, match="outside its scope"):
            gate.require_member(pid, pidfd, "/this.slice/command.scope")
    finally:
        os.close(pidfd)


def test_parse_rejects_duplicate_fields():
    with pytest.raises(gate.GateError, match="duplicate"):
        gate.parse_json(b'{"operation_id":"a","operation_id":"b"}')


@pytest.mark.parametrize("preexisting", [False, True])
def test_control_lock_handles_restrictive_umask(tmp_path, monkeypatch, preexisting):
    runtime = tmp_path / "deployment"
    monkeypatch.setattr(gate, "RUNTIME", runtime)
    monkeypatch.setattr(gate.application_boot, "safe_directory", lambda _path: None)
    monkeypatch.setattr(gate.os, "geteuid", lambda: 0)
    fstat = os.fstat

    def owned_by_root(fd):
        fields = list(fstat(fd))
        fields[4:6] = [0, 0]
        return os.stat_result(fields)

    monkeypatch.setattr(gate.os, "fstat", owned_by_root)
    previous = os.umask(0o077)
    try:
        if preexisting:
            runtime.mkdir(mode=0o700)
            with (
                pytest.raises(gate.GateError, match="runtime is inaccessible"),
                gate.control_lock(),
            ):
                pytest.fail("inaccessible runtime was accepted")
            assert runtime.stat().st_mode & 0o777 == 0o700
            assert not (runtime / "control.lock").exists()
        else:
            with gate.control_lock():
                assert runtime.stat().st_mode & 0o777 == 0o755
                assert (runtime / "control.lock").stat().st_mode & 0o777 == 0o600
    finally:
        os.umask(previous)


@pytest.fixture
def cleanup_setup(monkeypatch, tmp_path):
    boot_id = tmp_path / "boot_id"
    boot_id.write_text(IDENTITY.boot_id)
    (tmp_path / "cgroup.controllers").touch()
    (tmp_path / "active.json").touch()
    (tmp_path / "gate.sock").touch()
    monkeypatch.setattr(gate, "RUNTIME", tmp_path)
    monkeypatch.setattr(gate, "BOOT_ID", boot_id)
    monkeypatch.setattr(gate, "CGROUP", tmp_path)
    monkeypatch.setattr(gate, "control_lock", nullcontext)
    monkeypatch.setattr(gate, "read_record", lambda: gate.Record(IDENTITY, 0))
    return tmp_path


def test_cleanup_never_stops_other_run(cleanup_setup, monkeypatch):
    def unexpected(*args):
        pytest.fail("wrong identity reached systemd")

    monkeypatch.setattr(gate, "run_systemd", unexpected)
    with pytest.raises(gate.GateError, match="does not match"):
        gate.cleanup(IDENTITY.operation_id, "c" * 32)
    assert (cleanup_setup / "active.json").is_file()


@pytest.mark.parametrize("condition", ["empty", "occupied", "queued", "never-started"])
@pytest.mark.parametrize("marked", [False, True])
def test_cleanup_requires_quiescence(cleanup_setup, monkeypatch, condition, marked):
    scope_glob = f"{IDENTITY.scope_prefix}*.scope"
    slice_directory = cleanup_setup / IDENTITY.slice
    active = cleanup_setup / "active.json"
    if not marked:
        active.unlink()
        (cleanup_setup / "gate.sock").unlink()

    def cleanup():
        if marked:
            gate.cleanup(IDENTITY.operation_id, IDENTITY.run_id)
        else:
            gate.cleanup_locked(IDENTITY, allow_missing=True)

    if condition in {"empty", "occupied"}:
        slice_directory.mkdir()
        populated = int(condition == "occupied")
        (slice_directory / "cgroup.events").write_text(f"populated {populated}\nfrozen 0\n")
    calls = []

    def systemd(argv, *, check=True):
        calls.append(argv[2:])
        if "list-jobs" in argv:
            assert argv[-2:] == [IDENTITY.slice, scope_glob]
            return b"42 start" if condition == "queued" else b""
        if "show" in argv:
            assert not check
            return b"not-found\n"
        if condition == "never-started":
            raise subprocess.CalledProcessError(1, argv)
        return b""

    monkeypatch.setattr(gate, "run_systemd", systemd)
    if condition in {"occupied", "queued"}:
        with pytest.raises(gate.GateError, match="remains populated|queued jobs"):
            cleanup()
        assert active.is_file() is marked
    else:
        cleanup()
        assert not active.exists()
        assert not (cleanup_setup / "gate.sock").exists()
    assert calls[0] == ["stop", IDENTITY.slice]


def test_cleanup_without_marker_preserves_unbound_socket(cleanup_setup, monkeypatch):
    (cleanup_setup / "active.json").unlink()
    socket_path = cleanup_setup / "gate.sock"
    socket_path.write_bytes(b"unbound")
    commands = []

    def systemd(argv):
        commands.append(argv)
        return b""

    monkeypatch.setattr(gate, "run_systemd", systemd)
    with pytest.raises(gate.GateError, match="requires exact cleanup"):
        gate.cleanup_locked(IDENTITY, allow_missing=True)
    assert commands[0][2:] == ["stop", IDENTITY.slice]
    assert commands[1][-2:] == [IDENTITY.slice, f"{IDENTITY.scope_prefix}*.scope"]
    assert len(commands) == 2
    assert socket_path.read_bytes() == b"unbound"


@pytest.mark.parametrize("reply", [gate.ACK, b"OK\ntrailing\n", b"", b"X" * 513 + b"\n"])
def test_enter_only_execs_exact_command_after_exact_ack(monkeypatch, tmp_path, reply):
    monkeypatch.setattr(launcher, "RUNTIME", tmp_path)
    monkeypatch.setattr(launcher, "peer_credentials", lambda _: (os.getpid(), 0, 0))
    exec_calls = []
    monkeypatch.setattr(launcher.os, "execv", lambda *args: exec_calls.append(args))
    command = "printf '%s\n' '$ORIGINAL'; cat"

    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
        listener.bind(str(tmp_path / "gate.sock"))
        listener.listen()
        listener.settimeout(1)

        def exchange():
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(1)
                request = gate.parse_json(gate.receive(connection))
                if reply:
                    connection.sendall(reply)
                return request

        with ThreadPoolExecutor(max_workers=1) as pool:
            request = pool.submit(exchange)
            if reply == gate.ACK:
                launcher.enter(IDENTITY, command)
                assert exec_calls == [("/bin/sh", ["/bin/sh", "-c", command])]
            else:
                with pytest.raises(gate.GateError):
                    launcher.enter(IDENTITY, command)
                assert exec_calls == []

            assert request.result(timeout=1) == asdict(IDENTITY)


def test_enter_rejects_non_root_peer_before_sending_identity(monkeypatch, tmp_path):
    monkeypatch.setattr(launcher, "RUNTIME", tmp_path)
    monkeypatch.setattr(launcher, "peer_credentials", lambda _: (os.getpid(), 1, 1))
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
        listener.bind(str(tmp_path / "gate.sock"))
        listener.listen()
        listener.settimeout(1)
        with pytest.raises(launcher.GateError, match="not root-owned"):
            launcher.enter(IDENTITY, "exit 99")
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(1)
            assert connection.recv(launcher.PACKET_LIMIT) == b""


def test_launcher_runs_from_standalone_copy_with_system_python(tmp_path):
    script = tmp_path / "launch.py"
    shutil.copyfile(launcher.__file__, script)
    # In isolated mode even modules beside the script must be ignored.
    (tmp_path / "steward.py").write_text("raise RuntimeError('unexpected package import')\n")
    result = subprocess.run(
        [
            "/usr/bin/python3",
            "-I",
            str(script),
            "--operation-id",
            "invalid",
            "--run-id",
            IDENTITY.run_id,
            "--boot-id",
            IDENTITY.boot_id,
            "--",
            "exit 99",
        ],
        cwd=tmp_path,
        env={"PYTHONPATH": str(tmp_path), "PYTHONHOME": str(tmp_path)},
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 1
    assert result.stderr == "deployment launcher: invalid deployment identity\n"
