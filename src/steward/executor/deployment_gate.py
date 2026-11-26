"""Private Linux login gate for isolated deployment transport experiments."""

from __future__ import annotations

import argparse
import fcntl
import os
import pwd
import secrets
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path

from .. import application_boot
from ..core.group_checkpoint import DeploymentFence
from .deployment_launcher import (
    ACK,
    PACKET_LIMIT,
    RUNTIME,
    GateError,
    Identity,
    add_enter_arguments,
    enter_from_args,
    parse_json,
    peer_credentials,
    receive,
)
from .host import SAFE_ENV

BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
PROC = Path("/proc")
CGROUP = Path("/sys/fs/cgroup")
SO_PEERPIDFD = getattr(socket, "SO_PEERPIDFD", 77)


@dataclass(frozen=True)
class Record:
    identity: Identity
    uid: int

    def __post_init__(self):
        if type(self.uid) is not int or not 0 <= self.uid < 2**32 - 1:
            raise GateError("invalid deployment login UID")


@contextmanager
def control_lock():
    if os.geteuid() != 0:
        raise GateError("deployment control requires root")
    application_boot.safe_directory(RUNTIME.parent)
    try:
        RUNTIME.mkdir(mode=0o755)
    except FileExistsError:
        pass
    else:
        RUNTIME.chmod(0o755)
    application_boot.safe_directory(RUNTIME)
    if RUNTIME.stat().st_mode & 0o111 != 0o111:
        raise GateError("deployment runtime is inaccessible to the login user")
    fd = os.open(
        RUNTIME / "control.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600
    )
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (
            info.st_uid,
            info.st_gid,
            stat.S_IMODE(info.st_mode),
            info.st_nlink,
        ) != (0, 0, 0o600, 1):
            raise GateError("unsafe deployment lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield fd
    finally:
        os.close(fd)


def require_fence(operation_id):
    fence = application_boot.read_deployment_fence()
    if fence is None or fence.operation_id != operation_id:
        raise GateError("the exact durable deployment fence is unavailable")
    return fence


def record_path():
    return RUNTIME / "active.json"


def read_record():
    with application_boot.protected(record_path(), 0o600) as handle:
        data = handle.read(PACKET_LIMIT + 1)
    if len(data) > PACKET_LIMIT:
        raise GateError("invalid deployment run record")
    fields = parse_json(data)
    uid = fields.pop("uid", None)
    return Record(Identity(**fields), uid)


def run_systemd(argv, pass_fds=(), *, check=True):
    return subprocess.run(
        argv,
        cwd="/",
        env=SAFE_ENV,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        pass_fds=pass_fds,
        timeout=7,
        check=check,
    ).stdout


def start_scope(identity, scope, pidfd, lock_fd):
    run_systemd(
        [
            "/usr/bin/busctl",
            "--system",
            "--timeout=5s",
            "call",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "StartTransientUnit",
            "ssa(sv)a(sa(sv))",
            scope,
            "fail",
            "2",
            "Slice",
            "s",
            identity.slice,
            "PIDFDs",
            "ah",
            "1",
            str(pidfd),
            "0",
        ],
        pass_fds=(pidfd, lock_fd),
    )


def require_member(pid, pidfd, expected):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    deadline = time.monotonic() + 2
    while not poller.poll(0):
        membership = (PROC / str(pid) / "cgroup").read_text().splitlines()
        if membership == [f"0::{expected}"] and not poller.poll(0):
            return
        if time.monotonic() >= deadline:
            break
        time.sleep(0.02)
    raise GateError("deployment peer is dead or outside its scope")


def admit(connection, record, fence: DeploymentFence, lock_fd, *, should_stop=None):
    pid, uid, _ = peer_credentials(connection)
    if uid != record.uid or pid <= 0:
        raise GateError("unauthorized deployment peer")
    # Linux returns a descriptor for the socket peer, avoiding a numeric PID lookup.
    (pidfd,) = struct.unpack("=i", connection.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD, 4))
    try:
        identity = Identity(**parse_json(receive(connection)))
        if identity != record.identity or require_fence(identity.operation_id) != fence:
            raise GateError("deployment identity or fence changed")
        if should_stop is not None and should_stop():
            raise GateError("deployment intake is closing")
        scope = f"{identity.scope_prefix}{secrets.token_hex(16)}.scope"
        start_scope(identity, scope, pidfd, lock_fd)
        require_member(pid, pidfd, f"/{identity.slice}/{scope}")
        if require_fence(identity.operation_id) != fence:
            raise GateError("deployment fence changed during admission")
        require_member(pid, pidfd, f"/{identity.slice}/{scope}")
        if should_stop is not None and should_stop():
            raise GateError("deployment intake is closing")
        connection.sendall(ACK)
    finally:
        os.close(pidfd)


def serve(operation_id, uid, *, identity=None, on_ready=None, should_stop=None, on_term=None):
    identity = identity or Identity(
        operation_id, secrets.token_hex(16), BOOT_ID.read_text().strip()
    )
    if identity.operation_id != operation_id or identity.boot_id != BOOT_ID.read_text().strip():
        raise GateError("deployment identity does not match current boot")
    record = Record(identity, uid)
    with control_lock() as lock_fd:
        fence = require_fence(operation_id)
        if os.path.lexists(record_path()) or os.path.lexists(RUNTIME / "gate.sock"):
            raise GateError("deployment run requires exact cleanup")
        gid = pwd.getpwuid(uid).pw_gid
        application_boot.store(record_path(), {**asdict(identity), "uid": uid})
        path = RUNTIME / "gate.sock"
        stopping = False

        def stop(_signum, _frame):
            nonlocal stopping
            stopping = True
            if on_term is not None:
                on_term()

        previous_handler = signal.signal(signal.SIGTERM, stop)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
                listener.bind(str(path))
                os.chown(path, 0, gid)
                os.chmod(path, 0o660)
                listener.listen(8)
                listener.settimeout(0.5)
                if on_ready is not None:
                    on_ready()
                while not stopping and (should_stop is None or not should_stop()):
                    try:
                        connection, _ = listener.accept()
                    except TimeoutError:
                        continue
                    with connection:
                        if stopping or (should_stop is not None and should_stop()):
                            break
                        connection.settimeout(2)
                        try:
                            admit(connection, record, fence, lock_fd, should_stop=should_stop)
                        except (
                            GateError,
                            application_boot.BootError,
                            OSError,
                            subprocess.SubprocessError,
                            ValueError,
                            TypeError,
                        ):
                            continue
        finally:
            signal.signal(signal.SIGTERM, previous_handler)
            path.unlink(missing_ok=True)


def cleanup_locked(identity, *, allow_missing=False):
    marked = os.path.lexists(record_path())
    socket_path = RUNTIME / "gate.sock"
    if marked:
        if read_record().identity != identity:
            raise GateError("deployment cleanup does not match the active run")
    elif not allow_missing:
        raise GateError("deployment gate requires exact cleanup")

    unit = identity.slice
    systemctl = ["/usr/bin/systemctl", "--system"]
    try:
        run_systemd([*systemctl, "stop", unit])
    except subprocess.CalledProcessError:
        load_state = run_systemd(
            [*systemctl, "show", "--property=LoadState", "--value", unit], check=False
        )
        if load_state.strip() != b"not-found" or (CGROUP / unit).exists():
            raise
    jobs = run_systemd(
        [
            *systemctl,
            "--plain",
            "--no-legend",
            "--no-pager",
            "list-jobs",
            unit,
            f"{identity.scope_prefix}*.scope",
        ]
    )
    if jobs.strip():
        raise GateError("deployment slice has queued jobs")
    # Check for the unified hierarchy even if the run cgroup was removed.
    (CGROUP / "cgroup.controllers").stat()
    try:
        events = (CGROUP / unit / "cgroup.events").read_text().splitlines()
    except FileNotFoundError:
        if (CGROUP / unit).exists():
            raise GateError("cannot verify deployment slice is empty") from None
    else:
        if "populated 0" not in events:
            raise GateError("deployment slice remains populated")
    if not marked and os.path.lexists(socket_path):
        raise GateError("deployment gate requires exact cleanup")
    if marked:
        socket_path.unlink(missing_ok=True)
        record_path().unlink()
        application_boot.sync_directory(RUNTIME)


def cleanup(operation_id, run_id):
    with control_lock():
        cleanup_locked(Identity(operation_id, run_id, BOOT_ID.read_text().strip()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    server = commands.add_parser("serve")
    server.add_argument("--operation-id", required=True)
    server.add_argument("--uid", type=int, required=True)
    cleaner = commands.add_parser("cleanup")
    cleaner.add_argument("--operation-id", required=True)
    cleaner.add_argument("--run-id", required=True)
    launcher = commands.add_parser("enter")
    add_enter_arguments(launcher)

    args = parser.parse_args()
    try:
        if args.action == "serve":
            serve(args.operation_id, args.uid)
        elif args.action == "cleanup":
            cleanup(args.operation_id, args.run_id)
        else:
            enter_from_args(parser, args)
    except (
        GateError,
        application_boot.BootError,
        OSError,
        subprocess.SubprocessError,
        ValueError,
        TypeError,
        KeyError,
    ) as error:
        print(f"deployment gate: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
