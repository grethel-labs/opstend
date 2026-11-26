#!/usr/bin/env python3
"""Fixed unprivileged guest-side runtime for an owned restore drill.

Only a randomly scoped private workspace can be removed. This helper receives
payloads on stdin, never selects a production destination, and does not stop or
remove arbitrary containers. The controller must independently verify the VM,
repository, snapshot and reader identity before invoking it.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import io
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import uuid
from pathlib import Path, PurePosixPath

MAX_PAYLOAD = 128 * 1024 * 1024
MAX_ARCHIVE = 32 * 1024 * 1024
MAX_EXPANDED = 128 * 1024 * 1024
MAX_BINARY = 64 * 1024 * 1024
FILES = frozenset(
    {
        "archive",
        "restic",
        "repository",
        "password",
        "username",
        "auth-password",
        "ca.pem",
        "receipt.json",
        "spec.json",
    }
)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, data, mode=0o600):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(os.dup(fd), "wb") as stream:
            stream.write(data)
            stream.flush()
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def read_owned(path, *, maximum=MAX_PAYLOAD, mode=0o600):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != mode
            or info.st_nlink != 1
            or info.st_size > maximum
        ):
            raise ValueError("unsafe workspace file")
        with os.fdopen(os.dup(fd), "rb") as stream:
            value = stream.read(maximum + 1)
        if len(value) > maximum:
            raise ValueError("workspace file too large")
        return value
    finally:
        os.close(fd)


def validate_state(state):
    if not isinstance(state, dict) or set(state) != {
        "v",
        "token",
        "uid",
        "uuid",
        "boot_id",
        "commit",
        "files",
    }:
        raise ValueError("invalid workspace identity")
    if (
        type(state["v"]) is not int
        or state["v"] != 1
        or type(state["uid"]) is not int
        or state["uid"] <= 0
        or not isinstance(state["token"], str)
        or not re.fullmatch(r"[a-f0-9]{32}", state["token"])
        or not isinstance(state["commit"], str)
        or not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", state["commit"])
    ):
        raise ValueError("invalid workspace identity")
    try:
        if (
            str(uuid.UUID(state["uuid"])) != state["uuid"]
            or str(uuid.UUID(state["boot_id"])) != state["boot_id"]
        ):
            raise ValueError("invalid UUID")
    except (TypeError, ValueError, AttributeError):
        raise ValueError("invalid workspace identity") from None
    hashes = state["files"]
    if (
        not isinstance(hashes, dict)
        or set(hashes) != FILES
        or any(
            not isinstance(v, str) or not re.fullmatch(r"[a-f0-9]{64}", v) for v in hashes.values()
        )
    ):
        raise ValueError("invalid input bindings")
    return state


def marker_bytes(state):
    return json.dumps(validate_state(state), sort_keys=True, separators=(",", ":")).encode()


def check_identity(state):
    if os.geteuid() != state["uid"] or os.geteuid() == 0:
        raise ValueError("wrong guest user")
    actual_uuid = (
        subprocess.check_output(
            ["/usr/bin/sudo", "-n", "/usr/bin/cat", "/sys/class/dmi/id/product_uuid"],
            text=True,
            timeout=10,
        )
        .strip()
        .lower()
    )
    actual_boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().lower()
    if actual_uuid != state["uuid"] or actual_boot != state["boot_id"]:
        raise ValueError("guest identity changed")


def containers_empty():
    data = subprocess.check_output(
        ["/usr/bin/podman", "ps", "--all", "--format", "json"], text=True, timeout=30
    )
    value = json.loads(data)
    if not isinstance(value, list) or value:
        raise ValueError("guest containers are not empty")


def checked_dir(root):
    info = root.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ValueError("unsafe workspace directory")


def open_lock(root, *, create=False):
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    fd = os.open(root / "lock", flags, 0o600)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size != 0
        ):
            raise ValueError("unsafe workspace lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


def clean(root, state, *, lock_fd=None):
    """Delete only a token-bound inactive workspace, marker last."""
    checked_dir(root)
    own_lock = lock_fd is None
    if own_lock:
        try:
            lock_fd = open_lock(root)
        except FileNotFoundError:
            # A crash after removing the lock is recoverable only when no data remains.
            entries = {x.name for x in root.iterdir()}
            if entries - {"ownership.json"}:
                raise ValueError("workspace lock missing") from None
            if entries and read_owned(root / "ownership.json", maximum=65536) != marker_bytes(
                state
            ):
                raise ValueError("workspace identity mismatch") from None
            if entries:
                (root / "ownership.json").unlink()
                sync_dir(root)
            root.rmdir()
            sync_dir(root.parent)
            return
    try:
        entries = {x.name for x in root.iterdir()}
        marker = root / "ownership.json"
        pending = root / ".ownership-staging"
        if "ownership.json" in entries:
            if (
                read_owned(marker, maximum=65536) != marker_bytes(state)
                or ".ownership-staging" in entries
            ):
                raise ValueError("workspace identity mismatch")
            containers_empty()
            for item in root.iterdir():
                if item.name in ("ownership.json", "lock"):
                    continue
                if item.is_dir() and not item.is_symlink():
                    shutil.rmtree(item)
                else:
                    item.unlink()
            sync_dir(root)
            (root / "lock").unlink()
            sync_dir(root)
            marker.unlink()
            sync_dir(root)
        else:
            if entries - {"lock", ".ownership-staging"}:
                raise ValueError("workspace marker missing")
            if ".ownership-staging" in entries:
                partial = read_owned(pending, maximum=65536)
                if not marker_bytes(state).startswith(partial):
                    raise ValueError("staged workspace identity mismatch")
                pending.unlink()
                sync_dir(root)
            (root / "lock").unlink()
            sync_dir(root)
        root.rmdir()
        sync_dir(root.parent)
    finally:
        if own_lock:
            os.close(lock_fd)


def extract_archive(data, destination):
    if len(data) > MAX_ARCHIVE:
        raise ValueError("archive too large")
    destination.mkdir(mode=0o700)
    count = total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for item in archive:
            count += 1
            name = PurePosixPath(item.name)
            if (
                count > 10000
                or name.is_absolute()
                or not name.parts
                or any(x in ("", ".", "..") for x in name.parts)
            ):
                raise ValueError("unsafe archive path")
            target = destination.joinpath(*name.parts)
            if item.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
            elif item.isfile():
                total += item.size
                if total > MAX_EXPANDED:
                    raise ValueError("archive expands beyond limit")
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                stream = archive.extractfile(item)
                if stream is None:
                    raise ValueError("archive file missing")
                data = stream.read(item.size + 1)
                if len(data) != item.size:
                    raise ValueError("truncated archive file")
                write_new(target, data)
            else:
                raise ValueError("unsafe archive member")


def run_drill(root, state, files, lock_fd):
    repo = root / "repo"
    extract_archive(files["archive"], repo)
    tools = root / "tools"
    tools.mkdir(mode=0o700)
    write_new(tools / "restic", files["restic"], 0o700)
    creds = root / "credentials"
    creds.mkdir(mode=0o700)
    for name in (
        "repository",
        "password",
        "username",
        "auth-password",
        "ca.pem",
        "receipt.json",
        "spec.json",
    ):
        write_new(creds / name, files[name])
    wanted = {
        "annotated-types",
        "pydantic",
        "pydantic-core",
        "typing-extensions",
        "typing-inspection",
        "pyyaml",
    }
    blocks = []
    for block in re.split(
        r"(?m)^(?=[a-zA-Z0-9])", (repo / "requirements/controller.txt").read_text()
    ):
        name = block.split("==", 1)[0].lower().replace("_", "-")
        if name in wanted:
            blocks.append(block)
            wanted.remove(name)
    if wanted:
        raise ValueError("runtime requirements missing")
    requirements = root / "runtime-requirements.txt"
    write_new(requirements, "".join(blocks).encode())
    envdir = root / "venv"
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": pwd.getpwuid(os.geteuid()).pw_dir,
        "XDG_RUNTIME_DIR": f"/run/user/{os.geteuid()}",
        "PIP_CONFIG_FILE": "/dev/null",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(repo / "src"),
    }
    subprocess.run(
        [sys.executable, "-m", "venv", str(envdir)],
        cwd="/",
        env=env,
        capture_output=True,
        check=True,
        timeout=180,
        pass_fds=(lock_fd,),
    )
    subprocess.run(
        [
            str(envdir / "bin/python"),
            "-m",
            "pip",
            "install",
            "--require-hashes",
            "--only-binary=:all:",
            "--no-cache-dir",
            "-r",
            str(requirements),
        ],
        cwd="/",
        env=env,
        capture_output=True,
        check=True,
        timeout=180,
        pass_fds=(lock_fd,),
    )
    report = root / "report.json"
    command = [
        str(envdir / "bin/python"),
        "-B",
        "-m",
        "steward.backup",
        "restore-test",
        "--repository-file",
        str(creds / "repository"),
        "--password-file",
        str(creds / "password"),
        "--username-file",
        str(creds / "username"),
        "--auth-password-file",
        str(creds / "auth-password"),
        "--ca-file",
        str(creds / "ca.pem"),
        "--receipt",
        str(creds / "receipt.json"),
        "--spec",
        str(creds / "spec.json"),
        "--app",
        str(repo / "sample-app/sample-notes/app.py"),
        "--state-dir",
        str(root / "state"),
        "--restic-binary",
        str(tools / "restic"),
        "--out",
        str(report),
    ]
    subprocess.run(
        command, cwd="/", env=env, capture_output=True, check=True, timeout=300, pass_fds=(lock_fd,)
    )
    return json.loads(read_owned(report, maximum=65536))


def main():
    raw = sys.stdin.buffer.read(MAX_PAYLOAD + 1)
    if len(raw) > MAX_PAYLOAD:
        raise ValueError("payload too large")
    payload = json.loads(raw)
    state = validate_state(payload["state"])
    check_identity(state)
    root = Path("/tmp") / ("steward-restore-" + state["token"])
    if payload["action"] == "cleanup":
        try:
            root.lstat()
        except FileNotFoundError:
            print(json.dumps({"cleaned": True}))
            return
        clean(root, state)
        print(json.dumps({"cleaned": True}))
        return
    if payload["action"] != "run":
        raise ValueError("unknown action")
    encoded = payload["files"]
    if not isinstance(encoded, dict) or set(encoded) != FILES:
        raise ValueError("invalid input files")
    files = {name: base64.b64decode(value, validate=True) for name, value in encoded.items()}
    if (
        len(files["archive"]) > MAX_ARCHIVE
        or len(files["restic"]) > MAX_BINARY
        or any(
            len(value) > 65536 for name, value in files.items() if name not in ("archive", "restic")
        )
        or {name: digest(value) for name, value in files.items()} != state["files"]
    ):
        raise ValueError("input binding mismatch")
    containers_empty()
    root.mkdir(mode=0o700)
    lock_fd = open_lock(root, create=True)
    try:
        write_new(root / ".ownership-staging", marker_bytes(state))
        os.rename(root / ".ownership-staging", root / "ownership.json")
        sync_dir(root)
        report = run_drill(root, state, files, lock_fd)
        clean(root, state, lock_fd=lock_fd)
    finally:
        os.close(lock_fd)
    print(json.dumps({"report": report, "workspace_removed": not root.exists()}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit(
            "restore guest operation failed; guarded cleanup may be required"
        ) from None
