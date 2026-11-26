"""Enroll the stable deployment launcher on an installed Steward host."""

from __future__ import annotations

import argparse
import io
import json
import os
import stat
import sys
import tempfile
import zipfile
from pathlib import Path

from .. import __version__, application_boot
from ..application_boot import BootError, digest, protected, require, safe_directory, sync_directory
from . import deployment_gate
from .deployment_launcher import GateError, parse_json

INSTALL = Path("/etc/steward/install.json")
RELEASES = Path("/opt/steward/releases")
LIBEXEC = Path("/usr/local/libexec")
STATE = Path("/var/lib/steward")
MEMBER = "steward/executor/deployment_launcher.py"
RECORD_LIMIT = 4096
LAUNCHER_LIMIT = 64 * 1024
WHEEL_LIMIT = 16 * 1024 * 1024


def read_limited(path, mode, limit):
    with protected(path, mode) as handle:
        data = handle.read(limit + 1)
    require(len(data) <= limit, f"file exceeds enrollment size limit: {path.name}")
    return data


def installed_server():
    marker = parse_json(read_limited(INSTALL, 0o644, RECORD_LIMIT))
    server = marker.get("server_name")
    schema = marker.get("schema_version")
    require(
        type(schema) is int
        and schema == 1
        and marker.get("state") == "installed"
        and isinstance(server, str)
        and application_boot.SLUG.fullmatch(server) is not None,
        "invalid installed Steward marker",
    )
    return server


def active_dist():
    release = RELEASES / __version__
    dist = release / "dist"
    safe_directory(dist)
    current = RELEASES.parent / "current"
    info = current.lstat()
    require(
        stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and os.readlink(current) == str(release),
        "unexpected active Steward release",
    )
    return dist


def approved_launcher(wheel_sha256):
    dist = active_dist()
    expected = dist / f"steward-{__version__}-py3-none-any.whl"
    wheels = [
        path
        for path in dist.iterdir()
        if path.name.lower().startswith("steward-") and path.suffix.lower() == ".whl"
    ]
    require(wheels == [expected], "expected exactly one canonical Steward wheel")
    data = read_limited(expected, 0o644, WHEEL_LIMIT)
    require(digest(data) == wheel_sha256, "Steward wheel does not match approved SHA-256")

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        matches = [info for info in archive.infolist() if info.filename == MEMBER]
        require(len(matches) == 1, "expected exactly one deployment launcher in Steward wheel")
        member = matches[0]
        require(
            member.orig_filename == MEMBER
            and stat.S_IFMT(member.external_attr >> 16) in (0, stat.S_IFREG)
            and 0 < member.file_size <= LAUNCHER_LIMIT,
            "invalid deployment launcher in Steward wheel",
        )
        with archive.open(member) as handle:
            launcher = handle.read(LAUNCHER_LIMIT + 1)
    require(len(launcher) == member.file_size, "incomplete deployment launcher in Steward wheel")
    return launcher


def ensure_directory(path):
    safe_directory(path.parent)
    try:
        path.mkdir(mode=0o755)
    except FileExistsError:
        pass
    else:
        os.chown(path, 0, 0)
        path.chmod(0o755)
    safe_directory(path)
    sync_directory(path)
    sync_directory(path.parent)


def publish(path, data, mode):
    safe_directory(path.parent)
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fchown(handle.fileno(), 0, 0)
            os.fchmod(handle.fileno(), mode)
            os.fsync(handle.fileno())
        require(not os.path.lexists(path), f"enrollment file already exists: {path.name}")
        os.replace(name, path)
        sync_directory(path.parent)
    finally:
        Path(name).unlink(missing_ok=True)


def verify_launcher(path, expected):
    with protected(path, 0o644) as handle:
        require(handle.read(LAUNCHER_LIMIT + 1) == expected, "deployment launcher has drifted")
        os.fsync(handle.fileno())
    sync_directory(path.parent)


def require_launcher_access(path):
    require(path.lstat().st_mode & stat.S_IXOTH, f"deployment launcher is inaccessible: {path}")


def prepare(wheel_sha256):
    require(os.geteuid() == 0, "deployment enrollment requires root")
    require(application_boot.is_digest(wheel_sha256), "expected a lowercase SHA-256 digest")
    with deployment_gate.control_lock():
        require(
            not os.path.lexists(deployment_gate.record_path())
            and not os.path.lexists(deployment_gate.RUNTIME / "gate.sock"),
            "deployment run requires exact cleanup before enrollment",
        )
        require(application_boot.read_deployment_fence() is None, "deployment fence is active")
        server = installed_server()
        launcher = approved_launcher(wheel_sha256)
        expected = {
            "v": 1,
            "server_name": server,
            "wheel_sha256": wheel_sha256,
            "launcher_sha256": digest(launcher),
        }
        base = LIBEXEC / "steward"
        destination = base / "deployment-v1" / "launch.py"
        record = STATE / "deployment-enrollment-v1.json"
        launcher_directories = (LIBEXEC, base, destination.parent)

        if os.path.lexists(record):
            existing = parse_json(read_limited(record, 0o600, RECORD_LIMIT))
            require(
                type(existing.get("v")) is int and existing == expected,
                "deployment enrollment evidence does not match",
            )
            verify_launcher(destination, launcher)
            for directory in launcher_directories:
                require_launcher_access(directory)
            return {**expected, "changed": False}

        for directory in launcher_directories:
            ensure_directory(directory)
            require_launcher_access(directory)
        ensure_directory(STATE)
        if not os.path.lexists(destination):
            publish(destination, launcher, 0o644)
        verify_launcher(destination, launcher)
        require(installed_server() == server, "installed Steward marker changed during enrollment")
        active_dist()
        require(application_boot.read_deployment_fence() is None, "deployment fence is active")
        publish(record, (json.dumps(expected, sort_keys=True) + "\n").encode("ascii"), 0o600)
        return {**expected, "changed": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.sha256), sort_keys=True))
    except (BootError, GateError, OSError, ValueError, zipfile.BadZipFile, RuntimeError) as error:
        print(f"deployment enrollment: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
