#!/usr/bin/python3
"""Atomically claim a fresh layout before any other installation mutation.

Run as root on Linux. No public option redirects the protected system paths.
Existing layouts require a trusted ownership marker; foreign layouts stay closed.
"""

import argparse
import ctypes
import errno
import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path


def trusted(path, *, directory=False):
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError(f"untrusted ownership or permissions: {path}")


def validate_existing(target, server, *, guarded=False):
    trusted(target, directory=True)
    marker = target / "install.json"
    trusted(marker)
    if marker.stat().st_size > 4096:
        raise ValueError("oversized install marker")
    value = json.loads(marker.read_text())
    expected_schema = 2 if guarded else 1
    valid_states = ("installed",) if guarded else (None, "initializing", "installed")
    if (
        not isinstance(value, dict)
        or value.get("server_name") != server
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != expected_schema
        or value.get("state") not in valid_states
        or (guarded and set(value) != {"schema_version", "server_name", "state"})
    ):
        raise ValueError("install marker belongs to another or unsupported configuration")


def publish(staging, target):
    # Plain rename can replace an existing empty directory. NOREPLACE is vital:
    # a concurrent or foreign creator must never be overwritten/adopted.
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(staging), -100, os.fsencode(target), 1):
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError(error, os.strerror(error), str(target))
        raise OSError(error, os.strerror(error), str(target))


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def claim(root, server, revision, *, guarded=False):
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,30}[a-z0-9]", server):
        raise ValueError("invalid server name")
    if not re.fullmatch(r"[a-f0-9]{64}", revision):
        raise ValueError("invalid configuration revision")
    target = root / "etc/steward"
    # Repeat the read-only preflight's layout guard immediately before claiming.
    if os.path.lexists(root / "srv/isobox") or os.path.lexists(root / "run/docker.sock"):
        raise ValueError("foreign platform layout")
    if os.path.lexists(target):
        validate_existing(target, server, guarded=guarded)
        return False
    if guarded:
        raise ValueError("guarded deployment requires an installed marker")
    if os.path.lexists(root / "srv/steward"):
        raise ValueError("unmarked platform layout")
    staging = Path(tempfile.mkdtemp(prefix=".steward-bootstrap-", dir=target.parent))
    try:
        marker = staging / "install.json"
        with marker.open("x") as handle:
            json.dump(
                {
                    "server_name": server,
                    "schema_version": 1,
                    "state": "initializing",
                    "initial_revision": revision,
                },
                handle,
            )
            handle.write("\n")
            handle.flush()
            os.fchmod(handle.fileno(), 0o644)
            os.fsync(handle.fileno())
        staging.chmod(0o755)
        sync_dir(staging)
        try:
            publish(staging, target)
        except FileExistsError:
            validate_existing(target, server)
            return False
        sync_dir(target.parent)
        return True
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--guarded", action="store_true")
    parser.add_argument("server")
    parser.add_argument("revision")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("root required")
    try:
        changed = claim(Path("/"), args.server, args.revision, guarded=args.guarded)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"cannot claim installation: {exc}\n")
    print("claimed" if changed else "already owned")


if __name__ == "__main__":
    main()
