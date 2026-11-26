"""Atomically claim the fixed root-private backup credential directory."""

from __future__ import annotations

import ctypes
import errno
import os
import shutil
import stat
import tempfile
from pathlib import Path

MARKER = "steward-backup-credentials-v1\n"


def trusted(path: Path, mode: int, *, directory: bool):
    info = path.lstat()
    if (
        not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != mode
        or (not directory and (info.st_nlink != 1 or info.st_size > 128))
    ):
        raise ValueError("unsafe credential ownership")


def validate(target: Path):
    trusted(target, 0o700, directory=True)
    marker = target / ".steward-owned"
    trusted(marker, 0o600, directory=False)
    if marker.read_text() != MARKER:
        raise ValueError("foreign credential directory")


def sync_dir(path: Path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def claim(parent: Path) -> bool:
    parent_info = parent.lstat()
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != os.geteuid()
        or parent_info.st_mode & 0o022
    ):
        raise ValueError("unsafe credential parent")
    target = parent / "backup"
    if os.path.lexists(target):
        validate(target)
        return False
    staging = Path(tempfile.mkdtemp(prefix=".backup-claim-", dir=parent))
    try:
        with (staging / ".steward-owned").open("x") as handle:
            handle.write(MARKER)
            handle.flush()
            os.fchmod(handle.fileno(), 0o600)
            os.fsync(handle.fileno())
        sync_dir(staging)
        libc = ctypes.CDLL(None, use_errno=True)
        rename = libc.renameat2
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(staging), -100, os.fsencode(target), 1):
            error = ctypes.get_errno()
            if error == errno.EEXIST:
                validate(target)
                return False
            raise OSError(error, os.strerror(error))
        sync_dir(parent)
        return True
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main():
    if os.geteuid() != 0:
        raise SystemExit("credential directory claim requires root")
    try:
        print("claimed" if claim(Path("/etc/steward/secrets")) else "unchanged")
    except (OSError, ValueError):
        raise SystemExit("credential directory claim failed") from None


if __name__ == "__main__":
    main()
