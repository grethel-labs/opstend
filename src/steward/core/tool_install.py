"""Install a pinned bzip2 executable atomically, without archive scripts."""

from __future__ import annotations

import argparse
import bz2
import hashlib
import os
import re
import stat
import tempfile
from pathlib import Path

MAX_ARCHIVE = 64 * 1024 * 1024
MAX_EXECUTABLE = 128 * 1024 * 1024


def install(archive: Path, destination: Path, expected: str) -> bool:
    if not re.fullmatch(r"[a-f0-9]{64}", expected):
        raise ValueError("invalid archive digest")
    fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    temporary = None
    try:
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ARCHIVE:
                raise ValueError("invalid archive")
            data = source.read(MAX_ARCHIVE + 1)
        if len(data) != info.st_size or hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("archive digest mismatch")
        decompressor = bz2.BZ2Decompressor()
        binary = decompressor.decompress(data, max_length=MAX_EXECUTABLE + 1)
        if len(binary) > MAX_EXECUTABLE or not decompressor.eof or decompressor.unused_data:
            raise ValueError("invalid or oversized executable")
        if not binary.startswith(b"\x7fELF"):
            raise ValueError("not an ELF executable")
        try:
            existing_fd = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            existing_fd = None
        if existing_fd is not None:
            with os.fdopen(existing_fd, "rb") as existing:
                current = os.fstat(existing.fileno())
                if (
                    stat.S_ISREG(current.st_mode)
                    and current.st_uid == os.geteuid()
                    and stat.S_IMODE(current.st_mode) == 0o755
                    and current.st_size == len(binary)
                    and hashlib.file_digest(existing, "sha256").digest()
                    == hashlib.sha256(binary).digest()
                ):
                    return False
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as output:
            temporary = Path(output.name)
            output.write(binary)
            output.flush()
            os.fchmod(output.fileno(), 0o755)
            os.fsync(output.fileno())
        os.replace(temporary, destination)
        directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return True
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("sha256")
    args = parser.parse_args()
    try:
        print("installed" if install(args.archive, args.destination, args.sha256) else "unchanged")
    except (OSError, ValueError, EOFError):
        raise SystemExit("tool installation failed") from None


if __name__ == "__main__":
    main()
