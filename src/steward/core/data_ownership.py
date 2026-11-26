"""Conservative, bounded ownership checks for a paused application data tree.

These observations do not freeze writers and are not consistency evidence.
"""

import hashlib
import json
import os
import stat
import time
from pathlib import Path

from .backups import BackupError
from .filebackups import MAX_ENTRIES, safe_name


def inspect_data_ownership(
    source: Path, *, service_uid: int, max_bytes: int, deadline: float
) -> tuple[str, int]:
    """Reject untrusted owners, writable shared permissions, ACLs and unsafe entries."""
    if type(service_uid) is not int or service_uid < 0 or max_bytes < 1:
        raise BackupError("invalid_input")
    opened = []
    snapshots = []
    digest = hashlib.sha256()
    count = total = 0
    trusted = {os.geteuid(), service_uid}

    def signature(info):
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_uid,
            info.st_gid,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    def budget():
        if time.monotonic() >= deadline:
            raise BackupError("timeout")

    def check(fd, info, relative):
        budget()
        if info.st_dev != device or info.st_uid not in trusted or info.st_mode & 0o022:
            raise BackupError("unsafe_owner")
        if {"system.posix_acl_access", "system.posix_acl_default"} & set(os.listxattr(fd)):
            raise BackupError("unsafe_owner")
        digest.update(json.dumps([relative, signature(info)], ensure_ascii=True).encode() + b"\n")

    def walk(fd, prefix):
        nonlocal count, total
        before = os.fstat(fd)
        names = []
        with os.scandir(fd) as iterator:
            for entry in iterator:
                budget()
                count += 1
                if count > MAX_ENTRIES:
                    raise BackupError("limit_exceeded")
                names.append(entry.name)
        for name in sorted(names):
            relative = safe_name(prefix + name)
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            is_dir = stat.S_ISDIR(info.st_mode)
            if not is_dir and not (stat.S_ISREG(info.st_mode) and info.st_nlink == 1):
                raise BackupError("unsafe_entry")
            if is_dir and (len(opened) >= 128 or relative.count("/") >= 32):
                raise BackupError("limit_exceeded")
            if not is_dir:
                total += info.st_size
                if total > max_bytes:
                    raise BackupError("limit_exceeded")
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if is_dir:
                flags |= os.O_DIRECTORY
            child = os.open(name, flags, dir_fd=fd)
            retained = False
            try:
                if signature(os.fstat(child)) != signature(info):
                    raise BackupError("source_changed")
                check(child, info, relative)
                if is_dir:
                    opened.append(child)
                    retained = True
                    walk(child, relative + "/")
                elif signature(os.fstat(child)) != signature(info):
                    raise BackupError("source_changed")
            finally:
                if not retained:
                    os.close(child)
            snapshots.append((fd, name, signature(info)))
        if signature(os.fstat(fd)) != signature(before):
            raise BackupError("source_changed")

    try:
        root = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened.append(root)
        root_info = os.fstat(root)
        device = root_info.st_dev
        check(root, root_info, "")
        walk(root, "")
        for parent, name, expected in snapshots:
            budget()
            if signature(os.stat(name, dir_fd=parent, follow_symlinks=False)) != expected:
                raise BackupError("source_changed")
        if signature(os.fstat(root)) != signature(root_info):
            raise BackupError("source_changed")
        return digest.hexdigest(), total
    except (OSError, UnicodeError, ValueError):
        raise BackupError("unsafe_entry") from None
    finally:
        for fd in reversed(opened):
            os.close(fd)
