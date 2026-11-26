"""Publish verified capture bytes to a root-owned, backup-group-readable import.

The executor supplies every path and the fixed backup user's group. There is no
caller-supplied destination, credential lookup or application parser here.
"""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from collections.abc import Callable
from pathlib import Path

from .backups import BackupError, load_capture, regular_file


def acl_attributes(path: Path):
    return set(os.listxattr(path, follow_symlinks=False)) & {
        "system.posix_acl_access",
        "system.posix_acl_default",
    }


def clear_inherited_acl(path: Path):
    for attribute in acl_attributes(path):
        os.removexattr(path, attribute, follow_symlinks=False)


def owned_directory(path: Path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise BackupError("unsafe_spool")
    return info


def protected_capture(path: Path):
    owned_directory(path)
    for name in ("manifest.json", "data.tar", "database.sqlite"):
        candidate = path / name
        if not os.path.lexists(candidate):
            continue
        fd, info = regular_file(candidate)
        os.close(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o022 or info.st_nlink != 1:
            raise BackupError("unsafe_spool")
    return load_capture(path)


def sync_directory(path: Path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def export_capture(
    source: Path,
    destination: Path,
    *,
    capture_id: str,
    gid: int,
    before_publish: Callable | None = None,
):
    """Idempotently publish one exact private capture, with no write grant."""
    source, destination = source.absolute(), destination.absolute()
    if (
        source == destination
        or destination.is_relative_to(source)
        or source.is_relative_to(destination)
    ):
        raise BackupError("invalid_input")
    owned_directory(source.parent)
    owned_directory(destination.parent)
    manifest = protected_capture(source)
    if manifest.id != capture_id:
        raise BackupError("evidence_mismatch")
    if before_publish is not None:
        before_publish(manifest)
    if os.path.lexists(destination):
        existing = protected_capture(destination)
        if existing.id != capture_id:
            raise BackupError("evidence_mismatch")
        info = destination.lstat()
        if info.st_gid != gid or info.st_mode & 0o777 != 0o550 or acl_attributes(destination):
            raise BackupError("unsafe_spool")
        for name in ("manifest.json", manifest.filename):
            info = (destination / name).lstat()
            if (
                info.st_gid != gid
                or info.st_mode & 0o777 != 0o440
                or acl_attributes(destination / name)
            ):
                raise BackupError("unsafe_spool")
        return manifest
    if shutil.disk_usage(destination.parent).free < manifest.size + 512 * 1024 * 1024:
        raise BackupError("insufficient_space")
    temporary = Path(tempfile.mkdtemp(prefix=".export-", dir=destination.parent))
    try:
        # Masked named ACLs can become effective when a later chmod opens the
        # group mask. Remove inherited ACLs on our new private objects first.
        clear_inherited_acl(temporary)
        for name in (manifest.filename, "manifest.json"):
            source_fd, info = regular_file(source / name)
            limit = manifest.size if name == manifest.filename else 65536
            if info.st_size > limit:
                os.close(source_fd)
                raise BackupError("limit_exceeded")
            with os.fdopen(source_fd, "rb") as reader, (temporary / name).open("xb") as writer:
                remaining = info.st_size
                while remaining:
                    chunk = reader.read(min(65536, remaining))
                    if not chunk:
                        raise BackupError("source_changed")
                    writer.write(chunk)
                    remaining -= len(chunk)
                if reader.read(1):
                    raise BackupError("source_changed")
                clear_inherited_acl(temporary / name)
                os.fchown(writer.fileno(), -1, gid)
                os.fchmod(writer.fileno(), 0o440)
                writer.flush()
                os.fsync(writer.fileno())
        if load_capture(temporary).id != capture_id:
            raise BackupError("evidence_mismatch")
        os.chown(temporary, -1, gid)
        os.chmod(temporary, 0o550)  # noqa: S103 - root owner, fixed backup group: read/traverse only
        sync_directory(temporary)
        os.rename(temporary, destination)
        sync_directory(destination.parent)
        return manifest
    finally:
        if temporary.exists():
            os.chmod(temporary, 0o700)
            shutil.rmtree(temporary)
