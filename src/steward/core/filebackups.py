"""Bounded file captures while a trusted caller verifies workload quiescence.

No database parser runs here. These local manifests are not executor attestations.
Only regular files/directories are accepted; links and special files fail closed.
"""

from __future__ import annotations

import os
import shutil
import stat
import tarfile
import time
from collections.abc import Callable
from pathlib import Path, PurePosixPath

from .backups import BackupError, Binding, FilesystemCapture, digest_file, private_json

MAX_ENTRIES = 10000
ARCHIVE_OVERHEAD_MAX = MAX_ENTRIES * 16384 + 10240
MAX_RESTORE_BYTES = 1024 * 1024 * 1024


class TimedReader:
    def __init__(self, stream, budget):
        self.stream, self.budget = stream, budget

    def read(self, size):
        self.budget()
        return self.stream.read(size)


def signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def safe_name(name):
    try:
        size = len(name.encode())
    except UnicodeError:
        raise BackupError("unsafe_entry") from None
    if (
        not name
        or size > 4096
        or any(ord(c) < 32 or ord(c) == 127 for c in name)
        or "\\" in name
        or name.startswith("/")
        or any(part in ("", ".", "..") for part in name.split("/"))
    ):
        raise BackupError("unsafe_entry")
    return name


def capture_files(
    source: Path,
    destination: Path,
    binding: Binding,
    *,
    is_quiescent: Callable[[], bool],
    max_bytes: int = 256 * 1024 * 1024,
    timeout_s: float = 180,
) -> FilesystemCapture:
    """Copy a whole data tree only while both quiescence checks succeed.

    The caller must hold the workload mutation lock throughout, and its probe
    must establish that all writers are stopped. This function never executes
    a caller-supplied command or treats filesystem inactivity as quiescence.
    """
    if max_bytes < 1 or max_bytes > 2**40 or timeout_s <= 0:
        raise BackupError("invalid_input")
    source = source.absolute()
    destination = destination.absolute()
    if destination.resolve().is_relative_to(source.resolve()):
        raise BackupError("invalid_input")
    if is_quiescent() is not True:
        raise BackupError("not_quiescent")
    started = time.time()
    deadline = time.monotonic() + timeout_s
    entries = total = discovered = 0
    opened = []
    snapshots = []
    complete = False
    destination.mkdir(mode=0o700)

    def budget():
        if time.monotonic() > deadline:
            raise BackupError("timeout")

    def walk(directory_fd, prefix, archive):
        nonlocal entries, total, discovered
        before = os.fstat(directory_fd)
        names = []
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                budget()
                discovered += 1
                if discovered > MAX_ENTRIES:
                    raise BackupError("limit_exceeded")
                names.append(entry.name)
        for name in sorted(names):
            budget()
            relative = safe_name(prefix + name)
            entries += 1
            if entries > MAX_ENTRIES:
                raise BackupError("limit_exceeded")
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                if len(opened) >= 128 or relative.count("/") >= 32:
                    raise BackupError("limit_exceeded")
                child = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd
                )
                opened.append(child)
                if signature(os.fstat(child)) != signature(info):
                    raise BackupError("source_changed")
                item = tarfile.TarInfo(relative)
                item.type, item.mode = tarfile.DIRTYPE, info.st_mode & 0o777
                archive.addfile(item)
                walk(child, relative + "/", archive)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                total += info.st_size
                if total > max_bytes:
                    raise BackupError("limit_exceeded")
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
                with os.fdopen(fd, "rb") as stream:
                    if signature(os.fstat(fd)) != signature(info):
                        raise BackupError("source_changed")
                    item = tarfile.TarInfo(relative)
                    item.size, item.mode = info.st_size, info.st_mode & 0o777
                    archive.addfile(item, TimedReader(stream, budget))
                    if signature(os.fstat(fd)) != signature(info):
                        raise BackupError("source_changed")
            else:
                raise BackupError("unsafe_entry")
            snapshots.append((directory_fd, name, signature(info)))
        if signature(os.fstat(directory_fd)) != signature(before):
            raise BackupError("source_changed")

    try:
        root_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened.append(root_fd)
        archive_path = destination / "data.tar"
        with archive_path.open("xb") as stream:
            os.chmod(archive_path, 0o600)
            with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
                walk(root_fd, "", archive)
            stream.flush()
            os.fsync(stream.fileno())
        for parent, name, before in snapshots:
            budget()
            if signature(os.stat(name, dir_fd=parent, follow_symlinks=False)) != before:
                raise BackupError("source_changed")
        if is_quiescent() is not True:
            raise BackupError("not_quiescent")
        digest, size = digest_file(archive_path, max_bytes=max_bytes + ARCHIVE_OVERHEAD_MAX)
        budget()
        manifest = FilesystemCapture(
            binding=binding,
            created_at=started,
            completed_at=time.time(),
            size=size,
            sha256=digest,
            entries=entries,
            data_bytes=total,
        )
        verify_archive(archive_path, manifest)
        budget()
        private_json(destination / "manifest.json", manifest.model_dump(mode="json"))
        complete = True
        return manifest
    except (OSError, tarfile.TarError):
        raise BackupError("capture_failed") from None
    finally:
        for fd in reversed(opened):
            os.close(fd)
        if not complete:
            shutil.rmtree(destination)


def verify_archive(path: Path, manifest: FilesystemCapture) -> None:
    """Validate a bounded portable tree without extracting application data."""
    names = {}
    total = 0
    try:
        with tarfile.open(path, "r:") as archive:
            for item in archive:
                name = safe_name(item.name)
                if name in names or not (item.isfile() or item.isdir()):
                    raise BackupError("unsafe_entry")
                if item.mode & ~0o777 or item.uid != 0 or item.gid != 0:
                    raise BackupError("unsafe_entry")
                for parent in PurePosixPath(name).parents:
                    if str(parent) != "." and names.get(str(parent)) != "dir":
                        raise BackupError("unsafe_entry")
                names[name] = "dir" if item.isdir() else "file"
                total += item.size
                if len(names) > manifest.entries or total > manifest.data_bytes:
                    raise BackupError("limit_exceeded")
            if len(names) != manifest.entries or total != manifest.data_bytes:
                raise BackupError("evidence_mismatch")
    except (OSError, tarfile.TarError):
        raise BackupError("invalid_archive") from None


def materialize_tree(archive_path: Path, manifest: FilesystemCapture, workspace: Path) -> Path:
    """Restore and re-capture one verified tree inside an empty private workspace.

    This is an offline drill primitive, not a production replacement operation.
    Every archive member is validated before extraction; a deterministic second
    capture verifies the entire restored tree, including empty directories and
    portable permission bits. The caller owns and removes the private workspace.
    """
    if (
        manifest.data_bytes > MAX_RESTORE_BYTES
        or manifest.size > MAX_RESTORE_BYTES + ARCHIVE_OVERHEAD_MAX
    ):
        raise BackupError("limit_exceeded")
    info = workspace.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o777 != 0o700
        or any(workspace.iterdir())
    ):
        raise BackupError("invalid_input")
    digest, size = digest_file(archive_path, max_bytes=manifest.size)
    if digest != manifest.sha256 or size != manifest.size:
        raise BackupError("evidence_mismatch")
    verify_archive(archive_path, manifest)
    data, verification = workspace / "data", workspace / "verification"
    data.mkdir(mode=0o700)
    try:
        with tarfile.open(archive_path, "r:") as archive:
            members = archive.getmembers()
            archive.extractall(data, members=members, filter="data")
        # data_filter tightens permissions; restore the validated portable mode
        # after extraction. Files first, then deepest directories, to keep paths
        # traversable while applying restrictive modes.
        for item in sorted(members, key=lambda item: (item.isdir(), -item.name.count("/"))):
            target = data.joinpath(*PurePosixPath(safe_name(item.name)).parts)
            actual = target.lstat()
            if (item.isdir() and not stat.S_ISDIR(actual.st_mode)) or (
                item.isfile() and not stat.S_ISREG(actual.st_mode)
            ):
                raise BackupError("unsafe_entry")
            target.chmod(item.mode & 0o777, follow_symlinks=False)
        restored = capture_files(
            data,
            verification,
            manifest.binding,
            is_quiescent=lambda: True,
            max_bytes=max(1, manifest.data_bytes),
        )
        if (
            restored.sha256 != manifest.sha256
            or restored.size != manifest.size
            or restored.entries != manifest.entries
            or restored.data_bytes != manifest.data_bytes
        ):
            raise BackupError("evidence_mismatch")
        digest, size = digest_file(archive_path, max_bytes=manifest.size)
        if digest != manifest.sha256 or size != manifest.size:
            raise BackupError("evidence_mismatch")
        shutil.rmtree(verification)
        return data
    except BackupError:
        raise
    except (OSError, tarfile.TarError, ValueError):
        raise BackupError("invalid_archive") from None
