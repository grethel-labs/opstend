"""Narrow, restart-safe retirement of a previously authorized private capture.

The executor must persist the intent and verify retention policy before invoking
this primitive. It does not decide eligibility or select a project or path.
"""

from __future__ import annotations

import ctypes
import errno
import os
import stat
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .backupexport import acl_attributes
from .backups import BackupError


class RetirementIntent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    artifact: str = Field(pattern=r"^[a-f0-9]{32}$")
    capture_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    namespace: Literal["capture", "import"] = "capture"
    data_name: Literal["data.tar", "database.sqlite"]
    directory_device: int = Field(ge=0)
    directory_inode: int = Field(gt=0)
    data_device: int = Field(ge=0)
    data_inode: int = Field(gt=0)
    manifest_device: int = Field(ge=0)
    manifest_inode: int = Field(gt=0)


def _rename_noreplace(parent_fd: int, source: str, destination: str):
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent_fd, os.fsencode(source), parent_fd, os.fsencode(destination), 1):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def retire_capture(parent: Path, intent: RetirementIntent, *, import_gid: int | None = None) -> str:
    """Resume a journaled capture retirement without following links.

    Caller must hold the root project lock, prevent new exports for this
    artifact, and durably record this exact intent before the first call.
    Missing files are accepted only inside the same previously renamed directory.
    """
    parent = Path(parent)
    pfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_info = os.fstat(pfd)
        imported = intent.namespace == "import"
        if (
            parent_info.st_uid != os.geteuid()
            or stat.S_IMODE(parent_info.st_mode) != (0o750 if imported else 0o700)
            or (imported and (import_gid is None or parent_info.st_gid != import_gid))
            or acl_attributes(parent)
        ):
            raise BackupError("unsafe_spool")
        retiring = ".retiring-" + intent.artifact

        def info(name):
            try:
                return os.stat(name, dir_fd=pfd, follow_symlinks=False)
            except FileNotFoundError:
                return None

        source_info, retired_info = info(intent.artifact), info(retiring)
        if source_info is not None and retired_info is not None:
            raise BackupError("ambiguous_retirement")
        if source_info is None and retired_info is None:
            return "already_absent"
        chosen = intent.artifact if source_info is not None else retiring
        existing = source_info if source_info is not None else retired_info
        if (
            existing is None
            or not stat.S_ISDIR(existing.st_mode)
            or existing.st_uid != os.geteuid()
            or stat.S_IMODE(existing.st_mode) not in ((0o550, 0o700) if imported else (0o700,))
            or (imported and existing.st_gid != import_gid)
            or (existing.st_dev, existing.st_ino)
            != (intent.directory_device, intent.directory_inode)
            or acl_attributes(parent / chosen)
        ):
            raise BackupError("unsafe_spool")
        dfd = os.open(chosen, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=pfd)
        try:
            opened = os.fstat(dfd)
            if (opened.st_dev, opened.st_ino) != (existing.st_dev, existing.st_ino):
                raise BackupError("unsafe_spool")
            expected = {
                "manifest.json": (intent.manifest_device, intent.manifest_inode),
                intent.data_name: (intent.data_device, intent.data_inode),
            }
            names = set()
            with os.scandir(dfd) as iterator:
                for entry in iterator:
                    names.add(entry.name)
                    if len(names) > len(expected):
                        raise BackupError("ambiguous_retirement")
            if not names <= expected.keys() or (
                source_info is not None and names != expected.keys()
            ):
                raise BackupError("ambiguous_retirement")
            for name in names:
                entry = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                if (
                    not stat.S_ISREG(entry.st_mode)
                    or entry.st_uid != os.geteuid()
                    or stat.S_IMODE(entry.st_mode) != (0o440 if imported else 0o600)
                    or (imported and entry.st_gid != import_gid)
                    or entry.st_nlink != 1
                    or (entry.st_dev, entry.st_ino) != expected[name]
                    or acl_attributes(parent / chosen / name)
                ):
                    raise BackupError("unsafe_spool")
            if imported and stat.S_IMODE(opened.st_mode) == 0o550:
                # Keep the directory root-private after a crash and make its
                # fixed entries removable without granting write to the worker.
                os.fchmod(dfd, 0o700)
                os.fsync(dfd)
            if source_info is not None:
                try:
                    _rename_noreplace(pfd, intent.artifact, retiring)
                except OSError as exc:
                    if exc.errno == errno.EEXIST:
                        raise BackupError("ambiguous_retirement") from None
                    raise
                os.fsync(pfd)
            for name in (intent.data_name, "manifest.json"):
                if name in names:
                    os.unlink(name, dir_fd=dfd)
                    os.fsync(dfd)
        finally:
            os.close(dfd)
        os.rmdir(retiring, dir_fd=pfd)
        os.fsync(pfd)
        return "removed"
    finally:
        os.close(pfd)
