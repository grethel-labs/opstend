"""Replace one project's data tree with an exact, verified capture (L06).

Root-side primitive for update recovery. It never deletes data: the live tree is
renamed to `data.preserved-<token>` and stays until an operator removes it. The swap is
two atomic renames; a process death between them is recognised from the directory
layout alone and finished, so a retry after any crash converges on the same state and
never restores twice over data written after the first restore.

Layout under the project root (`/srv/steward/projects/<id>`), `token` derived from the
approval id:

    data/                      live tree, owned by the service user
    .restore-<token>/data/     verified staging tree (extracted and re-captured)
    data.preserved-<token>/    the tree that was replaced
"""

from __future__ import annotations

import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

from ..core.backups import BackupError, FilesystemCapture
from ..core.filebackups import materialize_tree
from ..core.update_recovery import MAX_PRESERVED_TREES

FREE_MARGIN = 256 * 1024 * 1024


@dataclass(frozen=True)
class Restored:
    state: str  # "restored" | "already_restored" | "finished"
    preserved: str  # directory name under the project root


def _sync(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _lstat_dir(path: Path):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(info.st_mode):
        raise BackupError("unsafe_entry")
    return info


def _chown_tree(top: Path, uid: int, gid: int) -> None:
    os.lchown(top, uid, gid)
    for current, directories, files in os.walk(top, followlinks=False):
        for name in (*directories, *files):
            os.lchown(os.path.join(current, name), uid, gid)


def preserved_trees(root: Path) -> list[str]:
    try:
        return sorted(n for n in os.listdir(root) if n.startswith("data.preserved-"))
    except OSError:
        return []


def restore_tree(
    root: Path, archive_dir: Path, manifest: FilesystemCapture, *, token: str, service_uid: int
) -> Restored:
    """Make `root/data` equal to the capture. The workload must be stopped by the caller.

    Raises BackupError (stable `error_class`) and changes nothing visible unless the
    verified staging tree is complete."""
    if not token.isalnum() or len(token) > 40:
        raise BackupError("invalid_input")
    data, preserved = root / "data", root / f"data.preserved-{token}"
    stage = root / f".restore-{token}"
    if _lstat_dir(root) is None:
        raise BackupError("invalid_input")

    if os.path.lexists(preserved):
        # An earlier attempt already moved the live tree away.
        if os.path.lexists(stage):
            staged = stage / "data"
            if _lstat_dir(staged) is not None:
                if os.path.lexists(data):
                    raise BackupError("evidence_mismatch")
                os.rename(staged, data)  # finish the interrupted swap
                _sync(root)
            elif _lstat_dir(data) is None:
                raise BackupError("evidence_mismatch")
            try:
                os.rmdir(stage)  # only the empty leftover of the finished swap
            except OSError:
                raise BackupError("evidence_mismatch") from None
            _sync(root)
            return Restored("finished", preserved.name)
        if _lstat_dir(data) is None or _lstat_dir(preserved) is None:
            raise BackupError("evidence_mismatch")
        return Restored("already_restored", preserved.name)

    live = _lstat_dir(data)
    if live is None or live.st_uid != service_uid:
        raise BackupError("unsafe_owner")
    if len(preserved_trees(root)) >= MAX_PRESERVED_TREES:
        raise BackupError("retention_limit")
    if shutil.disk_usage(root).free < manifest.data_bytes + FREE_MARGIN:
        raise BackupError("insufficient_space")
    if os.path.lexists(stage):
        shutil.rmtree(stage)  # leftover of our own incomplete staging (the live tree is untouched)
    stage.mkdir(mode=0o700)
    try:
        tree = materialize_tree(archive_dir / manifest.filename, manifest, stage)
        _chown_tree(tree, service_uid, live.st_gid)
        os.chmod(tree, 0o700)
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    _sync(stage)
    os.rename(data, preserved)
    _sync(root)
    os.rename(tree, data)
    _sync(root)
    os.rmdir(stage)
    _sync(root)
    return Restored("restored", preserved.name)
