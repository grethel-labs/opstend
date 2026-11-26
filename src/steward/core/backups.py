"""Consistent SQLite captures and explicitly scoped backup evidence.

These operator-local captures are not executor attestations and cannot authorize
production recovery or mutation. Application verification is a separate gate.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import stat
import time
from pathlib import Path
from typing import Literal
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field

from .canonical import revision_id
from .config import ImageRef, Slug
from .inventory import Digest


class BackupError(Exception):
    def __init__(self, error_class: str):
        super().__init__(error_class)
        self.error_class = error_class


class Data(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class Binding(Data):
    server: Slug
    project: Slug
    config_revision: Digest
    image: ImageRef
    source_revision: str = Field(pattern=r"^[A-Za-z0-9@:._/+-]{1,200}$")


class Capture(Data):
    v: Literal[1] = 1
    origin: Literal["operator_local"] = "operator_local"
    binding: Binding
    created_at: float = Field(ge=0)
    completed_at: float = Field(ge=0)
    mechanism: Literal["sqlite_online_backup"] = "sqlite_online_backup"
    filename: Literal["database.sqlite"] = "database.sqlite"
    size: int = Field(ge=0, le=2**40)
    sha256: Digest
    database_integrity: Literal["ok"] = "ok"

    @property
    def id(self):
        return revision_id(self.model_dump(mode="json"))


class FilesystemCapture(Data):
    v: Literal[1] = 1
    origin: Literal["operator_local"] = "operator_local"
    binding: Binding
    created_at: float = Field(ge=0)
    completed_at: float = Field(ge=0)
    mechanism: Literal["verified_quiescence"] = "verified_quiescence"
    filename: Literal["data.tar"] = "data.tar"
    size: int = Field(ge=0, le=2**40)
    sha256: Digest
    entries: int = Field(ge=0, le=10000)
    data_bytes: int = Field(ge=0, le=2**40)

    @property
    def id(self):
        return revision_id(self.model_dump(mode="json"))


class Receipt(Data):
    v: Literal[1] = 1
    provider: Literal["restic"] = "restic"
    capture: Capture | FilesystemCapture = Field(discriminator="mechanism")
    repository_id: Digest
    snapshot_id: Digest
    snapshot_path: str = Field(min_length=1, max_length=4096)
    snapshot_created_at: float = Field(ge=0)
    recorded_at: float = Field(ge=0)
    integrity_checked_at: float | None = Field(None, ge=0)
    restore_verified_at: float | None = Field(None, ge=0)
    application_verified: Literal[False] = False


def private_json(path: Path, body: dict):
    """A private report replacement; retain the old report on write failure."""
    import tempfile

    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, mode="w", encoding="utf-8", delete=False
        ) as handle:
            temporary = Path(handle.name)
            json.dump(body, handle, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def regular_file(path: Path, *, limit: int | None = None) -> tuple[int, os.stat_result]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (limit is not None and info.st_size > limit):
            raise BackupError("invalid_input")
        return fd, info
    except BaseException:
        os.close(fd)
        raise


def digest_file(path: Path, *, max_bytes: int) -> tuple[str, int]:
    fd, info = regular_file(path, limit=max_bytes)
    digest, size = hashlib.sha256(), 0
    with os.fdopen(fd, "rb") as handle:
        while block := handle.read(1024 * 1024):
            size += len(block)
            if size > max_bytes:
                raise BackupError("limit_exceeded")
            digest.update(block)
        after = os.fstat(handle.fileno())
    if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    ):
        raise BackupError("source_changed")
    return digest.hexdigest(), size


def database_check(path: Path, *, timeout_s: float = 180):
    deadline = time.monotonic() + timeout_s
    connection = sqlite3.connect(
        "file:" + quote(str(path.resolve()), safe="/") + "?mode=ro", uri=True, timeout=5
    )
    try:
        connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 10000)
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA query_only=ON")
        if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise BackupError("database_invalid")
    finally:
        connection.close()


def capture_sqlite(
    source: Path,
    destination: Path,
    binding: Binding,
    *,
    max_bytes: int = 256 * 1024 * 1024,
    timeout_s: float = 180,
) -> Capture:
    if not 1024 <= max_bytes <= 64 * 1024**3 or not 0 < timeout_s <= 3600:
        raise BackupError("invalid_input")
    fd, original = regular_file(source)
    os.close(fd)
    # The directory is claimed exclusively; an existing capture is never replaced.
    destination.mkdir(mode=0o700)
    complete = False
    started_at = time.time()
    try:
        deadline = time.monotonic() + timeout_s
        target = destination / "database.sqlite"
        src = sqlite3.connect(
            "file:" + quote(str(source.absolute()), safe="/") + "?mode=ro", uri=True, timeout=5
        )
        try:
            src.execute("PRAGMA trusted_schema=OFF")
            src.execute("PRAGMA query_only=ON")
            src.execute("PRAGMA mmap_size=0")
            src.execute("PRAGMA cache_size=-8192")
            page_size = src.execute("PRAGMA page_size").fetchone()[0]
            if page_size * src.execute("PRAGMA page_count").fetchone()[0] > max_bytes:
                raise BackupError("limit_exceeded")
            dst = sqlite3.connect(target)
            try:

                def progress(_status, _remaining, total):
                    if total * page_size > max_bytes:
                        raise BackupError("limit_exceeded")
                    if time.monotonic() >= deadline:
                        raise BackupError("timeout")

                src.backup(dst, pages=16, progress=progress, sleep=0.01)
                if dst.execute("PRAGMA journal_mode=DELETE").fetchone()[0] != "delete":
                    raise BackupError("capture_failed")
            finally:
                dst.close()
        finally:
            src.close()
        current = source.lstat()
        if stat.S_ISLNK(current.st_mode) or (current.st_dev, current.st_ino) != (
            original.st_dev,
            original.st_ino,
        ):
            raise BackupError("source_changed")
        database_check(target, timeout_s=max(0.001, deadline - time.monotonic()))
        target.chmod(0o600)
        digest, size = digest_file(target, max_bytes=max_bytes)
        if time.monotonic() >= deadline:
            raise BackupError("timeout")
        manifest = Capture(
            binding=binding,
            created_at=started_at,
            completed_at=time.time(),
            size=size,
            sha256=digest,
        )
        private_json(destination / "manifest.json", manifest.model_dump(mode="json"))
        complete = True
        return manifest
    except (sqlite3.Error, OSError):
        raise BackupError("capture_failed") from None
    finally:
        if not complete:
            shutil.rmtree(destination)


def load_capture(directory: Path) -> Capture | FilesystemCapture:
    if not directory.is_dir() or directory.is_symlink():
        raise BackupError("invalid_input")
    fd, _info = regular_file(directory / "manifest.json", limit=65536)
    with os.fdopen(fd, "rb") as handle:
        raw = json.load(handle)
    if not isinstance(raw, dict):
        raise BackupError("invalid_input")
    model = FilesystemCapture if raw.get("mechanism") == "verified_quiescence" else Capture
    manifest = model.model_validate(raw)
    if {p.name for p in directory.iterdir()} != {"manifest.json", manifest.filename}:
        raise BackupError("invalid_input")
    digest, size = digest_file(directory / manifest.filename, max_bytes=manifest.size)
    if digest != manifest.sha256 or size != manifest.size:
        raise BackupError("evidence_mismatch")
    if isinstance(manifest, FilesystemCapture):
        from .filebackups import verify_archive

        verify_archive(directory / manifest.filename, manifest)
    return manifest
