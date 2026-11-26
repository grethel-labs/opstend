"""Archives of retired applications and their restore (L09 steps 2 and 3).

Layout under the root-owned archive root (default ``/srv/steward/archive``)::

    <application>/.lock
    <application>/<operation>/manifest.json   exact data/image bindings, written last
    <application>/<operation>/state.json      durable journal (atomic replace + fsync)
    <application>/<operation>/data/<service>/{data.tar,manifest.json}
    <application>/<operation>/images/<service>.tar

There is deliberately no function that deletes a verified archive: only the
partial output of an operation that never reached ``verified`` can be discarded.
Retirement releases the *working* data only after the archive was re-read and
verified; re-addition restores and verifies before anything starts.
Error classes are stable strings, never paths or file content.
"""

from __future__ import annotations

import ctypes
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import time
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .backupexport import acl_attributes, protected_capture, sync_directory
from .backups import (
    BackupError,
    Binding,
    FilesystemCapture,
    digest_file,
    private_json,
    regular_file,
)
from .canonical import revision_id
from .config import ImageRef, Slug
from .data_ownership import inspect_data_ownership
from .filebackups import ARCHIVE_OVERHEAD_MAX, capture_files, materialize_tree
from .ids import graph_identifier
from .inventory import Digest

ARCHIVE_ROOT = Path("/srv/steward/archive")
IMAGE_CACHE = Path("/var/lib/steward/images")
MAX_OPERATIONS = 64
MAX_IMAGE_BYTES = 4 * 1024**3
MAX_MANIFEST_BYTES = 262144
FREE_SPACE_RESERVE = 512 * 1024 * 1024
OPERATION = re.compile(r"[a-f0-9]{32}")
RENAME_NOREPLACE = 1

Phase = Literal[
    "archiving",
    "archived",
    "verified",
    "releasing",
    "released",
    "reactivated",
    "cancelled",
    "failed",
]
TERMINAL = frozenset({"reactivated", "cancelled", "failed"})
UNVERIFIED = frozenset({"archiving", "archived"})
TRANSITIONS: dict[str, frozenset[str]] = {
    "archiving": frozenset({"archived", "failed"}),
    "archived": frozenset({"verified", "failed"}),
    "verified": frozenset({"releasing", "cancelled"}),
    "releasing": frozenset({"released", "reactivated"}),
    "released": frozenset({"reactivated"}),
}
Release = Literal["pending", "moved", "deleted"]


class Data(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)


class Identity(Data):
    """The numerical identity that owns archived data; it stays reserved."""

    uid: int = Field(ge=30000, le=39999)
    gid: int = Field(ge=1, lt=2**32 - 1)
    subuid: list[int] = Field(min_length=2, max_length=2)
    subgid: list[int] = Field(min_length=2, max_length=2)

    @field_validator("subuid", "subgid")
    @classmethod
    def _range(cls, value: list[int]) -> list[int]:
        if value[1] != 65536 or not 1 <= value[0] <= 2**32 - 1 - 65536:
            raise ValueError("invalid subordinate range")
        return value


class ImageCopy(Data):
    cache_name: str = Field(pattern=r"^[a-f0-9]{64}\.tar$")
    sha256: Digest
    size: int = Field(ge=1, le=MAX_IMAGE_BYTES)


class ServiceArchive(Data):
    service: Slug
    user: str = Field(pattern=r"^stw-s[0-9a-f]{20}$")
    unit: str = Field(pattern=r"^s[0-9a-f]{20}\.service$")
    identity: Identity
    image: ImageRef
    image_tag: str = Field(pattern=r"^localhost/steward/[a-z0-9-]{2,64}:sha256-[a-f0-9]{32}$")
    image_copy: ImageCopy | None = None
    data_source: str | None = Field(None, max_length=4096)
    data: FilesystemCapture | None = None
    source_signature: Digest | None = None

    @model_validator(mode="after")
    def _data(self):
        if (self.data_source is None) != (self.data is None) or (self.data is None) != (
            self.source_signature is None
        ):
            raise ValueError("incomplete data binding")
        return self


class ArchiveManifest(Data):
    v: Literal[1] = 1
    application: Slug
    isolation: Literal["separate"] = "separate"
    operation_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    applied_revision: Digest
    desired_revision: Digest
    server: Slug
    created_at: float = Field(ge=0)
    completed_at: float = Field(ge=0)
    services: dict[Slug, ServiceArchive] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def _bindings(self):
        if self.completed_at < self.created_at:
            raise ValueError("invalid archive times")
        for name, item in self.services.items():
            stem = graph_identifier("s", self.application, name)
            if (
                item.service != name
                or item.user != "stw-" + stem
                or item.unit != stem + ".service"
                or (
                    item.data is not None
                    and (
                        item.data.binding.project != stem
                        or item.data.binding.config_revision != self.applied_revision
                        or item.data.binding.server != self.server
                    )
                )
            ):
                raise ValueError("archive service binding mismatch")
        return self

    @property
    def id(self) -> str:
        return revision_id(self.model_dump(mode="json"))


class ArchiveState(Data):
    v: Literal[1] = 1
    operation_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    application: Slug
    phase: Phase
    generation: int = Field(ge=0, le=100000)
    created_at: float = Field(ge=0)
    updated_at: float = Field(ge=0)
    applied_revision: Digest
    desired_revision: Digest
    manifest_id: Digest | None = None
    released: dict[Slug, Release] = Field(default_factory=dict, max_length=64)
    error_class: str | None = Field(None, pattern=r"^[a-z_]{1,40}$")

    @model_validator(mode="after")
    def _consistent(self):
        if (self.phase not in ("archiving", "failed")) and self.manifest_id is None:
            raise ValueError("archive state lacks its manifest binding")
        if self.phase in ("archiving", "archived", "verified", "cancelled") and any(
            value != "pending" for value in self.released.values()
        ):
            raise ValueError("data was released before verification")
        return self


@dataclass(frozen=True)
class ServiceInput:
    """Registered, root-derived facts for one service; never caller supplied."""

    service: str
    user: str
    unit: str
    identity: dict
    image: str
    image_tag: str
    source_revision: str
    data_source: Path | None


def image_cache_name(reference: str, tag: str) -> str:
    """Mirror ansible's `[image_ref, image_tag] | to_json | hash('sha256')` cache name."""
    return hashlib.sha256(json.dumps([reference, tag]).encode()).hexdigest() + ".tar"


def retired_name(operation_id: str, service: str) -> str:
    return f".retired-{operation_id[:12]}-{service}"


# ---- directories, locks and the journal ---------------------------------------------


def _private_directory(path: Path, *, create: bool = False) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if not create:
            raise BackupError("invalid_input") from None
        path.mkdir(mode=0o700)
        path.chmod(0o700)
        sync_directory(path.parent)
        info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o777 != 0o700
        or acl_attributes(path)
    ):
        raise BackupError("unsafe_archive")


def application_directory(root: Path, application: str, *, create: bool = False) -> Path:
    if (
        not isinstance(application, str)
        or re.fullmatch(r"[a-z][a-z0-9-]{1,30}[a-z0-9]", application) is None
    ):
        raise BackupError("invalid_input")
    try:
        _private_directory(root, create=create)
        path = root / application
        _private_directory(path, create=create)
    except OSError:
        raise BackupError("unsafe_archive") from None
    return path


def operation_directory(root: Path, application: str, operation_id: str) -> Path:
    if OPERATION.fullmatch(operation_id) is None:
        raise BackupError("invalid_input")
    return application_directory(root, application) / operation_id


@contextmanager
def archive_lock(root: Path, application: str, *, create: bool = False):
    """One archive operation per application; the executor and deployment share it."""
    directory = application_directory(root, application, create=create)
    try:
        fd = os.open(directory / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError:
        raise BackupError("unsafe_archive") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
            raise BackupError("unsafe_archive")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BackupError("target_busy") from None
        yield directory
    finally:
        os.close(fd)


def read_state(operation: Path) -> ArchiveState:
    try:
        fd, info = regular_file(operation / "state.json", limit=65536)
    except OSError:
        raise BackupError("corrupt_archive") from None
    with os.fdopen(fd, "rb") as handle:
        if info.st_uid != os.geteuid() or info.st_mode & 0o777 != 0o600 or info.st_nlink != 1:
            raise BackupError("unsafe_archive")
        try:
            state = ArchiveState.model_validate_json(handle.read())
        except ValueError:
            raise BackupError("corrupt_archive") from None
    if state.operation_id != operation.name:
        raise BackupError("corrupt_archive")
    return state


def write_state(operation: Path, state: ArchiveState) -> None:
    private_json(operation / "state.json", state.model_dump(mode="json"))
    sync_directory(operation)


def operations(root: Path, application: str) -> list[ArchiveState]:
    """All journaled operations, oldest first; unknown entries fail closed."""
    directory = application_directory(root, application)
    states = []
    with os.scandir(directory) as entries:
        for entry in entries:
            if entry.name == ".lock":
                continue
            if OPERATION.fullmatch(entry.name) is None or len(states) >= MAX_OPERATIONS:
                raise BackupError("unsafe_archive")
            _private_directory(directory / entry.name)
            state = read_state(directory / entry.name)
            if state.application != application:
                raise BackupError("corrupt_archive")
            states.append(state)
    return sorted(states, key=lambda item: (item.created_at, item.operation_id))


def active_operation(root: Path, application: str) -> ArchiveState | None:
    active = [item for item in operations(root, application) if item.phase not in TERMINAL]
    if len(active) > 1:
        raise BackupError("state_conflict")
    return active[0] if active else None


def start_operation(
    root: Path,
    application: str,
    operation_id: str,
    *,
    applied_revision: str,
    desired_revision: str,
    now: float | None = None,
) -> ArchiveState:
    directory = application_directory(root, application, create=True)
    if active_operation(root, application) is not None:
        raise BackupError("state_conflict")
    if len(operations(root, application)) >= MAX_OPERATIONS:
        raise BackupError("archive_capacity")
    operation = directory / operation_id
    if OPERATION.fullmatch(operation_id) is None:
        raise BackupError("invalid_input")
    operation.mkdir(mode=0o700)
    operation.chmod(0o700)
    stamp = time.time() if now is None else now
    state = ArchiveState(
        operation_id=operation_id,
        application=application,
        phase="archiving",
        generation=0,
        created_at=stamp,
        updated_at=stamp,
        applied_revision=applied_revision,
        desired_revision=desired_revision,
    )
    write_state(operation, state)
    sync_directory(directory)
    return state


def advance(
    root: Path,
    state: ArchiveState,
    phase: str | None = None,
    *,
    now: float | None = None,
    **changes,
) -> ArchiveState:
    """Persist the next journal state; only declared transitions are possible."""
    operation = operation_directory(root, state.application, state.operation_id)
    if read_state(operation) != state:
        raise BackupError("state_conflict")
    if phase is not None and phase != state.phase and phase not in TRANSITIONS.get(state.phase, ()):
        raise BackupError("state_conflict")
    try:
        updated = ArchiveState.model_validate(
            {
                **state.model_dump(mode="json"),
                **changes,
                "phase": phase or state.phase,
                "generation": state.generation + 1,
                "updated_at": time.time() if now is None else now,
            }
        )
    except ValueError:
        raise BackupError("state_conflict") from None
    write_state(operation, updated)
    return updated


def discard_unverified(root: Path, state: ArchiveState, error_class: str) -> ArchiveState:
    """Remove the partial output of an operation that never verified.

    This is the only removal of archive bytes. It refuses any state from
    ``verified`` onward, so a verified archive can never be deleted here.
    """
    if state.phase not in UNVERIFIED:
        raise BackupError("state_conflict")
    operation = operation_directory(root, state.application, state.operation_id)
    if read_state(operation) != state:
        raise BackupError("state_conflict")
    for name in ("data", "images", "manifest.json"):
        target = operation / name
        info = None
        try:
            info = target.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISDIR(info.st_mode):
            shutil.rmtree(target)
        else:
            target.unlink()
    sync_directory(operation)
    return advance(root, state, "failed", error_class=error_class)


# ---- writing ------------------------------------------------------------------------


def _copy_image(source: Path, destination: Path, limit: int) -> tuple[str, int]:
    fd, info = regular_file(source, limit=limit)
    digest, size = hashlib.sha256(), 0
    try:
        if info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o022:
            raise BackupError("unsafe_entry")
        with os.fdopen(fd, "rb") as reader, destination.open("xb") as writer:
            os.chmod(destination, 0o600)
            while block := reader.read(1024 * 1024):
                size += len(block)
                if size > limit:
                    raise BackupError("limit_exceeded")
                digest.update(block)
                writer.write(block)
            writer.flush()
            os.fsync(writer.fileno())
            after = os.fstat(reader.fileno())
        if (after.st_size, after.st_mtime_ns) != (info.st_size, info.st_mtime_ns) or size < 1:
            raise BackupError("source_changed")
    except OSError:
        raise BackupError("capture_failed") from None
    return digest.hexdigest(), size


def write_archive(
    operation: Path,
    state: ArchiveState,
    *,
    server: str,
    services: list[ServiceInput],
    image_cache: Path,
    is_quiescent: Callable[[], bool],
    max_data_bytes: int,
    timeout_s: float = 300,
    now: Callable[[], float] = time.time,
) -> ArchiveManifest:
    """Copy every registered data tree and image archive, then publish the manifest.

    The caller holds the application lock, has verified that every writer is
    stopped, and persists the journal. Failure leaves partial output for
    `discard_unverified`; the working data is never touched here.
    """
    if state.phase != "archiving" or not services or max_data_bytes < 1:
        raise BackupError("invalid_input")
    started = now()
    deadline = time.monotonic() + timeout_s
    signatures: dict[str, tuple[str, int]] = {}
    total = 0
    for item in services:
        if item.data_source is not None:
            signature, size = inspect_data_ownership(
                item.data_source,
                service_uid=item.identity["uid"],
                max_bytes=max(1, max_data_bytes - total),
                deadline=deadline,
            )
            signatures[item.service] = (signature, size)
            total += size
    images: dict[str, Path | None] = {}
    image_bytes = 0
    for item in services:
        path = image_cache / image_cache_name(item.image, item.image_tag)
        try:
            info = path.lstat()
        except FileNotFoundError:
            images[item.service] = None
            continue
        if not stat.S_ISREG(info.st_mode):
            raise BackupError("unsafe_entry")
        images[item.service] = path
        image_bytes += info.st_size
    needed = (
        total
        + image_bytes
        + sum(1 for item in services if item.data_source is not None) * ARCHIVE_OVERHEAD_MAX
        + FREE_SPACE_RESERVE
    )
    if shutil.disk_usage(operation).free < needed:
        raise BackupError("insufficient_space")
    (operation / "data").mkdir(mode=0o700, exist_ok=True)
    (operation / "images").mkdir(mode=0o700, exist_ok=True)
    entries: dict[str, ServiceArchive] = {}
    used = 0
    for item in sorted(services, key=lambda value: value.service):
        stem = graph_identifier("s", state.application, item.service)
        capture = copy = signature = None
        if item.data_source is not None:
            binding = {
                "server": server,
                "project": stem,
                "config_revision": state.applied_revision,
                "image": item.image,
                "source_revision": item.source_revision,
            }
            capture = capture_files(
                item.data_source,
                operation / "data" / item.service,
                Binding.model_validate(binding),
                is_quiescent=is_quiescent,
                max_bytes=max(1, max_data_bytes - used),
                timeout_s=max(1.0, deadline - time.monotonic()),
            )
            used += capture.data_bytes
            signature = signatures[item.service][0]
        if images[item.service] is not None:
            sha256, size = _copy_image(
                images[item.service], operation / "images" / f"{item.service}.tar", MAX_IMAGE_BYTES
            )
            copy = ImageCopy(cache_name=images[item.service].name, sha256=sha256, size=size)
        entries[item.service] = ServiceArchive(
            service=item.service,
            user=item.user,
            unit=item.unit,
            identity=Identity.model_validate(item.identity),
            image=item.image,
            image_tag=item.image_tag,
            image_copy=copy,
            data_source=None if item.data_source is None else str(item.data_source),
            data=capture,
            source_signature=signature,
        )
        if time.monotonic() >= deadline:
            raise BackupError("timeout")
    manifest = ArchiveManifest(
        application=state.application,
        operation_id=state.operation_id,
        applied_revision=state.applied_revision,
        desired_revision=state.desired_revision,
        server=server,
        created_at=started,
        completed_at=max(started, now()),
        services=entries,
    )
    try:
        private_json(operation / "manifest.json", manifest.model_dump(mode="json"))
        sync_directory(operation / "data")
        sync_directory(operation / "images")
        sync_directory(operation)
    except OSError:
        raise BackupError("capture_failed") from None
    return manifest


# ---- verification -------------------------------------------------------------------


def _protected_file(path: Path, *, limit: int) -> None:
    fd, info = regular_file(path, limit=limit)
    os.close(fd)
    if (
        info.st_uid != os.geteuid()
        or info.st_mode & 0o777 != 0o600
        or info.st_nlink != 1
        or acl_attributes(path)
    ):
        raise BackupError("unsafe_archive")


def verify_archive(operation: Path, *, expected_id: str) -> ArchiveManifest:
    """Independently re-read every archived byte and the structure around it."""
    try:
        _private_directory(operation)
        _protected_file(operation / "manifest.json", limit=MAX_MANIFEST_BYTES)
        fd, _ = regular_file(operation / "manifest.json", limit=MAX_MANIFEST_BYTES)
        with os.fdopen(fd, "rb") as handle:
            manifest = ArchiveManifest.model_validate_json(handle.read())
        if manifest.id != expected_id or manifest.operation_id != operation.name:
            raise BackupError("evidence_mismatch")
        names = {entry.name for entry in os.scandir(operation)}
        data = {name for name, item in manifest.services.items() if item.data is not None}
        images = {name for name, item in manifest.services.items() if item.image_copy is not None}
        if names != {"manifest.json", "state.json", "data", "images"}:
            raise BackupError("evidence_mismatch")
        for name in ("data", "images"):
            _private_directory(operation / name)
        if {entry.name for entry in os.scandir(operation / "data")} != data or {
            entry.name for entry in os.scandir(operation / "images")
        } != {f"{name}.tar" for name in images}:
            raise BackupError("evidence_mismatch")
        for name in sorted(data):
            _private_directory(operation / "data" / name)
            for filename in ("data.tar", "manifest.json"):
                _protected_file(
                    operation / "data" / name / filename,
                    limit=manifest.services[name].data.size + MAX_MANIFEST_BYTES,
                )
            capture = protected_capture(operation / "data" / name)
            if capture != manifest.services[name].data:
                raise BackupError("evidence_mismatch")
        for name in sorted(images):
            copy = manifest.services[name].image_copy
            path = operation / "images" / f"{name}.tar"
            _protected_file(path, limit=copy.size)
            digest, size = digest_file(path, max_bytes=copy.size)
            if digest != copy.sha256 or size != copy.size:
                raise BackupError("evidence_mismatch")
        return manifest
    except BackupError:
        raise
    except (OSError, ValueError):
        raise BackupError("corrupt_archive") from None


# ---- releasing the working area -----------------------------------------------------


def release_data(data_root: Path, operation_id: str, service: str) -> Release:
    """Remove one service's working data after its archive verified; idempotent.

    The live directory is renamed first (atomic), then the renamed copy is
    removed, so an interruption leaves either the intact tree or an unambiguous
    `.retired-*` leftover that a retry or the restore step finishes.
    """
    live = data_root / service
    leftover = data_root / retired_name(operation_id, service)
    parent = os.open(data_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            info = live.lstat()
        except FileNotFoundError:
            info = None
        if info is not None:
            if not stat.S_ISDIR(info.st_mode):
                raise BackupError("unsafe_entry")
            if os.path.lexists(leftover):
                raise BackupError("state_conflict")
            rename_noreplace(parent, live.name, parent, leftover.name)
            os.fsync(parent)
        try:
            retired = leftover.lstat()
        except FileNotFoundError:
            return "deleted"
        if not stat.S_ISDIR(retired.st_mode):
            raise BackupError("unsafe_entry")
        shutil.rmtree(leftover)
        os.fsync(parent)
        return "deleted"
    except OSError:
        raise BackupError("release_failed") from None
    finally:
        os.close(parent)


def rename_noreplace(source_fd: int, source: str, target_fd: int, target: str) -> None:
    rename = ctypes.CDLL(None, use_errno=True).renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(source_fd, os.fsencode(source), target_fd, os.fsencode(target), RENAME_NOREPLACE):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), target)


def image_cache_matches(path: Path, copy: ImageCopy) -> bool | None:
    """True when the cached tar equals the archived copy, None when it is absent."""
    try:
        digest, size = digest_file(path, max_bytes=copy.size)
    except FileNotFoundError:
        return None
    except (BackupError, OSError):
        return False
    return digest == copy.sha256 and size == copy.size


def release_image_cache(image_cache: Path, copy: ImageCopy) -> bool:
    """Remove the root cache file only when it equals the verified archive copy."""
    path = image_cache / copy.cache_name
    state = image_cache_matches(path, copy)
    if state is None:
        return False
    if state is not True:
        raise BackupError("evidence_mismatch")
    path.unlink()
    sync_directory(image_cache)
    return True


# ---- restoring ----------------------------------------------------------------------


def _chown_tree(root: Path, uid: int, gid: int) -> None:
    stack = [root]
    while stack:
        current = stack.pop()
        os.lchown(current, uid, gid)
        with os.scandir(current) as entries:
            for entry in entries:
                if entry.is_symlink():
                    raise BackupError("unsafe_entry")
                if entry.is_dir(follow_symlinks=False):
                    stack.append(Path(entry.path))
                else:
                    os.lchown(entry.path, uid, gid)


def restore_service_data(
    operation: Path,
    manifest: ArchiveManifest,
    service: str,
    target: Path,
    *,
    uid: int,
    gid: int,
) -> None:
    """Verify, extract and publish one data tree; the target stays empty until complete.

    ``target`` must be the freshly prepared, empty, service-owned 0700 directory.
    The tree is built and verified in a private sibling, handed to the service
    identity, then swapped into place with a no-replace rename.
    """
    item = manifest.services[service]
    if item.data is None or item.data_source != str(target):
        raise BackupError("binding_changed")
    try:
        info = target.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (uid, gid, 0o700)
            or acl_attributes(target)
        ):
            raise BackupError("unsafe_target")
        with os.scandir(target) as entries:
            if any(True for _ in entries):
                raise BackupError("target_not_empty")
        staging = target.parent / f".restore-{manifest.operation_id[:12]}-{service}"
        if os.path.lexists(staging):
            leftover = staging.lstat()
            if not stat.S_ISDIR(leftover.st_mode) or leftover.st_uid != os.geteuid():
                raise BackupError("unsafe_target")
            shutil.rmtree(staging)  # scratch from an interrupted restore; the archive is intact
        staging.mkdir(mode=0o700)
        staging.chmod(0o700)
        try:
            tree = materialize_tree(operation / "data" / service / "data.tar", item.data, staging)
            _chown_tree(tree, uid, gid)
            os.chmod(tree, 0o700)
            sync_directory(tree.parent)
            parent_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            staging_fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.rmdir(target)
                rename_noreplace(staging_fd, tree.name, parent_fd, target.name)
                os.fsync(parent_fd)
            finally:
                os.close(staging_fd)
                os.close(parent_fd)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
    except BackupError:
        raise
    except OSError:
        raise BackupError("restore_failed") from None


def restore_image(
    operation: Path, manifest: ArchiveManifest, service: str, image_cache: Path
) -> bool:
    """Put the archived image tar back into the root cache; never replaces a cache file."""
    copy = manifest.services[service].image_copy
    if copy is None:
        return False
    destination = image_cache / copy.cache_name
    state = image_cache_matches(destination, copy)
    if state is True:
        return False
    if state is False:
        raise BackupError("evidence_mismatch")
    source = operation / "images" / f"{service}.tar"
    temporary = image_cache / f".restore-{manifest.operation_id[:12]}-{service}.tar"
    try:
        if os.path.lexists(temporary):
            temporary.unlink()
        _copy_to(source, temporary, copy)
        os.chmod(temporary, 0o644)
        os.link(temporary, destination)  # fails if a cache file appeared meanwhile
    except FileExistsError:
        raise BackupError("state_conflict") from None
    except OSError:
        raise BackupError("restore_failed") from None
    finally:
        temporary.unlink(missing_ok=True)
    sync_directory(image_cache)
    return True


def _copy_to(source: Path, destination: Path, copy: ImageCopy) -> None:
    sha256, size = _copy_image(source, destination, copy.size)
    if sha256 != copy.sha256 or size != copy.size:
        raise BackupError("evidence_mismatch")


# ---- re-addition --------------------------------------------------------------------


@dataclass(frozen=True)
class ReactivationService:
    user: str
    identity: dict
    data_source: Path | None
    image: str
    image_tag: str


def source_intact(item: ServiceArchive, target: Path, *, max_bytes: int) -> bool:
    """True when the working tree still has the exact signature recorded at archive time."""
    try:
        signature, _ = inspect_data_ownership(
            target,
            service_uid=item.identity.uid,
            max_bytes=max_bytes,
            deadline=time.monotonic() + 300,
        )
    except (BackupError, OSError):
        return False
    return signature == item.source_signature


def _empty_directory(path: Path) -> bool:
    try:
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise BackupError("unsafe_target")
        with os.scandir(path) as entries:
            return not any(True for _ in entries)
    except OSError:
        raise BackupError("unsafe_target") from None


def reactivate(
    root: Path,
    application: str,
    *,
    services: dict[str, ReactivationService],
    isolation: str,
    image_cache: Path,
    check_identity: Callable[[str, dict], None],
    max_data_bytes: int = 1024 * 1024 * 1024,
    owner_of: Callable[[Identity], tuple[int, int]] = lambda identity: (identity.uid, identity.gid),
) -> dict:
    """Verify and restore an application's archive before it can start.

    Called by the deployment while the application is still stopped. With no
    unfinished archive it does nothing. An operation that never began releasing
    data is cancelled (the working data is authoritative and must still match
    the archive); otherwise every released data tree is restored from the
    verified archive. Any mismatch (corrupt archive, changed identity, changed
    binding, non-empty target) raises a stable error and leaves the archive and
    working area untouched.
    """
    if not (root / application).exists():
        return {"changed": False, "state": "none"}
    with archive_lock(root, application) as directory:
        state = active_operation(root, application)
        if state is None:
            return {"changed": False, "state": "none"}
        operation = directory / state.operation_id
        if isolation != "separate":
            raise BackupError("shared_unavailable")
        if state.phase in UNVERIFIED:
            discard_unverified(root, state, "readded")
            return {"changed": True, "state": "cancelled", "operation": state.operation_id}
        manifest = verify_archive(operation, expected_id=state.manifest_id or "")
        if manifest.isolation != isolation or manifest.application != application:
            raise BackupError("binding_changed")
        for name, item in manifest.services.items():
            current = services.get(name)
            if current is None:
                raise BackupError("binding_changed")
            if current.user != item.user:
                raise BackupError("binding_changed")
            if current.identity != item.identity.model_dump(mode="json"):
                raise BackupError("identity_changed")
            if (item.data_source is None) != (current.data_source is None) or (
                item.data_source is not None and str(current.data_source) != item.data_source
            ):
                raise BackupError("binding_changed")
            check_identity(item.user, item.identity.model_dump(mode="json"))
        restored, kept = [], []
        for name in sorted(manifest.services):
            item = manifest.services[name]
            current = services[name]
            if item.data is not None:
                target = current.data_source
                leftover = target.parent / retired_name(state.operation_id, name)
                begun = state.released.get(name, "pending") != "pending"
                moved = os.path.lexists(leftover)
                if not begun and not moved:
                    # Release never started: the working tree must still be the archived one.
                    if not source_intact(item, target, max_bytes=max_data_bytes):
                        raise BackupError("source_changed")
                    kept.append(name)
                elif (
                    state.released.get(name) == "moved"
                    and not moved
                    and not _empty_directory(target)
                ):
                    # Intent was journaled but the rename never happened.
                    if not source_intact(item, target, max_bytes=max_data_bytes):
                        raise BackupError("source_changed")
                    kept.append(name)
                else:
                    uid, gid = owner_of(item.identity)
                    restore_service_data(operation, manifest, name, target, uid=uid, gid=gid)
                    restored.append(name)
                    if moved:
                        shutil.rmtree(leftover)  # verified copy of what was just restored
            if (
                item.image_copy is not None
                and current.image == item.image
                and current.image_tag == item.image_tag
            ):
                restore_image(operation, manifest, name, image_cache)
        if state.phase == "verified":
            advance(root, state, "cancelled", error_class="readded")
            result = "cancelled"
        else:
            advance(root, state, "reactivated")
            result = "reactivated"
        return {
            "changed": True,
            "state": result,
            "operation": state.operation_id,
            "restored": restored,
            "kept": kept,
        }
