"""Offline publication and independent admission of one exact repository build input."""

from __future__ import annotations

import argparse
import fcntl
import grp
import hashlib
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, BinaryIO

from pydantic import Field, StringConstraints, model_validator

from .. import application_boot as boot
from ..executor.deployment_launcher import GateError
from . import repository_fetch_package as fetch
from .builder import BuildError, BuildRequest
from .canonical import canonical_json, revision_id
from .config import GitCommit, Repository, Slug, WorkloadContract
from .repositories import FetchError, SourceRecord, checked_store_path, load_record, source_digest
from .repository_contract import propose_contract
from .repository_handoff_objects import MAX_PACK_BYTES, import_pack, stage_pack

DIRECTORY = Path("/var/lib/steward-repository-source-handoff")
RUNTIME = Path("/run/steward-repository-source-handoff")
GROUP = "steward-build-input"
READY = "ready"
STAGE_PACK = "source.pack"
STAGE_JSON = "stage.json"
MAGIC = b"STEWARDSOURCE\x01"
METADATA_LIMIT = 8 * 2**20
COPY_SECONDS = 30
COPY_BLOCK = 256 * 1024

Timestamp = Annotated[
    str, StringConstraints(pattern=r"^[0-9]{4}(-[0-9]{2}){2}T[0-9]{2}(:[0-9]{2}){2}Z$")
]


class ExpectedInput(fetch.WireModel):
    """Current authority selected independently of the ready file."""

    generation: fetch.RunID
    base_revision: fetch.Digest
    repository: Slug
    application: Slug
    service: Slug
    commit: GitCommit


class Authority(fetch.WireModel):
    generation: fetch.RunID
    base_revision: fetch.Digest
    repository: fetch.RepositoryInput
    credential_required: bool
    operator_contract: WorkloadContract | None

    @model_validator(mode="after")
    def validate_repository_binding(self) -> Authority:
        repo = self.proposal_repository()
        if repo.url != self.repository.url or repo.ref != self.repository.ref:
            raise ValueError("source authority is not canonical")
        return self

    def expected(self) -> ExpectedInput:
        repo = self.repository
        return ExpectedInput(
            generation=self.generation,
            base_revision=self.base_revision,
            repository=repo.id,
            application=repo.application,
            service=repo.service,
            commit=repo.revision,
        )

    def proposal_repository(self) -> Repository:
        # Validation of a private SSH repository requires a reference. The
        # proposal inspector has no credential resolver and does no fetching.
        return Repository.model_validate(
            {
                **self.repository.model_dump(),
                "credential": fetch.CREDENTIAL_REF if self.credential_required else None,
                "contract": self.operator_contract,
            },
            strict=True,
        )


class Inputs(fetch.WireModel):
    tree: GitCommit
    source_digest: fetch.Digest
    fetched_at: Timestamp
    contract: WorkloadContract
    contract_digest: fetch.Digest
    inventory: dict
    inventory_digest: fetch.Digest
    input_digest: fetch.Digest
    pack_bytes: Annotated[int, Field(gt=0, le=MAX_PACK_BYTES)]
    pack_sha256: fetch.Digest


class Staged(fetch.WireModel):
    invocation: fetch.RunID
    authority_digest: fetch.Digest
    inputs: Inputs


class Sealed(fetch.WireModel):
    authority: Authority
    inputs: Inputs


def _authority(manifest: fetch.Manifest) -> Authority:
    handoff = manifest.handoff
    if handoff is None or handoff.generation is None:
        raise BuildError("handoff_unavailable", "a fresh repository candidate is required")
    return Authority(
        generation=handoff.generation,
        base_revision=manifest.base_revision,
        repository=manifest.repository,
        credential_required=manifest.credential_required,
        operator_contract=handoff.contract,
    )


def _invocation() -> str:
    value = os.environ.get("INVOCATION_ID", "")
    if len(value) != 32 or any(c not in "0123456789abcdef" for c in value):
        raise BuildError("bad_handoff", "systemd invocation is missing")
    return value


def _metadata(handle: BinaryIO, size: int) -> object:
    if not 0 < size <= METADATA_LIMIT:
        raise BuildError("bad_handoff", "invalid metadata size")

    def unique(pairs):
        data = dict(pairs)
        if len(data) != len(pairs):
            raise BuildError("bad_handoff", "duplicate metadata field")
        return data

    def nonfinite(_value):
        raise BuildError("bad_handoff", "invalid metadata number")

    data = handle.read(size)
    if len(data) != size:
        raise BuildError("bad_handoff", "truncated metadata")
    return json.loads(data, object_pairs_hook=unique, parse_constant=nonfinite)


def _encoded(model: fetch.WireModel) -> bytes:
    data = canonical_json(model.model_dump(mode="json")).encode()
    if not 0 < len(data) <= METADATA_LIMIT:
        raise BuildError("bad_handoff", "metadata exceeds its limit")
    return data


def _digest(model: fetch.WireModel) -> str:
    return hashlib.sha256(_encoded(model)).hexdigest()


def _record(authority: Authority, inputs: Inputs) -> SourceRecord:
    repo = authority.repository
    if source_digest(repo.revision, inputs.tree) != inputs.source_digest:
        raise BuildError("bad_handoff", "source identity differs")
    if (
        revision_id(inputs.contract.model_dump(mode="json")) != inputs.contract_digest
        or revision_id(inputs.inventory) != inputs.inventory_digest
        or inputs.inventory.get("commit") != repo.revision
        or inputs.inventory.get("tree") != inputs.tree
    ):
        raise BuildError("bad_handoff", "contract or inventory identity differs")
    if authority.operator_contract is not None and inputs.contract != authority.operator_contract:
        raise BuildError("bad_handoff", "operator workload contract differs")
    return SourceRecord(
        repository=repo.id,
        application=repo.application,
        service=repo.service,
        url=repo.url,
        ref=repo.ref,
        requested_revision=repo.revision,
        commit=repo.revision,
        tree=inputs.tree,
        source_digest=inputs.source_digest,
        store=f"{repo.revision}.git",
        fetched_at=inputs.fetched_at,
    )


@contextmanager
def _private_directory(path: Path, uid: int) -> Iterator[int]:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
            raise BuildError("bad_handoff", "unsafe private directory")
        yield fd
    finally:
        os.close(fd)


@contextmanager
def _private_file(directory: int, name: str, uid: int) -> Iterator[tuple[BinaryIO, os.stat_result]]:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (
            info.st_uid,
            stat.S_IMODE(info.st_mode),
            info.st_nlink,
        ) != (uid, 0o600, 1):
            raise BuildError("bad_handoff", "unsafe private file")
        yield handle, info


@contextmanager
def _locked_source(authority: Authority, uid: int) -> Iterator[tuple[SourceRecord, Path]]:
    repo = authority.proposal_repository()
    namespace = fetch.STORE / repo.application / repo.service
    boot.safe_directory(fetch.STORE.parent)
    # The repository namespace is fetch-owned. Its components are checked by
    # load_record under the same per-service lock used by the W37 writer.
    with (
        _private_directory(fetch.STORE, uid),
        _private_directory(namespace.parent, uid),
        _private_directory(namespace, uid) as directory,
        _private_file(directory, ".lock", uid) as (lock, _),
    ):
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BuildError("handoff_busy", "source namespace is busy") from None
        record = load_record(fetch.STORE, repo.application, repo.service, repo.revision)
        if (
            record.repository != repo.id
            or record.application != repo.application
            or record.service != repo.service
            or record.url != repo.url
            or record.ref != repo.ref
            or record.requested_revision != repo.revision
            or record.commit != repo.revision
            or record.repair_base_commit is not None
            or source_digest(record.commit, record.tree) != record.source_digest
        ):
            raise BuildError("bad_handoff", "retained source differs from the installed pin")
        yield record, checked_store_path(fetch.STORE, record)


def _pack_digest(source: BinaryIO, size: int, dest: BinaryIO | None = None) -> str:
    if not 0 < size <= MAX_PACK_BYTES:
        raise BuildError("bad_handoff", "invalid pack size")
    deadline = time.monotonic() + COPY_SECONDS
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        if time.monotonic() >= deadline:
            raise BuildError("bad_handoff", "source copy timed out")
        data = source.read(min(remaining, COPY_BLOCK))
        if not data:
            raise BuildError("bad_handoff", "source pack is truncated")
        digest.update(data)
        if dest is not None:
            dest.write(data)
        remaining -= len(data)
    if source.read(1):
        raise BuildError("bad_handoff", "source pack contains trailing data")
    return digest.hexdigest()


def _proposal_request(
    authority: Authority, record: SourceRecord, pack: Path, scratch: Path
) -> BuildRequest:
    local_root = scratch / "source"
    namespace = local_root / record.application / record.service
    local_root.mkdir(mode=0o700)
    namespace.parent.mkdir(mode=0o700)
    namespace.mkdir(mode=0o700)
    import_pack(pack, record, namespace / record.store, scratch)
    with _create_private(namespace / f"{record.commit}.json") as handle:
        handle.write(canonical_json(record.persisted()).encode())
    proposal = propose_contract(authority.proposal_repository(), record, local_root)
    if proposal.repository != record.repository:
        raise BuildError("bad_handoff", "proposal belongs to another repository")
    return BuildRequest.create(record, proposal, local_root)


def _create_private(path: Path) -> BinaryIO:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    return os.fdopen(fd, "wb")


def _prepare(uid: int, gid: int) -> None:
    if (os.geteuid(), os.getegid()) != (uid, gid):
        raise BuildError("bad_handoff", "unexpected fetch identity")
    invocation = _invocation()
    fetch._directory(gid)
    authority = _authority(fetch._read_active(gid))
    boot.safe_directory(RUNTIME.parent)
    pack = RUNTIME / STAGE_PACK
    with (
        _private_directory(RUNTIME, uid) as directory,
        tempfile.TemporaryDirectory(prefix="prepare-", dir=RUNTIME) as work,
        _locked_source(authority, uid) as (record, store),
    ):
        scratch = Path(work)
        stage_pack(store, record, pack, scratch)
        request = _proposal_request(authority, record, pack, scratch)
        with _private_file(directory, STAGE_PACK, uid) as (handle, info):
            pack_digest = _pack_digest(handle, info.st_size)
        inputs = Inputs(
            tree=record.tree,
            source_digest=record.source_digest,
            fetched_at=record.fetched_at,
            contract=WorkloadContract.model_validate(request.contract),
            contract_digest=request.contract_digest,
            inventory=request.inventory,
            inventory_digest=revision_id(request.inventory),
            input_digest=request.input_digest,
            pack_bytes=info.st_size,
            pack_sha256=pack_digest,
        )
        staged = Staged(invocation=invocation, authority_digest=_digest(authority), inputs=inputs)
        with _create_private(RUNTIME / STAGE_JSON) as handle:
            handle.write(_encoded(staged))


def _reader_gid() -> int:
    gid = grp.getgrnam(GROUP).gr_gid
    if gid <= 0:
        raise BuildError("bad_handoff", "unsafe reader group")
    return gid


def _custody(gid: int) -> None:
    boot.safe_directory(DIRECTORY)
    info = DIRECTORY.lstat()
    if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (0, gid, 0o750):
        raise BuildError("bad_handoff", "unsafe publication directory")


def _open_ready(gid: int) -> BinaryIO:
    _custody(gid)
    return boot.protected(DIRECTORY / READY, 0o640, gid)


def _withdraw_file(path: Path, mode: int, gid: int = 0) -> None:
    try:
        with boot.protected(path, mode, gid):
            path.unlink()
        boot.sync_directory(path.parent)
    except FileNotFoundError:
        pass


def withdraw_ready() -> None:
    """Revoke builder admission while the caller holds the deployment lock."""
    if not os.path.lexists(DIRECTORY):
        return
    gid = _reader_gid()
    _custody(gid)
    _withdraw_file(DIRECTORY / READY, 0o640, gid)
    staging = DIRECTORY / ".staging"
    if os.path.lexists(staging):
        with _private_directory(staging, 0) as directory:
            _discard_incoming(directory, gid)


def _discard_incoming(directory: int, gid: int) -> None:
    try:
        fd = os.open("incoming", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        return
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or (info.st_gid, stat.S_IMODE(info.st_mode))
            not in {(0, 0o600), (gid, 0o600), (gid, 0o640)}
        ):
            raise BuildError("bad_handoff", "unsafe unfinished publication")
        os.unlink("incoming", dir_fd=directory)
        os.fsync(directory)
    finally:
        os.close(fd)


def _seal(authority: Authority, invocation: str, uid: int, gid: int) -> None:
    boot.safe_directory(RUNTIME.parent)
    _custody(gid)
    staging = DIRECTORY / ".staging"
    staging.mkdir(mode=0o700, exist_ok=True)
    incoming = staging / "incoming"
    if os.path.lexists(DIRECTORY / READY):
        with _open_ready(gid):
            pass
    with (
        _private_directory(staging, 0) as pending,
        _private_directory(RUNTIME, uid) as runtime,
        _private_file(runtime, STAGE_JSON, uid) as (meta, meta_info),
        _private_file(runtime, STAGE_PACK, uid) as (source, source_info),
    ):
        _discard_incoming(pending, gid)
        staged = Staged.model_validate(_metadata(meta, meta_info.st_size))
        if (
            meta.read(1)
            or staged.invocation != invocation
            or staged.authority_digest != _digest(authority)
        ):
            raise BuildError("bad_handoff", "staging differs from active invocation or authority")
        _record(authority, staged.inputs)
        if source_info.st_size != staged.inputs.pack_bytes:
            raise BuildError("bad_handoff", "staged pack size differs")
        header = _encoded(Sealed(authority=authority, inputs=staged.inputs))
        try:
            with _create_private(incoming) as out:
                out.write(MAGIC + struct.pack("!I", len(header)) + header)
                if _pack_digest(source, staged.inputs.pack_bytes, out) != staged.inputs.pack_sha256:
                    raise BuildError("bad_handoff", "staged pack digest differs")
                after = os.fstat(source.fileno())
                if (after.st_size, after.st_ctime_ns) != (
                    source_info.st_size,
                    source_info.st_ctime_ns,
                ):
                    raise BuildError("bad_handoff", "staged pack changed during copy")
                out.flush()
                # Apply the reader mode only once the file is at the boundary.
                # Any interrupted incoming file remains in the root-only directory.
                os.fchown(out.fileno(), 0, gid)
                os.fchmod(out.fileno(), 0o640)
                os.fsync(out.fileno())
            os.replace(incoming, DIRECTORY / READY)
            boot.sync_directory(DIRECTORY)
            boot.sync_directory(staging)
        finally:
            incoming.unlink(missing_ok=True)


def _read_header(handle: BinaryIO) -> Sealed:
    prefix = handle.read(len(MAGIC) + 4)
    if len(prefix) != len(MAGIC) + 4 or not prefix.startswith(MAGIC):
        raise BuildError("bad_handoff", "unknown source capsule")
    size = struct.unpack("!I", prefix[-4:])[0]
    return Sealed.model_validate(_metadata(handle, size))


@contextmanager
def _open_handoff(
    expected: ExpectedInput, work_root: Path, *, input_digest: str | None = None
) -> Iterator[BuildRequest]:
    """Load the current capsule inside BuildRunner's owned job workspace."""
    uid = os.geteuid()
    if uid == 0:
        raise BuildError("bad_handoff", "source import must run unprivileged")
    with (
        _private_directory(work_root, uid),
        tempfile.TemporaryDirectory(
            prefix="handoff-", dir=work_root, ignore_cleanup_errors=True
        ) as work,
    ):
        scratch = Path(work)
        pack = scratch / STAGE_PACK
        try:
            gid = _reader_gid()
            with _open_ready(gid) as handle:
                sealed = _read_header(handle)
                if sealed.authority.expected() != expected or (
                    input_digest is not None and input_digest != sealed.inputs.input_digest
                ):
                    raise BuildError("bad_handoff", "capsule differs from the requested input")
                with _create_private(pack) as out:
                    digest = _pack_digest(handle, sealed.inputs.pack_bytes, out)
                if digest != sealed.inputs.pack_sha256:
                    raise BuildError("bad_handoff", "sealed pack digest differs")
            record = _record(sealed.authority, sealed.inputs)
            request = _proposal_request(sealed.authority, record, pack, scratch)
            pack.unlink()
            if (
                request.contract_digest != sealed.inputs.contract_digest
                or revision_id(request.inventory) != sealed.inputs.inventory_digest
                or request.input_digest != sealed.inputs.input_digest
            ):
                raise BuildError("bad_handoff", "reconstructed build input differs")
            # Withdrawal unlinks READY. Opening it again is the admission
            # point, after all expensive work and before handing off the job.
            with _open_ready(gid) as current:
                if _read_header(current) != sealed:
                    raise BuildError("bad_handoff", "source authority changed during import")
        except (boot.BootError, FetchError, OSError, RecursionError, ValueError, KeyError):
            raise BuildError("bad_handoff", "cannot verify source capsule") from None
        yield request


def _root_command(command: str, uid: int, gid: int) -> None:
    if os.geteuid() != 0:
        raise BuildError("bad_handoff", "handoff custody requires root")
    invocation = _invocation()
    with boot.deployment_lock(timeout=30, create=False):
        fetch._directory(gid)
        fetch._require_no_marker()
        manifest = fetch._read_active(gid)
        authority = _authority(manifest)
        fetch._require_scope(manifest, uid)
        fetch._require_applied(manifest)
        fetch.require_unit_quiescent(fetch.UNIT)
        reader_gid = _reader_gid()
        _custody(reader_gid)
        if command == "publish":
            _seal(authority, invocation, uid, reader_gid)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m steward.core.repository_source_handoff")
    parser.add_argument("command", choices=("verify", "prepare", "publish"))
    command = parser.parse_args(argv).command
    try:
        uid, gid = fetch._account()
        if command == "prepare":
            _prepare(uid, gid)
        else:
            _root_command(command, uid, gid)
    except (
        boot.BootError,
        BuildError,
        FetchError,
        GateError,
        KeyError,
        OSError,
        RecursionError,
        ValueError,
        subprocess.SubprocessError,
    ) as exc:
        code = exc.code if isinstance(exc, (BuildError, FetchError)) else type(exc).__name__
        print(f"repository source handoff {command} failed ({code})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
