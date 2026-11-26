"""Verify one installed repository input offline under a dedicated identity."""

from __future__ import annotations

import argparse
import fcntl
import grp
import os
import pwd
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Annotated

from pydantic import StringConstraints

from .. import application_boot as boot
from ..executor.deployment_launcher import GateError
from . import repository_fetch_package as fetch
from . import repository_source_handoff as handoff
from .builder import JOB_ID, BuildError
from .canonical import canonical_json, revision_id
from .store import CapacityError, Store

ACCOUNT = "steward-repo-build"
UNIT = fetch.BUILD_VERIFY_UNIT
STATE = Path("/var/lib/steward-repository-build-verify")
ADMISSION = "build-verify.json"
PENDING = ".build-verify.incoming"
JOB_KIND = "repository.build.verify"
LEASE_SECONDS = 330  # Longer than the unit's bounded startup, including offline import.
ADMISSION_LIMIT = 4096
LEDGER_NAME = re.compile(r"[0-9a-f]{64}\.sqlite(?:-wal|-shm|-journal)?")
WORK_NAME = re.compile(r"job-[0-9a-f]{32}-[a-z0-9_]{8}")


class Admission(fetch.WireModel):
    invocation: fetch.RunID
    release: Annotated[str, StringConstraints(min_length=1, max_length=96)]
    expected: handoff.ExpectedInput
    input_digest: fetch.Digest
    capsule_digest: fetch.Digest
    confirmed: bool = False

    def binding(self) -> dict:
        return self.model_dump(mode="json", exclude={"invocation", "confirmed"})

    def proof(self) -> dict:
        return {
            "status": "input_verified",
            "release": self.release,
            **self.expected.model_dump(mode="json"),
            "input_digest": self.input_digest,
            "authorizes": [],
        }


def _identity(*, allow_absent: bool = False) -> tuple[int, int] | None:
    all_groups, all_users = grp.getgrall(), pwd.getpwall()
    groups = [item for item in all_groups if item.gr_name == ACCOUNT]
    users = [item for item in all_users if item.pw_name == ACCOUNT]
    try:
        group = grp.getgrnam(ACCOUNT)
    except KeyError:
        group = None
    try:
        user = pwd.getpwnam(ACCOUNT)
    except KeyError:
        user = None
    boot.require(groups == ([group] if group else []), "unsafe builder group")
    boot.require(users == ([user] if user else []), "unsafe builder account")
    if group is not None:
        boot.require(
            group.gr_gid > 0
            and grp.getgrgid(group.gr_gid) == group
            and not group.gr_mem
            and [item for item in all_groups if item.gr_gid == group.gr_gid] == [group]
            and [item for item in all_users if item.pw_gid == group.gr_gid] == users,
            "unsafe builder group",
        )
    if user is None and allow_absent:
        return None
    boot.require(
        user is not None
        and group is not None
        and user.pw_uid > 0
        and pwd.getpwuid(user.pw_uid) == user
        and [item for item in all_users if item.pw_uid == user.pw_uid] == [user]
        and user.pw_gid == group.gr_gid
        and user.pw_dir == "/nonexistent"
        and user.pw_shell == "/usr/sbin/nologin"
        and set(os.getgrouplist(ACCOUNT, user.pw_gid)) == {user.pw_gid},
        "unsafe builder account",
    )
    return user.pw_uid, user.pw_gid


def _require_worker() -> None:
    uid, gid = _identity()
    boot.require(
        (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) == (uid, uid, gid, gid)
        and set(os.getgroups()) - {gid} == {handoff._reader_gid()},
        "unexpected builder identity",
    )


def _release() -> str:
    release = fetch._require_installed_release()
    venv = boot.RELEASES / release / "venv"
    boot.safe_directory(venv)
    boot.require(
        Path(sys.prefix).resolve(strict=True) == venv
        and Path(__file__).resolve(strict=True).is_relative_to(venv),
        "builder code is outside the installed release",
    )
    return release


def _current(invocation: str) -> Admission:
    release = _release()
    fetch._require_no_marker()
    fetch_uid, fetch_gid = fetch._account()
    fetch._directory(fetch_gid)
    manifest = fetch._read_active(fetch_gid)
    fetch._require_scope(manifest, fetch_uid)
    fetch._require_applied(manifest)
    authority = handoff._authority(manifest)
    with handoff._open_ready(handoff._reader_gid()) as handle:
        sealed = handoff._read_header(handle)
        if sealed.authority != authority:
            raise BuildError("bad_handoff", "capsule authority differs from active manifest")
    return Admission(
        invocation=invocation,
        release=release,
        expected=authority.expected(),
        input_digest=sealed.inputs.input_digest,
        capsule_digest=handoff._digest(sealed),
    )


def _read_admission() -> Admission:
    gid = handoff._reader_gid()
    handoff._custody(gid)
    with boot.protected(handoff.DIRECTORY / ADMISSION, 0o640, gid) as handle:
        data = handle.read(ADMISSION_LIMIT + 1)
    boot.require(len(data) <= ADMISSION_LIMIT, "verification binding is too large")
    return Admission.model_validate_json(data)


def withdraw_admission() -> None:
    """Remove the invocation binding while holding the deployment lock."""
    path = handoff.DIRECTORY / ADMISSION
    pending = handoff.DIRECTORY / PENDING
    if not (os.path.lexists(path) or os.path.lexists(pending)):
        return
    gid = handoff._reader_gid()
    handoff._custody(gid)
    handoff._withdraw_file(path, 0o640, gid)
    _discard_pending(pending, gid)


def _discard_pending(path: Path, gid: int) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    mode = stat.S_IMODE(info.st_mode)
    boot.require(
        (info.st_gid, mode) in {(0, 0o600), (gid, 0o600), (gid, 0o640)},
        "unsafe staged verification binding",
    )
    handoff._withdraw_file(path, mode, info.st_gid)


def _write_admission(admission: Admission) -> None:
    gid = handoff._reader_gid()
    handoff._custody(gid)
    path = handoff.DIRECTORY / ADMISSION
    if os.path.lexists(path):
        with boot.protected(path, 0o640, gid):
            pass
    pending = path.with_name(PENDING)
    _discard_pending(pending, gid)
    try:
        with handoff._create_private(pending) as handle:
            handle.write(admission.model_dump_json().encode())
            handle.flush()
            os.fchown(handle.fileno(), 0, gid)
            os.fchmod(handle.fileno(), 0o640)
            os.fsync(handle.fileno())
        os.replace(pending, path)
        boot.sync_directory(path.parent)
    finally:
        pending.unlink(missing_ok=True)


def _require_current_capsule(admission: Admission, *, verify_pack: bool = False) -> None:
    if _read_admission() != admission:
        raise BuildError("bad_handoff", "verification authority was withdrawn")
    with handoff._open_ready(handoff._reader_gid()) as handle:
        sealed = handoff._read_header(handle)
        if (
            sealed.authority.expected() != admission.expected
            or sealed.inputs.input_digest != admission.input_digest
            or handoff._digest(sealed) != admission.capsule_digest
        ):
            raise BuildError("bad_handoff", "verification capsule was replaced")
        if verify_pack and (
            handoff._pack_digest(handle, sealed.inputs.pack_bytes) != sealed.inputs.pack_sha256
        ):
            raise BuildError("bad_handoff", "verification capsule pack digest differs")


def _private_state(uid: int, gid: int) -> None:
    boot.safe_directory(STATE.parent)
    info = STATE.lstat()
    boot.require(
        stat.S_ISDIR(info.st_mode)
        and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (uid, gid, 0o700),
        "unsafe builder verification state",
    )


def _private_file(info: os.stat_result) -> bool:
    return stat.S_ISREG(info.st_mode) and (
        info.st_uid,
        info.st_gid,
        stat.S_IMODE(info.st_mode),
        info.st_nlink,
    ) == (os.geteuid(), os.getegid(), 0o600, 1)


@contextmanager
def _job_state(key: str) -> Iterator[Path]:
    _private_state(os.geteuid(), os.getegid())
    lock = os.open(STATE / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        boot.require(_private_file(os.fstat(lock)), "unsafe builder verification lock")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BuildError("verification_busy") from None
        ledger = STATE / f"{key}.sqlite"
        for path in STATE.iterdir():
            if LEDGER_NAME.fullmatch(path.name):
                boot.require(_private_file(path.lstat()), "unsafe verification ledger")
                if not path.name.startswith(ledger.name):
                    path.unlink()
            elif WORK_NAME.fullmatch(path.name):
                with handoff._private_directory(path, os.geteuid()):
                    shutil.rmtree(path)
        yield ledger
    finally:
        os.close(lock)


def _open_store(ledger: Path) -> Store:
    if not ledger.exists():
        with handoff._create_private(ledger):
            pass
    return Store(ledger)


def _enqueue_job(store: Store, admission: Admission, key: str) -> dict:
    binding = admission.binding()
    target = f"verify:{admission.expected.application}/{admission.expected.service}"
    job, _ = store.enqueue(
        JOB_KIND,
        target,
        binding,
        idempotency_key=f"{JOB_KIND}:{key}",
        created_by="systemd",
        max_attempts=2,
        max_total=1,
    )
    if (
        job["kind"] != JOB_KIND
        or job["target"] != target
        or job["payload"] != binding
        or not JOB_ID.fullmatch(job["id"])
    ):
        raise BuildError("bad_job", "verification job binding differs")
    return job


def _run_job(store: Store, job: dict, admission: Admission, state: Path) -> None:
    worker = f"verify:{admission.invocation}"
    if job["state"] == "failed":
        raise BuildError("verification_failed")
    if store.claim(worker, lease_s=LEASE_SECONDS, job_id=job["id"]) is None:
        raise BuildError("verification_busy")
    try:
        with tempfile.TemporaryDirectory(prefix=f"job-{job['id']}-", dir=state) as work:
            with handoff._open_handoff(
                admission.expected, Path(work), input_digest=admission.input_digest
            ):
                _require_current_capsule(admission)
            if not store.heartbeat(job["id"], worker, lease_s=LEASE_SECONDS):
                raise BuildError("lease_lost")
    except (BuildError, boot.BootError, FileNotFoundError, ValueError) as exc:
        error = exc.code if isinstance(exc, BuildError) else "bad_handoff"
        if store.finish(job["id"], worker, ok=False, error=error) is None:
            raise BuildError("lease_lost") from None
        raise
    # The worker records an import. Only the root hook can confirm current authority.
    if (
        store.finish(job["id"], worker, ok=True, result={"status": "capsule_imported"})
        != "succeeded"
    ):
        raise BuildError("lease_lost")


def _verify_job(admission: Admission) -> None:
    key = revision_id(admission.binding())
    _require_current_capsule(admission)
    with _job_state(key) as ledger:
        if admission.confirmed:
            _require_current_capsule(admission, verify_pack=True)
            return
        _require_current_capsule(admission)
        with closing(_open_store(ledger)) as store:
            store.reconcile()
            job = _enqueue_job(store, admission, key)
            if job["state"] != "succeeded":
                _run_job(store, job, admission, ledger.parent)
                return

        # If the root hook did not confirm the import, start a fresh leased job.
        for suffix in ("", "-wal", "-shm", "-journal"):
            ledger.with_name(ledger.name + suffix).unlink(missing_ok=True)
        _require_current_capsule(admission)
        with closing(_open_store(ledger)) as store:
            _run_job(store, _enqueue_job(store, admission, key), admission, ledger.parent)


def _require_invocation(command: str) -> str:
    invocation = handoff._invocation()
    fields = fetch._repository_unit_fields(UNIT)
    phase = {"admit": "start-pre", "finish": "start-post"}[command]
    boot.require(
        fields.get("ActiveState") == "activating"
        and fields.get("SubState") == phase
        and fields.get("InvocationID") == invocation
        and fields.get("ControlGroup") == f"/system.slice/{UNIT}",
        "unexpected verification unit invocation",
    )
    return invocation


def _root_command(command: str) -> None:
    boot.require(os.geteuid() == 0, "verification custody requires root")
    if command == "identity":
        _identity(allow_absent=True)
        return
    invocation = _require_invocation(command)
    _private_state(*_identity())
    with boot.deployment_lock(timeout=30, create=False):
        admission = _current(invocation)
        if command == "admit":
            try:
                previous = _read_admission()
            except FileNotFoundError:
                pass
            else:
                if previous.confirmed and previous.binding() == admission.binding():
                    admission = admission.model_copy(update={"confirmed": True})
            _write_admission(admission)
        else:
            admitted = _read_admission()
            if admitted.invocation != invocation or admitted.binding() != admission.binding():
                raise BuildError("bad_handoff", "verification authority changed")
            _write_admission(admission.model_copy(update={"confirmed": True}))
            print(canonical_json(admission.proof()), flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m steward.core.repository_build_verify")
    parser.add_argument("command", choices=("identity", "admit", "verify", "finish"))
    command = parser.parse_args(argv).command
    try:
        if command == "verify":
            _require_worker()
            admission = _read_admission()
            if admission.invocation != handoff._invocation() or admission.release != _release():
                raise BuildError("bad_handoff", "verification invocation or release differs")
            _verify_job(admission)
        else:
            _root_command(command)
    except (
        boot.BootError,
        BuildError,
        CapacityError,
        GateError,
        KeyError,
        OSError,
        RecursionError,
        ValueError,
        sqlite3.Error,
        subprocess.SubprocessError,
    ) as exc:
        code = exc.code if isinstance(exc, BuildError) else type(exc).__name__
        print(f"repository build input {command} failed ({code})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
