"""Leased uploads of protected capture imports; no host mutation authority."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import signal
import sqlite3
import stat
import sys
import threading
import time
import uuid
from contextlib import contextmanager, suppress
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .adapters.backups import Restic
from .core import ipc
from .core.backup_changes import Changes, changes, initialize
from .core.backup_observations import Page, SnapshotChanged, query
from .core.backupexport import acl_attributes
from .core.backups import (
    BackupError,
    Capture,
    FilesystemCapture,
    Receipt,
    load_capture,
    regular_file,
)
from .core.config import BackupEndpoint, Slug
from .core.inventory import Digest
from .core.store import CapacityError, Store
from .executor.protocol import PROTOCOL_VERSION, ExecutorError, call

MAX_RETENTION_HINTS = 1280
MAX_BACKUP_JOBS = 1280
LOCK_RETRY_INTERVAL_S = 300
MAX_LOCK_ATTEMPTS = 12


class Upload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project: Slug
    artifact: str = Field(pattern=r"^[a-f0-9]{32}$")
    capture_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    repository_id: str = Field(pattern=r"^[a-f0-9]{64}$")


class ReceiptSelection(BaseModel):
    """An exact operator selection, never a caller-selected repository path."""

    model_config = ConfigDict(extra="forbid")
    project: Slug
    config_revision: Digest
    repository_id: Digest
    capture_id: Digest
    snapshot_id: Digest


def service_endpoint(path: Path, *, owner_uid: int = 0) -> BackupEndpoint:
    """Read only a root-controlled enabled service endpoint."""
    fd, info = regular_file(path, limit=65536)
    with os.fdopen(fd, "rb") as handle:
        if info.st_uid != owner_uid or info.st_mode & 0o022:
            raise BackupError("invalid_service_config")
        data = json.load(handle)
    if not isinstance(data, dict) or data.get("enabled") is not True:
        raise BackupError("invalid_service_config")
    return BackupEndpoint.model_validate(data.get("endpoint"))


class Imports:
    def __init__(self, root: Path, *, owner_uid: int = 0):
        self.root, self.owner = root, owner_uid

    def directory(self, path, mode):
        info = path.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != self.owner
            or info.st_gid != os.getegid()
            or info.st_mode & 0o777 != mode
        ):
            raise BackupError("unsafe_import")

    def manifest(self, project, artifact):
        Upload(project=project, artifact=artifact, capture_id="0" * 64, repository_id="0" * 64)
        self.directory(self.root, 0o750)
        self.directory(self.root / project, 0o750)
        path = self.root / project / artifact
        self.directory(path, 0o550)
        if acl_attributes(path):
            raise BackupError("unsafe_import")
        fd, _info = regular_file(path / "manifest.json", limit=65536)
        with os.fdopen(fd, "rb") as handle:
            raw = json.load(handle)
        if not isinstance(raw, dict):
            raise BackupError("invalid_import")
        model = FilesystemCapture if raw.get("mechanism") == "verified_quiescence" else Capture
        manifest = model.model_validate(raw)
        names = []
        with os.scandir(path) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > 2:
                    raise BackupError("invalid_import")
        if (
            set(names) != {"manifest.json", manifest.filename}
            or manifest.binding.project != project
        ):
            raise BackupError("invalid_import")
        for name in names:
            info = (path / name).lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != self.owner
                or info.st_gid != os.getegid()
                or info.st_mode & 0o777 != 0o440
                or info.st_nlink != 1
                or acl_attributes(path / name)
            ):
                raise BackupError("unsafe_import")
        return path, manifest

    @contextmanager
    def locked_manifest(self, project, artifact):
        """Fence root cleanup for the full use of one protected import."""
        Upload(project=project, artifact=artifact, capture_id="0" * 64, repository_id="0" * 64)
        self.directory(self.root, 0o750)
        self.directory(self.root / project, 0o750)
        path = self.root / project / artifact
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                raise BackupError("unavailable") from None
            checked_path, manifest = self.manifest(project, artifact)
            opened, current = os.fstat(fd), checked_path.lstat()
            if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                raise BackupError("unsafe_import")
            yield checked_path, manifest
        finally:
            os.close(fd)

    def discover(self):
        self.directory(self.root, 0o750)
        count = 0
        with os.scandir(self.root) as projects:
            for project in projects:
                count += 1
                if count > 128 or not re.fullmatch(r"[a-z][a-z0-9-]{1,30}[a-z0-9]", project.name):
                    raise BackupError("import_limit")
                self.directory(Path(project.path), 0o750)
                artifacts = 0
                with os.scandir(project.path) as entries:
                    for artifact in entries:
                        artifacts += 1
                        if artifacts > 10:
                            raise BackupError("import_limit")
                        if artifact.name.startswith(".export-"):
                            continue  # root-private in-progress publication is not an import
                        yield self.manifest(project.name, artifact.name)


class Ledger(Store):
    def __init__(self, path):
        super().__init__(path)
        self._conn().execute(
            "CREATE TABLE IF NOT EXISTS backup_receipts (repository TEXT, capture TEXT, "
            "body TEXT NOT NULL, PRIMARY KEY(repository,capture))"
        )
        self._conn().execute(
            "CREATE TABLE IF NOT EXISTS retention_hints (project TEXT NOT NULL, "
            "artifact TEXT NOT NULL, capture_id TEXT NOT NULL, "
            "PRIMARY KEY(project, artifact, capture_id))"
        )
        self._conn().execute(
            "CREATE TABLE IF NOT EXISTS backup_lock_waits ("
            "job_id TEXT PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE, "
            "attempts INTEGER NOT NULL CHECK (attempts BETWEEN 1 AND 12))"
        )
        with self._tx() as db:
            initialize(db)

    def receipt(self, repository, capture):
        row = (
            self._conn()
            .execute(
                "SELECT body FROM backup_receipts WHERE repository=? AND capture=?",
                (repository, capture),
            )
            .fetchone()
        )
        return Receipt.model_validate_json(row[0]) if row else None

    def selected_receipt(self, selection: ReceiptSelection) -> Receipt:
        """Read one completed worker receipt and its matching job in one snapshot.

        This is worker-reported evidence, not root provenance or authorization
        to replace production data.
        """
        db = self._conn()
        db.execute("BEGIN")
        try:
            row = db.execute(
                "SELECT body FROM backup_receipts WHERE repository=? AND capture=?",
                (selection.repository_id, selection.capture_id),
            ).fetchone()
            if row is None:
                raise ExecutorError("conflict", "selected backup evidence unavailable")
            receipt = Receipt.model_validate_json(row["body"])
            if (
                receipt.repository_id != selection.repository_id
                or receipt.capture.id != selection.capture_id
                or receipt.snapshot_id != selection.snapshot_id
                or receipt.capture.binding.project != selection.project
                or receipt.capture.binding.config_revision != selection.config_revision
                or receipt.integrity_checked_at is None
                or receipt.restore_verified_at is None
            ):
                raise ExecutorError("conflict", "selected backup evidence unavailable")
            rows = db.execute(
                "SELECT target,payload FROM jobs WHERE kind='backup_upload' "
                "AND state='succeeded' AND target=? LIMIT ?",
                (selection.project, MAX_BACKUP_JOBS + 1),
            ).fetchall()
            if len(rows) > MAX_BACKUP_JOBS:
                raise ExecutorError("conflict", "selected backup evidence unavailable")
            matched = False
            for job in rows:
                payload = Upload.model_validate_json(job["payload"])
                if job["target"] != payload.project:
                    raise ValueError("job target mismatch")
                if (
                    payload.project == selection.project
                    and payload.repository_id == selection.repository_id
                    and payload.capture_id == selection.capture_id
                ):
                    matched = True
            if not matched:
                raise ExecutorError("conflict", "selected backup evidence unavailable")
            db.execute("COMMIT")
            return receipt
        except BaseException:
            db.execute("ROLLBACK")
            raise

    def defer_for_permit(self, job_id, worker, reason, *, now=None):
        """Keep a gated job retryable without consuming upload attempts."""
        now = time.time() if now is None else now
        if reason not in ("upload_cancelled", "permit_unavailable"):
            raise ValueError("invalid permit delay")
        with self._tx() as db:
            changed = db.execute(
                "UPDATE jobs SET state='queued', attempts=MAX(attempts-1,0), "
                "not_before=?, lease_owner=NULL, lease_expires=NULL, error=?, updated_at=? "
                "WHERE id=? AND state='running' AND lease_owner=? AND lease_expires>?",
                (now + 300, reason, now, job_id, worker, now),
            ).rowcount
        return changed == 1

    def defer_repository_lock(self, job_id, worker, *, now=None, recovered=False):
        """Bound lock waits separately from upload failures under the current lease."""
        now = time.time() if now is None else now
        if type(recovered) is not bool:
            raise ValueError("invalid lock recovery result")
        with self._tx() as db:
            job = db.execute(
                "SELECT id FROM jobs WHERE id=? AND kind='backup_upload' AND state='running' "
                "AND lease_owner=? AND lease_expires>?",
                (job_id, worker, now),
            ).fetchone()
            if job is None:
                return None
            row = db.execute(
                "SELECT attempts FROM backup_lock_waits WHERE job_id=?", (job_id,)
            ).fetchone()
            attempts = (row[0] if row else 0) + 1
            if recovered:
                db.execute("DELETE FROM backup_lock_waits WHERE job_id=?", (job_id,))
                db.execute(
                    "UPDATE jobs SET state='queued', attempts=MAX(attempts-1,0), not_before=?, "
                    "lease_owner=NULL, lease_expires=NULL, error='repository_locked', updated_at=? "
                    "WHERE id=?",
                    (now, now, job_id),
                )
                return "queued"
            if attempts >= MAX_LOCK_ATTEMPTS:
                db.execute(
                    "UPDATE jobs SET state='failed', lease_owner=NULL, lease_expires=NULL, "
                    "error='repository_locked', updated_at=? WHERE id=?",
                    (now, job_id),
                )
                db.execute("DELETE FROM backup_lock_waits WHERE job_id=?", (job_id,))
                return "failed"
            db.execute(
                "INSERT INTO backup_lock_waits VALUES (?,?) "
                "ON CONFLICT(job_id) DO UPDATE SET attempts=excluded.attempts",
                (job_id, attempts),
            )
            db.execute(
                "UPDATE jobs SET state='queued', attempts=MAX(attempts-1,0), not_before=?, "
                "lease_owner=NULL, lease_expires=NULL, error='repository_locked', updated_at=? "
                "WHERE id=?",
                (now + LOCK_RETRY_INTERVAL_S, now, job_id),
            )
            return "queued"

    def checkpoint(self, job, worker, receipt, *, done=False, enqueue_hint=False, now=None):
        now = time.time() if now is None else now
        payload = Upload.model_validate(job["payload"])
        if (
            receipt.repository_id != payload.repository_id
            or receipt.capture.id != payload.capture_id
        ):
            raise BackupError("evidence_mismatch")
        summary = {
            "capture_id": receipt.capture.id,
            "snapshot_id": receipt.snapshot_id,
            "uploaded": True,
            "data_checked": receipt.integrity_checked_at is not None,
            "restored_bytes_verified": receipt.restore_verified_at is not None,
            "application_verified": False,
        }
        if done and not (summary["data_checked"] and summary["restored_bytes_verified"]):
            raise BackupError("incomplete_evidence")
        with self._tx() as db:
            row = db.execute(
                "SELECT id FROM jobs WHERE id=? AND state='running' "
                "AND lease_owner=? AND lease_expires>?",
                (job["id"], worker, now),
            ).fetchone()
            if row is None:
                raise BackupError("lease_lost")
            previous = db.execute(
                "SELECT body FROM backup_receipts WHERE repository=? AND capture=?",
                (receipt.repository_id, receipt.capture.id),
            ).fetchone()
            if previous:
                old = Receipt.model_validate_json(previous[0])
                if (old.snapshot_id, old.snapshot_path, old.snapshot_created_at) != (
                    receipt.snapshot_id,
                    receipt.snapshot_path,
                    receipt.snapshot_created_at,
                ):
                    raise BackupError("evidence_mismatch")
            db.execute(
                "INSERT OR REPLACE INTO backup_receipts VALUES (?,?,?)",
                (
                    receipt.repository_id,
                    receipt.capture.id,
                    receipt.model_dump_json(),
                ),
            )
            if enqueue_hint:
                key = (payload.project, payload.artifact, payload.capture_id)
                present = db.execute(
                    "SELECT 1 FROM retention_hints WHERE project=? AND artifact=? AND capture_id=?",
                    key,
                ).fetchone()
                if not present:
                    count = db.execute("SELECT COUNT(*) FROM retention_hints").fetchone()[0]
                    if count >= MAX_RETENTION_HINTS:
                        # Hints are interchangeable wakeups, not evidence;
                        # keep the newest bounded set and periodic fallback.
                        db.execute(
                            "DELETE FROM retention_hints WHERE rowid IN (SELECT rowid "
                            "FROM retention_hints ORDER BY rowid DESC LIMIT -1 OFFSET ?)",
                            (MAX_RETENTION_HINTS - 1,),
                        )
                    db.execute("INSERT INTO retention_hints VALUES (?, ?, ?)", key)
            if done:
                db.execute("DELETE FROM backup_lock_waits WHERE job_id=?", (job["id"],))
                db.execute(
                    "UPDATE jobs SET state='succeeded', lease_owner=NULL, lease_expires=NULL, "
                    "result=?, error=NULL, updated_at=? WHERE id=?",
                    (json.dumps(summary), now, job["id"]),
                )
            else:
                db.execute(
                    "UPDATE jobs SET result=?, updated_at=? WHERE id=?",
                    (json.dumps(summary), now, job["id"]),
                )
        return summary


class QueryService:
    """Read-only worker claims; clients never receive the private database."""

    def __init__(self, ledger, readers, *, max_age_s, clock=time.time):
        self.ledger, self.readers = ledger, readers
        self.max_age_s, self.clock = max_age_s, clock

    def handle(self, raw: bytes, peer_uid: int) -> dict:
        try:
            role = "operator" if peer_uid == 0 else self.readers.get(peer_uid)
            if role not in ("operator", "api", "collector", "controller"):
                raise ExecutorError("unauthorized_peer", "peer is not a backup reader")
            request = json.loads(raw)
            if not isinstance(request, dict) or request.get("v") != PROTOCOL_VERSION:
                raise ValueError("invalid request")
            action, params = request.get("action"), request.get("params", {})
            if action == "backups_query":
                page = Page.model_validate(params)
                result = query(self.ledger, page, now=self.clock(), max_age_s=self.max_age_s)
            elif action == "backups_changes" and role in ("operator", "collector"):
                result = changes(self.ledger, Changes.model_validate(params))
            elif action == "backups_receipt" and peer_uid == 0:
                receipt = self.ledger.selected_receipt(ReceiptSelection.model_validate(params))
                result = {
                    "receipt": receipt.model_dump(mode="json"),
                    "provenance": "worker_reported",
                    "production_restore_authorized": False,
                }
            else:
                raise ExecutorError("policy_denied", "read-only action is not allowed")
            return {"ok": True, "result": result}
        except SnapshotChanged:
            return {"ok": False, "error_class": "conflict", "message": "backup snapshot changed"}
        except ExecutorError as exc:
            return {"ok": False, "error_class": exc.error_class, "message": exc.message}
        except (ValueError, TypeError, ValidationError):
            return {"ok": False, "error_class": "bad_request", "message": "invalid backup query"}
        except Exception:  # noqa: BLE001 - do not expose paths or private database errors
            return {
                "ok": False,
                "error_class": "internal",
                "message": "backup evidence unavailable",
            }
        finally:
            self.ledger.close()


class Runner:
    def __init__(
        self, state: Path, imports: Imports, adapter, *, clock=time.time, permit=None, hint=None
    ):
        if state.absolute().is_relative_to(
            imports.root.absolute()
        ) or imports.root.absolute().is_relative_to(state.absolute()):
            raise BackupError("unsafe_state")
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = state.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o777 != 0o700
        ):
            raise BackupError("unsafe_state")
        self.state, self.imports, self.adapter, self.clock = state, imports, adapter, clock
        self.permit = permit
        self.hint = hint
        self._capacity_report_next = 0.0
        self.jobs = Ledger(state / "jobs.db")
        self.worker, self.stop = uuid.uuid4().hex, threading.Event()

    def run_once(self):
        fd = os.open(self.state / "worker.lock", os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise BackupError("worker_busy") from None
            return self._run_once()
        finally:
            self.jobs.close()
            os.close(fd)

    def _flush_retention_hints(self):
        if self.hint is None:
            return
        rows = (
            self.jobs._conn()
            .execute(
                "SELECT project, artifact, capture_id FROM retention_hints ORDER BY rowid LIMIT 10"
            )
            .fetchall()
        )
        for row in rows:
            try:
                response = self.hint(
                    "backup_retention_hint",
                    {
                        "project_id": row["project"],
                        "artifact": row["artifact"],
                        "capture_id": row["capture_id"],
                    },
                    timeout=10,
                )
            except (ExecutorError, OSError):
                break
            if (
                not isinstance(response, dict)
                or set(response) != {"accepted"}
                or response["accepted"] is not True
            ):
                break
            with self.jobs._tx() as db:
                db.execute(
                    "DELETE FROM retention_hints WHERE project=? AND artifact=? AND capture_id=?",
                    (row["project"], row["artifact"], row["capture_id"]),
                )

    def _report_job_capacity(self) -> None:
        if self.hint is None:
            return
        now = time.monotonic()
        if now < self._capacity_report_next:
            return
        try:
            response = self.hint(
                "backup_worker_capacity_report",
                {},
                timeout=10,
            )
        except (ExecutorError, OSError):
            return
        if (
            isinstance(response, dict)
            and set(response) == {"accepted"}
            and response["accepted"] is True
        ):
            self._capacity_report_next = now + 300

    def _run_once(self):
        self.jobs.reconcile(now=self.clock())
        self._flush_retention_hints()
        self.adapter.health()
        repository = self.adapter.repository_id()
        capacity = None
        for _path, manifest in self.imports.discover():
            artifact = _path.name
            payload = Upload(
                project=manifest.binding.project,
                artifact=artifact,
                capture_id=manifest.id,
                repository_id=repository,
            )
            try:
                self.jobs.enqueue(
                    "backup_upload",
                    payload.project,
                    payload.model_dump(),
                    idempotency_key=f"backup:{repository}:{manifest.id}",
                    created_by="backup",
                    max_attempts=3,
                    max_total=MAX_BACKUP_JOBS,
                    now=self.clock(),
                )
            except CapacityError:
                capacity = payload
                break
        if capacity is not None:
            self._report_job_capacity()
        job = self.jobs.claim(self.worker, lease_s=60, now=self.clock())
        if job is None:
            return (
                {"state": "capacity_blocked", "error_class": "worker_job_limit"}
                if capacity
                else None
            )
        finished = threading.Event()
        lost = threading.Event()

        def guard():
            if (
                self.stop.is_set()
                or lost.is_set()
                or not self.jobs.heartbeat(job["id"], self.worker, lease_s=60, now=self.clock())
            ):
                lost.set()
                raise BackupError("lease_lost")

        def heartbeat():
            try:
                while not finished.wait(10):
                    try:
                        guard()
                    except Exception:  # noqa: BLE001 - uncertainty prohibits publication
                        lost.set()
                        return
            finally:
                self.jobs.close()

        thread = threading.Thread(target=heartbeat, daemon=True, name="backup-lease")
        thread.start()
        try:
            payload = Upload.model_validate(job["payload"])
            if job["kind"] != "backup_upload" or payload.repository_id != repository:
                raise BackupError("repository_changed")
            if isinstance(self.adapter, Restic):
                self.adapter.set_job_context(
                    job_id=job["id"], repository_id=repository, capture_id=payload.capture_id
                )
            with self.imports.locked_manifest(payload.project, payload.artifact) as (
                path,
                manifest,
            ):
                if self.permit is not None:
                    try:
                        decision = self.permit(
                            "backup_upload_permit",
                            {
                                "project_id": payload.project,
                                "artifact": payload.artifact,
                                "capture_id": payload.capture_id,
                            },
                            timeout=10,
                        )
                    except (ExecutorError, OSError):
                        decision = None
                    allowed = (
                        isinstance(decision, dict)
                        and set(decision) == {"permitted", "reason"}
                        and decision["permitted"] is True
                        and decision["reason"] == "registered"
                    )
                    if not allowed:
                        cancelled = (
                            isinstance(decision, dict)
                            and set(decision) == {"permitted", "reason"}
                            and decision["permitted"] is False
                            and decision["reason"] == "cancelled"
                        )
                        reason = "upload_cancelled" if cancelled else "permit_unavailable"
                        deferred = self.jobs.defer_for_permit(
                            job["id"], self.worker, reason, now=self.clock()
                        )
                        return {
                            "job_id": job["id"],
                            "state": "queued" if deferred else "lease_lost",
                            "error_class": reason,
                        }
                if load_capture(path).id != payload.capture_id:
                    raise BackupError("evidence_mismatch")
                guard()
                receipt = self.jobs.receipt(repository, manifest.id)
                if receipt is None:
                    receipt = self.adapter.backup(path)
                    guard()
                    self.jobs.checkpoint(
                        job,
                        self.worker,
                        receipt,
                        enqueue_hint=self.hint is not None,
                        now=self.clock(),
                    )
                    self._flush_retention_hints()
                guard()
                checked = self.adapter.check(receipt)
                guard()
                if checked.integrity_checked_at is None:
                    raise BackupError("incomplete_evidence")
                self.jobs.checkpoint(job, self.worker, checked, now=self.clock())
                restored = self.adapter.restore_test(checked)
                guard()
                return self.jobs.checkpoint(job, self.worker, restored, done=True, now=self.clock())
        except BackupError as exc:
            if exc.error_class == "repository_locked":
                recovered = False
                if isinstance(self.adapter, Restic):

                    def recovery_guard():
                        guard()
                        if self.permit is not None:
                            decision = self.permit(
                                "backup_lock_cleanup_permit",
                                {
                                    "project_id": payload.project,
                                    "artifact": payload.artifact,
                                    "capture_id": payload.capture_id,
                                },
                                timeout=10,
                            )
                            if not (
                                isinstance(decision, dict)
                                and set(decision) == {"permitted", "reason"}
                                and decision["permitted"] is True
                                and decision["reason"] == "registered"
                            ):
                                raise BackupError("permit_unavailable")

                    # Unknown or unavailable locks remain untouched.
                    with (
                        suppress(BackupError, ExecutorError, OSError, ValueError),
                        self.imports.locked_manifest(payload.project, payload.artifact) as (
                            path,
                            manifest,
                        ),
                    ):
                        if (
                            manifest.id != payload.capture_id
                            or load_capture(path).id != payload.capture_id
                        ):
                            raise BackupError("evidence_mismatch") from None
                        recovered = self.adapter.recover_observed_locks(guard=recovery_guard) > 0
                state = self.jobs.defer_repository_lock(
                    job["id"], self.worker, now=self.clock(), recovered=recovered
                )
                return {
                    "job_id": job["id"],
                    "state": state or "lease_lost",
                    "error_class": exc.error_class,
                }
            state = self.jobs.finish(
                job["id"],
                self.worker,
                ok=False,
                error=exc.error_class,
                retryable=exc.error_class
                in (
                    "unavailable",
                    "timeout",
                    "lease_lost",
                    "integrity_failed",
                ),
                now=self.clock(),
            )
            return {
                "job_id": job["id"],
                "state": state or "lease_lost",
                "error_class": exc.error_class,
            }
        except (ValueError, OSError):
            state = self.jobs.finish(
                job["id"], self.worker, ok=False, error="invalid_import", now=self.clock()
            )
            return {
                "job_id": job["id"],
                "state": state or "lease_lost",
                "error_class": "invalid_import",
            }
        finally:
            if isinstance(self.adapter, Restic):
                self.adapter.clear_job_context()
            finished.set()
            thread.join(15)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--imports-root", type=Path, default=Path("/var/lib/steward-backup-import"))
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/steward-backup"))
    parser.add_argument("--repository-file", type=Path, required=True)
    parser.add_argument("--password-file", type=Path, required=True)
    parser.add_argument("--username-file", type=Path)
    parser.add_argument("--auth-password-file", type=Path)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--restic-binary", type=Path)
    parser.add_argument("--endpoint-file", type=Path, help="root-controlled service endpoint JSON")
    parser.add_argument("--query-socket", default="/run/steward-backup/query.sock")
    parser.add_argument("--query-group", default="steward-obs")
    parser.add_argument(
        "--reader",
        action="append",
        default=["api=steward-api", "collector=steward-col", "controller=steward-ctl"],
    )
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("run uploads under the dedicated unprivileged backup identity")
    os.umask(0o077)
    try:
        runner = Runner(
            args.state_dir,
            Imports(args.imports_root),
            Restic(
                repository_file=args.repository_file,
                password_file=args.password_file,
                username_file=args.username_file,
                auth_password_file=args.auth_password_file,
                ca_file=args.ca_file,
                state_dir=args.state_dir / "restic",
                binary=args.restic_binary,
                endpoint=service_endpoint(args.endpoint_file) if args.endpoint_file else None,
            ),
            permit=call if args.endpoint_file else None,
            hint=call if args.endpoint_file else None,
        )
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, lambda *_: runner.stop.set())
        server = None
        if args.endpoint_file:
            from .backupscheduler import Scheduler, read_config
            from .collector import resolve_readers

            config = read_config(args.endpoint_file)
            scheduler = Scheduler(config, runner.imports, runner.state / "schedule.db")
            if not args.once:
                service = QueryService(
                    runner.jobs, resolve_readers(args.reader), max_age_s=2 * config.interval_s
                )
                server = ipc.bind(args.query_socket, service.handle, args.query_group)
                threading.Thread(
                    target=server.serve_forever, daemon=True, name="backup-query"
                ).start()

            def schedule_loop():
                while not runner.stop.is_set():
                    try:
                        for project, outcome in scheduler.tick().items():
                            if outcome != "scheduled":
                                print(
                                    f"backup scheduler: {project}: {outcome}",
                                    file=sys.stderr,
                                    flush=True,
                                )
                    except (OSError, sqlite3.Error, ValueError):
                        print("backup scheduler: state_unavailable", file=sys.stderr, flush=True)
                    runner.stop.wait(15)

            threading.Thread(target=schedule_loop, name="backup-scheduler", daemon=True).start()
        try:
            while not runner.stop.is_set():
                try:
                    result = runner.run_once()
                except BackupError as exc:
                    if args.once:
                        raise
                    print(f"backup worker: {exc.error_class}", file=sys.stderr, flush=True)
                    result = None
                if args.once:
                    print(json.dumps(result))
                    if result and result.get("error_class"):
                        raise SystemExit(1)
                    return
                runner.stop.wait(15)
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()
    except (BackupError, ValueError, OSError, sqlite3.Error) as exc:
        raise SystemExit(
            "backup worker failed: "
            + (
                exc.error_class
                if isinstance(exc, BackupError)
                else "state_unavailable"
                if isinstance(exc, sqlite3.Error)
                else "invalid_input"
            )
        ) from None


if __name__ == "__main__":
    main()
