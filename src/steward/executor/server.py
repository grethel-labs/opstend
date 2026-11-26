"""Privileged host executor.

Small by design. It accepts only registered actions with schema-validated
parameters, decides authorisation itself (peer UID -> role -> action -> policy
from the root-owned registry) and writes its own audit log. It never runs
shell strings, caller-supplied paths or caller-supplied playbooks.

Audit policy: every mutation and every refused request is one audit record.
Successful read-only requests are counted and written as one `reads` summary
per hour, so routine polling does not grow the log without bound.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import pwd
import re
import shutil
import sqlite3
import sys
import threading
import time
import uuid
from collections.abc import Callable
from contextlib import ExitStack, contextmanager, nullcontext
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError, model_validator

from .. import application_boot as boot
from ..core import ipc
from ..core.application_ops import derive_group_plan, rederive_checkpoint_plan
from ..core.audit import AuditLog
from ..core.backups import Binding
from ..core.config import ImageRef, Slug
from ..core.group_checkpoint import (
    MAX_GROUP_CHECKPOINTS,
    MAX_GROUP_GENERATION,
    DeploymentFence,
    GroupCheckpoint,
    GroupPlan,
    OperationId,
)
from ..core.health import classify as classify_health
from ..core.ids import graph_identifier, valid_request_id
from ..core.inventory import Digest
from ..core.maintenance_runs import MaintenanceRuns
from ..core.maintenance_work import WORK, policy_summary, resource_check, window_dict
from ..core.secrets import redact, redact_tree
from ..core.store import Store
from . import containment
from .host import Host
from .image_update import recover_updates
from .protocol import (
    DEFAULT_SOCKET,
    PROTOCOL_VERSION,
    REQUEST_TTL_S,
    ExecutorError,
)

REGISTRY_PATH = "/etc/steward/executor.json"
STATE_DIR = "/var/lib/steward-executor"
AUDIT_PATH = "/var/log/steward-executor/audit.jsonl"
LOCK_DIR = "/run/steward-executor/locks"
PROJECT_DATA_ROOT = Path("/srv/steward/projects")
APPLICATION_DATA_ROOT = Path("/srv/steward/applications")
BACKUP_IMPORT_ROOT = Path("/var/lib/steward-backup-import")
RESTART_BUDGET_PER_HOUR = 6
ROLES = ("operator", "api", "controller", "collector", "scanner", "backup")
READ_SUMMARY_INTERVAL_S = 3600
JOURNAL_MESSAGE_MAX = 1000
MAX_CANCELLED_UPLOADS = 128
MAX_GROUP_HISTORY = 1024
IMAGE_REFERENCE = TypeAdapter(ImageRef)


class Params(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NoParams(Params):
    pass


class AuditSinceParams(Params):
    offset: int = Field(ge=0)
    prev_hash: str = Field(pattern=r"^([a-f0-9]{64})?$")
    limit: int = Field(200, ge=1, le=500)


class InventoryParams(Params):
    offset: int = Field(0, ge=0, le=50000)
    limit: int = Field(200, ge=1, le=200)
    expected_revision: str | None = Field(None, pattern=r"^[a-f0-9]{64}$")


class ApplicationGroupStatusParams(Params):
    application: Slug
    expected_revision: Digest


class ApplicationGroupStopParams(ApplicationGroupStatusParams):
    service: Slug
    previous_operation_id: OperationId | None = None
    previous_generation: int | None = Field(None, strict=True, ge=0, le=MAX_GROUP_GENERATION)

    @model_validator(mode="after")
    def _previous_checkpoint(self):
        if (self.previous_operation_id is None) != (self.previous_generation is None):
            raise ValueError("previous operation and generation must be supplied together")
        return self


class ApplicationGroupResumeParams(ApplicationGroupStatusParams):
    operation_id: OperationId
    generation: int = Field(strict=True, ge=0, le=MAX_GROUP_GENERATION)


class ApplicationRetireParams(Params):
    application: Slug
    expected_revision: Digest
    desired_revision: Digest
    desired_applications: list[Slug] = Field(max_length=16)

    @model_validator(mode="after")
    def _distinct(self):
        if (
            len(set(self.desired_applications)) != len(self.desired_applications)
            or self.application in self.desired_applications
            or self.expected_revision == self.desired_revision
        ):
            raise ValueError("retirement needs distinct revisions and a unique desired list")
        return self


class ApplicationRetirementStatusParams(Params):
    application: Slug


class ImageInventoryParams(Params):
    project_id: Slug | None = None
    application: Slug | None = None
    service: Slug | None = None
    expected_revision: Digest | None = None

    @model_validator(mode="after")
    def _target(self):
        if self.model_fields_set == {"project_id"} and self.project_id is not None:
            return self
        if (
            self.model_fields_set == {"application", "service", "expected_revision"}
            and self.application is not None
            and self.service is not None
            and self.expected_revision is not None
        ):
            return self
        raise ValueError("supply either project_id or application, service and expected_revision")


class JournalSinceParams(Params):
    cursor: str | None = Field(None, pattern=r"^[A-Za-z0-9=;_-]{1,512}$")
    limit: int = Field(200, ge=1, le=500)
    skip_to_end: bool = False


class RestartParams(Params):
    project_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,30}[a-z0-9]$")
    reason: str = Field(max_length=200, pattern=r"^[\x20-\x7e]*$")


class MaintenanceAdmitParams(Params):
    # Registered work only (core/maintenance_work.py WORK); never a command or a duration.
    work_id: Literal["resource_check"]


class BackupCaptureParams(Params):
    project_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,30}[a-z0-9]$")


class BackupScheduleParams(BackupCaptureParams):
    expected_revision: str | None = Field(None, pattern=r"^[a-f0-9]{64}$")


class BackupRecoverParams(BackupCaptureParams):
    accept_current: bool = False


class BackupExportParams(BackupCaptureParams):
    artifact: str = Field(pattern=r"^[a-f0-9]{32}$")
    capture_id: str = Field(pattern=r"^[a-f0-9]{64}$")


class BackupCancellationForgetParams(BackupExportParams):
    acknowledge_forget: Literal[True]


class BackupImportRetireParams(BackupExportParams):
    acknowledge_import_removal: Literal[True]


class BackupUploadCancelParams(BackupExportParams):
    acknowledge_abandonment: Literal[True]


class BackupRetentionAckParams(BackupExportParams):
    acknowledge_removal: Literal[True]


class BackupPause(Params):
    binding: Binding
    user: str = Field(pattern=r"^stw-[a-z][a-z0-9-]{1,30}[a-z0-9]$")
    unit: str = Field(pattern=r"^[a-z][a-z0-9-]{1,30}[a-z0-9]\.service$")
    artifact: str = Field(pattern=r"^[a-f0-9]{32}$")
    prepared_at: float = Field(ge=0, allow_inf_nan=False)
    recovery_error: (
        Literal[
            "execution_failed",
            "policy_denied",
            "kill_switch",
            "unavailable",
            "internal",
            "target_busy",
        ]
        | None
    ) = None


class BackupScheduledRun(Params):
    artifact: str = Field(pattern=r"^[a-f0-9]{32}$")
    phase: Literal["admitted", "capturing", "captured", "exported", "failed"]
    capture_started: bool = False
    created_at: float = Field(ge=0, allow_inf_nan=False)
    config_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    capture_id: str | None = Field(None, pattern=r"^[a-f0-9]{64}$")
    capture_created_at: float | None = Field(None, ge=0, allow_inf_nan=False)
    result: dict | None = None

    @model_validator(mode="after")
    def complete_phases(self):
        if self.phase in ("captured", "exported") and (
            not self.capture_started or self.capture_id is None or self.capture_created_at is None
        ):
            raise ValueError("completed capture metadata is required")
        if self.phase == "exported" and (
            not self.result
            or self.result.get("artifact") != self.artifact
            or self.result.get("capture_id") != self.capture_id
            or self.result.get("uploaded") is not False
        ):
            raise ValueError("export result does not bind this capture")
        return self


@dataclass(frozen=True)
class Action:
    params: type[Params]
    roles: frozenset[str]
    mutating: bool
    handler: Callable[..., dict[str, Any]]


def load_registry(path: str) -> dict[str, Any]:
    """Read the registry, refusing anything not exclusively controlled by root."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if st.st_uid != os.geteuid() or st.st_mode & 0o022:
            raise ExecutorError("internal", "registry has unsafe ownership or mode")
        with os.fdopen(os.dup(fd), encoding="utf-8") as handle:
            return json.load(handle)
    finally:
        os.close(fd)


def pause_contract_matches(intent: BackupPause, registry: dict) -> bool:
    spec = registry["projects"].get(intent.binding.project)
    return bool(
        spec
        and spec.get("deploy")
        and spec.get("allow_backup_pause")
        and registry["config_revision"] == intent.binding.config_revision
        and registry.get("server_name") == intent.binding.server
        and spec["user"] == intent.user
        and spec["unit"] == intent.unit
        and spec["image"] == intent.binding.image
        and spec["source_revision"] == intent.binding.source_revision
    )


class Executor:
    def __init__(
        self,
        *,
        registry_path: str,
        state_dir: str,
        audit_path: str,
        lock_dir: str,
        host: Host | None = None,
    ):
        self.registry_path = registry_path
        self.host = host or Host()
        self.audit = AuditLog(audit_path)
        self.lock_dir = Path(lock_dir)
        self.lock_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._db_path = os.path.join(state_dir, "state.db")
        self._maintenance_db_path = os.path.join(state_dir, "maintenance.db")
        self._db_lock = threading.Lock()
        self.retention_wakeup = threading.Event()
        self.group_recovery_wakeup = threading.Event()
        self._retention_hint_lock = threading.Lock()
        self._retention_hint_next = 0.0
        self._worker_capacity_next = 0.0
        self._reads: dict[str, int] = {}
        self._reads_since = time.time()
        self._reads_lock = threading.Lock()
        with self._db() as db:
            db.executescript(
                "CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, expires_at REAL);"
                "CREATE TABLE IF NOT EXISTS mutations (target TEXT, action TEXT, ts REAL);"
                "CREATE TABLE IF NOT EXISTS backup_pauses "
                "(project TEXT PRIMARY KEY, intent TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS backup_schedule "
                "(project TEXT PRIMARY KEY, body TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS backup_removal_ack "
                "(project TEXT NOT NULL, artifact TEXT NOT NULL, capture_id TEXT NOT NULL, "
                "config_revision TEXT NOT NULL, capture_created_at REAL NOT NULL, "
                "acknowledged_at REAL NOT NULL, PRIMARY KEY(project, artifact));"
                "CREATE TABLE IF NOT EXISTS backup_upload_protection "
                "(project TEXT NOT NULL, artifact TEXT NOT NULL, capture_id TEXT NOT NULL, "
                "config_revision TEXT NOT NULL, capture_created_at REAL NOT NULL, "
                "registered_at REAL NOT NULL, PRIMARY KEY(project, artifact));"
                "CREATE TABLE IF NOT EXISTS backup_upload_cancellations "
                "(project TEXT NOT NULL, artifact TEXT NOT NULL, capture_id TEXT NOT NULL, "
                "cancelled_at REAL NOT NULL, PRIMARY KEY(project, artifact));"
                "CREATE TABLE IF NOT EXISTS backup_retirement_intents "
                "(project TEXT PRIMARY KEY, body TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS backup_import_retirement_intents "
                "(project TEXT PRIMARY KEY, body TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS application_group_intents "
                "(application TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE, "
                "generation INTEGER NOT NULL, body TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS application_group_operator_intents "
                "(operation_id TEXT PRIMARY KEY, application TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS application_group_history "
                "(operation_id TEXT PRIMARY KEY, application TEXT NOT NULL, body TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS application_capture_workflows "
                "(application TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE, "
                "body TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS deployment_fence "
                "(singleton INTEGER PRIMARY KEY CHECK(singleton=1), body TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS site_deployments "
                "(operation_id TEXT PRIMARY KEY, state TEXT NOT NULL, body TEXT NOT NULL);"
            )

    def hint_retention(self, *, now: float | None = None) -> bool:
        """Coalesce untrusted wakeups without widening retention authority."""
        now = time.monotonic() if now is None else now
        with self._retention_hint_lock:
            if now < self._retention_hint_next:
                return False
            self._retention_hint_next = now + 30
            self.retention_wakeup.set()
            return True

    def report_worker_capacity(self, *, now: float | None = None) -> bool:
        """Rate-limit a clearly attributed, untrusted worker capacity report."""
        now = time.monotonic() if now is None else now
        with self._retention_hint_lock:
            if now < self._worker_capacity_next:
                return False
            self.audit.append(
                "backup_capacity", namespace="worker", reason="limit", reported_by="backup"
            )
            self._worker_capacity_next = now + 300
            return True

    def backup_pause(self, project: str) -> BackupPause | None:
        with self._db() as db:
            row = db.execute(
                "SELECT intent FROM backup_pauses WHERE project=?", (project,)
            ).fetchone()
        return BackupPause.model_validate_json(row[0]) if row else None

    def backup_pause_summaries(self) -> list[dict]:
        with self._db() as db:
            rows = db.execute(
                "SELECT project, intent FROM backup_pauses ORDER BY project"
            ).fetchall()
        return [
            {
                "project_id": project,
                "prepared_at": (intent := BackupPause.model_validate_json(raw)).prepared_at,
                "error_class": intent.recovery_error,
            }
            for project, raw in rows
        ]

    def record_backup_pause_failure(
        self, project: str, error_class: str, *, expected: BackupPause | None = None
    ) -> None:
        if error_class == "target_busy":
            return
        with self._db() as db:
            row = db.execute(
                "SELECT intent FROM backup_pauses WHERE project=?", (project,)
            ).fetchone()
            if row:
                current = BackupPause.model_validate_json(row[0])
                if (
                    expected is not None
                    and current.model_copy(update={"recovery_error": None}) != expected
                ):
                    return
                body = current.model_dump()
                body["recovery_error"] = error_class
                intent = BackupPause.model_validate(body)
                db.execute(
                    "UPDATE backup_pauses SET intent=? WHERE project=?",
                    (intent.model_dump_json(), project),
                )

    def save_backup_pause(self, intent: BackupPause) -> None:
        with self._db() as db:
            db.execute(
                "INSERT INTO backup_pauses VALUES (?,?)",
                (
                    intent.binding.project,
                    intent.model_dump_json(),
                ),
            )

    def clear_backup_pause(self, project: str) -> None:
        with self._db() as db:
            db.execute("DELETE FROM backup_pauses WHERE project=?", (project,))

    def recover_backup_pause(
        self,
        project: str,
        registry: dict,
        *,
        automatic: bool,
        accept_current: bool = False,
        expected: BackupPause | None = None,
    ) -> dict:
        with self.backup_mutation_lock(project, registry):
            intent = self.backup_pause(project)
            if intent is None:
                return {"project_id": project, "pending": False, "resumed": False}
            if (
                expected is not None
                and intent.model_copy(update={"recovery_error": None}) != expected
            ):
                return {
                    "project_id": project,
                    "pending": True,
                    "resumed": False,
                    "superseded": True,
                }
            spec = registry["projects"].get(project)
            if accept_current:
                if (
                    automatic
                    or not spec
                    or spec["user"] != intent.user
                    or spec["unit"] != intent.unit
                ):
                    raise ExecutorError(
                        "policy_denied", "cannot acknowledge a different workload identity"
                    )
                state = self.host.user_unit(intent.user, intent.unit)
                matches = (
                    state["load"] == "loaded" and state["active"] == "active"
                    if spec["deploy"]
                    else self.host.workload_quiescent(intent.user, intent.unit)
                )
                if not matches:
                    raise ExecutorError(
                        "policy_denied",
                        "current workload state does not match its deployment contract",
                    )
                self.audit.append(
                    "backup_resume",
                    project_id=project,
                    artifact=intent.artifact,
                    automatic=False,
                    outcome="accepted_current",
                )
                self.clear_backup_pause(project)
                return {
                    "project_id": project,
                    "pending": False,
                    "resumed": False,
                    "accepted_current": True,
                }
            if not pause_contract_matches(intent, registry):
                raise ExecutorError(
                    "policy_denied", "backup pause recovery needs its original active contract"
                )
            if automatic and self.host.kill_switch():
                raise ExecutorError("kill_switch", "automatic backup recovery is stopped")
            state = self.host.user_unit(intent.user, intent.unit)
            if state["load"] != "loaded" or state["active"] not in ("active", "inactive", "failed"):
                raise ExecutorError("unavailable", "backup recovery workload state is not known")
            if state["active"] != "active":
                ok = self.host.set_user_unit(intent.user, intent.unit, running=True)
                state = self.host.user_unit(intent.user, intent.unit)
                if not ok or state["active"] != "active":
                    raise ExecutorError("execution_failed", "backup pause recovery failed")
            self.audit.append(
                "backup_resume",
                project_id=project,
                artifact=intent.artifact,
                automatic=automatic,
                outcome="ok",
            )
            self.clear_backup_pause(project)
            return {"project_id": project, "pending": False, "resumed": True}

    def recover_backup_pauses(self, stop: threading.Event | None = None) -> None:
        """Recover startup pauses; retry only the initially captured projects.

        Direct callers without a stop event perform a single pass. The server
        retries startup intents without adopting captures created afterwards.
        """
        try:
            with self._db() as db:
                rows = db.execute("SELECT project, intent FROM backup_pauses").fetchall()
            pending = {}
            for project, body in rows:
                intent = BackupPause.model_validate_json(body)
                if intent.binding.project != project:
                    raise ValueError("inconsistent backup pause")
                pending[project] = intent.model_copy(update={"recovery_error": None})
        except Exception:  # noqa: BLE001 - retain intents and report failed recovery inspection
            self.audit.append("backup_resume", outcome="internal", automatic=True)
            return
        while pending and (stop is None or not stop.is_set()):
            for project in sorted(pending):
                try:
                    self.recover_backup_pause(
                        project,
                        load_registry(self.registry_path),
                        automatic=True,
                        expected=pending[project],
                    )
                    pending.pop(project)
                except ExecutorError as exc:
                    self.record_backup_pause_failure(
                        project, exc.error_class, expected=pending[project]
                    )
                    self.audit.append(
                        "backup_resume", project_id=project, outcome=exc.error_class, automatic=True
                    )
                except Exception:  # noqa: BLE001 - one failure must not hide other pauses
                    self.record_backup_pause_failure(project, "internal", expected=pending[project])
                    self.audit.append(
                        "backup_resume", project_id=project, outcome="internal", automatic=True
                    )
            if stop is None or not pending:
                return
            stop.wait(15)

    @contextmanager
    def _db(self):
        with self._db_lock:
            conn = sqlite3.connect(self._db_path, timeout=10)
            try:
                with conn:
                    yield conn
            finally:
                conn.close()

    @contextmanager
    def maintenance_store(self, *, create: bool = True):
        """Durable maintenance run records; `create=False` never creates the file."""
        if not create and not os.path.exists(self._maintenance_db_path):
            yield None
            return
        store = Store(self._maintenance_db_path)
        try:
            yield store
        finally:
            store.close()

    # ---- request pipeline ------------------------------------------------------

    def role_for(self, uid: int, registry: dict[str, Any]) -> str:
        if uid == 0:
            return "operator"
        for role, peer_uid in registry.get("peers", {}).items():
            if role in ROLES and role != "operator" and peer_uid == uid:
                return role
        raise ExecutorError("unauthorized_peer", "peer is not a registered component")

    def handle(self, raw: bytes, peer_uid: int) -> dict[str, Any]:
        """Process one request. Always audits; never raises."""
        action_name, request_id, role = "?", None, None
        try:
            try:
                request = json.loads(raw)
            except ValueError:
                raise ExecutorError("bad_request", "request is not valid JSON") from None
            if not isinstance(request, dict) or request.get("v") != PROTOCOL_VERSION:
                raise ExecutorError("bad_request", "unsupported protocol version")
            action_name = str(request.get("action"))[:64]
            candidate = request.get("request_id")
            if not valid_request_id(candidate):
                raise ExecutorError("bad_request", "invalid request_id")
            request_id = candidate
            registry = load_registry(self.registry_path)
            role = self.role_for(peer_uid, registry)
            action = ACTIONS.get(action_name)
            if action is None:
                raise ExecutorError("unknown_action", "action is not registered")
            if role not in action.roles:
                raise ExecutorError("forbidden_role", f"role {role} may not call {action_name}")
            try:
                params = action.params.model_validate(request.get("params") or {})
            except ValidationError as exc:
                raise ExecutorError(
                    "bad_request", f"invalid parameters: {exc.error_count()} error(s)"
                ) from None
            if action.mutating:
                self._check_freshness(request, request_id)
                if role != "operator" and self.host.kill_switch():
                    raise ExecutorError("kill_switch", "automatic mutations are stopped")
            result = action.handler(self, params, role, registry)
            if action.mutating:
                self.audit.append(
                    "request",
                    action=action_name,
                    role=role,
                    peer_uid=peer_uid,
                    request_id=request_id,
                    outcome="ok",
                    params=request.get("params") or {},
                )
            else:
                self.count_read(role, action_name)
            return {"ok": True, "result": result}
        except ExecutorError as exc:
            self.audit.append(
                "request",
                action=action_name,
                role=role,
                peer_uid=peer_uid,
                request_id=request_id,
                outcome=exc.error_class,
                detail=exc.message,
            )
            return {"ok": False, "error_class": exc.error_class, "message": exc.message}
        except Exception as exc:  # noqa: BLE001 - the executor must answer and audit
            self.audit.append(
                "request",
                action=action_name,
                role=role,
                peer_uid=peer_uid,
                request_id=request_id,
                outcome="internal",
                detail=type(exc).__name__,
            )
            return {"ok": False, "error_class": "internal", "message": type(exc).__name__}

    def count_read(self, role: str, action: str, now: float | None = None) -> None:
        """Count a successful read; write one summary record per interval."""
        now = time.time() if now is None else now
        with self._reads_lock:
            key = f"{role}:{action}"
            self._reads[key] = self._reads.get(key, 0) + 1
            if now - self._reads_since < READ_SUMMARY_INTERVAL_S:
                return
            counts, since = self._reads, self._reads_since
            self._reads, self._reads_since = {}, now
        self.audit.append("reads", since=round(since, 3), until=round(now, 3), counts=counts)

    def _check_freshness(self, request: dict[str, Any], request_id: str) -> None:
        now = time.time()
        expires_at = request.get("expires_at")
        if not isinstance(expires_at, int | float) or expires_at < now:
            raise ExecutorError("expired", "request expired")
        if expires_at > now + REQUEST_TTL_S + 5:
            raise ExecutorError("bad_request", "expiry too far in the future")
        with self._db() as db:
            db.execute("DELETE FROM requests WHERE expires_at < ?", (now,))
            try:
                db.execute("INSERT INTO requests VALUES (?, ?)", (request_id, expires_at))
            except sqlite3.IntegrityError:
                raise ExecutorError("replay", "request_id was already used") from None

    @contextmanager
    def target_lock(self, target: str):
        """Exclusive, non-blocking lock: one mutation per target at a time."""
        fd = os.open(
            self.lock_dir / f"{target}.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600
        )
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ExecutorError(
                    "target_busy", f"another mutation of {target} is running"
                ) from None
            yield
        finally:
            os.close(fd)

    @contextmanager
    def target_locks(self, targets: list[str]):
        """Acquire a bounded set of root-derived targets in deterministic order.

        Group operations must derive the targets from the root-owned registry;
        this helper never authorizes caller-supplied target names by itself.
        """
        if (
            not isinstance(targets, list)
            or not 1 <= len(targets) <= 65
            or any(
                not isinstance(target, str)
                or re.fullmatch(r"(?:application|project)-[a-z][a-z0-9-]{1,30}[a-z0-9]", target)
                is None
                for target in targets
            )
            or len(targets) != len(set(targets))
        ):
            raise ValueError("invalid group lock targets")
        with ExitStack() as stack:
            for target in sorted(targets):
                stack.enter_context(self.target_lock(target))
            yield

    def _read_group_checkpoint(self, db: sqlite3.Connection, application: str):
        return db.execute(
            "SELECT g.operation_id, g.generation, g.body, o.application "
            "FROM application_group_intents g "
            "LEFT JOIN application_group_operator_intents o ON o.operation_id=g.operation_id "
            "WHERE g.application=?",
            (application,),
        ).fetchone()

    def group_checkpoint(self, application: str) -> GroupCheckpoint | None:
        """Read a durable group intent; never infer that its host work completed."""
        with self._db() as db:
            row = self._read_group_checkpoint(db, application)
        if row is None:
            return None
        checkpoint = GroupCheckpoint.model_validate_json(row[2]).with_persisted_owner(row[3])
        if (
            checkpoint.plan.application != application
            or checkpoint.operation_id != row[0]
            or checkpoint.generation != row[1]
        ):
            raise ValueError("inconsistent persisted group checkpoint")
        return checkpoint

    def ensure_group_restart_allowed(self, registry: dict[str, Any], spec: dict[str, Any]) -> None:
        """Reject single-unit restarts covered by an unfinished group intent.

        The caller holds deployment-execution through the host operation. This
        prevents a group from being admitted between this check and the restart.
        Unknown or stale checkpoint contracts fail closed.
        """
        with self._db() as db:
            rows = db.execute(
                "SELECT application, operation_id, generation, body FROM application_group_intents "
                "LIMIT ?",
                (MAX_GROUP_CHECKPOINTS + 1,),
            ).fetchall()
        if len(rows) > MAX_GROUP_CHECKPOINTS:
            raise ExecutorError("unavailable", "group checkpoint capacity exceeded")
        for application, operation_id, generation, body in rows:
            try:
                checkpoint = GroupCheckpoint.model_validate_json(body)
                if (
                    checkpoint.plan.application != application
                    or checkpoint.operation_id != operation_id
                    or checkpoint.generation != generation
                ):
                    raise ValueError("inconsistent group checkpoint")
                if checkpoint.phase in ("complete", "recovered"):
                    continue
                plan = GroupPlan.model_validate(rederive_checkpoint_plan(registry, checkpoint.plan))
                if plan != checkpoint.plan:
                    raise ValueError("group contract changed")
                services = registry["applications"][application]["services"]
                for name in plan.start_order + plan.external_dependencies:
                    service = services[name]
                    if (service["user"], service["unit"]) == (spec["user"], spec["unit"]):
                        raise ExecutorError(
                            "unavailable", "application group transition is pending"
                        )
            except (ValueError, KeyError, TypeError):
                raise ExecutorError("unavailable", "application group state is unknown") from None

    @contextmanager
    def group_backup_locks(self, plan: GroupPlan):
        """Fence project backup activity and retained pauses for a group plan.

        Call under deployment-execution. Physical unit identity, rather than a
        project alias, determines overlap. Backups retain their project locks
        during capture, so unrelated projects need not wait for the copy.
        """
        registry = load_registry(self.registry_path)
        try:
            fresh = GroupPlan.model_validate(rederive_checkpoint_plan(registry, plan))
            if fresh != plan:
                raise ValueError("group contract changed")
            services = registry["applications"][plan.application]["services"]
            identities = {
                (services[name]["user"], services[name]["unit"])
                for name in plan.start_order + plan.external_dependencies
            }
            projects = registry.get("projects", {})
            if not isinstance(projects, dict) or len(projects) > 64:
                raise ValueError("invalid project registry")
            aliases = []
            for project, spec in projects.items():
                if (
                    not isinstance(project, str)
                    or re.fullmatch(r"[a-z][a-z0-9-]{1,30}[a-z0-9]", project) is None
                    or not isinstance(spec, dict)
                ):
                    raise ValueError("invalid project registration")
                if (spec["user"], spec["unit"]) in identities:
                    aliases.append("project-" + project)
        except (ValueError, KeyError, TypeError):
            raise ExecutorError("unavailable", "application backup contract is unknown") from None
        with ExitStack() as stack:
            for target in sorted(set(plan.lock_targets) | set(aliases)):
                stack.enter_context(self.target_lock(target))
            if load_registry(self.registry_path) != registry:
                raise ExecutorError("conflict", "registry changed while locking group")
            with self._db() as db:
                rows = db.execute("SELECT project, intent FROM backup_pauses LIMIT 65").fetchall()
            if len(rows) > 64:
                raise ExecutorError("unavailable", "backup pause capacity exceeded")
            for project, body in rows:
                try:
                    pause = BackupPause.model_validate_json(body)
                    if pause.binding.project != project:
                        raise ValueError("inconsistent backup pause")
                except (ValueError, TypeError):
                    raise ExecutorError("unavailable", "backup pause state is unknown") from None
                if (pause.user, pause.unit) in identities:
                    raise ExecutorError("unavailable", "backup pause recovery is pending")
            yield

    @contextmanager
    def backup_mutation_lock(self, project: str, registry: dict, *, locked: bool = False):
        """Hold the project lock beyond admission, without a long global lock."""
        with ExitStack() as stack:
            with self.target_lock("deployment-execution"):
                if self.deployment_fence() is not None:
                    raise ExecutorError("target_busy", "deployment recovery is pending")
                if not locked:
                    stack.enter_context(self.target_lock(f"project-{project}"))
                latest = load_registry(self.registry_path)
                if latest != registry:
                    raise ExecutorError("conflict", "backup registry changed")
                spec = latest["projects"].get(project)
                if spec is None:
                    raise ExecutorError("policy_denied", "project is not registered")
                self.ensure_group_restart_allowed(latest, spec)
            yield

    def group_history(self, operation_id: str):
        """Read one retained terminal group result without granting restore authority."""
        from ..core.group_backups import GroupHistory

        if not isinstance(operation_id, str) or re.fullmatch(r"[a-f0-9]{32}", operation_id) is None:
            raise ExecutorError("bad_request", "invalid group operation identity")
        with self._db() as db:
            row = db.execute(
                "SELECT h.application, h.body, o.application FROM application_group_history h "
                "LEFT JOIN application_group_operator_intents o ON o.operation_id=h.operation_id "
                "WHERE h.operation_id=?",
                (operation_id,),
            ).fetchone()
        if row is None:
            return None
        try:
            history = GroupHistory.model_validate_json(row[1])
            if (
                history.checkpoint.operation_id != operation_id
                or history.checkpoint.plan.application != row[0]
            ):
                raise ValueError("inconsistent group history")
            checkpoint = history.checkpoint.with_persisted_owner(row[2])
            return GroupHistory(
                archived_at=history.archived_at, checkpoint=checkpoint, workflow=history.workflow
            )
        except ValueError:
            raise ExecutorError("unavailable", "group history is inconsistent") from None

    def archive_group_checkpoint(self, application: str, operation_id: str, generation: int):
        """Move an exact terminal checkpoint into bounded immutable history.

        This private operation keeps capture artifacts and never authorizes a
        restore, deletion or public group action. Retrying an already archived
        identity cannot remove a newer active checkpoint.
        """
        from ..core.group_backups import GroupCaptureWorkflow, GroupHistory

        if (
            not isinstance(application, str)
            or re.fullmatch(r"[a-z][a-z0-9-]{1,30}[a-z0-9]", application) is None
            or not isinstance(operation_id, str)
            or re.fullmatch(r"[a-f0-9]{32}", operation_id) is None
            or type(generation) is not int
            or not 0 <= generation <= MAX_GROUP_GENERATION
        ):
            raise ExecutorError("bad_request", "invalid group checkpoint identity")
        existing = self.group_history(operation_id)
        if existing is not None:
            if (
                existing.checkpoint.plan.application != application
                or existing.checkpoint.generation != generation
            ):
                raise ExecutorError("conflict", "archived group identity changed")
            self.audit.append(
                "application_group_archive",
                application=application,
                operation_id=operation_id,
                outcome="confirmed",
            )
            return existing
        initial = self.group_checkpoint(application)
        if (
            initial is None
            or initial.operation_id != operation_id
            or initial.generation != generation
        ):
            raise ExecutorError("conflict", "group checkpoint changed")
        if initial.phase not in ("complete", "recovered"):
            raise ExecutorError("policy_denied", "group checkpoint is not terminal")
        with (
            self.group_driver_lock(initial),
            self.target_lock("deployment-execution"),
            self.target_locks(initial.plan.lock_targets),
        ):
            if self.deployment_fence() is not None or self.group_checkpoint(application) != initial:
                raise ExecutorError("conflict", "group or deployment state changed")
            self.audit.append(
                "application_group_archive",
                application=application,
                operation_id=operation_id,
                outcome="prepared",
            )
            with self._db() as db:
                db.execute("BEGIN IMMEDIATE")
                row = self._read_group_checkpoint(db, application)
                if (
                    row is None
                    or row[0] != operation_id
                    or row[1] != generation
                    or GroupCheckpoint.model_validate_json(row[2]).with_persisted_owner(row[3])
                    != initial
                ):
                    raise ExecutorError("conflict", "group checkpoint changed")
                workflow_row = db.execute(
                    "SELECT operation_id, body FROM application_capture_workflows "
                    "WHERE application=?",
                    (application,),
                ).fetchone()
                workflow = None
                if workflow_row is not None:
                    try:
                        workflow = GroupCaptureWorkflow.model_validate_json(workflow_row[1])
                    except ValueError:
                        raise ExecutorError(
                            "unavailable", "group capture workflow is inconsistent"
                        ) from None
                    if workflow.operation_id != workflow_row[0] or workflow.phase == "prepared":
                        raise ExecutorError("target_busy", "group capture workflow is unresolved")
                if (
                    db.execute("SELECT COUNT(*) FROM application_group_history").fetchone()[0]
                    >= MAX_GROUP_HISTORY
                ):
                    raise ExecutorError("unavailable", "group history capacity reached")
                try:
                    history = GroupHistory(
                        archived_at=time.time(), checkpoint=initial, workflow=workflow
                    )
                    db.execute(
                        "INSERT INTO application_group_history VALUES (?,?,?)",
                        (
                            operation_id,
                            application,
                            history.model_dump_json(exclude={"checkpoint": {"operator_managed"}}),
                        ),
                    )
                except (ValueError, sqlite3.IntegrityError):
                    raise ExecutorError("unavailable", "group history is inconsistent") from None
                if workflow_row is not None:
                    deleted = db.execute(
                        "DELETE FROM application_capture_workflows WHERE application=? "
                        "AND operation_id=? AND body=?",
                        (application, workflow_row[0], workflow_row[1]),
                    )
                    if deleted.rowcount != 1:
                        raise ExecutorError("conflict", "group capture workflow changed")
                deleted = db.execute(
                    "DELETE FROM application_group_intents WHERE application=? "
                    "AND operation_id=? AND generation=? AND body=?",
                    (application, operation_id, generation, row[2]),
                )
                if deleted.rowcount != 1:
                    raise ExecutorError("conflict", "group checkpoint changed")
            self.audit.append(
                "application_group_archive",
                application=application,
                operation_id=operation_id,
                outcome="archived",
            )
            return history

    def begin_group_checkpoint(
        self,
        application: str,
        service: str,
        *,
        expected_revision: str,
        original_running: dict[str, bool],
        scope: Literal["dependents", "application"] = "dependents",
        _expected_plan: GroupPlan | None = None,
        operator_managed: bool = False,
        previous: tuple[str, int] | None = None,
    ) -> GroupCheckpoint:
        """Persist a root-registry-derived intent; this does not authorize host work."""
        try:
            with self._db() as db:
                db.execute("BEGIN IMMEDIATE")
                if db.execute("SELECT 1 FROM deployment_fence WHERE singleton=1").fetchone():
                    raise ExecutorError("target_busy", "deployment fence is active")
                count = db.execute("SELECT COUNT(*) FROM application_group_intents").fetchone()[0]
                if count > MAX_GROUP_CHECKPOINTS or (
                    count == MAX_GROUP_CHECKPOINTS and previous is None
                ):
                    raise ExecutorError("unavailable", "group checkpoint capacity reached")
                registry = load_registry(self.registry_path)
                plan = GroupPlan.model_validate(
                    derive_group_plan(
                        registry,
                        application,
                        service,
                        expected_revision=expected_revision,
                        scope=scope,
                    )
                )
                if _expected_plan is not None and plan != _expected_plan:
                    raise ExecutorError("conflict", "group contract changed during observation")
                operation_id = uuid.uuid4()
                if operator_managed:
                    # Legacy checkpoints use v4. A v5 identity also detects a missing marker.
                    operation_id = uuid.uuid5(uuid.NAMESPACE_OID, operation_id.hex)
                checkpoint = GroupCheckpoint(
                    operation_id=operation_id.hex,
                    plan=plan,
                    original_running=original_running,
                    operator_managed=operator_managed,
                )
                if previous is not None:
                    if not operator_managed:
                        raise ExecutorError("policy_denied", "operator checkpoint is required")
                    self._replace_group_checkpoint(db, application, previous)
                if operator_managed:
                    if self.host.kill_switch():
                        raise ExecutorError(
                            "kill_switch", "application group operations are stopped"
                        )
                    db.execute(
                        "INSERT INTO application_group_operator_intents VALUES (?,?)",
                        (checkpoint.operation_id, application),
                    )
                    self.audit.append(
                        "application_group_admission",
                        application=application,
                        service=service,
                        operation_id=checkpoint.operation_id,
                        previous_operation_id=previous[0] if previous else None,
                        revision=expected_revision,
                        role="operator",
                    )
                db.execute(
                    "INSERT INTO application_group_intents VALUES (?,?,?,?)",
                    (
                        application,
                        checkpoint.operation_id,
                        checkpoint.generation,
                        checkpoint.persisted_json(),
                    ),
                )
        except sqlite3.IntegrityError:
            raise ExecutorError("target_busy", "application already has a group intent") from None
        return checkpoint

    def _replace_group_checkpoint(
        self, db: sqlite3.Connection, application: str, previous: tuple[str, int]
    ) -> None:
        from ..core.group_backups import GroupHistory

        row = self._read_group_checkpoint(db, application)
        if row is None or row[:2] != previous:
            raise ExecutorError("conflict", "previous group checkpoint changed")
        predecessor = GroupCheckpoint.model_validate_json(row[2]).with_persisted_owner(row[3])
        if (
            predecessor.plan.application != application
            or (predecessor.operation_id, predecessor.generation) != previous
        ):
            raise ExecutorError("unavailable", "group checkpoint is inconsistent")
        if not predecessor.operator_managed or predecessor.phase not in ("complete", "recovered"):
            raise ExecutorError("target_busy", "previous operator checkpoint is not terminal")
        if db.execute(
            "SELECT 1 FROM application_capture_workflows WHERE application=?", (application,)
        ).fetchone():
            raise ExecutorError("target_busy", "application has a capture workflow")
        if (
            db.execute("SELECT COUNT(*) FROM application_group_history").fetchone()[0]
            >= MAX_GROUP_HISTORY
        ):
            raise ExecutorError("unavailable", "group history capacity reached")
        history = GroupHistory(archived_at=time.time(), checkpoint=predecessor)
        self.audit.append(
            "application_group_archive",
            application=application,
            operation_id=predecessor.operation_id,
            outcome="prepared",
        )
        db.execute(
            "INSERT INTO application_group_history VALUES (?,?,?)",
            (
                predecessor.operation_id,
                application,
                history.model_dump_json(exclude={"checkpoint": {"operator_managed"}}),
            ),
        )
        db.execute("DELETE FROM application_group_intents WHERE application=?", (application,))

    def _operator_group_boot_ready(self) -> bool:
        unit = self.host.system_unit(boot.BOOT_UNIT)
        return (unit.get("load"), unit.get("active"), unit.get("sub")) == (
            "loaded",
            "active",
            "exited",
        )

    def _operator_group_authority(self, registry, plan) -> dict[str, boot.Target]:
        if self.host.kill_switch():
            raise ExecutorError("kill_switch", "application group operations are stopped")
        if self.deployment_fence() is not None:
            raise ExecutorError("target_busy", "deployment fence is active")
        try:
            authority = boot.require_group_authority(self.host, registry, plan)
            if not set(plan.start_order + plan.external_dependencies) <= authority.keys():
                raise boot.BootError("incomplete application boot authority")
            return authority
        except (boot.BootError, OSError, ValueError, KeyError) as exc:
            raise ExecutorError(
                "policy_denied", "application boot authority is unavailable"
            ) from exc

    def _disabled_group_manager_quiescent(self, target: boot.Target) -> bool:
        try:
            boot.verify_stop_identity(target.binding)
            return boot.manager_quiescent(self.host, target.binding)
        except (boot.BootError, OSError, ValueError, KeyError):
            return False

    def _group_observation(self, spec, target: boot.Target | None) -> bool | None:
        state = self.host.group_service_running(spec["user"], spec["unit"], spec["container"])
        if target is None:
            return state
        if state is None:
            if not target.enabled and self._disabled_group_manager_quiescent(target):
                return False
            return None
        if self.host.application_unit_transitioning(spec["user"], spec["unit"]) is not False:
            return None
        return state

    def _group_quiescent(self, spec, target: boot.Target | None) -> bool:
        if self.host.group_service_quiescent(spec["user"], spec["unit"], spec["container"]):
            return True
        return (
            target is not None
            and not target.enabled
            and self.host.group_service_running(spec["user"], spec["unit"], spec["container"])
            is None
            and self._disabled_group_manager_quiescent(target)
        )

    def _require_group_health(self, target: boot.Target, *, retry: bool = False) -> None:
        health = target.health
        if health is None:
            return
        deadline = time.monotonic() + 5 if retry else None
        try:
            port = target.port
            uid = target.binding.uid
            if port is None:
                raise boot.BootError("group health listener ownership is unconfirmed")
            for attempt in range(health.retries if retry else 1):
                if deadline is not None:
                    if attempt:
                        if deadline - time.monotonic() <= 2:
                            break
                        time.sleep(2)
                    if time.monotonic() >= deadline:
                        break
                if not self.host.application_listener_owned(port, uid):
                    continue
                timeout = health.timeout_s
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    timeout = min(timeout, remaining)
                try:
                    healthy = self.host.http_health(port, health.path, timeout)["ok"]
                finally:
                    if not self.host.application_listener_owned(port, uid):
                        raise boot.BootError("group health listener ownership changed")
                if healthy and (deadline is None or time.monotonic() <= deadline):
                    return
            raise boot.BootError("group health check failed")
        except (boot.BootError, OSError, ValueError) as exc:
            raise ExecutorError("unavailable", "group service health is not confirmed") from exc

    @contextmanager
    def observed_group_execution(
        self,
        application: str,
        service: str,
        *,
        expected_revision: str,
        scope: Literal["dependents", "application"] = "dependents",
        operator_managed: bool = False,
        previous: tuple[str, int] | None = None,
    ):
        """Lock root-derived targets and persist an observed group checkpoint.

        Operator admission verifies boot authority before observing or recording
        intent. Internal capture callers retain their existing admission path.
        """
        with self.target_lock("deployment-execution"):
            registry = load_registry(self.registry_path)
            if operator_managed and registry.get("config_revision") != expected_revision:
                raise ExecutorError("conflict", "active configuration changed")
            try:
                plan = GroupPlan.model_validate(
                    derive_group_plan(
                        registry,
                        application,
                        service,
                        expected_revision=expected_revision,
                        scope=scope,
                    )
                )
            except ValueError as exc:
                if not operator_managed:
                    raise
                raise ExecutorError("policy_denied", "invalid application group selection") from exc
            with self.group_backup_locks(plan):
                registry = load_registry(self.registry_path)
                latest = GroupPlan.model_validate(
                    derive_group_plan(
                        registry,
                        application,
                        service,
                        expected_revision=expected_revision,
                        scope=scope,
                    )
                )
                if latest != plan:
                    raise ExecutorError("conflict", "group contract changed before observation")
                authority = (
                    self._operator_group_authority(registry, plan) if operator_managed else {}
                )
                specs = registry["applications"][application]["services"]
                states = {}
                for name in plan.start_order + plan.external_dependencies:
                    spec = specs[name]
                    state = self._group_observation(spec, authority.get(name))
                    if type(state) is not bool:
                        raise ExecutorError("unavailable", "group service state is not known")
                    if state and not spec["deploy"]:
                        raise ExecutorError("policy_denied", "disabled group service is running")
                    if (
                        operator_managed
                        and not state
                        and not self._group_quiescent(spec, authority[name])
                    ):
                        raise ExecutorError("unavailable", "stopped group service is not quiescent")
                    states[name] = state
                for name, running in states.items():
                    if running and any(not states[dep] for dep in specs[name]["depends_on"]):
                        raise ExecutorError(
                            "policy_denied", "running service has a stopped dependency"
                        )
                if operator_managed and load_registry(self.registry_path) != registry:
                    raise ExecutorError("conflict", "registry changed during group observation")
                checkpoint = self.begin_group_checkpoint(
                    application,
                    service,
                    expected_revision=expected_revision,
                    original_running={name: states[name] for name in plan.start_order},
                    scope=scope,
                    _expected_plan=plan,
                    operator_managed=operator_managed,
                    previous=previous,
                )
                yield checkpoint

    @contextmanager
    def deployment_execution(
        self,
        *,
        base_revision: str,
        desired_revision: str,
        operation_id: str | None = None,
        reserve_site: Callable[..., None] | None = None,
        resume_site: Callable[..., None] | None = None,
    ):
        """Hold a live host lock around a durable deployment intent.

        The persistent fence alone permits exact-token recovery, so it does not
        prevent two processes with the same token from running at once. Future
        deployment integration must hold this context for every host mutation
        through verification and release. Exiting, including on error, never
        clears the durable intent; an interrupted run requires reconciliation.
        Orphaned child processes can outlive the lock holder; integration must
        stop or reconcile them before another process resumes host changes.
        This helper neither authorizes nor performs a deployment.
        """
        with self.target_lock("deployment-execution"), ExitStack() as stack:
            registry = load_registry(self.registry_path)
            projects = registry.get("projects", {})
            if (
                not isinstance(projects, dict)
                or len(projects) > 64
                or any(
                    not isinstance(project, str)
                    or re.fullmatch(r"[a-z][a-z0-9-]{1,30}[a-z0-9]", project) is None
                    for project in projects
                )
            ):
                raise ExecutorError("unavailable", "deployment project registry is unknown")
            for project in sorted(projects):
                stack.enter_context(self.target_lock(f"project-{project}"))
            if load_registry(self.registry_path) != registry:
                raise ExecutorError("conflict", "deployment registry changed while locking")
            with self._db() as db:
                if db.execute("SELECT 1 FROM backup_pauses LIMIT 1").fetchone():
                    raise ExecutorError("target_busy", "backup pause recovery is pending")
            if not self.host.deployment_rollbacks_quiescent():
                raise ExecutorError("target_busy", "deployment rollback is active or unknown")
            yield self.begin_deployment_fence(
                base_revision=base_revision,
                desired_revision=desired_revision,
                operation_id=operation_id,
                reserve_site=reserve_site,
                resume_site=resume_site,
            )

    def deployment_fence(self) -> DeploymentFence | None:
        """Read the durable deployment intent, if any."""
        with self._db() as db:
            row = db.execute("SELECT body FROM deployment_fence WHERE singleton=1").fetchone()
        return DeploymentFence.model_validate_json(row[0]) if row else None

    def begin_deployment_fence(
        self,
        *,
        base_revision: str,
        desired_revision: str,
        operation_id: str | None = None,
        reserve_site: Callable[..., None] | None = None,
        resume_site: Callable[..., None] | None = None,
    ) -> DeploymentFence:
        """Reserve a deployment intent or resume its exact existing binding.

        This internal primitive has no deployment side effects and is not a
        registered action. Future integration must establish authorization,
        audit and recovery before it can guard real configuration writes.
        """
        if reserve_site is not None and resume_site is not None:
            raise ValueError("deployment reservation and recovery are mutually exclusive")
        requested = DeploymentFence(
            operation_id=operation_id if operation_id is not None else uuid.uuid4().hex,
            base_revision=base_revision,
            desired_revision=desired_revision,
        )
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT body FROM deployment_fence WHERE singleton=1").fetchone()
            registry = load_registry(self.registry_path)
            current_revision = registry.get("config_revision")
            if row:
                existing = DeploymentFence.model_validate_json(row[0])
                if (
                    reserve_site is not None
                    or existing != requested
                    or current_revision
                    not in (
                        existing.base_revision,
                        existing.desired_revision,
                    )
                ):
                    raise ExecutorError("target_busy", "another deployment fence is active")
                if resume_site is not None:
                    resume_site(db, existing)
                return existing
            if resume_site is not None:
                raise ExecutorError("conflict", "the exact deployment fence is absent")
            if current_revision != requested.base_revision:
                raise ExecutorError("conflict", "deployment base revision changed")
            rows = db.execute(
                "SELECT application, operation_id, generation, body FROM application_group_intents "
                "LIMIT ?",
                (MAX_GROUP_CHECKPOINTS + 1,),
            ).fetchall()
            if len(rows) > MAX_GROUP_CHECKPOINTS:
                raise ExecutorError("unavailable", "group checkpoint capacity exceeded")
            for application, op_id, generation, body in rows:
                checkpoint = GroupCheckpoint.model_validate_json(body)
                if (
                    checkpoint.plan.application != application
                    or checkpoint.operation_id != op_id
                    or checkpoint.generation != generation
                    or checkpoint.phase not in ("complete", "recovered")
                ):
                    raise ExecutorError("target_busy", "application group intent is active")
            db.execute("INSERT INTO deployment_fence VALUES (1,?)", (requested.model_dump_json(),))
            if reserve_site is not None:
                reserve_site(db, requested)
        return requested

    def release_deployment_fence(self, operation_id: str) -> None:
        """Release only the exact intent after the desired registry is present.

        A future authorized caller must verify and audit deployment success
        before invoking this primitive. No registered action calls it yet.
        """
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT body FROM deployment_fence WHERE singleton=1").fetchone()
            if row is None:
                raise ExecutorError("conflict", "deployment fence is absent")
            fence = DeploymentFence.model_validate_json(row[0])
            if fence.operation_id != operation_id:
                raise ExecutorError("conflict", "deployment fence changed")
            if load_registry(self.registry_path).get("config_revision") != fence.desired_revision:
                raise ExecutorError("policy_denied", "desired registry is not active")
            db.execute("DELETE FROM deployment_fence WHERE singleton=1")

    def advance_group_checkpoint(
        self,
        application: str,
        operation_id: str,
        generation: int,
        transition: str,
        *,
        observed_running: bool | None = None,
    ) -> GroupCheckpoint:
        """Advance one checkpoint with registry revalidation and CAS fencing.

        Future host operations must also hold the derived locks and fence
        configuration changes; this method has no host side effects.
        """
        current = self.group_checkpoint(application)
        if (
            current is None
            or current.operation_id != operation_id
            or type(generation) is not int
            or current.generation != generation
        ):
            raise ExecutorError("conflict", "group checkpoint changed")
        registry = load_registry(self.registry_path)
        try:
            plan = GroupPlan.model_validate(rederive_checkpoint_plan(registry, current.plan))
        except ValueError:
            raise ExecutorError("policy_denied", "group contract changed") from None
        if plan != current.plan:
            raise ExecutorError("policy_denied", "group contract changed")
        updated = current.advance(transition, observed_running=observed_running)
        with self._db() as db:
            result = db.execute(
                "UPDATE application_group_intents SET generation=?, body=? "
                "WHERE application=? AND operation_id=? AND generation=?",
                (
                    updated.generation,
                    updated.persisted_json(),
                    application,
                    operation_id,
                    generation,
                ),
            )
            if result.rowcount != 1:
                raise ExecutorError("conflict", "group checkpoint changed")
        return updated

    def begin_group_recovery(
        self, application: str, operation_id: str, generation: int
    ) -> GroupCheckpoint:
        """Start restoring the confirmed stopped prefix after a partial stop.

        A pending stop is either cancelled in its original state or confirmed
        from an observed quiescent stop without repeating the host command.
        This internal method is not a registered action.
        """
        with self.target_lock("deployment-execution"):
            initial = self.group_checkpoint(application)
            if (
                initial is None
                or initial.operation_id != operation_id
                or type(generation) is not int
                or initial.generation != generation
            ):
                raise ExecutorError("conflict", "group checkpoint changed")
            if initial.phase != "stopping":
                raise ExecutorError("policy_denied", "group is not stopping")
            with self.group_backup_locks(initial.plan):
                current = self.group_checkpoint(application)
                if current != initial or self.deployment_fence() is not None:
                    raise ExecutorError("conflict", "group or deployment state changed")
                registry = load_registry(self.registry_path)
                try:
                    plan = GroupPlan.model_validate(
                        rederive_checkpoint_plan(registry, current.plan)
                    )
                except ValueError:
                    raise ExecutorError("policy_denied", "group contract changed") from None
                if plan != current.plan:
                    raise ExecutorError("policy_denied", "group contract changed")
                authority = (
                    self._operator_group_authority(registry, plan)
                    if current.operator_managed
                    else {}
                )
                specs = registry["applications"][application]["services"]
                states = {}
                for name in plan.start_order + plan.external_dependencies:
                    spec = specs[name]
                    state = self._group_observation(spec, authority.get(name))
                    if type(state) is not bool:
                        raise ExecutorError("unavailable", "group service state is not known")
                    if name in plan.external_desired_running and state and not spec["deploy"]:
                        raise ExecutorError("policy_denied", "disabled dependency is running")
                    states[name] = state
                stopped_pending = bool(
                    current.pending
                    and current.original_running[current.pending.service]
                    and states[current.pending.service] is False
                )
                for index, name in enumerate(plan.stop_order):
                    expected = (
                        False
                        if index < current.stop_index
                        or (index == current.stop_index and stopped_pending)
                        else current.original_running[name]
                    )
                    if states[name] != expected:
                        raise ExecutorError("conflict", "group service state needs reconciliation")
                    spec = specs[name]
                    if not states[name] and not self._group_quiescent(spec, authority.get(name)):
                        raise ExecutorError("unavailable", "stopped group service is not quiescent")
                for name, state in states.items():
                    if state and any(not states[dep] for dep in specs[name]["depends_on"]):
                        raise ExecutorError(
                            "policy_denied", "running service has a stopped dependency"
                        )
                if stopped_pending:
                    self.audit.append(
                        "application_group_step",
                        application=application,
                        service=current.pending.service,
                        operation_id=operation_id,
                        action="stop",
                        outcome="confirmed",
                    )
                    current = self.advance_group_checkpoint(
                        application,
                        operation_id,
                        current.generation,
                        "confirm",
                        observed_running=False,
                    )
                self.audit.append(
                    "application_group_phase",
                    application=application,
                    operation_id=operation_id,
                    phase="recover",
                )
                observed = states[current.pending.service] if current.pending else None
                return self.advance_group_checkpoint(
                    application,
                    operation_id,
                    current.generation,
                    "recover",
                    observed_running=observed,
                )

    def reconcile_group_step(
        self, application: str, operation_id: str, generation: int
    ) -> GroupCheckpoint:
        """Reconcile one checkpointed automatic group step under derived locks.

        Operator checkpoints require current boot authority before preparing or
        performing a step. Capture checkpoints use the internal workflow.
        """
        with self.target_lock("deployment-execution"):
            initial = self.group_checkpoint(application)
            if (
                initial is None
                or initial.operation_id != operation_id
                or type(generation) is not int
                or initial.generation != generation
            ):
                raise ExecutorError("conflict", "group checkpoint changed")
            if initial.phase not in ("stopping", "resuming", "recovering"):
                raise ExecutorError("policy_denied", "group is not transitioning")
            with self.group_backup_locks(initial.plan):
                current = self.group_checkpoint(application)
                if current != initial or self.deployment_fence() is not None:
                    raise ExecutorError("conflict", "group or deployment state changed")
                registry = load_registry(self.registry_path)
                try:
                    plan = GroupPlan.model_validate(
                        rederive_checkpoint_plan(registry, current.plan)
                    )
                except ValueError:
                    raise ExecutorError("policy_denied", "group contract changed") from None
                if plan != current.plan:
                    raise ExecutorError("policy_denied", "group contract changed")
                authority = (
                    self._operator_group_authority(registry, plan)
                    if current.operator_managed
                    else {}
                )
                specs = registry["applications"][application]["services"]
                if current.phase == "stopping":
                    order, index = plan.stop_order, current.stop_index
                elif current.phase == "resuming":
                    order, index = plan.start_order, current.resume_index
                else:
                    order = list(reversed(plan.stop_order[: current.stop_index]))
                    index = current.recovery_index
                states = {}
                for name in plan.start_order + plan.external_dependencies:
                    spec = specs[name]
                    state = self._group_observation(spec, authority.get(name))
                    if type(state) is not bool:
                        raise ExecutorError("unavailable", "group service state is not known")
                    if name in plan.external_desired_running and state and not spec["deploy"]:
                        raise ExecutorError("policy_denied", "disabled dependency is running")
                    states[name] = state
                if current.phase in ("resuming", "recovering"):
                    for name, state in states.items():
                        if state and any(not states[dep] for dep in specs[name]["depends_on"]):
                            raise ExecutorError(
                                "policy_denied", "running service has a stopped dependency"
                            )
                if current.phase == "recovering":
                    for name in plan.stop_order[current.stop_index :]:
                        if states[name] != current.original_running[name]:
                            raise ExecutorError("conflict", "group service state drifted")
                        if not states[name]:
                            spec = specs[name]
                            if not self._group_quiescent(spec, authority.get(name)):
                                raise ExecutorError(
                                    "unavailable", "stopped group service is not quiescent"
                                )
                for pos, name in enumerate(order):
                    original = current.original_running[name]
                    if current.phase == "stopping":
                        allowed = {False} if pos < index else {original}
                        if pos == index and current.pending is not None:
                            allowed = {original, False}
                    else:
                        allowed = {original} if pos < index else {False}
                        if pos == index and current.pending is not None:
                            allowed = {False, original}
                    if states[name] not in allowed:
                        raise ExecutorError("conflict", "group service state drifted")
                    if not states[name]:
                        spec = specs[name]
                        if not self._group_quiescent(spec, authority.get(name)):
                            raise ExecutorError(
                                "unavailable", "stopped group service is not quiescent"
                            )
                if index == len(order):
                    transition = (
                        "pause"
                        if current.phase == "stopping"
                        else "finish_recovery"
                        if current.phase == "recovering"
                        else "finish"
                    )
                    self.audit.append(
                        "application_group_phase",
                        application=application,
                        operation_id=operation_id,
                        phase=transition,
                    )
                    return self.advance_group_checkpoint(
                        application, operation_id, current.generation, transition
                    )
                if current.pending is None:
                    current = self.advance_group_checkpoint(
                        application, operation_id, current.generation, "prepare"
                    )
                name = order[index]
                desired = current.phase != "stopping" and current.original_running[name]
                spec = specs[name]
                if desired:
                    for dependency in spec["depends_on"]:
                        if not states[dependency]:
                            raise ExecutorError("policy_denied", "group dependency is not running")
                        if current.operator_managed:
                            self._require_group_health(authority[dependency])
                changed = states[name] != desired
                if changed:
                    if current.operator_managed:
                        if not authority[name].enabled:
                            raise ExecutorError(
                                "policy_denied", "disabled group service cannot transition"
                            )
                        if load_registry(self.registry_path) != registry:
                            raise ExecutorError(
                                "conflict", "registry changed during group observation"
                            )
                    if self.host.kill_switch():
                        raise ExecutorError("kill_switch", "automatic group operation is stopped")
                    action = "application_group_start" if desired else "application_group_stop"
                    self.spend_budget(spec["lock"], action, RESTART_BUDGET_PER_HOUR)
                    self.audit.append(
                        "application_group_step",
                        application=application,
                        service=name,
                        operation_id=operation_id,
                        action=action,
                        outcome="attempt",
                    )
                    if current.operator_managed and self.host.kill_switch():
                        raise ExecutorError(
                            "kill_switch", "application group operations are stopped"
                        )
                    if not self.host.set_user_unit(spec["user"], spec["unit"], running=desired):
                        raise ExecutorError("execution_failed", "group service transition failed")
                deadline = time.monotonic() + 5 if changed else time.monotonic()
                for _ in range(51):
                    observed = self._group_observation(spec, authority.get(name))
                    confirmed = type(observed) is bool and observed == desired
                    if confirmed and (desired or self._group_quiescent(spec, authority.get(name))):
                        break
                    if time.monotonic() >= deadline:
                        raise ExecutorError("unavailable", "group transition is not confirmed")
                    time.sleep(0.1)
                else:
                    raise ExecutorError("unavailable", "group transition is not confirmed")
                if desired and current.operator_managed:
                    target = authority[name]
                    self._require_group_health(target, retry=True)
                    if (
                        target.health is not None
                        and self._group_observation(spec, target) is not True
                    ):
                        raise ExecutorError("unavailable", "group transition is not confirmed")
                self.audit.append(
                    "application_group_step",
                    application=application,
                    service=name,
                    operation_id=operation_id,
                    action="start" if desired else "stop",
                    outcome="confirmed",
                )
                return self.advance_group_checkpoint(
                    application,
                    operation_id,
                    current.generation,
                    "confirm",
                    observed_running=observed,
                )

    def stop_group_with_recovery(
        self, application: str, operation_id: str, generation: int
    ) -> dict[str, Any]:
        """Stop a group or attempt bounded restoration after a transition failure.

        This is an internal automatic coordinator, not a registered action.
        Concurrent/stale callers and the kill switch are not overridden. A
        failure to establish safe recovery leaves the checkpoint intact.
        """
        current = self.group_checkpoint(application)
        if current is None or current.operation_id != operation_id:
            raise ExecutorError("conflict", "group checkpoint changed")
        with self.group_driver_lock(current):
            return self._stop_group_with_recovery(application, operation_id, generation)

    @contextmanager
    def group_driver_lock(self, checkpoint: GroupCheckpoint | str):
        """Serialize group drivers by the registered application identity."""
        application = (
            checkpoint.plan.application if isinstance(checkpoint, GroupCheckpoint) else checkpoint
        )
        application_lock = "application-" + graph_identifier("a", application)
        with self.target_lock("group-driver-" + application_lock):
            yield

    def _stop_group_with_recovery(
        self, application: str, operation_id: str, generation: int
    ) -> dict[str, Any]:
        current = self.group_checkpoint(application)
        if (
            current is None
            or current.operation_id != operation_id
            or type(generation) is not int
            or current.generation != generation
        ):
            raise ExecutorError("conflict", "group checkpoint changed")
        if current.phase != "stopping":
            raise ExecutorError("policy_denied", "group is not stopping")
        failure = None
        failed_generation = current.generation
        for _ in range(len(current.plan.stop_order) + 1):
            failed_generation = current.generation
            try:
                current = self.reconcile_group_step(application, operation_id, current.generation)
            except ExecutorError as exc:
                if exc.error_class in ("target_busy", "conflict", "kill_switch"):
                    raise
                failure = exc.error_class
                break
            except OSError:
                failure = "internal"
                break
            if current.phase == "paused":
                return {"state": "paused", "checkpoint": current, "error_class": None}
        if failure is None:
            raise ExecutorError("internal", "group stop exceeded its step bound")
        self.audit.append(
            "application_group_failure",
            application=application,
            operation_id=operation_id,
            error_class=failure,
        )
        current = self.group_checkpoint(application)
        if (
            current is None
            or current.operation_id != operation_id
            or current.phase != "stopping"
            or current.generation not in (failed_generation, failed_generation + 1)
            or (current.generation == failed_generation + 1 and current.pending is None)
        ):
            raise ExecutorError("conflict", "group checkpoint changed during failure handling")
        try:
            current = self.begin_group_recovery(application, operation_id, current.generation)
            for _ in range(len(current.plan.stop_order) + 1):
                current = self.reconcile_group_step(application, operation_id, current.generation)
                if current.phase == "recovered":
                    return {"state": "recovered", "checkpoint": current, "error_class": failure}
            raise ExecutorError("internal", "group recovery exceeded its step bound")
        except (ExecutorError, OSError) as exc:
            current = self.group_checkpoint(application)
            if current is None or current.operation_id != operation_id:
                raise ExecutorError(
                    "conflict", "group checkpoint changed during recovery"
                ) from None
            return {
                "state": "recovery_pending",
                "checkpoint": current,
                "error_class": failure,
                "recovery_error_class": exc.error_class
                if isinstance(exc, ExecutorError)
                else "internal",
            }

    def group_capture_workflow(self, application: str):
        """Read a root-owned capture workflow without assuming its capture succeeded."""
        from ..core.group_backups import GroupCaptureWorkflow

        with self._db() as db:
            row = db.execute(
                "SELECT operation_id, body FROM application_capture_workflows WHERE application=?",
                (application,),
            ).fetchone()
        if row is None:
            return None
        workflow = GroupCaptureWorkflow.model_validate_json(row[1])
        if workflow.application != application or workflow.operation_id != row[0]:
            raise ValueError("inconsistent group capture workflow")
        return workflow

    def begin_group_capture_workflow(self, checkpoint: GroupCheckpoint):
        """Persist recovery intent before any group stop; never infer capture success."""
        from ..core.group_backups import GroupCaptureWorkflow

        if (
            checkpoint.operator_managed
            or checkpoint.phase != "stopping"
            or checkpoint.plan.scope != "application"
            or checkpoint.plan.data_contract_revision is None
        ):
            raise ExecutorError("policy_denied", "a bound application stop is required")
        workflow = GroupCaptureWorkflow(
            application=checkpoint.plan.application,
            operation_id=checkpoint.operation_id,
            data_contract_revision=checkpoint.plan.data_contract_revision,
        )
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._read_group_checkpoint(db, checkpoint.plan.application)
            if (
                row is None
                or row[0] != checkpoint.operation_id
                or row[1] != checkpoint.generation
                or GroupCheckpoint.model_validate_json(row[2]).with_persisted_owner(row[3])
                != checkpoint
            ):
                raise ExecutorError("conflict", "group checkpoint changed")
            if (
                db.execute("SELECT COUNT(*) FROM application_capture_workflows").fetchone()[0]
                >= MAX_GROUP_CHECKPOINTS
            ):
                raise ExecutorError("unavailable", "group capture workflow capacity exceeded")
            try:
                db.execute(
                    "INSERT INTO application_capture_workflows VALUES (?,?,?)",
                    (workflow.application, workflow.operation_id, workflow.model_dump_json()),
                )
            except sqlite3.IntegrityError:
                raise ExecutorError(
                    "target_busy", "group capture workflow already exists"
                ) from None
        self.group_recovery_wakeup.set()
        return workflow

    def update_group_capture_workflow(
        self,
        previous,
        *,
        phase: str,
        artifact: str | None = None,
        capture_id: str | None = None,
        error_class: str | None = None,
    ):
        """CAS a workflow outcome; a partial capture never becomes successful."""
        from ..core.group_backups import GroupCaptureWorkflow

        if previous.phase == "captured":
            if (
                phase != "failed"
                or artifact != previous.artifact
                or capture_id != previous.capture_id
            ):
                raise ExecutorError("conflict", "captured workflow binding changed")
        elif previous.phase != "prepared":
            raise ExecutorError("conflict", "group capture workflow is already resolved")
        updated = GroupCaptureWorkflow(
            application=previous.application,
            operation_id=previous.operation_id,
            data_contract_revision=previous.data_contract_revision,
            phase=phase,
            artifact=artifact,
            capture_id=capture_id,
            error_class=error_class,
        )
        with self._db() as db:
            result = db.execute(
                "UPDATE application_capture_workflows SET body=? WHERE application=? "
                "AND operation_id=? AND body=?",
                (
                    updated.model_dump_json(),
                    previous.application,
                    previous.operation_id,
                    previous.model_dump_json(),
                ),
            )
            if result.rowcount != 1:
                raise ExecutorError("conflict", "group capture workflow changed")
        if updated.phase == "failed":
            self.audit.append(
                "application_group_capture_workflow",
                application=updated.application,
                operation_id=updated.operation_id,
                outcome="failed",
                error_class=updated.error_class,
            )
        return updated

    def resume_paused_group(self, application: str, operation_id: str, generation: int):
        """Commit a resume intent under all group and deployment locks."""
        with self.target_lock("deployment-execution"):
            initial = self.group_checkpoint(application)
            if (
                initial is None
                or initial.operation_id != operation_id
                or type(generation) is not int
                or initial.generation != generation
            ):
                raise ExecutorError("conflict", "group checkpoint changed")
            if initial.phase != "paused":
                raise ExecutorError("policy_denied", "group is not paused")
            with self.group_backup_locks(initial.plan):
                if (
                    self.group_checkpoint(application) != initial
                    or self.deployment_fence() is not None
                ):
                    raise ExecutorError("conflict", "group or deployment state changed")
                if initial.operator_managed:
                    registry = load_registry(self.registry_path)
                    self._operator_group_authority(registry, initial.plan)
                self.audit.append(
                    "application_group_phase",
                    application=application,
                    operation_id=operation_id,
                    phase="resume",
                )
                return self.advance_group_checkpoint(
                    application, operation_id, generation, "resume"
                )

    def recover_capture_group(self, application: str, operation_id: str) -> GroupCheckpoint:
        """Restore a failed capture's original state while its driver lock is held."""
        checkpoint = self.group_checkpoint(application)
        if checkpoint is None or checkpoint.operation_id != operation_id:
            raise ExecutorError("conflict", "group checkpoint changed")
        if checkpoint.phase == "stopping":
            checkpoint = self.begin_group_recovery(application, operation_id, checkpoint.generation)
        elif checkpoint.phase == "paused":
            checkpoint = self.resume_paused_group(application, operation_id, checkpoint.generation)
        if checkpoint.phase in ("complete", "recovered"):
            return checkpoint
        if checkpoint.phase not in ("recovering", "resuming"):
            raise ExecutorError("conflict", "group cannot be restored")
        for _ in range(len(checkpoint.plan.start_order) + 1):
            checkpoint = self.reconcile_group_step(application, operation_id, checkpoint.generation)
            if checkpoint.phase in ("complete", "recovered"):
                return checkpoint
        raise ExecutorError("internal", "group recovery exceeded its step bound")

    def preflight_application_capture(self, checkpoint: GroupCheckpoint) -> None:
        """Reject known capture failures before stopping any application service."""
        from ..core.backupexport import owned_directory
        from ..core.backups import BackupError
        from ..core.config import Backup
        from ..core.data_ownership import inspect_data_ownership
        from ..core.filebackups import ARCHIVE_OVERHEAD_MAX

        application = checkpoint.plan.application
        with self.target_lock("deployment-execution"), self.group_backup_locks(checkpoint.plan):
            if (
                self.group_checkpoint(application) != checkpoint
                or self.deployment_fence() is not None
            ):
                raise ExecutorError("conflict", "group or deployment state changed")
            if self.host.kill_switch():
                raise ExecutorError("kill_switch", "automatic application captures are stopped")
            registry = load_registry(self.registry_path)
            specs = registry["applications"][application]["services"]
            if set(specs) != set(checkpoint.plan.start_order):
                raise ExecutorError("policy_denied", "application coverage changed")
            try:
                for directory in (
                    APPLICATION_DATA_ROOT.parent,
                    APPLICATION_DATA_ROOT,
                    APPLICATION_DATA_ROOT / application,
                    APPLICATION_DATA_ROOT / application / "data",
                ):
                    owned_directory(directory)
                data_services = []
                for name in sorted(specs):
                    spec = specs[name]
                    source, target = spec.get("data_source"), spec.get("data_target")
                    if (source is None) != (target is None):
                        raise ExecutorError(
                            "policy_denied", "application data contract is incomplete"
                        )
                    if source is not None:
                        expected = APPLICATION_DATA_ROOT / application / "data" / name
                        if source != str(expected) or spec.get("allow_backup_pause") is not True:
                            raise ExecutorError(
                                "policy_denied", "application data capture is not authorized"
                            )
                        fd = os.open(expected, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                        os.close(fd)
                        data_services.append(name)
                if not data_services:
                    raise ExecutorError("policy_denied", "application has no registered data")
                base = Path(self._db_path).parent
                owned_directory(base)
                spool = base / "group-captures"
                spool.mkdir(mode=0o700, exist_ok=True)
                if owned_directory(spool).st_mode & 0o777 != 0o700:
                    raise BackupError("unsafe_spool")
                spool = spool / application
                spool.mkdir(mode=0o700, exist_ok=True)
                if owned_directory(spool).st_mode & 0o777 != 0o700:
                    raise BackupError("unsafe_spool")
                if backup_namespace_full(spool):
                    raise BackupError("retention_limit")
                maximum = Backup.model_validate(registry.get("backup", {})).max_mib * 1024 * 1024
                if (
                    shutil.disk_usage(spool).free
                    < maximum + len(data_services) * ARCHIVE_OVERHEAD_MAX + 512 * 1024 * 1024
                ):
                    raise BackupError("insufficient_space")
                budget_action, budget_limit = self._capture_budget()
                with self._db() as db:
                    used = db.execute(
                        "SELECT COUNT(*) FROM mutations WHERE target=? AND action=? AND ts>=?",
                        (
                            "application-" + graph_identifier("a", application),
                            budget_action,
                            time.time() - 3600,
                        ),
                    ).fetchone()[0]
                if used >= budget_limit:
                    raise ExecutorError("budget_exhausted", "application capture budget is used up")
                deadline = time.monotonic() + 180
                total = 0
                for name in data_services:
                    uid = self.host.service_user_uid(specs[name]["user"])
                    if uid is None:
                        raise BackupError("unsafe_owner")
                    if maximum - total < 1:
                        raise BackupError("limit_exceeded")
                    _, size = inspect_data_ownership(
                        APPLICATION_DATA_ROOT / application / "data" / name,
                        service_uid=uid,
                        max_bytes=maximum - total,
                        deadline=deadline,
                    )
                    total += size
                    if self.host.service_user_uid(specs[name]["user"]) != uid:
                        raise BackupError("unsafe_owner")
            except (BackupError, OSError) as exc:
                cause = exc.error_class if isinstance(exc, BackupError) else io_cause(exc)
                raise ExecutorError(
                    "unavailable", "application capture prerequisites are unavailable: " + cause
                ) from None

    def capture_application_with_recovery(
        self, application: str, operation_id: str, generation: int
    ):
        try:
            return self._capture_application_with_recovery(application, operation_id, generation)
        finally:
            self.group_recovery_wakeup.set()

    def _capture_application_with_recovery(
        self, application: str, operation_id: str, generation: int
    ):
        """Run bounded stop/capture/resume; persist enough intent for restart recovery.

        This private coordinator does not establish application consistency and
        is not a registered action. Kill switch, locks and budgets still apply.
        """
        checkpoint = self.group_checkpoint(application)
        if checkpoint is None or checkpoint.operation_id != operation_id:
            raise ExecutorError("conflict", "group checkpoint changed")
        with self.group_driver_lock(checkpoint):
            checkpoint = self.group_checkpoint(application)
            if (
                checkpoint is None
                or checkpoint.operation_id != operation_id
                or type(generation) is not int
                or checkpoint.generation != generation
            ):
                raise ExecutorError("conflict", "group checkpoint changed")
            workflow = self.begin_group_capture_workflow(checkpoint)
            self.audit.append(
                "application_group_capture_workflow",
                application=application,
                operation_id=operation_id,
                outcome="started",
            )
            try:
                self.preflight_application_capture(checkpoint)
                stopped = self._stop_group_with_recovery(application, operation_id, generation)
            except Exception as exc:  # noqa: BLE001 - persist failure before safe recovery
                error = exc.error_class if isinstance(exc, ExecutorError) else "internal"
                cause = message_cause(exc) if isinstance(exc, ExecutorError) else None
                self.audit.append(
                    "application_group_capture",
                    application=application,
                    operation_id=operation_id,
                    outcome="preflight_failed",
                    error_class=cause or error,
                )
                workflow = self.update_group_capture_workflow(
                    workflow, phase="failed", error_class=error
                )
                if error not in ("target_busy", "conflict", "kill_switch"):
                    try:
                        checkpoint = self.recover_capture_group(application, operation_id)
                        if checkpoint.phase in ("complete", "recovered"):
                            return {
                                "state": "capture_failed",
                                "workflow": workflow,
                                "checkpoint": checkpoint,
                            }
                    except Exception as recovery_exc:  # noqa: BLE001 - retain recovery intent
                        return {
                            "state": "recovery_pending",
                            "workflow": workflow,
                            "recovery_error_class": recovery_exc.error_class
                            if isinstance(recovery_exc, ExecutorError)
                            else "internal",
                        }
                return {"state": "recovery_pending", "workflow": workflow}
            if stopped["state"] != "paused":
                workflow = self.update_group_capture_workflow(
                    workflow, phase="failed", error_class=stopped["error_class"] or "internal"
                )
                return {
                    "state": "capture_failed"
                    if stopped["state"] == "recovered"
                    else "recovery_pending",
                    "workflow": workflow,
                    "checkpoint": stopped["checkpoint"],
                }
            checkpoint = stopped["checkpoint"]
            try:
                capture = self.capture_paused_application(
                    application, operation_id, checkpoint.generation
                )
                workflow = self.update_group_capture_workflow(
                    workflow,
                    phase="captured",
                    artifact=capture["artifact"],
                    capture_id=capture["capture_id"],
                )
            except Exception as exc:  # noqa: BLE001 - persist failure before safe recovery
                error = exc.error_class if isinstance(exc, ExecutorError) else "internal"
                workflow = self.update_group_capture_workflow(
                    workflow, phase="failed", error_class=error
                )
            recovery_error = "internal"
            try:
                checkpoint = self.resume_paused_group(
                    application, operation_id, checkpoint.generation
                )
                for _ in range(len(checkpoint.plan.start_order) + 1):
                    checkpoint = self.reconcile_group_step(
                        application, operation_id, checkpoint.generation
                    )
                    if checkpoint.phase == "complete":
                        self.audit.append(
                            "application_group_capture_workflow",
                            application=application,
                            operation_id=operation_id,
                            outcome=workflow.phase,
                        )
                        return {
                            "state": "captured"
                            if workflow.phase == "captured"
                            else "capture_failed",
                            "workflow": workflow,
                            "checkpoint": checkpoint,
                        }
            except Exception as exc:  # noqa: BLE001 - retain the checkpoint for recovery
                recovery_error = exc.error_class if isinstance(exc, ExecutorError) else "internal"
            return {
                "state": "recovery_pending",
                "workflow": workflow,
                "checkpoint": self.group_checkpoint(application),
                "recovery_error_class": recovery_error,
            }

    def _capture_budget(self) -> tuple[str, int]:
        if CAPTURE_ALLOWANCE.get() == "incident":
            return "application_group_capture_incident", 3
        return "application_group_capture", 1

    def capture_paused_application(
        self, application: str, operation_id: str, generation: int
    ) -> dict[str, Any]:
        """Capture under a pause; a failed attempt does not consume the success budget.

        Attempts stay bounded separately, so a persistent fault cannot cause an
        unbounded stop/start loop.
        """
        started = time.time()
        try:
            return self._capture_paused_application(application, operation_id, generation)
        except BaseException:
            action, _ = self._capture_budget()
            with self._db() as db:
                db.execute(
                    "DELETE FROM mutations WHERE target=? AND action=? AND ts>=?",
                    ("application-" + graph_identifier("a", application), action, started),
                )
            raise

    def _capture_paused_application(
        self, application: str, operation_id: str, generation: int
    ) -> dict[str, Any]:
        """Capture every registered data tree under one fully paused checkpoint.

        Internal foundation only: no public action, upload, retention or restore
        authority is granted by this local result. Container quiescence alone does
        not establish that unrelated host processes cannot write the data; the
        resulting record explicitly does not claim application consistency.
        Incomplete directories remain private until a future recovery policy.
        """
        from ..core.backupexport import owned_directory, sync_directory
        from ..core.backups import BackupError, private_json
        from ..core.config import Backup
        from ..core.data_ownership import inspect_data_ownership
        from ..core.filebackups import ARCHIVE_OVERHEAD_MAX, capture_files
        from ..core.group_backups import GroupCapture

        with self.target_lock("deployment-execution"):
            initial = self.group_checkpoint(application)
            if (
                initial is None
                or initial.operation_id != operation_id
                or type(generation) is not int
                or initial.generation != generation
            ):
                raise ExecutorError("conflict", "group checkpoint changed")
            if (
                initial.phase != "paused"
                or initial.plan.scope != "application"
                or initial.plan.data_contract_revision is None
            ):
                raise ExecutorError("policy_denied", "a fully paused application is required")
            with self.group_backup_locks(initial.plan):
                current = self.group_checkpoint(application)
                if current != initial or self.deployment_fence() is not None:
                    raise ExecutorError("conflict", "group or deployment state changed")
                registry = load_registry(self.registry_path)
                specs = registry["applications"][application]["services"]
                if set(specs) != set(current.plan.start_order):
                    raise ExecutorError("policy_denied", "application coverage changed")
                data_services = []
                for name in sorted(specs):
                    spec = specs[name]
                    source, target = spec.get("data_source"), spec.get("data_target")
                    if (source is None) != (target is None):
                        raise ExecutorError(
                            "policy_denied", "application data contract is incomplete"
                        )
                    if source is not None:
                        expected = APPLICATION_DATA_ROOT / application / "data" / name
                        if source != str(expected) or spec.get("allow_backup_pause") is not True:
                            raise ExecutorError(
                                "policy_denied", "application data capture is not authorized"
                            )
                        data_services.append(name)
                if not data_services:
                    raise ExecutorError("policy_denied", "application has no registered data")
                policy = Backup.model_validate(registry.get("backup", {}))
                maximum = policy.max_mib * 1024 * 1024
                deadline = time.monotonic() + 180

                def quiescent():
                    if time.monotonic() >= deadline or self.host.kill_switch():
                        return False
                    for name in current.plan.start_order:
                        spec = specs[name]
                        if not self.host.group_service_quiescent(
                            spec["user"], spec["unit"], spec["container"]
                        ) or not self.host.workload_quiescent(spec["user"], spec["unit"]):
                            return False
                    return True

                if self.host.kill_switch():
                    raise ExecutorError("kill_switch", "automatic application captures are stopped")
                if not quiescent():
                    raise ExecutorError("unavailable", "application writers are not quiescent")
                group_users = sorted({specs[name]["user"] for name in current.plan.start_order})
                if not self.host.group_users_within_systemd_slices(group_users):
                    raise ExecutorError("unavailable", "application user process scope is unknown")
                base = Path(self._db_path).parent
                try:
                    for directory in (
                        APPLICATION_DATA_ROOT.parent,
                        APPLICATION_DATA_ROOT,
                        APPLICATION_DATA_ROOT / application,
                        APPLICATION_DATA_ROOT / application / "data",
                    ):
                        owned_directory(directory)
                    owned_directory(base)
                    spool = base / "group-captures"
                    spool.mkdir(mode=0o700, exist_ok=True)
                    if owned_directory(spool).st_mode & 0o777 != 0o700:
                        raise BackupError("unsafe_spool")
                    spool = spool / application
                    spool.mkdir(mode=0o700, exist_ok=True)
                    if owned_directory(spool).st_mode & 0o777 != 0o700:
                        raise BackupError("unsafe_spool")
                    if backup_namespace_full(spool):
                        raise BackupError("retention_limit")
                    if (
                        shutil.disk_usage(spool).free
                        < maximum + len(data_services) * ARCHIVE_OVERHEAD_MAX + 512 * 1024 * 1024
                    ):
                        raise BackupError("insufficient_space")
                    target = "application-" + graph_identifier("a", application)
                    self.spend_budget(
                        target, "application_group_capture_attempt", CAPTURE_ATTEMPTS_PER_HOUR
                    )
                    budget_action, budget_limit = self._capture_budget()
                    self.spend_budget(target, budget_action, budget_limit)
                    artifact = uuid.uuid4().hex
                    destination = spool / artifact
                    destination.mkdir(mode=0o700)
                    sync_directory(spool)
                    self.audit.append(
                        "application_group_capture",
                        application=application,
                        operation_id=operation_id,
                        artifact=artifact,
                        outcome="started",
                    )
                    started = time.time()
                    total = 0
                    captures = {}
                    ownership = {}
                    for name in data_services:
                        spec = specs[name]
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or maximum - total < 1:
                            raise BackupError("limit_exceeded")
                        binding = Binding(
                            server=registry["server_name"],
                            project=graph_identifier("s", application, name),
                            config_revision=current.plan.config_revision,
                            image=spec["image"],
                            source_revision=spec["source_revision"],
                        )
                        uid = self.host.service_user_uid(spec["user"])
                        if uid is None:
                            raise BackupError("unsafe_owner")
                        source = APPLICATION_DATA_ROOT / application / "data" / name
                        ownership[name] = (
                            uid,
                            inspect_data_ownership(
                                source,
                                service_uid=uid,
                                max_bytes=maximum - total,
                                deadline=deadline,
                            ),
                        )
                        remaining = deadline - time.monotonic()
                        captures[name] = capture_files(
                            APPLICATION_DATA_ROOT / application / "data" / name,
                            destination / name,
                            binding,
                            max_bytes=maximum - total,
                            timeout_s=remaining,
                            is_quiescent=quiescent,
                        )
                        total += captures[name].data_bytes
                        sync_directory(destination / name)
                    for name in data_services:
                        uid, before = ownership[name]
                        if self.host.service_user_uid(specs[name]["user"]) != uid:
                            raise BackupError("unsafe_owner")
                        after = inspect_data_ownership(
                            APPLICATION_DATA_ROOT / application / "data" / name,
                            service_uid=uid,
                            max_bytes=maximum,
                            deadline=deadline,
                        )
                        if before != after:
                            raise BackupError("source_changed")
                    if (
                        not quiescent()
                        or not self.host.group_users_within_systemd_slices(group_users)
                        or self.group_checkpoint(application) != current
                    ):
                        raise BackupError("not_quiescent")
                    if (
                        load_registry(self.registry_path) != registry
                        or self.deployment_fence() is not None
                    ):
                        raise BackupError("evidence_mismatch")
                    result = GroupCapture(
                        application=application,
                        config_revision=current.plan.config_revision,
                        data_contract_revision=current.plan.data_contract_revision,
                        operation_id=operation_id,
                        checkpoint_generation=current.generation,
                        created_at=started,
                        completed_at=time.time(),
                        original_running=current.original_running,
                        data_services=data_services,
                        captures=captures,
                    )
                    private_json(destination / "manifest.json", result.model_dump(mode="json"))
                    sync_directory(destination)
                    self.audit.append(
                        "application_group_capture",
                        application=application,
                        operation_id=operation_id,
                        artifact=artifact,
                        outcome="complete",
                        capture_id=result.id,
                    )
                    return {
                        "artifact": artifact,
                        "capture_id": result.id,
                        "capture": result.model_dump(mode="json"),
                        "uploaded": False,
                    }
                except BackupError as exc:
                    self.audit.append(
                        "application_group_capture",
                        application=application,
                        operation_id=operation_id,
                        outcome="failed",
                        error_class=exc.error_class,
                    )
                    raise ExecutorError(
                        "execution_failed", "application capture failed: " + exc.error_class
                    ) from None
                except OSError as exc:
                    cause = io_cause(exc)
                    self.audit.append(
                        "application_group_capture",
                        application=application,
                        operation_id=operation_id,
                        outcome="failed",
                        error_class=cause,
                    )
                    raise ExecutorError(
                        "execution_failed", "application capture failed: " + cause
                    ) from None

    def verify_group_capture(
        self, application: str, artifact: str, capture_id: str
    ) -> dict[str, Any]:
        """Re-read an exact private group artifact; no backup authority is granted."""
        from ..core.backupexport import owned_directory
        from ..core.backups import BackupError
        from ..core.group_backups import load_group_capture

        if (
            not isinstance(application, str)
            or re.fullmatch(r"[a-z][a-z0-9-]{1,30}[a-z0-9]", application) is None
            or not isinstance(artifact, str)
            or re.fullmatch(r"[a-f0-9]{32}", artifact) is None
            or not isinstance(capture_id, str)
            or re.fullmatch(r"[a-f0-9]{64}", capture_id) is None
        ):
            raise ExecutorError("bad_request", "invalid group capture identity")
        with self.target_lock("application-" + graph_identifier("a", application)):
            try:
                base = Path(self._db_path).parent
                root = base / "group-captures"
                project = root / application
                for directory in (base, root, project):
                    owned_directory(directory)
                manifest = load_group_capture(project / artifact, expected_id=capture_id)
                if manifest.application != application:
                    raise BackupError("evidence_mismatch")
                return {
                    "artifact": artifact,
                    "capture_id": manifest.id,
                    "capture": manifest.model_dump(mode="json"),
                    "uploaded": False,
                }
            except BackupError as exc:
                raise ExecutorError(
                    "unavailable", "group capture verification failed: " + exc.error_class
                ) from None
            except OSError:
                raise ExecutorError("unavailable", "group capture verification failed") from None

    def spend_budget(self, target: str, action: str, per_hour: int) -> None:
        now = time.time()
        with self._db() as db:
            db.execute("DELETE FROM mutations WHERE ts < ?", (now - 3600,))
            used = db.execute(
                "SELECT COUNT(*) FROM mutations WHERE target=? AND action=?", (target, action)
            ).fetchone()[0]
            if used >= per_hour:
                raise ExecutorError("budget_exhausted", f"{action} budget for {target} is used up")
            db.execute("INSERT INTO mutations VALUES (?,?,?)", (target, action, now))


# ---- actions -----------------------------------------------------------------------


def _container_hardening(info: dict[str, Any] | None, spec: dict[str, Any]) -> dict[str, Any]:
    """Compare a running container against the isolation the contract demands."""
    if info is None:
        return {"inspected": False, "violations": ["container not found"]}
    host_config = info.get("HostConfig", {})
    checks = {
        "read_only_rootfs": host_config.get("ReadonlyRootfs") is True,
        "non_root_user": str(info.get("Config", {}).get("User", "")).split(":")[0]
        not in ("", "0", "root"),
        "no_new_privileges": "no-new-privileges" in (host_config.get("SecurityOpt") or []),
        "no_capabilities": not info.get("EffectiveCaps"),
        "not_privileged": host_config.get("Privileged") is False,
        "no_host_network": host_config.get("NetworkMode") != "host",
        "memory_limit": host_config.get("Memory") == spec["memory_mb"] * 2**20,
        "pids_limit": host_config.get("PidsLimit") == spec["pids"],
        "seccomp_default": not any(
            str(opt).startswith("seccomp=unconfined")
            for opt in host_config.get("SecurityOpt") or []
        ),
    }
    return {
        "inspected": True,
        "checks": checks,
        "apparmor_profile": info.get("AppArmorProfile") or None,
        "violations": sorted(name for name, ok in checks.items() if not ok),
    }


CAPTURE_ALLOWANCE: ContextVar[str | None] = ContextVar("capture_allowance", default=None)
CAPTURE_ATTEMPTS_PER_HOUR = 6


@contextmanager
def capture_allowance(kind: Literal["incident"]):
    """Internal only: the quarantine driver selects its own bounded capture allowance."""
    token = CAPTURE_ALLOWANCE.set(kind)
    try:
        yield
    finally:
        CAPTURE_ALLOWANCE.reset(token)


def message_cause(exc: ExecutorError) -> str | None:
    """The stable cause token after the last ': ' of an executor message, if any."""
    tail = exc.message.rpartition(": ")[2]
    return tail if re.fullmatch(r"[a-z_]{3,40}", tail) and ": " in exc.message else None


def io_cause(exc: OSError) -> str:
    """A stable, specific cause for a filesystem failure (never a path or message)."""
    import errno

    if exc.errno in (errno.EPERM, errno.EACCES, errno.EROFS):
        return "spool_unwritable"
    if exc.errno in (errno.ENOSPC, errno.EDQUOT):
        return "insufficient_space"
    return "io_error"


def backup_namespace_full(directory: Path) -> bool:
    """Count only far enough to establish the fixed ten-object bound."""
    with os.scandir(directory) as entries:
        for index, _ in enumerate(entries, 1):
            if index >= 10:
                return True
    return False


def backup_capacity(ex: Executor, registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Bounded root-side capacity observations; no paths or removal authority."""
    from ..core.backupexport import owned_directory
    from ..core.backups import BackupError
    from ..core.config import Backup
    from ..core.filebackups import ARCHIVE_OVERHEAD_MAX

    policy = Backup.model_validate(registry.get("backup", {}))
    if not policy.enabled:
        return {}
    capture_root = Path(ex._db_path).parent / "captures"
    required = policy.max_mib * 1024 * 1024 + ARCHIVE_OVERHEAD_MAX + 512 * 1024 * 1024

    def inspect(root, project, *, imported):
        if os.path.lexists(root):
            root_info = owned_directory(root)
            if imported and (
                root_info.st_gid != ex.host.backup_group() or root_info.st_mode & 0o777 != 0o750
            ):
                raise BackupError("unsafe_spool")
            anchor = root
        else:
            anchor = root.parent
        directory = root / project
        count = 0
        if os.path.lexists(directory):
            info = owned_directory(directory)
            if info.st_mode & 0o777 != (0o750 if imported else 0o700):
                raise BackupError("unsafe_spool")
            if imported and info.st_gid != ex.host.backup_group():
                raise BackupError("unsafe_spool")
            with os.scandir(directory) as entries:
                for _ in entries:
                    count += 1
                    if count == 10:
                        break
        return count, shutil.disk_usage(anchor).free

    results = {}
    for project, spec in registry["projects"].items():
        if not spec.get("has_data") or not spec.get("allow_backup_pause"):
            continue
        # The append-only uploader has no independent remote capacity probe.
        reasons = ["remote_unknown"]
        try:
            with ex._db() as db:
                count = db.execute(
                    "SELECT COUNT(*) FROM backup_upload_cancellations WHERE project=?", (project,)
                ).fetchone()[0]
            if count >= MAX_CANCELLED_UPLOADS:
                reasons.append("cancellation_limit")
        except sqlite3.Error:
            reasons.append("cancellation_unknown")
        try:
            count, free = inspect(capture_root, project, imported=False)
            if count >= 10:
                reasons.append("capture_limit")
            if free < required:
                reasons.append("capture_space")
        except (OSError, BackupError, KeyError):
            reasons.append("capture_unknown")
        try:
            count, free = inspect(BACKUP_IMPORT_ROOT, project, imported=True)
            if count >= 10:
                reasons.append("import_limit")
            if free < 512 * 1024 * 1024:
                reasons.append("import_space")
        except (OSError, BackupError, KeyError):
            reasons.append("import_unknown")
        results[project] = {"reasons": reasons}
    return results


def backup_schedule_observations(ex: Executor, registry: dict[str, Any]) -> dict[str, dict]:
    """Expose bounded root-owned schedule records without claiming upload success."""
    from ..core.config import Backup

    policy = Backup.model_validate(registry.get("backup", {}))
    if not policy.enabled:
        return {}
    projects = [
        project
        for project, spec in registry["projects"].items()
        if spec.get("has_data") and spec.get("allow_backup_pause")
    ]
    observations = {}
    try:
        with ex._db() as db:
            for project in projects:
                row = db.execute(
                    "SELECT body FROM backup_schedule WHERE project=?", (project,)
                ).fetchone()
                if row is None:
                    observations[project] = {"state": "missing", "interval_s": policy.interval_s}
                    continue
                try:
                    run = BackupScheduledRun.model_validate_json(row[0])
                except (ValueError, TypeError):
                    observations[project] = {"state": "invalid", "interval_s": policy.interval_s}
                    continue
                observations[project] = {
                    "state": run.phase,
                    "interval_s": policy.interval_s,
                    "config_revision": run.config_revision,
                    "schedule_started_at": run.created_at,
                    "capture_id": run.capture_id,
                    "capture_created_at": run.capture_created_at,
                    "provenance": "executor_schedule",
                }
    except sqlite3.Error:
        return {
            project: {"state": "unavailable", "interval_s": policy.interval_s}
            for project in projects
        }
    return observations


def application_group_status(
    ex: Executor, params: ApplicationGroupStatusParams, _role: str, _registry: dict[str, Any]
) -> dict[str, Any]:
    """Read the persisted group checkpoint under the deployment and application locks."""
    application = params.application
    target = "application-" + graph_identifier("a", application)

    def read_registry():
        try:
            return load_registry(ex.registry_path)
        except (ExecutorError, OSError, ValueError):
            raise ExecutorError("unavailable", "application registry is unavailable") from None

    with ex.target_lock("deployment-execution"), ex.target_lock(target):
        registry = read_registry()
        revision = registry.get("config_revision") if isinstance(registry, dict) else None
        if not isinstance(revision, str) or re.fullmatch(r"[a-f0-9]{64}", revision) is None:
            raise ExecutorError("unavailable", "application registry has an invalid revision")
        if revision != params.expected_revision:
            raise ExecutorError("conflict", "active configuration changed")
        applications = registry.get("applications", {})
        if not isinstance(applications, dict) or len(applications) > 16:
            raise ExecutorError("unavailable", "application registry is invalid")
        if application not in applications:
            raise ExecutorError("policy_denied", "application is not registered")
        registration = applications[application]
        if (
            not isinstance(registration, dict)
            or registration.get("lock") != target
            or registration.get("isolation") not in ("shared", "separate")
        ):
            raise ExecutorError("unavailable", "application registration identity is invalid")
        try:
            checkpoint = ex.group_checkpoint(application)
        except (ValueError, TypeError, sqlite3.Error):
            raise ExecutorError("unavailable", "application group checkpoint is invalid") from None
        if checkpoint is not None and checkpoint.phase not in ("complete", "recovered"):
            try:
                plan = GroupPlan.model_validate(rederive_checkpoint_plan(registry, checkpoint.plan))
            except (ValueError, KeyError, TypeError):
                raise ExecutorError("conflict", "application group contract changed") from None
            if plan != checkpoint.plan:
                raise ExecutorError("conflict", "application group contract changed")
        # The registry writer can replace the file without the executor locks.
        if read_registry() != registry:
            raise ExecutorError("conflict", "application registry changed during observation")
        if checkpoint is None:
            return {"state": "idle", "checkpoint": None}
        return {"state": checkpoint.phase, "checkpoint": checkpoint.model_dump(mode="json")}


def application_group_stop(
    ex: Executor, params: ApplicationGroupStopParams, _role: str, _registry: dict[str, Any]
) -> dict[str, Any]:
    """Pause a registered service and its transitive dependents."""
    if ex.host.kill_switch():
        raise ExecutorError("kill_switch", "application group operations are stopped")
    if not ex._operator_group_boot_ready():
        raise ExecutorError("unavailable", "application boot has not completed")
    previous = (
        (params.previous_operation_id, params.previous_generation)
        if params.previous_operation_id is not None and params.previous_generation is not None
        else None
    )
    with ex.group_driver_lock(params.application):
        with ex.observed_group_execution(
            params.application,
            params.service,
            expected_revision=params.expected_revision,
            operator_managed=True,
            previous=previous,
        ) as checkpoint:
            pass  # release the observation locks before the driver reacquires them
        result = ex._stop_group_with_recovery(
            params.application, checkpoint.operation_id, checkpoint.generation
        )
        return {**result, "checkpoint": result["checkpoint"].model_dump(mode="json")}


def application_group_resume(
    ex: Executor, params: ApplicationGroupResumeParams, _role: str, _registry: dict[str, Any]
) -> dict[str, Any]:
    """Restore the observed original state for an exact operator checkpoint."""
    if ex.host.kill_switch():
        raise ExecutorError("kill_switch", "application group operations are stopped")
    if not ex._operator_group_boot_ready():
        raise ExecutorError("unavailable", "application boot has not completed")
    application, operation_id = params.application, params.operation_id
    with ex.group_driver_lock(application):
        registry = load_registry(ex.registry_path)
        if registry.get("config_revision") != params.expected_revision:
            raise ExecutorError("conflict", "active configuration changed")
        checkpoint = ex.group_checkpoint(application)
        if (
            checkpoint is None
            or checkpoint.operation_id != operation_id
            or checkpoint.generation != params.generation
        ):
            raise ExecutorError("conflict", "group checkpoint changed")
        if not checkpoint.operator_managed:
            raise ExecutorError("policy_denied", "operator checkpoint is required")
        if checkpoint.phase == "stopping":
            checkpoint = ex.begin_group_recovery(application, operation_id, checkpoint.generation)
        elif checkpoint.phase == "paused":
            checkpoint = ex.resume_paused_group(application, operation_id, checkpoint.generation)
        for _ in range(len(checkpoint.plan.start_order) + 1):
            if checkpoint.phase in ("complete", "recovered"):
                break
            checkpoint = ex.reconcile_group_step(application, operation_id, checkpoint.generation)
        if checkpoint.phase not in ("complete", "recovered"):
            raise ExecutorError("internal", "group resume exceeded its step bound")
        return {"state": checkpoint.phase, "checkpoint": checkpoint.model_dump(mode="json")}


def probe_health(host, spec: dict[str, Any]) -> dict[str, Any]:
    """Run the registered probe kind; older registries without the field use http."""
    probe = spec.get("health_probe", "http")
    timeout = spec["health_timeout_s"]
    if probe == "tcp":
        result = host.tcp_health(spec["host_port"], timeout)
    elif probe == "container":
        result = host.container_health(spec["user"], spec["container"], timeout)
    else:
        result = host.http_health(spec["host_port"], spec["health_path"], timeout)
    return classify_health(result, spec.get("health_max_ms"))


def maintenance_status(ex: Executor, registry: dict[str, Any], now: float) -> dict[str, Any]:
    """Read-only maintenance view; older registries without a policy report unconfigured."""
    policy = registry.get("maintenance")
    if not isinstance(policy, dict):
        return {"configured": False}
    runs: list[dict[str, Any]] | None
    try:
        with ex.maintenance_store(create=False) as store:
            runs = MaintenanceRuns(store).history(10) if store is not None else []
    except Exception:  # noqa: BLE001 - unreadable records are reported as unknown
        runs = None
    summary = policy_summary(policy, now, runs)
    if policy.get("drills"):
        from .drills import drill_status

        try:
            summary["drill_state"] = drill_status(ex, None, "api", registry)
        except Exception:  # noqa: BLE001 - unreadable drill records are reported as unknown
            summary["drill_state"] = None
    if runs is None:
        summary["recent_runs_state"] = "unknown"
    return summary


PLANNED_RESTART_LOOKBACK = 200


def planned_backup_restarts(ex: Executor) -> dict[str, float]:
    """Projects whose workload was last restarted by an audited backup pause/capture.

    Derived only from the executor's own audit trail (`backup_resume` with outcome ok);
    callers cannot add entries. Lets the controller treat that restart as planned."""
    out: dict[str, float] = {}
    try:
        entries = ex.audit.read(PLANNED_RESTART_LOOKBACK)
    except (OSError, ValueError):
        return out
    for entry in entries:
        project, ts = entry.get("project_id"), entry.get("ts")
        if (
            entry.get("event") == "backup_resume"
            and entry.get("outcome") == "ok"
            and isinstance(project, str)
            and type(ts) in (int, float)
        ):
            out[project] = max(out.get(project, 0.0), float(ts))
    return out


def platform_status(ex: Executor, _params: NoParams, _role: str, registry: dict[str, Any]):
    host = ex.host
    projects = {}
    for project_id, spec in registry["projects"].items():
        unit = host.user_unit(spec["user"], spec["unit"])
        entry: dict[str, Any] = {
            "deploy": spec["deploy"],
            "unit": unit,
            "allow_restart": spec["allow_restart"],
            "health_retries": spec["health_retries"],
        }
        if spec["deploy"]:
            entry["health"] = probe_health(host, spec)
            entry["hardening"] = _container_hardening(
                host.container(spec["user"], spec["container"]), spec
            )
        projects[project_id] = entry
    schedule_observations = backup_schedule_observations(ex, registry)
    try:
        deployment_recovery = "pending" if ex.deployment_fence() is not None else "clear"
    except Exception:  # noqa: BLE001 - a broken fence must be reported as unknown
        deployment_recovery = "unknown"
    return {
        "checked_at": time.time(),
        "release": registry["release"],
        "config_revision": registry["config_revision"],
        "automation_profile": registry["automation_profile"],
        "reserved_memory_mb": registry["reserved_memory_mb"],
        "kill_switch": host.kill_switch(),
        "reboot_required": host.reboot_required(),
        "firewall": {
            "managed": registry["firewall_managed"],
            "loaded": host.firewall_loaded() if registry["firewall_managed"] else None,
        },
        "platform_units": [host.system_unit(u) for u in registry["platform_units"]],
        "proxy": host.user_unit(registry["proxy_user"], "proxy.service"),
        "failed_units": host.failed_units(),
        "resources": host.resources(),
        "projects": projects,
        "deployment_recovery": deployment_recovery,
        **({"containment_enabled": True} if containment.policy_enabled(registry) else {}),
        "backup_enabled": registry.get("backup", {}).get("enabled") is True,
        "backup_recovery": ex.backup_pause_summaries(),
        "backup_planned_restarts": planned_backup_restarts(ex),
        "backup_capacity": backup_capacity(ex, registry),
        "backup_schedule_observations": schedule_observations,
        "maintenance": maintenance_status(ex, registry, time.time()),
    }


def maintenance_admit(
    ex: Executor, params: MaintenanceAdmitParams, role: str, registry: dict[str, Any]
):
    """Admit, record and run one registered read-only maintenance check.

    Honours the kill switch for every role, never reboots (work kind is fixed to
    routine), runs only inside the regular window and at most once per window.
    """
    if ex.host.kill_switch():
        raise ExecutorError("kill_switch", "maintenance work is stopped")
    spec = WORK[params.work_id]
    with ex.target_lock("maintenance"):
        registry = load_registry(ex.registry_path)
        policy = registry.get("maintenance")
        if not isinstance(policy, dict):
            raise ExecutorError("policy_denied", "no maintenance policy is configured")
        with ex.maintenance_store() as store:
            runs = MaintenanceRuns(store)
            now = time.time()
            for job_id in runs.recover(now):
                interrupted = store.get_job(job_id) or {}
                ex.audit.append(
                    "maintenance_run",
                    work=(interrupted.get("payload") or {}).get("work"),
                    run_id=job_id,
                    outcome="failed",
                    cause="interrupted",
                )
            try:
                decision = runs.request(
                    policy["weekly_window"],
                    now,
                    work=params.work_id,
                    work_seconds=spec.work_seconds,
                    kind=spec.kind,
                    allow_reboot=False,
                    created_by=role,
                )
            except (KeyError, TypeError, ValueError):
                raise ExecutorError("policy_denied", "maintenance policy is not valid") from None
            admission = decision.admission
            if not decision.created or decision.job is None:
                return {
                    "admitted": False,
                    "reason": admission.reason,
                    "window": window_dict(admission.window),
                    "retry_at": admission.retry_at.isoformat() if admission.retry_at else None,
                }
            worker = f"executor-{os.getpid()}"
            job = runs.begin(worker, now)
            if job is None or job["id"] != decision.job["id"]:
                if job is not None:
                    runs.complete(
                        job["id"], worker, ok=False, now=time.time(), error="unexpected run"
                    )
                raise ExecutorError("internal", "maintenance run could not be started")
            payload = job["payload"]
            common = {
                "work": params.work_id,
                "run_id": job["id"],
                "window_start": payload["window_start"],
                "window_end": payload["window_end"],
            }
            ex.audit.append("maintenance_run", outcome="started", **common)
            try:
                result = resource_check(
                    ex.host.resources(), ex.host.load_average(), registry["reserved_memory_mb"]
                )
                error = None
            except Exception as exc:  # noqa: BLE001 - a failed check is recorded, not raised
                result, error = None, f"check failed: {type(exc).__name__}"
            state = runs.complete(
                job["id"], worker, ok=error is None, now=time.time(), result=result, error=error
            )
            if state is None:
                result, error, state = None, "lease lost before completion", "failed"
            outcome = "completed" if state == "succeeded" else "failed"
            ex.audit.append(
                "maintenance_run", outcome=outcome, **common, **({"cause": error} if error else {})
            )
            return {
                "admitted": True,
                "reason": admission.reason,
                "run_id": job["id"],
                "state": outcome,
                "window": window_dict(admission.window),
                "result": result,
                "error": error,
            }


def workload_restart(ex: Executor, params: RestartParams, role: str, registry: dict[str, Any]):
    # Serialize admission and the actual restart with group observation/steps.
    with ex.target_lock("deployment-execution"):
        if ex.deployment_fence() is not None:
            raise ExecutorError("target_busy", "deployment recovery is pending")
        registry = load_registry(ex.registry_path)
        spec = registry["projects"].get(params.project_id)
        if spec is None:
            raise ExecutorError("policy_denied", "project is not registered")
        if not spec["deploy"]:
            raise ExecutorError("policy_denied", "project is configured as stopped (deploy: false)")
        if not spec["allow_restart"] and role != "operator":
            raise ExecutorError("policy_denied", "no maintenance contract permits restarts")
        with ex.target_lock(f"project-{params.project_id}"):
            if ex.backup_pause(params.project_id) is not None:
                raise ExecutorError("unavailable", "backup pause recovery is pending")
            ex.ensure_group_restart_allowed(registry, spec)
            if role != "operator":
                ex.spend_budget(params.project_id, "workload_restart", RESTART_BUDGET_PER_HOUR)
            ok, detail = ex.host.restart_user_unit(spec["user"], spec["unit"])
            if not ok:
                raise ExecutorError("execution_failed", detail or "restart failed")
            return {
                "project_id": params.project_id,
                "unit": ex.host.user_unit(spec["user"], spec["unit"]),
            }


def firewall_reassert(ex: Executor, _params: NoParams, _role: str, registry: dict[str, Any]):
    with ex.target_lock("deployment-execution"), ex.target_lock("firewall"):
        if ex.deployment_fence() is not None:
            raise ExecutorError("target_busy", "deployment recovery is pending")
        if registry != load_registry(ex.registry_path):
            raise ExecutorError("conflict", "firewall registry changed before reassertion")
        if not registry["firewall_managed"]:
            raise ExecutorError("policy_denied", "firewall is not managed by steward")
        ex.spend_budget("firewall", "firewall_reassert", RESTART_BUDGET_PER_HOUR)
        ok, detail = ex.host.firewall_reassert()
        if not ok or not ex.host.firewall_loaded():
            raise ExecutorError("execution_failed", detail or "ruleset did not load")
        return {"loaded": True}


def backup_capture(
    ex: Executor,
    params: BackupCaptureParams,
    _role: str,
    registry: dict[str, Any],
    *,
    _locked: bool = False,
    _artifact: str | None = None,
    _max_bytes: int | None = None,
    _before_capture: Callable[[], None] | None = None,
):
    """Capture registered project data under the same lock as workload restart."""
    from ..core.backups import BackupError, Binding
    from ..core.config import Backup
    from ..core.filebackups import ARCHIVE_OVERHEAD_MAX, capture_files

    spec = registry["projects"].get(params.project_id)
    if _max_bytes is None:
        _max_bytes = Backup.model_validate(registry.get("backup", {})).max_mib * 1024 * 1024
    if not spec or not spec.get("has_data") or not spec.get("allow_backup_pause"):
        raise ExecutorError(
            "policy_denied", "data capture requires an explicit backup pause contract"
        )
    binding = Binding(
        server=registry["server_name"],
        project=params.project_id,
        config_revision=registry["config_revision"],
        image=spec["image"],
        source_revision=spec["source_revision"],
    )
    with ex.backup_mutation_lock(params.project_id, registry, locked=_locked):
        if ex.backup_pause(params.project_id) is not None:
            raise ExecutorError("unavailable", "backup pause recovery is pending")
        with ex._db() as db:
            retiring = db.execute(
                "SELECT 1 FROM backup_retirement_intents WHERE project=? "
                "UNION ALL SELECT 1 FROM backup_import_retirement_intents WHERE project=? LIMIT 1",
                (params.project_id, params.project_id),
            ).fetchone()
        if retiring:
            raise ExecutorError("unavailable", "project has a pending backup retirement")
        # Retain bounded private artifacts until a later upload/retention workflow
        # can prove which captures may be removed. Never delete recovery points here.
        spool = Path(ex._db_path).parent / "captures" / params.project_id
        spool.mkdir(mode=0o700, parents=True, exist_ok=True)
        if backup_namespace_full(spool):
            ex.audit.append(
                "backup_capacity", project_id=params.project_id, namespace="capture", reason="limit"
            )
            raise ExecutorError(
                "unavailable",
                "the capture spool of this project holds 10 artifacts; export and retire old "
                "captures (steward-host backup-export, backup-retention-purge; see "
                "docs/operations.md, 'Capture spool limit') and retry",
            )
        if shutil.disk_usage(spool).free < _max_bytes + ARCHIVE_OVERHEAD_MAX + 512 * 1024 * 1024:
            ex.audit.append(
                "backup_capacity", project_id=params.project_id, namespace="capture", reason="space"
            )
            raise ExecutorError(
                "unavailable", "capture needs source/metadata capacity plus 512 MiB reserve"
            )
        state = ex.host.user_unit(spec["user"], spec["unit"])
        if state["load"] != "loaded" or state["active"] not in ("active", "inactive", "failed"):
            raise ExecutorError("unavailable", "workload state is not known")
        was_active = state["active"] == "active"
        if was_active and not spec["deploy"]:
            raise ExecutorError(
                "policy_denied", "stop the workload configured as stopped before capture"
            )
        if _role != "operator" and ex.host.kill_switch():
            raise ExecutorError("kill_switch", "automatic captures are stopped")
        artifact = _artifact or uuid.uuid4().hex
        if _before_capture is not None:
            _before_capture()
        if was_active:
            ex.save_backup_pause(
                BackupPause(
                    binding=binding,
                    user=spec["user"],
                    unit=spec["unit"],
                    artifact=artifact,
                    prepared_at=time.time(),
                )
            )
            ex.audit.append(
                "backup_pause",
                project_id=params.project_id,
                artifact=artifact,
                outcome="prepared",
                automatic=_role != "operator",
            )
        try:
            if was_active and not ex.host.set_user_unit(spec["user"], spec["unit"], running=False):
                raise ExecutorError("execution_failed", "workload stop failed")
            manifest = capture_files(
                PROJECT_DATA_ROOT / params.project_id / "data",
                spool / artifact,
                binding,
                max_bytes=_max_bytes,
                is_quiescent=lambda: ex.host.workload_quiescent(spec["user"], spec["unit"]),
            )
        except BackupError as exc:
            raise ExecutorError("execution_failed", "capture failed: " + exc.error_class) from None
        finally:
            if was_active:
                intent = ex.backup_pause(params.project_id)
                if intent is None or not pause_contract_matches(
                    intent, load_registry(ex.registry_path)
                ):
                    ex.record_backup_pause_failure(params.project_id, "policy_denied")
                    raise ExecutorError(
                        "policy_denied", "backup pause contract changed; recovery is pending"
                    )
                resumed = ex.host.set_user_unit(spec["user"], spec["unit"], running=True)
                state = ex.host.user_unit(spec["user"], spec["unit"])
                if not resumed or state["active"] != "active":
                    ex.record_backup_pause_failure(params.project_id, "execution_failed")
                    raise ExecutorError(
                        "execution_failed", "workload resume failed; inspect retained capture state"
                    )
                ex.audit.append(
                    "backup_resume",
                    project_id=params.project_id,
                    artifact=artifact,
                    automatic=_role != "operator",
                    outcome="ok",
                )
                ex.clear_backup_pause(params.project_id)
        return {
            "project_id": params.project_id,
            "artifact": artifact,
            "capture_id": manifest.id,
            "capture": manifest.model_dump(mode="json"),
            "resumed": was_active,
            "uploaded": False,
            "authority": "root-owned executor spool; manifest origin alone grants no authority",
        }


def proxy_restart(ex: Executor, _params: NoParams, role: str, registry: dict[str, Any]):
    with ex.target_lock("deployment-execution"):
        if ex.deployment_fence() is not None:
            raise ExecutorError("target_busy", "deployment recovery is pending")
        registry = load_registry(ex.registry_path)
        with ex.target_lock("proxy"):
            if role != "operator":
                ex.spend_budget("proxy", "proxy_restart", RESTART_BUDGET_PER_HOUR)
            ok, detail = ex.host.restart_user_unit(registry["proxy_user"], "proxy.service")
            if not ok:
                raise ExecutorError("execution_failed", detail or "restart failed")
            return {"unit": ex.host.user_unit(registry["proxy_user"], "proxy.service")}


def backup_recover(ex: Executor, params: BackupRecoverParams, _role: str, registry: dict):
    try:
        return ex.recover_backup_pause(
            params.project_id, registry, automatic=False, accept_current=params.accept_current
        )
    except ExecutorError as exc:
        ex.record_backup_pause_failure(params.project_id, exc.error_class)
        raise


def backup_export(
    ex: Executor, params: BackupExportParams, _role: str, registry: dict, *, _locked=False
):
    from ..core.backupexport import export_capture, owned_directory
    from ..core.backups import BackupError

    if params.project_id not in registry["projects"]:
        raise ExecutorError("policy_denied", "project is not registered")
    with nullcontext() if _locked else ex.target_lock(f"project-{params.project_id}"):
        if ex.backup_pause(params.project_id) is not None:
            raise ExecutorError("unavailable", "backup pause recovery is pending")
        source = Path(ex._db_path).parent / "captures" / params.project_id / params.artifact
        with ex._db() as db:
            retiring = db.execute(
                "SELECT 1 FROM backup_retirement_intents WHERE project=? "
                "UNION ALL SELECT 1 FROM backup_import_retirement_intents WHERE project=? LIMIT 1",
                (params.project_id, params.project_id),
            ).fetchone()
        if retiring:
            raise ExecutorError("unavailable", "project has a pending backup retirement")
        with ex._db() as db:
            cancelled = db.execute(
                "SELECT 1 FROM backup_upload_cancellations WHERE project=? "
                "AND (artifact=? OR capture_id=?)",
                (params.project_id, params.artifact, params.capture_id),
            ).fetchone()
        if cancelled:
            raise ExecutorError(
                "policy_denied", "cancelled upload must be reinstated before export"
            )
        try:
            gid = ex.host.backup_group()
            root_info = owned_directory(BACKUP_IMPORT_ROOT)
            if root_info.st_gid != gid or root_info.st_mode & 0o777 != 0o750:
                raise BackupError("unsafe_spool")
            project = BACKUP_IMPORT_ROOT / params.project_id
            if not os.path.lexists(project):
                project.mkdir(mode=0o750)
                os.chown(project, -1, gid)
            info = owned_directory(project)
            if info.st_gid == gid and info.st_mode & 0o777 == 0o700:
                # Executor UMask=0077 also applies to mkdir(mode=0750).
                # Repair only the safe root-private intermediate permission.
                project.chmod(0o750)
                info = project.lstat()
            if info.st_gid != gid or info.st_mode & 0o777 != 0o750:
                raise BackupError("unsafe_spool")
            destination = project / params.artifact
            if not os.path.lexists(destination) and backup_namespace_full(project):
                raise BackupError("retention_limit")

            def protect_upload(manifest):
                if manifest.binding.project != params.project_id:
                    raise BackupError("evidence_mismatch")
                binding = (manifest.id, manifest.binding.config_revision, manifest.created_at)
                with ex._db() as db:
                    existing = db.execute(
                        "SELECT capture_id, config_revision, capture_created_at "
                        "FROM backup_upload_protection WHERE project=? AND artifact=?",
                        (params.project_id, params.artifact),
                    ).fetchone()
                    if existing is not None and tuple(existing) != binding:
                        raise BackupError("evidence_mismatch")
                    if existing is None:
                        db.execute(
                            "INSERT INTO backup_upload_protection "
                            "(project, artifact, capture_id, config_revision, "
                            "capture_created_at, registered_at) VALUES (?, ?, ?, ?, ?, ?)",
                            (params.project_id, params.artifact, *binding, time.time()),
                        )

            manifest = export_capture(
                source,
                destination,
                capture_id=params.capture_id,
                gid=gid,
                before_publish=protect_upload,
            )
        except (BackupError, OSError, KeyError) as exc:
            reason = exc.error_class if isinstance(exc, BackupError) else "unavailable"
            if reason in ("retention_limit", "insufficient_space"):
                ex.audit.append(
                    "backup_capacity",
                    project_id=params.project_id,
                    namespace="import",
                    reason="limit" if reason == "retention_limit" else "space",
                )
            raise ExecutorError("execution_failed", "capture export failed: " + reason) from None
        return {
            "project_id": params.project_id,
            "artifact": params.artifact,
            "capture_id": manifest.id,
            "import_dir": str(destination),
            "uploaded": False,
        }


def backup_upload_permit(ex: Executor, params: BackupExportParams, _role: str, registry: dict):
    """Read-only root decision for one pre-registered managed upload."""
    from ..core.config import Backup

    policy = Backup.model_validate(registry.get("backup", {}))
    project = registry["projects"].get(params.project_id)
    if (
        not policy.enabled
        or not project
        or not project.get("has_data")
        or not project.get("allow_backup_pause")
    ):
        return {"permitted": False, "reason": "unavailable"}
    with ex._db() as db:
        registration = db.execute(
            "SELECT capture_id FROM backup_upload_protection WHERE project=? AND artifact=?",
            (params.project_id, params.artifact),
        ).fetchone()
        cancellation = db.execute(
            "SELECT capture_id FROM backup_upload_cancellations WHERE project=? AND artifact=?",
            (params.project_id, params.artifact),
        ).fetchone()
        retiring = db.execute(
            "SELECT 1 FROM backup_retirement_intents WHERE project=? "
            "UNION ALL SELECT 1 FROM backup_import_retirement_intents WHERE project=? LIMIT 1",
            (params.project_id, params.project_id),
        ).fetchone()
    if retiring:
        return {"permitted": False, "reason": "unavailable"}
    if cancellation:
        # The tombstone remains authoritative after the import is retired.
        return {
            "permitted": False,
            "reason": "cancelled" if cancellation[0] == params.capture_id else "unavailable",
        }
    if not registration or registration[0] != params.capture_id:
        return {"permitted": False, "reason": "unavailable"}
    return {"permitted": True, "reason": "registered"}


def backup_lock_cleanup_permit(ex: Executor, params: BackupExportParams, role: str, registry: dict):
    """Fence automatic repository lock recovery with current root policy."""
    if ex.host.kill_switch():
        return {"permitted": False, "reason": "unavailable"}
    return backup_upload_permit(ex, params, role, registry)


def backup_retention_hint(ex: Executor, params: BackupExportParams, _role: str, registry: dict):
    """Accept a bounded wakeup, never upload evidence or deletion authority."""
    from ..core.config import Backup

    project = registry["projects"].get(params.project_id)
    if not Backup.model_validate(registry.get("backup", {})).enabled or not project:
        return {"accepted": True}
    with ex._db() as db:
        registered = db.execute(
            "SELECT 1 FROM backup_upload_protection WHERE project=? "
            "AND artifact=? AND capture_id=?",
            (params.project_id, params.artifact, params.capture_id),
        ).fetchone()
        cancelled = db.execute(
            "SELECT 1 FROM backup_upload_cancellations WHERE project=? "
            "AND artifact=? AND capture_id=?",
            (params.project_id, params.artifact, params.capture_id),
        ).fetchone()
    if (
        registered
        and not cancelled
        and project.get("has_data")
        and project.get("allow_backup_pause")
    ):
        ex.hint_retention()
    # Stale, cancelled and coalesced hints are safely acknowledged as no-ops.
    return {"accepted": True}


def backup_worker_capacity_report(ex: Executor, _params: NoParams, _role: str, registry: dict):
    """Record a rate-limited worker claim, without granting mutation authority."""
    from ..core.config import Backup

    if Backup.model_validate(registry.get("backup", {})).enabled:
        ex.report_worker_capacity()
    return {"accepted": True}


def backup_upload_cancellation(
    ex: Executor, params: BackupExportParams, _role: str, registry: dict, *, cancel: bool
):
    """Change only a root-owned cancellation record while the service is stopped."""
    from ..core.backupexport import acl_attributes, owned_directory, protected_capture
    from ..core.backups import BackupError

    if params.project_id not in registry["projects"]:
        raise ExecutorError("policy_denied", "project is not registered")
    with ex.target_lock(f"project-{params.project_id}"):
        if not ex.host.backup_worker_stopped():
            raise ExecutorError("policy_denied", "backup service is not confirmed stopped")
        with ex._db() as db:
            if db.execute(
                "SELECT 1 FROM backup_import_retirement_intents WHERE project=?",
                (params.project_id,),
            ).fetchone():
                raise ExecutorError("policy_denied", "project has a pending import retirement")
        try:
            gid = ex.host.backup_group()
            root_info = owned_directory(BACKUP_IMPORT_ROOT)
            project = BACKUP_IMPORT_ROOT / params.project_id
            project_info = owned_directory(project)
            if (
                root_info.st_gid != gid
                or root_info.st_mode & 0o777 != 0o750
                or project_info.st_gid != gid
                or project_info.st_mode & 0o777 != 0o750
                or acl_attributes(BACKUP_IMPORT_ROOT)
                or acl_attributes(project)
            ):
                raise BackupError("unsafe_spool")
            path = project / params.artifact
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise ExecutorError("target_busy", "backup import is in use") from None
                opened, current = os.fstat(fd), path.lstat()
                if (
                    opened.st_uid != os.geteuid()
                    or opened.st_gid != gid
                    or opened.st_mode & 0o777 != 0o550
                    or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
                    or acl_attributes(path)
                    or not ex.host.backup_worker_stopped()
                ):
                    raise BackupError("unsafe_spool")
                manifest = protected_capture(path)
                for name in ("manifest.json", manifest.filename):
                    info = (path / name).lstat()
                    if (
                        info.st_gid != gid
                        or info.st_mode & 0o777 != 0o440
                        or acl_attributes(path / name)
                    ):
                        raise BackupError("unsafe_spool")
                if (
                    manifest.id != params.capture_id
                    or manifest.binding.project != params.project_id
                ):
                    raise BackupError("evidence_mismatch")
                with ex._db() as db:
                    row = db.execute(
                        "SELECT capture_id, config_revision, capture_created_at "
                        "FROM backup_upload_protection WHERE project=? AND artifact=?",
                        (params.project_id, params.artifact),
                    ).fetchone()
                    if row != (manifest.id, manifest.binding.config_revision, manifest.created_at):
                        raise BackupError("evidence_mismatch")
                    previous = db.execute(
                        "SELECT capture_id FROM backup_upload_cancellations "
                        "WHERE project=? AND artifact=?",
                        (params.project_id, params.artifact),
                    ).fetchone()
                    if previous and previous[0] != params.capture_id:
                        raise BackupError("evidence_mismatch")
                    if cancel and not previous:
                        count = db.execute(
                            "SELECT COUNT(*) FROM backup_upload_cancellations WHERE project=?",
                            (params.project_id,),
                        ).fetchone()[0]
                        if count >= MAX_CANCELLED_UPLOADS:
                            raise BackupError("cancellation_limit")
                        db.execute(
                            "INSERT INTO backup_upload_cancellations VALUES (?, ?, ?, ?)",
                            (params.project_id, params.artifact, params.capture_id, time.time()),
                        )
                    if not cancel and previous:
                        db.execute(
                            "DELETE FROM backup_upload_cancellations "
                            "WHERE project=? AND artifact=? AND capture_id=?",
                            (params.project_id, params.artifact, params.capture_id),
                        )
            finally:
                os.close(fd)
        except (BackupError, OSError, ValueError, KeyError) as exc:
            if isinstance(exc, BackupError) and exc.error_class == "cancellation_limit":
                ex.audit.append(
                    "backup_capacity",
                    project_id=params.project_id,
                    namespace="metadata",
                    reason="limit",
                )
            raise ExecutorError(
                "unavailable", "backup cancellation state could not be verified"
            ) from None
    return {
        "project_id": params.project_id,
        "artifact": params.artifact,
        "capture_id": params.capture_id,
        "cancelled": cancel,
        "deleted": False,
        "cleanup_authorized": False,
    }


def backup_upload_cancel(ex: Executor, params: BackupUploadCancelParams, role: str, registry: dict):
    return backup_upload_cancellation(ex, params, role, registry, cancel=True)


def backup_upload_reinstate(ex: Executor, params: BackupExportParams, role: str, registry: dict):
    return backup_upload_cancellation(ex, params, role, registry, cancel=False)


def backup_cancellation_forget(
    ex: Executor, params: BackupCancellationForgetParams, _role: str, registry: dict
):
    """Forget only an explicitly reconciled, unreferenced root cancellation."""
    from ..core.backupexport import acl_attributes, owned_directory
    from ..core.backupretention import inspect_namespace
    from ..core.backups import BackupError

    if params.project_id not in registry["projects"]:
        raise ExecutorError("policy_denied", "project is not registered")
    with ex.target_lock(f"project-{params.project_id}"):
        if not ex.host.backup_worker_stopped():
            raise ExecutorError("policy_denied", "backup service is not confirmed stopped")
        with ex._db() as db:
            cancellation = db.execute(
                "SELECT capture_id FROM backup_upload_cancellations WHERE project=? AND artifact=?",
                (params.project_id, params.artifact),
            ).fetchone()
            if not cancellation:
                return {
                    "project_id": params.project_id,
                    "artifact": params.artifact,
                    "forgotten": False,
                }
            if cancellation[0] != params.capture_id:
                raise ExecutorError("policy_denied", "cancellation identity does not match")
            if db.execute(
                "SELECT 1 FROM backup_upload_protection WHERE project=? "
                "AND (artifact=? OR capture_id=?)",
                (params.project_id, params.artifact, params.capture_id),
            ).fetchone():
                raise ExecutorError("policy_denied", "upload registration remains protected")
            if db.execute(
                "SELECT 1 FROM backup_retirement_intents WHERE project=? "
                "UNION ALL SELECT 1 FROM backup_import_retirement_intents WHERE project=? LIMIT 1",
                (params.project_id, params.project_id),
            ).fetchone():
                raise ExecutorError("policy_denied", "project has a pending backup retirement")
            if db.execute(
                "SELECT 1 FROM backup_removal_ack WHERE project=? AND (artifact=? OR capture_id=?)",
                (params.project_id, params.artifact, params.capture_id),
            ).fetchone():
                raise ExecutorError("policy_denied", "capture acknowledgement remains")
            scheduled = db.execute(
                "SELECT body FROM backup_schedule WHERE project=?", (params.project_id,)
            ).fetchone()
        if ex.backup_pause(params.project_id) is not None:
            raise ExecutorError("policy_denied", "backup pause recovery is pending")
        if scheduled:
            run = BackupScheduledRun.model_validate_json(scheduled[0])
            if run.artifact == params.artifact or run.capture_id == params.capture_id:
                raise ExecutorError("policy_denied", "scheduled capture remains")
        try:
            roots = [(Path(ex._db_path).parent / "captures", False), (BACKUP_IMPORT_ROOT, True)]
            for root, imported in roots:
                if not os.path.lexists(root):
                    continue
                info = owned_directory(root)
                gid = ex.host.backup_group() if imported else None
                if acl_attributes(root) or (
                    imported and (info.st_gid != gid or info.st_mode & 0o777 != 0o750)
                ):
                    raise BackupError("unsafe_spool")
                listing = inspect_namespace(
                    root / params.project_id, params.project_id, imported=imported, group_id=gid
                )
                if (
                    listing["truncated"]
                    or listing["unknown"]
                    or any(
                        item["state"] != "metadata_only"
                        or item["artifact"] == params.artifact
                        or item["capture_id"] == params.capture_id
                        for item in listing["items"]
                    )
                ):
                    raise BackupError("ambiguous_retirement")
            if not ex.host.backup_worker_stopped():
                raise BackupError("unsafe_spool")
            with ex._db() as db:
                removed = (
                    db.execute(
                        "DELETE FROM backup_upload_cancellations WHERE project=? "
                        "AND artifact=? AND capture_id=?",
                        (params.project_id, params.artifact, params.capture_id),
                    ).rowcount
                    == 1
                )
            return {
                "project_id": params.project_id,
                "artifact": params.artifact,
                "forgotten": removed,
            }
        except (BackupError, OSError, ValueError, KeyError):
            raise ExecutorError(
                "unavailable", "cancellation could not be reconciled safely"
            ) from None


def backup_import_purge(
    ex: Executor, params: BackupImportRetireParams, role: str, registry: dict, *, _resume_only=False
):
    """Retire one cancelled import while retaining its verified root capture."""
    from ..core.backupexport import acl_attributes, owned_directory, protected_capture
    from ..core.backupretention import RetentionItem, classify, inspect_namespace
    from ..core.backupretire import RetirementIntent, retire_capture
    from ..core.backups import BackupError

    if params.project_id not in registry["projects"]:
        raise ExecutorError("policy_denied", "project is not registered")
    captures = Path(ex._db_path).parent / "captures"
    spool = captures / params.project_id
    project = BACKUP_IMPORT_ROOT / params.project_id
    with ex.target_lock(f"project-{params.project_id}"):
        if role != "operator" and ex.host.kill_switch():
            raise ExecutorError("kill_switch", "automatic import retirement is stopped")
        if not ex.host.backup_worker_stopped():
            raise ExecutorError("policy_denied", "backup service is not confirmed stopped")
        with ex._db() as db:
            if db.execute(
                "SELECT 1 FROM backup_retirement_intents WHERE project=?", (params.project_id,)
            ).fetchone():
                raise ExecutorError("policy_denied", "project has a pending capture retirement")
            saved = db.execute(
                "SELECT body FROM backup_import_retirement_intents WHERE project=?",
                (params.project_id,),
            ).fetchone()
            pending = db.execute(
                "SELECT capture_id, config_revision, capture_created_at "
                "FROM backup_upload_protection "
                "WHERE project=? AND artifact=?",
                (params.project_id, params.artifact),
            ).fetchone()
            cancellation = db.execute(
                "SELECT capture_id FROM backup_upload_cancellations WHERE project=? AND artifact=?",
                (params.project_id, params.artifact),
            ).fetchone()
            scheduled = db.execute(
                "SELECT body FROM backup_schedule WHERE project=?", (params.project_id,)
            ).fetchone()
        if _resume_only and not saved:
            return {
                "project_id": params.project_id,
                "artifact": params.artifact,
                "outcome": "already_resolved",
            }
        if (
            not pending
            or not cancellation
            or pending[0] != params.capture_id
            or cancellation[0] != params.capture_id
        ):
            raise ExecutorError("policy_denied", "exact cancelled upload registration required")
        pause = ex.backup_pause(params.project_id)
        if (pause and pause.artifact == params.artifact) or (
            scheduled
            and BackupScheduledRun.model_validate_json(scheduled[0]).artifact == params.artifact
        ):
            raise ExecutorError("policy_denied", "capture is needed by an active schedule or pause")
        try:
            owned_directory(captures)
            owned_directory(spool)
            source = protected_capture(spool / params.artifact)
            if source.binding.project != params.project_id or (
                source.id,
                source.binding.config_revision,
                source.created_at,
            ) != tuple(pending):
                raise BackupError("evidence_mismatch")
            gid = ex.host.backup_group()
            root_info, project_info = owned_directory(BACKUP_IMPORT_ROOT), owned_directory(project)
            if (
                root_info.st_gid != gid
                or root_info.st_mode & 0o777 != 0o750
                or project_info.st_gid != gid
                or project_info.st_mode & 0o777 != 0o750
                or acl_attributes(BACKUP_IMPORT_ROOT)
                or acl_attributes(project)
            ):
                raise BackupError("unsafe_spool")
            if saved:
                intent = RetirementIntent.model_validate_json(saved[0])
                if intent.namespace != "import" or (intent.artifact, intent.capture_id) != (
                    params.artifact,
                    params.capture_id,
                ):
                    raise ExecutorError("policy_denied", "another import retirement is pending")
            else:
                listing = inspect_namespace(spool, params.project_id, imported=False)
                if listing["truncated"] or listing["unknown"]:
                    raise BackupError("ambiguous_retirement")
                items = []
                for item in listing["items"]:
                    if item["state"] != "metadata_only":
                        raise BackupError("ambiguous_retirement")
                    manifest = protected_capture(spool / item["artifact"])
                    if (
                        manifest.binding.project != params.project_id
                        or manifest.id != item["capture_id"]
                    ):
                        raise BackupError("evidence_mismatch")
                    items.append(
                        RetentionItem(
                            artifact=item["artifact"],
                            capture_id=manifest.id,
                            created_at=manifest.created_at,
                            complete=True,
                            operator_acknowledged=item["artifact"] == params.artifact,
                        )
                    )
                if not any(
                    item.artifact == params.artifact and item.eligible
                    for item in classify(items, now=time.time())
                ):
                    raise ExecutorError("policy_denied", "capture is protected by retention policy")
                path = project / params.artifact
                manifest = protected_capture(path)
                info = path.lstat()
                if (
                    manifest.id != source.id
                    or info.st_gid != gid
                    or info.st_mode & 0o777 != 0o550
                    or acl_attributes(path)
                ):
                    raise BackupError("unsafe_spool")
                data, manifest_file = (
                    (path / manifest.filename).lstat(),
                    (path / "manifest.json").lstat(),
                )
                for name, entry in ((manifest.filename, data), ("manifest.json", manifest_file)):
                    if (
                        entry.st_gid != gid
                        or entry.st_mode & 0o777 != 0o440
                        or acl_attributes(path / name)
                    ):
                        raise BackupError("unsafe_spool")
                intent = RetirementIntent(
                    namespace="import",
                    artifact=params.artifact,
                    capture_id=params.capture_id,
                    data_name=manifest.filename,
                    directory_device=info.st_dev,
                    directory_inode=info.st_ino,
                    data_device=data.st_dev,
                    data_inode=data.st_ino,
                    manifest_device=manifest_file.st_dev,
                    manifest_inode=manifest_file.st_ino,
                )
            # Root-controlled directory inode is the same lock observed by the managed worker.
            original, hidden = project / params.artifact, project / (".retiring-" + params.artifact)
            chosen = original if os.path.lexists(original) else hidden
            fd = None
            try:
                if os.path.lexists(chosen):
                    fd = os.open(chosen, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        raise ExecutorError("target_busy", "backup import is in use") from None
                    info = os.fstat(fd)
                    if (info.st_dev, info.st_ino) != (
                        intent.directory_device,
                        intent.directory_inode,
                    ):
                        raise BackupError("unsafe_spool")
                if not ex.host.backup_worker_stopped():
                    raise ExecutorError("policy_denied", "backup service is not confirmed stopped")
                if not saved:
                    with ex._db() as db:
                        db.execute(
                            "INSERT INTO backup_import_retirement_intents VALUES (?, ?)",
                            (params.project_id, intent.model_dump_json()),
                        )
                outcome = retire_capture(project, intent, import_gid=gid)
                with ex._db() as db:
                    db.execute(
                        "DELETE FROM backup_upload_protection WHERE project=? "
                        "AND artifact=? AND capture_id=?",
                        (params.project_id, params.artifact, params.capture_id),
                    )
                    db.execute(
                        "DELETE FROM backup_import_retirement_intents WHERE project=?",
                        (params.project_id,),
                    )
                return {
                    "project_id": params.project_id,
                    "artifact": params.artifact,
                    "outcome": outcome,
                }
            finally:
                if fd is not None:
                    os.close(fd)
        except ExecutorError:
            raise
        except (BackupError, OSError, ValueError, KeyError):
            raise ExecutorError("unavailable", "import retirement refused or interrupted") from None


def backup_retention_status(ex: Executor, params: BackupCaptureParams, _role: str, registry: dict):
    """Inspect root-owned project metadata without granting cleanup authority."""
    from ..core.backupexport import owned_directory
    from ..core.backupretention import inspect_namespace
    from ..core.backups import BackupError

    if params.project_id not in registry["projects"]:
        raise ExecutorError("policy_denied", "project is not registered")
    captures = Path(ex._db_path).parent / "captures"
    with ex.target_lock(f"project-{params.project_id}"):
        try:
            if os.path.lexists(captures):
                owned_directory(captures)
            spool = inspect_namespace(
                captures / params.project_id, params.project_id, imported=False
            )
            if os.path.lexists(BACKUP_IMPORT_ROOT):
                root_info = owned_directory(BACKUP_IMPORT_ROOT)
                group_id = ex.host.backup_group()
                if root_info.st_gid != group_id or root_info.st_mode & 0o777 != 0o750:
                    raise BackupError("unsafe_spool")
                imports = inspect_namespace(
                    BACKUP_IMPORT_ROOT / params.project_id,
                    params.project_id,
                    imported=True,
                    group_id=group_id,
                )
            else:
                imports = {"items": [], "unknown": 0, "truncated": False, "at_capacity": False}
        except (BackupError, OSError, ValueError):
            raise ExecutorError("unavailable", "backup retention metadata unavailable") from None
        with ex._db() as db:
            acknowledgements = {
                (row[0], row[1]): row[2]
                for row in db.execute(
                    "SELECT artifact, capture_id, acknowledged_at "
                    "FROM backup_removal_ack WHERE project=?",
                    (params.project_id,),
                )
            }
            pending = {
                (row[0], row[1])
                for row in db.execute(
                    "SELECT artifact, capture_id FROM backup_upload_protection WHERE project=?",
                    (params.project_id,),
                )
            }
            cancellation_rows = db.execute(
                "SELECT artifact, capture_id FROM backup_upload_cancellations "
                "WHERE project=? ORDER BY artifact LIMIT ?",
                (params.project_id, MAX_CANCELLED_UPLOADS + 1),
            ).fetchall()
        cancellation_records = []
        incomplete = len(cancellation_rows) > MAX_CANCELLED_UPLOADS
        for artifact, capture_id in cancellation_rows[:MAX_CANCELLED_UPLOADS]:
            try:
                checked = BackupExportParams(
                    project_id=params.project_id, artifact=artifact, capture_id=capture_id
                )
            except ValueError:
                incomplete = True
                continue
            cancellation_records.append(
                {"artifact": checked.artifact, "capture_id": checked.capture_id}
            )
        cancelled = {(item["artifact"], item["capture_id"]) for item in cancellation_records}
        for namespace in (spool, imports):
            for item in namespace["items"]:
                key = (item["artifact"], item.get("capture_id"))
                item["upload_protection"] = (
                    "cancelled" if key in cancelled else "pending" if key in pending else "unknown"
                )
                if namespace is spool and key in acknowledgements:
                    item["removal_acknowledged_at"] = acknowledgements[key]
        return {
            "project_id": params.project_id,
            "captures": spool,
            "imports": imports,
            "cancellation_records": cancellation_records,
            "cancellation_records_incomplete": incomplete,
        }


def backup_retention_ack(
    ex: Executor, params: BackupRetentionAckParams, _role: str, registry: dict
):
    """Record an operator acknowledgement for one independently validated capture."""
    from ..core.backupexport import owned_directory, protected_capture
    from ..core.backups import BackupError

    if params.project_id not in registry["projects"]:
        raise ExecutorError("policy_denied", "project is not registered")
    captures = Path(ex._db_path).parent / "captures"
    with ex.target_lock(f"project-{params.project_id}"):
        pause = ex.backup_pause(params.project_id)
        if pause is not None and pause.artifact == params.artifact:
            raise ExecutorError("policy_denied", "capture is needed for pending pause recovery")
        with ex._db() as db:
            row = db.execute(
                "SELECT body FROM backup_schedule WHERE project=?", (params.project_id,)
            ).fetchone()
        if row:
            run = BackupScheduledRun.model_validate_json(row[0])
            if run.artifact == params.artifact:
                raise ExecutorError("policy_denied", "capture belongs to the current scheduled run")
        try:
            owned_directory(captures)
            project = captures / params.project_id
            owned_directory(project)
            manifest = protected_capture(project / params.artifact)
            if manifest.binding.project != params.project_id or manifest.id != params.capture_id:
                raise BackupError("evidence_mismatch")
        except (BackupError, OSError, ValueError):
            raise ExecutorError(
                "unavailable", "capture metadata or contents could not be verified"
            ) from None
        now = time.time()
        with ex._db() as db:
            db.execute(
                "INSERT OR REPLACE INTO backup_removal_ack "
                "(project, artifact, capture_id, config_revision, "
                "capture_created_at, acknowledged_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    params.project_id,
                    params.artifact,
                    manifest.id,
                    manifest.binding.config_revision,
                    manifest.created_at,
                    now,
                ),
            )
        return {
            "project_id": params.project_id,
            "artifact": params.artifact,
            "capture_id": manifest.id,
            "acknowledged_at": now,
            "deleted": False,
            "cleanup_authorized": False,
        }


def backup_retention_revoke(ex: Executor, params: BackupExportParams, _role: str, registry: dict):
    """Withdraw only an exact root-owned operator acknowledgement."""
    if params.project_id not in registry["projects"]:
        raise ExecutorError("policy_denied", "project is not registered")
    with ex.target_lock(f"project-{params.project_id}"), ex._db() as db:
        if db.execute(
            "SELECT 1 FROM backup_retirement_intents WHERE project=? "
            "UNION ALL SELECT 1 FROM backup_import_retirement_intents WHERE project=? LIMIT 1",
            (params.project_id, params.project_id),
        ).fetchone():
            raise ExecutorError("policy_denied", "project has a pending backup retirement")
        cursor = db.execute(
            "DELETE FROM backup_removal_ack WHERE project=? AND artifact=? AND capture_id=?",
            (params.project_id, params.artifact, params.capture_id),
        )
        revoked = cursor.rowcount == 1
    return {"project_id": params.project_id, "artifact": params.artifact, "revoked": revoked}


def backup_retention_purge(
    ex: Executor, params: BackupExportParams, role: str, registry: dict, *, _resume_only=False
):
    """Retire one acknowledged, old private capture with no upload dependency."""
    from ..core.backupexport import owned_directory, protected_capture
    from ..core.backupretention import RetentionItem, classify, inspect_namespace
    from ..core.backupretire import RetirementIntent, retire_capture
    from ..core.backups import BackupError

    if params.project_id not in registry["projects"]:
        raise ExecutorError("policy_denied", "project is not registered")
    if role != "operator" and not _resume_only:
        from ..core.config import Backup

        spec = registry["projects"][params.project_id]
        if (
            not Backup.model_validate(registry.get("backup", {})).enabled
            or not spec.get("has_data")
            or not spec.get("allow_backup_pause")
        ):
            raise ExecutorError("policy_denied", "automatic backup retention is disabled")
    captures = Path(ex._db_path).parent / "captures"
    parent = captures / params.project_id
    with ex.target_lock(f"project-{params.project_id}"):
        if role != "operator" and ex.host.kill_switch():
            raise ExecutorError("kill_switch", "automatic backup retirement is stopped")
        with ex._db() as db:
            if db.execute(
                "SELECT 1 FROM backup_import_retirement_intents WHERE project=?",
                (params.project_id,),
            ).fetchone():
                raise ExecutorError("policy_denied", "project has a pending import retirement")
            saved = db.execute(
                "SELECT body FROM backup_retirement_intents WHERE project=?", (params.project_id,)
            ).fetchone()
        if _resume_only and not saved:
            return {
                "project_id": params.project_id,
                "artifact": params.artifact,
                "outcome": "already_resolved",
            }
        try:
            owned_directory(captures)
            owned_directory(parent)
            if saved:
                intent = RetirementIntent.model_validate_json(saved[0])
                if (intent.artifact, intent.capture_id) != (params.artifact, params.capture_id):
                    raise ExecutorError("policy_denied", "another capture retirement is pending")
                pause = ex.backup_pause(params.project_id)
                if pause and pause.artifact == params.artifact:
                    raise ExecutorError("policy_denied", "capture is needed for pause recovery")
                with ex._db() as db:
                    pending = db.execute(
                        "SELECT 1 FROM backup_upload_protection WHERE project=? "
                        "AND (artifact=? OR capture_id=?)",
                        (params.project_id, params.artifact, params.capture_id),
                    ).fetchone()
                    scheduled = db.execute(
                        "SELECT body FROM backup_schedule WHERE project=?", (params.project_id,)
                    ).fetchone()
                if pending or (
                    scheduled
                    and BackupScheduledRun.model_validate_json(scheduled[0]).artifact
                    == params.artifact
                ):
                    raise ExecutorError("policy_denied", "capture has pending upload or schedule")
                if os.path.lexists(BACKUP_IMPORT_ROOT):
                    root_info = owned_directory(BACKUP_IMPORT_ROOT)
                    gid = ex.host.backup_group()
                    if root_info.st_gid != gid or root_info.st_mode & 0o777 != 0o750:
                        raise BackupError("unsafe_spool")
                    imports = inspect_namespace(
                        BACKUP_IMPORT_ROOT / params.project_id,
                        params.project_id,
                        imported=True,
                        group_id=gid,
                    )
                    if (
                        imports["truncated"]
                        or imports["unknown"]
                        or any(
                            item["state"] != "metadata_only"
                            or item["artifact"] == params.artifact
                            or item["capture_id"] == params.capture_id
                            for item in imports["items"]
                        )
                    ):
                        raise BackupError("ambiguous_retirement")
            else:
                pause = ex.backup_pause(params.project_id)
                if pause and pause.artifact == params.artifact:
                    raise ExecutorError("policy_denied", "capture is needed for pause recovery")
                with ex._db() as db:
                    scheduled = db.execute(
                        "SELECT body FROM backup_schedule WHERE project=?", (params.project_id,)
                    ).fetchone()
                    pending = db.execute(
                        "SELECT 1 FROM backup_upload_protection WHERE project=? "
                        "AND (artifact=? OR capture_id=?)",
                        (params.project_id, params.artifact, params.capture_id),
                    ).fetchone()
                    ack = db.execute(
                        "SELECT capture_id, config_revision, capture_created_at "
                        "FROM backup_removal_ack WHERE project=? AND artifact=?",
                        (params.project_id, params.artifact),
                    ).fetchone()
                if pending or (
                    scheduled
                    and BackupScheduledRun.model_validate_json(scheduled[0]).artifact
                    == params.artifact
                ):
                    raise ExecutorError("policy_denied", "capture has pending upload or schedule")
                if not ack or ack[0] != params.capture_id:
                    raise ExecutorError("policy_denied", "exact removal acknowledgement required")
                if os.path.lexists(BACKUP_IMPORT_ROOT):
                    info = owned_directory(BACKUP_IMPORT_ROOT)
                    gid = ex.host.backup_group()
                    if info.st_gid != gid or info.st_mode & 0o777 != 0o750:
                        raise BackupError("unsafe_spool")
                    imports = inspect_namespace(
                        BACKUP_IMPORT_ROOT / params.project_id,
                        params.project_id,
                        imported=True,
                        group_id=gid,
                    )
                    if imports["truncated"] or imports["unknown"]:
                        raise BackupError("ambiguous_retirement")
                    for item in imports["items"]:
                        if (
                            item["state"] != "metadata_only"
                            or item["artifact"] == params.artifact
                            or item["capture_id"] == params.capture_id
                        ):
                            raise BackupError("ambiguous_retirement")
                listing = inspect_namespace(parent, params.project_id, imported=False)
                if listing["truncated"] or listing["unknown"]:
                    raise BackupError("ambiguous_retirement")
                items = []
                target_manifest = None
                for item in listing["items"]:
                    if item["state"] != "metadata_only":
                        raise BackupError("ambiguous_retirement")
                    manifest = protected_capture(parent / item["artifact"])
                    if (
                        manifest.binding.project != params.project_id
                        or manifest.id != item["capture_id"]
                    ):
                        raise BackupError("evidence_mismatch")
                    if item["artifact"] == params.artifact:
                        target_manifest = manifest
                    items.append(
                        RetentionItem(
                            artifact=item["artifact"],
                            capture_id=manifest.id,
                            created_at=manifest.created_at,
                            complete=True,
                            operator_acknowledged=item["artifact"] == params.artifact,
                        )
                    )
                if target_manifest is None or (
                    target_manifest.id,
                    target_manifest.binding.config_revision,
                    target_manifest.created_at,
                ) != tuple(ack):
                    raise BackupError("evidence_mismatch")
                decisions = classify(items, now=time.time())
                if not any(
                    item.artifact == params.artifact and item.eligible for item in decisions
                ):
                    raise ExecutorError("policy_denied", "capture is protected by retention policy")
                target = parent / params.artifact
                directory = target.lstat()
                data = (target / target_manifest.filename).lstat()
                manifest_file = (target / "manifest.json").lstat()
                intent = RetirementIntent(
                    artifact=params.artifact,
                    capture_id=params.capture_id,
                    data_name=target_manifest.filename,
                    directory_device=directory.st_dev,
                    directory_inode=directory.st_ino,
                    data_device=data.st_dev,
                    data_inode=data.st_ino,
                    manifest_device=manifest_file.st_dev,
                    manifest_inode=manifest_file.st_ino,
                )
                with ex._db() as db:
                    db.execute(
                        "INSERT INTO backup_retirement_intents VALUES (?, ?)",
                        (params.project_id, intent.model_dump_json()),
                    )
            outcome = retire_capture(parent, intent)
            with ex._db() as db:
                db.execute(
                    "DELETE FROM backup_removal_ack WHERE project=? "
                    "AND artifact=? AND capture_id=?",
                    (params.project_id, params.artifact, params.capture_id),
                )
                # The registered upload and every matching import were checked
                # absent under this same lock. Without a capture, import or root
                # registration, a stale worker cannot reacquire a permit.
                db.execute(
                    "DELETE FROM backup_upload_cancellations WHERE project=? "
                    "AND artifact=? AND capture_id=?",
                    (params.project_id, params.artifact, params.capture_id),
                )
                db.execute(
                    "DELETE FROM backup_retirement_intents WHERE project=?", (params.project_id,)
                )
            return {
                "project_id": params.project_id,
                "artifact": params.artifact,
                "outcome": outcome,
            }
        except ExecutorError:
            raise
        except (BackupError, OSError, ValueError, KeyError):
            raise ExecutorError(
                "unavailable", "capture retirement refused or interrupted"
            ) from None


def backup_schedule(ex: Executor, params: BackupScheduleParams, role: str, registry: dict):
    """One bounded automatic pause attempt per rolling configured interval."""
    from ..core.backupexport import protected_capture
    from ..core.backups import BackupError
    from ..core.config import Backup

    policy = Backup.model_validate(registry.get("backup", {}))
    spec = registry["projects"].get(params.project_id)
    if (
        params.expected_revision is not None
        and params.expected_revision != registry["config_revision"]
    ):
        raise ExecutorError("conflict", "active configuration changed")
    if (
        not policy.enabled
        or not spec
        or not spec.get("has_data")
        or not spec.get("allow_backup_pause")
    ):
        raise ExecutorError(
            "policy_denied", "scheduled backup requires an enabled explicit project contract"
        )

    def persist(body):
        with ex._db() as db:
            db.execute(
                "INSERT OR REPLACE INTO backup_schedule VALUES (?,?)",
                (params.project_id, BackupScheduledRun.model_validate(body).model_dump_json()),
            )

    with ex.target_lock(f"project-{params.project_id}"):
        if ex.backup_pause(params.project_id) is not None:
            raise ExecutorError("unavailable", "backup pause recovery is pending")
        with ex._db() as db:
            saved = db.execute(
                "SELECT body FROM backup_schedule WHERE project=?", (params.project_id,)
            ).fetchone()
        run = BackupScheduledRun.model_validate_json(saved[0]).model_dump() if saved else None
        now = time.time()
        if (
            params.expected_revision is not None
            and run
            and run["config_revision"] != params.expected_revision
            and (
                run["phase"] in ("admitted", "capturing", "captured")
                or now < run["created_at"] + policy.interval_s
            )
        ):
            raise ExecutorError("conflict", "previous schedule belongs to another configuration")
        if run and run["phase"] == "exported" and now < run["created_at"] + policy.interval_s:
            return {
                **run["result"],
                "reused": True,
                "next_capture_at": run["created_at"] + policy.interval_s,
            }
        if run and run["phase"] == "failed" and now < run["created_at"] + policy.interval_s:
            raise ExecutorError(
                "budget_exhausted",
                "this interval's capture attempt failed; no repeated pause allowed",
            )
        if run and run["phase"] in ("capturing", "captured"):
            source = Path(ex._db_path).parent / "captures" / params.project_id / run["artifact"]
            try:
                manifest = protected_capture(source)
                if (
                    manifest.binding.project != params.project_id
                    or manifest.binding.config_revision != run["config_revision"]
                ):
                    raise BackupError("evidence_mismatch")
                run["capture_id"] = manifest.id
                run["capture_created_at"] = manifest.created_at
                run["phase"] = "captured"
                persist(run)
            except (BackupError, OSError, ValueError):
                run["phase"] = "failed"
                persist(run)
                raise ExecutorError(
                    "unavailable", "interrupted capture is incomplete; retained for inspection"
                ) from None
        else:
            if not run or run["phase"] != "admitted":
                run = {
                    "artifact": uuid.uuid4().hex,
                    "phase": "admitted",
                    "created_at": now,
                    "config_revision": registry["config_revision"],
                }
            # Commit before any pause; a failed or ambiguous capture cannot be
            # retried into repeated downtime by a compromised backup identity.
            persist(run)

            def begin_capture():
                run.update(
                    {
                        "capture_started": True,
                        "phase": "capturing",
                        "created_at": time.time(),
                        "config_revision": registry["config_revision"],
                    }
                )
                persist(run)

            try:
                result = backup_capture(
                    ex,
                    params,
                    role,
                    registry,
                    _locked=True,
                    _artifact=run["artifact"],
                    _max_bytes=policy.max_mib * 1024 * 1024,
                    _before_capture=begin_capture,
                )
                run["capture_id"] = result["capture_id"]
                run["capture_created_at"] = result["capture"]["created_at"]
                run["phase"] = "captured"
                persist(run)
            except Exception as exc:
                # A valid manifest may already exist when only resume failed.
                # Keep the ambiguous phase so recovery can export it without
                # another pause, or fence an incomplete attempt until next due.
                outcome = exc.error_class if isinstance(exc, ExecutorError) else "internal"
                persist(run)
                ex.audit.append(
                    "backup_schedule",
                    project_id=params.project_id,
                    artifact=run["artifact"],
                    automatic=role != "operator",
                    outcome=outcome,
                )
                raise
        result = backup_export(
            ex,
            BackupExportParams(
                project_id=params.project_id, artifact=run["artifact"], capture_id=run["capture_id"]
            ),
            role,
            registry,
            _locked=True,
        )
        result.update(
            {
                "capture_created_at": run["capture_created_at"],
                "config_revision": run["config_revision"],
            }
        )
        run["phase"], run["result"] = "exported", result
        persist(run)
        return {**result, "reused": False, "next_capture_at": run["created_at"] + policy.interval_s}


def _active_image_service(spec: object) -> bool:
    return isinstance(spec, dict) and spec.get("manage") is True and spec.get("deploy") is True


def _inventory_application_services(registry: dict[str, Any]) -> list[str]:
    if not containment.policy_enabled(registry):
        return []
    return sorted(
        f"{application}/{service}"
        for application, app in registry.get("applications", {}).items()
        if app.get("isolation") == "separate"
        for service, spec in app["services"].items()
        if _active_image_service(spec)
    )


def inventory_page(ex: Executor, params: InventoryParams, _role: str, registry: dict[str, Any]):
    from ..core.inventory import Inventory

    application_services = _inventory_application_services(registry)
    inventory = Inventory.model_validate(
        {
            **ex.host.inventory(),
            "config_revision": registry["config_revision"],
            "projects": sorted(registry["projects"]),
            **({"application_services": application_services} if application_services else {}),
        }
    )
    if params.expected_revision and params.expected_revision != inventory.revision:
        raise ExecutorError("unavailable", "inventory changed during collection")
    metadata = inventory.model_dump(mode="json", exclude={"packages"}, exclude_none=True)
    return {
        "revision": inventory.revision,
        "total": len(inventory.packages),
        "metadata": metadata,
        "packages": [
            p.model_dump() for p in inventory.packages[params.offset : params.offset + params.limit]
        ],
    }


def runtime_image_observation(ex: Executor, spec: dict[str, Any]) -> dict[str, Any]:
    """Project the runtime identity of one trusted registry target."""
    container = ex.host.container(spec["user"], spec["container"])
    return {
        "configured_image": spec["image"],
        "observed_image_id": (container or {}).get("Image"),
        "observed_image_digest": (container or {}).get("ImageDigest"),
        "observed": container is not None,
        "observed_running": (container or {}).get("State", {}).get("Running") is True,
        "configured_image_identity": ex.host.configured_image_identity(spec["image"]),
    }


def _image_inventory_projection(ex: Executor, spec: dict[str, Any], *, exposed: bool):
    return {
        "source_revision": spec["source_revision"],
        "deploy": spec["deploy"],
        "exposed": exposed,
        **runtime_image_observation(ex, spec),
    }


def image_inventory(
    ex: Executor, params: ImageInventoryParams, role: str, registry: dict[str, Any]
):
    if params.project_id is not None:
        spec = registry["projects"].get(params.project_id)
        if spec is None:
            raise ExecutorError("policy_denied", "project is not registered")
        return {
            "project": params.project_id,
            "config_revision": registry["config_revision"],
            **_image_inventory_projection(ex, spec, exposed=spec["exposed"]),
        }

    application, service = params.application, params.service
    app_lock = "application-" + graph_identifier("a", application)
    stem = graph_identifier("s", application, service)
    service_lock = "project-" + stem
    with ex.target_lock("deployment-execution"):
        fresh = load_registry(ex.registry_path)
        if role == "scanner" and fresh.get("peers") != registry.get("peers"):
            raise ExecutorError("conflict", "registered peers changed")
        containment._policy(fresh)
        if ex.deployment_fence() is not None:
            raise ExecutorError("target_busy", "deployment recovery is pending")
        if fresh.get("config_revision") != params.expected_revision:
            raise ExecutorError("conflict", "active configuration changed")
        app = containment._application(fresh, application)
        spec = app["services"].get(service)
        if not _active_image_service(spec):
            raise ExecutorError("policy_denied", "service is not registered and active")
        if (
            app.get("lock") != app_lock
            or spec.get("user") != "stw-" + stem
            or spec.get("unit") != stem + ".service"
            or spec.get("container") != stem
            or spec.get("lock") != service_lock
        ):
            raise ExecutorError("unavailable", "application service identity is invalid")
        try:
            IMAGE_REFERENCE.validate_python(spec.get("image"))
        except ValidationError:
            raise ExecutorError("unavailable", "application service image is invalid") from None
        observation = _image_inventory_projection(ex, spec, exposed=bool(spec["routes"]))
    return {
        "application": application,
        "service": service,
        "config_revision": fresh["config_revision"],
        **observation,
    }


def audit_tail(ex: Executor, _params: NoParams, _role: str, _registry: dict[str, Any]):
    ok, count = ex.audit.verify()
    return {"chain_ok": ok, "records": count, "entries": ex.audit.read(200)}


def audit_since(ex: Executor, params: AuditSinceParams, _role: str, _registry: dict[str, Any]):
    known = ex.host.known_secret_values() if _role == "collector" else ()

    def view(entry):
        if _role != "collector":
            return entry
        safe = {
            **entry,
            "request_id": entry.get("request_id")
            if valid_request_id(entry.get("request_id"))
            else None,
        }
        safe = {**redact_tree(safe, known), "hash": entry["hash"], "prev": entry["prev"]}
        if len(json.dumps(safe, ensure_ascii=False).encode()) > 65536:
            safe = {
                "ts": entry["ts"],
                "hash": entry["hash"],
                "prev": entry["prev"],
                "event": "audit_record_truncated",
                "truncated": True,
                "original_event": str(entry.get("event", "unknown"))[:100],
            }
        return safe

    return ex.audit.read_since(
        params.offset, params.prev_hash, params.limit, max_bytes=128 * 1024, transform=view
    )


def _journal_sources(registry: dict[str, Any]) -> tuple[list[str], dict[int, str]]:
    """Journal matches for registered components only, and uid -> project/proxy."""
    matches = []
    for unit in registry["platform_units"]:
        matches += [f"_SYSTEMD_UNIT={unit}", f"UNIT={unit}"]
    owners: dict[int, str] = {}
    users = {registry["proxy_user"]: "proxy"}
    users.update({spec["user"]: pid for pid, spec in registry["projects"].items()})
    for user, owner in users.items():
        try:
            uid = pwd.getpwnam(user).pw_uid
        except KeyError:
            continue
        owners[uid] = owner
        matches.append(f"_UID={uid}")
    return matches, owners


def _journal_text(value: Any) -> str:
    if isinstance(value, list):  # journald encodes non-UTF-8 messages as byte arrays
        value = bytes(v & 0xFF for v in value if isinstance(v, int)).decode("utf-8", "replace")
    return str(value or "")


def journal_since(ex: Executor, params: JournalSinceParams, _role: str, registry: dict[str, Any]):
    """Warnings and errors of registered components, redacted before they leave root."""
    matches, owners = _journal_sources(registry)
    raw, cursor, more = ex.host.journal(matches, params.cursor, params.limit, params.skip_to_end)
    secrets = ex.host.known_secret_values()
    entries = []
    for item in raw:
        try:
            uid = int(item.get("_UID", -1))
            ts = int(item["__REALTIME_TIMESTAMP"]) / 1e6
        except (KeyError, ValueError):
            continue
        unit = (
            item.get("_SYSTEMD_USER_UNIT")
            or item.get("UNIT")
            or item.get("USER_UNIT")
            or item.get("_SYSTEMD_UNIT")
            or item.get("SYSLOG_IDENTIFIER")
            or "?"
        )
        entries.append(
            {
                "cursor": item.get("__CURSOR"),
                "ts": round(ts, 6),
                "priority": int(item.get("PRIORITY", 6)),
                "unit": str(unit)[:100],
                "owner": owners.get(uid),
                "message": redact(_journal_text(item.get("MESSAGE")), secrets)[
                    :JOURNAL_MESSAGE_MAX
                ],
            }
        )
    return {"entries": entries, "cursor": cursor, "more": more}


def application_retire(
    ex: Executor, params: ApplicationRetireParams, _role: str, _registry: dict[str, Any]
) -> dict[str, Any]:
    """Archive and release a removed, disabled, separately isolated application."""
    from .retirement import retire_application

    return retire_application(ex, params)


def application_retirement_status(
    ex: Executor, params: ApplicationRetirementStatusParams, _role: str, _registry: dict[str, Any]
) -> dict[str, Any]:
    from .retirement import retirement_status

    return retirement_status(ex, params.application)


_OPERATING = frozenset({"operator", "api", "controller"})
_COLLECT = frozenset({"operator", "collector"})
ACTIONS: dict[str, Action] = {
    "incident_open": Action(
        containment.IncidentOpenParams,
        frozenset({"operator", "controller"}),
        True,
        containment.incident_open,
    ),
    "incident_advance": Action(
        containment.IncidentAdvanceParams,
        frozenset({"operator", "controller"}),
        True,
        containment.incident_advance,
    ),
    "incident_reactivate": Action(
        containment.IncidentReactivateParams,
        frozenset({"operator", "controller"}),
        True,
        containment.incident_reactivate,
    ),
    "incident_status": Action(
        containment.IncidentStatusParams,
        frozenset({"operator", "controller", "api"}),
        False,
        containment.incident_status,
    ),
    # Restores recorded containment only (never creates new); allowed under the kill switch.
    "containment_reassert": Action(
        containment.NoParams,
        frozenset({"operator", "controller"}),
        False,
        containment.containment_reassert,
    ),
    "application_retire": Action(
        ApplicationRetireParams, frozenset({"operator"}), True, application_retire
    ),
    "application_retirement_status": Action(
        ApplicationRetirementStatusParams,
        frozenset({"operator"}),
        False,
        application_retirement_status,
    ),
    "application_group_stop": Action(
        ApplicationGroupStopParams, frozenset({"operator"}), True, application_group_stop
    ),
    "application_group_resume": Action(
        ApplicationGroupResumeParams, frozenset({"operator"}), True, application_group_resume
    ),
    "application_group_status": Action(
        ApplicationGroupStatusParams, frozenset({"operator"}), False, application_group_status
    ),
    "backup_cancellation_forget": Action(
        BackupCancellationForgetParams, frozenset({"operator"}), True, backup_cancellation_forget
    ),
    "backup_import_purge": Action(
        BackupImportRetireParams, frozenset({"operator"}), True, backup_import_purge
    ),
    "backup_upload_cancel": Action(
        BackupUploadCancelParams, frozenset({"operator"}), True, backup_upload_cancel
    ),
    "backup_upload_reinstate": Action(
        BackupExportParams, frozenset({"operator"}), True, backup_upload_reinstate
    ),
    "backup_worker_capacity_report": Action(
        NoParams, frozenset({"backup"}), False, backup_worker_capacity_report
    ),
    "backup_retention_hint": Action(
        BackupExportParams, frozenset({"operator", "backup"}), True, backup_retention_hint
    ),
    "backup_upload_permit": Action(
        BackupExportParams, frozenset({"operator", "backup"}), False, backup_upload_permit
    ),
    "backup_lock_cleanup_permit": Action(
        BackupExportParams, frozenset({"operator", "backup"}), False, backup_lock_cleanup_permit
    ),
    "backup_retention_revoke": Action(
        BackupExportParams, frozenset({"operator"}), True, backup_retention_revoke
    ),
    "backup_retention_purge": Action(
        BackupExportParams, frozenset({"operator"}), True, backup_retention_purge
    ),
    "backup_retention_ack": Action(
        BackupRetentionAckParams, frozenset({"operator"}), True, backup_retention_ack
    ),
    "backup_retention_status": Action(
        BackupCaptureParams, frozenset({"operator"}), False, backup_retention_status
    ),
    "backup_schedule": Action(
        BackupScheduleParams, frozenset({"operator", "backup"}), True, backup_schedule
    ),
    "backup_export": Action(BackupExportParams, frozenset({"operator"}), True, backup_export),
    "backup_recover": Action(BackupRecoverParams, frozenset({"operator"}), True, backup_recover),
    "backup_capture": Action(BackupCaptureParams, frozenset({"operator"}), True, backup_capture),
    "inventory_page": Action(
        InventoryParams, frozenset({"operator", "scanner"}), False, inventory_page
    ),
    "image_inventory": Action(
        ImageInventoryParams, frozenset({"operator", "scanner"}), False, image_inventory
    ),
    "platform_status": Action(NoParams, _OPERATING, False, platform_status),
    "maintenance_admit": Action(
        MaintenanceAdmitParams, frozenset({"operator"}), True, maintenance_admit
    ),
    "audit_tail": Action(NoParams, frozenset({"operator", "api"}), False, audit_tail),
    "audit_since": Action(AuditSinceParams, _COLLECT, False, audit_since),
    "journal_since": Action(JournalSinceParams, _COLLECT, False, journal_since),
    "workload_restart": Action(RestartParams, _OPERATING, True, workload_restart),
    "firewall_reassert": Action(
        NoParams, frozenset({"operator", "controller"}), True, firewall_reassert
    ),
    "proxy_restart": Action(NoParams, frozenset({"operator", "controller"}), True, proxy_restart),
}


from .image_update import register as _register_image_updates  # noqa: E402

_register_image_updates(ACTIONS, Action)

from .config_apply import register as _register_config_apply  # noqa: E402

_register_config_apply(ACTIONS, Action)

from .drills import register as _register_drills  # noqa: E402

_register_drills(ACTIONS, Action)


class RetirementRecovery:
    """Retry root-recorded retirement intents without authorizing new work."""

    def __init__(self, executor: Executor):
        self.executor = executor
        self.retries: dict[str, tuple[int, float]] = {}

    def tick(self, *, now: float | None = None) -> None:
        from ..core.backupretire import RetirementIntent

        now = time.monotonic() if now is None else now
        with self.executor._db() as db:
            captures = db.execute(
                "SELECT project, body FROM backup_retirement_intents ORDER BY project"
            ).fetchall()
            imports = db.execute(
                "SELECT project, body FROM backup_import_retirement_intents ORDER BY project"
            ).fetchall()
        rows = [(project, body, "capture") for project, body in captures]
        rows += [(project, body, "import") for project, body in imports]

        def retry_key(project, namespace):
            return project if namespace == "capture" else "import:" + project

        present = {retry_key(project, namespace) for project, _, namespace in rows}
        self.retries = {key: state for key, state in self.retries.items() if key in present}
        for project, body, namespace in rows:
            key = retry_key(project, namespace)
            attempts, due = self.retries.get(key, (0, 0.0))
            if now < due:
                continue
            try:
                intent = RetirementIntent.model_validate_json(body)
                if intent.namespace != namespace:
                    raise ValueError("retirement namespace mismatch")
                common = {
                    "project_id": project,
                    "artifact": intent.artifact,
                    "capture_id": intent.capture_id,
                }
                self.executor.audit.append(
                    "backup_retirement",
                    project_id=project,
                    artifact=intent.artifact,
                    namespace=namespace,
                    automatic=True,
                    outcome="started",
                )
                registry = load_registry(self.executor.registry_path)
                if namespace == "capture":
                    result = backup_retention_purge(
                        self.executor,
                        BackupExportParams(**common),
                        "retention",
                        registry,
                        _resume_only=True,
                    )
                else:
                    result = backup_import_purge(
                        self.executor,
                        BackupImportRetireParams(**common, acknowledge_import_removal=True),
                        "retention",
                        registry,
                        _resume_only=True,
                    )
                self.executor.audit.append(
                    "backup_retirement",
                    project_id=project,
                    artifact=intent.artifact,
                    namespace=namespace,
                    automatic=True,
                    outcome=result["outcome"],
                )
                self.retries.pop(key, None)
            except Exception as exc:  # noqa: BLE001 - keep the intent and retry other projects
                outcome = exc.error_class if isinstance(exc, ExecutorError) else "internal"
                try:
                    self.executor.audit.append(
                        "backup_retirement",
                        project_id=project,
                        namespace=namespace,
                        automatic=True,
                        outcome=outcome,
                    )
                except Exception:  # noqa: BLE001 - keep retrying even if audit storage is unavailable
                    print("backup retirement: audit unavailable", file=sys.stderr, flush=True)
                attempts += 1
                self.retries[key] = (attempts, now + min(5 * 2 ** min(attempts - 1, 6), 300))

    def run(self, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                self.tick()
            except Exception:  # noqa: BLE001 - do not lose retry loop on transient state errors
                try:
                    self.executor.audit.append(
                        "backup_retirement", automatic=True, outcome="internal"
                    )
                except Exception:  # noqa: BLE001 - stderr remains available when audit storage fails
                    print("backup retirement: audit unavailable", file=sys.stderr, flush=True)
            stop.wait(15)


class RetentionSweep:
    """Select only root-acknowledged candidates; the executor revalidates all policy."""

    def __init__(self, executor: Executor):
        self.executor = executor
        self.cursors: dict[str, str] = {}
        self.project_cursor: str | None = None
        self.next_attempt = 0.0

    def tick(self, *, wall: float | None = None, now: float | None = None) -> None:
        from ..core.backupretention import MIN_AGE_S
        from ..core.config import Backup

        wall = time.time() if wall is None else wall
        now = time.monotonic() if now is None else now
        if now < self.next_attempt:
            return
        registry = load_registry(self.executor.registry_path)
        if (
            not Backup.model_validate(registry.get("backup", {})).enabled
            or self.executor.host.kill_switch()
        ):
            return
        projects = sorted(registry["projects"].items())
        if self.project_cursor is not None:
            for index, (project, _spec) in enumerate(projects):
                if project == self.project_cursor:
                    projects = projects[index + 1 :] + projects[: index + 1]
                    break
        for project, spec in projects:
            if not spec.get("has_data") or not spec.get("allow_backup_pause"):
                continue
            attempted = False
            try:
                with self.executor._db() as db:
                    if db.execute(
                        "SELECT 1 FROM backup_retirement_intents WHERE project=? "
                        "UNION ALL SELECT 1 FROM backup_import_retirement_intents "
                        "WHERE project=? LIMIT 1",
                        (project, project),
                    ).fetchone():
                        continue
                    rows = db.execute(
                        "SELECT a.artifact, a.capture_id FROM backup_removal_ack a "
                        "WHERE a.project=? AND a.capture_created_at<=? AND NOT EXISTS "
                        "(SELECT 1 FROM backup_upload_protection p WHERE p.project=a.project "
                        "AND (p.artifact=a.artifact OR p.capture_id=a.capture_id)) "
                        "ORDER BY a.capture_created_at, a.artifact LIMIT 10",
                        (project, wall - MIN_AGE_S),
                    ).fetchall()
                pause = self.executor.backup_pause(project)
                previous = self.cursors.get(project)
                if previous is not None:
                    for index, (artifact, _capture_id) in enumerate(rows):
                        if artifact == previous:
                            rows = rows[index + 1 :] + rows[: index + 1]
                            break
                for artifact, capture_id in rows:
                    params = BackupExportParams(
                        project_id=project, artifact=artifact, capture_id=capture_id
                    )
                    if pause and pause.artifact == artifact:
                        continue
                    if os.path.lexists(BACKUP_IMPORT_ROOT / project / artifact):
                        continue
                    self.cursors[project] = artifact
                    self.project_cursor = project
                    attempted = True
                    self.next_attempt = now + 300
                    self.executor.audit.append(
                        "backup_retirement",
                        project_id=project,
                        artifact=artifact,
                        namespace="capture",
                        automatic=True,
                        outcome="started",
                    )
                    latest = load_registry(self.executor.registry_path)
                    result = backup_retention_purge(self.executor, params, "retention", latest)
                    self.executor.audit.append(
                        "backup_retirement",
                        project_id=project,
                        artifact=artifact,
                        namespace="capture",
                        automatic=True,
                        outcome=result["outcome"],
                    )
                    return  # at most one expensive full-data verification per host and cycle
            except Exception as exc:  # noqa: BLE001 - one project cannot starve the rest
                outcome = exc.error_class if isinstance(exc, ExecutorError) else "internal"
                try:
                    self.executor.audit.append(
                        "backup_retirement",
                        project_id=project,
                        namespace="capture",
                        automatic=True,
                        outcome=outcome,
                    )
                except Exception:  # noqa: BLE001 - retry in a later cycle if audit is unavailable
                    print("backup retention: audit unavailable", file=sys.stderr, flush=True)
                if attempted:
                    return

    def run(self, stop: threading.Event) -> None:
        while not stop.is_set():
            self.executor.retention_wakeup.clear()
            try:
                self.tick()
            except Exception:  # noqa: BLE001 - keep observing if root state is unavailable
                print("backup retention: state unavailable", file=sys.stderr, flush=True)
            remaining = self.next_attempt - time.monotonic()
            timeout = min(300, max(0.1, remaining)) if remaining > 0 else 300
            self.executor.retention_wakeup.wait(timeout)


class GroupStartupRecovery:
    """Recover startup transitions and later durable capture workflows.

    Paused groups are resumed only when a matching durable capture workflow owns them.
    The driver lock protects against a surviving internal coordinator; future
    public drivers must cooperate with it before group actions can be enabled.
    """

    def __init__(self, executor: Executor):
        from ..core.group_backups import GroupCaptureWorkflow

        self.executor = executor
        with executor._db() as db:
            rows = db.execute(
                "SELECT g.application, g.operation_id, g.generation, g.body, "
                "w.operation_id, w.body "
                "FROM application_group_intents g LEFT JOIN application_capture_workflows w "
                "ON w.application=g.application ORDER BY g.application LIMIT ?",
                (MAX_GROUP_CHECKPOINTS + 1,),
            ).fetchall()
        if len(rows) > MAX_GROUP_CHECKPOINTS:
            raise ValueError("group checkpoint capacity exceeded")
        self.candidates = {}
        self.verified_workflows = {}
        for application, operation_id, generation, body, workflow_id, workflow_body in rows:
            try:
                checkpoint = GroupCheckpoint.model_validate_json(body)
                if (
                    checkpoint.plan.application != application
                    or checkpoint.operation_id != operation_id
                    or checkpoint.generation != generation
                ):
                    raise ValueError("inconsistent persisted group checkpoint")
                if checkpoint.phase in ("complete", "recovered") and workflow_id is not None:
                    workflow = GroupCaptureWorkflow.model_validate_json(workflow_body)
                    if (
                        workflow.application != application
                        or workflow.operation_id != workflow_id
                        or workflow.operation_id != operation_id
                    ):
                        raise ValueError("inconsistent persisted capture workflow")
                    if workflow.phase == "failed" or (
                        workflow.phase == "captured" and checkpoint.phase == "complete"
                    ):
                        continue
                if checkpoint.phase not in ("stopping", "recovering", "resuming") and not (
                    checkpoint.phase in ("paused", "complete", "recovered")
                    and workflow_id is not None
                ):
                    continue
            except ValueError:
                # Keep corrupt rows visible to the retry/audit path, without host effects.
                pass
            self.candidates[application] = operation_id

    def discover_capture_workflows(self) -> None:
        """Adopt only capture workflows, never later unrelated group operations."""
        from ..core.group_backups import GroupCaptureWorkflow

        with self.executor._db() as db:
            rows = db.execute(
                "SELECT g.application, g.operation_id, g.generation, g.body, "
                "w.operation_id, w.body FROM application_group_intents g "
                "JOIN application_capture_workflows w ON w.application=g.application "
                "ORDER BY g.application LIMIT ?",
                (MAX_GROUP_CHECKPOINTS + 1,),
            ).fetchall()
        if len(rows) > MAX_GROUP_CHECKPOINTS:
            raise ValueError("group capture workflow capacity exceeded")
        for application, operation_id, generation, body, workflow_id, workflow_body in rows:
            try:
                checkpoint = GroupCheckpoint.model_validate_json(body)
                workflow = GroupCaptureWorkflow.model_validate_json(workflow_body)
                if (
                    checkpoint.plan.application != application
                    or checkpoint.operation_id != operation_id
                    or checkpoint.generation != generation
                    or workflow.application != application
                    or workflow.operation_id != workflow_id
                    or workflow_id != operation_id
                ):
                    raise ValueError("inconsistent persisted capture workflow")
                if checkpoint.phase in ("complete", "recovered") and (
                    workflow.phase == "failed"
                    or (workflow.phase == "captured" and checkpoint.phase == "complete")
                ):
                    continue
            except ValueError:
                pass  # retain malformed state for the audited fail-closed retry path
            self.candidates.setdefault(application, operation_id)

    def tick(self) -> None:
        for application, operation_id in list(self.candidates.items()):
            try:
                checkpoint = self.executor.group_checkpoint(application)
                if checkpoint is None or checkpoint.operation_id != operation_id:
                    self.candidates.pop(application, None)
                    continue
                if checkpoint.operator_managed and not self.executor._operator_group_boot_ready():
                    continue
                with self.executor.group_driver_lock(checkpoint):
                    checkpoint = self.executor.group_checkpoint(application)
                    if checkpoint is None or checkpoint.operation_id != operation_id:
                        self.candidates.pop(application, None)
                        continue
                    workflow = self.executor.group_capture_workflow(application)
                    if workflow is not None:
                        if (
                            checkpoint.operator_managed
                            or workflow.operation_id != operation_id
                            or checkpoint.plan.scope != "application"
                            or workflow.data_contract_revision
                            != checkpoint.plan.data_contract_revision
                        ):
                            raise ExecutorError(
                                "conflict", "group capture workflow binding changed"
                            )
                        if (
                            checkpoint.phase == "complete"
                            and workflow.phase in ("captured", "failed")
                        ) or (checkpoint.phase == "recovered" and workflow.phase == "failed"):
                            self.candidates.pop(application, None)
                            self.verified_workflows.pop(application, None)
                            continue
                        if workflow.phase == "captured" and checkpoint.phase in (
                            "stopping",
                            "recovering",
                            "recovered",
                        ):
                            raise ExecutorError(
                                "conflict", "group capture workflow state is inconsistent"
                            )
                        if (
                            workflow.phase == "captured"
                            and self.verified_workflows.get(application) != workflow
                        ):
                            try:
                                self.executor.verify_group_capture(
                                    application, workflow.artifact, workflow.capture_id
                                )
                                self.verified_workflows[application] = workflow
                            except ExecutorError as exc:
                                if exc.error_class == "target_busy":
                                    raise
                                self.executor.audit.append(
                                    "application_group_capture_workflow",
                                    application=application,
                                    operation_id=operation_id,
                                    outcome="capture_unavailable",
                                )
                                workflow = self.executor.update_group_capture_workflow(
                                    workflow,
                                    phase="failed",
                                    artifact=workflow.artifact,
                                    capture_id=workflow.capture_id,
                                    error_class="unavailable",
                                )
                        if workflow.phase == "prepared":
                            self.executor.audit.append(
                                "application_group_capture_workflow",
                                application=application,
                                operation_id=operation_id,
                                outcome="interrupted",
                            )
                            workflow = self.executor.update_group_capture_workflow(
                                workflow, phase="failed", error_class="unavailable"
                            )
                    if checkpoint.phase == "stopping":
                        checkpoint = self.executor.begin_group_recovery(
                            application, operation_id, checkpoint.generation
                        )
                    if checkpoint.phase == "paused" and workflow is not None:
                        checkpoint = self.executor.resume_paused_group(
                            application, operation_id, checkpoint.generation
                        )
                    if checkpoint.phase in ("recovering", "resuming"):
                        checkpoint = self.executor.reconcile_group_step(
                            application, operation_id, checkpoint.generation
                        )
                    if checkpoint.phase in ("paused", "complete", "recovered"):
                        self.candidates.pop(application, None)
            except Exception as exc:  # noqa: BLE001 - retain failed intent for retry
                outcome = exc.error_class if isinstance(exc, ExecutorError) else "internal"
                if outcome == "target_busy":
                    continue
                try:
                    self.executor.audit.append(
                        "application_group_startup_recovery",
                        application=application,
                        operation_id=operation_id,
                        outcome=outcome,
                    )
                except Exception:  # noqa: BLE001 - failure must not discard the intent
                    print("group startup recovery: audit unavailable", file=sys.stderr, flush=True)

    def run(self, stop: threading.Event) -> None:
        while not stop.is_set():
            self.executor.group_recovery_wakeup.clear()
            try:
                self.discover_capture_workflows()
                self.tick()
            except Exception:  # noqa: BLE001 - retain durable state for retry
                print("group recovery: state unavailable", file=sys.stderr, flush=True)
            if not stop.is_set():
                self.executor.group_recovery_wakeup.wait(15 if self.candidates else 30)


# ---- socket server -----------------------------------------------------------------


def serve(executor: Executor, socket_path: str, socket_group: str | None) -> None:
    recovery = GroupStartupRecovery(executor)
    containment.reassert_at_startup(executor)
    server = ipc.bind(socket_path, executor.handle, socket_group)
    executor.audit.append("executor_start", pid=os.getpid())
    stop = threading.Event()
    with server:
        threading.Thread(target=recovery.run, args=(stop,), daemon=True).start()
        threading.Thread(target=executor.recover_backup_pauses, args=(stop,), daemon=True).start()
        threading.Thread(target=RetirementRecovery(executor).run, args=(stop,), daemon=True).start()
        threading.Thread(target=RetentionSweep(executor).run, args=(stop,), daemon=True).start()
        threading.Thread(
            target=containment.PeriodicReassert(executor).run, args=(stop,), daemon=True
        ).start()
        threading.Thread(target=recover_updates, args=(executor,), daemon=True).start()
        try:
            server.serve_forever()
        finally:
            stop.set()
            executor.retention_wakeup.set()
            executor.group_recovery_wakeup.set()


def main() -> None:
    parser = argparse.ArgumentParser(description="steward privileged host executor")
    parser.add_argument("--socket", default=DEFAULT_SOCKET)
    parser.add_argument("--socket-group", default="steward-exec")
    parser.add_argument("--registry", default=REGISTRY_PATH)
    parser.add_argument("--state-dir", default=STATE_DIR)
    parser.add_argument("--audit", default=AUDIT_PATH)
    parser.add_argument("--lock-dir", default=LOCK_DIR)
    args = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit("steward-executor must run as root")
    executor = Executor(
        registry_path=args.registry,
        state_dir=args.state_dir,
        audit_path=args.audit,
        lock_dir=args.lock_dir,
    )
    serve(executor, args.socket, args.socket_group)


if __name__ == "__main__":
    main()
