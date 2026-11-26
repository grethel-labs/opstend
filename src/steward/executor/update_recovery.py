"""Recovery of a verified image update (L06): data capture, restore and `rollback`.

Builds on the L05 journal (`image_update.py`). Three things happen here:

1. **Admission.** `recovery_mode` (core/update_recovery.py) turns the signed migration
   kind into the recovery the host must be able to perform. An update whose recovery
   cannot be guaranteed is refused before anything changes.
2. **Exact capture.** A `restore_required` update stops the workload, captures its data
   tree under the stopped workload, rehearses the restore in a private workspace and
   journals the capture identity. Only then is the new image installed and started.
   Writes that happen after that point are never lost silently: a restore keeps the
   replaced tree as `data.preserved-<token>`.
3. **Recovery.** A failed health/start check, a failed install or a process death
   reverts to the previous image, restoring the journaled capture first when the
   migration needs it. An interrupted update that may have migrated data is *reverted,
   never completed or repeated*. The operator action `rollback` returns an applied
   update to the previous image with the same machinery and the same journal.

Nothing is deleted: preserved trees and captures stay until an operator removes them.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..adapters.remediation import ApplyPlan, RemediationAdapter, RemediationError
from ..core.backups import BackupError, Binding, FilesystemCapture, load_capture
from ..core.config import Backup
from ..core.filebackups import (
    ARCHIVE_OVERHEAD_MAX,
    MAX_RESTORE_BYTES,
    capture_files,
    materialize_tree,
)
from ..core.update_evidence import ROLLBACK_FROM, UpdateLedger, UpdateRejected
from ..core.update_recovery import (
    CAPTURE_MODES,
    MAX_PRESERVED_TREES,
    CaptureRef,
    capture_matches,
    capture_ref,
    recovery_mode,
)
from . import image_update as iu
from . import update_auto_rollback as auto_rollback
from .data_restore import FREE_MARGIN, preserved_trees, restore_tree
from .protocol import ExecutorError

if TYPE_CHECKING:
    from .server import Executor

CAPTURE_RESERVE = 512 * 1024 * 1024


class RecoveryFailed(Exception):
    """A recovery step could not be completed; `message` is bounded and secret-free."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message[:300]


class RollbackParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_id: str = Field(pattern=iu.PROJECT_ID)
    approval_id: str = Field(pattern=iu.APPROVAL_ID)
    digest: str = Field(pattern=iu.DIGEST, description="Digest of the update being rolled back.")
    acknowledge_data_restore: bool = Field(
        False,
        strict=True,  # "yes" or 1 are not an acknowledgement
        description="Required for an update that needs an exact data restore: data written "
        "after the update is preserved on the host, not live.",
    )
    automatic: bool = Field(
        False,
        strict=True,
        description="Controller only: automatic rollback of a durably unhealthy update "
        "(migration `none`, inside the contract's window); rechecked by the executor.",
    )


# ---- locations and helpers -----------------------------------------------------------


def _data_root(project: str) -> Path:
    from . import server

    return server.PROJECT_DATA_ROOT / project


def _spool(ex: Executor, project: str) -> Path:
    return Path(ex._db_path).parent / "captures" / project


def _token(approval_id: str) -> str:
    return hashlib.sha256(approval_id.encode()).hexdigest()[:24]


def _capture_limit(registry: dict[str, Any]) -> int:
    configured = Backup.model_validate(registry.get("backup", {})).max_mib * 1024 * 1024
    return min(configured, MAX_RESTORE_BYTES)


# ---- admission -----------------------------------------------------------------------


def admit_recovery(
    ex: Executor, registry: dict[str, Any], spec: dict[str, Any], project: str, migration: str
) -> str:
    """The recovery mode for this update; refuses (before any change) when it cannot be met."""
    mode = recovery_mode(
        migration, has_data=spec["has_data"], allow_backup_pause=spec["allow_backup_pause"]
    )
    if mode in CAPTURE_MODES:
        _require_restore_capacity(ex, registry, spec, project)
    return mode


def _require_restore_capacity(
    ex: Executor, registry: dict[str, Any], spec: dict[str, Any], project: str
) -> None:
    from .server import backup_namespace_full

    root = _data_root(project)
    try:
        info = os.lstat(root / "data")
    except OSError:
        raise ExecutorError("unavailable", "project data directory is not available") from None
    if not stat.S_ISDIR(info.st_mode) or ex.host.service_user_uid(spec["user"]) != info.st_uid:
        raise ExecutorError("policy_denied", "project data is not owned by its service user")
    if len(preserved_trees(root)) >= MAX_PRESERVED_TREES - 1:
        raise ExecutorError(
            "unavailable", "preserved data trees reached their limit; remove old ones first"
        )
    spool = _spool(ex, project)
    try:
        spool.mkdir(mode=0o700, parents=True, exist_ok=True)
        if backup_namespace_full(spool):
            raise ExecutorError(
                "unavailable",
                "the capture spool of this project holds 10 artifacts; export and retire old "
                "captures (steward-host backup-export, backup-retention-purge; see "
                "docs/operations.md, 'Capture spool limit') and retry",
            )
        limit = _capture_limit(registry)
        if shutil.disk_usage(spool).free < limit + ARCHIVE_OVERHEAD_MAX + CAPTURE_RESERVE:
            raise ExecutorError("unavailable", "a recovery capture needs more free space")
        if shutil.disk_usage(root).free < limit + FREE_MARGIN:
            raise ExecutorError("unavailable", "a data restore would need more free space")
    except OSError:
        raise ExecutorError("unavailable", "capture storage is not available") from None
    state = ex.host.user_unit(spec["user"], spec["unit"])
    if state["load"] != "loaded" or state["active"] not in ("active", "inactive", "failed"):
        raise ExecutorError("unavailable", "workload state is not known")


# ---- capture ---------------------------------------------------------------------------


def _rehearse(root: Path, capture_dir: Path, manifest: FilesystemCapture) -> None:
    """Prove the capture restores bit-exactly before the update may touch the data."""
    work = Path(tempfile.mkdtemp(prefix=".rehearse-", dir=root))
    try:
        materialize_tree(capture_dir / manifest.filename, manifest, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def capture_before_update(
    ex: Executor,
    adapter: RemediationAdapter,
    ledger: UpdateLedger,
    plan: ApplyPlan,
    registry: dict[str, Any],
    approval_id: str,
    contract: Any,
    *,
    automatic: bool = False,
    rehearse: bool = True,
) -> None:
    """Stop the workload, capture its exact data and (unless `rehearse` is off) rehearse
    the restore. A `reversible` update captures only as an exact fallback: no rehearsal.

    Returns with the workload stopped and the capture journaled. On failure the
    previous workload is resumed and the update is finished as failed."""
    host, project = ex.host, plan.project
    root, spool = _data_root(project), _spool(ex, project)
    artifact = uuid.uuid4().hex
    ledger.journal(approval_id, phase="capturing", capture_artifact=artifact)
    was_active = host.user_unit(plan.user, plan.unit)["active"] == "active"
    try:
        if was_active and not host.set_user_unit(plan.user, plan.unit, running=False):
            raise RecoveryFailed("workload stop failed")
        binding = Binding(
            server=registry["server_name"],
            project=project,
            config_revision=plan.old_config_revision,
            image=plan.old_image,
            source_revision=plan.old_source_revision,
        )
        manifest = capture_files(
            root / "data",
            spool / artifact,
            binding,
            max_bytes=_capture_limit(registry),
            is_quiescent=lambda: host.workload_quiescent(plan.user, plan.unit),
        )
        if rehearse:
            _rehearse(root, spool / artifact, manifest)
        if automatic and host.kill_switch():  # the capture can take minutes
            raise RecoveryFailed("kill switch engaged during the capture")
    except (BackupError, RecoveryFailed, OSError, ValueError) as exc:
        reason = (
            exc.message
            if isinstance(exc, RecoveryFailed)
            else "capture failed: " + getattr(exc, "error_class", type(exc).__name__)
        )
        raise _capture_aborted(
            ex, adapter, ledger, plan, contract, approval_id, reason, was_active
        ) from None
    ref = capture_ref(manifest, artifact)
    ledger.journal(
        approval_id,
        phase="captured",
        recovery_capture=ref.model_dump(mode="json"),
        capture_id=ref.capture_id,
    )
    ex.audit.append(
        "update_apply",
        project_id=project,
        approval_id=approval_id,
        outcome="captured",
        capture_id=ref.capture_id,
    )


def _capture_aborted(
    ex, adapter, ledger, plan, contract, approval_id, reason: str, was_active: bool
) -> ExecutorError:
    """No change was made to the image or the configuration: resume and report."""
    ledger.journal(approval_id, phase="capture_failed", reason=reason[:200])
    try:
        if was_active:
            adapter.restart(plan)
            iu._verify(
                ex,
                adapter,
                plan,
                iu._expected_id(ex, plan.old_image),
                contract.verify_timeout_s,
            )
    except (RemediationError, iu._VerificationFailed, ExecutorError):
        ledger.finish(approval_id, "revert_failed", reverted=False)
        return ExecutorError(
            "execution_failed",
            f"update not started ({reason}); the previous workload could not be resumed",
        )
    ledger.finish(approval_id, "failed", reverted=True)
    ex.audit.append(
        "update_apply",
        project_id=plan.project,
        approval_id=approval_id,
        outcome="failed_capture",
        reason=reason[:200],
    )
    return ExecutorError("execution_failed", f"update not started ({reason}); workload resumed")


def recover_capture_phase(
    ex: Executor,
    adapter: RemediationAdapter,
    ledger: UpdateLedger,
    approval_id: str,
    plan: ApplyPlan,
    contract: Any,
    journal: dict[str, Any],
) -> str:
    """Process death while capturing or after the capture, before anything was installed.

    The previous image is still installed: resume the workload, never continue."""
    artifact = journal.get("capture_artifact")
    if journal.get("phase") == "capturing" and isinstance(artifact, str):
        directory = _spool(ex, plan.project) / artifact
        if (
            len(artifact) == 32
            and artifact.isalnum()
            and directory.is_dir()
            and not directory.is_symlink()
            and not (directory / "manifest.json").exists()
        ):
            shutil.rmtree(directory, ignore_errors=True)  # incomplete: never a recovery point
    error = _capture_aborted(
        ex, adapter, ledger, plan, contract, approval_id, "interrupted before installation", True
    )
    del error  # the ledger holds the honest outcome
    return ledger.get(approval_id)["state"]


# ---- restore ---------------------------------------------------------------------------


def _load_capture(
    ex: Executor, plan: ApplyPlan, registry: dict[str, Any], ref: CaptureRef
) -> FilesystemCapture:
    """Re-read the exact journaled capture; any mismatch or damage is a refusal."""
    try:
        manifest = load_capture(_spool(ex, plan.project) / ref.artifact)
        ok = capture_matches(
            manifest,
            ref,
            server=registry["server_name"],
            project=plan.project,
            image=plan.old_image,
            source_revision=plan.old_source_revision,
            config_revision=plan.old_config_revision,
        )
    except (BackupError, OSError, ValidationError, ValueError, KeyError):
        ok = False
    if not ok:
        raise RecoveryFailed("the recovery capture is missing, damaged or does not match")
    return manifest  # type: ignore[return-value]


def _journal_ref(journal: dict[str, Any]) -> CaptureRef | None:
    raw = journal.get("recovery_capture")
    if journal.get("recovery_mode") != "restore_required" or raw is None:
        return None
    try:
        return CaptureRef.model_validate(raw)
    except ValidationError:
        raise RecoveryFailed("the journaled recovery capture is invalid") from None


def _fallback_ref(journal: dict[str, Any]) -> CaptureRef | None:
    """Capture of a `reversible` update: used only when an exact restore is asked for."""
    raw = journal.get("recovery_capture")
    if journal.get("recovery_mode") != "reversible_capture" or raw is None:
        return None
    try:
        return CaptureRef.model_validate(raw)
    except ValidationError:
        raise RecoveryFailed("the journaled recovery capture is invalid") from None


def restore_fallback(ex: Executor, ledger: UpdateLedger, approval_id: str, plan: ApplyPlan) -> bool:
    """Exact data restore for a `reversible` update whose image-only revert failed.

    Returns False when the update has no such capture. Newer data is preserved."""
    ref = _fallback_ref(ledger.get(approval_id)["journal"])
    if ref is None:
        return False
    _restore(ex, ledger, approval_id, plan, ref)
    return True


def restore_before_revert(
    ex: Executor, ledger: UpdateLedger, approval_id: str, plan: ApplyPlan
) -> None:
    """Put the captured data back before the previous image starts (no-op without capture)."""
    ref = _journal_ref(ledger.get(approval_id)["journal"])
    if ref is not None:
        _restore(ex, ledger, approval_id, plan, ref)


def _restore(
    ex: Executor, ledger: UpdateLedger, approval_id: str, plan: ApplyPlan, ref: CaptureRef
) -> dict[str, Any]:
    from .server import load_registry

    registry = load_registry(ex.registry_path)
    spec = registry["projects"][plan.project]
    manifest = _load_capture(ex, plan, registry, ref)
    host = ex.host
    if not host.workload_quiescent(plan.user, plan.unit):
        if not host.set_user_unit(plan.user, plan.unit, running=False):
            raise RecoveryFailed("workload stop failed before the data restore")
        if not host.workload_quiescent(plan.user, plan.unit):
            raise RecoveryFailed("workload writers are not quiescent")
    uid = host.service_user_uid(spec["user"])
    if uid is None:
        raise RecoveryFailed("service user is not known")
    try:
        result = restore_tree(
            _data_root(plan.project),
            _spool(ex, plan.project) / ref.artifact,
            manifest,
            token=_token(approval_id),
            service_uid=uid,
        )
    except (BackupError, OSError) as exc:
        raise RecoveryFailed(
            "data restore failed: " + getattr(exc, "error_class", type(exc).__name__)
        ) from None
    ledger.journal(
        approval_id,
        data_restore=result.state,
        preserved_data=result.preserved,
        **({"preserved_at": iu._now()} if result.state == "restored" else {}),
    )
    ex.audit.append(
        "update_data_restore",
        project_id=plan.project,
        approval_id=approval_id,
        capture_id=ref.capture_id,
        outcome=result.state,
        preserved=result.preserved,
    )
    return {"state": result.state, "preserved_data": result.preserved}


# ---- rollback ---------------------------------------------------------------------------


def rollback(ex: Executor, params: RollbackParams, role: str, registry: dict[str, Any]):
    """Return one applied update to its previous image (and data when the migration needs it)."""
    from .server import load_registry

    if (role == "controller") != params.automatic:
        # Only the controller rolls back by itself, and only by saying so explicitly.
        raise ExecutorError("policy_denied", "rollback is an operator action")
    adapter = iu._adapter(ex)
    ledger = iu._ledger(ex)
    project, approval_id = params.project_id, params.approval_id
    with ex.target_lock("deployment-execution"):
        if ex.deployment_fence() is not None:
            raise ExecutorError("target_busy", "deployment recovery is pending")
        registry = load_registry(ex.registry_path)
        spec, contract = iu._contract(registry, project)
        with ex.target_lock(f"project-{project}"):
            if ex.backup_pause(project) is not None:
                raise ExecutorError("unavailable", "backup pause recovery is pending")
            ex.ensure_group_restart_allowed(registry, spec)
            try:
                # An interrupted apply or rollback of this project is settled first.
                iu._recover_locked(ex, adapter, ledger, project, registry)
                registry = load_registry(ex.registry_path)
                spec, contract = iu._contract(registry, project)
                row = ledger.get(approval_id)
                if row is None or row["project"] != project:
                    raise UpdateRejected("unknown_approval", "approval was not applied here")
                journal = row["journal"]
                if row["state"] not in ROLLBACK_FROM:
                    raise UpdateRejected(
                        "in_progress" if row["state"] in ("applying", "rolling_back") else "replay",
                        f"approval is {row['state']}; there is nothing to roll back",
                    )
                if journal.get("new_image", "").rsplit("@", 1)[-1] != params.digest:
                    raise UpdateRejected("digest_mismatch", "digest is not the applied update")
                forward = adapter.resume_plan(project, journal)
                if row["state"] == "applied":
                    # The applied state must still be the live one; a later change wins.
                    current = adapter.plan(
                        registry, project, forward.old_image, forward.old_source_revision
                    )
                    if current != forward.reversed():
                        raise ExecutorError("conflict", "a later change superseded this update")
                marker = None
                if params.automatic:
                    marker = auto_rollback.require(
                        ex,
                        registry,
                        spec,
                        contract,
                        row,
                        project,
                        iu._now(),
                        acknowledge_data_restore=params.acknowledge_data_restore,
                    )
                ref = _journal_ref(journal)
                if journal.get("recovery_mode") == "restore_required":
                    if ref is None:
                        raise ExecutorError("unavailable", "the update has no recovery capture")
                    if not params.acknowledge_data_restore:
                        raise ExecutorError(
                            "policy_denied",
                            "this update needs an exact data restore: data written since the "
                            "update is preserved on the host, not live; acknowledge it",
                        )
                    _load_capture(ex, forward, registry, ref)
                    root = _data_root(project)
                    if (
                        len(preserved_trees(root)) >= MAX_PRESERVED_TREES
                        and not (root / f"data.preserved-{_token(approval_id)}").exists()
                    ):
                        raise ExecutorError(
                            "unavailable", "preserved data trees reached their limit"
                        )
                exact = False
                if journal.get("recovery_mode") == "reversible_capture":
                    fallback = _fallback_ref(journal)
                    if params.acknowledge_data_restore:
                        if fallback is None:
                            raise ExecutorError("unavailable", "the update has no capture")
                        _load_capture(ex, forward, registry, fallback)
                        root = _data_root(project)
                        if (
                            len(preserved_trees(root)) >= MAX_PRESERVED_TREES
                            and not (root / f"data.preserved-{_token(approval_id)}").exists()
                        ):
                            raise ExecutorError(
                                "unavailable", "preserved data trees reached their limit"
                            )
                        exact = True
                previous = ledger.begin_rollback(approval_id)
            except UpdateRejected as exc:
                raise iu._deny(exc) from None
            except RecoveryFailed as exc:
                raise ExecutorError("unavailable", exc.message) from None
            except RemediationError as exc:
                raise iu._fail(exc) from None
            ledger.journal(
                approval_id,
                phase="rollback_started",
                rollback_from=previous,
                rollback_requested_at=iu._now(),
                **({"rollback_exact": True} if exact else {}),
                **({"auto_rollback": marker} if marker else {}),
            )
            if marker:
                ex.audit.append(
                    "update_auto_rollback",
                    project_id=project,
                    approval_id=approval_id,
                    outcome="started",
                    reason=marker["reason"],
                )
            ex.audit.append(
                "update_rollback", project_id=project, approval_id=approval_id, outcome="started"
            )
            return _run_rollback(ex, adapter, ledger, approval_id, forward, contract)


def _run_rollback(ex, adapter, ledger, approval_id, forward: ApplyPlan, contract) -> dict[str, Any]:
    """Idempotent: every step may be repeated after a crash. No automatic forward revert."""
    plan = forward.reversed()
    journal = ledger.get(approval_id)["journal"]
    restored: dict[str, Any] = {}
    try:
        ref = _journal_ref(journal)
        if ref is None and journal.get("rollback_exact") is True:
            ref = _fallback_ref(journal)  # the operator asked for the exact fallback
        # The previous image first: when it cannot be fetched nothing has been changed yet.
        ledger.journal(approval_id, phase="rollback_preparing")
        expected = adapter.present(plan) or adapter.prepare(plan)
        if ref is not None:
            ledger.journal(approval_id, phase="rollback_restoring")
            restored = _restore(ex, ledger, approval_id, forward, ref)
        ledger.journal(approval_id, phase="rollback_installing", rollback_image_id=expected)
        adapter.install(plan, "new")  # "new" of the reversed plan is the previous image
        ledger.journal(approval_id, phase="rollback_installed")
        adapter.restart(plan)
        ledger.journal(approval_id, phase="rollback_restarted")
        facts = iu._verify(ex, adapter, plan, expected, contract.verify_timeout_s)
    except (RemediationError, RecoveryFailed, iu._VerificationFailed) as exc:
        reason = getattr(exc, "message", None) or str(exc)
        ledger.finish(approval_id, "rollback_failed", phase="rollback_failed", reason=reason[:200])
        ex.audit.append(
            "update_rollback",
            project_id=plan.project,
            approval_id=approval_id,
            outcome="failed",
            reason=reason[:200],
        )
        raise ExecutorError(
            "execution_failed",
            f"rollback failed ({reason[:150]}); retry the rollback or inspect the host",
        ) from None
    journal = ledger.get(approval_id)["journal"]
    ledger.finish(approval_id, "rolled_back", phase="rolled_back", reason="", **facts)
    ex.audit.append(
        "update_rollback",
        project_id=plan.project,
        approval_id=approval_id,
        outcome="rolled_back",
        image=plan.new_image,
        config_revision=plan.new_config_revision,
    )
    return {
        "project_id": plan.project,
        "approval_id": approval_id,
        "state": "rolled_back",
        "image": plan.new_image,
        "rolled_back_from": plan.old_image,
        "config_revision": plan.new_config_revision,
        "data_restore": journal.get("data_restore") or restored.get("state"),
        "preserved_data": journal.get("preserved_data"),
        "verified": facts,
    }


def resume_rollbacks(
    ex: Executor,
    adapter: RemediationAdapter,
    ledger: UpdateLedger,
    project: str,
    registry: dict[str, Any],
) -> list[str]:
    """Finish a rollback whose worker died (same target state, never a new decision)."""
    from ..core.config import UpdatePolicy

    outcomes = []
    for approval_id in ledger.rolling_back(project):
        journal = ledger.get(approval_id)["journal"]
        try:
            contract = UpdatePolicy.model_validate(registry["projects"][project].get("update"))
            forward = adapter.resume_plan(project, journal)
            _run_rollback(ex, adapter, ledger, approval_id, forward, contract)
        except ExecutorError:
            pass  # the ledger holds the honest outcome (rollback_failed)
        except (RemediationError, KeyError, ValidationError):
            ledger.finish(approval_id, "rollback_failed", reason="rollback could not be resumed")
        outcomes.append(f"{approval_id}:{ledger.get(approval_id)['state']}")
    return outcomes


def register(actions: dict, action_cls) -> None:
    actions["rollback"] = action_cls(
        RollbackParams, frozenset({"operator", "controller"}), True, rollback
    )
