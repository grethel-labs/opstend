"""Registered actions for verified image updates (L04 evidence, L05 apply).

`update_validate` checks signed evidence against the root-owned contract and
records it durably. `apply_verified_image` rechecks everything at execution time
(evidence, kill switch, maintenance window, backup age, revision, target lock,
budget), journals each phase, applies the image through the RemediationAdapter
and reports success only after the actual running image, health and isolation
were observed. A failed apply restores the previous image; an update that needs
an exact data restore is captured first and restored by `update_recovery.py`
(L06), which also provides the operator `rollback`.

Availability: the contract that enables these actions exists only in registries
rendered from `projects[].update`, which `UNAVAILABLE_FEATURES` rejects in this
release. Automatic callers additionally need `automation_profile == "patch"`.
Both gates keep the capability unreachable in production until it is accepted;
tests construct registries directly.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError, model_validator

from ..adapters.remediation import (
    ApplyPlan,
    HostImageRemediation,
    Paths,
    RemediationAdapter,
    RemediationError,
)
from ..core.backups import Capture, FilesystemCapture
from ..core.config import UpdatePolicy
from ..core.images import image_id
from ..core.maintenance import admit
from ..core.update_evidence import (
    UpdateLedger,
    UpdateRejected,
    require_fresh_backup,
    validate_update,
)
from ..core.update_recovery import CAPTURE_MODES
from .protocol import ExecutorError
from .update_emergency import (
    REASON_PATTERN,
    announce,
    refuse_automatic,
    window_allows_or_emergency,
)

if TYPE_CHECKING:
    from .server import Executor

UPDATE_BUDGET_PER_HOUR = 2
MAX_PENDING_APPROVALS = 64
VERIFY_POLL_S = 2.0
PROJECT_ID = r"^[a-z][a-z0-9-]{1,30}[a-z0-9]$"
DIGEST = r"^sha256:[a-f0-9]{64}$"
APPROVAL_ID = r"^[A-Za-z0-9_-]{16,64}$"
_CAPTURE = TypeAdapter(Capture | FilesystemCapture)


def _now() -> float:  # replaced by tests; the executor otherwise uses the wall clock
    return time.time()


def _monotonic() -> float:  # replaced by tests
    return time.monotonic()


def _sleep(seconds: float) -> None:  # replaced by tests
    time.sleep(seconds)


class _Params(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UpdateValidateParams(_Params):
    project_id: str = Field(pattern=PROJECT_ID)
    digest: str = Field(pattern=DIGEST)
    attestation: dict[str, Any]
    approval: dict[str, Any]


class ApplyVerifiedImageParams(_Params):
    project_id: str = Field(pattern=PROJECT_ID)
    approval_id: str = Field(pattern=APPROVAL_ID)
    digest: str = Field(pattern=DIGEST)
    emergency_confirm: bool = Field(
        False,
        strict=True,
        description="Operator only: apply outside the maintenance window (audited, announced).",
    )
    emergency_reason: str | None = Field(None, pattern=REASON_PATTERN)

    @model_validator(mode="after")
    def _emergency_needs_reason(self) -> ApplyVerifiedImageParams:
        if self.emergency_confirm != (self.emergency_reason is not None):
            raise ValueError("emergency_confirm and emergency_reason go together")
        return self


class UpdateStatusParams(_Params):
    project_id: str = Field(pattern=PROJECT_ID)


# ---- helpers -------------------------------------------------------------------------


def _ledger(ex: Executor) -> UpdateLedger:
    if getattr(ex, "update_ledger", None) is None:
        ex.update_ledger = UpdateLedger(ex._db)
    return ex.update_ledger


def _adapter(ex: Executor) -> RemediationAdapter:
    if getattr(ex, "remediation", None) is None:
        ex.remediation = HostImageRemediation(ex.host, Paths(registry=Path(ex.registry_path)))
    adapter = ex.remediation
    if not adapter.health():
        raise ExecutorError("unavailable", "image update host operations are not available")
    return adapter


def _contract(registry: dict[str, Any], project: str) -> tuple[dict[str, Any], UpdatePolicy]:
    spec = registry["projects"].get(project)
    if spec is None:
        raise ExecutorError("policy_denied", "project is not registered")
    if not spec.get("update"):
        raise ExecutorError("policy_denied", "project has no verified update contract")
    if not spec["deploy"]:
        raise ExecutorError("policy_denied", "project is configured as stopped (deploy: false)")
    try:
        return spec, UpdatePolicy.model_validate(spec["update"])
    except ValidationError:
        raise ExecutorError("policy_denied", "update contract in the registry is invalid") from None


def _deny(exc: UpdateRejected) -> ExecutorError:
    error_class = {"expired": "expired", "replay": "replay", "in_progress": "target_busy"}.get(
        exc.code, "policy_denied"
    )
    return ExecutorError(error_class, f"update evidence rejected: {exc.code}")


def _fail(exc: RemediationError) -> ExecutorError:
    error_class = exc.error_class
    if error_class not in ("conflict", "policy_denied", "execution_failed", "unavailable"):
        error_class = "execution_failed"
    return ExecutorError(error_class, exc.message)


def _latest_capture(
    ex: Executor, project: str, registry: dict[str, Any], spec: dict
) -> float | None:
    """Completion time of the newest executor capture bound to the current deployment."""
    spool = Path(ex._db_path).parent / "captures" / project
    newest: float | None = None
    try:
        entries = sorted(spool.iterdir())[:64]
    except OSError:
        return None
    for entry in entries:
        manifest = entry / "manifest.json"
        try:
            if entry.is_symlink() or manifest.is_symlink() or manifest.stat().st_size > 65536:
                continue
            capture = _CAPTURE.validate_json(manifest.read_bytes())
        except (OSError, ValidationError, ValueError):
            continue
        binding = capture.binding
        if (
            binding.server == registry["server_name"]
            and binding.project == project
            and binding.config_revision == registry["config_revision"]
            and binding.image == spec["image"]
            and binding.source_revision == spec["source_revision"]
        ):
            newest = max(newest or 0.0, capture.completed_at)
    return newest


class _VerificationFailed(Exception):
    pass


def _verify(
    ex: Executor,
    adapter: RemediationAdapter,
    plan: ApplyPlan,
    expected_id: str | None,
    timeout_s: int,
) -> dict[str, Any]:
    """Observe the actual state; only a complete positive observation is success."""
    from .server import _container_hardening, load_registry, probe_health

    deadline = _monotonic() + timeout_s
    while True:
        reason = "not observed"
        try:
            spec = load_registry(ex.registry_path)["projects"][plan.project]
            observed = adapter.observe(plan)
            if not observed.running:
                reason = "container is not running"
            elif expected_id is not None and observed.image_id != expected_id:
                reason = "running image does not match the approved digest"
            elif observed.image_id is None:
                reason = "running image identity is unknown"
            else:
                health = probe_health(ex.host, spec)
                hardening = _container_hardening(observed.container, spec)
                if not health["ok"]:
                    reason = f"health is {health.get('state', 'not ok')}"
                elif hardening["violations"]:
                    reason = "isolation violations: " + ",".join(hardening["violations"])
                else:
                    return {
                        "running_image_id": observed.image_id,
                        "image_verified": expected_id is not None,
                        "health": health.get("state"),
                        "isolation_violations": [],
                    }
        except (OSError, KeyError, ValueError) as exc:
            reason = f"observation failed: {type(exc).__name__}"
        if _monotonic() >= deadline:
            raise _VerificationFailed(reason)
        _sleep(VERIFY_POLL_S)


def _expected_id(ex: Executor, image: str) -> str | None:
    identity = ex.host.configured_image_identity(image) or {}
    if identity.get("manifest_digest") != image.rsplit("@", 1)[1]:
        return None
    return image_id(identity.get("id"))


def _revert(ex, adapter, ledger, approval_id, plan, contract, reason: str) -> ExecutorError:
    """Restore the previous image after a failed apply; report the outcome honestly."""
    from .update_recovery import RecoveryFailed, restore_before_revert, restore_fallback

    ledger.journal(approval_id, phase="reverting", reason=reason[:200])
    try:
        restore_before_revert(ex, ledger, approval_id, plan)  # data first, when captured
        try:
            adapter.install(plan, "old")
            adapter.restart(plan)
            _verify(ex, adapter, plan, _expected_id(ex, plan.old_image), contract.verify_timeout_s)
        except (RemediationError, _VerificationFailed):
            # A `reversible` update's old image could not run on the new data: fall back to
            # the exact capture taken before the update (newer data is preserved).
            if not restore_fallback(ex, ledger, approval_id, plan):
                raise
            adapter.install(plan, "old")
            adapter.restart(plan)
            _verify(ex, adapter, plan, _expected_id(ex, plan.old_image), contract.verify_timeout_s)
    except (RemediationError, _VerificationFailed, ExecutorError, RecoveryFailed) as exc:
        ledger.finish(approval_id, "revert_failed", phase="revert_failed", reverted=False)
        ex.audit.append(
            "update_apply",
            project_id=plan.project,
            approval_id=approval_id,
            outcome="revert_failed",
            reason=reason[:200],
        )
        return ExecutorError(
            "execution_failed",
            f"update failed ({reason}); previous image could not be restored: "
            f"{getattr(exc, 'message', str(exc))[:100]}",
        )
    ledger.finish(approval_id, "failed", phase="reverted", reverted=True)
    ex.audit.append(
        "update_apply",
        project_id=plan.project,
        approval_id=approval_id,
        outcome="failed_reverted",
        reason=reason[:200],
    )
    return ExecutorError("execution_failed", f"update failed ({reason}); previous image restored")


def _complete(ex, adapter, ledger, approval_id, plan, contract, expected_id) -> dict[str, Any]:
    """Install, restart and verify the new image; revert on any failure."""
    try:
        ledger.journal(approval_id, phase="installing")
        adapter.install(plan, "new")
        ledger.journal(approval_id, phase="installed")
        adapter.restart(plan)
        ledger.journal(approval_id, phase="restarted")
        facts = _verify(ex, adapter, plan, expected_id, contract.verify_timeout_s)
    except RemediationError as exc:
        raise _revert(ex, adapter, ledger, approval_id, plan, contract, exc.message) from None
    except _VerificationFailed as exc:
        raise _revert(ex, adapter, ledger, approval_id, plan, contract, str(exc)) from None
    ledger.finish(approval_id, "applied", phase="verified", applied_at=_now(), **facts)
    ex.audit.append(
        "update_apply",
        project_id=plan.project,
        approval_id=approval_id,
        outcome="applied",
        image=plan.new_image,
        config_revision=plan.new_config_revision,
    )
    return {
        "project_id": plan.project,
        "approval_id": approval_id,
        "state": "applied",
        "image": plan.new_image,
        "previous_image": plan.old_image,
        "config_revision": plan.new_config_revision,
        "verified": facts,
    }


def _recover_locked(ex, adapter, ledger, project: str, registry: dict[str, Any]) -> list[str]:
    """Finish or revert an apply (or finish a rollback) whose worker died.

    Caller holds both target locks."""
    from .update_recovery import recover_capture_phase, resume_rollbacks

    outcomes = []
    for approval_id in ledger.applying(project):
        row = ledger.get(approval_id)
        journal = row["journal"]
        phase = journal.get("phase")
        if phase in ("capturing", "captured", "capture_failed"):
            # The workload may be stopped; the previous image is still installed.
            spec = registry["projects"][project]
            contract = UpdatePolicy.model_validate(spec["update"])
            outcomes.append(
                f"{approval_id}:"
                + recover_capture_phase(
                    ex,
                    adapter,
                    ledger,
                    approval_id,
                    adapter.resume_plan(project, journal),
                    contract,
                    journal,
                )
            )
            continue
        if phase not in ("installing", "installed", "restarted", "reverting"):
            # Nothing was written to the desired state yet: the update never started.
            ledger.finish(approval_id, "failed", reason="interrupted before installation")
            outcomes.append(f"{approval_id}:abandoned")
            continue
        spec = registry["projects"][project]
        contract = UpdatePolicy.model_validate(spec["update"])
        plan = adapter.resume_plan(project, journal)
        try:
            if phase == "reverting":
                _revert(ex, adapter, ledger, approval_id, plan, contract, "interrupted revert")
            elif journal.get("migration", "none") != "none":
                # The new image may already have migrated data: never run it again.
                _revert(
                    ex,
                    adapter,
                    ledger,
                    approval_id,
                    plan,
                    contract,
                    "interrupted update with a data migration is reverted, not repeated",
                )
            else:
                expected = journal.get("expected_image_id")
                _complete(ex, adapter, ledger, approval_id, plan, contract, expected)
        except ExecutorError:
            pass  # the ledger holds the honest outcome (failed or revert_failed)
        outcomes.append(f"{approval_id}:{ledger.get(approval_id)['state']}")
    outcomes += resume_rollbacks(ex, adapter, ledger, project, registry)
    return outcomes


def recover_updates(ex: Executor, *, automatic: bool = True) -> list[str]:
    """After a restart: complete or revert every interrupted apply, never blindly repeat."""
    from .server import load_registry

    ledger = _ledger(ex)
    pending = [*ledger.applying(), *ledger.rolling_back()]
    if not pending or (automatic and ex.host.kill_switch()):
        return []
    adapter = _adapter(ex)
    outcomes: list[str] = []
    for project in sorted({ledger.get(a)["project"] for a in pending}):
        try:
            with ex.target_lock("deployment-execution"):
                registry = load_registry(ex.registry_path)
                with ex.target_lock(f"project-{project}"):
                    outcomes += _recover_locked(ex, adapter, ledger, project, registry)
        except ExecutorError as exc:
            ex.audit.append("update_apply", project_id=project, outcome=exc.error_class)
    return outcomes


# ---- actions -------------------------------------------------------------------------


def update_validate(ex: Executor, params: UpdateValidateParams, _role: str, registry: dict):
    spec, contract = _contract(registry, params.project_id)
    ledger = _ledger(ex)
    try:
        update = validate_update(
            contract,
            server=registry["server_name"],
            project=params.project_id,
            config_revision=registry["config_revision"],
            current_image=spec["image"],
            candidate_digest=params.digest,
            attestation=params.attestation,
            approval=params.approval,
            now=_now(),
        )
        if ledger.pending_count() >= MAX_PENDING_APPROVALS:
            raise ExecutorError("unavailable", "too many pending update approvals")
        outcome = ledger.record(update, params.attestation, params.approval)
    except UpdateRejected as exc:
        raise _deny(exc) from None
    ex.audit.append(
        "update_validate",
        project_id=params.project_id,
        approval_id=update.approval_id,
        image=update.image,
        outcome=outcome,
    )
    return {
        "project_id": params.project_id,
        "approval_id": update.approval_id,
        "state": "validated",
        "repeat": outcome == "same",
        "image": update.image,
        "version": update.version,
        "expires_at": update.expires_at,
    }


def apply_verified_image(
    ex: Executor, params: ApplyVerifiedImageParams, role: str, registry: dict[str, Any]
):
    from .server import load_registry
    from .update_recovery import admit_recovery, capture_before_update

    adapter = _adapter(ex)
    ledger = _ledger(ex)
    with ex.target_lock("deployment-execution"):
        if ex.deployment_fence() is not None:
            raise ExecutorError("target_busy", "deployment recovery is pending")
        registry = load_registry(ex.registry_path)
        spec, contract = _contract(registry, params.project_id)
        with ex.target_lock(f"project-{params.project_id}"):
            if ex.backup_pause(params.project_id) is not None:
                raise ExecutorError("unavailable", "backup pause recovery is pending")
            ex.ensure_group_restart_allowed(registry, spec)
            if params.emergency_confirm:
                refuse_automatic(ex, role, params.project_id, params.approval_id)
            if role != "operator":
                if registry.get("automation_profile") != "patch":
                    raise ExecutorError("policy_denied", "automatic updates need the patch profile")
                if ex.host.kill_switch():
                    raise ExecutorError("kill_switch", "automatic updates are stopped")
            try:
                # An interrupted apply of this project is completed or reverted first.
                _recover_locked(ex, adapter, ledger, params.project_id, registry)
                registry = load_registry(ex.registry_path)
                spec, contract = _contract(registry, params.project_id)
                row = ledger.get(params.approval_id)
                if row is None or row["project"] != params.project_id:
                    raise UpdateRejected("unknown_approval", "approval was not validated")
                if row["state"] != "validated":
                    raise UpdateRejected(
                        {"applying": "in_progress", "invalidated": "invalidated"}.get(
                            row["state"], "replay"
                        )
                    )
                now = _now()
                try:
                    update = validate_update(
                        contract,
                        server=registry["server_name"],
                        project=params.project_id,
                        config_revision=registry["config_revision"],
                        current_image=spec["image"],
                        candidate_digest=params.digest,
                        attestation=row["attestation"],
                        approval=row["approval"],
                        now=now,
                    )
                except UpdateRejected as exc:
                    if exc.code in ("revision_mismatch", "policy_mismatch", "already_current"):
                        ledger.invalidate(
                            params.approval_id
                        )  # a binding changed: never valid again
                    raise
                if update.binding != row["binding"]:
                    ledger.invalidate(params.approval_id)
                    raise UpdateRejected("approval_conflict", "bindings changed since validation")
                emergency = window_allows_or_emergency(
                    registry,
                    contract,
                    now,
                    emergency=params.emergency_confirm,
                    check_window=_require_window,
                )
                mode = admit_recovery(
                    ex, registry, spec, params.project_id, update.migration
                )  # before any side effect: an unrecoverable migration is refused here
                if spec.get("has_data"):
                    require_fresh_backup(
                        _latest_capture(ex, params.project_id, registry, spec),
                        now=now,
                        max_age_s=contract.backup_max_age_s,
                    )
                plan = adapter.plan(
                    registry, params.project_id, update.image, update.source_revision
                )
                if role != "operator":
                    ex.spend_budget(
                        params.project_id, "apply_verified_image", UPDATE_BUDGET_PER_HOUR
                    )
                ledger.claim(params.approval_id)
            except UpdateRejected as exc:
                raise _deny(exc) from None
            except RemediationError as exc:
                raise _fail(exc) from None

            ledger.journal(
                params.approval_id,
                phase="prepare",
                started_at=now,
                migration=update.migration,
                recovery_mode=mode,
                **plan.journal(),
            )
            if emergency:
                announce(ex, plan.project, params.approval_id, params.emergency_reason or "")
                ledger.journal(params.approval_id, emergency_reason=params.emergency_reason)
            ex.audit.append(
                "update_apply",
                project_id=plan.project,
                approval_id=params.approval_id,
                outcome="started",
                image=plan.new_image,
            )
            try:
                expected_id = adapter.prepare(plan)
            except RemediationError as exc:
                ledger.finish(params.approval_id, "failed", phase="prepare", reason=exc.message)
                ex.audit.append(
                    "update_apply",
                    project_id=plan.project,
                    approval_id=params.approval_id,
                    outcome="failed_prepare",
                )
                raise _fail(exc) from None
            if role != "operator" and ex.host.kill_switch():
                # The fetch can take minutes: recheck before touching the desired state.
                ledger.finish(params.approval_id, "failed", phase="prepare", reason="kill switch")
                raise ExecutorError("kill_switch", "automatic updates are stopped")
            ledger.journal(params.approval_id, phase="prepared", expected_image_id=expected_id)
            if mode in CAPTURE_MODES:
                capture_before_update(
                    ex,
                    adapter,
                    ledger,
                    plan,
                    registry,
                    params.approval_id,
                    contract,
                    automatic=role != "operator",
                    rehearse=mode == "restore_required",
                )
            return _complete(ex, adapter, ledger, params.approval_id, plan, contract, expected_id)


def _require_window(registry: dict[str, Any], contract: UpdatePolicy, now: float) -> None:
    window = registry.get("maintenance")
    if not window:
        raise ExecutorError("policy_denied", "no maintenance window is configured")
    admission = admit(
        window["weekly_window"],
        datetime.fromtimestamp(now, UTC),
        work_seconds=contract.apply_seconds,
    )
    if not admission.allowed:
        raise ExecutorError("policy_denied", f"outside the maintenance window: {admission.reason}")


def update_status(ex: Executor, params: UpdateStatusParams, _role: str, registry: dict):
    if params.project_id not in registry["projects"]:
        raise ExecutorError("policy_denied", "project is not registered")
    out: dict[str, Any] = {
        "project_id": params.project_id,
        "approvals": _ledger(ex).summaries(params.project_id),
    }
    update = registry["projects"][params.project_id].get("update")
    if isinstance(update, dict) and isinstance(update.get("verify_timeout_s"), int):
        out["verify_timeout_s"] = update["verify_timeout_s"]  # lets callers size their timeout
    if isinstance(update, dict):
        try:
            policy = UpdatePolicy.model_validate(update)
            out["rollback_window_s"] = policy.effective_rollback_window_s
            out["min_healthy_s"] = policy.effective_min_healthy_s
        except ValidationError:
            pass  # unreadable settings: callers fall back to the safe "do nothing"
    return out


def register(actions: dict, action_cls) -> None:
    from .update_recovery import register as register_recovery
    from .update_retention import register as register_retention

    register_recovery(actions, action_cls)
    register_retention(actions, action_cls)
    operating = frozenset({"operator", "controller"})
    actions["update_validate"] = action_cls(UpdateValidateParams, operating, True, update_validate)
    actions["apply_verified_image"] = action_cls(
        ApplyVerifiedImageParams, operating, True, apply_verified_image
    )
    actions["update_status"] = action_cls(
        UpdateStatusParams, frozenset({"operator", "controller", "api"}), False, update_status
    )
