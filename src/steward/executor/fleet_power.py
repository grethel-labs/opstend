"""Root-only FL03 command polling through the current PX03 runtime."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from time import monotonic

from pydantic import Field

from steward.core import pve_native as native
from steward.core import pve_native_install as install
from steward.core.canonical import revision_id
from steward.core.fleet_native_profile import _local_binding
from steward.core.fleet_policy import RegistryId, RoleAssignment
from steward.core.fleet_policy_reconcile import respects_limits
from steward.core.fleet_policy_target import FleetPolicyTargetState, FleetPolicyTargetStore
from steward.core.fleet_power import (
    CommandPoll,
    CommandReport,
    CommandSpec,
    CommandWork,
    EnrollmentGeneration,
)
from steward.core.maintenance import regular_window
from steward.core.pve_inventory_models import Projection
from steward.core.pve_power import _PLAN_FIELDS, GuestTarget, JobRecord, _digest
from steward.executor import pve_power as power
from steward.executor.protocol import ExecutorError
from steward.executor.pve_power_api import DISPATCH_TASK_WINDOW_S
from steward.fleet_transport import FleetClient


class _Config(Projection):
    controller_url: str = Field(min_length=1, max_length=269)
    agent_id: RegistryId
    enrollment_generation: EnrollmentGeneration


def _private_file(directory: Path, name: str) -> Path:
    path = directory / name
    install._object(path, stat.S_IFREG, 0o600, 0, 0)
    return path


def _load_config(directory: Path) -> _Config:
    raw = native._read_file(_private_file(directory, "fleet-power.json"), 4096, private=True)
    json.loads(raw, object_pairs_hook=native._unique_object)
    return _Config.model_validate_json(raw)


def _native_digest(job: JobRecord) -> str:
    return revision_id(job.model_dump(mode="json", include=_PLAN_FIELDS))


def _admitted(state: FleetPolicyTargetState, spec: CommandSpec) -> bool:
    effective = state.effective
    return (
        effective is not None
        and state.local.target == spec.target
        and state.local.revision == spec.local_revision
        and state.applied_revision == spec.policy_revision
        and state.approval_id == spec.policy_approval
        and respects_limits(effective, state.local)
        and RoleAssignment(subject=spec.subject, role=spec.role)
        in effective.values.role_assignments
    )


def _window_open(windows: tuple[str, ...], now: datetime) -> bool:
    return not windows or any(regular_window(window, now).contains(now) for window in windows)


def _refused(work: CommandWork, reason: str) -> CommandReport:
    return CommandReport(
        command_id=work.spec.command_id,
        claim_id=work.claim_id,
        native_digest=work.native_digest,
        state="refused",
        reason=reason,
    )


def _report(work: CommandWork, job: JobRecord) -> CommandReport:
    if job.error_code == "no_dispatch":
        return _refused(work, "no_dispatch")
    state = {
        "prepared": "prepared",
        "dispatching": "uncertain",
        "accepted": "accepted",
        "verifying": "accepted",
        "uncertain": "uncertain",
        "succeeded": "succeeded",
        "failed": "failed",
    }[job.state]
    upid = job.legs[-1].upid if job.legs else None
    return CommandReport(
        command_id=job.job_id,
        claim_id=work.claim_id,
        native_digest=_native_digest(job),
        state=state,
        reason=job.error_code,
        task_ref=_digest(upid) if upid else None,
        observed_state=job.current_state if job.state != "prepared" else None,
    )


def _reconcile(executor: power.PowerExecutor, job: JobRecord, origin: str) -> JobRecord:
    """Use PX03's protected task baseline to find a uniquely attributable lost reply."""
    if job.next_action != "reconcile":
        return job
    leg = job.legs[-1]
    upid = None
    if leg.upid is None and leg.prior_upids is not None:
        since = int(leg.dispatched_at.timestamp())
        until = since + DISPATCH_TASK_WINDOW_S
        if executor.now().timestamp() >= until + 1:
            authority = executor.authority()
            if authority.binding != job.binding or authority.api.actor != leg.actor:
                return job
            executor._guest(authority, job.target, job.operation)
            authority.api.validate_permissions(authority.policy)
            candidates = set(
                authority.api.recent_tasks(job.target, leg.operation, since=since, until=until)
            ) - set(leg.prior_upids)
            if len(candidates) == 1:
                upid = candidates.pop()
    return executor.reconcile(
        power._ReconcileParams(job_id=job.job_id, upid=upid), fleet_origin=origin
    )


def _run_work(
    executor: power.PowerExecutor,
    state: FleetPolicyTargetState,
    config: _Config,
    work: CommandWork,
    started: float,
    *,
    clock: Callable[[], float] = monotonic,
    local_binding: Callable[[], tuple[str, str]] = _local_binding,
) -> CommandReport:
    spec = work.spec
    current_generation = config.enrollment_generation
    original_enrollment = spec.enrollment_generation == current_generation
    rotated_reconciliation = (
        work.phase == "reconcile" and spec.enrollment_generation < current_generation
    )
    if (
        spec.target != state.local.target
        or spec.agent_id != config.agent_id
        or work.recipient_generation != current_generation
        or not (original_enrollment or rotated_reconciliation)
    ):
        raise ValueError("Fleet work does not match this enrollment")
    origin = revision_id(spec.model_dump(mode="json"))
    target = GuestTarget(node=spec.scope.node, kind=spec.scope.kind, vmid=spec.scope.vmid)
    job = executor.journal.get(spec.command_id)
    if job is not None:
        if job.fleet_origin != origin or job.target != target:
            if work.phase == "prepare":
                return _refused(work, "native_origin_conflict")
            raise ValueError("Fleet work does not match the native job origin")
        if work.phase != "prepare" and work.native_digest != _native_digest(job):
            raise ValueError("Fleet work does not match the native plan digest")
    elif work.phase != "prepare":
        raise ValueError("Fleet work has no recoverable native plan")

    def instance_matches() -> bool:
        try:
            return local_binding() == (spec.scope.node, spec.scope.instance_binding)
        except (OSError, ValueError, subprocess.SubprocessError):
            return False

    def claim_live() -> bool:
        return clock() - started < work.valid_for_ms / 1000 and executor.now() < work.claim_until

    # Existing intent is durable evidence regardless of later policy changes.
    if job is not None and job.state != "prepared":
        if work.phase == "reconcile" and claim_live() and instance_matches():
            try:
                job = _reconcile(executor, job, origin)
            except ExecutorError:
                job = executor._get(spec.command_id)
        return _report(work, job)
    if work.phase == "reconcile":
        if not claim_live():
            raise ValueError("Fleet reconciliation claim expired")
        executor._fail(job, "no_dispatch")
        return _refused(work, "no_dispatch")
    if not _admitted(state, spec):
        return _refused(work, "local_policy_changed")
    windows = state.effective.values.maintenance_windows
    if not _window_open(windows, executor.now()):
        return _refused(work, "outside_maintenance_window")

    def can_dispatch() -> bool:
        if not instance_matches():
            return False
        now = executor.now()
        return _window_open(windows, now) and now < spec.expires_at and claim_live()

    if not can_dispatch():
        return _refused(work, "fleet_admission_changed")
    try:
        if work.phase == "execute":
            job = executor.execute(
                power._ExecuteParams(job_id=spec.command_id),
                fleet_origin=origin,
                fleet_check=can_dispatch,
            )
        elif job is not None:
            if executor._expired(job):
                return _refused(work, "confirmation_expired")
        else:
            executor._check_kill_switch()
            authority = executor.authority()
            guest = executor._guest(authority, target, "start")
            if (guest.pve_uid, guest.registered_at_ms) != (
                spec.scope.pve_uid,
                spec.scope.registered_at_ms,
            ):
                return _refused(work, "native_generation_changed")
            job = executor._plan(
                authority,
                target,
                "start",
                spec.command_id,
                fleet_origin=origin,
                deadline=spec.expires_at,
            )
    except ExecutorError as exc:
        recorded_job = executor.journal.get(spec.command_id)
        if recorded_job is not None and recorded_job.legs:
            return _report(work, recorded_job)
        return _refused(work, exc.error_class)
    return _report(work, job)


def _poll(
    executor: power.PowerExecutor,
    store: FleetPolicyTargetStore,
    client: FleetClient,
    config: _Config,
) -> CommandReport | None:
    with store.admission() as state:
        if state.applied_revision is None or state.approval_id is None:
            return None
        request = CommandPoll(
            target=state.local.target,
            local_revision=state.local.revision,
            policy_revision=state.applied_revision,
            policy_approval=state.approval_id,
        )
        started = monotonic()
        work = client.poll_power(request).work
        if work is None:
            return None
        report = _run_work(executor, state, config, work, started)
        executor.audit.append(
            "pve_fleet_power_result",
            job_id=report.command_id,
            vmid=work.spec.scope.vmid,
            outcome=report.state,
            error_code=report.reason,
        )
    if client.poll_power(request.model_copy(update={"report": report})).work is not None:
        raise ValueError("Fleet report response contained an unexpected claim")
    return report


def main() -> None:
    if os.geteuid() != 0 or len(sys.argv) != 1:
        print("Fleet power polling requires local root and no arguments.", file=sys.stderr)
        raise SystemExit(1)
    try:
        with install._locked():
            paths, installed, audit = power._runtime_context()
            config = _load_config(power._STATE)
            client = FleetClient(
                endpoint=config.controller_url,
                cert_file=_private_file(power._STATE, "fleet-client.crt"),
                key_file=_private_file(power._STATE, "fleet-client.key"),
                server_ca_file=_private_file(power._STATE, "fleet-controller-ca.crt"),
            )
            store = FleetPolicyTargetStore(_private_file(power._STATE, "fleet-policy.sqlite3"))
            result = _poll(power._runtime_executor(paths, installed, audit), store, client, config)
    except (
        ExecutorError,
        install.InstallError,
        OSError,
        RecursionError,
        ValueError,
        sqlite3.Error,
    ):
        print("Fleet power poll could not complete.", file=sys.stderr)
        raise SystemExit(1) from None
    print(json.dumps({"state": "idle"} if result is None else {"state": result.state}))


if __name__ == "__main__":
    main()
