"""Root-only schedule custody through the active signed native PVE runtime."""

import json
import os
import sqlite3
import subprocess
import sys
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager, nullcontext
from dataclasses import dataclass
from time import monotonic

from steward.core import pve_native as native
from steward.core import pve_native_install as install
from steward.core.fleet_adoption_models import NativeBackupJobId, pve_backup_job_ref
from steward.core.fleet_native_profile import _local_binding
from steward.core.fleet_ownership import (
    LocalOwnershipRequest,
    NativeOwnershipRecord,
    OwnershipExchange,
    OwnershipPlan,
    OwnershipReply,
)
from steward.core.fleet_policy import FleetTarget, PolicyName, RoleAssignment
from steward.core.fleet_policy_reconcile import respects_limits
from steward.core.fleet_policy_target import FleetPolicyTargetState, FleetPolicyTargetStore
from steward.core.pve_inventory_models import Projection
from steward.core.pve_power import PowerJournal, PowerJournalError
from steward.executor import pve_power as power
from steward.executor.fleet_power import _Config, _load_config, _private_file
from steward.executor.protocol import ExecutorError
from steward.executor.pve_schedule_ownership import verify_schedule
from steward.fleet_transport import FleetClient


class _ScheduleConfig(Projection):
    native_job_id: NativeBackupJobId
    profile: PolicyName


@dataclass(frozen=True)
class _Local:
    executor: power.PowerExecutor
    state: FleetPolicyTargetState
    config: _Config
    schedule: _ScheduleConfig


def _conflict(message: str) -> ExecutorError:
    return ExecutorError("conflict", message)


def _verify_current(
    executor: power.PowerExecutor,
    state: FleetPolicyTargetState,
    config: _Config,
    schedule: _ScheduleConfig,
    plan: OwnershipPlan,
    local_binding: Callable[[], tuple[str, str]],
    *,
    recovery: bool,
) -> None:
    effective = state.effective
    same_enrollment = plan.enrollment_generation == config.enrollment_generation
    rotated = recovery and plan.enrollment_generation < config.enrollment_generation
    if (
        state.local.target != plan.target
        or plan.agent_id != config.agent_id
        or not (same_enrollment or rotated)
        or plan.profile != schedule.profile
        or (
            not recovery
            and (
                effective is None
                or state.local.revision != plan.local_revision
                or state.applied_revision != plan.policy_revision
                or state.approval_id != plan.policy_approval
                or not respects_limits(effective, state.local)
                or RoleAssignment(subject=plan.subject, role="operator")
                not in effective.values.role_assignments
                or plan.profile not in effective.values.backup_profile_refs
            )
        )
    ):
        raise _conflict("The applied target policy, scope, or enrollment changed.")
    if (
        local_binding() != (plan.scope.node, plan.scope.instance_binding)
        or pve_backup_job_ref(plan.scope.instance_binding, schedule.native_job_id)
        != plan.schedule_ref
    ):
        raise _conflict("The native instance or registered schedule changed.")
    executor._check_kill_switch()
    authority = executor.authority()
    scope = plan.scope
    registered = authority.policy.guest(scope.vmid)
    if (
        registered is None
        or authority.policy.node != scope.node
        or registered.kind != scope.kind
        or (registered.pve_uid, registered.registered_at_ms)
        != (scope.pve_uid, scope.registered_at_ms)
    ):
        raise _conflict("The registered native guest generation changed.")
    if recovery:
        observed = authority.api.observe(scope)
        if (observed.pve_uid, observed.registered_at_ms) != (
            scope.pve_uid,
            scope.registered_at_ms,
        ):
            raise _conflict("The observed native guest generation changed.")
    else:
        authority.api.validate_permissions(authority.policy)
        executor._observe(authority, scope, "start")
    if executor.load_policy().revision != authority.policy.revision:
        raise _conflict("The native power policy changed.")


def _check_previous(plan: OwnershipPlan, record: NativeOwnershipRecord | None) -> None:
    if record is None:
        if plan.epoch != 0 or plan.previous_owner != "standalone":
            raise _conflict("Initial ownership must come from standalone epoch zero.")
        return
    previous = record.plan
    if (
        record.state not in {"active", "canceled"}
        or plan.previous_owner != record.owner
        or plan.epoch != record.epoch
        or plan.target != previous.target
        or plan.scope != previous.scope
        or plan.instance_id != previous.instance_id
        or plan.schedule_ref != previous.schedule_ref
    ):
        raise _conflict("The handoff does not follow the current native ownership epoch.")


class _Handoff:
    def __init__(
        self,
        executor: power.PowerExecutor,
        state: FleetPolicyTargetState,
        config: _Config,
        schedule: _ScheduleConfig,
        exchange: Callable[[OwnershipExchange], OwnershipReply],
        *,
        clock: Callable[[], float] = monotonic,
        local_binding: Callable[[], tuple[str, str]] = _local_binding,
        verify: Callable[..., str] = verify_schedule,
        local_context: Callable[[], AbstractContextManager[_Local]] | None = None,
    ) -> None:
        self.executor = executor
        self.target = state.local.target
        initial = _Local(executor, state, config, schedule)
        self.local_context = local_context or (lambda: nullcontext(initial))
        self.exchange = exchange
        self.clock = clock
        self.local_binding = local_binding
        self.verify = verify

    def _exchange(
        self,
        target: FleetTarget,
        transition_id: str,
        digest: str,
        record: NativeOwnershipRecord | None = None,
    ) -> OwnershipReply:
        reply = self.exchange(
            OwnershipExchange(
                target=target,
                transition_id=transition_id,
                digest=digest,
                receipt=record.receipt if record is not None else None,
            )
        )
        if (reply.plan.target, reply.plan.transition_id, reply.plan.digest) != (
            target,
            transition_id,
            digest,
        ) or (record is not None and reply.status != record.status):
            raise _conflict("The coordinator did not acknowledge this exact ownership state.")
        return reply

    def _acknowledge(self, record: NativeOwnershipRecord) -> None:
        self._exchange(record.plan.target, record.plan.transition_id, record.plan.digest, record)

    def _verify(self, local: _Local, plan: OwnershipPlan, *, enabled: bool, recovery: bool) -> str:
        _verify_current(
            local.executor,
            local.state,
            local.config,
            local.schedule,
            plan,
            self.local_binding,
            recovery=recovery,
        )
        return self.verify(plan, local.schedule.native_job_id, enabled=enabled)

    @staticmethod
    def _save(
        executor: power.PowerExecutor,
        record: NativeOwnershipRecord,
        previous: NativeOwnershipRecord | None,
        admit: Callable[[], None],
    ) -> None:
        executor.audit.append(
            "pve_writer_ownership_intent",
            transition_id=record.plan.transition_id,
            schedule_ref=record.plan.schedule_ref,
            vmid=record.plan.scope.vmid,
            subject=record.plan.subject,
            local_uid=0,
            owner=record.owner,
            epoch=record.epoch,
            state=record.state,
        )
        executor.journal.write_ownership(record, previous=previous, now=executor.now(), admit=admit)
        executor.audit.append(
            "pve_writer_ownership_recorded",
            transition_id=record.plan.transition_id,
            subject=record.plan.subject,
            local_uid=0,
            owner=record.owner,
            epoch=record.epoch,
            state=record.state,
        )

    def run(self, request: LocalOwnershipRequest) -> NativeOwnershipRecord:
        transition_id, digest = request.transition_id, request.digest
        if transition_id is None or digest is None:
            raise _conflict("Exact local transition confirmation is required.")
        before = self.executor.journal.ownership()
        exact = before is not None and (before.plan.transition_id, before.plan.digest) == (
            transition_id,
            digest,
        )
        if exact and before.state == "canceled":
            if request.action != "cancel":
                raise _conflict("The local transition was canceled.")
            self._acknowledge(before)
            return before
        if request.action == "prepare" and exact:
            return before
        if request.action in {"confirm", "resume"} and not exact:
            raise _conflict("The exact transition is absent from the native journal.")
        if request.action == "resume":
            return self._resume(before)
        if request.action == "confirm" and before.state != "pausing":
            self._acknowledge(before)
            return before
        if request.action == "cancel" and exact and before.state != "pausing":
            raise _conflict("The local ownership change is already committed.")

        started = self.clock()
        reply = self._exchange(self.target, transition_id, digest)
        if reply.status.state != "pausing":
            raise _conflict("The exact coordinator transition is no longer pausing.")
        with self.local_context() as local:
            self._verify_expected(local, before)
            if request.action == "cancel":
                record = self._cancel(local, reply.plan, before, staged=exact)
            else:
                record = self._advance(local, request, reply, before, started)
        if record.state != "pausing":
            self._acknowledge(record)
        return record

    @staticmethod
    def _verify_expected(local: _Local, before: NativeOwnershipRecord | None) -> None:
        if local.executor.journal.ownership() != before:
            raise _conflict("The native ownership journal changed during the request.")

    def _cancel(
        self,
        local: _Local,
        plan: OwnershipPlan,
        before: NativeOwnershipRecord | None,
        *,
        staged: bool,
    ) -> NativeOwnershipRecord:
        if not staged:
            _check_previous(plan, before)
        fingerprint = self._verify(local, plan, enabled=True, recovery=True)
        if before is not None and fingerprint != before.schedule_fingerprint:
            raise _conflict("The enabled schedule differs from the recorded definition.")
        record = NativeOwnershipRecord(
            plan=plan, state="canceled", schedule_fingerprint=fingerprint
        )
        self._save(local.executor, record, before, local.executor._check_kill_switch)
        return record

    def _advance(
        self,
        local: _Local,
        request: LocalOwnershipRequest,
        reply: OwnershipReply,
        before: NativeOwnershipRecord | None,
        started: float,
    ) -> NativeOwnershipRecord:
        claim = reply.claim

        def check_claim() -> None:
            local.executor._check_kill_switch()
            if (
                claim is None
                or self.clock() - started >= claim.valid_for_ms / 1000
                or local.executor.now() >= claim.claim_until
            ):
                raise _conflict("A live coordinator claim and drained fleet commands are required.")

        check_claim()
        plan = reply.plan
        if request.action == "prepare":
            _check_previous(plan, before)
            fingerprint = self._verify(local, plan, enabled=True, recovery=False)
            if before is not None and before.schedule_fingerprint != fingerprint:
                raise _conflict("The native schedule definition changed after the prior handoff.")
            record = NativeOwnershipRecord(
                plan=plan, state="pausing", schedule_fingerprint=fingerprint
            )
        else:
            fingerprint = self._verify(local, plan, enabled=False, recovery=False)
            if fingerprint != before.schedule_fingerprint:
                raise _conflict("The disabled schedule differs from the staged definition.")
            record = before.model_copy(update={"state": "committed"})
        self._save(local.executor, record, before, check_claim)
        return record

    def _resume(self, before: NativeOwnershipRecord) -> NativeOwnershipRecord:
        if before.state == "pausing":
            raise _conflict("Confirm the disabled schedule and ownership change before re-arming.")
        if before.state == "active":
            self._acknowledge(before)
            return before
        self._acknowledge(before)
        with self.local_context() as local:
            self._verify_expected(local, before)
            fingerprint = self._verify(local, before.plan, enabled=True, recovery=True)
            if fingerprint != before.schedule_fingerprint:
                raise _conflict("The enabled schedule differs from the committed definition.")
            record = before.model_copy(update={"state": "active"})
            self._save(local.executor, record, before, local.executor._check_kill_switch)
        self._acknowledge(record)
        return record


def _read_local_inputs() -> tuple[
    power.PowerExecutor, _Config, _ScheduleConfig, FleetPolicyTargetStore
]:
    paths, installed, audit = power._runtime_context()
    directory = power._STATE
    config = _load_config(directory)
    schedule_raw = native._read_file(
        _private_file(directory, "fleet-ownership.json"), power._MAX_REQUEST, private=True
    )
    json.loads(schedule_raw, object_pairs_hook=native._unique_object)
    schedule = _ScheduleConfig.model_validate_json(schedule_raw)
    store = FleetPolicyTargetStore(_private_file(directory, "fleet-policy.sqlite3"))
    return power._runtime_executor(paths, installed, audit), config, schedule, store


def _execute(request: LocalOwnershipRequest) -> dict:
    with install._locked():
        if request.action == "status":
            power._runtime_context()
            record = PowerJournal(power._STATE).ownership()
            if record is None:
                return {"owner": "standalone", "epoch": 0, "state": "unmanaged"}
            return record.status.model_dump(mode="json")
        executor, config, schedule, store = _read_local_inputs()
        state = store.state()
        directory = power._STATE
        client = FleetClient(
            endpoint=config.controller_url,
            cert_file=_private_file(directory, "fleet-client.crt"),
            key_file=_private_file(directory, "fleet-client.key"),
            server_ca_file=_private_file(directory, "fleet-controller-ca.crt"),
        )

    @contextmanager
    def local_context() -> Iterator[_Local]:
        # Match fleet power lock ordering. Coordinator exchanges run outside both locks.
        with install._locked():
            current, binding, definition, current_store = _read_local_inputs()
            if binding.controller_url != config.controller_url:
                raise _conflict("The configured coordinator changed during the request.")
            with current_store.admission() as admitted:
                yield _Local(current, admitted, binding, definition)

    result = _Handoff(
        executor,
        state,
        config,
        schedule,
        client.exchange_ownership,
        local_context=local_context,
    ).run(request)
    return result.status.model_dump(mode="json")


def main() -> None:
    if os.geteuid() != 0 or len(sys.argv) != 1:
        print("Native writer ownership requires local root and no arguments.", file=sys.stderr)
        raise SystemExit(1)
    try:
        raw = sys.stdin.buffer.read(power._MAX_REQUEST + 1)
        if len(raw) > power._MAX_REQUEST:
            raise ValueError
        json.loads(raw, object_pairs_hook=native._unique_object)
        request = LocalOwnershipRequest.model_validate_json(raw)
        result = _execute(request)
    except ExecutorError as exc:
        print(exc.message, file=sys.stderr)
        raise SystemExit(1) from None
    except PowerJournalError as exc:
        message = (
            "A native job for the guest is active or unresolved."
            if exc.code == "target_busy"
            else "The native ownership journal refused the request."
        )
        print(message, file=sys.stderr)
        raise SystemExit(1) from None
    except (
        install.InstallError,
        OSError,
        RecursionError,
        ValueError,
        sqlite3.Error,
        subprocess.SubprocessError,
    ):
        print(
            "Native ownership inputs, signed runtime, or coordinator are unavailable.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
    print(json.dumps(result, allow_nan=False))


if __name__ == "__main__":
    main()
