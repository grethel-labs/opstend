"""Root-only command executor for the signed native PVE installation."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import stat
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType

from pydantic import ValidationError

from steward.core import pve_native as native
from steward.core import pve_native_install as install
from steward.core.audit import AuditLog
from steward.core.canonical import canonical_json
from steward.core.pve_inventory_models import Projection, Vmid
from steward.core.pve_power import (
    GuestState,
    GuestTarget,
    JobId,
    JobRecord,
    LegOperation,
    PowerJournal,
    PowerJournalError,
    PowerLeg,
    PowerOperation,
    PowerPolicy,
    Upid,
    _installed_power_runtime,
)
from steward.executor.protocol import PROTOCOL_VERSION, ExecutorError
from steward.executor.pve_power_api import (
    DISPATCH_TASK_WINDOW_S,
    PowerApi,
    verify_local_lxc_state,
    verify_local_pending,
)

_STATE = Path("/var/lib/opstend-pve-executor")
_POLICY = "power.json"
_AUDIT = "audit.jsonl"
_MAX_REQUEST = 4096
_CONFIRM_TTL = timedelta(minutes=5)


class _PlanParams(Projection):
    vmid: Vmid
    operation: PowerOperation


class _JobParams(Projection):
    job_id: JobId


class _ExecuteParams(_JobParams):
    continue_reboot: bool = False


class _ReconcileParams(_JobParams):
    upid: Upid | None = None


@dataclass(frozen=True)
class _Action:
    params: type[Projection]
    method: str


_ACTIONS = MappingProxyType(
    {
        "pve_power_plan": _Action(_PlanParams, "plan"),
        "pve_power_execute": _Action(_ExecuteParams, "execute"),
        "pve_power_status": _Action(_JobParams, "status"),
        "pve_power_reconcile": _Action(_ReconcileParams, "reconcile"),
    }
)


@dataclass(frozen=True)
class _Authority:
    policy: PowerPolicy
    binding: str
    api: PowerApi


def _now() -> datetime:
    return datetime.now(UTC)


class PowerExecutor:
    def __init__(
        self,
        journal: PowerJournal,
        audit: AuditLog,
        authority: Callable[[], _Authority],
        load_policy: Callable[[], PowerPolicy],
        kill_switch: Callable[[], bool],
        pending_check: Callable[[GuestTarget], None],
        state_check: Callable[[GuestTarget, GuestState], None],
        now: Callable[[], datetime] = _now,
    ):
        self.journal = journal
        self.audit = audit
        self.authority = authority
        self.load_policy = load_policy
        self.kill_switch = kill_switch
        self.pending_check = pending_check
        self.state_check = state_check
        self.now = now

    def _get(self, job_id: JobId) -> JobRecord:
        job = self.journal.get(job_id)
        if job is None:
            raise ExecutorError("policy_denied", "No such native power job.")
        return job

    def _save(self, before: JobRecord, **changes) -> JobRecord:
        after = before.model_copy(
            update={"updated_at": max(before.updated_at, self.now()), **changes}
        )
        self.journal.write(after, previous=before)
        return after

    def _fail(self, job: JobRecord, error: str, **changes) -> JobRecord:
        return self._save(job, state="failed", next_action=None, error_code=error, **changes)

    @staticmethod
    def _guest(authority: _Authority, target: GuestTarget, operation: PowerOperation):
        guest = authority.policy.guest(target.vmid)
        if guest is None or (
            target.node != authority.policy.node
            or target.kind != guest.kind
            or operation not in guest.operations
        ):
            raise ExecutorError(
                "policy_denied", "Guest operation is outside the native power policy."
            )
        return guest

    def _observe(self, authority: _Authority, target: GuestTarget, operation: PowerOperation):
        guest = self._guest(authority, target, operation)
        observed = authority.api.observe(target)
        if (observed.pve_uid, observed.registered_at_ms) != (guest.pve_uid, guest.registered_at_ms):
            raise ExecutorError("conflict", "The registered guest generation changed.")
        self.state_check(target, observed.state)
        self.pending_check(target)
        return observed

    def plan(self, params: _PlanParams) -> JobRecord:
        authority = self.authority()
        guest = authority.policy.guest(params.vmid)
        if guest is None:
            raise ExecutorError("policy_denied", "Guest is outside the native power policy.")
        target = GuestTarget(node=authority.policy.node, kind=guest.kind, vmid=guest.vmid)
        return self._plan(authority, target, params.operation, uuid.uuid4().hex)

    def _plan(
        self,
        authority: _Authority,
        target: GuestTarget,
        operation: PowerOperation,
        job_id: JobId,
        *,
        fleet_origin: str | None = None,
        deadline: datetime | None = None,
    ) -> JobRecord:
        self._guest(authority, target, operation)
        authority.api.validate_permissions(authority.policy)
        observed = self._observe(authority, target, operation)
        required = "stopped" if operation == "start" else "running"
        if observed.state != required:
            raise ExecutorError("conflict", "Guest power state does not allow this operation.")
        now = self.now()
        expires = now + _CONFIRM_TTL
        if deadline is not None:
            expires = min(expires, deadline)
        if expires <= now:
            raise ExecutorError("conflict", "The native plan has expired.")
        job = JobRecord(
            schema_version=1,
            job_id=job_id,
            operation=operation,
            target=target,
            policy_revision=authority.policy.revision,
            binding=authority.binding,
            observation=observed,
            created_at=now,
            expires_at=expires,
            updated_at=now,
            state="prepared",
            current_state=observed.state,
            next_action="execute",
            error_code=None,
            legs=(),
            fleet_origin=fleet_origin,
        )
        self.journal.write(job, previous=None)
        return job

    def status(self, params: _JobParams) -> JobRecord:
        return self._get(params.job_id)

    def _expired(self, job: JobRecord) -> bool:
        return not job.created_at <= self.now() < job.expires_at

    @staticmethod
    def _check_origin(job: JobRecord, fleet_origin: str | None) -> None:
        if job.fleet_origin != fleet_origin:
            raise ExecutorError("policy_denied", "The native job belongs to another origin.")

    def execute(
        self,
        params: _ExecuteParams,
        *,
        fleet_origin: str | None = None,
        fleet_check: Callable[[], bool] | None = None,
    ) -> JobRecord:
        job = self._get(params.job_id)
        self._check_origin(job, fleet_origin)
        if fleet_origin is not None and fleet_check is None:
            raise ExecutorError("policy_denied", "Fleet dispatch requires a live admission check.")
        if job.next_action != "execute":
            return job
        if params.continue_reboot != bool(job.legs):
            if not params.continue_reboot:
                # Repeating the first confirmation cannot dispatch a reboot's second leg.
                return job
            raise ExecutorError("conflict", "The job has no verified reboot to continue.")
        if job.legs and not (
            job.operation == "reboot"
            and job.state == "verifying"
            and len(job.legs) == 1
            and job.legs[0].state == "succeeded"
            and job.current_state == "stopped"
        ):
            raise ExecutorError("conflict", "The recorded shutdown is unverified.")
        if self._expired(job):
            return self._fail(job, "confirmation_expired")
        self._check_kill_switch()
        authority = self.authority()
        if authority.policy.revision != job.policy_revision or authority.binding != job.binding:
            return self._fail(job, "policy_changed")
        self._guest(authority, job.target, job.operation)
        authority.api.validate_permissions(authority.policy)
        operation = "start" if job.operation == "start" or job.legs else "shutdown"
        baseline_since = int(self.now().timestamp())
        prior_upids = authority.api.recent_tasks(job.target, operation, since=baseline_since)
        try:
            observed = self._observe(authority, job.target, job.operation)
        except ExecutorError as error:
            if error.error_class in ("conflict", "policy_denied"):
                return self._fail(job, "guest_changed")
            raise
        state_unchanged = observed.state == "stopped" if job.legs else observed == job.observation
        if not state_unchanged:
            return self._fail(job, "state_changed", current_state=observed.state)
        if self.load_policy().revision != job.policy_revision:
            return self._fail(job, "policy_changed")
        self._check_kill_switch()
        if self._expired(job):
            return self._fail(job, "confirmation_expired")
        if fleet_check is not None and not fleet_check():
            return self._fail(job, "fleet_admission_changed")
        return self._dispatch(
            job, authority, operation, observed.state, prior_upids, baseline_since, fleet_check
        )

    def _check_kill_switch(self) -> None:
        if self.kill_switch():
            raise ExecutorError("kill_switch", "Native PVE power operations are stopped.")

    def _dispatch(
        self,
        job: JobRecord,
        authority: _Authority,
        operation: LegOperation,
        current_state: GuestState,
        prior_upids: tuple[str, ...],
        baseline_since: int,
        fleet_check: Callable[[], bool] | None = None,
    ) -> JobRecord:
        self.audit.append(
            "pve_power_dispatch_intent",
            job_id=job.job_id,
            vmid=job.target.vmid,
            operation=operation,
        )
        dispatched_at = self.now()
        if dispatched_at.timestamp() < baseline_since:
            raise ExecutorError("conflict", "The clock changed during native task admission.")
        leg = PowerLeg(
            operation=operation,
            dispatched_at=dispatched_at,
            actor=authority.api.actor,
            state="dispatching",
            upid=None,
            prior_upids=prior_upids,
        )
        job = self._save(
            job,
            legs=(*job.legs, leg),
            state="dispatching",
            current_state=current_state,
            next_action="reconcile",
            error_code=None,
        )
        if fleet_check is not None and not fleet_check():
            return self._dispatch_failed(job, leg, "fleet_admission_changed")
        if self.kill_switch():
            return self._dispatch_failed(job, leg, "kill_switch")
        if self._expired(job):
            return self._dispatch_failed(job, leg, "confirmation_expired")
        try:
            upid = authority.api.dispatch(
                job.target, operation, dispatched_at=leg.dispatched_at.timestamp()
            )
        except ExecutorError as error:
            if not error.outcome_unknown:
                error_code = {
                    "policy_denied": "native_permission_denied",
                    "unavailable": "native_not_sent",
                }.get(error.error_class)
                if error_code is not None:
                    return self._dispatch_failed(job, leg, error_code)
            return self._uncertain(job)
        if upid in prior_upids:
            return self._uncertain(job)
        return self._save(
            job,
            state="accepted",
            legs=(
                *job.legs[:-1],
                leg.model_copy(update={"state": "accepted", "upid": upid}),
            ),
        )

    def _dispatch_failed(self, job: JobRecord, leg: PowerLeg, error_code: str) -> JobRecord:
        failed = leg.model_copy(update={"state": "failed"})
        return self._fail(job, error_code, legs=(*job.legs[:-1], failed))

    def _uncertain(self, job: JobRecord) -> JobRecord:
        leg = job.legs[-1].model_copy(update={"state": "uncertain"})
        return self._save(
            job,
            state="uncertain",
            error_code="dispatch_unknown",
            legs=(
                *job.legs[:-1],
                leg,
            ),
        )

    def reconcile(self, params: _ReconcileParams, *, fleet_origin: str | None = None) -> JobRecord:
        job = self._get(params.job_id)
        self._check_origin(job, fleet_origin)
        if job.next_action != "reconcile":
            if params.upid is not None:
                raise ExecutorError("conflict", "This job does not need an unbound native task.")
            if job.state == "verifying" and self._expired(job):
                return self._fail(job, "confirmation_expired")
            return job
        if job.state == "dispatching":
            job = self._uncertain(job)
        leg = job.legs[-1]
        if params.upid is not None and leg.upid is not None and params.upid != leg.upid:
            raise ExecutorError("conflict", "This job already binds a different native task.")
        upid = leg.upid or params.upid
        if upid is None:
            return job

        authority = self.authority()
        if authority.binding != job.binding or authority.api.actor != leg.actor:
            raise ExecutorError("conflict", "Native target or task principal changed.")
        self._guest(authority, job.target, job.operation)
        authority.api.validate_permissions(authority.policy)
        if leg.upid is None:
            if leg.prior_upids is None:
                raise ExecutorError(
                    "conflict", "The dispatch has no protected native task baseline."
                )
            since = int(leg.dispatched_at.timestamp())
            candidates = authority.api.recent_tasks(
                job.target, leg.operation, since=since, until=since + DISPATCH_TASK_WINDOW_S
            )
            if set(candidates) - set(leg.prior_upids) != {upid}:
                raise ExecutorError(
                    "conflict", "The supplied task does not uniquely match the dispatch."
                )
        state = (
            "succeeded"
            if leg.state == "succeeded"
            else authority.api.task(
                job.target, leg.operation, upid, dispatched_at=leg.dispatched_at.timestamp()
            )
        )
        legs = (*job.legs[:-1], leg.model_copy(update={"state": state, "upid": upid}))
        if state == "failed":
            return self._fail(job, "native_task_failed", legs=legs, current_state=None)
        if state == "running":
            return self._save(job, state="accepted", legs=legs, error_code=None)

        job = self._save(job, state="verifying", legs=legs, error_code=None)
        observed = self._observe(authority, job.target, job.operation)
        if (observed.pve_uid, observed.registered_at_ms) != (
            job.observation.pve_uid,
            job.observation.registered_at_ms,
        ):
            raise ExecutorError("conflict", "The job's guest generation changed.")
        expected = "running" if leg.operation == "start" else "stopped"
        if observed.state != expected:
            return self._save(job, error_code="state_mismatch", current_state=observed.state)
        if job.operation == "reboot" and len(job.legs) == 1:
            if self._expired(job):
                return self._fail(job, "confirmation_expired", current_state=observed.state)
            if authority.policy.revision != job.policy_revision:
                return self._fail(job, "policy_changed", current_state=observed.state)
            return self._save(job, next_action="execute", current_state=observed.state)
        return self._save(job, state="succeeded", next_action=None, current_state=observed.state)

    def handle(self, raw: bytes) -> dict:
        action_name = "invalid"
        try:
            request = json.loads(
                raw,
                object_pairs_hook=native._unique_object,
                parse_constant=native._reject_api_constant,
            )
            if (
                not isinstance(request, dict)
                or request.keys() != {"v", "action", "params"}
                or type(request["v"]) is not int
                or request["v"] != PROTOCOL_VERSION
                or not isinstance(request["action"], str)
            ):
                raise ValueError
            action = _ACTIONS.get(request["action"])
            if action is None:
                raise ExecutorError("unknown_action", "This native power action is unregistered.")
            action_name = request["action"]
            params = action.params.model_validate(request["params"])
            job = getattr(self, action.method)(params)
        except (ValueError, RecursionError) as error:
            if isinstance(error, PowerJournalError):
                error_class = {
                    "target_busy": "target_busy",
                    "journal_conflict": "conflict",
                    "task_conflict": "conflict",
                }.get(error.code, "unavailable")
                failure = ExecutorError(
                    error_class, "The native power journal refused the request."
                )
            elif isinstance(error, ValidationError) or action_name == "invalid":
                failure = ExecutorError("bad_request", "Invalid native power request.")
            else:
                failure = ExecutorError("internal", "Native power processing failed.")
        except ExecutorError as error:
            failure = error
        else:
            self.audit.append(
                "pve_power_request",
                action=action_name,
                job_id=job.job_id,
                vmid=job.target.vmid,
                outcome=job.state,
                error_code=job.error_code,
            )
            return {"ok": True, "result": job.public()}
        self.audit.append("pve_power_request", action=action_name, outcome=failure.error_class)
        return _error(failure)


def _read_policy[T: Projection](path: Path, model: type[T]) -> T:
    try:
        install._object(path, stat.S_IFREG, 0o600, 0, 0)
        raw = native._read_file(path, 64 * 1024, private=True)
        document = json.loads(
            raw, object_pairs_hook=native._unique_object, parse_constant=native._reject_api_constant
        )
        policy = model.model_validate_json(canonical_json(document))
    except (install.InstallError, OSError, ValueError, RecursionError):
        raise ExecutorError(
            "unavailable", f"The native PVE policy {path.name} is missing or invalid."
        ) from None
    if policy.node != socket.gethostname().split(".", 1)[0]:
        raise ExecutorError(
            "policy_denied", f"The native PVE policy {path.name} targets another node."
        )
    return policy


def _policy() -> PowerPolicy:
    return _read_policy(_STATE / _POLICY, PowerPolicy)


def _authority(installed: dict, paths: dict[str, Path]) -> _Authority:
    policy = _policy()
    intent = installed["intent"]
    ca_file, health_token, *_ = intent["refs"]
    write_token = Path(policy.write_token_file)
    managed = (*paths.values(), _STATE, native._UNIT_DIR)
    aliases = [Path(health_token)]
    if "inventory_token_file" in intent:
        aliases.append(Path(intent["inventory_token_file"]))
    ca = Path(ca_file)
    try:
        install._credential(ca, managed, private=False)
        for token_file in (write_token, *aliases):
            install._credential(token_file, managed, private=True)
        token = native._load_token(write_token)
        actor = token.partition("=")[0]
        if any(
            write_token == ref
            or actor.casefold() == native._load_token(ref).partition("=")[0].casefold()
            for ref in aliases
        ):
            raise ExecutorError("policy_denied", "Use a dedicated PVE power token.")
        fingerprint = hashlib.sha256(native._read_file(ca, 1024 * 1024)).hexdigest()
        api = PowerApi(intent["api_name"], ca, token)
    except (native.PreflightError, OSError, ValueError):
        raise ExecutorError(
            "unavailable", "Native PVE power credentials are unavailable."
        ) from None
    binding = hashlib.sha256(
        canonical_json(
            {
                "reservation": installed["reservation"],
                "node": policy.node,
                "api_name": intent["api_name"],
                "ca_sha256": fingerprint,
                "actor": actor,
            }
        ).encode()
    ).hexdigest()
    return _Authority(policy, binding, api)


def _runtime_context() -> tuple[dict[str, Path], dict, AuditLog]:
    for parent in reversed(_STATE.parents):
        install._secure_directory(parent)
    install._directory(_STATE, 0o700, 0, 0)
    paths, installed, python = _installed_power_runtime()
    if (
        not sys.flags.isolated
        or not sys.dont_write_bytecode
        or Path(sys.prefix).resolve(strict=True) != python.parents[1]
    ):
        raise install.InstallError("Native power requires the active signed installation.")
    audit = _STATE / _AUDIT
    if native._exists(audit):
        install._object(audit, stat.S_IFREG, 0o600, 0, 0)
    return paths, installed, AuditLog(audit)


def _runtime() -> PowerExecutor:
    paths, installed, audit = _runtime_context()
    return _runtime_executor(paths, installed, audit)


def _runtime_executor(paths: dict[str, Path], installed: dict, audit: AuditLog) -> PowerExecutor:
    return PowerExecutor(
        PowerJournal(_STATE),
        audit,
        lambda: _authority(installed, paths),
        _policy,
        lambda: native._exists(_STATE / "kill-switch"),
        verify_local_pending,
        verify_local_lxc_state,
    )


def _error(error: ExecutorError) -> dict:
    return {"ok": False, "error_class": error.error_class, "message": error.message}


def execute_local(raw: bytes, *, uid: int) -> dict:
    if uid != 0:
        return _error(ExecutorError("unauthorized_peer", "Native power requires local root."))
    if len(raw) > _MAX_REQUEST:
        return _error(ExecutorError("bad_request", "Native power request is too large."))
    try:
        with install._locked():
            return _runtime().handle(raw)
    except (install.InstallError, OSError):
        return _error(
            ExecutorError("unavailable", "The native executor or its journal is unavailable.")
        )
    except Exception:  # noqa: BLE001 - retain the dispatch journal and keep private details out of IPC
        return _error(ExecutorError("internal", "Native power processing failed."))


def main() -> None:
    result = execute_local(sys.stdin.buffer.read(_MAX_REQUEST + 1), uid=os.geteuid())
    print(json.dumps(result, allow_nan=False))


if __name__ == "__main__":
    main()
