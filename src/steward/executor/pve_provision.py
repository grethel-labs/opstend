"""Root-only signed executor for native PVE full clones."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from pydantic import ValidationError

from steward.core import pve_native as native
from steward.core import pve_native_install as install
from steward.core.audit import AuditLog
from steward.core.canonical import canonical_json
from steward.core.pve_inventory_models import Projection, Vmid
from steward.core.pve_power import GuestTarget, JobId, PowerJournal, PowerJournalError, PowerPolicy
from steward.core.pve_provision import (
    CloneLeg,
    CloneUpid,
    ProvisionJob,
    ProvisionName,
    ProvisionPolicy,
    ProvisionTarget,
    ProvisionTemplate,
)
from steward.executor.protocol import PROTOCOL_VERSION, ExecutorError
from steward.executor.pve_power import (
    _CONFIRM_TTL,
    _MAX_REQUEST,
    _STATE,
    _error,
    _now,
    _read_policy,
    _runtime_context,
)
from steward.executor.pve_provision_api import CLONE_TASK_WINDOW_S, ProvisionApi, ProvisionEvidence


class _PlanParams(Projection):
    template_vmid: Vmid
    vmid: Vmid
    name: ProvisionName


class _JobParams(Projection):
    job_id: JobId


class _ReconcileParams(_JobParams):
    upid: CloneUpid | None = None


_ACTIONS = MappingProxyType(
    {
        "pve_provision_plan": (_PlanParams, "plan"),
        "pve_provision_execute": (_JobParams, "execute"),
        "pve_provision_status": (_JobParams, "status"),
        "pve_provision_reconcile": (_ReconcileParams, "reconcile"),
    }
)


@dataclass(frozen=True)
class _Authority:
    policy: ProvisionPolicy
    binding: str
    api: ProvisionApi


class ProvisionExecutor:
    def __init__(
        self,
        journal: PowerJournal,
        audit: AuditLog,
        authority: Callable[[], _Authority],
        kill_switch: Callable[[], bool],
        evidence: ProvisionEvidence,
        now=_now,
    ):
        self.journal = journal
        self.audit = audit
        self.authority = authority
        self.kill_switch = kill_switch
        self.evidence = evidence
        self.now = now

    def _get(self, job_id: JobId) -> ProvisionJob:
        job = self.journal.get_provision(job_id)
        if job is None:
            raise ExecutorError("policy_denied", "No such native provision job.")
        return job

    def _save(self, job: ProvisionJob, **changes) -> ProvisionJob:
        updated = job.model_copy(update={"updated_at": max(job.updated_at, self.now()), **changes})
        self.journal.write(updated, previous=job)
        return updated

    def _fail(self, job: ProvisionJob, code: str, **changes) -> ProvisionJob:
        return self._save(job, state="failed", next_action=None, error_code=code, **changes)

    @staticmethod
    def _scope(
        policy: ProvisionPolicy, template_vmid: Vmid, vmid: Vmid
    ) -> tuple[ProvisionTemplate, ProvisionTarget]:
        template = policy.template(template_vmid)
        destination = policy.target(vmid)
        if template is None or destination is None or destination.template_vmid != template_vmid:
            raise ExecutorError(
                "policy_denied", "The clone is outside the native provision policy."
            )
        return template, destination

    def plan(self, params: _PlanParams) -> ProvisionJob:
        authority = self.authority()
        policy = authority.policy
        template, destination = self._scope(policy, params.template_vmid, params.vmid)
        source = GuestTarget(node=policy.node, kind=template.kind, vmid=template.vmid)
        target = GuestTarget(node=policy.node, kind=template.kind, vmid=destination.vmid)
        authority.api.validate_permissions(policy)
        observation = self.evidence.observe_source(source, template, destination)
        now = self.now()
        job = ProvisionJob(
            schema_version=1,
            job_id=uuid.uuid4().hex,
            target=target,
            source=source,
            destination=destination,
            name=params.name,
            observation=observation,
            policy_revision=policy.revision,
            binding=authority.binding,
            created_at=now,
            expires_at=now + _CONFIRM_TTL,
            updated_at=now,
            state="prepared",
            next_action="execute",
        )
        self.journal.write(job, previous=None)
        return job

    def status(self, params: _JobParams) -> ProvisionJob:
        return self._get(params.job_id)

    def _expired(self, job: ProvisionJob) -> bool:
        return not job.created_at <= self.now() < job.expires_at

    @staticmethod
    def _same_authority(job: ProvisionJob, authority: _Authority) -> bool:
        return authority.policy.revision == job.policy_revision and authority.binding == job.binding

    def execute(self, params: _JobParams) -> ProvisionJob:
        job = self._get(params.job_id)
        if job.state != "prepared" or job.legs or job.next_action != "execute":
            return job
        if self._expired(job):
            return self._fail(job, "confirmation_expired")
        self._check_kill_switch()
        authority = self.authority()
        if not self._same_authority(job, authority):
            return self._fail(job, "policy_changed")
        template, destination = self._scope(authority.policy, job.source.vmid, job.target.vmid)
        authority.api.validate_permissions(authority.policy)
        baseline_since = int(self.now().timestamp())
        prior_upids = authority.api.recent_tasks(job, since=baseline_since)
        try:
            observation = self.evidence.observe_source(job.source, template, destination)
        except ExecutorError as error:
            if error.error_class in {"conflict", "policy_denied"}:
                return self._fail(job, "template_changed")
            raise
        if observation != job.observation:
            return self._fail(job, "template_changed")
        current = self.authority()
        if not self._same_authority(job, current):
            return self._fail(job, "policy_changed")
        self._check_kill_switch()
        if self._expired(job):
            return self._fail(job, "confirmation_expired")
        return self._dispatch(job, current.api, prior_upids, baseline_since)

    def _check_kill_switch(self) -> None:
        if self.kill_switch():
            raise ExecutorError("kill_switch", "Native PVE provisioning is stopped.")

    def _dispatch(
        self,
        job: ProvisionJob,
        api: ProvisionApi,
        prior_upids: tuple[str, ...],
        baseline_since: int,
    ) -> ProvisionJob:
        self.audit.append(
            "pve_provision_dispatch_intent",
            job_id=job.job_id,
            source_vmid=job.source.vmid,
            vmid=job.target.vmid,
        )
        dispatched_at = self.now()
        if dispatched_at.timestamp() < baseline_since:
            raise ExecutorError("conflict", "The clock changed during native clone admission.")
        leg = CloneLeg(
            dispatched_at=dispatched_at,
            actor=api.actor,
            state="dispatching",
            prior_upids=prior_upids,
        )
        job = self._save(
            job, legs=(leg,), state="dispatching", next_action="reconcile", error_code=None
        )
        if self.kill_switch():
            return self._dispatch_failed(job, "kill_switch")
        if self._expired(job):
            return self._dispatch_failed(job, "confirmation_expired")
        try:
            upid = api.dispatch(job, dispatched_at=dispatched_at.timestamp())
        except ExecutorError as error:
            if not error.outcome_unknown:
                code = {
                    "conflict": "vmid_conflict",
                    "policy_denied": "native_permission_denied",
                    "unavailable": "native_not_sent",
                }.get(error.error_class)
                if code is not None:
                    return self._dispatch_failed(job, code)
            return self._uncertain(job)
        except Exception:  # noqa: BLE001 - a write may have reached PVE before the exception
            return self._uncertain(job)
        if upid in prior_upids:
            return self._uncertain(job)
        return self._save(
            job,
            state="accepted",
            legs=(leg.model_copy(update={"state": "accepted", "upid": upid}),),
        )

    def _dispatch_failed(self, job: ProvisionJob, code: str) -> ProvisionJob:
        return self._fail(job, code, legs=(job.legs[0].model_copy(update={"state": "failed"}),))

    def _uncertain(self, job: ProvisionJob) -> ProvisionJob:
        return self._save(
            job,
            state="uncertain",
            error_code="dispatch_unknown",
            legs=(job.legs[0].model_copy(update={"state": "uncertain"}),),
        )

    def reconcile(self, params: _ReconcileParams) -> ProvisionJob:
        job = self._get(params.job_id)
        if job.next_action != "reconcile":
            if params.upid is not None:
                raise ExecutorError("conflict", "This job does not need a native task binding.")
            return job
        if job.state == "dispatching":
            job = self._uncertain(job)
        leg = job.legs[0]
        if params.upid is not None and leg.upid is not None and params.upid != leg.upid:
            raise ExecutorError("conflict", "This job already binds a different native task.")
        upid = leg.upid or params.upid
        if upid is None or leg.state == "failed":
            return job
        authority = self.authority()
        api = authority.api
        if not self._same_authority(job, authority) or api.actor != leg.actor:
            raise ExecutorError("conflict", "Native provision authority changed.")
        api.validate_permissions(authority.policy)
        dispatched_at = leg.dispatched_at.timestamp()
        if leg.upid is None:
            self._prove_task(api, job, leg, upid)
        state = (
            "succeeded"
            if leg.state == "succeeded"
            else api.task(job, upid, dispatched_at=dispatched_at)
        )
        if state == "vmid_conflict":
            return self._fail(
                job,
                "vmid_conflict",
                legs=(leg.model_copy(update={"state": "failed", "upid": upid}),),
            )
        legs = (leg.model_copy(update={"state": state, "upid": upid}),)
        if state == "failed":
            return self._save(job, state="uncertain", error_code="native_task_failed", legs=legs)
        if state == "running":
            if leg.upid is None:
                raise ExecutorError("conflict", "A recovered native task must be complete.")
            return self._save(job, state="accepted", legs=legs, error_code=None)

        job = self._save(job, state="verifying", legs=legs, error_code=None)
        try:
            completed_at = api.completion_time(job, upid, dispatched_at=dispatched_at)
            result = self.evidence.verify_target(
                job, dispatched_at=dispatched_at, completed_at=completed_at
            )
        except ExecutorError as error:
            code = "target_mismatch" if error.error_class == "conflict" else "target_unverified"
            return self._save(job, error_code=code)
        return self._save(job, state="succeeded", next_action=None, result=result)

    @staticmethod
    def _prove_task(api: ProvisionApi, job: ProvisionJob, leg: CloneLeg, upid: CloneUpid) -> None:
        if leg.prior_upids is None:
            raise ExecutorError("conflict", "The dispatch has no protected native task baseline.")
        since = int(leg.dispatched_at.timestamp())
        candidates = api.recent_tasks(job, since=since, until=since + CLONE_TASK_WINDOW_S)
        if set(candidates) - set(leg.prior_upids) != {upid}:
            raise ExecutorError("conflict", "The supplied task does not uniquely match the clone.")
        api.verify_task_target(job, upid, dispatched_at=leg.dispatched_at.timestamp())

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
                raise ExecutorError(
                    "unknown_action", "This native provision action is unregistered."
                )
            action_name = request["action"]
            model, method = action
            job = getattr(self, method)(model.model_validate(request["params"]))
        except (ValueError, RecursionError) as error:
            if isinstance(error, PowerJournalError):
                code = {
                    "target_busy": "target_busy",
                    "journal_conflict": "conflict",
                    "task_conflict": "conflict",
                }.get(error.code, "unavailable")
                failure = ExecutorError(code, "The native provision journal refused the request.")
            elif isinstance(error, ValidationError) or action_name == "invalid":
                failure = ExecutorError("bad_request", "Invalid native provision request.")
            else:
                failure = ExecutorError("internal", "Native provision processing failed.")
        except ExecutorError as error:
            failure = error
        else:
            self.audit.append(
                "pve_provision_request",
                action=action_name,
                job_id=job.job_id,
                vmid=job.target.vmid,
                outcome=job.state,
                error_code=job.error_code,
            )
            return {"ok": True, "result": job.public()}
        self.audit.append("pve_provision_request", action=action_name, outcome=failure.error_class)
        return _error(failure)


def _authority(installed: dict, paths: dict[str, Path]) -> _Authority:
    policy = _read_policy(_STATE / "provision.json", ProvisionPolicy)
    intent = installed["intent"]
    ca_file, health_token, *_ = intent["refs"]
    aliases = [Path(health_token)]
    if "inventory_token_file" in intent:
        aliases.append(Path(intent["inventory_token_file"]))
    power_policy = _STATE / "power.json"
    if native._exists(power_policy):
        aliases.append(Path(_read_policy(power_policy, PowerPolicy).write_token_file))
    ca = Path(ca_file)
    write_token = Path(policy.write_token_file)
    managed = (*paths.values(), _STATE, native._UNIT_DIR)
    try:
        install._credential(ca, managed, private=False)
        for token_file in (write_token, *aliases):
            install._credential(token_file, managed, private=True)
        token = native._load_token(write_token)
        actor = token.partition("=")[0]
        principal = actor.partition("!")[0].casefold()
        if principal == "root@pam" or any(
            write_token == ref or principal == native._load_token(ref).partition("!")[0].casefold()
            for ref in aliases
        ):
            raise ExecutorError(
                "policy_denied", "Use a dedicated non-root PVE provision user and token."
            )
        fingerprint = hashlib.sha256(native._read_file(ca, 1024 * 1024)).hexdigest()
        api = ProvisionApi(intent["api_name"], ca, token)
    except (native.PreflightError, OSError, ValueError):
        raise ExecutorError(
            "unavailable", "Native PVE provisioning credentials are unavailable."
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


def _runtime() -> ProvisionExecutor:
    paths, installed, audit = _runtime_context()
    return ProvisionExecutor(
        PowerJournal(_STATE),
        audit,
        lambda: _authority(installed, paths),
        lambda: native._exists(_STATE / "kill-switch"),
        ProvisionEvidence(),
    )


def execute_local(raw: bytes, *, uid: int) -> dict:
    if uid != 0:
        return _error(
            ExecutorError("unauthorized_peer", "Native provisioning requires local root.")
        )
    if len(raw) > _MAX_REQUEST:
        return _error(ExecutorError("bad_request", "Native provision request is too large."))
    try:
        with install._locked():
            return _runtime().handle(raw)
    except (install.InstallError, OSError):
        return _error(
            ExecutorError("unavailable", "The native executor or its journal is unavailable.")
        )
    except Exception:  # noqa: BLE001 - retain the dispatch journal and keep private details out of IPC
        return _error(ExecutorError("internal", "Native provision processing failed."))


def main() -> None:
    result = execute_local(sys.stdin.buffer.read(_MAX_REQUEST + 1), uid=os.geteuid())
    print(json.dumps(result, allow_nan=False))


if __name__ == "__main__":
    main()
