"""Executor actions for exposure removal and quarantine (L07 step 3, L08).

The controller only reports *that* a finding is critical and exposed; the
executor re-derives exposure from its root-owned registry, keeps the deadline on
its own clock and drives a durable state machine (`core/incidents.py`). Each
call performs one stage and persists the phase before and after every host
effect, so a crash, restart or reboot resumes at the recorded phase:

* notice -> disconnecting -> disconnected: at the deadline (or at once for a
  known-exploited finding) the proxy's loopback path to the application's routed
  backends is rejected in a dedicated nftables table. This waits for neither
  backup nor notification, touches no data and never touches SSH or the host's
  administrative services.
* backup_pending -> backup_verified: a checkpoint-bound group capture is taken
  and re-read. A failed backup leaves the stack running, disconnected and
  escalated; nothing is stopped without a verified capture.
* stopping -> quarantined: announce (audit record -> collector -> outbox, whose
  failure cannot block anything), then stop in reverse dependency order.
* fix_verification -> reactivating -> reactivated: start in dependency order
  while still disconnected, accept only fresh runtime-bound `not_affected` scan
  evidence for the running image, then lift the block.

Nothing here is reachable unless the root registry carries an enabled
`containment` section, which this release never renders.
"""

from __future__ import annotations

import contextlib
import re
import time
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..core import critical_risk as risk
from ..core.application_ops import derive_group_plan
from ..core.config import ImageRef, Slug
from ..core.ids import graph_identifier
from ..core.images import image_id, runtime_identity_verified
from ..core.incidents import (
    CONTAINED,
    TERMINAL,
    BackupRef,
    FindingRef,
    Incident,
    IncidentError,
    IncidentStore,
    incident_id,
    summary,
)
from ..core.inventory import Digest
from ..core.vulnerabilities import ScanResult
from .protocol import ExecutorError

BUSY = ("target_busy", "conflict", "kill_switch")
MAX_ATTEMPTS = 24


class _Params(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ImageBinding(_Params):
    image: ImageRef
    image_id: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")


class FindingParam(_Params):
    service: Slug
    advisory: str = Field(pattern=r"^[A-Za-z0-9._:-]{1,120}$")
    verdict: Literal["critical", "critical_exploited"]
    binding: ImageBinding | None = None


class IncidentOpenParams(_Params):
    application: Slug
    expected_revision: Digest | None = None
    findings: list[FindingParam] = Field(min_length=1, max_length=64)


class IncidentAdvanceParams(_Params):
    application: Slug


class ServiceEvidence(_Params):
    service: Slug
    scan: dict[str, Any]


class IncidentReactivateParams(_Params):
    application: Slug
    expected_revision: Digest | None = None
    evidence: list[ServiceEvidence] = Field(default_factory=list, max_length=64)


class IncidentStatusParams(_Params):
    application: Slug | None = None


class NoParams(_Params):
    pass


class ContainmentPolicy(BaseModel):
    """Root-registry `containment` section; absent means the feature is off."""

    model_config = ConfigDict(extra="forbid")
    enabled: Literal[True]
    notice_minutes: int = Field(60, ge=15, le=1440)
    immediate_if_known_exploited: bool = True
    evidence_max_age_s: int = Field(3600, ge=300, le=86400)


def _policy(registry: dict[str, Any]) -> ContainmentPolicy:
    try:
        policy = registry.get("containment")
        if isinstance(policy, dict) and policy.get("enabled") is True:
            return ContainmentPolicy.model_validate(policy)
    except ValidationError:
        pass
    raise ExecutorError("policy_denied", "exposure containment is not enabled")


def policy_enabled(registry: dict[str, Any]) -> bool:
    try:
        _policy(registry)
    except ExecutorError:
        return False
    return True


def _application(registry: dict[str, Any], name: str) -> dict[str, Any]:
    app = registry.get("applications", {}).get(name)
    if not isinstance(app, dict) or app.get("isolation") != "separate":
        raise ExecutorError("policy_denied", "only separately isolated applications")
    return app


def _lock_name(application: str) -> str:
    return "incident-" + graph_identifier("a", application)


def routed_ports(app: dict[str, Any]) -> list[int]:
    return sorted(app["services"][name]["host_port"] for name in risk.routed_services(app))


class Containment:
    clock = staticmethod(time.time)

    def __init__(self, ex: Any):
        self.ex = ex
        base = Path(ex._db_path).parent
        self.store = IncidentStore(base / "incidents")
        self.rules = base / "containment.nft"

    # ---- helpers -----------------------------------------------------------------

    def _registry(self) -> dict[str, Any]:
        from .server import load_registry

        return load_registry(self.ex.registry_path)

    def _audit(self, inc: Incident, outcome: str, **fields: Any) -> None:
        self.ex.audit.append(
            "incident",
            application=inc.application,
            incident_id=inc.id,
            correlation_id=inc.correlation_id,
            phase=inc.phase,
            outcome=outcome,
            **fields,
        )

    def _desired(self, *, exclude: str | None = None) -> set[int]:
        ports: set[int] = set()
        for inc in self.store.all():
            if inc.contained and inc.application != exclude:
                ports.update(inc.ports)
        return ports

    def _apply(self, ports: set[int]) -> bool:
        host = self.ex.host
        try:
            with self.ex.target_lock("firewall"):
                if ports:
                    ok, _ = host.containment_apply(sorted(ports), self.rules)
                    return bool(ok) and host.containment_ports() == ports
                ok, _ = host.containment_clear()
                return bool(ok) and host.containment_ports() is None
        except OSError:
            return False

    def _plan(self, registry: dict[str, Any], app: str) -> dict[str, Any]:
        services = registry["applications"][app]["services"]
        try:
            return derive_group_plan(
                registry,
                app,
                sorted(services)[0],
                expected_revision=registry["config_revision"],
                scope="application",
            )
        except (ValueError, KeyError):
            raise ExecutorError("policy_denied", "application contract is not operable") from None

    def _check_controller_state(
        self, registry: dict, expected_revision: str | None, authorized: dict | None
    ) -> None:
        if authorized is not None and registry.get("peers") != authorized.get("peers"):
            raise ExecutorError("conflict", "registered peers changed")
        if expected_revision is None:
            raise ExecutorError("bad_request", "expected_revision is required for controller")
        if registry.get("config_revision") != expected_revision:
            raise ExecutorError("conflict", "active configuration changed")
        if self.ex.deployment_fence() is not None:
            raise ExecutorError("target_busy", "deployment recovery is pending")
        if self.ex.host.kill_switch():
            raise ExecutorError("kill_switch", "automatic mutations are stopped")

    def _check_observed_state(self, registry: dict) -> None:
        if self._registry() != registry:
            raise ExecutorError("conflict", "registry changed during containment operation")
        self._check_controller_state(registry, registry["config_revision"], None)

    def _running_image_id(self, spec: dict) -> str | None:
        from .server import IMAGE_REFERENCE, _active_image_service, runtime_image_observation

        if not _active_image_service(spec):
            return None
        try:
            IMAGE_REFERENCE.validate_python(spec.get("image"))
        except ValidationError:
            return None
        observed = runtime_image_observation(self.ex, spec)
        if runtime_identity_verified(observed):
            return image_id(observed["observed_image_id"])
        return None

    # ---- open ----------------------------------------------------------------------

    def open(
        self, params: IncidentOpenParams, role: str, authorized: dict | None = None
    ) -> dict[str, Any]:
        controller = role == "controller"
        if not controller and len(params.findings) > 20:
            raise ExecutorError("bad_request", "at most 20 operator findings are allowed")
        with (
            self.ex.target_lock(_lock_name(params.application)),
            self.ex.target_lock("deployment-execution") if controller else contextlib.nullcontext(),
        ):
            registry = self._registry()
            if controller:
                self._check_controller_state(registry, params.expected_revision, authorized)
            return self._open(params, registry, controller=controller)

    def _open(
        self, params: IncidentOpenParams, registry: dict, *, controller: bool
    ) -> dict[str, Any]:
        policy = _policy(registry)
        app = _application(registry, params.application)
        observed_ids: dict[str, str | None] = {}
        for finding in params.findings:
            spec = app["services"].get(finding.service)
            if spec is None:
                raise ExecutorError("policy_denied", "unknown service")
            if not risk.exposers(app, finding.service):
                raise ExecutorError("policy_denied", "service is not exposed to the network")
            if controller:
                binding = finding.binding
                if binding is None or binding.image != spec.get("image"):
                    raise ExecutorError(
                        "policy_denied", "finding image binding is missing or stale"
                    )
                if finding.service not in observed_ids:
                    observed_ids[finding.service] = self._running_image_id(spec)
                if binding.image_id != observed_ids[finding.service]:
                    raise ExecutorError("policy_denied", "finding runtime identity is not current")
        if controller:
            self._check_observed_state(registry)
        ports = routed_ports(app)
        exposers = sorted({name for f in params.findings for name in risk.exposers(app, f.service)})
        exploited = any(f.verdict == "critical_exploited" for f in params.findings)
        mode = app.get("on_critical", "quarantine")
        rules = risk.Policy(mode, policy.notice_minutes * 60, policy.immediate_if_known_exploited)
        now = self.clock()
        refs = [FindingRef(**f.model_dump(exclude={"binding"})) for f in params.findings]
        try:
            existing = self.store.get(params.application)
        except IncidentError:
            raise ExecutorError("unavailable", "incident state is unreadable") from None
        if existing is not None and existing.phase not in TERMINAL:
            merged = list(existing.findings)
            new_services = {}
            if controller:
                affected = set(existing.affected)
                for ref in refs:
                    if ref.service not in affected:
                        new_services.setdefault(ref.service, ref)
                if len(merged) + len(new_services) > 64:
                    merged = list({ref.service: ref for ref in reversed(merged)}.values())
                if len(merged) + len(new_services) > 64:
                    raise ExecutorError("conflict", "incident service coverage exceeds the limit")
                merged.extend(new_services.values())
                for ref in refs:
                    if ref not in merged and len(merged) < 64:
                        merged.append(ref)
            else:
                for ref in refs:
                    if ref not in merged and len(merged) < 20:
                        merged.append(ref)
            changes: dict[str, Any] = {"findings": merged}
            if new_services:
                changes["vulnerable_images"] = existing.vulnerable_images | {
                    service: app["services"][service]["image"] for service in new_services
                }
            if exploited and not existing.exploited:
                changes["exploited"] = True
                if existing.phase == "notice":
                    changes["deadline"] = min(
                        existing.deadline,
                        risk.deadline(existing.opened_at, exploited=True, policy=rules),
                    )
            if changes["findings"] == existing.findings and len(changes) == 1:
                return {"created": False, "incident": summary(existing)}
            updated = self.store.update(existing, **changes)
            self._audit(updated, "updated")
            return {"created": False, "incident": summary(updated)}
        incident = Incident(
            id=incident_id(params.application, now),
            application=params.application,
            seq=1,
            phase="notice",
            opened_at=now,
            deadline=risk.deadline(now, exploited=exploited, policy=rules),
            exploited=exploited,
            on_critical=mode,
            config_revision=registry["config_revision"],
            findings=refs,
            exposers=exposers,
            ports=ports,
            vulnerable_images={n: s["image"] for n, s in app["services"].items()},
        )
        created = self.store.open(incident)
        self._audit(created, "opened", deadline=created.deadline, exploited=exploited)
        return {"created": True, "incident": summary(created)}

    # ---- advance -------------------------------------------------------------------

    def advance(self, params: IncidentAdvanceParams, role: str) -> dict[str, Any]:
        registry = self._registry()
        policy = _policy(registry)
        _application(registry, params.application)
        with self.ex.target_lock(_lock_name(params.application)):
            inc = self._require(params.application)
            return self._stage(inc, registry, policy, controller=role == "controller")

    def _require(self, application: str) -> Incident:
        try:
            inc = self.store.get(application)
        except IncidentError:
            raise ExecutorError("unavailable", "incident state is unreadable") from None
        if inc is None or inc.phase in TERMINAL:
            raise ExecutorError("policy_denied", "no open incident")
        return inc

    def _result(self, inc: Incident, **extra: Any) -> dict[str, Any]:
        return {"state": inc.phase, "incident": summary(inc), **extra}

    def _stage(
        self, inc: Incident, registry: dict, policy: ContainmentPolicy, *, controller: bool
    ) -> dict[str, Any]:
        now = self.clock()
        if inc.phase == "notice":
            if inc.on_critical == "notify":
                if now >= inc.deadline and inc.escalated_at is None:
                    inc = self.store.update(inc, escalated_at=now)
                    self._audit(inc, "escalated", reason="notify_policy_deadline")
                return self._result(inc, waiting="notify_only")
            if now < inc.deadline:
                return self._result(inc, waiting="notice", remaining_s=round(inc.deadline - now))
            return self._disconnect(inc, registry, now, controller=controller)
        if inc.phase in ("disconnecting", "disconnect_failed"):
            return self._disconnect(inc, registry, now, controller=controller)
        if inc.phase in ("disconnected", "backup_pending", "backup_failed"):
            return self._backup(inc, registry, now)
        if inc.phase in ("backup_verified", "stopping", "stop_failed"):
            return self._stop(inc, registry, now)
        if inc.phase == "quarantined":
            self.hold(inc, registry)
            return self._result(inc, waiting="fix")
        return self._result(inc, waiting="reactivation")

    # -- exposure removal --

    def _disconnect(
        self, inc: Incident, registry: dict, now: float, *, controller: bool
    ) -> dict[str, Any]:
        if not controller:
            return self._disconnect_current(inc, registry, now)
        with self.ex.target_lock("deployment-execution"):
            registry = self._registry()
            _policy(registry)
            _application(registry, inc.application)
            if self.ex.deployment_fence() is not None:
                raise ExecutorError("target_busy", "deployment recovery is pending")
            if self.ex.host.kill_switch():
                raise ExecutorError("kill_switch", "automatic mutations are stopped")
            return self._disconnect_current(inc, registry, self.clock())

    def _disconnect_current(self, inc: Incident, registry: dict, now: float) -> dict[str, Any]:
        current = routed_ports(registry["applications"][inc.application])
        ports = sorted(set(inc.ports) | set(current))
        if inc.phase in ("notice", "disconnect_failed"):
            inc = self.store.transition(inc, "disconnecting", now, ports=ports)
        elif ports != inc.ports:
            inc = self.store.update(inc, ports=ports)
        ok = self._apply(self._desired())
        if ok:
            inc = self.store.transition(
                inc, "disconnected", now, disconnected_at=now, error_class=None
            )
            self._audit(inc, "exposure_removed", ports=len(inc.ports))
        else:
            inc = self.store.transition(
                inc, "disconnect_failed", now, "apply", error_class="execution_failed"
            )
            self._audit(inc, "escalated", reason="exposure_removal_failed")
        return self._result(inc)

    # -- backup --

    def _fail(
        self, inc: Incident, to: str, now: float, error: str, **fields: Any
    ) -> dict[str, Any]:
        code = re.sub(r"[^a-z_]", "_", error.lower())[:40] or "unknown"
        inc = self.store.transition(inc, to, now, code, error_class=code, **fields)  # type: ignore[arg-type]
        self._audit(inc, "escalated", reason=error)
        return self._result(inc)

    @staticmethod
    def _stateless(registry: dict, app: str) -> bool:
        """Only an explicit contract marker (`stateless: true`) lets a stack stop without a
        backup. An application that merely has no registered data is not stateless."""
        return registry.get("applications", {}).get(app, {}).get("stateless") is True

    def _skip_backup(self, inc: Incident, now: float) -> dict[str, Any]:
        """Stateless contract: nothing exists to back up; record that, never fake a capture."""
        if inc.phase in ("disconnected", "backup_failed"):
            inc = self.store.transition(inc, "backup_pending", now, error_class=None)
        inc = self.store.transition(inc, "backup_verified", now, error_class=None)
        self._audit(inc, "backup_skipped", reason="stateless_contract")
        return self._result(inc)

    def _backup(self, inc: Incident, registry: dict, now: float) -> dict[str, Any]:
        from .server import capture_allowance, message_cause

        ex = self.ex
        app = inc.application
        if self._stateless(registry, app):
            return self._skip_backup(inc, now)
        if inc.phase in ("disconnected", "backup_failed"):
            attempts = {**inc.attempts, "backup": inc.attempts.get("backup", 0) + 1}
            if attempts["backup"] > MAX_ATTEMPTS:
                return self._result(inc, blocked="backup_attempts_exhausted")
            inc = self.store.transition(
                inc,
                "backup_pending",
                now,
                backup_operation=None,
                attempts=attempts,
                error_class=None,
            )
        try:
            checkpoint = ex.group_checkpoint(app)
            if inc.backup_operation is None:
                if checkpoint is not None:
                    if checkpoint.phase not in ("complete", "recovered"):
                        return self._result(inc, waiting="group_transition")
                    ex.archive_group_checkpoint(app, checkpoint.operation_id, checkpoint.generation)
                service = sorted(registry["applications"][app]["services"])[0]
                with ex.observed_group_execution(
                    app, service, expected_revision=registry["config_revision"], scope="application"
                ) as started:
                    pass
                inc = self.store.update(inc, backup_operation=started.operation_id)
                with capture_allowance("incident"):
                    ex.capture_application_with_recovery(
                        app, started.operation_id, started.generation
                    )
            return self._finish_backup(inc, registry, self.clock())
        except ExecutorError as exc:
            if exc.error_class in BUSY:
                return self._result(inc, waiting=exc.error_class)
            return self._fail(
                inc, "backup_failed", self.clock(), message_cause(exc) or exc.error_class
            )
        except (OSError, ValueError):
            return self._fail(inc, "backup_failed", self.clock(), "internal")

    def _cause(self, inc: Incident, default: str) -> str:
        """The specific capture failure (for example spool_unwritable) from the audit trail."""
        for entry in reversed(self.ex.audit.read(200)):
            if (
                entry.get("event") == "application_group_capture"
                and entry.get("operation_id") == inc.backup_operation
                and entry.get("outcome") in ("failed", "preflight_failed")
                and re.fullmatch(r"[a-z_]{3,40}", str(entry.get("error_class")))
            ):
                return entry["error_class"]
        return default

    def _finish_backup(self, inc: Incident, registry: dict, now: float) -> dict[str, Any]:
        ex = self.ex
        app = inc.application
        checkpoint = ex.group_checkpoint(app)
        if checkpoint is None or checkpoint.operation_id != inc.backup_operation:
            return self._fail(inc, "backup_failed", now, "interrupted")
        if checkpoint.phase not in ("complete", "recovered"):
            return self._result(inc, waiting="group_transition")
        workflow = ex.group_capture_workflow(app)
        if workflow is None or workflow.operation_id != inc.backup_operation:
            return self._fail(inc, "backup_failed", now, "capture_missing")
        if workflow.phase != "captured" or not workflow.artifact or not workflow.capture_id:
            return self._fail(
                inc,
                "backup_failed",
                now,
                self._cause(inc, workflow.error_class or "capture_failed"),
            )
        try:
            verified = ex.verify_group_capture(app, workflow.artifact, workflow.capture_id)
        except ExecutorError as exc:
            return self._fail(inc, "backup_failed", now, exc.error_class)
        manifest = verified["capture"]
        if (
            manifest["application"] != app
            or manifest["config_revision"] != registry["config_revision"]
            or not manifest["data_services"]
            or inc.disconnected_at is None
            or manifest["completed_at"] < inc.disconnected_at
        ):
            return self._fail(inc, "backup_failed", now, "capture_binding")
        inc = self.store.transition(
            inc,
            "backup_verified",
            now,
            backup=BackupRef(artifact=workflow.artifact, capture_id=workflow.capture_id),
            error_class=None,
        )
        self._audit(inc, "backup_verified", capture_id=workflow.capture_id)
        with contextlib.suppress(ExecutorError):  # a later backup attempt archives it first
            ex.archive_group_checkpoint(app, checkpoint.operation_id, checkpoint.generation)
        return self._result(inc)

    # -- shutdown --

    def _set_stack(self, registry: dict, app: str, order: list[str], *, running: bool) -> None:
        host = self.ex.host
        specs = registry["applications"][app]["services"]
        for name in order:
            spec = specs[name]
            if running and not spec["deploy"]:
                continue
            state = host.group_service_running(spec["user"], spec["unit"], spec["container"])
            if state is running:
                continue
            if not host.set_user_unit(spec["user"], spec["unit"], running=running):
                raise ExecutorError("execution_failed", "service state change failed")
            observed = host.group_service_running(spec["user"], spec["unit"], spec["container"])
            if observed is not running or (
                not running
                and not host.group_service_quiescent(spec["user"], spec["unit"], spec["container"])
            ):
                raise ExecutorError("execution_failed", "service did not reach its target state")

    def _stop(
        self, inc: Incident, registry: dict, now: float, *, deployment_locked: bool = False
    ) -> dict[str, Any]:
        ex = self.ex
        app = inc.application
        if inc.phase in ("backup_verified", "stop_failed"):
            inc = self.store.transition(inc, "stopping", now, error_class=None)
        if inc.backup is None and not self._stateless(registry, app):
            return self._fail(inc, "stop_failed", now, "no_backup")
        try:
            if inc.backup is not None:
                ex.verify_group_capture(app, inc.backup.artifact, inc.backup.capture_id)
        except ExecutorError as exc:
            return self._fail(inc, "stop_failed", now, "backup_" + exc.error_class)
        if not inc.attempts.get("announced"):
            self._audit(inc, "announced", stage="shutdown")
            inc = self.store.update(inc, attempts={**inc.attempts, "announced": 1})
        try:
            plan = self._plan(registry, app)
            with (
                contextlib.nullcontext()
                if deployment_locked
                else ex.target_lock("deployment-execution"),
                ex.target_locks(plan["lock_targets"]),
            ):
                if ex.deployment_fence() is not None:
                    raise ExecutorError("target_busy", "deployment recovery is pending")
                self._set_stack(registry, app, plan["stop_order"], running=False)
        except ExecutorError as exc:
            if exc.error_class in BUSY:
                return self._result(inc, waiting=exc.error_class)
            return self._fail(inc, "stop_failed", self.clock(), exc.error_class)
        inc = self.store.transition(inc, "quarantined", self.clock(), error_class=None)
        self._audit(inc, "quarantined")
        return self._result(inc, rescan_interval_s=rescan_interval(None))

    def hold(self, inc: Incident, registry: dict) -> bool:
        """Keep a quarantined stack down (after a reboot or an unexpected start)."""
        plan = self._plan(registry, inc.application)
        specs = registry["applications"][inc.application]["services"]
        running = [
            n
            for n in plan["stop_order"]
            if self.ex.host.group_service_running(
                specs[n]["user"], specs[n]["unit"], specs[n]["container"]
            )
            is not False
        ]
        if not running:
            return False
        with (
            self.ex.target_lock("deployment-execution"),
            self.ex.target_locks(plan["lock_targets"]),
        ):
            self._set_stack(registry, inc.application, plan["stop_order"], running=False)
        self._audit(inc, "quarantine_reasserted", services=len(running))
        return True

    # ---- reactivation --------------------------------------------------------------

    def reactivate(
        self, params: IncidentReactivateParams, role: str, authorized: dict | None = None
    ) -> dict[str, Any]:
        controller = role == "controller"
        app = params.application
        with (
            self.ex.target_lock(_lock_name(app)),
            self.ex.target_lock("deployment-execution") if controller else contextlib.nullcontext(),
        ):
            registry = self._registry()
            if controller:
                self._check_controller_state(registry, params.expected_revision, authorized)
            policy = _policy(registry)
            _application(registry, app)
            inc = self._require(app)
            now = self.clock()
            retry = inc.phase in ("reactivating", "reactivation_failed")
            if inc.phase == "quarantined" or (
                controller and (inc.phase == "fix_verification" or retry)
            ):
                specs = registry["applications"][app]["services"]
                unchanged = [
                    s
                    for s in inc.affected
                    if s not in specs or specs[s]["image"] == inc.vulnerable_images.get(s)
                ]
                if unchanged:
                    return self._result(inc, blocked="fix_not_applied", services=unchanged)
            if inc.phase == "quarantined":
                inc = self.store.transition(inc, "fix_verification", now, fix_started_at=now)
                self._audit(inc, "fix_verification_started")
            if inc.phase == "fix_verification":
                try:
                    self._start_fix(inc, registry, deployment_locked=controller)
                except ExecutorError as exc:
                    return self._result(inc, blocked="start_" + exc.error_class)
            elif retry and not controller:
                return self._reactivate(inc, now)
            elif not retry:
                return self._result(inc, blocked="not_quarantined")
            return self._verify_fix(inc, registry, policy, params.evidence, controller=controller)

    def _start_fix(self, inc: Incident, registry: dict, *, deployment_locked: bool) -> None:
        ex = self.ex
        plan = self._plan(registry, inc.application)
        with (
            contextlib.nullcontext()
            if deployment_locked
            else ex.target_lock("deployment-execution"),
            ex.target_locks(plan["lock_targets"]),
        ):
            if deployment_locked:
                self._check_observed_state(registry)
            elif ex.deployment_fence() is not None:
                raise ExecutorError("target_busy", "deployment recovery is pending")
            self._set_stack(registry, inc.application, plan["start_order"], running=True)

    def _verify_fix(
        self,
        inc: Incident,
        registry: dict,
        policy: ContainmentPolicy,
        evidence: list[ServiceEvidence],
        *,
        controller: bool,
    ) -> dict[str, Any]:
        host = self.ex.host
        app = inc.application
        specs = registry["applications"][app]["services"]
        now = self.clock()
        by_service = {item.service: item for item in evidence}
        problems: list[str] = []
        still_vulnerable = False
        for name in inc.affected:
            spec, item = specs.get(name), by_service.get(name)
            if spec is None or item is None:
                problems.append(f"{name}:no_evidence")
                continue
            try:
                scan = ScanResult.model_validate(item.scan)
            except ValidationError:
                problems.append(f"{name}:invalid_evidence")
                continue
            state = scan.state_at(
                now, inventory_revision=scan.inventory_revision, max_age_s=policy.evidence_max_age_s
            )
            subject = scan.subject
            bound = (
                scan.complete
                and subject.kind == "image"
                and subject.image == spec["image"]
                and subject.runtime_verified
                and inc.fix_started_at is not None
                and scan.checked_at >= inc.fix_started_at
            )
            if controller:
                bound = (
                    bound
                    and scan.source == "trivy"
                    and scan.database_updated_at is not None
                    and subject.scope == f"{app}/{name}"
                )
                running_id = (
                    self._running_image_id(spec)
                    if bound and state in ("confirmed", "not_affected")
                    else None
                )
                bound = (
                    running_id is not None
                    and subject.expected_image_id == running_id
                    and host.group_service_running(spec["user"], spec["unit"], spec["container"])
                    is True
                )
                still_vulnerable |= bound and state == "confirmed"
            else:
                container = host.container(spec["user"], spec["container"])
                running_id = image_id((container or {}).get("Image"))
                still_vulnerable |= state == "confirmed"
                bound = (
                    bound
                    and running_id is not None
                    and subject.expected_image_id == running_id
                    and host.group_service_running(spec["user"], spec["unit"], spec["container"])
                    is True
                )
            if state != "not_affected" or not bound:
                problems.append(f"{name}:{state if state != 'not_affected' else 'unbound'}")
        if controller:
            self._check_observed_state(registry)
        if still_vulnerable and inc.phase == "fix_verification":
            inc = self.store.transition(
                inc,
                "stopping",
                now,
                "fix_rejected",
                fix_started_at=None,
                error_class="still_vulnerable",
            )
            self._audit(inc, "fix_rejected")
            return self._stop(inc, registry, now, deployment_locked=controller)
        if problems:
            return self._result(inc, needs="evidence", problems=sorted(problems)[:20])
        if inc.phase == "fix_verification":
            inc = self.store.transition(inc, "reactivating", now)
            self._audit(inc, "fix_verified")
        return self._reactivate(inc, now)

    def _reactivate(self, inc: Incident, now: float) -> dict[str, Any]:
        if inc.phase == "reactivation_failed":
            inc = self.store.transition(inc, "reactivating", now, error_class=None)
        if self._apply(self._desired(exclude=inc.application)):
            inc = self.store.transition(inc, "reactivated", self.clock())
            self._audit(inc, "reactivated")
            return self._result(inc)
        inc = self.store.transition(
            inc, "reactivation_failed", self.clock(), "apply", error_class="execution_failed"
        )
        self._audit(inc, "escalated", reason="route_restore_failed")
        return self._result(inc)

    # ---- restart / reboot -----------------------------------------------------------

    def reassert(self) -> dict[str, Any]:
        """Restore the recorded containment and keep quarantined stacks down."""
        incidents = self.store.all()
        desired: set[int] = set()
        for inc in incidents:
            if inc.contained:
                desired.update(inc.ports)
        current = self.ex.host.containment_ports()
        changed = False
        if (current or set()) != desired:
            changed = self._apply(desired)
            if not changed:
                raise ExecutorError("execution_failed", "containment could not be restored")
        registry = self._registry()
        held = []
        for inc in incidents:
            if inc.phase == "quarantined":
                with self.ex.target_lock(_lock_name(inc.application)):
                    if self.hold(inc, registry):
                        held.append(inc.application)
        if changed:
            self.ex.audit.append("incident_reassert", ports=sorted(desired))
        return {"ports": sorted(desired), "changed": changed, "held": held}

    def applications(self, registry: dict[str, Any]) -> dict[str, Any]:
        """Executor-derived exposure per separately isolated application."""
        return {
            name: {
                "on_critical": app.get("on_critical", "quarantine"),
                "exposure": risk.exposure(app),
            }
            for name, app in sorted(registry.get("applications", {}).items())
            if app.get("isolation") == "separate"
        }

    def status(self, application: str | None, registry: dict | None = None) -> dict[str, Any]:
        if registry is None:
            registry = self._registry()
        try:
            incidents = (
                [i for i in [self.store.get(application)] if i] if application else self.store.all()
            )
        except IncidentError:
            raise ExecutorError("unavailable", "incident state is unreadable") from None
        ports = self.ex.host.containment_ports()
        return {
            "config_revision": registry["config_revision"],
            "applications": self.applications(registry),
            "incidents": [summary(i) for i in incidents],
            "blocked_ports": None if ports is None else sorted(ports),
        }


def rescan_interval(configured_s: int | None) -> int:
    """Scan faster while a finding is open, within the scanner's own 300 s floor."""
    return max(300, min(configured_s or 1800, 1800))


def contained_phases() -> frozenset[str]:
    return CONTAINED


def _driver(ex: Any) -> Containment:
    driver = getattr(ex, "_containment", None)
    if driver is None:
        driver = ex._containment = Containment(ex)
    return driver


def incident_open(ex, params: IncidentOpenParams, role: str, registry):
    return _driver(ex).open(params, role, registry)


def incident_advance(ex, params: IncidentAdvanceParams, role: str, _registry):
    return _driver(ex).advance(params, role)


def incident_reactivate(ex, params: IncidentReactivateParams, role: str, registry):
    return _driver(ex).reactivate(params, role, registry)


def incident_status(ex, params: IncidentStatusParams, _role: str, registry):
    _policy(registry)
    return _driver(ex).status(params.application, registry)


def containment_reassert(ex, _params: NoParams, _role: str, registry):
    _policy(registry)
    return _driver(ex).reassert()


def reassert_at_startup(ex: Any) -> None:
    """Executor start: restore recorded containment before serving requests."""
    try:
        _policy(ex_registry(ex))
        _driver(ex).reassert()
    except (ExecutorError, IncidentError, OSError, ValueError):
        return  # feature off, or recorded state unusable: the controller retries


def ex_registry(ex: Any) -> dict[str, Any]:
    from .server import load_registry

    return load_registry(ex.registry_path)


class PeriodicReassert:
    """Every cycle: restore the block and stop a stray start of a quarantined stack."""

    INTERVAL_S = 30

    def __init__(self, ex: Any):
        self.ex = ex

    def tick(self) -> None:
        try:
            _policy(ex_registry(self.ex))
            _driver(self.ex).reassert()
        except (ExecutorError, IncidentError, OSError, ValueError):
            return  # feature off, busy or unusable: retried next cycle

    def run(self, stop: Any) -> None:
        while not stop.is_set():
            self.tick()
            stop.wait(self.INTERVAL_S)
