"""Deterministic self-management controller.

Runs without AI and without the web UI. Each cycle it reads the verified host
status from the executor, derives findings with fixed rules and, where a
registered remediation exists and policy allows it, asks the executor to act.
The executor stays the authority: it re-checks role, policy, kill switch,
locks and budgets for every request.

An AI advisor (later stage) can only add proposals to this same pipeline; it
cannot widen the set of actions.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import signal
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from functools import partial
from pathlib import Path
from typing import Any

from .core.ai_auth import auth_finding
from .core.audit import AuditLog
from .core.backup_join import correlate, read_snapshot
from .core.drill_cycle import DrillCycle
from .core.patch_profile import APPLY_ACTION, global_block, select_update
from .core.patch_stability import (
    StabilityTracker,
    durable_suspects,
    min_healthy_s,
    rollback_block,
    rollback_selection,
)
from .core.risk_cycle import RiskCycle
from .executor.protocol import DEFAULT_SOCKET, ExecutorError, call, update_call_timeout

SCAN_SOCKET = "/run/steward-scanner/query.sock"
STATE_DIR = "/var/lib/steward-controller"
INTERVAL_S = 30
COOLDOWN_S = 120
DISK_FREE_MIN_FRACTION = 0.10
RETENTION_INTERVAL_S = 600
SEVERITIES = ("info", "warning", "high", "critical")


@dataclass
class Finding:
    id: str
    severity: str
    target: str
    summary: str
    remediation: str | None = None  # registered executor action
    params: dict[str, Any] = field(default_factory=dict)
    blocked: str | None = None  # why no automatic remediation happens
    correlation_id: str | None = None  # stable while the finding stays open


def evaluate(status: dict[str, Any], failures: dict[str, int]) -> list[Finding]:
    """Fixed rules: verified status in, findings out. Updates `failures` counters."""
    out: list[Finding] = []
    deployment = status.get("deployment_recovery")
    if deployment not in ("clear", "pending"):
        deployment = "unknown"
    if deployment != "clear":
        out.append(
            Finding(
                "deployment_recovery",
                "high",
                "host",
                "A deployment intent requires reconciliation."
                if deployment == "pending"
                else "Deployment state could not be checked.",
                blocked="deployment state must be resolved before automatic restarts",
            )
        )
    firewall = status["firewall"]
    if firewall["managed"] and not firewall["loaded"]:
        out.append(
            Finding(
                "firewall_missing",
                "critical",
                "firewall",
                "Managed firewall ruleset is not loaded.",
                **(
                    {"remediation": "firewall_reassert"}
                    if deployment == "clear"
                    else {"blocked": "deployment state must be resolved"}
                ),
            )
        )
    for unit in status["platform_units"]:
        if unit["active"] != "active":
            out.append(
                Finding(
                    f"platform_unit_down:{unit['unit']}",
                    "high",
                    unit["unit"],
                    f"Platform unit {unit['unit']} is {unit['active']}.",
                )
            )
    if status["proxy"]["active"] != "active":
        out.append(
            Finding(
                "proxy_down",
                "high",
                "proxy",
                f"Reverse proxy is {status['proxy']['active']}.",
                **(
                    {"remediation": "proxy_restart"}
                    if deployment == "clear"
                    else {"blocked": "deployment state must be resolved before automatic restarts"}
                ),
            )
        )
    capacity_messages = {
        "capture_limit": "Capture storage reached its ten-artifact limit.",
        "capture_space": "Capture storage lacks the configured free-space reserve.",
        "import_limit": "Import storage reached its ten-artifact limit.",
        "import_space": "Import storage lacks its minimum free-space reserve.",
        "cancellation_limit": "Backup cancellation records reached their safety limit.",
    }
    for project_id, observation in sorted(status.get("backup_capacity", {}).items()):
        reasons = observation.get("reasons", [])
        for reason in reasons:
            if reason in capacity_messages:
                out.append(
                    Finding(
                        f"backup_capacity:{project_id}:{reason}",
                        "high",
                        project_id,
                        capacity_messages[reason],
                        blocked="protected backup artifacts require operator investigation",
                    )
                )
            elif reason in (
                "capture_unknown",
                "import_unknown",
                "remote_unknown",
                "cancellation_unknown",
            ):
                out.append(
                    Finding(
                        f"backup_capacity:{project_id}:{reason}",
                        "warning",
                        project_id,
                        "Remote backup capacity is unknown."
                        if reason == "remote_unknown"
                        else "Backup storage capacity could not be checked.",
                        blocked="capacity is unknown until the storage boundary is checked",
                    )
                )
    for project_id, observation in sorted(status.get("backup_schedule_observations", {}).items()):
        state = observation["state"]
        finding = None
        if state == "missing":
            finding = ("warning", "No scheduled capture record is available for this project.")
        elif state in ("invalid", "unavailable"):
            finding = ("high", "The root-owned backup schedule record could not be checked.")
        elif observation.get("config_revision") != status.get("config_revision"):
            finding = (
                "warning",
                "The last scheduled capture belongs to a different configuration.",
            )
        elif state == "failed":
            finding = ("high", "The last scheduled capture failed and requires investigation.")
        else:
            stamp = observation.get("capture_created_at")
            if stamp is None:
                stamp = observation.get("schedule_started_at")
            now = status["checked_at"]
            if stamp is None or stamp > now:
                finding = ("warning", "Scheduled capture time is unknown or in the future.")
            elif now - stamp > 2 * observation["interval_s"]:
                finding = ("high", "The last scheduled capture record is overdue.")
        if finding:
            out.append(
                Finding(
                    f"backup_schedule:{project_id}",
                    finding[0],
                    project_id,
                    finding[1],
                    blocked="capture observations do not authorize backup cleanup or recovery",
                )
            )
    for project_id, project in sorted(status["projects"].items()):
        pause = next(
            (p for p in status.get("backup_recovery", []) if p["project_id"] == project_id), None
        )
        if pause is not None:
            age = max(0, status["checked_at"] - pause["prepared_at"])
            out.append(
                Finding(
                    f"backup_pause:{project_id}",
                    "high" if age > 300 or pause.get("error_class") else "info",
                    project_id,
                    "Backup pause or recovery is pending.",
                    blocked="executor recovery must resolve this pause before ordinary restarts",
                )
            )
            if project["unit"]["active"] != "active":
                failures.pop(project_id, None)
                continue
        active = project["unit"]["active"] == "active"
        if not project["deploy"]:
            failures.pop(project_id, None)
            if active:
                out.append(
                    Finding(
                        f"should_be_stopped:{project_id}",
                        "warning",
                        project_id,
                        "Project is configured as stopped but its unit is active.",
                        blocked="needs a deployment run",
                    )
                )
            continue
        restart = (
            {"remediation": "workload_restart", "params": {"project_id": project_id}}
            if project["allow_restart"]
            else {"blocked": "no maintenance contract (maintenance.allow_restart)"}
        )
        if pause is not None:
            restart = {"blocked": "backup pause recovery is pending"}
        if deployment != "clear":
            restart = {"blocked": "deployment state must be resolved before automatic restarts"}
        if not active:
            failures.pop(project_id, None)
            out.append(
                Finding(
                    f"workload_down:{project_id}",
                    "high",
                    project_id,
                    f"Unit is {project['unit']['active']}.",
                    **restart,
                )
            )
            continue
        if project["health"]["ok"]:
            failures.pop(project_id, None)
        elif project["health"].get("state") == "unknown":
            # The probe could not tell: neither healthy nor a reason to restart.
            failures.pop(project_id, None)
            out.append(
                Finding(
                    f"health_unknown:{project_id}",
                    "warning",
                    project_id,
                    f"Health could not be verified ({project['health'].get('error')}).",
                )
            )
        else:
            failures[project_id] = failures.get(project_id, 0) + 1
            detail = (
                project["health"].get("status")
                or project["health"].get("error")
                or project["health"].get("state")
            )
            if failures[project_id] >= project.get("health_retries", 3):
                out.append(
                    Finding(
                        f"workload_unhealthy:{project_id}",
                        "high",
                        project_id,
                        f"Health check failed {failures[project_id]}x ({detail}).",
                        **restart,
                    )
                )
            else:
                out.append(
                    Finding(
                        f"health_flapping:{project_id}",
                        "warning",
                        project_id,
                        f"Health check failed {failures[project_id]}x ({detail}).",
                    )
                )
        violations = project["hardening"]["violations"]
        if violations:
            out.append(
                Finding(
                    f"isolation_drift:{project_id}",
                    "high",
                    project_id,
                    "Container deviates from its isolation contract: " + ", ".join(violations),
                    blocked="needs a deployment run",
                )
            )
    if status["failed_units"]:
        out.append(
            Finding(
                "failed_units",
                "warning",
                "host",
                "Failed systemd units: " + ", ".join(status["failed_units"][:10]),
            )
        )
    if status["reboot_required"]:
        out.append(
            Finding(
                "reboot_required",
                "warning",
                "host",
                "A reboot is required to finish installed updates.",
                blocked="reboots are never automatic",
            )
        )
    res = status["resources"]
    if res["disk_total_mb"] and res["disk_free_mb"] / res["disk_total_mb"] < DISK_FREE_MIN_FRACTION:
        out.append(
            Finding(
                "disk_low",
                "high",
                "host",
                f"Only {res['disk_free_mb']} MB free on the root filesystem.",
                blocked="data is never deleted automatically",
            )
        )
    if (
        res["memory_available_mb"] is not None
        and res["memory_available_mb"] < status.get("reserved_memory_mb", 0) // 4
    ):
        out.append(
            Finding(
                "memory_low",
                "warning",
                "host",
                f"Only {res['memory_available_mb']} MB memory available.",
            )
        )
    ai_login = auth_finding(status.get("ai_auth"))
    if ai_login is not None:  # optional AI login state; never blocks anything else
        out.append(Finding(**ai_login))
    if status["kill_switch"]:
        out.append(
            Finding(
                "kill_switch",
                "info",
                "host",
                "Kill switch is active: automatic mutations are stopped.",
            )
        )
    return out


class Controller:
    def __init__(
        self,
        state_dir: str,
        socket_path: str = DEFAULT_SOCKET,
        executor=call,
        *,
        backup_socket: str | None = None,
        backup=call,
        scan_query=None,
    ):
        self.state_dir = Path(state_dir)
        self.export_dir = self.state_dir / "export"
        self.socket_path = socket_path
        self.executor = executor
        self.backup_socket, self.backup = backup_socket, backup
        self.actions = AuditLog(self.state_dir / "actions.jsonl")
        self.failures: dict[str, int] = {}
        self.last_attempt: dict[str, float] = {}
        self.correlations: dict[str, str] = {}
        # Optional critical-risk driver (L07/L08); None keeps the cycle unchanged.
        self.risk = (
            RiskCycle(executor, None, socket_path=socket_path, scan_query=scan_query)
            if scan_query is not None
            else None
        )
        self.require_containment_status = scan_query is not None
        # Announced-drill driver (L11); acts only if the executor's registry configures drills.
        self.drills = DrillCycle(executor, socket_path)
        # Durable health-time tracker for the patch profile's stability gate.
        self.stability = StabilityTracker(self.state_dir / "stability.json")
        self._retention_at = 0.0
        self._retention: list[Finding] = []

    def _correlate(self, findings: list[Finding]) -> None:
        """Give every open finding a correlation id; forget ids of resolved ones."""
        open_ids = {f.id for f in findings}
        self.correlations = {k: v for k, v in self.correlations.items() if k in open_ids}
        for finding in findings:
            finding.correlation_id = self.correlations.setdefault(
                finding.id, f"f{uuid.uuid4().hex[:16]}"
            )

    def backup_evidence(self, status: dict) -> tuple[dict, list[Finding]]:
        """Correlate worker reports without granting them host authority."""
        schedule = status.get("backup_schedule_observations", {})
        if not schedule:
            return {}, []
        try:
            if not self.backup_socket:
                raise ValueError("worker socket not configured")
            records = read_snapshot(self.backup, self.backup_socket)
            observations = correlate(
                schedule,
                records,
                revision=status["config_revision"],
                now=max(status["checked_at"], time.time()),
            )
        except (ExecutorError, ValueError, TypeError, KeyError, OSError):
            return (
                {
                    project: {"state": "unknown", "reason": "worker_unavailable"}
                    for project in schedule
                },
                [
                    Finding(
                        "backup_worker_unavailable",
                        "warning",
                        "backup-worker",
                        "Backup worker evidence is unavailable or incomplete.",
                        blocked="worker observations do not authorize cleanup or recovery",
                    )
                ],
            )
        findings = []
        for project, observation in sorted(observations.items()):
            state = observation["state"]
            root = schedule[project]
            capture_at = root.get("capture_created_at")
            overdue = (
                capture_at is not None and status["checked_at"] - capture_at > root["interval_s"]
            )
            message, severity = None, "warning"
            if state == "unknown" and observation["reason"] in (
                "ambiguous_worker_records",
                "worker_evidence_mismatch",
            ):
                message = "Worker evidence for the root capture is ambiguous or inconsistent."
            elif state == "missing" and overdue:
                message = "No worker upload record is available for the scheduled capture."
            elif state == "failed":
                message, severity = (
                    "The backup worker reports a failed attempt for the capture.",
                    "high",
                )
            elif state == "reported" and overdue:
                if observation["uploaded_at"] is None:
                    message = "The backup worker has not reported an upload for the capture."
                elif observation["integrity_checked_at"] is None:
                    message = "The backup worker has not reported a full-data integrity check."
                elif observation["restored_bytes_at"] is None:
                    message = "The backup worker has not reported restored-byte verification."
            if message:
                findings.append(
                    Finding(
                        f"backup_worker:{project}",
                        severity,
                        project,
                        message,
                        blocked="worker observations do not authorize cleanup or recovery",
                    )
                )
        return observations, findings

    def cycle(self, now: float | None = None) -> dict[str, Any]:
        now = time.time() if now is None else now
        try:
            status = self.executor("platform_status", socket_path=self.socket_path)
        except ExecutorError as exc:
            snapshot = {
                "generated_at": now,
                "status_ok": False,
                "error": {"class": exc.error_class, "message": exc.message},
                "findings": [
                    asdict(
                        Finding(
                            "status_unavailable",
                            "critical",
                            "executor",
                            "Verified host status is unavailable.",
                        )
                    )
                ],
            }
            self._export(snapshot)
            return snapshot
        findings = evaluate(status, self.failures)
        backup_observations, backup_findings = self.backup_evidence(status)
        findings.extend(backup_findings)
        if self.risk is not None and (
            not self.require_containment_status or status.get("containment_enabled") is True
        ):
            try:
                findings.extend(Finding(**item) for item in self.risk.run(now))
            except Exception as exc:  # noqa: BLE001 - risk handling must not stop observation
                findings.append(
                    Finding("risk_cycle_error", "high", "controller", type(exc).__name__)
                )
        findings.extend(self.retention_findings(now))
        self._correlate(findings)
        for finding in findings:
            if not finding.remediation or status["kill_switch"]:
                if finding.remediation:
                    finding.blocked = "kill switch is active"
                continue
            key = f"{finding.remediation}:{finding.target}"
            if now - self.last_attempt.get(key, 0) < COOLDOWN_S:
                finding.blocked = "cooling down after the last attempt"
                continue
            self.last_attempt[key] = now
            params = dict(finding.params)
            if finding.remediation == "workload_restart":
                params["reason"] = f"controller: {finding.id}"
            try:
                self.executor(
                    finding.remediation,
                    params,
                    socket_path=self.socket_path,
                    request_id=f"{finding.correlation_id}-{uuid.uuid4().hex[:8]}",
                )
                self.actions.append(
                    "remediation",
                    finding=finding.id,
                    action=finding.remediation,
                    target=finding.target,
                    correlation_id=finding.correlation_id,
                    outcome="ok",
                )
            except ExecutorError as exc:
                # Escalate with the concrete cause instead of retrying blindly.
                finding.blocked = f"escalated: {exc.error_class} ({exc.message})"
                self.actions.append(
                    "remediation",
                    finding=finding.id,
                    action=finding.remediation,
                    target=finding.target,
                    correlation_id=finding.correlation_id,
                    outcome=exc.error_class,
                    detail=exc.message,
                )
        try:
            rollback = self.auto_rollback(status, now)
        except Exception as exc:  # noqa: BLE001 - never stop observation
            rollback = {"state": "error", "reason": type(exc).__name__}
        try:
            patch = self.patch_updates(status, now)
        except Exception as exc:  # noqa: BLE001 - the patch path must never stop observation
            patch = {"state": "error", "reason": type(exc).__name__}
        try:
            drills = self.drills.run(status, now)
        except Exception as exc:  # noqa: BLE001 - drills must never stop observation
            drills = {"state": "error", "reason": type(exc).__name__}
        snapshot = {
            "generated_at": now,
            "status_ok": True,
            "status": status,
            "patch": patch,
            "rollback": rollback,
            "drills": drills,
            "backup_observations": backup_observations,
            "findings": [asdict(f) for f in findings],
            "actions": self.actions.read(100),
        }
        self._export(snapshot)
        return snapshot

    def patch_updates(self, status: dict[str, Any], now: float) -> dict[str, Any]:
        """The `patch` profile: request one validated, approved update inside the window.

        Only `update_status` (read) and `apply_verified_image` are ever called; evidence,
        window, backup, revision, lock, budget and kill switch are rechecked by the
        executor. Without the profile nothing is requested and nothing is read."""
        if status.get("automation_profile") != "patch":
            return {"state": "off"}
        self.stability.observe(status, now)  # also outside the window: health time accrues
        blocked = global_block(status)
        if blocked:
            return {"state": "blocked", "reason": blocked}
        approvals: dict[str, list[dict[str, Any]]] = {}
        verify_s: dict[str, int] = {}
        healthy_s: dict[str, int] = {}
        unknown = []
        for project in sorted(status.get("projects", {})):
            try:
                result = self.executor(
                    "update_status", {"project_id": project}, socket_path=self.socket_path
                )
                approvals[project] = list(result["approvals"])
                if type(result.get("verify_timeout_s")) is int:
                    verify_s[project] = result["verify_timeout_s"]
                healthy_s[project] = min_healthy_s(result)
            except (ExecutorError, KeyError, TypeError):
                unknown.append(project)  # unreadable approvals never select an update
        healthy_for = {p: self.stability.healthy_for(p, now) for p in approvals}
        chosen, skipped = select_update(status, approvals, now, healthy_for, healthy_s)
        skipped.update({p: "approvals could not be read" for p in unknown})
        report: dict[str, Any] = {"state": "idle", "skipped": skipped}
        if chosen is None:
            return report
        key = f"{APPLY_ACTION}:{chosen['project_id']}"
        if now - self.last_attempt.get(key, 0) < COOLDOWN_S:
            return {**report, "state": "cooling_down", "target": chosen["project_id"]}
        self.last_attempt[key] = now
        outcome, detail = "ok", None
        try:
            self.executor(
                APPLY_ACTION,
                chosen,
                socket_path=self.socket_path,
                request_id=f"patch-{uuid.uuid4().hex[:16]}",
                timeout=update_call_timeout(verify_s.get(chosen["project_id"], 600)),
            )
        except ExecutorError as exc:
            outcome, detail = exc.error_class, exc.message
            if exc.error_class == "unavailable" or exc.outcome_unknown:
                # The executor may still be working (or recovering): never report
                # failure from the client side, read what the ledger says.
                outcome, detail = self._outcome_unknown(chosen)
        self.stability.reset(chosen["project_id"], now)  # health time restarts after an apply
        self.actions.append(
            "patch",
            action=APPLY_ACTION,
            target=chosen["project_id"],
            approval_id=chosen["approval_id"],
            outcome=outcome,
            detail=detail,
        )
        return {**report, "state": "requested", "target": chosen["project_id"], "outcome": outcome}

    def auto_rollback(self, status: dict[str, Any], now: float) -> dict[str, Any]:
        """Decision 15: roll back a just-applied `none` update that became durably unhealthy.

        Asks the executor's `rollback` action once per update; the executor re-derives the
        migration kind, window, health, profile and budget and refuses anything else. A
        migrating update is never touched here: it keeps escalating to the operator."""
        if rollback_block(status) is not None:
            return {"state": "off"}
        suspects = durable_suspects(status, self.failures)
        skipped: dict[str, str] = {}
        for project in suspects:
            try:
                result = self.executor(
                    "update_status", {"project_id": project}, socket_path=self.socket_path
                )
                candidate, reason = rollback_selection(result, project, now)
            except (ExecutorError, KeyError, TypeError):
                continue  # unreadable approvals never trigger a rollback
            if candidate is None:
                skipped[project] = reason or "no eligible update"
                continue
            key = f"rollback:{project}"
            if now - self.last_attempt.get(key, 0) < COOLDOWN_S:
                return {"state": "cooling_down", "target": project}
            self.last_attempt[key] = now
            params = {
                "project_id": project,
                "approval_id": candidate["approval_id"],
                "digest": candidate["digest"],
                "automatic": True,
            }
            outcome, detail = "ok", None
            try:
                self.executor(
                    "rollback",
                    params,
                    socket_path=self.socket_path,
                    request_id=f"rollback-{uuid.uuid4().hex[:16]}",
                    timeout=update_call_timeout(result.get("verify_timeout_s", 600)),
                )
            except ExecutorError as exc:
                outcome, detail = exc.error_class, exc.message
            self.stability.reset(project, now)
            self.actions.append(
                "auto_rollback",
                action="rollback",
                target=project,
                approval_id=candidate["approval_id"],
                outcome=outcome,
                detail=detail,
            )
            return {"state": "requested", "target": project, "outcome": outcome}
        return {"state": "idle", "skipped": skipped} if skipped else {"state": "idle"}

    def retention_findings(self, now: float) -> list[Finding]:
        """Decision 16: report update captures and preserved trees older than 30 days as
        cleanup candidates and hint before the limits. Read-only; nothing is removed."""
        if now - self._retention_at < RETENTION_INTERVAL_S:
            return self._retention
        self._retention_at = now
        try:
            report = self.executor("update_retention_status", socket_path=self.socket_path)
            out: list[Finding] = []
            for project, item in sorted(report["projects"].items()):
                if item["cleanup_candidates"]:
                    out.append(
                        Finding(
                            f"update_retention:{project}:candidates",
                            "info",
                            project,
                            f"{item['cleanup_candidates']} update capture(s) or preserved "
                            "data tree(s) are older than 30 days and are cleanup candidates "
                            "(steward-host update-retention).",
                            blocked="update captures and preserved data are never deleted "
                            "automatically",
                        )
                    )
                for name, label in (
                    ("preserved_trees", "preserved data trees"),
                    ("spool_captures", "captures in the executor spool"),
                ):
                    if item[name]["hint"]:
                        out.append(
                            Finding(
                                f"update_retention:{project}:{name}",
                                "warning",
                                project,
                                f"{item[name]['count']} of {item[name]['limit']} {label}: "
                                "export and remove old ones before the limit blocks an "
                                "update or restore.",
                                blocked="data is never deleted automatically",
                            )
                        )
            self._retention = out
        except Exception:  # noqa: BLE001 - an optional hint never stops observation
            self._retention = []
        return self._retention

    def _outcome_unknown(self, chosen: dict[str, str]) -> tuple[str, str]:
        try:
            result = self.executor(
                "update_status", {"project_id": chosen["project_id"]}, socket_path=self.socket_path
            )
            row = next(
                (a for a in result["approvals"] if a.get("approval_id") == chosen["approval_id"]),
                None,
            )
            state = row.get("state") if row else None
        except (ExecutorError, KeyError, TypeError):
            state = None
        return "outcome_unknown", f"client timeout or dropped connection; ledger state: {state}"

    def _export(self, snapshot: dict[str, Any]) -> None:
        self.export_dir.mkdir(parents=True, exist_ok=True)
        tmp = self.export_dir / "state.json.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(snapshot, handle)
        os.replace(tmp, self.export_dir / "state.json")


def _scanner_unavailable(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
    raise ExecutorError("unavailable", "scanner observations are unavailable")


def main() -> None:
    parser = argparse.ArgumentParser(description="steward self-management controller")
    parser.add_argument("--state-dir", default=STATE_DIR)
    parser.add_argument("--socket", default=DEFAULT_SOCKET)
    parser.add_argument("--backup-socket", default=None)
    parser.add_argument("--interval", type=int, default=INTERVAL_S)
    parser.add_argument("--scan-observations", action="store_true")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    os.umask(0o027)
    scan_query = _scanner_unavailable
    if args.scan_observations:
        try:
            uid = pwd.getpwnam("steward-scan").pw_uid
        except (KeyError, OSError):
            uid = 0
        if uid > 0:
            scan_query = partial(call, socket_path=SCAN_SOCKET, expected_peer_uid=uid)
    controller = Controller(
        args.state_dir, args.socket, backup_socket=args.backup_socket, scan_query=scan_query
    )
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    while not stop.is_set():
        try:
            controller.cycle()
        except Exception as exc:  # noqa: BLE001 - keep observing
            print(f"cycle failed: {type(exc).__name__}: {exc}", flush=True)
        if args.once:
            break
        stop.wait(args.interval)


if __name__ == "__main__":
    main()
