"""Event collector.

Runs as its own identity without host privileges and without network. Each
cycle it pulls, through the executor, new executor audit records and new
warnings/errors from the journals of registered components (already redacted
by the executor), reads the controller's snapshot, and turns all of it into
normalized events. Cursors are stored in the same transaction as the events,
so a crash never loses or duplicates an event.

Readers query events through the collector's own socket; the database file is
not shared with any other trust domain.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import signal
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .core import ipc
from .core.backup_changes import Change
from .core.events import SEVERITIES, Event, EventStore, correlation_from_request
from .core.ids import valid_request_id
from .executor.protocol import DEFAULT_SOCKET, PROTOCOL_VERSION, ExecutorError, call
from .executor.server import ACTIONS

STATE_DIR = "/var/lib/steward-collector"
QUERY_SOCKET = "/run/steward-collector/query.sock"
CONTROLLER_EXPORT = "/var/lib/steward-controller/export/state.json"
INTERVAL_S = 15
SNAPSHOT_STALE_S = 120
AUDIT_BATCH = 500
JOURNAL_BATCH = 500
JOURNAL_BACKLOG_CYCLES = 3
LOG_EVENTS_PER_UNIT = 50
MAINTENANCE_ANNOUNCE_LEAD_S = 24 * 3600
TARGET_OF = {"firewall_reassert": "firewall", "proxy_restart": "proxy"}


# ---- mapping: executor audit -> events ------------------------------------------------


def audit_events(entry: dict[str, Any]) -> list[Event]:
    kind = entry.get("event")
    ts = float(entry.get("ts", time.time()))
    ref = str(entry.get("hash"))
    if kind == "backup_retirement":
        outcome = entry.get("outcome")
        namespace = entry.get("namespace")
        if outcome == "started":
            return []
        allowed = {
            "removed",
            "already_absent",
            "already_resolved",
            "policy_denied",
            "target_busy",
            "kill_switch",
            "unavailable",
            "internal",
        }
        if not isinstance(outcome, str) or outcome not in allowed:
            outcome = "internal"
        if namespace not in ("capture", "import"):
            namespace = "unknown"
        success = outcome in ("removed", "already_absent", "already_resolved")
        project = entry.get("project_id")
        return [
            Event(
                ts=ts,
                source="executor",
                source_ref=ref,
                kind="backup.retirement",
                severity="info"
                if success
                else "high"
                if outcome in ("unavailable", "internal")
                else "warning",
                project=project,
                target=project,
                outcome=outcome,
                summary="Backup retention completed."
                if success
                else "Backup retention was refused or interrupted.",
                data={"namespace": namespace, "automatic": entry.get("automatic") is True},
            )
        ]
    if kind == "backup_capacity":
        namespace = entry.get("namespace")
        reason = entry.get("reason")
        if namespace not in ("capture", "import", "metadata", "worker") or reason not in (
            "limit",
            "space",
        ):
            return []
        reported = namespace == "worker"
        if reported and (entry.get("reported_by") != "backup" or reason != "limit"):
            return []
        project = None if reported else entry.get("project_id")
        data = {"namespace": namespace, "reason": reason}
        if reported:
            data["reported_by"] = "backup"
        return [
            Event(
                ts=ts,
                source="executor",
                source_ref=ref,
                kind="backup.capacity",
                severity="high",
                project=project,
                target="backup-worker" if reported else project,
                outcome="refused",
                summary="The backup worker reported its job capacity is full."
                if reported
                else "Backup storage capacity prevented an operation.",
                data=data,
            )
        ]
    if kind in ("backup_pause", "backup_resume", "backup_schedule"):
        outcome = str(entry.get("outcome"))
        project = entry.get("project_id")
        return [
            Event(
                ts=ts,
                source="executor",
                source_ref=ref,
                kind={
                    "backup_pause": "backup.pause",
                    "backup_resume": "backup.resume",
                    "backup_schedule": "backup.schedule",
                }[kind],
                severity="info" if outcome in ("prepared", "ok", "accepted_current") else "high",
                project=project,
                target=project,
                outcome=outcome,
                correlation_id=correlation_from_request(entry.get("artifact")),
                summary=f"Backup pause lifecycle: {kind}, {outcome}.",
                data={"automatic": entry.get("automatic", False)},
            )
        ]
    if kind in ("update_emergency", "update_auto_rollback"):
        outcome = str(entry.get("outcome"))[:40]
        project = str(entry.get("project_id"))[:60]
        emergency = kind == "update_emergency"
        return [
            Event(
                ts=ts,
                source="executor",
                source_ref=ref,
                kind="update.emergency" if emergency else "update.auto_rollback",
                severity="high",
                project=project,
                target=project,
                outcome=outcome,
                summary=(
                    f"Operator emergency update outside the maintenance window: {outcome}."
                    if emergency
                    else f"Automatic rollback of an unhealthy update: {outcome}."
                ),
                data={
                    "approval_id": str(entry.get("approval_id"))[:64],
                    "reason": str(entry.get("reason"))[:200],
                    "role": str(entry.get("role"))[:20],
                },
            )
        ]
    if kind == "incident":
        outcome = str(entry.get("outcome"))[:40]
        correlation = entry.get("correlation_id")
        failed = outcome == "escalated" or outcome == "fix_rejected"
        return [
            Event(
                ts=ts,
                source="executor",
                source_ref=ref,
                kind=f"incident.{outcome}",
                severity="high" if failed else "critical" if outcome == "opened" else "warning",
                project=str(entry.get("application"))[:60],
                correlation_id=correlation if valid_request_id(correlation) else None,
                outcome=outcome,
                summary=f"Incident {entry.get('incident_id')}: {outcome} ({entry.get('phase')}).",
                data={"phase": entry.get("phase"), "reason": entry.get("reason")},
            )
        ]
    if kind == "maintenance_run":
        outcome = entry.get("outcome")
        if outcome not in ("started", "completed", "failed"):
            return []
        run_id = entry.get("run_id")
        work = str(entry.get("work"))[:40]
        return [
            Event(
                ts=ts,
                source="executor",
                source_ref=ref,
                kind=f"maintenance.{outcome}",
                severity="high" if outcome == "failed" else "info",
                target="host",
                correlation_id=run_id if valid_request_id(run_id) else None,
                outcome=outcome,
                summary=f"Maintenance work {work} {outcome}.",
                data={
                    "work": work,
                    "window_start": entry.get("window_start"),
                    "window_end": entry.get("window_end"),
                    "cause": entry.get("cause"),
                },
            )
        ]
    if kind == "maintenance_drill":
        outcome = entry.get("outcome")
        if outcome not in ("announced", "started", "completed", "failed", "released"):
            return []
        run_id = entry.get("run_id")
        drill = str(entry.get("drill") or "")[:20]
        service = entry.get("service")
        keys = ("drill", "drills", "elapsed_s", "cause", "suspended", "window_start", "window_end")
        return [
            Event(
                ts=ts,
                source="executor",
                source_ref=ref,
                kind=f"maintenance.drill_{outcome}",
                severity="high" if outcome == "failed" else "info",
                project=str(service)[:60] if service and service != "host" else None,
                target="host",
                correlation_id=run_id if valid_request_id(run_id) else None,
                outcome=outcome,
                summary=f"Maintenance drill {drill or 'set'} {outcome}.",
                data={key: entry[key] for key in keys if entry.get(key) is not None},
            )
        ]
    if kind == "request":
        action = str(entry.get("action"))
        outcome = str(entry.get("outcome"))
        params = entry.get("params") if isinstance(entry.get("params"), dict) else {}
        project = params.get("project_id")
        target = project or TARGET_OF.get(action)
        known = ACTIONS.get(action)
        detail = f" ({entry['detail']})" if entry.get("detail") else ""
        common = {
            "ts": ts,
            "source": "executor",
            "source_ref": ref,
            "project": project,
            "target": target,
            "outcome": outcome,
            "correlation_id": correlation_from_request(entry.get("request_id")),
            "data": {"role": entry.get("role"), "action": action},
        }
        if known is not None and known.mutating:
            severity = (
                "info"
                if outcome == "ok"
                else "high"
                if outcome in ("budget_exhausted", "execution_failed", "internal")
                else "warning"
            )
            return [
                Event(
                    kind=f"action.{action}",
                    severity=severity,
                    summary=f"{action} requested by {entry.get('role')}: {outcome}{detail}",
                    **common,
                )
            ]
        if outcome != "ok":
            severity = "high" if outcome == "unauthorized_peer" else "warning"
            return [
                Event(
                    kind="request.denied",
                    severity=severity,
                    summary=f"refused {action} from {entry.get('role') or 'unknown peer'}: "
                    f"{outcome}{detail}",
                    **common,
                )
            ]
        return []
    if kind == "kill_switch":
        state = "on" if entry.get("state") == "on" else "off"
        return [
            Event(
                ts=ts,
                source="executor",
                source_ref=ref,
                kind=f"kill_switch.{state}",
                severity="warning",
                target="host",
                summary=f"Kill switch {state} (by {entry.get('by', 'unknown')}).",
            )
        ]
    if kind == "deployment":
        outcome = str(entry.get("outcome", "verified"))
        release = entry.get("release")
        revision = str(entry.get("revision", ""))[:12]
        summary = (
            f"Host verification passed for release {release} (configuration {revision})."
            if outcome == "host_verified"
            else f"Deployment of release {release} applied and verified (configuration {revision})."
        )
        return [
            Event(
                ts=ts,
                source="executor",
                source_ref=ref,
                kind="deployment",
                severity="info",
                target="host",
                outcome=outcome,
                summary=summary,
                data={"revision": entry.get("revision"), "release": entry.get("release")},
            )
        ]
    if kind == "executor_start":
        return [
            Event(
                ts=ts,
                source="executor",
                source_ref=ref,
                kind="platform.executor_start",
                severity="info",
                target="executor",
                summary="Host executor started.",
            )
        ]
    return []  # `reads` summaries and unknown records carry no event


# ---- mapping: controller snapshot -> events ---------------------------------------------


def snapshot_events(
    snapshot: dict[str, Any], previous: dict[str, dict[str, Any]], now: float
) -> tuple[list[Event], dict[str, dict[str, Any]]]:
    """Diff the controller's open findings against the last known set."""
    projects = set((snapshot.get("status") or {}).get("projects", {}))
    current: dict[str, dict[str, Any]] = {}
    events: list[Event] = []
    for finding in snapshot.get("findings") or []:
        fid = str(finding["id"])
        known = previous.get(fid)
        corr = finding.get("correlation_id") or (known or {}).get("correlation_id")
        corr = corr or f"f-{uuid.uuid4().hex[:16]}"
        target = finding.get("target")
        project = target if target in projects else None
        blocked = finding.get("blocked") or ""
        current[fid] = {
            "correlation_id": corr,
            "severity": finding["severity"],
            "escalated": blocked if blocked.startswith("escalated") else None,
            "target": target,
            "project": project,
            "summary": finding.get("summary", ""),
        }
        if known is None:
            events.append(
                Event(
                    ts=now,
                    source="controller",
                    source_ref=f"{corr}:opened",
                    kind="finding.opened",
                    severity=finding["severity"],
                    project=project,
                    target=target,
                    correlation_id=corr,
                    summary=finding.get("summary", fid),
                    data={
                        "finding": fid,
                        "remediation": finding.get("remediation"),
                        "blocked": blocked or None,
                    },
                )
            )
        escalated = current[fid]["escalated"]
        if escalated and escalated != (known or {}).get("escalated"):
            events.append(
                Event(
                    ts=now,
                    source="controller",
                    source_ref=f"{corr}:escalated:{hashlib.sha256(escalated.encode()).hexdigest()[:16]}",
                    kind="finding.escalated",
                    severity="high",
                    project=project,
                    target=target,
                    correlation_id=corr,
                    outcome="escalated",
                    summary=f"{finding.get('summary', fid)} Automatic handling failed: {escalated}",
                    data={"finding": fid},
                )
            )
    for fid, known in previous.items():
        if fid not in current:
            events.append(
                Event(
                    ts=now,
                    source="controller",
                    source_ref=f"{known['correlation_id']}:resolved",
                    kind="finding.resolved",
                    severity="info",
                    project=known.get("project"),
                    target=known.get("target"),
                    correlation_id=known["correlation_id"],
                    outcome="resolved",
                    summary=f"Resolved: {known.get('summary') or fid}",
                    data={"finding": fid},
                )
            )
    return events, current


def maintenance_events(snapshot: dict[str, Any], now: float) -> list[Event]:
    """Announce the regular window once, a day ahead (or while it is open).

    The source_ref names the window start, so repeated cycles and restarts add
    nothing. Only the executor's reported summary is used; a policy that is not
    valid or a missing summary announces nothing.
    """
    summary = (snapshot.get("status") or {}).get("maintenance")
    if not isinstance(summary, dict) or summary.get("state") not in ("in_window", "outside_window"):
        return []
    window = summary.get("current_window") or summary.get("next_window")
    try:
        start = datetime.fromisoformat(window["start"])
        end = datetime.fromisoformat(window["end"])
    except (KeyError, TypeError, ValueError):
        return []
    if start.timestamp() - now > MAINTENANCE_ANNOUNCE_LEAD_S:
        return []
    return [
        Event(
            ts=now,
            source="controller",
            source_ref=f"maintenance:announced:{window['start']}",
            kind="maintenance.window_announced",
            severity="info",
            target="host",
            outcome="announced",
            summary=(
                f"Regular maintenance window {start:%Y-%m-%d %H:%M} to {end:%H:%M} UTC. "
                "Planned maintenance work runs only inside it."
            ),
            data={
                "window_start": window["start"],
                "window_end": window["end"],
                "allow_reboot": summary.get("allow_reboot") is True,
            },
        )
    ]


# ---- collector ----------------------------------------------------------------------------


class Collector:
    def __init__(
        self,
        state_dir: str,
        *,
        executor=call,
        executor_socket: str = DEFAULT_SOCKET,
        controller_export: str = CONTROLLER_EXPORT,
        retention_days: int = 30,
        max_events: int = 200_000,
        scanner_socket: str | None = None,
        scanner=call,
        backup_socket: str | None = None,
        backup=call,
    ):
        self.store = EventStore(Path(state_dir) / "events.db")
        self.executor = executor
        self.executor_socket = executor_socket
        self.controller_export = Path(controller_export)
        self.retention_days = retention_days
        self.max_events = max_events
        self.scanner_socket, self.scanner = scanner_socket, scanner
        self.backup_socket, self.backup = backup_socket, backup

    # Gaps are tracked as state so that each gap produces exactly one opening and
    # one closing event, however long it lasts.
    def _gap(self, source: str, open_: bool, now: float, reason: str = "") -> list[Event]:
        gaps = {g["source"]: g for g in self.store.get_meta("open_gaps", [])}
        if open_ == (source in gaps):
            return []
        if open_:
            gaps[source] = {"source": source, "since": now, "reason": reason}
            event = Event(
                ts=now,
                source="collector",
                source_ref=f"gap:{source}:{now}",
                kind="observation_gap",
                severity="high",
                target=source,
                summary=f"Observation gap: {reason}",
            )
        else:
            since = gaps.pop(source)["since"]
            event = Event(
                ts=now,
                source="collector",
                source_ref=f"gap-closed:{source}:{since}",
                kind="observation_restored",
                severity="info",
                target=source,
                summary=f"Observation of {source} restored after {round(now - since)} s.",
            )
        self.store.add([event], {"open_gaps": list(gaps.values())})
        return [event]

    def _call(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        return self.executor(action, params, socket_path=self.executor_socket)

    def collect_audit(self, now: float) -> int:
        added = 0
        for _ in range(20):  # bounded catch-up per cycle
            cursor = self.store.get_meta("audit_cursor", {"offset": 0, "hash": ""})
            result = self._call(
                "audit_since",
                {"offset": cursor["offset"], "prev_hash": cursor["hash"], "limit": AUDIT_BATCH},
            )
            events: list[Event] = []
            if result["reset"]:
                events.append(
                    Event(
                        ts=now,
                        source="collector",
                        source_ref=f"audit-reset:{result['next_offset']}:{result['next_hash']}",
                        kind="audit.discontinuity",
                        severity="high",
                        target="executor",
                        summary="The executor audit no longer continues where it was last read "
                        "(rotated, truncated or rewritten). Records in between may be missing.",
                    )
                )
            for entry in result["entries"]:
                events.extend(audit_events(entry))
                view = {k: v for k, v in entry.items() if k not in ("hash", "prev")}
                truncated = len(json.dumps(view).encode()) > 2048
                events.append(
                    Event(
                        ts=float(entry["ts"]),
                        source="audit",
                        source_ref=entry["hash"],
                        kind="audit.record",
                        severity="info",
                        target="executor",
                        summary=f"Executor audit record: {entry.get('event', 'unknown')}.",
                        data={
                            "original_hash": entry["hash"],
                            "previous_hash": entry["prev"],
                            "redacted": True,
                            "view": {"truncated": True} if truncated else view,
                        },
                    )
                )
            next_cursor = {"offset": result["next_offset"], "hash": result["next_hash"]}
            added += self.store.add(events, {"audit_cursor": next_cursor})
            if not result["more"]:
                break
        return added

    def collect_journal(self, now: float) -> int:
        cursor = self.store.get_meta("journal_cursor")
        backlog = int(self.store.get_meta("journal_backlog", 0))
        if backlog >= JOURNAL_BACKLOG_CYCLES:
            result = self._call(
                "journal_since", {"cursor": cursor, "limit": 1, "skip_to_end": True}
            )
            event = Event(
                ts=now,
                source="collector",
                source_ref=f"backlog:{cursor}",
                kind="log.backlog",
                severity="warning",
                target="journal",
                summary="Log volume exceeded what the collector can keep up with; warnings "
                "and errors in between were skipped (still in the journal).",
            )
            return self.store.add(
                [event], {"journal_cursor": result["cursor"], "journal_backlog": 0}
            )
        result = self._call(
            "journal_since", {"cursor": cursor, "limit": JOURNAL_BATCH, "skip_to_end": False}
        )
        events: list[Event] = []
        per_unit: dict[str, int] = {}
        for entry in result["entries"]:
            unit = entry["unit"]
            per_unit[unit] = per_unit.get(unit, 0) + 1
            if per_unit[unit] > LOG_EVENTS_PER_UNIT:
                continue
            priority = entry["priority"]
            events.append(
                Event(
                    ts=entry["ts"],
                    source="journal",
                    source_ref=str(entry["cursor"]),
                    kind="log",
                    severity="high" if priority <= 2 else "warning" if priority == 3 else "info",
                    project=entry["owner"] if entry["owner"] not in (None, "proxy") else None,
                    target=entry["owner"] or unit,
                    summary=f"{unit}: {entry['message']}",
                    data={"unit": unit, "priority": priority},
                )
            )
        for unit, count in per_unit.items():
            if count > LOG_EVENTS_PER_UNIT:
                events.append(
                    Event(
                        ts=now,
                        source="collector",
                        source_ref=f"suppressed:{unit}:{result['cursor']}",
                        kind="log.suppressed",
                        severity="info",
                        target=unit,
                        summary=f"{unit}: {count - LOG_EVENTS_PER_UNIT} further log lines "
                        "in this interval not stored.",
                    )
                )
        meta = {
            "journal_cursor": result["cursor"],
            "journal_backlog": backlog + 1 if result["more"] else 0,
        }
        return self.store.add(events, meta)

    def collect_controller(self, now: float) -> int:
        try:
            snapshot = json.loads(self.controller_export.read_text(encoding="utf-8"))
            age = now - float(snapshot["generated_at"])
        except (OSError, ValueError, KeyError, TypeError):
            return len(self._gap("controller", True, now, "no controller snapshot readable"))
        if age > SNAPSHOT_STALE_S:
            return len(
                self._gap("controller", True, now, f"controller snapshot is {round(age)} s old")
            )
        added = len(self._gap("controller", False, now))
        previous = self.store.get_meta("open_findings", {})
        events, current = snapshot_events(snapshot, previous, now)
        events.extend(maintenance_events(snapshot, now))
        return added + self.store.add(events, {"open_findings": current})

    def collect_scanner(self, now: float) -> int:
        if not self.scanner_socket:
            return self._close_disabled_observation_gaps(now, "scanner", "Scanner")
        try:
            cursor = self.store.get_meta("scanner_cursor", {"stream": None, "id": 0})

            def changes(after_id):
                return self.scanner(
                    "scans_changes",
                    {"after_id": after_id, "limit": 200},
                    socket_path=self.scanner_socket,
                )

            result = changes(cursor["id"])
            coverage = result["coverage"]
            stream, oldest = coverage["stream_id"], coverage["oldest_id"]
            reset = cursor["stream"] is not None and cursor["stream"] != stream
            missing = oldest is not None and cursor["id"] < oldest - 1
            events = []
            if reset or missing:
                events.append(
                    Event(
                        ts=now,
                        source="scanner",
                        source_ref=f"gap:{stream}:{cursor['id']}:{oldest}",
                        kind="observation_gap",
                        severity="high",
                        target="scanner",
                        summary=(
                            "Scanner change history was reset or pruned; "
                            "earlier findings may be missing."
                        ),
                    )
                )
            if reset:
                result = changes(0)
                coverage = result["coverage"]
                if coverage["stream_id"] != stream:
                    raise ValueError("scanner feed changed again")
            for item in result["changes"]:
                events.append(
                    Event(
                        ts=item["ts"],
                        source="scanner",
                        source_ref=f"{stream}:{item['id']}",
                        kind=item["kind"],
                        severity=item["severity"],
                        summary=item["summary"],
                        project=None if item["scope"] == "host" else item["scope"],
                        target=item["scope"],
                        data=item["data"],
                    )
                )
            summary = self.scanner("scans_summary", {}, socket_path=self.scanner_socket)
            added = self.store.add(
                events,
                {
                    "scanner_cursor": {"stream": stream, "id": result["next_id"]},
                    "scanner_coverage": summary,
                },
            )
            stale = summary["enabled"] and (summary["stale"] or not summary.get("generated_at"))
            self._gap("scanner", bool(stale), now, "no recent scanner snapshot")
            backlog = (
                coverage["newest_id"] is not None and result["next_id"] < coverage["newest_id"]
            )
            self._gap("scanner_backlog", backlog, now, "scanner change feed not yet caught up")
            return added
        except (ExecutorError, ValueError, KeyError, TypeError):
            return len(self._gap("scanner", True, now, "scanner observations unavailable"))

    def _close_disabled_observation_gaps(self, now: float, source: str, label: str) -> int:
        names = {source, f"{source}_backlog"}
        gaps = self.store.get_meta("open_gaps", [])
        disabled = [gap for gap in gaps if gap["source"] in names]
        if not disabled:
            return 0
        events = [
            Event(
                ts=now,
                source="collector",
                source_ref=f"gap-disabled:{gap['source']}:{gap['since']}",
                kind="observation_disabled",
                severity="info",
                target=gap["source"],
                summary=f"{label} observation was disabled while the gap was open.",
            )
            for gap in disabled
        ]
        return self.store.add(
            events, {"open_gaps": [gap for gap in gaps if gap["source"] not in names]}
        )

    def collect_backup(self, now: float) -> int:
        """Ingest worker claims and the feed cursor in one collector transaction."""
        if not self.backup_socket:
            return self._close_disabled_observation_gaps(now, "backup", "Backup")
        try:
            cursor = self.store.get_meta("backup_cursor", {"stream": None, "id": 0})

            def read(after):
                result = self.backup(
                    "backups_changes",
                    {"after_id": after, "limit": 200},
                    socket_path=self.backup_socket,
                )
                coverage = result["coverage"]
                stream, oldest, newest = (
                    coverage["stream_id"],
                    coverage["oldest_id"],
                    coverage["newest_id"],
                )
                if (
                    not isinstance(stream, str)
                    or not re.fullmatch(r"[a-f0-9]{32}", stream)
                    or type(newest) is not int
                    or newest < 0
                    or (
                        oldest is not None
                        and (type(oldest) is not int or not 1 <= oldest <= newest)
                    )
                    or type(coverage["baseline"]) is not bool
                    or not isinstance(result["changes"], list)
                    or len(result["changes"]) > 200
                ):
                    raise ValueError("invalid backup coverage")
                items = [Change.model_validate(item) for item in result["changes"]]
                ids = [item.id for item in items]
                if (
                    ids != sorted(set(ids))
                    or any(i <= after or i > newest for i in ids)
                    or result["next_id"]
                    != (ids[-1] if ids else newest if after < newest else after)
                ):
                    raise ValueError("invalid backup cursor")
                return result, coverage, items

            result, coverage, items = read(cursor["id"])
            stream, oldest, newest = (
                coverage["stream_id"],
                coverage["oldest_id"],
                coverage["newest_id"],
            )
            reset = cursor["stream"] is not None and cursor["stream"] != stream
            rollback = cursor["id"] > newest
            baseline = cursor["stream"] is None and coverage["baseline"]
            after = cursor["id"]
            if reset or rollback:
                result, coverage, items = read(0)
                if coverage["stream_id"] != stream:
                    raise ValueError("backup feed changed again")
                oldest, newest = coverage["oldest_id"], coverage["newest_id"]
                after = 0
            expected = after + 1
            missing = False
            for item in items:
                if item.id != expected:
                    missing = True
                expected = item.id + 1
            if not items and after < newest:
                missing = True
            events = []
            if reset or rollback or missing or baseline:
                events.append(
                    Event(
                        ts=now,
                        source="backup",
                        source_ref=f"gap:{stream}:{cursor['stream']}:{cursor['id']}:{oldest}:{newest}",
                        kind="observation_gap",
                        severity="high",
                        target="backup-worker",
                        summary="Backup worker history was reset, pruned or predates observation.",
                        data={"reported_by": "backup", "baseline": baseline},
                    )
                )
            for item in items:
                if item.error and item.error != item.previous_error:
                    kind, severity = "backup.worker_failure", "high"
                    summary = "The backup worker reported an unsuccessful attempt."
                elif item.error is None and item.previous_error and item.state == "succeeded":
                    kind, severity = "backup.worker_recovered", "info"
                    summary = "The backup worker reported recovery of a previously failed job."
                else:
                    continue
                events.append(
                    Event(
                        ts=item.ts,
                        source="backup",
                        source_ref=f"{stream}:{item.id}",
                        kind=kind,
                        severity=severity,
                        project=item.project,
                        target=item.project,
                        outcome=item.state,
                        summary=summary,
                        data={
                            "reported_by": "backup",
                            "job_id": item.job_id,
                            "capture_id": item.capture_id,
                            "repository_id": item.repository_id,
                            "error": item.error,
                            "uploaded_at": item.uploaded_at,
                            "integrity_checked_at": item.integrity_checked_at,
                            "restored_bytes_at": item.restored_bytes_at,
                        },
                    )
                )
            added = self.store.add(
                events,
                {
                    "backup_cursor": {"stream": stream, "id": result["next_id"]},
                },
            )
            self._gap("backup", False, now)
            self._gap(
                "backup_backlog",
                result["next_id"] < coverage["newest_id"],
                now,
                "backup change feed not yet caught up",
            )
            return added
        except (ExecutorError, ValueError, KeyError, TypeError):
            return len(self._gap("backup", True, now, "backup observations unavailable"))

    def cycle(self, now: float | None = None) -> dict[str, Any]:
        now = time.time() if now is None else now
        counts: dict[str, Any] = {}
        try:
            counts["audit"] = self.collect_audit(now)
            counts["journal"] = self.collect_journal(now)
            self._gap("executor", False, now)
        except ExecutorError as exc:
            self._gap("executor", True, now, f"executor unavailable ({exc.error_class})")
            counts["executor_error"] = exc.error_class
        counts["controller"] = self.collect_controller(now)
        counts["scanner"] = self.collect_scanner(now)
        counts["backup"] = self.collect_backup(now)
        counts["pruned"] = self.store.prune(
            now=now, retention_days=self.retention_days, max_events=self.max_events
        )
        self.store.add([], {"last_cycle": now})
        return counts


# ---- query socket -----------------------------------------------------------------------


class QueryParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    since: float | None = None
    until: float | None = None
    project: str | None = Field(None, pattern=r"^[a-z][a-z0-9-]{1,30}[a-z0-9]$")
    min_severity: str = Field("info", pattern="^(" + "|".join(SEVERITIES) + ")$")
    kind_prefix: str | None = Field(None, pattern=r"^[a-z_.]{1,40}$")
    correlation_id: str | None = Field(None, pattern=r"^[A-Za-z0-9:_.-]{1,80}$")
    delivery: str | None = Field(None, pattern=r"^(immediate|digest|none)$")
    after_id: int | None = Field(None, ge=0)
    limit: int = Field(200, ge=1, le=500)


class QueryService:
    """Read-only access for registered readers. Roles come from peer credentials."""

    def __init__(self, store: EventStore, readers: dict[int, str]):
        self.store = store
        self.readers = readers

    def handle(self, raw: bytes, peer_uid: int) -> dict[str, Any]:
        try:
            if peer_uid != 0 and peer_uid not in self.readers:
                raise ExecutorError("unauthorized_peer", "peer is not a registered reader")
            try:
                request = json.loads(raw)
            except ValueError:
                raise ExecutorError("bad_request", "request is not valid JSON") from None
            if not isinstance(request, dict) or request.get("v") != PROTOCOL_VERSION:
                raise ExecutorError("bad_request", "unsupported protocol version")
            action = request.get("action")
            if action == "events_coverage":
                return {"ok": True, "result": self.store.coverage()}
            if action != "events_query":
                raise ExecutorError("unknown_action", "action is not registered")
            try:
                params = QueryParams.model_validate(request.get("params") or {})
            except ValidationError as exc:
                raise ExecutorError(
                    "bad_request", f"invalid parameters: {exc.error_count()} error(s)"
                ) from None
            rows = self.store.query(**params.model_dump())
            events, size = [], 0
            for event in rows:
                length = len(json.dumps(event, ensure_ascii=False).encode())
                if size + length > 128 * 1024:
                    break
                events.append(event)
                size += length
            return {
                "ok": True,
                "result": {
                    "events": events,
                    "coverage": self.store.coverage(),
                    "truncated": len(events) < len(rows),
                },
            }
        except ExecutorError as exc:
            return {"ok": False, "error_class": exc.error_class, "message": exc.message}
        except Exception as exc:  # noqa: BLE001 - answer every request
            return {"ok": False, "error_class": "internal", "message": type(exc).__name__}
        finally:
            self.store.close()


def resolve_readers(names: list[str]) -> dict[int, str]:
    readers = {}
    for name in names:
        role, _, user = name.partition("=")
        if not re.fullmatch(r"[a-z]+", role):
            continue
        try:
            readers[pwd.getpwnam(user).pw_uid] = role
        except KeyError:
            continue
    return readers


def main() -> None:
    parser = argparse.ArgumentParser(description="steward event collector")
    parser.add_argument("--state-dir", default=STATE_DIR)
    parser.add_argument("--executor-socket", default=DEFAULT_SOCKET)
    parser.add_argument("--query-socket", default=QUERY_SOCKET)
    parser.add_argument("--query-group", default="steward-obs")
    parser.add_argument("--controller-export", default=CONTROLLER_EXPORT)
    parser.add_argument("--scanner-socket", default="/run/steward-scanner/query.sock")
    parser.add_argument("--backup-socket", default=None)
    parser.add_argument(
        "--reader",
        action="append",
        default=["api=steward-api", "notifier=steward-notify", "bot=steward-bot"],
    )
    parser.add_argument("--retention-days", type=int, default=30)
    parser.add_argument("--max-events", type=int, default=200_000)
    parser.add_argument("--interval", type=int, default=INTERVAL_S)
    args = parser.parse_args()
    os.umask(0o077)
    collector = Collector(
        args.state_dir,
        executor_socket=args.executor_socket,
        controller_export=args.controller_export,
        retention_days=args.retention_days,
        max_events=args.max_events,
        scanner_socket=args.scanner_socket,
        backup_socket=args.backup_socket,
    )
    service = QueryService(collector.store, resolve_readers(args.reader))
    server = ipc.bind(args.query_socket, service.handle, args.query_group)
    threading.Thread(target=server.serve_forever, daemon=True, name="query").start()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    while not stop.is_set():
        try:
            collector.cycle()
        except Exception as exc:  # noqa: BLE001 - keep collecting
            print(f"cycle failed: {type(exc).__name__}: {exc}", flush=True)
        stop.wait(args.interval)
    server.shutdown()


if __name__ == "__main__":
    main()
