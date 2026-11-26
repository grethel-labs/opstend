"""Controller-side driver for the critical-risk response (L07/L08).

Reads exposure and incident state from the executor, normalizes scan evidence
with the fixed decision table (`critical_risk`) and only ever *requests*: it
opens an incident for a critical finding and ticks the executor's state machine.
The executor re-derives exposure, keeps the deadline on its own clock and
enforces every gate, so a wrong or missing input here can delay containment
(and is reported) but cannot trigger or skip it. Missing, stale or failed scan
evidence is surfaced as an unknown-evidence escalation, never as a clean result.
"""

from __future__ import annotations

import json
import time
import uuid
from collections import deque
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import Any

from pydantic import TypeAdapter

from ..executor.protocol import MAX_MESSAGE_BYTES, ExecutorError
from . import critical_risk as risk
from .images import image_id
from .inventory import Digest
from .vulnerabilities import ScanResult

Call = Callable[..., dict[str, Any]]
Source = Callable[[], list[dict[str, Any]] | None]
SCAN_READ_TIMEOUT_S = 5.0
SCAN_READ_MAX_PAGES = 128
DIGEST = TypeAdapter(Digest)
ACTIVE_FOR_ADVANCE = frozenset(
    {
        "notice",
        "disconnecting",
        "disconnect_failed",
        "disconnected",
        "backup_pending",
        "backup_failed",
        "backup_verified",
        "stopping",
        "stop_failed",
        "quarantined",
        "fix_verification",
        "reactivating",
        "reactivation_failed",
    }
)
REACTIVATION_PHASES = frozenset(
    {"quarantined", "fix_verification", "reactivating", "reactivation_failed"}
)
FAILURES = {
    "disconnect_failed": "Exposure removal failed; the application is still reachable.",
    "backup_failed": "Backup failed; the stack stays running but disconnected.",
    "stop_failed": "Quarantine shutdown failed; the stack is disconnected.",
    "reactivation_failed": "Route restore failed; the application stays disconnected.",
}


def scan_evidence(record: dict[str, Any]) -> dict[str, Any] | None:
    """The `ScanResult` view of an observation record, or None when it is not one."""
    try:
        value = {k: v for k, v in record.items() if k in ScanResult.model_fields}
        return ScanResult.model_validate(value).model_dump(mode="json")
    except ValueError:
        return None


def _exact_scan(record: dict, scope: str) -> ScanResult:
    scan = ScanResult.model_validate(
        {k: v for k, v in record.items() if k in ScanResult.model_fields}
    )
    subject = scan.subject
    if (
        scan.source != "trivy"
        or subject.kind != "image"
        or subject.scope != scope
        or not subject.runtime_verified
        or not image_id(subject.expected_image_id)
        or record.get("subject_key") != subject.key
        or scan.state not in ("confirmed", "not_affected")
        or scan.database_updated_at is None
    ):
        raise ValueError("scan is not current exact Trivy evidence")
    return scan


def _target_services(reach: dict[str, str], incident: dict | None) -> set[str]:
    exposed = {service for service, value in reach.items() if value != "none"}
    return (
        exposed | {finding["service"] for finding in incident["findings"]} if incident else exposed
    )


@dataclass
class ScopeEvidence:
    scans: list[ScanResult]
    complete: bool = False
    total: int | None = None

    def exact_result(self) -> ScanResult | None:
        if not self.complete or not self.scans:
            return None
        return self.scans[0].model_copy(
            update={"findings": [finding for scan in self.scans for finding in scan.findings]}
        )


class ScannerRead:
    """A single bounded read of one snapshot, shared across all applications."""

    def __init__(self, query: Call, revision: str):
        self.query = query
        self.revision = revision
        self.deadline = time.monotonic() + SCAN_READ_TIMEOUT_S
        self.pages = 0
        self.snapshot: str | None = None

    def _page(self, scope: str, offset: int) -> dict:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ExecutorError("unavailable", "scan read deadline exceeded")
        params: dict[str, Any] = {"project": scope, "expected_revision": self.revision}
        if self.snapshot is not None:
            params["snapshot_id"] = self.snapshot
        if offset:
            params["finding_offset"] = offset
        self.pages += 1
        try:
            page = self.query("scans_query", params, timeout=remaining)
        except ExecutorError:
            raise
        except Exception as exc:  # noqa: BLE001 - scanner faults must not stop incident advancement
            raise ExecutorError("unavailable", "scan page unavailable") from exc
        if time.monotonic() >= self.deadline:
            raise ExecutorError("unavailable", "scan read deadline exceeded")
        snapshot = DIGEST.validate_python(page["snapshot_id"])
        if self.snapshot is not None and self.snapshot != snapshot:
            raise ExecutorError("conflict", "scan snapshot changed")
        self.snapshot = snapshot
        return page

    def read(self, scopes: list[str]) -> dict[str, ScopeEvidence]:
        evidence = {scope: ScopeEvidence([]) for scope in scopes}
        pending = deque(scopes)
        while pending and self.pages < SCAN_READ_MAX_PAGES and time.monotonic() < self.deadline:
            scope = pending.popleft()
            result = evidence[scope]
            offset = len(result.scans)
            try:
                page = self._page(scope, offset)
                records = page["records"]
                if (
                    type(page["total"]) is not int
                    or page["total"] != 1
                    or page["next_offset"] is not None
                    or not isinstance(records, list)
                    or len(records) != 1
                ):
                    continue
                record = records[0]
                scan = _exact_scan(record, scope)
                total = record["findings_total"]
                if (
                    type(total) is not int
                    or not 0 <= total <= 1000
                    or len(scan.findings) != (1 if scan.state == "confirmed" else 0)
                    or (scan.state == "confirmed") != (total > 0)
                ):
                    raise ValueError("invalid finding count")
                if offset and (
                    total != result.total
                    or scan.model_dump(exclude={"findings"})
                    != result.scans[0].model_dump(exclude={"findings"})
                ):
                    raise ValueError("scan changed during paging")
                result.total = total
                result.scans.append(scan)
                result.complete = len(result.scans) >= max(1, total)
                if not result.complete:
                    pending.append(scope)
            except ExecutorError as exc:
                if exc.error_class == "conflict":
                    return {}
            except (KeyError, TypeError, AttributeError, ValueError):
                # A later page can downgrade the same scan to stale or unknown.
                evidence[scope] = ScopeEvidence([])
        return evidence


class RiskCycle:
    def __init__(
        self,
        call: Call,
        source: Source,
        *,
        socket_path: str | None = None,
        scan_query: Call | None = None,
    ):
        self.call = call
        self.source = source
        self.socket_path = socket_path
        self.scan_query = scan_query
        self.scan_start = 0

    def _read(self, action: str) -> dict[str, Any]:
        extra = {"socket_path": self.socket_path} if self.socket_path else {}
        return self.call(action, {}, **extra)

    def _request(self, action: str, params: dict[str, Any], cid: str) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"request_id": f"{cid}-{uuid.uuid4().hex[:8]}"}
        if self.socket_path:
            kwargs["socket_path"] = self.socket_path
        return self.call(action, params, **kwargs)

    def run(self, now: float) -> list[dict[str, Any]]:
        """One cycle. The executor owns deadlines and the scanner timestamps its pages."""
        findings: list[dict[str, Any]] = []

        def add(fid: str, severity: str, target: str, summary: str, blocked: str | None = None):
            findings.append(
                {
                    "id": fid,
                    "severity": severity,
                    "target": target,
                    "summary": summary,
                    "blocked": blocked,
                }
            )

        try:
            self._read("containment_reassert")
        except ExecutorError as exc:
            if exc.error_class != "policy_denied":
                add(
                    "containment_reassert_failed",
                    "high",
                    "executor",
                    "Exposure containment could not be reasserted.",
                    exc.error_class,
                )
        try:
            state = self._read("incident_status")
        except ExecutorError as exc:
            if exc.error_class != "policy_denied":
                add(
                    "containment_unavailable",
                    "high",
                    "executor",
                    "Exposure containment state is unavailable.",
                    exc.error_class,
                )
            return findings

        records = None
        revision = state.get("config_revision")
        scanner = None
        if self.scan_query is not None:
            with suppress(ValueError):
                scanner = ScannerRead(self.scan_query, DIGEST.validate_python(revision))
        elif self.source is not None:
            # An unavailable injected source must not block incident advancement.
            with suppress(Exception):
                candidate = self.source()
                if isinstance(candidate, list):
                    records = candidate
        incidents = {i["application"]: i for i in state["incidents"]}
        scanner_evidence = {}
        if scanner:
            scopes = sorted(
                f"{application}/{service}"
                for application, info in state["applications"].items()
                for service in _target_services(info["exposure"], incidents.get(application))
            )
            if scopes:
                start = self.scan_start % len(scopes)
                self.scan_start = start + 1
                scanner_evidence = scanner.read(scopes[start:] + scopes[:start])
        for application, info in state["applications"].items():
            target = f"application:{application}"
            incident = incidents.get(application)
            cid = incident["id"] if incident else "none"
            reach = info["exposure"]
            exposed = {service for service, value in reach.items() if value != "none"}
            evidence = {}
            for service in _target_services(reach, incident):
                scope = f"{application}/{service}"
                evidence[service] = (
                    scanner_evidence.get(scope, ScopeEvidence([]))
                    if scanner
                    else self._fixture_evidence(records, scope, now)
                )
            critical = {}
            for service in sorted(exposed):
                observed = evidence[service]
                for scan in observed.scans:
                    for item in risk.evidence_from_record(scan.model_dump(mode="json")):
                        decision = risk.decide(item, reach[service])
                        if decision.verdict == "critical_exploited" or (
                            decision.verdict == "critical" and service not in critical
                        ):
                            critical[service] = {
                                "service": service,
                                "advisory": decision.advisory,
                                "verdict": decision.verdict,
                                "binding": {
                                    "image": scan.subject.image,
                                    "image_id": image_id(scan.subject.expected_image_id),
                                },
                            }
            if any(not observed.complete for observed in evidence.values()) or any(
                value == "unknown" for value in reach.values()
            ):
                if records is None and scanner is None:
                    add(
                        f"risk_evidence_unavailable:{application}",
                        "high",
                        target,
                        "Vulnerability evidence is unavailable and coverage is unknown.",
                    )
                else:
                    add(
                        f"risk_unknown:{application}",
                        "high",
                        target,
                        "Exposure or scan coverage is unknown, incomplete or stale.",
                    )

            def blocked(
                exc: ExecutorError, application: str = application, target: str = target
            ) -> None:
                add(
                    f"incident_blocked:{application}",
                    "critical",
                    target,
                    "A critical exposed finding could not be handled automatically.",
                    f"escalated: {exc.error_class}",
                )

            open_refused = False
            if revision and critical:
                try:
                    opened = self._request(
                        "incident_open",
                        {
                            "application": application,
                            "expected_revision": revision,
                            "findings": list(critical.values()),
                        },
                        cid,
                    )
                    incident = opened["incident"]
                except ExecutorError as exc:
                    open_refused = True
                    blocked(exc)
            if incident and incident["phase"] in ACTIVE_FOR_ADVANCE:
                try:
                    result = self._request(
                        "incident_advance", {"application": application}, incident["id"]
                    )
                    if result.get("state") in REACTIVATION_PHASES and revision and not open_refused:
                        self._try_reactivate(application, result["incident"], revision, evidence)
                    if result.get("state") in FAILURES:
                        add(
                            f"incident_{result['state']}:{application}",
                            "critical",
                            target,
                            FAILURES[result["state"]],
                        )
                except ExecutorError as exc:
                    blocked(exc)
        return findings

    @staticmethod
    def _fixture_evidence(records: list[dict] | None, scope: str, now: float) -> ScopeEvidence:
        matches = [
            record
            for record in records or []
            if isinstance(record, dict)
            and isinstance(record.get("subject"), dict)
            and record["subject"].get("scope") == scope
        ]
        if len(matches) != 1:
            return ScopeEvidence([])
        record = matches[0]
        try:
            scan = _exact_scan(record, scope)
        except (TypeError, ValueError):
            return ScopeEvidence([])
        if scan.state_at(now, inventory_revision=scan.inventory_revision) != scan.state:
            return ScopeEvidence([])
        return ScopeEvidence([scan], record.get("findings_total") == len(scan.findings))

    def _try_reactivate(
        self, application: str, incident: dict, revision: str, evidence: dict[str, ScopeEvidence]
    ) -> None:
        affected = {f["service"] for f in incident["findings"]}
        scans = []
        size = 0
        exact = {
            service: evidence.get(service, ScopeEvidence([])).exact_result() for service in affected
        }
        complete = all(scan is not None for scan in exact.values())
        for service, scan in sorted(exact.items()):
            if scan is None or (scan.state == "not_affected" and not complete):
                continue
            item = {"service": service, "scan": scan.model_dump(mode="json")}
            size += len(json.dumps(item)) + 2
            if len(scans) >= 64 or size > MAX_MESSAGE_BYTES - 1024:
                scans = [item for item in scans if item["scan"]["state"] == "confirmed"]
                break
            scans.append(item)
        self._request(
            "incident_reactivate",
            {"application": application, "expected_revision": revision, "evidence": scans},
            incident["id"],
        )
