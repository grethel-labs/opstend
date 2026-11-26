"""Deterministic critical-risk decision (L07 steps 1 and 2).

A fixed table turns exact scan evidence, reachability, KEV/EPSS context and the
application's policy into one verdict. Nothing here calls a model, performs a
host action or trusts free text. Missing evidence is never a clean result: an
unknown, stale, failed or runtime-unbound observation yields `unknown`, which
escalates but can neither open nor close a containment on its own.

Decision table (first matching row wins, evaluated per finding):

| # | Evidence                                              | Verdict            |
|---|-------------------------------------------------------|--------------------|
| 1 | host-scope finding (sshd, kernel, host packages)      | `host_escalate`    |
| 2 | state not confirmed/not_affected, or not runtime-bound | `unknown`          |
| 3 | not_affected                                          | `clear`            |
| 4 | service not exposed (no route in its dependency path) | `unreachable`      |
| 5 | exposure cannot be derived                            | `unknown`          |
| 6 | KEV-listed and severity high/critical/unrated         | `critical_exploited` |
| 7 | severity critical, unless KEV *and* EPSS are both    | `critical`         |
|   | available and show not-listed and EPSS < EPSS_FLOOR   |                    |
| 8 | KEV-listed at lower severity; high or unrated severity;| `notify`          |
|   | critical with positive low-exploitability evidence    |                    |
| 9 | other confirmed finding                               | `monitor`          |

A high CVSS score alone never reaches `critical` (ADR 0002 section 5). The
EPSS floor is a product default (open question) and is the only numeric
threshold; the notice period and the known-exploited exception come from the
maintenance emergency policy (ADR 0002 sections 5 and 8).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from .intelligence import CVEContext

Verdict = Literal[
    "clear",
    "unreachable",
    "monitor",
    "notify",
    "unknown",
    "host_escalate",
    "critical",
    "critical_exploited",
]
RANK: dict[str, int] = {
    "clear": 0,
    "unreachable": 1,
    "monitor": 2,
    "notify": 3,
    "unknown": 4,
    "host_escalate": 5,
    "critical": 6,
    "critical_exploited": 7,
}
Exposure = Literal["direct", "indirect", "none", "unknown"]
Response = Literal["none", "notify", "escalate", "notice", "contain_now"]

EPSS_FLOOR = 0.10
DEFAULT_NOTICE_S = 3600
HOST_SCOPE = "host"


@dataclass(frozen=True)
class Policy:
    on_critical: Literal["quarantine", "notify"] = "quarantine"
    notice_s: int = DEFAULT_NOTICE_S
    immediate_if_known_exploited: bool = True


@dataclass(frozen=True)
class FindingEvidence:
    scope: str
    subject_key: str
    advisory: str
    state: str
    bound: bool
    severity: str = "unknown"
    kev: Literal["listed", "not_listed", "unknown"] = "unknown"
    epss: float | None = None


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str
    scope: str
    advisory: str


@dataclass(frozen=True)
class Assessment:
    verdict: Verdict
    decisions: tuple[Decision, ...]

    @property
    def exploited(self) -> bool:
        return any(d.verdict == "critical_exploited" for d in self.decisions)

    @property
    def critical(self) -> tuple[Decision, ...]:
        return tuple(d for d in self.decisions if d.verdict in ("critical", "critical_exploited"))


# ---- exposure from the application graph --------------------------------------------


def _closure(services: dict[str, Any], start: str) -> set[str]:
    seen: set[str] = set()
    pending = [start]
    while pending:
        name = pending.pop()
        if name in seen or name not in services:
            continue
        seen.add(name)
        pending.extend(services[name].get("depends_on", []))
    return seen


def routed_services(application: dict[str, Any]) -> set[str]:
    return {
        name
        for name, spec in application["services"].items()
        if spec.get("manage") is True and spec.get("deploy") is True and spec.get("routes")
    }


def exposure(application: dict[str, Any]) -> dict[str, Exposure]:
    """Direct (own route) or indirect (a dependency of a routed service) exposure."""
    services = application["services"]
    direct = routed_services(application)
    reached: set[str] = set()
    for name in direct:
        reached |= _closure(services, name)
    return {
        name: "direct" if name in direct else "indirect" if name in reached else "none"
        for name, spec in services.items()
    }


def exposers(application: dict[str, Any], service: str) -> list[str]:
    """Routed services whose route is the network path to `service`."""
    services = application["services"]
    return sorted(
        name for name in routed_services(application) if service in _closure(services, name)
    )


# ---- evidence normalization -----------------------------------------------------------


def _kev_epss(contexts: list[dict]) -> tuple[str, float | None]:
    parsed = []
    for value in contexts:
        try:
            parsed.append(CVEContext.model_validate(value))
        except ValueError:
            return "unknown", None
    if any(c.kev.state == "available" and c.kev.listed is True for c in parsed):
        kev = "listed"
    elif parsed and all(c.kev.state == "available" and c.kev.listed is False for c in parsed):
        kev = "not_listed"
    else:
        kev = "unknown"
    epss: float | None = None
    if parsed and all(c.epss.state == "available" and c.epss.score is not None for c in parsed):
        epss = max(c.epss.score for c in parsed if c.epss.score is not None)
    return kev, epss


def evidence_from_record(record: dict[str, Any]) -> list[FindingEvidence]:
    """Normalize one time-evaluated observation (`Observations.query` record).

    A record whose finding list is truncated is incomplete evidence: it adds an
    unbound entry so the page cannot be read as "no further findings".
    """
    subject = record.get("subject") or {}
    scope = str(subject.get("scope", ""))
    key = str(record.get("subject_key", ""))
    state = str(record.get("state", "unknown"))
    bound = subject.get("kind") != "image" or bool(
        subject.get("runtime_verified") and subject.get("expected_image_id")
    )
    if state != "confirmed":
        return [FindingEvidence(scope, key, "-", state, bound)]
    result = []
    findings = record.get("findings") or []
    for finding in findings:
        kev, epss = _kev_epss(finding.get("exploit_context") or [])
        result.append(
            FindingEvidence(
                scope,
                key,
                str(finding.get("id", "-")),
                state,
                bound,
                str(finding.get("severity", "unknown")),
                kev,  # type: ignore[arg-type]
                epss,
            )
        )
    if not findings or int(record.get("findings_total", len(findings))) > len(findings):
        result.append(FindingEvidence(scope, key, "-", "unknown", False))
    return result


# ---- the table ------------------------------------------------------------------------


def decide(evidence: FindingEvidence, reach: Exposure) -> Decision:
    def out(verdict: Verdict, reason: str) -> Decision:
        return Decision(verdict, reason, evidence.scope, evidence.advisory)

    if evidence.scope == HOST_SCOPE:
        if evidence.state == "confirmed" and evidence.bound:
            return out("host_escalate", "host_service_never_shut_down")
        return out("unknown", "host_evidence_unknown")
    if evidence.state not in ("confirmed", "not_affected") or not evidence.bound:
        return out(
            "unknown", "evidence_unbound" if not evidence.bound else "evidence_" + evidence.state
        )
    if evidence.state == "not_affected":
        return out("clear", "not_affected")
    if reach == "none":
        return out("unreachable", "no_route_in_dependency_path")
    if reach == "unknown":
        return out("unknown", "exposure_unknown")
    exploitable_severity = evidence.severity in ("high", "critical", "unknown")
    if evidence.kev == "listed" and exploitable_severity:
        return out("critical_exploited", "known_exploited")
    if evidence.severity == "critical":
        low = (
            evidence.kev == "not_listed"
            and evidence.epss is not None
            and evidence.epss < EPSS_FLOOR
        )
        if not low:
            return out("critical", "critical_severity_reachable")
        return out("notify", "critical_with_low_exploitability_evidence")
    if evidence.kev == "listed" or evidence.severity in ("high", "unknown"):
        return out("notify", "not_critical_by_table")
    return out("monitor", "low_severity")


def assess(
    reach: dict[str, Exposure], scope_services: dict[str, str], evidence: list[FindingEvidence]
) -> Assessment:
    """Combine per-finding decisions for one application.

    `reach` is the executor-derived exposure per service (`exposure()`).
    `scope_services` maps a scan scope to the application's service id; a scope
    that is not in it is not this application's evidence.
    """
    decisions = []
    for item in evidence:
        if item.scope == HOST_SCOPE:
            decisions.append(decide(item, "none"))
            continue
        service = scope_services.get(item.scope)
        if service is None:
            continue
        decisions.append(decide(item, reach.get(service, "unknown")))
    verdict: Verdict = max((d.verdict for d in decisions), key=RANK.__getitem__, default="clear")
    return Assessment(verdict, tuple(decisions))


def response(assessment: Assessment, policy: Policy) -> Response:
    """What the verdict asks for. `contain_now` still waits for the executor's own gates."""
    verdict = assessment.verdict
    if verdict in ("critical", "critical_exploited"):
        if policy.on_critical == "notify":
            return "notify"
        if verdict == "critical_exploited" and policy.immediate_if_known_exploited:
            return "contain_now"
        return "notice"
    if verdict in ("host_escalate", "unknown"):
        return "escalate"
    if verdict == "notify":
        return "notify"
    return "none"


def deadline(opened_at: float, *, exploited: bool, policy: Policy) -> float:
    """End of the notice period; an exploited finding with the exception has none."""
    if exploited and policy.immediate_if_known_exploited:
        return opened_at
    return opened_at + policy.notice_s
