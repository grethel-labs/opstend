"""Fixed decision table, exposure from the graph, deadline and unknown handling (L07)."""

import pytest

from steward.core import critical_risk as risk
from steward.core.critical_risk import FindingEvidence, Policy


def app(**routes):
    """frontend -> backend -> database, worker -> database; only `routes` are routed."""
    deps = {
        "database": [],
        "backend": ["database"],
        "frontend": ["backend"],
        "worker": ["database"],
    }
    return {
        "services": {
            name: {
                "manage": True,
                "deploy": True,
                "depends_on": value,
                "routes": routes.get(name, []),
                "host_port": 21000 + index,
            }
            for index, (name, value) in enumerate(deps.items())
        }
    }


def evidence(scope="database", **kw):
    base = dict(
        scope=scope, subject_key="k", advisory="CVE-2026-0001", state="confirmed", bound=True,
        severity="critical", kev="unknown", epss=None,
    )  # fmt: skip
    return FindingEvidence(**{**base, **kw})


def verdict(reach="direct", **kw):
    return risk.decide(evidence(**kw), reach).verdict


def test_exposure_is_direct_indirect_or_none():
    reach = risk.exposure(app(frontend=["shop.example.test"]))
    assert reach == {
        "database": "indirect",
        "backend": "indirect",
        "frontend": "direct",
        "worker": "none",
    }
    assert risk.exposers(app(frontend=["h"]), "database") == ["frontend"]
    assert risk.exposers(app(frontend=["h"]), "worker") == []
    # an unmanaged or stopped routed service exposes nothing
    stopped = app(frontend=["h"])
    stopped["services"]["frontend"]["deploy"] = False
    assert set(risk.exposure(stopped).values()) == {"none"}


@pytest.mark.parametrize(
    ("reach", "kw", "expected"),
    [
        ("direct", {}, "critical"),  # critical, nothing known about exploitation
        ("indirect", {}, "critical"),  # a database behind a public frontend
        ("direct", {"kev": "listed"}, "critical_exploited"),
        ("direct", {"kev": "listed", "severity": "high"}, "critical_exploited"),
        ("direct", {"kev": "listed", "severity": "unknown"}, "critical_exploited"),
        ("direct", {"kev": "listed", "severity": "medium"}, "notify"),
        ("direct", {"severity": "high"}, "notify"),  # high CVSS alone never isolates
        ("direct", {"severity": "high", "kev": "not_listed", "epss": 0.9}, "notify"),
        ("direct", {"severity": "low"}, "monitor"),
        ("direct", {"kev": "not_listed", "epss": 0.02}, "notify"),  # positive low evidence only
        ("direct", {"kev": "not_listed", "epss": 0.10}, "critical"),  # floor is exclusive
        ("direct", {"kev": "not_listed", "epss": None}, "critical"),  # EPSS unknown
        ("direct", {"kev": "unknown", "epss": 0.0}, "critical"),  # KEV unknown
        ("none", {}, "unreachable"),
        ("none", {"kev": "listed"}, "unreachable"),
        ("unknown", {}, "unknown"),
        ("direct", {"state": "not_affected"}, "clear"),
        ("none", {"state": "not_affected"}, "clear"),
    ],
)
def test_decision_table(reach, kw, expected):
    assert verdict(reach, **kw) == expected


@pytest.mark.parametrize("state", ["unknown", "stale", "scan_failed"])
def test_missing_evidence_is_unknown_never_clear(state):
    assert verdict(state=state) == "unknown"
    assert verdict("none", state=state) == "unknown"
    assert verdict(bound=False) == "unknown"  # image not bound to the running instance
    assert verdict(bound=False, state="not_affected") == "unknown"


def test_host_scope_is_escalated_never_contained():
    assert verdict("none", scope="host", kev="listed") == "host_escalate"
    assert verdict("none", scope="host", state="stale") == "unknown"
    assessment = risk.assess({}, {}, [evidence("host", kev="listed")])
    assert assessment.verdict == "host_escalate" and not assessment.critical
    assert risk.response(assessment, Policy()) == "escalate"


def test_assessment_takes_worst_verdict_and_ignores_foreign_scopes():
    reach = risk.exposure(app(frontend=["h"]))
    scope = {name: name for name in reach}
    items = [
        evidence("worker"),  # unexposed -> unreachable
        evidence("database", severity="high"),  # notify
        evidence("backend", kev="listed"),  # exploited
        evidence("other-app-service"),  # not this application
    ]
    result = risk.assess(reach, scope, items)
    assert result.verdict == "critical_exploited" and result.exploited
    assert [d.scope for d in result.critical] == ["backend"]
    stale = risk.assess(reach, scope, [evidence("database", state="stale")])
    assert stale.verdict == "unknown" and not stale.critical
    assert risk.assess(reach, scope, []).verdict == "clear"


def test_responses_and_deadlines():
    reach = {"database": "direct"}
    plain = risk.assess(reach, {"database": "database"}, [evidence()])
    exploited = risk.assess(reach, {"database": "database"}, [evidence(kev="listed")])
    default = Policy()
    assert risk.response(plain, default) == "notice"
    assert risk.response(exploited, default) == "contain_now"
    assert risk.response(exploited, Policy(immediate_if_known_exploited=False)) == "notice"
    assert risk.response(plain, Policy(on_critical="notify")) == "notify"
    assert risk.response(exploited, Policy(on_critical="notify")) == "notify"
    assert risk.deadline(1000.0, exploited=False, policy=default) == 4600.0
    assert risk.deadline(1000.0, exploited=True, policy=default) == 1000.0
    assert (
        risk.deadline(1000.0, exploited=True, policy=Policy(immediate_if_known_exploited=False))
        == 4600.0
    )
    assert risk.deadline(0.0, exploited=False, policy=Policy(notice_s=900)) == 900.0


def context(kev_listed, epss, *, state="available"):
    kev = {"source": "kev", "state": state, "checked_at": 1.0, "published_at": 1.0}
    score = {"source": "epss", "state": state, "checked_at": 1.0, "published_at": 1.0}
    if state == "available":
        kev |= {"listed": kev_listed, "catalog_version": "v1"}
        score |= {"score": epss, "percentile": 0.5}
    return {"cve": "CVE-2026-0001", "kev": kev, "epss": score}


def record(**kw):
    value = {
        "subject": {"scope": "database", "kind": "image", "runtime_verified": True,
                    "expected_image_id": "sha256:" + "a" * 64},
        "subject_key": "key",
        "state": "confirmed",
        "findings": [{"id": "CVE-2026-0001", "severity": "critical", "exploit_context": []}],
        "findings_total": 1,
    }  # fmt: skip
    return value | kw


def test_evidence_from_record_normalizes_context_and_binding():
    [item] = risk.evidence_from_record(record())
    assert (item.kev, item.epss, item.bound) == ("unknown", None, True)
    listed = record(
        findings=[{"id": "X", "severity": "high", "exploit_context": [context(True, 0.5)]}]
    )
    assert risk.evidence_from_record(listed)[0].kev == "listed"
    low = record(
        findings=[{"id": "X", "severity": "critical", "exploit_context": [context(False, 0.01)]}]
    )
    [item] = risk.evidence_from_record(low)
    assert (item.kev, item.epss) == ("not_listed", 0.01)
    stale = record(
        findings=[
            {
                "id": "X",
                "severity": "critical",
                "exploit_context": [context(None, None, state="stale")],
            }
        ]
    )
    [item] = risk.evidence_from_record(stale)
    assert (item.kev, item.epss) == ("unknown", None)
    garbage = record(
        findings=[{"id": "X", "severity": "critical", "exploit_context": [{"cve": "x"}]}]
    )
    assert risk.evidence_from_record(garbage)[0].kev == "unknown"


def test_unbound_truncated_and_failed_records_are_never_clean():
    unbound = record(subject={"scope": "database", "kind": "image", "runtime_verified": False})
    assert risk.evidence_from_record(unbound)[0].bound is False
    # a page that omits findings is incomplete evidence
    paged = record(findings_total=3)
    assert any(e.state == "unknown" and not e.bound for e in risk.evidence_from_record(paged))
    empty = record(findings=[], findings_total=0)
    assert risk.evidence_from_record(empty)[0].state == "unknown"
    failed = record(state="scan_failed", findings=[])
    assert risk.evidence_from_record(failed)[0].state == "scan_failed"
    decisions = risk.assess(
        {"database": "direct"}, {"database": "database"}, risk.evidence_from_record(failed)
    )
    assert decisions.verdict == "unknown"
