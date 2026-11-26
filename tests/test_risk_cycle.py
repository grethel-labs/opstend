"""Controller-side critical-risk driver against the real executor (L07/L08)."""

import json
import time
import uuid

import pytest

from steward.core.risk_cycle import RiskCycle, scan_evidence
from steward.core.vulnerabilities import Component, ScanResult
from steward.executor.protocol import ExecutorError
from test_containment import apply_fix, audit, expire, stored, write
from test_containment import env as env
from test_containment import group_host as group_host
from test_containment import group_registry as group_registry
from test_controller import make

CTL = 4242


def caller(env):
    def call(action, params=None, socket_path=None, request_id=None):
        raw = json.dumps(
            {
                "v": 1,
                "action": action,
                "params": params or {},
                "request_id": request_id or uuid.uuid4().hex,
                "expires_at": time.time() + 60,
            }
        ).encode()
        response = env.ex.handle(raw, CTL)
        if response["ok"]:
            return response["result"]
        raise ExecutorError(response["error_class"], response["message"])

    return call


def image_record(env, service="database", *, state="confirmed", kev=False, severity="critical"):
    spec = env.specs[service]
    subject = Component(
        kind="image", scope=f"shop/{service}", name=service + "-image",
        version=spec["image"].split("@")[1], image=spec["image"], runtime_verified=True,
        expected_image_id=env.running[spec["container"]],
    )  # fmt: skip
    advisory = {"id": "CVE-2026-0001", "summary": "x", "severity": severity}
    if kev:
        now = time.time()
        kev_ev = {"source": "kev", "state": "available", "checked_at": now,
                  "published_at": now, "listed": True, "catalog_version": "v1"}  # fmt: skip
        epss = {"source": "epss", "state": "available", "checked_at": now,
                "published_at": now, "score": 0.9, "percentile": 0.9}  # fmt: skip
        advisory["exploit_context"] = [{"cve": "CVE-2026-0001", "kev": kev_ev, "epss": epss}]
    confirmed = state == "confirmed"
    scan = ScanResult(
        source="trivy", inventory_revision="c" * 64, subject=subject, checked_at=time.time(),
        database_updated_at=time.time(), state=state, complete=state != "unknown",
        findings=[advisory] if confirmed else [],
    )  # fmt: skip
    record = scan.model_dump(mode="json")
    record["subject_key"] = subject.key
    record["findings_total"] = 1 if confirmed else 0
    return record


def cycle(env, records):
    if records is not None:
        scopes = {record["subject"]["scope"] for record in records}
        records = [
            *records,
            *(
                image_record(env, service, state="not_affected")
                for service in ("frontend", "backend", "database")
                if f"shop/{service}" not in scopes
            ),
        ]
    return RiskCycle(caller(env), lambda: records).run(time.time())


def ids(findings):
    return [f["id"] for f in findings]


def test_disabled_feature_is_silent(env):
    del env.registry["containment"]
    write(env.ex, env.registry)
    assert cycle(env, [image_record(env, kev=True)]) == []
    assert stored(env) is None and env.net.ports is None


def test_missing_scan_evidence_is_reported_never_treated_as_clean(env):
    from steward.collector import snapshot_events

    findings = cycle(env, None)
    assert ids(findings) == ["risk_evidence_unavailable:shop"]
    events, _ = snapshot_events(
        {"status": {"projects": {"shop": {}}}, "findings": findings}, {}, time.time()
    )
    assert events[0].project is None and events[0].target == "application:shop"
    assert stored(env) is None
    unknown = image_record(env, state="unknown")
    assert ids(cycle(env, [unknown])) == ["risk_unknown:shop"]
    assert stored(env) is None and env.net.ports is None


def test_nothing_is_opened_for_a_high_severity_score_or_a_clean_scan(env):
    assert cycle(env, [image_record(env, severity="high")]) == []
    assert cycle(env, [image_record(env, state="not_affected")]) == []
    assert cycle(env, [image_record(env, "worker")]) == []  # unexposed
    assert stored(env) is None


def test_critical_finding_runs_the_whole_response_and_a_verified_reactivation(env):
    findings = cycle(env, [image_record(env, kev=True)])  # known exploited: no notice period
    assert findings == [] and stored(env).phase == "disconnected" and env.net.ports == {21003}
    cycle(env, [image_record(env, kev=True)])
    cycle(env, [image_record(env, kev=True)])
    assert stored(env).phase == "quarantined" and not any(env.states.values())
    cycle(env, [image_record(env, kev=True)])  # a repeated finding changes nothing
    assert stored(env).phase == "quarantined"
    apply_fix(env)
    cycle(env, [image_record(env, state="not_affected")])
    assert stored(env).phase == "fix_verification" and env.net.ports == {21003}
    assert all(env.states.values())
    cycle(env, [image_record(env, state="not_affected")])
    assert stored(env) is None and env.net.ports is None
    ids_seen = {e["correlation_id"] for e in audit(env)}
    assert len(ids_seen) == 1 and next(iter(ids_seen)).startswith("inc-")


def test_notice_period_is_kept_by_the_executor_not_the_controller(env):
    cycle(env, [image_record(env)])
    assert stored(env).phase == "notice" and env.net.ports is None
    cycle(env, [image_record(env)])
    assert stored(env).phase == "notice"
    expire(env)
    cycle(env, [image_record(env)])
    assert stored(env).phase == "disconnected" and env.net.ports == {21003}


def test_failed_stages_are_escalated_as_critical_findings(env):
    env.net.fail = True
    findings = cycle(env, [image_record(env, kev=True)])
    assert ids(findings) == ["incident_disconnect_failed:shop"]
    assert findings[0]["severity"] == "critical"


def test_executor_refusal_is_escalated_not_swallowed(env):
    env.ex.host.killed = True
    findings = cycle(env, [image_record(env, kev=True)])
    assert ids(findings) == ["incident_blocked:shop"]
    assert findings[0]["blocked"].startswith("escalated: kill_switch")
    assert stored(env) is None and env.net.ports is None


def test_scan_evidence_view_drops_page_fields_and_rejects_garbage(env):
    record = image_record(env, state="not_affected")
    view = scan_evidence(record)
    assert view is not None and "subject_key" not in view and view["state"] == "not_affected"
    assert scan_evidence({"state": "not_affected"}) is None


def test_controller_cycle_adds_risk_findings_and_survives_a_failing_driver(executor, tmp_path):
    (tmp_path / "ctl").mkdir()
    controller = make(executor, tmp_path)

    class Good:
        def run(self, now):
            return [{"id": "x:shop", "severity": "critical", "target": "shop",
                     "summary": "s", "blocked": None}]  # fmt: skip

    class Broken:
        def run(self, now):
            raise RuntimeError("boom")

    controller.risk = Good()
    assert [f["id"] for f in controller.cycle()["findings"]] == ["x:shop"]
    controller.risk = Broken()
    assert [f["id"] for f in controller.cycle()["findings"]] == ["risk_cycle_error"]
    controller.risk = None
    assert controller.cycle()["findings"] == []


@pytest.mark.parametrize("state", ["stale", "scan_failed"])
def test_incident_proceeds_when_evidence_goes_stale(env, state):
    cycle(env, [image_record(env, kev=True)])
    bad = image_record(env, state="unknown")
    bad.update(state=state, complete=False)
    for _ in range(3):
        cycle(env, [bad])
    assert stored(env).phase == "quarantined"


def scan_query(env, handle):
    calls = []

    def query(action, params, *, timeout):
        assert action == "scans_query" and 0 < timeout <= 5
        assert params["expected_revision"] == env.registry["config_revision"]
        assert params.get("snapshot_id") == ("a" * 64 if calls else None)
        assert set(params) <= {"expected_revision", "project", "snapshot_id", "finding_offset"}
        calls.append(params)
        return handle(params)

    return query, calls


def page(record=None, *, snapshot="a" * 64):
    return {
        "snapshot_id": snapshot,
        "records": [record] if record is not None else [],
        "total": int(record is not None),
        "next_offset": None,
    }


@pytest.mark.parametrize("gap", ["missing", "truncated"])
def test_confirmed_page_can_open_with_an_explicit_coverage_gap(env, gap):
    def handle(params):
        if params["project"] == "shop/database":
            record = image_record(env, kev=True)
            if gap == "truncated":
                if params.get("finding_offset"):
                    raise ExecutorError("unavailable", "page unavailable")
                record["findings_total"] = 2
            return page(record)
        return page()

    query, calls = scan_query(env, handle)
    outcome = RiskCycle(caller(env), None, scan_query=query).run(time.time())
    assert ids(outcome) == ["risk_unknown:shop"]
    assert stored(env).phase == "disconnected"
    assert {p["project"] for p in calls} == {"shop/backend", "shop/database", "shop/frontend"}


@pytest.mark.parametrize("failure", ["stale", "changed", "wrong_scope", "wrong_source", "unbound"])
def test_untrustworthy_page_cannot_open_an_incident(env, failure):
    def handle(params):
        service = params["project"].split("/")[1]
        if service != "database":
            return page(image_record(env, service, state="not_affected"))
        record = image_record(env, kev=True)
        if failure == "stale":
            record["findings_total"] = 2
            if params.get("finding_offset"):
                record.update(state="stale", complete=False)
        if failure == "changed":
            if not params.get("finding_offset"):
                record["findings_total"] = 2
            else:
                return page(record, snapshot="b" * 64)
        if failure == "wrong_scope":
            record = image_record(env, "frontend", kev=True)
        if failure == "wrong_source":
            record["source"] = "osv"
        if failure == "unbound":
            record["subject"]["runtime_verified"] = False
        return page(record)

    query, _ = scan_query(env, handle)
    assert ids(RiskCycle(caller(env), None, scan_query=query).run(time.time())) == [
        "risk_unknown:shop"
    ]
    assert stored(env) is None


def test_scan_read_page_budget_is_shared_between_services(env, monkeypatch):
    from steward.core import risk_cycle

    monkeypatch.setattr(risk_cycle, "SCAN_READ_MAX_PAGES", 2)

    calls = []

    def query(_action, params, *, timeout):
        calls.append(params["project"])
        assert "finding_offset" not in params
        record = image_record(env, params["project"].split("/")[1], severity="high")
        record["findings_total"] = 10
        return page(record)

    risk = RiskCycle(caller(env), None, scan_query=query)
    for _ in range(2):
        assert ids(risk.run(time.time())) == ["risk_unknown:shop"]
    assert calls == ["shop/backend", "shop/database", "shop/database", "shop/frontend"]
    assert stored(env) is None


def test_later_snapshot_conflict_discards_earlier_clean_evidence(env):
    cycle(env, [image_record(env, kev=True)])
    for _ in range(3):
        cycle(env, None)
    apply_fix(env)
    cycle(env, None)
    assert stored(env).phase == "fix_verification"

    def handle(params):
        service = params["project"].split("/")[1]
        snapshot = "b" * 64 if service == "frontend" else "a" * 64
        return page(image_record(env, service, state="not_affected"), snapshot=snapshot)

    query, _ = scan_query(env, handle)
    assert ids(RiskCycle(caller(env), None, scan_query=query).run(time.time())) == [
        "risk_unknown:shop"
    ]
    assert stored(env).phase == "fix_verification" and env.net.ports == {21003}


def test_many_advisories_do_not_displace_another_affected_service(env):
    backend = image_record(env, "backend", kev=True)
    backend["findings_total"] = 21

    def handle(params):
        service = params["project"].split("/")[1]
        if service == "frontend":
            return page(image_record(env, service, state="not_affected"))
        if service == "database":
            return page(image_record(env, service, kev=True))
        advisory = {
            **backend["findings"][0],
            "id": f"CVE-2026-{params.get('finding_offset', 0) + 1000}",
        }
        return page({**backend, "findings": [advisory]})

    query, _ = scan_query(env, handle)
    assert RiskCycle(caller(env), None, scan_query=query).run(time.time()) == []
    assert stored(env).affected == ["backend", "database"]


def test_reassert_and_open_errors_do_not_prevent_incident_advance(env):
    cycle(env, [image_record(env)])
    expire(env)
    executor_call = caller(env)
    calls = []

    def failing_call(action, *args, **kwargs):
        calls.append(action)
        if action in ("containment_reassert", "incident_open"):
            raise ExecutorError("conflict", "synthetic refusal")
        return executor_call(action, *args, **kwargs)

    records = [
        image_record(env),
        image_record(env, "frontend", state="not_affected"),
        image_record(env, "backend", state="not_affected"),
    ]
    findings = RiskCycle(
        failing_call,
        lambda: records,
    ).run(time.time())

    assert ids(findings) == ["containment_reassert_failed", "incident_blocked:shop"]
    assert calls == ["containment_reassert", "incident_status", "incident_open", "incident_advance"]
    assert stored(env).phase == "disconnected"


def test_source_exception_allows_empty_fix_verification_request(env):
    for _ in range(3):
        cycle(env, [image_record(env, kev=True)])
    assert stored(env).phase == "quarantined"
    apply_fix(env)

    def unavailable():
        raise RuntimeError("source unavailable")

    findings = RiskCycle(caller(env), unavailable).run(time.time())
    assert ids(findings) == ["risk_evidence_unavailable:shop"]
    assert stored(env).phase == "fix_verification"
    assert env.net.ports == {21003}


def test_critical_finding_on_second_page_is_used(env):
    record = image_record(env, severity="high")
    record["findings_total"] = 2

    def handle(params):
        service = params["project"].split("/")[1]
        if service != "database":
            return page(image_record(env, service, state="not_affected"))
        if params.get("finding_offset") == 1:
            return page(
                {
                    **record,
                    "findings": [
                        {"id": "CVE-2026-0002", "severity": "critical", "summary": "critical"},
                    ],
                }
            )
        return page(record)

    query, calls = scan_query(env, handle)
    assert RiskCycle(caller(env), None, scan_query=query).run(time.time()) == []
    assert stored(env).findings[0].advisory == "CVE-2026-0002"
    assert [p.get("finding_offset", 0) for p in calls if p["project"] == "shop/database"] == [0, 1]


def test_partial_clean_scan_is_omitted_from_reactivation(env):
    incident = {
        "id": "inc-test",
        "application": "shop",
        "phase": "fix_verification",
        "findings": [{"service": "database"}, {"service": "backend"}],
    }
    reactivation = []

    def call(action, params, **kwargs):
        if action == "containment_reassert":
            return {}
        if action == "incident_status":
            return {
                "applications": {"shop": {"exposure": {"database": "indirect", "backend": "none"}}},
                "incidents": [incident],
                "config_revision": env.registry["config_revision"],
            }
        if action == "incident_advance":
            return {"state": incident["phase"], "incident": incident}
        assert action == "incident_reactivate"
        reactivation.append(params)
        return {}

    def handle(params):
        if params["project"] == "shop/database":
            return page(image_record(env, state="not_affected"))
        assert params["project"] == "shop/backend"
        return page()

    query, _ = scan_query(env, handle)
    findings = RiskCycle(call, None, scan_query=query).run(time.time())
    assert ids(findings) == ["risk_unknown:shop"]
    assert reactivation == [
        {
            "application": "shop",
            "expected_revision": env.registry["config_revision"],
            "evidence": [],
        }
    ]
