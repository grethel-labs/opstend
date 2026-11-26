"""Maintenance policy in the executor registry, status and the registered admit action."""

from __future__ import annotations

import json
import os
import time
import uuid
from datetime import UTC, datetime

import pytest

from steward.collector import audit_events, maintenance_events
from steward.controller import Controller
from steward.core import render
from steward.core.config import parse_config
from steward.core.events import Event, classify
from steward.core.maintenance_work import WORK, resource_check
from steward.executor.protocol import ExecutorError

SPEC = "Sun 03:00 Europe/Berlin"
POLICY = {
    "weekly_window": SPEC,
    "allow_reboot": False,
    "emergency": {"notice_minutes": 60, "immediate_if_known_exploited": True},
    "drills": [],
}
ME = 0  # operator role is root's UID


def ts(*args: int) -> float:
    return datetime(*args, tzinfo=UTC).timestamp()


IN_WINDOW = ts(2026, 11, 22, 2, 5)  # Sunday 03:05 Berlin (CET)
BEFORE = ts(2026, 11, 21, 12)
NEXT_START = "2026-11-22T02:00:00+00:00"


class Clock:
    def __init__(self, now: float):
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch):
    fake = Clock(BEFORE)
    monkeypatch.setattr(time, "time", fake)
    return fake


@pytest.fixture
def maintained(executor, clock):
    """Executor whose root-owned registry carries a maintenance policy."""
    registry = json.loads(executor.registry_file.read_text())
    registry["maintenance"] = POLICY
    executor.registry_file.write_text(json.dumps(registry))
    executor.host.load_average = lambda: {"load1": 0.1, "load5": 0.1, "load15": 0.1, "cpus": 2}
    return executor


def call(ex, action, params=None, uid=ME):
    body = {
        "v": 1,
        "action": action,
        "params": params or {},
        "request_id": uuid.uuid4().hex,
        "expires_at": time.time() + 60,
    }
    return ex.handle(json.dumps(body).encode(), uid)


def admit(ex, **kw):
    return call(ex, "maintenance_admit", {"work_id": "resource_check"}, **kw)


# ---- rendering ---------------------------------------------------------------------------


def test_registry_without_policy_has_no_maintenance_key_and_same_revision(cfg):
    registry = render.render_registry(cfg)
    assert "maintenance" not in registry


def test_policy_is_rendered_into_the_registry(raw_config):
    raw_config["maintenance"] = {"weekly_window": SPEC}
    registry = render.render_registry(parse_config(raw_config))
    assert registry["maintenance"] == POLICY


# ---- read-only status ----------------------------------------------------------------------


def test_status_of_older_registry_reports_unconfigured(executor):
    result = call(executor, "platform_status", uid=0)
    assert result["result"]["maintenance"] == {"configured": False}


def test_status_shows_next_window_outside_and_current_inside(maintained, clock):
    status = call(maintained, "platform_status")["result"]["maintenance"]
    assert status["state"] == "outside_window" and status["current_window"] is None
    assert status["next_window"]["start"] == NEXT_START
    assert status["recent_runs"] == []
    assert not os.path.exists(maintained._maintenance_db_path)  # a read never creates the store
    clock.now = IN_WINDOW
    status = call(maintained, "platform_status")["result"]["maintenance"]
    assert status["state"] == "in_window"
    assert status["current_window"]["start"] == NEXT_START
    assert status["next_window"]["start"] == "2026-11-29T02:00:00+00:00"


def test_status_with_invalid_policy_is_unknown_and_status_still_answers(maintained):
    registry = json.loads(maintained.registry_file.read_text())
    registry["maintenance"] = {"weekly_window": "never"}
    maintained.registry_file.write_text(json.dumps(registry))
    result = call(maintained, "platform_status")
    assert result["ok"]
    assert result["result"]["maintenance"]["state"] == "unknown"
    assert "next_window" not in result["result"]["maintenance"]


def test_controller_still_restarts_with_maintenance_policy_even_if_invalid(maintained, tmp_path):
    registry = json.loads(maintained.registry_file.read_text())
    registry["maintenance"] = {"weekly_window": "never"}
    maintained.registry_file.write_text(json.dumps(registry))
    (tmp_path / "ctl").mkdir()

    def via_controller(action, params=None, socket_path=None, request_id=None):
        body = {
            "v": 1,
            "action": action,
            "params": params or {},
            "request_id": request_id or uuid.uuid4().hex,
            "expires_at": time.time() + 60,
        }
        response = maintained.handle(json.dumps(body).encode(), 4242)
        if response["ok"]:
            return response["result"]
        raise ExecutorError(response["error_class"], response["message"])

    maintained.host.units["notes.service"] = "failed"
    snapshot = Controller(str(tmp_path / "ctl"), executor=via_controller).cycle()
    assert [f["id"] for f in snapshot["findings"]] == ["workload_down:notes"]
    assert maintained.host.calls == [("restart", "stw-notes", "notes.service")]
    assert snapshot["status"]["maintenance"]["state"] == "unknown"


# ---- the registered admit action -----------------------------------------------------------


def test_only_the_operator_may_admit(maintained):
    assert admit(maintained, uid=os.getuid())["error_class"] == "forbidden_role"
    assert admit(maintained, uid=4242)["error_class"] == "forbidden_role"


@pytest.mark.parametrize(
    "params",
    [
        {"work_id": "restart"},
        {"work_id": "resource_check", "command": "reboot"},
        {"work_id": "resource_check", "seconds": 5},
        {},
    ],
)
def test_admit_accepts_only_registered_work_without_free_form_input(maintained, params):
    assert call(maintained, "maintenance_admit", params)["error_class"] == "bad_request"


def test_registered_work_is_routine_and_never_a_reboot():
    assert set(WORK) == {"resource_check"}
    assert all(spec.kind == "routine" for spec in WORK.values())


def test_admit_without_policy_is_denied(executor, clock):
    assert admit(executor)["error_class"] == "policy_denied"


def test_kill_switch_stops_admission_even_for_the_operator(maintained, clock):
    clock.now = IN_WINDOW
    maintained.host.killed = True
    assert admit(maintained)["error_class"] == "kill_switch"
    assert maintained.audit.read()[-1]["outcome"] == "kill_switch"
    assert not any(e["event"] == "maintenance_run" for e in maintained.audit.read())


def test_outside_window_is_refused_and_records_nothing(maintained, clock):
    reply = admit(maintained)
    assert reply["ok"] and reply["result"]["admitted"] is False
    assert reply["result"]["reason"] == "outside_window"
    assert reply["result"]["retry_at"] == NEXT_START
    assert not any(e["event"] == "maintenance_run" for e in maintained.audit.read())
    status = call(maintained, "platform_status")["result"]["maintenance"]
    assert status["recent_runs"] == []


def test_inside_window_is_admitted_once_then_refused(maintained, clock):
    clock.now = IN_WINDOW
    first = admit(maintained)["result"]
    assert first["admitted"] is True and first["state"] == "completed"
    assert first["result"]["healthy"] is True and first["window"]["start"] == NEXT_START
    assert maintained.host.calls == []  # a read-only check: nothing was restarted or rebooted
    clock.now = IN_WINDOW + 300
    second = admit(maintained)["result"]
    assert second["admitted"] is False and second["reason"] == "already_recorded_in_window"
    runs = call(maintained, "platform_status")["result"]["maintenance"]["recent_runs"]
    assert [(r["work"], r["state"]) for r in runs] == [("resource_check", "succeeded")]
    audit = [e for e in maintained.audit.read() if e["event"] == "maintenance_run"]
    assert [e["outcome"] for e in audit] == ["started", "completed"]
    assert audit[0]["run_id"] == first["run_id"]


def test_window_end_boundary_and_next_week_allow_a_new_run(maintained, clock):
    clock.now = IN_WINDOW
    assert admit(maintained)["result"]["admitted"] is True
    clock.now = ts(2026, 11, 22, 2, 59)  # 60 s of work no longer fits before 03:00 UTC
    assert admit(maintained)["result"]["reason"] == "already_recorded_in_window"
    clock.now = ts(2026, 11, 29, 2, 10)
    assert admit(maintained)["result"]["admitted"] is True


def test_failed_check_is_recorded_failed_and_not_repeated_in_the_window(maintained, clock):
    clock.now = IN_WINDOW

    def broken():
        raise OSError("no meminfo")

    maintained.host.resources = broken
    result = admit(maintained)["result"]
    assert result["admitted"] is True and result["state"] == "failed"
    assert "OSError" in result["error"] and result["result"] is None
    audit = [e for e in maintained.audit.read() if e["event"] == "maintenance_run"]
    assert [e["outcome"] for e in audit] == ["started", "failed"]
    maintained.host.resources = lambda: {
        "memory_total_mb": 4000,
        "memory_available_mb": 3000,
        "disk_total_mb": 40000,
        "disk_free_mb": 30000,
    }
    assert admit(maintained)["result"]["reason"] == "already_recorded_in_window"


def test_interrupted_run_is_closed_failed_on_the_next_request(maintained, clock):
    clock.now = IN_WINDOW
    from steward.core.maintenance_runs import MaintenanceRuns

    with maintained.maintenance_store() as store:
        runs = MaintenanceRuns(store)
        assert runs.request(
            SPEC, IN_WINDOW, work="resource_check", work_seconds=60, created_by="operator"
        ).created
        assert runs.begin("executor-dead", IN_WINDOW)
    clock.now = IN_WINDOW + 600  # lease long expired, executor restarted
    reply = admit(maintained)["result"]
    assert reply["admitted"] is False and reply["reason"] == "already_recorded_in_window"
    audit = [e for e in maintained.audit.read() if e["event"] == "maintenance_run"]
    assert [(e["outcome"], e["cause"]) for e in audit] == [("failed", "interrupted")]


def test_invalid_policy_denies_admission(maintained, clock):
    registry = json.loads(maintained.registry_file.read_text())
    registry["maintenance"] = {"weekly_window": "never"}
    maintained.registry_file.write_text(json.dumps(registry))
    assert admit(maintained)["error_class"] == "policy_denied"


# ---- resource check ------------------------------------------------------------------------


GOOD = {
    "memory_total_mb": 4000,
    "memory_available_mb": 3000,
    "disk_total_mb": 40000,
    "disk_free_mb": 30000,
}
LOAD = {"load5": 0.5, "cpus": 2}


def test_resource_check_compares_against_totals():
    assert resource_check(GOOD, LOAD, 512)["healthy"] is True
    low_disk = resource_check({**GOOD, "disk_free_mb": 3000}, LOAD, 512)
    assert low_disk["healthy"] is False and low_disk["checks"]["disk"] is False
    low_mem = resource_check({**GOOD, "memory_available_mb": 100}, LOAD, 512)
    assert low_mem["checks"]["memory"] is False
    busy = resource_check(GOOD, {"load5": 9.0, "cpus": 2}, 512)
    assert busy["checks"]["load"] is False


@pytest.mark.parametrize(
    "resources, load",
    [
        ({**GOOD, "memory_available_mb": None}, LOAD),
        ({**GOOD, "disk_total_mb": 0}, LOAD),
        (GOOD, {"load5": 1.0, "cpus": None}),
        (GOOD, {"cpus": 2}),
    ],
)
def test_missing_measurements_are_not_success(resources, load):
    with pytest.raises(ValueError):
        resource_check(resources, load, 512)


# ---- events --------------------------------------------------------------------------------


def entry(outcome, **extra):
    return {
        "event": "maintenance_run",
        "ts": IN_WINDOW,
        "hash": uuid.uuid4().hex + uuid.uuid4().hex,
        "work": "resource_check",
        "run_id": uuid.uuid4().hex,
        "window_start": NEXT_START,
        "window_end": "2026-11-22T03:00:00+00:00",
        "outcome": outcome,
        **extra,
    }


@pytest.mark.parametrize(
    "outcome, severity, delivery",
    [
        ("started", "info", "digest"),
        ("completed", "info", "digest"),
        ("failed", "high", "immediate"),
    ],
)
def test_run_audit_records_become_lifecycle_events(outcome, severity, delivery):
    (event,) = audit_events(entry(outcome))
    assert event.kind == f"maintenance.{outcome}" and event.severity == severity
    assert event.correlation_id and event.outcome == outcome
    assert classify(event) == delivery


def test_unknown_run_outcome_creates_no_event():
    assert audit_events(entry("refused")) == []


def snapshot_with(maintenance):
    return {"status": {"maintenance": maintenance}}


def window_summary(state="outside_window"):
    window = {"start": NEXT_START, "end": "2026-11-22T03:00:00+00:00"}
    return {
        "configured": True,
        "state": state,
        "allow_reboot": False,
        "current_window": window if state == "in_window" else None,
        "next_window": window,
    }


def test_window_is_announced_a_day_ahead_once_per_window():
    assert maintenance_events(snapshot_with(window_summary()), IN_WINDOW - 3 * 86400) == []
    (event,) = maintenance_events(snapshot_with(window_summary()), IN_WINDOW - 3600)
    assert event.kind == "maintenance.window_announced" and event.outcome == "announced"
    assert classify(event) == "immediate"
    again = maintenance_events(snapshot_with(window_summary()), IN_WINDOW - 1800)
    assert again[0].source_ref == event.source_ref  # the event store ignores the repeat
    in_window = maintenance_events(snapshot_with(window_summary("in_window")), IN_WINDOW)
    assert in_window[0].source_ref == event.source_ref


@pytest.mark.parametrize(
    "summary",
    [
        None,
        {"configured": False},
        {"configured": True, "state": "unknown"},
        {"state": "outside_window"},
    ],
)
def test_nothing_is_announced_without_a_verified_window(summary):
    assert maintenance_events(snapshot_with(summary), IN_WINDOW) == []
    assert maintenance_events({}, IN_WINDOW) == []


def test_event_type_is_unchanged_for_other_kinds():
    event = Event(
        ts=1.0,
        source="x",
        source_ref="y",
        kind="maintenance.completed",
        severity="info",
        summary="s",
    )
    assert classify(event) == "digest"


def test_hostcli_admit_sends_only_the_registered_work_id(monkeypatch):
    import sys

    from steward import hostcli

    calls = []
    monkeypatch.setattr(hostcli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        hostcli, "call", lambda action, params, **kw: calls.append((action, params)) or {"ok": 1}
    )
    monkeypatch.setattr(sys, "argv", ["steward-host", "maintenance-admit", "resource_check"])
    hostcli.main()
    assert calls == [("maintenance_admit", {"work_id": "resource_check"})]
    monkeypatch.setattr(sys, "argv", ["steward-host", "maintenance-admit", "reboot"])
    with pytest.raises(SystemExit):
        hostcli.main()
    assert len(calls) == 1
