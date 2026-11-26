from __future__ import annotations

from datetime import UTC, datetime

import pytest

from steward.core.maintenance import plan_emergency_window
from steward.core.maintenance_runs import MaintenanceRuns
from steward.core.store import Store

SPEC = "Sun 03:00 Europe/Berlin"


def ts(*args: int) -> float:
    return datetime(*args, tzinfo=UTC).timestamp()


@pytest.fixture
def runs(tmp_path):
    store = Store(tmp_path / "maintenance.db")
    yield MaintenanceRuns(store)
    store.close()


IN_WINDOW = ts(2026, 11, 22, 2, 5)


def test_outside_window_records_nothing(runs):
    decision = runs.request(SPEC, ts(2026, 11, 21, 12), work="resources", work_seconds=60)
    assert not decision.admission.allowed and decision.job is None
    assert runs.history() == []


def test_admitted_run_is_recorded_started_and_completed(runs):
    decision = runs.request(SPEC, IN_WINDOW, work="resources", work_seconds=300)
    assert decision.created and decision.job["state"] == "queued"
    job = runs.begin("controller", IN_WINDOW + 1)
    assert job["state"] == "running" and job["payload"]["window"] == "regular_window"
    assert runs.complete(job["id"], "controller", ok=True, now=IN_WINDOW + 60) == "succeeded"
    assert [j["state"] for j in runs.history()] == ["succeeded"]


def test_second_request_in_same_window_is_refused_even_after_failure(runs):
    first = runs.request(SPEC, IN_WINDOW, work="resources", work_seconds=60)
    job = runs.begin("controller", IN_WINDOW)
    runs.complete(job["id"], "controller", ok=False, now=IN_WINDOW + 5, error="boom")
    again = runs.request(SPEC, IN_WINDOW + 30, work="resources", work_seconds=60)
    assert first.created and not again.created
    assert again.admission.reason == "already_recorded_in_window"
    assert again.job["state"] == "failed" and again.job["error"] == "boom"
    assert len(runs.history()) == 1


def test_different_work_in_same_window_is_independent(runs):
    assert runs.request(SPEC, IN_WINDOW, work="resources", work_seconds=60).created
    assert runs.request(SPEC, IN_WINDOW, work="restart-test", work_seconds=60).created


def test_next_window_allows_the_same_work_again(runs):
    runs.request(SPEC, IN_WINDOW, work="resources", work_seconds=60)
    later = ts(2026, 11, 29, 2, 5)
    assert runs.request(SPEC, later, work="resources", work_seconds=60).created


def test_interrupted_run_fails_without_automatic_retry(runs):
    runs.request(SPEC, IN_WINDOW, work="resources", work_seconds=60)
    job = runs.begin("controller", IN_WINDOW)
    assert runs.recover(IN_WINDOW + 10) == []  # lease still valid
    assert runs.recover(IN_WINDOW + 10_000) == [job["id"]]
    final = runs.history()[0]
    assert final["state"] == "failed" and "retry limit reached" in final["error"]
    assert runs.begin("controller", IN_WINDOW + 10_001) is None


def test_stale_worker_cannot_complete_after_lease_loss(runs):
    runs.request(SPEC, IN_WINDOW, work="resources", work_seconds=60)
    job = runs.begin("controller", IN_WINDOW)
    assert runs.complete(job["id"], "other", ok=True, now=IN_WINDOW + 1) is None
    assert runs.complete(job["id"], "controller", ok=True, now=IN_WINDOW + 10_000) is None


def test_run_claimed_after_window_end_is_closed_without_starting(runs):
    runs.request(SPEC, IN_WINDOW, work="resources", work_seconds=600)
    late = ts(2026, 11, 22, 2, 55)
    assert runs.begin("controller", late) is None
    final = runs.history()[0]
    assert final["state"] == "failed" and final["error"] == "window expired before start"


def test_reboot_requires_consent_and_records_nothing_without_it(runs):
    denied = runs.request(SPEC, IN_WINDOW, work="reboot", work_seconds=120, kind="reboot")
    assert denied.admission.reason == "reboot_not_permitted" and not runs.history()
    granted = runs.request(
        SPEC, IN_WINDOW, work="reboot", work_seconds=120, kind="reboot", allow_reboot=True
    )
    assert granted.created


def test_emergency_window_run_is_bound_to_its_own_window(runs):
    now = ts(2026, 11, 24, 10)
    emergency = plan_emergency_window(
        datetime.fromtimestamp(now, UTC), reason="isolation_lost", notice_minutes=60
    )
    early = runs.request(SPEC, now + 600, work="fix", work_seconds=60, emergency=emergency)
    assert early.job is None
    inside = runs.request(SPEC, now + 3700, work="fix", work_seconds=60, emergency=emergency)
    assert inside.created and inside.job["payload"]["window"] == "emergency_window"


def test_invalid_work_ids_are_rejected(runs):
    for bad in ("", "A", "x y", "a/b", "../x"):
        with pytest.raises(ValueError):
            runs.request(SPEC, IN_WINDOW, work=bad, work_seconds=60)


def test_state_survives_reopening_the_store(tmp_path):
    path = tmp_path / "m.db"
    first = Store(path)
    MaintenanceRuns(first).request(SPEC, IN_WINDOW, work="resources", work_seconds=60)
    first.close()
    second = Store(path)
    again = MaintenanceRuns(second).request(SPEC, IN_WINDOW + 5, work="resources", work_seconds=60)
    assert not again.created and again.admission.reason == "already_recorded_in_window"
    second.close()


def test_ordinary_controller_restarts_do_not_depend_on_maintenance_policy():
    import ast
    from pathlib import Path

    import steward.controller as controller

    tree = ast.parse(Path(controller.__file__).read_text())
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom | ast.Import)
        for alias in node.names
    } | {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not any("maintenance" in name for name in imported)
