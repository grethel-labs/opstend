"""W17: regression tests for the three defects found during the W15 host gates.

1. auto-rollback targets only the newest applied update of a project;
2. a planned, audited backup pause/capture restart is neutral for the stability clock;
3. `update-retention` lists, ages and counts every spool artifact, plain captures included.
"""

from __future__ import annotations

from steward.controller import Controller
from steward.core import update_retention
from steward.core.patch_stability import StabilityTracker, rollback_candidate, rollback_selection
from test_patch_profile import Harness
from test_update_hardening import DAY, align_clock, healthy_status, retention
from test_update_recovery import RESTORE, build, spool
from update_support import OLD_IMAGE

NOW = 10_000.0


def applied_row(approval_id, applied_at, **over):
    return {
        "state": "applied",
        "approval_id": approval_id,
        "new_image": OLD_IMAGE.rsplit("@", 1)[0] + "@sha256:" + "b" * 64,
        "migration": "none",
        "applied_at": applied_at,
        **over,
    }


def selection(rows):
    return {"approvals": rows, "rollback_window_s": 1800}


def test_only_the_newest_applied_update_can_be_an_auto_rollback_target():
    older = applied_row("approval-older00001", NOW - 600)
    newer = applied_row(
        "approval-newer00001", NOW - 60, state="restore_required", migration=RESTORE
    )
    candidate, reason = rollback_selection(selection([newer, older]), "shop", NOW)
    assert candidate is None and "restore_required" in reason
    assert rollback_candidate(selection([newer, older]), "shop", NOW) is None
    unstamped = {**newer, "updated_at": NOW - 60}
    del unstamped["applied_at"]  # ordered by its update time instead
    assert rollback_candidate(selection([older, unstamped]), "shop", NOW) is None
    newest_ok = applied_row("approval-newest0001", NOW - 30)
    chosen = rollback_candidate(selection([older, newest_ok]), "shop", NOW)
    assert chosen["approval_id"] == "approval-newest0001"
    expired = applied_row("approval-late000001", NOW - 1900)
    still_ok = applied_row("approval-old0000001", NOW - 2000)
    assert rollback_candidate(selection([expired, still_ok]), "shop", NOW) is None


def test_the_controller_never_calls_rollback_for_an_older_approval(tmp_path):
    calls = []
    rows = [
        applied_row("approval-older00001", NOW - 600),
        applied_row("approval-newer00001", NOW - 60, state="restore_required", migration=RESTORE),
    ]

    def executor(action, params=None, **_kw):
        calls.append(action)
        if action == "update_status":
            return selection(rows)
        raise AssertionError(action)

    controller = Controller(str(tmp_path), "sock", executor)
    controller.failures["shop"] = 10
    status = {
        "automation_profile": "patch",
        "kill_switch": False,
        "deployment_recovery": "clear",
        "projects": {"shop": {"deploy": True, "unit": {"active": "active"}, "health_retries": 3}},
    }
    out = controller.auto_rollback(status, NOW)
    assert out["state"] == "idle" and "restore_required" in out["skipped"]["shop"]
    assert calls == ["update_status"]


def planned_status(**over):
    status = healthy_status()
    status["checked_at"] = 5000.0
    status.update(over)
    return status


def test_a_planned_backup_pause_does_not_reset_the_stability_clock(tmp_path):
    tracker = StabilityTracker(tmp_path / "stability.json")
    tracker.observe(planned_status(checked_at=1000.0), 1000.0)
    tracker.observe(planned_status(checked_at=1100.0), 1100.0)
    pause = {"project_id": "shop", "prepared_at": 1140.0, "error_class": None}
    paused = planned_status(checked_at=1150.0, backup_recovery=[pause])
    paused["projects"]["shop"]["unit"] = {"active": "inactive"}
    paused["projects"]["shop"]["health"] = {"ok": False}
    tracker.observe(paused, 1150.0)
    assert tracker.healthy_for("shop", 1150.0) == 150.0
    starting = planned_status(checked_at=1200.0, backup_planned_restarts={"shop": 1190.0})
    starting["projects"]["shop"]["health"] = {"ok": False}
    tracker.observe(starting, 1200.0)
    assert tracker.healthy_for("shop", 1200.0) == 200.0
    healthy = planned_status(checked_at=1250.0, backup_planned_restarts={"shop": 1190.0})
    tracker.observe(healthy, 1250.0)
    assert tracker.healthy_for("shop", 1250.0) == 250.0


def test_an_unplanned_or_stale_unhealthy_observation_still_resets(tmp_path):
    def pause(at, error):
        return [{"project_id": "shop", "prepared_at": at, "error_class": error}]

    for extra in (
        {},
        {"backup_planned_restarts": {"shop": 100.0}},
        {"backup_recovery": pause(4990.0, "execution_failed")},
        {"backup_recovery": pause(100.0, None)},
        {"backup_planned_restarts": {"other": 4990.0}},
    ):
        tracker = StabilityTracker(tmp_path / "s.json")
        tracker.observe(planned_status(checked_at=4900.0), 4900.0)
        bad = planned_status(**extra)
        bad["projects"]["shop"]["health"] = {"ok": False}
        tracker.observe(bad, 5000.0)
        assert tracker.healthy_for("shop", 5000.0) == 0.0, extra


def test_plain_captures_are_listed_aged_and_counted(tmp_path, raw_config, monkeypatch):
    w = build(tmp_path, raw_config, monkeypatch, "none", profile="patch")
    align_clock(w, monkeypatch)
    for index in range(8):
        plain = spool(w) / f"{index:032x}"
        plain.mkdir(parents=True)
        (plain / "data.tar").write_bytes(b"x")
    report = retention(w)["result"]["projects"]["shop"]
    plains = [i for i in report["items"] if i["kind"] == "capture" and not i["bound_to_update"]]
    assert len(plains) == 9 and all(  # 8 here plus the fixture's own backup capture
        i["age_days"] is not None for i in plains
    )
    assert report["spool_captures"]["count"] == 9 and report["spool_captures"]["hint"] is True
    ids = {f["id"] for f in Harness(w, tmp_path).cycle()["findings"]}
    assert "update_retention:shop:spool_captures" in ids
    assert len(list(spool(w).iterdir())) >= 8  # nothing deleted


def test_old_plain_captures_become_cleanup_candidates():
    items = [{"name": "a" * 32, "created_at": 0.0}, {"name": "b" * 32, "created_at": 31 * DAY}]
    report = update_retention.project_report([], [], items, 31 * DAY)
    assert report["spool_captures"]["count"] == 2 and report["cleanup_candidates"] == 1
    assert [i["bound_to_update"] for i in report["items"]] == [False, False]
    bound = [{"name": "a" * 32, "approval_id": "x", "created_at": 0.0}]
    both = update_retention.project_report(bound, [], items, 31 * DAY)
    assert both["spool_captures"]["count"] == 2 and len(both["items"]) == 2
