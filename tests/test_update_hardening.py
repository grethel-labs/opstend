"""Operator decisions of 2026-11-23 for updates (W15), local fake-host evidence only.

* 5: operator emergency confirmation for an update outside the maintenance window;
* 14: `reversible` migrations take an update-time capture (see test_update_recovery.py);
* 15: automatic rollback of a verified-healthy `none` update that turns durably unhealthy;
* 16: update captures and preserved trees are never deleted, only reported after 30 days;
* 17: the patch controller path waits for continuous health.

Decision 20 (stateless marker) is covered in test_containment.py and test_config.py.
No VM, no real Podman or systemd: control flow, bindings and refusals only.
"""

from __future__ import annotations

import json

import pytest

import test_remediation as tr
from steward.collector import audit_events
from steward.controller import COOLDOWN_S
from steward.core import update_retention
from steward.core.config import UpdatePolicy
from steward.core.events import classify
from steward.core.patch_stability import (
    GAP_S,
    StabilityTracker,
    durable_suspects,
    rollback_candidate,
)
from steward.executor import image_update
from test_patch_profile import Harness
from test_update_recovery import RESTORE, build, journal, preserved, rollback, spool, state
from update_support import NEW_DIGEST, OLD_IMAGE

DAY = 86400.0


def audit_of(w, event):
    return [e for e in w.ex.audit.read(500) if e["event"] == event]


def applied_world(tmp_path, raw_config, monkeypatch, migration="none", profile="patch"):
    w = build(tmp_path, raw_config, monkeypatch, migration, profile=profile)
    w.host.migrates = False
    return w


# ---- decision 5: emergency confirmation -------------------------------------------------------


@pytest.fixture
def late(tmp_path, raw_config, monkeypatch):
    """Evidence and backup are fresh but only seconds remain of the window."""
    w = applied_world(tmp_path, raw_config, monkeypatch)
    start = (tr.NOW // 60) * 60 - 300
    monkeypatch.setattr(image_update, "_now", lambda: start + 3600 - 30)
    return w


def emergency(w, uid=tr.OPERATOR, reason="database disk is failing, vendor fix", **over):
    params = {
        "project_id": "shop",
        "approval_id": tr.APPROVAL_ID,
        "digest": "sha256:" + NEW_DIGEST,
        "emergency_confirm": True,
        "emergency_reason": reason,
        **over,
    }
    return tr.call(w, "apply_verified_image", params, uid)


def test_outside_the_window_the_operator_needs_the_explicit_confirmation(late):
    w = late
    refused = tr.apply(w)
    assert refused["error_class"] == "policy_denied" and "maintenance window" in refused["message"]
    assert state(w) == "validated" and not audit_of(w, "update_emergency")
    result = emergency(w)
    assert result["ok"] and state(w) == "applied" and w.host.current_tag == tr.NEW_TAG
    (entry,) = audit_of(w, "update_emergency")
    assert entry["outcome"] == "confirmed" and entry["role"] == "operator"
    assert entry["approval_id"] == tr.APPROVAL_ID and "vendor fix" in entry["reason"]
    assert journal(w)["emergency_reason"].startswith("database disk")


def test_the_emergency_is_announced_as_an_immediate_event(late):
    w = late
    assert emergency(w)["ok"]
    (entry,) = audit_of(w, "update_emergency")
    (event,) = audit_events(entry)
    assert event.kind == "update.emergency" and classify(event) == "immediate"
    assert event.severity == "high" and event.project == "shop"


@pytest.mark.parametrize("uid", [tr.ME, 4242])  # controller and api
def test_automatic_callers_can_never_use_the_emergency_path(late, uid):
    w = late
    result = emergency(w, uid)
    assert result["error_class"] in ("policy_denied", "forbidden_role")
    assert state(w) == "validated" and w.host.calls == [] and w.host.current_tag == tr.OLD_TAG
    if uid == tr.ME:
        (entry,) = audit_of(w, "update_emergency")
        assert entry["outcome"] == "denied" and entry["role"] == "controller"


def test_the_controller_still_waits_for_the_window(late):
    w = late
    assert tr.apply(w, tr.ME)["error_class"] == "policy_denied"
    assert state(w) == "validated"


def test_confirmation_and_reason_go_together(late):
    w = late
    assert emergency(w, reason=None)["error_class"] == "bad_request"
    assert emergency(w, emergency_confirm=False)["error_class"] == "bad_request"
    assert emergency(w, reason="short")["error_class"] == "bad_request"
    assert emergency(w, emergency_confirm="yes")["error_class"] == "bad_request"
    assert state(w) == "validated"


def test_emergency_waives_only_the_window(late):
    w = late
    for path in spool(w).glob("*"):  # no capture bound to the deployment any more
        import shutil

        shutil.rmtree(path)
    result = emergency(w)
    assert result["error_class"] == "policy_denied" and "missing_backup" in result["message"]
    assert state(w) == "validated"
    registry = tr.registry_of(w)
    del registry["maintenance"]  # no window at all is a configuration gap, not an emergency
    w.paths.registry.write_text(json.dumps(registry))
    assert "window" in emergency(w)["message"]


def test_a_confirmation_inside_the_window_is_not_an_emergency(tmp_path, raw_config, monkeypatch):
    w = applied_world(tmp_path, raw_config, monkeypatch)
    assert emergency(w)["ok"]
    assert not audit_of(w, "update_emergency")


# ---- decision 15: automatic rollback ----------------------------------------------------------


def automatic(w, uid=tr.ME, **over):
    params = {
        "project_id": "shop",
        "approval_id": tr.APPROVAL_ID,
        "digest": "sha256:" + NEW_DIGEST,
        "automatic": True,
        **over,
    }
    return tr.call(w, "rollback", params, uid)


@pytest.fixture
def degraded(tmp_path, raw_config, monkeypatch):
    """An update verified healthy and applied; the new image then turns unhealthy."""
    w = applied_world(tmp_path, raw_config, monkeypatch)
    assert tr.apply(w)["ok"] and state(w) == "applied"
    w.host.health_ok = False  # the fake probe answers by this flag until the next restart
    return w


def test_automatic_rollback_returns_the_previous_image_once(degraded):
    w = degraded
    result = automatic(w)
    assert result["ok"] and state(w) == "rolled_back" and w.host.current_tag == tr.OLD_TAG
    marker = journal(w)["auto_rollback"]
    assert marker["reason"] == "durably_unhealthy"
    assert audit_of(w, "update_auto_rollback")[0]["outcome"] == "started"
    (event,) = audit_events(audit_of(w, "update_auto_rollback")[0])
    assert event.kind == "update.auto_rollback" and classify(event) == "immediate"
    assert not automatic(w)["ok"]  # one attempt, never repeated


def test_automatic_rollback_is_refused_for_every_other_condition(degraded, monkeypatch):
    w = degraded
    assert automatic(w, tr.OPERATOR)["error_class"] == "policy_denied"  # automatic is controller's
    assert automatic(w, acknowledge_data_restore=True)["error_class"] == "policy_denied"
    w.host.health_ok = True  # healthy again: nothing to roll back
    assert "not observed as unhealthy" in automatic(w)["message"]
    w.host.health_ok = False
    monkeypatch.setattr(image_update, "_now", lambda: tr.NOW + 1800 + 5)
    assert "window has passed" in automatic(w)["message"]
    monkeypatch.setattr(image_update, "_now", lambda: tr.NOW)
    w.host.killed = True
    assert automatic(w)["error_class"] == "kill_switch"
    w.host.killed = False
    assert state(w) == "applied" and w.host.current_tag == tr.NEW_TAG
    assert "auto_rollback" not in journal(w)


def test_the_window_can_be_disabled_and_the_profile_is_required(tmp_path, raw_config, monkeypatch):
    off = build(
        tmp_path / "off", raw_config, monkeypatch, "none", profile="patch",
        contract={"rollback_window_s": 0},
    )  # fmt: skip
    off.host.migrates = False
    assert tr.apply(off)["ok"]
    off.host.health_ok = False
    assert "not enabled" in automatic(off)["message"]
    assert state(off) == "applied"
    observe = build(tmp_path / "observe", raw_config, monkeypatch, "none", profile="observe")
    observe.host.migrates = False
    assert tr.apply(observe)["ok"]
    observe.host.health_ok = False
    assert "patch profile" in automatic(observe)["message"]
    assert state(observe) == "applied"


def test_an_unknown_probe_never_triggers_a_rollback(degraded):
    w = degraded
    w.host.http_health = lambda *_args: {"ok": False, "state": "unknown"}  # cannot tell
    result = automatic(w)
    assert result["error_class"] == "policy_denied" and state(w) == "applied"


def test_a_migrating_update_is_never_rolled_back_automatically(tmp_path, raw_config, monkeypatch):
    w = build(tmp_path, raw_config, monkeypatch, RESTORE, profile="patch")
    assert tr.apply(w)["ok"]
    w.host.health_ok = False
    result = automatic(w)
    assert result["error_class"] == "policy_denied" and "operator only" in result["message"]
    assert state(w) == "applied" and w.host.current_tag == tr.NEW_TAG
    assert rollback(w, ack=True)["ok"]  # the operator still can


def test_the_controller_rolls_back_a_durably_unhealthy_update_once(
    tmp_path, raw_config, monkeypatch
):
    w = applied_world(tmp_path, raw_config, monkeypatch)
    h = Harness(w, tmp_path)
    assert h.cycle()["patch"]["outcome"] == "ok" and state(w) == "applied"
    w.host.health_ok = False
    w.host.unhealthy_tags.add(tr.NEW_TAG)  # a restart does not heal the new image
    outcomes = []
    for _ in range(12):
        h.clock += 31
        outcomes.append(h.cycle()["rollback"])
        if state(w) == "rolled_back":
            break
    assert state(w) == "rolled_back" and w.host.current_tag == tr.OLD_TAG
    assert outcomes[0]["state"] == "idle"  # a few failed checks are not durable
    assert [o for o in outcomes if o["state"] == "requested"] == [outcomes[-1]]
    (entry,) = [e for e in h.controller.actions.read() if e["event"] == "auto_rollback"]
    assert entry["outcome"] == "ok" and entry["approval_id"] == tr.APPROVAL_ID
    h.clock += 5 * COOLDOWN_S
    assert h.cycle()["rollback"]["state"] == "idle"  # never repeated
    assert h.calls.count("rollback") == 1


def test_a_healthy_update_or_a_migrating_one_is_never_selected_by_the_controller():
    now = 10_000.0
    base = {
        "state": "applied",
        "approval_id": "approval-0123456789",
        "new_image": OLD_IMAGE.rsplit("@", 1)[0] + "@sha256:" + "b" * 64,
        "migration": "none",
        "applied_at": now - 60,
    }

    def result(**over):
        return {"approvals": [{**base, **over}], "rollback_window_s": 1800}

    assert rollback_candidate(result(), "shop", now)["digest"] == "sha256:" + "b" * 64
    assert rollback_candidate(result(migration="reversible"), "shop", now) is None
    assert rollback_candidate(result(migration=RESTORE), "shop", now) is None
    assert rollback_candidate(result(state="rolled_back"), "shop", now) is None
    assert rollback_candidate(result(auto_rollback={"at": 1}), "shop", now) is None
    assert rollback_candidate(result(applied_at=now - 1801), "shop", now) is None
    assert rollback_candidate(result(applied_at=None), "shop", now) is None
    assert rollback_candidate({**result(), "rollback_window_s": 0}, "shop", now) is None
    status = {"projects": {"shop": {"deploy": True, "unit": {"active": "active"}}}}
    assert durable_suspects(status, {"shop": 5}) == []
    assert durable_suspects(status, {"shop": 6}) == ["shop"]


# ---- decision 17: stability gate --------------------------------------------------------------


def healthy_status():
    return {
        "projects": {
            "shop": {
                "deploy": True,
                "unit": {"active": "active"},
                "health": {"ok": True},
                "hardening": {"violations": []},
            }
        }
    }


def test_the_tracker_counts_only_continuous_observed_health(tmp_path):
    path = tmp_path / "stability.json"
    tracker = StabilityTracker(path)
    status = healthy_status()
    for t in (1000.0, 1100.0, 1200.0):
        tracker.observe(status, t)
    assert tracker.healthy_for("shop", 1200.0) == 200.0
    assert StabilityTracker(path).healthy_for("shop", 1200.0) == 200.0  # durable
    tracker.observe(status, 1200.0 + GAP_S + 1)  # the controller was away: the clock restarts
    assert tracker.healthy_for("shop", 1200.0 + GAP_S + 1) == 0.0
    tracker.observe(status, 2000.0)
    tracker.observe(status, 2100.0)
    assert tracker.healthy_for("shop", 2100.0) == 100.0
    status["projects"]["shop"]["health"] = {"ok": False}
    tracker.observe(status, 2150.0)
    assert tracker.healthy_for("shop", 2150.0) == 0.0
    status["projects"]["shop"]["health"] = {"ok": True}
    tracker.observe(status, 2200.0)
    assert tracker.healthy_for("shop", 2200.0) == 0.0  # starts over after the blip
    tracker.observe(status, 100.0)  # a clock that went backwards is not continuity
    assert tracker.healthy_for("shop", 100.0) == 0.0


def test_a_damaged_tracker_file_only_delays(tmp_path):
    path = tmp_path / "stability.json"
    path.write_text("{not json")
    tracker = StabilityTracker(path)
    assert tracker.healthy_for("shop", 1.0) == 0.0
    path.write_text(json.dumps({"shop": {"since": "x", "last": None}}))
    assert StabilityTracker(path).healthy_for("shop", 1.0) == 0.0


def test_the_controller_updates_only_after_thirty_minutes_of_health(
    tmp_path, raw_config, monkeypatch
):
    w = applied_world(tmp_path, raw_config, monkeypatch)
    h = Harness(w, tmp_path)
    h.controller.stability._state.clear()  # no history: the service was not observed before
    start = h.clock
    first = h.cycle()["patch"]
    assert first["state"] == "idle" and "required before an update" in first["skipped"]["shop"]
    while h.clock - start < 1800 - 100:
        h.clock += 100
        assert h.cycle()["patch"]["state"] == "idle" and h.applies == 0
    h.clock += 100
    assert h.cycle()["patch"]["state"] == "requested" and state(w) == "applied"


def test_a_health_blip_restarts_the_clock(tmp_path, raw_config, monkeypatch):
    w = applied_world(tmp_path, raw_config, monkeypatch)
    h = Harness(w, tmp_path)
    w.host.health_ok = False
    h.clock += 10
    assert h.cycle()["patch"]["state"] == "idle" and h.applies == 0  # unhealthy: no update
    w.host.health_ok = True
    h.clock += 10
    first = h.cycle()["patch"]
    assert first["state"] == "idle" and h.applies == 0  # healthy again, but not for 30 minutes
    h.clock += 1700
    h.controller.stability._state["shop"]["last"] = h.clock - 1  # observed throughout
    assert h.cycle()["patch"]["state"] == "idle"
    h.clock += 200
    h.controller.stability._state["shop"]["last"] = h.clock - 1
    assert h.cycle()["patch"]["state"] == "requested"


def test_the_contract_can_lower_the_minimum(tmp_path, raw_config, monkeypatch):
    w = build(
        tmp_path, raw_config, monkeypatch, "none", profile="patch", contract={"min_healthy_s": 0}
    )
    w.host.migrates = False
    h = Harness(w, tmp_path)
    h.controller.stability._state.clear()
    assert h.cycle()["patch"]["state"] == "requested" and state(w) == "applied"


def test_defaults_stay_out_of_canonical_data_and_policy_revisions(raw_config):
    from steward.core.update_evidence import policy_revision
    from update_support import contract_data

    plain = UpdatePolicy.model_validate(contract_data())
    assert plain.effective_rollback_window_s == 1800 and plain.effective_min_healthy_s == 1800
    assert "rollback_window_s" not in plain.canonical_dump()
    tuned = UpdatePolicy.model_validate(contract_data(rollback_window_s=600, min_healthy_s=900))
    assert tuned.canonical_dump()["rollback_window_s"] == 600
    assert policy_revision(tuned) != policy_revision(plain)


# ---- decision 16: retention report ------------------------------------------------------------


def align_clock(w, monkeypatch):
    """Captures use the real clock and preserved trees real file times; the fake apply
    clock is 50 days ahead, so give both the fake clock's time base."""
    from steward.executor import update_retention as executor_retention

    monkeypatch.setattr(executor_retention, "_tree_age_source", lambda *_a: tr.NOW - 100)
    for record in w.ex.update_ledger.capture_records("shop"):
        row = w.ex.update_ledger.get(record["approval_id"])
        ref = {**row["journal"]["recovery_capture"], "completed_at": tr.NOW - 100}
        w.ex.update_ledger.journal(record["approval_id"], recovery_capture=ref)


def retention(w, uid=tr.OPERATOR, **params):
    return tr.call(w, "update_retention_status", params, uid)


def test_captures_and_preserved_trees_become_candidates_after_thirty_days(
    tmp_path, raw_config, monkeypatch
):
    w = build(tmp_path, raw_config, monkeypatch, RESTORE, profile="patch")
    assert tr.apply(w)["ok"] and rollback(w, ack=True)["ok"] and len(preserved(w)) == 1
    align_clock(w, monkeypatch)
    before = retention(w)["result"]["projects"]["shop"]
    assert before["cleanup_candidates"] == 0
    assert {i["kind"] for i in before["items"]} == {"capture", "preserved_tree"}
    monkeypatch.setattr(image_update, "_now", lambda: tr.NOW + 29 * DAY)
    assert retention(w)["result"]["cleanup_candidates"] == 0
    monkeypatch.setattr(image_update, "_now", lambda: tr.NOW + 31 * DAY)
    after = retention(w)["result"]
    # the update capture, the preserved tree and (new) the plain pre-update backup capture
    assert (
        after["cleanup_candidates"] == 3 and after["projects"]["shop"]["items"][0]["age_days"] == 31
    )
    # read-only: nothing was removed, for any role that may read it
    assert len(preserved(w)) == 1 and list(spool(w).glob("*/data.tar"))
    assert retention(w, 4242)["ok"] and retention(w, tr.ME)["ok"]
    assert retention(w, 31337)["error_class"] == "unauthorized_peer"
    assert retention(w, project_id="ghost")["error_class"] == "policy_denied"
    assert retention(w, command="rm")["error_class"] == "bad_request"
    assert len(preserved(w)) == 1 and list(spool(w).glob("*/data.tar"))


def test_a_hint_is_raised_before_the_tree_limit(tmp_path, raw_config, monkeypatch):
    w = build(tmp_path, raw_config, monkeypatch, "none", profile="patch")
    align_clock(w, monkeypatch)
    report = retention(w)["result"]["projects"]["shop"]
    assert report["preserved_trees"] == {"count": 0, "limit": 8, "hint": False}
    for index in range(6):
        (w.data.parent / f"data.preserved-{index:02d}").mkdir()
    report = retention(w)["result"]["projects"]["shop"]
    assert report["preserved_trees"] == {"count": 6, "limit": 8, "hint": True}
    assert report["cleanup_candidates"] == 0  # young trees are only a limit hint


def test_the_controller_reports_candidates_and_limit_hints(tmp_path, raw_config, monkeypatch):
    w = build(tmp_path, raw_config, monkeypatch, "none", profile="patch")
    for index in range(6):
        (w.data.parent / f"data.preserved-{index:02d}").mkdir()
    h = Harness(w, tmp_path)
    ids = {f["id"] for f in h.cycle()["findings"]}
    assert "update_retention:shop:preserved_trees" in ids
    pure = update_retention.classify(
        [{"kind": "capture", "name": "a" * 32, "created_at": 0.0}], 31 * DAY
    )
    assert pure[0]["cleanup_candidate"] and pure[0]["age_days"] == 31
    unknown = update_retention.classify([{"kind": "capture", "name": "b" * 32}], 31 * DAY)
    assert not unknown[0]["cleanup_candidate"] and unknown[0]["age_days"] is None


def test_nothing_here_deletes_anything():
    import inspect

    from steward.executor import update_retention as executor_module

    source = inspect.getsource(update_retention) + inspect.getsource(executor_module)
    for forbidden in ("rmtree", "unlink", "os.remove", "rmdir", "shutil.move"):
        assert forbidden not in source
