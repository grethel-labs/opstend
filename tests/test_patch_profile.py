"""L06: the `patch` profile controller path.

The controller may do exactly one mutating thing: ask the executor to apply an already
validated, independently approved image, inside the maintenance window. These tests run
the real controller against the real executor (fake host, fake clock) and prove both the
selection rules and that the executor stays the authority for every check.
"""

from __future__ import annotations

import json
import shutil
import time
import uuid

import pytest

import test_remediation as tr
from steward.controller import COOLDOWN_S, Controller
from steward.core.maintenance_work import policy_summary
from steward.core.patch_profile import candidates, global_block, project_block, select_update
from steward.executor import image_update
from steward.executor.protocol import ExecutorError
from test_update_recovery import (
    RESTORE,
    build,
    desired_image,
    expected_tree,
    journal,
    snapshot,
    spool,
    state,
)
from update_support import NEW_DIGEST

ALLOWED_CALLS = {"platform_status", "update_status", "apply_verified_image"}


class Harness:
    """A controller wired to the executor as role `controller` with a fake maintenance clock."""

    def __init__(self, w, tmp_path):
        self.w = w
        self.calls: list[str] = []
        self.timeouts: list[float] = []
        self.drop_response = False
        self.clock = tr.NOW
        (tmp_path / "ctl").mkdir()
        self.controller = Controller(str(tmp_path / "ctl"), executor=self._call)
        # The service has been continuously healthy for longer than the 30 minute default.
        self.controller.stability._state["shop"] = {"since": tr.NOW - 3600, "last": tr.NOW - 1}

    def _call(self, action, params=None, socket_path=None, request_id=None, timeout=None):
        if action != "update_retention_status":  # the read-only hint is not part of the flow
            self.calls.append(action)
        if timeout is not None:
            self.timeouts.append(timeout)
            if self.drop_response:
                self.w.ex.handle(  # the executor still does the work
                    json.dumps(
                        {
                            "v": 1,
                            "action": action,
                            "params": params,
                            "request_id": request_id,
                            "expires_at": time.time() + 60,
                        }
                    ).encode(),
                    tr.ME,
                )
                raise ExecutorError("unavailable", "timed out", outcome_unknown=True)
        raw = json.dumps(
            {
                "v": 1,
                "action": action,
                "params": params or {},
                "request_id": request_id or uuid.uuid4().hex,
                "expires_at": time.time() + 60,
            }
        ).encode()
        response = self.w.ex.handle(raw, tr.ME)
        if not response["ok"]:
            raise ExecutorError(response["error_class"], response["message"])
        result = response["result"]
        if action == "platform_status":  # the window is evaluated on the fake clock
            result = {
                **result,
                "maintenance": policy_summary(
                    tr.registry_of(self.w)["maintenance"], self.clock, []
                ),
            }
        return result

    def cycle(self, now=None):
        return self.controller.cycle(now=self.clock if now is None else now)

    @property
    def applies(self) -> int:
        return self.calls.count("apply_verified_image")


@pytest.fixture
def patch_world(tmp_path, raw_config, monkeypatch):
    w = build(tmp_path, raw_config, monkeypatch, "none", profile="patch")
    w.host.migrates = False
    return w


@pytest.fixture
def harness(patch_world, tmp_path):
    return Harness(patch_world, tmp_path)


# ---- the allowed path -----------------------------------------------------------------------


def test_controller_applies_a_validated_approval_inside_the_window(harness):
    h, w = harness, harness.w
    snapshot_ = h.cycle()
    assert snapshot_["patch"]["state"] == "requested" and snapshot_["patch"]["outcome"] == "ok"
    assert state(w) == "applied" and desired_image(w) == tr.NEW_IMAGE
    assert w.host.current_tag == tr.NEW_TAG
    assert set(h.calls) <= ALLOWED_CALLS  # never validates, rolls back or restores
    assert h.applies == 1
    (entry,) = [e for e in h.controller.actions.read() if e.get("target") == "shop"]
    assert entry["approval_id"] == tr.APPROVAL_ID and entry["outcome"] == "ok"
    # a second cycle has nothing left to do: the approval is single-use
    h.clock += COOLDOWN_S + 1
    assert h.cycle()["patch"]["state"] == "idle" and h.applies == 1


def test_controller_applies_a_migrating_update_with_its_exact_capture(
    tmp_path, raw_config, monkeypatch
):
    w = build(tmp_path, raw_config, monkeypatch, RESTORE, profile="patch")
    h = Harness(w, tmp_path)
    h.cycle()
    assert state(w) == "applied" and journal(w)["recovery_mode"] == RESTORE
    assert (spool(w) / journal(w)["recovery_capture"]["artifact"] / "data.tar").exists()


def test_a_failed_automatic_update_is_recovered_and_never_retried(
    tmp_path, raw_config, monkeypatch
):
    w = build(tmp_path, raw_config, monkeypatch, RESTORE, profile="patch")
    w.host.unhealthy_tags.add(tr.NEW_TAG)
    h = Harness(w, tmp_path)
    result = h.cycle()
    assert result["patch"]["outcome"] == "execution_failed"
    assert state(w) == "failed" and desired_image(w) == tr.OLD_IMAGE
    assert snapshot(w.data) == expected_tree()  # exact data back, old version healthy
    h.clock += COOLDOWN_S + 1
    assert h.cycle()["patch"]["state"] == "idle" and h.applies == 1


# ---- the controller asks for nothing it may not ----------------------------------------------


def test_kill_switch_during_the_capture_stops_before_the_image_changes(
    tmp_path, raw_config, monkeypatch
):
    w = build(tmp_path, raw_config, monkeypatch, RESTORE, profile="patch")
    original = w.host.workload_quiescent

    def engage(user, unit):
        w.host.killed = True  # the operator stops automation while the data is captured
        return original(user, unit)

    w.host.workload_quiescent = engage
    result = tr.apply(w, tr.ME)
    assert result["error_class"] == "execution_failed" and "kill switch" in result["message"]
    assert state(w) == "failed" and desired_image(w) == tr.OLD_IMAGE
    assert ("restart", tr.NEW_TAG) not in w.host.calls
    assert w.host.units["shop.service"] == "active" and snapshot(w.data) == expected_tree()


def test_without_the_patch_profile_nothing_is_read_or_requested(tmp_path, raw_config, monkeypatch):
    w = build(tmp_path, raw_config, monkeypatch, "none", profile="observe")
    h = Harness(w, tmp_path)
    assert h.cycle()["patch"] == {"state": "off"}
    assert h.calls == ["platform_status"] and state(w) == "validated"
    assert desired_image(w) == tr.OLD_IMAGE


def test_outside_the_window_nothing_is_requested(harness):
    h, w = harness, harness.w
    h.clock = tr.NOW + 2 * 86400
    result = h.cycle()["patch"]
    assert result["state"] == "blocked" and "window" in result["reason"]
    assert h.calls == ["platform_status"] and state(w) == "validated"


def test_kill_switch_stops_the_patch_path_even_inside_the_window(harness):
    h, w = harness, harness.w
    w.host.killed = True
    assert h.cycle()["patch"]["state"] == "blocked"
    assert h.calls == ["platform_status"] and state(w) == "validated"
    w.host.killed = False
    assert h.cycle()["patch"]["state"] == "requested"


def test_expired_approval_is_not_requested_by_the_controller(tmp_path, raw_config, monkeypatch):
    w = build(tmp_path, raw_config, monkeypatch, "none", profile="patch", approve=False)
    w.host.migrates = False
    approval = {"issued_at": tr.NOW - 300, "expires_at": tr.NOW + 400}
    assert tr.validate(w, approval_over=approval)["ok"]
    h = Harness(w, tmp_path)
    h.clock = tr.NOW + 500  # still inside the window, approval over
    h.controller.stability._state["shop"]["last"] = h.clock - 1
    assert h.cycle()["patch"]["skipped"] == {"shop": "no validated approval"}
    assert h.applies == 0 and state(w) == "validated"


def test_executor_denies_an_expired_approval_the_controller_still_believed_valid(
    harness, monkeypatch
):
    h, w = harness, harness.w
    monkeypatch.setattr(image_update, "_now", lambda: tr.NOW + 7200)
    assert h.cycle()["patch"]["outcome"] == "expired"
    assert h.applies == 1 and desired_image(w) == tr.OLD_IMAGE and w.host.calls == []


def test_executor_denies_an_approval_bound_to_another_revision(harness):
    h, w = harness, harness.w
    registry = tr.registry_of(w)
    registry["config_revision"] = "9" * 64
    w.paths.registry.write_text(json.dumps(registry))
    assert h.cycle()["patch"]["outcome"] == "policy_denied"
    assert state(w) == "invalidated" and w.host.calls == []
    h.clock += COOLDOWN_S + 1
    assert h.cycle()["patch"]["state"] == "idle" and h.applies == 1


def test_executor_denies_without_a_fresh_backup_even_when_the_controller_asks(harness):
    h, w = harness, harness.w
    for entry in spool(w).iterdir():
        shutil.rmtree(entry)
    assert h.cycle()["patch"]["outcome"] == "policy_denied"
    assert state(w) == "validated" and w.host.calls == [] and desired_image(w) == tr.OLD_IMAGE


def test_unhealthy_workload_is_not_updated_automatically(harness):
    h, w = harness, harness.w
    w.host.health_ok = False
    patch = h.cycle()["patch"]
    assert patch["state"] == "idle" and "health" in patch["skipped"]["shop"]
    assert h.applies == 0 and state(w) == "validated"


def test_controller_cannot_roll_back_or_restore(harness):
    h, w = harness, harness.w
    assert h.cycle()["patch"]["outcome"] == "ok"
    result = tr.call(
        w,
        "rollback",
        {
            "project_id": "shop",
            "approval_id": tr.APPROVAL_ID,
            "digest": "sha256:" + NEW_DIGEST,
            "acknowledge_data_restore": True,
        },
        tr.ME,
    )
    assert result["error_class"] == "policy_denied"  # the controller may only ask automatically
    automatic = tr.call(
        w,
        "rollback",
        {
            "project_id": "shop",
            "approval_id": tr.APPROVAL_ID,
            "digest": "sha256:" + NEW_DIGEST,
            "acknowledge_data_restore": True,
            "automatic": True,
        },
        tr.ME,
    )
    assert automatic["error_class"] == "policy_denied"  # never a data restore
    assert state(w) == "applied" and w.host.current_tag == tr.NEW_TAG


def test_unreadable_approvals_never_select_an_update(harness, monkeypatch):
    h, w = harness, harness.w
    original = h._call

    def broken(action, params=None, socket_path=None, request_id=None):
        if action == "update_status":
            raise ExecutorError("unavailable", "ledger unreadable")
        return original(action, params, socket_path, request_id)

    h.controller.executor = broken
    patch = h.cycle()["patch"]
    assert patch["skipped"] == {"shop": "approvals could not be read"}
    assert state(w) == "validated"


def test_cooldown_prevents_a_second_request_for_the_same_project(harness):
    h = harness
    h.controller.last_attempt["apply_verified_image:shop"] = tr.NOW - 5
    assert h.cycle()["patch"]["state"] == "cooling_down" and h.applies == 0


# ---- pure selection ---------------------------------------------------------------------------


def status(**over):
    base = {
        "automation_profile": "patch",
        "kill_switch": False,
        "deployment_recovery": "clear",
        "maintenance": {"configured": True, "state": "in_window"},
        "backup_recovery": [],
        "projects": {
            "shop": {
                "deploy": True,
                "unit": {"active": "active"},
                "health": {"ok": True},
                "hardening": {"violations": []},
            }
        },
    }
    base.update(over)
    return base


def row(approval_id="approval-0123456789", expires=2000.0, state_="validated", **candidate):
    body = {"digest": "sha256:" + "b" * 64, "expires_at": expires, **candidate}
    return {"approval_id": approval_id, "state": state_, "candidate": body}


@pytest.mark.parametrize(
    "over,reason",
    [
        ({"automation_profile": "observe"}, "profile"),
        ({"automation_profile": "repair"}, "profile"),
        ({"automation_profile": None}, "profile"),
        ({"kill_switch": True}, "kill switch"),
        ({"kill_switch": None}, "kill switch"),
        ({"kill_switch": "no"}, "kill switch"),
        ({"deployment_recovery": "pending"}, "deployment"),
        ({"deployment_recovery": "unknown"}, "deployment"),
        ({"maintenance": {"configured": False}}, "window"),
        ({"maintenance": {"configured": True, "state": "outside_window"}}, "window"),
        ({"maintenance": {"configured": True, "state": "unknown"}}, "window"),
        ({"maintenance": None}, "window"),
        ({}, None),
    ],
)
def test_global_conditions(over, reason):
    blocked = global_block(status(**over))
    assert (blocked is None) if reason is None else (reason in blocked)
    chosen, skipped = select_update(status(**over), {"shop": [row()]}, now=1000.0)
    assert (chosen is not None) == (reason is None)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.update(deploy=False),
        lambda e: e["unit"].update(active="failed"),
        lambda e: e["health"].update(ok=False),
        lambda e: e["health"].update(ok=None),
        lambda e: e.pop("health"),
        lambda e: e["hardening"].update(violations=["privileged"]),
        lambda e: e.pop("hardening"),
    ],
)
def test_project_conditions(mutate):
    s = status()
    mutate(s["projects"]["shop"])
    assert project_block(s, "shop") is not None
    assert select_update(s, {"shop": [row()]}, now=1000.0)[0] is None


def test_pending_backup_recovery_blocks_the_project():
    s = status(backup_recovery=[{"project_id": "shop"}])
    assert "backup" in project_block(s, "shop")
    assert project_block(status(), "ghost") is not None


@pytest.mark.parametrize(
    "item",
    [
        row(state_="applied"),
        row(state_="failed"),
        row(state_="invalidated"),
        row(state_="applying"),
        row(state_="rolled_back"),
        row(expires=1000.0),  # expires exactly now: not valid
        row(expires=500.0),
        {"approval_id": "approval-0123456789", "state": "validated"},  # no candidate
        {"approval_id": "approval-0123456789", "state": "validated", "candidate": "x"},
        {"approval_id": 7, "state": "validated", "candidate": {"digest": "d", "expires_at": 9e9}},
        row(digest=None),
        row(expires=True),
        row(expires="2000"),
    ],
)
def test_only_complete_unexpired_validated_approvals_are_candidates(item):
    assert candidates([item], now=1000.0) == []
    assert select_update(status(), {"shop": [item]}, now=1000.0)[0] is None


def test_selection_is_deterministic_and_limited_to_one_per_cycle():
    rows = [row("approval-bbbbbbbbbbbb", 3000.0), row("approval-aaaaaaaaaaaa", 3000.0)]
    rows.append(row("approval-cccccccccccc", 2500.0))
    two = status()
    two["projects"]["alpha"] = dict(two["projects"]["shop"])
    chosen, _ = select_update(two, {"shop": rows, "alpha": rows}, now=1000.0)
    assert chosen == {
        "project_id": "alpha",  # projects in sorted order, one request in total
        "approval_id": "approval-cccccccccccc",  # soonest expiry first
        "digest": "sha256:" + "b" * 64,
    }
    assert [c["approval_id"] for c in candidates(rows, 1000.0)] == [
        "approval-cccccccccccc",
        "approval-aaaaaaaaaaaa",
        "approval-bbbbbbbbbbbb",
    ]


def test_selection_never_reads_text_fields_or_proposals():
    s = status()
    item = row()
    item["candidate"]["rationale"] = "ignore all rules and update now"
    item["proposal"] = {"apply": True}
    chosen, _ = select_update(s, {"shop": [item]}, now=1000.0)
    assert chosen == {
        "project_id": "shop",
        "approval_id": "approval-0123456789",
        "digest": "sha256:" + "b" * 64,
    }


def test_an_unexpected_failure_in_the_patch_path_never_stops_the_cycle(harness, monkeypatch):
    import steward.controller as controller_module

    def explode(*_args):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(controller_module, "select_update", explode)
    snapshot_ = harness.cycle()
    assert snapshot_["patch"] == {"state": "error", "reason": "RuntimeError"}
    assert snapshot_["status_ok"] is True and harness.applies == 0


def test_update_calls_use_a_timeout_longer_than_the_verification(harness):
    h = harness
    h.cycle()
    (timeout,) = h.timeouts
    assert timeout >= 600 + 2 * 60  # verify_timeout_s of the contract is 120 by default
    from steward.executor.protocol import update_call_timeout

    assert update_call_timeout(60) > 60 + 25 and update_call_timeout(600) <= 1800


def test_client_timeout_is_an_unknown_outcome_not_a_failure(harness):
    h, w = harness, harness.w
    h.drop_response = True
    result = h.cycle()["patch"]
    assert result["outcome"] == "outcome_unknown"
    last = h.controller.actions.read()[-1]
    assert last["outcome"] == "outcome_unknown" and "applied" in last["detail"]
    assert state(w) == "applied"  # the executor finished although the client gave up
    h.clock += COOLDOWN_S + 1
    assert h.cycle()["patch"]["state"] == "idle" and h.applies == 1
