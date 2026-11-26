"""L11: announced maintenance drills (fake clock, fake host, local files only).

Real restarts, real isolated restore and the second-window behavior on a stack are
the host gate (tests/integration/gates/m5_l10_l11.md).
"""

from __future__ import annotations

import copy
import json
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from conftest import FakeHost
from steward.collector import audit_events
from steward.core import render
from steward.core.backups import Binding
from steward.core.config import parse_config
from steward.core.drill_cycle import DrillCycle
from steward.core.drills import DrillLedger
from steward.core.filebackups import capture_files
from steward.executor import drills
from steward.executor import server as executor_server
from steward.executor.protocol import ExecutorError

OPERATOR, CONTROLLER = 0, 4343
# Sunday 2026-11-22; the weekly window is 03:00-04:00 UTC.
SUNDAY = datetime(2026, 11, 22, tzinfo=UTC).timestamp()
ANNOUNCE_AT = SUNDAY + 2 * 3600  # one hour before the window
IN_WINDOW = SUNDAY + 3 * 3600 + 600
NEXT_WEEK = 7 * 86400


class Host(FakeHost):
    def __init__(self):
        super().__init__()
        self.recovers = True
        self.unhealthy_after_restart = False
        self.load = {"load5": 0.1, "cpus": 2}

    def load_average(self):
        return self.load

    def restart_user_unit(self, user, unit):
        self.calls.append(("restart", user, unit))
        self.health_ok = not self.unhealthy_after_restart
        return True, ""


class World:
    pass


@pytest.fixture
def world(tmp_path, raw_config, monkeypatch):
    raw = copy.deepcopy(raw_config)
    raw["maintenance"] = {
        "weekly_window": "Sun 03:00 UTC",
        "drills": ["resources", "restart", "restore"],
    }
    cfg = parse_config(raw, allow_unavailable=True)
    registry = render.render_registry(cfg)
    registry["peers"] = {"controller": CONTROLLER}
    root = tmp_path / "host"
    (root / "state").mkdir(parents=True)
    path = root / "executor.json"
    path.write_text(json.dumps(registry))
    path.chmod(0o600)
    host = Host()
    ex = executor_server.Executor(
        registry_path=str(path),
        state_dir=str(root / "state"),
        audit_path=str(root / "audit.jsonl"),
        lock_dir=str(root / "locks"),
        host=host,
    )
    clock = {"wall": ANNOUNCE_AT, "mono": 0.0}
    monkeypatch.setattr(drills, "_now", lambda: clock["wall"])
    monkeypatch.setattr(drills, "_monotonic", lambda: clock["mono"])

    def sleep(seconds):
        clock["mono"] += seconds
        clock["wall"] += seconds

    monkeypatch.setattr(drills, "_sleep", sleep)
    w = World()
    w.ex, w.host, w.clock, w.root, w.registry, w.path = ex, host, clock, root, registry, path
    w.project = next(iter(registry["projects"]))
    return w


def call(w, action, params=None, uid=OPERATOR):
    raw = json.dumps(
        {
            "v": 1,
            "action": action,
            "params": params or {},
            "request_id": uuid.uuid4().hex,
            "expires_at": time.time() + 60,
        }
    ).encode()
    out = w.ex.handle(raw, uid)
    return out


def announce(w):
    w.clock["wall"] = ANNOUNCE_AT
    out = call(w, "drill_announce")
    assert out["ok"] and out["result"]["announced"], out
    w.clock["wall"] = IN_WINDOW
    return out["result"]


def run(w, drill, project=None, uid=OPERATOR):
    params = {"drill": drill, **({"project_id": project} if project else {})}
    return call(w, "drill_run", params, uid)


def events(w):
    return [json.loads(line) for line in (w.root / "audit.jsonl").read_text().splitlines()]


def add_capture(w, project=None, *, completed_ok=True):
    project = project or w.project
    spec = w.registry["projects"][project]
    data = w.root / "data"
    data.mkdir(exist_ok=True)
    (data / "notes.db").write_text("note")
    binding = Binding(
        server=w.registry["server_name"],
        project=project,
        config_revision=w.registry["config_revision"],
        image=spec["image"],
        source_revision=spec["source_revision"],
    )
    spool = Path(w.ex._db_path).parent / "captures" / project / uuid.uuid4().hex
    spool.parent.mkdir(parents=True, exist_ok=True)
    capture_files(data, spool, binding, is_quiescent=lambda: True)
    return spool


# ---- announcement and window ------------------------------------------------------------


def test_nothing_runs_without_a_window_or_an_announcement(world):
    world.clock["wall"] = SUNDAY + 12 * 3600  # outside the window
    out = run(world, "resources")["result"]
    assert out["state"] == "deferred" and out["reason"] == "outside_window"
    world.clock["wall"] = IN_WINDOW  # inside, but never announced
    assert run(world, "resources")["result"]["reason"] == "not_announced"
    assert world.host.calls == []
    assert DrillLedger(str(world.root / "state" / "drills.db")).runs() == []


def test_announcement_needs_lead_time_and_is_idempotent(world):
    world.clock["wall"] = SUNDAY + 3 * 3600 - 300  # five minutes before: too late
    assert call(world, "drill_announce")["result"]["reason"] == "too_late"
    world.clock["wall"] = SUNDAY - 3 * 86400
    assert call(world, "drill_announce")["result"]["reason"] == "too_early"
    first = announce(world)
    assert first["created"] is True and first["drills"] == ["resources", "restart", "restore"]
    world.clock["wall"] = ANNOUNCE_AT
    assert call(world, "drill_announce")["result"]["created"] is False
    assert [e["outcome"] for e in events(world) if e.get("event") == "maintenance_drill"] == [
        "announced"
    ]


def test_a_late_announcement_does_not_count(world):
    ledger = DrillLedger(str(world.root / "state" / "drills.db"))
    start = datetime.fromtimestamp(SUNDAY + 3 * 3600, UTC).isoformat()
    ledger.announce(start, ["resources"], SUNDAY + 3 * 3600 - 60)  # only a minute ahead
    world.clock["wall"] = IN_WINDOW
    assert run(world, "resources")["result"]["reason"] == "not_announced"


def test_unconfigured_drills_and_the_kill_switch_refuse(world):
    announce(world)
    world.registry["maintenance"]["drills"] = ["resources"]
    world.path.write_text(json.dumps(world.registry))
    assert run(world, "restart", world.project)["error_class"] == "policy_denied"
    world.registry["maintenance"].pop("drills")
    world.path.write_text(json.dumps(world.registry))
    assert run(world, "resources")["error_class"] == "policy_denied"
    world.host.killed = True
    assert run(world, "resources", uid=CONTROLLER)["error_class"] == "kill_switch"


def test_a_registry_without_drills_has_no_drill_path(raw_config):
    """maintenance.drills stays unavailable for users: a config with it is rejected."""
    raw = copy.deepcopy(raw_config)
    raw["maintenance"] = {"weekly_window": "Sun 03:00 UTC", "drills": ["restart"]}
    with pytest.raises(Exception, match="maintenance.drills"):
        parse_config(raw)


# ---- the drills ---------------------------------------------------------------------------


def test_resource_drill_is_recorded_once_per_window(world):
    announce(world)
    done = run(world, "resources", uid=CONTROLLER)["result"]
    assert done["state"] == "completed" and done["result"]["healthy"] is True
    assert run(world, "resources")["result"]["reason"] == "already_ran_in_window"
    world.clock["wall"] += NEXT_WEEK  # next week needs its own announcement
    assert run(world, "resources")["result"]["reason"] == "not_announced"


def test_unhealthy_resources_defer_restart_and_restore(world):
    announce(world)
    world.host.load = {"load5": 50.0, "cpus": 2}
    assert run(world, "restart", world.project)["result"]["reason"] == "resources_unhealthy"
    assert world.host.calls == []


def test_restart_drill_measures_recovery_time(world):
    announce(world)
    out = run(world, "restart", world.project, uid=CONTROLLER)["result"]
    assert out["state"] == "completed" and out["result"]["health"] == "healthy"
    assert isinstance(out["elapsed_s"], float)
    assert world.host.calls == [("restart", "stw-notes", "notes.service")]
    started = [e for e in events(world) if e.get("event") == "maintenance_drill"]
    assert [e["outcome"] for e in started] == ["announced", "started", "completed"]
    assert all("reboot" not in repr(c) for c in world.host.calls)


def test_failed_recovery_suspends_the_service_until_release(world):
    announce(world)
    world.host.unhealthy_after_restart = True
    out = run(world, "restart", world.project)["result"]
    assert out["state"] == "failed" and out["cause"] in ("not_healthy_in_time", "overrun")
    assert out["elapsed_s"] <= drills.BUDGET_S["restart"] + 5  # bounded by the budget
    failed = [e for e in events(world) if e.get("event") == "maintenance_drill"][-1]
    assert failed["outcome"] == "failed" and failed["suspended"] is True
    # next week, announced: the suspended service is still skipped
    world.clock["wall"] += NEXT_WEEK
    announce_next = call(world, "drill_announce")
    world.clock["wall"] += 3 * 3600  # (announce_next may be too early; announce by ledger)
    del announce_next
    ledger = DrillLedger(str(world.root / "state" / "drills.db"))
    start = datetime.fromtimestamp(SUNDAY + NEXT_WEEK + 3 * 3600, UTC).isoformat()
    ledger.announce(start, ["restart"], SUNDAY + NEXT_WEEK)
    world.clock["wall"] = IN_WINDOW + NEXT_WEEK
    world.host.unhealthy_after_restart = False
    assert run(world, "restart", world.project)["result"]["reason"] == "suspended"
    assert len(world.host.calls) == 1
    # only an operator releases; the controller cannot
    assert (
        call(world, "drill_release", {"project_id": world.project}, CONTROLLER)["error_class"]
        == "forbidden_role"
    )
    assert call(world, "drill_release", {"project_id": world.project})["result"]["released"]
    assert run(world, "restart", world.project)["result"]["state"] == "completed"


def test_a_verified_update_releases_a_suspension(world):
    announce(world)
    ledger = DrillLedger(str(world.root / "state" / "drills.db"))
    ledger.suspend(world.project, "r" * 32, "not_healthy_in_time", IN_WINDOW - 100)

    class Updates:
        def summaries(self, project, limit):
            return [{"state": "applied", "updated_at": IN_WINDOW - 50}]

    world.ex.update_ledger = Updates()
    assert run(world, "restart", world.project)["result"]["state"] == "completed"
    assert ledger.suspension(world.project) is None


def test_overrun_of_the_window_fails_and_suspends(world):
    """The unhealthy service is observed only until the window ends."""
    world.clock["wall"] = SUNDAY + 3 * 3600 + 3600 - 120  # two minutes before the end
    ledger = DrillLedger(str(world.root / "state" / "drills.db"))
    start = datetime.fromtimestamp(SUNDAY + 3 * 3600, UTC).isoformat()
    ledger.announce(start, ["restart"], ANNOUNCE_AT)
    out = run(world, "restart", world.project)
    # 300 s of work does not fit before the end: deferred, nothing was restarted
    assert out["result"]["reason"] == "does_not_fit_before_window_end"
    assert world.host.calls == []


def test_dead_executor_leaves_a_started_run_that_is_recovered_as_failed(world):
    announce(world)
    ledger = DrillLedger(str(world.root / "state" / "drills.db"))
    start = datetime.fromtimestamp(SUNDAY + 3 * 3600, UTC).isoformat()
    assert ledger.begin("restart", world.project, start, IN_WINDOW - 30)  # then the process died
    assert run(world, "restart", world.project)["result"]["reason"] == "suspended"
    assert [r["state"] for r in ledger.runs()] == ["failed"]
    assert ledger.runs()[0]["cause"] == "interrupted"


def test_restore_drill_is_isolated_and_never_touches_production(world):
    announce(world)
    assert run(world, "restore", world.project)["result"]["reason"] == "no_verified_capture"
    add_capture(world)
    data = world.root / "data"
    before = (data / "notes.db").read_text()
    out = run(world, "restore", world.project)["result"]
    assert out["state"] == "completed" and out["result"]["isolated"] is True
    assert (data / "notes.db").read_text() == before
    assert world.host.calls == []  # no stop, no restart, no replacement
    work = Path(world.ex._db_path).parent / "drill-work"
    assert list(work.iterdir()) == []  # the private workspace is removed


def test_drill_results_are_exported_as_events_and_status(world):
    announce(world)
    run(world, "restart", world.project)
    mapped = [e for entry in events(world) for e in audit_events(entry)]
    kinds = [e.kind for e in mapped if e.kind.startswith("maintenance.drill_")]
    assert kinds == [
        "maintenance.drill_announced",
        "maintenance.drill_started",
        "maintenance.drill_completed",
    ]
    assert {e.delivery for e in mapped if e.kind.endswith("completed")} == {"digest"}
    status = call(world, "platform_status", uid=CONTROLLER)["result"]["maintenance"]
    assert status["drill_state"]["runs"][0]["drill"] == "restart"
    assert status["drill_state"]["suspensions"] == []


# ---- the controller driver -------------------------------------------------------------------


def test_controller_announces_ahead_and_asks_each_target_once_per_window():
    calls = []

    def executor(action, params, **kwargs):
        calls.append((action, params))
        return {"announced": True, "state": "completed"}

    cycle = DrillCycle(executor, "sock")
    base = {
        "kill_switch": False,
        "deployment_recovery": "clear",
        "projects": {
            "notes": {"deploy": True, "allow_restart": True, "health": {"state": "healthy"}}
        },
    }
    window = {"start": datetime.fromtimestamp(SUNDAY + 3 * 3600, UTC).isoformat()}
    before = {
        **base,
        "maintenance": {
            "drills": ["resources", "restart"],
            "state": "outside_window",
            "next_window": window,
        },
    }
    assert cycle.run(before, ANNOUNCE_AT)["state"] == "announce"
    assert cycle.run(before, ANNOUNCE_AT)["state"] == "waiting"  # announced once
    inside = {
        **base,
        "maintenance": {
            "drills": ["resources", "restart"],
            "state": "in_window",
            "current_window": window,
        },
    }
    asked = [cycle.run(inside, IN_WINDOW)["state"] for _ in range(4)]
    assert asked == ["asked", "asked", "done", "done"]
    assert [c[1].get("drill") for c in calls[1:]] == ["resources", "restart"]
    blocked = {**inside, "kill_switch": True}
    assert cycle.run(blocked, IN_WINDOW)["state"] == "blocked"
    assert DrillCycle(executor, "s").run({"maintenance": {}}, 0)["state"] == "off"


def test_controller_survives_an_executor_refusal():
    def executor(action, params, **kwargs):
        raise ExecutorError("kill_switch", "stopped")

    cycle = DrillCycle(executor, "sock")
    window = {"start": datetime.fromtimestamp(SUNDAY + 3 * 3600, UTC).isoformat()}
    status = {
        "deployment_recovery": "clear",
        "maintenance": {"drills": ["resources"], "state": "in_window", "current_window": window},
    }
    assert cycle.run(status, IN_WINDOW) == {"state": "error", "class": "kill_switch"}
