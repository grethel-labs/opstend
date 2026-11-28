from datetime import UTC, datetime, time, timedelta

import pytest

from opstend.core.audit import AuditLog
from opstend.core.jobs import (
    ActionRegistry,
    Engine,
    FunctionAction,
    Job,
    JobError,
    JobState,
    Step,
    StepState,
)
from opstend.core.policy import Autonomy, Category, Governor, Policy, Verdict
from opstend.core.store import ConflictError, Store
from opstend.core.windows import Window

# -- store ----------------------------------------------------------------


def test_store_versions_and_conflicts():
    s = Store()
    assert s.put("host", "a", {"x": 1}) == 1
    assert s.put("host", "a", {"x": 2}, expect_version=1) == 2
    with pytest.raises(ConflictError):
        s.put("host", "a", {"x": 3}, expect_version=1)
    assert s.get("host", "a") == {"x": 2}


def test_store_replace_kind_removes_missing():
    s = Store()
    s.put("guest", "1", {"n": 1})
    s.put("guest", "2", {"n": 2})
    s.replace_kind("guest", {"2": {"n": 22}, "3": {"n": 3}})
    assert [d["n"] for d in s.list("guest")] == [22, 3]


def test_store_apply_rejects_unknown():
    with pytest.raises(ValueError):
        Store().apply({"op": "drop"})


# -- audit ----------------------------------------------------------------


def test_audit_chain_detects_tampering():
    log = AuditLog()
    log.record("alice", "job.approve", "guest/1")
    log.record("opstend", "guest.start", "guest/1")
    assert log.verify()
    log._db.execute("UPDATE audit SET actor='mallory' WHERE seq=1")
    assert not log.verify()


# -- windows --------------------------------------------------------------


def test_window_follows_local_time_across_dst():
    w = Window(days=["sun"], start=time(2, 0), duration_minutes=120, timezone="Europe/Berlin")
    # Sunday 2026-03-29 is the DST switch in Europe. 01:30 UTC is 03:30 CEST.
    assert w.is_open(datetime(2026, 3, 29, 1, 30, tzinfo=UTC))
    # A winter Sunday: 02:30 CET is 01:30 UTC.
    assert w.is_open(datetime(2026, 1, 4, 1, 30, tzinfo=UTC))
    assert not w.is_open(datetime(2026, 1, 4, 4, 30, tzinfo=UTC))


def test_window_next_open_is_in_future():
    w = Window(days=["wed"], start=time(22, 0), timezone="UTC")
    now = datetime(2026, 11, 28, 12, 0, tzinfo=UTC)  # Saturday
    start, end = w.next_open(now)
    assert start.weekday() == 2 and start > now and end > start


def test_window_validation():
    with pytest.raises(ValueError):
        Window(days=["funday"])
    with pytest.raises(ValueError):
        Window(duration_minutes=1)


# -- policy ---------------------------------------------------------------


def test_governor_budget_cooldown_and_window():
    policy = Policy(
        window=Window(days=["mon"], start=time(0, 0), duration_minutes=60, timezone="UTC")
    )
    g = Governor(policy)
    t0 = datetime(2026, 11, 30, 0, 10, tzinfo=UTC)  # Monday, inside window
    assert g.decide(Category.RESTART, "svc", now=t0).verdict == Verdict.RUN
    g.spend(Category.RESTART, "svc", now=t0)
    assert (
        g.decide(Category.RESTART, "svc", now=t0 + timedelta(minutes=1)).verdict == Verdict.BLOCKED
    )
    for i in range(2):
        g.spend(Category.RESTART, "svc", now=t0 + timedelta(minutes=11 * (i + 1)))
    later = t0 + timedelta(minutes=40)
    assert "budget" in g.decide(Category.RESTART, "svc", now=later).reason
    outside = datetime(2026, 12, 1, 12, 0, tzinfo=UTC)
    assert g.decide(Category.PATCH, "host", now=outside).verdict == Verdict.WAIT_WINDOW
    assert g.decide(Category.PATCH, "host", urgent=True, now=outside).verdict == Verdict.RUN


def test_governor_respects_autonomy_and_kill_switch():
    policy = Policy()
    policy.autonomy[Category.NETWORK] = Autonomy.OBSERVE
    g = Governor(policy)
    assert g.decide(Category.NETWORK, "sw").verdict == Verdict.RECORD_ONLY
    assert g.decide(Category.UPGRADE, "x").verdict == Verdict.WAIT_APPROVAL
    policy.kill_switch = True
    assert g.decide(Category.RESTART, "svc").verdict == Verdict.WAIT_APPROVAL


# -- jobs -----------------------------------------------------------------


def _engine(state: dict, fail: str | None = None, leader=lambda: True):
    store = Store()
    reg = ActionRegistry()

    def make(name):
        async def execute(params, ctx):
            if name == fail:
                raise RuntimeError("boom")
            state[name] = params.get("value", True)
            return {"before": None}

        async def undo(params, ctx, result):
            state.pop(name, None)

        reg.register(
            FunctionAction(
                name,
                "power",
                describe=lambda p: f"set {name}",
                execute=execute,
                undo=undo,
                facts=lambda p, s: s.get("guest", "g1"),
            )
        )

    for n in ("a", "b", "c"):
        make(n)
    return Engine(store, AuditLog(), reg, is_leader=leader), store


async def test_job_runs_with_approval_and_readback():
    state: dict = {}
    engine, _store = _engine(state)
    job = await engine.preview(
        Job(title="t", category="power", target="g1", steps=[Step(action="a"), Step(action="b")])
    )
    assert job.state == JobState.AWAITING_APPROVAL
    assert job.steps[0].effect == "set a"
    await engine.approve(job.id, "alice", job.fingerprint)
    done = await engine.run(job.id)
    assert done.state == JobState.SUCCEEDED
    assert state == {"a": True, "b": True}


async def test_stale_preview_is_refused():
    engine, store = _engine({})
    store.put("guest", "g1", {"state": "stopped"})
    job = await engine.preview(
        Job(title="t", category="power", target="g1", steps=[Step(action="a")])
    )
    store.put("guest", "g1", {"state": "running"})
    with pytest.raises(JobError):
        await engine.approve(job.id, "alice")
    assert engine.get(job.id).state == JobState.REJECTED


async def test_failure_rolls_back_completed_steps():
    state: dict = {}
    engine, _ = _engine(state, fail="c")
    job = await engine.preview(
        Job(
            title="t",
            category="power",
            target="g1",
            steps=[Step(action="a"), Step(action="b"), Step(action="c")],
        ),
        auto_approve=True,
    )
    done = await engine.run(job.id)
    assert done.state == JobState.ROLLED_BACK
    assert state == {}
    assert [s.state for s in done.steps] == [
        StepState.ROLLED_BACK,
        StepState.ROLLED_BACK,
        StepState.FAILED,
    ]


async def test_idempotency_key_returns_existing_job():
    engine, _ = _engine({})
    j1 = await engine.preview(
        Job(title="t", category="power", target="g", idempotency_key="k", steps=[Step(action="a")])
    )
    j2 = await engine.preview(
        Job(title="t", category="power", target="g", idempotency_key="k", steps=[Step(action="a")])
    )
    assert j1.id == j2.id


async def test_non_leader_cannot_run():
    engine, _ = _engine({}, leader=lambda: False)
    job = await engine.preview(
        Job(title="t", category="power", target="g", steps=[Step(action="a")]), auto_approve=True
    )
    with pytest.raises(JobError):
        await engine.run(job.id)
