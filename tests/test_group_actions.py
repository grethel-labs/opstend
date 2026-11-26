"""Executor protocol coverage for operator application group actions."""

import json
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from steward import application_boot as boot
from steward.core.config import Health, parse_config
from steward.core.render import prepare_application_registry
from steward.executor import server
from steward.executor.host import Host
from steward.executor.protocol import ExecutorError
from steward.executor.server import GroupStartupRecovery
from test_application_graph import graph
from test_executor import request
from test_group_checkpoint import advance, begin, restart
from test_group_reconcile import group_host as group_host


@pytest.fixture
def group_registry(raw_config, executor):
    application = graph(raw_config)
    application["services"][2]["deploy"] = False
    registry = prepare_application_registry(parse_config(raw_config, allow_unavailable=True))
    registry["peers"] = {"api": 4241, "controller": 4242}
    write_registry(executor, registry)
    return registry


def write_registry(executor, registry):
    Path(executor.registry_path).write_text(json.dumps(registry))


def status(executor, registry, *, peer=0, **params):
    body = {"application": "shop", "expected_revision": registry["config_revision"]}
    body.update(params)
    return executor.handle(request("application_group_status", body), peer)


def test_idle_status_is_operator_only_and_read_only(executor, group_registry):
    payload = request(
        "application_group_status",
        {"application": "shop", "expected_revision": group_registry["config_revision"]},
        expires_at=0,
    )
    for _ in range(2):
        response = executor.handle(payload, 0)
        assert response["ok"]
        assert response["result"] == {"state": "idle", "checkpoint": None}
    for peer, error_class in (
        (4241, "forbidden_role"),
        (4242, "forbidden_role"),
        (31337, "unauthorized_peer"),
    ):
        assert executor.handle(payload, peer)["error_class"] == error_class
    assert executor.group_checkpoint("shop") is None
    assert executor.host.calls == []


@pytest.mark.parametrize(
    "params",
    [
        {"application": "../shop"},
        {"application": 1},
        {"expected_revision": "z" * 64},
        {"expected_revision": None},
        {"target": "database"},
        {"uid": 0},
        {"unit": "database.service"},
    ],
)
def test_status_refuses_invalid_parameters(executor, group_registry, params):
    assert status(executor, group_registry, **params)["error_class"] == "bad_request"


def test_status_reports_pending_and_confirmed_progress_after_restart(executor, group_registry):
    checkpoint = advance(executor, begin(executor, group_registry), "prepare")
    assert checkpoint.pending.service == "worker"
    reopened = restart(executor)
    response = status(reopened, group_registry)
    assert response["result"] == {
        "state": "stopping",
        "checkpoint": checkpoint.model_dump(mode="json"),
    }
    assert reopened.group_checkpoint("shop") == checkpoint

    confirmed = advance(reopened, checkpoint, "confirm", observed_running=False)
    assert confirmed.pending is None and confirmed.stop_index == 1
    reopened = restart(reopened)
    response = status(reopened, group_registry)
    assert response["result"] == {
        "state": "stopping",
        "checkpoint": confirmed.model_dump(mode="json"),
    }
    assert reopened.group_checkpoint("shop") == confirmed
    assert executor.host.calls == []


def test_status_reports_terminal_checkpoint_after_revision_change(executor, group_registry):
    checkpoint = begin(executor, group_registry)
    for _ in checkpoint.plan.stop_order:
        checkpoint = advance(executor, checkpoint, "prepare")
        checkpoint = advance(executor, checkpoint, "confirm", observed_running=False)
    checkpoint = advance(executor, checkpoint, "pause")
    checkpoint = advance(executor, checkpoint, "resume")
    for service in checkpoint.plan.start_order:
        checkpoint = advance(executor, checkpoint, "prepare")
        checkpoint = advance(
            executor, checkpoint, "confirm", observed_running=checkpoint.original_running[service]
        )
    checkpoint = advance(executor, checkpoint, "finish")
    group_registry["config_revision"] = "a" * 64
    write_registry(executor, group_registry)
    assert status(executor, group_registry)["result"] == {
        "state": "complete",
        "checkpoint": checkpoint.model_dump(mode="json"),
    }


def test_status_refuses_stale_revision_and_changed_active_binding(executor, group_registry):
    checkpoint = begin(executor, group_registry)
    assert status(executor, group_registry, expected_revision="a" * 64)["error_class"] == "conflict"
    group_registry["applications"]["shop"]["services"]["frontend"]["deploy"] = True
    write_registry(executor, group_registry)
    assert status(executor, group_registry)["error_class"] == "conflict"
    group_registry["config_revision"] = "a" * 64
    write_registry(executor, group_registry)
    assert status(executor, group_registry)["error_class"] == "conflict"
    assert executor.group_checkpoint("shop") == checkpoint


def test_status_requires_registered_application(executor, group_registry):
    assert status(executor, group_registry, application="other")["error_class"] == "policy_denied"
    group_registry.pop("applications")
    write_registry(executor, group_registry)
    assert status(executor, group_registry)["error_class"] == "policy_denied"


def test_status_refuses_corrupt_checkpoint(executor, group_registry):
    begin(executor, group_registry)
    with executor._db() as db:
        db.execute("UPDATE application_group_intents SET generation=1 WHERE application='shop'")
    assert status(executor, group_registry)["error_class"] == "unavailable"


def test_status_refuses_corrupt_registration(executor, group_registry):
    group_registry["applications"]["shop"]["lock"] = "unrelated"
    write_registry(executor, group_registry)
    assert status(executor, group_registry)["error_class"] == "unavailable"


def test_status_refuses_held_deployment_or_application_lock(executor, group_registry):
    for target in ("deployment-execution", group_registry["applications"]["shop"]["lock"]):
        with executor.target_lock(target):
            assert status(executor, group_registry)["error_class"] == "target_busy"
    assert status(executor, group_registry)["result"] == {"state": "idle", "checkpoint": None}


def test_status_refuses_registry_replaced_during_observation(executor, group_registry, monkeypatch):
    read_checkpoint = executor.group_checkpoint

    def replace_registry(application):
        group_registry["config_revision"] = "a" * 64
        write_registry(executor, group_registry)
        return read_checkpoint(application)

    monkeypatch.setattr(executor, "group_checkpoint", replace_registry)
    assert status(executor, group_registry)["error_class"] == "conflict"


@pytest.fixture
def boot_authority(executor, monkeypatch):
    def authority(host, registry, plan):
        services = registry["applications"][plan.application]["services"]
        return {
            name: SimpleNamespace(enabled=services[name]["deploy"], health=None)
            for name in plan.start_order + plan.external_dependencies
        }

    monkeypatch.setattr(boot, "require_group_authority", authority)
    monkeypatch.setattr(
        executor.host,
        "system_unit",
        lambda unit: {"load": "loaded", "active": "active", "sub": "exited"},
        raising=False,
    )
    monkeypatch.setattr(
        executor.host, "application_unit_transitioning", lambda user, unit: False, raising=False
    )
    return authority


def mutate(executor, registry, action="stop", *, peer=0, checkpoint=None, **changes):
    params = {"application": "shop", "expected_revision": registry["config_revision"]}
    if action == "stop":
        params["service"] = "database"
    if checkpoint is not None:
        prefix = "previous_" if action == "stop" else ""
        params[f"{prefix}operation_id"] = checkpoint.operation_id
        params[f"{prefix}generation"] = checkpoint.generation
    return executor.handle(request(f"application_group_{action}", params | changes), peer)


@pytest.fixture
def group_readiness(executor, group_registry, group_host, boot_authority, monkeypatch):
    port, uid = 8123, 4243
    clock = SimpleNamespace(now=0.0, sleeps=[])
    events = []
    listener = [("0100007F", port, uid, "0A")]
    evidence = SimpleNamespace(
        health=Health(), sockets=lambda: listener, probe=lambda timeout: {"ok": True}
    )

    def sleep(seconds):
        assert seconds > 0
        clock.now += seconds
        clock.sleeps.append(seconds)

    def authority(host, registry, plan):
        targets = boot_authority(host, registry, plan)
        targets["database"] = boot.Target(
            binding=SimpleNamespace(uid=uid), enabled=True, port=port, health=evidence.health
        )
        return targets

    def owns_listener(actual_port, actual_uid):
        assert (actual_port, actual_uid) == (port, uid)
        listening = SimpleNamespace(_tcp_sockets=evidence.sockets)
        owned = Host.application_listener_owned(listening, actual_port, actual_uid)
        events.append(("ownership", owned))
        return owned

    def probe(actual_port, path, timeout):
        assert (actual_port, path) == (port, evidence.health.path)
        assert events[-1] == ("ownership", True)
        pending = executor.group_checkpoint("shop").pending
        assert pending is not None
        events.append(("probe", pending.service))
        return evidence.probe(timeout)

    append = executor.audit.append

    def audit(event, **fields):
        if event == "application_group_step":
            events.append((fields["outcome"], fields["service"]))
        return append(event, **fields)

    monkeypatch.setattr(
        server, "time", SimpleNamespace(time=time.time, monotonic=lambda: clock.now, sleep=sleep)
    )
    monkeypatch.setattr(boot, "require_group_authority", authority)
    monkeypatch.setattr(executor.host, "application_listener_owned", owns_listener, raising=False)
    monkeypatch.setattr(executor.host, "http_health", probe, raising=False)
    monkeypatch.setattr(executor.audit, "append", audit)
    assert mutate(executor, group_registry)["result"]["state"] == "paused"
    events.clear()
    return executor.group_checkpoint("shop"), evidence, listener, events, clock


def test_operator_resume_waits_for_listener_and_recovers_transient_probe_error(
    executor, group_registry, group_host, group_readiness
):
    paused, evidence, listener, events, clock = group_readiness
    sockets = iter([[]])
    evidence.sockets = lambda: next(sockets, listener)
    probes = iter([{"ok": False, "error": "ConnectionResetError"}, {"ok": True}, {"ok": True}])

    def probe(timeout):
        if events[-1] == ("probe", "database"):
            assert 0 < timeout <= 5 - clock.now
        return next(probes)

    evidence.probe = probe
    response = mutate(executor, group_registry, "resume", checkpoint=paused)
    assert response["ok"], response
    assert response["result"]["state"] == "complete"
    assert group_host[1] == [
        ("worker", False),
        ("database", False),
        ("database", True),
        ("worker", True),
    ]
    assert [event for event in events if event[1] not in ("backend", "frontend")] == [
        ("attempt", "database"),
        ("ownership", False),
        ("ownership", True),
        ("probe", "database"),
        ("ownership", True),
        ("ownership", True),
        ("probe", "database"),
        ("ownership", True),
        ("confirmed", "database"),
        ("ownership", True),
        ("probe", "worker"),
        ("ownership", True),
        ("attempt", "worker"),
        ("confirmed", "worker"),
    ]


@pytest.mark.parametrize("fault", ["foreign", "multiple", "disappearing"])
def test_operator_resume_requires_exact_listener_ownership(
    executor, group_registry, group_host, group_readiness, fault
):
    paused, evidence, listener, events, clock = group_readiness
    evidence.health = Health(retries=2)
    address, port, uid, state = listener[0]
    foreign = (address, port, uid + 1, state)
    if fault == "foreign":
        evidence.sockets = lambda: [foreign]
    elif fault == "multiple":
        evidence.sockets = lambda: [*listener, foreign]
    else:
        sockets = iter([listener, []])
        evidence.sockets = lambda: next(sockets, [])
    assert mutate(executor, group_registry, "resume", checkpoint=paused)["error_class"] == (
        "unavailable"
    )
    pending = executor.group_checkpoint("shop")
    assert pending.phase == "resuming" and pending.pending.service == "database"
    assert restart(executor).group_checkpoint("shop") == pending
    assert group_host[1][-1:] == [("database", True)]
    assert not group_host[0]["worker"]
    assert ("confirmed", "database") not in events
    assert [event for event in events if event[0] == "probe"] == (
        [("probe", "database")] if fault == "disappearing" else []
    )
    if fault != "disappearing":
        assert events.count(("ownership", False)) == evidence.health.retries
        assert len(clock.sleeps) == evidence.health.retries - 1

    sockets = iter([[]])
    evidence.sockets = lambda: next(sockets, listener)
    assert mutate(executor, group_registry, "resume", checkpoint=pending)["result"]["state"] == (
        "complete"
    )
    assert group_host[1].count(("database", True)) == 1
    assert events.count(("attempt", "database")) == 1
    assert events.count(("confirmed", "database")) == 1


@pytest.mark.parametrize("late_success", [False, True])
def test_operator_resume_bounds_probe_time_and_preserves_unconfirmed_start(
    executor, group_registry, group_host, group_readiness, late_success
):
    paused, evidence, _, events, clock = group_readiness
    evidence.health = Health(retries=10, timeout_s=60)

    def exhaust_deadline(timeout):
        assert 0 < timeout <= 5
        clock.now += 5.1 if late_success else 5
        return {"ok": late_success}

    evidence.probe = exhaust_deadline
    assert mutate(executor, group_registry, "resume", checkpoint=paused)["error_class"] == (
        "unavailable"
    )
    assert events.count(("probe", "database")) == 1
    assert not clock.sleeps
    assert ("confirmed", "database") not in events
    assert executor.group_checkpoint("shop").pending.service == "database"
    assert not group_host[0]["worker"]


def test_operator_resume_checks_dependency_health_once_per_attempt(
    executor, group_registry, group_host, group_readiness
):
    paused, evidence, _, events, clock = group_readiness
    probes = iter([{"ok": True}, {"ok": False}])
    evidence.probe = lambda timeout: next(probes)
    assert mutate(executor, group_registry, "resume", checkpoint=paused)["error_class"] == (
        "unavailable"
    )
    pending = executor.group_checkpoint("shop")
    assert pending.pending.service == "worker"
    assert ("confirmed", "database") in events and ("attempt", "worker") not in events
    assert events.count(("probe", "worker")) == 1
    assert not clock.sleeps
    assert not group_host[0]["worker"]


def test_operator_resume_reobserves_unit_after_successful_health(
    executor, group_registry, group_host, group_readiness
):
    paused, evidence, _, events, _ = group_readiness
    states, mutations = group_host

    def exit_during_probe(timeout):
        states["database"] = False
        return {"ok": True}

    evidence.probe = exit_during_probe
    assert mutate(executor, group_registry, "resume", checkpoint=paused)["error_class"] == (
        "unavailable"
    )
    assert events == [
        ("attempt", "database"),
        ("ownership", True),
        ("probe", "database"),
        ("ownership", True),
    ]
    pending = executor.group_checkpoint("shop")
    assert pending.pending.service == "database"
    assert mutations[-1] == ("database", True)
    assert not states["worker"]


def test_operator_protocol_requires_registered_ids_and_exact_identity(
    executor, group_registry, group_host, boot_authority
):
    _, mutations = group_host
    for action in ("stop", "resume"):
        for peer, error in (
            (4241, "forbidden_role"),
            (4242, "forbidden_role"),
            (31337, "unauthorized_peer"),
        ):
            assert mutate(executor, group_registry, action, peer=peer)["error_class"] == error

    for bad in (
        {"service": "../database"},
        {"unit": "database.service"},
        {"previous_operation_id": "a" * 32},
        {"previous_generation": 0},
        {"previous_operation_id": "a" * 32, "previous_generation": False},
    ):
        assert mutate(executor, group_registry, **bad)["error_class"] == "bad_request"
    for bad in ({}, {"operation_id": "a" * 32}, {"operation_id": "a" * 32, "generation": "0"}):
        assert mutate(executor, group_registry, "resume", **bad)["error_class"] == "bad_request"
    assert mutate(executor, group_registry, service="missing")["error_class"] == "policy_denied"
    assert mutate(executor, group_registry, expected_revision="a" * 64)["error_class"] == "conflict"
    assert executor.group_checkpoint("shop") is None
    assert not mutations


def test_operator_stop_and_resume_preserve_dependency_order_and_original_intent(
    executor, group_registry, group_host, boot_authority
):
    states, mutations = group_host
    states.update(backend=True, frontend=True, worker=False)
    group_registry["applications"]["shop"]["services"]["frontend"]["deploy"] = True
    write_registry(executor, group_registry)
    original = states.copy()

    assert mutate(executor, group_registry)["result"]["state"] == "paused"
    paused = executor.group_checkpoint("shop")
    assert paused.operator_managed and paused.original_running == original
    assert mutations == [("frontend", False), ("backend", False), ("database", False)]
    assert not any(states.values())
    assert mutate(executor, group_registry, checkpoint=paused)["error_class"] == "target_busy"
    assert (
        mutate(executor, group_registry, "resume", checkpoint=paused, generation=0)["error_class"]
        == "conflict"
    )
    assert (
        mutate(executor, group_registry, "resume", checkpoint=paused, expected_revision="a" * 64)[
            "error_class"
        ]
        == "conflict"
    )
    assert executor.group_checkpoint("shop") == paused

    assert (
        mutate(executor, group_registry, "resume", checkpoint=paused)["result"]["state"]
        == "complete"
    )
    complete = executor.group_checkpoint("shop")
    assert states == original
    assert mutations == [
        ("frontend", False),
        ("backend", False),
        ("database", False),
        ("database", True),
        ("backend", True),
        ("frontend", True),
    ]
    assert mutate(executor, group_registry, checkpoint=paused)["error_class"] == "conflict"
    assert mutate(executor, group_registry)["error_class"] == "target_busy"
    assert executor.group_checkpoint("shop") == complete
    assert mutate(executor, group_registry, checkpoint=complete)["result"]["state"] == "paused"
    replacement = executor.group_checkpoint("shop")
    assert replacement.operation_id != complete.operation_id
    assert executor.group_history(complete.operation_id).checkpoint == complete
    assert (
        mutate(executor, group_registry, "resume", checkpoint=complete)["error_class"] == "conflict"
    )
    assert executor.group_checkpoint("shop") == replacement


def test_operator_admission_acquires_real_locks_before_boot_authority(
    executor, group_registry, group_host, boot_authority, monkeypatch
):
    _, mutations = group_host
    peer = restart(executor)
    application = group_registry["applications"]["shop"]
    database = application["services"]["database"]
    group_registry["projects"] = {"aa-alias": {"user": database["user"], "unit": database["unit"]}}
    write_registry(executor, group_registry)
    target_locks = sorted(
        {
            application["lock"],
            *(spec["lock"] for spec in application["services"].values()),
            "project-aa-alias",
        }
    )
    driver = "group-driver-" + application["lock"]
    expected = [driver, "deployment-execution", *target_locks]
    lock = executor.target_lock
    held = []
    events = []

    @contextmanager
    def traced_lock(target):
        with lock(target):
            held.append(target)
            events.append(target)
            try:
                yield
            finally:
                assert held.pop() == target

    def authority(host, registry, plan):
        events.append("boot authority")
        assert held == expected
        for target in expected:
            with pytest.raises(ExecutorError, match="another mutation"), peer.target_lock(target):
                pytest.fail("the group must hold its real flock during Boot authority checks")
        return boot_authority(host, registry, plan)

    monkeypatch.setattr(executor, "target_lock", traced_lock)
    monkeypatch.setattr(boot, "require_group_authority", authority)
    for target in expected:
        with peer.target_lock(target):
            assert mutate(executor, group_registry)["error_class"] == "target_busy"
    assert executor.group_checkpoint("shop") is None and not mutations
    events.clear()
    assert mutate(executor, group_registry)["result"]["state"] == "paused"
    assert events[: len(expected) + 1] == [*expected, "boot authority"]
    assert mutations == [("worker", False), ("database", False)]
    paused = executor.group_checkpoint("shop")
    assert (
        mutate(executor, group_registry, "resume", checkpoint=paused)["result"]["state"]
        == "complete"
    )
    assert mutations == [
        ("worker", False),
        ("database", False),
        ("database", True),
        ("worker", True),
    ]


def test_operator_admission_requires_ready_boot_exact_authority_and_no_durable_fence(
    executor, group_registry, group_host, boot_authority, monkeypatch
):
    _, mutations = group_host
    boot_state = {"load": "loaded", "active": "active", "sub": "running"}
    monkeypatch.setattr(executor.host, "system_unit", lambda unit: boot_state)
    assert mutate(executor, group_registry)["error_class"] == "unavailable"
    boot_state["sub"] = "exited"
    executor.host.killed = True
    assert mutate(executor, group_registry)["error_class"] == "kill_switch"
    executor.host.killed = False

    def reject(host, registry, plan):
        assert plan.config_revision == group_registry["config_revision"]
        raise boot.BootError("registry binding is stale")

    monkeypatch.setattr(boot, "require_group_authority", reject)
    assert mutate(executor, group_registry)["error_class"] == "policy_denied"
    monkeypatch.setattr(boot, "require_group_authority", boot_authority)
    executor.begin_deployment_fence(
        base_revision=group_registry["config_revision"], desired_revision="a" * 64
    )
    with executor.target_lock("deployment-execution"):
        pass
    assert mutate(executor, group_registry)["error_class"] == "target_busy"
    assert executor.group_checkpoint("shop") is None and not mutations


def test_interrupted_operator_resume_retries_exact_checkpoint_without_repeating_effect(
    executor, group_registry, group_host, boot_authority, monkeypatch
):
    states, mutations = group_host
    assert mutate(executor, group_registry)["result"]["state"] == "paused"
    paused = executor.group_checkpoint("shop")
    original_change = executor.host.set_user_unit

    def interrupt(user, unit, *, running):
        original_change(user, unit, running=running)
        raise KeyboardInterrupt

    monkeypatch.setattr(executor.host, "set_user_unit", interrupt)
    with pytest.raises(KeyboardInterrupt):
        mutate(executor, group_registry, "resume", checkpoint=paused)
    reopened = restart(executor)
    pending = reopened.group_checkpoint("shop")
    assert pending.phase == "resuming" and pending.pending.service == "database"
    assert states["database"] and not states["worker"]
    assert (
        mutate(reopened, group_registry, "resume", checkpoint=paused)["error_class"] == "conflict"
    )
    assert reopened.group_checkpoint("shop") == pending
    monkeypatch.setattr(executor.host, "set_user_unit", original_change)

    executor.host.killed = True
    assert (
        mutate(reopened, group_registry, "resume", checkpoint=pending)["error_class"]
        == "kill_switch"
    )
    executor.host.killed = False

    def reject(host, registry, plan):
        raise boot.BootError("boot authority changed after the interrupted start")

    monkeypatch.setattr(boot, "require_group_authority", reject)
    assert (
        mutate(reopened, group_registry, "resume", checkpoint=pending)["error_class"]
        == "policy_denied"
    )
    assert reopened.group_checkpoint("shop") == pending
    assert mutations == [("worker", False), ("database", False), ("database", True)]
    monkeypatch.setattr(boot, "require_group_authority", boot_authority)
    assert (
        mutate(reopened, group_registry, "resume", checkpoint=pending)["result"]["state"]
        == "complete"
    )
    assert states == paused.original_running
    assert mutations == [
        ("worker", False),
        ("database", False),
        ("database", True),
        ("worker", True),
    ]


def test_operator_startup_recovery_leaves_deployment_lock_available_until_boot_exits(
    executor, group_registry, group_host, boot_authority, monkeypatch
):
    states, mutations = group_host
    original_change = executor.host.set_user_unit

    def interrupt(user, unit, *, running):
        original_change(user, unit, running=running)
        raise KeyboardInterrupt

    monkeypatch.setattr(executor.host, "set_user_unit", interrupt)
    with pytest.raises(KeyboardInterrupt):
        mutate(executor, group_registry)
    reopened = restart(executor)
    pending = reopened.group_checkpoint("shop")
    assert pending.phase == "stopping" and pending.pending.service == "worker"
    assert not states["worker"]
    monkeypatch.setattr(executor.host, "set_user_unit", original_change)
    boot_state = {"load": "loaded", "active": "activating", "sub": "start"}
    monkeypatch.setattr(executor.host, "system_unit", lambda unit: boot_state)
    recovery = GroupStartupRecovery(reopened)
    target_lock = reopened.target_lock
    attempts = []

    @contextmanager
    def traced_lock(target):
        attempts.append(target)
        with target_lock(target):
            yield

    monkeypatch.setattr(reopened, "target_lock", traced_lock)
    with executor.target_lock("deployment-execution"):
        recovery.tick()
    assert attempts == [] and recovery.candidates == {"shop": pending.operation_id}
    assert reopened.group_checkpoint("shop") == pending
    assert mutations == [("worker", False)]
    boot_state.update(active="active", sub="exited")
    for _ in range(len(pending.plan.start_order) + 2):
        if not recovery.candidates:
            break
        recovery.tick()
    assert "deployment-execution" in attempts
    assert not recovery.candidates
    assert reopened.group_checkpoint("shop").phase == "recovered"
    assert states == pending.original_running
    assert mutations == [("worker", False), ("worker", True)]


def test_operator_checkpoint_and_history_keep_legacy_json_shape(
    executor, group_registry, group_host, boot_authority
):
    assert mutate(executor, group_registry)["result"]["state"] == "paused"
    paused = executor.group_checkpoint("shop")
    assert mutate(executor, group_registry, "resume", checkpoint=paused)["result"]["state"] == (
        "complete"
    )
    complete = executor.group_checkpoint("shop")
    with executor._db() as db:
        active = json.loads(
            db.execute(
                "SELECT body FROM application_group_intents WHERE application='shop'"
            ).fetchone()[0]
        )
    assert active == complete.model_dump(mode="json", exclude={"operator_managed"})

    assert mutate(executor, group_registry, checkpoint=complete)["result"]["state"] == "paused"
    with executor._db() as db:
        history = json.loads(
            db.execute(
                "SELECT body FROM application_group_history WHERE operation_id=?",
                (complete.operation_id,),
            ).fetchone()[0]
        )
    assert history["checkpoint"] == active
    assert restart(executor).group_history(complete.operation_id).checkpoint == complete


def test_kill_switch_enabled_during_attempt_audit_preserves_pending_without_host_effect(
    executor, group_registry, group_host, boot_authority, monkeypatch
):
    states, mutations = group_host
    original = states.copy()
    append = executor.audit.append

    def enable_after_attempt(event, **fields):
        entry = append(event, **fields)
        if event == "application_group_step" and fields.get("outcome") == "attempt":
            executor.host.killed = True
        return entry

    monkeypatch.setattr(executor.audit, "append", enable_after_attempt)
    assert mutate(executor, group_registry)["error_class"] == "kill_switch"
    pending = executor.group_checkpoint("shop")
    assert pending.phase == "stopping" and pending.pending.service == "worker"
    assert states == original and not mutations


@pytest.mark.parametrize("damage", ["missing", "wrong-application"])
def test_operator_resume_rejects_unbound_checkpoint_marker(
    executor, group_registry, group_host, boot_authority, damage
):
    _, mutations = group_host
    assert mutate(executor, group_registry)["result"]["state"] == "paused"
    paused = executor.group_checkpoint("shop")
    before_damage = list(mutations)
    with executor._db() as db:
        if damage == "missing":
            db.execute(
                "DELETE FROM application_group_operator_intents WHERE operation_id=?",
                (paused.operation_id,),
            )
        else:
            db.execute(
                "UPDATE application_group_operator_intents SET application='other' "
                "WHERE operation_id=?",
                (paused.operation_id,),
            )
    reopened = restart(executor)
    assert status(reopened, group_registry)["error_class"] == "unavailable"
    response = mutate(reopened, group_registry, "resume", checkpoint=paused)
    assert not response["ok"]
    assert mutations == before_damage
