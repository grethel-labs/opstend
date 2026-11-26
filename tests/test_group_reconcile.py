"""A group transition is checkpointed, locked and reobserved before confirmation."""

import json
from pathlib import Path

import pytest

from steward.executor.protocol import ExecutorError
from test_group_checkpoint import group_registry as group_registry


@pytest.fixture
def group_host(executor, group_registry):
    services = group_registry["applications"]["shop"]["services"]
    by_container = {spec["container"]: name for name, spec in services.items()}
    by_unit = {spec["unit"]: name for name, spec in services.items()}
    states = {"database": True, "backend": False, "frontend": False, "worker": True}
    mutations = []

    def observe(_user, _unit, container):
        return states[by_container[container]]

    def quiescent(_user, _unit, container):
        return states[by_container[container]] is False

    def change(_user, unit, *, running):
        name = by_unit[unit]
        mutations.append((name, running))
        states[name] = running
        return True

    executor.host.group_service_running = observe
    executor.host.group_service_quiescent = quiescent
    executor.host.set_user_unit = change
    return states, mutations


def step(executor, checkpoint):
    return executor.reconcile_group_step("shop", checkpoint.operation_id, checkpoint.generation)


def begin(executor, group_registry, target="database"):
    with executor.observed_group_execution(
        "shop", target, expected_revision=group_registry["config_revision"]
    ) as checkpoint:
        return checkpoint


def test_group_stop_and_resume_preserve_original_states(executor, group_registry, group_host):
    states, mutations = group_host
    checkpoint = begin(executor, group_registry)
    for _ in range(4):
        checkpoint = step(executor, checkpoint)
    checkpoint = step(executor, checkpoint)
    assert checkpoint.phase == "paused" and not any(states.values())
    checkpoint = executor.advance_group_checkpoint(
        "shop", checkpoint.operation_id, checkpoint.generation, "resume"
    )
    for _ in range(4):
        checkpoint = step(executor, checkpoint)
    checkpoint = step(executor, checkpoint)
    assert checkpoint.phase == "complete"
    assert states == checkpoint.original_running
    assert mutations == [
        ("worker", False),
        ("database", False),
        ("database", True),
        ("worker", True),
    ]
    assert executor.audit.verify()[0]


def test_interrupted_command_is_reconciled_without_repeating_it(
    executor, group_registry, group_host
):
    states, mutations = group_host
    checkpoint = begin(executor, group_registry)
    original = executor.host.set_user_unit

    def ambiguous(user, unit, *, running):
        original(user, unit, running=running)
        return False

    executor.host.set_user_unit = ambiguous
    with pytest.raises(ExecutorError) as error:
        step(executor, checkpoint)
    assert error.value.error_class == "execution_failed"
    pending = executor.group_checkpoint("shop")
    assert pending.pending.service == "worker" and states["worker"] is False
    executor.host.set_user_unit = original
    recovered = step(executor, pending)
    assert recovered.pending is None and recovered.stop_index == 1
    assert mutations == [("worker", False)]


def test_kill_switch_and_state_drift_leave_checkpoint_recoverable(
    executor, group_registry, group_host
):
    states, mutations = group_host
    checkpoint = begin(executor, group_registry)
    states["backend"] = True
    with pytest.raises(ExecutorError) as error:
        step(executor, checkpoint)
    assert error.value.error_class == "conflict" and executor.group_checkpoint("shop") == checkpoint
    states["backend"] = False
    executor.host.killed = True
    with pytest.raises(ExecutorError) as error:
        step(executor, checkpoint)
    assert error.value.error_class == "kill_switch" and not mutations
    pending = executor.group_checkpoint("shop")
    assert pending.pending.service == "worker"
    executor.host.killed = False
    assert step(executor, pending).stop_index == 1


def test_resume_refuses_stopped_external_dependency(executor, group_registry, group_host):
    states, mutations = group_host
    checkpoint = begin(executor, group_registry, "worker")
    checkpoint = step(executor, checkpoint)
    checkpoint = step(executor, checkpoint)
    checkpoint = executor.advance_group_checkpoint(
        "shop", checkpoint.operation_id, checkpoint.generation, "resume"
    )
    states["database"] = False
    with pytest.raises(ExecutorError) as error:
        step(executor, checkpoint)
    assert error.value.error_class == "policy_denied"
    assert executor.group_checkpoint("shop").pending.service == "worker"
    assert mutations == [("worker", False)]


def test_nonquiescent_service_and_competing_lock_block_mutation(
    executor, group_registry, group_host
):
    states, mutations = group_host
    checkpoint = begin(executor, group_registry)
    executor.host.group_service_quiescent = lambda *_: False
    with pytest.raises(ExecutorError) as error:
        step(executor, checkpoint)
    assert error.value.error_class == "unavailable" and not mutations
    executor.host.group_service_quiescent = lambda _user, _unit, container: (
        states[
            next(
                name
                for name, spec in group_registry["applications"]["shop"]["services"].items()
                if spec["container"] == container
            )
        ]
        is False
    )
    with (
        executor.target_lock(checkpoint.plan.lock_targets[0]),
        pytest.raises(ExecutorError) as error,
    ):
        step(executor, checkpoint)
    assert error.value.error_class == "target_busy" and not mutations


def test_failed_confirmation_audit_leaves_pending_without_repeating_host_action(
    executor, group_registry, group_host, monkeypatch
):
    states, mutations = group_host
    checkpoint = begin(executor, group_registry)
    append = executor.audit.append

    def audit(event, **fields):
        if fields.get("outcome") == "confirmed":
            raise OSError("audit unavailable")
        return append(event, **fields)

    monkeypatch.setattr(executor.audit, "append", audit)
    with pytest.raises(OSError):
        step(executor, checkpoint)
    pending = executor.group_checkpoint("shop")
    assert pending.pending.service == "worker" and states["worker"] is False
    monkeypatch.setattr(executor.audit, "append", append)
    assert step(executor, pending).stop_index == 1
    assert mutations == [("worker", False)]


def test_budget_exhaustion_persists_pending_without_host_mutation(
    executor, group_registry, group_host, monkeypatch
):
    states, mutations = group_host
    checkpoint = begin(executor, group_registry)

    def deny(*args):
        raise ExecutorError("budget_exhausted", "test budget")

    monkeypatch.setattr(executor, "spend_budget", deny)
    with pytest.raises(ExecutorError) as error:
        step(executor, checkpoint)
    assert error.value.error_class == "budget_exhausted" and not mutations
    assert executor.group_checkpoint("shop").pending.service == "worker"


def test_previously_stopped_dependent_cannot_restart_during_group_transition(
    executor, group_registry, group_host
):
    states, mutations = group_host
    checkpoint = begin(executor, group_registry)
    checkpoint = step(executor, checkpoint)
    states["worker"] = True
    with pytest.raises(ExecutorError) as error:
        step(executor, checkpoint)
    assert error.value.error_class == "conflict"
    assert executor.group_checkpoint("shop") == checkpoint
    assert mutations == [("worker", False)]


def test_disabled_external_dependency_cannot_run_during_reconciliation(
    executor, group_registry, group_host
):
    states, mutations = group_host
    group_registry["applications"]["shop"]["services"]["database"]["deploy"] = False
    Path(executor.registry_path).write_text(json.dumps(group_registry))
    states["database"] = False
    states["worker"] = False
    checkpoint = begin(executor, group_registry, "worker")
    states["database"] = True
    with pytest.raises(ExecutorError) as error:
        step(executor, checkpoint)
    assert error.value.error_class == "policy_denied" and not mutations
    assert executor.group_checkpoint("shop") == checkpoint


def recover(executor, checkpoint):
    return executor.begin_group_recovery("shop", checkpoint.operation_id, checkpoint.generation)


def test_partial_stop_restores_original_state_in_dependency_order(
    executor, group_registry, group_host
):
    states, mutations = group_host
    checkpoint = begin(executor, group_registry)
    for _ in range(3):
        checkpoint = step(executor, checkpoint)
    assert checkpoint.stop_index == 3 and not states["worker"] and states["database"]
    checkpoint = recover(executor, checkpoint)
    assert checkpoint.phase == "recovering"
    for _ in range(3):
        checkpoint = step(executor, checkpoint)
    checkpoint = step(executor, checkpoint)
    assert checkpoint.phase == "recovered" and states == checkpoint.original_running
    assert mutations == [("worker", False), ("worker", True)]
    fence = executor.begin_deployment_fence(
        base_revision=group_registry["config_revision"], desired_revision="b" * 64
    )
    assert fence and executor.group_checkpoint("shop") == checkpoint


def test_recovery_can_cancel_pending_stop_that_never_happened(executor, group_registry, group_host):
    states, mutations = group_host
    checkpoint = begin(executor, group_registry)
    executor.host.set_user_unit = lambda *_args, **_kwargs: False
    with pytest.raises(ExecutorError):
        step(executor, checkpoint)
    pending = executor.group_checkpoint("shop")
    assert pending.pending.service == "worker" and states["worker"]
    checkpoint = recover(executor, pending)
    assert checkpoint.phase == "recovering" and checkpoint.recovery_from_pending
    checkpoint = step(executor, checkpoint)
    assert checkpoint.phase == "recovered" and not mutations


def test_recovery_confirms_pending_stop_without_repeating_it(executor, group_registry, group_host):
    states, mutations = group_host
    checkpoint = begin(executor, group_registry)
    change = executor.host.set_user_unit

    def ambiguous(user, unit, *, running):
        change(user, unit, running=running)
        return False

    executor.host.set_user_unit = ambiguous
    with pytest.raises(ExecutorError):
        step(executor, checkpoint)
    pending = executor.group_checkpoint("shop")
    checkpoint = recover(executor, pending)
    assert checkpoint.phase == "recovering" and checkpoint.stop_index == 1
    assert mutations == [("worker", False)]
    executor.host.set_user_unit = change
    checkpoint = step(executor, checkpoint)
    checkpoint = step(executor, checkpoint)
    assert checkpoint.phase == "recovered" and states == checkpoint.original_running
    assert mutations == [("worker", False), ("worker", True)]


def test_interrupted_recovery_start_does_not_repeat_host_command(
    executor, group_registry, group_host
):
    states, mutations = group_host
    checkpoint = step(executor, begin(executor, group_registry))
    checkpoint = recover(executor, checkpoint)
    change = executor.host.set_user_unit

    def ambiguous(user, unit, *, running):
        change(user, unit, running=running)
        return False

    executor.host.set_user_unit = ambiguous
    with pytest.raises(ExecutorError):
        step(executor, checkpoint)
    pending = executor.group_checkpoint("shop")
    assert pending.pending.service == "worker" and states["worker"]
    executor.host.set_user_unit = change
    checkpoint = step(executor, pending)
    checkpoint = step(executor, checkpoint)
    assert checkpoint.phase == "recovered" and states == checkpoint.original_running
    assert mutations == [("worker", False), ("worker", True)]


def test_recovery_honors_kill_switch_and_preserves_pending(executor, group_registry, group_host):
    states, mutations = group_host
    checkpoint = recover(executor, step(executor, begin(executor, group_registry)))
    executor.host.killed = True
    with pytest.raises(ExecutorError) as error:
        step(executor, checkpoint)
    assert error.value.error_class == "kill_switch" and not states["worker"]
    pending = executor.group_checkpoint("shop")
    assert pending.phase == "recovering" and pending.pending.service == "worker"
    executor.host.killed = False
    checkpoint = step(executor, pending)
    checkpoint = step(executor, checkpoint)
    assert checkpoint.phase == "recovered" and states["worker"]


def test_recovery_cannot_complete_after_external_dependency_stops(
    executor, group_registry, group_host
):
    states, mutations = group_host
    checkpoint = step(executor, begin(executor, group_registry, "worker"))
    checkpoint = recover(executor, checkpoint)
    checkpoint = step(executor, checkpoint)
    assert states["worker"]
    states["database"] = False
    with pytest.raises(ExecutorError) as error:
        step(executor, checkpoint)
    assert error.value.error_class == "policy_denied"
    assert executor.group_checkpoint("shop") == checkpoint


def test_recovery_audit_failure_after_confirm_keeps_safe_retry_state(
    executor, group_registry, group_host, monkeypatch
):
    states, mutations = group_host
    checkpoint = begin(executor, group_registry)
    change = executor.host.set_user_unit

    def ambiguous(user, unit, *, running):
        change(user, unit, running=running)
        return False

    executor.host.set_user_unit = ambiguous
    with pytest.raises(ExecutorError):
        step(executor, checkpoint)
    pending = executor.group_checkpoint("shop")
    append = executor.audit.append

    def fail_recovery_phase(event, **fields):
        if event == "application_group_phase" and fields.get("phase") == "recover":
            raise OSError("audit unavailable")
        return append(event, **fields)

    monkeypatch.setattr(executor.audit, "append", fail_recovery_phase)
    with pytest.raises(OSError):
        recover(executor, pending)
    confirmed = executor.group_checkpoint("shop")
    assert confirmed.phase == "stopping" and confirmed.stop_index == 1 and confirmed.pending is None
    assert mutations == [("worker", False)] and not states["worker"]
    monkeypatch.setattr(executor.audit, "append", append)
    executor.host.set_user_unit = change
    checkpoint = recover(executor, confirmed)
    checkpoint = step(executor, checkpoint)
    checkpoint = step(executor, checkpoint)
    assert checkpoint.phase == "recovered" and states == checkpoint.original_running
    assert mutations == [("worker", False), ("worker", True)]


def test_automatic_group_stop_success_reaches_paused(executor, group_registry, group_host):
    states, mutations = group_host
    checkpoint = begin(executor, group_registry)
    outcome = executor.stop_group_with_recovery(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    assert outcome["state"] == "paused" and outcome["error_class"] is None
    assert not any(states.values()) and outcome["checkpoint"].phase == "paused"
    assert mutations == [("worker", False), ("database", False)]


def test_automatic_group_stop_recovers_partial_failure(executor, group_registry, group_host):
    states, mutations = group_host
    checkpoint = begin(executor, group_registry)
    change = executor.host.set_user_unit
    database = group_registry["applications"]["shop"]["services"]["database"]["unit"]

    def fail_database(user, unit, *, running):
        if unit == database and not running:
            return False
        return change(user, unit, running=running)

    executor.host.set_user_unit = fail_database
    outcome = executor.stop_group_with_recovery(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    assert outcome["state"] == "recovered" and outcome["error_class"] == "execution_failed"
    assert states == outcome["checkpoint"].original_running
    assert mutations == [("worker", False), ("worker", True)]
    assert executor.audit.verify()[0]


def test_automatic_recovery_reconciles_stop_that_completed_before_error(
    executor, group_registry, group_host
):
    states, mutations = group_host
    checkpoint = begin(executor, group_registry)
    change = executor.host.set_user_unit
    calls = [0]

    def ambiguous(user, unit, *, running):
        result = change(user, unit, running=running)
        calls[0] += 1
        return False if calls[0] == 1 else result

    executor.host.set_user_unit = ambiguous
    outcome = executor.stop_group_with_recovery(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    assert outcome["state"] == "recovered" and states == outcome["checkpoint"].original_running
    assert mutations == [("worker", False), ("worker", True)]


def test_automatic_recovery_preserves_pending_if_state_becomes_unknown(
    executor, group_registry, group_host
):
    states, mutations = group_host
    checkpoint = begin(executor, group_registry)
    observe = executor.host.group_service_running
    change = executor.host.set_user_unit
    uncertain = [False]

    def ambiguous(user, unit, *, running):
        result = change(user, unit, running=running)
        uncertain[0] = True
        return False if result else result

    executor.host.set_user_unit = ambiguous
    executor.host.group_service_running = lambda *args: None if uncertain[0] else observe(*args)
    outcome = executor.stop_group_with_recovery(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    assert (
        outcome["state"] == "recovery_pending" and outcome["recovery_error_class"] == "unavailable"
    )
    assert outcome["checkpoint"].pending.service == "worker" and not states["worker"]
    assert mutations == [("worker", False)]


def test_automatic_coordinator_does_not_override_kill_switch_or_competing_lock(
    executor, group_registry, group_host
):
    states, mutations = group_host
    checkpoint = begin(executor, group_registry)
    executor.host.killed = True
    with pytest.raises(ExecutorError) as error:
        executor.stop_group_with_recovery("shop", checkpoint.operation_id, checkpoint.generation)
    assert error.value.error_class == "kill_switch" and not mutations
    pending = executor.group_checkpoint("shop")
    executor.host.killed = False
    with executor.target_lock(pending.plan.lock_targets[0]), pytest.raises(ExecutorError) as error:
        executor.stop_group_with_recovery("shop", pending.operation_id, pending.generation)
    assert error.value.error_class == "target_busy" and not mutations


def test_transition_waits_briefly_for_observation_without_repeating_host_command(
    executor, group_registry, group_host, monkeypatch
):
    states, mutations = group_host
    checkpoint = begin(executor, group_registry)
    observe = executor.host.group_service_running
    after_mutation = [False]
    delayed_reads = [0]
    change = executor.host.set_user_unit

    def change_and_delay(user, unit, *, running):
        result = change(user, unit, running=running)
        after_mutation[0] = True
        return result

    def delayed(user, unit, container):
        if after_mutation[0] and delayed_reads[0] < 2:
            delayed_reads[0] += 1
            return None
        return observe(user, unit, container)

    monkeypatch.setattr("steward.executor.server.time.sleep", lambda _delay: None)
    executor.host.set_user_unit = change_and_delay
    executor.host.group_service_running = delayed
    checkpoint = step(executor, checkpoint)
    assert checkpoint.stop_index == 1 and delayed_reads[0] == 2
    assert mutations == [("worker", False)] and not states["worker"]


def test_automatic_recovery_reports_os_error_and_keeps_pending(
    executor, group_registry, group_host
):
    states, mutations = group_host
    checkpoint = begin(executor, group_registry)
    change = executor.host.set_user_unit
    database = group_registry["applications"]["shop"]["services"]["database"]["unit"]
    worker = group_registry["applications"]["shop"]["services"]["worker"]["unit"]

    def fail_stop_and_recovery(user, unit, *, running):
        if unit == database and not running:
            return False
        if unit == worker and running:
            raise OSError("temporary failure")
        return change(user, unit, running=running)

    executor.host.set_user_unit = fail_stop_and_recovery
    outcome = executor.stop_group_with_recovery(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    assert outcome["state"] == "recovery_pending" and outcome["error_class"] == "execution_failed"
    assert outcome["recovery_error_class"] == "internal"
    assert outcome["checkpoint"].pending.service == "worker" and not states["worker"]
    assert mutations == [("worker", False)]


def test_automatic_failure_handler_refuses_other_checkpoint_progress(
    executor, group_registry, group_host, monkeypatch
):
    states, mutations = group_host
    checkpoint = begin(executor, group_registry)

    def other_worker(application, operation_id, generation):
        prepared = executor.advance_group_checkpoint(
            application, operation_id, generation, "prepare"
        )
        states["worker"] = False
        executor.advance_group_checkpoint(
            application, operation_id, prepared.generation, "confirm", observed_running=False
        )
        raise ExecutorError("execution_failed", "simulated competing progress")

    monkeypatch.setattr(executor, "reconcile_group_step", other_worker)
    with pytest.raises(ExecutorError) as error:
        executor.stop_group_with_recovery("shop", checkpoint.operation_id, checkpoint.generation)
    assert error.value.error_class == "conflict" and not mutations
    current = executor.group_checkpoint("shop")
    assert current.phase == "stopping" and current.stop_index == 1


def test_startup_recovery_restores_interrupted_stop_and_preserves_paused(
    executor, group_registry, group_host
):
    from steward.executor.server import GroupStartupRecovery

    states, mutations = group_host
    checkpoint = begin(executor, group_registry)
    checkpoint = step(executor, checkpoint)
    assert checkpoint.stop_index == 1 and not states["worker"]
    recovery = GroupStartupRecovery(executor)
    while recovery.candidates:
        recovery.tick()
    assert executor.group_checkpoint("shop").phase == "recovered"
    assert states == checkpoint.original_running
    assert mutations == [("worker", False), ("worker", True)]


def test_startup_recovery_preserves_paused(executor, group_registry, group_host):
    from steward.executor.server import GroupStartupRecovery

    _, mutations = group_host
    checkpoint = begin(executor, group_registry)
    for _ in range(5):
        checkpoint = step(executor, checkpoint)
    assert checkpoint.phase == "paused"
    before = list(mutations)
    recovery = GroupStartupRecovery(executor)
    recovery.tick()
    assert not recovery.candidates
    assert executor.group_checkpoint("shop") == checkpoint
    assert mutations == before
    checkpoint = executor.advance_group_checkpoint(
        "shop", checkpoint.operation_id, checkpoint.generation, "resume"
    )
    recovery.tick()
    assert executor.group_checkpoint("shop") == checkpoint
    assert mutations == before


def test_startup_recovery_retries_busy_driver_and_ignores_new_intents(
    executor, group_registry, group_host
):
    from steward.executor.server import GroupStartupRecovery

    empty_recovery = GroupStartupRecovery(executor)
    checkpoint = begin(executor, group_registry)
    empty_recovery.tick()
    assert executor.group_checkpoint("shop") == checkpoint
    recovery = GroupStartupRecovery(executor)
    with executor.group_driver_lock(checkpoint):
        recovery.tick()
    assert recovery.candidates and executor.group_checkpoint("shop") == checkpoint
    recovery.tick()
    assert executor.group_checkpoint("shop").phase == "recovered"


def test_startup_recovery_keeps_kill_switch_and_intent(executor, group_registry, group_host):
    from steward.executor.server import GroupStartupRecovery

    states, mutations = group_host
    checkpoint = step(executor, begin(executor, group_registry))
    executor.host.killed = True
    recovery = GroupStartupRecovery(executor)
    recovery.tick()
    assert recovery.candidates
    assert executor.group_checkpoint("shop").phase == "recovering"
    assert not states["worker"] and mutations == [("worker", False)]
    executor.host.killed = False
    while recovery.candidates:
        recovery.tick()
    assert states == checkpoint.original_running


def test_restart_fenced_by_group_and_external_dependency(executor, group_registry, group_host):
    from steward.executor.server import RestartParams, workload_restart

    specs = group_registry["applications"]["shop"]["services"]
    group_registry["projects"] = {
        name: {**specs[name], "deploy": True, "allow_restart": True}
        for name in ("worker", "database", "backend")
    }
    Path(executor.registry_path).write_text(json.dumps(group_registry))
    checkpoint = begin(executor, group_registry, target="worker")
    for name in ("worker", "database"):
        with pytest.raises(ExecutorError) as error:
            workload_restart(
                executor,
                RestartParams(project_id=name, reason="health"),
                "controller",
                group_registry,
            )
        assert error.value.error_class == "unavailable"
    workload_restart(
        executor, RestartParams(project_id="backend", reason="health"), "controller", group_registry
    )
    assert [call[2] for call in executor.host.calls if call[0] == "restart"] == [
        specs["backend"]["unit"]
    ]
    checkpoint = executor.begin_group_recovery(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    checkpoint = step(executor, checkpoint)
    assert checkpoint.phase == "recovered"
    workload_restart(
        executor, RestartParams(project_id="worker", reason="health"), "controller", group_registry
    )


def test_restart_rejects_changed_or_corrupt_group_contract(executor, group_registry, group_host):
    from steward.executor.server import RestartParams, workload_restart

    service = group_registry["applications"]["shop"]["services"]["worker"]
    group_registry["projects"] = {"worker": {**service, "deploy": True, "allow_restart": True}}
    Path(executor.registry_path).write_text(json.dumps(group_registry))
    begin(executor, group_registry, target="worker")
    group_registry["config_revision"] = "f" * 64
    Path(executor.registry_path).write_text(json.dumps(group_registry))
    with pytest.raises(ExecutorError) as error:
        workload_restart(
            executor,
            RestartParams(project_id="worker", reason="health"),
            "operator",
            group_registry,
        )
    assert error.value.error_class == "unavailable" and not executor.host.calls
    with executor._db() as db:
        db.execute("UPDATE application_group_intents SET body='{}'")
    with pytest.raises(ExecutorError) as error:
        workload_restart(
            executor,
            RestartParams(project_id="worker", reason="health"),
            "operator",
            group_registry,
        )
    assert error.value.error_class == "unavailable" and not executor.host.calls


def test_restart_and_group_admission_are_serialized(executor, group_registry, group_host):
    import threading

    from steward.executor.server import RestartParams, workload_restart

    service = group_registry["applications"]["shop"]["services"]["worker"]
    group_registry["projects"] = {"worker": {**service, "deploy": True, "allow_restart": True}}
    Path(executor.registry_path).write_text(json.dumps(group_registry))
    entered, release = threading.Event(), threading.Event()
    original = executor.host.restart_user_unit

    def slow(user, unit):
        entered.set()
        assert release.wait(10)
        return original(user, unit)

    executor.host.restart_user_unit = slow
    errors = []

    def restart():
        try:
            workload_restart(
                executor,
                RestartParams(project_id="worker", reason="health"),
                "controller",
                group_registry,
            )
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=restart)
    thread.start()
    try:
        assert entered.wait(5)
        with pytest.raises(ExecutorError) as error:
            begin(executor, group_registry, target="worker")
        assert error.value.error_class == "target_busy"
    finally:
        release.set()
        thread.join(10)
    assert not errors and not thread.is_alive()
    assert begin(executor, group_registry, target="worker").phase == "stopping"


def test_restart_is_fenced_for_fully_paused_group(executor, group_registry, group_host):
    from steward.executor.server import RestartParams, workload_restart

    service = group_registry["applications"]["shop"]["services"]["worker"]
    group_registry["projects"] = {"worker": {**service, "deploy": True, "allow_restart": True}}
    Path(executor.registry_path).write_text(json.dumps(group_registry))
    checkpoint = begin(executor, group_registry, target="worker")
    checkpoint = step(executor, step(executor, checkpoint))
    assert checkpoint.phase == "paused"
    for role in ("controller", "operator"):
        with pytest.raises(ExecutorError) as error:
            workload_restart(
                executor, RestartParams(project_id="worker", reason="health"), role, group_registry
            )
        assert error.value.error_class == "unavailable"
    assert executor.group_checkpoint("shop") == checkpoint
    assert not executor.host.calls


def backup_pause_for_group(executor, group_registry, name="worker"):
    import time

    from steward.core.backups import Binding
    from steward.executor.server import BackupPause

    service = group_registry["applications"]["shop"]["services"][name]
    group_registry.setdefault("projects", {})["alias"] = {
        **service,
        "deploy": True,
        "allow_backup_pause": True,
    }
    group_registry["server_name"] = "test-server"
    Path(executor.registry_path).write_text(json.dumps(group_registry))
    pause = BackupPause(
        binding=Binding(
            server="test-server",
            project="alias",
            config_revision=group_registry["config_revision"],
            image=service["image"],
            source_revision=service["source_revision"],
        ),
        user=service["user"],
        unit=service["unit"],
        artifact="a" * 32,
        prepared_at=time.time(),
    )
    return pause


def test_group_waits_for_existing_backup_project_lock_and_pause(
    executor, group_registry, group_host
):
    pause = backup_pause_for_group(executor, group_registry)
    with executor.target_lock("project-alias"):
        with pytest.raises(ExecutorError) as error:
            begin(executor, group_registry, target="worker")
        assert error.value.error_class == "target_busy"
    executor.save_backup_pause(pause)
    with pytest.raises(ExecutorError) as error:
        begin(executor, group_registry, target="worker")
    assert error.value.error_class == "unavailable"
    executor.clear_backup_pause("alias")
    assert begin(executor, group_registry, target="worker").phase == "stopping"


def test_group_steps_and_backup_recovery_refuse_conflicting_durable_intents(
    executor, group_registry, group_host
):
    pause = backup_pause_for_group(executor, group_registry)
    checkpoint = begin(executor, group_registry, target="worker")
    executor.save_backup_pause(pause)
    with pytest.raises(ExecutorError) as error:
        step(executor, checkpoint)
    assert error.value.error_class == "unavailable"
    with pytest.raises(ExecutorError) as error:
        executor.recover_backup_pause("alias", group_registry, automatic=True)
    assert error.value.error_class == "unavailable"
    assert executor.group_checkpoint("shop") == checkpoint
    assert executor.backup_pause("alias") == pause
    assert not executor.host.calls


def test_backup_admission_fences_group_without_holding_global_lock(
    executor, group_registry, group_host
):
    backup_pause_for_group(executor, group_registry)
    with executor.backup_mutation_lock("alias", group_registry):
        with executor.target_lock("deployment-execution"):
            pass
        with pytest.raises(ExecutorError) as error:
            begin(executor, group_registry, target="worker")
        assert error.value.error_class == "target_busy"
    begin(executor, group_registry, target="worker")
    with (
        pytest.raises(ExecutorError) as error,
        executor.backup_mutation_lock("alias", group_registry),
    ):
        pytest.fail("backup must not start over a group checkpoint")
    assert error.value.error_class == "unavailable"


def test_corrupt_backup_pause_blocks_group_admission(executor, group_registry, group_host):
    backup_pause_for_group(executor, group_registry)
    with executor._db() as db:
        db.execute("INSERT INTO backup_pauses VALUES ('alias', '{}')")
    with pytest.raises(ExecutorError) as error:
        begin(executor, group_registry, target="worker")
    assert error.value.error_class == "unavailable"
    assert executor.group_checkpoint("shop") is None


def test_real_capture_excludes_group_until_data_and_resume_finish(
    executor, group_registry, group_host, tmp_path, monkeypatch
):
    import threading

    from steward.core import filebackups
    from steward.core.backups import load_capture
    from steward.core.filebackups import materialize_tree
    from steward.executor import server

    states, mutations = group_host
    service = group_registry["applications"]["shop"]["services"]["worker"]
    group_registry["projects"] = {
        "alias": {**service, "deploy": True, "has_data": True, "allow_backup_pause": True}
    }
    group_registry["server_name"] = "test-server"
    Path(executor.registry_path).write_text(json.dumps(group_registry))
    data = tmp_path / "data-root" / "alias" / "data"
    data.mkdir(parents=True)
    (data / "message.txt").write_text("recoverable application data")
    monkeypatch.setattr(server, "PROJECT_DATA_ROOT", tmp_path / "data-root")
    original_change = executor.host.set_user_unit

    def change(user, unit, *, running):
        result = original_change(user, unit, running=running)
        executor.host.units[unit] = "active" if running else "inactive"
        return result

    executor.host.units[service["unit"]] = "active"
    executor.host.set_user_unit = change
    executor.host.workload_quiescent = lambda _user, _unit: not states["worker"]
    copying, release = threading.Event(), threading.Event()
    read = filebackups.TimedReader.read

    def paused_read(reader, size):
        chunk = read(reader, size)
        copying.set()
        assert release.wait(10)
        return chunk

    monkeypatch.setattr(filebackups.TimedReader, "read", paused_read)
    results, errors = [], []

    def run_capture():
        try:
            results.append(
                server.backup_capture(
                    executor,
                    server.BackupCaptureParams(project_id="alias"),
                    "operator",
                    group_registry,
                )
            )
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=run_capture)
    worker.start()
    try:
        assert copying.wait(10) and states["worker"] is False
        with pytest.raises(ExecutorError) as error:
            begin(executor, group_registry, target="worker")
        assert error.value.error_class == "target_busy"
        assert executor.group_checkpoint("shop") is None
    finally:
        release.set()
        worker.join(30)
    assert not worker.is_alive() and not errors and len(results) == 1
    assert states["worker"] is True and mutations == [("worker", False), ("worker", True)]
    artifact = Path(executor._db_path).parent / "captures" / "alias" / results[0]["artifact"]
    manifest = load_capture(artifact)
    assert manifest.id == results[0]["capture_id"]
    workspace = tmp_path / "restored"
    workspace.mkdir(mode=0o700)
    restored = materialize_tree(artifact / "data.tar", manifest, workspace)
    assert (restored / "message.txt").read_text() == "recoverable application data"
    assert executor.backup_pause("alias") is None
    assert begin(executor, group_registry, target="worker").phase == "stopping"


def test_application_scope_stops_independent_writers_and_restores_original_intent(
    executor, group_registry, group_host
):
    states, mutations = group_host
    with executor.observed_group_execution(
        "shop", "frontend", expected_revision=group_registry["config_revision"], scope="application"
    ) as checkpoint:
        assert checkpoint.plan.scope == "application"
        assert checkpoint.plan.start_order == ["database", "backend", "frontend", "worker"]
    for _ in range(5):
        checkpoint = step(executor, checkpoint)
    assert checkpoint.phase == "paused" and not any(states.values())
    checkpoint = executor.advance_group_checkpoint(
        "shop", checkpoint.operation_id, checkpoint.generation, "resume"
    )
    for _ in range(5):
        checkpoint = step(executor, checkpoint)
    assert checkpoint.phase == "complete" and states == checkpoint.original_running
    assert mutations == [
        ("worker", False),
        ("database", False),
        ("database", True),
        ("worker", True),
    ]


def test_old_checkpoint_without_scope_remains_recoverable(executor, group_registry, group_host):
    checkpoint = begin(executor, group_registry, target="worker")
    body = json.loads(checkpoint.model_dump_json())
    body["plan"].pop("scope")
    with executor._db() as db:
        db.execute(
            "UPDATE application_group_intents SET body=? WHERE application=?",
            (json.dumps(body), "shop"),
        )
    recovered = executor.group_checkpoint("shop")
    assert recovered == checkpoint and recovered.plan.scope == "dependents"
    assert step(executor, recovered).stop_index == 1


def test_startup_recovery_preserves_full_application_scope(executor, group_registry, group_host):
    from steward.executor.server import GroupStartupRecovery

    states, mutations = group_host
    with executor.observed_group_execution(
        "shop", "frontend", expected_revision=group_registry["config_revision"], scope="application"
    ) as checkpoint:
        pass
    checkpoint = step(executor, checkpoint)
    assert not states["worker"] and checkpoint.plan.scope == "application"
    recovery = GroupStartupRecovery(executor)
    while recovery.candidates:
        recovery.tick()
    restored = executor.group_checkpoint("shop")
    assert restored.phase == "recovered" and restored.plan.scope == "application"
    assert states == checkpoint.original_running
    assert mutations == [("worker", False), ("worker", True)]


def test_application_scope_fences_independent_service_restart(executor, group_registry, group_host):
    from steward.executor.server import RestartParams, workload_restart

    worker = group_registry["applications"]["shop"]["services"]["worker"]
    group_registry["projects"] = {"worker": {**worker, "deploy": True, "allow_restart": True}}
    Path(executor.registry_path).write_text(json.dumps(group_registry))
    with executor.observed_group_execution(
        "shop", "frontend", expected_revision=group_registry["config_revision"], scope="application"
    ):
        pass
    with pytest.raises(ExecutorError) as error:
        workload_restart(
            executor,
            RestartParams(project_id="worker", reason="health"),
            "controller",
            group_registry,
        )
    assert error.value.error_class == "unavailable" and not executor.host.calls
