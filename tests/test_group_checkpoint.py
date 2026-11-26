"""Durable group intents never authorize or pretend to perform host work."""

import json
import select
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from steward.core.config import parse_config
from steward.core.group_checkpoint import GroupCheckpoint
from steward.core.render import prepare_application_registry
from steward.executor.protocol import ExecutorError
from steward.executor.server import Executor
from test_application_graph import graph


@pytest.fixture
def group_registry(raw_config, executor):
    app = graph(raw_config)
    app["services"][2]["deploy"] = False
    registry = prepare_application_registry(parse_config(raw_config, allow_unavailable=True))
    Path(executor.registry_path).write_text(json.dumps(registry))
    return registry


def restart(executor):
    return Executor(
        registry_path=executor.registry_path,
        state_dir=str(Path(executor._db_path).parent),
        audit_path=str(executor.audit.path),
        lock_dir=str(executor.lock_dir),
        host=executor.host,
    )


def begin(executor, registry):
    return executor.begin_group_checkpoint(
        "shop",
        "database",
        expected_revision=registry["config_revision"],
        original_running={"database": True, "backend": False, "frontend": False, "worker": True},
    )


def advance(executor, cp, transition, observed_running=None):
    return executor.advance_group_checkpoint(
        "shop", cp.operation_id, cp.generation, transition, observed_running=observed_running
    )


def test_checkpoint_survives_restart_and_preserves_original_intent(executor, group_registry):
    cp = begin(executor, group_registry)
    assert cp.phase == "stopping" and cp.generation == 0
    cp = advance(executor, cp, "prepare")
    assert cp.pending.kind == "stop" and cp.pending.service == "worker"
    recovered = restart(executor)
    assert recovered.group_checkpoint("shop") == cp
    with pytest.raises(ValueError, match="observed group state"):
        advance(recovered, cp, "confirm", observed_running=True)
    assert recovered.group_checkpoint("shop") == cp
    cp = advance(recovered, cp, "confirm", observed_running=False)
    for name in cp.plan.stop_order[1:]:
        cp = advance(recovered, cp, "prepare")
        assert cp.pending.service == name
        cp = advance(recovered, cp, "confirm", observed_running=False)
    cp = advance(recovered, cp, "pause")
    assert cp.phase == "paused"
    cp = advance(recovered, cp, "resume")
    for name in cp.plan.start_order:
        cp = advance(recovered, cp, "prepare")
        assert cp.pending.service == name
        cp = advance(recovered, cp, "confirm", observed_running=cp.original_running[name])
    cp = advance(recovered, cp, "finish")
    assert cp.phase == "complete" and recovered.group_checkpoint("shop") == cp
    assert executor.host.calls == []  # persistence is not an executable action


def test_process_death_leaves_pending_step_for_reconciliation(executor, group_registry):
    code = """import sys,time
from steward.executor.server import Executor
e=Executor(registry_path=sys.argv[1],state_dir=sys.argv[2],audit_path=sys.argv[3],lock_dir=sys.argv[4])
c=e.begin_group_checkpoint('shop','database',expected_revision=sys.argv[5],original_running={'database':True,'backend':False,'frontend':False,'worker':True})
e.advance_group_checkpoint('shop',c.operation_id,c.generation,'prepare')
print('ready',flush=True)
time.sleep(60)
"""
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            code,
            executor.registry_path,
            str(Path(executor._db_path).parent),
            str(executor.audit.path),
            str(executor.lock_dir),
            group_registry["config_revision"],
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert select.select([process.stdout], [], [], 30)[0]
        assert process.stdout.readline().strip() == "ready"
    finally:
        process.kill()
        process.communicate(timeout=10)
    recovered = executor.group_checkpoint("shop")
    assert recovered.generation == 1 and recovered.pending.service == "worker"
    assert advance(executor, recovered, "confirm", observed_running=False).stop_index == 1
    assert executor.host.calls == []


def test_checkpoint_refuses_unsafe_or_out_of_order_transitions(executor, group_registry):
    with pytest.raises(ValueError):
        executor.begin_group_checkpoint(
            "shop",
            "database",
            expected_revision=group_registry["config_revision"],
            original_running={"database": True, "backend": False, "frontend": True, "worker": True},
        )
    assert executor.group_checkpoint("shop") is None
    cp = begin(executor, group_registry)
    with pytest.raises(ExecutorError) as error:
        begin(executor, group_registry)
    assert error.value.error_class == "target_busy"
    for transition in ("pause", "resume", "finish", "confirm"):
        with pytest.raises(ValueError):
            advance(executor, cp, transition)
    assert executor.group_checkpoint("shop") == cp
    forged = cp.model_dump(mode="python")
    forged["pending"] = {"kind": "stop", "service": "database"}
    with pytest.raises(ValueError):
        GroupCheckpoint.model_validate(forged)
    forged = cp.model_dump(mode="python")
    forged["stop_index"] = len(cp.plan.stop_order)
    forged["phase"] = "paused"
    with pytest.raises(ValueError, match="generation"):
        GroupCheckpoint.model_validate(forged)


def test_stale_generation_and_changed_registry_fail_closed(executor, group_registry):
    cp = begin(executor, group_registry)
    next_cp = advance(executor, cp, "prepare")
    with pytest.raises(ExecutorError) as error:
        advance(executor, cp, "prepare")
    assert error.value.error_class == "conflict"
    altered = json.loads(json.dumps(group_registry))
    altered["applications"]["shop"]["services"]["backend"]["unit"] = "ssh.service"
    Path(executor.registry_path).write_text(json.dumps(altered))
    with pytest.raises(ExecutorError) as error:
        advance(executor, next_cp, "confirm", observed_running=False)
    assert error.value.error_class == "policy_denied"
    assert executor.group_checkpoint("shop") == next_cp


def test_concurrent_executor_instances_fence_stale_checkpoint(executor, group_registry):
    cp = begin(executor, group_registry)
    other = restart(executor)
    barrier = threading.Barrier(2)

    def attempt(instance):
        barrier.wait(timeout=5)
        try:
            return advance(instance, cp, "prepare").generation
        except ExecutorError as exc:
            return exc.error_class

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, (executor, other)))
    assert sorted(str(result) for result in results) == ["1", "conflict"]
    current = executor.group_checkpoint("shop")
    assert current.generation == 1 and current.pending.service == "worker"


def test_corrupt_persisted_generation_is_not_recovered_as_success(executor, group_registry):
    begin(executor, group_registry)
    with executor._db() as db:
        db.execute("UPDATE application_group_intents SET generation=1 WHERE application='shop'")
    with pytest.raises(ValueError, match="inconsistent persisted group checkpoint"):
        executor.group_checkpoint("shop")
    assert executor.host.calls == []


def test_deployment_fence_blocks_groups_and_requires_exact_resume(executor, group_registry):
    base = group_registry["config_revision"]
    desired = "b" * 64
    fence = executor.begin_deployment_fence(base_revision=base, desired_revision=desired)
    assert restart(executor).deployment_fence() == fence
    with pytest.raises(ExecutorError) as error:
        begin(executor, group_registry)
    assert error.value.error_class == "target_busy"
    assert (
        executor.begin_deployment_fence(
            base_revision=base, desired_revision=desired, operation_id=fence.operation_id
        )
        == fence
    )
    with pytest.raises(ExecutorError) as error:
        executor.begin_deployment_fence(base_revision=base, desired_revision=desired)
    assert error.value.error_class == "target_busy"
    with pytest.raises(ExecutorError) as error:
        executor.release_deployment_fence("0" * 32)
    assert error.value.error_class == "conflict"
    with pytest.raises(ExecutorError) as error:
        executor.release_deployment_fence(fence.operation_id)
    assert error.value.error_class == "policy_denied"
    assert executor.deployment_fence() == fence
    changed = {**group_registry, "config_revision": desired}
    Path(executor.registry_path).write_text(json.dumps(changed))
    assert (
        executor.begin_deployment_fence(
            base_revision=base, desired_revision=desired, operation_id=fence.operation_id
        )
        == fence
    )
    executor.release_deployment_fence(fence.operation_id)
    assert executor.deployment_fence() is None
    assert executor.host.calls == []


def test_unfinished_group_blocks_deployment_fence(executor, group_registry):
    cp = begin(executor, group_registry)
    with pytest.raises(ExecutorError) as error:
        executor.begin_deployment_fence(
            base_revision=group_registry["config_revision"], desired_revision="b" * 64
        )
    assert error.value.error_class == "target_busy"
    assert executor.group_checkpoint("shop") == cp and executor.deployment_fence() is None


def test_completed_group_does_not_block_deployment_fence(executor, group_registry):
    cp = begin(executor, group_registry)
    for _ in cp.plan.stop_order:
        cp = advance(executor, cp, "prepare")
        cp = advance(executor, cp, "confirm", observed_running=False)
    cp = advance(executor, cp, "pause")
    cp = advance(executor, cp, "resume")
    for name in cp.plan.start_order:
        cp = advance(executor, cp, "prepare")
        cp = advance(executor, cp, "confirm", observed_running=cp.original_running[name])
    cp = advance(executor, cp, "finish")
    fence = executor.begin_deployment_fence(
        base_revision=group_registry["config_revision"], desired_revision="b" * 64
    )
    assert executor.group_checkpoint("shop") == cp and executor.deployment_fence() == fence


def test_corrupt_group_blocks_deployment_fence(executor, group_registry):
    begin(executor, group_registry)
    with executor._db() as db:
        db.execute("UPDATE application_group_intents SET generation=1 WHERE application='shop'")
    with pytest.raises(ExecutorError) as error:
        executor.begin_deployment_fence(
            base_revision=group_registry["config_revision"], desired_revision="b" * 64
        )
    assert error.value.error_class == "target_busy" and executor.deployment_fence() is None


def test_group_and_deployment_admission_are_atomic(executor, group_registry):
    other = restart(executor)
    barrier = threading.Barrier(2)

    def group():
        barrier.wait(timeout=5)
        try:
            begin(executor, group_registry)
            return "group"
        except ExecutorError as exc:
            return exc.error_class

    def deployment():
        barrier.wait(timeout=5)
        try:
            other.begin_deployment_fence(
                base_revision=group_registry["config_revision"], desired_revision="b" * 64
            )
            return "deployment"
        except ExecutorError as exc:
            return exc.error_class

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(group), pool.submit(deployment)]
        results = [future.result(timeout=10) for future in futures]
    assert results.count("target_busy") == 1
    assert (executor.group_checkpoint("shop") is None) != (executor.deployment_fence() is None)


def test_deployment_execution_serializes_exact_resume_and_keeps_fence_on_error(
    executor, group_registry
):
    base, desired, operation_id = group_registry["config_revision"], "b" * 64, "c" * 32
    with (
        pytest.raises(RuntimeError, match="interrupted"),
        executor.deployment_execution(
            base_revision=base, desired_revision=desired, operation_id=operation_id
        ) as fence,
    ):
        with (
            pytest.raises(ExecutorError) as error,
            restart(executor).deployment_execution(
                base_revision=base, desired_revision=desired, operation_id=operation_id
            ),
        ):
            pytest.fail("concurrent execution admitted")
        assert error.value.error_class == "target_busy"
        raise RuntimeError("interrupted")
    assert executor.deployment_fence() == fence
    with restart(executor).deployment_execution(
        base_revision=base, desired_revision=desired, operation_id=operation_id
    ) as resumed:
        assert resumed == fence
    assert executor.deployment_fence() == fence
    assert executor.host.calls == []


def test_killed_deployment_execution_releases_live_lock_but_not_fence(executor, group_registry):
    code = """import sys,time
from steward.executor.server import Executor
e=Executor(registry_path=sys.argv[1],state_dir=sys.argv[2],audit_path=sys.argv[3],lock_dir=sys.argv[4])
with e.deployment_execution(base_revision=sys.argv[5],desired_revision='b'*64,operation_id='c'*32):
 print('ready',flush=True)
 time.sleep(60)
"""
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            code,
            executor.registry_path,
            str(Path(executor._db_path).parent),
            str(executor.audit.path),
            str(executor.lock_dir),
            group_registry["config_revision"],
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert select.select([process.stdout], [], [], 30)[0]
        assert process.stdout.readline().strip() == "ready"
        with (
            pytest.raises(ExecutorError) as error,
            executor.deployment_execution(
                base_revision=group_registry["config_revision"],
                desired_revision="b" * 64,
                operation_id="c" * 32,
            ),
        ):
            pytest.fail("live process was not fenced")
        assert error.value.error_class == "target_busy"
    finally:
        process.kill()
        process.communicate(timeout=10)
    with executor.deployment_execution(
        base_revision=group_registry["config_revision"],
        desired_revision="b" * 64,
        operation_id="c" * 32,
    ) as resumed:
        assert resumed == executor.deployment_fence()
    assert executor.host.calls == []


def test_deployment_execution_refuses_active_or_unknown_rollback(executor, group_registry):
    executor.host.deployment_rollbacks_quiescent = lambda: False
    with (
        pytest.raises(ExecutorError) as error,
        executor.deployment_execution(
            base_revision=group_registry["config_revision"], desired_revision="b" * 64
        ),
    ):
        pytest.fail("deployment admitted while a rollback may be active")
    assert error.value.error_class == "target_busy"
    assert executor.deployment_fence() is None
    executor.host.deployment_rollbacks_quiescent = lambda: True
    with executor.deployment_execution(
        base_revision=group_registry["config_revision"], desired_revision="b" * 64
    ) as fence:
        assert executor.deployment_fence() == fence


def test_observed_group_checkpoint_derives_running_state_and_holds_locks(executor, group_registry):
    services = group_registry["applications"]["shop"]["services"]
    actual = {"database": True, "backend": False, "frontend": False, "worker": True}
    by_container = {spec["container"]: name for name, spec in services.items()}
    calls = []

    def observe(user, unit, container):
        name = by_container[container]
        assert (user, unit) == (services[name]["user"], services[name]["unit"])
        with pytest.raises(ExecutorError), restart(executor).target_lock(services[name]["lock"]):
            pytest.fail("observation ran without its target lock")
        calls.append(name)
        return actual[name]

    executor.host.group_service_running = observe
    with executor.observed_group_execution(
        "shop", "database", expected_revision=group_registry["config_revision"]
    ) as checkpoint:
        assert checkpoint.original_running == actual
        assert set(calls) == set(actual)
        with pytest.raises(ExecutorError), restart(executor).target_lock("deployment-execution"):
            pytest.fail("deployment lock was not held")
        assert executor.group_checkpoint("shop") == checkpoint
    assert executor.host.calls == []


@pytest.mark.parametrize(
    "condition", ["unknown", "disabled_running", "dependency_stopped", "revision_change"]
)
def test_observed_group_rejects_ambiguous_or_changed_state(executor, group_registry, condition):
    services = group_registry["applications"]["shop"]["services"]
    by_container = {spec["container"]: name for name, spec in services.items()}
    actual = {"database": True, "backend": False, "frontend": False, "worker": True}
    if condition == "unknown":
        actual["database"] = None
    elif condition == "disabled_running":
        actual["frontend"] = True
    elif condition == "dependency_stopped":
        actual["database"] = False

    def observe(user, unit, container):
        if condition == "revision_change":
            Path(executor.registry_path).write_text(
                json.dumps({**group_registry, "config_revision": "b" * 64})
            )
        elif condition == "contract_change":
            changed = json.loads(json.dumps(group_registry))
            changed["applications"]["shop"]["services"]["worker"]["depends_on"] = []
            Path(executor.registry_path).write_text(json.dumps(changed))
        return actual[by_container[container]]

    executor.host.group_service_running = observe
    with (
        pytest.raises((ExecutorError, ValueError)),
        executor.observed_group_execution(
            "shop", "database", expected_revision=group_registry["config_revision"]
        ),
    ):
        pytest.fail("unsafe group observation admitted")
    assert executor.group_checkpoint("shop") is None
    with executor.target_lock("deployment-execution"):
        pass
    assert executor.host.calls == []


def test_observed_leaf_requires_running_external_prerequisite(executor, group_registry):
    services = group_registry["applications"]["shop"]["services"]
    by_container = {spec["container"]: name for name, spec in services.items()}
    executor.host.group_service_running = lambda _user, _unit, container: (
        by_container[container] == "worker"
    )
    with (
        pytest.raises(ExecutorError) as error,
        executor.observed_group_execution(
            "shop", "worker", expected_revision=group_registry["config_revision"]
        ),
    ):
        pytest.fail("stopped external prerequisite admitted")
    assert error.value.error_class == "policy_denied" and executor.group_checkpoint("shop") is None


def test_legacy_checkpoint_without_recovery_fields_remains_readable(executor, group_registry):
    checkpoint = begin(executor, group_registry)
    legacy = checkpoint.model_dump(mode="json")
    legacy.pop("recovery_index")
    legacy.pop("recovery_from_pending")
    assert GroupCheckpoint.model_validate(legacy) == checkpoint


def test_recovery_checkpoint_rejects_forged_progress(executor, group_registry):
    checkpoint = begin(executor, group_registry)
    recovering = checkpoint.advance("recover")
    forged = recovering.model_dump(mode="python")
    forged["recovery_index"] = 1
    with pytest.raises(ValueError):
        GroupCheckpoint.model_validate(forged)
    forged = recovering.model_dump(mode="python")
    forged["recovery_from_pending"] = True
    with pytest.raises(ValueError):
        GroupCheckpoint.model_validate(forged)
