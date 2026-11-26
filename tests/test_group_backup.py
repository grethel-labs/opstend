"""A local group capture is complete only with every paused data tree."""

import json
from pathlib import Path

import pytest

from steward.core.filebackups import materialize_tree
from steward.core.group_backups import GroupCapture
from steward.executor import server
from steward.executor.protocol import ExecutorError
from test_group_checkpoint import group_registry as group_registry
from test_group_reconcile import group_host as group_host


@pytest.fixture
def paused_application(executor, group_registry, group_host, tmp_path, monkeypatch):
    states, _ = group_host
    Path(executor._db_path).parent.chmod(0o700)
    root = tmp_path / "applications"
    monkeypatch.setattr(server, "APPLICATION_DATA_ROOT", root)
    group_registry["server_name"] = "test-server"
    group_registry["backup"] = {"max_mib": 1}
    specs = group_registry["applications"]["shop"]["services"]
    for name, spec in specs.items():
        if name in ("database", "worker"):
            path = root / "shop" / "data" / name
            path.mkdir(parents=True)
            (path / "value.txt").write_text("original " + name)
            path.chmod(0o700)
            (path / "value.txt").chmod(0o600)
            spec.update(data_source=str(path), data_target="/data", allow_backup_pause=True)
        else:
            spec.update(data_source=None, data_target=None)
    for directory in (root, root / "shop", root / "shop" / "data"):
        directory.chmod(0o700)
    Path(executor.registry_path).write_text(json.dumps(group_registry))
    by_unit = {spec["unit"]: name for name, spec in specs.items()}
    executor.host.workload_quiescent = lambda _user, unit: states[by_unit[unit]] is False
    with executor.observed_group_execution(
        "shop", "frontend", expected_revision=group_registry["config_revision"], scope="application"
    ) as checkpoint:
        pass
    for _ in range(len(checkpoint.plan.stop_order) + 1):
        checkpoint = executor.reconcile_group_step(
            "shop", checkpoint.operation_id, checkpoint.generation
        )
    assert checkpoint.phase == "paused" and not any(states.values())
    return executor, group_registry, checkpoint, root


def test_complete_group_capture_preserves_and_verifies_each_tree(paused_application, tmp_path):
    executor, _registry, checkpoint, _root = paused_application
    result = executor.capture_paused_application(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    manifest = GroupCapture.model_validate(result["capture"])
    assert manifest.id == result["capture_id"] and result["uploaded"] is False
    assert manifest.application_consistent is False
    assert manifest.writer_coverage == "registered_containers"
    assert manifest.data_services == ["database", "worker"]
    assert manifest.original_running == checkpoint.original_running
    assert manifest.data_contract_revision == checkpoint.plan.data_contract_revision
    artifact = Path(executor._db_path).parent / "group-captures" / "shop" / result["artifact"]
    assert GroupCapture.model_validate_json((artifact / "manifest.json").read_text()) == manifest
    for name in manifest.data_services:
        workspace = tmp_path / ("restored-" + name)
        workspace.mkdir(mode=0o700)
        restored = materialize_tree(
            artifact / name / "data.tar", manifest.captures[name], workspace
        )
        assert (restored / "value.txt").read_text() == "original " + name
    assert executor.group_checkpoint("shop") == checkpoint
    assert executor.audit.verify()[0]
    with pytest.raises(ExecutorError) as error:
        executor.capture_paused_application("shop", checkpoint.operation_id, checkpoint.generation)
    assert error.value.error_class == "budget_exhausted"
    assert len(list(artifact.parent.iterdir())) == 1
    malformed = manifest.model_dump(mode="json")
    malformed["captures"].pop("worker")
    with pytest.raises(ValueError, match="incomplete"):
        GroupCapture.model_validate(malformed)


def test_partial_group_capture_is_retained_without_complete_manifest(paused_application):
    executor, _registry, checkpoint, root = paused_application
    (root / "shop" / "data" / "worker" / "unsafe").symlink_to("/etc/shadow")
    with pytest.raises(ExecutorError) as error:
        executor.capture_paused_application("shop", checkpoint.operation_id, checkpoint.generation)
    assert error.value.error_class == "execution_failed"
    spool = Path(executor._db_path).parent / "group-captures" / "shop"
    artifacts = list(spool.iterdir())
    assert len(artifacts) == 1 and (artifacts[0] / "database" / "manifest.json").is_file()
    assert not (artifacts[0] / "manifest.json").exists()
    assert executor.group_checkpoint("shop") == checkpoint
    entries = [
        event for event in executor.audit.read() if event["event"] == "application_group_capture"
    ]
    assert [event["outcome"] for event in entries] == ["started", "failed"]
    assert executor.audit.verify()[0]


def test_group_capture_requires_full_scope_matching_contract_and_quiescence(paused_application):
    executor, registry, checkpoint, _root = paused_application
    with pytest.raises(ExecutorError) as error:
        executor.capture_paused_application(
            "shop", checkpoint.operation_id, checkpoint.generation + 1
        )
    assert error.value.error_class == "conflict"
    executor.host.killed = True
    with pytest.raises(ExecutorError) as error:
        executor.capture_paused_application("shop", checkpoint.operation_id, checkpoint.generation)
    assert error.value.error_class == "kill_switch"
    executor.host.killed = False
    executor.host.workload_quiescent = lambda *_: False
    with pytest.raises(ExecutorError) as error:
        executor.capture_paused_application("shop", checkpoint.operation_id, checkpoint.generation)
    assert error.value.error_class == "unavailable"
    assert not (Path(executor._db_path).parent / "group-captures").exists()
    registry["applications"]["shop"]["services"]["worker"]["data_source"] = "/etc"
    Path(executor.registry_path).write_text(json.dumps(registry))
    with pytest.raises(ExecutorError) as error:
        executor.capture_paused_application("shop", checkpoint.operation_id, checkpoint.generation)
    assert error.value.error_class == "unavailable"


def test_group_capture_enforces_one_total_size_bound(paused_application):
    executor, _registry, checkpoint, root = paused_application
    for name in ("database", "worker"):
        (root / "shop" / "data" / name / "large").write_bytes(b"x" * (600 * 1024))
    with pytest.raises(ExecutorError) as error:
        executor.capture_paused_application("shop", checkpoint.operation_id, checkpoint.generation)
    assert error.value.error_class == "execution_failed"
    artifact = next((Path(executor._db_path).parent / "group-captures" / "shop").iterdir())
    assert not (artifact / "manifest.json").exists()
    assert executor.group_checkpoint("shop") == checkpoint


def test_group_capture_rejects_symlinked_parent(paused_application):
    executor, _registry, checkpoint, root = paused_application
    data = root / "shop" / "data"
    real = root / "shop" / "real-data"
    data.rename(real)
    data.symlink_to(real, target_is_directory=True)
    with pytest.raises(ExecutorError) as error:
        executor.capture_paused_application("shop", checkpoint.operation_id, checkpoint.generation)
    assert error.value.error_class == "execution_failed"
    assert executor.group_checkpoint("shop") == checkpoint
    assert not (Path(executor._db_path).parent / "group-captures").exists()


def test_group_capture_holds_locks_through_all_data(paused_application, monkeypatch):
    import threading

    from steward.core import filebackups

    executor, _registry, checkpoint, _root = paused_application
    entered, release = threading.Event(), threading.Event()
    original = filebackups.TimedReader.read

    def blocking(reader, size):
        data = original(reader, size)
        entered.set()
        assert release.wait(10)
        return data

    monkeypatch.setattr(filebackups.TimedReader, "read", blocking)
    errors = []

    def capture():
        try:
            executor.capture_paused_application(
                "shop", checkpoint.operation_id, checkpoint.generation
            )
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=capture)
    thread.start()
    try:
        assert entered.wait(10)
        with pytest.raises(ExecutorError) as error:
            executor.begin_group_recovery("shop", checkpoint.operation_id, checkpoint.generation)
        assert error.value.error_class == "target_busy"
    finally:
        release.set()
        thread.join(30)
    assert not errors and not thread.is_alive()
    assert executor.group_checkpoint("shop") == checkpoint


def test_capture_does_not_claim_application_consistency(paused_application):
    executor, _registry, checkpoint, _root = paused_application
    result = executor.capture_paused_application(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    forged = result["capture"]
    forged["application_consistent"] = True
    with pytest.raises(ValueError):
        GroupCapture.model_validate(forged)


def test_changed_boolean_backup_contract_fails_closed(paused_application):
    executor, registry, checkpoint, _root = paused_application
    registry["applications"]["shop"]["services"]["worker"]["allow_backup_pause"] = "yes"
    Path(executor.registry_path).write_text(json.dumps(registry))
    with pytest.raises(ExecutorError) as error:
        executor.capture_paused_application("shop", checkpoint.operation_id, checkpoint.generation)
    assert error.value.error_class == "unavailable"
    assert not (Path(executor._db_path).parent / "group-captures").exists()


def test_capture_refuses_data_tree_removed_from_registry_after_pause(paused_application):
    executor, registry, checkpoint, _root = paused_application
    service = registry["applications"]["shop"]["services"]["worker"]
    service["data_source"] = service["data_target"] = None
    Path(executor.registry_path).write_text(json.dumps(registry))
    with pytest.raises(ExecutorError) as error:
        executor.capture_paused_application("shop", checkpoint.operation_id, checkpoint.generation)
    assert error.value.error_class == "unavailable"
    assert not (Path(executor._db_path).parent / "group-captures").exists()


def test_legacy_application_checkpoint_can_resume_but_cannot_authorize_capture(paused_application):
    executor, _registry, checkpoint, _root = paused_application
    body = json.loads(checkpoint.model_dump_json())
    body["plan"].pop("data_contract_revision")
    with executor._db() as db:
        db.execute(
            "UPDATE application_group_intents SET body=? WHERE application=?",
            (json.dumps(body), "shop"),
        )
    legacy = executor.group_checkpoint("shop")
    assert legacy.plan.data_contract_revision is None
    with pytest.raises(ExecutorError) as error:
        executor.capture_paused_application("shop", legacy.operation_id, legacy.generation)
    assert error.value.error_class == "policy_denied"
    resumed = executor.advance_group_checkpoint(
        "shop", legacy.operation_id, legacy.generation, "resume"
    )
    assert resumed.phase == "resuming"
    resumed = executor.reconcile_group_step("shop", resumed.operation_id, resumed.generation)
    assert resumed.resume_index == 1


def test_partial_group_checkpoint_cannot_authorize_application_capture(
    executor, group_registry, group_host
):
    with executor.observed_group_execution(
        "shop", "worker", expected_revision=group_registry["config_revision"]
    ) as checkpoint:
        pass
    for _ in range(len(checkpoint.plan.stop_order) + 1):
        checkpoint = executor.reconcile_group_step(
            "shop", checkpoint.operation_id, checkpoint.generation
        )
    assert checkpoint.phase == "paused" and checkpoint.plan.scope == "dependents"
    with pytest.raises(ExecutorError) as error:
        executor.capture_paused_application("shop", checkpoint.operation_id, checkpoint.generation)
    assert error.value.error_class == "policy_denied"
    assert not (Path(executor._db_path).parent / "group-captures").exists()


def test_group_artifact_reverified_after_executor_restart(paused_application):
    import subprocess
    import sys

    executor, _registry, checkpoint, _root = paused_application
    result = executor.capture_paused_application(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    code = """import json,sys
from steward.executor.server import Executor
e=Executor(registry_path=sys.argv[1],state_dir=sys.argv[2],audit_path=sys.argv[3],lock_dir=sys.argv[4])
print(json.dumps(e.verify_group_capture('shop',sys.argv[5],sys.argv[6])))
"""
    process = subprocess.run(
        [
            sys.executable,
            "-c",
            code,
            executor.registry_path,
            str(Path(executor._db_path).parent),
            str(executor.audit.path),
            str(executor.lock_dir),
            result["artifact"],
            result["capture_id"],
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    checked = json.loads(process.stdout)
    assert checked == result
    assert checked["capture"]["application_consistent"] is False
    assert executor.group_checkpoint("shop") == checkpoint


@pytest.mark.parametrize(
    "damage", ["archive", "manifest", "missing", "extra", "hardlink", "mode", "symlink"]
)
def test_group_verification_rejects_tampering_and_partial_results(paused_application, damage):
    executor, _registry, checkpoint, _root = paused_application
    result = executor.capture_paused_application(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    artifact = Path(executor._db_path).parent / "group-captures" / "shop" / result["artifact"]
    child = artifact / "worker"
    if damage == "archive":
        path = child / "data.tar"
        raw = bytearray(path.read_bytes())
        raw[0] ^= 1
        path.write_bytes(raw)
    elif damage == "manifest":
        path = artifact / "manifest.json"
        body = json.loads(path.read_text())
        body["original_running"]["worker"] = False
        path.write_text(json.dumps(body))
    elif damage == "missing":
        (child / "data.tar").unlink()
    elif damage == "extra":
        (artifact / "unexpected").touch()
    elif damage == "hardlink":
        import os

        os.link(child / "data.tar", artifact.parent / "linked-file")
    elif damage == "mode":
        (child / "data.tar").chmod(0o640)
    else:
        (child / "data.tar").unlink()
        (child / "data.tar").symlink_to("/etc/passwd")
    with pytest.raises(ExecutorError) as error:
        executor.verify_group_capture("shop", result["artifact"], result["capture_id"])
    assert error.value.error_class == "unavailable"
    assert executor.group_checkpoint("shop") == checkpoint


def test_group_verification_requires_exact_ids_and_application_lock(paused_application):
    executor, _registry, checkpoint, _root = paused_application
    result = executor.capture_paused_application(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    with pytest.raises(ExecutorError) as error:
        executor.verify_group_capture("shop", result["artifact"], "0" * 64)
    assert error.value.error_class == "unavailable"
    with pytest.raises(ExecutorError) as error:
        executor.verify_group_capture("../shop", result["artifact"], result["capture_id"])
    assert error.value.error_class == "bad_request"
    with executor.target_lock(
        next(t for t in checkpoint.plan.lock_targets if t.startswith("application-"))
    ):
        with pytest.raises(ExecutorError) as error:
            executor.verify_group_capture("shop", result["artifact"], result["capture_id"])
        assert error.value.error_class == "target_busy"


def test_group_verification_rejects_acl_on_private_artifact(paused_application, monkeypatch):
    from steward.core import backupexport

    executor, _registry, checkpoint, _root = paused_application
    result = executor.capture_paused_application(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    artifact = Path(executor._db_path).parent / "group-captures" / "shop" / result["artifact"]
    actual = backupexport.acl_attributes
    monkeypatch.setattr(
        backupexport,
        "acl_attributes",
        lambda path: {"system.posix_acl_access"} if path == artifact else actual(path),
    )
    with pytest.raises(ExecutorError) as error:
        executor.verify_group_capture("shop", result["artifact"], result["capture_id"])
    assert error.value.error_class == "unavailable"


@pytest.fixture
def starting_application(executor, group_registry, group_host, tmp_path, monkeypatch):
    states, _ = group_host
    Path(executor._db_path).parent.chmod(0o700)
    root = tmp_path / "applications"
    monkeypatch.setattr(server, "APPLICATION_DATA_ROOT", root)
    group_registry["server_name"] = "test-server"
    group_registry["backup"] = {"max_mib": 1}
    specs = group_registry["applications"]["shop"]["services"]
    for name, spec in specs.items():
        if name in ("database", "worker"):
            path = root / "shop" / "data" / name
            path.mkdir(parents=True)
            (path / "value.txt").write_text("original " + name)
            path.chmod(0o700)
            (path / "value.txt").chmod(0o600)
            spec.update(data_source=str(path), data_target="/data", allow_backup_pause=True)
        else:
            spec.update(data_source=None, data_target=None)
    for directory in (root, root / "shop", root / "shop" / "data"):
        directory.chmod(0o700)
    Path(executor.registry_path).write_text(json.dumps(group_registry))
    by_unit = {spec["unit"]: name for name, spec in specs.items()}
    executor.host.workload_quiescent = lambda _user, unit: states[by_unit[unit]] is False
    with executor.observed_group_execution(
        "shop", "frontend", expected_revision=group_registry["config_revision"], scope="application"
    ) as checkpoint:
        pass
    return executor, checkpoint, root


def test_group_capture_workflow_stops_captures_and_restores_original_intent(
    starting_application, group_host
):
    executor, checkpoint, _root = starting_application
    states, mutations = group_host
    result = executor.capture_application_with_recovery(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    assert result["state"] == "captured" and result["workflow"].phase == "captured"
    assert result["checkpoint"].phase == "complete" and states == checkpoint.original_running
    assert mutations == [
        ("worker", False),
        ("database", False),
        ("database", True),
        ("worker", True),
    ]
    checked = executor.verify_group_capture(
        "shop", result["workflow"].artifact, result["workflow"].capture_id
    )
    assert checked["capture"]["application_consistent"] is False
    assert executor.audit.verify()[0]


def test_group_capture_failure_restores_workloads_without_claiming_success(
    starting_application, group_host, monkeypatch
):
    executor, checkpoint, root = starting_application
    states, _ = group_host
    preflight = executor.preflight_application_capture

    def change_after_preflight(checkpoint):
        preflight(checkpoint)
        (root / "shop" / "data" / "worker" / "unsafe").symlink_to("/etc/shadow")

    monkeypatch.setattr(executor, "preflight_application_capture", change_after_preflight)
    result = executor.capture_application_with_recovery(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    assert result["state"] == "capture_failed" and result["workflow"].phase == "failed"
    assert result["workflow"].error_class == "execution_failed"
    assert result["checkpoint"].phase == "complete" and states == checkpoint.original_running
    assert executor.group_capture_workflow("shop") == result["workflow"]
    assert any(
        event.get("event") == "application_group_capture_workflow"
        and event.get("outcome") == "failed"
        and event.get("error_class") == "execution_failed"
        for event in executor.audit.read()
    )


def test_restart_recovers_interrupted_capture_pause_without_claiming_success(
    starting_application, group_host
):
    from steward.executor.server import GroupStartupRecovery

    executor, checkpoint, _root = starting_application
    states, _ = group_host
    executor.begin_group_capture_workflow(checkpoint)
    for _ in range(len(checkpoint.plan.stop_order) + 1):
        checkpoint = executor.reconcile_group_step(
            "shop", checkpoint.operation_id, checkpoint.generation
        )
    assert checkpoint.phase == "paused"
    recovery = GroupStartupRecovery(executor)
    while recovery.candidates:
        recovery.tick()
    assert executor.group_checkpoint("shop").phase == "complete"
    workflow = executor.group_capture_workflow("shop")
    assert workflow.phase == "failed" and workflow.error_class == "unavailable"
    assert states == checkpoint.original_running


def test_restart_keeps_captured_evidence_while_resuming(
    starting_application, group_host, monkeypatch
):
    from steward.executor.server import GroupStartupRecovery

    executor, checkpoint, _root = starting_application
    states, _ = group_host
    workflow = executor.begin_group_capture_workflow(checkpoint)
    for _ in range(len(checkpoint.plan.stop_order) + 1):
        checkpoint = executor.reconcile_group_step(
            "shop", checkpoint.operation_id, checkpoint.generation
        )
    capture = executor.capture_paused_application(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    workflow = executor.update_group_capture_workflow(
        workflow, phase="captured", artifact=capture["artifact"], capture_id=capture["capture_id"]
    )
    checks = []
    verify = executor.verify_group_capture

    def count_verification(*args):
        checks.append(True)
        return verify(*args)

    monkeypatch.setattr(executor, "verify_group_capture", count_verification)
    recovery = GroupStartupRecovery(executor)
    while recovery.candidates:
        recovery.tick()
    assert checks == [True]
    assert executor.group_checkpoint("shop").phase == "complete"
    assert executor.group_capture_workflow("shop") == workflow
    assert (
        executor.verify_group_capture("shop", workflow.artifact, workflow.capture_id)["capture_id"]
        == workflow.capture_id
    )
    assert states == checkpoint.original_running


def test_unexpected_capture_exception_still_restores_group(
    starting_application, group_host, monkeypatch
):
    executor, checkpoint, _root = starting_application
    states, _ = group_host

    def fail(*_args, **_kwargs):
        raise RuntimeError("fixture failure")

    monkeypatch.setattr(executor, "capture_paused_application", fail)
    result = executor.capture_application_with_recovery(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    assert result["state"] == "capture_failed" and result["workflow"].error_class == "internal"
    assert result["checkpoint"].phase == "complete" and states == checkpoint.original_running


def test_restart_recovers_partial_group_stop_with_capture_intent(starting_application, group_host):
    from steward.executor.server import GroupStartupRecovery

    executor, checkpoint, _root = starting_application
    states, _ = group_host
    executor.begin_group_capture_workflow(checkpoint)
    checkpoint = executor.reconcile_group_step(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    assert not states["worker"]
    recovery = GroupStartupRecovery(executor)
    while recovery.candidates:
        recovery.tick()
    restored = executor.group_checkpoint("shop")
    assert restored.phase == "recovered" and states == checkpoint.original_running
    assert executor.group_capture_workflow("shop").phase == "failed"


def test_corrupt_capture_workflow_does_not_resume_paused_group(starting_application, group_host):
    from steward.executor.server import GroupStartupRecovery

    executor, checkpoint, _root = starting_application
    states, _ = group_host
    executor.begin_group_capture_workflow(checkpoint)
    for _ in range(len(checkpoint.plan.stop_order) + 1):
        checkpoint = executor.reconcile_group_step(
            "shop", checkpoint.operation_id, checkpoint.generation
        )
    with executor._db() as db:
        db.execute("UPDATE application_capture_workflows SET body='{}' WHERE application='shop'")
    recovery = GroupStartupRecovery(executor)
    recovery.tick()
    assert recovery.candidates and executor.group_checkpoint("shop") == checkpoint
    assert not any(states.values())


def test_kill_switch_does_not_start_services_during_workflow_recovery(
    starting_application, group_host
):
    from steward.executor.server import GroupStartupRecovery

    executor, checkpoint, _root = starting_application
    states, mutations = group_host
    executor.begin_group_capture_workflow(checkpoint)
    for _ in range(len(checkpoint.plan.stop_order) + 1):
        checkpoint = executor.reconcile_group_step(
            "shop", checkpoint.operation_id, checkpoint.generation
        )
    before = list(mutations)
    executor.host.killed = True
    recovery = GroupStartupRecovery(executor)
    recovery.tick()
    assert recovery.candidates and not any(states.values()) and mutations == before
    executor.host.killed = False
    while recovery.candidates:
        recovery.tick()
    assert states == checkpoint.original_running


def test_mismatched_workflow_never_resumes_group(starting_application, group_host):
    from steward.executor.server import GroupStartupRecovery

    executor, checkpoint, _root = starting_application
    states, _ = group_host
    workflow = executor.begin_group_capture_workflow(checkpoint)
    for _ in range(len(checkpoint.plan.stop_order) + 1):
        checkpoint = executor.reconcile_group_step(
            "shop", checkpoint.operation_id, checkpoint.generation
        )
    altered = workflow.model_copy(update={"data_contract_revision": "0" * 64})
    with executor._db() as db:
        db.execute(
            "UPDATE application_capture_workflows SET body=? WHERE application=?",
            (altered.model_dump_json(), "shop"),
        )
    recovery = GroupStartupRecovery(executor)
    recovery.tick()
    assert recovery.candidates and executor.group_checkpoint("shop") == checkpoint
    assert not any(states.values())


def test_live_capture_coordinator_driver_is_not_taken_over(starting_application):
    from steward.executor.server import GroupStartupRecovery

    executor, checkpoint, _root = starting_application
    executor.begin_group_capture_workflow(checkpoint)
    recovery = GroupStartupRecovery(executor)
    with executor.group_driver_lock(checkpoint):
        recovery.tick()
    assert recovery.candidates and executor.group_checkpoint("shop") == checkpoint
    assert executor.group_capture_workflow("shop").phase == "prepared"


def test_unexpected_stop_exception_restores_already_stopped_group(
    starting_application, group_host, monkeypatch
):
    executor, checkpoint, _root = starting_application
    states, mutations = group_host
    original = executor.reconcile_group_step
    calls = []

    def fail_second(*args, **kwargs):
        calls.append(True)
        if len(calls) == 2:
            raise RuntimeError("fixture failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(executor, "reconcile_group_step", fail_second)
    result = executor.capture_application_with_recovery(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    assert result["state"] == "capture_failed" and result["workflow"].error_class == "internal"
    assert result["checkpoint"].phase == "recovered" and states == checkpoint.original_running
    assert mutations == [("worker", False), ("worker", True)]


def test_restart_marks_damaged_capture_failed_but_restores_group(starting_application, group_host):
    from steward.executor.server import GroupStartupRecovery

    executor, checkpoint, _root = starting_application
    states, _ = group_host
    workflow = executor.begin_group_capture_workflow(checkpoint)
    for _ in range(len(checkpoint.plan.stop_order) + 1):
        checkpoint = executor.reconcile_group_step(
            "shop", checkpoint.operation_id, checkpoint.generation
        )
    capture = executor.capture_paused_application(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    workflow = executor.update_group_capture_workflow(
        workflow, phase="captured", artifact=capture["artifact"], capture_id=capture["capture_id"]
    )
    archive = (
        Path(executor._db_path).parent
        / "group-captures"
        / "shop"
        / workflow.artifact
        / "worker"
        / "data.tar"
    )
    data = bytearray(archive.read_bytes())
    data[0] ^= 1
    archive.write_bytes(data)
    recovery = GroupStartupRecovery(executor)
    while recovery.candidates:
        recovery.tick()
    failed = executor.group_capture_workflow("shop")
    assert failed.phase == "failed" and failed.error_class == "unavailable"
    assert failed.artifact == workflow.artifact and failed.capture_id == workflow.capture_id
    assert (
        executor.group_checkpoint("shop").phase == "complete"
        and states == checkpoint.original_running
    )


def test_completed_workflow_is_not_rehashed_on_every_executor_start(
    starting_application, monkeypatch
):
    from steward.executor.server import GroupStartupRecovery

    executor, checkpoint, _root = starting_application
    result = executor.capture_application_with_recovery(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    assert result["state"] == "captured"

    def unexpected(*_args, **_kwargs):
        raise AssertionError("finished group capture should not be rehashed on startup")

    monkeypatch.setattr(executor, "verify_group_capture", unexpected)
    recovery = GroupStartupRecovery(executor)
    assert not recovery.candidates
    recovery.candidates["shop"] = checkpoint.operation_id  # already queued while driver was active
    recovery.tick()
    assert not recovery.candidates


def test_live_worker_recovers_a_new_capture_workflow_after_transient_lock(
    starting_application, group_host, monkeypatch
):
    import threading
    import time

    from steward.executor.server import GroupStartupRecovery

    executor, checkpoint, _root = starting_application
    states, _ = group_host
    recovery = GroupStartupRecovery(executor)
    # Model a worker that was already running before this group was admitted.
    recovery.candidates.clear()
    stop = threading.Event()
    worker = threading.Thread(target=recovery.run, args=(stop,))
    original = executor.resume_paused_group
    calls = []

    def fail_once(*args, **kwargs):
        calls.append(True)
        if len(calls) == 1:
            raise ExecutorError("target_busy", "temporary conflict")
        return original(*args, **kwargs)

    monkeypatch.setattr(executor, "resume_paused_group", fail_once)
    worker.start()
    try:
        result = executor.capture_application_with_recovery(
            "shop", checkpoint.operation_id, checkpoint.generation
        )
        assert result["state"] == "recovery_pending" and result["workflow"].phase == "captured"
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if executor.group_checkpoint("shop").phase == "complete":
                break
            executor.group_recovery_wakeup.set()
            time.sleep(0.05)
        assert executor.group_checkpoint("shop").phase == "complete"
        assert states == checkpoint.original_running
        assert executor.group_capture_workflow("shop").phase == "captured"
    finally:
        stop.set()
        executor.group_recovery_wakeup.set()
        worker.join(5)
    assert not worker.is_alive()


def test_live_discovery_does_not_adopt_unrelated_later_group(executor, group_registry, group_host):
    from steward.executor.server import GroupStartupRecovery

    recovery = GroupStartupRecovery(executor)
    with executor.observed_group_execution(
        "shop", "worker", expected_revision=group_registry["config_revision"]
    ) as checkpoint:
        pass
    recovery.discover_capture_workflows()
    recovery.tick()
    assert not recovery.candidates and executor.group_checkpoint("shop") == checkpoint


def test_terminal_interrupted_workflow_is_failed_without_restarting_services(
    starting_application, group_host
):
    from steward.executor.server import GroupStartupRecovery

    executor, checkpoint, _root = starting_application
    states, mutations = group_host
    executor.begin_group_capture_workflow(checkpoint)
    for _ in range(len(checkpoint.plan.stop_order) + 1):
        checkpoint = executor.reconcile_group_step(
            "shop", checkpoint.operation_id, checkpoint.generation
        )
    checkpoint = executor.resume_paused_group(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    for _ in range(len(checkpoint.plan.start_order) + 1):
        checkpoint = executor.reconcile_group_step(
            "shop", checkpoint.operation_id, checkpoint.generation
        )
    assert checkpoint.phase == "complete"
    before = list(mutations)
    recovery = GroupStartupRecovery(executor)
    recovery.tick()
    assert not recovery.candidates and executor.group_capture_workflow("shop").phase == "failed"
    assert mutations == before and states == checkpoint.original_running


def test_full_group_capture_spool_is_refused_before_any_service_stops(
    starting_application, group_host
):
    executor, checkpoint, _root = starting_application
    states, mutations = group_host
    spool = Path(executor._db_path).parent / "group-captures" / "shop"
    spool.mkdir(parents=True, mode=0o700)
    spool.parent.chmod(0o700)
    for index in range(10):
        (spool / f"{index:032x}").mkdir(mode=0o700)
    result = executor.capture_application_with_recovery(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    assert result["state"] == "capture_failed" and result["workflow"].error_class == "unavailable"
    assert result["checkpoint"].phase == "recovered"
    assert states == checkpoint.original_running and mutations == []
    assert len(list(spool.iterdir())) == 10


def test_group_capture_budget_is_checked_before_any_service_stops(starting_application, group_host):
    from steward.core.ids import graph_identifier

    executor, checkpoint, _root = starting_application
    states, mutations = group_host
    executor.spend_budget(
        "application-" + graph_identifier("a", "shop"), "application_group_capture", 1
    )
    result = executor.capture_application_with_recovery(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    assert (
        result["state"] == "capture_failed" and result["workflow"].error_class == "budget_exhausted"
    )
    assert result["checkpoint"].phase == "recovered"
    assert states == checkpoint.original_running and mutations == []


def test_missing_application_data_is_refused_before_any_service_stops(
    starting_application, group_host
):
    import shutil

    executor, checkpoint, root = starting_application
    states, mutations = group_host
    shutil.rmtree(root / "shop" / "data" / "worker")
    result = executor.capture_application_with_recovery(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    assert result["state"] == "capture_failed" and result["workflow"].error_class == "unavailable"
    assert result["checkpoint"].phase == "recovered"
    assert states == checkpoint.original_running and mutations == []


def test_failure_audit_outage_retains_recoverable_workflow(
    starting_application, group_host, monkeypatch
):
    from steward.executor.server import GroupStartupRecovery

    executor, checkpoint, root = starting_application
    states, _ = group_host
    preflight = executor.preflight_application_capture

    def change_after_preflight(checkpoint):
        preflight(checkpoint)
        (root / "shop" / "data" / "worker" / "unsafe").symlink_to("/etc/shadow")

    monkeypatch.setattr(executor, "preflight_application_capture", change_after_preflight)
    original = executor.audit.append

    def no_failure_audit(event, **fields):
        if event == "application_group_capture_workflow" and fields.get("outcome") == "failed":
            raise OSError("fixture audit outage")
        return original(event, **fields)

    monkeypatch.setattr(executor.audit, "append", no_failure_audit)
    with pytest.raises(OSError):
        executor.capture_application_with_recovery(
            "shop", checkpoint.operation_id, checkpoint.generation
        )
    assert executor.group_capture_workflow("shop").phase == "failed"
    assert executor.group_checkpoint("shop").phase == "paused"
    monkeypatch.setattr(executor.audit, "append", original)
    recovery = GroupStartupRecovery(executor)
    while recovery.candidates:
        recovery.tick()
    assert executor.group_checkpoint("shop").phase == "complete"
    assert states == checkpoint.original_running


def test_archiving_group_workflow_allows_later_capture_without_losing_first(
    starting_application, group_host
):
    import time

    executor, first, _root = starting_application
    states, _ = group_host
    first_result = executor.capture_application_with_recovery(
        "shop", first.operation_id, first.generation
    )
    first_done = first_result["checkpoint"]
    history = executor.archive_group_checkpoint("shop", first.operation_id, first_done.generation)
    assert history.checkpoint == first_done and history.workflow == first_result["workflow"]
    assert (
        executor.group_checkpoint("shop") is None
        and executor.group_capture_workflow("shop") is None
    )
    old = executor.verify_group_capture(
        "shop", history.workflow.artifact, history.workflow.capture_id
    )
    assert old["capture"]["application_consistent"] is False
    with executor._db() as db:
        db.execute(
            "UPDATE mutations SET ts=? WHERE action=?",
            (time.time() - 3601, "application_group_capture"),
        )
    with executor.observed_group_execution(
        "shop", "frontend", expected_revision=first.plan.config_revision, scope="application"
    ) as second:
        pass
    assert second.operation_id != first.operation_id
    assert (
        executor.archive_group_checkpoint("shop", first.operation_id, first_done.generation)
        == history
    )
    assert executor.group_checkpoint("shop") == second
    second_result = executor.capture_application_with_recovery(
        "shop", second.operation_id, second.generation
    )
    assert second_result["state"] == "captured" and states == first.original_running
    assert second_result["workflow"].artifact != history.workflow.artifact
    assert (
        executor.verify_group_capture(
            "shop", history.workflow.artifact, history.workflow.capture_id
        )
        == old
    )
    assert executor.group_history(first.operation_id) == history


def test_archiving_rejects_active_unresolved_and_capacity_without_data_loss(
    starting_application, monkeypatch
):
    executor, checkpoint, _root = starting_application
    with pytest.raises(ExecutorError) as error:
        executor.archive_group_checkpoint("shop", checkpoint.operation_id, checkpoint.generation)
    assert error.value.error_class == "policy_denied"
    result = executor.capture_application_with_recovery(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    done = result["checkpoint"]
    monkeypatch.setattr(server, "MAX_GROUP_HISTORY", 0)
    with pytest.raises(ExecutorError) as error:
        executor.archive_group_checkpoint("shop", checkpoint.operation_id, done.generation)
    assert error.value.error_class == "unavailable"
    assert executor.group_checkpoint("shop") == done
    assert executor.group_capture_workflow("shop") == result["workflow"]
    assert executor.group_history(checkpoint.operation_id) is None


def test_archiving_unresolved_workflow_requires_reconciliation(starting_application):
    from steward.executor.server import GroupStartupRecovery

    executor, checkpoint, _root = starting_application
    executor.begin_group_capture_workflow(checkpoint)
    for _ in range(len(checkpoint.plan.stop_order) + 1):
        checkpoint = executor.reconcile_group_step(
            "shop", checkpoint.operation_id, checkpoint.generation
        )
    checkpoint = executor.resume_paused_group(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    for _ in range(len(checkpoint.plan.start_order) + 1):
        checkpoint = executor.reconcile_group_step(
            "shop", checkpoint.operation_id, checkpoint.generation
        )
    with pytest.raises(ExecutorError) as error:
        executor.archive_group_checkpoint("shop", checkpoint.operation_id, checkpoint.generation)
    assert error.value.error_class == "target_busy"
    assert executor.group_checkpoint("shop") == checkpoint
    recovery = GroupStartupRecovery(executor)
    recovery.tick()
    assert executor.group_capture_workflow("shop").phase == "failed"
    history = executor.archive_group_checkpoint(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    assert history.workflow.phase == "failed" and history.checkpoint == checkpoint


def test_archive_after_audit_failure_is_idempotently_recoverable(starting_application, monkeypatch):
    executor, checkpoint, _root = starting_application
    result = executor.capture_application_with_recovery(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    done = result["checkpoint"]
    original = executor.audit.append

    def fail_completion(event, **fields):
        if event == "application_group_archive" and fields.get("outcome") == "archived":
            raise OSError("fixture audit outage")
        return original(event, **fields)

    monkeypatch.setattr(executor.audit, "append", fail_completion)
    with pytest.raises(OSError):
        executor.archive_group_checkpoint("shop", checkpoint.operation_id, done.generation)
    retained = executor.group_history(checkpoint.operation_id)
    assert retained is not None and executor.group_checkpoint("shop") is None
    monkeypatch.setattr(executor.audit, "append", original)
    assert (
        executor.archive_group_checkpoint("shop", checkpoint.operation_id, done.generation)
        == retained
    )
    assert executor.audit.verify()[0]


def test_corrupt_workflow_and_history_cannot_erase_checkpoints(starting_application):
    executor, checkpoint, _root = starting_application
    result = executor.capture_application_with_recovery(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    done = result["checkpoint"]
    with executor._db() as db:
        db.execute("UPDATE application_capture_workflows SET body='{}' WHERE application='shop'")
    with pytest.raises(ExecutorError) as error:
        executor.archive_group_checkpoint("shop", done.operation_id, done.generation)
    assert error.value.error_class == "unavailable"
    assert (
        executor.group_checkpoint("shop") == done
        and executor.group_history(done.operation_id) is None
    )
    with executor._db() as db:
        db.execute(
            "UPDATE application_capture_workflows SET body=? WHERE application=?",
            (result["workflow"].model_dump_json(), "shop"),
        )
    history = executor.archive_group_checkpoint("shop", done.operation_id, done.generation)
    with executor._db() as db:
        db.execute(
            "UPDATE application_group_history SET body='{}' WHERE operation_id=?",
            (done.operation_id,),
        )
    with pytest.raises(ExecutorError) as error:
        executor.group_history(done.operation_id)
    assert error.value.error_class == "unavailable"
    with pytest.raises(ExecutorError) as error:
        executor.archive_group_checkpoint("shop", done.operation_id, done.generation)
    assert error.value.error_class == "unavailable"
    assert (
        executor.verify_group_capture(
            "shop", history.workflow.artifact, history.workflow.capture_id
        )["capture_id"]
        == history.workflow.capture_id
    )


def test_concurrent_archivers_preserve_one_exact_history(starting_application):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    executor, checkpoint, _root = starting_application
    result = executor.capture_application_with_recovery(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    done = result["checkpoint"]
    barrier = Barrier(2)

    def archive():
        barrier.wait()
        try:
            return executor.archive_group_checkpoint("shop", done.operation_id, done.generation)
        except ExecutorError as exc:
            assert exc.error_class in ("target_busy", "conflict")
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: archive(), range(2)))
    history = executor.group_history(done.operation_id)
    assert history is not None and any(value == history for value in outcomes)
    assert all(value is None or value == history for value in outcomes)
    with executor._db() as db:
        assert db.execute("SELECT COUNT(*) FROM application_group_history").fetchone()[0] == 1
    assert executor.group_checkpoint("shop") is None


def test_archive_transaction_rolls_back_if_checkpoint_delete_fails(starting_application):
    import sqlite3

    executor, checkpoint, _root = starting_application
    result = executor.capture_application_with_recovery(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    done = result["checkpoint"]
    with executor._db() as db:
        db.execute(
            "CREATE TRIGGER reject_group_delete BEFORE DELETE ON application_group_intents BEGIN SELECT RAISE(ABORT, 'fixture'); END"
        )
    with pytest.raises(sqlite3.IntegrityError):
        executor.archive_group_checkpoint("shop", done.operation_id, done.generation)
    assert executor.group_checkpoint("shop") == done
    assert executor.group_capture_workflow("shop") == result["workflow"]
    assert executor.group_history(done.operation_id) is None
    assert (
        executor.verify_group_capture(
            "shop", result["workflow"].artifact, result["workflow"].capture_id
        )["capture_id"]
        == result["workflow"].capture_id
    )


def test_archive_waits_for_deployment_and_preserves_old_revision(starting_application):
    executor, checkpoint, _root = starting_application
    result = executor.capture_application_with_recovery(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    done = result["checkpoint"]
    fence = executor.begin_deployment_fence(
        base_revision=checkpoint.plan.config_revision, desired_revision="b" * 64
    )
    with pytest.raises(ExecutorError) as error:
        executor.archive_group_checkpoint("shop", done.operation_id, done.generation)
    assert error.value.error_class == "conflict" and executor.group_checkpoint("shop") == done
    registry = json.loads(Path(executor.registry_path).read_text())
    registry["config_revision"] = "b" * 64
    Path(executor.registry_path).write_text(json.dumps(registry))
    executor.release_deployment_fence(fence.operation_id)
    history = executor.archive_group_checkpoint("shop", done.operation_id, done.generation)
    assert history.checkpoint.plan.config_revision == checkpoint.plan.config_revision
    assert (
        executor.verify_group_capture(
            "shop", history.workflow.artifact, history.workflow.capture_id
        )["capture_id"]
        == history.workflow.capture_id
    )


def test_archive_failed_capture_keeps_partial_data_for_investigation(
    starting_application, monkeypatch
):
    executor, checkpoint, root = starting_application
    preflight = executor.preflight_application_capture

    def change_after_preflight(checkpoint):
        preflight(checkpoint)
        (root / "shop" / "data" / "worker" / "unsafe").symlink_to("/etc/shadow")

    monkeypatch.setattr(executor, "preflight_application_capture", change_after_preflight)
    result = executor.capture_application_with_recovery(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    done = result["checkpoint"]
    spool = Path(executor._db_path).parent / "group-captures" / "shop"
    partial = next(spool.iterdir())
    assert result["state"] == "capture_failed" and not (partial / "manifest.json").exists()
    history = executor.archive_group_checkpoint("shop", done.operation_id, done.generation)
    assert history.workflow.phase == "failed"
    assert partial.is_dir() and (partial / "database" / "data.tar").is_file()
    assert not (partial / "manifest.json").exists()


def test_out_of_slice_process_scope_blocks_group_capture(paused_application):
    executor, _registry, checkpoint, _root = paused_application
    executor.host.group_users_within_systemd_slices = lambda _users: False
    with pytest.raises(ExecutorError) as error:
        executor.capture_paused_application("shop", checkpoint.operation_id, checkpoint.generation)
    assert error.value.error_class == "unavailable"
    assert not (Path(executor._db_path).parent / "group-captures").exists()
    assert executor.group_checkpoint("shop") == checkpoint


def test_out_of_slice_process_appearing_during_capture_prevents_group_manifest(paused_application):
    executor, _registry, checkpoint, _root = paused_application
    checks = []

    def scope(_users):
        checks.append(True)
        return len(checks) == 1

    executor.host.group_users_within_systemd_slices = scope
    with pytest.raises(ExecutorError) as error:
        executor.capture_paused_application("shop", checkpoint.operation_id, checkpoint.generation)
    assert error.value.error_class == "execution_failed" and len(checks) == 2
    artifact = next((Path(executor._db_path).parent / "group-captures" / "shop").iterdir())
    assert not (artifact / "manifest.json").exists()
    assert executor.group_checkpoint("shop") == checkpoint


def test_group_capture_rejects_shared_writable_data(paused_application):
    executor, _registry, checkpoint, root = paused_application
    (root / "shop" / "data" / "worker" / "value.txt").chmod(0o666)
    with pytest.raises(ExecutorError, match="unsafe_owner"):
        executor.capture_paused_application("shop", checkpoint.operation_id, checkpoint.generation)
    spool = Path(executor._db_path).parent / "group-captures" / "shop"
    artifact = next(spool.iterdir())
    assert (artifact / "database" / "manifest.json").is_file()
    assert not (artifact / "manifest.json").exists()


def test_group_capture_detects_change_to_already_captured_tree(paused_application, monkeypatch):
    from steward.core import filebackups

    executor, _registry, checkpoint, root = paused_application
    original = filebackups.capture_files

    def change_after_second(*args, **kwargs):
        result = original(*args, **kwargs)
        if args[0].name == "worker":
            (root / "shop" / "data" / "database" / "value.txt").write_text("changed later")
        return result

    monkeypatch.setattr(filebackups, "capture_files", change_after_second)
    with pytest.raises(ExecutorError, match="source_changed"):
        executor.capture_paused_application("shop", checkpoint.operation_id, checkpoint.generation)
    spool = Path(executor._db_path).parent / "group-captures" / "shop"
    assert not (next(spool.iterdir()) / "manifest.json").exists()


@pytest.mark.parametrize(
    "problem", ["writable", "symlink", "oversized", "combined_size", "unknown_uid"]
)
def test_preflight_rejects_unsafe_data_before_stopping(starting_application, group_host, problem):
    executor, checkpoint, root = starting_application
    states, mutations = group_host
    worker = root / "shop" / "data" / "worker"
    if problem == "writable":
        (worker / "value.txt").chmod(0o666)
    elif problem == "symlink":
        (worker / "link").symlink_to("value.txt")
    elif problem == "oversized":
        with (worker / "value.txt").open("wb") as stream:
            stream.truncate(1024 * 1024 + 1)
    elif problem == "combined_size":
        for name in ("database", "worker"):
            with (root / "shop" / "data" / name / "value.txt").open("wb") as stream:
                stream.truncate(600 * 1024)
    else:
        executor.host.service_user_uid = lambda user: None
    result = executor.capture_application_with_recovery(
        "shop", checkpoint.operation_id, checkpoint.generation
    )
    assert result["state"] == "capture_failed"
    assert result["workflow"].error_class == "unavailable"
    assert result["checkpoint"].phase == "recovered"
    assert states == checkpoint.original_running and mutations == []
    assert not list((Path(executor._db_path).parent / "group-captures" / "shop").iterdir())
