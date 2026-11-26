import json
import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from steward.core.backups import load_capture
from steward.executor import server
from steward.executor.host import Host


def request(**params):
    return json.dumps(
        {
            "v": 1,
            "action": "backup_capture",
            "params": {"project_id": "notes", **params},
            "request_id": uuid.uuid4().hex,
            "expires_at": time.time() + 60,
        }
    ).encode()


@pytest.fixture
def capture_host(executor, tmp_path, monkeypatch):
    registry = json.loads(executor.registry_file.read_text())
    registry["projects"]["notes"]["allow_backup_pause"] = True
    executor.registry_file.write_text(json.dumps(registry))
    data = tmp_path / "projects" / "notes" / "data"
    data.mkdir(parents=True)
    (data / "durable").write_text("important data")
    monkeypatch.setattr(server, "PROJECT_DATA_ROOT", tmp_path / "projects")

    def set_state(user, unit, *, running):
        executor.host.calls.append(("set", running))
        executor.host.units[unit] = "active" if running else "inactive"
        return True

    executor.host.set_user_unit = set_state
    executor.host.workload_quiescent = lambda user, unit: executor.host.units[unit] == "inactive"
    return executor, data


def test_capture_requires_operator_and_explicit_pause_contract(executor):
    assert executor.handle(request(), os.getuid())["error_class"] == "forbidden_role"
    assert executor.handle(request(), 0)["error_class"] == "policy_denied"
    assert executor.host.calls == []


def test_registered_capture_pauses_resumes_and_retains_private_artifact(capture_host):
    executor, data = capture_host
    result = executor.handle(request(), 0)
    assert result["ok"]
    result = result["result"]
    assert result["resumed"] and result["uploaded"] is False
    target = data.parents[2] / "state" / "captures" / "notes" / result["artifact"]
    manifest = load_capture(target)
    assert manifest.id == result["capture_id"]
    assert manifest.binding.project == "notes"
    assert target.stat().st_mode & 0o777 == 0o700
    assert executor.host.calls == [("set", False), ("set", True)]


def test_capture_error_resumes_workload_and_cleans_partial_output(capture_host):
    executor, data = capture_host
    (data / "unsafe").symlink_to("/etc/shadow")
    result = executor.handle(request(), 0)
    assert result["error_class"] == "execution_failed"
    assert executor.host.units["notes.service"] == "active"
    assert executor.host.calls == [("set", False), ("set", True)]
    assert list((data.parents[2] / "state" / "captures" / "notes").iterdir()) == []


def test_stopped_workload_is_not_started_by_capture(capture_host):
    executor, _data = capture_host
    executor.host.units["notes.service"] = "inactive"
    assert executor.handle(request(), 0)["ok"]
    assert executor.host.calls == []


def test_capture_uses_existing_project_lock_and_refuses_caller_paths(capture_host):
    executor, _data = capture_host
    with executor.target_lock("project-notes"):
        assert executor.handle(request(), 0)["error_class"] == "target_busy"
    assert executor.handle(request(path="/etc"), 0)["error_class"] == "bad_request"
    assert not executor.host.calls


def test_failed_resume_is_not_reported_as_success(capture_host):
    executor, _data = capture_host
    original = executor.host.set_user_unit

    def fail_resume(user, unit, *, running):
        return False if running else original(user, unit, running=running)

    executor.host.set_user_unit = fail_resume
    result = executor.handle(request(), 0)
    assert result["error_class"] == "execution_failed"
    assert "resume failed" in result["message"]
    assert executor.backup_pause("notes") is not None
    assert executor.backup_pause_summaries()[0]["error_class"] == "execution_failed"


def prepare_interrupted_pause(executor):
    from steward.core.backups import Binding

    registry = json.loads(executor.registry_file.read_text())
    spec = registry["projects"]["notes"]
    executor.save_backup_pause(
        server.BackupPause(
            binding=Binding(
                server=registry["server_name"],
                project="notes",
                config_revision=registry["config_revision"],
                image=spec["image"],
                source_revision=spec["source_revision"],
            ),
            user=spec["user"],
            unit=spec["unit"],
            artifact="a" * 32,
            prepared_at=time.time(),
        )
    )
    executor.host.units["notes.service"] = "inactive"
    return registry


def test_intent_survives_sigkill_and_fresh_executor_recovers(capture_host):
    executor, _data = capture_host

    # Start a fresh interpreter; never fork a multithreaded pytest process.
    code = """
import json, os, signal, sys, time, uuid
from steward.executor.host import Host
from steward.executor.server import Executor
class CrashHost(Host):
    def user_unit(self, *_):
        return {"load": "loaded", "active": "active"}
    def set_user_unit(self, *_, running):
        assert not running
        os.kill(os.getpid(), signal.SIGKILL)
ex = Executor(registry_path=sys.argv[1], state_dir=sys.argv[2],
              audit_path=sys.argv[3], lock_dir=sys.argv[4], host=CrashHost())
ex.handle(json.dumps({"v": 1, "action": "backup_capture", "params": {"project_id": "notes"},
                      "request_id": uuid.uuid4().hex, "expires_at": time.time()+60}).encode(), 0)
raise SystemExit("capture did not reach crash boundary")
"""
    process = subprocess.run(
        [
            sys.executable,
            "-c",
            code,
            executor.registry_path,
            os.path.dirname(executor._db_path),
            str(executor.audit.path),
            str(executor.lock_dir),
        ],
        capture_output=True,
        timeout=15,
        check=False,
        env={
            "PATH": "/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(Path(server.__file__).resolve().parents[2]),
        },
    )
    assert process.returncode == -signal.SIGKILL
    fresh = server.Executor(
        registry_path=executor.registry_path,
        state_dir=os.path.dirname(executor._db_path),
        audit_path=str(executor.audit.path),
        lock_dir=str(executor.lock_dir),
        host=executor.host,
    )
    assert fresh.backup_pause("notes") is not None
    executor.host.units["notes.service"] = "inactive"
    fresh.recover_backup_pauses()
    assert fresh.backup_pause("notes") is None
    assert executor.host.units["notes.service"] == "active"
    assert executor.host.calls == [("set", True)]
    # Repeated startup recovery does not restart an already recovered workload.
    fresh.recover_backup_pauses()
    assert executor.host.calls == [("set", True)]


@pytest.mark.parametrize("change", ["revision", "disabled", "stopped", "user"])
def test_recovery_keeps_intent_when_original_contract_changed(capture_host, change):
    executor, _data = capture_host
    registry = prepare_interrupted_pause(executor)
    if change == "revision":
        registry["config_revision"] = "0" * 64
    elif change == "disabled":
        registry["projects"]["notes"]["allow_backup_pause"] = False
    elif change == "stopped":
        registry["projects"]["notes"]["deploy"] = False
    else:
        registry["projects"]["notes"]["user"] = "stw-other"
    executor.registry_file.write_text(json.dumps(registry))
    executor.recover_backup_pauses()
    assert executor.backup_pause("notes") is not None
    assert not executor.host.calls


def test_automatic_recovery_respects_kill_switch_but_operator_may_resume(capture_host):
    executor, _data = capture_host
    registry = prepare_interrupted_pause(executor)
    executor.host.killed = True
    executor.recover_backup_pauses()
    assert executor.backup_pause("notes") is not None and not executor.host.calls
    result = executor.recover_backup_pause("notes", registry, automatic=False)
    assert result["resumed"] and executor.backup_pause("notes") is None


def test_pending_recovery_blocks_capture_and_ordinary_restarts(capture_host):
    executor, _data = capture_host
    registry = prepare_interrupted_pause(executor)
    assert executor.handle(request(), 0)["error_class"] == "unavailable"
    with pytest.raises(server.ExecutorError, match="recovery is pending"):
        server.workload_restart(
            executor, server.RestartParams(project_id="notes", reason="retry"), "operator", registry
        )
    assert not executor.host.calls


def test_recovery_action_is_operator_only_and_never_claims_a_backup_upload(capture_host):
    executor, _data = capture_host
    prepare_interrupted_pause(executor)
    raw = json.loads(request())
    raw["action"] = "backup_recover"
    assert executor.handle(json.dumps(raw).encode(), os.getuid())["error_class"] == "forbidden_role"
    raw["request_id"] = uuid.uuid4().hex
    result = executor.handle(json.dumps(raw).encode(), 0)
    assert result["ok"] and result["result"] == {
        "project_id": "notes",
        "pending": False,
        "resumed": True,
    }


def test_pending_recovery_is_observed_without_ordinary_controller_restart(capture_host):
    from steward.controller import evaluate

    executor, _data = capture_host
    prepare_interrupted_pause(executor)
    status = executor.handle(
        json.dumps(
            {
                "v": 1,
                "action": "platform_status",
                "request_id": uuid.uuid4().hex,
            }
        ).encode(),
        0,
    )["result"]
    findings = evaluate(status, {})
    pending = next(f for f in findings if f.id == "backup_pause:notes")
    assert pending.severity == "info" and not pending.remediation
    status["checked_at"] += 301
    pending = next(f for f in evaluate(status, {}) if f.id == "backup_pause:notes")
    assert pending.severity == "high" and not pending.remediation


def test_policy_change_during_capture_prevents_stale_resume_and_can_be_acknowledged(
    capture_host, monkeypatch
):
    from steward.core import filebackups

    executor, _data = capture_host
    original = filebackups.capture_files

    def change_policy(*args, **kwargs):
        manifest = original(*args, **kwargs)
        registry = json.loads(executor.registry_file.read_text())
        registry["config_revision"] = "0" * 64
        registry["projects"]["notes"]["deploy"] = False
        executor.registry_file.write_text(json.dumps(registry))
        return manifest

    monkeypatch.setattr(filebackups, "capture_files", change_policy)
    result = executor.handle(request(), 0)
    assert result["error_class"] == "policy_denied"
    assert executor.host.calls == [("set", False)]
    assert executor.backup_pause("notes") is not None
    registry = json.loads(executor.registry_file.read_text())
    result = executor.recover_backup_pause("notes", registry, automatic=False, accept_current=True)
    assert result["accepted_current"] and not result["resumed"]
    assert executor.backup_pause("notes") is None
    assert executor.host.calls == [("set", False)]


def test_accept_current_never_starts_an_inactive_desired_running_workload(capture_host):
    executor, _data = capture_host
    registry = prepare_interrupted_pause(executor)
    with pytest.raises(server.ExecutorError, match="does not match"):
        executor.recover_backup_pause("notes", registry, automatic=False, accept_current=True)
    assert executor.backup_pause("notes") is not None and not executor.host.calls


def test_registered_export_requires_operator_exact_id_and_pending_recovery_clearance(
    capture_host, tmp_path, monkeypatch
):
    executor, _data = capture_host
    captured = executor.handle(request(), 0)["result"]
    root = tmp_path / "imports"
    root.mkdir(mode=0o750)
    root.chmod(0o750)
    monkeypatch.setattr(server, "BACKUP_IMPORT_ROOT", root)
    executor.host.backup_group = os.getgid
    raw = json.loads(request(artifact=captured["artifact"], capture_id=captured["capture_id"]))
    raw["action"] = "backup_export"
    assert executor.handle(json.dumps(raw).encode(), os.getuid())["error_class"] == "forbidden_role"
    previous_mask = os.umask(0o077)
    try:
        result = executor.handle(json.dumps(raw).encode(), 0)
    finally:
        os.umask(previous_mask)
    assert result["ok"] and result["result"]["uploaded"] is False
    imported = root / "notes" / captured["artifact"]
    assert load_capture(imported).id == captured["capture_id"]
    prepare_interrupted_pause(executor)
    raw["request_id"] = uuid.uuid4().hex
    assert executor.handle(json.dumps(raw).encode(), 0)["error_class"] == "unavailable"
    assert load_capture(imported).id == captured["capture_id"]


def test_export_rejects_caller_path_traversal(capture_host):
    executor, _data = capture_host
    raw = json.loads(request(artifact="../../etc", capture_id="a" * 64))
    raw["action"] = "backup_export"
    assert executor.handle(json.dumps(raw).encode(), 0)["error_class"] == "bad_request"


@pytest.fixture
def scheduled(capture_host, tmp_path, monkeypatch):
    executor, data = capture_host
    registry = json.loads(executor.registry_file.read_text())
    registry["peers"]["backup"] = 4444
    registry["backup"] = {"enabled": True, "interval_s": 3600, "max_mib": 1}
    executor.registry_file.write_text(json.dumps(registry))
    imports = tmp_path / "imports"
    imports.mkdir(mode=0o750)
    imports.chmod(0o750)
    monkeypatch.setattr(server, "BACKUP_IMPORT_ROOT", imports)
    executor.host.backup_group = os.getgid
    clock = [time.time()]
    monkeypatch.setattr(server.time, "time", lambda: clock[0])

    def schedule(**params):
        raw = json.loads(request(**params))
        raw["action"] = "backup_schedule"
        return executor.handle(json.dumps(raw).encode(), 4444)

    return executor, data, clock, schedule


def test_scheduled_capture_is_rate_limited_idempotent_and_never_claims_upload(scheduled):
    executor, _data, clock, schedule = scheduled
    first = schedule()
    assert first["ok"]
    assert not first["result"]["uploaded"] and not first["result"]["reused"]
    second = schedule()
    assert second["ok"] and second["result"]["reused"]
    assert second["result"]["capture_id"] == first["result"]["capture_id"]
    assert executor.host.calls == [("set", False), ("set", True)]
    clock[0] += 3601
    third = schedule()
    assert third["ok"] and third["result"]["artifact"] != first["result"]["artifact"]
    assert executor.host.calls == [("set", False), ("set", True)] * 2


def test_automatic_backup_role_cannot_bypass_cadence_with_operator_capture(scheduled):
    executor, _data, _clock, schedule = scheduled
    assert executor.handle(request(), 4444)["error_class"] == "forbidden_role"
    assert schedule(_artifact="a" * 32)["error_class"] == "bad_request"
    assert not executor.host.calls


def test_scheduled_backup_respects_kill_switch_and_disabled_policy(scheduled):
    executor, _data, _clock, schedule = scheduled
    executor.host.killed = True
    assert schedule()["error_class"] == "kill_switch"
    executor.host.killed = False
    registry = json.loads(executor.registry_file.read_text())
    registry["backup"]["enabled"] = False
    executor.registry_file.write_text(json.dumps(registry))
    assert schedule()["error_class"] == "policy_denied"
    assert not executor.host.calls


def test_failed_scheduled_capture_cannot_be_retried_into_repeated_downtime(scheduled):
    executor, data, clock, schedule = scheduled
    (data / "unsafe").symlink_to("/etc/shadow")
    assert schedule()["error_class"] == "execution_failed"
    assert schedule()["error_class"] == "unavailable"  # reconcile incomplete attempt
    assert schedule()["error_class"] == "budget_exhausted"
    assert executor.host.calls == [("set", False), ("set", True)]
    (data / "unsafe").unlink()
    clock[0] += 3601
    assert schedule()["ok"]


def test_failed_export_resumes_without_another_capture_pause(scheduled):
    executor, _data, _clock, schedule = scheduled

    def unavailable():
        raise KeyError("backup identity temporarily unavailable")

    executor.host.backup_group = unavailable
    assert schedule()["error_class"] == "execution_failed"
    executor.host.backup_group = os.getgid
    assert schedule()["ok"]
    assert executor.host.calls == [("set", False), ("set", True)]


def test_interruption_after_capture_recovers_same_artifact_without_another_pause(
    scheduled, monkeypatch
):
    executor, _data, _clock, schedule = scheduled
    original = server.backup_capture
    captured = []

    def interrupt(*args, **kwargs):
        result = original(*args, **kwargs)
        captured.append(result)
        raise SystemExit("controlled process boundary")

    monkeypatch.setattr(server, "backup_capture", interrupt)
    with pytest.raises(SystemExit):
        schedule()
    monkeypatch.setattr(server, "backup_capture", original)
    result = schedule()
    assert result["ok"] and result["result"]["capture_id"] == captured[0]["capture_id"]
    assert result["result"]["artifact"] == captured[0]["artifact"]
    assert executor.host.calls == [("set", False), ("set", True)]


def test_invalid_persisted_schedule_cannot_supply_a_path_or_new_capture(scheduled):
    executor, _data, _clock, schedule = scheduled
    assert schedule()["ok"]
    with executor._db() as db:
        raw = json.loads(
            db.execute("SELECT body FROM backup_schedule WHERE project='notes'").fetchone()[0]
        )
        raw["artifact"] = "../../escape"
        db.execute("UPDATE backup_schedule SET body=? WHERE project='notes'", (json.dumps(raw),))
    assert schedule()["error_class"] == "internal"
    assert executor.host.calls == [("set", False), ("set", True)]


def test_schedule_keeps_cadence_across_clock_rollback(scheduled):
    executor, _data, clock, schedule = scheduled
    first = schedule()["result"]
    clock[0] -= 7200
    second = schedule()["result"]
    assert second["reused"] and first["artifact"] == second["artifact"]
    assert second["next_capture_at"] == first["next_capture_at"]
    assert executor.host.calls == [("set", False), ("set", True)]


def test_capacity_failure_before_pause_can_retry_without_consuming_pause_budget(
    scheduled, monkeypatch
):
    executor, _data, _clock, schedule = scheduled
    registry = json.loads(executor.registry_file.read_text())
    registry["backup"]["max_mib"] = 1024
    executor.registry_file.write_text(json.dumps(registry))
    monkeypatch.setattr(server.shutil, "disk_usage", lambda _: SimpleNamespace(free=800 * 1024**2))
    assert schedule()["error_class"] == "unavailable"
    assert not executor.host.calls
    monkeypatch.setattr(server.shutil, "disk_usage", lambda _: SimpleNamespace(free=20 * 1024**3))
    assert schedule()["ok"]
    assert executor.host.calls == [("set", False), ("set", True)]


@pytest.mark.parametrize(
    "response",
    [
        (0, "[]", True),
        (0, '[{"State":"exited"}]', True),
        (0, '[{"State":"running"}]', False),
        (0, '[{"State":"unknown"}]', False),
        (0, "null", False),
        (1, "unavailable", False),
    ],
)
def test_real_host_quiescence_requires_successful_stopped_container_inventory(response):
    code, body, expected = response
    host = Host()
    host.user_unit = lambda *_: {"load": "loaded", "active": "inactive"}
    host._as_user = lambda *_: (code, body)
    assert host.workload_quiescent("stw-notes", "notes.service") is expected


def test_scheduler_lost_response_reuses_root_capture_without_another_pause(scheduled, tmp_path):
    from steward.backupscheduler import ScheduleConfig, Scheduler
    from steward.backupworker import Imports
    from steward.executor.protocol import ExecutorError

    executor, _data, clock, schedule = scheduled
    registry = json.loads(executor.registry_file.read_text())
    config = ScheduleConfig(
        enabled=True,
        interval_s=3600,
        max_mib=1,
        endpoint={"host": "backup.test", "addresses": ["192.0.2.1"]},
        config_revision=registry["config_revision"],
        projects=["notes"],
        credentials=["repository", "password"],
    )
    calls = []

    def request(_action, _params, *, timeout):
        result = schedule()
        assert result["ok"]
        calls.append(result["result"])
        if len(calls) == 1:
            raise ExecutorError("unavailable", "response lost")
        return result["result"]

    state = tmp_path / "scheduler.db"
    imports = Imports(server.BACKUP_IMPORT_ROOT, owner_uid=os.getuid())
    scheduler = Scheduler(config, imports, state, clock=lambda: clock[0], request=request)
    assert scheduler.tick() == {"notes": "unavailable"}
    clock[0] += 60
    restarted = Scheduler(config, imports, state, clock=lambda: clock[0], request=request)
    assert restarted.tick() == {"notes": "scheduled"}
    assert calls[1]["reused"] and calls[0]["capture_id"] == calls[1]["capture_id"]
    assert executor.host.calls == [("set", False), ("set", True)]


def test_retention_metadata_is_operator_only_and_preserves_partial_objects(scheduled):
    executor, _data, _clock, schedule = scheduled
    assert schedule()["ok"]
    captures = Path(executor._db_path).parent / "captures" / "notes"
    captures.parent.chmod(0o700)
    partial = captures / ("f" * 32)
    partial.mkdir(mode=0o700)
    (partial / "data.tar").write_bytes(b"unfinished")
    unknown = captures / "unrecognized"
    unknown.mkdir(mode=0o700)
    raw = json.loads(request())
    raw["action"] = "backup_retention_status"
    assert executor.handle(json.dumps(raw).encode(), 4444)["error_class"] == "forbidden_role"
    result = executor.handle(json.dumps(raw).encode(), 0)
    assert result["ok"]
    data = result["result"]
    assert data["captures"]["unknown"] == 1
    assert {item["state"] for item in data["captures"]["items"]} == {
        "metadata_only",
        "protected_unknown",
    }
    assert data["imports"]["items"][0]["state"] == "metadata_only"
    assert data["imports"]["items"][0]["upload_protection"] == "pending"
    protected = [item for item in data["captures"]["items"] if item["state"] == "metadata_only"]
    assert protected[0]["upload_protection"] == "pending"
    assert partial.exists() and unknown.exists()
    assert "path" not in json.dumps(data)


def test_retention_metadata_fails_closed_for_foreign_parent(scheduled):
    executor, _data, _clock, schedule = scheduled
    assert schedule()["ok"]
    captures = Path(executor._db_path).parent / "captures" / "notes"
    captures.parent.chmod(0o700)
    captures.chmod(0o777)
    raw = json.loads(request())
    raw["action"] = "backup_retention_status"
    result = executor.handle(json.dumps(raw).encode(), 0)
    assert result["error_class"] == "unavailable"
    assert list(captures.iterdir())


def test_retention_metadata_rejects_links_and_bounds_unknown_objects(scheduled, tmp_path):
    executor, _data, _clock, schedule = scheduled
    first = schedule()["result"]
    root = Path(executor._db_path).parent / "captures"
    root.chmod(0o700)
    spool = root / "notes"
    artifact = spool / first["artifact"]
    archive = artifact / "data.tar"
    outside = tmp_path / "external-data"
    archive.rename(outside)
    archive.symlink_to(outside)
    raw = json.loads(request())
    raw["action"] = "backup_retention_status"
    result = executor.handle(json.dumps(raw).encode(), 0)["result"]
    assert result["captures"]["items"] == [
        {
            "artifact": first["artifact"],
            "state": "protected_unknown",
            "upload_protection": "unknown",
        }
    ]
    for index in range(9):
        (spool / f"unknown-{index}").mkdir()
    result = executor.handle(json.dumps(raw).encode(), 0)["result"]
    assert result["captures"]["at_capacity"] is True
    assert result["captures"]["truncated"] is False
    (spool / "unknown-9").mkdir()
    result = executor.handle(json.dumps(raw).encode(), 0)["result"]
    assert result["captures"]["truncated"] is True
    assert result["captures"]["at_capacity"] is True
    assert result["captures"]["items"] == []
    assert outside.exists() and archive.is_symlink()


def retention_ack_request(artifact, capture_id, **extra):
    raw = json.loads(request())
    raw["action"] = "backup_retention_ack"
    raw["params"].update(artifact=artifact, capture_id=capture_id, **extra)
    return json.dumps(raw).encode()


def test_retention_ack_is_root_owned_exact_and_never_deletes(capture_host, monkeypatch, tmp_path):
    executor, _data = capture_host
    capture = executor.handle(request(), 0)["result"]
    artifact, capture_id = capture["artifact"], capture["capture_id"]
    root = Path(executor._db_path).parent / "captures"
    root.chmod(0o700)
    monkeypatch.setattr(server, "BACKUP_IMPORT_ROOT", tmp_path / "no-imports")
    path = root / "notes" / artifact
    no_ack = retention_ack_request(artifact, capture_id)
    assert executor.handle(no_ack, 0)["error_class"] == "bad_request"
    request_ack = lambda: retention_ack_request(  # noqa: E731
        artifact, capture_id, acknowledge_removal=True
    )
    assert executor.handle(request_ack(), os.getuid())["error_class"] == "forbidden_role"
    wrong = retention_ack_request(artifact, "a" * 64, acknowledge_removal=True)
    assert executor.handle(wrong, 0)["error_class"] == "unavailable"
    manifest = load_capture(path)
    spec = json.loads(executor.registry_file.read_text())["projects"]["notes"]
    executor.save_backup_pause(
        server.BackupPause(
            binding=manifest.binding,
            user=spec["user"],
            unit=spec["unit"],
            artifact=artifact,
            prepared_at=time.time(),
        )
    )
    assert executor.handle(request_ack(), 0)["error_class"] == "policy_denied"
    executor.clear_backup_pause("notes")
    result = executor.handle(request_ack(), 0)
    assert result["ok"]
    assert result["result"]["deleted"] is False
    assert result["result"]["cleanup_authorized"] is False
    with executor._db() as db:
        row = db.execute("SELECT project, artifact, capture_id FROM backup_removal_ack").fetchone()
    assert row == ("notes", artifact, capture_id)
    assert path.is_dir() and (path / "data.tar").is_file()
    assert executor.audit.read()[-1]["action"] == "backup_retention_ack"
    executor = server.Executor(
        registry_path=executor.registry_path,
        state_dir=str(Path(executor._db_path).parent),
        audit_path=str(executor.audit.path),
        lock_dir=str(executor.lock_dir),
        host=executor.host,
    )
    status = json.loads(request())
    status["action"] = "backup_retention_status"
    listing = executor.handle(json.dumps(status).encode(), 0)["result"]
    assert (
        listing["captures"]["items"][0]["removal_acknowledged_at"]
        == result["result"]["acknowledged_at"]
    )
    revoke = json.loads(retention_ack_request(artifact, capture_id))
    revoke["action"] = "backup_retention_revoke"
    assert (
        executor.handle(json.dumps(revoke).encode(), os.getuid())["error_class"] == "forbidden_role"
    )
    assert executor.handle(json.dumps(revoke).encode(), 0)["result"]["revoked"] is True
    revoke["request_id"] = uuid.uuid4().hex
    assert executor.handle(json.dumps(revoke).encode(), 0)["result"]["revoked"] is False
    with executor._db() as db:
        assert db.execute("SELECT COUNT(*) FROM backup_removal_ack").fetchone()[0] == 0
    assert path.is_dir()


def test_retention_ack_rejects_changed_capture_and_current_schedule(scheduled):
    executor, _data, _clock, schedule = scheduled
    first = schedule()["result"]
    root = Path(executor._db_path).parent / "captures"
    root.chmod(0o700)
    raw = retention_ack_request(first["artifact"], first["capture_id"], acknowledge_removal=True)
    assert executor.handle(raw, 0)["error_class"] == "policy_denied"
    with executor._db() as db:
        db.execute("DELETE FROM backup_schedule WHERE project=?", ("notes",))
    archive = root / "notes" / first["artifact"] / "data.tar"
    archive.write_bytes(b"changed")
    raw = retention_ack_request(first["artifact"], first["capture_id"], acknowledge_removal=True)
    assert executor.handle(raw, 0)["error_class"] == "unavailable"
    with executor._db() as db:
        assert db.execute("SELECT COUNT(*) FROM backup_removal_ack").fetchone()[0] == 0
    assert archive.read_bytes() == b"changed"


def test_export_records_pending_before_publication_and_survives_retry(
    capture_host, tmp_path, monkeypatch
):
    from steward.core import backupexport

    executor, _data = capture_host
    captured = executor.handle(request(), 0)["result"]
    imports = tmp_path / "imports"
    imports.mkdir(mode=0o750)
    imports.chmod(0o750)
    monkeypatch.setattr(server, "BACKUP_IMPORT_ROOT", imports)
    executor.host.backup_group = os.getgid
    raw = json.loads(request(artifact=captured["artifact"], capture_id=captured["capture_id"]))
    raw["action"] = "backup_export"
    original_usage = backupexport.shutil.disk_usage
    monkeypatch.setattr(backupexport.shutil, "disk_usage", lambda _: SimpleNamespace(free=0))
    assert executor.handle(json.dumps(raw).encode(), 0)["error_class"] == "execution_failed"
    assert not (imports / "notes" / captured["artifact"]).exists()
    with executor._db() as db:
        original = db.execute(
            "SELECT project, artifact, capture_id, registered_at FROM backup_upload_protection"
        ).fetchone()
    assert original[:3] == ("notes", captured["artifact"], captured["capture_id"])
    with executor._db() as db:
        db.execute("UPDATE backup_upload_protection SET capture_id=?", ("a" * 64,))
    raw["request_id"] = uuid.uuid4().hex
    assert executor.handle(json.dumps(raw).encode(), 0)["error_class"] == "execution_failed"
    assert not (imports / "notes" / captured["artifact"]).exists()
    with executor._db() as db:
        db.execute("UPDATE backup_upload_protection SET capture_id=?", (captured["capture_id"],))
    monkeypatch.setattr(backupexport.shutil, "disk_usage", original_usage)
    fresh = server.Executor(
        registry_path=executor.registry_path,
        state_dir=str(Path(executor._db_path).parent),
        audit_path=str(executor.audit.path),
        lock_dir=str(executor.lock_dir),
        host=executor.host,
    )
    raw["request_id"] = uuid.uuid4().hex
    assert fresh.handle(json.dumps(raw).encode(), 0)["ok"]
    assert load_capture(imports / "notes" / captured["artifact"]).id == captured["capture_id"]
    with fresh._db() as db:
        assert db.execute(
            "SELECT project, artifact, capture_id, registered_at FROM backup_upload_protection"
        ).fetchall() == [original]


@pytest.fixture
def old_retention_captures(capture_host, tmp_path, monkeypatch):
    executor, _data = capture_host
    now = time.time()
    clock = [now - 10 * 86400]
    monkeypatch.setattr(server.time, "time", lambda: clock[0])
    monkeypatch.setattr(server, "BACKUP_IMPORT_ROOT", tmp_path / "no-imports")
    captures = []
    for _ in range(3):
        result = executor.handle(request(), 0)
        assert result["ok"], result
        captures.append(result["result"])
        clock[0] += 86400
    clock[0] = now
    root = Path(executor._db_path).parent / "captures"
    root.chmod(0o700)
    return executor, root / "notes", captures


def retention_action(action, capture, *, acknowledge=False):
    raw = json.loads(
        retention_ack_request(
            capture["artifact"],
            capture["capture_id"],
            **({"acknowledge_removal": True} if acknowledge else {}),
        )
    )
    raw["action"] = action
    return json.dumps(raw).encode()


def test_retirement_requires_ack_and_preserves_two_newest(old_retention_captures):
    executor, parent, captures = old_retention_captures
    old, middle, newest = captures
    assert (
        executor.handle(retention_action("backup_retention_purge", old), 0)["error_class"]
        == "policy_denied"
    )
    assert executor.handle(retention_action("backup_retention_ack", middle, acknowledge=True), 0)[
        "ok"
    ]
    assert (
        executor.handle(retention_action("backup_retention_purge", middle), 0)["error_class"]
        == "policy_denied"
    )
    assert executor.handle(retention_action("backup_retention_ack", old, acknowledge=True), 0)["ok"]
    result = executor.handle(retention_action("backup_retention_purge", old), 0)
    assert result["ok"], result
    assert result["result"]["outcome"] == "removed"
    assert not (parent / old["artifact"]).exists()
    assert (parent / middle["artifact"]).exists() and (parent / newest["artifact"]).exists()
    with executor._db() as db:
        assert db.execute("SELECT COUNT(*) FROM backup_retirement_intents").fetchone()[0] == 0


def test_retirement_refuses_pending_or_unknown_data(old_retention_captures):
    executor, parent, captures = old_retention_captures
    old = captures[0]
    assert executor.handle(retention_action("backup_retention_ack", old, acknowledge=True), 0)["ok"]
    with executor._db() as db:
        db.execute(
            "INSERT INTO backup_upload_protection VALUES (?, ?, ?, ?, ?, ?)",
            ("notes", old["artifact"], old["capture_id"], "a" * 64, 0, 0),
        )
    assert (
        executor.handle(retention_action("backup_retention_purge", old), 0)["error_class"]
        == "policy_denied"
    )
    with executor._db() as db:
        db.execute("DELETE FROM backup_upload_protection")
    (parent / "unknown").mkdir()
    assert (
        executor.handle(retention_action("backup_retention_purge", old), 0)["error_class"]
        == "unavailable"
    )
    assert (parent / old["artifact"]).exists()


def test_retirement_resumes_after_interruption_under_durable_intent(
    old_retention_captures, monkeypatch
):
    executor, parent, captures = old_retention_captures
    old = captures[0]
    assert executor.handle(retention_action("backup_retention_ack", old, acknowledge=True), 0)["ok"]
    original = os.unlink
    calls = []

    def interrupt(name, *, dir_fd=None):
        calls.append(name)
        if len(calls) == 2:
            raise OSError("injected failure")
        return original(name, dir_fd=dir_fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "unlink", interrupt)
        assert (
            executor.handle(retention_action("backup_retention_purge", old), 0)["error_class"]
            == "unavailable"
        )
    hidden = parent / (".retiring-" + old["artifact"])
    assert hidden.is_dir() and not (parent / old["artifact"]).exists()
    assert (
        executor.handle(retention_action("backup_retention_revoke", old), 0)["error_class"]
        == "policy_denied"
    )
    fresh = server.Executor(
        registry_path=executor.registry_path,
        state_dir=str(Path(executor._db_path).parent),
        audit_path=str(executor.audit.path),
        lock_dir=str(executor.lock_dir),
        host=executor.host,
    )
    result = fresh.handle(retention_action("backup_retention_purge", old), 0)
    assert result["ok"] and result["result"]["outcome"] == "removed"
    assert not hidden.exists()
    assert all((parent / item["artifact"]).exists() for item in captures[1:])


def test_retirement_refuses_existing_import_and_nonoperator(
    old_retention_captures, tmp_path, monkeypatch
):
    from steward.core.backupexport import export_capture

    executor, parent, captures = old_retention_captures
    old = captures[0]
    assert executor.handle(retention_action("backup_retention_ack", old, acknowledge=True), 0)["ok"]
    assert (
        executor.handle(retention_action("backup_retention_purge", old), os.getuid())["error_class"]
        == "forbidden_role"
    )
    imports = tmp_path / "imports"
    imports.mkdir(mode=0o750)
    imports.chmod(0o750)
    project = imports / "notes"
    project.mkdir(mode=0o750)
    project.chmod(0o750)
    export_capture(
        parent / old["artifact"],
        project / old["artifact"],
        capture_id=old["capture_id"],
        gid=os.getgid(),
    )
    monkeypatch.setattr(server, "BACKUP_IMPORT_ROOT", imports)
    executor.host.backup_group = os.getgid
    assert (
        executor.handle(retention_action("backup_retention_purge", old), 0)["error_class"]
        == "unavailable"
    )
    assert (parent / old["artifact"]).exists()
    assert (project / old["artifact"]).exists()


def test_retirement_journal_fences_exports_before_rename(old_retention_captures, monkeypatch):
    from steward.core import backupretire

    executor, parent, captures = old_retention_captures
    old = captures[0]
    assert executor.handle(retention_action("backup_retention_ack", old, acknowledge=True), 0)["ok"]
    with monkeypatch.context() as patch:
        patch.setattr(
            backupretire, "_rename_noreplace", lambda *_: (_ for _ in ()).throw(OSError("failure"))
        )
        assert (
            executor.handle(retention_action("backup_retention_purge", old), 0)["error_class"]
            == "unavailable"
        )
    assert (parent / old["artifact"]).exists()
    assert executor.handle(request(), 0)["error_class"] == "unavailable"
    export = retention_action("backup_export", old)
    assert executor.handle(export, 0)["error_class"] == "unavailable"
    assert (
        executor.handle(retention_action("backup_retention_purge", captures[1]), 0)["error_class"]
        == "policy_denied"
    )
    assert executor.handle(retention_action("backup_retention_purge", old), 0)["ok"]
    assert not (parent / old["artifact"]).exists()


def test_automatic_retirement_recovery_respects_kill_switch_and_backoff(
    old_retention_captures, monkeypatch
):
    from steward.core import backupretire

    executor, parent, captures = old_retention_captures
    old = captures[0]
    assert executor.handle(retention_action("backup_retention_ack", old, acknowledge=True), 0)["ok"]
    with monkeypatch.context() as patch:
        patch.setattr(
            backupretire, "_rename_noreplace", lambda *_: (_ for _ in ()).throw(OSError("failure"))
        )
        assert (
            executor.handle(retention_action("backup_retention_purge", old), 0)["error_class"]
            == "unavailable"
        )
    fresh = server.Executor(
        registry_path=executor.registry_path,
        state_dir=str(Path(executor._db_path).parent),
        audit_path=str(executor.audit.path),
        lock_dir=str(executor.lock_dir),
        host=executor.host,
    )
    with fresh._db() as db:
        db.execute("INSERT INTO backup_retirement_intents VALUES (?, ?)", ("broken", "invalid"))
    recovery = server.RetirementRecovery(fresh)
    fresh.host.killed = True
    recovery.tick(now=0)
    assert (parent / old["artifact"]).exists()
    assert recovery.retries["notes"] == (1, 5)
    fresh.host.killed = False
    recovery.tick(now=4)
    assert (parent / old["artifact"]).exists()
    recovery.tick(now=5)
    assert not (parent / old["artifact"]).exists()
    assert all((parent / item["artifact"]).exists() for item in captures[1:])
    assert "broken" in recovery.retries
    events = [event for event in fresh.audit.read() if event["event"] == "backup_retirement"]
    assert any(event["outcome"] == "kill_switch" for event in events)
    assert any(event["outcome"] == "removed" for event in events)


def test_resume_only_never_starts_a_new_retirement(old_retention_captures):
    executor, parent, captures = old_retention_captures
    old = captures[0]
    assert executor.handle(retention_action("backup_retention_ack", old, acknowledge=True), 0)["ok"]
    params = server.BackupExportParams(
        project_id="notes", artifact=old["artifact"], capture_id=old["capture_id"]
    )
    registry = json.loads(executor.registry_file.read_text())
    result = server.backup_retention_purge(
        executor, params, "retention", registry, _resume_only=True
    )
    assert result["outcome"] == "already_resolved"
    assert (parent / old["artifact"]).exists()


def test_automatic_recovery_fails_closed_on_pending_or_unavailable_audit(
    old_retention_captures, monkeypatch
):
    from steward.core import backupretire

    executor, parent, captures = old_retention_captures
    old = captures[0]
    assert executor.handle(retention_action("backup_retention_ack", old, acknowledge=True), 0)["ok"]
    with monkeypatch.context() as patch:
        patch.setattr(
            backupretire, "_rename_noreplace", lambda *_: (_ for _ in ()).throw(OSError("failure"))
        )
        assert (
            executor.handle(retention_action("backup_retention_purge", old), 0)["error_class"]
            == "unavailable"
        )
    recovery = server.RetirementRecovery(executor)
    with monkeypatch.context() as patch:
        patch.setattr(
            executor.audit, "append", lambda *_args, **_kw: (_ for _ in ()).throw(OSError("full"))
        )
        recovery.tick(now=0)
    assert (parent / old["artifact"]).exists()
    with executor._db() as db:
        db.execute(
            "INSERT INTO backup_upload_protection VALUES (?, ?, ?, ?, ?, ?)",
            ("notes", old["artifact"], old["capture_id"], "a" * 64, 0, 0),
        )
    recovery.tick(now=5)
    assert (parent / old["artifact"]).exists()
    assert recovery.retries["notes"] == (2, 15)
    with executor._db() as db:
        db.execute("DELETE FROM backup_upload_protection")
    recovery.tick(now=15)
    assert not (parent / old["artifact"]).exists()


def test_executor_service_starts_retirement_recovery(old_retention_captures, monkeypatch):
    import threading

    from steward.core import backupretire

    executor, parent, captures = old_retention_captures
    old = captures[0]
    assert executor.handle(retention_action("backup_retention_ack", old, acknowledge=True), 0)["ok"]
    with monkeypatch.context() as patch:
        patch.setattr(
            backupretire, "_rename_noreplace", lambda *_: (_ for _ in ()).throw(OSError("failure"))
        )
        assert (
            executor.handle(retention_action("backup_retention_purge", old), 0)["error_class"]
            == "unavailable"
        )
    recovered = threading.Event()
    original_tick = server.RetirementRecovery.tick

    def tick_then_signal(self):
        try:
            original_tick(self)
        finally:
            recovered.set()

    class FakeSocketServer:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def serve_forever(self):
            assert recovered.wait(5)

    monkeypatch.setattr(server.RetirementRecovery, "tick", tick_then_signal)
    monkeypatch.setattr(server.ipc, "bind", lambda *_args: FakeSocketServer())
    server.serve(executor, "unused", None)
    assert not (parent / old["artifact"]).exists()
    assert all((parent / item["artifact"]).exists() for item in captures[1:])


def test_retirement_recovery_refuses_import_that_appeared_after_intent(
    old_retention_captures, tmp_path, monkeypatch
):
    from steward.core import backupretire
    from steward.core.backupexport import export_capture

    executor, parent, captures = old_retention_captures
    old = captures[0]
    assert executor.handle(retention_action("backup_retention_ack", old, acknowledge=True), 0)["ok"]
    with monkeypatch.context() as patch:
        patch.setattr(
            backupretire, "_rename_noreplace", lambda *_: (_ for _ in ()).throw(OSError("failure"))
        )
        assert (
            executor.handle(retention_action("backup_retention_purge", old), 0)["error_class"]
            == "unavailable"
        )
    imports = tmp_path / "late-imports"
    imports.mkdir(mode=0o750)
    imports.chmod(0o750)
    project = imports / "notes"
    project.mkdir(mode=0o750)
    project.chmod(0o750)
    export_capture(
        parent / old["artifact"],
        project / old["artifact"],
        capture_id=old["capture_id"],
        gid=os.getgid(),
    )
    monkeypatch.setattr(server, "BACKUP_IMPORT_ROOT", imports)
    executor.host.backup_group = os.getgid
    recovery = server.RetirementRecovery(executor)
    recovery.tick(now=0)
    assert (parent / old["artifact"]).exists()
    assert (project / old["artifact"]).exists()
    assert recovery.retries["notes"] == (1, 5)


def test_full_backup_capacity_is_observed_and_refusal_emits_immediate_event(scheduled):
    from steward.collector import audit_events
    from steward.controller import evaluate

    executor, _data, _clock, schedule = scheduled
    spool = Path(executor._db_path).parent / "captures" / "notes"
    spool.mkdir(mode=0o700, parents=True)
    spool.parent.chmod(0o700)
    for index in range(10):
        (spool / f"{index:032x}").mkdir(mode=0o700)
    registry = json.loads(executor.registry_file.read_text())
    status = server.platform_status(executor, server.NoParams(), "controller", registry)
    assert "capture_limit" in status["backup_capacity"]["notes"]["reasons"]
    findings = evaluate(status, {})
    finding = next(item for item in findings if item.id == "backup_capacity:notes:capture_limit")
    assert finding.severity == "high" and finding.remediation is None
    remote = next(item for item in findings if item.id == "backup_capacity:notes:remote_unknown")
    assert remote.severity == "warning" and remote.remediation is None
    assert schedule()["error_class"] == "unavailable"
    assert executor.host.calls == []
    capacity = next(
        item for item in reversed(executor.audit.read()) if item["event"] == "backup_capacity"
    )
    (event,) = audit_events(capacity)
    assert event.kind == "backup.capacity" and event.delivery == "immediate"
    assert event.project == "notes" and event.data == {"namespace": "capture", "reason": "limit"}


def test_capacity_marks_unsafe_or_low_space_as_unknown_or_refused(scheduled, tmp_path, monkeypatch):
    executor, _data, _clock, schedule = scheduled
    registry = json.loads(executor.registry_file.read_text())
    capture_root = Path(executor._db_path).parent / "captures"
    capture_root.symlink_to(tmp_path, target_is_directory=True)
    status = server.platform_status(executor, server.NoParams(), "controller", registry)
    assert "capture_unknown" in status["backup_capacity"]["notes"]["reasons"]
    capture_root.unlink()
    capture_root.mkdir(mode=0o700)
    monkeypatch.setattr(server.shutil, "disk_usage", lambda _: SimpleNamespace(free=0))
    status = server.platform_status(executor, server.NoParams(), "controller", registry)
    assert set(status["backup_capacity"]["notes"]["reasons"]) >= {"capture_space", "import_space"}
    assert schedule()["error_class"] == "unavailable"
    event = next(
        item for item in reversed(executor.audit.read()) if item["event"] == "backup_capacity"
    )
    assert event["namespace"] == "capture" and event["reason"] == "space"
    registry["backup"]["enabled"] = False
    assert server.backup_capacity(executor, registry) == {}


def test_full_import_refusal_emits_capacity_event_without_repeated_pause(scheduled):
    from steward.collector import audit_events

    executor, _data, _clock, schedule = scheduled
    project = server.BACKUP_IMPORT_ROOT / "notes"
    project.mkdir(mode=0o750)
    project.chmod(0o750)
    for index in range(10):
        (project / f"{index:032x}").mkdir(mode=0o550)
    first = schedule()
    assert first["error_class"] == "execution_failed"
    second = schedule()
    assert second["error_class"] == "execution_failed"
    assert executor.host.calls == [("set", False), ("set", True)]
    entry = next(
        item for item in reversed(executor.audit.read()) if item["event"] == "backup_capacity"
    )
    (event,) = audit_events(entry)
    assert event.delivery == "immediate"
    assert event.data == {"namespace": "import", "reason": "limit"}
    registry = json.loads(executor.registry_file.read_text())
    status = server.platform_status(executor, server.NoParams(), "controller", registry)
    assert "import_limit" in status["backup_capacity"]["notes"]["reasons"]


def test_managed_upload_permit_binds_root_registration_and_cancellation(scheduled):
    executor, _data, _clock, schedule = scheduled
    capture = schedule()["result"]
    raw = json.loads(retention_ack_request(capture["artifact"], capture["capture_id"]))
    raw["action"] = "backup_upload_permit"
    result = executor.handle(json.dumps(raw).encode(), 4444)
    assert result["result"] == {"permitted": True, "reason": "registered"}
    raw["params"]["capture_id"] = "f" * 64
    assert executor.handle(json.dumps(raw).encode(), 4444)["result"] == {
        "permitted": False,
        "reason": "unavailable",
    }
    raw["params"]["capture_id"] = capture["capture_id"]
    with executor._db() as db:
        db.execute(
            "INSERT INTO backup_upload_cancellations VALUES (?, ?, ?, ?)",
            ("notes", capture["artifact"], capture["capture_id"], time.time()),
        )
    assert executor.handle(json.dumps(raw).encode(), 4444)["result"] == {
        "permitted": False,
        "reason": "cancelled",
    }
    registry = json.loads(executor.registry_file.read_text())
    registry["backup"]["enabled"] = False
    executor.registry_file.write_text(json.dumps(registry))
    assert executor.handle(json.dumps(raw).encode(), 4444)["result"] == {
        "permitted": False,
        "reason": "unavailable",
    }


@pytest.mark.parametrize(
    "changes,expected",
    [
        ({}, True),
        ({"LoadState": "not-found"}, False),
        ({"ActiveState": "active", "SubState": "running"}, False),
        ({"MainPID": "10"}, False),
        ({"ControlGroup": "/system.slice/steward-backup.service"}, False),
        ({"KillMode": "process"}, False),
        ({"SubState": "unknown"}, False),
        ({"ActiveState": "failed", "SubState": "failed"}, True),
    ],
)
def test_backup_worker_stop_requires_loaded_empty_control_group(changes, expected):
    host = Host()
    properties = {
        "LoadState": "loaded",
        "ActiveState": "inactive",
        "SubState": "dead",
        "MainPID": "0",
        "ControlGroup": "",
        "KillMode": "control-group",
    }
    properties.update(changes)
    host._run = lambda *_args, **_kwargs: (
        0,
        "\n".join(f"{key}={value}" for key, value in properties.items()),
    )
    assert host.backup_worker_stopped() is expected


def upload_transition(action, capture, *, acknowledge=False):
    raw = json.loads(
        retention_ack_request(
            capture["artifact"],
            capture["capture_id"],
            **({"acknowledge_abandonment": True} if acknowledge else {}),
        )
    )
    raw["action"] = action
    return json.dumps(raw).encode()


def test_cancel_and_reinstate_are_operator_only_fenced_and_never_delete(scheduled):
    executor, _data, _clock, schedule = scheduled
    capture = schedule()["result"]
    path = server.BACKUP_IMPORT_ROOT / "notes" / capture["artifact"]
    executor.host.backup_worker_stopped = lambda: False
    assert (
        executor.handle(upload_transition("backup_upload_cancel", capture, acknowledge=True), 4444)[
            "error_class"
        ]
        == "forbidden_role"
    )
    assert (
        executor.handle(upload_transition("backup_upload_cancel", capture), 0)["error_class"]
        == "bad_request"
    )
    assert (
        executor.handle(upload_transition("backup_upload_cancel", capture, acknowledge=True), 0)[
            "error_class"
        ]
        == "policy_denied"
    )
    executor.host.backup_worker_stopped = lambda: True
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        assert (
            executor.handle(
                upload_transition("backup_upload_cancel", capture, acknowledge=True), 0
            )["error_class"]
            == "target_busy"
        )
    finally:
        os.close(fd)
    result = executor.handle(
        upload_transition("backup_upload_cancel", capture, acknowledge=True), 0
    )
    assert result["ok"], result
    assert result["result"]["cancelled"] is True
    assert result["result"]["deleted"] is False and result["result"]["cleanup_authorized"] is False
    (Path(executor._db_path).parent / "captures").chmod(0o700)
    status = json.loads(request())
    status["action"] = "backup_retention_status"
    inventory = executor.handle(json.dumps(status).encode(), 0)["result"]
    assert inventory["imports"]["items"][0]["upload_protection"] == "cancelled"
    permit = upload_transition("backup_upload_permit", capture)
    assert executor.handle(permit, 4444)["result"] == {"permitted": False, "reason": "cancelled"}
    with executor._db() as db:
        assert db.execute("SELECT COUNT(*) FROM backup_upload_protection").fetchone()[0] == 1
    assert path.is_dir()
    result = executor.handle(upload_transition("backup_upload_reinstate", capture), 0)
    assert result["ok"] and result["result"]["cancelled"] is False
    assert executor.handle(permit, 4444)["result"] == {"permitted": True, "reason": "registered"}
    assert path.is_dir()


def test_cancel_rejects_changed_binding_or_stop_state_race(scheduled):
    executor, _data, _clock, schedule = scheduled
    capture = schedule()["result"]
    states = iter([True, False])
    executor.host.backup_worker_stopped = lambda: next(states)
    assert (
        executor.handle(upload_transition("backup_upload_cancel", capture, acknowledge=True), 0)[
            "error_class"
        ]
        == "unavailable"
    )
    executor.host.backup_worker_stopped = lambda: True
    with executor._db() as db:
        db.execute("UPDATE backup_upload_protection SET capture_id=?", ("f" * 64,))
    assert (
        executor.handle(upload_transition("backup_upload_cancel", capture, acknowledge=True), 0)[
            "error_class"
        ]
        == "unavailable"
    )
    with executor._db() as db:
        assert db.execute("SELECT COUNT(*) FROM backup_upload_cancellations").fetchone()[0] == 0


@pytest.fixture
def cancelled_old_import(old_retention_captures, tmp_path, monkeypatch):
    executor, spool, captures = old_retention_captures
    old = captures[0]
    imports = tmp_path / "imports-for-retirement"
    imports.mkdir(mode=0o750)
    imports.chmod(0o750)
    monkeypatch.setattr(server, "BACKUP_IMPORT_ROOT", imports)
    executor.host.backup_group = os.getgid
    executor.host.backup_worker_stopped = lambda: True
    raw = retention_action("backup_export", old)
    assert executor.handle(raw, 0)["ok"]
    assert executor.handle(upload_transition("backup_upload_cancel", old, acknowledge=True), 0)[
        "ok"
    ]
    return executor, spool, imports / "notes" / old["artifact"], captures


def import_purge_request(capture, *, acknowledge=True):
    raw = json.loads(retention_action("backup_import_purge", capture))
    if acknowledge:
        raw["params"]["acknowledge_import_removal"] = True
    return json.dumps(raw).encode()


def test_cancelled_import_retirement_preserves_capture_and_tombstone(cancelled_old_import):
    executor, spool, path, captures = cancelled_old_import
    old = captures[0]
    assert (
        executor.handle(import_purge_request(old, acknowledge=False), 0)["error_class"]
        == "bad_request"
    )
    assert (
        executor.handle(import_purge_request(old), os.getuid())["error_class"] == "forbidden_role"
    )
    executor.host.backup_worker_stopped = lambda: False
    assert executor.handle(import_purge_request(old), 0)["error_class"] == "policy_denied"
    executor.host.backup_worker_stopped = lambda: True
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        assert executor.handle(import_purge_request(old), 0)["error_class"] == "target_busy"
    finally:
        os.close(fd)
    result = executor.handle(import_purge_request(old), 0)
    assert result["ok"], result
    assert result["result"]["outcome"] == "removed" and not path.exists()
    assert all((spool / item["artifact"]).exists() for item in captures)
    with executor._db() as db:
        assert db.execute("SELECT COUNT(*) FROM backup_upload_protection").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM backup_upload_cancellations").fetchone()[0] == 1
        assert (
            db.execute("SELECT COUNT(*) FROM backup_import_retirement_intents").fetchone()[0] == 0
        )
    assert (
        executor.handle(retention_action("backup_export", old), 0)["error_class"] == "policy_denied"
    )

    registry = json.loads(executor.registry_file.read_text())
    registry["backup"]["enabled"] = True
    registry["peers"]["backup"] = 4444
    executor.registry_file.write_text(json.dumps(registry))
    permit = executor.handle(upload_transition("backup_upload_permit", old), 4444)
    assert permit["result"] == {"permitted": False, "reason": "cancelled"}


def test_import_retirement_resumes_after_sealing_without_losing_capture(
    cancelled_old_import, monkeypatch
):
    from steward.core import backupretire

    executor, spool, path, captures = cancelled_old_import
    old = captures[0]
    with monkeypatch.context() as patch:
        patch.setattr(
            backupretire, "_rename_noreplace", lambda *_: (_ for _ in ()).throw(OSError("fail"))
        )
        assert executor.handle(import_purge_request(old), 0)["error_class"] == "unavailable"
    assert path.is_dir() and path.stat().st_mode & 0o777 == 0o700
    assert (
        executor.handle(upload_transition("backup_upload_reinstate", old), 0)["error_class"]
        == "policy_denied"
    )
    assert (
        executor.handle(retention_action("backup_export", old), 0)["error_class"] == "unavailable"
    )
    executor.host.backup_worker_stopped = lambda: False
    assert executor.handle(import_purge_request(old), 0)["error_class"] == "policy_denied"
    executor.host.backup_worker_stopped = lambda: True
    fresh = server.Executor(
        registry_path=executor.registry_path,
        state_dir=str(Path(executor._db_path).parent),
        audit_path=str(executor.audit.path),
        lock_dir=str(executor.lock_dir),
        host=executor.host,
    )
    result = fresh.handle(import_purge_request(old), 0)
    assert result["ok"] and result["result"]["outcome"] == "removed"
    assert not path.exists() and (spool / old["artifact"]).exists()


def test_import_retirement_refuses_newest_capture_and_unfinished_upload(
    old_retention_captures, tmp_path, monkeypatch
):
    executor, spool, captures = old_retention_captures
    middle = captures[1]
    imports = tmp_path / "protected-imports"
    imports.mkdir(mode=0o750)
    imports.chmod(0o750)
    monkeypatch.setattr(server, "BACKUP_IMPORT_ROOT", imports)
    executor.host.backup_group = os.getgid
    executor.host.backup_worker_stopped = lambda: True
    assert executor.handle(retention_action("backup_export", middle), 0)["ok"]
    assert executor.handle(import_purge_request(middle), 0)["error_class"] == "policy_denied"
    assert executor.handle(upload_transition("backup_upload_cancel", middle, acknowledge=True), 0)[
        "ok"
    ]
    assert executor.handle(import_purge_request(middle), 0)["error_class"] == "policy_denied"
    assert (imports / "notes" / middle["artifact"]).exists()
    assert all((spool / item["artifact"]).exists() for item in captures)


def test_import_retirement_resumes_after_partial_unlink(cancelled_old_import, monkeypatch):
    executor, spool, path, captures = cancelled_old_import
    old = captures[0]
    original = os.unlink
    calls = []

    def interrupt(name, *, dir_fd=None):
        calls.append(name)
        if len(calls) == 2:
            raise OSError("injected failure")
        return original(name, dir_fd=dir_fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "unlink", interrupt)
        assert executor.handle(import_purge_request(old), 0)["error_class"] == "unavailable"
    hidden = path.parent / (".retiring-" + old["artifact"])
    assert hidden.is_dir() and not path.exists() and (spool / old["artifact"]).exists()
    with executor._db() as db:
        assert db.execute("SELECT COUNT(*) FROM backup_upload_protection").fetchone()[0] == 1
    result = executor.handle(import_purge_request(old), 0)
    assert result["ok"] and not hidden.exists()
    assert (spool / old["artifact"]).exists()


def test_separately_acknowledged_capture_can_be_retired_after_import(cancelled_old_import):
    executor, spool, path, captures = cancelled_old_import
    old = captures[0]
    assert executor.handle(import_purge_request(old), 0)["ok"]
    assert (
        executor.handle(retention_action("backup_retention_purge", old), 0)["error_class"]
        == "policy_denied"
    )
    assert executor.handle(retention_action("backup_retention_ack", old, acknowledge=True), 0)["ok"]
    result = executor.handle(retention_action("backup_retention_purge", old), 0)
    assert result["ok"] and not (spool / old["artifact"]).exists()
    assert not path.exists() and all((spool / item["artifact"]).exists() for item in captures[1:])
    with executor._db() as db:
        assert db.execute("SELECT COUNT(*) FROM backup_upload_cancellations").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM backup_upload_protection").fetchone()[0] == 0
    registry = json.loads(executor.registry_file.read_text())
    registry["backup"]["enabled"] = True
    registry["peers"]["backup"] = 4444
    executor.registry_file.write_text(json.dumps(registry))
    permit = executor.handle(upload_transition("backup_upload_permit", old), 4444)
    assert permit["result"] == {"permitted": False, "reason": "unavailable"}
    assert (
        executor.handle(retention_action("backup_export", old), 0)["error_class"]
        == "execution_failed"
    )


def test_import_retirement_automatic_recovery_obeys_stop_and_kill_switch(
    cancelled_old_import, monkeypatch
):
    from steward.core import backupretire

    executor, spool, path, captures = cancelled_old_import
    old = captures[0]
    with monkeypatch.context() as patch:
        patch.setattr(
            backupretire, "_rename_noreplace", lambda *_: (_ for _ in ()).throw(OSError("fail"))
        )
        assert executor.handle(import_purge_request(old), 0)["error_class"] == "unavailable"
    recovery = server.RetirementRecovery(executor)
    executor.host.killed = True
    recovery.tick(now=0)
    assert path.exists() and recovery.retries["import:notes"] == (1, 5)
    executor.host.killed = False
    executor.host.backup_worker_stopped = lambda: False
    recovery.tick(now=5)
    assert path.exists() and recovery.retries["import:notes"] == (2, 15)
    executor.host.backup_worker_stopped = lambda: True
    recovery.tick(now=15)
    assert not path.exists() and (spool / old["artifact"]).exists()
    with executor._db() as db:
        assert db.execute("SELECT COUNT(*) FROM backup_upload_protection").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM backup_upload_cancellations").fetchone()[0] == 1


def test_upload_permit_fails_closed_while_any_retirement_is_pending(scheduled):
    executor, _data, _clock, schedule = scheduled
    capture = schedule()["result"]
    permit = upload_transition("backup_upload_permit", capture)
    assert executor.handle(permit, 4444)["result"]["permitted"] is True
    with executor._db() as db:
        db.execute(
            "INSERT INTO backup_import_retirement_intents VALUES (?, ?)", ("notes", "invalid")
        )
    assert executor.handle(permit, 4444)["result"] == {"permitted": False, "reason": "unavailable"}


def test_automatic_retention_selects_only_acknowledged_safe_captures(old_retention_captures):
    executor, parent, captures = old_retention_captures
    old = captures[0]
    sweep = server.RetentionSweep(executor)
    sweep.tick()
    assert (parent / old["artifact"]).exists()
    assert executor.handle(retention_action("backup_retention_ack", old, acknowledge=True), 0)["ok"]
    sweep.tick()  # disabled policy is inert even with an acknowledgement
    assert (parent / old["artifact"]).exists()
    registry = json.loads(executor.registry_file.read_text())
    registry["backup"]["enabled"] = True
    executor.registry_file.write_text(json.dumps(registry))
    executor.host.killed = True
    sweep.tick()
    assert (parent / old["artifact"]).exists()
    executor.host.killed = False
    sweep.tick()
    assert not (parent / old["artifact"]).exists()
    assert all((parent / item["artifact"]).exists() for item in captures[1:])
    assert any(
        item["event"] == "backup_retirement" and item["outcome"] == "removed"
        for item in executor.audit.read()
    )


def test_automatic_retention_does_not_authorize_pending_or_recent_data(old_retention_captures):
    executor, parent, captures = old_retention_captures
    old, middle, _newest = captures
    for item in (old, middle):
        assert executor.handle(retention_action("backup_retention_ack", item, acknowledge=True), 0)[
            "ok"
        ]
    registry = json.loads(executor.registry_file.read_text())
    registry["backup"]["enabled"] = True
    executor.registry_file.write_text(json.dumps(registry))
    with executor._db() as db:
        db.execute(
            "INSERT INTO backup_upload_protection VALUES (?, ?, ?, ?, ?, ?)",
            ("notes", old["artifact"], old["capture_id"], "a" * 64, 0, 0),
        )
    sweep = server.RetentionSweep(executor)
    sweep.tick()
    assert (parent / old["artifact"]).exists()
    assert (parent / middle["artifact"]).exists()  # one of the two newest


def test_automatic_retention_rotates_after_a_candidate_failure(old_retention_captures, monkeypatch):
    executor, parent, captures = old_retention_captures
    fourth = executor.handle(request(), 0)["result"]
    old, second = captures[:2]
    for item in (old, second):
        assert executor.handle(retention_action("backup_retention_ack", item, acknowledge=True), 0)[
            "ok"
        ]
    registry = json.loads(executor.registry_file.read_text())
    registry["backup"]["enabled"] = True
    executor.registry_file.write_text(json.dumps(registry))
    original = server.backup_retention_purge
    attempts = []

    def fail_one(ex, params, role, registry, **kwargs):
        attempts.append(params.artifact)
        if params.artifact == old["artifact"]:
            raise server.ExecutorError("unavailable", "transient")
        return original(ex, params, role, registry, **kwargs)

    monkeypatch.setattr(server, "backup_retention_purge", fail_one)
    sweep = server.RetentionSweep(executor)
    sweep.tick(now=0)
    assert (parent / old["artifact"]).exists() and (parent / second["artifact"]).exists()
    sweep.tick(now=299)
    assert attempts == [old["artifact"]]
    sweep.tick(now=300)
    assert attempts == [old["artifact"], second["artifact"]]
    assert (parent / old["artifact"]).exists() and not (parent / second["artifact"]).exists()
    assert (parent / fourth["artifact"]).exists()


def test_automatic_retention_rechecks_ack_and_latest_contract(old_retention_captures, monkeypatch):
    executor, parent, captures = old_retention_captures
    old = captures[0]
    assert executor.handle(retention_action("backup_retention_ack", old, acknowledge=True), 0)["ok"]
    registry = json.loads(executor.registry_file.read_text())
    registry["backup"]["enabled"] = True
    executor.registry_file.write_text(json.dumps(registry))
    original = server.backup_retention_purge

    def revoke_before_purge(ex, params, role, registry, **kwargs):
        with ex._db() as db:
            db.execute("DELETE FROM backup_removal_ack WHERE project=?", (params.project_id,))
        return original(ex, params, role, registry, **kwargs)

    monkeypatch.setattr(server, "backup_retention_purge", revoke_before_purge)
    server.RetentionSweep(executor).tick()
    assert (parent / old["artifact"]).exists()
    assert executor.handle(retention_action("backup_retention_ack", old, acknowledge=True), 0)["ok"]
    registry["projects"]["notes"]["allow_backup_pause"] = False
    params = server.BackupExportParams(
        project_id="notes", artifact=old["artifact"], capture_id=old["capture_id"]
    )
    with pytest.raises(server.ExecutorError, match="automatic backup retention is disabled"):
        original(executor, params, "retention", registry)
    assert (parent / old["artifact"]).exists()


def test_executor_service_starts_acknowledged_retention_sweep(old_retention_captures, monkeypatch):
    import threading

    executor, parent, captures = old_retention_captures
    old = captures[0]
    assert executor.handle(retention_action("backup_retention_ack", old, acknowledge=True), 0)["ok"]
    registry = json.loads(executor.registry_file.read_text())
    registry["backup"]["enabled"] = True
    executor.registry_file.write_text(json.dumps(registry))
    swept = threading.Event()
    original = server.RetentionSweep.tick

    def tick_then_signal(self):
        try:
            original(self)
        finally:
            swept.set()

    class FakeSocketServer:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def serve_forever(self):
            assert swept.wait(5)

    monkeypatch.setattr(server.RetentionSweep, "tick", tick_then_signal)
    monkeypatch.setattr(server.ipc, "bind", lambda *_args: FakeSocketServer())
    server.serve(executor, "unused", None)
    assert not (parent / old["artifact"]).exists()
    assert all((parent / item["artifact"]).exists() for item in captures[1:])


def test_cancellation_metadata_limit_refuses_and_emits_capacity_alert(scheduled):
    from steward.collector import audit_events
    from steward.controller import evaluate

    executor, _data, _clock, schedule = scheduled
    capture = schedule()["result"]
    executor.host.backup_worker_stopped = lambda: True
    with executor._db() as db:
        db.executemany(
            "INSERT INTO backup_upload_cancellations VALUES (?, ?, ?, ?)",
            [
                ("notes", f"{index:032x}", f"{index:064x}", 0)
                for index in range(server.MAX_CANCELLED_UPLOADS)
            ],
        )
    result = executor.handle(
        upload_transition("backup_upload_cancel", capture, acknowledge=True), 0
    )
    assert result["error_class"] == "unavailable"
    path = server.BACKUP_IMPORT_ROOT / "notes" / capture["artifact"]
    assert path.is_dir()
    with executor._db() as db:
        assert (
            db.execute("SELECT COUNT(*) FROM backup_upload_cancellations").fetchone()[0]
            == server.MAX_CANCELLED_UPLOADS
        )
    event = next(
        item for item in reversed(executor.audit.read()) if item["event"] == "backup_capacity"
    )
    (mapped,) = audit_events(event)
    assert mapped.delivery == "immediate" and mapped.data == {
        "namespace": "metadata",
        "reason": "limit",
    }
    root = Path(executor._db_path).parent / "captures"
    root.chmod(0o700)
    registry = json.loads(executor.registry_file.read_text())
    status = server.platform_status(executor, server.NoParams(), "controller", registry)
    finding = next(
        item
        for item in evaluate(status, {})
        if item.id == "backup_capacity:notes:cancellation_limit"
    )
    assert finding.severity == "high" and finding.remediation is None


def test_automatic_retention_bounds_work_per_host_and_rotates_projects(executor, monkeypatch):
    registry = json.loads(executor.registry_file.read_text())
    registry["backup"]["enabled"] = True
    registry["projects"]["alpha"] = dict(registry["projects"]["notes"])
    registry["projects"]["alpha"]["allow_backup_pause"] = True
    registry["projects"]["notes"]["allow_backup_pause"] = True
    executor.registry_file.write_text(json.dumps(registry))
    now = time.time()
    with executor._db() as db:
        for index, project in enumerate(("alpha", "notes"), 1):
            db.execute(
                "INSERT INTO backup_removal_ack VALUES (?, ?, ?, ?, ?, ?)",
                (project, f"{index:032x}", f"{index:064x}", "a" * 64, now - 9 * 86400, now),
            )
    attempts = []

    def fake_purge(_ex, params, _role, _registry, **_kwargs):
        attempts.append(params.project_id)
        if params.project_id == "alpha":
            raise server.ExecutorError("unavailable", "temporary")
        return {"outcome": "removed"}

    monkeypatch.setattr(server, "backup_retention_purge", fake_purge)
    sweep = server.RetentionSweep(executor)
    sweep.tick(wall=now, now=0)
    assert attempts == ["alpha"]
    sweep.tick(wall=now, now=299)
    assert attempts == ["alpha"]
    sweep.tick(wall=now, now=300)
    assert attempts == ["alpha", "notes"]


def test_backup_hint_is_bound_coalesced_and_never_grants_retention_authority(scheduled):
    executor, _data, _clock, schedule = scheduled
    capture = schedule()["result"]
    raw = json.loads(retention_action("backup_retention_hint", capture))
    assert executor.handle(json.dumps(raw).encode(), 4444)["result"] == {"accepted": True}
    assert executor.retention_wakeup.is_set()
    executor.retention_wakeup.clear()
    raw["request_id"] = uuid.uuid4().hex
    assert executor.handle(json.dumps(raw).encode(), 4444)["result"] == {"accepted": True}
    assert not executor.retention_wakeup.is_set()
    executor._retention_hint_next = 0
    raw["params"]["capture_id"] = "f" * 64
    raw["request_id"] = uuid.uuid4().hex
    assert executor.handle(json.dumps(raw).encode(), 4444)["result"] == {"accepted": True}
    assert not executor.retention_wakeup.is_set()
    raw["params"]["capture_id"] = capture["capture_id"]
    raw["request_id"] = uuid.uuid4().hex
    executor.host.killed = True
    assert executor.handle(json.dumps(raw).encode(), 4444)["error_class"] == "kill_switch"
    assert not executor.retention_wakeup.is_set()
    with executor._db() as db:
        assert db.execute("SELECT COUNT(*) FROM backup_removal_ack").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM backup_retirement_intents").fetchone()[0] == 0


def test_retention_sweep_loop_wakes_on_hint_without_waiting_for_period():
    import threading

    class FakeExecutor:
        retention_wakeup = threading.Event()

    sweep = server.RetentionSweep(FakeExecutor())
    first, second = threading.Event(), threading.Event()
    calls = []

    def tick():
        calls.append(True)
        (first if len(calls) == 1 else second).set()

    sweep.tick = tick
    stop = threading.Event()
    thread = threading.Thread(target=sweep.run, args=(stop,), daemon=True)
    thread.start()
    try:
        assert first.wait(2)
        FakeExecutor.retention_wakeup.set()
        assert second.wait(2)
    finally:
        stop.set()
        FakeExecutor.retention_wakeup.set()
        thread.join(2)
    assert not thread.is_alive()


def test_cancelled_or_disabled_hint_is_noop_and_rejects_extra_claims(scheduled):
    executor, _data, _clock, schedule = scheduled
    capture = schedule()["result"]
    raw = json.loads(retention_action("backup_retention_hint", capture))
    with executor._db() as db:
        db.execute(
            "INSERT INTO backup_upload_cancellations VALUES (?, ?, ?, ?)",
            ("notes", capture["artifact"], capture["capture_id"], time.time()),
        )
    assert executor.handle(json.dumps(raw).encode(), 4444)["result"] == {"accepted": True}
    assert not executor.retention_wakeup.is_set()
    with executor._db() as db:
        db.execute("DELETE FROM backup_upload_cancellations")
    registry = json.loads(executor.registry_file.read_text())
    registry["backup"]["enabled"] = False
    executor.registry_file.write_text(json.dumps(registry))
    raw["request_id"] = uuid.uuid4().hex
    assert executor.handle(json.dumps(raw).encode(), 4444)["result"] == {"accepted": True}
    assert not executor.retention_wakeup.is_set()
    raw["params"]["restore_verified"] = True
    raw["request_id"] = uuid.uuid4().hex
    assert executor.handle(json.dumps(raw).encode(), 4444)["error_class"] == "bad_request"


def test_worker_hint_replay_through_executor_keeps_upload_and_retention_evidence_separate(
    scheduled, tmp_path
):
    from steward.backupworker import Imports, Runner
    from steward.core.backups import Receipt
    from steward.executor.protocol import ExecutorError

    executor, _data, clock, schedule = scheduled
    capture = schedule()["result"]
    calls = []

    def bridge(action, params, *, timeout):
        raw = json.loads(request())
        raw.update(action=action, params=params)
        response = executor.handle(json.dumps(raw).encode(), 4444)
        if not response["ok"]:
            raise ExecutorError(response["error_class"], response["message"])
        if action == "backup_retention_hint":
            calls.append(action)
            if len(calls) == 1:
                raise ExecutorError("unavailable", "response lost")
        return response["result"]

    class Backend:
        uploads = 0

        def health(self):
            return {"ready": True}

        def repository_id(self):
            return "c" * 64

        def backup(self, path):
            self.uploads += 1
            manifest = load_capture(path)
            return Receipt(
                capture=manifest,
                repository_id="c" * 64,
                snapshot_id="d" * 64,
                snapshot_path=str(path),
                snapshot_created_at=clock[0],
                recorded_at=clock[0],
            )

        def check(self, receipt):
            return receipt.model_copy(update={"integrity_checked_at": clock[0]})

        def restore_test(self, receipt):
            return receipt.model_copy(update={"restore_verified_at": clock[0]})

    backend = Backend()
    imports = Imports(server.BACKUP_IMPORT_ROOT, owner_uid=os.getuid())
    state = tmp_path / "worker"
    first = Runner(state, imports, backend, clock=lambda: clock[0], permit=bridge, hint=bridge)
    assert first.run_once()["restored_bytes_verified"]
    assert executor.retention_wakeup.is_set() and backend.uploads == 1
    assert first.jobs._conn().execute("SELECT COUNT(*) FROM retention_hints").fetchone()[0] == 1
    second = Runner(state, imports, backend, clock=lambda: clock[0], permit=bridge, hint=bridge)
    assert second.run_once() is None and backend.uploads == 1
    assert second.jobs._conn().execute("SELECT COUNT(*) FROM retention_hints").fetchone()[0] == 0
    assert calls == ["backup_retention_hint", "backup_retention_hint"]
    with executor._db() as db:
        assert db.execute("SELECT COUNT(*) FROM backup_upload_protection").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM backup_removal_ack").fetchone()[0] == 0
    assert (server.BACKUP_IMPORT_ROOT / "notes" / capture["artifact"]).is_dir()


@pytest.fixture
def orphan_cancellation(executor, tmp_path, monkeypatch):
    monkeypatch.setattr(server, "BACKUP_IMPORT_ROOT", tmp_path / "no-imports")
    executor.host.backup_worker_stopped = lambda: True
    artifact, capture_id = "a" * 32, "b" * 64
    with executor._db() as db:
        db.execute(
            "INSERT INTO backup_upload_cancellations VALUES (?, ?, ?, ?)",
            ("notes", artifact, capture_id, time.time()),
        )
    return executor, artifact, capture_id


def forget_request(artifact, capture_id, *, acknowledge=True):
    raw = json.loads(retention_ack_request(artifact, capture_id))
    raw["action"] = "backup_cancellation_forget"
    if acknowledge:
        raw["params"]["acknowledge_forget"] = True
    return json.dumps(raw).encode()


def test_orphan_cancellation_is_listed_and_forgotten_only_by_operator(orphan_cancellation):
    executor, artifact, capture_id = orphan_cancellation
    raw = json.loads(request())
    raw["action"] = "backup_retention_status"
    listing = executor.handle(json.dumps(raw).encode(), 0)["result"]
    assert listing["cancellation_records"] == [{"artifact": artifact, "capture_id": capture_id}]
    assert listing["cancellation_records_incomplete"] is False
    assert (
        executor.handle(forget_request(artifact, capture_id), os.getuid())["error_class"]
        == "forbidden_role"
    )
    assert (
        executor.handle(forget_request(artifact, capture_id, acknowledge=False), 0)["error_class"]
        == "bad_request"
    )
    result = executor.handle(forget_request(artifact, capture_id), 0)
    assert result["ok"] and result["result"]["forgotten"] is True
    assert executor.handle(forget_request(artifact, capture_id), 0)["result"]["forgotten"] is False
    with executor._db() as db:
        assert db.execute("SELECT COUNT(*) FROM backup_upload_cancellations").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM backup_upload_protection").fetchone()[0] == 0
    registry = json.loads(executor.registry_file.read_text())
    registry["backup"]["enabled"] = True
    registry["projects"]["notes"]["allow_backup_pause"] = True
    registry["peers"]["backup"] = 4444
    executor.registry_file.write_text(json.dumps(registry))
    raw = json.loads(retention_ack_request(artifact, capture_id))
    raw["action"] = "backup_upload_permit"
    assert executor.handle(json.dumps(raw).encode(), 4444)["result"] == {
        "permitted": False,
        "reason": "unavailable",
    }


def test_forget_refuses_active_worker_pending_registration_and_stop_race(orphan_cancellation):
    executor, artifact, capture_id = orphan_cancellation
    executor.host.backup_worker_stopped = lambda: False
    assert (
        executor.handle(forget_request(artifact, capture_id), 0)["error_class"] == "policy_denied"
    )
    executor.host.backup_worker_stopped = lambda: True
    with executor._db() as db:
        db.execute(
            "INSERT INTO backup_upload_protection VALUES (?, ?, ?, ?, ?, ?)",
            ("notes", artifact, capture_id, "c" * 64, 0, 0),
        )
    assert (
        executor.handle(forget_request(artifact, capture_id), 0)["error_class"] == "policy_denied"
    )
    with executor._db() as db:
        db.execute("DELETE FROM backup_upload_protection")
    states = iter([True, False])
    executor.host.backup_worker_stopped = lambda: next(states)
    assert executor.handle(forget_request(artifact, capture_id), 0)["error_class"] == "unavailable"
    with executor._db() as db:
        assert db.execute("SELECT COUNT(*) FROM backup_upload_cancellations").fetchone()[0] == 1


def test_forget_refuses_other_artifact_with_same_capture(
    old_retention_captures, tmp_path, monkeypatch
):
    executor, parent, captures = old_retention_captures
    artifact, capture_id = "f" * 32, captures[0]["capture_id"]
    monkeypatch.setattr(server, "BACKUP_IMPORT_ROOT", tmp_path / "no-imports")
    executor.host.backup_worker_stopped = lambda: True
    with executor._db() as db:
        db.execute(
            "INSERT INTO backup_upload_cancellations VALUES (?, ?, ?, ?)",
            ("notes", artifact, capture_id, time.time()),
        )
    result = executor.handle(forget_request(artifact, capture_id), 0)
    assert result["error_class"] == "unavailable"
    assert (parent / captures[0]["artifact"]).exists()
    with executor._db() as db:
        assert db.execute("SELECT COUNT(*) FROM backup_upload_cancellations").fetchone()[0] == 1


def test_forget_refuses_unrecognized_namespace_objects(orphan_cancellation, tmp_path):
    executor, artifact, capture_id = orphan_cancellation
    root = Path(executor._db_path).parent / "captures"
    root.mkdir(mode=0o700)
    project = root / "notes"
    project.mkdir(mode=0o700)
    unknown = project / "foreign"
    unknown.mkdir(mode=0o700)
    assert executor.handle(forget_request(artifact, capture_id), 0)["error_class"] == "unavailable"
    assert unknown.is_dir()
    with executor._db() as db:
        assert db.execute("SELECT COUNT(*) FROM backup_upload_cancellations").fetchone()[0] == 1


@pytest.mark.parametrize(
    "blocker", ["capture_ack", "capture_intent", "import_intent", "same_capture_pending"]
)
def test_forget_preserves_cancellation_when_root_authority_is_ambiguous(
    orphan_cancellation, blocker
):
    executor, artifact, capture_id = orphan_cancellation
    with executor._db() as db:
        if blocker == "capture_ack":
            db.execute(
                "INSERT INTO backup_removal_ack VALUES (?, ?, ?, ?, ?, ?)",
                ("notes", artifact, capture_id, "c" * 64, 1, 1),
            )
        elif blocker == "capture_intent":
            db.execute("INSERT INTO backup_retirement_intents VALUES (?, ?)", ("notes", "invalid"))
        elif blocker == "import_intent":
            db.execute(
                "INSERT INTO backup_import_retirement_intents VALUES (?, ?)", ("notes", "invalid")
            )
        else:
            db.execute(
                "INSERT INTO backup_upload_protection VALUES (?, ?, ?, ?, ?, ?)",
                ("notes", "d" * 32, capture_id, "c" * 64, 1, 1),
            )
    assert (
        executor.handle(forget_request(artifact, capture_id), 0)["error_class"] == "policy_denied"
    )
    with executor._db() as db:
        assert db.execute("SELECT COUNT(*) FROM backup_upload_cancellations").fetchone()[0] == 1


def test_retention_inventory_bounds_cancellation_records(executor, tmp_path, monkeypatch):
    monkeypatch.setattr(server, "BACKUP_IMPORT_ROOT", tmp_path / "no-imports")
    with executor._db() as db:
        db.executemany(
            "INSERT INTO backup_upload_cancellations VALUES (?, ?, ?, ?)",
            [
                ("notes", f"{i:032x}", f"{i:064x}", 1)
                for i in range(server.MAX_CANCELLED_UPLOADS + 1)
            ],
        )
    raw = json.loads(request())
    raw["action"] = "backup_retention_status"
    result = executor.handle(json.dumps(raw).encode(), 0)["result"]
    assert len(result["cancellation_records"]) == server.MAX_CANCELLED_UPLOADS
    assert result["cancellation_records_incomplete"] is True


def test_worker_capacity_report_is_attributed_and_rate_limited_even_with_kill_switch(scheduled):
    from steward.collector import audit_events

    executor, _data, _clock, schedule = scheduled
    schedule()
    raw = json.loads(request())
    raw["action"], raw["params"] = "backup_worker_capacity_report", {}
    assert executor.handle(json.dumps(raw).encode(), 0)["error_class"] == "forbidden_role"
    executor.host.killed = True
    assert executor.handle(json.dumps(raw).encode(), 4444)["result"] == {"accepted": True}
    assert executor.handle(json.dumps(raw).encode(), 4444)["result"] == {"accepted": True}
    capacity = [entry for entry in executor.audit.read() if entry["event"] == "backup_capacity"]
    assert len(capacity) == 1 and capacity[0]["reported_by"] == "backup"
    (event,) = audit_events(capacity[0])
    assert event.delivery == "immediate" and "worker reported" in event.summary
    assert event.target == "backup-worker" and event.project is None
    assert event.data == {"namespace": "worker", "reason": "limit", "reported_by": "backup"}
    assert not executor.retention_wakeup.is_set()
    raw["params"] = {"project_id": "missing"}
    assert executor.handle(json.dumps(raw).encode(), 4444)["error_class"] == "bad_request"
    raw["params"] = {}
    executor._worker_capacity_next = 0
    registry = json.loads(executor.registry_file.read_text())
    registry["backup"]["enabled"] = False
    executor.registry_file.write_text(json.dumps(registry))
    assert executor.handle(json.dumps(raw).encode(), 4444)["result"] == {"accepted": True}
    assert (
        len([entry for entry in executor.audit.read() if entry["event"] == "backup_capacity"]) == 1
    )
    with executor._db() as db:
        assert db.execute("SELECT COUNT(*) FROM backup_removal_ack").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM backup_retirement_intents").fetchone()[0] == 0


def test_root_schedule_observations_distinguish_missing_stale_clock_and_configuration(scheduled):
    from steward.controller import evaluate

    executor, _data, clock, schedule = scheduled
    registry = json.loads(executor.registry_file.read_text())

    def observation():
        status = server.platform_status(executor, server.NoParams(), "controller", registry)
        findings = {f.id: f for f in evaluate(status, {})}
        return status["backup_schedule_observations"]["notes"], findings.get(
            "backup_schedule:notes"
        )

    root, finding = observation()
    assert root["state"] == "missing" and "No scheduled capture" in finding.summary
    first = schedule()["result"]
    root, finding = observation()
    assert root["state"] == "exported" and finding is None
    assert root["capture_id"] == first["capture_id"]
    assert root["capture_created_at"] == first["capture_created_at"]
    assert root["provenance"] == "executor_schedule" and "uploaded" not in root
    clock[0] += 7201
    root, finding = observation()
    assert "overdue" in finding.summary and finding.severity == "high"
    assert root["capture_created_at"] == first["capture_created_at"]
    clock[0] -= 10000
    _root, finding = observation()
    assert "future" in finding.summary
    registry["config_revision"] = "f" * 64
    _root, finding = observation()
    assert "different configuration" in finding.summary
    with executor._db() as db:
        db.execute("UPDATE backup_schedule SET body='{}' WHERE project='notes'")
    root, finding = observation()
    assert root["state"] == "invalid" and finding.severity == "high"
    registry["backup"]["enabled"] = False
    assert server.backup_schedule_observations(executor, registry) == {}


def test_root_schedule_failed_and_pending_are_not_reported_as_success(scheduled):
    from steward.controller import evaluate

    executor, _data, clock, _schedule = scheduled
    registry = json.loads(executor.registry_file.read_text())
    run = {
        "artifact": "a" * 32,
        "phase": "failed",
        "created_at": clock[0],
        "config_revision": registry["config_revision"],
    }
    with executor._db() as db:
        db.execute("INSERT INTO backup_schedule VALUES (?,?)", ("notes", json.dumps(run)))
    status = server.platform_status(executor, server.NoParams(), "controller", registry)
    finding = next(f for f in evaluate(status, {}) if f.id == "backup_schedule:notes")
    assert finding.severity == "high" and "failed" in finding.summary
    assert finding.remediation is None
    run["phase"] = "capturing"
    with executor._db() as db:
        db.execute("UPDATE backup_schedule SET body=? WHERE project='notes'", (json.dumps(run),))
    clock[0] += 7201
    status = server.platform_status(executor, server.NoParams(), "controller", registry)
    finding = next(f for f in evaluate(status, {}) if f.id == "backup_schedule:notes")
    assert "overdue" in finding.summary and finding.remediation is None


def test_schedule_observation_database_failure_is_unknown_not_missing(scheduled, monkeypatch):
    import sqlite3
    from contextlib import contextmanager

    executor, _data, _clock, _schedule = scheduled
    registry = json.loads(executor.registry_file.read_text())

    @contextmanager
    def unavailable():
        raise sqlite3.OperationalError("private database error")
        yield  # pragma: no cover

    monkeypatch.setattr(executor, "_db", unavailable)
    result = server.backup_schedule_observations(executor, registry)
    assert result["notes"]["state"] == "unavailable"
    assert "private database error" not in repr(result)


def test_schedule_status_clock_is_sampled_after_schedule_observation(scheduled, monkeypatch):
    executor, _data, clock, schedule = scheduled
    assert schedule()["ok"]
    registry = json.loads(executor.registry_file.read_text())
    original = server.backup_schedule_observations

    def concurrent_capture(ex, reg):
        clock[0] += 1
        return original(ex, reg)

    monkeypatch.setattr(server, "backup_schedule_observations", concurrent_capture)
    status = server.platform_status(executor, server.NoParams(), "controller", registry)
    assert status["checked_at"] == clock[0]
    assert (
        status["checked_at"]
        >= status["backup_schedule_observations"]["notes"]["capture_created_at"]
    )


def test_revision_bound_schedule_refuses_changed_configuration_and_prior_capture(scheduled):
    executor, _data, clock, schedule = scheduled
    registry = json.loads(executor.registry_file.read_text())
    revision = registry["config_revision"]
    assert schedule(expected_revision="f" * 64)["error_class"] == "conflict"
    assert executor.host.calls == []
    first = schedule(expected_revision=revision)
    assert first["ok"] and first["result"]["uploaded"] is False
    registry["config_revision"] = "f" * 64
    executor.registry_file.write_text(json.dumps(registry))
    assert schedule(expected_revision=revision)["error_class"] == "conflict"
    assert schedule(expected_revision="f" * 64)["error_class"] == "conflict"
    assert executor.host.calls == [("set", False), ("set", True)]
    clock[0] += 3601
    next_run = schedule(expected_revision="f" * 64)
    assert next_run["ok"] and next_run["result"]["config_revision"] == "f" * 64
    assert executor.host.calls == [("set", False), ("set", True)] * 2


def test_startup_recovery_retries_busy_original_pause(capture_host, monkeypatch):
    from steward.executor.protocol import ExecutorError

    executor, _ = capture_host
    prepare_interrupted_pause(executor)
    original = executor.recover_backup_pause
    attempts = []

    def busy_once(*args, **kwargs):
        attempts.append(True)
        if len(attempts) == 1:
            raise ExecutorError("target_busy", "temporary lock")
        return original(*args, **kwargs)

    class Stop:
        def is_set(self):
            return False

        def wait(self, _timeout):
            return False

    monkeypatch.setattr(executor, "recover_backup_pause", busy_once)
    executor.recover_backup_pauses(Stop())
    assert len(attempts) == 2
    assert executor.backup_pause("notes") is None
    assert executor.host.units["notes.service"] == "active"


def test_startup_recovery_does_not_adopt_replacement_pause(capture_host, monkeypatch):
    from steward.executor.protocol import ExecutorError

    executor, _ = capture_host
    prepare_interrupted_pause(executor)
    old = executor.backup_pause("notes")
    original = executor.recover_backup_pause
    attempts = []

    def busy_once(*args, **kwargs):
        attempts.append(True)
        if len(attempts) == 1:
            raise ExecutorError("target_busy", "temporary lock")
        return original(*args, **kwargs)

    class Stop:
        def is_set(self):
            return False

        def wait(self, _timeout):
            executor.clear_backup_pause("notes")
            executor.save_backup_pause(old.model_copy(update={"artifact": "b" * 32}))
            return False

    monkeypatch.setattr(executor, "recover_backup_pause", busy_once)
    executor.recover_backup_pauses(Stop())
    assert len(attempts) == 2
    assert executor.backup_pause("notes").artifact == "b" * 32
    assert executor.host.units["notes.service"] == "inactive"


def test_deployment_execution_fences_running_backup_and_retained_pause(capture_host):
    from steward.executor.protocol import ExecutorError

    executor, _ = capture_host
    registry = json.loads(executor.registry_file.read_text())
    base = registry["config_revision"]
    with executor.target_lock("project-notes"):
        with (
            pytest.raises(ExecutorError) as error,
            executor.deployment_execution(base_revision=base, desired_revision="b" * 64),
        ):
            pytest.fail("deployment crossed active backup lock")
        assert error.value.error_class == "target_busy"
    prepare_interrupted_pause(executor)
    with (
        pytest.raises(ExecutorError) as error,
        executor.deployment_execution(base_revision=base, desired_revision="b" * 64),
    ):
        pytest.fail("deployment crossed retained backup pause")
    assert error.value.error_class == "target_busy"
    assert executor.deployment_fence() is None
    executor.recover_backup_pauses()
    with executor.deployment_execution(base_revision=base, desired_revision="b" * 64) as fence:
        assert executor.deployment_fence() == fence
    assert executor.deployment_fence() == fence


def test_durable_deployment_fence_blocks_backup_and_restart_after_lock_release(capture_host):
    from steward.executor.protocol import ExecutorError

    executor, _ = capture_host
    registry = json.loads(executor.registry_file.read_text())
    base = registry["config_revision"]
    with executor.deployment_execution(base_revision=base, desired_revision="b" * 64) as fence:
        pass
    assert executor.deployment_fence() == fence
    result = executor.handle(request(), 0)
    assert result["error_class"] == "target_busy" and not executor.host.calls
    with pytest.raises(ExecutorError) as error:
        server.workload_restart(
            executor,
            server.RestartParams(project_id="notes", reason="health"),
            "operator",
            registry,
        )
    assert error.value.error_class == "target_busy" and not executor.host.calls
    changed = {**registry, "config_revision": "b" * 64}
    executor.registry_file.write_text(json.dumps(changed))
    executor.release_deployment_fence(fence.operation_id)
    assert executor.handle(request(), 0)["ok"]


def test_lock_cleanup_permit_checks_kill_switch_and_exact_capture(scheduled):
    executor, _data, _clock, schedule = scheduled
    capture = schedule()["result"]
    raw = json.loads(retention_ack_request(capture["artifact"], capture["capture_id"]))
    raw["action"] = "backup_lock_cleanup_permit"
    assert executor.handle(json.dumps(raw).encode(), 4444)["result"] == {
        "permitted": True,
        "reason": "registered",
    }
    executor.host.killed = True
    assert executor.handle(json.dumps(raw).encode(), 4444)["result"] == {
        "permitted": False,
        "reason": "unavailable",
    }
    executor.host.killed = False
    raw["params"]["capture_id"] = "f" * 64
    assert executor.handle(json.dumps(raw).encode(), 4444)["result"] == {
        "permitted": False,
        "reason": "unavailable",
    }
