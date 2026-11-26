import fcntl
import os
import time

import pytest

from steward.backupworker import Imports, Runner
from steward.core.backupexport import export_capture
from steward.core.backups import BackupError, Binding, Receipt, load_capture
from steward.core.filebackups import capture_files


class Backend:
    def __init__(self, clock):
        self.clock, self.remote = clock, {}
        self.uploads = self.backup_calls = 0
        self.repository = "c" * 64
        self.fail_restore = False
        self.after_check = self.after_upload = None

    def health(self):
        return {"ready": True}

    def repository_id(self):
        return self.repository

    def backup(self, path):
        self.backup_calls += 1
        capture = load_capture(path)
        key = self.repository, capture.id
        if key not in self.remote:
            self.uploads += 1
            self.remote[key] = Receipt(
                capture=capture,
                repository_id=self.repository,
                snapshot_id="d" * 64,
                snapshot_path=str(path),
                snapshot_created_at=self.clock[0],
                recorded_at=self.clock[0],
            )
        if self.after_upload:
            self.after_upload()
        return self.remote[key]

    def check(self, receipt):
        if self.after_check:
            self.after_check()
        return receipt.model_copy(update={"integrity_checked_at": self.clock[0]})

    def restore_test(self, receipt):
        if self.fail_restore:
            raise BackupError("unavailable")
        return receipt.model_copy(update={"restore_verified_at": self.clock[0]})


@pytest.fixture
def worker(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "state").write_bytes(b"private state")
    source = tmp_path / "capture"
    manifest = capture_files(
        data,
        source,
        Binding(
            server="test-server",
            project="notes",
            config_revision="a" * 64,
            image="docker.io/library/python@sha256:" + "b" * 64,
            source_revision="bundled:sample-notes@0.1.0",
        ),
        is_quiescent=lambda: True,
    )
    root = tmp_path / "imports"
    root.mkdir(mode=0o750)
    root.chmod(0o750)
    (root / "notes").mkdir(mode=0o750)
    (root / "notes").chmod(0o750)
    target = root / "notes" / ("e" * 32)
    export_capture(source, target, capture_id=manifest.id, gid=os.getgid())
    clock = [time.time()]
    backend = Backend(clock)
    runner = Runner(
        tmp_path / "worker", Imports(root, owner_uid=os.getuid()), backend, clock=lambda: clock[0]
    )
    return runner, backend, clock, target, manifest


def test_upload_check_and_restore_are_separate_durable_evidence(worker):
    runner, backend, _clock, _target, manifest = worker
    result = runner.run_once()
    assert result["uploaded"] and result["data_checked"] and result["restored_bytes_verified"]
    assert result["application_verified"] is False
    assert runner.jobs.list_jobs()[0]["state"] == "succeeded"
    receipt = runner.jobs.receipt("c" * 64, manifest.id)
    assert receipt.restore_verified_at is not None
    assert runner.run_once() is None
    assert backend.uploads == backend.backup_calls == 1


def test_failed_restore_restarts_from_saved_snapshot_without_new_upload(worker):
    runner, backend, clock, _target, manifest = worker
    backend.fail_restore = True
    result = runner.run_once()
    assert result["state"] == "queued"
    stored = runner.jobs.receipt("c" * 64, manifest.id)
    assert stored.integrity_checked_at is not None and stored.restore_verified_at is None
    fresh = Runner(runner.state, runner.imports, backend, clock=lambda: clock[0])
    clock[0] += 600
    backend.fail_restore = False
    result = fresh.run_once()
    assert result["restored_bytes_verified"]
    assert backend.backup_calls == 1
    assert (
        fresh.jobs.receipt("c" * 64, manifest.id).snapshot_created_at == stored.snapshot_created_at
    )


def test_lost_lease_cannot_publish_checked_or_succeeded_evidence(worker):
    runner, backend, clock, _target, manifest = worker

    def steal():
        with runner.jobs._tx() as db:
            db.execute("UPDATE jobs SET lease_owner='other', lease_expires=?", (clock[0] + 60,))

    backend.after_check = steal
    result = runner.run_once()
    assert result["state"] == "lease_lost"
    receipt = runner.jobs.receipt("c" * 64, manifest.id)
    assert receipt.integrity_checked_at is receipt.restore_verified_at is None
    assert runner.jobs.list_jobs()[0]["state"] == "running"


def test_unknown_upload_after_expired_lease_is_reconciled_without_freshening_capture(worker):
    runner, backend, clock, _target, manifest = worker
    backend.after_upload = lambda: clock.__setitem__(0, clock[0] + 61)
    assert runner.run_once()["state"] == "lease_lost"
    assert runner.jobs.receipt("c" * 64, manifest.id) is None
    backend.after_upload = None
    assert runner.run_once()["restored_bytes_verified"]
    assert backend.uploads == 1 and backend.backup_calls == 2
    assert runner.jobs.receipt("c" * 64, manifest.id).capture.created_at == manifest.created_at


def test_second_worker_cannot_run_while_shared_state_is_locked(worker):
    runner, backend, _clock, _target, _manifest = worker
    with (runner.state / "worker.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with pytest.raises(BackupError, match="worker_busy"):
            runner.run_once()
    assert backend.backup_calls == 0


def test_unsealed_import_is_never_uploaded(worker):
    runner, backend, _clock, target, _manifest = worker
    (target / "data.tar").chmod(0o660)
    with pytest.raises(BackupError, match="unsafe_import"):
        runner.run_once()
    assert backend.backup_calls == 0


def test_repository_change_cannot_redirect_an_existing_job(worker):
    runner, backend, clock, _target, manifest = worker
    backend.fail_restore = True
    assert runner.run_once()["state"] == "queued"
    old = runner.jobs.receipt("c" * 64, manifest.id)
    backend.repository = "f" * 64
    backend.fail_restore = False
    clock[0] += 600
    result = runner.run_once()
    assert result["error_class"] == "repository_changed"
    assert runner.jobs.receipt("c" * 64, manifest.id) == old
    assert runner.jobs.receipt("f" * 64, manifest.id) is None
    # Only the separately bound new-target job may upload to the new repository.
    assert runner.run_once()["restored_bytes_verified"]
    assert backend.uploads == 2


def test_snapshot_identity_cannot_change_between_evidence_phases(worker):
    runner, backend, _clock, _target, manifest = worker
    original = backend.restore_test
    backend.restore_test = lambda receipt: original(receipt).model_copy(
        update={"snapshot_id": "f" * 64}
    )
    result = runner.run_once()
    assert result["state"] == "failed" and result["error_class"] == "evidence_mismatch"
    stored = runner.jobs.receipt("c" * 64, manifest.id)
    assert stored.snapshot_id == "d" * 64 and stored.restore_verified_at is None


def test_production_import_owner_is_root_and_mismatched_owners_are_rejected(worker):
    runner, backend, _clock, _target, _manifest = worker
    assert Imports(runner.imports.root).owner == 0
    runner.imports.owner = os.getuid() + 1
    with pytest.raises(BackupError, match="unsafe_import"):
        runner.run_once()
    assert backend.backup_calls == 0


def test_worker_state_cannot_contain_or_be_inside_the_import_namespace(worker):
    runner, backend, _clock, _target, _manifest = worker
    for state in (runner.imports.root / "state", runner.imports.root.parent):
        with pytest.raises(BackupError, match="unsafe_state"):
            Runner(state, runner.imports, backend)


def test_scheduler_reuses_persisted_due_hint_and_checks_root_import(worker):
    from steward.backupscheduler import ScheduleConfig, Scheduler

    runner, _backend, clock, target, manifest = worker
    config = ScheduleConfig(
        enabled=True,
        interval_s=3600,
        max_mib=10,
        endpoint={"host": "backup.test", "addresses": ["192.0.2.1"]},
        config_revision="a" * 64,
        projects=["notes"],
        credentials=["repository", "password"],
    )
    calls = []

    def request(action, params, *, timeout):
        calls.append((action, params, timeout))
        return {
            "project_id": "notes",
            "artifact": target.name,
            "capture_id": manifest.id,
            "import_dir": str(target),
            "uploaded": False,
            "capture_created_at": manifest.created_at,
            "config_revision": manifest.binding.config_revision,
            "next_capture_at": clock[0] + 3600,
        }

    state = runner.state / "schedule.db"
    scheduler = Scheduler(config, runner.imports, state, clock=lambda: clock[0], request=request)
    assert scheduler.tick() == {"notes": "scheduled"}
    assert calls == [("backup_schedule", {"project_id": "notes"}, 60)]
    restarted = Scheduler(config, runner.imports, state, clock=lambda: clock[0], request=request)
    assert restarted.tick() == {}
    clock[0] -= 120
    assert restarted.tick() == {}
    assert len(calls) == 1
    changed = config.model_copy(update={"config_revision": "b" * 64})
    reconfigured = Scheduler(
        changed, runner.imports, state, clock=lambda: clock[0], request=request
    )
    assert reconfigured.tick() == {"notes": "scheduled"}
    clock[0] += 3720
    assert reconfigured.tick() == {"notes": "scheduled"}


def test_scheduler_isolates_failures_and_rejects_mismatched_evidence(worker):
    from steward.backupscheduler import ScheduleConfig, Scheduler
    from steward.executor.protocol import ExecutorError

    runner, _backend, clock, target, manifest = worker
    config = ScheduleConfig(
        enabled=True,
        interval_s=3600,
        max_mib=10,
        endpoint={"host": "backup.test", "addresses": ["192.0.2.1"]},
        config_revision="a" * 64,
        projects=["broken", "notes"],
        credentials=["repository", "password"],
    )
    attempts = []

    def request(_action, params, *, timeout):
        project = params["project_id"]
        attempts.append(project)
        if project == "broken":
            raise ExecutorError("target_busy", "busy")
        return {
            "project_id": "notes",
            "artifact": target.name,
            "capture_id": "f" * 64,
            "import_dir": str(target),
            "uploaded": False,
            "capture_created_at": manifest.created_at,
            "config_revision": manifest.binding.config_revision,
            "next_capture_at": clock[0] + 3600,
        }

    scheduler = Scheduler(
        config,
        runner.imports,
        runner.state / "schedule.db",
        clock=lambda: clock[0],
        request=request,
    )
    assert scheduler.tick() == {"broken": "target_busy", "notes": "invalid_evidence"}
    assert attempts == ["broken", "notes"]
    assert scheduler.tick() == {}
    clock[0] += 60
    scheduler.tick()
    assert attempts == ["broken", "notes", "broken", "notes"]


def test_active_upload_holds_import_lock_until_receipt_commit(worker):
    runner, backend, _clock, target, _manifest = worker
    checks = []

    def cleanup_is_fenced():
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            checks.append(True)
        finally:
            os.close(fd)

    backend.after_upload = cleanup_is_fenced
    backend.after_check = cleanup_is_fenced
    assert runner.run_once()["restored_bytes_verified"]
    assert checks == [True, True]
    fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(fd)


def test_worker_retries_when_cleanup_holds_exclusive_import_lock(worker):
    runner, backend, clock, target, _manifest = worker
    fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = runner.run_once()
        assert result["error_class"] == "unavailable" and result["state"] == "queued"
        assert backend.backup_calls == 0
    finally:
        os.close(fd)
    clock[0] += 600
    assert runner.run_once()["restored_bytes_verified"]


def test_managed_worker_defers_cancelled_upload_then_retries_after_reinstatement(worker):
    runner, backend, clock, target, manifest = worker
    decision = [{"permitted": False, "reason": "cancelled"}]
    calls = []

    def permit(action, params, *, timeout):
        lock_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(lock_fd)
        calls.append((action, params, timeout))
        return decision[0]

    managed = Runner(runner.state, runner.imports, backend, clock=lambda: clock[0], permit=permit)
    result = managed.run_once()
    assert result["state"] == "queued" and result["error_class"] == "upload_cancelled"
    assert backend.backup_calls == 0
    assert managed.jobs.list_jobs()[0]["attempts"] == 0
    assert calls == [
        (
            "backup_upload_permit",
            {"project_id": "notes", "artifact": target.name, "capture_id": manifest.id},
            10,
        )
    ]
    decision[0] = {"permitted": True, "reason": "registered"}
    clock[0] += 301
    assert managed.run_once()["restored_bytes_verified"]
    assert backend.backup_calls == 1


def test_managed_worker_never_exhausts_attempts_while_executor_is_unavailable(worker):
    from steward.executor.protocol import ExecutorError

    runner, backend, clock, _target, _manifest = worker

    def unavailable(*_args, **_kwargs):
        raise ExecutorError("unavailable", "not reachable")

    managed = Runner(
        runner.state, runner.imports, backend, clock=lambda: clock[0], permit=unavailable
    )
    for _ in range(5):
        assert managed.run_once()["error_class"] == "permit_unavailable"
        assert managed.jobs.list_jobs()[0]["attempts"] == 0
        clock[0] += 301
    assert backend.backup_calls == 0


@pytest.mark.parametrize(
    "decision",
    [
        {"permitted": 1, "reason": "registered"},
        {"permitted": True, "reason": "registered", "extra": 1},
        None,
    ],
)
def test_managed_upload_requires_an_exact_boolean_permit(worker, decision):
    runner, backend, clock, _target, _manifest = worker
    managed = Runner(
        runner.state,
        runner.imports,
        backend,
        clock=lambda: clock[0],
        permit=lambda *_args, **_kw: decision,
    )
    result = managed.run_once()
    assert result["error_class"] == "permit_unavailable"
    assert managed.jobs.list_jobs()[0]["attempts"] == 0
    assert backend.backup_calls == 0


def test_retention_hint_survives_lost_response_and_restarts_without_new_upload(worker):
    from steward.executor.protocol import ExecutorError

    runner, backend, clock, target, manifest = worker
    attempts = []

    def hint(action, params, *, timeout):
        attempts.append((action, params, timeout))
        if len(attempts) == 1:
            raise ExecutorError("unavailable", "response lost")
        return {"accepted": True}

    managed = Runner(runner.state, runner.imports, backend, clock=lambda: clock[0], hint=hint)
    assert managed.run_once()["restored_bytes_verified"]
    assert backend.backup_calls == 1
    assert managed.jobs._conn().execute("SELECT COUNT(*) FROM retention_hints").fetchone()[0] == 1
    restarted = Runner(runner.state, runner.imports, backend, clock=lambda: clock[0], hint=hint)
    assert restarted.run_once() is None
    assert backend.backup_calls == 1
    assert len(attempts) == 2
    assert attempts[0] == (
        "backup_retention_hint",
        {"project_id": "notes", "artifact": target.name, "capture_id": manifest.id},
        10,
    )
    assert restarted.jobs._conn().execute("SELECT COUNT(*) FROM retention_hints").fetchone()[0] == 0


def test_upload_wakeup_is_independent_of_later_restore_failure(worker):
    runner, backend, clock, _target, _manifest = worker
    backend.fail_restore = True
    hints = []

    def hint(*args, **kwargs):
        hints.append((args, kwargs))
        return {"accepted": True}

    managed = Runner(runner.state, runner.imports, backend, clock=lambda: clock[0], hint=hint)
    assert managed.run_once()["state"] == "queued"
    assert len(hints) == 1
    assert managed.jobs._conn().execute("SELECT COUNT(*) FROM retention_hints").fetchone()[0] == 0
    assert managed.jobs.list_jobs()[0]["state"] != "succeeded"


def test_retention_hint_outbox_is_bounded_and_keeps_new_wakeup(worker, monkeypatch):
    import steward.backupworker as module
    from steward.executor.protocol import ExecutorError

    runner, backend, clock, target, manifest = worker
    monkeypatch.setattr(module, "MAX_RETENTION_HINTS", 2)
    with runner.jobs._tx() as db:
        db.executemany(
            "INSERT INTO retention_hints VALUES (?, ?, ?)",
            [("old", f"{i:032x}", f"{i:064x}") for i in range(4)],
        )

    def unavailable(*_args, **_kwargs):
        raise ExecutorError("unavailable", "offline")

    managed = Runner(
        runner.state, runner.imports, backend, clock=lambda: clock[0], hint=unavailable
    )
    assert managed.run_once()["restored_bytes_verified"]
    rows = (
        managed.jobs._conn()
        .execute("SELECT project, artifact, capture_id FROM retention_hints")
        .fetchall()
    )
    assert len(rows) == 2
    assert any(tuple(row) == ("notes", target.name, manifest.id) for row in rows)


def test_lost_lease_before_upload_checkpoint_does_not_publish_hint(worker):
    runner, backend, clock, _target, _manifest = worker
    hints = []
    backend.after_upload = lambda: clock.__setitem__(0, clock[0] + 61)
    managed = Runner(
        runner.state,
        runner.imports,
        backend,
        clock=lambda: clock[0],
        hint=lambda *args, **kwargs: hints.append((args, kwargs)),
    )
    assert managed.run_once()["state"] == "lease_lost"
    assert not hints
    assert managed.jobs._conn().execute("SELECT COUNT(*) FROM retention_hints").fetchone()[0] == 0


def test_hint_and_upload_receipt_commit_atomically_across_sql_failure(worker):
    import sqlite3

    runner, backend, clock, _target, manifest = worker
    hints = []
    managed = Runner(
        runner.state,
        runner.imports,
        backend,
        clock=lambda: clock[0],
        hint=lambda *args, **kwargs: hints.append((args, kwargs)) or {"accepted": True},
    )
    managed.jobs._conn().execute(
        "CREATE TRIGGER reject_hint BEFORE INSERT ON retention_hints "
        "BEGIN SELECT RAISE(ABORT, 'injected'); END"
    )
    with pytest.raises(sqlite3.IntegrityError):
        managed.run_once()
    assert managed.jobs.receipt("c" * 64, manifest.id) is None
    assert managed.jobs._conn().execute("SELECT COUNT(*) FROM retention_hints").fetchone()[0] == 0
    assert managed.jobs.list_jobs()[0]["state"] == "running" and not hints
    managed.jobs._conn().execute("DROP TRIGGER reject_hint")
    clock[0] += 61
    assert managed.run_once()["restored_bytes_verified"]
    assert backend.uploads == 1 and backend.backup_calls == 2
    assert len(hints) == 1


def test_worker_capacity_preserves_and_processes_existing_job(worker, monkeypatch):
    import steward.backupworker as module

    runner, backend, clock, target, manifest = worker
    monkeypatch.setattr(module, "MAX_BACKUP_JOBS", 1)
    payload = {
        "project": "notes",
        "artifact": target.name,
        "capture_id": manifest.id,
        "repository_id": backend.repository,
    }
    existing, _ = runner.jobs.enqueue(
        "backup_upload",
        "notes",
        payload,
        idempotency_key="existing",
        created_by="backup",
        now=clock[0],
    )
    reports = []

    def hint(action, params, *, timeout):
        reports.append((action, params, timeout))
        return {"accepted": True}

    managed = Runner(runner.state, runner.imports, backend, clock=lambda: clock[0], hint=hint)
    assert managed.run_once()["restored_bytes_verified"]
    assert managed.jobs.list_jobs()[0]["id"] == existing["id"]
    assert managed.jobs.list_jobs()[0]["state"] == "succeeded"
    assert any(
        action == "backup_worker_capacity_report" and params == {} for action, params, _ in reports
    )
    assert backend.backup_calls == 1


def test_worker_capacity_refusal_preserves_failed_job_and_is_rate_limited(worker, monkeypatch):
    import steward.backupworker as module

    runner, backend, clock, target, manifest = worker
    monkeypatch.setattr(module, "MAX_BACKUP_JOBS", 1)
    payload = {
        "project": "notes",
        "artifact": target.name,
        "capture_id": manifest.id,
        "repository_id": backend.repository,
    }
    job, _ = runner.jobs.enqueue(
        "backup_upload",
        "notes",
        payload,
        idempotency_key="previous",
        created_by="backup",
        now=clock[0],
    )
    with runner.jobs._tx() as db:
        db.execute("UPDATE jobs SET state='failed', error='investigate' WHERE id=?", (job["id"],))
    reports = []

    def hint(action, params, *, timeout):
        reports.append((action, params, timeout))
        return {"accepted": True}

    managed = Runner(runner.state, runner.imports, backend, clock=lambda: clock[0], hint=hint)
    assert managed.run_once() == {"state": "capacity_blocked", "error_class": "worker_job_limit"}
    assert managed.run_once() == {"state": "capacity_blocked", "error_class": "worker_job_limit"}
    assert len(reports) == 1 and reports[0][0] == "backup_worker_capacity_report"
    assert managed.jobs.list_jobs()[0]["error"] == "investigate"
    assert backend.backup_calls == 0


def test_observations_keep_distinct_phases_and_original_capture_age(worker):
    from steward.core.backup_observations import Page, SnapshotChanged, query

    runner, backend, clock, _target, manifest = worker
    backend.fail_restore = True
    assert runner.run_once()["state"] == "queued"
    first = query(runner.jobs, Page(project="notes"), now=clock[0], max_age_s=86400)
    record = first["records"][0]
    assert first["ledger_coverage"] == "complete"
    assert record["capture_created_at"] == manifest.created_at
    assert record["uploaded_at"] is not None and record["integrity_checked_at"] is not None
    assert record["restored_bytes_at"] is record["application_drill_at"] is None
    assert record["job_error"] == "unavailable" and record["provenance"] == "worker_reported"
    assert "snapshot_path" not in record
    assert query(runner.jobs, Page(project="other"), now=clock[0], max_age_s=86400)["total"] == 0
    clock[0] += 90000
    backend.fail_restore = False
    assert runner.run_once()["restored_bytes_verified"]
    with pytest.raises(SnapshotChanged):
        query(
            runner.jobs,
            Page(project="notes", snapshot_id=first["snapshot_id"]),
            now=clock[0],
            max_age_s=86400,
        )
    second = query(runner.jobs, Page(project="notes"), now=clock[0], max_age_s=86400)
    record = second["records"][0]
    assert record["capture_created_at"] == manifest.created_at
    assert record["capture_freshness"] == "stale" and record["restored_bytes_at"] is not None
    assert record["application_drill_at"] is None


def test_observations_refuse_mismatched_receipt_and_bound_pages(worker):
    from pydantic import ValidationError

    from steward.core.backup_observations import Page, query

    runner, _backend, clock, _target, _manifest = worker
    assert runner.run_once()["uploaded"]
    with pytest.raises(ValidationError):
        Page(limit=201)
    with runner.jobs._tx() as db:
        db.execute("UPDATE jobs SET target='other'")
    with pytest.raises(ValueError, match="target mismatch"):
        query(runner.jobs, Page(), now=clock[0], max_age_s=86400)


def test_backup_query_socket_limits_roles_and_keeps_partial_evidence(worker, tmp_path):
    import json
    import threading

    from steward.backupworker import QueryService
    from steward.core import ipc
    from steward.executor.protocol import ExecutorError, call

    runner, backend, clock, _target, _manifest = worker
    backend.fail_restore = True
    runner.run_once()
    service = QueryService(
        runner.jobs, {os.getuid(): "collector"}, max_age_s=86400, clock=lambda: clock[0]
    )

    def request(action, params):
        return json.dumps({"v": 1, "action": action, "params": params}).encode()

    assert (
        service.handle(request("backups_query", {}), 987654)["error_class"] == "unauthorized_peer"
    )
    assert service.handle(request("backup_schedule", {}), 0)["error_class"] == "policy_denied"
    assert (
        service.handle(request("backups_query", {"limit": 201}), 0)["error_class"] == "bad_request"
    )
    socket_path = str(tmp_path / "query.sock")
    server = ipc.bind(socket_path, service.handle, None)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = call("backups_query", {"project": "notes"}, socket_path=socket_path)
        record = response["records"][0]
        assert record["integrity_checked_at"] is not None and record["restored_bytes_at"] is None
        assert record["application_drill_at"] is None and record["job_error"] == "unavailable"
        with runner.jobs._tx() as db:
            db.execute("UPDATE jobs SET error='timeout'")
        with pytest.raises(ExecutorError, match="conflict"):
            call(
                "backups_query",
                {"project": "notes", "snapshot_id": response["snapshot_id"]},
                socket_path=socket_path,
            )
        with pytest.raises(ExecutorError, match="policy_denied"):
            call("backup_retention_hint", {}, socket_path=socket_path)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_observation_unknown_without_receipt_and_snapshot_pagination(worker):
    from steward.backupworker import Upload
    from steward.core.backup_observations import Page, query

    runner, _backend, clock, target, manifest = worker
    payload = Upload(
        project="notes", artifact=target.name, capture_id=manifest.id, repository_id="c" * 64
    )
    runner.jobs.enqueue(
        "backup_upload",
        "notes",
        payload.model_dump(),
        idempotency_key="pending",
        created_by="backup",
        now=clock[0],
    )
    first = query(runner.jobs, Page(limit=1), now=clock[0], max_age_s=86400)
    record = first["records"][0]
    assert record["capture_created_at"] is None and record["capture_freshness"] == "unknown"
    assert record["uploaded_at"] is record["integrity_checked_at"] is None
    assert record["restored_bytes_at"] is record["application_drill_at"] is None
    again = query(
        runner.jobs, Page(snapshot_id=first["snapshot_id"]), now=clock[0] + 100, max_age_s=86400
    )
    assert again["snapshot_id"] == first["snapshot_id"]


def test_change_feed_is_atomic_and_collector_replays_without_duplicates(worker, tmp_path):
    import threading

    from steward.backupworker import QueryService
    from steward.collector import Collector
    from steward.core import ipc
    from steward.core.backup_changes import Changes, changes

    runner, backend, clock, _target, _manifest = worker
    backend.fail_restore = True
    assert runner.run_once()["error_class"] == "unavailable"
    before = changes(runner.jobs, Changes())
    assert any(item["error"] == "unavailable" for item in before["changes"])
    assert before["changes"][-1]["integrity_checked_at"] is not None
    with pytest.raises(RuntimeError), runner.jobs._tx() as db:
        db.execute("UPDATE jobs SET error='timeout'")
        raise RuntimeError("rollback")
    assert changes(runner.jobs, Changes()) == before
    socket_path = str(tmp_path / "backup.sock")
    service = QueryService(runner.jobs, {os.getuid(): "collector"}, max_age_s=86400)
    server = ipc.bind(socket_path, service.handle, None)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    collector = Collector(str(tmp_path), backup_socket=socket_path)
    try:
        assert collector.collect_backup(clock[0]) == 1
        events = collector.store.query(kind_prefix="backup.worker_")
        assert len(events) == 1 and events[0]["kind"] == "backup.worker_failure"
        assert events[0]["delivery"] == "immediate"
        assert events[0]["data"]["integrity_checked_at"] is not None
        assert events[0]["data"]["restored_bytes_at"] is None
        assert collector.collect_backup(clock[0]) == 0
        collector.store.close()
        collector = Collector(str(tmp_path), backup_socket=socket_path)
        assert collector.collect_backup(clock[0]) == 0
        clock[0] += 600
        backend.fail_restore = False
        assert runner.run_once()["restored_bytes_verified"]
        assert collector.collect_backup(clock[0]) == 1
        events = collector.store.query(kind_prefix="backup.worker_")
        assert {e["kind"] for e in events} == {"backup.worker_failure", "backup.worker_recovered"}
        assert backend.backup_calls == 1
        with runner.jobs._tx() as db:
            db.execute("DELETE FROM backup_changes")
        # Sequence retains evidence of history loss for an earlier cursor.
        collector.store.add(
            [], {"backup_cursor": {"stream": before["coverage"]["stream_id"], "id": 0}}
        )
        collector.collect_backup(clock[0])
        gaps = collector.store.query(kind_prefix="observation_gap")
        assert any(e["source"] == "backup" for e in gaps)
        assert collector.store.get_meta("backup_cursor")["id"] > 0
        assert collector.collect_backup(clock[0]) == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
        collector.store.close()


def test_existing_jobs_start_feed_with_explicit_baseline(worker, tmp_path):
    from steward.backupworker import Ledger, Upload
    from steward.core.backup_changes import Changes, changes
    from steward.core.store import Store

    _runner, _backend, clock, target, manifest = worker
    path = tmp_path / "legacy.db"
    legacy = Store(path)
    payload = Upload(
        project="notes", artifact=target.name, capture_id=manifest.id, repository_id="c" * 64
    )
    legacy.enqueue(
        "backup_upload",
        "notes",
        payload.model_dump(),
        idempotency_key="legacy",
        created_by="backup",
        now=clock[0],
    )
    legacy.close()
    ledger = Ledger(path)
    first = changes(ledger, Changes())
    assert first["coverage"]["baseline"] is True
    assert len(first["changes"]) == 1 and first["changes"][0]["state"] == "queued"
    ledger.close()
    reopened = Ledger(path)
    assert changes(reopened, Changes()) == first
    reopened.close()


def test_backup_change_feed_restricts_readers(worker):
    import json

    from steward.backupworker import QueryService

    runner, _backend, _clock, _target, _manifest = worker
    service = QueryService(runner.jobs, {101: "api", 102: "collector"}, max_age_s=86400)
    raw = json.dumps({"v": 1, "action": "backups_changes", "params": {}}).encode()
    assert service.handle(raw, 101)["error_class"] == "policy_denied"
    assert service.handle(raw, 102)["ok"] is True
    assert service.handle(raw, 103)["error_class"] == "unauthorized_peer"


def test_collector_detects_interior_feed_loss_and_stream_reset(worker, tmp_path):
    from steward.backupworker import QueryService
    from steward.collector import Collector
    from steward.core.backup_changes import Changes, changes
    from steward.executor.protocol import ExecutorError

    runner, backend, clock, _target, _manifest = worker
    backend.fail_restore = True
    runner.run_once()
    feed = changes(runner.jobs, Changes())
    assert len(feed["changes"]) >= 3
    with runner.jobs._tx() as db:
        db.execute("DELETE FROM backup_changes WHERE id=?", (feed["changes"][1]["id"],))
    service = QueryService(runner.jobs, {42: "collector"}, max_age_s=86400)

    def read(action, params, *, socket_path):
        import json

        response = service.handle(
            json.dumps({"v": 1, "action": action, "params": params}).encode(), 42
        )
        if not response["ok"]:
            raise ExecutorError(response["error_class"], response["message"])
        return response["result"]

    collector = Collector(str(tmp_path), backup_socket="fixture", backup=read)
    collector.collect_backup(clock[0])
    assert len(collector.store.query(kind_prefix="observation_gap")) == 1
    with runner.jobs._tx() as db:
        db.execute("UPDATE backup_feed_meta SET value=? WHERE key='stream'", ("f" * 32,))
    collector.collect_backup(clock[0])
    assert len(collector.store.query(kind_prefix="observation_gap")) == 2
    assert collector.store.get_meta("backup_cursor")["stream"] == "f" * 32


def test_backup_feed_retention_keeps_newest_changes_and_exposes_gap(worker, tmp_path, monkeypatch):
    import steward.core.backup_changes as feed
    from steward.backupworker import Ledger, Upload

    _runner, _backend, clock, target, manifest = worker
    monkeypatch.setattr(feed, "MAX_CHANGES", 3)
    ledger = Ledger(tmp_path / "bounded.db")
    payload = Upload(
        project="notes", artifact=target.name, capture_id=manifest.id, repository_id="c" * 64
    )
    ledger.enqueue(
        "backup_upload",
        "notes",
        payload.model_dump(),
        idempotency_key="bound",
        created_by="backup",
        now=clock[0],
    )
    for error in ("unavailable", "timeout", "unavailable", "timeout"):
        with ledger._tx() as db:
            db.execute("UPDATE jobs SET error=?", (error,))
    result = feed.changes(ledger, feed.Changes())
    assert len(result["changes"]) == 3
    assert result["coverage"]["oldest_id"] == 3
    assert result["coverage"]["newest_id"] == 5
    assert [item["id"] for item in result["changes"]] == [3, 4, 5]
    ledger.close()


def test_disabling_backup_observation_closes_gap_without_claiming_recovery(tmp_path):
    from steward.collector import Collector
    from steward.executor.protocol import ExecutorError

    def unavailable(*args, **kwargs):
        raise ExecutorError("unavailable", "offline")

    collector = Collector(str(tmp_path), backup_socket="fixture", backup=unavailable)
    assert collector.collect_backup(100) == 1
    collector.backup_socket = None
    assert collector.collect_backup(101) == 1
    assert collector.collect_backup(102) == 0
    kinds = {event["kind"] for event in collector.store.query()}
    assert {"observation_gap", "observation_disabled"} <= kinds
    assert "observation_restored" not in kinds
    assert collector.store.get_meta("open_gaps") == []


def test_controller_correlates_root_capture_with_worker_phases_over_socket(worker, tmp_path):
    import threading

    from steward.backupworker import QueryService
    from steward.controller import Controller
    from steward.core import ipc

    runner, backend, clock, _target, manifest = worker
    backend.fail_restore = True
    assert runner.run_once()["error_class"] == "unavailable"
    path = str(tmp_path / "backup-join.sock")
    service = QueryService(
        runner.jobs, {os.getuid(): "controller"}, max_age_s=7200, clock=lambda: clock[0]
    )
    server = ipc.bind(path, service.handle, None)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    root = {
        "state": "exported",
        "config_revision": "a" * 64,
        "capture_id": manifest.id,
        "capture_created_at": manifest.created_at,
        "interval_s": 3600,
    }
    status = {
        "config_revision": "a" * 64,
        "checked_at": clock[0],
        "backup_schedule_observations": {"notes": root},
    }
    ctl = Controller(str(tmp_path), backup_socket=path)
    try:
        observations, findings = ctl.backup_evidence(status)
        item = observations["notes"]
        assert item["state"] == "failed" and findings[0].severity == "high"
        assert item["root_provenance"] == "executor_schedule"
        assert item["worker_provenance"] == "worker_reported"
        assert item["uploaded_at"] is not None and item["integrity_checked_at"] is not None
        assert item["restored_bytes_at"] is item["application_drill_at"] is None
        assert findings[0].remediation is None
        clock[0] += 600
        status["checked_at"] = clock[0]
        backend.fail_restore = False
        assert runner.run_once()["restored_bytes_verified"]
        observations, findings = ctl.backup_evidence(status)
        item = observations["notes"]
        assert item["state"] == "reported" and not findings
        assert item["capture_created_at"] == manifest.created_at
        assert item["restored_bytes_at"] is not None and item["application_drill_at"] is None
        assert backend.backup_calls == 1
        root["capture_id"] = "f" * 64
        status["checked_at"] += 7200
        observations, findings = ctl.backup_evidence(status)
        assert observations["notes"]["state"] == "missing"
        assert "No worker upload record" in findings[0].summary
        root["capture_id"] = manifest.id
        root["capture_created_at"] += 1
        observations, findings = ctl.backup_evidence(status)
        assert observations["notes"]["reason"] == "worker_evidence_mismatch"
        assert findings[0].remediation is None
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_controller_rejects_ambiguous_or_unavailable_worker_evidence(worker, tmp_path):
    from steward.controller import Controller
    from steward.core.backup_join import WorkerRecord, correlate
    from steward.core.backup_observations import Page, query
    from steward.executor.protocol import ExecutorError

    runner, _backend, clock, _target, manifest = worker
    assert runner.run_once()["uploaded"]
    page = query(runner.jobs, Page(), now=clock[0], max_age_s=7200)
    record = WorkerRecord.model_validate(page["records"][0])
    root = {
        "state": "exported",
        "config_revision": "a" * 64,
        "capture_id": manifest.id,
        "capture_created_at": manifest.created_at,
        "interval_s": 3600,
    }
    schedule = {"notes": root}
    duplicate = record.model_copy(update={"job_id": "f" * 32, "repository_id": "e" * 64})
    assert (
        correlate(schedule, [record, duplicate], revision="a" * 64, now=clock[0])["notes"]["reason"]
        == "ambiguous_worker_records"
    )
    invalid = record.model_copy(update={"restored_bytes_at": clock[0] + 100})
    assert (
        correlate(schedule, [invalid], revision="a" * 64, now=clock[0])["notes"]["reason"]
        == "worker_evidence_mismatch"
    )

    def unavailable(*args, **kwargs):
        raise ExecutorError("unavailable", "private details")

    ctl = Controller(str(tmp_path), backup_socket="fixture", backup=unavailable)
    status = {
        "config_revision": "a" * 64,
        "checked_at": clock[0],
        "backup_schedule_observations": schedule,
    }
    observations, findings = ctl.backup_evidence(status)
    assert observations["notes"]["state"] == "unknown"
    assert (
        findings[0].id == "backup_worker_unavailable"
        and "private details" not in findings[0].summary
    )

    page["ledger_coverage"] = "truncated"
    ctl.backup = lambda *args, **kwargs: page
    observations, findings = ctl.backup_evidence(status)
    assert observations["notes"]["state"] == "unknown" and findings[0].remediation is None


def test_controller_can_query_worker_but_cannot_read_change_feed(worker):
    import json

    from steward.backupworker import QueryService

    runner, _backend, _clock, _target, _manifest = worker
    service = QueryService(runner.jobs, {101: "controller"}, max_age_s=7200)
    request = {"v": 1, "params": {}}
    assert service.handle(json.dumps({**request, "action": "backups_query"}).encode(), 101)["ok"]
    assert (
        service.handle(json.dumps({**request, "action": "backups_changes"}).encode(), 101)[
            "error_class"
        ]
        == "policy_denied"
    )


def test_worker_snapshot_pagination_requires_complete_unchanged_evidence(worker):
    from steward.core.backup_join import read_snapshot
    from steward.core.backup_observations import Page, query

    runner, _backend, clock, _target, _manifest = worker
    runner.run_once()
    record = query(runner.jobs, Page(), now=clock[0], max_age_s=7200)["records"][0]
    rows = [{**record, "job_id": f"{i:032x}"} for i in range(201)]
    calls = []

    def request(action, params, *, socket_path, timeout):
        assert action == "backups_query" and timeout == 5
        calls.append(params)
        offset = params["offset"]
        return {
            "snapshot_id": "a" * 64,
            "observed_at": clock[0],
            "ledger_coverage": "complete",
            "total": 201,
            "next_offset": 200 if offset == 0 else None,
            "records": rows[offset : offset + 200],
        }

    assert len(read_snapshot(request, "fixture")) == 201
    assert calls[1]["snapshot_id"] == "a" * 64

    def changed(*args, **kwargs):
        page = request(*args, **kwargs)
        if args[1]["offset"]:
            page["snapshot_id"] = "b" * 64
        return page

    with pytest.raises(ValueError, match="snapshot changed"):
        read_snapshot(changed, "fixture")


def test_controller_cycle_exports_correlated_failure_without_mutation(worker, executor, tmp_path):
    import json
    import threading

    from steward.backupworker import QueryService
    from steward.controller import Controller
    from steward.core import ipc
    from steward.executor import server as executor_server

    runner, backend, clock, _target, manifest = worker
    backend.fail_restore = True
    runner.run_once()
    registry = json.loads(executor.registry_file.read_text())
    status = executor_server.platform_status(
        executor, executor_server.NoParams(), "controller", registry
    )
    status["config_revision"] = "a" * 64
    status["checked_at"] = clock[0]
    status["backup_schedule_observations"] = {
        "notes": {
            "state": "exported",
            "config_revision": "a" * 64,
            "capture_id": manifest.id,
            "capture_created_at": manifest.created_at,
            "interval_s": 3600,
        }
    }
    path = str(tmp_path / "backup-cycle.sock")
    service = QueryService(runner.jobs, {os.getuid(): "controller"}, max_age_s=7200)
    socket_server = ipc.bind(path, service.handle, None)
    thread = threading.Thread(target=socket_server.serve_forever, daemon=True)
    thread.start()

    def executor_call(action, **kwargs):
        assert action == "platform_status"
        return status

    state = tmp_path / "controller-state"
    state.mkdir()
    ctl = Controller(str(state), executor=executor_call, backup_socket=path)
    try:
        snapshot = ctl.cycle(now=clock[0])
        assert snapshot["backup_observations"]["notes"]["state"] == "failed"
        finding = next(f for f in snapshot["findings"] if f["id"] == "backup_worker:notes")
        assert finding["severity"] == "high" and finding["remediation"] is None
        assert not executor.host.calls
        exported = json.loads((state / "export/state.json").read_text())
        assert exported["backup_observations"]["notes"]["application_drill_at"] is None
    finally:
        socket_server.shutdown()
        socket_server.server_close()
        thread.join()


def test_only_root_operator_can_select_exact_completed_backup_receipt(worker):
    import json

    from steward.backupworker import QueryService

    runner, _, clock, _, manifest = worker
    assert runner.run_once()["restored_bytes_verified"]
    service = QueryService(
        runner.jobs,
        {101: "api", 102: "collector", 103: "controller", 104: "operator"},
        max_age_s=86400,
        clock=lambda: clock[0],
    )
    selection = {
        "project": "notes",
        "config_revision": "a" * 64,
        "repository_id": "c" * 64,
        "capture_id": manifest.id,
        "snapshot_id": "d" * 64,
    }

    def request(params):
        return json.dumps({"v": 1, "action": "backups_receipt", "params": params}).encode()

    response = service.handle(request(selection), 0)
    assert response["ok"] is True
    assert response["result"]["receipt"]["snapshot_id"] == selection["snapshot_id"]
    assert response["result"]["receipt"]["capture"]["binding"]["project"] == "notes"
    assert response["result"]["provenance"] == "worker_reported"
    assert response["result"]["production_restore_authorized"] is False
    for uid in (101, 102, 103, 104):
        assert service.handle(request(selection), uid)["error_class"] == "policy_denied"
    assert service.handle(request(selection), 999)["error_class"] == "unauthorized_peer"
    assert (
        service.handle(request({**selection, "path": "/etc/shadow"}), 0)["error_class"]
        == "bad_request"
    )
    for field, value in (
        ("project", "other"),
        ("config_revision", "f" * 64),
        ("repository_id", "f" * 64),
        ("capture_id", "f" * 64),
        ("snapshot_id", "f" * 64),
    ):
        assert service.handle(request({**selection, field: value}), 0)["error_class"] == "conflict"


def test_operator_receipt_requires_completed_check_restore_and_matching_job(worker):
    import json

    from steward.backupworker import QueryService

    runner, backend, clock, _, manifest = worker
    backend.fail_restore = True
    runner.run_once()
    service = QueryService(runner.jobs, {}, max_age_s=86400, clock=lambda: clock[0])
    selection = {
        "project": "notes",
        "config_revision": "a" * 64,
        "repository_id": "c" * 64,
        "capture_id": manifest.id,
        "snapshot_id": "d" * 64,
    }
    request = json.dumps({"v": 1, "action": "backups_receipt", "params": selection}).encode()
    assert service.handle(request, 0)["error_class"] == "conflict"
    backend.fail_restore = False
    clock[0] += 600
    assert runner.run_once()["restored_bytes_verified"]
    assert service.handle(request, 0)["ok"]
    with runner.jobs._tx() as db:
        db.execute("UPDATE jobs SET state='failed' WHERE kind='backup_upload'")
    assert service.handle(request, 0)["error_class"] == "conflict"


def test_hostcli_receipt_uses_fixed_worker_socket_and_exact_selection(monkeypatch, capsys):
    import json
    import sys

    from steward import hostcli

    calls = []
    monkeypatch.setattr(hostcli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        hostcli,
        "call",
        lambda action, params, **kwargs: (
            calls.append((action, params, kwargs))
            or {"provenance": "worker_reported", "production_restore_authorized": False}
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "steward-host",
            "backup-receipt",
            "notes",
            "--config-revision",
            "a" * 64,
            "--repository-id",
            "b" * 64,
            "--capture-id",
            "c" * 64,
            "--snapshot-id",
            "d" * 64,
        ],
    )
    hostcli.main()
    assert calls == [
        (
            "backups_receipt",
            {
                "project": "notes",
                "config_revision": "a" * 64,
                "repository_id": "b" * 64,
                "capture_id": "c" * 64,
                "snapshot_id": "d" * 64,
            },
            {"socket_path": hostcli.BACKUP_SOCKET, "timeout": 10},
        )
    ]
    assert json.loads(capsys.readouterr().out)["production_restore_authorized"] is False


def test_hostcli_receipt_refuses_non_root_before_worker_access(monkeypatch):
    import sys

    from steward import hostcli

    monkeypatch.setattr(hostcli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(hostcli, "call", lambda *args, **kwargs: pytest.fail("worker contacted"))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "steward-host",
            "backup-receipt",
            "notes",
            "--config-revision",
            "a" * 64,
            "--repository-id",
            "b" * 64,
            "--capture-id",
            "c" * 64,
            "--snapshot-id",
            "d" * 64,
        ],
    )
    with pytest.raises(SystemExit, match="must run as root"):
        hostcli.main()


def test_operator_receipt_refuses_truncated_job_history(worker, monkeypatch):
    import json

    from steward import backupworker
    from steward.backupworker import QueryService, Upload

    runner, _, clock, target, manifest = worker
    assert runner.run_once()["restored_bytes_verified"]
    payload = Upload(
        project="notes", artifact=target.name, capture_id=manifest.id, repository_id="c" * 64
    )
    runner.jobs.enqueue(
        "backup_upload",
        "notes",
        payload.model_dump(),
        idempotency_key="second-fixture",
        created_by="backup",
        now=clock[0],
    )
    with runner.jobs._tx() as db:
        db.execute("UPDATE jobs SET state='succeeded' WHERE kind='backup_upload'")
    monkeypatch.setattr(backupworker, "MAX_BACKUP_JOBS", 1)
    service = QueryService(runner.jobs, {}, max_age_s=86400, clock=lambda: clock[0])
    request = json.dumps(
        {
            "v": 1,
            "action": "backups_receipt",
            "params": {
                "project": "notes",
                "config_revision": "a" * 64,
                "repository_id": "c" * 64,
                "capture_id": manifest.id,
                "snapshot_id": "d" * 64,
            },
        }
    ).encode()
    assert service.handle(request, 0)["error_class"] == "conflict"


def test_repository_lock_retries_without_claiming_integrity(worker):
    runner, backend, clock, _target, manifest = worker

    def locked():
        raise BackupError("repository_locked")

    backend.after_upload = locked
    result = runner.run_once()
    assert result["state"] == "queued" and result["error_class"] == "repository_locked"
    assert runner.jobs.receipt("c" * 64, manifest.id) is None
    fresh = Runner(runner.state, runner.imports, backend, clock=lambda: clock[0])
    clock[0] += 600
    backend.after_upload = None
    assert fresh.run_once()["restored_bytes_verified"] is True
    assert backend.uploads == 1


def test_repository_lock_waits_are_durable_bounded_and_preserve_attempts(worker):
    from steward.backupworker import LOCK_RETRY_INTERVAL_S, MAX_LOCK_ATTEMPTS

    runner, backend, clock, _target, manifest = worker

    def locked():
        raise BackupError("repository_locked")

    backend.after_upload = locked
    for attempt in range(MAX_LOCK_ATTEMPTS):
        runner = Runner(runner.state, runner.imports, backend, clock=lambda: clock[0])
        result = runner.run_once()
        job = runner.jobs.get_job(result["job_id"])
        assert result["state"] == ("failed" if attempt == MAX_LOCK_ATTEMPTS - 1 else "queued")
        assert job["error"] == "repository_locked"
        assert job["attempts"] == (1 if result["state"] == "failed" else 0)
        assert runner.jobs.receipt("c" * 64, manifest.id) is None
        if result["state"] == "queued":
            assert job["not_before"] == clock[0] + LOCK_RETRY_INTERVAL_S
            clock[0] += LOCK_RETRY_INTERVAL_S
    assert runner.jobs._conn().execute("SELECT COUNT(*) FROM backup_lock_waits").fetchone()[0] == 0


def test_repository_lock_wait_rejects_stale_lease(worker):
    runner, backend, clock, _target, _manifest = worker

    def steal():
        with runner.jobs._tx() as db:
            db.execute("UPDATE jobs SET lease_owner='replacement'")
        raise BackupError("repository_locked")

    backend.after_upload = steal
    result = runner.run_once()
    assert result["state"] == "lease_lost"
    assert runner.jobs.get_job(result["job_id"])["lease_owner"] == "replacement"
    assert runner.jobs._conn().execute("SELECT COUNT(*) FROM backup_lock_waits").fetchone()[0] == 0


def test_repository_lock_cleared_after_several_restarts_completes_same_capture(worker):
    from steward.backupworker import LOCK_RETRY_INTERVAL_S

    runner, backend, clock, _target, manifest = worker

    def locked():
        raise BackupError("repository_locked")

    backend.after_upload = locked
    ids = set()
    for _ in range(4):
        runner = Runner(runner.state, runner.imports, backend, clock=lambda: clock[0])
        outcome = runner.run_once()
        ids.add(outcome["job_id"])
        assert outcome["state"] == "queued"
        clock[0] += LOCK_RETRY_INTERVAL_S
    backend.after_upload = None
    runner = Runner(runner.state, runner.imports, backend, clock=lambda: clock[0])
    result = runner.run_once()
    assert len(ids) == 1 and result["capture_id"] == manifest.id
    assert result["restored_bytes_verified"] and backend.uploads == 1
    assert runner.jobs._conn().execute("SELECT COUNT(*) FROM backup_lock_waits").fetchone()[0] == 0


def test_owned_lock_recovery_on_last_wait_allows_immediate_retry(worker):
    from steward.backupworker import MAX_LOCK_ATTEMPTS, Upload

    runner, _backend, clock, target, manifest = worker
    payload = Upload(
        project="notes", artifact=target.name, capture_id=manifest.id, repository_id="c" * 64
    )
    job, _ = runner.jobs.enqueue(
        "backup_upload",
        "notes",
        payload.model_dump(),
        idempotency_key="lock-final",
        created_by="backup",
        now=clock[0],
    )
    with runner.jobs._tx() as db:
        db.execute("INSERT INTO backup_lock_waits VALUES (?,?)", (job["id"], MAX_LOCK_ATTEMPTS - 1))
    claimed = runner.jobs.claim("fixture", now=clock[0])
    assert claimed["id"] == job["id"]
    assert (
        runner.jobs.defer_repository_lock(job["id"], "fixture", now=clock[0], recovered=True)
        == "queued"
    )
    updated = runner.jobs.get_job(job["id"])
    assert updated["not_before"] == clock[0] and updated["attempts"] == 0
    assert runner.jobs._conn().execute("SELECT COUNT(*) FROM backup_lock_waits").fetchone()[0] == 0


@pytest.mark.parametrize("allowed", [True, False])
def test_lock_recovery_holds_import_lock_and_requires_fresh_cleanup_permit(
    worker, tmp_path, allowed
):
    from steward.adapters.backups import Restic
    from steward.backupworker import LOCK_RETRY_INTERVAL_S

    runner, _backend, clock, target, _manifest = worker
    for name, value in (("repo", "rest:https://backup.example.org/repo"), ("pass", "x" * 48)):
        path = tmp_path / name
        path.write_text(value)
        path.chmod(0o600)
    adapter = Restic(
        repository_file=tmp_path / "repo",
        password_file=tmp_path / "pass",
        state_dir=tmp_path / "restic",
    )
    adapter.health = lambda: {"ready": True}
    adapter.repository_id = lambda: "c" * 64

    def locked(_path):
        raise BackupError("repository_locked")

    adapter.backup = locked
    deletions = []

    def recover(*, guard):
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)
        guard()
        deletions.append(True)
        return 1

    adapter.recover_observed_locks = recover
    actions = []

    def permit(action, _params, **_kwargs):
        actions.append(action)
        if action == "backup_lock_cleanup_permit" and not allowed:
            return {"permitted": False, "reason": "unavailable"}
        return {"permitted": True, "reason": "registered"}

    runner.adapter, runner.permit = adapter, permit
    result = runner.run_once()
    assert result["state"] == "queued"
    assert actions == ["backup_upload_permit", "backup_lock_cleanup_permit"]
    assert deletions == ([True] if allowed else [])
    job = runner.jobs.get_job(result["job_id"])
    assert job["not_before"] == clock[0] + (0 if allowed else LOCK_RETRY_INTERVAL_S)
