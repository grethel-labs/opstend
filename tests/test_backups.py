import json
import os
import sqlite3
import stat
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest

from steward.adapters.backups import Restic, line_secret, repository_url
from steward.core.backups import BackupError, Binding, capture_sqlite, load_capture


@pytest.fixture
def binding():
    return Binding(
        server="test-server",
        project="notes",
        config_revision="a" * 64,
        image="docker.io/library/python@sha256:" + "b" * 64,
        source_revision="bundled:sample-notes@0.1.0",
    )


@pytest.fixture
def database(tmp_path):
    path = tmp_path / "notes.db"
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, value TEXT)")
    db.execute("INSERT INTO notes VALUES (1,'committed')")
    db.commit()
    yield path, db
    db.close()


def test_sqlite_capture_includes_wal_and_excludes_uncommitted_data(database, tmp_path, binding):
    path, db = database
    db.execute("UPDATE notes SET value='not committed'")
    target = tmp_path / "capture"
    manifest = capture_sqlite(path, target, binding)
    assert manifest == load_capture(target)
    assert manifest.origin == "operator_local"
    assert stat.S_IMODE(target.stat().st_mode) == 0o700
    assert stat.S_IMODE((target / "database.sqlite").stat().st_mode) == 0o600
    with sqlite3.connect(target / "database.sqlite") as restored:
        assert restored.execute("SELECT value FROM notes").fetchone()[0] == "committed"
        assert restored.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    assert {p.name for p in target.iterdir()} == {"manifest.json", "database.sqlite"}


def test_capture_is_transactionally_consistent_while_writer_runs(tmp_path, binding):
    path = tmp_path / "live.db"
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE balances(id INTEGER PRIMARY KEY, value INTEGER)")
    db.executemany("INSERT INTO balances VALUES (?,?)", [(1, 0), (2, 0)])
    db.commit()
    stop, started = threading.Event(), threading.Event()

    def writer():
        connection = sqlite3.connect(path)
        try:
            while not stop.is_set():
                with connection:
                    connection.execute("UPDATE balances SET value=value+1 WHERE id=1")
                    connection.execute("UPDATE balances SET value=value-1 WHERE id=2")
                started.set()
        finally:
            connection.close()

    thread = threading.Thread(target=writer)
    thread.start()
    try:
        assert started.wait(5)
        target = tmp_path / "captured"
        capture_sqlite(path, target, binding)
        with sqlite3.connect(target / "database.sqlite") as restored:
            assert restored.execute("SELECT SUM(value) FROM balances").fetchone()[0] == 0
    finally:
        stop.set()
        thread.join(5)
        db.close()
    assert not thread.is_alive()


def test_tampering_extra_files_and_existing_capture_are_rejected(database, tmp_path, binding):
    path, _db = database
    target = tmp_path / "capture"
    original = capture_sqlite(path, target, binding)
    with pytest.raises(FileExistsError):
        capture_sqlite(path, target, binding)
    assert load_capture(target) == original
    (target / "secret").write_text("never include credentials")
    with pytest.raises(BackupError, match="invalid_input"):
        load_capture(target)
    (target / "secret").unlink()
    with (target / "database.sqlite").open("ab") as handle:
        handle.write(b"changed")
    with pytest.raises(BackupError):
        load_capture(target)


def test_capture_limits_and_invalid_database_fail_without_finished_manifest(
    database, tmp_path, binding
):
    path, _db = database
    for source, name, limit in ((path, "small", 1024), (tmp_path / "invalid", "bad", 102400)):
        if source != path:
            source.write_bytes(b"not a database")
        target = tmp_path / name
        with pytest.raises(BackupError):
            capture_sqlite(source, target, binding, max_bytes=limit)
        assert not target.exists()
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(OSError):
        capture_sqlite(link, tmp_path / "link-capture", binding)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(BackupError):
        capture_sqlite(fifo, tmp_path / "fifo-capture", binding)


@pytest.mark.parametrize(
    "url",
    [
        "sftp:host:/data",
        "rclone:remote:repo",
        "/local/repo",
        "rest:http://host/repo",
        "rest:https://user:secret@host/repo",
        "rest:https://host:0/repo",
        "rest:https://host/../repo",
        "rest:https://host/repo?x=y",
        "rest:https://host/repo#fragment",
        "rest:https://ho\nst/repo",
    ],
)
def test_only_explicit_unambiguous_rest_https_repository_is_allowed(url):
    with pytest.raises(BackupError, match="invalid_repository"):
        repository_url(url.encode())


class FixtureRestic(Restic):
    def __init__(self, tmp_path, capture):
        for name, value in (("repo", "rest:https://backup.example.org/repo"), ("pass", "x" * 48)):
            file = tmp_path / name
            file.write_text(value)
            file.chmod(0o600)
        super().__init__(
            repository_file=tmp_path / "repo",
            password_file=tmp_path / "pass",
            state_dir=tmp_path / "state",
        )
        self.capture = capture
        self.calls = []
        self.saved = False
        self.failed = False
        self.snapshot_time = datetime.now(UTC).isoformat()

    def _run(self, args, *, cwd=None):
        self.calls.append(args)
        if self.failed:
            raise BackupError("unavailable")
        if args[0] == "version":
            return b'{"version":"0.19.1"}'
        if args[:2] == ["cat", "config"]:
            return json.dumps({"version": 2, "id": "c" * 64}).encode()
        if args[0] == "snapshots":
            return json.dumps([{"id": "d" * 64}] if self.saved else []).encode()
        if args[0] == "backup":
            self.saved = True
            return json.dumps({"message_type": "summary", "snapshot_id": "d" * 64}).encode()
        if args[:2] == ["cat", "snapshot"]:
            return json.dumps(
                {
                    "paths": [str(self.capture.resolve())],
                    "hostname": "steward",
                    "time": self.snapshot_time,
                    "tags": self._tags(load_capture(self.capture)),
                }
            ).encode()
        if args[0] == "check":
            return b'{"message_type":"summary","num_errors":0}'
        raise AssertionError(args)


def test_backup_retry_is_idempotent_and_upload_is_not_restore_proof(database, tmp_path, binding):
    path, _db = database
    target = tmp_path / "capture"
    capture_sqlite(path, target, binding)
    adapter = FixtureRestic(tmp_path, target)
    receipt = adapter.backup(target)
    retried = adapter.backup(target)
    assert receipt.snapshot_id == retried.snapshot_id
    assert receipt.snapshot_created_at == retried.snapshot_created_at
    assert sum(args[0] == "backup" for args in adapter.calls) == 1
    assert next(args for args in adapter.calls if args[0] == "backup")[-1] == str(target)
    assert receipt.integrity_checked_at is receipt.restore_verified_at is None
    checked = adapter.check(receipt)
    assert checked.integrity_checked_at is not None and checked.restore_verified_at is None
    assert checked.application_verified is False
    assert ["check", "--read-data"] in adapter.calls
    adapter.failed = True
    with pytest.raises(BackupError):
        adapter.check(checked)
    assert checked.restore_verified_at is None


def test_adapter_refuses_putting_credential_state_inside_backup_source(database, tmp_path, binding):
    path, _db = database
    target = tmp_path / "capture"
    capture_sqlite(path, target, binding)
    adapter = FixtureRestic(tmp_path, target)
    adapter.state = target / "would-leak-credentials"
    with pytest.raises(BackupError, match="invalid_input"):
        adapter.backup(target)
    assert not adapter.calls


def test_malformed_snapshot_row_is_a_stable_failure(database, tmp_path, binding):
    path, _db = database
    target = tmp_path / "capture"
    capture_sqlite(path, target, binding)
    adapter = FixtureRestic(tmp_path, target)
    original = adapter._run

    def malformed(args, **kwargs):
        return b"[null]" if args[0] == "snapshots" else original(args, **kwargs)

    adapter._run = malformed
    with pytest.raises(BackupError, match="invalid_response"):
        adapter.backup(target)


@pytest.mark.parametrize("suffix", [b"", b"\n", b"\r\n"])
def test_single_line_password_preserves_spaces_and_accepts_one_line_ending(tmp_path, suffix):
    path = tmp_path / "secret"
    value = b" " + b"x" * 48 + b" "
    path.write_bytes(value + suffix)
    path.chmod(0o600)
    assert line_secret(path, minimum=32) == value


@pytest.mark.parametrize("value", [b"short\n" + b"x" * 48, b"x" * 48 + b"\n\n", b"x" * 32 + b"\ry"])
def test_multiline_password_cannot_pass_length_check_using_ignored_lines(tmp_path, value):
    path = tmp_path / "secret"
    path.write_bytes(value)
    path.chmod(0o600)
    with pytest.raises(BackupError, match="invalid_credentials"):
        line_secret(path, minimum=32)


def test_restored_capture_is_exact_private_and_cleaned_on_error(database, tmp_path, binding):
    import shutil

    path, _db = database
    source = tmp_path / "capture"
    manifest = capture_sqlite(path, source, binding)
    adapter = FixtureRestic(tmp_path, source)
    adapter.state.mkdir(mode=0o700)
    receipt = adapter.backup(source)
    original = adapter._run
    targets = []

    def execute(args, **kwargs):
        if args[0] == "restore":
            assert args[1] == receipt.snapshot_id + ":" + receipt.snapshot_path
            assert args[-1] == "--verify"
            dest = Path(args[args.index("--target") + 1])
            targets.append(dest)
            for item in source.iterdir():
                shutil.copyfile(item, dest / item.name)
            return b""
        return original(args, **kwargs)

    adapter._run = execute
    with (
        pytest.raises(RuntimeError, match="interrupted"),
        adapter.restored_capture(receipt) as (target, restored),
    ):
        assert restored == manifest and load_capture(target) == manifest
        assert target.parent == adapter.state and target.stat().st_mode & 0o077 == 0
        raise RuntimeError("interrupted")
    assert len(targets) == 1 and not targets[0].exists()
    result = adapter.restore_test(receipt)
    assert result.restore_verified_at is not None and result.application_verified is False
    assert all(not path.exists() for path in targets)


def test_restored_capture_refuses_wrong_repository_or_tampered_data(database, tmp_path, binding):
    import shutil

    path, _db = database
    source = tmp_path / "capture"
    capture_sqlite(path, source, binding)
    adapter = FixtureRestic(tmp_path, source)
    adapter.state.mkdir(mode=0o700)
    receipt = adapter.backup(source)
    with (
        pytest.raises(BackupError, match="evidence_mismatch"),
        adapter.restored_capture(receipt.model_copy(update={"repository_id": "f" * 64})),
    ):
        pytest.fail("mismatched repository was accepted")
    original = adapter._run
    targets = []

    def execute(args, **kwargs):
        if args[0] == "restore":
            dest = Path(args[args.index("--target") + 1])
            targets.append(dest)
            for item in source.iterdir():
                shutil.copyfile(item, dest / item.name)
            (dest / "database.sqlite").write_bytes(b"damaged")
            return b""
        return original(args, **kwargs)

    adapter._run = execute
    with pytest.raises(BackupError), adapter.restored_capture(receipt):
        pytest.fail("damaged restore was accepted")
    assert targets and all(not path.exists() for path in targets)


def test_restored_tree_provides_verified_private_tree_and_cleans_up(tmp_path, binding):
    import shutil

    from steward.core.filebackups import capture_files

    source = tmp_path / "source"
    source.mkdir()
    (source / "empty").mkdir()
    (source / "attachment").write_text("private attachment")
    capture = tmp_path / "capture"
    manifest = capture_files(source, capture, binding, is_quiescent=lambda: True)
    adapter = FixtureRestic(tmp_path, capture)
    adapter.state.mkdir(mode=0o700)
    receipt = adapter.backup(capture)
    original = adapter._run
    targets = []

    def execute(args, **kwargs):
        if args[0] == "restore":
            dest = Path(args[args.index("--target") + 1])
            targets.append(dest)
            for item in capture.iterdir():
                shutil.copyfile(item, dest / item.name)
            return b""
        return original(args, **kwargs)

    adapter._run = execute
    with (
        pytest.raises(RuntimeError, match="consumer interrupted"),
        adapter.restored_tree(receipt) as (data, restored),
    ):
        assert restored == manifest
        assert (data / "empty").is_dir()
        assert (data / "attachment").read_text() == "private attachment"
        targets.append(data.parent)
        raise RuntimeError("consumer interrupted")
    assert len(targets) == 2 and all(not target.exists() for target in targets)
    assert receipt.restore_verified_at is None and receipt.application_verified is False


def test_read_only_adapter_never_attempts_repository_mutation(tmp_path, monkeypatch):
    from steward.adapters import backups

    repository, password = tmp_path / "repo", tmp_path / "password"
    repository.write_text("rest:https://backup.example.org/repo")
    password.write_text("x" * 48)
    repository.chmod(0o600)
    password.chmod(0o600)
    adapter = Restic(
        repository_file=repository,
        password_file=password,
        state_dir=tmp_path / "state",
        read_only=True,
    )
    commands = []
    monkeypatch.setattr(
        backups, "run_bounded", lambda argv, **kwargs: commands.append(argv) or b"{}"
    )
    adapter._run(["cat", "config"])
    assert "--no-lock" in commands[0] and commands[0][-2:] == ["cat", "config"]
    for args in (
        ["init"],
        ["backup", "/source"],
        ["forget", "--prune"],
        ["snapshots", "--tag", "x"],
    ):
        with pytest.raises(BackupError, match="policy_denied"):
            adapter._run(args)
    assert len(commands) == 1


def test_systemd_credential_acl_only_allows_service_user(monkeypatch):
    import struct

    from steward.adapters.backups import _systemd_acl

    uid = 1234
    entries = [
        (1, 4, 0xFFFFFFFF),
        (2, 4, uid),
        (4, 0, 0xFFFFFFFF),
        (16, 4, 0xFFFFFFFF),
        (32, 0, 0xFFFFFFFF),
    ]

    def encoded(items):
        return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *item) for item in items)

    monkeypatch.setattr("os.getxattr", lambda *_: encoded(entries))
    assert _systemd_acl(1, uid, 4)
    assert not _systemd_acl(1, uid + 1, 4)
    assert not _systemd_acl(1, uid, 5)
    monkeypatch.setattr("os.getxattr", lambda *_: encoded(entries + [(2, 4, uid + 1)]))
    assert not _systemd_acl(1, uid, 4)
    monkeypatch.setattr("os.getxattr", lambda *_: b"invalid")
    assert not _systemd_acl(1, uid, 4)


def test_group_readable_ordinary_secret_remains_rejected(tmp_path, monkeypatch):
    secret = tmp_path / "secret"
    secret.write_bytes(b"a" * 48)
    secret.chmod(0o640)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    with pytest.raises(BackupError, match="invalid_credentials"):
        line_secret(secret, minimum=32)


def test_repository_identity_lookup_has_short_deadline_without_shortening_data_checks(
    tmp_path, monkeypatch
):
    from steward.core.process import CommandError

    repository = tmp_path / "repository"
    password = tmp_path / "password"
    repository.write_text("rest:https://backup.example.org/repo")
    password.write_text("x" * 48)
    repository.chmod(0o600)
    password.chmod(0o600)
    adapter = Restic(
        repository_file=repository, password_file=password, state_dir=tmp_path / "state"
    )
    timeouts = []

    def run(argv, *, cwd, env, timeout, max_bytes):
        timeouts.append(timeout)
        if argv[-2:] == ["cat", "config"]:
            raise CommandError("timeout")
        return b"{}"

    monkeypatch.setattr("steward.adapters.backups.run_bounded", run)
    with pytest.raises(BackupError, match="timeout"):
        adapter.repository_id()
    adapter._run(["check", "--read-data"])
    assert timeouts == [30, adapter.timeout_s]


@pytest.mark.parametrize(
    ("exit_code", "expected"),
    [(11, "repository_locked"), (1, "unavailable"), (None, "unavailable")],
)
def test_restic_reports_repository_lock_without_exposing_process_output(
    tmp_path, monkeypatch, caplog, exit_code, expected
):
    from steward.adapters import backups
    from steward.core.process import CommandError

    for name, value in (("repo", "rest:https://backup.example.org/repo"), ("pass", "x" * 48)):
        path = tmp_path / name
        path.write_text(value)
        path.chmod(0o600)
    adapter = Restic(
        repository_file=tmp_path / "repo",
        password_file=tmp_path / "pass",
        state_dir=tmp_path / "state",
    )

    def failed(*args, **kwargs):
        raise CommandError("unavailable", exit_code=exit_code)

    monkeypatch.setattr(backups, "run_bounded", failed)
    with pytest.raises(BackupError, match=expected) as error:
        adapter._run(["check", "--read-data"])
    assert error.value.error_class == expected
    expected_log = "Restic check failed (unavailable"
    if exit_code is not None:
        expected_log += f", exit {exit_code}"
    assert [record.getMessage() for record in caplog.records] == [expected_log + ")"]


def test_lock_recovery_only_deletes_exact_reverified_candidate(tmp_path, monkeypatch):
    from steward.core import restic_process_journal

    for name, value in (("repo", "rest:https://backup.example.org/repo"), ("pass", "x" * 48)):
        path = tmp_path / name
        path.write_text(value)
        path.chmod(0o600)
    adapter = Restic(
        repository_file=tmp_path / "repo",
        password_file=tmp_path / "pass",
        state_dir=tmp_path / "state",
    )
    adapter.set_job_context(job_id="a" * 32, repository_id="b" * 64, capture_id="c" * 64)
    lock = {"pid": 123, "time": "fixture"}
    monkeypatch.setattr(
        restic_process_journal,
        "recoverable_lock_bindings",
        lambda *args, **kwargs: [("d" * 64, lock, 123)],
    )
    values = {"config": {"id": "b" * 64}, "lock": lock}
    present = {"d" * 64}
    monkeypatch.setattr(
        adapter,
        "_run",
        lambda args, **kwargs: (
            "\n".join(present).encode()
            if args[0] == "list"
            else json.dumps(values[args[1]]).encode()
        ),
    )
    deleted = []

    def remove(lock_id):
        deleted.append(lock_id)
        present.remove(lock_id)

    monkeypatch.setattr(adapter, "_delete_exact_lock", remove)
    guards = []
    assert adapter.recover_observed_locks(guard=lambda: guards.append(True)) == 1
    assert deleted == ["d" * 64] and len(guards) == 2
    deleted.clear()
    present.add("d" * 64)
    values["lock"] = {"pid": 456}
    assert adapter.recover_observed_locks(guard=lambda: None) == 0 and not deleted
    values["config"] = {"id": "e" * 64}
    with pytest.raises(BackupError, match="repository_changed"):
        adapter.recover_observed_locks(guard=lambda: None)
    assert not deleted


def test_lock_recovery_rechecks_authority_before_deletion(tmp_path, monkeypatch):
    from steward.core import restic_process_journal

    for name, value in (("repo", "rest:https://backup.example.org/repo"), ("pass", "x" * 48)):
        path = tmp_path / name
        path.write_text(value)
        path.chmod(0o600)
    adapter = Restic(
        repository_file=tmp_path / "repo",
        password_file=tmp_path / "pass",
        state_dir=tmp_path / "state",
    )
    adapter.set_job_context(job_id="a" * 32, repository_id="b" * 64, capture_id="c" * 64)
    lock = {"pid": 123}
    monkeypatch.setattr(
        restic_process_journal,
        "recoverable_lock_bindings",
        lambda *args, **kwargs: [("d" * 64, lock, 123)],
    )
    values = {"config": {"id": "b" * 64}, "lock": lock}
    monkeypatch.setattr(
        adapter,
        "_run",
        lambda args, **kwargs: (
            ("d" * 64).encode() if args[0] == "list" else json.dumps(values[args[1]]).encode()
        ),
    )
    deleted = []
    monkeypatch.setattr(adapter, "_delete_exact_lock", deleted.append)
    calls = []

    def guard():
        calls.append(True)
        if len(calls) == 2:
            raise BackupError("lease_lost")

    with pytest.raises(BackupError, match="lease_lost"):
        adapter.recover_observed_locks(guard=guard)
    assert not deleted


def test_exact_lock_delete_uses_fixed_https_path_and_rejects_redirect(tmp_path, monkeypatch):
    from steward.adapters import backups

    for name, value in (("repo", "rest:https://backup.example.org/repo"), ("pass", "x" * 48)):
        path = tmp_path / name
        path.write_text(value)
        path.chmod(0o600)
    adapter = Restic(
        repository_file=tmp_path / "repo",
        password_file=tmp_path / "pass",
        state_dir=tmp_path / "state",
    )
    calls = []

    class Response:
        status = 204

        def read(self, limit):
            assert limit == 65537
            return b""

    class Connection:
        def __init__(self, host, port, **kwargs):
            assert host == "backup.example.org" and port == 443 and kwargs["timeout"] == 10

        def request(self, method, path, **kwargs):
            calls.append((method, path))

        def getresponse(self):
            return Response()

        def close(self):
            pass

    monkeypatch.setattr(backups.http.client, "HTTPSConnection", Connection)
    adapter._delete_exact_lock("d" * 64)
    assert calls == [("DELETE", "/repo/locks/" + "d" * 64)]
    with pytest.raises(BackupError, match="policy_denied"):
        adapter._delete_exact_lock("../foreign")
    Response.status = 302
    with pytest.raises(BackupError, match="unavailable"):
        adapter._delete_exact_lock("d" * 64)


def test_lock_cleanup_does_not_claim_recovery_if_lock_remains(tmp_path, monkeypatch):
    from steward.core import restic_process_journal

    for name, value in (("repo", "rest:https://backup.example.org/repo"), ("pass", "x" * 48)):
        path = tmp_path / name
        path.write_text(value)
        path.chmod(0o600)
    adapter = Restic(
        repository_file=tmp_path / "repo",
        password_file=tmp_path / "pass",
        state_dir=tmp_path / "state",
    )
    adapter.set_job_context(job_id="a" * 32, repository_id="b" * 64, capture_id="c" * 64)
    lock = {"pid": 123}
    monkeypatch.setattr(
        restic_process_journal,
        "recoverable_lock_bindings",
        lambda *args, **kwargs: [("d" * 64, lock, 123)],
    )
    values = {"config": {"id": "b" * 64}, "lock": lock}
    monkeypatch.setattr(
        adapter,
        "_run",
        lambda args, **kwargs: (
            ("d" * 64).encode() if args[0] == "list" else json.dumps(values[args[1]]).encode()
        ),
    )
    monkeypatch.setattr(adapter, "_delete_exact_lock", lambda lock_id: None)
    with pytest.raises(BackupError, match="unavailable"):
        adapter.recover_observed_locks(guard=lambda: None)


def test_absent_old_binding_does_not_block_a_later_owned_lock(tmp_path, monkeypatch):
    from steward.core import restic_process_journal

    for name, value in (("repo", "rest:https://backup.example.org/repo"), ("pass", "x" * 48)):
        path = tmp_path / name
        path.write_text(value)
        path.chmod(0o600)
    adapter = Restic(
        repository_file=tmp_path / "repo",
        password_file=tmp_path / "pass",
        state_dir=tmp_path / "state",
    )
    adapter.set_job_context(job_id="a" * 32, repository_id="b" * 64, capture_id="c" * 64)
    old, active = "d" * 64, "e" * 64
    candidates = [(old, {"pid": 123}, 123), (active, {"pid": 456}, 456)]
    monkeypatch.setattr(
        restic_process_journal, "recoverable_lock_bindings", lambda *args, **kwargs: candidates
    )
    present = {active}
    reads = []

    def read(args, **kwargs):
        if args == ["cat", "config"]:
            return json.dumps({"id": "b" * 64}).encode()
        if args == ["list", "locks"]:
            return "\n".join(present).encode()
        reads.append(args[2])
        return json.dumps({"pid": 456}).encode()

    def remove(lock_id):
        assert lock_id == active
        present.remove(lock_id)

    monkeypatch.setattr(adapter, "_run", read)
    monkeypatch.setattr(adapter, "_delete_exact_lock", remove)
    assert adapter.recover_observed_locks(guard=lambda: None) == 1
    assert reads == [active] and not present


def test_lock_disappearing_during_read_is_skipped_only_after_fresh_listing(tmp_path, monkeypatch):
    from steward.core import restic_process_journal

    for name, value in (("repo", "rest:https://backup.example.org/repo"), ("pass", "x" * 48)):
        path = tmp_path / name
        path.write_text(value)
        path.chmod(0o600)
    adapter = Restic(
        repository_file=tmp_path / "repo",
        password_file=tmp_path / "pass",
        state_dir=tmp_path / "state",
    )
    adapter.set_job_context(job_id="a" * 32, repository_id="b" * 64, capture_id="c" * 64)
    old, active = "d" * 64, "e" * 64
    candidates = [(old, {"pid": 123}, 123), (active, {"pid": 456}, 456)]
    monkeypatch.setattr(
        restic_process_journal, "recoverable_lock_bindings", lambda *args, **kwargs: candidates
    )
    present = {old, active}

    def read(args, **kwargs):
        if args == ["cat", "config"]:
            return json.dumps({"id": "b" * 64}).encode()
        if args == ["list", "locks"]:
            return "\n".join(sorted(present)).encode()
        if args[2] == old:
            present.remove(old)
            raise BackupError("unavailable")
        return json.dumps({"pid": 456}).encode()

    monkeypatch.setattr(adapter, "_run", read)
    monkeypatch.setattr(adapter, "_delete_exact_lock", present.remove)
    assert adapter.recover_observed_locks(guard=lambda: None) == 1 and not present
