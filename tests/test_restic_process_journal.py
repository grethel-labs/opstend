import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from steward.core.backups import BackupError
from steward.core.process import run_bounded
from steward.core.restic_process_journal import ResticProcessJournal, process_start_ticks


def journal(root):
    return ResticProcessJournal(root, job_id="a" * 32, repository_id="b" * 64, capture_id="c" * 64)


def test_child_waits_until_bound_record_is_durable(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    record = journal(state)
    marker = tmp_path / "executed"

    def before_start(pid):
        assert not marker.exists()
        record.record(pid, operation="backup")
        body = json.loads(record.path.read_text())
        assert body["pid"] == pid and body["start_ticks"] == process_start_ticks(pid)
        assert body["job_id"] == "a" * 32 and body["repository_id"] == "b" * 64

    run_bounded(
        [sys.executable, "-c", "import pathlib,sys;pathlib.Path(sys.argv[1]).touch()", str(marker)],
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin"},
        timeout=5,
        max_bytes=100,
        on_start=before_start,
    )
    assert marker.exists() and record.path.exists()
    record.clear_success()
    assert not list((state / "process-journal").iterdir())


def test_failed_durable_callback_never_executes_child(tmp_path):
    marker = tmp_path / "executed"

    def reject(_pid):
        raise BackupError("unsafe_state")

    with pytest.raises(BackupError, match="unsafe_state"):
        run_bounded(
            [
                sys.executable,
                "-c",
                "import pathlib,sys;pathlib.Path(sys.argv[1]).touch()",
                str(marker),
            ],
            cwd=tmp_path,
            env={"PATH": "/usr/bin:/bin"},
            timeout=5,
            max_bytes=100,
            on_start=reject,
        )
    assert not marker.exists()


def test_parent_death_before_release_prevents_child_execution(tmp_path):
    marker = tmp_path / "executed"
    announced = tmp_path / "announced"
    code = """import os,pathlib,sys,time
from steward.core.process import run_bounded
def blocked(pid):
 pathlib.Path(sys.argv[1]).write_text(str(pid));time.sleep(30)
run_bounded([sys.executable,'-c','import pathlib,sys;pathlib.Path(sys.argv[1]).touch()',sys.argv[2]],cwd=pathlib.Path(sys.argv[3]),env={'PATH':'/usr/bin:/bin'},timeout=60,max_bytes=100,on_start=blocked)
"""
    parent = subprocess.Popen(
        [sys.executable, "-c", code, str(announced), str(marker), str(tmp_path)]
    )
    try:
        end = time.monotonic() + 10
        while not announced.exists() and time.monotonic() < end:
            assert parent.poll() is None
            time.sleep(0.01)
        assert announced.exists()
        pid = int(announced.read_text())
        parent.kill()
        parent.wait(timeout=5)
        end = time.monotonic() + 5
        while Path(f"/proc/{pid}/stat").exists() and time.monotonic() < end:
            if Path(f"/proc/{pid}/stat").read_text().split()[2] == "Z":
                break
            time.sleep(0.01)
        assert not marker.exists()
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait(timeout=5)


def test_unsafe_journal_directory_is_rejected(tmp_path):
    (tmp_path / "process-journal").symlink_to(tmp_path)
    with pytest.raises(BackupError, match="unsafe_state"):
        journal(tmp_path).record(os.getpid(), operation="backup")


def test_exact_lock_is_bound_only_to_live_matching_process(tmp_path):
    from datetime import UTC, datetime

    record = journal(tmp_path)
    record.record(os.getpid(), operation="backup")
    lock = {
        "time": datetime.now(UTC).isoformat(),
        "pid": os.getpid(),
        "uid": os.geteuid(),
        "gid": os.getegid(),
        "hostname": record.recorded["host"],
        "username": "fixture",
        "exclusive": False,
    }
    for key, value in (("pid", os.getpid() + 1), ("uid", os.geteuid() + 1), ("hostname", "other")):
        altered = {**lock, key: value}
        assert not record.bind_observed_lock("d" * 64, altered)
    assert not record.bind_observed_lock("../unsafe", lock)
    assert record.bind_observed_lock("d" * 64, lock)
    binding = next((tmp_path / "process-journal").glob("*.lock"))
    assert json.loads(binding.read_text())["process_record"] == record.path.name
    assert not record.bind_observed_lock("d" * 64, lock)
    record.clear_success()
    assert not list((tmp_path / "process-journal").iterdir())


def test_reused_or_missing_process_cannot_bind_a_lock(tmp_path, monkeypatch):
    from datetime import UTC, datetime

    record = journal(tmp_path)
    record.record(os.getpid(), operation="backup")
    lock = {
        "time": datetime.now(UTC).isoformat(),
        "pid": os.getpid(),
        "uid": os.geteuid(),
        "gid": os.getegid(),
        "hostname": record.recorded["host"],
        "exclusive": False,
    }
    monkeypatch.setitem(record.recorded, "start_ticks", record.recorded["start_ticks"] + 1)
    assert not record.process_is_live()
    assert not record.bind_observed_lock("e" * 64, lock)
    assert not list((tmp_path / "process-journal").glob("*.lock"))


def test_recovery_candidates_require_absent_exact_observed_process(tmp_path):
    from datetime import UTC, datetime

    from steward.core.restic_process_journal import recoverable_lock_bindings

    child = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"])
    try:
        record = journal(tmp_path)
        record.record(child.pid, operation="backup")
        lock = {
            "time": datetime.now(UTC).isoformat(),
            "pid": child.pid,
            "uid": os.geteuid(),
            "gid": os.getegid(),
            "hostname": record.recorded["host"],
            "exclusive": False,
        }
        assert record.bind_observed_lock("d" * 64, lock)
        context = {"job_id": "a" * 32, "repository_id": "b" * 64, "capture_id": "c" * 64}
        assert recoverable_lock_bindings(tmp_path, **context) == []
        child.kill()
        child.wait(timeout=5)
        assert recoverable_lock_bindings(tmp_path, **context) == [("d" * 64, lock, child.pid)]
        assert recoverable_lock_bindings(tmp_path, **{**context, "repository_id": "e" * 64}) == []
        assert recoverable_lock_bindings(tmp_path, **{**context, "job_id": "f" * 32}) == []
        data = json.loads(record.path.read_text())
        data["boot_id"] = "f" * 36
        record.path.write_text(json.dumps(data))
        assert recoverable_lock_bindings(tmp_path, **context) == []
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def test_recovery_rejects_unsafe_binding_and_unknown_process(tmp_path, monkeypatch):
    from datetime import UTC, datetime

    from steward.core import restic_process_journal as module

    record = journal(tmp_path)
    record.record(os.getpid(), operation="backup")
    lock = {
        "time": datetime.now(UTC).isoformat(),
        "pid": os.getpid(),
        "uid": os.geteuid(),
        "gid": os.getegid(),
        "hostname": record.recorded["host"],
        "exclusive": False,
    }
    assert record.bind_observed_lock("d" * 64, lock)
    binding = next((tmp_path / "process-journal").glob("*.lock"))
    binding.chmod(0o666)
    args = {"job_id": "a" * 32, "repository_id": "b" * 64, "capture_id": "c" * 64}
    with pytest.raises(BackupError, match="unsafe_state"):
        module.recoverable_lock_bindings(tmp_path, **args)
    binding.chmod(0o600)
    actual = os.kill

    def inaccessible(pid, signal):
        if pid == os.getpid() and signal == 0:
            raise PermissionError("unknown")
        return actual(pid, signal)

    monkeypatch.setattr(os, "kill", inaccessible)
    with pytest.raises(BackupError, match="process_identity_unknown"):
        module.recoverable_lock_bindings(tmp_path, **args)
