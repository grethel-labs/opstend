"""Unprivileged guest workspace and interruption guards for restore drills."""

import importlib.util
import io
import os
import tarfile
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "restore_guest", Path(__file__).with_name("restore_guest.py")
)
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


@pytest.fixture
def state():
    return {
        "v": 1,
        "token": "a" * 32,
        "uid": os.geteuid(),
        "uuid": "3b35da2d-cff1-4412-9b26-6b28440b1f18",
        "boot_id": "e03b068f-8076-48be-a90f-987724d10623",
        "commit": "b" * 40,
        "files": {name: "c" * 64 for name in guest.FILES},
    }


def workspace(tmp_path, state, *, marker=True):
    root = tmp_path / ("steward-restore-" + state["token"])
    root.mkdir(mode=0o700)
    lock = guest.open_lock(root, create=True)
    os.close(lock)
    if marker:
        guest.write_new(root / "ownership.json", guest.marker_bytes(state))
    return root


def test_cleanup_removes_only_owned_workspace_without_following_symlinks(
    tmp_path, state, monkeypatch
):
    root = workspace(tmp_path, state)
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    (foreign / "keep").write_text("untouched")
    (root / "link").symlink_to(foreign, target_is_directory=True)
    (root / "secret").write_bytes(b"fixture")
    monkeypatch.setattr(guest, "containers_empty", lambda: None)
    guest.clean(root, state)
    assert not root.exists()
    assert (foreign / "keep").read_text() == "untouched"


def test_cleanup_refuses_active_lock_and_leaves_credentials(tmp_path, state, monkeypatch):
    root = workspace(tmp_path, state)
    (root / "secret").write_bytes(b"fixture")
    lock = guest.open_lock(root)
    monkeypatch.setattr(guest, "containers_empty", lambda: None)
    try:
        with pytest.raises(BlockingIOError):
            guest.clean(root, state)
        assert (root / "secret").read_bytes() == b"fixture"
    finally:
        os.close(lock)
    guest.clean(root, state)
    assert not root.exists()


def test_cleanup_refuses_foreign_marker_or_running_container(tmp_path, state, monkeypatch):
    root = workspace(tmp_path, state)
    (root / "secret").write_bytes(b"fixture")
    foreign = {**state, "token": "d" * 32}
    with pytest.raises(ValueError, match="identity mismatch"):
        guest.clean(root, foreign)
    monkeypatch.setattr(
        guest, "containers_empty", lambda: (_ for _ in ()).throw(ValueError("running"))
    )
    with pytest.raises(ValueError, match="running"):
        guest.clean(root, state)
    assert (root / "secret").exists()


def test_cleanup_recovers_only_exact_interrupted_marker_prefix(tmp_path, state):
    root = workspace(tmp_path, state, marker=False)
    marker = guest.marker_bytes(state)
    guest.write_new(root / ".ownership-staging", marker[:30])
    guest.clean(root, state)
    assert not root.exists()
    root = workspace(tmp_path, state, marker=False)
    guest.write_new(root / ".ownership-staging", b"unrelated")
    with pytest.raises(ValueError, match="identity mismatch"):
        guest.clean(root, state)
    assert root.exists()


def test_cleanup_rejects_missing_marker_when_files_exist(tmp_path, state):
    root = workspace(tmp_path, state, marker=False)
    (root / "secret").write_bytes(b"fixture")
    with pytest.raises(ValueError, match="marker missing"):
        guest.clean(root, state)
    assert (root / "secret").exists()


def test_cleanup_recovers_after_last_lock_unlink(tmp_path, state):
    root = workspace(tmp_path, state)
    (root / "lock").unlink()
    guest.clean(root, state)
    assert not root.exists()


@pytest.mark.parametrize(
    "field,value", [("token", "../foreign"), ("uid", 0), ("v", True), ("commit", "bad")]
)
def test_invalid_scope_is_rejected(state, field, value):
    state[field] = value
    with pytest.raises(ValueError):
        guest.validate_state(state)


@pytest.mark.parametrize(
    "name,kind", [("../foreign", "file"), ("link", "symlink"), ("hard", "hardlink")]
)
def test_extract_refuses_traversal_and_links(tmp_path, name, kind):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        item = tarfile.TarInfo(name)
        if kind == "file":
            item.size = 1
            archive.addfile(item, io.BytesIO(b"x"))
        else:
            item.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
            item.linkname = "../foreign"
            archive.addfile(item)
    with pytest.raises(ValueError):
        guest.extract_archive(buffer.getvalue(), tmp_path / "repo")
    assert not (tmp_path / "foreign").exists()


def test_guest_entry_runs_bound_inputs_and_removes_workspace(tmp_path, state, monkeypatch, capsys):
    import base64
    import json
    import sys

    files = {name: (name + "-fixture").encode() for name in guest.FILES}
    state["files"] = {name: guest.digest(value) for name, value in files.items()}
    payload = {
        "action": "run",
        "state": state,
        "files": {k: base64.b64encode(v).decode() for k, v in files.items()},
    }
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode())))
    monkeypatch.setattr(guest, "Path", lambda value: tmp_path if value == "/tmp" else Path(value))
    monkeypatch.setattr(guest, "check_identity", lambda value: None)
    monkeypatch.setattr(guest, "containers_empty", lambda: None)
    monkeypatch.setattr(
        guest,
        "run_drill",
        lambda root, actual, received, fd: {"bound": actual == state and received == files},
    )
    guest.main()
    assert json.loads(capsys.readouterr().out) == {
        "report": {"bound": True},
        "workspace_removed": True,
    }
    assert not (tmp_path / ("steward-restore-" + state["token"])).exists()


def test_guest_entry_keeps_failed_workspace_for_guarded_cleanup(tmp_path, state, monkeypatch):
    import base64
    import json
    import sys

    files = {name: (name + "-fixture").encode() for name in guest.FILES}
    state["files"] = {name: guest.digest(value) for name, value in files.items()}
    payload = {
        "action": "run",
        "state": state,
        "files": {k: base64.b64encode(v).decode() for k, v in files.items()},
    }
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode())))
    monkeypatch.setattr(guest, "Path", lambda value: tmp_path if value == "/tmp" else Path(value))
    monkeypatch.setattr(guest, "check_identity", lambda value: None)
    monkeypatch.setattr(guest, "containers_empty", lambda: None)
    monkeypatch.setattr(
        guest, "run_drill", lambda *args: (_ for _ in ()).throw(ValueError("simulated failure"))
    )
    with pytest.raises(ValueError, match="simulated failure"):
        guest.main()
    root = tmp_path / ("steward-restore-" + state["token"])
    assert root.exists() and (root / "ownership.json").exists()
    guest.clean(root, state)
    assert not root.exists()


@pytest.mark.parametrize("interruption", [1, 2, 3])
def test_cleanup_retries_after_each_final_unlink(tmp_path, state, monkeypatch, interruption):
    root = workspace(tmp_path, state)
    (root / "data").write_bytes(b"fixture")
    monkeypatch.setattr(guest, "containers_empty", lambda: None)
    original = Path.unlink
    count = 0

    def interrupted(path, *args, **kwargs):
        nonlocal count
        original(path, *args, **kwargs)
        if path.parent == root:
            count += 1
            if count == interruption:
                raise OSError("interrupted cleanup")

    monkeypatch.setattr(Path, "unlink", interrupted)
    with pytest.raises(OSError, match="interrupted cleanup"):
        guest.clean(root, state)
    monkeypatch.setattr(Path, "unlink", original)
    guest.clean(root, state)
    assert not root.exists()


def test_cleanup_refuses_while_child_still_inherits_workspace_lock(tmp_path, state, monkeypatch):
    import subprocess
    import sys

    root = workspace(tmp_path, state)
    (root / "secret").write_bytes(b"fixture")
    monkeypatch.setattr(guest, "containers_empty", lambda: None)
    lock = guest.open_lock(root)
    child = subprocess.Popen(
        [sys.executable, "-c", "import os; os.read(0, 1)"],
        stdin=subprocess.PIPE,
        pass_fds=(lock,),
    )
    os.close(lock)
    try:
        with pytest.raises(BlockingIOError):
            guest.clean(root, state)
        assert (root / "secret").exists()
    finally:
        child.communicate(b"x", timeout=10)
    assert child.returncode == 0
    guest.clean(root, state)
    assert not root.exists()
