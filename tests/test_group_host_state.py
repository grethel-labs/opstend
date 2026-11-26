"""Unit and exact container observations must agree before group admission."""

import json

import pytest

from steward.executor.host import Host


@pytest.mark.parametrize(
    ("unit", "entries", "result"),
    [
        (
            "loaded|active|running",
            [
                {
                    "Names": ["notes"],
                    "Labels": {"PODMAN_SYSTEMD_UNIT": "notes.service"},
                    "State": "running",
                    "Pid": 123,
                }
            ],
            True,
        ),
        ("loaded|inactive|dead", [], False),
        (
            "loaded|failed|failed",
            [
                {
                    "Names": ["notes"],
                    "Labels": {"PODMAN_SYSTEMD_UNIT": "notes.service"},
                    "State": "exited",
                    "Pid": 0,
                }
            ],
            False,
        ),
        (
            "loaded|inactive|dead",
            [
                {
                    "Names": ["notes"],
                    "Labels": {"PODMAN_SYSTEMD_UNIT": "notes.service"},
                    "State": "exited",
                    "Pid": False,
                }
            ],
            None,
        ),
        ("loaded|active|running", [], None),
        (
            "loaded|inactive|dead",
            [
                {
                    "Names": ["notes"],
                    "Labels": {"PODMAN_SYSTEMD_UNIT": "notes.service"},
                    "State": "running",
                    "Pid": 123,
                }
            ],
            None,
        ),
        (
            "loaded|active|running",
            [{"Names": ["notes"], "Labels": {}, "State": "running", "Pid": 123}],
            None,
        ),
        (
            "loaded|active|running",
            [
                {
                    "Names": ["notes-other"],
                    "Labels": {"PODMAN_SYSTEMD_UNIT": "notes.service"},
                    "State": "running",
                    "Pid": 123,
                }
            ],
            None,
        ),
        (
            "loaded|active|running",
            [
                {
                    "Names": ["notes"],
                    "Labels": {"PODMAN_SYSTEMD_UNIT": "notes.service"},
                    "State": "paused",
                    "Pid": 123,
                }
            ],
            None,
        ),
        ("not-found|inactive|dead", [], None),
        ("loaded|activating|start", [], None),
        ("loaded|active|running", "malformed", None),
    ],
)
def test_group_service_observation_fails_closed(monkeypatch, unit, entries, result):
    host = Host()
    load, active, sub = unit.split("|")

    def command(user, argv):
        assert user == "stw-notes"
        if argv[0] == "systemctl":
            return 0, f"LoadState={load}\nActiveState={active}\nSubState={sub}\n"
        assert argv == ["podman", "ps", "--all", "--filter", "name=^notes$", "--format", "json"]
        return 0, entries if isinstance(entries, str) else json.dumps(entries)

    monkeypatch.setattr(host, "_as_user", command)
    assert host.group_service_running("stw-notes", "notes.service", "notes") is result


def test_group_service_observation_rejects_unsafe_identity_and_command_failure(monkeypatch):
    host = Host()
    monkeypatch.setattr(host, "_as_user", lambda *args: (1, "unavailable"))
    assert host.group_service_running("stw-notes", "notes.service", "notes") is None
    assert host.group_service_running("stw-notes", "ssh.service", "notes") is None
    assert host.group_service_running("root", "notes.service", "notes") is None


@pytest.mark.parametrize(
    ("observation", "show", "expected"),
    [
        (
            False,
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nControlGroup=\n",
            True,
        ),
        (
            False,
            "LoadState=loaded\nActiveState=failed\nSubState=failed\nMainPID=0\nControlPID=0\nControlGroup=\n",
            True,
        ),
        (True, "", False),
        (None, "", False),
        (
            False,
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=7\nControlGroup=\n",
            False,
        ),
        (
            False,
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nControlGroup=/lingering\n",
            False,
        ),
        (
            False,
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlGroup=\n",
            False,
        ),
    ],
)
def test_group_quiescence_requires_known_stopped_unit_without_cgroup(
    monkeypatch, observation, show, expected
):
    host = Host()
    monkeypatch.setattr(host, "group_service_running", lambda *args: observation)
    monkeypatch.setattr(host, "_as_user", lambda *args: (0, show))
    assert host.group_service_quiescent("stw-notes", "notes.service", "notes") is expected


@pytest.fixture
def writer_topology(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from steward.executor import host as hostmod

    root = tmp_path / "proc"
    root.mkdir()
    identities = {"stw-one": 10001, "stw-two": 10002}

    def lookup(user):
        if user not in identities:
            raise KeyError(user)
        return SimpleNamespace(pw_uid=identities[user])

    monkeypatch.setattr(hostmod, "PROC_ROOT", root)
    monkeypatch.setattr(hostmod.pwd, "getpwnam", lookup)

    def add(pid, uid, cgroup, *, tid=None, task_uid=None):
        proc = root / str(pid)
        proc.mkdir(exist_ok=True)
        (proc / "status").write_text(f"Name:\ttest\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
        (proc / "stat").write_text(f"{pid} (fake) S " + "0 " * 18 + "123\n")
        task = proc / "task" / str(tid or pid)
        task.mkdir(parents=True)
        value = uid if task_uid is None else task_uid
        (task / "status").write_text(f"Uid:\t{value}\t{value}\t{value}\t{value}\n")
        (task / "stat").write_text(f"{tid or pid} (fake) S " + "0 " * 18 + "123\n")
        (task / "cgroup").write_text(f"0::{cgroup}\n")
        return proc, task

    return root, add, identities


def test_group_user_process_scope_requires_all_observed_tasks_in_their_slices(writer_topology):
    root, add, _ = writer_topology
    add(101, 10001, "/user.slice/user-10001.slice/user@10001.service")
    add(102, 10002, "/user.slice/user-10002.slice/session-1.scope")
    add(103, 0, "/system.slice/other.service")
    assert Host().group_users_within_systemd_slices(["stw-one", "stw-two"])
    add(104, 10001, "/system.slice/stray.service")
    assert not Host().group_users_within_systemd_slices(["stw-one", "stw-two"])
    assert root.exists()


@pytest.mark.parametrize(
    "failure",
    [
        "missing_user",
        "missing_task",
        "wrong_uid",
        "bad_cgroup",
        "malformed_status",
        "malformed_identity",
        "too_many",
    ],
)
def test_group_user_process_scope_fails_closed_when_observation_is_unknown(
    writer_topology, monkeypatch, failure
):
    from steward.executor import host as hostmod

    root, add, identities = writer_topology
    proc, task = add(101, 10001, "/user.slice/user-10001.slice/user@10001.service")
    users = ["stw-one"]
    if failure == "missing_user":
        users.append("stw-two")
    elif failure == "missing_task":
        (task / "status").unlink()
    elif failure == "wrong_uid":
        (task / "status").write_text("Uid:\t10002\t10002\t10002\t10002\n")
    elif failure == "bad_cgroup":
        (task / "cgroup").write_text("0::/user.slice/user-10001.slice-escape/foo\n")
    elif failure == "malformed_status":
        (proc / "status").write_text("Uid: invalid\n")
    elif failure == "malformed_identity":
        (task / "stat").write_text("malformed\n")
    else:
        monkeypatch.setattr(hostmod, "MAX_PROCESS_ENTRIES", 1)
    assert not Host().group_users_within_systemd_slices(users)
    assert identities and root.exists()


def test_group_user_process_scope_rejects_unknown_or_alias_uids(writer_topology):
    _root, add, identities = writer_topology
    add(101, 10001, "/user.slice/user-10001.slice/user@10001.service")
    assert not Host().group_users_within_systemd_slices(["stw-missing"])
    assert not Host().group_users_within_systemd_slices(["../bad"])
    identities["stw-two"] = 10001
    assert not Host().group_users_within_systemd_slices(["stw-one", "stw-two"])


def test_group_user_scope_rejects_task_identity_change_during_observation(
    writer_topology, monkeypatch
):
    import io
    from pathlib import Path

    _root, add, _ = writer_topology
    _proc, task = add(101, 10001, "/user.slice/user-10001.slice/user@10001.service")
    target = task / "stat"
    original = Path.open
    reads = []

    def changed(path, *args, **kwargs):
        if path == target:
            reads.append(True)
            return io.StringIO(
                "101 (fake) S " + "0 " * 18 + ("123\n" if len(reads) == 1 else "124\n")
            )
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", changed)
    assert not Host().group_users_within_systemd_slices(["stw-one"])
    assert len(reads) == 2
