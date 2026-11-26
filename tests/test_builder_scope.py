"""Exercise scope admission against synthetic cgroup v2 files."""

from contextlib import contextmanager
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest

from steward.core import builder_scope as bs

UID = 1500
PID = 3210
SCOPE = (
    f"/user.slice/user-{UID}.slice/user@{UID}.service/app.slice/"
    f"steward-build-{'a' * 32}-build.scope"
)
COMMAND = ["/usr/bin/podman", "--cgroup-manager=cgroupfs", "info"]


class ExecCalled(Exception):
    """A successful exec replaces the process, so stop the helper here."""


@pytest.fixture
def kernel(tmp_path, monkeypatch):
    cgroup = tmp_path / "cgroup"
    scope = cgroup / SCOPE[1:]
    scope.mkdir(parents=True)
    membership = tmp_path / "self.cgroup"
    membership.write_text(f"0::{SCOPE}\n")
    for name, contents in {
        "cgroup.type": "domain",
        "memory.max": "2097152",
        "memory.swap.max": "0",
        "cpu.max": "200000 100000",
        "pids.max": "32",
        "cgroup.subtree_control": "",
    }.items():
        (scope / name).write_text(contents + "\n")

    state = SimpleNamespace(
        scope=scope,
        membership=membership,
        uids=(UID, UID, UID),
        moves=True,
        delegated="cpu memory pids",
        denied=None,
        written=[],
        executed=[],
        argv=[str(UID), SCOPE, "2097152", "200", "32", "--", *COMMAND],
    )
    original_open = Path.open

    @contextmanager
    def kernel_write(path):
        if path.name == state.denied:
            raise PermissionError(path)
        output = StringIO()
        yield output
        state.written.append((path.relative_to(scope).as_posix(), output.getvalue().split()))
        if path.name == "cgroup.procs" and state.moves:
            membership.write_text(f"0::{SCOPE}/runner\n")
        if path.name == "cgroup.subtree_control":
            with original_open(path, "w", encoding="ascii") as control:
                control.write(state.delegated + "\n")

    def fake_open(path, mode="r", *args, **kwargs):
        if mode == "w" and scope in path.parents:
            return kernel_write(path)
        return original_open(path, mode, *args, **kwargs)

    def execv(executable, argv):
        state.executed.append((executable, argv))
        raise ExecCalled

    monkeypatch.setattr(bs, "CGROUP", cgroup)
    monkeypatch.setattr(bs, "SELF_CGROUP", membership)
    monkeypatch.setattr(bs.os, "getresuid", lambda: state.uids)
    monkeypatch.setattr(bs.os, "getpid", lambda: PID)
    monkeypatch.setattr(bs.os, "execv", execv)
    monkeypatch.setattr(Path, "open", fake_open)
    return state


@pytest.mark.parametrize("tighter", [False, True])
def test_spawns_command_only_after_limits_migration_and_delegation(kernel, tighter):
    if tighter:
        for name, value in {
            "memory.max": "1048576",
            "cpu.max": "70000 50000",
            "pids.max": "24",
        }.items():
            (kernel.scope / name).write_bytes(value.encode())
    with pytest.raises(ExecCalled):
        bs.main(kernel.argv)
    assert kernel.written == [
        ("runner/cgroup.procs", [str(PID)]),
        ("cgroup.subtree_control", ["+cpu", "+memory", "+pids"]),
    ]
    assert kernel.executed == [(COMMAND[0], COMMAND)]


@pytest.mark.parametrize(
    "name, contents",
    [
        ("cgroup.type", "threaded"),
        ("memory.max", "max"),
        ("memory.max", "2097153"),
        ("memory.swap.max", "max"),
        ("memory.swap.max", "1"),
        ("cpu.max", "max 100000"),
        ("cpu.max", "100001 50000"),
        ("cpu.max", "1000 0"),
        ("pids.max", "max"),
        ("pids.max", "33"),
        ("pids.max", "invalid"),
    ],
)
def test_invalid_kernel_limits_fail_before_any_write(kernel, name, contents):
    (kernel.scope / name).write_bytes(contents.encode())
    assert bs.main(kernel.argv) == bs.REFUSED
    assert kernel.written == []
    assert kernel.executed == []


@pytest.mark.parametrize(
    "member",
    [
        f"0::{SCOPE}/runner\n",
        f"0::{SCOPE}.other\n",
        f"1:cpu:{SCOPE}\n",
        f"0::{SCOPE}\n1:cpu:{SCOPE}\n",
    ],
)
def test_requires_exact_v2_membership(kernel, member):
    kernel.membership.write_text(member)
    assert bs.main(kernel.argv) == bs.REFUSED
    assert kernel.written == []
    assert kernel.executed == []


def test_rejects_noncanonical_expected_scope_even_if_membership_matches(kernel):
    expected = SCOPE.replace("/app.slice/", "/other.slice/")
    alternate = bs.CGROUP / expected[1:]
    alternate.parent.mkdir(parents=True)
    kernel.scope.rename(alternate)
    kernel.membership.write_text(f"0::{expected}\n")
    kernel.argv[1] = expected
    assert bs.main(kernel.argv) == bs.REFUSED
    assert kernel.written == []
    assert kernel.executed == []


@pytest.mark.parametrize("index, value", [(4, "0"), (5, "-"), (6, "podman")])
def test_invalid_arguments_fail_before_any_write(kernel, index, value):
    kernel.argv[index] = value
    assert bs.main(kernel.argv) == bs.REFUSED
    assert kernel.written == []
    assert kernel.executed == []


def test_refusal_exit_code_matches_helper_contract():
    assert bs.main([]) == bs.REFUSED


def test_rejects_mismatched_saved_uid(kernel):
    kernel.uids = (UID, UID, 0)
    assert bs.main(kernel.argv) == bs.REFUSED
    assert kernel.written == []
    assert kernel.executed == []


@pytest.mark.parametrize(
    "case", ["move_denied", "not_moved", "delegate_denied", "missing_controller"]
)
def test_refuses_to_exec_when_migration_or_delegation_fails(kernel, case):
    if case == "move_denied":
        kernel.denied = "cgroup.procs"
    elif case == "not_moved":
        kernel.moves = False
    elif case == "delegate_denied":
        kernel.denied = "cgroup.subtree_control"
    elif case == "missing_controller":
        kernel.delegated = "cpu pids"
    assert bs.main(kernel.argv) == bs.REFUSED
    assert kernel.executed == []
