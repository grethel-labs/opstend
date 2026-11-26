"""Verify a transient builder scope before replacing this process with its command."""

import os
import re
import sys
from pathlib import Path

CGROUP = Path("/sys/fs/cgroup")
SELF_CGROUP = Path("/proc/self/cgroup")
CONTROLLERS = ("cpu", "memory", "pids")
ADMISSION_ERROR = "steward builder scope admission failed"
REFUSED = 78


def _positive(value: str) -> int:
    if re.fullmatch(r"[1-9][0-9]*", value) is None:
        raise ValueError
    return int(value)


def _require_membership(expected: str) -> None:
    if SELF_CGROUP.read_text(encoding="ascii").splitlines() != [f"0::{expected}"]:
        raise ValueError


def _verify_limits(scope: Path, memory: int, cpu: int, pids: int) -> None:
    if (scope / "cgroup.type").read_text(encoding="ascii").strip() != "domain":
        raise ValueError
    if _positive((scope / "memory.max").read_text(encoding="ascii").strip()) > memory:
        raise ValueError
    if (scope / "memory.swap.max").read_text(encoding="ascii").strip() != "0":
        raise ValueError
    quota, period = map(_positive, (scope / "cpu.max").read_text(encoding="ascii").split())
    if quota * 100 > period * cpu:
        raise ValueError
    if _positive((scope / "pids.max").read_text(encoding="ascii").strip()) > pids:
        raise ValueError


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    try:
        uid_arg, expected, memory_arg, cpu_arg, pids_arg, separator, *command = args
        if separator != "--" or not command or command[0] != "/usr/bin/podman":
            raise ValueError
        if any("\0" in arg for arg in command):
            raise ValueError

        uid = _positive(uid_arg)
        memory, cpu, pids = map(_positive, (memory_arg, cpu_arg, pids_arg))
        if uid < 100 or os.getresuid() != (uid, uid, uid):
            raise ValueError
        scope_pattern = (
            rf"/user\.slice/user-{uid}\.slice/user@{uid}\.service/app\.slice/"
            r"steward-build-[0-9a-f]{32}-(?:probe|build|push|clean)\.scope"
        )
        if re.fullmatch(scope_pattern, expected) is None:
            raise ValueError
        scope = CGROUP / expected[1:]
        _require_membership(expected)
        _verify_limits(scope, memory, cpu, pids)

        # Domain controllers require an empty scope root before delegation.
        runner = scope / "runner"
        runner.mkdir()
        with (runner / "cgroup.procs").open("w", encoding="ascii") as procs:
            procs.write(f"{os.getpid()}\n")
        subtree_control = scope / "cgroup.subtree_control"
        with subtree_control.open("w", encoding="ascii") as control:
            control.write(" ".join(f"+{name}" for name in CONTROLLERS) + "\n")
        if not set(CONTROLLERS).issubset(subtree_control.read_text(encoding="ascii").split()):
            raise ValueError
        _require_membership(f"{expected}/runner")
        os.execv(command[0], command)  # noqa: S606 - fixed Podman executable, no shell
    except (OSError, ValueError):
        print(ADMISSION_ERROR, file=sys.stderr)
        return REFUSED


if __name__ == "__main__":
    sys.exit(main())
