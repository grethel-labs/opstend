"""Read-only evidence for handing off one existing native PVE backup job."""

import json
import re
import stat
from pathlib import Path

from steward.core import pve_native as native
from steward.core.canonical import revision_id
from steward.core.fleet_adoption_models import NativeBackupJobId
from steward.core.fleet_ownership import OwnershipPlan
from steward.executor.protocol import ExecutorError
from steward.executor.pve_power_api import _read_local

_JOB_STATES = Path("/var/lib/pve-manager/jobs")
_SCHEDULER_GROUP = "/system.slice/pvescheduler.service"
_CGROUP_ROOT = Path("/sys/fs/cgroup")
_RESPONSE_LIMIT = 128 * 1024


def _unproven() -> ExecutorError:
    return ExecutorError("conflict", "Native backup schedule evidence is incomplete or changed.")


def _busy() -> ExecutorError:
    return ExecutorError("target_busy", "Native scheduler workers or tasks have not drained.")


def _json(raw: bytes):
    try:
        return json.loads(
            raw,
            object_pairs_hook=native._unique_object,
            parse_constant=native._reject_api_constant,
        )
    except (ValueError, RecursionError):
        raise _unproven() from None


def _pvesh(plan: OwnershipPlan, path: str, *options: str):
    return _json(
        _read_local(
            plan.scope,
            ["/usr/bin/pvesh", "--noproxy", "get", path, "--output-format", "json", *options],
            _RESPONSE_LIMIT,
        )
    )


def _bool(value: object) -> bool:
    if type(value) not in (bool, int) or value not in (0, 1):
        raise _unproven()
    return bool(value)


def _vmids(value: object) -> tuple[int, ...]:
    if type(value) is int:
        value = str(value)
    if not isinstance(value, str) or not re.fullmatch(
        r"[1-9][0-9]{2,8}(?:[,;\s]+[1-9][0-9]{2,8})*", value, re.ASCII
    ):
        raise _unproven()
    return tuple(int(vmid) for vmid in re.split(r"[,;\s]+", value, flags=re.ASCII))


def _no_duplicate(plan: OwnershipPlan, job_id: NativeBackupJobId) -> None:
    rows = _pvesh(plan, "/cluster/backup")
    if not isinstance(rows, list):
        raise _unproven()
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise _unproven()
        identifier = row["id"]
        if identifier in seen:
            raise _unproven()
        seen.add(identifier)
        if identifier == job_id or row.get("node") not in (None, plan.scope.node):
            continue
        if not _bool(row.get("enabled", 1)):
            continue
        if (
            _bool(row.get("all", 0))
            or row.get("pool") is not None
            or plan.scope.vmid in _vmids(row.get("vmid"))
        ):
            raise _unproven()
    if job_id not in seen:
        raise _unproven()


def read_schedule(plan: OwnershipPlan, job_id: NativeBackupJobId, *, enabled: bool) -> str:
    row = _pvesh(plan, f"/cluster/backup/{job_id}")
    if (
        not isinstance(row, dict)
        or row.get("id") != job_id
        or row.get("type") != "vzdump"
        or row.get("node") != plan.scope.node
        or row.get("schedule") != plan.calendar
        or _bool(row.get("enabled", 1)) != enabled
        or _bool(row.get("all", 0))
        or row.get("pool") is not None
        or row.get("exclude") is not None
        or "script" in row
        or _bool(row.get("repeat-missed", 0))
        or _vmids(row.get("vmid")) != (plan.scope.vmid,)
    ):
        raise _unproven()
    return revision_id({key: value for key, value in row.items() if key != "enabled"})


def _scheduler(plan: OwnershipPlan) -> tuple[str, str, int]:
    raw = _read_local(
        plan.scope,
        [
            "/usr/bin/systemctl",
            "--system",
            "--no-pager",
            "show",
            "pvescheduler.service",
            "--property=LoadState,ActiveState,MainPID,ControlGroup",
        ],
        4096,
    )
    try:
        items = [line.split("=", 1) for line in raw.decode("ascii").splitlines()]
        fields = dict(items)
    except ValueError:
        raise _unproven() from None
    if (
        len(items) != 4
        or set(fields) != {"LoadState", "ActiveState", "MainPID", "ControlGroup"}
        or fields["LoadState"] != "loaded"
        or not re.fullmatch(r"0|[1-9][0-9]{0,9}", fields["MainPID"])
    ):
        raise _unproven()
    return fields["ActiveState"], fields["ControlGroup"], int(fields["MainPID"])


def _scheduler_quiet(plan: OwnershipPlan) -> None:
    unit = _scheduler(plan)
    state, group, main = unit
    if unit != ("inactive", "", 0) and (
        group != _SCHEDULER_GROUP
        or not ((state == "active" and main > 0) or (state == "inactive" and main == 0))
    ):
        raise _unproven()

    # pvescheduler forks before reading jobs.cfg. A worker already holding the
    # formerly enabled definition could still fork a backup after its disable.
    # An inactive unit with no cgroup, or exactly its main PID and no descendants,
    # proves no such worker can outlive the first disabled read.
    directory = _CGROUP_ROOT / _SCHEDULER_GROUP.lstrip("/")
    try:
        with (directory / "cgroup.procs").open("rb") as handle:
            processes = handle.read(4097)
        with (directory / "cgroup.stat").open("rb") as handle:
            descendants = handle.read(4097)
    except FileNotFoundError:
        if unit != ("inactive", "", 0) or directory.exists():
            raise _unproven() from None
    else:
        if len(processes) > 4096 or len(descendants) > 4096:
            raise _unproven()
        if (
            processes.splitlines() != ([str(main).encode("ascii")] if main else [])
            or b"nr_descendants 0" not in descendants.splitlines()
            or b"nr_dying_descendants 0" not in descendants.splitlines()
        ):
            raise _busy()
    if _scheduler(plan) != unit:
        raise _unproven()


def _native_state(plan: OwnershipPlan, job_id: NativeBackupJobId) -> None:
    path = _JOB_STATES / f"vzdump-{job_id}.json"
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
        or info.st_nlink != 1
    ):
        raise _unproven()
    row = _json(native._read_file(path, 4096))
    if not isinstance(row, dict):
        raise _unproven()
    if row.get("state") == "created":
        if type(row.get("time")) is not int or row["time"] <= 0 or "upid" in row or "msg" in row:
            raise _unproven()
    elif row.get("state") == "stopped":
        message, upid = row.get("msg"), row.get("upid")
        task = _upid(upid, plan.scope.node)
        if (
            not isinstance(message, str)
            or not message.strip()
            or message in {"internal error", "task log not found"}
            or (upid is not None and (task is None or task["worker"] != "vzdump"))
            or (upid is None and (type(row.get("time")) is not int or row["time"] <= 0))
        ):
            raise _unproven()
    elif row.get("state") in ("starting", "started"):
        raise _busy()
    else:
        raise _unproven()


def _upid(value: object, node: str) -> re.Match[str] | None:
    if not isinstance(value, str):
        return None
    return re.fullmatch(
        rf"UPID:{re.escape(node)}:[0-9A-F]{{8}}:[0-9A-F]{{8,9}}:[0-9A-F]{{8}}:"
        r"(?P<worker>[A-Za-z0-9_+-]+):(?P<id>[^:\s]*):[^:\s]+:",
        value,
        re.ASCII,
    )


def _no_active_tasks(plan: OwnershipPlan) -> None:
    # Unfiltered local root read: scheduled or multi-guest task IDs need not contain a VMID.
    # PVE returns active and recently stopped rows in the active source.
    limit = 250
    rows = _pvesh(
        plan,
        f"/nodes/{plan.scope.node}/tasks",
        "--source",
        "active",
        "--limit",
        str(limit),
    )
    if not isinstance(rows, list) or len(rows) >= limit:
        raise _unproven()
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or row.get("node") != plan.scope.node:
            raise _unproven()
        task = _upid(row.get("upid"), plan.scope.node)
        if task is None or task["worker"] != row.get("type") or row["upid"] in seen:
            raise _unproven()
        seen.add(row["upid"])
        if (
            task["worker"] != "vzdump"
            and task["id"] != str(plan.scope.vmid)
            and str(row.get("id")) != str(plan.scope.vmid)
        ):
            continue
        if (
            type(row.get("starttime")) is not int
            or not isinstance(row.get("status"), str)
            or not row["status"].strip()
        ):
            raise _unproven()
        if (
            row["status"].upper() in {"RUNNING", "UNKNOWN"}
            or type(row.get("endtime")) is not int
            or not 0 < row["starttime"] <= row["endtime"]
        ):
            raise _busy()


def verify_schedule(plan: OwnershipPlan, job_id: NativeBackupJobId, *, enabled: bool) -> str:
    try:
        first = read_schedule(plan, job_id, enabled=enabled)
        _no_duplicate(plan, job_id)
        if not enabled:
            _scheduler_quiet(plan)
            _native_state(plan, job_id)
            _no_active_tasks(plan)
        if read_schedule(plan, job_id, enabled=enabled) != first:
            raise _unproven()
    except OSError:
        raise _unproven() from None
    return first
