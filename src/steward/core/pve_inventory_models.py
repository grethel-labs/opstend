"""Typed projections of read-only Proxmox VE inventory evidence."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

from .pve_native import _validate_api_name

MAX_RESOURCES = 256
MAX_TASKS = 20
MAX_POINTS = 64
_RRD_BUCKET_SECONDS = 60
_RRD_HEARTBEAT_SECONDS = 120

EvidenceState = Literal[
    "observed", "absent", "restricted", "missing", "unavailable", "invalid", "budget"
]
EvidenceSource = Literal[
    "cluster_resources", "guest_config", "guest_rrd", "guest_tasks", "permissions"
]
GuestKind = Literal["qemu", "lxc"]
ResourceName = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")]
PoolName = Annotated[
    str, Field(max_length=255, pattern=r"^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+){0,2}$")
]
NodeName = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")]
Vmid = Annotated[int, Field(ge=100, le=999_999_999)]
Count = Annotated[int, Field(ge=0, le=2**63 - 1)]
Quantity = Annotated[float, Field(ge=0, allow_inf_nan=False)]
ResourceStatus = Literal[
    "online", "offline", "running", "stopped", "paused", "available", "unknown"
]
TaskOperation = Literal[
    "create", "start", "stop", "shutdown", "reboot", "reset", "suspend", "resume", "migrate"
]
TaskState = Literal["running", "succeeded", "warning", "failed"]


class Projection(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, hide_input_in_errors=True)


class TimedProjection(Projection):
    observed_at: AwareDatetime

    @field_validator("observed_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)


class Evidence(TimedProjection):
    source: EvidenceSource
    state: EvidenceState


class Node(Projection):
    evidence: Evidence
    node: NodeName
    status: ResourceStatus | None = None
    cpu_capacity: Quantity | None = None
    max_memory_bytes: Count | None = None
    max_disk_bytes: Count | None = None
    uptime_seconds: Count | None = None


class NetworkAttachment(Projection):
    index: Annotated[int, Field(ge=0, le=255)]
    bridge: ResourceName | None = None
    vlan_tag: Annotated[int, Field(ge=1, le=4094)] | None = None


class NetworkObservation(Projection):
    evidence: Evidence
    items: tuple[NetworkAttachment, ...] = Field(default=(), max_length=256)


class MeasurementPoint(Projection):
    time: AwareDatetime
    cpu_fraction: Quantity | None = None
    cpu_capacity: Quantity | None = None
    memory_bytes: Quantity | None = None
    max_memory_bytes: Quantity | None = None
    host_memory_bytes: Quantity | None = None
    disk_bytes: Quantity | None = None
    max_disk_bytes: Quantity | None = None
    disk_read_bytes_per_second: Quantity | None = None
    disk_write_bytes_per_second: Quantity | None = None
    net_in_bytes_per_second: Quantity | None = None
    net_out_bytes_per_second: Quantity | None = None


class MeasurementObservation(Projection):
    evidence: Evidence
    items: tuple[MeasurementPoint, ...] = Field(default=(), max_length=MAX_POINTS)


class GuestTask(Projection):
    operation: TaskOperation
    state: TaskState
    started_at: AwareDatetime
    finished_at: AwareDatetime | None = None
    warning_count: Count | None = None


class TaskObservation(Projection):
    evidence: Evidence
    items: tuple[GuestTask, ...] = Field(default=(), max_length=MAX_TASKS)


class Guest(Projection):
    evidence: Evidence
    node: NodeName
    vmid: Vmid
    kind: GuestKind
    name: ResourceName | None = None
    pool: PoolName | None = None
    status: ResourceStatus | None = None
    pve_uid: str | None = Field(default=None, pattern=r"^[a-z2-7]{20}$", exclude=True, repr=False)
    registered_at_ms: int | None = Field(
        default=None, gt=0, le=999_999_999_999_999, exclude=True, repr=False
    )
    cpu_fraction: Quantity | None = None
    cpu_capacity: Count | None = None
    memory_bytes: Count | None = None
    max_memory_bytes: Count | None = None
    disk_bytes: Count | None = None
    max_disk_bytes: Count | None = None
    uptime_seconds: Count | None = None
    network: NetworkObservation | None = None
    measurements: MeasurementObservation | None = None
    tasks: TaskObservation | None = None


class Pool(Projection):
    evidence: Evidence
    pool: PoolName


class Datastore(Projection):
    evidence: Evidence
    node: NodeName
    storage: ResourceName
    status: ResourceStatus | None = None
    plugin_type: ResourceName | None = None
    content: tuple[ResourceName, ...] = Field(default=(), max_length=16)
    shared: bool | None = None
    max_disk_bytes: Count | None = None


class ResourceIndex(Projection):
    nodes: tuple[Node, ...] = Field(default=(), max_length=MAX_RESOURCES)
    guests: tuple[Guest, ...] = Field(default=(), max_length=MAX_RESOURCES)
    pools: tuple[Pool, ...] = Field(default=(), max_length=MAX_RESOURCES)
    datastores: tuple[Datastore, ...] = Field(default=(), max_length=MAX_RESOURCES)


class InventorySnapshot(ResourceIndex, TimedProjection):
    v: Literal[1] = 1
    api_name: Annotated[str, Field(max_length=253)]
    evidence: Evidence
    coverage: Literal["token_scope"] = "token_scope"

    @field_validator("api_name")
    @classmethod
    def _api_identity(cls, name: str) -> str:
        _validate_api_name(name)
        return name


def _rows(data: object, limit: int) -> list[dict]:
    if (
        not isinstance(data, list)
        or len(data) > limit
        or any(not isinstance(item, dict) for item in data)
    ):
        raise ValueError("invalid inventory rows")
    return data


def _status(data: object) -> ResourceStatus | None:
    if data is None:
        return None
    if not isinstance(data, str):
        raise ValueError("invalid resource status")
    if data in ("online", "offline", "running", "stopped", "paused", "available"):
        return data
    return "unknown"


def _shared(data: object) -> bool | None:
    if data is None or isinstance(data, bool):
        return data
    if type(data) is int and data in (0, 1):
        return bool(data)
    raise ValueError("invalid datastore shared flag")


def _content(data: object) -> tuple[str, ...]:
    if data is None or data == "":
        return ()
    if not isinstance(data, str) or len(data) > 512:
        raise ValueError("invalid datastore content")
    return tuple(data.split(","))


def _unique(items, key):
    if len({key(item) for item in items}) != len(items):
        raise ValueError("duplicate inventory identity")
    return tuple(items)


def _validate_resource_id(row: dict, expected: str) -> None:
    if "id" in row and row["id"] != expected:
        raise ValueError("inventory resource ID disagrees with selector")


def parse_resources(data: object, evidence: Evidence) -> ResourceIndex:
    nodes = []
    guests = []
    pools = []
    datastores = []
    for row in _rows(data, MAX_RESOURCES):
        kind = row.get("type")
        if not isinstance(kind, str):
            raise ValueError("invalid inventory resource type")
        if kind == "node":
            _validate_resource_id(row, f"node/{row.get('node')}")
            nodes.append(
                Node(
                    evidence=evidence,
                    node=row.get("node"),
                    status=_status(row.get("status")),
                    cpu_capacity=row.get("maxcpu"),
                    max_memory_bytes=row.get("maxmem"),
                    max_disk_bytes=row.get("maxdisk"),
                    uptime_seconds=row.get("uptime"),
                )
            )
        elif kind in ("qemu", "lxc"):
            _validate_resource_id(row, f"{kind}/{row.get('vmid')}")
            guests.append(
                Guest(
                    evidence=evidence,
                    node=row.get("node"),
                    vmid=row.get("vmid"),
                    kind=kind,
                    name=row.get("name"),
                    pool=row.get("pool"),
                    status=_status(row.get("status")),
                    pve_uid=row.get("uid"),
                    registered_at_ms=row.get("rtime"),
                    cpu_fraction=row.get("cpu"),
                    cpu_capacity=row.get("maxcpu"),
                    memory_bytes=row.get("mem"),
                    max_memory_bytes=row.get("maxmem"),
                    disk_bytes=row.get("disk"),
                    max_disk_bytes=row.get("maxdisk"),
                    uptime_seconds=row.get("uptime"),
                )
            )
        elif kind == "pool":
            _validate_resource_id(row, f"/pool/{row.get('pool')}")
            pools.append(Pool(evidence=evidence, pool=row.get("pool")))
        elif kind == "storage":
            _validate_resource_id(row, f"storage/{row.get('node')}/{row.get('storage')}")
            datastores.append(
                Datastore(
                    evidence=evidence,
                    node=row.get("node"),
                    storage=row.get("storage"),
                    status=_status(row.get("status")),
                    plugin_type=row.get("plugintype"),
                    content=_content(row.get("content")),
                    shared=_shared(row.get("shared")),
                    max_disk_bytes=row.get("maxdisk"),
                )
            )
    return ResourceIndex(
        nodes=_unique(nodes, lambda item: item.node),
        guests=_unique(guests, lambda item: item.vmid),
        pools=_unique(pools, lambda item: item.pool),
        datastores=_unique(datastores, lambda item: (item.node, item.storage)),
    )


def parse_network(data: object) -> tuple[NetworkAttachment, ...]:
    if not isinstance(data, dict):
        raise ValueError("invalid guest configuration")
    attachments = []
    for key, value in data.items():
        if not isinstance(key, str):
            raise ValueError("invalid guest configuration field name")
        match = re.fullmatch(r"net(0|[1-9][0-9]{0,2})", key)
        if match is None:
            continue
        if not isinstance(value, str) or not value or len(value) > 4096:
            raise ValueError("invalid guest network configuration")
        fields = {}
        for option in value.split(","):
            name, _, setting = option.partition("=")
            if name not in ("bridge", "tag"):
                continue
            if name in fields or not setting:
                raise ValueError("invalid guest network attribute")
            fields[name] = setting
        tag = fields.get("tag")
        if tag is not None and not re.fullmatch(r"[0-9]{1,4}", tag):
            raise ValueError("invalid guest VLAN tag")
        attachments.append(
            NetworkAttachment(
                index=int(match[1]),
                bridge=fields.get("bridge"),
                vlan_tag=int(tag) if tag is not None else None,
            )
        )
    return tuple(sorted(attachments, key=lambda item: item.index))


def _timestamp(value: object) -> datetime:
    if type(value) is not int or not 0 <= value <= 253_402_300_799:
        raise ValueError("invalid inventory timestamp")
    return datetime.fromtimestamp(value, UTC)


def parse_measurements(data: object, *, registered_after: int) -> tuple[MeasurementPoint, ...]:
    points = []
    # The VMID-keyed RRD can interpolate across a gap up to the heartbeat.
    # Keep only complete minute buckets beyond that cross-generation window.
    first_bucket = registered_after + _RRD_HEARTBEAT_SECONDS + _RRD_BUCKET_SECONDS
    for row in _rows(data, MAX_POINTS):
        timestamp = _timestamp(row.get("time"))
        if row["time"] < first_bucket:
            continue
        points.append(
            MeasurementPoint(
                time=timestamp,
                cpu_fraction=row.get("cpu"),
                cpu_capacity=row.get("maxcpu"),
                memory_bytes=row.get("mem"),
                max_memory_bytes=row.get("maxmem"),
                host_memory_bytes=row.get("memhost"),
                disk_bytes=row.get("disk"),
                max_disk_bytes=row.get("maxdisk"),
                disk_read_bytes_per_second=row.get("diskread"),
                disk_write_bytes_per_second=row.get("diskwrite"),
                net_in_bytes_per_second=row.get("netin"),
                net_out_bytes_per_second=row.get("netout"),
            )
        )
    return tuple(sorted(_unique(points, lambda item: item.time), key=lambda item: item.time))


_TASK_OPERATIONS: tuple[TaskOperation, ...] = (
    "create",
    "start",
    "stop",
    "shutdown",
    "reboot",
    "suspend",
    "resume",
    "migrate",
)
_QEMU_TASKS = {f"qm{operation}": operation for operation in _TASK_OPERATIONS} | {"qmreset": "reset"}
_LXC_TASKS = {f"vz{operation}": operation for operation in _TASK_OPERATIONS}


def parse_tasks(
    data: object, *, node: str, vmid: int, kind: GuestKind, registered_after: int
) -> tuple[GuestTask, ...]:
    operations = _QEMU_TASKS if kind == "qemu" else _LXC_TASKS
    tasks = []
    for row in _rows(data, MAX_TASKS):
        if row.get("node") != node or row.get("id") != str(vmid):
            continue
        task_type = row.get("type")
        if not isinstance(task_type, str):
            raise ValueError("invalid guest task type")
        operation = operations.get(task_type)
        if operation is None:
            continue
        started_at = _timestamp(row.get("starttime"))
        if row["starttime"] < registered_after:
            continue
        end = row.get("endtime")
        status = row.get("status")
        if status is not None and (not isinstance(status, str) or not status):
            raise ValueError("invalid guest task status")
        warning_count = None
        if end is None:
            if status not in (None, "RUNNING", "running"):
                raise ValueError("completed guest task has no end time")
            finished_at = None
            state = "running"
        else:
            finished_at = _timestamp(end)
            if finished_at < started_at or status in (None, "RUNNING", "running"):
                raise ValueError("invalid completed guest task")
            warning = re.fullmatch(r"WARNINGS: ([1-9][0-9]{0,8})", status)
            if warning:
                warning_count = int(warning[1])
                state = "warning"
            else:
                state = "succeeded" if status == "OK" else "failed"
        tasks.append(
            GuestTask(
                operation=operation,
                state=state,
                started_at=started_at,
                finished_at=finished_at,
                warning_count=warning_count,
            )
        )
    return tuple(sorted(tasks, key=lambda item: item.started_at, reverse=True))
