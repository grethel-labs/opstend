"""Fixed, same-node Proxmox full clone operations and native readback."""

from __future__ import annotations

import json
import math
import re
import ssl
import time
from pathlib import Path
from typing import Literal
from urllib.parse import quote, urlencode

from pydantic import ValidationError

from steward.core import pve_native as native
from steward.core.pve_inventory_models import MAX_RESOURCES
from steward.core.pve_power import GuestTarget
from steward.core.pve_provision import (
    CLONE_UPID_PATTERN,
    CloneProfile,
    ProvisionedGuest,
    ProvisionJob,
    ProvisionNetwork,
    ProvisionPolicy,
    ProvisionTarget,
    ProvisionTemplate,
    TemplateEvidence,
)

from .protocol import ExecutorError
from .pve_power_api import (
    _MAX_RESPONSE,
    _TIMEOUT,
    _matches_task,
    _read_local,
    _task_fields,
    _zero,
    verify_local_lxc_state,
    verify_local_pending,
)

CLONE_TASK_WINDOW_S = 30
_TASK_LIST_LIMIT = 9
_TASK_LOG_LIMIT = 500
_TaskState = Literal["running", "succeeded", "failed", "vmid_conflict"]
_UPID = re.compile(CLONE_UPID_PATTERN)
_NODE = r"[A-Za-z0-9][A-Za-z0-9-]{0,62}"
_UID = re.compile(r"[a-z2-7]{20}")
_DIGEST = re.compile(r"[0-9a-f]{40}")
_MAC = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
_NET_KEY = re.compile(r"net(0|[1-9][0-9]?)")
_DISK_KEY = re.compile(r"(?:scsi|virtio|sata|ide)(?:0|[1-9][0-9]?)")
_STORAGE = r"[A-Za-z][A-Za-z0-9_.-]*"
_UUID = r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"
_COMMON = {
    "digest",
    "name",
    "description",
    "meta",
    "ostype",
    "uid",
    "template",
    "onboot",
    "cores",
    "memory",
}
_QEMU = _COMMON | {"boot", "scsihw", "sockets", "vcpus", "balloon", "serial0", "smbios1", "vmgenid"}
_LXC = _COMMON | {"arch", "hostname", "swap", "unprivileged"}
_QEMU_NICS = {"virtio", "e1000", "e1000e", "rtl8139", "vmxnet3"}


def _denied() -> ExecutorError:
    return ExecutorError("policy_denied", "PVE clone evidence does not authorize the operation")


def _unavailable(*, unknown: bool = False) -> ExecutorError:
    return ExecutorError(
        "unavailable", "PVE clone evidence is unavailable", outcome_unknown=unknown
    )


def _guest_path(target: GuestTarget) -> str:
    return f"/nodes/{target.node}/{target.kind}/{target.vmid}"


def _worker(source: GuestTarget) -> str:
    return "qmclone" if source.kind == "qemu" else "vzclone"


def _collision(reason: object, vmid: int) -> bool:
    return isinstance(reason, str) and (
        reason == f"unable to create VM {vmid}: config file already exists"
        or re.fullmatch(rf"(?:VM|CT) {vmid} already exists(?: on node '{_NODE}')?", reason)
        is not None
    )


def _rows(data: object) -> list[dict]:
    if (
        not isinstance(data, list)
        or len(data) > MAX_RESOURCES
        or any(not isinstance(row, dict) for row in data)
    ):
        raise _denied()
    return data


class ProvisionApi:
    """Only the exact clone POST and same-node, token-owned task reads."""

    def __init__(self, api_name: str, ca_file: Path, token: str):
        try:
            native._validate_api_name(api_name)
            match = native._TOKEN.fullmatch(token)
            if match is None or tuple(part.lower() for part in match.groups()) == ("root", "pam"):
                raise _denied()
            self._context = native._api_context(ca_file)
        except (OSError, ValueError):
            raise _unavailable() from None
        self.actor = token.partition("=")[0]
        self._api_name = api_name
        self._token = token

    def _request(
        self,
        path: str,
        *,
        body: bytes | None = None,
        vmid: int | None = None,
        envelope: bool = False,
    ) -> object:
        post = body is not None
        try:
            status, data = native._request_api_response(
                self._api_name,
                self._context,
                self._token,
                f"/api2/json{path}",
                deadline=time.monotonic() + _TIMEOUT,
                max_response=_MAX_RESPONSE,
                method="POST" if post else "GET",
                body=body or b"",
                include_envelope=envelope,
                include_error_reason=post,
            )
        except ssl.SSLCertVerificationError:
            raise _unavailable() from None
        except (OSError, native._ApiPayloadError):
            raise _unavailable(unknown=post) from None
        if status == 401 or (status == 403 and not post):
            raise _denied()
        # LXC checks some permissions after reserving the destination.
        # A 403 can therefore follow a partial clone with unsuccessful cleanup.
        if post and status == 500 and vmid is not None and _collision(data, vmid):
            raise ExecutorError("conflict", "PVE reports that the target VMID is already occupied")
        if status != 200:
            raise _unavailable(unknown=post)
        return data

    def validate_permissions(self, policy: ProvisionPolicy) -> None:
        try:
            supported = native._supports_api_version(self._request("/version"))
        except native._ApiPayloadError:
            raise _unavailable() from None
        if not supported:
            raise _denied()

        expected = {
            f"/vms/{template.vmid}": ("VM.Clone", "VM.Audit") for template in policy.templates
        }
        for target in policy.targets:
            expected[f"/vms/{target.vmid}"] = ("VM.Allocate", "VM.Audit")
            expected[f"/storage/{target.storage}"] = ("Datastore.AllocateSpace", "Datastore.Audit")
            for network in target.networks:
                path = f"/sdn/zones/localnetwork/{network.bridge}"
                if network.vlan_tag is not None:
                    path += f"/{network.vlan_tag}"
                expected[path] = ("SDN.Use",)

        acl = self._request("/access/permissions")
        if not isinstance(acl, dict) or acl.keys() != expected.keys():
            raise _denied()
        for path, (required, *optional) in expected.items():
            grants = acl[path]
            if (
                not isinstance(grants, dict)
                or required not in grants
                or grants.keys() - {required, *optional}
                or not all(_zero(flag) for flag in grants.values())
            ):
                raise _denied()

    def _dispatch_fields(
        self, job: ProvisionJob, upid: object, dispatched_at: float
    ) -> dict | None:
        if not math.isfinite(dispatched_at) or dispatched_at < 0:
            raise _denied()
        return _task_fields(
            upid,
            _UPID,
            job.source,
            _worker(job.source),
            self.actor,
            math.floor(dispatched_at),
            math.floor(dispatched_at + CLONE_TASK_WINDOW_S),
        )

    def dispatch(self, job: ProvisionJob, *, dispatched_at: float) -> str:
        if not math.isfinite(dispatched_at) or dispatched_at < 0:
            raise _denied()
        name_key = "name" if job.source.kind == "qemu" else "hostname"
        body = urlencode(
            {
                "newid": job.target.vmid,
                "full": 1,
                "pool": job.destination.pool,
                "storage": job.destination.storage,
                name_key: job.name,
            }
        ).encode("ascii")
        upid = self._request(f"{_guest_path(job.source)}/clone", body=body, vmid=job.target.vmid)
        if not isinstance(upid, str) or self._dispatch_fields(job, upid, dispatched_at) is None:
            raise _unavailable(unknown=True)
        return upid

    def _task_status(self, job: ProvisionJob, upid: str, dispatched_at: float) -> str | None:
        fields = self._dispatch_fields(job, upid, dispatched_at)
        if fields is None:
            raise _denied()
        data = self._request(f"/nodes/{job.source.node}/tasks/{quote(upid, safe='')}/status")
        if not _matches_task(data, fields):
            raise _unavailable()
        if data.get("status") == "running" and "exitstatus" not in data:
            return None
        if (
            data.get("status") == "stopped"
            and isinstance(data.get("exitstatus"), str)
            and data["exitstatus"] not in ("", "unknown", "unexpected status")
            and not data["exitstatus"].startswith("unable to get last line from task log - ")
        ):
            return data["exitstatus"]
        raise _unavailable()

    def task(self, job: ProvisionJob, upid: str, *, dispatched_at: float) -> _TaskState:
        status = self._task_status(job, upid, dispatched_at)
        if status is None:
            return "running"
        if status == "OK":
            return "succeeded"
        if _collision(status, job.target.vmid):
            return "vmid_conflict"
        return "failed"

    def verify_task_target(self, job: ProvisionJob, upid: str, *, dispatched_at: float) -> None:
        status = self._task_status(job, upid, dispatched_at)
        # A running worker's log can still change.
        if status is None:
            raise _unavailable()
        path = (
            f"/nodes/{job.source.node}/tasks/{quote(upid, safe='')}/log"
            f"?start=0&limit={_TASK_LOG_LIMIT}"
        )
        document = self._request(path, envelope=True)
        if not isinstance(document, dict):
            raise _unavailable()
        total, rows = document.get("total"), document.get("data")
        if (
            type(total) is not int
            or not 2 <= total <= _TASK_LOG_LIMIT
            or not isinstance(rows, list)
            or len(rows) != total
            or any(
                not isinstance(row, dict)
                or row.keys() != {"n", "t"}
                or type(row["n"]) is not int
                or row["n"] != number
                or not isinstance(row["t"], str)
                for number, row in enumerate(rows, 1)
            )
        ):
            raise _unavailable()
        text = [row["t"] for row in rows]
        kind = "VM" if job.source.kind == "qemu" else "container"
        expected = f"creating a clone of {kind} {job.source.vmid} with ID {job.target.vmid}"
        terminal = (
            "TASK OK"
            if status == "OK"
            else (
                f"TASK {status}"
                if re.fullmatch(r"WARNINGS: [0-9]+", status)
                else f"TASK ERROR: {status}"
            )
        )
        markers = [line for line in text if line.startswith("creating a clone of ")]
        endings = [line for line in text if line.startswith("TASK ")]
        if markers != [expected] or endings != [terminal] or text[-1] != terminal:
            raise _unavailable()

    def recent_tasks(
        self, job: ProvisionJob, *, since: int, until: int | None = None
    ) -> tuple[str, ...]:
        if (
            type(since) is not int
            or since < 0
            or (until is not None and (type(until) is not int or until < since))
        ):
            raise _denied()
        return tuple(self._task_rows(job.source, since=since, until=until, archive=False))

    def completion_time(self, job: ProvisionJob, upid: str, *, dispatched_at: float) -> int:
        fields = self._dispatch_fields(job, upid, dispatched_at)
        if fields is None:
            raise _denied()
        start = fields["starttime"]
        rows = self._task_rows(job.source, since=start, until=start, archive=True)
        row = rows.get(upid)
        if row is None or row.get("status") != "OK":
            raise _unavailable()
        end = row.get("endtime")
        if type(end) is not int or end < start:
            raise _unavailable()
        return end

    def _task_rows(
        self, source: GuestTarget, *, since: int, until: int | None, archive: bool
    ) -> dict[str, dict]:
        query = {
            "vmid": source.vmid,
            "typefilter": _worker(source),
            "source": "archive" if archive else "all",
            "limit": _TASK_LIST_LIMIT,
            "since": since,
        }
        if until is not None:
            query["until"] = until
        data = self._request(f"/nodes/{source.node}/tasks?{urlencode(query)}")
        if not isinstance(data, list) or len(data) >= _TASK_LIST_LIMIT:
            raise _unavailable()
        upids: dict[str, dict] = {}
        for row in data:
            if not isinstance(row, dict) or not isinstance(upid := row.get("upid"), str):
                raise _unavailable()
            fields = _task_fields(upid, _UPID, source, _worker(source), self.actor, since, until)
            if fields is None or upid in upids:
                raise _unavailable()
            if not archive and row.get("user") == self.actor and "tokenid" not in row:
                fields["user"] = self.actor
                del fields["tokenid"]
            if not _matches_task(row, fields):
                raise _unavailable()
            upids[upid] = row
        return upids


def _uint(value: object, *, minimum: int = 0) -> int:
    if isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,18}", value):
        value = int(value)
    if type(value) is not int or not minimum <= value <= 2**63 - 1:
        raise _denied()
    return value


def _properties(parts: list[str]) -> dict[str, str]:
    result = {}
    for part in parts:
        key, sep, value = part.partition("=")
        if not sep or not key or not value or key in result:
            raise _denied()
        result[key] = value
    return result


def _network(kind: str, index: int, raw: object) -> ProvisionNetwork:
    if not isinstance(raw, str):
        raise _denied()
    fields = _properties(raw.split(","))
    if kind == "qemu":
        models = fields.keys() & _QEMU_NICS
        if len(models) != 1:
            raise _denied()
        mac = fields.pop(models.pop())
    else:
        mac = fields.pop("hwaddr", "")
        if (
            re.fullmatch(r"eth(?:0|[1-9][0-9]{0,2})", fields.pop("name", "")) is None
            or fields.pop("type", "veth") != "veth"
            or fields.pop("ip", "manual") not in {"manual", "dhcp"}
            or fields.pop("ip6", "manual") not in {"manual", "auto", "dhcp"}
        ):
            raise _denied()
    bridge = fields.pop("bridge", "")
    tag = fields.pop("tag", None)
    link_down = fields.pop("link_down", "0")
    if (
        not _MAC.fullmatch(mac)
        or link_down not in {"0", "1"}
        or fields.pop("firewall", "0") not in {"0", "1"}
        or fields
    ):
        raise _denied()
    return ProvisionNetwork(
        index=index,
        bridge=bridge,
        vlan_tag=_uint(tag, minimum=1) if tag is not None else None,
        link_down=link_down == "1",
    )


def _volume(
    target: GuestTarget, raw: object, destination: ProvisionTarget | None
) -> tuple[str, int]:
    if not isinstance(raw, str):
        raise _denied()
    volid, *parts = raw.split(",")
    disk = rf"{'vm' if destination else '(?:base|vm)'}-{target.vmid}-disk-[0-9]+"
    match = re.fullmatch(rf"({_STORAGE}):(?:{disk}|{target.vmid}/{disk}\.(?:raw|qcow2))", volid)
    if match is None or (destination is not None and match[1] != destination.storage):
        raise _denied()
    fields = _properties(parts)
    raw_size = fields.pop("size", "")
    size = re.fullmatch(r"([1-9][0-9]{0,15})([KMGT]?)", raw_size)
    if size is None or any(
        key != "discard" or value not in ("on", "ignore") for key, value in fields.items()
    ):
        raise _denied()
    powers = {"": 0, "K": 10, "M": 20, "G": 30, "T": 40}
    return volid, int(size[1]) << powers[size[2]]


def _profile(
    target: GuestTarget, config: dict, destination: ProvisionTarget | None = None
) -> tuple[CloneProfile, dict[str, int]]:
    qemu = target.kind == "qemu"
    cores, memory = _uint(config.get("cores"), minimum=1), _uint(config.get("memory"), minimum=1)
    if not _zero(config.get("onboot", 0)):
        raise _denied()
    volumes = {}
    disk_keys = set()
    networks = []
    for key, value in config.items():
        if match := _NET_KEY.fullmatch(key):
            networks.append(_network(target.kind, int(match[1]), value))
        elif _DISK_KEY.fullmatch(key) is not None if qemu else key == "rootfs":
            volid, size = _volume(target, value, destination)
            if volid in volumes:
                raise _denied()
            volumes[volid] = size
            disk_keys.add(key)
        elif key not in (_QEMU if qemu else _LXC):
            raise _denied()
    if qemu:
        if (
            config.get("serial0", "socket") != "socket"
            or re.fullmatch(
                r"uuid=" + _UUID, config.get("smbios1", "uuid=00000000-0000-0000-0000-000000000000")
            )
            is None
            or re.fullmatch(_UUID, config.get("vmgenid", "00000000-0000-0000-0000-000000000000"))
            is None
        ):
            raise _denied()
        if "boot" in config:
            boot = config["boot"]
            if (
                not isinstance(boot, str)
                or not boot.startswith("order=")
                or any(device not in disk_keys for device in boot.removeprefix("order=").split(";"))
            ):
                raise _denied()
        vcpus = cores * _uint(config.get("sockets", 1), minimum=1)
        if _uint(config.get("vcpus", 0)) > vcpus or _uint(config.get("balloon", 0)) > memory:
            raise _denied()
        swap = 0
    else:
        if _uint(config.get("unprivileged")) != 1:
            raise _denied()
        vcpus, swap = cores, _uint(config.get("swap"))
    return CloneProfile(
        vcpus=vcpus,
        memory_mib=memory,
        disk_bytes=sum(volumes.values()),
        swap_mib=swap,
        networks=tuple(networks),
    ), volumes


class ProvisionEvidence:
    """Read bounded local PVE evidence as root with native proxying disabled."""

    def _get(self, target: GuestTarget, path: str, *options: str) -> object:
        payload = _read_local(
            target,
            ["/usr/bin/pvesh", "--noproxy", "get", path, *options, "--output-format", "json"],
            _MAX_RESPONSE,
        )
        try:
            return json.loads(
                payload,
                object_pairs_hook=native._unique_object,
                parse_constant=native._reject_api_constant,
            )
        except (ValueError, RecursionError):
            raise _unavailable() from None

    def _pool(self, guest: GuestTarget, destination: ProvisionTarget) -> dict:
        # The pool ID may be nested. Supply it as a parameter instead of a path.
        pools = _rows(self._get(guest, "/pools", "--poolid", destination.pool))
        if len(pools) != 1 or pools[0].get("poolid") != destination.pool:
            raise _denied()
        _rows(pools[0].get("members"))
        return pools[0]

    def _affinities(self, guest: GuestTarget, destination: ProvisionTarget) -> dict:
        pool = self._pool(guest, destination)
        storage = self._get(guest, f"/nodes/{guest.node}/storage/{destination.storage}/status")
        content = "images" if guest.kind == "qemu" else "rootdir"
        if (
            not isinstance(storage, dict)
            or _uint(storage.get("active")) != 1
            or _uint(storage.get("enabled")) != 1
            or not isinstance(storage.get("content"), str)
            or content not in storage["content"].split(",")
        ):
            raise _denied()

        if destination.networks:
            bridges = _rows(self._get(guest, f"/nodes/{guest.node}/network", "--type", "bridge"))
            for network in destination.networks:
                matches = [row for row in bridges if row.get("iface") == network.bridge]
                if (
                    len(matches) != 1
                    or matches[0].get("type") != "bridge"
                    or _uint(matches[0].get("active")) != 1
                    or (
                        network.vlan_tag is not None
                        and _uint(matches[0].get("bridge_vlan_aware")) != 1
                    )
                ):
                    raise _denied()
        return pool

    def _guest(self, guest: GuestTarget, *, template: bool) -> tuple[str, int, dict]:
        roster = _rows(self._get(guest, "/cluster/resources", "--type", "vm"))
        matches = [row for row in roster if row.get("vmid") == guest.vmid]
        if len(matches) != 1:
            raise _denied()
        row = matches[0]
        uid, registered_at = row.get("uid"), row.get("rtime")
        if (
            type(row.get("vmid")) is not int
            or row.get("node") != guest.node
            or row.get("type") != guest.kind
            or row.get("id") != f"{guest.kind}/{guest.vmid}"
            or not isinstance(uid, str)
            or _UID.fullmatch(uid) is None
            or type(registered_at) is not int
            or not 0 < registered_at <= 999_999_999_999_999
            or "hastate" in row
            or "lock" in row
        ):
            raise _denied()
        path = _guest_path(guest)
        detail = self._get(guest, f"{path}/status/current")
        if (
            not isinstance(detail, dict)
            or type(detail.get("vmid")) is not int
            or detail["vmid"] != guest.vmid
            or detail.get("uid") != uid
            or detail.get("status") != "stopped"
            or not _zero(detail.get("pid", 0))
            or not isinstance(detail.get("ha"), dict)
            or not _zero(detail["ha"].get("managed"))
            or _uint(detail.get("template", 0)) != int(template)
            or "lock" in detail
            or (guest.kind == "qemu" and detail.get("qmpstatus") != "stopped")
        ):
            raise _denied()
        verify_local_lxc_state(guest, "stopped")
        verify_local_pending(guest)
        config = self._get(guest, f"{path}/config", "--current", "1")
        snapshots = _rows(self._get(guest, f"{path}/snapshot"))
        if (
            not isinstance(config, dict)
            or not isinstance(digest := config.get("digest"), str)
            or not _DIGEST.fullmatch(digest)
            or _uint(config.get("template", 0)) != int(template)
            or len(snapshots) != 1
            or snapshots[0].get("name") != "current"
            or "parent" in snapshots[0]
            or snapshots[0].get("digest", digest) != digest
            or not _zero(snapshots[0].get("running", 0))
        ):
            raise _denied()
        return uid, registered_at, config

    def _profile(
        self, guest: GuestTarget, config: dict, destination: ProvisionTarget | None = None
    ) -> CloneProfile:
        try:
            profile, volumes = _profile(guest, config, destination)
        except (TypeError, ValidationError):
            raise _denied() from None

        # The configured size field alone need not describe the storage volume.
        for storage in {volid.partition(":")[0] for volid in volumes}:
            data = self._get(
                guest, f"/nodes/{guest.node}/storage/{storage}/content", "--vmid", str(guest.vmid)
            )
            rows = _rows(data)
            for volid, size in volumes.items():
                if volid.partition(":")[0] != storage:
                    continue
                matches = [row for row in rows if row.get("volid") == volid]
                content = "images" if guest.kind == "qemu" else "rootdir"
                if (
                    len(matches) != 1
                    or not _matches_task(matches[0], {"vmid": guest.vmid, "content": content})
                    or _uint(matches[0].get("size"), minimum=1) != size
                ):
                    raise _denied()
        return profile

    def observe_source(
        self, source: GuestTarget, template: ProvisionTemplate, destination: ProvisionTarget
    ) -> TemplateEvidence:
        if (source.kind, source.vmid) != (
            template.kind,
            template.vmid,
        ) or source.vmid != destination.template_vmid:
            raise _denied()
        self._affinities(source, destination)
        uid, registered_at, config = self._guest(source, template=True)
        if (uid, registered_at, config["digest"]) != (
            template.pve_uid,
            template.registered_at_ms,
            template.config_digest,
        ):
            raise _denied()
        profile = self._profile(source, config)
        if not profile.fits(destination):
            raise _denied()
        return TemplateEvidence(
            pve_uid=uid,
            registered_at_ms=registered_at,
            config_digest=config["digest"],
            profile=profile,
        )

    def verify_target(
        self, job: ProvisionJob, *, dispatched_at: float, completed_at: int
    ) -> ProvisionedGuest:
        if (
            not math.isfinite(dispatched_at)
            or dispatched_at < 0
            or type(completed_at) is not int
            or completed_at < math.floor(dispatched_at)
        ):
            raise _denied()
        target, destination = job.target, job.destination
        pool = self._affinities(target, destination)
        members = [row for row in pool["members"] if row.get("vmid") == target.vmid]
        if len(members) != 1 or not _matches_task(
            members[0],
            {
                "vmid": target.vmid,
                "node": target.node,
                "type": target.kind,
                "id": f"{target.kind}/{target.vmid}",
            },
        ):
            raise _denied()
        uid, registered_at, config = self._guest(target, template=False)
        if (
            uid == job.observation.pve_uid
            or registered_at <= job.observation.registered_at_ms
            or registered_at < math.floor(dispatched_at * 1000)
            or registered_at // 1000 > completed_at
            or config.get("name" if target.kind == "qemu" else "hostname") != job.name
        ):
            raise _denied()
        profile = self._profile(target, config, destination)
        if profile != job.observation.profile or not profile.fits(destination):
            raise _denied()
        return ProvisionedGuest(pve_uid=uid, registered_at_ms=registered_at)
