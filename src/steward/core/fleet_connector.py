"""Read-only inventory from an operator-approved PVE route in the target network."""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from hashlib import sha256
from pathlib import Path
from threading import BoundedSemaphore, Event, Thread
from typing import TYPE_CHECKING, cast

from pydantic import TypeAdapter, ValidationError

from steward.core.fleet_adoption_models import (
    AuditPrivilege,
    Calendar,
    PveAdoptionEvidence,
    PveBackupSchedule,
    ScheduleState,
)
from steward.core.pve_inventory import (
    _MAX_REQUESTS,
    _MAX_RESPONSE,
    _REQUEST_TIMEOUT,
    _TIMEOUT,
    _Acl,
    _Collector,
    _InventoryFailure,
)
from steward.core.pve_inventory_models import MAX_RESOURCES, InventorySnapshot
from steward.core.pve_native import (
    API_PORT,
    PVE_VERSION,
    _api_context,
    _load_token,
    _remaining,
    _request_api_response,
    _validate_api_name,
)

if TYPE_CHECKING:
    from steward.core.fleet_enrollment import PveConnectorRoute

_STATUS = "/api2/json/cluster/status"
_BACKUP = "/api2/json/cluster/backup"
_NATIVE_ID = re.compile(r"[a-z2-7]{20}")
_FINGERPRINT = re.compile(r"[0-9a-f]{64}")
_BACKUP_JOB_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_VMID = re.compile(r"[1-9][0-9]{2,8}")
_CALENDAR = TypeAdapter(Calendar)
_Address = ipaddress.IPv4Address | ipaddress.IPv6Address
# libc resolution can outlive the request. A bounded number of daemon threads
# may finish an abandoned lookup, but can never connect or access credentials.
_RESOLVER_SLOTS = BoundedSemaphore(4)


class PveConnectorError(ValueError):
    """The approved PVE route could not provide bound inventory."""


def pve_instance_binding(native_id: str) -> str:
    if not isinstance(native_id, str) or _NATIVE_ID.fullmatch(native_id) is None:
        raise PveConnectorError("Invalid PVE native instance ID.")
    return sha256(native_id.encode("ascii")).hexdigest()


def _check_dns(api_name: str, address: _Address, deadline: float) -> None:
    error = PveConnectorError("Could not verify the approved PVE address.")
    if not _RESOLVER_SLOTS.acquire(timeout=_remaining(deadline)):
        raise error
    done = Event()
    addresses: set[_Address] = set()

    def resolve() -> None:
        try:
            rows = socket.getaddrinfo(api_name, API_PORT, type=socket.SOCK_STREAM)
            addresses.update(ipaddress.ip_address(row[4][0]) for row in rows)
        except (OSError, ValueError):
            addresses.clear()
        finally:
            _RESOLVER_SLOTS.release()
            done.set()

    try:
        Thread(target=resolve, daemon=True).start()
    except RuntimeError:
        _RESOLVER_SLOTS.release()
        raise error from None
    if not done.wait(_remaining(deadline)) or addresses != {address}:
        raise error
    _remaining(deadline)


def _verify_status(data: object, route: PveConnectorRoute) -> None:
    error = PveConnectorError("Could not verify the approved PVE instance and node.")
    if not isinstance(data, list) or not 1 <= len(data) <= MAX_RESOURCES + 1:
        raise error
    cluster = None
    local = None
    nodes = set()
    for row in data:
        if not isinstance(row, dict):
            raise error
        if row.get("type") == "cluster" and row.get("id") == "cluster" and cluster is None:
            cluster = row
            continue
        name, is_local = row.get("name"), row.get("local")
        if (
            row.get("type") != "node"
            or not isinstance(name, str)
            or row.get("id") != f"node/{name}"
            or name in nodes
            or type(is_local) is not int
            or is_local not in (0, 1)
        ):
            raise error
        nodes.add(name)
        if is_local == 1:
            if local is not None:
                raise error
            local = row
    if local is None or local["name"] != route.node:
        raise error
    if route.kind == "cluster" and cluster is not None:
        if any("cluster-id" in row for row in data if row is not cluster):
            raise error
        native_id = cluster.get("cluster-id")
    elif route.kind == "standalone" and cluster is None and len(nodes) == 1:
        native_id = local.get("cluster-id")
    else:
        raise error
    if pve_instance_binding(native_id) != route.instance_binding:
        raise error


class _RemoteCollector(_Collector):
    request_limit = _MAX_REQUESTS + 2

    def __init__(self, route: PveConnectorRoute, ca_file: Path, token: str, deadline: float):
        self.route = route
        _validate_api_name(route.api_name)
        api_name = route.api_name.lower()
        self.address = ipaddress.ip_address(route.address)
        if str(self.address) != route.address or "%" in route.address:
            raise PveConnectorError("Invalid approved PVE address.")
        try:
            numeric_name = ipaddress.ip_address(api_name)
        except ValueError:
            self.dns_name = True
        else:
            if numeric_name != self.address or api_name != str(self.address):
                raise PveConnectorError("Invalid approved PVE address.")
            self.dns_name = False
        if _FINGERPRINT.fullmatch(route.transport_fingerprint) is None:
            raise PveConnectorError("Invalid approved PVE transport fingerprint.")
        context = _api_context(ca_file)
        context.hostname_checks_common_name = False
        super().__init__(api_name, context, token, deadline)
        self.detail_deadline -= _REQUEST_TIMEOUT

    def _check_address(self, deadline: float) -> None:
        if self.dns_name:
            try:
                _check_dns(self.api_name, self.address, deadline)
            except TimeoutError:
                raise PveConnectorError("Could not verify the approved PVE address.") from None

    def _request(self, path: str, deadline: float) -> tuple[int, object]:
        self._check_address(deadline)
        status, data = _request_api_response(
            self.api_name,
            self.context,
            self.token,
            path,
            deadline=deadline,
            max_response=_MAX_RESPONSE,
            _pinned_address=self.address,
            _leaf_fingerprint=self.route.transport_fingerprint,
        )
        if 300 <= status <= 399:
            raise PveConnectorError("Unexpected response from the approved PVE route.")
        return status, data

    def _check_identity(self, acl: _Acl, *, final: bool = False) -> None:
        # PVE requires Sys.Audit on / for status. A non-propagating grant
        # allows this check without adding visibility at descendant ACL paths.
        if acl.get("/", {}).get("Sys.Audit") != 0:
            raise PveConnectorError("The PVE token requires non-propagating root Sys.Audit.")
        data, evidence = self._get(_STATUS, "permissions", final=final)
        if evidence.state != "observed":
            raise PveConnectorError("Could not verify the approved PVE instance and node.")
        _verify_status(data, self.route)
        if final:
            self._check_address(min(self.deadline, time.monotonic() + _REQUEST_TIMEOUT))


class _AdoptionCollector(_RemoteCollector):
    request_limit = _RemoteCollector.request_limit + 1

    def _check_identity(self, acl: _Acl, *, final: bool = False) -> None:
        super()._check_identity(acl, final=final)
        privileges = {name for permissions in acl.values() for name in permissions}
        if final:
            self.audit_privileges &= privileges
        else:
            self.audit_privileges = privileges
            # This endpoint is gated by root Sys.Audit, not per-guest ACLs.
            # Hold its response until the final guest roster and ACL check.
            self.backup_rows, self.backup_evidence = self._get(_BACKUP, "cluster_resources")

    def collect_adoption(self) -> tuple[InventorySnapshot, PveAdoptionEvidence]:
        snapshot = self.collect()
        state = cast(ScheduleState, self.backup_evidence.state)
        schedules = ()
        if state == "observed":
            if not isinstance(self.backup_rows, list) or len(self.backup_rows) > MAX_RESOURCES:
                state = "invalid"
            else:
                schedules = _project_backup_jobs(self.backup_rows, self.route, snapshot)
        _remaining(self.deadline)
        return snapshot, PveAdoptionEvidence(
            observed_at=snapshot.observed_at,
            node=self.route.node,
            pve_version=PVE_VERSION,
            audit_privileges=cast(tuple[AuditPrivilege, ...], tuple(sorted(self.audit_privileges))),
            schedule_state=state,
            schedules=schedules,
        )


def _explicit_selection(row: dict, visible_vmids: set[int], node: str) -> tuple[int, ...]:
    if {"pool", "exclude"} & row.keys() or row.get("node", node) != node:
        return ()
    all_guests = row.get("all", 0)
    if type(all_guests) is not int or all_guests != 0:
        return ()
    raw = row.get("vmid")
    if not isinstance(raw, str) or len(raw) > 10 * MAX_RESOURCES:
        return ()
    parts = raw.split(",")
    if len(parts) > MAX_RESOURCES or any(_VMID.fullmatch(part) is None for part in parts):
        return ()
    vmids = {int(part) for part in parts}
    if len(vmids) != len(parts) or not vmids <= visible_vmids:
        return ()
    return tuple(sorted(vmids))


def _project_backup_jobs(
    rows: list, route: PveConnectorRoute, snapshot: InventorySnapshot
) -> tuple[PveBackupSchedule, ...]:
    visible_vmids = {guest.vmid for guest in snapshot.guests if guest.node == route.node}
    jobs: dict[str, PveBackupSchedule] = {}
    duplicates: set[str] = set()
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        job_id = row.get("id")
        if not isinstance(job_id, str) or _BACKUP_JOB_ID.fullmatch(job_id) is None:
            continue
        if job_id in seen:
            duplicates.add(job_id)
            continue
        seen.add(job_id)
        vmids = _explicit_selection(row, visible_vmids, route.node)
        enabled = row.get("enabled", 1)
        if not vmids or type(enabled) not in (bool, int) or enabled not in (0, 1):
            continue
        try:
            calendar = _CALENDAR.validate_python(row.get("schedule"), strict=True)
        except ValidationError:
            calendar = None
        ref = sha256(f"pve-backup-job:v1:{route.instance_binding}:{job_id}".encode("ascii"))
        jobs[job_id] = PveBackupSchedule(
            job_ref=ref.hexdigest(), schedule=calendar, enabled=bool(enabled), vmids=vmids
        )
    return tuple(
        sorted(
            (job for job_id, job in jobs.items() if job_id not in duplicates),
            key=lambda job: job.job_ref,
        )
    )


def _connector_token(ca_file: Path, token_ref: str) -> str:
    prefix, separator, token_path = token_ref.partition(":")
    token_file = Path(token_path)
    if (
        prefix != "file"
        or not separator
        or not token_file.is_absolute()
        or not ca_file.is_absolute()
    ):
        raise PveConnectorError("Use absolute paths for the PVE CA and private token file.")
    return _load_token(token_file)


def collect_pve_inventory(
    route: PveConnectorRoute, *, ca_file: Path, token_ref: str
) -> InventorySnapshot:
    """Read scoped evidence only after verifying the approved transport and native instance."""
    deadline = time.monotonic() + _TIMEOUT + _REQUEST_TIMEOUT
    try:
        token = _connector_token(ca_file, token_ref)
        return _RemoteCollector(route, ca_file, token, deadline).collect()
    except PveConnectorError:
        raise
    except (OSError, ValueError, _InventoryFailure):
        raise PveConnectorError(
            "Could not collect inventory from the approved PVE route."
        ) from None


def collect_pve_adoption(
    route: PveConnectorRoute, *, ca_file: Path, token_ref: str
) -> tuple[InventorySnapshot, PveAdoptionEvidence]:
    """Read token-scoped native schedules together with bound standalone inventory."""
    if route.kind != "standalone":
        raise PveConnectorError("PVE adoption requires an approved standalone route.")
    deadline = time.monotonic() + _TIMEOUT + _REQUEST_TIMEOUT
    try:
        token = _connector_token(ca_file, token_ref)
        return _AdoptionCollector(route, ca_file, token, deadline).collect_adoption()
    except PveConnectorError:
        raise
    except (OSError, ValueError, _InventoryFailure):
        raise PveConnectorError(
            "Could not collect adoption evidence from the approved PVE route."
        ) from None
