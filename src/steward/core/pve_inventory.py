"""Bounded, read-only inventory from an explicitly registered local PVE API."""

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from ssl import SSLContext
from typing import TypeVar

from steward.core.pve_inventory_models import (
    MAX_RESOURCES,
    Evidence,
    EvidenceSource,
    EvidenceState,
    Guest,
    InventorySnapshot,
    MeasurementObservation,
    NetworkObservation,
    Pool,
    ResourceIndex,
    TaskObservation,
    parse_measurements,
    parse_network,
    parse_resources,
    parse_tasks,
)
from steward.core.pve_native import (
    PreflightError,
    _api_context,
    _ApiPayloadError,
    _load_token,
    _read_api_response,
    _validate_api_name,
)

_Acl = dict[str, dict[str, int]]
_GuestKey = tuple[str, int, str, str | None, str | None, int | None]
_Item = TypeVar("_Item")

_PERMISSIONS = "/api2/json/access/permissions"
_RESOURCES = "/api2/json/cluster/resources"
_ALLOWED_AUDIT = frozenset({"VM.Audit", "Sys.Audit", "Datastore.Audit", "Pool.Audit"})
_TIMEOUT = 10
_REQUEST_TIMEOUT = 2
_FINAL_RESERVE = 3
_MAX_RESPONSE = 256 * 1024
# Initial/final permissions and resources, plus at most two exact-node checks
# per distinct node or guest, and three detail calls per visible guest.
_MAX_REQUESTS = 5 * MAX_RESOURCES + 4


@dataclass(frozen=True)
class RegisteredLocalTarget:
    """Operator-supplied certificate identity and credentials for the fixed loopback API.

    Provision a dedicated inventory token with privilege separation enabled and
    explicit least-privilege scope. PVE allows the collector to check effective
    permissions. The resulting inventory is limited to the scope of that token.
    """

    api_name: str
    ca_file: Path
    inventory_token_file: Path
    health_token_file: Path


class _InventoryFailure(Exception):
    """An evidence failure that prevents publishing scoped inventory."""

    def __init__(self, evidence: Evidence):
        self.evidence = evidence


def _evidence(source: EvidenceSource, state: EvidenceState) -> Evidence:
    return Evidence(source=source, observed_at=datetime.now(UTC), state=state)


def _has_audit(acl: _Acl, path: str, privilege: str) -> bool:
    # PVE provides effective entries for exact ACL paths and pool members.
    # Descendant visibility from propagating grants is checked by the PVE roster.
    if path in acl:
        return privilege in acl[path]
    while path != "/":
        path = path.rpartition("/")[0] or "/"
        if acl.get(path, {}).get(privilege) == 1:
            return True
    return False


def _status_state(status: int) -> EvidenceState:
    if status == 200:
        return "observed"
    if status in (401, 403):
        return "restricted"
    if status == 404:
        return "missing"
    if status == 429 or 300 <= status <= 399 or 500 <= status <= 599:
        return "unavailable"
    return "invalid"


class _Collector:
    def __init__(
        self, target: RegisteredLocalTarget, context: SSLContext, token: str, deadline: float
    ):
        self.target = target
        self.context = context
        self.token = token
        self.deadline = deadline
        self.detail_deadline = deadline - _FINAL_RESERVE
        self.requests = 0

    def _get(
        self, path: str, source: EvidenceSource, *, final: bool = False
    ) -> tuple[object, Evidence]:
        deadline = self.deadline if final else self.detail_deadline
        now = time.monotonic()
        if self.requests >= _MAX_REQUESTS or now >= deadline:
            return None, _evidence(source, "budget")
        self.requests += 1
        data = None
        try:
            status, data = _read_api_response(
                self.target.api_name,
                self.context,
                self.token,
                path,
                deadline=min(deadline, now + _REQUEST_TIMEOUT),
                max_response=_MAX_RESPONSE,
            )
            state = _status_state(status)
        except _ApiPayloadError:
            state = "invalid"
        except OSError:
            state = "unavailable"
        if time.monotonic() >= deadline:
            return None, _evidence(source, "budget")
        return data, _evidence(source, state)

    def permissions(self, *, node: str | None = None, final: bool = False) -> _Acl:
        scope = f"/nodes/{node}" if node is not None else None
        path = f"{_PERMISSIONS}?path={scope}" if scope else _PERMISSIONS
        data, evidence = self._get(path, "permissions", final=final)
        if evidence.state != "observed":
            raise _InventoryFailure(evidence)
        if not isinstance(data, dict) or (scope is not None and data.keys() != {scope}):
            raise _InventoryFailure(evidence.model_copy(update={"state": "invalid"}))
        privileges: set[str] = set()
        for acl_path, acl in data.items():
            if (
                not isinstance(acl_path, str)
                or not acl_path.startswith("/")
                or not isinstance(acl, dict)
                or any(type(flag) is not int or flag not in (0, 1) for flag in acl.values())
            ):
                raise _InventoryFailure(evidence.model_copy(update={"state": "invalid"}))
            privileges.update(acl)
        if not privileges <= _ALLOWED_AUDIT:
            raise _InventoryFailure(evidence.model_copy(update={"state": "restricted"}))
        return data

    def resources(self, *, final: bool = False) -> tuple[ResourceIndex, Evidence]:
        data, evidence = self._get(_RESOURCES, "cluster_resources", final=final)
        if evidence.state != "observed":
            raise _InventoryFailure(evidence)
        try:
            return parse_resources(data, evidence), evidence
        except ValueError:
            raise _InventoryFailure(evidence.model_copy(update={"state": "invalid"})) from None

    def _observe(
        self, path: str, source: EvidenceSource, parser: Callable[[object], tuple[_Item, ...]]
    ) -> tuple[Evidence, tuple[_Item, ...]]:
        data, evidence = self._get(path, source)
        if evidence.state != "observed":
            return evidence, ()
        try:
            items = parser(data)
        except ValueError:
            return evidence.model_copy(update={"state": "invalid"}), ()
        return (evidence if items else evidence.model_copy(update={"state": "absent"})), items

    def guest_detail(self, guest: Guest, node_audit: bool) -> Guest:
        node = guest.node
        vmid = guest.vmid
        path = f"/api2/json/nodes/{node}/{guest.kind}/{vmid}"
        config, network = self._observe(f"{path}/config?current=1", "guest_config", parse_network)
        rrd, measurements = _evidence("guest_rrd", "missing"), ()
        task_evidence = _evidence("guest_tasks", "missing" if node_audit else "restricted")
        tasks = ()
        if guest.pve_uid is not None and guest.registered_at_ms is not None:
            # Task timestamps have second precision. Exclude the registration
            # second itself to avoid attributing events from a previous guest.
            registered_after = guest.registered_at_ms // 1000 + 1
            rrd, measurements = self._observe(
                f"{path}/rrddata?timeframe=hour&cf=AVERAGE",
                "guest_rrd",
                lambda data: parse_measurements(data, registered_after=registered_after),
            )
            if node_audit:
                task_evidence, tasks = self._observe(
                    f"/api2/json/nodes/{node}/tasks?vmid={vmid}&source=all&limit=20",
                    "guest_tasks",
                    lambda data: parse_tasks(
                        data,
                        node=node,
                        vmid=vmid,
                        kind=guest.kind,
                        registered_after=registered_after,
                    ),
                )
        return guest.model_copy(
            update={
                "network": NetworkObservation(evidence=config, items=network),
                "measurements": MeasurementObservation(evidence=rrd, items=measurements),
                "tasks": TaskObservation(evidence=task_evidence, items=tasks),
            }
        )

    def audited_nodes(self, nodes: set[str], acl: _Acl, *, final: bool = False) -> set[str]:
        result = set()
        for node in sorted(nodes):
            path = f"/nodes/{node}"
            if _has_audit(acl, path, "Sys.Audit"):
                exact_acl = self.permissions(node=node, final=final)
                if _has_audit(exact_acl, path, "Sys.Audit"):
                    result.add(node)
        return result

    def collect(self) -> InventorySnapshot:
        initial_acl = self.permissions()
        initial, _ = self.resources()
        candidates = tuple(
            guest
            for guest in initial.guests
            if _has_audit(initial_acl, f"/vms/{guest.vmid}", "VM.Audit")
        )
        nodes = {row.node for row in (*initial.nodes, *candidates)}
        node_audits = self.audited_nodes(nodes, initial_acl)
        details = {
            _guest_key(guest): self.guest_detail(guest, guest.node in node_audits)
            for guest in candidates
        }

        # PVE's ACL listing omits denied child paths. Read its authoritative
        # roster after the ACL check so a new child deny is enforced there.
        final_acl = self.permissions(final=True)
        final, evidence = self.resources(final=True)
        final_nodes = {row.node for row in (*final.nodes, *final.guests)}
        node_audits = self.audited_nodes(node_audits & final_nodes, final_acl, final=True)
        nodes = tuple(
            row
            for row in final.nodes
            if row.node in node_audits and _has_audit(final_acl, f"/nodes/{row.node}", "Sys.Audit")
        )
        pool_ids = {
            row.pool
            for row in initial.pools
            if _has_audit(initial_acl, f"/pool/{row.pool}", "Pool.Audit")
        }
        pools = tuple(
            row
            for row in final.pools
            if row.pool in pool_ids and _has_audit(final_acl, f"/pool/{row.pool}", "Pool.Audit")
        )
        store_ids = {
            (row.node, row.storage)
            for row in initial.datastores
            if _has_audit(initial_acl, f"/storage/{row.storage}", "Datastore.Audit")
        }
        datastores = tuple(
            row
            for row in final.datastores
            if (row.node, row.storage) in store_ids
            and _has_audit(final_acl, f"/storage/{row.storage}", "Datastore.Audit")
        )
        guests = _visible_guests(final.guests, details, node_audits, pools, final_acl)
        if time.monotonic() >= self.deadline:
            raise _InventoryFailure(evidence.model_copy(update={"state": "budget"}))
        if not (nodes or guests or pools or datastores):
            evidence = evidence.model_copy(update={"state": "absent"})
        return InventorySnapshot(
            api_name=self.target.api_name,
            observed_at=evidence.observed_at,
            evidence=evidence,
            nodes=nodes,
            guests=guests,
            pools=pools,
            datastores=datastores,
        )


def _guest_key(guest: Guest) -> _GuestKey:
    return guest.node, guest.vmid, guest.kind, guest.name, guest.pve_uid, guest.registered_at_ms


def _visible_guests(
    rows: tuple[Guest, ...],
    details: dict[_GuestKey, Guest],
    audited_nodes: set[str],
    pools: tuple[Pool, ...],
    final_acl: _Acl,
) -> tuple[Guest, ...]:
    visible_pools = {pool.pool for pool in pools}
    result = []
    for row in rows:
        detail = details.get(_guest_key(row))
        if detail is None or not _has_audit(final_acl, f"/vms/{row.vmid}", "VM.Audit"):
            continue
        tasks = detail.tasks
        if row.node not in audited_nodes or not _has_audit(
            final_acl, f"/nodes/{row.node}", "Sys.Audit"
        ):
            tasks = TaskObservation(evidence=_evidence("guest_tasks", "restricted"), items=())
        result.append(
            row.model_copy(
                update={
                    "pool": row.pool if row.pool in visible_pools else None,
                    "network": detail.network,
                    "measurements": detail.measurements,
                    "tasks": tasks,
                }
            )
        )
    return tuple(result)


def collect_inventory(target: RegisteredLocalTarget) -> InventorySnapshot:
    """Collect scoped evidence without returning API bodies or credentials."""
    deadline = time.monotonic() + _TIMEOUT
    _validate_api_name(target.api_name)
    if not all(
        path.is_absolute()
        for path in (target.ca_file, target.inventory_token_file, target.health_token_file)
    ):
        raise PreflightError("Use absolute paths for the registered CA and PVE token files.")
    token = _load_token(target.inventory_token_file)
    health_token = _load_token(target.health_token_file)
    if token.partition("=")[0] == health_token.partition("=")[0]:
        raise PreflightError("Inventory and health require distinct PVE token identities.")
    try:
        context = _api_context(target.ca_file)
    except (OSError, ValueError):
        evidence = _evidence("permissions", "unavailable")
    else:
        try:
            return _Collector(target, context, token, deadline).collect()
        except _InventoryFailure as exc:
            evidence = exc.evidence
    return InventorySnapshot(
        api_name=target.api_name, observed_at=evidence.observed_at, evidence=evidence
    )
