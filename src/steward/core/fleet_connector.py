"""Read-only inventory from an operator-approved PVE route in the target network."""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from hashlib import sha256
from pathlib import Path
from threading import BoundedSemaphore, Event, Thread
from typing import TYPE_CHECKING

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
    _api_context,
    _load_token,
    _remaining,
    _request_api_response,
    _validate_api_name,
)

if TYPE_CHECKING:
    from steward.core.fleet_enrollment import PveConnectorRoute

_STATUS = "/api2/json/cluster/status"
_NATIVE_ID = re.compile(r"[a-z2-7]{20}")
_FINGERPRINT = re.compile(r"[0-9a-f]{64}")
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


def collect_pve_inventory(
    route: PveConnectorRoute, *, ca_file: Path, token_ref: str
) -> InventorySnapshot:
    """Read scoped evidence only after verifying the approved transport and native instance."""
    deadline = time.monotonic() + _TIMEOUT + _REQUEST_TIMEOUT
    prefix, separator, token_path = token_ref.partition(":")
    token_file = Path(token_path)
    if (
        prefix != "file"
        or not separator
        or not token_file.is_absolute()
        or not ca_file.is_absolute()
    ):
        raise PveConnectorError("Use absolute paths for the PVE CA and private token file.")
    try:
        token = _load_token(token_file)
        return _RemoteCollector(route, ca_file, token, deadline).collect()
    except PveConnectorError:
        raise
    except (OSError, ValueError, _InventoryFailure):
        raise PveConnectorError(
            "Could not collect inventory from the approved PVE route."
        ) from None
