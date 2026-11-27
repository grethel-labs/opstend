"""Fixed native PVE power calls for exact registered guests."""

from __future__ import annotations

import json
import math
import os
import re
import socket
import ssl
import time
from pathlib import Path
from typing import Literal
from urllib.parse import quote

from steward.core import pve_native as native
from steward.core.process import CommandError, run_bounded
from steward.core.pve_inventory_models import MAX_RESOURCES
from steward.core.pve_power import (
    UPID_PATTERN,
    GuestObservation,
    GuestState,
    GuestTarget,
    LegOperation,
    PowerPolicy,
)

from .protocol import ExecutorError

_PERMISSIONS = "/api2/json/access/permissions"
_ROSTER = "/api2/json/cluster/resources?type=vm"
_PRIVILEGES = frozenset({"VM.Audit", "VM.PowerMgmt"})
_TIMEOUT = 2
DISPATCH_TASK_WINDOW_S = _TIMEOUT
_MAX_RESPONSE = 256 * 1024
_TASK_LIST_LIMIT = 9
_UID = re.compile(r"[a-z2-7]{20}")
_UPID = re.compile(UPID_PATTERN)
_POST_BODIES = {"start": b"", "shutdown": b"forceStop=0"}
_TaskState = Literal["running", "succeeded", "failed"]


def _denied() -> ExecutorError:
    return ExecutorError("policy_denied", "PVE power evidence does not authorize the operation")


def _unavailable(*, outcome_unknown: bool = False) -> ExecutorError:
    return ExecutorError(
        "unavailable", "PVE power API evidence is unavailable", outcome_unknown=outcome_unknown
    )


def _zero(value: object) -> bool:
    return type(value) is int and value == 0


def _guest_path(target: GuestTarget) -> str:
    return f"/api2/json/nodes/{target.node}/{target.kind}/{target.vmid}"


def _worker_type(target: GuestTarget, operation: LegOperation) -> str:
    return ("qm" if target.kind == "qemu" else "vz") + operation


def _matches_task(data: object, fields: dict) -> bool:
    return isinstance(data, dict) and all(
        type(data.get(key)) is type(value) and data[key] == value for key, value in fields.items()
    )


def _task_fields(
    upid: object,
    pattern: re.Pattern[str],
    target: GuestTarget,
    expected_worker: str,
    expected_actor: str,
    since: int,
    until: int | None,
) -> dict | None:
    if not isinstance(upid, str) or len(upid) > 512:
        return None
    match = pattern.fullmatch(upid)
    if match is None:
        return None
    node, raw_pid, raw_pstart, raw_time, worker, vmid, actor = match.groups()
    pid, pstart, start = (int(raw, 16) for raw in (raw_pid, raw_pstart, raw_time))
    if (
        node != target.node
        or worker != expected_worker
        or vmid != str(target.vmid)
        or actor != expected_actor
        or not pid
        or not pstart
        or start < since
        or (until is not None and start > until)
    ):
        return None
    user, _, tokenid = expected_actor.partition("!")
    return {
        "upid": upid,
        "node": node,
        "type": worker,
        "id": vmid,
        "user": user,
        "tokenid": tokenid,
        "pid": pid,
        "pstart": pstart,
        "starttime": start,
    }


def _check_pending(data: object) -> None:
    if not isinstance(data, list):
        raise _denied()
    seen = set()
    for row in data:
        if not isinstance(row, dict) or row.keys() - {"key", "value", "pending", "delete"}:
            raise _denied()
        key = row.get("key")
        if (
            not isinstance(key, str)
            or not key
            or key in seen
            or "pending" in row
            or "value" not in row
            or not _zero(row.get("delete", 0))
            or key == "lock"
        ):
            raise _denied()
        seen.add(key)


def _read_local(target: GuestTarget, argv: list[str], max_bytes: int) -> bytes:
    if os.geteuid() != 0 or socket.gethostname().partition(".")[0] != target.node:
        raise _denied()
    try:
        return run_bounded(
            argv,
            cwd=Path("/"),
            env={"LANG": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            timeout=_TIMEOUT,
            max_bytes=max_bytes,
        )
    except (CommandError, OSError):
        raise _unavailable() from None


def verify_local_pending(target: GuestTarget) -> None:
    """Check native pending configuration that PVE may hide from VM.Audit."""
    path = _guest_path(target).removeprefix("/api2/json")
    contents = _read_local(
        target,
        ["/usr/bin/pvesh", "--noproxy", "get", f"{path}/pending", "--output-format", "json"],
        _MAX_RESPONSE,
    )
    try:
        data = json.loads(
            contents,
            object_pairs_hook=native._unique_object,
            parse_constant=native._reject_api_constant,
        )
    except (ValueError, RecursionError):
        raise _unavailable() from None
    _check_pending(data)


def verify_local_lxc_state(target: GuestTarget, expected_state: GuestState) -> None:
    """Distinguish a running LXC guest from a frozen one."""
    # A configured template or a guest that has not started may have no LXC
    # runtime record. Callers verify PVE's stopped state and absent PID first.
    if target.kind != "lxc" or expected_state != "running":
        return
    state = _read_local(target, ["/usr/bin/lxc-info", "-n", str(target.vmid), "-sH"], 64)
    if state not in (b"RUNNING\n", b"STOPPED\n", b"FROZEN\n"):
        raise _unavailable()
    if state != b"RUNNING\n":
        raise _denied()


class PowerApi:
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

    def _request(self, path: str, *, body: bytes | None = None) -> object:
        post = body is not None
        try:
            status, data = native._request_api_response(
                self._api_name,
                self._context,
                self._token,
                path,
                deadline=time.monotonic() + _TIMEOUT,
                max_response=_MAX_RESPONSE,
                method="POST" if post else "GET",
                body=body or b"",
            )
        except ssl.SSLCertVerificationError:
            # Certificate verification completes before the token or request is sent.
            raise _unavailable() from None
        except (OSError, native._ApiPayloadError):
            raise _unavailable(outcome_unknown=post) from None
        if status in (401, 403):
            raise _denied()
        if status != 200:
            raise _unavailable(outcome_unknown=post)
        return data

    def validate_permissions(self, policy: PowerPolicy) -> None:
        try:
            supported = native._supports_api_version(self._request(native._API_VERSION))
        except native._ApiPayloadError:
            raise _unavailable() from None
        if not supported:
            raise _denied()
        acl = self._request(_PERMISSIONS)
        expected = {f"/vms/{guest.vmid}" for guest in policy.guests}
        if not isinstance(acl, dict) or acl.keys() != expected:
            raise _denied()
        for permissions in acl.values():
            if (
                not isinstance(permissions, dict)
                or permissions.keys() != _PRIVILEGES
                or any(type(flag) is not int or flag not in (0, 1) for flag in permissions.values())
            ):
                raise _denied()

    def observe(self, target: GuestTarget) -> GuestObservation:
        roster = self._request(_ROSTER)
        if not isinstance(roster, list) or len(roster) > MAX_RESOURCES:
            raise _denied()
        if any(not isinstance(row, dict) or type(row.get("vmid")) is not int for row in roster):
            raise _denied()
        rows = [row for row in roster if row["vmid"] == target.vmid]
        if len(rows) != 1:
            raise _denied()
        row = rows[0]
        uid, registered_at = row.get("uid"), row.get("rtime")
        if (
            row.get("node") != target.node
            or row.get("type") != target.kind
            or row.get("id") != f"{target.kind}/{target.vmid}"
            or not isinstance(uid, str)
            or not _UID.fullmatch(uid)
            or type(registered_at) is not int
            or not 0 < registered_at <= 999_999_999_999_999
            or "hastate" in row
            or "lock" in row
        ):
            raise _denied()

        path = _guest_path(target)
        detail = self._request(f"{path}/status/current")
        if (
            not isinstance(detail, dict)
            or type(detail.get("vmid")) is not int
            or detail["vmid"] != target.vmid
            or detail.get("uid") != uid
            or not isinstance(detail.get("ha"), dict)
            or not _zero(detail["ha"].get("managed"))
            or not _zero(detail.get("template", 0))
            or "lock" in detail
        ):
            raise _denied()
        # Roster status is sourced from cached RRD data. Use current native status.
        state = detail.get("status")
        if state not in ("running", "stopped"):
            raise _denied()
        if target.kind == "qemu" and detail.get("qmpstatus") != state:
            raise _denied()
        pid = detail.get("pid", 0)
        if type(pid) is not int or (not 0 < pid <= 2**31 - 1 if state == "running" else pid != 0):
            raise _denied()
        _check_pending(self._request(f"{path}/pending"))
        return GuestObservation(
            pve_uid=uid, registered_at_ms=registered_at, state=state, pid=pid or None
        )

    def _upid_fields(
        self,
        target: GuestTarget,
        operation: LegOperation,
        upid: object,
        since: int,
        until: int | None,
    ) -> dict | None:
        return _task_fields(
            upid, _UPID, target, _worker_type(target, operation), self.actor, since, until
        )

    def dispatch(
        self, target: GuestTarget, operation: LegOperation, *, dispatched_at: float
    ) -> str:
        if operation not in _POST_BODIES or not math.isfinite(dispatched_at):
            raise _denied()
        upid = self._request(
            f"{_guest_path(target)}/status/{operation}", body=_POST_BODIES[operation]
        )
        if (
            self._upid_fields(
                target,
                operation,
                upid,
                math.floor(dispatched_at),
                math.floor(dispatched_at + DISPATCH_TASK_WINDOW_S),
            )
            is None
        ):
            raise _unavailable(outcome_unknown=True)
        return upid

    def task(
        self, target: GuestTarget, operation: LegOperation, upid: str, *, dispatched_at: float
    ) -> _TaskState:
        if operation not in _POST_BODIES or not math.isfinite(dispatched_at):
            raise _denied()
        fields = self._upid_fields(
            target,
            operation,
            upid,
            math.floor(dispatched_at),
            math.floor(dispatched_at + DISPATCH_TASK_WINDOW_S),
        )
        if fields is None:
            raise _denied()
        data = self._request(f"/api2/json/nodes/{target.node}/tasks/{quote(upid, safe='')}/status")
        if not _matches_task(data, fields):
            raise _unavailable()
        if data.get("status") == "running" and "exitstatus" not in data:
            return "running"
        if (
            data.get("status") == "stopped"
            and isinstance(data.get("exitstatus"), str)
            and data["exitstatus"]
        ):
            return "succeeded" if data["exitstatus"] == "OK" else "failed"
        raise _unavailable()

    def recent_tasks(
        self, target: GuestTarget, operation: LegOperation, *, since: int, until: int | None = None
    ) -> tuple[str, ...]:
        if (
            operation not in _POST_BODIES
            or type(since) is not int
            or since < 0
            or (until is not None and (type(until) is not int or until < since))
        ):
            raise _denied()
        # Without Sys.Audit, PVE lists only owned tasks. Its userfilter can
        # miss archived token tasks because they split the actor into fields.
        path = (
            f"/api2/json/nodes/{target.node}/tasks?vmid={target.vmid}"
            f"&typefilter={_worker_type(target, operation)}"
            f"&source=all&limit={_TASK_LIST_LIMIT}&since={since}"
        )
        if until is not None:
            path += f"&until={until}"
        data = self._request(path)
        if not isinstance(data, list) or len(data) >= _TASK_LIST_LIMIT:
            raise _unavailable()
        upids: dict[str, None] = {}
        for row in data:
            if not isinstance(row, dict) or not isinstance(upid := row.get("upid"), str):
                raise _unavailable()
            fields = self._upid_fields(target, operation, upid, since, until)
            if fields is None or upid in upids:
                raise _unavailable()
            if row.get("user") == self.actor and "tokenid" not in row:
                # Active rows can keep the full actor while archived rows split it.
                fields["user"] = self.actor
                del fields["tokenid"]
            if not _matches_task(row, fields):
                raise _unavailable()
            upids[upid] = None
        return tuple(upids)
