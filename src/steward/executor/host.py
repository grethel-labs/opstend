"""Host access used by executor actions.

Every command is a fixed argv built from the root-owned registry. There is no
shell, no caller-supplied path and no caller-supplied argument.
"""

from __future__ import annotations

import http.client
import json
import os
import pwd
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

from ..core.images import image_id
from .containment_host import ContainmentHostMixin
from .image_host import ImageHostMixin

CMD_TIMEOUT_S = 30
KILLSWITCH_PATH = "/etc/steward/killswitch"
SECRETS_DIR = "/etc/steward/secrets"
PROC_ROOT = Path("/proc")
APPLICATION_PROXY_USER = "steward-proxy"
APPLICATION_PROXY_UNIT = "proxy.service"
MAX_PROCESS_ENTRIES = 65536
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
JOURNAL_PRIORITY = "warning"  # warnings and worse; info lines stay in the journal
PODMAN_ID = re.compile(r"[0-9a-f]{64}")
POD_INSPECT = (
    '{"id":{{json .ID}},"name":{{json .Name}},"infra":{{json .InfraContainerID}},'
    '"unit":{{json (index .Labels "PODMAN_SYSTEMD_UNIT")}},'
    '"members":{{json .Containers}}}'
)
INFRA_INSPECT = (
    '{"id":{{json .ID}},"name":{{json .Name}},"pod":{{json .Pod}},"infra":{{json .IsInfra}},'
    '"state":{{json .State}},"unit":{{json (index .Config.Labels "PODMAN_SYSTEMD_UNIT")}},'
    '"userns":{{json .HostConfig.UsernsMode}}}'
)


def read_process_metadata(path: Path) -> str:
    with path.open(encoding="ascii") as handle:
        text = handle.read(16385)
    if len(text) > 16384:
        raise ValueError("process metadata exceeds the size limit")
    return text


def process_namespace(path: Path) -> tuple[int, int, int]:
    raw = read_process_metadata(path / "stat")
    end = raw.rfind(")")
    fields = raw[end + 1 :].split() if end >= 0 else []
    if (
        raw.partition(" (")[0] != path.name
        or len(fields) < 20
        or re.fullmatch(r"[0-9]{1,20}", fields[19]) is None
    ):
        raise ValueError("invalid application infrastructure process identity")
    namespace = (path / "ns" / "user").stat()
    return int(fields[19]), namespace.st_dev, namespace.st_ino


def process_uids(path: Path) -> tuple[int, ...]:
    with path.open("r", encoding="utf-8") as handle:
        value = handle.read(16385)
    rows = [line.split()[1:] for line in value.splitlines() if line.startswith("Uid:")]
    if (
        len(value) > 16384
        or len(rows) != 1
        or len(rows[0]) != 4
        or any(not item.isascii() or not item.isdecimal() for item in rows[0])
    ):
        raise ValueError("invalid process uid metadata")
    return tuple(int(item) for item in rows[0])


class Host(ImageHostMixin, ContainmentHostMixin):
    """Real host. Tests substitute a fake with the same methods."""

    def backup_group(self) -> int:
        return pwd.getpwnam("steward-backup").pw_gid

    def _run(self, argv: list[str], timeout: int = CMD_TIMEOUT_S) -> tuple[int, str]:
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=SAFE_ENV,
                cwd="/",
                check=False,
            )
        except subprocess.TimeoutExpired:
            return 124, "timeout"
        except OSError as exc:
            return 127, str(exc)
        return proc.returncode, proc.stdout if proc.returncode == 0 else proc.stderr

    def _as_user(self, user: str, argv: list[str], timeout: int = CMD_TIMEOUT_S) -> tuple[int, str]:
        try:
            entry = pwd.getpwnam(user)
        except KeyError:
            return 1, f"user {user} does not exist"
        return self._run(
            [
                "setpriv",
                f"--reuid={entry.pw_uid}",
                f"--regid={entry.pw_gid}",
                "--init-groups",
                "env",
                "-i",
                f"XDG_RUNTIME_DIR=/run/user/{entry.pw_uid}",
                f"HOME={entry.pw_dir}",
                f"PATH={SAFE_ENV['PATH']}",
                *argv,
            ],
            timeout,
        )

    @staticmethod
    def _parse_show(text: str) -> dict[str, str]:
        return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)

    def system_unit(self, unit: str) -> dict[str, Any]:
        rc, out = self._run(["systemctl", "show", unit, "-p", "LoadState,ActiveState,SubState"])
        props = self._parse_show(out) if rc == 0 else {}
        return {
            "unit": unit,
            "load": props.get("LoadState", "unknown"),
            "active": props.get("ActiveState", "unknown"),
            "sub": props.get("SubState", "unknown"),
        }

    def backup_worker_stopped(self) -> bool:
        """Fail closed unless the fixed service is loaded, stopped and cgroup-free."""
        rc, out = self._run(
            [
                "systemctl",
                "show",
                "steward-backup.service",
                "-p",
                "LoadState,ActiveState,SubState,MainPID,ControlGroup,KillMode",
            ]
        )
        if rc:
            return False
        props = self._parse_show(out)
        return (
            props.get("LoadState") == "loaded"
            and (props.get("ActiveState"), props.get("SubState"))
            in (("inactive", "dead"), ("failed", "failed"))
            and props.get("MainPID") == "0"
            and props.get("ControlGroup") == ""
            and props.get("KillMode") == "control-group"
        )

    def deployment_rollbacks_quiescent(self) -> bool:
        """Refuse deployment admission while built-in rollback jobs may still run.

        These timers are independent systemd units, outside the deploying
        process's cgroup. Check their services as well as their timers: a timer
        can already have fired while its service is still changing the host.
        Missing or malformed systemd results are never treated as quiescence.
        """
        for prefix in ("steward-ssh-rollback", "steward-firewall-rollback"):
            for kind in ("timer", "service"):
                rc, out = self._run(
                    [
                        "systemctl",
                        "show",
                        f"{prefix}.{kind}",
                        "-p",
                        "LoadState,ActiveState,SubState,MainPID,ControlGroup,Job",
                    ]
                )
                if rc:
                    return False
                props = self._parse_show(out)
                if props.get("LoadState") not in ("loaded", "not-found") or (
                    props.get("ActiveState"),
                    props.get("SubState"),
                ) not in (("inactive", "dead"), ("failed", "failed")):
                    return False
                if props.get("Job") != "":
                    return False
                if props.get("LoadState") == "not-found" and (
                    props.get("ActiveState"),
                    props.get("SubState"),
                ) != ("inactive", "dead"):
                    return False
                if kind == "service" and (
                    props.get("MainPID") != "0" or props.get("ControlGroup") != ""
                ):
                    return False
        return True

    def user_unit(self, user: str, unit: str) -> dict[str, Any]:
        rc, out = self._as_user(
            user,
            ["systemctl", "--user", "show", unit, "-p", "LoadState,ActiveState,SubState,NRestarts"],
        )
        props = self._parse_show(out) if rc == 0 else {}
        return {
            "unit": unit,
            "load": props.get("LoadState", "unknown"),
            "active": props.get("ActiveState", "unknown"),
            "sub": props.get("SubState", "unknown"),
            "restarts": int(props.get("NRestarts", "0") or 0),
        }

    def start_application_manager(self, uid: int) -> bool:
        if type(uid) is not int or not 30000 <= uid <= 39999:
            return False
        rc, _ = self._run(["systemctl", "start", f"user@{uid}.service"])
        return rc == 0

    def stop_application_manager(self, uid: int) -> bool:
        """Stop one dedicated manager (retirement); callers verify quiescence afterwards."""
        if type(uid) is not int or not 30000 <= uid <= 39999:
            return False
        rc, _ = self._run(["systemctl", "stop", f"user@{uid}.service"])
        return rc == 0

    def remove_user_image(self, user: str, tag: str) -> bool:
        """Remove one registered local image tag. Absence is success, uncertainty is not."""
        if (
            re.fullmatch(r"stw-s[0-9a-f]{20}", user) is None
            or re.fullmatch(r"localhost/steward/s[0-9a-f]{20}:sha256-[a-f0-9]{32}", tag) is None
        ):
            return False
        try:
            pwd.getpwnam(user)
        except KeyError:
            return False
        rc, _ = self._as_user(user, ["podman", "image", "exists", tag])
        if rc == 1:
            return True
        if rc != 0:
            return False
        rc, _ = self._as_user(user, ["podman", "image", "rm", tag])
        rc_after, _ = self._as_user(user, ["podman", "image", "exists", tag])
        return rc == 0 and rc_after == 1

    def application_manager_quiescent(self, uid: int, subuid: list[int]) -> bool:
        """Recognize an explicitly stopped dedicated manager with no surviving account tasks."""
        if (
            type(uid) is not int
            or not 30000 <= uid <= 39999
            or not isinstance(subuid, list)
            or len(subuid) != 2
            or any(type(item) is not int for item in subuid)
            or subuid[1] != 65536
            or not 1 <= subuid[0] <= 2**32 - 1 - 65536
        ):
            return False
        argv = [
            "systemctl",
            "show",
            f"user@{uid}.service",
            "-p",
            "LoadState,ActiveState,SubState,MainPID,ControlPID,ControlGroup,Job",
        ]
        expected = {
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "SubState": "dead",
            "MainPID": "0",
            "ControlPID": "0",
            "ControlGroup": "",
            "Job": "",
        }
        rc, out = self._run(argv)
        if rc or self._parse_show(out) != expected:
            return False
        start, width = subuid
        count = 0
        try:
            with os.scandir(PROC_ROOT) as processes:
                for process in processes:
                    if not process.name.isascii() or not process.name.isdecimal():
                        continue
                    count += 1
                    if count > MAX_PROCESS_ENTRIES:
                        return False
                    try:
                        with os.scandir(Path(process.path) / "task") as tasks:
                            for task in tasks:
                                if not task.name.isascii() or not task.name.isdecimal():
                                    continue
                                count += 1
                                if count > MAX_PROCESS_ENTRIES:
                                    return False
                                try:
                                    ids = process_uids(Path(task.path) / "status")
                                except FileNotFoundError:
                                    continue
                                if any(
                                    number == uid or start <= number < start + width
                                    for number in ids
                                ):
                                    return False
                    except FileNotFoundError:
                        continue
        except (OSError, ValueError):
            return False
        rc, out = self._run(argv)
        return rc == 0 and self._parse_show(out) == expected

    def application_unit_authority(self, user: str, unit: str, source: Path) -> bool:
        rc, out = self._as_user(
            user,
            [
                "systemctl",
                "--user",
                "show",
                "--all",
                "-p",
                "LoadState,UnitFileState,SourcePath,DropInPaths",
                unit,
            ],
        )
        return rc == 0 and self._parse_show(out) == {
            "LoadState": "loaded",
            "UnitFileState": "generated",
            "SourcePath": str(source),
            "DropInPaths": "",
        }

    def application_unit_transitioning(self, user: str, unit: str) -> bool | None:
        rc, out = self._as_user(
            user, ["systemctl", "--user", "show", "--all", "-p", "LoadState,ActiveState,Job", unit]
        )
        props = self._parse_show(out)
        if (
            rc
            or set(props) != {"LoadState", "ActiveState", "Job"}
            or props["LoadState"] != "loaded"
        ):
            return None
        if props["Job"] or props["ActiveState"] in {"activating", "deactivating"}:
            return True
        if props["ActiveState"] in {"inactive", "failed", "active"}:
            return False
        return None

    def application_pod_members(
        self, user: str, pod: str, *, require_running: bool = True
    ) -> list[str] | None:
        """Observe non-infrastructure members without mutating the pod."""
        rc, text = self._as_user(user, ["podman", "pod", "inspect", pod])
        if rc:
            return None
        try:
            records = json.loads(text)
            if not isinstance(records, list) or len(records) != 1:
                return None
            record = records[0]
            if record["Name"] != pod:
                return None
            infra = record["InfraContainerID"]
            containers = record["Containers"]
            members = [item["Id"] for item in containers]
            if (
                not isinstance(infra, str)
                or infra not in members
                or len(set(members)) != len(members)
                or any(re.fullmatch(r"[a-f0-9]{64}", item) is None for item in members)
                or (
                    require_running
                    and next(item["State"] for item in containers if item["Id"] == infra)
                    != "running"
                )
            ):
                return None
            return [member for member in members if member != infra]
        except (AttributeError, KeyError, TypeError, ValueError):
            return None

    def application_pod_absent(self, user: str, pod: str) -> bool:
        rc, _ = self._as_user(user, ["podman", "pod", "exists", pod])
        return rc == 1

    def application_infra_maps(self, user: str, unit: str, uid: int) -> tuple[str, str]:
        """Read stable kernel maps for the identified running shared infrastructure."""
        if (
            not re.fullmatch(r"a[0-9a-f]{20}-pod\.service", unit)
            or user != "stw-" + unit.removesuffix("-pod.service")
            or type(uid) is not int
            or not 30000 <= uid <= 39999
        ):
            raise ValueError("invalid application infrastructure binding")
        pod_name = "steward-" + unit.removesuffix("-pod.service")
        infra_name = pod_name + "-infra"

        def inspect(kind: str, template: str, identifier: str) -> dict[str, Any]:
            rc, raw = self._as_user(
                user, ["podman", kind, "inspect", "--format", template, identifier]
            )
            if rc or len(raw) > 65536:
                raise ValueError("application infrastructure inspection failed")
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise ValueError("invalid application infrastructure inspection")
            return result

        def observe() -> tuple[str, str, int, str, str]:
            pod = inspect("pod", POD_INSPECT, pod_name)
            pod_id, infra_id = pod.get("id"), pod.get("infra")
            if (
                not isinstance(pod_id, str)
                or not PODMAN_ID.fullmatch(pod_id)
                or not isinstance(infra_id, str)
                or not PODMAN_ID.fullmatch(infra_id)
                or infra_id == pod_id
                or pod.get("name") != pod_name
                or pod.get("unit") != unit
                or not isinstance(pod.get("members"), list)
            ):
                raise ValueError("unexpected shared application pod")
            members = [
                item
                for item in pod["members"]
                if isinstance(item, dict)
                and (item.get("Id") == infra_id or item.get("Name") == infra_name)
            ]
            if members != [{"Id": infra_id, "Name": infra_name, "State": "running"}]:
                raise ValueError("application infrastructure pod member is unavailable")
            infra = inspect("container", INFRA_INSPECT, infra_id)
            if (
                infra.get("id") != infra_id
                or infra.get("name") != infra_name
                or infra.get("pod") != pod_id
                or infra.get("infra") is not True
                or infra.get("unit") != unit
                or infra.get("userns") != "private"
                or not isinstance(infra.get("state"), dict)
            ):
                raise ValueError("unexpected application infrastructure container")
            state = infra["state"]
            pid, started, cgroup = (state.get(key) for key in ("Pid", "StartedAt", "CgroupPath"))
            user_slice = f"/user.slice/user-{uid}.slice/user@{uid}.service/"
            if (
                type(pid) is not int
                or not 0 < pid < 2**31
                or state.get("Status") != "running"
                or state.get("Running") is not True
                or any(state.get(key) is not False for key in ("Paused", "Restarting", "Dead"))
                or not isinstance(started, str)
                or not started
                or not isinstance(cgroup, str)
                or not cgroup.startswith(user_slice)
                or not cgroup.endswith(f"/user-libpod_pod_{pod_id}.slice/libpod-{infra_id}.scope")
            ):
                raise ValueError("application infrastructure process is unavailable")
            return pod_id, infra_id, pid, started, cgroup

        observed = observe()
        path = PROC_ROOT / str(observed[2])
        cgroup = "0::" + observed[4]
        namespace = process_namespace(path)
        process_cgroup = read_process_metadata(path / "cgroup").splitlines()
        if process_cgroup not in ([cgroup], [cgroup + "/container"]):
            raise ValueError("unexpected application infrastructure process cgroup")
        maps = tuple(read_process_metadata(path / key) for key in ("uid_map", "gid_map"))
        if (
            observe() != observed
            or process_namespace(path) != namespace
            or read_process_metadata(path / "cgroup").splitlines() != process_cgroup
        ):
            raise ValueError("application infrastructure process changed during inspection")
        return maps[0], maps[1]

    def group_service_running(self, user: str, unit: str, container: str) -> bool | None:
        """Observe one registered unit and container; uncertainty is not stopped.

        This is an observation, not authorization or proof of data quiescence.
        The caller must derive all identities from its root-owned registry and
        hold the corresponding locks while it uses the result.
        """
        if (
            not re.fullmatch(r"[a-z][a-z0-9-]{1,30}[a-z0-9]", container)
            or unit != container + ".service"
            or not re.fullmatch(r"stw-[a-z0-9-]{2,27}", user)
        ):
            return None
        return self._unit_container_running(user, unit, container)

    def _unit_container_running(self, user: str, unit: str, container: str) -> bool | None:
        rc, text = self._as_user(
            user, ["systemctl", "--user", "show", unit, "-p", "LoadState,ActiveState,SubState"]
        )
        if rc:
            return None
        props = self._parse_show(text)
        if props.get("LoadState") != "loaded":
            return None
        rc, text = self._as_user(
            user, ["podman", "ps", "--all", "--filter", f"name=^{container}$", "--format", "json"]
        )
        if rc:
            return None
        try:
            entries = json.loads(text)
            if not isinstance(entries, list) or len(entries) > 1:
                return None
            entry = entries[0] if entries else None
            if entry is not None and (
                not isinstance(entry, dict)
                or entry.get("Names") != [container]
                or not isinstance(entry.get("Labels"), dict)
                or entry["Labels"].get("PODMAN_SYSTEMD_UNIT") != unit
            ):
                return None
            active = (props.get("ActiveState"), props.get("SubState"))
            if active == ("active", "running"):
                if (
                    entry is not None
                    and entry.get("State") == "running"
                    and type(entry.get("Pid")) is int
                    and entry["Pid"] > 0
                ):
                    return True
                return None
            if active in (("inactive", "dead"), ("failed", "failed")) and (
                entry is None
                or (
                    entry.get("State") in ("exited", "stopped", "created", "configured")
                    and type(entry.get("Pid")) is int
                    and entry["Pid"] == 0
                )
            ):
                return False
        except (ValueError, TypeError):
            pass
        return None

    def application_listener_owned(self, port: int, uid: int) -> bool:
        listening = [
            (address, owner)
            for address, local_port, owner, state in self._tcp_sockets()
            if state == "0A" and local_port == port
        ]
        return listening == [("0100007F", uid)]

    @staticmethod
    def _tcp_sockets() -> list[tuple[str, int, int, str]]:
        sockets = []
        for table, width in (("tcp", 8), ("tcp6", 32)):
            with (PROC_ROOT / "net" / table).open(encoding="ascii") as handle:
                if not handle.readline().strip().startswith("sl "):
                    raise ValueError("invalid TCP socket table")
                for index, row in enumerate(handle):
                    if index >= MAX_PROCESS_ENTRIES:
                        raise ValueError("too many TCP sockets to verify")
                    fields = row.split()
                    if len(fields) < 10:
                        raise ValueError("invalid TCP socket evidence")
                    address, separator, port = fields[1].partition(":")
                    if (
                        not separator
                        or len(address) != width
                        or re.fullmatch(r"[0-9A-F]+", address) is None
                        or re.fullmatch(r"[0-9A-F]{4}", port) is None
                        or re.fullmatch(r"[0-9A-F]{2}", fields[3]) is None
                        or not fields[7].isdecimal()
                    ):
                        raise ValueError("invalid TCP socket evidence")
                    sockets.append((address, int(port, 16), int(fields[7]), fields[3]))
        return sockets

    def application_proxy_running(self) -> bool | None:
        return self._unit_container_running(APPLICATION_PROXY_USER, APPLICATION_PROXY_UNIT, "proxy")

    def application_proxy_evicted(self, uid: int) -> bool:
        rc, output = self._as_user(
            APPLICATION_PROXY_USER,
            [
                "systemctl",
                "--user",
                "show",
                "--all",
                "-p",
                "LoadState,ActiveState,SubState,MainPID,ControlPID,ControlGroup,Job",
                APPLICATION_PROXY_UNIT,
            ],
        )
        state = self._parse_show(output)
        if (
            rc
            or (state.pop("ActiveState", None), state.pop("SubState", None))
            not in (("inactive", "dead"), ("failed", "failed"))
            or state
            != {
                "LoadState": "loaded",
                "MainPID": "0",
                "ControlPID": "0",
                "ControlGroup": "",
                "Job": "",
            }
        ):
            return False
        rc, output = self._as_user(
            APPLICATION_PROXY_USER,
            ["podman", "ps", "--all", "--filter", "name=^proxy$", "--format", "json"],
        )
        return (
            rc == 0
            and json.loads(output) == []
            and not any(
                owner == uid and state not in {"06", "07"}
                for _, _, owner, state in self._tcp_sockets()
            )
        )

    def service_user_uid(self, user: str) -> int | None:
        if not isinstance(user, str) or re.fullmatch(r"stw-[a-z0-9-]{2,27}", user) is None:
            return None
        try:
            uid = pwd.getpwnam(user).pw_uid
            return uid if type(uid) is int and 1000 <= uid < 2**32 - 1 else None
        except KeyError:
            return None

    def group_users_within_systemd_slices(self, users: list[str]) -> bool:
        """Observe whether current service-UID tasks remain in their user slices.

        This bounded snapshot is not a freeze and cannot rule out new tasks,
        subordinate UIDs, ACL writers or privileged processes. False includes
        unknown/inaccessible process state. It never grants consistency evidence.
        """
        if (
            not isinstance(users, list)
            or not 1 <= len(users) <= 64
            or any(
                not isinstance(user, str) or re.fullmatch(r"stw-[a-z0-9-]{2,27}", user) is None
                for user in users
            )
        ):
            return False
        try:
            names = sorted(set(users))
            identities = {user: pwd.getpwnam(user).pw_uid for user in names}
            if any(
                type(uid) is not int or not 1000 <= uid < 2**32 - 1 for uid in identities.values()
            ) or len(set(identities.values())) != len(identities):
                return False
            expected = {uid: f"/user.slice/user-{uid}.slice" for uid in identities.values()}
            seen = set()
            count = 0

            def read_limited(path: Path) -> str:
                with path.open("r", encoding="utf-8") as handle:
                    value = handle.read(16385)
                if len(value) > 16384:
                    raise ValueError("process metadata exceeds bound")
                return value

            def process_start(path: Path) -> int:
                raw = read_limited(path)
                end = raw.rfind(")")
                fields = raw[end + 1 :].split() if end >= 0 else []
                if len(fields) < 20 or not fields[19].isascii() or not fields[19].isdecimal():
                    raise ValueError("invalid process identity")
                return int(fields[19])

            def within_slice(path: Path, uid: int) -> bool:
                rows = read_limited(path).splitlines()
                if len(rows) != 1 or not rows[0].startswith("0::/"):
                    return False
                value = rows[0][3:]
                prefix = expected[uid]
                return value == prefix or value.startswith(prefix + "/")

            with os.scandir(PROC_ROOT) as processes:
                for process in processes:
                    if not process.name.isascii() or not process.name.isdecimal():
                        continue
                    count += 1
                    if count > MAX_PROCESS_ENTRIES:
                        return False
                    path = PROC_ROOT / process.name
                    try:
                        ids = process_uids(path / "status")
                    except FileNotFoundError:
                        continue
                    matching = set(ids) & expected.keys()
                    if not matching:
                        continue
                    if len(matching) != 1:
                        return False
                    uid = next(iter(matching))
                    try:
                        started = process_start(path / "stat")
                        verified_tasks = 0
                        with os.scandir(path / "task") as tasks:
                            for task in tasks:
                                if not task.name.isascii() or not task.name.isdecimal():
                                    continue
                                count += 1
                                if count > MAX_PROCESS_ENTRIES:
                                    return False
                                task_path = path / "task" / task.name
                                try:
                                    task_start = process_start(task_path / "stat")
                                    task_ids = process_uids(task_path / "status")
                                    if uid not in task_ids or not within_slice(
                                        task_path / "cgroup", uid
                                    ):
                                        return False
                                    if (
                                        process_uids(task_path / "status") != task_ids
                                        or process_start(task_path / "stat") != task_start
                                    ):
                                        return False
                                    verified_tasks += 1
                                except FileNotFoundError:
                                    continue
                        if (
                            not verified_tasks
                            or process_uids(path / "status") != ids
                            or process_start(path / "stat") != started
                        ):
                            return False
                        seen.add(uid)
                    except FileNotFoundError:
                        continue
            return seen == set(expected)
        except (KeyError, OSError, ValueError, UnicodeError):
            return False

    def group_service_quiescent(self, user: str, unit: str, container: str) -> bool:
        """Confirm this unit has no active process group or running container.

        This does not prove that unrelated processes cannot write the data.
        Backup admission needs its own broader writer and isolation checks.
        """
        if self.group_service_running(user, unit, container) is not False:
            return False
        rc, text = self._as_user(
            user,
            [
                "systemctl",
                "--user",
                "show",
                unit,
                "-p",
                "LoadState,ActiveState,SubState,MainPID,ControlPID,ControlGroup",
            ],
        )
        if rc:
            return False
        props = self._parse_show(text)
        return (
            props.get("LoadState") == "loaded"
            and (props.get("ActiveState"), props.get("SubState"))
            in (("inactive", "dead"), ("failed", "failed"))
            and props.get("MainPID") == "0"
            and props.get("ControlPID") == "0"
            and props.get("ControlGroup") == ""
        )

    def restart_user_unit(self, user: str, unit: str) -> tuple[bool, str]:
        rc, out = self._as_user(user, ["systemctl", "--user", "restart", unit])
        return rc == 0, out.strip()[:500]

    def set_user_unit(self, user: str, unit: str, *, running: bool) -> bool:
        action = "start" if running else "stop"
        rc, _ = self._as_user(user, ["systemctl", "--user", action, unit])
        return rc == 0

    def workload_quiescent(self, user: str, unit: str) -> bool:
        state = self.user_unit(user, unit)
        if state["load"] != "loaded" or state["active"] not in ("inactive", "failed"):
            return False
        rc, text = self._as_user(user, ["podman", "ps", "--all", "--format", "json"])
        if rc != 0:
            return False
        try:
            containers = json.loads(text)
            return isinstance(containers, list) and all(
                isinstance(c, dict)
                and c.get("State") in ("exited", "stopped", "created", "configured")
                for c in containers
            )
        except (ValueError, TypeError):
            return False

    def configured_image_identity(self, image: str) -> dict[str, str] | None:
        expected = image.rsplit("@", 1)[-1]
        rc, out = self._run(
            [
                "podman",
                "image",
                "inspect",
                "--format",
                '{"id":{{json .ID}},"digest":{{json .Digest}}}',
                image,
            ]
        )
        if rc != 0:
            return None
        try:
            info = json.loads(out)
            identity = image_id(info.get("id"))
            if identity and info.get("digest") == expected:
                return {"id": identity, "manifest_digest": expected}
        except (ValueError, TypeError, AttributeError):
            pass
        return None

    def container(self, user: str, name: str) -> dict[str, Any] | None:
        rc, out = self._as_user(user, ["podman", "container", "inspect", name])
        if rc != 0:
            return None
        try:
            data = json.loads(out)
            return data[0] if data else None
        except (ValueError, IndexError):
            return None

    def http_health(self, port: int, path: str, timeout: float) -> dict[str, Any]:
        started = time.monotonic()
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        try:
            conn.request("GET", path, headers={"User-Agent": "steward-health"})
            status = conn.getresponse().status
            return {
                "ok": 200 <= status < 300,
                "status": status,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            }
        except (OSError, http.client.HTTPException) as exc:
            return {"ok": False, "error": type(exc).__name__}
        finally:
            conn.close()

    def tcp_health(self, port: int, timeout: float) -> dict[str, Any]:
        """Verified TCP accept on the loopback port; no bytes are exchanged."""
        started = time.monotonic()
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=timeout):
                pass
        except OSError as exc:
            return {"ok": False, "error": type(exc).__name__}
        return {"ok": True, "elapsed_ms": int((time.monotonic() - started) * 1000)}

    def container_health(self, user: str, name: str, timeout: float) -> dict[str, Any]:
        """Run the container's own declared healthcheck; absence is `unknown`."""
        started = time.monotonic()
        rc, _ = self._as_user(user, ["podman", "healthcheck", "run", name], max(1, int(timeout)))
        if rc == 0:
            return {"ok": True, "elapsed_ms": int((time.monotonic() - started) * 1000)}
        if rc == 124:
            return {"ok": False, "state": "timeout", "error": "TimeoutError"}
        if rc == 1:
            return {"ok": False, "state": "unhealthy", "error": "healthcheck failed"}
        return {"ok": False, "state": "unknown", "error": f"healthcheck unavailable (rc {rc})"}

    def firewall_loaded(self) -> bool:
        return self._run(["nft", "list", "table", "inet", "steward"])[0] == 0

    def firewall_reassert(self) -> tuple[bool, str]:
        unit = "steward-firewall.service"
        rc, out = self._run(["systemctl", "show", "--property=ActiveState", "--value", unit])
        if rc != 0:
            return False, out.strip()[:500]
        # ExecStop deletes the table. Reload active units, even if the table is missing.
        verb = "reload" if out.strip() in {"active", "reloading"} else "start"
        rc, out = self._run(["systemctl", verb, unit])
        return rc == 0, out.strip()[:500]

    def failed_units(self) -> list[str]:
        rc, out = self._run(["systemctl", "list-units", "--failed", "--no-legend", "--plain"])
        if rc != 0:
            return []
        return [line.split()[0] for line in out.splitlines() if line.strip()]

    def resources(self) -> dict[str, Any]:
        meminfo = {}
        with open("/proc/meminfo", encoding="ascii") as handle:
            for line in handle:
                key, _, rest = line.partition(":")
                meminfo[key] = int(rest.split()[0]) // 1024
        disk = shutil.disk_usage("/")
        return {
            "memory_total_mb": meminfo.get("MemTotal"),
            "memory_available_mb": meminfo.get("MemAvailable"),
            "disk_total_mb": disk.total // 2**20,
            "disk_free_mb": disk.free // 2**20,
        }

    def load_average(self) -> dict[str, Any]:
        """Read-only load measurement for the registered maintenance resource check."""
        one, five, fifteen = os.getloadavg()
        return {"load1": one, "load5": five, "load15": fifteen, "cpus": os.cpu_count()}

    def reboot_required(self) -> bool:
        return os.path.exists("/run/reboot-required")

    def inventory(self) -> dict[str, Any]:
        """Installed binary/source versions; never inspect package scripts or secrets."""
        fields = (
            "${Package}\t${Version}\t${Architecture}\t"
            "${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n"
        )
        rc, text = self._run(["dpkg-query", "--show", f"--showformat={fields}"])
        if rc:
            raise RuntimeError("package inventory unavailable")
        packages = []
        for line in text.splitlines():
            parts = line.split("\t")
            if len(parts) != 6:
                raise RuntimeError("invalid package inventory")
            name, version, arch, source, source_version, status = parts
            if len(status) < 2 or status[1] != "i":
                continue
            packages.append(
                {
                    "name": name,
                    "version": version,
                    "architecture": arch,
                    "source_name": source or name,
                    "source_version": source_version or version,
                }
            )
        if len(packages) > 50000:
            raise RuntimeError("package inventory limit exceeded")
        release = {}
        with open("/etc/os-release", encoding="utf-8") as handle:
            for line in handle:
                key, _, value = line.strip().partition("=")
                if key in ("ID", "VERSION_ID"):
                    release[key] = value.strip('"')
        return {
            "os_id": release.get("ID"),
            "os_version": release.get("VERSION_ID"),
            "running_kernel": os.uname().release,
            "kernel_build": os.uname().version,
            "reboot_required": self.reboot_required(),
            "packages": sorted(packages, key=lambda p: (p["name"], p["architecture"])),
        }

    def kill_switch(self) -> bool:
        return os.path.lexists(KILLSWITCH_PATH)

    def journal(
        self, matches: list[str], cursor: str | None, limit: int, skip_to_end: bool
    ) -> tuple[list[dict[str, Any]], str | None, bool]:
        """Up to `limit` journal entries after `cursor` that match one of `matches`.

        Returns (entries, cursor to continue from, more entries pending). Without
        a cursor, reading starts one hour back. `skip_to_end` drops a backlog and
        returns only a cursor at the current end.
        """
        if not matches:
            return [], cursor, False
        argv = ["journalctl", "--no-pager", "--output=json", f"--priority={JOURNAL_PRIORITY}"]
        if skip_to_end:
            argv += ["--lines=1", "--show-cursor"]
        elif cursor:
            argv.append(f"--after-cursor={cursor}")
        else:
            argv.append("--since=-1h")
        for index, match in enumerate(matches):
            argv += (["+"] if index else []) + [match]
        entries: list[dict[str, Any]] = []
        more = False
        try:
            proc = subprocess.Popen(
                argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=SAFE_ENV, cwd="/"
            )
        except OSError:
            return [], cursor, False
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                try:
                    entries.append(json.loads(line))
                except ValueError:
                    continue
                if len(entries) > limit:
                    more = True
                    entries.pop()
                    break
        finally:
            proc.kill()
            proc.wait(timeout=CMD_TIMEOUT_S)
        if skip_to_end:
            return [], entries[-1].get("__CURSOR", cursor) if entries else cursor, False
        next_cursor = entries[-1].get("__CURSOR", cursor) if entries else cursor
        return entries, next_cursor, more

    def known_secret_values(self) -> tuple[str, ...]:
        """Values of deployed secrets, so logs can be redacted by exact match."""
        values: list[str] = []
        for root, _dirs, files in os.walk(SECRETS_DIR):
            for name in files:
                try:
                    with open(os.path.join(root, name), encoding="utf-8") as handle:
                        text = handle.read()
                except OSError:
                    continue
                if name.endswith(".env"):
                    values += [line.partition("=")[2] for line in text.splitlines() if "=" in line]
                else:
                    values.append(text.strip())
        return tuple(sorted({v for v in values if len(v) >= 6}, key=len, reverse=True))
