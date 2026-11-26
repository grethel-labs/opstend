"""Reject firewall transitions that would unguard a running candidate workload."""

import json
import re
import stat
import subprocess
import sys
from pathlib import Path

MANIFEST = Path("/var/lib/steward/application-units.json")


def load_previous():
    try:
        info = MANIFEST.lstat()
    except FileNotFoundError:
        return []
    if (
        not stat.S_ISREG(info.st_mode)
        or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (0, 0, 0o600)
        or info.st_nlink != 1
    ):
        raise ValueError("invalid application unit manifest")
    return json.loads(MANIFEST.read_text())


def manager_state(uid):
    return subprocess.check_output(
        ["systemctl", "show", "--property=ActiveState", "--value", f"user@{uid}.service"],
        text=True,
        timeout=15,
    ).strip()


def unit_state(entry):
    uid, user, unit = entry["uid"], entry["user"], entry["unit"]
    manager = manager_state(uid)
    if manager in {"inactive", "failed"}:
        return manager
    if manager != "active":
        raise ValueError(f"application user manager {user} is transitioning")
    return subprocess.check_output(
        [
            "runuser",
            "-u",
            user,
            "--",
            "env",
            f"XDG_RUNTIME_DIR=/run/user/{uid}",
            "systemctl",
            "--user",
            "show",
            "--property=ActiveState",
            "--value",
            unit,
        ],
        text=True,
        timeout=15,
    ).strip()


def listener_uids():
    sockets = {}
    for filename in ("/proc/net/tcp", "/proc/net/tcp6"):
        path = Path(filename)
        if not path.exists() and filename.endswith("tcp6"):
            continue
        for row in path.read_text().splitlines()[1:]:
            fields = row.split()
            if fields[3] != "0A":  # TCP_LISTEN
                continue
            port = int(fields[1].rsplit(":", 1)[1], 16)
            sockets.setdefault(port, set()).add(int(fields[7]))
    return sockets


def process_uids():
    owners = set()
    for path in Path("/proc").iterdir():
        if not path.name.isdecimal():
            continue
        try:
            fields = next(
                line.split()[1:]
                for line in (path / "status").read_bytes().splitlines()
                if line.startswith(b"Uid:")
            )
        except FileNotFoundError:
            continue
        owners.update(int(uid) for uid in fields)
    return owners


def dropped_managers(previous, desired, *, guarded=False):
    desired_ids = {entry["user"]: entry["identity"] for entry in desired}
    desired_uids = {identity["uid"] for identity in desired_ids.values()}
    dropped = {}
    for entry in previous:
        user, uid = entry["user"], entry["uid"]
        if user in desired_ids and desired_ids[user] != entry["identity"]:
            raise ValueError(f"UID, GID or subordinate ranges changed for {user}")
        if uid not in desired_uids:
            first = dropped.setdefault(uid, entry)
            if guarded and (user != first["user"] or entry["identity"] != first["identity"]):
                raise ValueError("conflicting identities for a dropped application UID")
    return dropped


def guarded_manager_quiescent(entry, ports):
    from steward.application_boot import BootError, identity_format, inspect_identity
    from steward.executor.host import Host

    try:
        user, identity = entry["user"], entry["identity"]
        if (
            not isinstance(user, str)
            or not re.fullmatch(r"stw-[as][0-9a-f]{20}", user)
            or not identity_format(identity)
            or entry["uid"] != identity["uid"]
            or any(type(port) is not int or not 1 <= port <= 65535 for port in ports)
        ):
            return False
        pinned = inspect_identity(user)
        uid, subuid = identity["uid"], identity["subuid"]
        host = Host()
        if pinned != identity or not host.application_manager_quiescent(uid, subuid):
            return False
        start, width = subuid
        return not any(
            state == "0A" and (port in ports or owner == uid or start <= owner < start + width)
            for _, port, owner, state in host._tcp_sockets()
        )
    except (BootError, KeyError, OSError, ValueError, subprocess.SubprocessError):
        return False


def verify_transition(previous, desired, listeners, state, manager, owners, *, guarded=False):
    dropped = dropped_managers(previous, desired, guarded=guarded)
    retired_ports = {}
    if guarded:
        for entry in previous:
            if entry["uid"] in dropped and entry["port"] is not None:
                retired_ports.setdefault(entry["uid"], set()).add(entry["port"])
    for uid, entry in dropped.items():
        user = entry["user"]
        if guarded:
            if not guarded_manager_quiescent(entry, retired_ports.get(uid, set())):
                raise ValueError(
                    f"cannot prove the user manager and all UID and subordinate UID tasks for "
                    f"{user} are stopped and its retired ports and identities have no TCP "
                    "listeners. Stop the user manager and all remaining workloads separately "
                    "before removing this application identity"
                )
        elif manager(uid) != "inactive" or uid in owners:
            raise ValueError(f"stop the user manager and all processes for {user} first")

    for entry in previous:
        if entry in desired:
            continue
        port = entry["port"]
        owners_at_port = listeners.get(port, set())
        if state(entry) not in {"inactive", "failed"} or entry["uid"] in owners_at_port:
            raise ValueError(f"stop {entry['unit']} before removing its firewall binding")

    for entry in desired:
        port = entry["port"]
        existing = listeners.get(port, set())
        if existing and (entry not in previous or existing != {entry["uid"]}):
            raise ValueError(f"application TCP port {port} already has an unexpected listener")


def main():
    try:
        previous = load_previous()
        configuration = json.load(sys.stdin)
        ids = configuration["ids"]
        desired = []
        for app in configuration["applications"]:
            members = [(service, service["host_port"]) for service in app["services"]]
            if app["pod"]:
                members.append((app["pod"], None))
            for unit, port in members:
                user = unit["user"]
                desired.append(
                    {
                        "user": user,
                        "uid": ids[user]["uid"],
                        "identity": {
                            key: ids[user][key] for key in ("uid", "gid", "subuid", "subgid")
                        },
                        "unit": unit["unit"],
                        "port": port,
                    }
                )
        mode = sys.argv[1:]
        if mode not in ([], ["--guarded-retirement"]):
            raise ValueError("invalid application transition inspection mode")
        guarded = mode == ["--guarded-retirement"]
        verify_transition(
            previous,
            desired,
            listener_uids(),
            unit_state,
            manager_state,
            () if guarded else process_uids(),
            guarded=guarded,
        )
        print(json.dumps(desired, sort_keys=True))
    except (KeyError, OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(str(error))


if __name__ == "__main__":
    main()
