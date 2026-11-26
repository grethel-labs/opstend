"""Prepare protected application directories and verify shared Podman data ownership."""

from __future__ import annotations

import ctypes
import json
import os
import pwd
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

from .core.ids import graph_identifier
from .core.render import SHARED_POD_UID
from .executor.host import Host

DATA_ROOT = Path("/srv/steward")
CONFIG_ROOT = Path("/etc/steward")
QUADLET_ROOT = Path("/etc/containers/systemd/users")
STATE_ROOT = Path("/var/lib/steward")
SLUG = re.compile(r"[a-z][a-z0-9-]{1,30}[a-z0-9]")
MAP_ROW = re.compile(r"[ \t]*([0-9]{1,10})[ \t]+([0-9]{1,10})[ \t]+([0-9]{1,10})[ \t]*")
ID_LIMIT = 2**32 - 1
INPUT_LIMIT = 16 * 1024 * 1024
IDENTITY_KEYS = ("uid", "gid", "subuid", "subgid")
RENAME_NOREPLACE = 1


def require(condition: object, message: str) -> None:
    if not condition:
        raise ValueError(message)


def protected_ancestors(path: Path) -> None:
    for parent in reversed(path.parents):
        info = parent.lstat()
        require(
            stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            f"unsafe application parent: {parent}",
        )


def exact_directory(path: Path, uid: int, gid: int, mode: int, *, create: bool = False) -> bool:
    """Check directory metadata. Only a newly created directory receives ownership."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        if not create:
            raise
        path.mkdir(mode=mode)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fchown(fd, uid, gid)
            info = os.fstat(fd)
        finally:
            os.close(fd)
        changed = True
    else:
        changed = False
    require(
        stat.S_ISDIR(info.st_mode)
        and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (uid, gid, mode),
        f"unexpected type, ownership or mode: {path}",
    )
    return changed


def rename_noreplace(source_fd: int, source: str, target_fd: int, target: str) -> None:
    rename = ctypes.CDLL(None, use_errno=True).renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(source_fd, os.fsencode(source), target_fd, os.fsencode(target), RENAME_NOREPLACE):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), target)


def publish_mapped_directory(path: Path, uid: int, gid: int) -> bool:
    """Publish a verified leaf, keeping incomplete directories outside service reach."""
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with tempfile.TemporaryDirectory(dir=path.parent, prefix=".steward-layout-") as staging:
            source = Path(staging) / "leaf"
            exact_directory(source, uid, gid, 0o700, create=True)
            source_fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                leaf_fd = os.open(
                    source.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=source_fd
                )
                try:
                    os.fsync(leaf_fd)
                finally:
                    os.close(leaf_fd)
                rename_noreplace(source_fd, source.name, parent_fd, path.name)
                os.fsync(source_fd)
            except FileExistsError:
                return exact_directory(path, uid, gid, 0o700)
            finally:
                os.close(source_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return True


def identity(account: object) -> dict[str, Any]:
    require(isinstance(account, dict), "missing application identity")
    pin = {name: account.get(name) for name in IDENTITY_KEYS}
    require(
        type(pin["uid"]) is int
        and 30000 <= pin["uid"] <= 39999
        and type(pin["gid"]) is int
        and 0 < pin["gid"] < ID_LIMIT,
        "invalid application account IDs",
    )
    for kind in ("uid", "gid"):
        assigned = pin["sub" + kind]
        require(
            isinstance(assigned, list)
            and len(assigned) == 2
            and all(type(value) is int for value in assigned)
            and assigned[1] == 65536
            and 0 < assigned[0] <= ID_LIMIT - assigned[1]
            and not assigned[0] <= pin[kind] < sum(assigned),
            "invalid application subordinate IDs",
        )
    return pin


def pinned_account(user: str, expected: dict[str, Any]) -> None:
    path = STATE_ROOT / "application-identities" / user
    protected_ancestors(path)
    exact_directory(path.parent, 0, 0, 0o700)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink)
            == (0, 0, 0o600, 1),
            "unsafe application identity pin",
        )
        data = handle.read(4097)
    require(len(data) <= 4096, "application identity pin exceeds the size limit")
    observed = json.loads(data)
    require(
        observed == expected and identity(observed) == expected, "application identity pin changed"
    )
    try:
        account = pwd.getpwnam(user)
    except KeyError as error:
        raise ValueError("application account is unavailable") from error
    require(
        (account.pw_uid, account.pw_gid, account.pw_dir)
        == (expected["uid"], expected["gid"], str(DATA_ROOT / "application-users" / user)),
        "application account changed",
    )


def layout_bindings(configuration: dict[str, Any]) -> tuple[Path, dict, list, dict]:
    require(isinstance(configuration, dict), "invalid application layout input")
    app, ids = configuration.get("application"), configuration.get("ids")
    require(isinstance(app, dict) and isinstance(ids, dict), "invalid application layout input")
    app_id, isolation, pod, services = (app.get(k) for k in ("id", "isolation", "pod", "services"))
    require(
        isinstance(app_id, str)
        and SLUG.fullmatch(app_id)
        and isolation in ("shared", "separate")
        and isinstance(services, list)
        and len(services) <= 64,
        "invalid application layout binding",
    )
    app_stem = graph_identifier("a", app_id)
    shared_user = "stw-" + app_stem
    if isolation == "shared" and services:
        require(
            isinstance(pod, dict)
            and (pod.get("user"), pod.get("unit"), pod.get("filename"))
            == (shared_user, app_stem + "-pod.service", app_stem + ".pod"),
            "invalid application pod binding",
        )
    else:
        require(pod is None, "unexpected application pod binding")
    data = DATA_ROOT / "applications" / app_id / "data"
    accounts = {}
    seen = set()
    for service in services:
        require(isinstance(service, dict), "invalid application service layout")
        service_id = service.get("id")
        require(
            isinstance(service_id, str) and SLUG.fullmatch(service_id) and service_id not in seen,
            "invalid application service ID",
        )
        seen.add(service_id)
        stem = graph_identifier("s", app_id, service_id)
        user = shared_user if isolation == "shared" else "stw-" + stem
        source = service.get("data_source")
        owner = service.get("data_owner_container_uid")
        mapped = isolation == "shared" and source is not None and owner != SHARED_POD_UID
        require(
            (service.get("user"), service.get("unit"), service.get("filename"))
            == (user, stem + ".service", stem + ".container")
            and service.get("manage", True) is True
            and type(service.get("deploy")) is bool
            and (source is None or source == str(data / service_id))
            and type(owner) is int
            and 1000 <= owner <= 60000
            and service.get("data_needs_mapped_owner") is mapped,
            "invalid application service layout binding",
        )
        if user not in accounts:
            accounts[user] = identity(ids.get(user))
    return data, pod, services, accounts


def ensure_layout(configuration: dict[str, Any]) -> bool:
    data, _, services, ids = layout_bindings(configuration)
    for parent, mode in (
        (DATA_ROOT, 0o755),
        (CONFIG_ROOT, 0o755),
        (CONFIG_ROOT / "secrets", 0o711),
        (QUADLET_ROOT, 0o755),
        (STATE_ROOT, 0o755),
    ):
        protected_ancestors(parent)
        exact_directory(parent, 0, 0, mode)
    directories = [
        (data.parent.parent, 0, 0, 0o755),
        (data.parent, 0, 0, 0o755),
        (data, 0, 0, 0o755),
        (CONFIG_ROOT / "secrets" / "applications", 0, 0, 0o711),
        (CONFIG_ROOT / "secrets" / "applications" / data.parent.name, 0, 0, 0o711),
        (STATE_ROOT / "application-activations", 0, 0, 0o700),
    ]
    for user in sorted(ids):
        directories.append((QUADLET_ROOT / str(ids[user]["uid"]), 0, 0, 0o755))
    for service in services:
        if service["data_source"] and not service["data_needs_mapped_owner"]:
            account = ids[service["user"]]
            directories.append((data / service["id"], account["uid"], account["gid"], 0o700))
    changed = False
    for path, uid, gid, mode in directories:
        changed |= exact_directory(path, uid, gid, mode, create=True)
    return changed


def parse_id_map(text: str, owner: int, subordinate: list[int]) -> list[tuple[int, int, int]]:
    rows = text.splitlines()
    require(1 <= len(rows) <= 340, "invalid application namespace map size")
    spans = []
    lower, count = subordinate
    for row in rows:
        match = MAP_ROW.fullmatch(row)
        require(match is not None, "malformed application namespace map")
        inside, outside, width = (int(number) for number in match.groups())
        require(
            width > 0
            and inside + width <= ID_LIMIT
            and outside + width <= ID_LIMIT
            and (
                (inside, outside, width) == (SHARED_POD_UID, owner, 1)
                or lower <= outside
                and outside + width <= lower + count
            ),
            "application namespace map leaves the pinned IDs",
        )
        spans.append((inside, outside, width))
    require((SHARED_POD_UID, owner, 1) in spans, "application keep-id slot changed")
    for axis in (0, 1):
        ordered = sorted(spans, key=lambda span: span[axis])
        require(
            all(a[axis] + a[2] <= b[axis] for a, b in zip(ordered, ordered[1:], strict=False)),
            "application namespace map ranges overlap",
        )
    return spans


def translated_id(spans: list[tuple[int, int, int]], container_id: int) -> int:
    for inside, outside, width in spans:
        if inside <= container_id < inside + width:
            return outside + container_id - inside
    raise ValueError("configured application data owner is unmapped")


def verify_mapped_layout(
    host: Host, configuration: dict[str, Any], *, create: bool = False
) -> bool:
    data, pod, services, ids = layout_bindings(configuration)
    mapped = [item for item in services if item["deploy"] and item["data_needs_mapped_owner"]]
    if not mapped:
        return False
    user = pod["user"]
    account = ids[user]
    pinned_account(user, account)
    protected_ancestors(data)
    for path in (DATA_ROOT, data.parent.parent, data.parent, data):
        exact_directory(path, 0, 0, 0o755)
    uid_map, gid_map = host.application_infra_maps(user, pod["unit"], account["uid"])
    uids = parse_id_map(uid_map, account["uid"], account["subuid"])
    gids = parse_id_map(gid_map, account["gid"], account["subgid"])
    missing = []
    for service in mapped:
        path = data / service["id"]
        owner = service["data_owner_container_uid"]
        uid, gid = translated_id(uids, owner), translated_id(gids, owner)
        try:
            exact_directory(path, uid, gid, 0o700)
        except FileNotFoundError:
            if not create:
                raise
            missing.append((path, uid, gid))
    changed = False
    for path, uid, gid in missing:
        changed |= publish_mapped_directory(path, uid, gid)
    return changed


def main() -> None:
    if os.geteuid() != 0 or sys.argv[1:] not in (["directories"], ["mapped"]):
        sys.exit("usage (root only): python -m steward.application_layout directories|mapped")
    os.umask(0o022)
    try:
        raw = sys.stdin.buffer.read(INPUT_LIMIT + 1)
        require(len(raw) <= INPUT_LIMIT, "application layout input exceeds the size limit")
        configuration = json.loads(raw)
        changed = (
            ensure_layout(configuration)
            if sys.argv[1] == "directories"
            else verify_mapped_layout(Host(), configuration, create=True)
        )
        print(json.dumps({"changed": changed}))
    except (OSError, ValueError, RecursionError) as error:
        if isinstance(error, json.JSONDecodeError):
            sys.exit("invalid application layout JSON")
        sys.exit(str(error))


if __name__ == "__main__":
    main()
