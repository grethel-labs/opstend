"""Private host entry point for the approved application boot lifecycle."""

from __future__ import annotations

import argparse
import fcntl
import grp
import hashlib
import json
import os
import pwd
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path

from . import __version__
from .application_layout import verify_mapped_layout
from .core.application_ops import derive_group_plan
from .core.canonical import canonical_json, revision_id
from .core.config import ConfigError, Health, effective, parse_config
from .core.group_checkpoint import (
    MAX_GROUP_CHECKPOINTS,
    DeploymentFence,
    GroupCheckpoint,
    GroupPlan,
)
from .core.ids import graph_identifier
from .core.render import (
    APPLICATION_PROXY_DYNAMIC,
    APPLICATION_PROXY_ROUTES,
    PROXY_USER,
    application_proxy_routes,
    prepare_application_registry,
    prepare_separate_application_egress,
    prepare_shared_application_egress,
    render_application_proxy_configuration,
    render_application_proxy_routes,
    render_application_quadlets,
)
from .executor.deployment_launcher import GateError, Identity, parse_json
from .executor.host import SAFE_ENV, Host
from .executor.protocol import ExecutorError

STATE = Path("/var/lib/steward")
EXECUTOR_STATE_DB = Path("/var/lib/steward-executor/state.db")
RUNTIME = Path("/run/steward-applications")
CONFIG = Path("/etc/steward")
RELEASES = Path("/opt/steward/releases")
QUADLETS = Path("/etc/containers/systemd/users")
HOMES = Path("/srv/steward/application-users")
SYSTEMD = Path("/etc/systemd/system")
PROXY_RUNTIME = Path(APPLICATION_PROXY_DYNAMIC)
PROXY_UNIT = "proxy.service"
BOOT_UNIT = "steward-applications.service"
DEPLOYMENT_LOCK = Path("/run/steward-executor/locks/deployment-execution.lock")
BOOT_DEPLOYMENT_LOCK_WAIT = 60
HANDOFF = "activation-handoff.json"
GUARDED_ROUTE_JOURNAL = "route-publication.json"
GUARDED_ROUTE_DRAIN = "route-drain.json"
LIMIT = 16 * 1024 * 1024
FENCE_BODY_LIMIT = 4096
GROUP_BODY_LIMIT = 32 * 1024
SHA = re.compile(r"[0-9a-f]{64}")
SLUG = re.compile(r"[a-z][a-z0-9-]{1,30}[a-z0-9]")
FILE = re.compile(r"[A-Za-z0-9_+.-]+")


class BootError(Exception):
    pass


EVIDENCE_ERRORS = (
    BootError,
    ConfigError,
    ExecutorError,
    GateError,
    KeyError,
    OSError,
    TypeError,
    ValueError,
    subprocess.SubprocessError,
)


def require(condition, message):
    if not condition:
        raise BootError(message)


def is_digest(value):
    return isinstance(value, str) and SHA.fullmatch(value) is not None


def safe_directory(path):
    for current in (*reversed(path.parents), path):
        info = current.lstat()
        require(
            stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            "unsafe application directory",
        )


def protected(path, mode, gid=0):
    safe_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    handle = os.fdopen(fd, "rb")
    info = os.fstat(fd)
    if not (
        stat.S_ISREG(info.st_mode)
        and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink)
        == (0, gid, mode, 1)
    ):
        handle.close()
        raise BootError("unsafe application file")
    return handle


def read_bytes(path, mode=0o600, gid=0):
    with protected(path, mode, gid) as handle:
        data = handle.read(LIMIT + 1)
    require(len(data) <= LIMIT, "application file exceeds size limit")
    return data


def read_optional(path):
    try:
        value = json.loads(read_bytes(path))
    except FileNotFoundError:
        return None
    require(value is not None, "invalid application record")
    return value


@contextmanager
def executor_state_snapshot():
    path = EXECUTOR_STATE_DB
    uid = os.geteuid()
    safe_directory(path.parent)
    directory = path.parent.lstat()
    require(
        stat.S_ISDIR(directory.st_mode)
        and directory.st_uid == uid
        and stat.S_IMODE(directory.st_mode) == 0o700,
        "unsafe executor state directory",
    )
    for suffix in ("", "-wal", "-shm", "-journal"):
        try:
            info = path.with_name(path.name + suffix).lstat()
        except FileNotFoundError:
            if suffix:
                continue
            raise
        require(
            stat.S_ISREG(info.st_mode)
            and (info.st_uid, stat.S_IMODE(info.st_mode), info.st_nlink) == (uid, 0o600, 1),
            "unsafe executor state file",
        )
    with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=1)) as db:
        db.execute("BEGIN")
        yield db


def deployment_fence_from(db) -> DeploymentFence | None:
    table = db.execute("PRAGMA main.table_list('deployment_fence')").fetchall()
    require(
        len(table) == 1 and table[0][:3] == ("main", "deployment_fence", "table"),
        "missing executor deployment fence table",
    )
    rows = db.execute(
        "SELECT CASE WHEN typeof(singleton) = 'integer' THEN singleton END, "
        "CASE WHEN length(CAST(body AS BLOB)) <= ? THEN body END "
        "FROM deployment_fence LIMIT 2",
        (FENCE_BODY_LIMIT,),
    ).fetchall()
    if not rows:
        return None
    require(len(rows) == 1, "invalid executor deployment fence")
    singleton, body = rows[0]
    require(type(singleton) is int and singleton == 1, "invalid executor deployment fence")
    require(isinstance(body, str), "invalid executor deployment fence")
    return DeploymentFence.model_validate_json(body)


def read_deployment_fence() -> DeploymentFence | None:
    try:
        with executor_state_snapshot() as db:
            return deployment_fence_from(db)
    except (OSError, sqlite3.Error, ValueError) as error:
        raise BootError("invalid or unavailable executor deployment fence evidence") from error


def read_group_intents() -> list[GroupCheckpoint]:
    try:
        with executor_state_snapshot() as db:
            require(deployment_fence_from(db) is None, "executor deployment recovery is pending")
            table = db.execute("PRAGMA main.table_list('application_group_intents')").fetchall()
            require(
                len(table) == 1 and table[0][:3] == ("main", "application_group_intents", "table"),
                "missing executor application group table",
            )
            marker_table = db.execute(
                "PRAGMA main.table_list('application_group_operator_intents')"
            ).fetchall()
            if marker_table:
                require(
                    len(marker_table) == 1
                    and marker_table[0][:3]
                    == ("main", "application_group_operator_intents", "table"),
                    "invalid executor application group operator marker table",
                )
                # Markers remain after archival. Only join active rows.
                query = (
                    "SELECT CASE WHEN length(CAST(g.application AS BLOB)) <= 32 "
                    "THEN g.application END, CASE WHEN length(CAST(g.operation_id AS BLOB)) = 32 "
                    "THEN g.operation_id END, "
                    "CASE WHEN typeof(g.generation) = 'integer' THEN g.generation END, "
                    "CASE WHEN length(CAST(g.body AS BLOB)) <= ? THEN g.body END, "
                    "o.operation_id IS NOT NULL, "
                    "CASE WHEN length(CAST(o.application AS BLOB)) <= 32 THEN o.application END "
                    "FROM application_group_intents g "
                    "LEFT JOIN application_group_operator_intents o "
                    "ON o.operation_id = g.operation_id LIMIT ?"
                )
            else:
                query = (
                    "SELECT CASE WHEN length(CAST(application AS BLOB)) <= 32 "
                    "THEN application END, CASE WHEN length(CAST(operation_id AS BLOB)) = 32 "
                    "THEN operation_id END, "
                    "CASE WHEN typeof(generation) = 'integer' THEN generation END, "
                    "CASE WHEN length(CAST(body AS BLOB)) <= ? THEN body END, 0, NULL "
                    "FROM application_group_intents LIMIT ?"
                )
            rows = db.execute(query, (GROUP_BODY_LIMIT, MAX_GROUP_CHECKPOINTS + 1)).fetchall()
        require(len(rows) <= MAX_GROUP_CHECKPOINTS, "too many application group checkpoints")
        applications = set()
        operations = set()
        checkpoints = []
        for application, operation_id, generation, body, marked, marker_application in rows:
            require(isinstance(body, str), "invalid application group checkpoint")
            fields = parse_json(body)
            require("operator_managed" not in fields, "invalid application group checkpoint format")
            require(
                not marked or type(marker_application) is str,
                "inconsistent application group operator marker",
            )
            checkpoint = GroupCheckpoint.model_validate(fields)
            try:
                checkpoint = checkpoint.with_persisted_owner(marker_application)
            except ValueError as error:
                raise BootError("inconsistent application group operator marker") from error
            require(
                application == checkpoint.plan.application
                and operation_id == checkpoint.operation_id
                and type(generation) is int
                and generation == checkpoint.generation
                and application not in applications
                and operation_id not in operations,
                "inconsistent application group checkpoint identity",
            )
            applications.add(application)
            operations.add(operation_id)
            if checkpoint.phase not in ("complete", "recovered"):
                require(checkpoint.operator_managed, "unknown active application group intent")
                checkpoints.append(checkpoint)
        return checkpoints
    except (GateError, OSError, sqlite3.Error, ValueError) as error:
        raise BootError(
            "invalid or unavailable executor deployment fence evidence or application group data"
        ) from error


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def store(path, value):
    safe_directory(path.parent)
    if os.path.lexists(path):
        with protected(path, 0o600):
            pass
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        sync_directory(path.parent)
    finally:
        Path(name).unlink(missing_ok=True)


@contextmanager
def runtime_lock(*, existing=False):
    safe_directory(RUNTIME.parent)
    if not existing:
        RUNTIME.mkdir(mode=0o700, exist_ok=True)
    info = RUNTIME.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o700),
        "unsafe application runtime directory",
    )
    access = os.O_RDONLY if existing else os.O_RDWR | os.O_CREAT
    fd = os.open(RUNTIME / "lock", access | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink)
            == (0, 0, 0o600, 1),
            "unsafe application runtime lock",
        )
        deadline = time.monotonic() + 30
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                require(time.monotonic() < deadline, "application boot lock is busy")
                time.sleep(0.1)
        yield
    finally:
        os.close(fd)


@contextmanager
def deployment_lock(*, timeout=0, create=True):
    safe_directory(DEPLOYMENT_LOCK.parent.parent)
    if create:
        DEPLOYMENT_LOCK.parent.mkdir(mode=0o700, exist_ok=True)
    safe_directory(DEPLOYMENT_LOCK.parent)
    access = os.O_CREAT | os.O_WRONLY if create else os.O_RDONLY
    fd = os.open(DEPLOYMENT_LOCK, access | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and (info.st_uid, stat.S_IMODE(info.st_mode), info.st_nlink) == (0, 0o600, 1),
            "unsafe deployment execution lock",
        )
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as error:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise BootError("deployment execution is busy") from error
                time.sleep(min(0.1, remaining))
        yield
    finally:
        os.close(fd)


@dataclass(frozen=True)
class Binding:
    application: str
    service: str | None
    isolation: str
    identity: dict

    @property
    def app_stem(self):
        return graph_identifier("a", self.application)

    @property
    def stem(self):
        if self.service is None:
            return self.app_stem
        return graph_identifier("s", self.application, self.service)

    @property
    def user(self):
        return "stw-" + (self.app_stem if self.isolation == "shared" else self.stem)

    @property
    def unit(self):
        return self.stem + ("-pod.service" if self.service is None else ".service")

    @property
    def source(self):
        suffix = ".pod" if self.service is None else ".container"
        return QUADLETS / str(self.identity["uid"]) / (self.stem + suffix)

    @property
    def pod_name(self):
        return "steward-" + self.app_stem

    @property
    def uid(self):
        return self.identity["uid"]

    def validate(self):
        require(
            isinstance(self.application, str)
            and SLUG.fullmatch(self.application)
            and self.isolation in ("separate", "shared")
            and (
                self.service is None
                and self.isolation == "shared"
                or isinstance(self.service, str)
                and SLUG.fullmatch(self.service)
            )
            and identity_format(self.identity),
            "invalid application ownership binding",
        )


def identity_format(identity):
    return (
        isinstance(identity, dict)
        and set(identity) == {"uid", "gid", "subuid", "subgid"}
        and type(identity["uid"]) is int
        and 30000 <= identity["uid"] <= 39999
        and type(identity["gid"]) is int
        and 1 <= identity["gid"] < 2**32 - 1
        and all(
            isinstance(identity[name], list)
            and len(identity[name]) == 2
            and all(type(item) is int for item in identity[name])
            and identity[name][1] == 65536
            and 1 <= identity[name][0] <= 2**32 - 1 - 65536
            for name in ("subuid", "subgid")
        )
    )


def helper(name, *argv, data=None):
    path = STATE / name
    with protected(path, 0o600):
        pass
    result = subprocess.run(
        ["/usr/bin/python3", str(path), *argv],
        input=data,
        capture_output=True,
        timeout=75,
        check=False,
        env=SAFE_ENV,
        cwd="/",
    )
    require(result.returncode == 0, "application host verification failed")
    return result.stdout


def inspect_identity(user):
    pinned = json.loads(read_bytes(STATE / "application-identities" / user))
    require(identity_format(pinned), "invalid application identity pin")
    observation = json.loads(helper("application-identity.py", user, str(HOMES / user)))
    require(
        observation["exists"] is True and {key: observation[key] for key in pinned} == pinned,
        "application identity changed",
    )
    return pinned


def verify_stop_identity(binding):
    pinned = json.loads(read_bytes(STATE / "application-identities" / binding.user))
    current = pwd.getpwnam(binding.user)
    require(
        pinned == binding.identity
        and (current.pw_uid, current.pw_gid) == (binding.uid, binding.identity["gid"]),
        "application identity changed",
    )


def guard_helpers():
    return {
        "identity": digest(read_bytes(STATE / "application-identity.py")),
        "dispatch": digest(read_bytes(STATE / "application-firewall.py")),
        "firewall": digest(read_bytes(CONFIG / "nftables" / "firewall-policy.py", 0o700)),
    }


def release_path(release):
    require(
        isinstance(release, dict)
        and set(release) == {"version", "files"}
        and release["version"] == __version__
        and isinstance(release["files"], dict)
        and 1 <= len(release["files"]) <= 4096,
        "invalid application release",
    )
    path = RELEASES / release["version"]
    current = RELEASES.parent / "current"
    safe_directory(path)
    info = current.lstat()
    require(
        stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and os.readlink(current) == str(path),
        "unexpected active release",
    )
    wheels = []
    for name, sha in release["files"].items():
        parts = name.split("/")
        require(
            all(FILE.fullmatch(part) and part not in (".", "..") for part in parts)
            and is_digest(sha),
            "invalid application release file",
        )
        if parts[0] == "bundles" and len(parts) >= 3:
            artifact = path.joinpath(*parts)
        else:
            require(
                len(parts) == 1 and (name.endswith(".whl") or name == "requirements.txt"),
                "unexpected application release artifact",
            )
            if name.endswith(".whl"):
                wheels.append(name)
            artifact = path / "dist" / name
        with protected(artifact, 0o644) as handle:
            require(
                hashlib.file_digest(handle, "sha256").hexdigest() == sha,
                "application release artifact changed",
            )
    require(
        len(wheels) == 1
        and wheels[0].startswith(f"steward-{__version__}-")
        and "requirements.txt" in release["files"],
        "incomplete application release",
    )
    return path


def require_bundle(path, bundle, files):
    root = path / "bundles" / bundle
    safe_directory(root)
    actual = set()
    for current, directories, names in os.walk(root, onerror=raise_walk_error):
        for directory in directories:
            safe_directory(Path(current) / directory)
        for name in names:
            actual.add((Path(current) / name).relative_to(path).as_posix())
    expected = {name for name in files if name.startswith(f"bundles/{bundle}/")}
    require(expected and actual == expected, "application bundle changed")


def raise_walk_error(error):
    raise error


@dataclass(frozen=True)
class Target:
    binding: Binding
    enabled: bool
    port: int | None
    health: Health | None
    mapped_layout: dict | None = None


def desired_configuration():
    desired_file = CONFIG / "config" / "desired.json"
    desired_gid = grp.getgrnam("steward-api").gr_gid
    desired = json.loads(read_bytes(desired_file, 0o640, desired_gid))
    cfg = parse_config(desired, allow_unavailable=True)
    require(desired == effective(cfg), "application desired configuration is not canonical")
    return cfg


def deployment_inputs(inputs):
    require(
        isinstance(inputs, dict)
        and set(inputs) == {"release", "revision", "source"}
        and is_digest(inputs["revision"])
        and is_digest(inputs["source"]),
        "invalid application approval inputs",
    )
    release = release_path(inputs["release"])
    registry = json.loads(read_bytes(CONFIG / "executor.json"))
    cfg = desired_configuration()
    configured = prepare_application_registry(cfg)
    require(
        configured["config_revision"] == inputs["revision"]
        and registry.get("config_revision") == configured["config_revision"]
        and registry.get("applications", {} if not cfg.applications else None)
        == configured["applications"],
        "application registry does not match desired revision",
    )
    require(
        set(cfg.unavailable_features()) <= {"applications"},
        "configuration cannot authorize application boot",
    )
    routes = application_proxy_routes(cfg)
    planned = {item["id"]: item for item in render_application_quadlets(cfg, str(release))}
    targets = []
    fingerprints = {}
    expected_manifest = []
    identities = {}
    bundles = set()
    for app in sorted(cfg.applications, key=lambda item: item.id):
        by_id = {service.id: service for service in app.services}
        units = planned[app.id]
        enabled = any(item["deploy"] for item in units["services"])
        for service in app.services:
            require(
                not service.manage
                or not service.deploy
                or all(by_id[name].manage and by_id[name].deploy for name in service.depends_on),
                "unsupported application configuration",
            )
        if not units["services"]:
            continue
        receipt = read_bytes(STATE / "application-activations" / app.id).decode().strip()
        require(is_digest(receipt), "invalid application activation receipt")
        artifacts = {}
        services = units["services"]
        mapped_layout = None
        if any(item["deploy"] and item["data_needs_mapped_owner"] for item in services):
            mapped_layout = {
                "application": {**units, "isolation": app.isolation},
                "ids": identities,
            }
        members = ([units["pod"]] if units["pod"] else []) + services
        for item in members:
            service = by_id[item["id"]] if "id" in item else None
            user = item["user"]
            if user not in identities:
                identities[user] = inspect_identity(user)
            binding = Binding(
                app.id, service.id if service else None, app.isolation, identities[user]
            )
            binding.validate()
            quadlet = read_bytes(binding.source, 0o644)
            require(
                binding.user == user
                and binding.unit == item["unit"]
                and quadlet == item["content"].encode(),
                "installed application Quadlet changed",
            )
            env_hash = None
            if service:
                env_path = CONFIG / "secrets" / "applications" / app.id / (service.id + ".env")
                if service.secrets:
                    env_hash = digest(read_bytes(env_path, 0o640, binding.identity["gid"]))
                else:
                    require(not os.path.lexists(env_path), "unexpected application environment")
                if service.bundle:
                    bundles.add(service.bundle)
            port = service.host_port if service else None
            expected_manifest.append(
                {
                    "user": user,
                    "uid": binding.uid,
                    "identity": binding.identity,
                    "unit": binding.unit,
                    "port": port,
                }
            )
            artifacts[binding.unit] = {"quadlet": digest(quadlet), "environment": env_hash}
            targets.append(
                Target(
                    binding,
                    service.deploy if service else enabled,
                    port,
                    service.health if service else None,
                    mapped_layout if service is None else None,
                )
            )
        fingerprints[app.id] = {"activation": receipt, "artifacts": artifacts}
    for bundle in sorted(bundles):
        require_bundle(release, bundle, inputs["release"]["files"])
    manifest = read_optional(STATE / "application-units.json")
    if manifest is None and not expected_manifest:
        manifest = []
    require(
        isinstance(manifest, list)
        and sorted(manifest, key=lambda item: item["unit"])
        == sorted(expected_manifest, key=lambda item: item["unit"]),
        "unexpected application unit manifest",
    )
    chains = prepare_separate_application_egress(cfg) + prepare_shared_application_egress(cfg)
    require(
        {record["user"] for record in chains} == set(identities)
        and len({identity["uid"] for identity in identities.values()}) == len(identities),
        "application firewall and identity bindings differ",
    )
    dispatch = {identities[record["user"]]["uid"]: record["chain"] for record in chains}
    active_uids = sorted({target.binding.uid for target in targets if target.enabled})
    require(
        cfg.hardening.firewall.manage or not active_uids,
        "application boot requires managed firewall",
    )
    manager_dropins = {}
    for uid in active_uids:
        path = SYSTEMD / f"user@{uid}.service.d" / "90-steward-applications.conf"
        manager_dropins[str(uid)] = digest(read_bytes(path, 0o644))
    evidence = {
        "registry": revision_id(registry),
        "applications": fingerprints,
        "identities": identities,
        "dispatch": {str(uid): chain for uid, chain in sorted(dispatch.items())},
        "manager_dropins": manager_dropins,
    }
    if routes:
        evidence["proxy"] = proxy_evidence(cfg, routes)
    return targets, evidence, routes


def verify_firewall(inputs, evidence):
    observed = json.loads(
        helper(
            "application-firewall.py",
            data=json.dumps(
                {
                    "source": inputs["source"],
                    "dispatch": evidence["dispatch"],
                }
            ).encode(),
        )
    )
    runtime = observed["runtime"]
    require(is_digest(runtime), "invalid verified application firewall runtime")
    return runtime


def proxy_account():
    account = pwd.getpwnam(PROXY_USER)
    require(
        account.pw_uid > 0
        and account.pw_gid > 0
        and account.pw_gid == grp.getgrnam(PROXY_USER).gr_gid
        and account.pw_dir == "/srv/steward/proxy",
        "unsafe application proxy account",
    )
    return account


def proxy_source(uid):
    return QUADLETS / str(uid) / "proxy.container"


def volatile_run():
    run = PROXY_RUNTIME.parent
    safe_directory(run)
    with Path("/proc/self/mountinfo").open(encoding="ascii") as handle:
        mounts = [line.split(" - ", 1) for line in handle]
    require(
        [right.split()[0] for left, right in mounts if left.split()[4] == str(run)] == ["tmpfs"]
        and not any(
            (mount := left.split()[4]) in (str(PROXY_RUNTIME), str(RUNTIME))
            or mount.startswith(str(PROXY_RUNTIME) + "/")
            or mount.startswith(str(RUNTIME) + "/")
            for left, _ in mounts
        ),
        "application proxy requires volatile /run storage",
    )


def proxy_directory(gid):
    volatile_run()
    info = PROXY_RUNTIME.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, gid, 0o750),
        "unsafe application proxy provider directory",
    )


def proxy_evidence(cfg, routes):
    account = proxy_account()
    proxy_directory(account.pw_gid)
    expected = render_application_proxy_configuration(cfg, routes)
    proxy = CONFIG / "proxy"
    persistent = proxy / "dynamic"
    safe_directory(persistent)
    require(
        {path.name for path in persistent.iterdir()} == {"routes.yml"}
        and {path.name for path in PROXY_RUNTIME.iterdir()}
        <= {"routes.yml", APPLICATION_PROXY_ROUTES},
        "unexpected application proxy provider entries",
    )
    artifacts = {
        "quadlet": read_bytes(proxy_source(account.pw_uid), 0o644),
        "static": read_bytes(proxy / "traefik.yml", 0o640, account.pw_gid),
        "dynamic": read_bytes(persistent / "routes.yml", 0o640, account.pw_gid),
        "runtime_legacy": read_bytes(PROXY_RUNTIME / "routes.yml", 0o640, account.pw_gid),
        "certificate": read_bytes(proxy / "certs" / "internal.crt", 0o640, account.pw_gid),
        "key": read_bytes(proxy / "certs" / "internal.key", 0o640, account.pw_gid),
    }
    require(
        all(artifacts[name] == expected[name].encode() for name in ("quadlet", "static", "dynamic"))
        and artifacts["runtime_legacy"] == artifacts["dynamic"],
        "installed application proxy configuration changed",
    )
    return {
        "uid": account.pw_uid,
        "gid": account.pw_gid,
        "artifacts": {name: digest(data) for name, data in artifacts.items()},
        "routes": digest(render_application_proxy_routes(routes).encode()),
    }


def proxy_authority(host, uid):
    # Drain is still needed when the durable deployment or its artifact hashes
    # have drifted. Restrict control to the fixed root-owned generated service.
    source = proxy_source(uid)
    with protected(source, 0o644):
        pass
    require(
        host.application_unit_authority(PROXY_USER, PROXY_UNIT, source),
        "application proxy unit source changed",
    )


def verify_proxy_running(host, evidence, *, wait=False):
    uid = evidence["proxy"]["uid"]
    deadline = time.monotonic() + (15 if wait else 0)
    while True:
        if host.application_proxy_running() is True:
            proxy_authority(host, uid)
            return
        require(time.monotonic() < deadline, "application proxy service is unavailable")
        time.sleep(0.2)


def route_path():
    return PROXY_RUNTIME / APPLICATION_PROXY_ROUTES


def route_present():
    # lexists() hides permission errors. An uninspectable route is not absent.
    try:
        route_path().lstat()
    except FileNotFoundError:
        return False
    return True


def install_route_file(routes, evidence):
    gid = evidence["proxy"]["gid"]
    proxy_directory(gid)
    data = render_application_proxy_routes(routes).encode()
    if route_present() and read_bytes(route_path(), 0o640, gid) == data:
        return False
    require(not route_present(), "old application routes require drain before replacement")
    fd, name = tempfile.mkstemp(dir=RUNTIME)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchown(handle.fileno(), 0, gid)
            os.fchmod(handle.fileno(), 0o640)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, route_path())
        sync_directory(PROXY_RUNTIME)
    finally:
        Path(name).unlink(missing_ok=True)
    return True


def drain_routes(host, *, private=None, may_be_loaded=False):
    marker_path = RUNTIME / GUARDED_ROUTE_DRAIN
    marker = read_optional(marker_path)
    if marker is None and not route_present() and not may_be_loaded:
        return False
    account = proxy_account()
    uid = account.pw_uid
    if marker is None:
        marker = {"uid": uid, "restore": host.application_proxy_running() is True}
        if private is not None:
            marker["private"] = private
        store(marker_path, marker)
    require(
        isinstance(marker, dict)
        and set(marker)
        == ({"uid", "restore", "private"} if private is not None else {"uid", "restore"})
        and marker.get("private") == private
        and type(marker["uid"]) is int
        and marker["uid"] == uid
        and type(marker["restore"]) is bool,
        "invalid application route drain record",
    )
    try:
        if route_present():
            proxy_directory(account.pw_gid)
            route_path().unlink()
            sync_directory(PROXY_RUNTIME)
    finally:
        # The owned file can be removed even when the loaded unit has drifted.
        # Process control still requires the fixed proxy's generated authority.
        proxy_authority(host, uid)
        require(
            host.set_user_unit(PROXY_USER, PROXY_UNIT, running=False)
            and host.application_proxy_evicted(uid),
            "application proxy eviction failed",
        )
    if marker["restore"]:
        proxy_authority(host, uid)
        require(
            host.set_user_unit(PROXY_USER, PROXY_UNIT, running=True)
            and host.application_proxy_running() is True,
            "legacy application proxy failed to restart",
        )
    marker_path.unlink()
    sync_directory(RUNTIME)
    return True


@dataclass
class Active:
    generation: str | None
    bindings: list[Binding]
    pending: list[Binding]

    def write(self):
        path = RUNTIME / "active.json"
        if not self.bindings:
            path.unlink(missing_ok=True)
            return
        store(
            path,
            {
                "generation": self.generation,
                "bindings": [asdict(item) for item in self.bindings],
                "pending": [binding.unit for binding in self.pending],
            },
        )


def read_active():
    raw = read_optional(RUNTIME / "active.json")
    if raw is None:
        return Active(None, [], [])
    require(
        isinstance(raw, dict)
        and set(raw) == {"generation", "bindings", "pending"}
        and is_digest(raw["generation"])
        and isinstance(raw["bindings"], list)
        and len(raw["bindings"]) <= 16 * 65,
        "invalid active application record",
    )
    bindings = []
    seen = set()
    for item in raw["bindings"]:
        require(isinstance(item, dict), "invalid active application binding")
        binding = Binding(**item)
        binding.validate()
        require(binding.unit not in seen, "duplicate active application binding")
        seen.add(binding.unit)
        bindings.append(binding)
    pending = raw["pending"]
    require(isinstance(pending, list), "invalid pending application bindings")
    selected = [binding for binding in bindings if binding.unit in pending]
    require([binding.unit for binding in selected] == pending, "invalid pending application order")
    return Active(raw["generation"], bindings, selected)


def health_check(host, target, *, retry):
    if target.health is None:
        return
    for attempt in range(target.health.retries if retry else 1):
        if attempt:
            time.sleep(2)
        if host.http_health(target.port, target.health.path, target.health.timeout_s)["ok"]:
            return
    raise BootError("application health check failed")


def verify_target_data(host, target):
    if target.mapped_layout is not None:
        try:
            verify_mapped_layout(host, target.mapped_layout)
        except (OSError, ValueError) as error:
            raise BootError("shared application data ownership verification failed") from error


def stop_bindings(host, active, *, pending_only=False):
    selected = (active.pending if pending_only else active.bindings).copy()
    for binding in reversed(selected):
        # Leave prerequisites running if an owned dependent cannot be stopped.
        verify_stop_identity(binding)
        pending = binding in active.pending
        observed = unit_running(host, binding)
        if observed is None and binding.service is None and not pending:
            # Quadlet's exit policy may still be removing the pod after the
            # final owned container has already stopped.
            deadline = time.monotonic() + 3
            while observed is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(0.1, remaining))
                observed = unit_running(host, binding)
        manager_stopped = observed is None and manager_quiescent(host, binding)
        transitioning = False
        if pending and not manager_stopped:
            transitioning = host.application_unit_transitioning(binding.user, binding.unit)
            require(transitioning is not None, "application start job state is unknown")
            if transitioning:
                assert_authority(host, binding)
        require(
            observed is not None or manager_stopped or transitioning,
            "application stop state is unknown",
        )
        if observed or transitioning:
            if binding.service is None:
                require(
                    host.application_pod_members(
                        binding.user, binding.pod_name, require_running=not transitioning
                    )
                    == []
                    or (
                        transitioning
                        and host.application_pod_absent(binding.user, binding.pod_name)
                    ),
                    "application pod may contain another workload",
                )
            require(
                host.set_user_unit(binding.user, binding.unit, running=False)
                and unit_running(host, binding) is False
                and (
                    not pending
                    or host.application_unit_transitioning(binding.user, binding.unit) is False
                ),
                "application unit failed to stop",
            )
        active.bindings.remove(binding)
        if binding in active.pending:
            active.pending.remove(binding)
        active.write()
    return bool(selected)


def manager_quiescent(host, binding):
    return host.application_manager_quiescent(binding.uid, binding.identity["subuid"])


def unit_running(host, binding):
    if binding.service is not None:
        return host.group_service_running(binding.user, binding.unit, binding.stem)
    state = host.user_unit(binding.user, binding.unit)
    if state["load"] == "loaded":
        observed = (state["active"], state["sub"])
        if observed == ("active", "running") and (
            host.application_pod_members(binding.user, binding.pod_name) is not None
        ):
            return True
        if observed in (("inactive", "dead"), ("failed", "failed")) and (
            host.application_pod_absent(binding.user, binding.pod_name)
        ):
            return False
    return None


def assert_authority(host, binding):
    require(
        host.application_unit_authority(binding.user, binding.unit, binding.source),
        "application unit source changed",
    )


def approved_inputs(record):
    require(
        isinstance(record, dict)
        and set(record) == {"generation", "inputs", "evidence"}
        and is_digest(record["generation"])
        and isinstance(record["evidence"], dict),
        "application boot has no approved deployment",
    )
    inputs = record["inputs"]
    helpers = guard_helpers()
    require(helpers == record["evidence"].get("helpers"), "approved application guard changed")
    targets, evidence, routes = deployment_inputs(inputs)
    evidence["helpers"] = helpers
    evidence["firewall_runtime"] = verify_firewall(inputs, evidence)
    require(evidence == record["evidence"], "approved application deployment inputs changed")
    return targets, evidence, routes


def verify_route_targets(host, targets, routes):
    by_service = {
        (target.binding.application, target.binding.service): target for target in targets
    }
    endpoints = {(route.application, route.service, route.port) for route in routes}
    for app, service, port in sorted(endpoints):
        target = by_service[app, service]
        require(
            target.enabled and target.port == port and target.health is not None,
            "application route target differs from approved deployment",
        )
        assert_authority(host, target.binding)
        require(
            unit_running(host, target.binding) is True
            and host.application_listener_owned(port, target.binding.uid),
            "application route target has no uniquely owned loopback listener",
        )
        health_check(host, target, retry=False)
        require(
            host.application_listener_owned(port, target.binding.uid),
            "application route listener changed during health check",
        )


def verify_live_routes(host, generation, targets, evidence, routes):
    active = read_active()
    require(
        routes
        and active.generation == generation
        and not active.pending
        and active.bindings == [target.binding for target in targets if target.enabled]
        and read_bytes(route_path(), 0o640, evidence["proxy"]["gid"])
        == render_application_proxy_routes(routes).encode(),
        "active application route authority changed",
    )
    verify_proxy_running(host, evidence)
    verify_route_targets(host, targets, routes)


def group_targets(registry, plan: GroupPlan, targets) -> dict[str, Target]:
    try:
        current = derive_group_plan(
            registry,
            plan.application,
            plan.target,
            expected_revision=plan.config_revision,
            scope=plan.scope,
        )
    except ValueError as error:
        raise BootError("invalid or unavailable application group authority") from error
    require(current == plan.model_dump(), "application group plan no longer matches registry")
    require(
        registry["applications"][plan.application]["isolation"] == "separate",
        "application group requires separate isolation",
    )
    desired = plan.desired_running | plan.external_desired_running
    selected = {
        target.binding.service: target
        for target in targets
        if target.binding.application == plan.application and target.binding.service in desired
    }
    require(
        selected.keys() == desired.keys()
        and all(
            target.binding.isolation == "separate" and target.enabled is desired[name]
            for name, target in selected.items()
        ),
        "application group bindings differ from approved boot inputs",
    )
    return selected


def private_group_registry(record, evidence, routes):
    from .executor import site_deployment

    try:
        cfg, installed = site_deployment.installed_config(private=True)
        marker = site_deployment.read_marker()
        require(
            marker["schema_version"] == 2 and marker["server_name"] == cfg.server.name,
            "application groups require an enrolled private deployment",
        )
        site_deployment.enrollment_evidence(marker)
    except site_deployment.boot.BootError as error:
        # When invoked with python -m, the site verifier imports the
        # package module and its BootError differs from __main__.BootError.
        raise BootError(str(error)) from error
    require(
        not routes
        and installed["config_revision"] == record["inputs"]["revision"]
        and revision_id(installed) == evidence["registry"],
        "application group authority differs from protected deployment inputs",
    )
    return installed


def require_group_authority(host, registry, plan: GroupPlan) -> dict[str, Target]:
    """Verify executor group authority while its deployment and target locks are held."""
    try:
        with runtime_lock(existing=True):
            require(
                read_optional(RUNTIME / "hold") is None
                and read_optional(RUNTIME / HANDOFF) is None,
                "application boot transition is unfinished",
            )
            record = read_optional(STATE / "application-boot.json")
            targets, evidence, routes = approved_inputs(record)
            installed = private_group_registry(record, evidence, routes)
            require(
                canonical_json(installed) == canonical_json(registry),
                "application group authority differs from protected deployment inputs",
            )
            selected = group_targets(installed, plan, targets)
            props = boot_unit_properties()
            boot_unit_digest()
            require_boot_unit(props)
            require(
                boot_unit_ready(props) and props.get("UnitFileState") == "enabled",
                "application boot unit has not been activated and enabled",
            )
            active = read_active()
            approved = [target.binding for target in targets if target.enabled]
            require(
                active.generation == record["generation"]
                and not active.pending
                and active.bindings
                == [binding for binding in approved if binding in active.bindings]
                and all(
                    not target.enabled or target.binding in active.bindings
                    for target in selected.values()
                ),
                "application group lacks approved boot ownership",
            )
            for target in selected.values():
                if target.enabled:
                    verify_stop_identity(target.binding)
                    assert_authority(host, target.binding)
            return selected
    except BootError:
        raise
    except EVIDENCE_ERRORS as error:
        raise BootError("invalid or unavailable application group authority") from error


def projected_group_state(checkpoint: GroupCheckpoint) -> dict[str, bool]:
    plan = checkpoint.plan
    stopped = plan.stop_order[: checkpoint.stop_index]
    if checkpoint.phase == "stopping":
        excluded = set(stopped)
        if checkpoint.pending is not None:
            excluded.add(checkpoint.pending.service)
        allowed = set(plan.start_order) - excluded
    elif checkpoint.phase == "paused":
        allowed = set()
    elif checkpoint.phase == "resuming":
        allowed = set(plan.start_order[: checkpoint.resume_index])
    else:
        require(checkpoint.phase == "recovering", "invalid application group projection phase")
        allowed = set(plan.start_order) - set(stopped)
        allowed.update(list(reversed(stopped))[: checkpoint.recovery_index])
    return {
        name: name in allowed and running for name, running in checkpoint.original_running.items()
    }


def group_projection(record, evidence, routes, targets, checkpoints):
    if not checkpoints:
        return {}
    registry = private_group_registry(record, evidence, routes)
    projection = {}
    for checkpoint in checkpoints:
        selected = group_targets(registry, checkpoint.plan, targets)
        for name, running in projected_group_state(checkpoint).items():
            projection[selected[name].binding.unit] = running
    return projection


def observe_projected_target(host, binding, *, require_quiescent=False):
    observed = unit_running(host, binding)
    if observed is None and manager_quiescent(host, binding):
        verify_stop_identity(binding)
        return False
    assert_authority(host, binding)
    require(
        observed is not None
        and host.application_unit_transitioning(binding.user, binding.unit) is False,
        "application start state is unknown",
    )
    if observed is False and require_quiescent:
        require(
            host.group_service_quiescent(binding.user, binding.unit, binding.stem),
            "application group unit is not quiescent",
        )
    return observed


def _retirement_observations(host, bindings, desired_running):
    """Check the old boot ownership before a guarded deployment stops any service."""
    active = read_active()
    require(not active.pending, "previous application startup requires recovery")
    observed = {}
    for name, binding in bindings.items():
        binding.validate()
        verify_stop_identity(binding)
        running = observe_projected_target(host, binding, require_quiescent=True)
        require(not running or desired_running[name], "disabled application unit is active")
        require(not running or binding in active.bindings, "active unit lacks boot ownership")
        observed[name] = running
    return observed


def quarantine_projection(targets):
    """Units of an application with an open quarantine stay down (L08 step 3)."""
    from .core.incidents import HOLD_DOWN, IncidentError, IncidentStore

    try:
        incidents = IncidentStore(EXECUTOR_STATE_DB.parent / "incidents").all()
    except IncidentError as error:
        raise BootError("application incident state is unreadable") from error
    held = {item.application for item in incidents if item.phase in HOLD_DOWN}
    return {t.binding.unit: False for t in targets if t.binding.application in held}


def start(host):
    try:
        checkpoints = read_group_intents()
    except EVIDENCE_ERRORS:
        drain_routes(host)
        raise
    if read_optional(RUNTIME / "hold") is not None:
        raise BootError("application deployment is in progress")
    try:
        return start_approved(host, checkpoints)
    except EVIDENCE_ERRORS:
        drain_routes(host)
        raise


def start_approved(host, checkpoints):
    if not checkpoints and read_optional(RUNTIME / "route-drain.json") is not None:
        drain_routes(host)
    record = read_optional(STATE / "application-boot.json")
    targets, evidence, routes = approved_inputs(record)
    generation = record["generation"]
    inputs = record["inputs"]
    projection = group_projection(record, evidence, routes, targets, checkpoints)
    projection.update(quarantine_projection(targets))
    if route_present():
        verify_live_routes(host, generation, targets, evidence, routes)
    enabled = [target for target in targets if target.enabled]
    active = read_active()
    approved = [target.binding for target in enabled]
    require(
        not active.pending
        and (
            not active.bindings
            or (
                active.generation == generation
                and active.bindings
                == [binding for binding in approved if binding in active.bindings]
            )
        ),
        "previous application activation has unresolved ownership",
    )

    def check_kill_switch():
        if projection:
            require(not host.kill_switch(), "automatic application group boot is stopped")

    def require_projected_state(target, running):
        binding = target.binding
        expected = projection.get(binding.unit, target.enabled)
        require(expected or running is False, "application unit conflicts with boot intent")
        require(
            running is False or binding in active.bindings,
            "active application unit lacks boot ownership",
        )

    check_kill_switch()
    if projection:
        for target in targets:
            binding = target.binding
            running = observe_projected_target(
                host, binding, require_quiescent=projection.get(binding.unit) is False
            )
            require_projected_state(target, running)

    enabled_uids = {target.binding.uid for target in enabled}
    for uid in sorted(enabled_uids):
        check_kill_switch()
        require(host.start_application_manager(uid), "application manager failed to start")
    observed = {}
    for target in targets:
        binding = target.binding
        if binding.uid not in enabled_uids:
            continue
        if projection:
            observed[binding.unit] = observe_projected_target(
                host, binding, require_quiescent=projection.get(binding.unit) is False
            )
            require_projected_state(target, observed[binding.unit])
            continue
        assert_authority(host, binding)
        observed[binding.unit] = unit_running(host, binding)
        require(observed[binding.unit] is not None, "application start state is unknown")
        require(
            target.enabled or observed[binding.unit] is False, "disabled application unit is active"
        )
        require(
            observed[binding.unit] is False or binding in active.bindings,
            "active application unit lacks boot ownership",
        )
    active.generation = generation
    projected_off = [
        target.binding for target in targets if projection.get(target.binding.unit) is False
    ]
    try:
        for target in enabled:
            binding = target.binding
            if binding in projected_off:
                continue
            if not observed[binding.unit]:
                check_kill_switch()
                running = (
                    observe_projected_target(host, binding)
                    if projection
                    else unit_running(host, binding)
                )
                require(running is False, "application state changed before start")
                require(
                    verify_firewall(inputs, evidence) == evidence["firewall_runtime"],
                    "approved application firewall runtime changed",
                )
                if binding not in active.bindings:
                    active.bindings = [
                        item for item in approved if item in active.bindings or item == binding
                    ]
                check_kill_switch()
                active.pending.append(binding)
                active.write()
                check_kill_switch()
                require(
                    host.set_user_unit(binding.user, binding.unit, running=True),
                    "application unit failed to start",
                )
            health_check(host, target, retry=True)
            require(unit_running(host, binding) is True, "application unit failed to become active")
            verify_target_data(host, target)
        unclaimed = [
            binding
            for binding in projected_off
            if binding in approved and binding not in active.bindings
        ]
        check_kill_switch()
        if projected_off:
            require(
                all(
                    observe_projected_target(host, binding, require_quiescent=True) is False
                    for binding in projected_off
                ),
                "application projected-off state changed during boot",
            )
        routes_changed = False
        if routes:
            verify_proxy_running(host, evidence, wait=True)
            verify_route_targets(host, targets, routes)
            require(
                verify_firewall(inputs, evidence) == evidence["firewall_runtime"],
                "application firewall runtime changed during publication",
            )
            routes_changed = install_route_file(routes, evidence)
    except EVIDENCE_ERRORS:
        drain_routes(host)
        stop_bindings(host, read_active(), pending_only=True)
        raise
    if active.pending or unclaimed:
        # Off bindings are owned but never pending. Startup recovery only stops
        # units whose start was attempted by this boot.
        active.bindings = [
            binding for binding in approved if binding in active.bindings or binding in unclaimed
        ]
        active.pending.clear()
        active.write()
        return True
    return routes_changed


def publish(host, generation, inputs):
    hold = read_optional(RUNTIME / "hold")
    require(hold == generation, "application deployment hold does not match")
    try:
        return publish_held(host, generation, inputs)
    except EVIDENCE_ERRORS:
        drain_routes(host)
        raise


def publish_held(host, generation, inputs, *, private=None, routed=False):
    if private and not routed:
        require_routeless(desired_configuration())
    elif private:
        require_route_transition_clear()
    elif read_optional(RUNTIME / "route-drain.json") is not None:
        drain_routes(host)
    targets, evidence, routes = deployment_inputs(inputs)
    if private and not routed:
        require(not routes, "private application deployment has routes")
    enabled = any(target.enabled for target in targets)
    if enabled:
        evidence["firewall_runtime"] = verify_firewall(inputs, evidence)
        evidence["helpers"] = guard_helpers()
    bindings = observe_targets(host, targets)
    previous = read_active()
    verify_previous_quiescent(host, previous, bindings)
    if enabled:
        require(
            verify_firewall(inputs, evidence) == evidence["firewall_runtime"],
            "application firewall runtime changed during publication",
        )
    path = STATE / "application-boot.json"
    prior = read_optional(path)
    record = (
        {"generation": generation, "inputs": inputs, "evidence": evidence} if bindings else None
    )
    changed = prior != record or previous.bindings != bindings
    handoff = None
    if private:
        props = boot_unit_properties()
        if bindings:
            boot_unit_digest()
            require_boot_unit(props)
            require(
                boot_unit_ready(props) or props.get("ActiveState") in ("inactive", "failed"),
                "application boot unit is transitioning",
            )
        else:
            require(
                props.get("ActiveState") in ("inactive", "failed"),
                "retired application boot unit is still active",
            )
        handoff = planned_handoff(private, props, bool(bindings))
    if route_present():
        if private:
            require(
                routed and prior == record and routes,
                "existing application routes differ from the guarded publication",
            )
            verify_live_routes(host, generation, targets, evidence, routes)
        elif prior != record or not routes:
            changed = drain_routes(host) or changed
    if routes:
        verify_proxy_running(host, evidence)
        verify_route_targets(host, targets, routes)
        require(
            verify_firewall(inputs, evidence) == evidence["firewall_runtime"],
            "application firewall runtime changed during route publication",
        )
    write_authority(path, record, prior, previous, generation, bindings)
    if private:
        if handoff is not None:
            store(RUNTIME / HANDOFF, handoff)
            changed = True
        if not bindings and not desired_configuration().applications:
            manifest = STATE / "application-units.json"
            observed = read_optional(manifest)
            require(observed in (None, []), "retired application ownership remains")
            if observed == []:
                remove_record(manifest)
                changed = True
    if routes and not private:
        changed = install_route_file(routes, evidence) or changed
    remove_record(RUNTIME / "hold")
    return changed


def observe_targets(host, targets):
    bindings = []
    for target in targets:
        observed = unit_running(host, target.binding)
        if observed is None and not target.enabled and manager_quiescent(host, target.binding):
            continue
        assert_authority(host, target.binding)
        require(
            observed is target.enabled,
            "application deployment state differs from target",
        )
        if target.enabled:
            verify_target_data(host, target)
            health_check(host, target, retry=False)
            bindings.append(target.binding)
    return bindings


def verify_previous_quiescent(host, previous, bindings):
    require(not previous.pending, "previous application startup requires recovery")
    for binding in previous.bindings:
        if binding not in bindings:
            verify_stop_identity(binding)
            observed = unit_running(host, binding)
            require(
                observed is False or (observed is None and manager_quiescent(host, binding)),
                "previous application unit remains active",
            )


def write_authority(path, record, prior, previous, generation, bindings):
    active = Active(generation, bindings, [])
    if previous != active:
        active.write()
    if record is None:
        path.unlink(missing_ok=True)
        sync_directory(path.parent)
    elif prior != record:
        store(path, record)


def inhibit(host, generation):
    path = RUNTIME / "hold"
    hold = read_optional(path)
    require(hold in (None, generation), "another application deployment holds the boot barrier")
    if hold is None:
        store(path, generation)
    return inhibit_routes(host, generation, fresh=hold is None)


def inhibit_routes(host, generation, *, fresh, private=None):
    if read_optional(RUNTIME / GUARDED_ROUTE_DRAIN) is not None:
        return drain_routes(host, private=private)
    present = route_present()
    try:
        record = read_optional(STATE / "application-boot.json")
    except EVIDENCE_ERRORS:
        if present:
            return drain_routes(host, private=private)
        raise
    same_generation = isinstance(record, dict) and record.get("generation") == generation
    if present:
        if same_generation:
            try:
                targets, evidence, routes = approved_inputs(record)
                verify_live_routes(host, generation, targets, evidence, routes)
            except EVIDENCE_ERRORS:
                return drain_routes(host, private=private)
        else:
            return drain_routes(host, private=private)
    return fresh and not same_generation


def remove_record(path):
    path.unlink()
    sync_directory(path.parent)


def require_routeless(cfg):
    require(
        not any(service.routes for app in cfg.applications for service in app.services)
        and not route_present()
        and not os.path.lexists(RUNTIME / GUARDED_ROUTE_DRAIN)
        and not os.path.lexists(RUNTIME / GUARDED_ROUTE_JOURNAL),
        "private application deployment requires absent routes and route-drain state",
    )


def private_hold(identity, revision, generation):
    return {
        "operation_id": identity.operation_id,
        "revision": revision,
        "generation": generation,
    }


def require_current_route_run(identity):
    from .executor.deployment_gate import BOOT_ID

    require(
        identity.boot_id == BOOT_ID.read_text().strip(),
        "guarded application route state belongs to another boot",
    )


def require_route_transition_clear(*, allow_drain=False):
    require(
        read_optional(RUNTIME / GUARDED_ROUTE_JOURNAL) is None
        and (allow_drain or read_optional(RUNTIME / GUARDED_ROUTE_DRAIN) is None),
        "guarded application route transition is unfinished",
    )


def guarded_route_generation(inputs):
    # Match the sorted JSON used by application-boot-inhibit.yml before the
    # firewall source digest is appended to the approval inputs.
    return digest(
        json.dumps(
            {"release": inputs["release"], "revision": inputs["revision"]}, sort_keys=True
        ).encode()
    )


def publish_guarded_routes(host, identity, record, targets, evidence, routes):
    generation = record["generation"]
    inputs = record["inputs"]
    present = route_present()
    if not routes:
        require(not present, "routeless guarded deployment has application routes")
        return
    if present:
        verify_live_routes(host, generation, targets, evidence, routes)
        return
    verify_proxy_running(host, evidence)
    verify_route_targets(host, targets, routes)
    require(
        verify_firewall(inputs, evidence) == evidence["firewall_runtime"],
        "application firewall runtime changed during route publication",
    )
    approved_digest = digest(render_application_proxy_routes(routes).encode())
    require(
        approved_digest == evidence["proxy"]["routes"],
        "guarded application route digest differs from approval",
    )
    proxy_directory(evidence["proxy"]["gid"])
    store(
        RUNTIME / GUARDED_ROUTE_JOURNAL,
        {
            **asdict(identity),
            "revision": inputs["revision"],
            "generation": generation,
            "routes": approved_digest,
        },
    )
    require(install_route_file(routes, evidence), "guarded application route publication changed")
    verify_live_routes(host, generation, targets, evidence, routes)


def route_run_identity(binding, *, publication=False):
    fields = {"operation_id", "run_id", "boot_id", "revision", "generation"}
    if publication:
        fields.add("routes")
    require(
        isinstance(binding, dict)
        and set(binding) == fields
        and is_digest(binding["revision"])
        and is_digest(binding["generation"])
        and (not publication or is_digest(binding["routes"])),
        "invalid guarded application route custody",
    )
    return Identity(binding["operation_id"], binding["run_id"], binding["boot_id"])


def reconcile_guarded_routes(host, identity, revision=None, *, committed=False, allow_early=True):
    # The caller holds deployment-execution and proves commit via the exact
    # receipt. Rollback can still use protected runtime evidence if SQLite fails.
    with runtime_lock():
        journal_path = RUNTIME / GUARDED_ROUTE_JOURNAL
        journal = read_optional(journal_path)
        if journal is not None:
            if route_run_identity(journal, publication=True) != identity:
                return False
            require_current_route_run(identity)
            require(
                revision == journal["revision"] or (revision is None and not committed),
                "guarded application route revision differs",
            )
            if not committed:
                # An unresolved journal excludes a successor. The exact run
                # owns the fixed path even if its contents or boot state drift.
                binding = {key: value for key, value in journal.items() if key != "routes"}
                try:
                    drain_routes(host, private=binding, may_be_loaded=True)
                except EVIDENCE_ERRORS:
                    # Late publication custody permits withdrawing the fixed
                    # path even if proxy identity cannot be used. Keep the
                    # journal until eviction can be proven independently.
                    if route_present():
                        volatile_run()
                        safe_directory(PROXY_RUNTIME)
                        route_path().unlink()
                        sync_directory(PROXY_RUNTIME)
                    raise
            else:
                require(
                    read_optional(RUNTIME / GUARDED_ROUTE_DRAIN) is None,
                    "committed application route drain is unfinished",
                )
            remove_record(journal_path)
            return True
        marker = read_optional(RUNTIME / GUARDED_ROUTE_DRAIN)
        if marker is None or not allow_early:
            return False
        require(
            isinstance(marker, dict)
            and set(marker) in ({"uid", "restore"}, {"uid", "restore", "private"})
            and type(marker["uid"]) is int
            and type(marker["restore"]) is bool,
            "invalid application route drain record",
        )
        if "private" not in marker:
            return False
        binding = marker["private"]
        if route_run_identity(binding) != identity:
            return False
        require_current_route_run(identity)
        require(
            not committed
            and revision in (None, binding["revision"])
            and read_optional(RUNTIME / "hold")
            == private_hold(identity, binding["revision"], binding["generation"]),
            "guarded application route drain differs from deployment hold",
        )
        return drain_routes(host, private=binding)


def inhibit_private(host, identity, revision, generation, *, routed):
    path = RUNTIME / "hold"
    hold = read_optional(path)
    expected = private_hold(identity, revision, generation)
    require(hold in (None, expected), "another application deployment holds the boot barrier")
    if routed:
        require(
            read_optional(RUNTIME / GUARDED_ROUTE_JOURNAL) is None,
            "guarded application route publication is unfinished",
        )
    if hold is None:
        store(path, expected)
    if routed:
        return inhibit_routes(
            host, generation, fresh=hold is None, private={**expected, **asdict(identity)}
        )
    record = read_optional(STATE / "application-boot.json")
    return hold is None and (not isinstance(record, dict) or record.get("generation") != generation)


def boot_unit_properties():
    from .executor.deployment_gate import run_systemd

    output = run_systemd(
        [
            "/usr/bin/systemctl",
            "--system",
            "show",
            "--property=LoadState,ActiveState,SubState,Result,UnitFileState,FragmentPath,"
            "MainPID,InvocationID,ControlGroup,DropInPaths,NeedDaemonReload",
            BOOT_UNIT,
        ],
        check=False,
    )
    return dict(line.split("=", 1) for line in output.decode("ascii").splitlines())


def boot_unit_digest():
    return digest(read_bytes(SYSTEMD / BOOT_UNIT, 0o644))


def require_boot_unit(props):
    require(
        props.get("LoadState") == "loaded"
        and props.get("FragmentPath") == str(SYSTEMD / BOOT_UNIT)
        and props.get("DropInPaths") == ""
        and props.get("NeedDaemonReload") == "no",
        "application boot unit has unexpected systemd authority",
    )


def boot_unit_ready(props):
    return (
        props.get("ActiveState") == "active"
        and props.get("SubState") == "exited"
        and props.get("Result") == "success"
        and props.get("MainPID") == "0"
    )


def planned_handoff(private, props, enabled):
    identity, revision, generation = private
    path = RUNTIME / HANDOFF
    prior = read_optional(path)
    expected = private_hold(identity, revision, generation)
    if prior is not None:
        old_identity = handoff_identity(prior)
        require(
            private_hold(old_identity, prior["revision"], prior["generation"]) == expected,
            "activation handoff belongs to another application deployment",
        )
    if not enabled or boot_unit_ready(props):
        require(prior is None, "unexpected activation handoff for a quiescent boot transition")
        return None
    receipt = {**asdict(identity), "revision": revision, "generation": generation}
    receipt["unit"] = boot_unit_digest()
    return None if prior == receipt else receipt


def handoff_identity(receipt):
    require(
        isinstance(receipt, dict)
        and set(receipt) == {"operation_id", "run_id", "boot_id", "revision", "generation", "unit"}
        and all(is_digest(receipt[key]) for key in ("revision", "generation", "unit")),
        "invalid application boot activation handoff",
    )
    return Identity(*(receipt[key] for key in ("operation_id", "run_id", "boot_id")))


def observe_guarded_authority(host, record, revision, *, routed=False):
    targets, evidence, routes = approved_inputs(record)
    require(
        record["inputs"]["revision"] == revision and (routed or not routes),
        "application authority differs from the private deployment",
    )
    bindings = observe_targets(host, targets)
    require(
        bindings and read_active() == Active(record["generation"], bindings, []),
        "running application ownership differs from its published authority",
    )
    return targets, evidence, routes


def adopt_private(host):
    from .executor.deployment_gate import PROC
    from .executor.deployment_launcher import ID
    from .executor.site_deployment import require_private_verifier

    props = boot_unit_properties()
    require_boot_unit(props)
    invocation = os.environ.get("INVOCATION_ID", "")
    cgroup = f"/system.slice/{BOOT_UNIT}"
    require(
        props.get("ActiveState") == "activating"
        and props.get("SubState") == "start"
        and props.get("MainPID") == str(os.getpid())
        and ID.fullmatch(invocation) is not None
        and props.get("InvocationID") == invocation
        and props.get("ControlGroup") == cgroup
        and (PROC / "self" / "cgroup").read_text() == f"0::{cgroup}\n",
        "application activation handoff requires the exact systemd MainPID",
    )
    path = RUNTIME / HANDOFF
    receipt = read_optional(path)
    identity = handoff_identity(receipt)
    revision = receipt["revision"]
    routed = require_private_verifier(identity, revision, scoped=False)
    if routed:
        require_route_transition_clear()
    else:
        require_routeless(desired_configuration())
    record = read_optional(STATE / "application-boot.json")
    require(
        isinstance(record, dict)
        and record.get("generation") == receipt["generation"]
        and receipt["unit"] == boot_unit_digest()
        and read_optional(RUNTIME / "hold") is None,
        "application activation handoff differs from published authority",
    )
    targets, evidence, routes = observe_guarded_authority(host, record, revision, routed=routed)
    if routed and route_present():
        verify_live_routes(host, receipt["generation"], targets, evidence, routes)
    require(
        require_private_verifier(identity, revision, scoped=False) == routed,
        "private application route authorization changed",
    )
    remove_record(path)
    return True


def verify_retired_targets(host, cfg):
    manifest = read_optional(STATE / "application-units.json")
    if not cfg.applications:
        require(manifest is None, "removed application manifest remains")
        return
    expected = []
    identities = {}
    applications = {app.id: app for app in cfg.applications}
    for app in render_application_quadlets(cfg, str(RELEASES / __version__)):
        configured = applications[app["id"]]
        ports = {service.id: service.host_port for service in configured.services}
        members = ([app["pod"]] if app["pod"] else []) + app["services"]
        for member in members:
            user = member["user"]
            if user not in identities:
                identities[user] = inspect_identity(user)
            binding = Binding(
                configured.id, member.get("id"), configured.isolation, identities[user]
            )
            require(
                binding.user == user and binding.unit == member["unit"], "wrong application binding"
            )
            observed = unit_running(host, binding)
            if not (observed is None and manager_quiescent(host, binding)):
                assert_authority(host, binding)
                require(observed is False, "disabled application workload is not quiescent")
            expected.append(
                {
                    "user": user,
                    "uid": binding.uid,
                    "identity": binding.identity,
                    "unit": binding.unit,
                    "port": ports.get(binding.service),
                }
            )
    require(
        isinstance(manifest, list)
        and sorted(manifest, key=lambda row: row["unit"])
        == sorted(expected, key=lambda row: row["unit"]),
        "retired application manifest differs from its declared bindings",
    )


def verify_guarded_deployment(host, revision, *, route_identity=None, route_generation=None):
    with runtime_lock():
        if route_identity is not None:
            require_current_route_run(route_identity)
            require_route_transition_clear()
        hold_path = RUNTIME / "hold"
        require(
            read_optional(RUNTIME / HANDOFF) is None and read_optional(hold_path) is None,
            "application boot transition is unfinished",
        )
        retained = route_identity is not None and route_present()
        record = None
        try:
            record = read_optional(STATE / "application-boot.json")
            verify_guarded_authority(host, revision, record, route_identity, route_generation)
        except EVIDENCE_ERRORS:
            if retained:
                if route_generation is None:
                    require(
                        isinstance(record, dict) and record["inputs"]["revision"] == revision,
                        "cannot bind retained application routes to the guarded deployment",
                    )
                    route_generation = guarded_route_generation(record["inputs"])
                require(is_digest(route_generation), "invalid guarded application route generation")
                hold = private_hold(route_identity, revision, route_generation)
                store(hold_path, hold)
                drain_routes(host, private={**hold, **asdict(route_identity)})
            raise


def verify_guarded_authority(host, revision, record, route_identity, route_generation):
    cfg = desired_configuration()
    if route_identity is None:
        require_routeless(cfg)
    require(revision_id(effective(cfg)) == revision, "private application revision differs")
    props = boot_unit_properties()
    if any(
        service.manage and service.deploy for app in cfg.applications for service in app.services
    ):
        boot_unit_digest()
        require_boot_unit(props)
        require(
            boot_unit_ready(props) and props.get("UnitFileState") == "enabled",
            "application boot unit has not been activated and enabled",
        )
        targets, evidence, routes = observe_guarded_authority(
            host, record, revision, routed=route_identity is not None
        )
        if route_identity is not None:
            expected = guarded_route_generation(record["inputs"])
            require(
                record["generation"] == expected and route_generation in (None, expected),
                "guarded application route generation differs",
            )
            publish_guarded_routes(host, route_identity, record, targets, evidence, routes)
    else:
        require(
            record is None
            and read_active() == Active(None, [], [])
            and not os.path.lexists(SYSTEMD / BOOT_UNIT)
            and props.get("LoadState") == "not-found"
            and props.get("ActiveState") == "inactive",
            "retired application boot authority remains",
        )
        verify_retired_targets(host, cfg)
        if route_identity is not None:
            require(not route_present(), "routeless guarded deployment has application routes")


def run_private(host, action, identity, revision, generation, inputs):
    from .executor.site_deployment import require_private_verifier

    routed = require_private_verifier(identity, revision)
    if not routed:
        require_routeless(desired_configuration())
    if action == "inhibit":
        return inhibit_private(host, identity, revision, generation, routed=routed)
    hold = private_hold(identity, revision, generation)
    require(read_optional(RUNTIME / "hold") == hold, "application deployment hold does not match")
    if action == "publish":
        require(
            isinstance(inputs, dict) and inputs.get("revision") == revision,
            "application publication does not match the private revision",
        )
        retained = routed and route_present()
        if retained:
            require_route_transition_clear()
        try:
            return publish_held(
                host, generation, inputs, private=(identity, revision, generation), routed=routed
            )
        except EVIDENCE_ERRORS:
            if retained and read_optional(RUNTIME / "hold") == hold:
                drain_routes(host, private={**hold, **asdict(identity)})
            raise
    if action == "drain-routes":
        require_route_transition_clear(allow_drain=True)
        return drain_routes(host, private={**hold, **asdict(identity)}) if routed else False
    active = read_active()
    verify_previous_quiescent(host, active, [])
    if active.bindings:
        Active(None, [], []).write()
        return True
    return False


def run_boot_action(host, action, generation, inputs, credentials):
    if credentials:
        with runtime_lock():
            return run_private(host, action, *credentials, generation, inputs)
    if (
        action == "start"
        and os.path.lexists(RUNTIME / HANDOFF)
        and read_deployment_fence() is not None
    ):
        with runtime_lock():
            return adopt_private(host)
    stop_hook = action in ("stop", "recover-start")
    if stop_hook and read_deployment_fence() is not None:
        # Guarded workload tasks own process changes. The unit's stop hooks
        # may be called by systemd while the coordinator holds the host lock.
        return False
    # An ordinary unit restart can overlap a registered group operation.
    # Wait within systemd's stop budget while preserving global-to-runtime order.
    wait = BOOT_DEPLOYMENT_LOCK_WAIT if stop_hook or action == "start" else 0
    with deployment_lock(timeout=wait):
        if stop_hook and read_deployment_fence() is not None:
            return False
        with runtime_lock():
            require(
                read_optional(RUNTIME / HANDOFF) is None,
                "application activation handoff is pending",
            )
            require(
                read_optional(RUNTIME / GUARDED_ROUTE_JOURNAL) is None,
                "guarded application route publication is unfinished",
            )
            if action == "start":
                return start(host)
            if not stop_hook:
                require(read_deployment_fence() is None, "executor deployment recovery is pending")
            if action == "inhibit":
                return inhibit(host, generation)
            if action == "drain-routes":
                require(
                    read_optional(RUNTIME / "hold") == generation,
                    "application deployment hold does not match",
                )
                return drain_routes(host)
            if action == "publish":
                return publish(host, generation, inputs)
            active = read_active()
            pending_only = action == "recover-start"
            changed = drain_routes(host) if not pending_only or active.pending else False
            return stop_bindings(host, active, pending_only=pending_only) or changed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action", choices=("inhibit", "publish", "start", "stop", "recover-start", "drain-routes")
    )
    parser.add_argument("generation", nargs="?")
    parser.add_argument("--deployment-operation-id")
    parser.add_argument("--deployment-run-id")
    parser.add_argument("--deployment-boot-id")
    parser.add_argument("--deployment-revision")
    args = parser.parse_args()
    identifiers = (args.deployment_operation_id, args.deployment_run_id, args.deployment_boot_id)
    private = any(value is not None for value in (*identifiers, args.deployment_revision))
    if (
        args.action in ("inhibit", "publish", "drain-routes")
        and not is_digest(args.generation)
        or args.action in ("start", "recover-start")
        and args.generation is not None
        or args.action == "stop"
        and (not is_digest(args.generation) if private else args.generation is not None)
        or private
        and (
            args.action not in ("inhibit", "publish", "stop", "drain-routes")
            or not is_digest(args.deployment_revision)
            or any(value is None for value in identifiers)
        )
    ):
        parser.error("invalid application boot arguments")
    try:
        require(os.geteuid() == 0, "application boot is root-only")
        inputs = None
        if args.action == "publish":
            raw = sys.stdin.buffer.read(LIMIT + 1)
            require(len(raw) <= LIMIT, "application approval input exceeds size limit")
            inputs = json.loads(raw)
        credentials = (Identity(*identifiers), args.deployment_revision) if private else None
        changed = run_boot_action(Host(), args.action, args.generation, inputs, credentials)
        print(json.dumps({"changed": changed}))
    except EVIDENCE_ERRORS as error:
        message = (
            str(error) if isinstance(error, BootError) else "invalid or unavailable host evidence"
        )
        sys.exit(f"application boot {args.action}: {message}")


if __name__ == "__main__":
    main()
