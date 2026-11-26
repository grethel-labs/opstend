"""Root coordinator for execution of an enrolled site deployment."""

from __future__ import annotations

import argparse
import grp
import hashlib
import http.client
import json
import os
import pwd
import re
import secrets
import select
import signal
import sqlite3
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import closing as close_connection
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path

from .. import application_boot as boot
from ..controller import evaluate
from ..core import app_archive
from ..core.backups import BackupError
from ..core.canonical import canonical_json, revision_id
from ..core.config import ConfigError, effective, parse_config
from ..core.group_checkpoint import DeploymentFence
from ..core.render import (
    APPLICATION_PROXY_ROUTES,
    PLATFORM_UNITS,
    prepare_application_registry,
    render_registry,
)
from ..core.retirement import Candidate, plan_retirements
from . import deployment_enrollment as enrollment
from . import deployment_gate as gate
from . import retirement
from .deployment_launcher import ID, GateError, Identity, parse_json
from .host import Host, process_namespace
from .protocol import ExecutorError, call
from .server import (
    AUDIT_PATH,
    LOCK_DIR,
    REGISTRY_PATH,
    STATE_DIR,
    Executor,
    NoParams,
    platform_status,
)

PYTHON = "/opt/steward/current/venv/bin/python"
SYSTEMCTL = ["/usr/bin/systemctl", "--system"]
COMMAND = "steward.executor.site_deployment"
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,39}")
START_WAIT = 25
FINISH_WAIT = 90
API_STATE = Path("/var/lib/steward-api")
RETIREMENT_PROTOCOL = "retirement_protocol"
UNVERIFIED = ("reserved", "active", "closing", "revoking", "pending")
ERRORS = (
    boot.BootError,
    ConfigError,
    ExecutorError,
    GateError,
    KeyError,
    OSError,
    TypeError,
    ValueError,
    TimeoutError,
    sqlite3.Error,
    subprocess.SubprocessError,
    http.client.HTTPException,
)


def executor():
    boot.read_deployment_fence()
    boot.safe_directory(Path(LOCK_DIR))
    return Executor(
        registry_path=REGISTRY_PATH, state_dir=STATE_DIR, audit_path=AUDIT_PATH, lock_dir=LOCK_DIR
    )


def identity_from(data):
    return Identity(*(data[name] for name in ("operation_id", "run_id", "boot_id")))


def public(record, state=None):
    result = {
        name: record[name] for name in ("operation_id", "run_id", "boot_id", "desired_revision")
    }
    if state is not None:
        result["state"] = state
    return result


def read_marker():
    marker = parse_json(enrollment.read_limited(enrollment.INSTALL, 0o644, enrollment.RECORD_LIMIT))
    boot.require(
        set(marker) == {"server_name", "schema_version", "state"}
        and type(marker["schema_version"]) is int
        and marker["schema_version"] in (1, 2)
        and marker["state"] == "installed"
        and isinstance(marker["server_name"], str)
        and boot.SLUG.fullmatch(marker["server_name"]) is not None,
        "invalid installed Steward marker",
    )
    return marker


def enrollment_evidence(marker):
    boot.safe_directory(enrollment.STATE)
    record = parse_json(
        enrollment.read_limited(
            enrollment.STATE / "deployment-enrollment-v1.json", 0o600, enrollment.RECORD_LIMIT
        )
    )
    boot.require(
        set(record) == {"v", "server_name", "wheel_sha256", "launcher_sha256"}
        and type(record["v"]) is int
        and record["v"] == 1
        and record["server_name"] == marker["server_name"]
        and boot.is_digest(record["wheel_sha256"])
        and boot.is_digest(record["launcher_sha256"]),
        "invalid protected deployment enrollment",
    )
    launcher = enrollment.LIBEXEC / "steward" / "deployment-v1" / "launch.py"
    data = enrollment.read_limited(launcher, 0o644, enrollment.LAUNCHER_LIMIT)
    for directory in (enrollment.LIBEXEC, launcher.parent.parent, launcher.parent):
        enrollment.require_launcher_access(directory)
    boot.require(
        boot.digest(data) == record["launcher_sha256"], "deployment launcher bytes changed"
    )


def graph_free():
    for path in (
        boot.STATE / "application-boot.json",
        boot.STATE / "application-units.json",
        boot.RUNTIME / "active.json",
        boot.RUNTIME / "hold",
        boot.RUNTIME / boot.HANDOFF,
        boot.RUNTIME / boot.GUARDED_ROUTE_DRAIN,
        boot.RUNTIME / boot.GUARDED_ROUTE_JOURNAL,
        boot.SYSTEMD / "steward-applications.service",
        boot.CONFIG / "proxy" / "dynamic" / APPLICATION_PROXY_ROUTES,
        boot.route_path(),
    ):
        boot.require(
            not os.path.lexists(path), "application boot ownership prevents site deployment"
        )


def declared_routes(cfg):
    return tuple(
        route for app in cfg.applications for service in app.services for route in service.routes
    )


def config_from(data, *, installed=False, private=False, routed=False):
    cfg = parse_config(data, allow_unavailable=installed or private)
    boot.require(
        (private or not cfg.applications)
        and canonical_json(data) == canonical_json(effective(cfg)),
        "site deployment requires a graph-free, strictly typed effective configuration",
    )
    if private:
        boot.require(
            set(cfg.unavailable_features()) <= {"applications"}
            and (not cfg.applications or cfg.hardening.firewall.manage),
            "unsupported private application deployment configuration",
        )
        check_declared_routes(cfg, routed)
    return cfg


def check_declared_routes(cfg, routed):
    routes = declared_routes(cfg)
    if routed:
        boot.require(
            all(route.tls == "internal" for route in routes),
            "application routes must use internal TLS",
        )
    else:
        boot.require(
            not routes, "private application deployment requires a routeless application graph"
        )


def require_no_application_routes(*, routed=False):
    paths = [boot.CONFIG / "proxy" / "dynamic" / APPLICATION_PROXY_ROUTES]
    if not routed:
        paths.extend(
            boot.RUNTIME / name for name in (boot.GUARDED_ROUTE_DRAIN, boot.GUARDED_ROUTE_JOURNAL)
        )
    for path in paths:
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        raise boot.BootError("application route evidence prevents private deployment")
    if not routed:
        boot.require(
            not boot.route_present(), "application route evidence prevents private deployment"
        )


def private_grant_binding(server_name, base_revision, desired_revision, release_hash):
    grant = parse_json(
        enrollment.read_limited(
            boot.STATE / "private-application-site.json", 0o600, enrollment.RECORD_LIMIT
        )
    )
    expected = {
        "version": 1,
        "server_name": server_name,
        "base_revision": base_revision,
        "desired_revision": desired_revision,
        "release_hash": release_hash,
    }
    routed = isinstance(grant, dict) and grant.get("version") == 2
    if routed:
        expected.update(version=2, application_routes="internal")
    boot.require(
        canonical_json(grant) == canonical_json(expected),
        "private application deployment grant differs from the exact transition",
    )
    return revision_id(grant), routed


def requested_grant_binding(request, cfg):
    return private_grant_binding(
        cfg.server.name,
        request["base_revision"],
        revision_id(effective(cfg)),
        revision_id(request["release"]),
    )


def require_private_grant(record):
    actual, routed = private_grant_binding(
        record["registry"]["server_name"],
        record["base_revision"],
        record["desired_revision"],
        revision_id(release_binding(record["release"])),
    )
    boot.require(
        actual == record.get("private_grant_hash")
        and (
            record.get("application_routes") == "internal"
            if routed
            else "application_routes" not in record
        ),
        "private application deployment grant differs from durable custody",
    )
    return routed


def installed_config(*, require_matching_registry=True, private=False, routed=False):
    boot.safe_directory(boot.CONFIG)
    registry = parse_json(boot.read_bytes(Path(REGISTRY_PATH)))
    desired = parse_json(
        boot.read_bytes(
            boot.CONFIG / "config" / "desired.json", 0o640, grp.getgrnam("steward-api").gr_gid
        )
    )
    cfg = config_from(desired, installed=True, private=private, routed=routed)
    boot.require(
        (private or registry.get("applications", {}) == {})
        and (
            not require_matching_registry or registry.get("config_revision") == revision_id(desired)
        )
        and registry.get("server_name") == cfg.server.name,
        "protected desired configuration and executor registry disagree",
    )
    if private:
        require_no_application_routes(routed=routed)
    else:
        graph_free()
    return cfg, registry


def release_binding(release):
    boot.require(
        isinstance(release, dict) and set(release) == {"version", "wheel", "files"},
        "invalid deployment release",
    )
    version, wheel, files = (release[key] for key in ("version", "wheel", "files"))
    boot.require(
        isinstance(version, str)
        and VERSION.fullmatch(version) is not None
        and wheel == f"steward-{version}-py3-none-any.whl"
        and isinstance(files, dict)
        and 3 <= len(files) <= 4096
        and wheel in files
        and "requirements.txt" in files,
        "incomplete deployment release",
    )
    for name, sha in files.items():
        parts = name.split("/")
        boot.require(
            boot.is_digest(sha)
            and all(boot.FILE.fullmatch(part) and part not in (".", "..") for part in parts)
            and (
                name in (wheel, "requirements.txt") or (len(parts) >= 3 and parts[0] == "bundles")
            ),
            "invalid deployment release artifact",
        )
    return release


def verify_release(release):
    release_binding(release)
    path = boot.RELEASES / release["version"]
    boot.safe_directory(path)
    boot.require(
        active_release() == release["version"],
        "active release differs from the deployment binding",
    )
    for name, digest in release["files"].items():
        artifact = path / name if name.startswith("bundles/") else path / "dist" / name
        with boot.protected(artifact, 0o644) as handle:
            boot.require(
                hashlib.file_digest(handle, "sha256").hexdigest() == digest,
                "installed release artifact differs from the deployment binding",
            )
    for bundle in {name.split("/")[1] for name in release["files"] if name.startswith("bundles/")}:
        boot.require_bundle(path, bundle, release["files"])


def activate():
    ex = executor()
    with ex.target_lock("deployment-execution"), gate.control_lock():
        boot.require(ex.deployment_fence() is None, "deployment fence is active")
        require_empty_gate()
        marker = read_marker()
        cfg, _ = installed_config()
        boot.require(marker["server_name"] == cfg.server.name, "installed server identity changed")
        enrollment_evidence(marker)
        if marker["schema_version"] == 2:
            return marker
        marker["schema_version"] = 2
        path = enrollment.INSTALL
        fd, temporary = tempfile.mkstemp(dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="ascii") as output:
                json.dump(marker, output, sort_keys=True)
                output.write("\n")
                output.flush()
                os.fchown(output.fileno(), 0, 0)
                os.fchmod(output.fileno(), 0o644)
                os.fsync(output.fileno())
            os.replace(temporary, path)
            boot.sync_directory(path.parent)
        finally:
            Path(temporary).unlink(missing_ok=True)
        return marker


def require_empty_gate():
    boot.require(
        not os.path.lexists(gate.record_path()) and not os.path.lexists(gate.RUNTIME / "gate.sock"),
        "deployment gate requires exact cleanup",
    )


def login_uid(user):
    uid = pwd.getpwnam(user).pw_uid
    sudo_uid = os.environ.get("SUDO_UID")
    sudo_user = os.environ.get("SUDO_USER")
    boot.require(
        (uid == 0 and sudo_uid is None and sudo_user is None)
        or (sudo_uid == str(uid) and sudo_user == user),
        "deployment SSH login does not match the protected configuration",
    )
    return uid


def validate_request(request, *, private=False, routed=False):
    fields = {"base_revision", "config", "release"}
    if private and RETIREMENT_PROTOCOL in request:
        fields.add(RETIREMENT_PROTOCOL)
        marker = request[RETIREMENT_PROTOCOL]
        boot.require(type(marker) is int and marker == 1, "unsupported retirement protocol")
    boot.require(
        set(request) == fields and boot.is_digest(request["base_revision"]),
        "invalid deployment request",
    )
    cfg = config_from(request["config"], private=private, routed=routed)
    release_binding(request["release"])
    return cfg


def validate_base(request, cfg, *, private=False, routed=False):
    marker = read_marker()
    boot.require(marker["schema_version"] == 2, "guarded site deployment is not activated")
    enrollment_evidence(marker)
    if routed:
        base, registry = installed_config(private=True, routed=True)
    else:
        base, registry = installed_config(private=True) if private else installed_config()
    boot.require(
        registry["config_revision"] == request["base_revision"]
        and marker["server_name"] == cfg.server.name == base.server.name
        and cfg.server.user == base.server.user
        and cfg.server.host == base.server.host
        and cfg.server.port == base.server.port,
        "configuration base revision or deployment server/login identity changed",
    )
    if private:
        check_declared_routes(cfg, routed)
        boot.require(
            bool(declared_routes(base) or declared_routes(cfg)) == routed,
            "private application grant does not match the base and target routes",
        )
        boot.require(
            bool(base.applications or cfg.applications),
            "private application grant requires an application base or target",
        )
        if not base.applications:
            graph_free()
        verify_registry(base, registry, deployment_registry(base, registry["release"]))
        target_applications = prepare_application_registry(cfg)["applications"]
        retained = {
            service["unit"]
            for app in target_applications.values()
            for service in app["services"].values()
            if service["manage"]
        }
        boot.require(
            all(
                service["unit"] in retained
                or not service["deploy"]
                or RETIREMENT_PROTOCOL in request
                and name not in target_applications
                for name, app in registry.get("applications", {}).items()
                for service in app["services"].values()
                if service["manage"]
            ),
            "application services must be disabled before retirement",
        )
    return base, registry


def fresh_retirements(request, registry, cfg, *, private):
    if not private:
        return []
    candidates = plan_retirements(registry, prepare_application_registry(cfg)).candidates
    boot.require(
        bool(candidates) == (RETIREMENT_PROTOCOL in request),
        "private application removal requires the retirement protocol",
    )
    for candidate in candidates:
        boot.require(
            candidate.stage in ("ready", "needs_disable"),
            f"application retirement is blocked: {candidate.stage}",
        )
    return candidates


def require_retirement_release(record):
    boot.require(
        record["base_release"] == record["release"]["version"]
        and record["base_artifact_hash"] == revision_id(record["release"]["files"]),
        "application removal requires the exact installed release; stage upgrades separately",
    )


def unit(identity):
    return f"stewardsite{identity.run_id}.service"


def request_path(identity):
    return gate.RUNTIME / f"request-{identity.operation_id}-{identity.run_id}.json"


def unit_properties(identity):
    output = gate.run_systemd(
        [
            *SYSTEMCTL,
            "show",
            "--property=InvocationID,MainPID,ExecMainStartTimestampMonotonic,ControlGroup,ActiveState",
            unit(identity),
        ],
        check=False,
    )
    return dict(line.split("=", 1) for line in output.decode("ascii").splitlines())


def process_identity(identity):
    inv = os.environ.get("INVOCATION_ID", "")
    props = unit_properties(identity)
    pid = os.getpid()
    boot.require(
        ID.fullmatch(inv) is not None
        and props.get("InvocationID") == inv
        and props.get("MainPID") == str(pid)
        and props.get("ControlGroup") == f"/system.slice/{unit(identity)}"
        and props.get("ExecMainStartTimestampMonotonic", "").isdigit(),
        "coordinator must be the exact systemd MainPID",
    )
    return {
        "invocation": inv,
        "pid": pid,
        "start": process_namespace(gate.PROC / str(pid))[0],
        "systemd_start": props["ExecMainStartTimestampMonotonic"],
    }


@contextmanager
def live_process(record):
    identity = identity_from(record)
    binding = record["process"]
    boot.require(
        identity.boot_id == gate.BOOT_ID.read_text().strip(), "deployment belongs to another boot"
    )
    pid = binding["pid"]
    fd = os.pidfd_open(pid)
    try:
        props = unit_properties(identity)
        boot.require(
            props.get("InvocationID") == binding["invocation"]
            and props.get("MainPID") == str(pid)
            and props.get("ExecMainStartTimestampMonotonic") == binding["systemd_start"]
            and props.get("ActiveState") == "active"
            and process_namespace(gate.PROC / str(pid))[0] == binding["start"],
            "the recorded deployment coordinator is not active",
        )
        gate.require_member(pid, fd, f"/system.slice/{unit(identity)}")
        yield fd
    finally:
        os.close(fd)


def find_record(db, operation_id):
    row = db.execute(
        "SELECT state, body FROM site_deployments WHERE operation_id=?", (operation_id,)
    ).fetchone()
    if row is None:
        raise GateError("deployment custody does not match a known operation")
    state, body = row
    record = parse_json(body)
    boot.require(identity_from(record).operation_id == operation_id, "deployment operation changed")
    boot.require(boot.is_digest(record["desired_revision"]), "invalid deployment revision")
    return state, record


def get_record(db, identity):
    state, record = find_record(db, identity.operation_id)
    boot.require(identity_from(record) == identity, "deployment run or boot does not match")
    return state, record


def live_state(record, state):
    if state in ("complete", "revoked", "pending"):
        return state
    if state in ("active", "closing"):
        identity = identity_from(record)
        try:
            with live_process(record):
                gate.require_fence(identity.operation_id)
                if state == "active":
                    boot.require(
                        gate.read_record() == gate.Record(identity, record["uid"])
                        and (gate.RUNTIME / "gate.sock").is_socket(),
                        "deployment intake is unavailable",
                    )
        except ERRORS:
            return "pending"
        return state
    boot.require(state in ("reserved", "revoking"), "unknown deployment state")
    return "pending"


def status(ex, identity, *, admission=False):
    with ex._db() as db:
        state, record = get_record(db, identity)
    result = public(record, live_state(record, state))
    if admission and result["state"] == "active" and "retirement" in record:
        result["retirement_required"] = True
    return result


def fence_in(db):
    row = db.execute("SELECT body FROM deployment_fence WHERE singleton=1").fetchone()
    return DeploymentFence.model_validate_json(row[0]) if row else None


def bound_metadata(fence, record):
    boot.require(
        fence is not None
        and fence.operation_id == record["operation_id"]
        and fence.desired_revision == record["desired_revision"]
        and record.get("base_revision", fence.base_revision) == fence.base_revision,
        "deployment custody differs from the durable fence",
    )
    release_hash = revision_id(release_binding(record["release"]))
    boot.require(
        record.get("release_hash", release_hash) == release_hash,
        "deployment release binding changed",
    )
    return fence.base_revision, release_hash


def query_status(db, operation_id=None):
    fence = fence_in(db)
    if operation_id is None:
        if fence is None:
            return None
        operation_id = fence.operation_id
    state, record = find_record(db, operation_id)
    if state == "complete":
        boot.require(
            fence is None or fence.operation_id != operation_id,
            "completed deployment still has a pending fence",
        )
        base_revision = record.get("base_revision")
        release_hash = record.get("release_hash")
    else:
        base_revision, release_hash = bound_metadata(fence, record)
    boot.require(
        all(value is None or boot.is_digest(value) for value in (base_revision, release_hash)),
        "invalid deployment binding metadata",
    )
    return {
        **public(record, live_state(record, state)),
        "base_revision": base_revision,
        "release_hash": release_hash,
    }


def begin(request, *, private=False):
    cfg = validate_request(request, private=private, routed=private)
    grant_hash, routed = requested_grant_binding(request, cfg) if private else (None, False)
    base, registry = validate_base(request, cfg, private=private, routed=routed)
    fresh_retirements(request, registry, cfg, private=private)
    uid = login_uid(base.server.user)
    ex = executor()
    identity = Identity(
        secrets.token_hex(16), secrets.token_hex(16), gate.BOOT_ID.read_text().strip()
    )
    with gate.control_lock():
        require_empty_gate()
        boot.require(ex.deployment_fence() is None, "deployment fence is active")
        boot.require_route_transition_clear()
        write_request(identity, request, uid, private_grant_hash=grant_hash, routed=routed)
    return start_coordinator(ex, identity, routed=routed)


def write_request(identity, request, uid, previous=None, *, private_grant_hash=None, routed=False):
    payload = {"request": request, "uid": uid, **asdict(identity)}
    if previous is not None:
        payload["previous"] = asdict(previous)
    if private_grant_hash is not None:
        payload["private_grant_hash"] = private_grant_hash
    if routed:
        payload["application_routes"] = "internal"
    boot.store(request_path(identity), payload)


def coordinator_python():
    path = boot.RELEASES / active_release() / "venv" / "bin" / "python"
    boot.safe_directory(path.parent)
    boot.require(
        path.is_file() and os.access(path, os.X_OK), "admission release lacks its interpreter"
    )
    return str(path)


def start_coordinator(ex, identity, *, routed=False):
    try:
        python = coordinator_python() if routed else PYTHON
        tokens = [identity.operation_id, identity.run_id, identity.boot_id]
        stop_hook = []
        if routed:
            command = " ".join([python, "-I", "-m", COMMAND, "_route_stop", *tokens])
            stop_hook = [f"--property=ExecStopPost={command}"]
        gate.run_systemd(
            [
                "/usr/bin/systemd-run",
                "--system",
                f"--unit={unit(identity)}",
                "--property=Type=exec",
                "--property=Restart=no",
                "--property=RuntimeMaxSec=60min",
                "--property=TimeoutStopSec=60s" if routed else "--property=TimeoutStopSec=10s",
                "--property=UMask=0077",
                *stop_hook,
                python,
                "-I",
                "-m",
                COMMAND,
                "_coordinate",
                *tokens,
            ]
        )
        deadline = time.monotonic() + START_WAIT
        while time.monotonic() < deadline:
            try:
                receipt = status(ex, identity, admission=True)
            except (boot.BootError, GateError):
                receipt = None
            if receipt is not None and receipt.pop("state") == "active":
                return receipt
            props = unit_properties(identity)
            if stopped_unit(props):
                raise GateError("deployment coordinator exited before confirming readiness")
            time.sleep(0.2)
        raise GateError("deployment coordinator did not confirm readiness")
    except ERRORS as error:
        raise GateError(
            f"deployment start unconfirmed ({json.dumps(asdict(identity))}): {error}"
        ) from error
    finally:
        request_path(identity).unlink(missing_ok=True)


def transition(db, identity, before, after):
    state, record = get_record(db, identity)
    boot.require(state in before, "deployment state changed")
    db.execute(
        "UPDATE site_deployments SET state=? WHERE operation_id=?", (after, identity.operation_id)
    )
    return record


def check_platform(ex, registry, cfg):
    observed = platform_status(ex, NoParams(), "operator", registry)
    boot.require(
        observed["deployment_recovery"] == "pending", "deployment fence evidence is unavailable"
    )
    findings = evaluate(observed, {name: 10**6 for name in observed["projects"]})
    blockers = [
        finding.id
        for finding in findings
        if finding.severity in ("high", "critical") and finding.id != "deployment_recovery"
    ]
    boot.require(not blockers, "platform verification failed: " + ", ".join(blockers))

    active = set(registry["platform_units"])
    for name in set(PLATFORM_UNITS) - active:
        output = (
            gate.run_systemd([*SYSTEMCTL, "show", "--property=ActiveState,UnitFileState", name])
            .decode("ascii")
            .splitlines()
        )
        boot.require(
            "UnitFileState=disabled" in output
            and ("ActiveState=inactive" in output or "ActiveState=failed" in output),
            f"unconfigured platform unit is active or enabled: {name}",
        )
    coverage = call("events_coverage", socket_path="/run/steward-collector/query.sock")
    boot.require(type(coverage.get("count")) is int, "collector did not report event coverage")
    if cfg.backup.enabled:
        gate.run_systemd([*SYSTEMCTL, "is-active", "--quiet", "steward-backup.service"])
    gate.run_systemd(["/usr/sbin/sshd", "-t"])
    gate.run_systemd([*SYSTEMCTL, "is-active", "--quiet", "ssh.service"])
    admin_hosts = ["localhost"]
    if cfg.admin.access == "private-lan":
        lan = cfg.admin.lan
        boot.require(
            lan is not None and lan.bind is not None, "private LAN admin bind is unresolved"
        )
        admin_hosts.append(str(lan.bind.ip))
    context = ssl.create_default_context(cafile=str(boot.CONFIG / "pki" / "ca.crt"))
    for hostname in admin_hosts:
        conn = http.client.HTTPSConnection(hostname, cfg.admin.port, timeout=5, context=context)
        try:
            conn.request("GET", "/api/session")
            boot.require(
                conn.getresponse().status == 401,
                f"admin TLS/session verification failed for {hostname}",
            )
        finally:
            conn.close()


def deployment_registry(cfg, release):
    if not cfg.applications:
        return {**render_registry(cfg), "release": release}
    legacy_cfg = cfg.model_copy(update={"applications": []})
    return {
        **render_registry(legacy_cfg),
        **prepare_application_registry(cfg),
        "release": release,
    }


def verify_registry(cfg, registry, expected):
    peers = {
        "api": pwd.getpwnam("steward-api").pw_uid,
        "controller": pwd.getpwnam("steward-ctl").pw_uid,
        "collector": pwd.getpwnam("steward-col").pw_uid,
        "scanner": pwd.getpwnam("steward-scan").pw_uid,
    }
    if cfg.backup.enabled:
        peers["backup"] = pwd.getpwnam("steward-backup").pw_uid
    boot.require(
        canonical_json(registry) == canonical_json({**expected, "peers": peers}),
        "installed executor registry differs from the deployment binding",
    )


def verify_configuration(record):
    marker = read_marker()
    private = "private_grant_hash" in record
    routed = require_private_grant(record) if private else False
    if routed:
        cfg, registry = installed_config(private=True, routed=True)
    else:
        cfg, registry = installed_config(private=True) if private else installed_config()
    enrollment_evidence(marker)
    boot.require(
        marker["schema_version"] == 2
        and marker["server_name"] == cfg.server.name
        and registry["config_revision"] == record["desired_revision"],
        "installed configuration differs from the deployment binding",
    )
    verify_registry(cfg, registry, record["registry"])
    verify_release(record["release"])
    return cfg, registry


def commit_success(ex, identity, fence, record):
    with ex._db() as db:
        db.execute("BEGIN IMMEDIATE")
        state, latest = get_record(db, identity)
        boot.require(
            state == "closing" and latest.get("retirement") == record.get("retirement"),
            "deployment state or retirement evidence changed",
        )
        row = db.execute("SELECT body FROM deployment_fence WHERE singleton=1").fetchone()
        boot.require(row == (fence.model_dump_json(),), "deployment fence changed")
        # The audit append is durable before SQLite commits. An interrupted
        # transaction can leave this verification evidence with a pending fence.
        entry = ex.audit.append(
            "deployment",
            revision=record["desired_revision"],
            release=record["release"]["version"],
            outcome="host_verified",
            **asdict(identity),
        )
        receipt = {**public(record), "audit_hash": entry["hash"]}
        for field in (
            "base_revision",
            "release_hash",
            "private_grant_hash",
            "application_routes",
            "retirement",
        ):
            if field in record:
                receipt[field] = record[field]
        if record.get("application_routes") == "internal":
            receipt["process"] = record["process"]
        db.execute(
            "UPDATE site_deployments SET state='complete', body=? WHERE operation_id=?",
            (canonical_json(receipt), identity.operation_id),
        )
        db.execute("DELETE FROM deployment_fence WHERE singleton=1")


def active_release():
    current = boot.RELEASES.parent / "current"
    boot.safe_directory(current.parent)
    info = current.lstat()
    target = Path(os.readlink(current))
    boot.require(
        stat.S_ISLNK(info.st_mode)
        and info.st_uid == 0
        and VERSION.fullmatch(target.name) is not None
        and target == boot.RELEASES / target.name,
        "unrecognized active release",
    )
    return target.name


def base_artifact_hash(version):
    boot.require(
        isinstance(version, str) and VERSION.fullmatch(version) is not None,
        "unrecognized base release",
    )
    path = boot.RELEASES / version
    boot.safe_directory(path / "bundles")
    files = {}
    for name in (f"steward-{version}-py3-none-any.whl", "requirements.txt"):
        with boot.protected(path / "dist" / name, 0o644) as handle:
            files[name] = hashlib.file_digest(handle, "sha256").hexdigest()
    for current, directories, names in os.walk(path / "bundles", onerror=boot.raise_walk_error):
        for directory in directories:
            boot.safe_directory(Path(current) / directory)
        for name in names:
            artifact = Path(current) / name
            boot.require(len(files) < 4096, "base release exceeds deployment artifact limit")
            with boot.protected(artifact, 0o644) as handle:
                files[artifact.relative_to(path).as_posix()] = hashlib.file_digest(
                    handle, "sha256"
                ).hexdigest()
    return revision_id(files)


def check_base_release(version, release, base_hash=None):
    active = active_release()
    if active == version and base_hash is not None and base_artifact_hash(version) == base_hash:
        return
    if active == release["version"]:
        verify_release(release)
        return
    boot.require(active == version, "unrecognized active release")
    boot.require(base_hash is None, "base release artifacts changed")
    base_artifact_hash(version)


def retirement_evidence(record, *, complete=False):
    evidence = record["retirement"]
    boot.require(
        isinstance(evidence, dict)
        and set(evidence) == {"candidates", "receipts"}
        and isinstance(evidence["candidates"], list)
        and isinstance(evidence["receipts"], dict),
        "invalid deployment retirement evidence",
    )
    candidates = [Candidate.model_validate(item) for item in evidence["candidates"]]
    names = [candidate.application for candidate in candidates]
    receipts = evidence["receipts"]
    boot.require(
        bool(names)
        and names == sorted(set(names))
        and all(candidate.stage in ("ready", "needs_disable") for candidate in candidates)
        and set(receipts) <= set(names)
        and (not complete or set(receipts) == set(names)),
        "deployment retirement receipts are incomplete or do not match the roster",
    )
    return candidates, receipts


def require_retirement_base(fence, record, installed, registry):
    boot.require(
        revision_id(effective(installed)) == fence.base_revision
        and registry["config_revision"] == fence.base_revision
        and revision_id(registry) == record["base_registry_hash"],
        "retirement requires the exact protected deployment base",
    )
    desired = {
        **record["registry"],
        "applications": record["registry"].get("applications", {}),
    }
    candidates, _ = retirement_evidence(record)
    boot.require(
        plan_retirements(registry, desired).candidates == candidates,
        "retirement roster differs from the protected deployment base",
    )


def verify_retirement_receipt(fence, candidate, receipt):
    boot.require(
        isinstance(receipt, dict)
        and set(receipt) == {"operation_id", "archive_id", "released"}
        and isinstance(receipt["operation_id"], str)
        and ID.fullmatch(receipt["operation_id"]) is not None
        and boot.is_digest(receipt["archive_id"]),
        "invalid released application retirement receipt",
    )
    application = candidate.application
    expected_release = {
        name: "deleted" if name in candidate.data_services else "pending"
        for name in candidate.services
    }
    try:
        state = app_archive.active_operation(app_archive.ARCHIVE_ROOT, application)
    except BackupError as error:
        raise boot.BootError("released retirement journal could not be verified") from error
    boot.require(
        state is not None
        and state.phase == "released"
        and state.operation_id == receipt["operation_id"]
        and state.manifest_id == receipt["archive_id"]
        and state.applied_revision == fence.base_revision
        and state.desired_revision == fence.desired_revision
        and state.released == receipt["released"] == expected_release,
        "retirement archive journal differs from its release receipt",
    )


def verify_retirement_receipts(fence, record, *, complete):
    bound_metadata(fence, record)
    candidates, receipts = retirement_evidence(record, complete=complete)
    for candidate in candidates:
        if candidate.application in receipts:
            verify_retirement_receipt(fence, candidate, receipts[candidate.application])
    return candidates, receipts


def retire_before_cutover(ex, identity, revision):
    require_active_verifier(
        identity, revision, private_only=True, scoped=True, retiring=True, ex=ex
    )
    with boot.runtime_lock():

        def active():
            routed = require_active_verifier(
                identity, revision, private_only=True, scoped=True, retiring=True, ex=ex
            )
            with ex._db() as db:
                db.execute("BEGIN")
                state, record = get_record(db, identity)
                fence = fence_in(db)
            boot.require(
                state == "active" and "retirement" in record,
                "deployment has no active retirement roster",
            )
            bound_metadata(fence, record)
            require_retirement_release(record)
            return routed, fence, record

        routed, fence, record = active()
        candidates, receipts = verify_retirement_receipts(fence, record, complete=False)
        if len(candidates) == len(receipts):
            return {"changed": False}
        release = record["release"]
        generation = boot.guarded_route_generation(
            {
                "release": {"version": release["version"], "files": release["files"]},
                "revision": revision,
            }
        )
        hold = boot.private_hold(identity, revision, generation)

        def require_base():
            current_routed, current_fence, current = active()
            boot.require(
                current_routed == routed
                and current_fence == fence
                and current["base_registry_hash"] == record["base_registry_hash"]
                and current["private_grant_hash"] == record["private_grant_hash"]
                and current["retirement"]["candidates"] == record["retirement"]["candidates"],
                "deployment retirement custody changed",
            )
            installed, registry = installed_config(private=True, routed=routed)
            require_retirement_base(fence, current, installed, registry)
            boot.require(active_release() == release["version"], "retirement base release changed")
            return registry

        def require_custody():
            require_base()
            boot.require(
                boot.read_optional(boot.RUNTIME / "hold") == hold and not boot.route_present(),
                "deployment retirement requires inhibited boot and absent application routes",
            )
            boot.require_route_transition_clear()

        registry = require_base()
        if ex.host.kill_switch():
            raise ExecutorError("kill_switch", "application retirement is stopped")
        changed = boot.inhibit_private(ex.host, identity, revision, generation, routed=routed)
        for candidate in candidates:
            if candidate.application in receipts:
                continue
            require_custody()
            result = retirement.retire_guarded_application(
                ex, registry, candidate, revision, require_custody
            )
            boot.require(result["state"] == "released", "application release did not complete")
            receipt = {field: result[field] for field in ("operation_id", "archive_id", "released")}
            verify_retirement_receipt(fence, candidate, receipt)
            require_custody()
            with ex._db() as db:
                db.execute("BEGIN IMMEDIATE")
                state, current = get_record(db, identity)
                boot.require(
                    state == "active" and fence_in(db) == fence and current == record,
                    "deployment retirement custody changed before recording release",
                )
                receipts[candidate.application] = receipt
                db.execute(
                    "UPDATE site_deployments SET body=? WHERE operation_id=?",
                    (canonical_json(record), identity.operation_id),
                )
            changed |= result["changed"]
        return {"changed": changed}


def verify_api_head(fence, *, private=False, routed=False, retirement=False, fresh=False):
    account = pwd.getpwnam("steward-api")
    boot.safe_directory(API_STATE.parent)
    for path in (API_STATE, API_STATE / "export"):
        info = path.lstat()
        boot.require(
            stat.S_ISDIR(info.st_mode)
            and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
            == (account.pw_uid, account.pw_gid, 0o700),
            "unsafe API export directory",
        )
    fd = os.open(API_STATE / "export" / "head.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        boot.require(
            stat.S_ISREG(info.st_mode)
            and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink)
            == (account.pw_uid, account.pw_gid, 0o600, 1),
            "unsafe API head export",
        )
        data = handle.read(boot.LIMIT + 1)
    boot.require(len(data) <= boot.LIMIT, "API head export exceeds size limit")
    head = parse_json(data)
    boot.require(
        set(head) == {"head", "applied", "config"}
        and boot.is_digest(head["head"])
        and head["applied"]
        in ((fence.base_revision,) if fresh else (fence.base_revision, fence.desired_revision))
        and (retirement and not fresh or head["head"] == head["applied"]),
        "API head has unreviewed changes",
    )
    if retirement and head["head"] != head["applied"]:
        # Pending edits are independently typed, but never supply the retirement roster.
        pending = parse_config(head["config"], allow_unavailable=True)
        boot.require(
            canonical_json(effective(pending)) == canonical_json(head["config"]),
            "pending API configuration is not canonical",
        )
    else:
        config_from(head["config"], installed=True, private=private, routed=routed)
    boot.require(revision_id(head["config"]) == head["head"], "API head digest changed")


def validate_resume(request, cfg, fence, record, uid, *, private=False):
    base_revision, _ = bound_metadata(fence, record)
    boot.require(
        private == ("private_grant_hash" in record), "deployment custody requires its original mode"
    )
    routed = require_private_grant(record) if private else False
    check_declared_routes(cfg, routed)
    release = request["release"]
    expected = deployment_registry(cfg, release["version"])
    boot.require(
        base_revision == request["base_revision"]
        and fence.desired_revision == expected["config_revision"]
        and canonical_json(record["release"]) == canonical_json(release)
        and canonical_json(record["registry"]) == canonical_json(expected),
        "requested configuration or release differs from the original deployment",
    )
    marker = read_marker()
    enrollment_evidence(marker)
    installed, registry = installed_config(
        require_matching_registry=False, private=private, routed=routed
    )
    boot.require(
        marker["schema_version"] == 2
        and marker["server_name"] == cfg.server.name == installed.server.name
        and cfg.server.user == installed.server.user
        and cfg.server.host == installed.server.host
        and cfg.server.port == installed.server.port
        and record["uid"] == uid == pwd.getpwnam(installed.server.user).pw_uid,
        "deployment server or login identity changed",
    )
    observed = revision_id(effective(installed))
    registry_revision = registry["config_revision"]
    boot.require(
        observed == request["observed_revision"]
        and observed in (fence.base_revision, fence.desired_revision)
        and registry_revision in (fence.base_revision, fence.desired_revision),
        "installed configuration and registry differ from the reviewed deployment boundary",
    )

    if "base_registry_hash" in record or "base_artifact_hash" in record:
        base_release = record.get("base_release")
        boot.require(
            isinstance(base_release, str)
            and VERSION.fullmatch(base_release) is not None
            and boot.is_digest(record.get("base_registry_hash"))
            and boot.is_digest(record.get("base_artifact_hash")),
            "incomplete deployment base binding",
        )
        registry_at_base = (
            registry_revision == fence.base_revision
            and revision_id(registry) == record["base_registry_hash"]
        )
        if not registry_at_base:
            boot.require(
                registry_revision == fence.desired_revision,
                "installed registry differs from the original deployment boundaries",
            )
            verify_registry(cfg, registry, expected)
        # Desired and registry are separate writes. Either target document
        # requires the exact target release, even if the other rename was lost.
        if observed != fence.base_revision or not registry_at_base:
            verify_release(release)
        else:
            check_base_release(base_release, release, record["base_artifact_hash"])
    else:
        # Older reservations lack independent evidence of the original registry.
        boot.require(
            observed == registry_revision,
            "installed configuration and registry differ from the reviewed deployment boundary",
        )
        if observed == fence.desired_revision and (
            observed != fence.base_revision or registry["release"] == release["version"]
        ):
            verify_registry(cfg, registry, expected)
            verify_release(release)
        else:
            version = record.get("base_release")
            boot.require(version is not None, "original base release binding is unavailable")
            check_base_release(version, release)
            verify_registry(installed, registry, deployment_registry(installed, version))
    at_base = observed == registry_revision == fence.base_revision
    if "retirement" in record:
        require_retirement_release(record)
        if at_base:
            require_retirement_base(fence, record, installed, registry)
        verify_retirement_receipts(fence, record, complete=not at_base)
        verify_api_head(fence, private=True, routed=routed, retirement=True)
    # Receiptless legacy reservations replay their exact original request.
    # A recovery never creates a retirement roster from a partially installed target.
    elif routed:
        verify_api_head(fence, private=True, routed=True)
    elif private:
        verify_api_head(fence, private=True)
    else:
        verify_api_head(fence)
    return routed


def request_config(request, *, recovery=False, private=False, routed=False):
    if not recovery:
        return validate_request(request, private=private, routed=routed)
    boot.require(
        set(request) == {"base_revision", "observed_revision", "config", "release"}
        and boot.is_digest(request["observed_revision"]),
        "invalid deployment recovery request",
    )
    return validate_request(
        {key: value for key, value in request.items() if key != "observed_revision"},
        private=private,
        routed=routed,
    )


def resume(operation_id, request, *, private=False):
    cfg = request_config(request, recovery=True, private=private, routed=private)
    uid = login_uid(cfg.server.user)
    ex = executor()
    with ex._db() as db:
        db.execute("BEGIN")
        state, record = find_record(db, operation_id)
        fence = fence_in(db)
    boot.require(state in (*UNVERIFIED, "revoked"), "verified deployment is already complete")
    routed = validate_resume(request, cfg, fence, record, uid, private=private)
    previous = identity_from(record)
    reject_live(record)
    reconcile_dead(ex, previous)
    identity = Identity(operation_id, secrets.token_hex(16), gate.BOOT_ID.read_text().strip())
    with gate.control_lock():
        require_empty_gate()
        write_request(
            identity,
            request,
            uid,
            previous=previous,
            private_grant_hash=record.get("private_grant_hash"),
            routed=routed,
        )
    return start_coordinator(ex, identity, routed=routed)


def coordinate(identity):
    operation_id = identity.operation_id
    payload = parse_json(boot.read_bytes(request_path(identity)))
    previous = Identity(**payload["previous"]) if "previous" in payload else None
    private = "private_grant_hash" in payload
    routed = private and payload.get("application_routes") == "internal"
    fields = {"operation_id", "run_id", "boot_id", "request", "uid"}
    if previous is not None:
        fields.add("previous")
    if private:
        fields.add("private_grant_hash")
    if routed:
        fields.add("application_routes")
    boot.require(
        set(payload) == fields
        and identity_from(payload) == identity
        and identity.boot_id == gate.BOOT_ID.read_text().strip()
        and (previous is None or previous.operation_id == operation_id and previous != identity),
        "deployment request identity changed",
    )
    request = payload["request"]
    cfg = request_config(request, recovery=previous is not None, private=private, routed=routed)
    ex = executor()
    release = request["release"]
    proposed_registry = deployment_registry(cfg, release["version"])
    record = {
        **asdict(identity),
        "uid": payload["uid"],
        "base_revision": request["base_revision"],
        "desired_revision": proposed_registry["config_revision"],
        "registry": proposed_registry,
        "release": release,
        "release_hash": revision_id(release),
        "process": process_identity(identity),
    }
    if private:
        record["private_grant_hash"] = payload["private_grant_hash"]
    if routed:
        record["application_routes"] = "internal"

    def validate_gate():
        gate.Record(identity, record["uid"])
        boot.require(
            pwd.getpwnam(cfg.server.user).pw_uid == record["uid"], "deployment login UID changed"
        )
        require_empty_gate()
        if private:
            require_private_grant(record)

    def validate_route_interpreter(version, artifact_hash=None):
        if not routed:
            return
        boot.require(
            sys.executable == str(boot.RELEASES / version / "venv" / "bin" / "python"),
            "routed coordinator is outside its admission release",
        )
        if version == release["version"]:
            boot.require(
                (artifact_hash or base_artifact_hash(version)) == revision_id(release["files"]),
                "routed deployment cannot replace its admission release in place",
            )

    def reserve(db, fence):
        boot.require_route_transition_clear()
        _, registry = validate_base(request, cfg, private=private, routed=routed)
        candidates = fresh_retirements(request, registry, cfg, private=private)
        version = active_release()
        boot.require(
            version == registry["release"], "active release and executor registry disagree"
        )
        record["base_release"] = version
        record["base_registry_hash"] = revision_id(registry)
        record["base_artifact_hash"] = base_artifact_hash(version)
        if candidates:
            require_retirement_release(record)
            verify_api_head(fence, private=True, routed=routed, retirement=True, fresh=True)
            for candidate in candidates:
                retirement.require_guarded_eligibility(
                    ex, registry, candidate.application, fence.desired_revision
                )
                boot.require(
                    db.execute(
                        "SELECT 1 FROM application_capture_workflows WHERE application=?",
                        (candidate.application,),
                    ).fetchone()
                    is None,
                    "an application capture workflow is unfinished",
                )
            record["retirement"] = {
                "candidates": [candidate.model_dump(mode="json") for candidate in candidates],
                "receipts": {},
            }
        validate_route_interpreter(version, record["base_artifact_hash"])
        with gate.control_lock():
            validate_gate()
            db.execute(
                "INSERT INTO site_deployments VALUES (?, 'reserved', ?)",
                (operation_id, canonical_json(record)),
            )

    def rotate(db, fence):
        state, old = get_record(db, previous)
        boot.require(state == "revoked", "previous deployment custody is not revoked")
        validate_resume(request, cfg, fence, old, record["uid"], private=private)
        boot.require_route_transition_clear()
        if routed:
            validate_route_interpreter(active_release())
        for field in ("base_release", "base_registry_hash", "base_artifact_hash", "retirement"):
            if field in old:
                record[field] = old[field]
        record["previous"] = asdict(previous)
        with gate.control_lock():
            validate_gate()
            entry = ex.audit.append(
                "deployment_recovery",
                outcome="custody_rotation_authorized",
                revision=record["desired_revision"],
                observed_revision=request["observed_revision"],
                previous=record["previous"],
                **asdict(identity),
            )
            record["recovery_audit_hash"] = entry["hash"]
            db.execute(
                "UPDATE site_deployments SET state='reserved', body=? WHERE operation_id=?",
                (canonical_json(record), operation_id),
            )

    def ready():
        with ex._db() as db:
            db.execute("BEGIN IMMEDIATE")
            transition(db, identity, ("reserved",), "active")

    def closing():
        with ex._db() as db:
            state, _ = get_record(db, identity)
        return state != "active"

    def wake(_number, _frame):
        # The persisted request is authoritative. The bounded gate loop reads it.
        pass

    expired = False

    def on_term(*_args):
        nonlocal expired
        expired = True

    signal.signal(signal.SIGUSR1, wake)
    signal.signal(signal.SIGTERM, on_term)
    with ex.deployment_execution(
        base_revision=payload["request"]["base_revision"],
        desired_revision=record["desired_revision"],
        operation_id=operation_id,
        reserve_site=reserve if previous is None else None,
        resume_site=rotate if previous is not None else None,
    ) as fence:
        request_path(identity).unlink(missing_ok=True)
        cleaned = False
        try:
            gate.serve(
                operation_id,
                record["uid"],
                identity=identity,
                on_ready=ready,
                should_stop=closing,
                on_term=on_term,
            )
            with ex._db() as db:
                state, latest = get_record(db, identity)
            if expired or state not in ("closing", "revoking"):
                return
            gate.cleanup(operation_id, identity.run_id)
            cleaned = True
            if state == "revoking":
                if routed:
                    boot.reconcile_guarded_routes(ex.host, identity, record["desired_revision"])
                with ex._db() as db:
                    db.execute("BEGIN IMMEDIATE")
                    transition(db, identity, ("revoking",), "revoked")
                return
            boot.require(
                ex.host.deployment_rollbacks_quiescent(), "deployment rollback still active"
            )
            if "retirement" in latest:
                record["retirement"] = latest["retirement"]
                verify_retirement_receipts(fence, record, complete=True)
                verify_api_head(fence, private=True, routed=routed, retirement=True)
            applied, registry = verify_configuration(record)
            check_platform(ex, registry, applied)
            if private and not routed:
                boot.verify_guarded_deployment(ex.host, record["desired_revision"])
            # Recheck the installed binding after probes took time outside SQLite.
            verify_configuration(record)
            boot.require(
                ex.host.deployment_rollbacks_quiescent(), "deployment rollback still active"
            )
            boot.require(not expired, "deployment coordinator expired")
            if routed:
                generation = boot.guarded_route_generation(
                    {
                        "release": {"version": release["version"], "files": release["files"]},
                        "revision": record["desired_revision"],
                    }
                )
                boot.verify_guarded_deployment(
                    ex.host,
                    record["desired_revision"],
                    route_identity=identity,
                    route_generation=generation,
                )
                require_private_grant(record)
                boot.require(not expired, "deployment coordinator expired")
            commit_success(ex, identity, fence, record)
        finally:
            with ex._db() as db:
                db.execute("BEGIN IMMEDIATE")
                state, latest = get_record(db, identity)
                remaining = fence_in(db) if routed else None
                if state in UNVERIFIED:
                    transition(
                        db,
                        identity,
                        UNVERIFIED,
                        "revoked" if cleaned and not routed and state == "revoking" else "pending",
                    )
            if routed and cleaned and state != "revoked":
                boot.reconcile_guarded_routes(
                    ex.host,
                    identity,
                    record["desired_revision"],
                    committed=route_commit_status(state, latest, remaining),
                )


def stopped_unit(props):
    return props.get("MainPID") == "0" and props.get("ActiveState") in ("inactive", "failed")


def is_live(record):
    try:
        with live_process(record):
            return True
    except ERRORS:
        return False


def reject_live(record):
    boot.require(not is_live(record), "deployment coordinator is live; use exact revoke first")


def require_stopped(identity, record):
    if identity.boot_id != gate.BOOT_ID.read_text().strip():
        return
    reject_live(record)
    boot.require(stopped_unit(unit_properties(identity)), "deployment coordinator has not stopped")
    (gate.CGROUP / "cgroup.controllers").stat()
    cg = gate.CGROUP / "system.slice" / unit(identity)
    try:
        events = (cg / "cgroup.events").read_text().splitlines()
    except FileNotFoundError:
        boot.require(not cg.exists(), "cannot verify deployment coordinator cgroup")
    else:
        boot.require("populated 0" in events, "deployment coordinator cgroup is still populated")


def route_commit_status(state, record, fence):
    if state != "complete":
        bound_metadata(fence, record)
        return False
    boot.require(
        record.get("application_routes") == "internal"
        and all(
            boot.is_digest(record.get(field))
            for field in (
                "audit_hash",
                "base_revision",
                "desired_revision",
                "release_hash",
                "private_grant_hash",
            )
        )
        and fence is None,
        "application route publication lacks an exact committed receipt",
    )
    return True


def route_stop_evidence(identity, invocation):
    with boot.executor_state_snapshot() as db:
        state, record = find_record(db, identity.operation_id)
        if identity_from(record) != identity:
            return None
        recorded_invocation = record["process"]["invocation"]
        boot.require(
            isinstance(recorded_invocation, str) and ID.fullmatch(recorded_invocation) is not None,
            "invalid durable systemd invocation evidence",
        )
        if recorded_invocation != invocation:
            return None
        boot.require(record.get("application_routes") == "internal", "invalid durable route mode")
        committed = route_commit_status(state, record, boot.deployment_fence_from(db))
        return record["desired_revision"], committed


def route_stop_hook(identity):
    invocation = os.environ.get("INVOCATION_ID", "")
    membership = (gate.PROC / "self" / "cgroup").read_text()
    props = unit_properties(identity)
    boot.require(
        ID.fullmatch(invocation) is not None
        and identity.boot_id == gate.BOOT_ID.read_text().strip()
        and membership == f"0::/system.slice/{unit(identity)}\n",
        "application route cleanup requires the exact systemd invocation cgroup",
    )
    boot.require(
        props.get("InvocationID") == invocation
        and props.get("ControlGroup") == f"/system.slice/{unit(identity)}",
        "application route cleanup requires the current systemd invocation",
    )
    with boot.deployment_lock(timeout=5):
        revision = None
        committed = False
        evidence_error = None
        try:
            evidence = route_stop_evidence(identity, invocation)
            if evidence is None:
                return
            revision, committed = evidence
        except ERRORS as error:
            # With unreadable custody, withdraw only evidence labelled with this run.
            evidence_error = error
        try:
            with gate.control_lock():
                gate.cleanup_locked(identity, allow_missing=True)
        except ERRORS:
            boot.reconcile_guarded_routes(
                Host(), identity, revision, committed=committed, allow_early=False
            )
            raise
        boot.reconcile_guarded_routes(Host(), identity, revision, committed=committed)
        if evidence_error is not None:
            raise boot.BootError(
                "route cleanup could not verify durable deployment custody"
            ) from evidence_error


def reconcile_dead(ex, identity):
    with ex.target_lock("deployment-execution"), gate.control_lock(), ex._db() as db:
        db.execute("BEGIN IMMEDIATE")
        state, record = get_record(db, identity)
        boot.require(state in (*UNVERIFIED, "revoked"), "verified deployment is already complete")
        bound_metadata(fence_in(db), record)
        require_stopped(identity, record)
        routed = record.get("application_routes") == "internal"
        try:
            if identity.boot_id == gate.BOOT_ID.read_text().strip():
                gate.cleanup_locked(identity, allow_missing=True)
            else:
                require_empty_gate()
        except ERRORS:
            if routed:
                boot.reconcile_guarded_routes(
                    ex.host, identity, record["desired_revision"], allow_early=False
                )
            raise
        if routed:
            boot.reconcile_guarded_routes(ex.host, identity, record["desired_revision"])
        if state in UNVERIFIED:
            transition(db, identity, UNVERIFIED, "revoked")
    return public(record, "revoked")


def close_receipt(ex, identity, target):
    with ex._db() as db:
        state, record = get_record(db, identity)
        if state == "pending":
            raise GateError("deployment coordinator exited without completing; recovery is pending")
    if state != target:
        return None
    if (
        target == "complete"
        and record.get("application_routes") == "internal"
        and os.path.lexists(boot.RUNTIME / boot.GUARDED_ROUTE_JOURNAL)
    ):
        if identity.boot_id == gate.BOOT_ID.read_text().strip() and not stopped_unit(
            unit_properties(identity)
        ):
            return None
        with ex.target_lock("deployment-execution"), boot.executor_state_snapshot() as db:
            state, record = get_record(db, identity)
            committed = route_commit_status(state, record, boot.deployment_fence_from(db))
            boot.require(committed, "route publication receipt changed")
            boot.reconcile_guarded_routes(
                ex.host, identity, record["desired_revision"], committed=True
            )
    return public(record, target)


def report_exit(ex, identity, target):
    receipt = close_receipt(ex, identity, target)
    if receipt is not None:
        return receipt
    with ex._db() as db:
        db.execute("BEGIN IMMEDIATE")
        state, record = get_record(db, identity)
        if state in UNVERIFIED:
            transition(db, identity, UNVERIFIED, "pending")
    raise GateError("deployment coordinator exited without completing; recovery is pending")


def request_close(ex, identity, verb):
    before, after, target = {
        "finish": (("active", "closing"), "closing", "complete"),
        "revoke": (UNVERIFIED, "revoking", "revoked"),
    }[verb]
    with ex._db() as db:
        state, record = get_record(db, identity)
    if state == target:
        receipt = close_receipt(ex, identity, target)
        if receipt is not None:
            return receipt
    try:
        with live_process(record) as fd:
            with ex._db() as db:
                db.execute("BEGIN IMMEDIATE")
                state, latest = get_record(db, identity)
                if state == target and latest.get("application_routes") != "internal":
                    return public(latest, target)
                if state != target:
                    transition(db, identity, before, after)
                    gate.require_fence(identity.operation_id)
            if state != target:
                signal.pidfd_send_signal(fd, signal.SIGUSR1)
    except ERRORS:
        if identity.boot_id != gate.BOOT_ID.read_text().strip():
            return report_exit(ex, identity, target)
        props = unit_properties(identity)
        if stopped_unit(props):
            return report_exit(ex, identity, target)
        if (
            record.get("application_routes") != "internal"
            or props.get("ActiveState") != "deactivating"
        ):
            raise

    deadline = time.monotonic() + FINISH_WAIT
    while time.monotonic() < deadline:
        receipt = close_receipt(ex, identity, target)
        if receipt is not None:
            return receipt
        try:
            with live_process(record) as fd:
                poll = select.poll()
                poll.register(fd, select.POLLIN)
                if poll.poll(250) and stopped_unit(unit_properties(identity)):
                    return report_exit(ex, identity, target)
        except ERRORS:
            receipt = close_receipt(ex, identity, target)
            if receipt is not None:
                return receipt
            if stopped_unit(unit_properties(identity)):
                return report_exit(ex, identity, target)
            time.sleep(0.2)
    raise GateError("timed out waiting for the deployment coordinator; recovery may be pending")


def revoke(ex, identity):
    with ex._db() as db:
        state, record = get_record(db, identity)
        if state == "revoked" and record.get("application_routes") != "internal":
            return public(record, state)
        boot.require(state != "complete", "verified deployment is already complete")
        bound_metadata(fence_in(db), record)
    if is_live(record):
        return request_close(ex, identity, "revoke")
    return reconcile_dead(ex, identity)


def require_verifier(identity, revision):
    require_active_verifier(identity, revision, private_only=False, scoped=True)


def require_private_verifier(identity, revision, *, scoped=True) -> bool:
    return require_active_verifier(identity, revision, private_only=True, scoped=scoped)


def require_active_verifier(identity, revision, *, private_only, scoped, retiring=False, ex=None):
    if ex is None:
        ex = executor()
    with ex._db() as db:
        state, record = get_record(db, identity)
    fence = gate.require_fence(identity.operation_id)
    boot.require(
        state == "active"
        and record["desired_revision"] == revision
        and fence.desired_revision == revision
        and gate.read_record() == gate.Record(identity, record["uid"]),
        "verification does not match an active guarded deployment",
    )
    private = "private_grant_hash" in record
    boot.require(private or not private_only, "verification requires private deployment custody")
    routed = False
    if private:
        bound_metadata(fence, record)
        routed = require_private_grant(record)
        if routed:
            require_no_application_routes(routed=True)
        else:
            require_no_application_routes()
    if "retirement" in record and not retiring:
        retirement_evidence(record, complete=True)
    if scoped:
        membership = (gate.PROC / "self" / "cgroup").read_text()
        pattern = f"0::/{identity.slice}/{identity.scope_prefix}[a-f0-9]{{32}}\\.scope\n"
        boot.require(
            re.fullmatch(pattern, membership) is not None,
            "verifier is outside the deployment scope",
        )
    with live_process(record):
        boot.require(status(ex, identity)["state"] == "active", "deployment intake is unavailable")
    return routed


def stdin_request():
    data = sys.stdin.buffer.read(boot.LIMIT + 1)
    boot.require(len(data) <= boot.LIMIT, "deployment request exceeds size limit")
    return parse_json(data)


def root_status(operation_id):
    boot.read_deployment_fence()
    path = boot.EXECUTOR_STATE_DB
    with close_connection(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=1)) as db:
        db.execute("BEGIN")
        return query_status(db, operation_id)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("activate", allow_abbrev=False)
    commands.add_parser("begin", allow_abbrev=False)
    commands.add_parser("begin-private", allow_abbrev=False)
    for action in ("_coordinate", "_route_stop", "_retire"):
        internal = commands.add_parser(action, allow_abbrev=False)
        for field in ("operation_id", "run_id", "boot_id"):
            internal.add_argument(field)
        if action == "_retire":
            internal.add_argument("revision")
    for action in ("resume", "resume-private"):
        recovery = commands.add_parser(action, allow_abbrev=False)
        recovery.add_argument("--operation-id", required=True)
    query = commands.add_parser("status", allow_abbrev=False)
    choice = query.add_mutually_exclusive_group(required=True)
    choice.add_argument("--current", action="store_true")
    choice.add_argument("--operation-id")
    query.add_argument("--run-id")
    query.add_argument("--boot-id")
    for action in ("finish", "revoke"):
        command = commands.add_parser(action, allow_abbrev=False)
        for field in ("operation-id", "run-id", "boot-id"):
            command.add_argument("--" + field, required=True)
    args = parser.parse_args()
    try:
        boot.require(os.geteuid() == 0, "deployment control requires root")
        if args.action == "_coordinate":
            coordinate(Identity(args.operation_id, args.run_id, args.boot_id))
            return 0
        if args.action == "_route_stop":
            route_stop_hook(Identity(args.operation_id, args.run_id, args.boot_id))
            return 0
        if args.action == "_retire":
            identity = Identity(args.operation_id, args.run_id, args.boot_id)
            result = retire_before_cutover(executor(), identity, args.revision)
        elif args.action == "activate":
            result = activate()
        elif args.action in ("begin", "begin-private"):
            result = begin(stdin_request(), private=args.action == "begin-private")
        elif args.action in ("resume", "resume-private"):
            boot.require(
                ID.fullmatch(args.operation_id) is not None, "invalid deployment operation"
            )
            result = resume(
                args.operation_id, stdin_request(), private=args.action == "resume-private"
            )
        elif args.action == "status":
            if args.current:
                boot.require(
                    args.run_id is None and args.boot_id is None,
                    "current deployment status takes no run or boot",
                )
                result = root_status(None)
            elif args.run_id is None and args.boot_id is None:
                boot.require(
                    ID.fullmatch(args.operation_id) is not None, "invalid deployment operation"
                )
                result = root_status(args.operation_id)
            else:
                boot.require(
                    args.run_id is not None and args.boot_id is not None,
                    "exact deployment status requires both run and boot",
                )
                result = status(executor(), Identity(args.operation_id, args.run_id, args.boot_id))
        else:
            identity = Identity(args.operation_id, args.run_id, args.boot_id)
            ex = executor()
            result = (
                request_close(ex, identity, "finish")
                if args.action == "finish"
                else revoke(ex, identity)
            )
        print(json.dumps(result, sort_keys=True))
    except ERRORS as error:
        print(f"site deployment: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
