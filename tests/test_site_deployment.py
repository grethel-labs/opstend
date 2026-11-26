import hashlib
import os
import sqlite3
from contextlib import contextmanager, nullcontext
from dataclasses import asdict
from unittest.mock import Mock

import pytest

from steward.application_boot import BootError
from steward.collector import audit_events
from steward.core.canonical import canonical_json
from steward.core.config import effective
from steward.executor import site_deployment as site
from steward.executor.deployment_launcher import GateError, Identity

IDENTITY = Identity("a" * 32, "b" * 32, "c" * 8 + "-cccc-cccc-cccc-" + "c" * 12)


def reserved(executor, *, callback=None):
    base = site.parse_json(executor.registry_file.read_bytes())["config_revision"]
    record = {**asdict(IDENTITY), "desired_revision": base, "release": {"version": "1.0"}}

    def reserve(db, _fence):
        db.execute(
            "INSERT INTO site_deployments VALUES (?, 'closing', ?)",
            (IDENTITY.operation_id, canonical_json(record)),
        )
        if callback is not None:
            callback()

    fence = executor.begin_deployment_fence(
        base_revision=base,
        desired_revision=base,
        operation_id=IDENTITY.operation_id,
        reserve_site=reserve,
    )
    return fence, record


def test_effective_binding_rejects_coercion(cfg):
    config = effective(cfg)
    site.config_from(config)
    config["server"]["port"] = str(config["server"]["port"])
    with pytest.raises(BootError, match="strictly typed"):
        site.config_from(config)


def test_release_binding_rejects_path_escape():
    release = {
        "version": "1.0",
        "wheel": "steward-1.0-py3-none-any.whl",
        "files": {
            "steward-1.0-py3-none-any.whl": "a" * 64,
            "requirements.txt": "b" * 64,
            "bundles/sample/../escaped": "c" * 64,
        },
    }
    with pytest.raises(BootError, match="invalid deployment release artifact"):
        site.release_binding(release)


def test_reservation_keeps_fence_and_custody_atomic(executor):
    def interruption():
        raise RuntimeError("interrupted reservation")

    with pytest.raises(RuntimeError, match="interrupted"):
        reserved(executor, callback=interruption)
    assert executor.deployment_fence() is None
    with executor._db() as db, pytest.raises(GateError, match="known operation"):
        site.get_record(db, IDENTITY)


def test_verified_receipt_is_exact_and_replayable_after_fence_release(executor):
    fence, record = reserved(executor)
    site.commit_success(executor, IDENTITY, fence, record)
    assert executor.deployment_fence() is None
    assert site.request_close(executor, IDENTITY, "finish") == site.public(record, "complete")
    assert site.status(executor, IDENTITY) == site.public(record, "complete")
    with executor._db() as db:
        state, durable = site.get_record(db, IDENTITY)
    assert state == "complete"
    assert durable == {**site.public(record), "audit_hash": executor.audit.read()[-1]["hash"]}
    wrong = Identity(IDENTITY.operation_id, "d" * 32, IDENTITY.boot_id)
    with pytest.raises(BootError, match="run or boot"):
        site.status(executor, wrong)


def test_audit_failure_keeps_exact_fence_and_custody(executor, monkeypatch):
    fence, record = reserved(executor)
    monkeypatch.setattr(executor.audit, "append", Mock(side_effect=OSError("audit failed")))
    with pytest.raises(OSError, match="audit failed"):
        site.commit_success(executor, IDENTITY, fence, record)
    assert executor.deployment_fence() == fence
    assert site.status(executor, IDENTITY) == site.public(record, "pending")


def test_crash_after_audit_keeps_exact_fence_and_custody(executor):
    fence, record = reserved(executor)
    with executor._db() as db:
        db.execute(
            "CREATE TRIGGER failed_release BEFORE DELETE ON deployment_fence "
            "BEGIN SELECT RAISE(ABORT, 'interrupted after audit'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="interrupted after audit"):
        site.commit_success(executor, IDENTITY, fence, record)
    (event,) = audit_events(executor.audit.read()[-1])
    assert event.outcome == "host_verified"
    assert event.summary == (
        f"Host verification passed for release 1.0 "
        f"(configuration {record['desired_revision'][:12]})."
    )
    assert executor.deployment_fence() == fence
    assert site.status(executor, IDENTITY) == site.public(record, "pending")


def test_activate_uses_prepared_launcher_after_ordinary_release_replacement(
    executor, cfg, tmp_path, monkeypatch
):
    marker = {"server_name": cfg.server.name, "schema_version": 1, "state": "installed"}
    install = tmp_path / "install.json"
    install.write_text(canonical_json(marker))
    libexec = tmp_path / "libexec"
    launcher = libexec / "steward" / "deployment-v1" / "launch.py"
    launcher.parent.mkdir(parents=True, mode=0o755)
    for directory in (libexec, launcher.parent.parent, launcher.parent):
        directory.chmod(0o755)
    launcher.write_bytes(b"launcher from the previously approved wheel")
    record = tmp_path / "deployment-enrollment-v1.json"
    record.write_text(
        canonical_json(
            {
                "v": 1,
                "server_name": cfg.server.name,
                "wheel_sha256": "a" * 64,
                "launcher_sha256": site.boot.digest(launcher.read_bytes()),
            }
        )
    )

    def unavailable_wheel(_expected):
        raise BootError("the original release wheel was replaced")

    monkeypatch.setattr(site, "executor", lambda: executor)
    monkeypatch.setattr(site, "installed_config", lambda: (cfg, {}))
    monkeypatch.setattr(site, "require_empty_gate", lambda: None)
    monkeypatch.setattr(site.gate, "control_lock", nullcontext)
    monkeypatch.setattr(site.boot, "safe_directory", lambda _path: None)
    monkeypatch.setattr(site.os, "fchown", lambda *_: None)
    monkeypatch.setattr(site.enrollment, "INSTALL", install)
    monkeypatch.setattr(site.enrollment, "STATE", tmp_path)
    monkeypatch.setattr(site.enrollment, "LIBEXEC", libexec)
    monkeypatch.setattr(site.enrollment, "read_limited", lambda path, *_: path.read_bytes())
    monkeypatch.setattr(site.enrollment, "approved_launcher", unavailable_wheel)

    assert site.activate() == {**marker, "schema_version": 2}
    assert site.parse_json(install.read_bytes())["schema_version"] == 2
    assert site.parse_json(record.read_bytes())["wheel_sha256"] == "a" * 64
    assert executor.deployment_fence() is None


def test_in_run_verification_requires_real_scope(executor, tmp_path, monkeypatch):
    fence, record = reserved(executor)
    record["uid"] = os.getuid()
    with executor._db() as db:
        db.execute("UPDATE site_deployments SET state='active', body=?", (canonical_json(record),))
    monkeypatch.setattr(site, "executor", lambda: executor)
    monkeypatch.setattr(site.gate, "require_fence", lambda _: fence)
    monkeypatch.setattr(site.gate, "read_record", lambda: site.gate.Record(IDENTITY, os.getuid()))
    monkeypatch.setattr(site.gate, "PROC", tmp_path)
    monkeypatch.setattr(site, "status", lambda *_, **__: {"state": "active"})

    @contextmanager
    def live(_):
        yield None

    monkeypatch.setattr(site, "live_process", live)
    process = tmp_path / "self"
    process.mkdir()
    membership = process / "cgroup"
    membership.write_text("0::/user.slice\n")
    with pytest.raises(BootError, match="outside the deployment scope"):
        site.require_verifier(IDENTITY, fence.desired_revision)
    membership.write_text(f"0::/{IDENTITY.slice}/{IDENTITY.scope_prefix}{'f' * 32}.scope\n")
    site.require_verifier(IDENTITY, fence.desired_revision)
    with pytest.raises(BootError, match="does not match"):
        site.require_verifier(IDENTITY, "d" * 64)


def release_for_test():
    wheel = "steward-9.0-py3-none-any.whl"
    return {
        "version": "9.0",
        "wheel": wheel,
        "files": {wheel: "a" * 64, "requirements.txt": "b" * 64, "bundles/demo/x": "c" * 64},
    }


def private_config(cfg, *, active=True, routes=(), archive_authorized=False):
    data = effective(cfg)
    data["applications"] = [
        {
            "id": "acceptance",
            "services": [
                {
                    "id": "worker",
                    "image": "docker.io/library/python@sha256:" + "9" * 64,
                    "source_revision": "fixture",
                    "maintenance": {"allow_backup_pause": archive_authorized},
                    "host_port": 21999,
                    "deploy": active,
                    "routes": list(routes),
                }
            ],
        }
    ]
    return site.parse_config(data, allow_unavailable=True)


def test_private_config_binds_root_derived_registry_and_refuses_disabled_routes(cfg):
    app = private_config(cfg)
    assert site.config_from(effective(app), private=True) == app
    with pytest.raises(site.ConfigError, match="not available"):
        site.config_from(effective(app))
    registry = site.deployment_registry(app, "9.0")
    assert registry == (
        site.deployment_registry(cfg, "9.0") | site.prepare_application_registry(app)
    )
    assert registry["projects"] == site.deployment_registry(cfg, "9.0")["projects"]
    routed = private_config(
        cfg, active=False, routes=[{"host": "fixture.example.com", "tls": "internal"}]
    )
    with pytest.raises(BootError, match="routeless"):
        site.config_from(effective(routed), private=True)


def test_private_grant_requires_exact_schema_and_transition(cfg, monkeypatch):
    app = private_config(cfg)
    release = release_for_test()
    read = Mock()
    monkeypatch.setattr(site.enrollment, "read_limited", read)
    for base, target in [(cfg, app), (app, app), (private_config(cfg, active=False), cfg)]:
        request = {"base_revision": site.revision_id(effective(base)), "release": release}
        grant = {
            "version": 1,
            "server_name": cfg.server.name,
            "base_revision": request["base_revision"],
            "desired_revision": site.revision_id(effective(target)),
            "release_hash": site.revision_id(release),
        }
        read.return_value = canonical_json(grant)
        assert site.requested_grant_binding(request, target) == (site.revision_id(grant), False)
    read.assert_called_with(
        site.boot.STATE / "private-application-site.json", 0o600, site.enrollment.RECORD_LIMIT
    )
    for altered in ({"version": True}, {"release_hash": "b" * 64}, {"extra": None}):
        read.return_value = canonical_json(grant | altered)
        with pytest.raises(BootError, match="exact transition"):
            site.requested_grant_binding(request, target)


def test_routed_grant_binds_all_declared_routes_and_exact_mode(cfg, monkeypatch):
    routes = [{"host": "fixture.example.com", "tls": "internal"}]
    base = private_config(cfg, active=False, routes=routes)
    public_cfg = cfg.model_copy(
        update={"proxy": cfg.proxy.model_copy(update={"acme_email": "owner@example.com"})}
    )
    public = private_config(public_cfg, active=False, routes=[routes[0] | {"tls": "acme"}])
    assert site.config_from(effective(base), private=True, routed=True) == base
    with pytest.raises(BootError, match="internal TLS"):
        site.config_from(effective(public), private=True, routed=True)
    release = release_for_test()
    stub_resume_host(monkeypatch, cfg)
    registry = site.deployment_registry(base, "8.0") | {
        "peers": dict.fromkeys(("api", "controller", "collector", "scanner"), os.getuid())
    }
    monkeypatch.setattr(site, "installed_config", lambda **_: (base, registry))
    request = {"base_revision": registry["config_revision"], "release": release}
    grant = {
        "version": 2,
        "application_routes": "internal",
        "server_name": cfg.server.name,
        "base_revision": request["base_revision"],
        "desired_revision": site.revision_id(effective(cfg)),
        "release_hash": site.revision_id(release),
    }
    read = Mock(return_value=canonical_json(grant))
    monkeypatch.setattr(site.enrollment, "read_limited", read)
    digest, routed = site.requested_grant_binding(request, cfg)
    assert (digest, routed) == (site.revision_id(grant), True)
    site.validate_base(request, cfg, private=True, routed=True)
    record = {
        **grant,
        "registry": site.deployment_registry(cfg, release["version"]),
        "release": release,
        "private_grant_hash": digest,
    }
    assert site.require_private_grant(record) is True
    del record["application_routes"]
    with pytest.raises(BootError, match="durable custody"):
        site.require_private_grant(record)
    for changed in (
        {"application_routes": "public"},
        {"version": 1},
        {"version": 2.0},
        {"extra": False},
    ):
        read.return_value = canonical_json(grant | changed)
        with pytest.raises(BootError, match="exact transition"):
            site.requested_grant_binding(request, cfg)
    base = private_config(cfg, active=False)
    registry.update(site.deployment_registry(base, "8.0"))
    with pytest.raises(BootError, match="base and target routes"):
        site.validate_base(
            {"base_revision": registry["config_revision"]}, cfg, private=True, routed=True
        )


def test_private_base_requires_exact_registry_and_disabled_retirement(cfg, monkeypatch):
    app = private_config(cfg)
    stub_resume_host(monkeypatch, cfg)
    installed = app
    registry = site.deployment_registry(installed, "8.0") | {
        "peers": dict.fromkeys(("api", "controller", "collector", "scanner"), os.getuid())
    }
    monkeypatch.setattr(site, "installed_config", lambda *, private: (installed, registry))
    request = {"base_revision": registry["config_revision"]}
    with pytest.raises(BootError, match="disabled before retirement"):
        site.validate_base(request, cfg, private=True)
    site.validate_base(request | {"retirement_protocol": 1}, cfg, private=True)
    installed = private_config(cfg, active=False)
    registry.update(site.deployment_registry(installed, "8.0"))
    request["base_revision"] = registry["config_revision"]
    site.validate_base(request, cfg, private=True)
    registry["applications"]["acceptance"]["services"]["worker"]["deploy"] = True
    with pytest.raises(BootError, match="registry differs"):
        site.validate_base(request, cfg, private=True)


def test_private_route_check_refuses_residual_symlink(monkeypatch, tmp_path):
    monkeypatch.setattr(site.boot, "RUNTIME", tmp_path)
    monkeypatch.setattr(site.boot, "CONFIG", tmp_path)
    monkeypatch.setattr(site.boot, "PROXY_RUNTIME", tmp_path)
    site.require_no_application_routes()
    for evidence in (tmp_path / "route-drain.json", site.boot.route_path()):
        evidence.symlink_to(tmp_path / "absent")
        with pytest.raises(BootError, match="route evidence"):
            site.require_no_application_routes()
        evidence.unlink()


def test_ordinary_graph_free_refuses_residual_private_handoff(monkeypatch, tmp_path):
    for directory in ("STATE", "RUNTIME", "SYSTEMD", "PROXY_RUNTIME"):
        monkeypatch.setattr(site.boot, directory, tmp_path)
    site.graph_free()
    (tmp_path / site.boot.HANDOFF).symlink_to(tmp_path / "absent")
    with pytest.raises(BootError, match="application boot ownership"):
        site.graph_free()


def test_private_api_head_accepts_only_bound_graph(cfg, monkeypatch, tmp_path):
    app = private_config(cfg)
    revision = site.revision_id(effective(app))
    base_revision = site.revision_id(effective(cfg))
    fence = site.DeploymentFence(
        operation_id=IDENTITY.operation_id, base_revision=base_revision, desired_revision=revision
    )
    export = tmp_path / "api" / "export"
    export.parent.mkdir(mode=0o700)
    export.mkdir(mode=0o700)
    head = export / "head.json"
    monkeypatch.setattr(site, "API_STATE", export.parent)
    monkeypatch.setattr(site.boot, "safe_directory", Mock())
    monkeypatch.setattr(
        site.pwd, "getpwnam", lambda _: Mock(pw_uid=os.getuid(), pw_gid=os.getgid())
    )
    head.write_text(
        canonical_json({"head": revision, "applied": revision, "config": effective(app)})
    )
    head.chmod(0o600)
    site.verify_api_head(fence, private=True)
    with pytest.raises(BootError, match="graph-free"):
        site.verify_api_head(fence)
    foreign = private_config(cfg, active=False)
    foreign_revision = site.revision_id(effective(foreign))
    head.write_text(
        canonical_json(
            {"head": foreign_revision, "applied": foreign_revision, "config": effective(foreign)}
        )
    )
    with pytest.raises(BootError, match="unreviewed changes"):
        site.verify_api_head(fence, private=True)
    pending = {"head": foreign_revision, "applied": base_revision, "config": effective(foreign)}
    head.write_text(canonical_json(pending))
    with pytest.raises(BootError, match="unreviewed changes"):
        site.verify_api_head(fence, private=True, retirement=True, fresh=True)
    site.verify_api_head(fence, private=True, retirement=True)
    assert site.parse_json(head.read_bytes()) == pending
    head.write_text(canonical_json(pending | {"applied": revision}))
    site.verify_api_head(fence, private=True, retirement=True)
    head.write_text(canonical_json(pending | {"config": effective(app)}))
    with pytest.raises(BootError, match="head digest changed"):
        site.verify_api_head(fence, private=True, retirement=True)
    head.write_text(
        canonical_json({"head": revision, "applied": revision, "config": effective(foreign)})
    )
    with pytest.raises(BootError, match="head digest changed"):
        site.verify_api_head(fence, private=True)


def recovery_fixture(executor, cfg, *, state="revoked"):
    base = effective(cfg)
    desired = effective(cfg)
    desired["reserved_memory_mb"] += 1
    desired = effective(site.parse_config(desired))
    release = release_for_test()
    request = {
        "base_revision": site.revision_id(base),
        "observed_revision": site.revision_id(base),
        "config": desired,
        "release": release,
    }
    cfg = site.config_from(desired)
    expected = site.deployment_registry(cfg, release["version"])
    record = {
        **asdict(IDENTITY),
        "desired_revision": expected["config_revision"],
        "registry": expected,
        "release": release,
        "base_release": "8.0",
        "uid": os.getuid(),
    }

    def reserve(db, _fence):
        db.execute(
            "INSERT INTO site_deployments VALUES (?, ?, ?)",
            (IDENTITY.operation_id, state, canonical_json(record)),
        )

    fence = executor.begin_deployment_fence(
        base_revision=request["base_revision"],
        desired_revision=expected["config_revision"],
        operation_id=IDENTITY.operation_id,
        reserve_site=reserve,
    )
    assert fence.base_revision != fence.desired_revision
    return request, fence, record


@pytest.mark.parametrize("routed", [False, True])
def test_private_verifier_requires_current_grant_and_exact_live_run(
    executor, cfg, monkeypatch, tmp_path, routed
):
    request, fence, record = recovery_fixture(executor, cfg, state="active")
    grant = {
        "version": 1,
        "server_name": cfg.server.name,
        "base_revision": fence.base_revision,
        "desired_revision": fence.desired_revision,
        "release_hash": site.revision_id(request["release"]),
    }
    if routed:
        grant.update(version=2, application_routes="internal")
        record["application_routes"] = "internal"
    record.update(base_revision=fence.base_revision, private_grant_hash=site.revision_id(grant))
    with executor._db() as db:
        db.execute("UPDATE site_deployments SET body=?", (canonical_json(record),))
    read = Mock(return_value=canonical_json(grant))
    monkeypatch.setattr(site, "executor", lambda: executor)
    monkeypatch.setattr(site, "live_process", lambda _: nullcontext())
    monkeypatch.setattr(site, "status", lambda *_, **__: {"state": "active"})
    monkeypatch.setattr(site, "require_no_application_routes", Mock())
    monkeypatch.setattr(site.enrollment, "read_limited", read)
    monkeypatch.setattr(site.gate, "require_fence", lambda _: fence)
    monkeypatch.setattr(site.gate, "read_record", lambda: site.gate.Record(IDENTITY, os.getuid()))
    monkeypatch.setattr(site.gate, "PROC", tmp_path)
    process = tmp_path / "self"
    process.mkdir()
    membership = process / "cgroup"
    revision = fence.desired_revision
    membership.write_text("0::/system.slice/steward-applications.service\n")
    with pytest.raises(BootError, match="outside the deployment scope"):
        site.require_private_verifier(IDENTITY, revision)
    assert site.require_private_verifier(IDENTITY, revision, scoped=False) is routed
    membership.write_text(f"0::/{IDENTITY.slice}/{IDENTITY.scope_prefix}{'f' * 32}.scope\n")
    assert site.require_private_verifier(IDENTITY, revision) is routed
    site.require_verifier(IDENTITY, revision)
    stale = Identity(IDENTITY.operation_id, "d" * 32, IDENTITY.boot_id)
    foreign = Identity("e" * 32, IDENTITY.run_id, IDENTITY.boot_id)
    for scoped in (True, False):
        with pytest.raises(BootError, match="run or boot"):
            site.require_private_verifier(stale, revision, scoped=scoped)
        with pytest.raises(GateError, match="known operation"):
            site.require_private_verifier(foreign, revision, scoped=scoped)
    read.return_value = canonical_json(grant | {"release_hash": "0" * 64})
    with pytest.raises(BootError, match="exact transition"):
        site.require_verifier(IDENTITY, revision)
    with pytest.raises(BootError, match="exact transition"):
        site.require_private_verifier(IDENTITY, revision, scoped=False)


@pytest.mark.parametrize("routed", [False, True])
def test_private_resume_reuses_exact_original_registry_on_mixed_install(cfg, monkeypatch, routed):
    routes = [{"host": "fixture.example.com", "tls": "internal"}] if routed else []
    base = private_config(cfg, routes=routes)
    desired = private_config(cfg, active=False, routes=routes)
    release = release_for_test()
    peers = dict.fromkeys(("api", "controller", "collector", "scanner"), os.getuid())
    base_registry = site.deployment_registry(base, "8.0") | {"peers": peers}
    desired_registry = site.deployment_registry(desired, release["version"])
    fence = site.DeploymentFence(
        operation_id=IDENTITY.operation_id,
        base_revision=base_registry["config_revision"],
        desired_revision=desired_registry["config_revision"],
    )
    request = {
        "base_revision": fence.base_revision,
        "observed_revision": fence.desired_revision,
        "config": effective(desired),
        "release": release,
    }
    grant = {
        "version": 1,
        "server_name": cfg.server.name,
        "base_revision": fence.base_revision,
        "desired_revision": fence.desired_revision,
        "release_hash": site.revision_id(release),
    }
    if routed:
        grant.update(version=2, application_routes="internal")
    record = {
        **asdict(IDENTITY),
        "uid": os.getuid(),
        "release": release,
        "base_revision": fence.base_revision,
        "desired_revision": fence.desired_revision,
        "registry": desired_registry,
        "base_release": "8.0",
        "base_registry_hash": site.revision_id(base_registry),
        "base_artifact_hash": "0" * 64,
        "private_grant_hash": site.revision_id(grant),
    }
    if routed:
        record["application_routes"] = "internal"
    stub_resume_host(monkeypatch, cfg)
    read = Mock(return_value=canonical_json(grant))
    monkeypatch.setattr(site.enrollment, "read_limited", read)
    monkeypatch.setattr(site, "installed_config", lambda **_: (desired, base_registry))
    check_release = Mock()
    monkeypatch.setattr(site, "verify_release", check_release)
    assert (
        site.validate_resume(request, desired, fence, record, os.getuid(), private=True) is routed
    )
    check_release.assert_called_once_with(release)
    route_option = {"routed": True} if routed else {}
    site.verify_api_head.assert_called_once_with(fence, private=True, **route_option)
    with pytest.raises(BootError, match="original mode"):
        site.validate_resume(request, desired, fence, record, os.getuid())
    base_registry["applications"]["acceptance"]["services"]["worker"]["host_port"] += 1
    with pytest.raises(BootError, match="original deployment boundaries"):
        site.validate_resume(request, desired, fence, record, os.getuid(), private=True)
    read.return_value = canonical_json(grant | {"base_revision": fence.desired_revision})
    with pytest.raises(BootError, match="exact transition"):
        site.validate_resume(request, desired, fence, record, os.getuid(), private=True)


def test_pending_status_requires_known_exact_fence(executor, cfg):
    with executor._db() as db:
        assert site.query_status(db) is None
        with pytest.raises(GateError, match="known operation"):
            site.query_status(db, IDENTITY.operation_id)
    request, fence, record = recovery_fixture(executor, cfg, state="reserved")
    with executor._db() as db:
        assert (
            site.query_status(db)
            == site.query_status(db, IDENTITY.operation_id)
            == {
                **site.public(record, "pending"),
                "base_revision": fence.base_revision,
                "release_hash": site.revision_id(request["release"]),
            }
        )
        db.execute("DELETE FROM site_deployments")
    with executor._db() as db, pytest.raises(GateError, match="known operation"):
        site.query_status(db)


def stub_resume_host(monkeypatch, cfg):
    monkeypatch.setattr(
        site,
        "read_marker",
        lambda: {
            "schema_version": 2,
            "server_name": cfg.server.name,
        },
    )
    monkeypatch.setattr(site, "enrollment_evidence", Mock())
    monkeypatch.setattr(site.pwd, "getpwnam", lambda _: Mock(pw_uid=os.getuid()))
    monkeypatch.setattr(site, "verify_api_head", Mock())


def test_resume_rejects_legacy_mixed_state_and_changed_manifest(executor, cfg, monkeypatch):
    request, fence, record = recovery_fixture(executor, cfg)
    desired = site.config_from(request["config"])
    stub_resume_host(monkeypatch, cfg)
    monkeypatch.setattr(site, "check_base_release", Mock())
    monkeypatch.setattr(site, "verify_registry", Mock())
    installed_registry = {**record["registry"], "release": "8.0"}
    monkeypatch.setattr(site, "installed_config", lambda **_: (cfg, installed_registry))
    with pytest.raises(BootError, match="reviewed deployment boundary"):
        site.validate_resume(request, desired, fence, record, os.getuid())
    installed_registry["config_revision"] = fence.base_revision
    site.validate_resume(request, desired, fence, record, os.getuid())
    site.check_base_release.assert_called_once_with("8.0", request["release"])
    site.verify_api_head.assert_called_once_with(fence)

    altered = {
        **request["release"],
        "files": {**request["release"]["files"], "requirements.txt": "d" * 64},
    }
    with pytest.raises(BootError, match="differs from the original deployment"):
        site.validate_resume({**request, "release": altered}, desired, fence, record, os.getuid())
    with pytest.raises(BootError, match="differs from the original deployment"):
        site.validate_resume(
            {**request, "base_revision": "c" * 64}, desired, fence, record, os.getuid()
        )


def test_resume_requires_exact_target_release_for_either_mixed_state(executor, cfg, monkeypatch):
    request, fence, record = recovery_fixture(executor, cfg)
    desired = site.config_from(request["config"])
    stub_resume_host(monkeypatch, cfg)
    base_registry = site.deployment_registry(cfg, record["base_release"])
    target_registry = {**record["registry"], "peers": {}}
    record["base_registry_hash"] = site.revision_id(base_registry)
    record["base_artifact_hash"] = "e" * 64
    installed, registry = cfg, target_registry
    monkeypatch.setattr(site, "installed_config", lambda **_: (installed, registry))
    monkeypatch.setattr(site, "check_base_release", Mock())
    monkeypatch.setattr(site, "verify_registry", Mock())
    monkeypatch.setattr(site, "verify_release", Mock())

    site.validate_resume(request, desired, fence, record, os.getuid())
    site.verify_registry.assert_called_once_with(desired, registry, record["registry"])
    site.verify_release.assert_called_once_with(request["release"])

    installed, registry = desired, base_registry
    request["observed_revision"] = fence.desired_revision
    site.verify_registry.reset_mock()
    site.verify_release.reset_mock()
    site.validate_resume(request, desired, fence, record, os.getuid())
    site.verify_release.assert_called_once_with(request["release"])
    site.check_base_release.assert_not_called()
    site.verify_registry.assert_not_called()

    site.verify_release.side_effect = BootError("active release differs")
    with pytest.raises(BootError, match="active release differs"):
        site.validate_resume(request, desired, fence, record, os.getuid())

    registry["release"] = "unknown"
    with pytest.raises(BootError, match="registry differs"):
        site.validate_resume(request, desired, fence, record, os.getuid())


def test_same_version_base_needs_original_or_exact_target_artifacts(monkeypatch, tmp_path):
    release = release_for_test()
    root = tmp_path / release["version"]
    paths = {
        name: root / name if name.startswith("bundles/") else root / "dist" / name
        for name in release["files"]
    }
    for name, path in paths.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"base")
        release["files"][name] = hashlib.sha256(b"target").hexdigest()
    monkeypatch.setattr(site.boot, "RELEASES", tmp_path)
    monkeypatch.setattr(site.boot, "safe_directory", lambda path: path.stat())
    monkeypatch.setattr(site.boot, "protected", lambda path, _: path.open("rb"))
    monkeypatch.setattr(site, "active_release", lambda: release["version"])
    monkeypatch.setattr(site, "verify_release", Mock(wraps=site.verify_release))
    original = site.base_artifact_hash(release["version"])
    site.check_base_release(release["version"], release, original)
    site.verify_release.assert_not_called()

    paths[release["wheel"]].write_bytes(b"target")
    with pytest.raises(BootError, match="installed release artifact differs"):
        site.check_base_release(release["version"], release, original)

    site.verify_release.reset_mock()
    for path in paths.values():
        path.write_bytes(b"target")
    site.check_base_release(release["version"], release, original)
    site.verify_release.assert_called_once_with(release)


def test_reconcile_dead_same_boot_cleans_exact_slice(executor, cfg, monkeypatch, tmp_path):
    _, fence, _ = recovery_fixture(executor, cfg, state="active")
    boot_id = tmp_path / "boot"
    boot_id.write_text(IDENTITY.boot_id)
    (tmp_path / "cgroup.controllers").touch()
    monkeypatch.setattr(site.gate, "BOOT_ID", boot_id)
    monkeypatch.setattr(site.gate, "CGROUP", tmp_path)
    monkeypatch.setattr(site.gate, "control_lock", nullcontext)
    monkeypatch.setattr(site.gate, "cleanup_locked", Mock())
    monkeypatch.setattr(
        site, "unit_properties", lambda _: {"MainPID": "0", "ActiveState": "inactive"}
    )
    monkeypatch.setattr(site, "is_live", lambda _: True)
    with pytest.raises(BootError, match="use exact revoke first"):
        site.reconcile_dead(executor, IDENTITY)
    site.gate.cleanup_locked.assert_not_called()
    monkeypatch.setattr(site, "is_live", lambda _: False)
    assert site.reconcile_dead(executor, IDENTITY)["state"] == "revoked"
    site.gate.cleanup_locked.assert_called_once_with(IDENTITY, allow_missing=True)
    assert executor.deployment_fence() == fence


def test_previous_boot_reconcile_uses_exact_record_and_no_host_signal(
    executor, cfg, monkeypatch, tmp_path
):
    _, fence, _ = recovery_fixture(executor, cfg, state="active")
    boot_id = tmp_path / "boot"
    boot_id.write_text("d" * 8 + "-dddd-dddd-dddd-" + "d" * 12)
    monkeypatch.setattr(site.gate, "BOOT_ID", boot_id)
    monkeypatch.setattr(site.gate, "control_lock", nullcontext)
    monkeypatch.setattr(site.gate, "cleanup_locked", Mock())
    monkeypatch.setattr(site, "unit_properties", Mock())
    monkeypatch.setattr(site, "require_empty_gate", Mock())
    wrong = Identity(IDENTITY.operation_id, "d" * 32, IDENTITY.boot_id)
    with pytest.raises(BootError, match="run or boot"):
        site.reconcile_dead(executor, wrong)
    assert site.reconcile_dead(executor, IDENTITY)["state"] == "revoked"
    site.require_empty_gate.assert_called_once()
    site.gate.cleanup_locked.assert_not_called()
    site.unit_properties.assert_not_called()
    assert executor.deployment_fence() == fence


def test_coordinator_epoch_rotation_keeps_exact_fence_on_both_sides_of_commit(
    executor, cfg, monkeypatch, tmp_path
):
    request, fence, record = recovery_fixture(executor, cfg)
    base = {"base_registry_hash": "e" * 64, "base_artifact_hash": "f" * 64}
    with executor._db() as db:
        db.execute("UPDATE site_deployments SET body=?", (canonical_json(record | base),))
    fresh = Identity(IDENTITY.operation_id, "d" * 32, IDENTITY.boot_id)
    competing = Identity(IDENTITY.operation_id, "e" * 32, IDENTITY.boot_id)
    boot_id = tmp_path / "boot"
    boot_id.write_text(IDENTITY.boot_id)
    monkeypatch.setattr(site.gate, "BOOT_ID", boot_id)
    monkeypatch.setattr(site.gate, "RUNTIME", tmp_path)
    monkeypatch.setattr(site.gate, "control_lock", nullcontext)
    monkeypatch.setattr(site.gate, "serve", Mock(side_effect=GateError("gate could not bind")))
    monkeypatch.setattr(site, "executor", lambda: executor)
    monkeypatch.setattr(site, "process_identity", lambda _: {})
    monkeypatch.setattr(site, "validate_resume", Mock())
    monkeypatch.setattr(site.signal, "signal", Mock())
    monkeypatch.setattr(site.pwd, "getpwnam", lambda _: Mock(pw_uid=record["uid"]))
    monkeypatch.setattr(site.boot, "safe_directory", Mock())
    monkeypatch.setattr(
        site.boot, "store", lambda path, payload: path.write_text(canonical_json(payload))
    )
    monkeypatch.setattr(site.boot, "read_bytes", lambda path: path.read_bytes())
    monkeypatch.setattr(executor.host, "deployment_rollbacks_quiescent", lambda: True)
    site.write_request(fresh, request, record["uid"], previous=IDENTITY)
    site.write_request(competing, request, record["uid"], previous=IDENTITY)
    assert site.request_path(fresh) != site.request_path(competing)

    with executor._db() as db:
        db.execute(
            "CREATE TRIGGER failed_rotate BEFORE UPDATE OF body ON site_deployments "
            "BEGIN SELECT RAISE(ABORT, 'interrupted during rotation'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="interrupted during rotation"):
        site.coordinate(fresh)
    assert executor.deployment_fence() == fence
    with executor._db() as db:
        assert site.query_status(db)["run_id"] == IDENTITY.run_id
        assert site.query_status(db)["state"] == "revoked"
        db.execute("DROP TRIGGER failed_rotate")
    site.gate.serve.assert_not_called()

    with pytest.raises(GateError, match="gate could not bind"):
        site.coordinate(fresh)
    assert executor.deployment_fence() == fence
    with executor._db() as db:
        status = site.query_status(db)
        assert status["run_id"] == fresh.run_id
        assert status["state"] == "pending"
        assert db.execute("SELECT COUNT(*) FROM site_deployments").fetchone() == (1,)
        durable = site.get_record(db, fresh)[1]
        assert durable["previous"] == asdict(IDENTITY)
        assert {field: durable[field] for field in base} == base
    with pytest.raises(BootError, match="run or boot"):
        site.coordinate(competing)
    assert executor.deployment_fence() == fence


def test_finish_reports_known_dead_epoch_as_pending(executor, cfg, monkeypatch, tmp_path):
    _, fence, _ = recovery_fixture(executor, cfg, state="active")
    boot_id = tmp_path / "boot"
    boot_id.write_text(IDENTITY.boot_id)
    monkeypatch.setattr(site.gate, "BOOT_ID", boot_id)
    monkeypatch.setattr(site, "live_process", Mock(side_effect=ProcessLookupError))
    monkeypatch.setattr(
        site, "unit_properties", lambda _: {"MainPID": "0", "ActiveState": "failed"}
    )
    with pytest.raises(GateError, match="exited without completing; recovery is pending"):
        site.request_close(executor, IDENTITY, "finish")
    with executor._db() as db:
        assert site.get_record(db, IDENTITY)[0] == "pending"
    assert executor.deployment_fence() == fence


@pytest.mark.parametrize("outcome", ["pending", "complete", "corrupt", "gate-failed", "stale"])
def test_routed_stop_hook_reconciles_exact_custody(executor, cfg, monkeypatch, tmp_path, outcome):
    _, fence, record = recovery_fixture(executor, cfg, state="closing")
    invocation = "d" * 32
    record.update(
        application_routes="internal",
        base_revision=fence.base_revision,
        release_hash=site.revision_id(record["release"]),
        private_grant_hash="e" * 64,
        process={"invocation": invocation if outcome != "stale" else "f" * 32},
    )
    with executor._db() as db:
        db.execute("UPDATE site_deployments SET body=?", (canonical_json(record),))
    if outcome == "complete":
        site.commit_success(executor, IDENTITY, fence, record)
    boot_id = tmp_path / "boot"
    boot_id.write_text(IDENTITY.boot_id)
    (tmp_path / "self").mkdir()
    cgroup = f"/system.slice/{site.unit(IDENTITY)}"
    (tmp_path / "self" / "cgroup").write_text(f"0::{cgroup}\n")
    monkeypatch.setattr(site.gate, "BOOT_ID", boot_id)
    monkeypatch.setattr(site.gate, "PROC", tmp_path)
    monkeypatch.setenv("INVOCATION_ID", invocation)
    monkeypatch.setattr(
        site, "unit_properties", lambda _: {"InvocationID": invocation, "ControlGroup": cgroup}
    )
    monkeypatch.setattr(site.boot, "deployment_lock", lambda *, timeout: nullcontext())
    monkeypatch.setattr(
        site.boot,
        "executor_state_snapshot",
        Mock(side_effect=sqlite3.DatabaseError) if outcome == "corrupt" else executor._db,
    )
    sequence = Mock()
    if outcome == "gate-failed":
        sequence.transport.side_effect = GateError("could not drain transport")
    monkeypatch.setattr(site.gate, "control_lock", nullcontext)
    monkeypatch.setattr(site.gate, "cleanup_locked", sequence.transport)
    monkeypatch.setattr(site.boot, "reconcile_guarded_routes", sequence.routes)
    monkeypatch.setattr(site, "Host", lambda: executor.host)

    if outcome == "corrupt":
        with pytest.raises(BootError, match="durable deployment custody"):
            site.route_stop_hook(IDENTITY)
    elif outcome == "gate-failed":
        with pytest.raises(GateError, match="drain transport"):
            site.route_stop_hook(IDENTITY)
    else:
        site.route_stop_hook(IDENTITY)
    if outcome == "stale":
        assert sequence.mock_calls == []
        return
    assert [call[0] for call in sequence.mock_calls] == ["transport", "routes"]
    sequence.transport.assert_called_once_with(IDENTITY, allow_missing=True)
    extra = {"allow_early": False} if outcome == "gate-failed" else {}
    sequence.routes.assert_called_once_with(
        executor.host,
        IDENTITY,
        None if outcome == "corrupt" else record["desired_revision"],
        committed=outcome == "complete",
        **extra,
    )


def test_routed_coordinator_uses_admission_release_for_stop_hook(executor, monkeypatch, tmp_path):
    python = "/opt/steward/releases/8.0/venv/bin/python"
    monkeypatch.setattr(site, "coordinator_python", lambda: python)
    monkeypatch.setattr(site.gate, "RUNTIME", tmp_path)
    systemd = Mock()
    monkeypatch.setattr(site.gate, "run_systemd", systemd)
    monkeypatch.setattr(site, "status", lambda *_, **__: {"state": "active"})
    site.start_coordinator(executor, IDENTITY, routed=True)
    argv = systemd.call_args.args[0]
    tokens = list(asdict(IDENTITY).values())
    assert "--property=TimeoutStopSec=60s" in argv
    assert (
        "--property=ExecStopPost="
        + " ".join([python, "-I", "-m", site.COMMAND, "_route_stop", *tokens])
        in argv
    )
    assert argv[-8:] == [python, "-I", "-m", site.COMMAND, "_coordinate", *tokens]


def test_exact_finish_retries_failed_postcommit_cleanup(executor, cfg, monkeypatch, tmp_path):
    _, fence, record = recovery_fixture(executor, cfg, state="closing")
    record.update(
        application_routes="internal",
        base_revision=fence.base_revision,
        release_hash=site.revision_id(record["release"]),
        private_grant_hash="e" * 64,
        process={"invocation": "f" * 32},
    )
    site.commit_success(executor, IDENTITY, fence, record)
    journal = tmp_path / site.boot.GUARDED_ROUTE_JOURNAL
    journal.touch()
    boot_id = tmp_path / "boot"
    boot_id.write_text(IDENTITY.boot_id)
    monkeypatch.setattr(site.boot, "RUNTIME", tmp_path)
    monkeypatch.setattr(site.gate, "BOOT_ID", boot_id)
    monkeypatch.setattr(
        site, "unit_properties", lambda _: {"MainPID": "0", "ActiveState": "failed"}
    )
    monkeypatch.setattr(site.boot, "executor_state_snapshot", executor._db)
    reconcile = Mock(side_effect=BootError("runtime cleanup failed"))
    monkeypatch.setattr(site.boot, "reconcile_guarded_routes", reconcile)
    with pytest.raises(BootError, match="runtime cleanup failed"):
        site.request_close(executor, IDENTITY, "finish")
    assert executor.deployment_fence() is None
    assert journal.exists()
    reconcile.reset_mock(side_effect=True)
    reconcile.side_effect = lambda *_args, **_kwargs: journal.unlink()
    assert site.request_close(executor, IDENTITY, "finish") == site.public(record, "complete")
    reconcile.assert_called_once_with(
        executor.host, IDENTITY, record["desired_revision"], committed=True
    )


@pytest.mark.parametrize("fail_commit", [False, True])
def test_routed_coordinator_closes_transport_before_publishing(
    executor, cfg, monkeypatch, tmp_path, fail_commit
):
    request, fence, durable = recovery_fixture(executor, cfg, state="closing")
    del request["observed_revision"]
    invocation = {"invocation": "d" * 32}
    desired_revision = fence.desired_revision
    boot_id = tmp_path / "boot"
    boot_id.write_text(IDENTITY.boot_id)
    monkeypatch.setattr(site, "executor", lambda: executor)
    monkeypatch.setattr(site, "process_identity", lambda _: invocation)
    monkeypatch.setattr(site.gate, "BOOT_ID", boot_id)
    monkeypatch.setattr(site.gate, "RUNTIME", tmp_path)
    monkeypatch.setattr(site.gate, "serve", Mock())
    monkeypatch.setattr(site.signal, "signal", Mock())
    monkeypatch.setattr(site.boot, "read_bytes", lambda path: path.read_bytes())
    monkeypatch.setattr(
        site.boot, "store", lambda path, payload: path.write_text(canonical_json(payload))
    )
    monkeypatch.setattr(executor, "deployment_execution", lambda **_: nullcontext(fence))
    monkeypatch.setattr(executor.host, "deployment_rollbacks_quiescent", lambda: True)
    site.write_request(IDENTITY, request, durable["uid"], private_grant_hash="e" * 64, routed=True)
    calls = Mock()
    calls.configuration.return_value = cfg, durable["registry"]
    monkeypatch.setattr(site.gate, "cleanup", calls.transport)
    monkeypatch.setattr(site, "verify_configuration", calls.configuration)
    monkeypatch.setattr(site, "check_platform", calls.platform)
    monkeypatch.setattr(site.boot, "verify_guarded_deployment", calls.publish)
    monkeypatch.setattr(site, "require_private_grant", calls.grant)
    monkeypatch.setattr(site.boot, "reconcile_guarded_routes", calls.reconcile)
    original_commit = site.commit_success
    calls.commit.side_effect = (
        sqlite3.DatabaseError("commit failed") if fail_commit else original_commit
    )
    monkeypatch.setattr(site, "commit_success", calls.commit)

    if fail_commit:
        with pytest.raises(sqlite3.DatabaseError, match="commit failed"):
            site.coordinate(IDENTITY)
        assert executor.deployment_fence() == fence
    else:
        site.coordinate(IDENTITY)
        assert executor.deployment_fence() is None
    assert [call[0] for call in calls.mock_calls] == [
        "transport",
        "configuration",
        "platform",
        "configuration",
        "publish",
        "grant",
        "commit",
        "reconcile",
    ]
    assert calls.publish.call_args.args == (executor.host, desired_revision)
    assert calls.publish.call_args.kwargs["route_identity"] == IDENTITY
    assert site.boot.is_digest(calls.publish.call_args.kwargs["route_generation"])
    calls.reconcile.assert_called_once_with(
        executor.host, IDENTITY, desired_revision, committed=not fail_commit
    )


@pytest.mark.parametrize("active", [True, False])
def test_fresh_private_removal_requires_root_derived_roster_and_protocol(cfg, active):
    base = private_config(cfg, active=active)
    release = release_for_test()
    registry = site.deployment_registry(base, release["version"])
    request = {
        "base_revision": registry["config_revision"],
        "config": effective(cfg),
        "release": release,
    }
    assert site.validate_request(request, private=True) == cfg
    with pytest.raises(BootError, match="requires the retirement protocol"):
        site.fresh_retirements(request, registry, cfg, private=True)

    marked = request | {"retirement_protocol": 1}
    assert site.validate_request(marked, private=True) == cfg
    [candidate] = site.fresh_retirements(marked, registry, cfg, private=True)
    assert candidate.application == "acceptance"
    assert candidate.stage == ("needs_disable" if active else "ready")
    with pytest.raises(BootError, match="requires the retirement protocol"):
        site.fresh_retirements(marked, registry, base, private=True)
    with pytest.raises(BootError, match="unsupported retirement protocol"):
        site.validate_request(marked | {"retirement_protocol": True}, private=True)
    with pytest.raises(BootError, match="invalid deployment request"):
        site.validate_request(marked)
    with pytest.raises(BootError, match="invalid deployment recovery request"):
        site.request_config(
            marked | {"observed_revision": request["base_revision"]}, private=True, recovery=True
        )

    application = registry["applications"]["acceptance"]
    application["services"]["worker"]["manage"] = False
    with pytest.raises(BootError, match="unmanaged_services"):
        site.fresh_retirements(marked, registry, cfg, private=True)
    application["isolation"] = "shared"
    with pytest.raises(BootError, match="shared_isolation_unavailable"):
        site.fresh_retirements(marked, registry, cfg, private=True)


def retirement_custody_fixture(executor, cfg, *, state="active"):
    base = private_config(cfg, archive_authorized=True)
    release = release_for_test()
    peers = dict.fromkeys(("api", "controller", "collector", "scanner"), os.getuid())
    registry = site.deployment_registry(base, release["version"]) | {"peers": peers}
    expected = site.deployment_registry(cfg, release["version"])
    candidates = site.fresh_retirements({"retirement_protocol": 1}, registry, cfg, private=True)
    record = {
        **asdict(IDENTITY),
        "uid": os.getuid(),
        "base_revision": registry["config_revision"],
        "desired_revision": expected["config_revision"],
        "registry": expected,
        "release": release,
        "base_release": release["version"],
        "base_registry_hash": site.revision_id(registry),
        "base_artifact_hash": site.revision_id(release["files"]),
        "private_grant_hash": "e" * 64,
        "retirement": {
            "candidates": [candidate.model_dump(mode="json") for candidate in candidates],
            "receipts": {},
        },
    }

    def reserve(db, _fence):
        db.execute(
            "INSERT INTO site_deployments VALUES (?, ?, ?)",
            (IDENTITY.operation_id, state, canonical_json(record)),
        )

    executor.registry_file.write_text(canonical_json(registry))
    fence = site.DeploymentFence(
        operation_id=IDENTITY.operation_id,
        base_revision=record["base_revision"],
        desired_revision=record["desired_revision"],
    )
    if state is not None:
        executor.begin_deployment_fence(**fence.model_dump(), reserve_site=reserve)
    return base, registry, fence, record


def retirement_journal(fence):
    return site.app_archive.ArchiveState(
        operation_id="f" * 32,
        application="acceptance",
        phase="released",
        generation=6,
        created_at=1.0,
        updated_at=2.0,
        applied_revision=fence.base_revision,
        desired_revision=fence.desired_revision,
        manifest_id="d" * 64,
        released={"worker": "deleted"},
    )


def released_receipt(journal):
    return {
        "operation_id": journal.operation_id,
        "archive_id": journal.manifest_id,
        "released": dict(journal.released),
    }


def test_retirement_requires_custody_before_inhibit_and_persists_receipt(
    executor, cfg, monkeypatch
):
    base, registry, fence, record = retirement_custody_fixture(executor, cfg)
    journal = retirement_journal(fence)
    receipt = released_receipt(journal)
    state = Mock(return_value="active")
    monkeypatch.setattr(site, "live_state", lambda record, persisted: state())
    assert site.status(executor, IDENTITY, admission=True)["retirement_required"] is True
    assert "retirement_required" not in site.status(executor, IDENTITY)
    scoped = Mock(return_value=False)
    monkeypatch.setattr(site, "require_active_verifier", scoped)
    monkeypatch.setattr(site, "installed_config", lambda **_: (base, registry))
    monkeypatch.setattr(site, "active_release", lambda: record["base_release"])
    monkeypatch.setattr(site.boot, "runtime_lock", nullcontext)
    barrier = Mock()
    monkeypatch.setattr(site.boot, "require_route_transition_clear", barrier)
    monkeypatch.setattr(site.boot, "route_present", lambda: False)
    hold = {}
    monkeypatch.setattr(site.boot, "read_optional", lambda _: hold or None)

    def inhibit(_, identity, revision, generation, *, routed):
        assert not routed
        hold.update(site.boot.private_hold(identity, revision, generation))
        return True

    inhibit_mock = Mock(side_effect=inhibit)
    monkeypatch.setattr(site.boot, "inhibit_private", inhibit_mock)
    monkeypatch.setattr(site.app_archive, "active_operation", lambda *_: journal)
    kill = Mock(return_value=True)
    monkeypatch.setattr(executor.host, "kill_switch", kill)

    def retire(_, protected_registry, candidate, revision, custody):
        assert protected_registry == registry
        assert candidate.application == "acceptance"
        assert revision == fence.desired_revision
        with executor._db() as db:
            assert site.get_record(db, IDENTITY)[1]["retirement"]["receipts"] == {}
        custody()
        return {**receipt, "state": "released", "changed": True}

    driver = Mock(side_effect=retire)
    monkeypatch.setattr(site.retirement, "retire_guarded_application", driver)
    with pytest.raises(site.ExecutorError, match="retirement is stopped"):
        site.retire_before_cutover(executor, IDENTITY, fence.desired_revision)
    inhibit_mock.assert_not_called()
    driver.assert_not_called()
    with pytest.raises(BootError, match="exact installed release"):
        site.require_retirement_release(record | {"base_artifact_hash": "0" * 64})

    kill.return_value = False
    with executor._db() as db:
        db.execute(
            "CREATE TRIGGER interrupt_retirement BEFORE UPDATE ON site_deployments "
            "BEGIN SELECT RAISE(ABORT, 'interrupted receipt'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="interrupted receipt"):
        site.retire_before_cutover(executor, IDENTITY, fence.desired_revision)
    with executor._db() as db:
        assert site.get_record(db, IDENTITY)[1]["retirement"]["receipts"] == {}
        db.execute("DROP TRIGGER interrupt_retirement")
    assert site.retire_before_cutover(executor, IDENTITY, fence.desired_revision) == {
        "changed": True
    }
    with executor._db() as db:
        assert site.get_record(db, IDENTITY)[1]["retirement"]["receipts"] == {"acceptance": receipt}
    assert site.retire_before_cutover(executor, IDENTITY, fence.desired_revision) == {
        "changed": False
    }
    assert driver.call_count == inhibit_mock.call_count == 2
    assert executor.deployment_fence() == fence
    scoped.assert_called_with(
        IDENTITY, fence.desired_revision, private_only=True, scoped=True, retiring=True, ex=executor
    )
    barrier.assert_called_with()


def test_retirement_resume_requires_released_receipts_after_either_cutover(
    executor, cfg, monkeypatch
):
    base, registry, fence, record = retirement_custody_fixture(executor, cfg, state="revoked")
    stub_resume_host(monkeypatch, cfg)
    monkeypatch.setattr(site, "require_private_grant", lambda _: False)
    monkeypatch.setattr(site, "check_base_release", Mock())
    monkeypatch.setattr(site, "verify_release", Mock())
    installed = Mock(return_value=(base, registry))
    monkeypatch.setattr(site, "installed_config", installed)
    request = {
        "base_revision": fence.base_revision,
        "observed_revision": fence.base_revision,
        "config": effective(cfg),
        "release": record["release"],
    }
    assert site.validate_resume(request, cfg, fence, record, os.getuid(), private=True) is False
    site.verify_api_head.assert_called_once_with(fence, private=True, routed=False, retirement=True)

    journal = retirement_journal(fence)
    observed_journal = Mock(return_value=journal)
    monkeypatch.setattr(site.app_archive, "active_operation", observed_journal)
    target_registry = dict(record["registry"], peers=registry["peers"])
    for config, current in ((cfg, registry), (base, target_registry)):
        installed.return_value = config, current
        request["observed_revision"] = site.revision_id(effective(config))
        receipts = record["retirement"]["receipts"]
        receipts.clear()
        with pytest.raises(BootError, match="retirement receipts are incomplete"):
            site.validate_resume(request, cfg, fence, record, os.getuid(), private=True)
        receipts["acceptance"] = released_receipt(journal)
        assert site.validate_resume(request, cfg, fence, record, os.getuid(), private=True) is False
        receipts["acceptance"]["archive_id"] = "0" * 64
        with pytest.raises(BootError, match="journal differs"):
            site.validate_resume(request, cfg, fence, record, os.getuid(), private=True)
        legacy = {key: value for key, value in record.items() if key != "retirement"}
        assert site.validate_resume(request, cfg, fence, legacy, os.getuid(), private=True) is False


@pytest.mark.parametrize(
    "released, blocked",
    [(False, None), (True, None), (False, "data"), (False, "incident"), (False, "journal")],
)
def test_retirement_coordinator_keeps_fence_until_exact_release_receipt(
    executor, cfg, monkeypatch, tmp_path, released, blocked
):
    base, registry, fence, record = retirement_custody_fixture(executor, cfg, state=None)
    if blocked == "data":
        registry["applications"]["acceptance"]["services"]["worker"]["allow_backup_pause"] = False
        executor.registry_file.write_text(canonical_json(registry))
    elif blocked == "incident":
        monkeypatch.setattr(
            site.retirement.IncidentStore, "get", Mock(return_value=Mock(phase="quarantined"))
        )
    journal = retirement_journal(fence)
    if blocked == "journal":
        (tmp_path / "archive" / "acceptance").mkdir(parents=True)
        monkeypatch.setattr(site.app_archive, "ARCHIVE_ROOT", tmp_path / "archive")
        journal = journal.model_copy(update={"desired_revision": "0" * 64})
    request = {
        "base_revision": fence.base_revision,
        "config": effective(cfg),
        "release": record["release"],
        "retirement_protocol": 1,
    }
    boot_id = tmp_path / "boot"
    boot_id.write_text(IDENTITY.boot_id)
    monkeypatch.setattr(site, "executor", lambda: executor)
    monkeypatch.setattr(site, "process_identity", lambda _: {"invocation": "d" * 32})
    monkeypatch.setattr(site.gate, "BOOT_ID", boot_id)
    monkeypatch.setattr(site.gate, "RUNTIME", tmp_path)
    monkeypatch.setattr(site.gate, "control_lock", nullcontext)
    monkeypatch.setattr(site.gate, "cleanup", Mock())
    monkeypatch.setattr(site.signal, "signal", Mock())
    monkeypatch.setattr(site.boot, "read_bytes", lambda path: path.read_bytes())
    monkeypatch.setattr(
        site.boot, "store", lambda path, payload: path.write_text(canonical_json(payload))
    )
    monkeypatch.setattr(site.boot, "require_route_transition_clear", Mock())
    monkeypatch.setattr(site, "require_empty_gate", Mock())
    monkeypatch.setattr(site, "validate_base", lambda *_, **__: (base, registry))
    monkeypatch.setattr(site.pwd, "getpwnam", lambda _: Mock(pw_uid=record["uid"]))
    monkeypatch.setattr(site, "require_private_grant", Mock(return_value=False))
    monkeypatch.setattr(site, "active_release", lambda: record["base_release"])
    monkeypatch.setattr(site, "base_artifact_hash", lambda _: record["base_artifact_hash"])
    monkeypatch.setattr(site, "verify_api_head", Mock())
    verification = Mock(return_value=(cfg, record["registry"]))
    monkeypatch.setattr(site, "verify_configuration", verification)
    monkeypatch.setattr(site, "check_platform", Mock())
    monkeypatch.setattr(site.boot, "verify_guarded_deployment", Mock())
    monkeypatch.setattr(executor.host, "deployment_rollbacks_quiescent", lambda: True)
    monkeypatch.setattr(site.app_archive, "active_operation", lambda *_: journal)
    site.write_request(IDENTITY, request, record["uid"], private_grant_hash="e" * 64)

    def serve(_operation_id, _uid, *, on_ready, **_):
        on_ready()
        with executor._db() as db:
            state, admitted = site.get_record(db, IDENTITY)
            assert state == "active"
            assert admitted["retirement"] == record["retirement"]
            assert site.fence_in(db) == fence
            if released:
                admitted["retirement"]["receipts"]["acceptance"] = released_receipt(journal)
            db.execute(
                "UPDATE site_deployments SET state='closing', body=? WHERE operation_id=?",
                (canonical_json(admitted), IDENTITY.operation_id),
            )

    serve_gate = Mock(side_effect=serve)
    monkeypatch.setattr(site.gate, "serve", serve_gate)
    if blocked:
        expected = {
            "data": "application data archive is not authorized",
            "incident": "an application incident is unfinished",
            "journal": "an unfinished retirement is bound to other revisions",
        }[blocked]
        with pytest.raises(site.ExecutorError, match=expected):
            site.coordinate(IDENTITY)
        assert executor.deployment_fence() is None
        with executor._db() as db:
            assert db.execute("SELECT 1 FROM site_deployments").fetchone() is None
        serve_gate.assert_not_called()
        verification.assert_not_called()
    elif released:
        site.coordinate(IDENTITY)
        assert executor.deployment_fence() is None
        with executor._db() as db:
            state, result = site.get_record(db, IDENTITY)
        assert state == "complete"
        assert result["retirement"]["receipts"] == {"acceptance": released_receipt(journal)}
        verification.assert_called()
    else:
        with pytest.raises(BootError, match="retirement receipts are incomplete"):
            site.coordinate(IDENTITY)
        assert executor.deployment_fence() == fence
        with executor._db() as db:
            assert site.get_record(db, IDENTITY)[0] == "pending"
        verification.assert_not_called()
    assert site.verify_api_head.call_args_list[0].kwargs == {
        "private": True,
        "routed": False,
        "retirement": True,
        "fresh": True,
    }
