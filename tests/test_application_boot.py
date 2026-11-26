import json
import sqlite3
from contextlib import closing, contextmanager, nullcontext
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from steward import __version__
from steward import application_boot as boot
from steward.core.application_ops import derive_group_plan
from steward.core.config import Health, effective, load_config_file
from steward.core.group_checkpoint import GroupCheckpoint, GroupPlan
from steward.core.render import (
    ApplicationProxyRoute,
    prepare_application_registry,
    render_application_quadlets,
)
from steward.executor import deployment_gate, site_deployment
from steward.executor import host as host_module
from steward.executor.deployment_launcher import Identity
from steward.executor.host import Host
from steward.executor.server import Executor

GENERATION = "a" * 64
RUNTIME_HASH = "c" * 64
HELPER_HASHES = {"identity": "d" * 64, "dispatch": "e" * 64, "firewall": "f" * 64}
HEALTH = Health(retries=1)


def pin(offset):
    return {
        "uid": 30000 + offset,
        "gid": 30000 + offset,
        "subuid": [200000 + offset * 65536, 65536],
        "subgid": [200000 + offset * 65536, 65536],
    }


def target(service, offset, *, app="example", isolation="separate", enabled=True):
    return boot.Target(
        boot.Binding(app, service, isolation, pin(offset)),
        enabled,
        21001 + offset if service else None,
        HEALTH if service else None,
    )


class FakeHost:
    def __init__(self, targets):
        self.running = {item.binding.unit: False for item in targets}
        self.unhealthy = set()
        self.calls = []
        self.stop_failure = set()
        self.transitioning = set()
        self.stopped_managers = set()
        self.pods = {item.binding.pod_name: [] for item in targets if item.binding.service is None}

    def start_application_manager(self, uid):
        self.calls.append(("manager", uid))
        return True

    def application_unit_authority(self, user, unit, source):
        return True

    def application_unit_transitioning(self, user, unit):
        return unit in self.transitioning

    def application_manager_quiescent(self, uid, subuid):
        return uid in self.stopped_managers

    def group_service_running(self, user, unit, stem):
        return self.running[unit]

    def group_service_quiescent(self, user, unit, stem):
        return self.running[unit] is False

    def user_unit(self, user, unit):
        active, sub = ("active", "running") if self.running[unit] else ("inactive", "dead")
        return {"load": "loaded", "active": active, "sub": sub}

    def application_pod_members(self, user, pod, *, require_running=True):
        return self.pods[pod]

    def application_pod_absent(self, user, pod):
        return not self.pods[pod]

    def http_health(self, port, path, timeout):
        self.calls.append(("health", port))
        return {"ok": port not in self.unhealthy}

    def set_user_unit(self, user, unit, *, running):
        verb = "start" if running else "stop"
        self.calls.append((verb, unit))
        if running:
            assert unit in [binding.unit for binding in boot.read_active().pending]
        elif unit in self.stop_failure:
            return False
        self.transitioning.discard(unit)
        self.running[unit] = running
        return True


@pytest.fixture
def executor_state(tmp_path, monkeypatch):
    state = tmp_path / "executor-state"
    state.mkdir(mode=0o700)
    registry = tmp_path / "executor.json"
    registry.write_text(json.dumps({"config_revision": GENERATION}))
    registry.chmod(0o600)
    executor = Executor(
        registry_path=str(registry),
        state_dir=str(state),
        audit_path=str(tmp_path / "executor-audit.jsonl"),
        lock_dir=str(tmp_path / "executor-locks"),
    )
    database = state / "state.db"
    database.chmod(0o600)
    monkeypatch.setattr(boot, "EXECUTOR_STATE_DB", database)
    return executor, database


@pytest.fixture
def lifecycle(tmp_path, monkeypatch, executor_state):
    (tmp_path / "run").mkdir()
    (tmp_path / "state").mkdir()
    monkeypatch.setattr(boot, "RUNTIME", tmp_path / "run")
    monkeypatch.setattr(boot, "STATE", tmp_path / "state")
    monkeypatch.setattr(boot, "safe_directory", lambda path: None)
    monkeypatch.setattr(boot, "guard_helpers", lambda: HELPER_HASHES)

    @contextmanager
    def protected(path, mode, gid=0):
        assert path.stat().st_mode & 0o777 == mode
        with path.open("rb") as file:
            yield file

    monkeypatch.setattr(boot, "protected", protected)

    def configure(targets):
        evidence = {"identities": {item.binding.user: item.binding.identity for item in targets}}
        host = FakeHost(targets)
        monkeypatch.setattr(
            boot, "deployment_inputs", lambda inputs: (targets, evidence.copy(), ())
        )
        monkeypatch.setattr(boot, "inspect_identity", evidence["identities"].__getitem__)
        monkeypatch.setattr(boot, "verify_stop_identity", lambda binding: None)

        def verify(inputs, observed):
            host.calls.append(("firewall",))
            return RUNTIME_HASH

        monkeypatch.setattr(boot, "verify_firewall", verify)
        boot.store(
            boot.STATE / "application-boot.json",
            {
                "generation": GENERATION,
                "inputs": {},
                "evidence": {
                    **evidence,
                    "firewall_runtime": RUNTIME_HASH,
                    "helpers": HELPER_HASHES,
                },
            },
        )
        return host

    return configure


def test_guarded_handoff_rechecks_exact_live_run_and_adopts_without_activation(
    lifecycle, tmp_path, monkeypatch
):
    dependency = target("source", 1)
    dependent = target("client", 0)
    host = lifecycle([dependency, dependent])
    host.running = dict.fromkeys(host.running, True)
    revision = "b" * 64
    boot_id = "12345678-1234-1234-1234-123456789abc"
    old = Identity("1" * 32, "2" * 32, boot_id)
    current = Identity(old.operation_id, "3" * 32, boot_id)
    other = Identity("4" * 32, current.run_id, boot_id)
    active_identity = old
    scopes = []

    def verify(identity, expected_revision, *, scoped=True):
        scopes.append(scoped)
        boot.require(
            identity == active_identity and expected_revision == revision, "stale private binding"
        )

    monkeypatch.setattr(site_deployment, "require_private_verifier", verify)
    monkeypatch.setattr(boot, "desired_configuration", lambda: SimpleNamespace(applications=[]))
    monkeypatch.setattr(boot, "route_present", lambda: False)
    systemd = tmp_path / "systemd"
    systemd.mkdir()
    unit = systemd / boot.BOOT_UNIT
    unit.write_text("root-owned boot unit\n")
    unit.chmod(0o644)
    monkeypatch.setattr(boot, "SYSTEMD", systemd)
    props = {
        "LoadState": "loaded",
        "FragmentPath": str(unit),
        "DropInPaths": "",
        "NeedDaemonReload": "no",
        "ActiveState": "inactive",
    }
    monkeypatch.setattr(boot, "boot_unit_properties", lambda: props)
    inputs = {"revision": revision}
    boot.run_private(host, "inhibit", old, revision, GENERATION, None)
    boot.run_private(host, "publish", old, revision, GENERATION, inputs)
    receipt = boot.RUNTIME / boot.HANDOFF
    assert boot.read_optional(receipt)["run_id"] == old.run_id

    proc = tmp_path / "proc"
    (proc / "self").mkdir(parents=True)
    cgroup = f"/system.slice/{boot.BOOT_UNIT}"
    (proc / "self/cgroup").write_text(f"0::{cgroup}\n")
    monkeypatch.setattr(deployment_gate, "PROC", proc)
    invocation = "5" * 32
    monkeypatch.setenv("INVOCATION_ID", invocation)
    props.update(
        ActiveState="activating",
        SubState="start",
        MainPID="0",
        InvocationID=invocation,
        ControlGroup=cgroup,
    )
    with pytest.raises(boot.BootError, match="systemd MainPID"):
        boot.adopt_private(host)
    assert receipt.exists()

    active_identity = current
    props["MainPID"] = str(boot.os.getpid())
    with pytest.raises(boot.BootError, match="stale private binding"):
        boot.adopt_private(host)
    with pytest.raises(boot.BootError, match="stale private binding"):
        boot.run_private(host, "inhibit", other, revision, GENERATION, None)
    assert boot.read_optional(receipt)["run_id"] == old.run_id

    props["ActiveState"] = "failed"
    boot.run_private(host, "inhibit", current, revision, GENERATION, None)
    boot.run_private(host, "publish", current, revision, GENERATION, inputs)
    assert boot.read_optional(receipt)["run_id"] == current.run_id
    props["ActiveState"] = "activating"
    assert boot.adopt_private(host)
    assert not receipt.exists()
    assert scopes[-2:] == [False, False]
    with pytest.raises(boot.BootError, match="invalid application boot activation handoff"):
        boot.adopt_private(host)

    # The receipt can be consumed before systemd records completion. A new
    # guarded publish can reconcile the already-running units and issue it again.
    props["ActiveState"] = "failed"
    boot.run_private(host, "inhibit", current, revision, GENERATION, None)
    boot.run_private(host, "publish", current, revision, GENERATION, inputs)
    assert receipt.exists()
    assert {name for name, *_ in host.calls} <= {"health", "firewall"}


def test_guarded_graph_retirement_removes_only_empty_manifest(lifecycle, tmp_path, monkeypatch):
    host = lifecycle([])
    cfg = SimpleNamespace(applications=[])
    revision = "b" * 64
    identity = Identity("1" * 32, "2" * 32, "12345678-1234-1234-1234-123456789abc")
    monkeypatch.setattr(site_deployment, "require_private_verifier", lambda *args: None)
    monkeypatch.setattr(boot, "desired_configuration", lambda: cfg)
    monkeypatch.setattr(boot, "route_present", lambda: False)
    monkeypatch.setattr(
        boot, "boot_unit_properties", lambda: {"LoadState": "not-found", "ActiveState": "inactive"}
    )
    monkeypatch.setattr(boot, "SYSTEMD", tmp_path / "systemd")
    monkeypatch.setattr(boot, "runtime_lock", nullcontext)
    monkeypatch.setattr(boot, "effective", lambda config: {})
    monkeypatch.setattr(boot, "revision_id", lambda effective: revision)
    manifest = boot.STATE / "application-units.json"
    unrelated = boot.STATE / "application-data"
    unrelated.write_bytes(b"data to preserve")
    boot.store(manifest, [])
    boot.run_private(host, "inhibit", identity, revision, GENERATION, None)
    assert boot.run_private(host, "publish", identity, revision, GENERATION, {"revision": revision})
    boot.verify_guarded_deployment(host, revision)
    assert not manifest.exists()
    assert unrelated.read_bytes() == b"data to preserve"
    assert host.calls == []


def test_boot_orders_dependencies_and_excludes_disabled_units(lifecycle):
    dependency = target("source", 1)
    dependent = target("client", 0)
    disabled = target("halted", 2, enabled=False)
    host = lifecycle([dependency, dependent, disabled])
    assert boot.start(host)
    unit_calls = [call for call in host.calls if call[0] not in ("manager", "firewall")]
    assert host.calls[0] == ("firewall",)
    assert ("manager", disabled.binding.uid) not in host.calls
    assert unit_calls == [
        ("start", dependency.binding.unit),
        ("health", dependency.port),
        ("start", dependent.binding.unit),
        ("health", dependent.port),
    ]
    assert not boot.read_active().pending
    assert not boot.start(host)


@pytest.mark.parametrize("invalid_map", [False, True])
def test_boot_verifies_mapped_data_after_pod_and_before_any_child(
    lifecycle, monkeypatch, invalid_map
):
    layout = {"application": "shared"}
    pod = replace(target(None, 0, isolation="shared"), mapped_layout=layout)
    child = target("source", 0, isolation="shared")
    host = lifecycle([pod, child])

    def check_layout(controller, configuration, *, create=False):
        assert controller is host and configuration is layout and not create
        assert host.running[pod.binding.unit] and not host.running[child.binding.unit]
        host.calls.append(("mapped",))
        if invalid_map:
            raise ValueError("unexpected leaf owner")
        return False

    monkeypatch.setattr(boot, "verify_mapped_layout", check_layout)
    if invalid_map:
        with pytest.raises(boot.BootError, match="data ownership verification failed"):
            boot.start(host)
        assert not boot.read_active().bindings
        final = ("stop", pod.binding.unit)
    else:
        assert boot.start(host)
        final = ("start", child.binding.unit)
    assert [call for call in host.calls if call[0] in ("start", "stop", "mapped")] == [
        ("start", pod.binding.unit),
        ("mapped",),
        final,
    ]


def test_publish_refuses_drifted_mapped_data_without_replacing_prior_authority(
    lifecycle, monkeypatch
):
    pod = replace(target(None, 0, isolation="shared"), mapped_layout={"application": "shared"})
    child = target("source", 0, isolation="shared")
    host = lifecycle([pod, child])
    host.running = dict.fromkeys(host.running, True)
    policy = boot.STATE / "application-boot.json"
    prior = policy.read_bytes()
    boot.inhibit(host, GENERATION)

    def reject_mapped_leaf(host, configuration, *, create=False):
        assert not create
        raise ValueError("unexpected leaf owner")

    monkeypatch.setattr(boot, "verify_mapped_layout", reject_mapped_leaf)
    with pytest.raises(boot.BootError, match="data ownership verification failed"):
        boot.publish(host, GENERATION, {})
    assert policy.read_bytes() == prior
    assert (boot.RUNTIME / "hold").exists()
    assert not boot.read_active().bindings


def test_health_failure_rolls_back_only_new_units(lifecycle):
    dependency = target("source", 0)
    dependent = target("client", 1)
    consumer = target("consumer", 2)
    host = lifecycle([dependency, dependent, consumer])
    host.running[dependency.binding.unit] = True
    boot.Active(GENERATION, [dependency.binding], []).write()
    host.unhealthy.add(consumer.port)
    with pytest.raises(boot.BootError, match="health"):
        boot.start(host)
    calls = [call for call in host.calls if call[0] in ("start", "stop")]
    assert calls == [
        ("start", dependent.binding.unit),
        ("start", consumer.binding.unit),
        ("stop", consumer.binding.unit),
        ("stop", dependent.binding.unit),
    ]
    assert host.running[dependency.binding.unit]
    assert boot.read_active().bindings == [dependency.binding]


def test_start_veto_during_inhibit_cannot_unwind_existing_receipt(lifecycle):
    item = target("source", 0)
    host = lifecycle([item])
    host.running[item.binding.unit] = True
    boot.Active(GENERATION, [item.binding], []).write()
    assert not boot.inhibit(host, GENERATION)
    assert not boot.inhibit(host, GENERATION)
    with pytest.raises(boot.BootError, match="another application deployment"):
        boot.inhibit(host, "b" * 64)
    with pytest.raises(boot.BootError, match="in progress"):
        boot.start(host)
    assert not boot.stop_bindings(host, boot.read_active(), pending_only=True)
    assert host.calls == []
    assert boot.read_active().bindings == [item.binding]


def test_start_refuses_unowned_active_unit(lifecycle):
    dependency = target("source", 0)
    dependent = target("client", 1)
    host = lifecycle([dependency, dependent])
    host.running[dependency.binding.unit] = True
    with pytest.raises(boot.BootError, match="lacks boot ownership"):
        boot.start(host)
    assert not any(call[0] in ("start", "stop") for call in host.calls)
    assert not boot.read_active().bindings


def test_firewall_runtime_drift_between_units_rolls_back_start(lifecycle, monkeypatch):
    first = target("source", 0)
    next_target = target("client", 1)
    host = lifecycle([first, next_target])
    runtime = iter([RUNTIME_HASH, RUNTIME_HASH, "d" * 64])
    monkeypatch.setattr(boot, "verify_firewall", lambda inputs, evidence: next(runtime))
    with pytest.raises(boot.BootError, match="firewall runtime changed"):
        boot.start(host)
    assert [call for call in host.calls if call[0] in ("start", "stop")] == [
        ("start", first.binding.unit),
        ("stop", first.binding.unit),
    ]
    assert not boot.read_active().bindings


def test_shutdown_uses_saved_bindings_and_leaves_unknown_evidence(lifecycle, monkeypatch):
    dependency = target("source", 0)
    dependent = target("client", 1)
    host = lifecycle([dependency, dependent])
    assert boot.start(host)
    host.calls.clear()
    (boot.STATE / "application-boot.json").unlink()

    def refuse_inputs(*args):
        pytest.fail("shutdown must not attempt to load current deployment inputs")

    monkeypatch.setattr(boot, "deployment_inputs", refuse_inputs)
    monkeypatch.setattr(boot, "verify_firewall", refuse_inputs)
    host.stop_failure.add(dependent.binding.unit)
    with pytest.raises(boot.BootError, match="failed to stop"):
        boot.stop_bindings(host, boot.read_active())
    assert boot.read_active().bindings == [dependency.binding, dependent.binding]
    assert host.calls == [("stop", dependent.binding.unit)]
    host.stop_failure.clear()
    host.calls.clear()
    assert boot.stop_bindings(host, boot.read_active())
    assert host.calls == [
        ("stop", dependent.binding.unit),
        ("stop", dependency.binding.unit),
    ]
    assert not boot.read_active().bindings


def test_stop_keeps_ownership_when_uid_reused(lifecycle, monkeypatch):
    item = target("source", 0)
    verify = boot.verify_stop_identity
    host = lifecycle([item])
    assert boot.start(host)
    host.calls.clear()
    identity_file = boot.STATE / "application-identities" / item.binding.user
    identity_file.parent.mkdir()
    boot.store(identity_file, item.binding.identity)
    monkeypatch.setattr(boot, "verify_stop_identity", verify)
    monkeypatch.setattr(
        boot.pwd, "getpwnam", lambda user: SimpleNamespace(pw_uid=39999, pw_gid=30000)
    )
    with pytest.raises(boot.BootError, match="identity changed"):
        boot.stop_bindings(host, boot.read_active())
    assert boot.read_active().bindings == [item.binding]
    assert host.calls == []


def test_shared_pod_start_and_ownership_bounded_shutdown(lifecycle):
    pod = target(None, 0, isolation="shared")
    item = target("source", 0, isolation="shared")
    host = lifecycle([pod, item])
    assert boot.start(host)
    assert [call for call in host.calls if call[0] == "start"] == [
        ("start", pod.binding.unit),
        ("start", item.binding.unit),
    ]
    host.pods[pod.binding.pod_name] = ["foreign"]
    with pytest.raises(boot.BootError, match="another workload"):
        boot.stop_bindings(host, boot.read_active())
    assert host.running[pod.binding.unit]
    assert boot.read_active().bindings == [pod.binding]
    host.pods[pod.binding.pod_name] = []
    assert boot.stop_bindings(host, boot.read_active())
    assert host.calls[-1] == ("stop", pod.binding.unit)


@pytest.mark.parametrize("pod_disappears", [True, False])
def test_shutdown_waits_for_quadlet_pod_auto_removal(lifecycle, monkeypatch, pod_disappears):
    database = target("database", 0)
    frontend = target("frontend", 1)
    pod = target(None, 2, app="shared-app", isolation="shared")
    child = target("client", 2, app="shared-app", isolation="shared")
    targets = [database, frontend, pod, child]
    bindings = [item.binding for item in targets]
    host = lifecycle(targets)
    for binding in bindings:
        host.running[binding.unit] = True
    host.pods[pod.binding.pod_name] = None
    boot.Active(GENERATION, bindings, []).write()
    elapsed = 0

    def wait(seconds):
        nonlocal elapsed
        elapsed += seconds
        if pod_disappears:
            host.running[pod.binding.unit] = False
            host.pods[pod.binding.pod_name] = []

    monkeypatch.setattr(boot, "time", SimpleNamespace(monotonic=lambda: elapsed, sleep=wait))

    if pod_disappears:
        assert boot.stop_bindings(host, boot.read_active())
        assert elapsed == pytest.approx(0.1)
        assert host.calls == [
            ("stop", child.binding.unit),
            ("stop", frontend.binding.unit),
            ("stop", database.binding.unit),
        ]
        assert not boot.read_active().bindings
    else:
        with pytest.raises(boot.BootError, match="application stop state is unknown"):
            boot.stop_bindings(host, boot.read_active())
        assert elapsed == pytest.approx(3)
        assert host.calls == [("stop", child.binding.unit)]
        assert boot.read_active().bindings == bindings[:-1]


def test_recover_crash_unwinds_only_pending_bindings(lifecycle):
    dependency = target("source", 0)
    dependent = target("client", 1)
    host = lifecycle([dependency, dependent])
    host.running = {dependency.binding.unit: True, dependent.binding.unit: True}
    boot.Active(GENERATION, [dependency.binding, dependent.binding], [dependent.binding]).write()
    assert boot.stop_bindings(host, boot.read_active(), pending_only=True)
    assert host.calls == [("stop", dependent.binding.unit)]
    assert boot.read_active().bindings == [dependency.binding]


def test_recover_cancels_only_exact_pending_start_job(lifecycle, monkeypatch):
    item = target("source", 0)
    host = lifecycle([item])
    host.running[item.binding.unit] = None
    host.transitioning.add(item.binding.unit)
    boot.Active(GENERATION, [item.binding], [item.binding]).write()
    with pytest.MonkeyPatch.context() as unavailable:
        unavailable.setattr(host, "application_unit_authority", lambda *args: False)
        with pytest.raises(boot.BootError, match="source changed"):
            boot.stop_bindings(host, boot.read_active(), pending_only=True)
    assert host.calls == []
    assert boot.read_active().pending == [item.binding]
    monkeypatch.setattr(host, "application_unit_authority", lambda *args: True)
    assert boot.stop_bindings(host, boot.read_active(), pending_only=True)
    assert host.calls == [("stop", item.binding.unit)]
    assert not boot.read_active().bindings


def test_stop_and_retract_after_inert_manager_was_stopped(lifecycle):
    item = target("source", 0, enabled=False)
    host = lifecycle([item])
    host.running[item.binding.unit] = None
    boot.Active(GENERATION, [item.binding], []).write()
    with pytest.raises(boot.BootError, match="stop state is unknown"):
        boot.stop_bindings(host, boot.read_active())
    assert boot.read_active().bindings == [item.binding]
    host.stopped_managers.add(item.binding.uid)
    assert boot.stop_bindings(host, boot.read_active())
    assert host.calls == []
    boot.inhibit(host, GENERATION)
    assert boot.publish(host, GENERATION, {})
    assert not (boot.STATE / "application-boot.json").exists()


def test_publish_refreshes_explicit_deploy_ownership_without_start(lifecycle):
    item = target("source", 0)
    host = lifecycle([item])
    host.running[item.binding.unit] = True
    boot.inhibit(host, GENERATION)
    assert boot.publish(host, GENERATION, {})
    assert not (boot.RUNTIME / "hold").exists()
    assert boot.read_active().bindings == [item.binding]
    boot.inhibit(host, GENERATION)
    assert not boot.publish(host, GENERATION, {})
    assert not any(call[0] in ("start", "stop", "manager") for call in host.calls)


def test_release_hashes_and_root_records_bind_boot_before_any_manager(
    tmp_path, lifecycle, monkeypatch
):
    config = load_config_file(
        Path("examples/server.application-planned.yml"), allow_unavailable=True
    )
    registry = prepare_application_registry(config)
    config_dir = tmp_path / "config"
    release_dir = tmp_path / "releases"
    release = release_dir / __version__
    quadlets = tmp_path / "quadlets"
    systemd = tmp_path / "systemd"
    monkeypatch.setattr(boot, "CONFIG", config_dir)
    monkeypatch.setattr(boot, "RELEASES", release_dir)
    monkeypatch.setattr(boot, "QUADLETS", quadlets)
    monkeypatch.setattr(boot, "SYSTEMD", systemd)
    monkeypatch.setattr(boot.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=123))
    monkeypatch.setattr(boot, "verify_firewall", lambda inputs, evidence: RUNTIME_HASH)

    def create(path, data, mode):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)

    create(config_dir / "executor.json", json.dumps(registry).encode(), 0o600)
    create(config_dir / "config" / "desired.json", json.dumps(effective(config)).encode(), 0o640)
    wheel = f"steward-{__version__}-py3-none-any.whl"
    files = {wheel: b"wheel", "requirements.txt": b"", "bundles/sample-notes/app.py": b"app"}
    for name, content in files.items():
        artifact = release / (name if name.startswith("bundles/") else f"dist/{name}")
        create(artifact, content, 0o644)
    current = tmp_path / "current"
    current.symlink_to(release)
    stat = Path.lstat

    def root_current(path):
        result = stat(path)
        if path == current:
            return SimpleNamespace(st_mode=result.st_mode, st_uid=0)
        return result

    monkeypatch.setattr(Path, "lstat", root_current)
    create(boot.STATE / "application-activations" / "example", b"e" * 64, 0o600)
    [app] = render_application_quadlets(config, str(release))
    manifest = []
    pins = {}
    for index, item in enumerate(app["services"]):
        identity = pin(index)
        pins[item["user"]] = identity
        create(quadlets / str(identity["uid"]) / item["filename"], item["content"].encode(), 0o644)
        create(
            systemd / f"user@{identity['uid']}.service.d" / "90-steward-applications.conf",
            b"[Unit]\nAfter=steward-firewall.service\n",
            0o644,
        )
        manifest.append(
            {
                "user": item["user"],
                "uid": identity["uid"],
                "identity": identity,
                "unit": item["unit"],
                "port": config.applications[0].services[index].host_port,
            }
        )
    create(boot.STATE / "application-units.json", json.dumps(manifest).encode(), 0o600)
    monkeypatch.setattr(boot, "inspect_identity", pins.__getitem__)
    inputs = {
        "revision": registry["config_revision"],
        "release": {
            "version": __version__,
            "files": {name: boot.digest(raw) for name, raw in files.items()},
        },
        "source": "b" * 64,
    }
    targets, evidence, routes = boot.deployment_inputs(inputs)
    assert not routes
    host = FakeHost(targets)
    boot.store(
        boot.STATE / "application-boot.json",
        {
            "generation": GENERATION,
            "inputs": inputs,
            "evidence": {**evidence, "firewall_runtime": RUNTIME_HASH, "helpers": HELPER_HASHES},
        },
    )
    create(boot.STATE / "application-activations" / "example", b"f" * 64, 0o600)
    with pytest.raises(boot.BootError, match="approved application deployment inputs changed"):
        boot.start(host)
    create(boot.STATE / "application-activations" / "example", b"e" * 64, 0o600)
    dropin = systemd / "user@30000.service.d" / "90-steward-applications.conf"
    create(dropin, b"[Unit]\n", 0o644)
    with pytest.raises(boot.BootError, match="approved application deployment inputs changed"):
        boot.start(host)
    create(release / "dist" / wheel, b"new wheel", 0o644)
    with pytest.raises(boot.BootError, match="artifact changed"):
        boot.start(host)
    assert host.calls == []


def test_pod_membership_requires_recognized_running_infrastructure(monkeypatch):
    host = Host()
    state = {
        "Name": "steward-app",
        "InfraContainerID": "a" * 64,
        "Containers": [{"Id": "a" * 64, "State": "running"}],
    }
    monkeypatch.setattr(host, "_as_user", lambda user, cmd: (0, json.dumps([state])))
    assert host.application_pod_members("stw-app", "steward-app") == []
    state["Containers"].append({"Id": "b" * 64, "State": "running"})
    assert host.application_pod_members("stw-app", "steward-app") == ["b" * 64]
    state["Containers"][0]["State"] = "stopped"
    assert host.application_pod_members("stw-app", "steward-app") is None


def test_stopped_manager_proof_refuses_subuid_task_and_rechecks_manager(tmp_path, monkeypatch):
    host = Host()
    monkeypatch.setattr(host_module, "PROC_ROOT", tmp_path)
    stopped = (
        "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\n"
        "ControlPID=0\nControlGroup=\nJob=\n"
    )
    responses = iter([stopped, stopped, stopped, stopped, stopped.replace("Job=", "Job=80")])
    monkeypatch.setattr(host, "_run", lambda command: (0, next(responses)))
    task = tmp_path / "99" / "task" / "100" / "status"
    task.parent.mkdir(parents=True)
    task.write_text("Uid:\t200001\t200001\t200001\t200001\n")
    assert not host.application_manager_quiescent(30000, [200000, 65536])
    task.write_text("Uid:\t2000\t2000\t2000\t2000\n")
    assert host.application_manager_quiescent(30000, [200000, 65536])
    assert not host.application_manager_quiescent(30000, [200000, 65536])


@pytest.fixture
def routed_lifecycle(lifecycle, tmp_path, monkeypatch):
    item = target("source", 0)
    host = lifecycle([item])
    provider = tmp_path / "proxy-runtime"
    provider.mkdir()
    monkeypatch.setattr(boot, "PROXY_RUNTIME", provider)
    monkeypatch.setattr(boot, "proxy_directory", lambda gid: None)
    monkeypatch.setattr(boot.os, "fchown", lambda fd, uid, gid: None)
    monkeypatch.setattr(boot, "proxy_account", lambda: SimpleNamespace(pw_uid=1001, pw_gid=1001))
    monkeypatch.setattr(boot, "proxy_authority", lambda host, uid: None)
    routes = (ApplicationProxyRoute(item.binding.application, "source", "source.test", item.port),)
    policy_path = boot.STATE / "application-boot.json"
    record = boot.read_optional(policy_path)
    record["evidence"]["proxy"] = {
        "uid": 1001,
        "gid": 1001,
        "routes": boot.digest(boot.render_application_proxy_routes(routes).encode()),
    }
    boot.store(policy_path, record)
    evidence = {
        key: value
        for key, value in record["evidence"].items()
        if key not in {"firewall_runtime", "helpers"}
    }
    monkeypatch.setattr(boot, "deployment_inputs", lambda inputs: ([item], evidence.copy(), routes))

    host.proxy_running = True
    host.evicted = True
    host.owned_listener = True
    host.application_proxy_running = lambda: host.proxy_running
    host.application_proxy_evicted = lambda uid: host.evicted and not host.proxy_running
    host.application_listener_owned = lambda port, uid: (
        host.owned_listener and (port, uid) == (item.port, item.binding.uid)
    )
    set_app_unit = host.set_user_unit

    def set_unit(user, unit, *, running):
        if user != "steward-proxy":
            return set_app_unit(user, unit, running=running)
        assert unit == "proxy.service"
        assert boot.read_optional(boot.RUNTIME / "route-drain.json") is not None
        assert not boot.route_path().exists()
        host.calls.append(("proxy", running))
        host.proxy_running = running
        return True

    host.set_user_unit = set_unit
    return host, item, routes


@pytest.fixture
def guarded_routes(routed_lifecycle, tmp_path, monkeypatch):
    host, item, routes = routed_lifecycle
    revision = "b" * 64
    identity = Identity("1" * 32, "2" * 32, "12345678-1234-1234-1234-123456789abc")
    boot_id = tmp_path / "boot_id"
    boot_id.write_text(identity.boot_id + "\n")
    monkeypatch.setattr(deployment_gate, "BOOT_ID", boot_id)
    monkeypatch.setattr(site_deployment, "require_private_verifier", lambda *args: True)
    monkeypatch.setattr(boot, "runtime_lock", nullcontext)
    cfg = SimpleNamespace(
        applications=[SimpleNamespace(services=[SimpleNamespace(manage=True, deploy=True)])]
    )
    monkeypatch.setattr(boot, "desired_configuration", lambda: cfg)
    monkeypatch.setattr(boot, "effective", lambda config: {})
    monkeypatch.setattr(boot, "revision_id", lambda effective: revision)
    unit = tmp_path / boot.BOOT_UNIT
    unit.write_text("root-owned boot unit\n")
    unit.chmod(0o644)
    monkeypatch.setattr(boot, "SYSTEMD", tmp_path)
    monkeypatch.setattr(
        boot,
        "boot_unit_properties",
        lambda: {
            "LoadState": "loaded",
            "FragmentPath": str(unit),
            "DropInPaths": "",
            "NeedDaemonReload": "no",
            "ActiveState": "active",
            "SubState": "exited",
            "Result": "success",
            "MainPID": "0",
            "UnitFileState": "enabled",
        },
    )
    inputs = {"revision": revision, "release": {"version": __version__, "files": {}}}
    generation = boot.digest(json.dumps(inputs, sort_keys=True).encode())
    inputs["source"] = "d" * 64
    return host, item, routes, identity, generation, inputs


def test_guarded_routes_are_journaled_only_at_coordinator_close(guarded_routes, monkeypatch):
    host, item, routes, identity, generation, inputs = guarded_routes
    revision = inputs["revision"]
    assert boot.start(host)
    assert boot.run_private(host, "inhibit", identity, revision, generation, None)
    assert host.calls[-2:] == [("proxy", False), ("proxy", True)]
    assert not boot.route_present()
    assert boot.run_private(host, "publish", identity, revision, generation, inputs)
    assert not boot.route_present()
    journal = boot.RUNTIME / boot.GUARDED_ROUTE_JOURNAL
    assert not journal.exists()

    install_route = boot.install_route_file

    def check_custody(routes, evidence):
        assert journal.stat().st_mode & 0o777 == 0o600
        assert boot.read_optional(journal) == {
            "operation_id": identity.operation_id,
            "run_id": identity.run_id,
            "boot_id": identity.boot_id,
            "revision": revision,
            "generation": generation,
            "routes": evidence["proxy"]["routes"],
        }
        return install_route(routes, evidence)

    monkeypatch.setattr(boot, "install_route_file", check_custody)
    host.unhealthy.add(item.port)
    with pytest.raises(boot.BootError, match="health"):
        boot.verify_guarded_deployment(host, revision, route_identity=identity)
    assert not journal.exists()
    assert not boot.route_present()
    host.unhealthy.clear()
    boot.verify_guarded_deployment(host, revision, route_identity=identity)
    assert boot.route_path().read_text() == boot.render_application_proxy_routes(routes)
    assert not boot.reconcile_guarded_routes(host, replace(identity, run_id="3" * 32))
    assert journal.exists() and boot.route_present()

    assert boot.reconcile_guarded_routes(host, identity, revision, committed=True)
    assert boot.route_present() and not journal.exists()
    inode = boot.route_path().stat().st_ino
    assert not boot.run_private(host, "inhibit", identity, revision, generation, None)
    assert not boot.run_private(host, "publish", identity, revision, generation, inputs)
    boot.verify_guarded_deployment(host, revision, route_identity=identity)
    assert boot.route_path().stat().st_ino == inode
    assert not journal.exists()


@pytest.mark.parametrize("at_close", [False, True])
def test_guarded_retained_route_drift_is_withdrawn(guarded_routes, at_close):
    host, item, _, identity, generation, inputs = guarded_routes
    revision = inputs["revision"]
    boot.run_private(host, "inhibit", identity, revision, generation, None)
    host.running[item.binding.unit] = True
    boot.run_private(host, "publish", identity, revision, generation, inputs)
    boot.verify_guarded_deployment(host, revision, route_identity=identity)
    assert boot.reconcile_guarded_routes(host, identity, revision, committed=True)

    successor = replace(identity, run_id="3" * 32)
    assert not boot.run_private(host, "inhibit", successor, revision, generation, None)
    assert boot.route_present()
    if at_close:
        assert not boot.run_private(host, "publish", successor, revision, generation, inputs)
        (boot.STATE / "application-boot.json").unlink()
        with pytest.raises(boot.BootError, match="has no approved deployment"):
            boot.verify_guarded_deployment(
                host, revision, route_identity=successor, route_generation=generation
            )
    else:
        host.unhealthy.add(item.port)
        with pytest.raises(boot.BootError, match="health"):
            boot.run_private(host, "publish", successor, revision, generation, inputs)

    assert not boot.route_present()
    assert not (boot.RUNTIME / boot.GUARDED_ROUTE_JOURNAL).exists()
    assert boot.read_optional(boot.RUNTIME / "hold") == boot.private_hold(
        successor, revision, generation
    )
    assert host.calls[-2:] == [("proxy", False), ("proxy", True)]


@pytest.mark.parametrize("early", [False, True])
def test_guarded_route_cleanup_retries_exact_failed_eviction(guarded_routes, early):
    host, item, _, identity, generation, inputs = guarded_routes
    revision = inputs["revision"]
    hold = boot.RUNTIME / "hold"
    marker = boot.RUNTIME / boot.GUARDED_ROUTE_DRAIN
    journal = boot.RUNTIME / boot.GUARDED_ROUTE_JOURNAL
    if early:
        assert boot.start(host)
        host.evicted = False
        with pytest.raises(boot.BootError, match="eviction failed"):
            boot.run_private(host, "inhibit", identity, revision, generation, None)
        assert hold.exists()
    else:
        boot.run_private(host, "inhibit", identity, revision, generation, None)
        host.running[item.binding.unit] = True
        boot.run_private(host, "publish", identity, revision, generation, inputs)
        boot.verify_guarded_deployment(host, revision, route_identity=identity)
        # The unresolved journal owns the provider path even if runtime state
        # drifts after publication, so the proxy must still lose cached routes.
        boot.route_path().write_text("changed provider contents")
        boot.Active(GENERATION, [], []).write()
        host.evicted = False
        with pytest.raises(boot.BootError, match="eviction failed"):
            boot.reconcile_guarded_routes(host, identity)

    assert not boot.route_present()
    assert journal.exists() is (not early)
    binding = boot.read_optional(marker)["private"]
    assert binding["generation"] == generation
    assert binding["run_id"] == identity.run_id
    assert not boot.reconcile_guarded_routes(host, replace(identity, run_id="3" * 32))
    assert marker.exists()
    host.evicted = True
    if early:
        assert not boot.reconcile_guarded_routes(host, identity, allow_early=False)
        assert marker.exists()
    assert boot.reconcile_guarded_routes(host, identity, allow_early=early)
    assert not boot.route_present() and not marker.exists() and not journal.exists()
    assert host.proxy_running
    if early:
        assert boot.read_optional(hold) == boot.private_hold(identity, revision, generation)


def test_unconfirmed_route_withdraws_file_before_proxy_identity_recovers(
    guarded_routes, monkeypatch
):
    host, item, _, identity, generation, inputs = guarded_routes
    revision = inputs["revision"]
    boot.run_private(host, "inhibit", identity, revision, generation, None)
    host.running[item.binding.unit] = True
    boot.run_private(host, "publish", identity, revision, generation, inputs)
    boot.verify_guarded_deployment(host, revision, route_identity=identity)

    def missing_account():
        raise KeyError("proxy")

    with monkeypatch.context() as override:
        override.setattr(boot, "volatile_run", lambda: None)
        override.setattr(boot, "proxy_account", missing_account)
        with pytest.raises(KeyError, match="proxy"):
            boot.reconcile_guarded_routes(host, identity)

    journal = boot.RUNTIME / boot.GUARDED_ROUTE_JOURNAL
    assert journal.exists() and not boot.route_present() and host.proxy_running
    assert boot.reconcile_guarded_routes(host, identity)
    assert not journal.exists() and not boot.route_present()
    assert host.calls[-2:] == [("proxy", False), ("proxy", True)]


def test_routed_boot_and_same_generation_inhibit_keep_healthy_route(routed_lifecycle):
    host, _, routes = routed_lifecycle
    assert boot.start(host)
    path = boot.route_path()
    inode = path.stat().st_ino
    assert path.stat().st_mode & 0o777 == 0o640
    assert path.read_text() == boot.render_application_proxy_routes(routes)
    assert not boot.inhibit(host, GENERATION)
    with pytest.raises(boot.BootError, match="application deployment is in progress"):
        boot.start(host)
    assert not boot.publish(host, GENERATION, {})
    assert path.stat().st_ino == inode
    assert not any(operation == "proxy" for operation, *_ in host.calls)


def test_routed_boot_rolls_back_when_no_exact_listener_is_owned(routed_lifecycle):
    host, item, _ = routed_lifecycle
    host.owned_listener = False
    with pytest.raises(boot.BootError, match="owned loopback listener"):
        boot.start(host)
    assert not boot.route_path().exists()
    assert not host.running[item.binding.unit]
    assert host.proxy_running


def test_same_generation_route_health_drift_evicts_cached_proxy(routed_lifecycle):
    host, item, _ = routed_lifecycle
    assert boot.start(host)
    host.unhealthy.add(item.port)
    assert boot.inhibit(host, GENERATION)
    assert boot.read_optional(boot.RUNTIME / "hold") == GENERATION
    assert not boot.route_path().exists()
    assert host.calls[-2:] == [("proxy", False), ("proxy", True)]
    assert host.running[item.binding.unit]
    assert not (boot.RUNTIME / "route-drain.json").exists()


def test_missing_durable_authority_with_live_routes_evicts_cached_proxy(routed_lifecycle):
    host, _, _ = routed_lifecycle
    assert boot.start(host)
    (boot.STATE / "application-boot.json").unlink()
    with pytest.raises(boot.BootError, match="no approved deployment"):
        boot.start(host)
    assert not boot.route_path().exists()
    assert host.calls[-2:] == [("proxy", False), ("proxy", True)]


@pytest.mark.parametrize("volatile_hold", [False, True])
def test_durable_fence_drains_live_routes(routed_lifecycle, executor_state, volatile_hold):
    host, item, _ = routed_lifecycle
    executor, _ = executor_state
    assert boot.start(host)
    active = boot.read_active()
    if volatile_hold:
        assert not boot.inhibit(host, GENERATION)
    executor.begin_deployment_fence(base_revision=GENERATION, desired_revision="b" * 64)
    host.calls.clear()

    with pytest.raises(boot.BootError, match="executor deployment recovery is pending"):
        boot.start(host)

    assert host.calls == [("proxy", False), ("proxy", True)]
    assert not boot.route_path().exists()
    assert boot.read_active() == active
    assert host.running[item.binding.unit]


@pytest.mark.parametrize(
    ("damage", "message"),
    [
        ("missing", "invalid or unavailable executor deployment fence evidence"),
        ("missing table", "missing executor deployment fence table"),
        ("malformed", "invalid or unavailable executor deployment fence evidence"),
        ("unsafe mode", "unsafe executor state file"),
        ("symlink", "unsafe executor state file"),
        ("unsafe journal", "unsafe executor state file"),
    ],
)
def test_untrusted_executor_evidence_drains_live_routes(
    routed_lifecycle, executor_state, damage, message
):
    host, item, _ = routed_lifecycle
    _, database = executor_state
    assert boot.start(host)
    if damage == "missing":
        database.unlink()
    elif damage == "missing table":
        with closing(sqlite3.connect(database)) as db, db:
            db.execute("DROP TABLE deployment_fence")
    elif damage == "malformed":
        with closing(sqlite3.connect(database)) as db, db:
            db.execute("INSERT INTO deployment_fence VALUES (1, '{}')")
    elif damage == "unsafe mode":
        database.chmod(0o644)
    elif damage == "symlink":
        moved = database.rename(database.with_suffix(".original"))
        database.symlink_to(moved)
    elif damage == "unsafe journal":
        database.with_name("state.db-journal").mkdir()
    host.calls.clear()

    with pytest.raises(boot.BootError, match=message):
        boot.start(host)

    assert host.calls == [("proxy", False), ("proxy", True)]
    assert not boot.route_path().exists()
    assert host.running[item.binding.unit]


def test_committed_wal_fence_is_visible_without_executor_service(lifecycle, executor_state):
    host = lifecycle([target("source", 0)])
    executor, database = executor_state
    with closing(sqlite3.connect(database)) as wal_connection:
        assert wal_connection.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        wal_connection.execute("BEGIN")
        assert wal_connection.execute("SELECT * FROM deployment_fence").fetchall() == []
        fence = executor.begin_deployment_fence(base_revision=GENERATION, desired_revision="b" * 64)
        for suffix in ("-wal", "-shm"):
            database.with_name(database.name + suffix).chmod(0o600)
        assert fence.operation_id.encode() not in database.read_bytes()
        assert fence.operation_id.encode() in database.with_name("state.db-wal").read_bytes()

        with pytest.raises(boot.BootError, match="executor deployment recovery is pending"):
            boot.start(host)

    assert host.calls == []
    assert not boot.read_active().pending


def test_proxy_authority_drift_withdraws_routes_before_eviction_recovery(
    routed_lifecycle, monkeypatch
):
    host, item, _ = routed_lifecycle
    assert boot.start(host)
    assert boot.route_path().exists()
    active = boot.read_active()
    previous_calls = len(host.calls)
    eviction_checks = []
    original_eviction = host.application_proxy_evicted

    def check_eviction(uid):
        assert not boot.route_path().exists()
        assert boot.read_optional(boot.RUNTIME / "route-drain.json") is not None
        eviction_checks.append(uid)
        return original_eviction(uid)

    def reject_authority(host, uid):
        raise boot.BootError("application proxy unit source changed")

    monkeypatch.setattr(host, "application_proxy_evicted", check_eviction)
    with monkeypatch.context() as drift:
        drift.setattr(boot, "proxy_authority", reject_authority)
        with pytest.raises(boot.BootError, match="proxy unit source changed"):
            boot.inhibit(host, GENERATION)

    marker = boot.RUNTIME / "route-drain.json"
    assert not boot.route_path().exists()
    assert boot.read_optional(marker) == {"uid": 1001, "restore": True}
    assert boot.read_optional(boot.RUNTIME / "hold") == GENERATION
    assert boot.read_active() == active
    assert host.calls[previous_calls:] == [("firewall",)]
    assert not eviction_checks
    assert host.proxy_running
    assert host.running[item.binding.unit]

    assert boot.inhibit(host, GENERATION)
    assert not boot.route_path().exists()
    assert not marker.exists()
    assert eviction_checks == [1001]
    assert host.calls[previous_calls:] == [("firewall",), ("proxy", False), ("proxy", True)]
    assert boot.read_active() == active
    assert host.running[item.binding.unit]
    assert host.proxy_running


def test_failed_eviction_leaves_marker_and_retries_with_no_route_file(routed_lifecycle):
    host, _, _ = routed_lifecycle
    assert boot.start(host)
    host.evicted = False
    with pytest.raises(boot.BootError, match="proxy eviction failed"):
        boot.drain_routes(host)
    assert not boot.route_path().exists()
    assert not host.proxy_running
    assert boot.read_optional(boot.RUNTIME / "route-drain.json") == {"uid": 1001, "restore": True}
    # The proxy might have started since the first eviction attempt.
    host.proxy_running = True
    host.evicted = True
    assert boot.drain_routes(host)
    assert host.calls[-2:] == [("proxy", False), ("proxy", True)]
    assert host.proxy_running
    assert not (boot.RUNTIME / "route-drain.json").exists()


def test_socket_proof_rejects_extra_listener_and_open_proxy_connection(tmp_path, monkeypatch):
    proc_net = tmp_path / "net"
    proc_net.mkdir()
    monkeypatch.setattr(host_module, "PROC_ROOT", tmp_path)
    tcp, tcp6 = proc_net / "tcp", proc_net / "tcp6"
    heading = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid\n"
    listener = "0: 0100007F:5209 00000000:0000 0A 0:0 00:0 0 30000 0 100\n"
    wildcard = "0: 00000000000000000000000000000000:5209 00000000:0000 0A 0:0 00:0 0 0 0 101\n"
    established = "1: 0100007F:01BB 0100007F:8402 01 0:0 00:0 0 1001 0 102\n"
    tcp.write_text(heading + listener)
    tcp6.write_text(heading)

    host = Host()
    inactive = (
        "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
        "MainPID=0\nControlPID=0\nControlGroup=\nJob=\n"
    )

    def proxy_command(user, argv):
        assert user == "steward-proxy"
        return 0, inactive if argv[0] == "systemctl" else "[]"

    monkeypatch.setattr(host, "_as_user", proxy_command)
    assert host.application_listener_owned(21001, 30000)
    assert not host.application_listener_owned(21001, 30001)
    assert host.application_proxy_evicted(1001)
    tcp6.write_text(heading + wildcard)
    assert not host.application_listener_owned(21001, 30000)
    tcp.write_text(heading + listener + established)
    assert not host.application_proxy_evicted(1001)
    tcp.write_text(heading + listener + established.replace(" 01 ", " 06 "))
    assert host.application_proxy_evicted(1001)


@pytest.fixture
def group_boot(lifecycle, tmp_path, monkeypatch):
    cfg = load_config_file(Path("examples/server.application-planned.yml"), allow_unavailable=True)
    app = cfg.applications[0]
    disabled = app.services[1].model_copy(
        update={"id": "notes-c", "deploy": False, "host_port": 21003}
    )
    app = app.model_copy(update={"services": [*app.services, disabled]})
    cfg = cfg.model_copy(update={"applications": [app]})
    registry = {**prepare_application_registry(cfg), "server_name": cfg.server.name}
    items = {
        name: target(name, index, enabled=name != "notes-c", app=app.id)
        for index, name in enumerate(("notes-a", "notes-b", "notes-c"))
    }
    other = target("source", 4, app="unrelated")
    host = lifecycle([*items.values(), other])
    host.stopped_managers.add(items["notes-c"].binding.uid)
    host.running[items["notes-c"].binding.unit] = None
    host.kill_switch = lambda: False
    monkeypatch.setattr(boot, "CONFIG", tmp_path / "config")
    monkeypatch.setattr(site_deployment, "REGISTRY_PATH", str(boot.CONFIG / "executor.json"))
    monkeypatch.setattr(boot.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=123))
    monkeypatch.setattr(site_deployment, "enrollment_evidence", lambda marker: None)
    monkeypatch.setattr(
        site_deployment,
        "read_marker",
        lambda: {"schema_version": 2, "server_name": cfg.server.name, "state": "installed"},
    )
    boot.CONFIG.mkdir()
    boot.store(boot.CONFIG / "executor.json", registry)
    desired = boot.CONFIG / "config" / "desired.json"
    desired.parent.mkdir()
    desired.write_text(json.dumps(effective(cfg)))
    desired.chmod(0o640)
    path = boot.STATE / "application-boot.json"
    record = boot.read_optional(path)
    record["inputs"]["revision"] = registry["config_revision"]
    record["evidence"]["registry"] = boot.revision_id(registry)
    boot.store(path, record)
    deployed_inputs = boot.deployment_inputs

    def inputs_with_registry(inputs):
        targets, evidence, routes = deployed_inputs(inputs)
        return targets, {**evidence, "registry": boot.revision_id(registry)}, routes

    monkeypatch.setattr(boot, "deployment_inputs", inputs_with_registry)
    plan = GroupPlan.model_validate(
        derive_group_plan(
            registry, app.id, "notes-a", expected_revision=registry["config_revision"]
        )
    )
    checkpoint = GroupCheckpoint(
        operation_id="11111111111151118111111111111111",
        operator_managed=True,
        plan=plan,
        original_running={"notes-a": True, "notes-b": True, "notes-c": False},
    )
    return host, items, other, checkpoint, registry


def write_group_intent(database, checkpoint):
    with closing(sqlite3.connect(database)) as db, db:
        db.execute(
            "INSERT INTO application_group_intents VALUES (?, ?, ?, ?)",
            (
                checkpoint.plan.application,
                checkpoint.operation_id,
                checkpoint.generation,
                checkpoint.persisted_json(),
            ),
        )
        if checkpoint.operator_managed:
            db.execute(
                "INSERT INTO application_group_operator_intents VALUES (?, ?)",
                (checkpoint.operation_id, checkpoint.plan.application),
            )


def advance_group(checkpoint, *steps):
    for step in steps:
        if isinstance(step, bool):
            checkpoint = checkpoint.advance("confirm", observed_running=step)
        else:
            checkpoint = checkpoint.advance(step)
    return checkpoint


STOP_ALL = ("prepare", False, "prepare", False, "prepare", False)
STOP_UNTIL_FIRST = ("prepare", False, "prepare", False)


@pytest.mark.parametrize(
    ("steps", "running"),
    [
        ((), ["notes-a", "notes-b"]),
        (("prepare",), ["notes-a", "notes-b"]),
        (STOP_UNTIL_FIRST[:-1], ["notes-a"]),
        ((*STOP_UNTIL_FIRST, "prepare"), []),
        ((*STOP_ALL, "pause"), []),
        ((*STOP_ALL, "pause", "resume", "prepare"), []),
        ((*STOP_ALL, "pause", "resume", "prepare", True, "prepare"), ["notes-a"]),
        ((*STOP_UNTIL_FIRST, "recover", "prepare"), ["notes-a"]),
        ((*STOP_ALL, "recover", "prepare", True, "prepare"), ["notes-a"]),
        ((*STOP_UNTIL_FIRST, "recover", "prepare", True, "prepare"), ["notes-a", "notes-b"]),
    ],
)
def test_group_boot_projects_checkpoint_phases(group_boot, executor_state, steps, running):
    host, items, other, checkpoint, _ = group_boot
    executor, database = executor_state
    checkpoint = advance_group(checkpoint, *steps)
    write_group_intent(database, checkpoint)

    assert boot.start(host)

    assert [call[1] for call in host.calls if call[0] == "start"] == [
        *(items[name].binding.unit for name in running),
        other.binding.unit,
    ]
    assert ("manager", items["notes-c"].binding.uid) not in host.calls
    assert boot.read_active() == boot.Active(
        GENERATION, [items["notes-a"].binding, items["notes-b"].binding, other.binding], []
    )
    assert executor.group_checkpoint(checkpoint.plan.application) == checkpoint


def test_group_boot_reads_committed_wal_checkpoint(group_boot, executor_state):
    host, items, other, checkpoint, _ = group_boot
    executor, database = executor_state
    checkpoint = advance_group(checkpoint, *STOP_ALL, "pause")
    with closing(sqlite3.connect(database)) as reader:
        assert reader.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        reader.execute("BEGIN")
        assert reader.execute("SELECT * FROM application_group_intents").fetchall() == []
        write_group_intent(database, checkpoint)
        assert checkpoint.operation_id.encode() not in database.read_bytes()
        assert checkpoint.operation_id.encode() in database.with_name("state.db-wal").read_bytes()

        assert boot.start(host)

    assert host.running[other.binding.unit]
    assert host.running[items["notes-a"].binding.unit] is False
    assert host.running[items["notes-b"].binding.unit] is False
    assert executor.group_checkpoint(checkpoint.plan.application) == checkpoint


@pytest.mark.parametrize(
    ("damage", "message"),
    [
        ("legacy", "unknown active application group intent"),
        ("view", "missing executor application group table"),
        ("marker view", "invalid executor application group operator marker table"),
        ("marker wrong app", "inconsistent application group operator marker"),
        ("missing marker", "inconsistent application group operator marker"),
        ("embedded flag", "invalid application group checkpoint format"),
        ("oversized", "invalid application group checkpoint"),
        ("identity", "inconsistent application group checkpoint identity"),
        ("bad json", "invalid or unavailable executor deployment fence evidence"),
        ("stale plan", "invalid or unavailable application group authority"),
    ],
)
def test_group_boot_rejects_untrusted_checkpoint(group_boot, executor_state, damage, message):
    host, _, _, checkpoint, _ = group_boot
    _, database = executor_state
    if damage == "legacy":
        checkpoint = checkpoint.model_copy(
            update={"operation_id": "1" * 32, "operator_managed": False}
        )
    elif damage == "stale plan":
        checkpoint = checkpoint.model_copy(
            update={"plan": checkpoint.plan.model_copy(update={"config_revision": "f" * 64})}
        )
    write_group_intent(database, checkpoint)
    with closing(sqlite3.connect(database)) as db, db:
        if damage == "view":
            db.execute("DROP TABLE application_group_intents")
            db.execute("CREATE VIEW application_group_intents AS SELECT 1")
        elif damage == "marker view":
            db.execute("DROP TABLE application_group_operator_intents")
            db.execute("CREATE VIEW application_group_operator_intents AS SELECT 1")
        elif damage == "marker wrong app":
            db.execute("UPDATE application_group_operator_intents SET application='another'")
        elif damage == "missing marker":
            db.execute("DELETE FROM application_group_operator_intents")
        elif damage == "embedded flag":
            db.execute(
                "UPDATE application_group_intents SET body=?", (checkpoint.model_dump_json(),)
            )
        elif damage == "oversized":
            db.execute("UPDATE application_group_intents SET body=?", (" " * (32 * 1024 + 1),))
        elif damage == "identity":
            db.execute("UPDATE application_group_intents SET generation=12")
        elif damage == "bad json":
            db.execute("UPDATE application_group_intents SET body='{}'")

    with pytest.raises(boot.BootError, match=message):
        boot.start(host)

    assert all(call == ("firewall",) for call in host.calls)
    assert not boot.read_active().bindings


def test_legacy_terminal_group_checkpoint_from_old_revision_does_not_fence_boot(
    group_boot, executor_state
):
    host, items, _, checkpoint, _ = group_boot
    _, database = executor_state
    checkpoint = checkpoint.advance("recover").advance("finish_recovery")
    checkpoint = checkpoint.model_copy(
        update={
            "operation_id": "1" * 32,
            "operator_managed": False,
            "plan": checkpoint.plan.model_copy(update={"config_revision": "f" * 64}),
        }
    )
    write_group_intent(database, checkpoint)
    with closing(sqlite3.connect(database)) as db, db:
        db.execute("DROP TABLE application_group_operator_intents")

    assert boot.start(host)
    assert host.running[items["notes-a"].binding.unit]
    assert host.running[items["notes-b"].binding.unit]


@pytest.mark.parametrize(
    "conflict", ["pending start", "unowned running", "not quiescent", "kill switch"]
)
def test_group_boot_vetoes_before_manager_or_workload_mutation(
    group_boot, executor_state, conflict
):
    host, items, other, checkpoint, _ = group_boot
    _, database = executor_state
    checkpoint = advance_group(checkpoint, *STOP_ALL, "pause", "resume", "prepare")
    write_group_intent(database, checkpoint)
    if conflict == "pending start":
        binding = items["notes-a"].binding
        boot.Active(GENERATION, [binding], []).write()
        host.running[binding.unit] = True
        message = "application unit conflicts with boot intent"
    elif conflict == "unowned running":
        host.running[other.binding.unit] = True
        message = "active application unit lacks boot ownership"
    elif conflict == "not quiescent":
        host.group_service_quiescent = lambda user, unit, stem: False
        message = "application group unit is not quiescent"
    else:
        host.kill_switch = lambda: True
        message = "automatic application group boot is stopped"

    with pytest.raises(boot.BootError, match=message):
        boot.start(host)

    assert host.calls == [("firewall",)]


def test_group_authority_requires_existing_boot_runtime_lock(group_boot):
    host, _, _, checkpoint, registry = group_boot
    boot.RUNTIME.rmdir()

    with pytest.raises(boot.BootError, match="invalid or unavailable application group authority"):
        boot.require_group_authority(host, registry, checkpoint.plan)

    assert not boot.RUNTIME.exists()


def test_group_authority_rechecks_installed_boot_bindings(group_boot, monkeypatch, tmp_path):
    host, items, _, checkpoint, registry = group_boot
    monkeypatch.setattr(boot, "runtime_lock", lambda *, existing: nullcontext())
    monkeypatch.setattr(boot, "SYSTEMD", tmp_path)
    (tmp_path / boot.BOOT_UNIT).write_text("[Unit]\n")
    (tmp_path / boot.BOOT_UNIT).chmod(0o644)
    props = {
        "LoadState": "loaded",
        "FragmentPath": str(tmp_path / boot.BOOT_UNIT),
        "DropInPaths": "",
        "NeedDaemonReload": "no",
        "ActiveState": "active",
        "SubState": "exited",
        "Result": "success",
        "MainPID": "0",
        "UnitFileState": "enabled",
    }
    monkeypatch.setattr(boot, "boot_unit_properties", lambda: props)

    with pytest.raises(boot.BootError, match="lacks approved boot ownership"):
        boot.require_group_authority(host, registry, checkpoint.plan)

    enabled = [target.binding for target in items.values() if target.enabled]
    boot.Active(GENERATION, enabled, []).write()
    assert boot.require_group_authority(host, registry, checkpoint.plan) == items

    props["ActiveState"] = "activating"
    with pytest.raises(boot.BootError, match="has not been activated"):
        boot.require_group_authority(host, registry, checkpoint.plan)
    props["ActiveState"] = "active"

    host.application_unit_authority = lambda user, unit, source: False
    with pytest.raises(boot.BootError, match="application unit source changed"):
        boot.require_group_authority(host, registry, checkpoint.plan)


@pytest.fixture
def contested_boot_lock(lifecycle, monkeypatch, tmp_path):
    path = tmp_path / "executor-locks" / "deployment-execution.lock"
    path.parent.mkdir(mode=0o700, exist_ok=True)
    path.touch(mode=0o600)
    monkeypatch.setattr(boot, "DEPLOYMENT_LOCK", path)
    fstat = boot.os.fstat
    inode = path.stat().st_ino

    def root_owned_lock(fd):
        info = fstat(fd)
        if info.st_ino != inode:
            return info
        return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_nlink=info.st_nlink)

    monkeypatch.setattr(boot.os, "fstat", root_owned_lock)
    with path.open("rb") as holder:
        boot.fcntl.flock(holder, boot.fcntl.LOCK_EX | boot.fcntl.LOCK_NB)
        yield lifecycle([]), holder


@pytest.mark.parametrize("action", ["start", "stop", "recover-start"])
def test_ordinary_boot_hooks_wait_for_deployment_lock(contested_boot_lock, monkeypatch, action):
    host, holder = contested_boot_lock
    events = []

    def release_after_contention(delay):
        assert delay == 0.1
        events.append("wait")
        boot.fcntl.flock(holder, boot.fcntl.LOCK_UN)

    @contextmanager
    def runtime_after_deployment():
        with pytest.raises(BlockingIOError):
            boot.fcntl.flock(holder, boot.fcntl.LOCK_EX | boot.fcntl.LOCK_NB)
        events.append("runtime")
        yield

    def ordinary_hook(*args, **kwargs):
        events.append(action)
        return True

    monkeypatch.setattr(
        boot, "time", SimpleNamespace(monotonic=lambda: 0, sleep=release_after_contention)
    )
    monkeypatch.setattr(boot, "runtime_lock", runtime_after_deployment)
    monkeypatch.setattr(boot, "start", ordinary_hook)
    monkeypatch.setattr(boot, "stop_bindings", ordinary_hook)

    assert boot.run_boot_action(host, action, None, None, None)
    assert events == ["wait", "runtime", action]


@pytest.mark.parametrize(("action", "budget"), [("start", 0.25), ("publish", 0)])
def test_ordinary_boot_lock_wait_has_deadline(contested_boot_lock, monkeypatch, action, budget):
    host, _ = contested_boot_lock
    delays = []
    monkeypatch.setattr(boot, "BOOT_DEPLOYMENT_LOCK_WAIT", 0.25)
    monkeypatch.setattr(
        boot, "time", SimpleNamespace(monotonic=lambda: sum(delays), sleep=delays.append)
    )

    with pytest.raises(boot.BootError, match="deployment execution is busy"):
        boot.run_boot_action(host, action, None, None, None)

    assert sum(delays) == pytest.approx(budget)


@pytest.mark.parametrize("action", ["stop", "recover-start"])
@pytest.mark.parametrize("fenced_at_entry", [True, False])
def test_boot_stop_hook_skips_guarded_fence_before_or_after_wait(
    contested_boot_lock, monkeypatch, action, fenced_at_entry
):
    host, holder = contested_boot_lock
    fence = object() if fenced_at_entry else None
    waits = []

    def fence_appears_during_wait(delay):
        nonlocal fence
        waits.append(delay)
        fence = object()
        boot.fcntl.flock(holder, boot.fcntl.LOCK_UN)

    @contextmanager
    def unexpected_runtime():
        pytest.fail("skip the stop hook before taking the Boot runtime lock")
        yield

    monkeypatch.setattr(boot, "read_deployment_fence", lambda: fence)
    monkeypatch.setattr(boot, "runtime_lock", unexpected_runtime)
    monkeypatch.setattr(
        boot, "time", SimpleNamespace(monotonic=lambda: 0, sleep=fence_appears_during_wait)
    )

    assert boot.run_boot_action(host, action, None, None, None) is False
    assert waits == ([] if fenced_at_entry else [0.1])


def test_group_boot_translates_site_verifier_error_from_package_module(
    group_boot, executor_state, monkeypatch
):
    host, _, _, checkpoint, _ = group_boot
    _, database = executor_state
    write_group_intent(database, checkpoint)

    class PackageBootError(Exception):
        pass

    def unavailable(*, private):
        assert private
        raise PackageBootError("private deployment inputs changed")

    monkeypatch.setattr(site_deployment, "boot", SimpleNamespace(BootError=PackageBootError))
    monkeypatch.setattr(site_deployment, "installed_config", unavailable)
    with pytest.raises(boot.BootError, match="private deployment inputs changed"):
        boot.start(host)

    assert host.calls == [("firewall",)]


def test_group_boot_rechecks_kill_switch_after_writing_pending_start(group_boot, executor_state):
    host, _, _, checkpoint, _ = group_boot
    _, database = executor_state
    write_group_intent(database, checkpoint)
    host.kill_switch = lambda: bool(boot.read_active().pending)

    with pytest.raises(boot.BootError, match="automatic application group boot is stopped"):
        boot.start(host)

    assert not any(call[0] in ("start", "stop") for call in host.calls)
    assert not boot.read_active().bindings


def test_ordinary_boot_restart_stops_owned_units_before_starting(
    contested_boot_lock, lifecycle, monkeypatch
):
    _, holder = contested_boot_lock
    item = target("source", 0)
    host = lifecycle([item])
    host.running[item.binding.unit] = True
    boot.Active(GENERATION, [item.binding], []).write()

    def release_after_contention(_delay):
        assert host.calls == []
        assert host.running[item.binding.unit]
        boot.fcntl.flock(holder, boot.fcntl.LOCK_UN)

    monkeypatch.setattr(
        boot, "time", SimpleNamespace(monotonic=lambda: 0, sleep=release_after_contention)
    )
    monkeypatch.setattr(boot, "runtime_lock", nullcontext)

    assert boot.run_boot_action(host, "stop", None, None, None)
    assert boot.run_boot_action(host, "recover-start", None, None, None) is False
    assert boot.run_boot_action(host, "start", None, None, None)

    assert [call for call in host.calls if call[0] in ("start", "stop")] == [
        ("stop", item.binding.unit),
        ("start", item.binding.unit),
    ]
