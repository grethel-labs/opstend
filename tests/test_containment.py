"""Executor exposure removal, quarantine and verified reactivation (L07 step 3, L08)."""

import json
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from steward.core import incidents as inc
from steward.core.vulnerabilities import Component, ScanResult
from steward.executor import containment, server
from steward.executor.protocol import ExecutorError
from test_executor import request
from test_group_checkpoint import group_registry as group_registry
from test_group_checkpoint import restart
from test_group_reconcile import group_host as group_host

REGISTRY_PEERS = {"api": 4241, "controller": 4242, "collector": 4343}
FINDING = {"service": "database", "advisory": "CVE-2026-0001", "verdict": "critical"}
EXPLOITED = {**FINDING, "verdict": "critical_exploited"}
STOP_ORDER = ["worker", "frontend", "backend", "database"]  # reverse dependency order


class Crash(Exception):
    pass


@pytest.fixture
def env(executor, group_registry, group_host, tmp_path, monkeypatch):
    states, mutations = group_host
    states.update(dict.fromkeys(states, True))
    Path(executor._db_path).parent.chmod(0o700)
    root = tmp_path / "applications"
    monkeypatch.setattr(server, "APPLICATION_DATA_ROOT", root)
    registry = group_registry
    registry.update(server_name="test-server", backup={"max_mib": 1}, peers=REGISTRY_PEERS)
    registry["containment"] = {"enabled": True}
    specs = registry["applications"]["shop"]["services"]
    for name, spec in specs.items():
        spec["deploy"] = True
        if name in ("database", "worker"):
            path = root / "shop" / "data" / name
            path.mkdir(parents=True)
            (path / "value.txt").write_text("original " + name)
            path.chmod(0o700)
            (path / "value.txt").chmod(0o600)
            spec.update(data_source=str(path), data_target="/data", allow_backup_pause=True)
        else:
            spec.update(data_source=None, data_target=None)
    specs["frontend"]["routes"] = ["shop.example.test"]
    for directory in (root, root / "shop", root / "shop" / "data"):
        directory.chmod(0o700)
    write(executor, registry)
    by_unit = {spec["unit"]: name for name, spec in specs.items()}
    host = executor.host
    host.workload_quiescent = lambda _user, unit: states[by_unit[unit]] is False
    net = SimpleNamespace(ports=None, fail=False, applies=0)

    def apply(ports, _path):
        net.applies += 1
        if net.fail:
            return False, "nft failed"
        net.ports = set(ports)
        return True, ""

    def clear():
        if not net.fail:
            net.ports = None
        return not net.fail, ""

    host.containment_apply = apply
    host.containment_clear = clear
    host.containment_ports = lambda: None if net.ports is None else set(net.ports)
    running = {spec["container"]: "sha256:" + f"{i:064x}" for i, spec in enumerate(specs.values())}
    manifests = {spec["container"]: spec["image"].rsplit("@", 1)[1] for spec in specs.values()}
    by_container = {spec["container"]: name for name, spec in specs.items()}
    host.container = lambda _user, name: {
        "Image": running[name],
        "ImageDigest": manifests[name],
        "State": {"Running": states[by_container[name]]},
    }
    host.configured_image_identity = lambda _image: None
    return SimpleNamespace(
        ex=executor, registry=registry, states=states, mutations=mutations, net=net,
        specs=specs, running=running, manifests=manifests, root=root,
    )  # fmt: skip


def write(executor, registry):
    Path(executor.registry_path).write_text(json.dumps(registry))


def driver(env):
    return containment._driver(env.ex)


def open_params(env, *findings):
    bound = []
    for finding in findings or (FINDING,):
        spec = env.specs.get(finding["service"])
        binding = (
            {"image": spec["image"], "image_id": env.running[spec["container"]]} if spec else None
        )
        bound.append({**finding, "binding": binding})
    return {
        "application": "shop",
        "expected_revision": env.registry["config_revision"],
        "findings": bound,
    }


def open_incident(env, *findings):
    return driver(env).open(
        containment.IncidentOpenParams.model_validate(open_params(env, *findings)),
        "controller",
    )


def tick(env, d=None):
    d = d or driver(env)
    return d.advance(containment.IncidentAdvanceParams(application="shop"), "controller")


def drive(env, target, *, limit=12, d=None):
    seen = []
    for _ in range(limit):
        result = tick(env, d)
        seen.append(result["state"])
        if result["state"] == target or result.get("waiting") or result.get("blocked"):
            break
    return seen


def expire(env):
    """Let the notice period elapse by moving the recorded deadline into the past."""
    store = driver(env).store
    store.update(store.get("shop"), deadline=time.time() - 1)


def stored(env):
    return inc.IncidentStore(Path(env.ex._db_path).parent / "incidents").get("shop")


def audit(env, outcome=None):
    entries = [e for e in env.ex.audit.read(500) if e["event"] == "incident"]
    return [e for e in entries if outcome in (None, e["outcome"])]


def reactivate(env, evidence=(), *, role="controller"):
    return driver(env).reactivate(
        containment.IncidentReactivateParams(
            application="shop",
            expected_revision=env.registry["config_revision"] if role == "controller" else None,
            evidence=list(evidence),
        ),
        role,
    )


def clean_scan(env, service="database", **changes):
    spec = env.specs[service]
    subject = Component(
        kind="image", scope=f"shop/{service}", name=service + "-image",
        version=spec["image"].split("@")[1], image=spec["image"], runtime_verified=True,
        expected_image_id=env.running[spec["container"]],
    )  # fmt: skip
    scan = ScanResult(
        source="trivy", inventory_revision="c" * 64, subject=subject, checked_at=time.time(),
        database_updated_at=time.time(), state="not_affected", complete=True,
    )  # fmt: skip
    return {"service": service, "scan": scan.model_dump(mode="json") | changes}


def apply_fix(env):
    """The fix lands on disk while quarantined: new image digests and revision."""
    for name, spec in env.specs.items():
        spec["image"] = spec["image"].rsplit("@", 1)[0] + "@sha256:" + "b" * 64
        env.running[spec["container"]] = "sha256:" + f"{0xB0 + len(name):064x}"
        env.manifests[spec["container"]] = spec["image"].rsplit("@", 1)[1]
    env.registry["config_revision"] = "e" * 64
    write(env.ex, env.registry)


def to_quarantine(env, *findings):
    open_incident(env, *(findings or [EXPLOITED]))
    assert drive(env, "quarantined")[-1] == "quarantined"
    env.mutations.clear()


# ---- admission --------------------------------------------------------------------------


def call(env, action, params, peer=0):
    return env.ex.handle(request(action, params), peer)


def test_feature_roles_schema_and_kill_switch(env):
    params = {"application": "shop", "findings": [FINDING]}
    assert call(env, "incident_open", params, peer=4343)["error_class"] == "forbidden_role"
    assert call(env, "incident_open", params, peer=4241)["error_class"] == "forbidden_role"
    assert call(env, "incident_open", params, peer=99)["error_class"] == "unauthorized_peer"
    extra = {**params, "command": "rm -rf /"}
    assert call(env, "incident_open", extra, peer=4242)["error_class"] == "bad_request"
    bad = {"application": "shop", "findings": [{**FINDING, "advisory": "x; reboot"}]}
    assert call(env, "incident_open", bad, peer=4242)["error_class"] == "bad_request"
    env.ex.host.killed = True
    assert call(env, "incident_open", params, peer=4242)["error_class"] == "kill_switch"
    assert call(env, "incident_advance", {"application": "shop"}, 4242)["error_class"] == (
        "kill_switch"
    )
    assert stored(env) is None and env.net.ports is None
    env.ex.host.killed = False
    assert call(env, "incident_open", open_params(env), peer=4242)["ok"]
    # read-only status is visible to the controller and api roles, not the collector
    assert call(env, "incident_status", {}, peer=4241)["ok"]
    assert call(env, "incident_status", {}, peer=4343)["error_class"] == "forbidden_role"


def test_incident_status_reports_the_exposure_revision(env):
    status = call(env, "incident_status", {}, peer=4242)["result"]
    assert status["config_revision"] == env.registry["config_revision"]
    assert status["applications"]["shop"]["exposure"]["database"] == "indirect"


@pytest.mark.parametrize(
    "policy, enabled",
    [
        (None, False),
        ({"enabled": False}, False),
        ({"enabled": 1}, False),
        ({"enabled": True, "notice_minutes": 1}, False),
        ({"enabled": True}, True),
    ],
)
def test_platform_status_advertises_only_enabled_containment(executor, policy, enabled):
    registry = server.load_registry(executor.registry_path)
    if policy is not None:
        registry["containment"] = policy
    write(executor, registry)
    status = executor.handle(request("platform_status"), 0)["result"]
    if enabled:
        assert status["containment_enabled"] is True
    else:
        assert "containment_enabled" not in status


def test_controller_open_requires_revision_and_current_binding(env):
    params = open_params(env)
    for changes, error in (
        ({"expected_revision": None}, "bad_request"),
        ({"expected_revision": "0" * 64}, "conflict"),
        ({"findings": [FINDING]}, "policy_denied"),
    ):
        assert call(env, "incident_open", params | changes, peer=4242)["error_class"] == error
    name = env.specs["database"]["container"]
    env.running[name] = "sha256:" + "e" * 64
    assert call(env, "incident_open", params, peer=4242)["error_class"] == "policy_denied"
    env.manifests[name] = "sha256:" + "f" * 64
    response = call(env, "incident_open", open_params(env), peer=4242)
    assert response["error_class"] == "policy_denied"
    assert stored(env) is None


def test_controller_open_observes_each_service_once_and_stores_only_finding_refs(env):
    observed = []
    inspect = env.ex.host.container

    def container(user, name):
        observed.append(name)
        return inspect(user, name)

    env.ex.host.container = container
    second = FINDING | {"advisory": "CVE-2026-0002"}
    result = open_incident(env, FINDING, second)
    assert result["created"]
    assert observed == [env.specs["database"]["container"]]
    assert [finding.model_dump() for finding in stored(env).findings] == [FINDING, second]


@pytest.mark.parametrize("drift", ["revision", "peers", "fence"])
def test_controller_open_checks_state_after_acquiring_deployment_lock(env, monkeypatch, drift):
    lock = env.ex.target_lock
    params = open_params(env)

    @contextmanager
    def target_lock(target):
        with lock(target):
            if target == "deployment-execution":
                if drift == "fence":
                    monkeypatch.setattr(env.ex, "deployment_fence", lambda: object())
                elif drift == "peers":
                    env.registry["peers"] = REGISTRY_PEERS | {"controller": 5234}
                    write(env.ex, env.registry)
                else:
                    env.registry["config_revision"] = "0" * 64
                    write(env.ex, env.registry)
            yield

    monkeypatch.setattr(env.ex, "target_lock", target_lock)
    result = call(env, "incident_open", params, peer=4242)
    assert result["error_class"] == ("target_busy" if drift == "fence" else "conflict")
    assert stored(env) is None


def test_disabled_feature_and_shared_isolation_are_refused(env):
    del env.registry["containment"]
    write(env.ex, env.registry)
    response = call(env, "incident_open", {"application": "shop", "findings": [FINDING]})
    assert response["error_class"] == "policy_denied" and "not enabled" in response["message"]
    assert call(env, "containment_reassert", {})["error_class"] == "policy_denied"
    env.registry["containment"] = {"enabled": True}
    env.registry["applications"]["shop"]["isolation"] = "shared"
    write(env.ex, env.registry)
    response = call(env, "incident_open", {"application": "shop", "findings": [FINDING]})
    assert (
        response["error_class"] == "policy_denied" and "separately isolated" in response["message"]
    )
    assert stored(env) is None and env.net.ports is None


def test_only_exposed_services_open_an_incident(env):
    worker = {**FINDING, "service": "worker"}  # nobody routes to it
    with pytest.raises(ExecutorError) as error:
        open_incident(env, worker)
    assert error.value.error_class == "policy_denied"
    with pytest.raises(ExecutorError):
        open_incident(env, {**FINDING, "service": "ghost"})
    assert stored(env) is None
    env.specs["frontend"]["deploy"] = False  # a stopped front end exposes nothing
    write(env.ex, env.registry)
    with pytest.raises(ExecutorError):
        open_incident(env)


# ---- L07: incident, deadline, exposure removal ---------------------------------------------


def test_incident_persists_deadline_id_and_exposure_across_restart(env):
    created = open_incident(env)["incident"]
    record = stored(env)
    assert record.phase == "notice" and record.deadline == record.opened_at + 3600
    assert record.exposers == ["frontend"] and record.ports == [21003]  # indirect database
    assert created["id"] == record.id and record.id.startswith("inc-")
    assert not record.exploited and audit(env, "opened")[0]["correlation_id"] == record.id
    again = open_incident(env)
    assert again["created"] is False and stored(env).seq == record.seq  # idempotent
    restarted = containment._driver(restart(env.ex))
    assert restarted.store.get("shop").deadline == record.deadline
    assert tick(env)["waiting"] == "notice" and env.net.applies == 0  # no early action


def test_known_exploited_exception_shortens_an_open_notice(env):
    open_incident(env)
    before = stored(env)
    open_incident(env, EXPLOITED)
    after = stored(env)
    assert after.exploited and after.deadline <= before.opened_at + 1
    assert len(after.findings) == 2
    assert tick(env)["state"] == "disconnected"  # no waiting for the hour


def test_exposure_removal_waits_for_neither_backup_nor_notification(env):
    open_incident(env)
    expire(env)
    # the backup would fail and nothing could be delivered: exposure ends regardless
    env.ex.capture_application_with_recovery = lambda *a: (_ for _ in ()).throw(Crash())
    result = tick(env)
    assert result["state"] == "disconnected" and env.net.ports == {21003}
    assert env.mutations == []  # no service was touched
    assert stored(env).disconnected_at is not None
    removed = audit(env, "exposure_removed")
    assert len(removed) == 1 and removed[0]["correlation_id"] == stored(env).id


def test_exposure_removal_failure_stays_open_escalates_and_retries(env):
    open_incident(env, EXPLOITED)
    env.net.fail = True
    result = tick(env)
    assert result["state"] == "disconnect_failed"
    assert audit(env, "escalated")[-1]["phase"] == "disconnect_failed"
    assert env.mutations == [] and stored(env).contained
    env.net.fail = False
    assert tick(env)["state"] == "disconnected" and env.net.ports == {21003}


def test_notify_policy_records_the_incident_but_never_contains(env):
    env.registry["applications"]["shop"]["on_critical"] = "notify"
    write(env.ex, env.registry)
    open_incident(env, EXPLOITED)
    record = stored(env)
    assert record.on_critical == "notify" and record.phase == "notice"
    expire(env)
    result = tick(env)
    assert result["waiting"] == "notify_only" and result["state"] == "notice"
    assert stored(env).escalated_at is not None and len(audit(env, "escalated")) == 1
    tick(env)
    assert len(audit(env, "escalated")) == 1  # escalated once
    assert env.net.ports is None and env.mutations == []


def test_ssh_and_other_ports_are_never_in_the_block(env):
    open_incident(env, EXPLOITED)
    tick(env)
    assert env.net.ports == {21003}  # the routed backend only; nothing like 22 or 80


def test_desired_block_is_derived_from_recorded_incidents(env):
    open_incident(env, EXPLOITED)
    tick(env)
    d = driver(env)
    assert d._desired() == {21003} and d._desired(exclude="shop") == set()


# ---- L08: backup, quarantine --------------------------------------------------------------------


def test_quarantine_end_to_end_with_backup_before_ordered_shutdown(env):
    open_incident(env, EXPLOITED)
    seen = drive(env, "quarantined")
    assert seen == ["disconnected", "backup_verified", "quarantined"]
    record = stored(env)
    assert record.backup and record.disconnected_at is not None
    assert env.net.ports == {21003}
    assert not any(env.states.values())
    stops = [name for name, running in env.mutations if running is False]
    assert stops[-4:] == STOP_ORDER and env.mutations[-1] == ("database", False)
    # the capture really exists, covers the registered data and was re-read
    verified = env.ex.verify_group_capture("shop", record.backup.artifact, record.backup.capture_id)
    assert verified["capture"]["data_services"] == ["database", "worker"]
    order = [e["outcome"] for e in audit(env)]
    assert order.index("exposure_removed") < order.index("backup_verified")
    assert order.index("backup_verified") < order.index("announced") < order.index("quarantined")
    assert {e["correlation_id"] for e in audit(env)} == {record.id}
    assert env.ex.audit.verify()[0]
    assert tick(env)["waiting"] == "fix"


def test_failed_backup_leaves_stack_running_disconnected_and_escalated(env):
    (env.root / "shop" / "data" / "worker" / "unsafe").symlink_to("/etc/shadow")
    open_incident(env, EXPLOITED)
    seen = drive(env, "backup_failed")
    assert seen[-1] == "backup_failed"
    record = stored(env)
    assert record.error_class and record.contained and record.backup is None
    assert env.net.ports == {21003}
    assert all(env.states.values())  # still running
    assert audit(env, "escalated")[-1]["phase"] == "backup_failed"
    # a retry never stops the stack without a verified capture, however often it is asked
    for _ in range(3):
        result = tick(env)
        assert result["state"] in ("backup_failed", "backup_pending")
    assert all(env.states.values()) and stored(env).phase != "quarantined"
    assert not audit(env, "quarantined")


def test_stack_without_registered_data_is_never_quarantined(env):
    for spec in env.specs.values():
        spec.update(data_source=None, data_target=None)
    write(env.ex, env.registry)
    open_incident(env, EXPLOITED)
    assert drive(env, "quarantined")[-1] == "backup_failed"
    assert all(env.states.values()) and env.net.ports == {21003}


def stateless(env):
    for spec in env.specs.values():
        spec.update(data_source=None, data_target=None)
    env.registry["applications"]["shop"]["stateless"] = True
    write(env.ex, env.registry)


def test_an_explicitly_stateless_application_is_stopped_without_a_backup(env):
    stateless(env)
    open_incident(env, EXPLOITED)
    seen = drive(env, "quarantined")
    assert seen == ["disconnected", "backup_verified", "quarantined"]
    record = stored(env)
    assert record.backup is None and record.backup_operation is None  # no capture was claimed
    assert not any(env.states.values()) and env.net.ports == {21003}
    stops = [name for name, running in env.mutations if running is False]
    assert stops[-4:] == STOP_ORDER
    skipped = audit(env, "backup_skipped")
    assert len(skipped) == 1 and skipped[0]["reason"] == "stateless_contract"
    assert not audit(env, "backup_verified")  # a skipped backup is never reported as verified
    assert tick(env)["waiting"] == "fix"


def test_the_stateless_marker_is_read_from_the_registry_only_and_can_be_withdrawn(env):
    stateless(env)
    open_incident(env, EXPLOITED)
    assert drive(env, "backup_verified")[-1] == "backup_verified"
    env.registry["applications"]["shop"].pop("stateless")  # the contract no longer says so
    write(env.ex, env.registry)
    result = tick(env)
    assert result["state"] == "stop_failed" and all(env.states.values())
    assert stored(env).error_class == "no_backup"


def test_stop_is_refused_when_the_backup_can_no_longer_be_read(env):
    open_incident(env, EXPLOITED)
    assert drive(env, "backup_verified")[-1] == "backup_verified"
    record = stored(env)
    artifact = Path(env.ex._db_path).parent / "group-captures" / "shop" / record.backup.artifact
    (artifact / "database" / "data.tar").write_bytes(b"tampered")
    env.mutations.clear()
    result = tick(env)
    assert result["state"] == "stop_failed" and all(env.states.values())
    assert env.mutations == [m for m in env.mutations if m[1] is True]  # nothing stopped by us


def test_deployment_fence_blocks_shutdown_but_not_the_disconnect(env):
    open_incident(env, EXPLOITED)
    assert drive(env, "backup_verified")[-1] == "backup_verified"
    env.ex.deployment_fence = lambda: object()
    assert tick(env)["waiting"] == "target_busy"
    assert stored(env).phase == "stopping" and env.net.ports == {21003}


def test_controller_disconnect_reads_current_ports_under_deployment_lock(env, monkeypatch):
    open_incident(env, EXPLOITED)
    with monkeypatch.context() as patch:
        patch.setattr(env.ex, "deployment_fence", lambda: object())
        with pytest.raises(ExecutorError, match="target_busy"):
            tick(env)
    assert stored(env).phase == "notice" and env.net.ports is None
    lock = env.ex.target_lock

    @contextmanager
    def install_before_lock(name):
        if name == "deployment-execution":
            env.specs["frontend"]["host_port"] = 22003
            env.registry["config_revision"] = "e" * 64
            write(env.ex, env.registry)
        with lock(name):
            yield

    monkeypatch.setattr(env.ex, "target_lock", install_before_lock)
    assert tick(env)["state"] == "disconnected"
    assert env.net.ports == {21003, 22003}


def test_controller_adds_a_service_to_an_incident_at_the_legacy_finding_cap(env):
    findings = [dict(FINDING, advisory=f"CVE-2026-{1000 + i}") for i in range(20)]
    params = {"application": "shop", "findings": findings}
    assert call(env, "incident_open", params)["ok"]
    open_incident(env, dict(FINDING, service="frontend"))
    assert stored(env).affected == ["database", "frontend"]


# ---- interruption at every transition -------------------------------------------------------------

TRANSITIONS = [
    "disconnecting", "disconnected", "backup_pending", "backup_verified", "stopping",
    "quarantined", "fix_verification", "reactivating", "reactivated",
]  # fmt: skip


@pytest.mark.parametrize("when", ["before", "after"])
@pytest.mark.parametrize("target", TRANSITIONS)
def test_crash_at_every_transition_resumes_without_lifting_the_block(
    env, monkeypatch, target, when
):
    """The process dies right before or right after persisting each phase change.

    A fresh executor (startup reassertion included) resumes from the durable record
    alone. At no observation after exposure removal may the block be missing while the
    incident is still open, and the run must still reach a verified reactivation.
    """
    original = inc.IncidentStore.transition
    armed = {"on": True}

    def crashing(self, incident, to, now, detail="", **changes):
        fire = armed["on"] and to == target
        if fire and when == "before":
            armed["on"] = False
            raise Crash(to)
        result = original(self, incident, to, now, detail, **changes)
        if fire and when == "after":
            armed["on"] = False
            raise Crash(to)
        return result

    monkeypatch.setattr(inc.IncidentStore, "transition", crashing)
    open_incident(env, EXPLOITED)
    crashed = fixed = False
    for _ in range(40):
        record = stored(env)
        if record is None:
            break
        try:
            if record.phase == "quarantined" and not fixed:
                apply_fix(env)
                fixed = True
            if (
                fixed
                and record.phase in ("quarantined", "fix_verification")
                or (record.phase in ("reactivating", "reactivation_failed"))
            ):
                reactivate(env, [clean_scan(env)])
            else:
                tick(env)
        except Crash:
            crashed = True
            env.ex = restart(env.ex)  # a new process: only the durable state survives
            containment.reassert_at_startup(env.ex)
        record = stored(env)
        if record is not None and record.phase in (
            "disconnected", "backup_pending", "backup_failed", "backup_verified", "stopping",
            "stop_failed", "quarantined", "fix_verification",
        ):  # fmt: skip
            assert env.net.ports == {21003}, record.phase
    assert crashed, "the injected crash must have fired"
    assert stored(env) is None and driver(env).store.closed("shop").phase == "reactivated"
    assert env.net.ports is None and all(env.states.values())
    spool = Path(env.ex._db_path).parent / "group-captures" / "shop"
    assert 1 <= len(list(spool.iterdir())) <= 2  # a resumed backup is not repeated needlessly
    assert env.ex.audit.verify()[0]


def test_interrupted_backup_checkpoint_is_not_restarted_underneath_recovery(env):
    open_incident(env, EXPLOITED)
    tick(env)  # disconnected
    with env.ex.observed_group_execution(
        "shop", "database", expected_revision=env.registry["config_revision"], scope="application"
    ):
        pass  # an unfinished group intent exists (for example mid-crash)
    result = tick(env)
    assert result["waiting"] == "group_transition" and stored(env).phase == "backup_pending"
    assert env.net.ports == {21003}


# ---- reboot / self-healing ------------------------------------------------------------------------


def test_reboot_restores_block_and_keeps_quarantine_down(env):
    to_quarantine(env)
    # reboot: the nft table is gone and the units came back up
    env.net.ports = None
    env.states.update(dict.fromkeys(env.states, True))
    containment.reassert_at_startup(restart(env.ex))
    assert env.net.ports == {21003}
    assert not any(env.states.values())
    assert [m for m in env.mutations if m[1] is False][-4:] == [(n, False) for n in STOP_ORDER]
    assert audit(env, "quarantine_reasserted")


def test_controller_reassert_action_is_a_no_op_when_nothing_changed(env):
    to_quarantine(env)
    result = call(env, "containment_reassert", {})
    assert result["ok"] and result["result"]["changed"] is False and not result["result"]["held"]
    env.net.ports = None
    result = call(env, "containment_reassert", {}, peer=4242)
    assert result["ok"] and result["result"]["changed"] is True and env.net.ports == {21003}


def test_startup_without_incidents_or_feature_changes_nothing(env):
    containment.reassert_at_startup(restart(env.ex))
    assert env.net.applies == 0 and env.mutations == []
    del env.registry["containment"]
    write(env.ex, env.registry)
    containment.reassert_at_startup(restart(env.ex))
    assert env.net.applies == 0


def test_ordinary_restart_of_a_quarantined_unit_is_not_a_lift(env):
    to_quarantine(env)
    # nothing in the ordinary self-healing path touches the incident or the block
    assert stored(env).phase == "quarantined"
    status = call(env, "incident_status", {"application": "shop"})["result"]
    assert status["blocked_ports"] == [21003]
    assert status["incidents"][0]["phase"] == "quarantined"
    assert status["applications"]["shop"]["exposure"]["database"] == "indirect"


# ---- L08: fix verification and reactivation ---------------------------------------------------


def test_verified_reactivation_starts_in_order_then_restores_the_route(env):
    to_quarantine(env)
    assert reactivate(env)["blocked"] == "fix_not_applied"  # nothing changed yet
    assert stored(env).phase == "quarantined" and env.net.ports == {21003}
    apply_fix(env)
    first = reactivate(env)  # starts disconnected, asks for evidence
    assert first["state"] == "fix_verification" and first["needs"] == "evidence"
    assert env.net.ports == {21003} and all(env.states.values())
    starts = [name for name, running in env.mutations if running]
    assert starts == ["database", "backend", "frontend", "worker"]  # dependency order
    result = reactivate(env, [clean_scan(env)])
    assert result["state"] == "reactivated", result
    assert env.net.ports is None and stored(env) is None
    assert driver(env).store.closed("shop").phase == "reactivated"
    assert audit(env, "reactivated") and audit(env, "fix_verified")
    assert {e["correlation_id"] for e in audit(env)} == {driver(env).store.closed("shop").id}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: s["scan"].update(checked_at=1.0, database_updated_at=1.0),  # stale
        lambda s: s["scan"].update(state="unknown", complete=False),
        lambda s: s["scan"].update(state="scan_failed", complete=False, error_class="timeout"),
        lambda s: s["scan"]["subject"].update(runtime_verified=False),
        lambda s: s["scan"]["subject"].update(scope="other/database"),
        lambda s: s["scan"].update(source="osv"),
        lambda s: s["scan"]["subject"].update(expected_image_id="sha256:" + "9" * 64),
        lambda s: s["scan"]["subject"].update(
            image="ghcr.io/x/y@sha256:" + "d" * 64, version="sha256:" + "d" * 64
        ),
        lambda s: s["scan"].update(checked_at=time.time() - 10, database_updated_at=time.time()),
    ],
)
def test_unverified_evidence_never_clears_quarantine(env, mutate):
    to_quarantine(env)
    apply_fix(env)
    reactivate(env)
    evidence = clean_scan(env)
    mutate(evidence)
    result = reactivate(env, [evidence])
    assert result["state"] == "fix_verification" and result["needs"] == "evidence"
    assert env.net.ports == {21003} and stored(env).phase == "fix_verification"
    assert reactivate(env)["needs"] == "evidence"  # no evidence at all
    assert reactivate(env, [clean_scan(env, "backend")])["needs"] == "evidence"  # wrong service


def test_confirmed_finding_on_the_fixed_instance_requarantines(env):
    to_quarantine(env)
    apply_fix(env)
    reactivate(env)
    still = clean_scan(env)
    still["scan"].update(
        state="confirmed",
        findings=[{"id": "CVE-2026-0001", "severity": "critical", "summary": "x"}],
    )
    result = reactivate(env, [still])
    assert result["state"] == "quarantined" and not any(env.states.values())
    assert env.net.ports == {21003} and audit(env, "fix_rejected")
    assert stored(env).fix_started_at is None


def test_route_restore_failure_stays_disconnected_and_retries(env, monkeypatch):
    to_quarantine(env)
    apply_fix(env)
    reactivate(env)
    env.net.fail = True
    result = reactivate(env, [clean_scan(env)])
    assert result["state"] == "reactivation_failed" and env.net.ports == {21003}
    env.net.fail = False
    assert reactivate(env)["needs"] == "evidence"
    assert env.net.ports == {21003}
    evidence = clean_scan(env)
    name = env.specs["database"]["container"]
    env.running[name] = "sha256:" + "f" * 64
    assert reactivate(env, [evidence])["needs"] == "evidence"
    assert env.net.ports == {21003}
    env.running[name] = evidence["scan"]["subject"]["expected_image_id"]
    clear = env.ex.host.containment_clear

    def fenced_clear():
        with pytest.raises(ExecutorError) as error, env.ex.target_lock("deployment-execution"):
            pytest.fail("route restore must hold the deployment lock")
        assert error.value.error_class == "target_busy"
        return clear()

    monkeypatch.setattr(env.ex.host, "containment_clear", fenced_clear)
    assert reactivate(env, [evidence])["state"] == "reactivated"
    assert env.net.ports is None


def test_controller_reactivation_guards_drift_fence_and_runtime_mismatch(env, monkeypatch):
    to_quarantine(env)
    apply_fix(env)
    params = {"application": "shop"}
    assert call(env, "incident_reactivate", params, peer=4242)["error_class"] == "bad_request"
    params["expected_revision"] = "0" * 64
    assert call(env, "incident_reactivate", params, peer=4242)["error_class"] == "conflict"
    params["expected_revision"] = env.registry["config_revision"]
    with monkeypatch.context() as patch:
        patch.setattr(env.ex, "deployment_fence", lambda: object())
        assert call(env, "incident_reactivate", params, peer=4242)["error_class"] == "target_busy"
    assert stored(env).phase == "quarantined" and not env.mutations
    reactivate(env)
    evidence = clean_scan(env)
    name = env.specs["database"]["container"]
    original = env.manifests[name]
    env.manifests[name] = "sha256:" + "f" * 64
    assert reactivate(env, [evidence])["needs"] == "evidence"
    env.manifests[name] = original
    observe = server.runtime_image_observation

    def drifting_observation(ex, spec):
        observation = observe(ex, spec)
        env.registry["config_revision"] = "0" * 64
        write(env.ex, env.registry)
        return observation

    monkeypatch.setattr(server, "runtime_image_observation", drifting_observation)
    params["evidence"] = [evidence]
    assert call(env, "incident_reactivate", params, peer=4242)["error_class"] == "conflict"
    assert stored(env).phase == "fix_verification" and env.net.ports == {21003}


def test_wrong_scope_confirmed_evidence_does_not_requarantine(env):
    to_quarantine(env)
    apply_fix(env)
    reactivate(env)
    evidence = clean_scan(
        env,
        state="confirmed",
        findings=[{"id": "CVE-2026-0001", "severity": "critical", "summary": "x"}],
    )
    evidence["scan"]["subject"]["scope"] = "other/database"
    assert reactivate(env, [evidence])["needs"] == "evidence"
    assert all(env.states.values()) and stored(env).phase == "fix_verification"
    assert env.net.ports == {21003}


def test_operator_can_open_and_retry_route_restore_with_legacy_payloads(env):
    assert call(env, "incident_open", {"application": "shop", "findings": [EXPLOITED]})["ok"]
    assert drive(env, "quarantined")[-1] == "quarantined"
    apply_fix(env)
    reactivate(env, role="operator")
    legacy = clean_scan(env, source="osv")
    legacy["scan"]["subject"]["scope"] = "database"
    env.net.fail = True
    assert reactivate(env, [legacy], role="operator")["state"] == "reactivation_failed"
    env.net.fail = False
    assert reactivate(env, role="operator")["state"] == "reactivated"
    assert env.net.ports is None


def test_start_failure_keeps_the_block_and_asks_again(env):
    to_quarantine(env)
    apply_fix(env)
    env.ex.host.set_user_unit = lambda *a, **k: False
    result = reactivate(env, [clean_scan(env)])
    assert result["blocked"].startswith("start_") and env.net.ports == {21003}
    assert stored(env).phase == "fix_verification"


def test_reactivation_before_quarantine_or_without_incident_is_refused(env):
    with pytest.raises(ExecutorError):
        reactivate(env)
    open_incident(env)
    assert reactivate(env)["blocked"] == "not_quarantined"
    assert env.net.ports is None and stored(env).phase == "notice"


# ---- Host regression checks: boot, stray starts, capture budget, causes ---------------------------


def test_periodic_reassert_stops_a_stray_start_within_one_cycle_and_audits_it(env):
    to_quarantine(env)
    env.states["frontend"] = True  # e.g. a deployment or boot unit started it
    env.net.ports = None  # and the table was lost
    containment.PeriodicReassert(env.ex).tick()
    assert not any(env.states.values()) and env.net.ports == {21003}
    assert audit(env, "quarantine_reasserted")
    before = len(audit(env))
    containment.PeriodicReassert(env.ex).tick()  # nothing to do: no new records
    assert len(audit(env)) == before


def test_periodic_reassert_is_silent_when_the_feature_is_off(env):
    del env.registry["containment"]
    write(env.ex, env.registry)
    containment.PeriodicReassert(env.ex).tick()
    assert env.net.applies == 0 and env.mutations == []


def test_boot_keeps_units_of_a_quarantined_application_down(tmp_path, monkeypatch):
    from steward import application_boot as boot
    from test_incidents import new

    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setattr(boot, "EXECUTOR_STATE_DB", state / "state.db")
    store = inc.IncidentStore(state / "incidents")
    targets = [
        SimpleNamespace(binding=SimpleNamespace(application="shop", unit="a.service")),
        SimpleNamespace(binding=SimpleNamespace(application="blog", unit="b.service")),
    ]
    assert boot.quarantine_projection(targets) == {}  # no incidents at all
    current = store.open(new())
    assert boot.quarantine_projection(targets) == {}  # notice: nothing stopped yet
    for phase in ("disconnecting", "disconnected", "backup_pending", "backup_verified"):
        current = store.transition(current, phase, 2000.0)
        assert boot.quarantine_projection(targets) == {}  # running but disconnected
    for phase in ("stopping", "quarantined", "fix_verification"):
        current = store.transition(current, phase, 2000.0)
        assert boot.quarantine_projection(targets) == {"a.service": False}
    (state / "incidents" / "shop.json").write_text("{broken")
    with pytest.raises(boot.BootError):
        boot.quarantine_projection(targets)  # unreadable evidence never means "start"


def test_failed_capture_does_not_consume_the_budget_but_attempts_are_bounded(env):
    link = env.root / "shop" / "data" / "worker" / "unsafe"
    link.symlink_to("/etc/shadow")
    open_incident(env, EXPLOITED)
    tick(env)  # disconnected
    assert tick(env)["state"] == "backup_failed"
    link.unlink()
    assert drive(env, "backup_verified")[-1] == "backup_verified"  # immediate retry works
    target = "application-" + containment.graph_identifier("a", "shop")
    with pytest.raises(ExecutorError) as error:
        for _ in range(server.CAPTURE_ATTEMPTS_PER_HOUR):
            env.ex.spend_budget(target, "application_group_capture_attempt", 6)
    assert error.value.error_class == "budget_exhausted"


def test_capture_failing_after_the_spend_refunds_the_success_budget(env, monkeypatch):
    from steward.core import filebackups
    from steward.core.backups import BackupError

    real = filebackups.capture_files
    monkeypatch.setattr(
        filebackups, "capture_files", lambda *a, **k: (_ for _ in ()).throw(BackupError("io"))
    )
    open_incident(env, EXPLOITED)
    tick(env)
    assert tick(env)["state"] == "backup_failed"
    target = "application-" + containment.graph_identifier("a", "shop")
    with env.ex._db() as db:
        rows = db.execute("SELECT action FROM mutations WHERE target=?", (target,)).fetchall()
    assert ("application_group_capture_incident",) not in rows  # refunded
    assert ("application_group_capture_attempt",) in rows  # attempts stay counted
    monkeypatch.setattr(filebackups, "capture_files", real)
    assert drive(env, "backup_verified")[-1] == "backup_verified"


def test_incident_backup_has_its_own_allowance_and_callers_cannot_select_it(env):
    target = "application-" + containment.graph_identifier("a", "shop")
    env.ex.spend_budget(target, "application_group_capture", 1)  # an ordinary capture this hour
    assert server.CAPTURE_ALLOWANCE.get() is None
    assert env.ex._capture_budget() == ("application_group_capture", 1)
    with server.capture_allowance("incident"):
        assert env.ex._capture_budget() == ("application_group_capture_incident", 3)
    assert server.CAPTURE_ALLOWANCE.get() is None
    open_incident(env, EXPLOITED)
    assert drive(env, "backup_verified")[-1] == "backup_verified"
    bad = {"application": "shop", "findings": [FINDING], "allowance": "incident"}
    assert call(env, "incident_open", bad)["error_class"] == "bad_request"


def test_unwritable_spool_is_reported_with_a_specific_cause(env, monkeypatch):
    import errno

    real = Path.mkdir

    def mkdir(self, *args, **kwargs):
        if self.parent.name == "group-captures" and self.name == "shop":
            raise PermissionError(errno.EPERM, "immutable")
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", mkdir)
    open_incident(env, EXPLOITED)
    seen = drive(env, "quarantined")
    assert seen[-1] == "backup_failed"
    assert stored(env).error_class == "spool_unwritable"
    assert audit(env, "escalated")[-1]["reason"] == "spool_unwritable"
    assert all(env.states.values()) and env.net.ports == {21003}
