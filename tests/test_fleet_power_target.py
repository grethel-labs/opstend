import json
import sqlite3
from contextlib import closing
from datetime import timedelta
from uuid import uuid4

import pytest

from steward.core.fleet_policy import (
    EffectiveFleetPolicy,
    FleetLocalPolicy,
    FleetPolicyValues,
    FleetTarget,
    RoleAssignment,
)
from steward.core.fleet_policy_target import (
    FleetPolicyTargetConfig,
    FleetPolicyTargetState,
    FleetPolicyTargetStore,
)
from steward.core.fleet_power import CommandSpec, CommandWork, PowerScope
from steward.core.pve_power import PowerJournalError
from steward.executor import fleet_power
from steward.executor.protocol import ExecutorError
from steward.executor.pve_power_api import DISPATCH_TASK_WINDOW_S
from test_pve_power_executor import NODE, UID, VMID, FakeNode

BINDING = "b" * 64
CONFIG = fleet_power._Config(
    controller_url="https://coordinator.example", agent_id="a" * 32, enrollment_generation=3
)


@pytest.fixture
def target(tmp_path):
    host = FakeNode(tmp_path)
    identity = FleetTarget(kind="pve_guest", id="1" * 32, generation=2)
    values = FleetPolicyValues(role_assignments=(RoleAssignment(subject="alice", role="operator"),))
    local = FleetLocalPolicy(
        target=identity, revision="2" * 64, limits=values, observed_at=host.now
    )
    effective = EffectiveFleetPolicy(
        revision="3" * 64, target=identity, values=values, provenance={}, status="ready", issues=()
    )
    state = FleetPolicyTargetState(
        local=local, applied_revision=effective.revision, approval_id="4" * 32, effective=effective
    )
    spec = CommandSpec(
        command_id=uuid4().hex,
        target=identity,
        scope=PowerScope(
            node=NODE,
            kind="qemu",
            vmid=VMID,
            pve_uid=UID,
            registered_at_ms=1,
            instance_binding=BINDING,
        ),
        subject="alice",
        agent_id=CONFIG.agent_id,
        enrollment_generation=CONFIG.enrollment_generation,
        policy_revision=effective.revision,
        policy_approval=state.approval_id,
        local_revision=local.revision,
        expires_at=host.now + timedelta(seconds=30),
    )
    return host, state, spec


def claim(host, spec, phase="prepare", digest=None):
    return CommandWork(
        phase=phase,
        spec=spec,
        claim_id=uuid4().hex,
        native_digest=digest,
        claim_until=host.now + timedelta(seconds=5),
        valid_for_ms=5000,
        recipient_generation=CONFIG.enrollment_generation,
    )


def run(host, state, work, *, config=CONFIG, **options):
    clocks = {"clock": lambda: 0, "local_binding": lambda: (NODE, BINDING), **options}
    return fleet_power._run_work(host.executor, state, config, work, 0, **clocks)


@pytest.mark.parametrize("kind", ["qemu", "lxc"])
def test_prepares_executes_once_and_reports_verified_readback(target, kind):
    host, state, spec = target
    host.set_guest(kind=kind)
    spec = spec.model_copy(update={"scope": spec.scope.model_copy(update={"kind": kind})})
    prepared = run(host, state, claim(host, spec))
    assert prepared.state == "prepared"
    assert host.posts == []
    assert run(host, state, claim(host, spec)).native_digest == prepared.native_digest

    assert host.call("execute", job_id=spec.command_id)["error_class"] == "policy_denied"
    work = claim(host, spec, "execute", prepared.native_digest)
    first = run(host, state, work)
    host.executor = host.reopen()
    assert run(host, state, work) == first
    assert first.state == "accepted"
    assert host.posts == [(NODE, kind, VMID, "start")]
    assert host.call("reconcile", job_id=spec.command_id)["error_class"] == "policy_denied"

    host.finish_task()
    reconcile = claim(host, spec, "reconcile", prepared.native_digest)
    assert run(host, state, reconcile).state == "accepted"
    host.set_state("running")
    verified = run(host, state, reconcile)
    assert (verified.state, verified.observed_state, verified.task_ref) == (
        "succeeded",
        "running",
        first.task_ref,
    )
    assert "UPID" not in verified.model_dump_json()


@pytest.mark.parametrize("absolute", [False, True])
def test_expiry_rechecked_after_durable_dispatch_intent(target, monkeypatch, absolute):
    host, state, spec = target
    prepared = run(host, state, claim(host, spec))
    clock = [0]
    save = host.executor._save

    def save_then_expire(job, **changes):
        saved = save(job, **changes)
        if saved.state == "dispatching":
            if absolute:
                host.now += timedelta(seconds=5)
            else:
                clock[0] = 5
        return saved

    monkeypatch.setattr(host.executor, "_save", save_then_expire)
    execute = claim(host, spec, "execute", prepared.native_digest)
    result = run(host, state, execute, clock=lambda: clock[0])
    assert result.reason == "fleet_admission_changed"
    assert host.posts == []
    assert run(host, state, execute).state == "failed"


def test_expired_prepared_reconcile_records_no_dispatch(target):
    host, state, spec = target
    prepared = run(host, state, claim(host, spec))
    host.now += timedelta(seconds=31)
    reconcile = claim(host, spec, "reconcile", prepared.native_digest)
    assert run(host, state, reconcile).reason == "no_dispatch"
    host.executor = host.reopen()
    assert run(host, state, reconcile).state == "refused"
    assert host.executor.journal.get(spec.command_id).legs == ()
    assert host.posts == []


def test_origin_conflict_and_plan_digest_are_fenced(target):
    host, state, spec = target
    native_id = host.plan()
    local_collision = spec.model_copy(update={"command_id": native_id})
    assert run(host, state, claim(host, local_collision)).reason == "native_origin_conflict"
    work = claim(host, local_collision, "execute", "9" * 64)
    with pytest.raises(ValueError, match="native job origin"):
        run(host, state, work)
    assert host.executor.journal.get(native_id).fleet_origin is None
    database = host.directory / "power-jobs.sqlite3"
    with closing(sqlite3.connect(database)) as connection:
        local_record = connection.execute(
            "SELECT record FROM jobs WHERE job_id = ?", (native_id,)
        ).fetchone()[0]
    assert "fleet_origin" not in json.loads(local_record)

    run(host, state, claim(host, spec))
    original = host.executor.journal.get(spec.command_id)
    with pytest.raises(PowerJournalError, match="journal_conflict"):
        host.executor.journal.write(
            original.model_copy(update={"fleet_origin": None}), previous=original
        )
    with pytest.raises(ValueError, match="native plan digest"):
        run(host, state, claim(host, spec, "execute", "9" * 64))
    assert host.posts == []


@pytest.mark.parametrize(
    "failure", ["subject", "limits", "pointer", "instance", "identity", "pending"]
)
def test_target_rechecks_local_authority(target, failure):
    host, state, spec = target
    prepared = run(host, state, claim(host, spec))

    def local_binding():
        return NODE, "c" * 64 if failure == "instance" else BINDING

    if failure == "subject":
        effective = state.effective.model_copy(update={"values": FleetPolicyValues()})
        state = state.model_copy(update={"effective": effective})
    elif failure == "limits":
        state = state.model_copy(
            update={"local": state.local.model_copy(update={"revision": "8" * 64})}
        )
    elif failure == "pointer":
        state = state.model_copy(update={"approval_id": "5" * 32})
    elif failure == "identity":
        host.set_state("stopped", registration=2)
    elif failure == "pending":
        host.pending = True
    result = run(
        host,
        state,
        claim(host, spec, "execute", prepared.native_digest),
        local_binding=local_binding,
    )
    assert result.state in {"refused", "failed"}
    assert host.posts == []


def test_lost_native_response_reconciles_from_old_dispatch_window(target):
    host, state, spec = target
    prepared = run(host, state, claim(host, spec))
    host.failure = ExecutorError("unavailable", "lost native response", outcome_unknown=True)
    result = run(host, state, claim(host, spec, "execute", prepared.native_digest))
    assert result.state == "uncertain"
    assert result.task_ref is None
    host.executor = host.reopen()
    host.finish_task()
    host.set_state("running")
    host.now += timedelta(seconds=DISPATCH_TASK_WINDOW_S + 1)
    result = run(host, state, claim(host, spec, "reconcile", prepared.native_digest))
    assert result.state == "succeeded"
    assert len(host.posts) == 1


def test_maintenance_window_is_required_to_prepare_and_execute(target):
    host, state, spec = target
    # Start two seconds before a configured one-hour weekly window ends.
    host.now = host.now.replace(hour=0, minute=59, second=58)
    window = host.now.strftime("%a") + " 00:00 UTC"
    values = state.effective.values.model_copy(update={"maintenance_windows": (window,)})
    state = state.model_copy(
        update={
            "local": state.local.model_copy(update={"limits": values}),
            "effective": state.effective.model_copy(update={"values": values}),
        }
    )
    prepared = run(host, state, claim(host, spec))
    assert prepared.state == "prepared"
    host.now += timedelta(seconds=2)
    assert run(host, state, claim(host, spec)).reason == "outside_maintenance_window"
    work = claim(host, spec, "execute", prepared.native_digest)
    assert run(host, state, work).reason == "outside_maintenance_window"
    assert host.posts == []


def test_rotated_enrollment_only_reconciles_existing_native_intent(target):
    host, state, spec = target
    prepared = run(host, state, claim(host, spec))
    work = claim(host, spec, "execute", prepared.native_digest)
    newer = CONFIG.model_copy(update={"enrollment_generation": CONFIG.enrollment_generation + 1})
    forged_execute = work.model_copy(update={"recipient_generation": newer.enrollment_generation})
    with pytest.raises(ValueError, match="enrollment"):
        run(host, state, forged_execute, config=newer)
    assert host.posts == []
    assert run(host, state, work).state == "accepted"

    host.finish_task()
    host.set_state("running")
    reconcile = claim(host, spec, "reconcile", prepared.native_digest)
    reconcile = reconcile.model_copy(update={"recipient_generation": newer.enrollment_generation})
    with pytest.raises(ValueError, match="enrollment"):
        run(host, state, reconcile)
    assert run(host, state, reconcile, config=newer).state == "succeeded"
    assert len(host.posts) == 1


def test_applied_policy_cannot_change_during_target_admission(tmp_path, target):
    _, state, _ = target
    directory = tmp_path / "policy"
    directory.mkdir(mode=0o700)
    database = directory / "target.sqlite3"
    store = FleetPolicyTargetStore.configure(
        database, FleetPolicyTargetConfig(target=state.local.target, limits=state.local.limits)
    )
    with closing(sqlite3.connect(database, timeout=0)) as other:
        with store.admission() as admitted:
            assert admitted.local.limits == state.local.limits
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                other.execute("BEGIN IMMEDIATE")
        other.execute("BEGIN IMMEDIATE")
