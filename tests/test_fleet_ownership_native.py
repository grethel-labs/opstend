import json
import os
import sqlite3
from contextlib import closing, contextmanager
from datetime import timedelta
from uuid import uuid4

import pytest

from steward.core.fleet_adoption_models import pve_backup_job_ref
from steward.core.fleet_ownership import (
    LocalOwnershipRequest,
    OwnershipClaim,
    OwnershipPlan,
    OwnershipReply,
    OwnershipStatus,
)
from steward.core.pve_power import PowerJournalError
from steward.executor import fleet_ownership as ownership
from steward.executor import pve_schedule_ownership as native
from steward.executor.protocol import ExecutorError
from test_fleet_power_target import BINDING, CONFIG, claim, run
from test_fleet_power_target import target as fleet_target  # noqa: F401
from test_pve_power_executor import NODE, VMID

SCHEDULE = ownership._ScheduleConfig(native_job_id="backup-test", profile="lab-backup")
FINGERPRINT = "f" * 64


class Coordinator:
    def __init__(self, plan, now):
        self.plan = plan
        self.now = now
        self.state = "pausing"
        self.provide_claim = True
        self.online = True
        self.lose_receipt = None
        self.receipts = []

    def exchange(self, request):
        if not self.online:
            raise OSError("disconnected")
        assert (request.target, request.transition_id, request.digest) == (
            self.plan.target,
            self.plan.transition_id,
            self.plan.digest,
        )
        receipt = request.receipt
        if receipt is not None:
            self.receipts.append(receipt)
            self.state = receipt.state
            if receipt.state == self.lose_receipt:
                self.lose_receipt = None
                raise OSError("acknowledgement lost")
        return OwnershipReply(
            status=OwnershipStatus.from_plan(self.plan, self.state),
            plan=self.plan,
            claim=OwnershipClaim(claim_until=self.now() + timedelta(seconds=5), valid_for_ms=5000)
            if self.provide_claim and receipt is None and self.state == "pausing"
            else None,
        )


@pytest.fixture
def scope(fleet_target):  # noqa: F811 - pytest fixture imported above
    node, state, command = fleet_target
    node.executor.local_binding = lambda: (NODE, BINDING)
    profiles = {"backup_profile_refs": (SCHEDULE.profile,)}
    limits = state.local.limits.model_copy(update=profiles)
    values = state.effective.values.model_copy(update=profiles)
    state = state.model_copy(
        update={
            "local": state.local.model_copy(update={"limits": limits}),
            "effective": state.effective.model_copy(update={"values": values}),
        }
    )
    plan = OwnershipPlan(
        **command.model_dump(
            include={
                "target",
                "scope",
                "subject",
                "agent_id",
                "enrollment_generation",
                "policy_revision",
                "policy_approval",
                "local_revision",
            }
        ),
        transition_id=uuid4().hex,
        instance_id="5" * 32,
        schedule_ref=pve_backup_job_ref(BINDING, SCHEDULE.native_job_id),
        calendar="mon 03:17",
        profile=SCHEDULE.profile,
        previous_owner="standalone",
        next_owner="fleet",
        epoch=0,
    )
    coordinator = Coordinator(plan, lambda: node.now)
    return node, state, command, coordinator


def _request(plan, action):
    return LocalOwnershipRequest(
        action=action, transition_id=plan.transition_id, digest=plan.digest
    )


def test_round_trip_replays_lost_receipts_and_fences_both_writers(scope):
    node, state, command, coordinator = scope
    enabled = True
    fingerprint = FINGERPRINT

    def read(plan, job_id, *, enabled: bool):
        assert job_id == SCHEDULE.native_job_id and plan == coordinator.plan
        if enabled != is_enabled():
            raise ExecutorError("conflict", "schedule not in requested enabled state")
        return fingerprint

    def is_enabled():
        return enabled

    def local(action):
        return ownership._Handoff(
            node.executor,
            state,
            CONFIG,
            SCHEDULE,
            coordinator.exchange,
            clock=lambda: 0,
            local_binding=lambda: (NODE, BINDING),
            verify=read,
        ).run(_request(coordinator.plan, action))

    stale = node.result("plan", vmid=VMID, operation="start")["job_id"]
    db = node.directory / "power-jobs.sqlite3"
    with closing(sqlite3.connect(db)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (1,)
    paused = local("prepare")
    assert (paused.state, paused.owner, paused.epoch) == ("pausing", "standalone", 0)
    with closing(sqlite3.connect(db)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (2,)
    assert node.result("execute", job_id=stale)["error_code"] == "ownership_changed"
    assert node.call("plan", vmid=VMID, operation="start")["error_class"] == "policy_denied"
    assert run(node, state, claim(node, command)).reason == "policy_denied"
    with pytest.raises(ExecutorError, match="schedule not in requested enabled state"):
        local("confirm")
    enabled = False
    coordinator.provide_claim = False
    with pytest.raises(ExecutorError, match="live coordinator claim"):
        local("confirm")
    coordinator.provide_claim = True
    fingerprint = "d" * 64
    with pytest.raises(ExecutorError, match="differs from the staged"):
        local("confirm")
    fingerprint = FINGERPRINT
    coordinator.lose_receipt = "committed"
    with pytest.raises(OSError, match="acknowledgement lost"):
        local("confirm")
    coordinator.online = False
    node.executor = node.reopen()
    node.executor.local_binding = lambda: (NODE, BINDING)
    record = node.executor.journal.ownership()
    assert (record.state, record.owner, record.epoch) == ("committed", "fleet", 1)
    coordinator.state = "pausing"
    with pytest.raises(ExecutorError, match="already committed"):
        local("cancel")
    assert node.call("plan", vmid=VMID, operation="start")["error_class"] == "policy_denied"
    assert run(node, state, claim(node, command)).reason == "policy_denied"
    with pytest.raises(OSError, match="disconnected"):
        local("resume")
    coordinator.online = True
    assert local("confirm") == record
    assert coordinator.receipts[0] == coordinator.receipts[1]
    with pytest.raises(ExecutorError, match="schedule not in requested enabled state"):
        local("resume")

    enabled = True
    coordinator.lose_receipt = "active"
    with pytest.raises(OSError, match="acknowledgement lost"):
        local("resume")
    node.executor = node.reopen()
    node.executor.local_binding = lambda: (NODE, BINDING)
    assert local("resume").state == "active"
    assert coordinator.receipts[-1] == coordinator.receipts[-2]
    assert node.call("plan", vmid=VMID, operation="start")["error_class"] == "policy_denied"
    node.executor.local_binding = lambda: (NODE, "c" * 64)
    assert run(node, state, claim(node, command)).reason == "policy_denied"
    node.executor.local_binding = lambda: (NODE, BINDING)
    fleet_prepared = run(node, state, claim(node, command))
    assert fleet_prepared.state == "prepared"

    coordinator.plan = coordinator.plan.model_copy(
        update={
            "transition_id": uuid4().hex,
            "previous_owner": "fleet",
            "next_owner": "standalone",
            "epoch": 1,
        }
    )
    coordinator.state = "pausing"
    assert local("prepare").owner == "fleet"
    enabled = False
    assert local("confirm").owner == "standalone"
    enabled = True
    assert local("resume").epoch == 2
    assert run(
        node, state, claim(node, command, "execute", fleet_prepared.native_digest)
    ).reason == ("ownership_changed")
    assert node.result("plan", vmid=VMID, operation="start")["state"] == "prepared"
    assert node.posts == []


@pytest.mark.parametrize("staged", [False, True])
def test_cancel_allows_recovery_from_policy_drift_and_replays_receipt(scope, staged):
    node, state, command, coordinator = scope
    enabled = True
    fingerprint = FINGERPRINT
    config = CONFIG
    plan = coordinator.plan

    def verify(plan, job_id, *, enabled: bool):
        if enabled != is_enabled():
            raise ExecutorError("conflict", "schedule not in requested enabled state")
        return fingerprint

    def is_enabled():
        return enabled

    def local(action):
        return ownership._Handoff(
            node.executor,
            state,
            config,
            SCHEDULE,
            coordinator.exchange,
            local_binding=lambda: (NODE, BINDING),
            verify=verify,
        ).run(_request(plan, action))

    if staged:
        local("prepare")
    state = state.model_copy(
        update={"applied_revision": None, "approval_id": None, "effective": None}
    )
    config = CONFIG.model_copy(update={"enrollment_generation": 4})
    coordinator.provide_claim = False
    enabled = False
    with pytest.raises(ExecutorError, match="schedule not in requested enabled state"):
        local("cancel")
    enabled = True
    if staged:
        fingerprint = "d" * 64
        with pytest.raises(ExecutorError, match="differs from the recorded"):
            local("cancel")
        fingerprint = FINGERPRINT
    coordinator.lose_receipt = "canceled"
    with pytest.raises(OSError, match="acknowledgement lost"):
        local("cancel")
    record = node.executor.journal.ownership()
    assert (record.state, record.owner, record.epoch) == ("canceled", "standalone", 0)
    assert local("cancel") == record
    assert coordinator.receipts[-1] == coordinator.receipts[-2]
    with pytest.raises(ExecutorError, match="was canceled"):
        local("confirm")
    assert node.result("plan", vmid=VMID, operation="start")["state"] == "prepared"
    assert run(node, state, claim(node, command)).reason == "local_policy_changed"


def test_runtime_reloads_locked_policy_and_releases_both_locks_before_exchange(
    scope,
    monkeypatch,
):
    node, state, _, coordinator = scope
    locked = False
    admitted = False
    config = CONFIG
    fresh_state = state
    enabled = True

    @contextmanager
    def install_lock():
        nonlocal locked
        assert not locked
        locked = True
        try:
            yield
        finally:
            locked = False

    class Store:
        def state(self):
            assert locked and not admitted
            return state

        @contextmanager
        def admission(self):
            nonlocal admitted
            assert locked and not admitted
            admitted = True
            try:
                yield fresh_state
            finally:
                admitted = False

    def load():
        assert locked
        return node.executor, config, SCHEDULE, Store()

    def exchange(request):
        assert not locked and not admitted
        return coordinator.exchange(request)

    def verify(self, local, plan, *, enabled: bool, recovery: bool):
        assert locked and admitted and enabled == is_enabled()
        ownership._verify_current(
            local.executor,
            local.state,
            local.config,
            local.schedule,
            plan,
            lambda: (NODE, BINDING),
            recovery=recovery,
        )
        return FINGERPRINT

    def is_enabled():
        return enabled

    class Client:
        def __init__(self, **kwargs):
            assert locked

        exchange_ownership = staticmethod(exchange)

    monkeypatch.setattr(ownership.install, "_locked", install_lock)
    monkeypatch.setattr(ownership, "_read_local_inputs", load)
    monkeypatch.setattr(ownership, "_private_file", lambda directory, name: directory / name)
    monkeypatch.setattr(ownership, "FleetClient", Client)
    monkeypatch.setattr(ownership._Handoff, "_verify", verify)

    def local(action):
        return ownership._execute(_request(coordinator.plan, action))

    assert local("prepare")["state"] == "pausing"
    enabled = False
    fresh_state = state.model_copy(update={"applied_revision": "7" * 64})
    with pytest.raises(ExecutorError, match="policy, scope, or enrollment changed"):
        local("confirm")
    fresh_state = state
    assert local("confirm")["state"] == "committed"
    fresh_state = state.model_copy(
        update={"applied_revision": None, "approval_id": None, "effective": None}
    )
    config = CONFIG.model_copy(update={"enrollment_generation": 4})
    enabled = True
    assert local("resume")["state"] == "active"


def test_in_flight_native_job_drains_and_claim_is_rechecked_before_commit(scope):
    node, state, _, coordinator = scope
    job_id = node.result("plan", vmid=VMID, operation="start")["job_id"]
    node.result("execute", job_id=job_id)
    clock = 0
    expire_during_proof = False

    def verify(*args, **kwargs):
        nonlocal clock
        if expire_during_proof:
            clock += 5
        return FINGERPRINT

    handoff = ownership._Handoff(
        node.executor,
        state,
        CONFIG,
        SCHEDULE,
        coordinator.exchange,
        clock=lambda: clock,
        local_binding=lambda: (NODE, BINDING),
        verify=verify,
    )
    handoff.run(_request(coordinator.plan, "prepare"))
    with pytest.raises(PowerJournalError, match="target_busy"):
        handoff.run(_request(coordinator.plan, "confirm"))
    assert node.executor.journal.ownership().state == "pausing"
    node.finish_task()
    node.set_state("running")
    assert node.result("reconcile", job_id=job_id)["state"] == "succeeded"
    expire_during_proof = True
    with pytest.raises(ExecutorError, match="live coordinator claim"):
        handoff.run(_request(coordinator.plan, "confirm"))
    assert node.executor.journal.ownership().state == "pausing"
    expire_during_proof = False
    assert handoff.run(_request(coordinator.plan, "confirm")).state == "committed"


@pytest.fixture
def native_readback(tmp_path, monkeypatch, scope):
    plan = scope[-1].plan
    state_dir = tmp_path / "job-state"
    state_dir.mkdir()
    job_state = state_dir / f"vzdump-{SCHEDULE.native_job_id}.json"
    job_state.write_text('{"state":"created","time":1}')
    job_state.chmod(0o644)
    monkeypatch.setattr(native, "_JOB_STATES", state_dir)
    if os.geteuid() != 0:
        # The tests construct native file contents and model only the ownership metadata.
        original_lstat = type(job_state).lstat

        def root_owned(path):
            info = original_lstat(path)
            if path != job_state:
                return info
            fields = list(info)
            fields[4] = 0
            return os.stat_result(fields)

        monkeypatch.setattr(type(job_state), "lstat", root_owned)
    group = tmp_path / native._SCHEDULER_GROUP.lstrip("/")
    group.mkdir(parents=True)
    (group / "cgroup.procs").write_text("23\n")
    (group / "cgroup.stat").write_text("nr_descendants 0\nnr_dying_descendants 0\n")
    monkeypatch.setattr(native, "_CGROUP_ROOT", tmp_path)
    definition = {
        "id": SCHEDULE.native_job_id,
        "type": "vzdump",
        "node": NODE,
        "vmid": str(VMID),
        "schedule": plan.calendar,
        "enabled": 0,
        "storage": "local",
    }
    fixture = {
        "first": definition,
        "second": definition,
        "tasks": [],
        "index": [definition],
        "unit": f"LoadState=loaded\nActiveState=active\nMainPID=23\nControlGroup={native._SCHEDULER_GROUP}\n",
    }
    calls = []

    def read(target, argv, limit):
        assert target == plan.scope and limit > 0
        if argv[0] == "/usr/bin/systemctl":
            assert argv[4] == "pvescheduler.service"
            calls.append("unit")
            return fixture["unit"].encode("ascii")
        assert argv[:3] == ["/usr/bin/pvesh", "--noproxy", "get"]
        path = argv[3]
        if path == f"/cluster/backup/{SCHEDULE.native_job_id}":
            key = "first" if not calls else "second"
        elif path == "/cluster/backup":
            key = "index"
        else:
            assert path == f"/nodes/{NODE}/tasks"
            assert argv[6:10] == ["--source", "active", "--limit", "250"]
            key = "tasks"
        calls.append(key)
        return json.dumps(fixture[key]).encode("ascii")

    monkeypatch.setattr(native, "_read_local", read)
    return plan, fixture, group, job_state, calls


def test_native_proof_brackets_drain_between_disabled_reads(native_readback):
    plan, fixture, _, _, calls = native_readback
    disabled = native.verify_schedule(plan, SCHEDULE.native_job_id, enabled=False)
    assert calls == ["first", "index", "unit", "unit", "tasks", "second"]
    calls.clear()
    fixture["first"]["enabled"] = 1
    assert native.verify_schedule(plan, SCHEDULE.native_job_id, enabled=True) == disabled
    assert calls == ["first", "index", "second"]


@pytest.mark.parametrize(
    "case",
    [
        "scheduler_worker",
        "scheduler_subgroup",
        "starting",
        "active_backup",
        "active_guest_task",
        "ambiguous_backup",
        "changed_job",
        "other_enabled_job",
        "wrong_node",
        "all_guests",
        "legacy_definition",
    ],
)
def test_incomplete_native_proof_refuses_handoff(native_readback, case):
    plan, fixture, group, job_state, _ = native_readback
    if case == "scheduler_worker":
        (group / "cgroup.procs").write_text("23\n24\n")
    elif case == "scheduler_subgroup":
        (group / "cgroup.stat").write_text("nr_descendants 1\nnr_dying_descendants 0\n")
    elif case == "starting":
        job_state.write_text('{"state":"starting","time":42}')
    elif case in {"active_backup", "active_guest_task", "ambiguous_backup"}:
        worker, identifier = (
            ("qmstop", str(VMID)) if case == "active_guest_task" else ("vzdump", "")
        )
        fixture["tasks"] = [
            {
                "node": NODE,
                "type": worker,
                "starttime": 1,
                "status": "RUNNING",
                "upid": f"UPID:{NODE}:00000001:00000002:00000003:{worker}:{identifier}:root@pam:",
            }
        ]
        if case == "ambiguous_backup":
            fixture["tasks"][0]["status"] = "OK"
    elif case == "changed_job":
        fixture["second"] = {**fixture["first"], "storage": "other"}
    elif case == "other_enabled_job":
        fixture["index"].append({**fixture["first"], "id": "other", "enabled": 1})
    elif case == "wrong_node":
        fixture["first"]["node"] = "another"
    elif case == "all_guests":
        fixture["first"]["all"] = 1
    elif case == "legacy_definition":
        fixture["first"].pop("type")
    with pytest.raises(ExecutorError):
        native.verify_schedule(plan, SCHEDULE.native_job_id, enabled=False)
