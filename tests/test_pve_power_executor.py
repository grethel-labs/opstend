import json
import subprocess
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace

import pytest

from steward import __version__
from steward.cli import main as cli
from steward.core import pve_power as power_model
from steward.core.audit import AuditLog
from steward.core.pve_power import (
    GuestObservation,
    PowerJournal,
    PowerJournalError,
    PowerPolicy,
    RegisteredGuest,
)
from steward.executor import pve_power
from steward.executor.protocol import PROTOCOL_VERSION, ExecutorError

VMID = 190
NODE = "px03"
UID = "abcdefghijklmnopqrst"
ACTOR = "power@pve!token"
NOW = datetime.fromtimestamp(1_800_000_000, UTC)


def frame(action, **params):
    return json.dumps(
        {"v": PROTOCOL_VERSION, "action": f"pve_power_{action}", "params": params}
    ).encode()


class FakeNode:
    actor = ACTOR

    def __init__(self, directory):
        self.directory = directory
        self.now = NOW
        self.killed = False
        self.pending = False
        self.local_state = None
        self.permitted = True
        self.policy = PowerPolicy(
            node=NODE,
            write_token_file="/unused/token",
            guests=(
                RegisteredGuest(
                    kind="qemu",
                    vmid=VMID,
                    pve_uid=UID,
                    registered_at_ms=1,
                    operations=("start", "shutdown", "reboot"),
                ),
            ),
        )
        self.set_state("stopped")
        self.posts = []
        self.tasks = {}
        self.failure = None
        self.before_post = lambda: None
        self.executor = self.reopen()

    def reopen(self):
        return pve_power.PowerExecutor(
            PowerJournal(self.directory),
            AuditLog(self.directory / "audit.jsonl"),
            lambda: pve_power._Authority(self.policy, "a" * 64, self),
            lambda: self.policy,
            lambda: self.killed,
            self.check_pending,
            self.check_state,
            lambda: self.now,
        )

    def set_guest(self, **changes):
        guest = self.policy.guests[0].model_copy(update=changes)
        self.policy = self.policy.model_copy(update={"guests": (guest,)})

    def set_state(self, state, uid=UID, registration=1):
        self.observation = GuestObservation(
            pve_uid=uid,
            registered_at_ms=registration,
            state=state,
            pid=123 if state == "running" else None,
        )

    def check_pending(self, target):
        if self.pending:
            raise ExecutorError("policy_denied", "Pending local config.")

    def check_state(self, target, state):
        if self.local_state is not None and self.local_state != state:
            raise ExecutorError("conflict", "Observed and local state disagree.")

    def validate_permissions(self, policy):
        if not self.permitted:
            raise ExecutorError("policy_denied", "Native scope denied.")

    def observe(self, target):
        return self.observation

    def dispatch(self, target, operation, *, dispatched_at):
        self.before_post()
        self.posts.append((target.node, target.kind, target.vmid, operation))
        upid = self.add_task(operation, started=int(dispatched_at))
        if self.failure is not None:
            raise self.failure
        return upid

    def add_task(self, operation, *, started=None):
        kind = self.policy.guests[0].kind
        worker = ("qm" if kind == "qemu" else "vz") + operation
        started = int(self.now.timestamp()) if started is None else started
        upid = (
            f"UPID:{NODE}:{len(self.tasks) + 1:08X}:00000001:{started:08X}:"
            f"{worker}:{VMID}:{self.actor}:"
        )
        self.tasks[upid] = "running"
        return upid

    def recent_tasks(self, target, operation, *, since, until=None):
        worker = ("qm" if target.kind == "qemu" else "vz") + operation
        matches = []
        for upid in self.tasks:
            _, node, _, _, timestamp, kind, vmid, actor, _ = upid.split(":")
            started = int(timestamp, 16)
            if (
                (node, kind, vmid, actor) == (target.node, worker, str(target.vmid), self.actor)
                and started >= since
                and (until is None or started <= until)
            ):
                matches.append(upid)
        return tuple(matches)

    def task(self, target, operation, upid, *, dispatched_at):
        if upid not in self.tasks:
            raise ExecutorError("policy_denied", "No exact matching task.")
        return self.tasks[upid]

    def finish_task(self):
        upid = next(reversed(self.tasks))
        self.tasks[upid] = "succeeded"
        return upid

    def call(self, action, **params):
        return self.executor.handle(frame(action, **params))

    def result(self, action, **params):
        response = self.call(action, **params)
        assert response["ok"], response
        return response["result"]

    def plan(self, operation="start"):
        return self.result("plan", vmid=VMID, operation=operation)["job_id"]


@pytest.fixture
def host(tmp_path):
    return FakeNode(tmp_path)


@pytest.mark.parametrize("kind", ["qemu", "lxc"])
@pytest.mark.parametrize(
    ("operation", "initial", "first_leg", "after_first"),
    [
        ("start", "stopped", "start", "running"),
        ("shutdown", "running", "shutdown", "stopped"),
        ("reboot", "running", "shutdown", "stopped"),
    ],
)
def test_power_requires_task_and_state_readback(
    host, kind, operation, initial, first_leg, after_first
):
    host.set_guest(kind=kind)
    host.set_state(initial)
    job = host.plan(operation)

    def assert_dispatch_is_durable():
        record = host.reopen().journal.get(job)
        assert record.state == "dispatching"
        assert record.legs[-1].state == "dispatching"
        assert record.legs[-1].upid is None

    host.before_post = assert_dispatch_is_durable
    if operation == "reboot":
        assert host.call("execute", job_id=job, continue_reboot=True)["error_class"] == "conflict"
    assert host.result("execute", job_id=job)["state"] == "accepted"
    assert host.result("execute", job_id=job)["state"] == "accepted"
    assert host.result("reconcile", job_id=job)["tasks"][0]["state"] == "running"
    upid = host.finish_task()
    mismatch = host.result("reconcile", job_id=job)
    assert (mismatch["state"], mismatch["error_code"]) == ("verifying", "state_mismatch")
    assert upid not in json.dumps(mismatch)
    host.set_state(after_first)
    result = host.result("reconcile", job_id=job)
    expected = [(NODE, kind, VMID, first_leg)]

    if operation == "reboot":
        assert (result["state"], result["next_action"]) == ("verifying", "execute")
        assert host.result("execute", job_id=job) == result
        assert host.result("reconcile", job_id=job) == result
        assert host.posts == expected
        assert host.result("execute", job_id=job, continue_reboot=True)["state"] == "accepted"
        assert host.result("execute", job_id=job, continue_reboot=True)["state"] == "accepted"
        host.finish_task()
        host.set_state("running")
        result = host.result("reconcile", job_id=job)
        expected.append((NODE, kind, VMID, "start"))
        assert host.result("execute", job_id=job, continue_reboot=True) == result

    assert result["state"] == "succeeded"
    assert result["current_state"] == result["desired_state"]
    assert host.result("execute", job_id=job) == result
    assert host.result("status", job_id=job) == result
    assert host.posts == expected


def test_same_vmid_concurrent_plans_admit_one_dispatch(host, monkeypatch):
    jobs = [host.plan(), host.plan()]
    write = host.executor.journal.write
    barrier = Barrier(2, timeout=5)

    def synchronized_write(record, *, previous):
        if record.state == "dispatching":
            barrier.wait()
        return write(record, previous=previous)

    monkeypatch.setattr(host.executor.journal, "write", synchronized_write)
    with ThreadPoolExecutor(max_workers=2) as pool:
        replies = list(pool.map(lambda job: host.call("execute", job_id=job), jobs))
    assert sorted(
        reply["result"]["state"] if reply["ok"] else reply["error_class"] for reply in replies
    ) == ["accepted", "target_busy"]
    assert len(host.posts) == 1
    assert any(entry.get("outcome") == "target_busy" for entry in host.executor.audit.read())


def test_execute_rechecks_expiry(host):
    job = host.plan()
    host.now += timedelta(minutes=5)
    assert host.result("execute", job_id=job)["error_code"] == "confirmation_expired"
    assert host.posts == []


@pytest.mark.parametrize("change", ["pending", "uid", "registration", "state", "local_state"])
def test_execute_rechecks_guest(host, change):
    job = host.plan()
    if change == "pending":
        host.pending = True
    elif change == "uid":
        host.set_state("stopped", uid="bcdefghijklmnopqrstu")
    elif change == "registration":
        host.set_state("stopped", registration=2)
    elif change == "local_state":
        host.local_state = "running"
    else:
        host.set_state("running")
    result = host.result("execute", job_id=job)
    assert result["state"] == "failed"
    assert result["error_code"] == ("state_changed" if change == "state" else "guest_changed")
    assert host.posts == []


def test_execute_rechecks_policy_and_kill_switch(host):
    job = host.plan()
    host.killed = True
    assert host.call("execute", job_id=job)["error_class"] == "kill_switch"
    assert host.result("status", job_id=job)["state"] == "prepared"
    host.killed = False
    host.policy = host.policy.model_copy(update={"write_token_file": "/unused/replaced"})
    assert host.result("execute", job_id=job)["error_code"] == "policy_changed"
    assert host.posts == []


def test_request_rejects_unregistered_scope_and_unsafe_parameters(host, monkeypatch):
    monkeypatch.setattr(pve_power, "_runtime", lambda: host.executor)
    monkeypatch.setattr(pve_power.install, "_locked", nullcontext)
    request = frame("plan", vmid=VMID, operation="start")
    assert pve_power.execute_local(request, uid=1000)["error_class"] == "unauthorized_peer"
    for params in (
        {"vmid": VMID, "operation": "stop"},
        {"vmid": VMID, "operation": "start", "path": "/other"},
        {"vmid": VMID, "operation": "shutdown", "forceStop": True},
        {"vmid": str(VMID), "operation": "start"},
    ):
        assert (
            pve_power.execute_local(frame("plan", **params), uid=0)["error_class"] == "bad_request"
        )
    assert host.call("plan", vmid=VMID + 1, operation="start")["error_class"] == "policy_denied"
    job = host.plan()
    host.permitted = False
    assert host.call("execute", job_id=job)["error_class"] == "policy_denied"
    assert host.posts == []


class SimulatedCrash(BaseException):
    pass


@pytest.mark.parametrize("crashes", [False, True], ids=["lost-reply", "crash-after-post"])
def test_unknown_post_requires_exact_explicit_upid_after_reopen(host, crashes):
    job = host.plan()
    other = host.plan()
    if crashes:
        host.failure = SimulatedCrash()
        with pytest.raises(SimulatedCrash):
            host.call("execute", job_id=job)
    else:
        host.failure = ExecutorError("unavailable", "Reply lost.", outcome_unknown=True)
        assert host.result("execute", job_id=job)["state"] == "uncertain"

    upid = host.finish_task()
    host.executor = host.reopen()
    assert host.result("status", job_id=job)["state"] == ("dispatching" if crashes else "uncertain")
    assert host.result("reconcile", job_id=job)["state"] == "uncertain"
    assert host.result("execute", job_id=job)["state"] == "uncertain"
    assert host.call("execute", job_id=other)["error_class"] == "target_busy"
    host.set_state("running")
    wrong_guest = upid.replace(f":{VMID}:", f":{VMID + 1}:")
    assert not host.call("reconcile", job_id=job, upid=wrong_guest)["ok"]
    assert host.result("status", job_id=job)["tasks"] == []
    assert host.result("reconcile", job_id=job, upid=upid)["state"] == "succeeded"
    assert host.result("execute", job_id=job)["state"] == "succeeded"
    assert len(host.posts) == 1


@pytest.mark.parametrize("extra_candidate", [False, True], ids=["unique-new", "ambiguous"])
def test_unknown_reply_uses_durable_same_second_baseline(host, extra_candidate):
    job = host.plan()
    other = host.plan()
    historical = host.add_task("start")
    host.tasks[historical] = "succeeded"
    host.failure = ExecutorError("unavailable", "Reply lost.", outcome_unknown=True)
    assert host.result("execute", job_id=job)["state"] == "uncertain"
    dispatched = host.finish_task()
    if extra_candidate:
        host.add_task("start")
        host.finish_task()

    host.executor = host.reopen()
    assert host.executor.journal.get(job).legs[-1].prior_upids == (historical,)
    host.set_state("running")
    assert not host.call("reconcile", job_id=job, upid=historical)["ok"]
    if extra_candidate:
        assert not host.call("reconcile", job_id=job, upid=dispatched)["ok"]
        result = host.result("status", job_id=job)
        assert (result["state"], result["tasks"]) == ("uncertain", [])
        host.set_state("stopped")
        assert host.call("execute", job_id=other)["error_class"] == "target_busy"
    else:
        assert host.result("reconcile", job_id=job, upid=dispatched)["state"] == "succeeded"
    assert len(host.posts) == 1


def test_reconcile_refuses_reenrolled_guest_at_desired_state(host):
    job = host.plan()
    assert host.result("execute", job_id=job)["state"] == "accepted"
    host.finish_task()
    host.set_guest(registered_at_ms=2)
    host.set_state("running", registration=2)
    reply = host.call("reconcile", job_id=job)
    assert not reply["ok"]
    assert host.result("status", job_id=job)["state"] == "verifying"
    assert len(host.posts) == 1


def test_dispatch_journal_failure_prevents_post(host, monkeypatch):
    job = host.plan()

    def journal_unavailable(record, *, previous):
        assert record.state == "dispatching"
        raise PowerJournalError("journal_unavailable")

    monkeypatch.setattr(host.executor.journal, "write", journal_unavailable)
    assert host.call("execute", job_id=job)["error_class"] == "unavailable"
    assert host.reopen().journal.get(job).state == "prepared"
    assert host.posts == []


def test_cli_status_reads_job_through_fixed_isolated_executor(host, monkeypatch, capsys):
    job = host.plan()
    install = Path("/opt/opstend-pve")
    python = install / "releases" / __version__ / "venv/bin/python"
    monkeypatch.setattr(
        power_model,
        "_installed_power_runtime",
        lambda: ({"install": install}, {}, python),
    )
    monkeypatch.setattr(pve_power, "_runtime", host.reopen)
    monkeypatch.setattr(pve_power.install, "_locked", nullcontext)
    calls = []

    def run(argv, **options):
        calls.append((argv, options))
        reply = pve_power.execute_local(options["input"], uid=0)
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(reply).encode())

    monkeypatch.setattr(cli.subprocess, "run", run)
    args = cli.build_parser().parse_args(["pve-native", "power", "status", "--job-id", job])
    monkeypatch.setattr(cli, "os", SimpleNamespace(geteuid=lambda: 0))
    assert args.func(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert (result["job_id"], result["state"]) == (job, "prepared")
    assert calls == [
        (
            [
                str(python),
                "-I",
                "-B",
                "-m",
                "steward.executor.pve_power",
            ],
            {
                "input": frame("status", job_id=job),
                "stdout": subprocess.PIPE,
                "stderr": subprocess.DEVNULL,
                "cwd": "/",
                "env": {"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                "timeout": 60,
                "check": False,
            },
        )
    ]
    assert host.posts == []


def test_known_reply_reconciles_bound_upid_without_task_listing(host, monkeypatch):
    job = host.plan()
    assert host.result("execute", job_id=job)["state"] == "accepted"
    host.finish_task()
    host.set_state("running")

    def listing_unavailable(*args, **kwargs):
        pytest.fail("Known reply already proves the task UPID.")

    monkeypatch.setattr(host, "recent_tasks", listing_unavailable)
    assert host.result("reconcile", job_id=job)["state"] == "succeeded"


def test_cli_refuses_to_spawn_without_verified_runtime(host, monkeypatch):
    job = host.plan()
    args = cli.build_parser().parse_args(["pve-native", "power", "status", "--job-id", job])
    monkeypatch.setattr(cli, "os", SimpleNamespace(geteuid=lambda: 0))

    def invalid_runtime():
        raise pve_power.install.InstallError("Release verification failed.")

    def spawn(*args, **kwargs):
        pytest.fail("CLI spawned an unverified native executor.")

    monkeypatch.setattr(pve_power.install, "_locked", nullcontext)
    monkeypatch.setattr(power_model, "_installed_power_runtime", invalid_runtime)
    monkeypatch.setattr(cli.subprocess, "run", spawn)
    with pytest.raises(
        cli.CliError, match="Could not verify the active signed native executor"
    ) as exc:
        args.func(args)
    assert exc.value.code == cli.EXIT_UNAVAILABLE
