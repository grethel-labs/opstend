from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from threading import Barrier
from uuid import uuid4

import pytest
from pydantic import ValidationError

from steward.core.pve_power import (
    GuestObservation,
    GuestTarget,
    JobRecord,
    PowerJournal,
    PowerJournalError,
    PowerLeg,
    PowerPolicy,
    RegisteredGuest,
)

NOW = datetime(2026, 11, 27, 12, tzinfo=UTC)
UID = "abcdefghijklmnopqrst"
ACTOR = "power@pve!power"
UPID = f"UPID:pve:0000000A:0000000B:69286F40:qmstart:101:{ACTOR}:"


def plan(vmid=101, *, operation="start"):
    return JobRecord(
        job_id=uuid4().hex,
        operation=operation,
        target=GuestTarget(node="pve", kind="qemu", vmid=vmid),
        policy_revision="a" * 64,
        binding="b" * 64,
        observation=GuestObservation(pve_uid=UID, registered_at_ms=123, state="stopped"),
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        updated_at=NOW,
        state="prepared",
        next_action="execute",
    )


def dispatch(record):
    leg = PowerLeg(
        actor=ACTOR,
        operation="shutdown" if record.operation == "reboot" else record.operation,
        dispatched_at=NOW,
        state="dispatching",
    )
    return record.model_copy(
        update={"state": "dispatching", "next_action": "reconcile", "legs": (leg,)}
    )


def accept(record, upid=UPID):
    leg = record.legs[0].model_copy(update={"state": "accepted", "upid": upid})
    return record.model_copy(update={"state": "accepted", "legs": (leg,)})


def test_power_models_validate_guest_and_policy():
    guest = RegisteredGuest(
        kind="qemu", vmid=101, pve_uid=UID, registered_at_ms=123, operations=("shutdown", "start")
    )
    policy = PowerPolicy(node="pve", write_token_file="/private/power-token", guests=(guest,))
    reordered = PowerPolicy(
        node="pve",
        write_token_file="/private/power-token",
        guests=(guest.model_copy(update={"operations": ("start", "shutdown")}),),
    )
    assert policy.guest(101) == guest
    assert policy.guest(102) is None
    assert policy.revision == reordered.revision
    assert policy.revision != policy.model_copy(update={"node": "elsewhere"}).revision
    with pytest.raises(ValidationError):
        PowerPolicy(node="pve", write_token_file="/private/token", guests=(guest, guest))
    with pytest.raises(ValidationError):
        GuestTarget(node="pve", kind="qemu", vmid="101")
    with pytest.raises(ValidationError):
        GuestObservation(pve_uid=UID, registered_at_ms=123, state="running")
    with pytest.raises(ValidationError):
        GuestObservation(pve_uid=UID, registered_at_ms=123, state="stopped", pid=21)
    with pytest.raises(ValidationError):
        JobRecord.model_validate({**plan().model_dump(), "schema_version": True})
    with pytest.raises(ValidationError):
        PowerLeg(
            actor=ACTOR, operation="start", dispatched_at=NOW, state="accepted", upid=UPID + "\n"
        )


def test_public_job_redacts_native_task_and_guest_generation():
    job = accept(dispatch(plan()))
    assert job.public() == {
        "schema_version": 1,
        "job_id": job.job_id,
        "operation": "start",
        "target": {"node": "pve", "kind": "qemu", "vmid": 101},
        "state": "accepted",
        "created_at": "2026-11-27T12:00:00Z",
        "expires_at": "2026-11-27T12:05:00Z",
        "updated_at": "2026-11-27T12:00:00Z",
        "current_state": None,
        "next_action": "reconcile",
        "error_code": None,
        "observed_state": "stopped",
        "desired_state": "running",
        "tasks": [
            {
                "operation": "start",
                "task_ref": sha256(UPID.encode()).hexdigest(),
                "state": "accepted",
            }
        ],
    }
    assert job.legs[0].upid == UPID
    assert dispatch(plan()).public()["tasks"] == []


def test_journal_survives_reopen_and_rejects_stale_writes(tmp_path):
    journal = PowerJournal(tmp_path)
    prepared = plan()
    dispatched = dispatch(prepared)
    assert journal.get(prepared.job_id) is None
    journal.write(prepared, previous=None)
    journal.write(dispatched, previous=prepared)
    reopened = PowerJournal(tmp_path)
    assert reopened.get(prepared.job_id) == dispatched
    with pytest.raises(PowerJournalError, match="^journal_conflict$"):
        reopened.write(dispatched, previous=prepared)
    with pytest.raises(PowerJournalError, match="^journal_conflict$"):
        reopened.write(prepared, previous=dispatched)
    assert reopened.get(prepared.job_id) == dispatched
    accepted = accept(dispatched)
    reopened.write(accepted, previous=dispatched)
    assert journal.get(prepared.job_id) == accepted


def test_concurrent_dispatch_has_one_target_owner(tmp_path):
    jobs = [plan(), plan()]
    for job in jobs:
        PowerJournal(tmp_path).write(job, previous=None)
    barrier = Barrier(2)

    def compete(job):
        journal = PowerJournal(tmp_path)
        barrier.wait(timeout=5)
        try:
            journal.write(dispatch(job), previous=job)
        except PowerJournalError as exc:
            return exc.code
        return "dispatched"

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(compete, jobs)) == ["dispatched", "target_busy"]

    journal = PowerJournal(tmp_path)
    owner, blocked = sorted((journal.get(job.job_id) for job in jobs), key=lambda job: job.state)
    uncertain = owner.model_copy(update={"state": "uncertain"})
    journal.write(uncertain, previous=owner)
    with pytest.raises(PowerJournalError, match="^target_busy$"):
        journal.write(dispatch(blocked), previous=blocked)
    failed = uncertain.model_copy(update={"state": "failed"})
    journal.write(failed, previous=uncertain)
    journal.write(dispatch(blocked), previous=blocked)
    assert journal.get(owner.job_id) == failed


def test_native_task_claim_is_permanent_and_atomic(tmp_path):
    journal = PowerJournal(tmp_path)
    first = dispatch(plan())
    accepted = accept(first)
    journal.write(accepted, previous=None)
    failed = accepted.model_copy(update={"state": "failed"})
    journal.write(failed, previous=accepted)
    second = dispatch(plan())
    journal.write(second, previous=None)
    with pytest.raises(PowerJournalError, match="^task_conflict$"):
        journal.write(accept(second), previous=second)
    assert journal.get(second.job_id) == second


def test_reboot_cannot_reuse_first_leg_task(tmp_path):
    journal = PowerJournal(tmp_path)
    prepared = plan(operation="reboot")
    reboot = dispatch(prepared)
    shutdown_upid = UPID.replace("qmstart", "qmshutdown")
    first = reboot.legs[0].model_copy(update={"state": "succeeded", "upid": shutdown_upid})
    second = PowerLeg(
        actor=ACTOR, operation="start", dispatched_at=NOW, state="accepted", upid=shutdown_upid
    )
    invalid = reboot.model_copy(update={"state": "accepted", "legs": (first, second)})
    journal.write(prepared, previous=None)
    with pytest.raises(PowerJournalError, match="^task_conflict$"):
        journal.write(invalid, previous=prepared)
    assert journal.get(prepared.job_id) == prepared


@pytest.mark.parametrize("violation", ["mode", "symlink", "hardlink"])
def test_journal_rejects_unprivate_database(tmp_path, violation):
    journal = PowerJournal(tmp_path)
    prepared = plan()
    journal.write(prepared, previous=None)
    database = next(tmp_path.iterdir())
    assert database.stat().st_mode & 0o777 == 0o600
    if violation == "mode":
        database.chmod(0o644)
    elif violation == "symlink":
        moved = database.with_suffix(".moved")
        database.rename(moved)
        database.symlink_to(moved)
    else:
        database.with_suffix(".link").hardlink_to(database)
    with pytest.raises(PowerJournalError, match="^journal_unavailable$"):
        journal.get(prepared.job_id)
    with pytest.raises(PowerJournalError, match="^journal_unavailable$"):
        journal.write(dispatch(prepared), previous=prepared)
