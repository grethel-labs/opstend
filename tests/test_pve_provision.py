from contextlib import closing
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from sqlite3 import connect
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
)
from steward.core.pve_provision import (
    CloneLeg,
    CloneProfile,
    ProvisionedGuest,
    ProvisionJob,
    ProvisionLimits,
    ProvisionNetwork,
    ProvisionPolicy,
    ProvisionTarget,
    ProvisionTemplate,
    TemplateEvidence,
)

NOW = datetime(2026, 11, 27, 12, tzinfo=UTC)
UID = "abcdefghijklmnopqrst"
ACTOR = "clone@pve!clone"
UPID = f"UPID:pve:0000000A:0000000B:69286F40:qmclone:103:{ACTOR}:"
TEMPLATE = ProvisionTemplate(
    kind="qemu", vmid=103, pve_uid=UID, registered_at_ms=123, config_digest="c" * 40
)
NETWORK = ProvisionNetwork(index=0, bridge="vmbr0", vlan_tag=11, link_down=True)
LIMITS = ProvisionLimits(max_vcpus=2, max_memory_mib=512, max_disk_bytes=4096, max_swap_mib=0)
PROFILE = CloneProfile(vcpus=2, memory_mib=512, disk_bytes=4096, swap_mib=0, networks=(NETWORK,))


def clone_plan(vmid=101):
    return ProvisionJob(
        job_id=uuid4().hex,
        target=GuestTarget(node="pve", kind="qemu", vmid=vmid),
        source=GuestTarget(node="pve", kind="qemu", vmid=TEMPLATE.vmid),
        destination=ProvisionTarget(
            vmid=vmid,
            template_vmid=TEMPLATE.vmid,
            pool="allowed-pool",
            storage="allowed-storage",
            networks=(NETWORK,),
            limits=LIMITS,
        ),
        name="example-vm",
        observation=TemplateEvidence(
            **TEMPLATE.model_dump(exclude={"kind", "vmid"}), profile=PROFILE
        ),
        policy_revision="a" * 64,
        binding="b" * 64,
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        updated_at=NOW,
        state="prepared",
        next_action="execute",
    )


def power_plan():
    return JobRecord(
        job_id=uuid4().hex,
        operation="start",
        target=GuestTarget(node="pve", kind="qemu", vmid=101),
        policy_revision="a" * 64,
        binding="b" * 64,
        observation=GuestObservation(pve_uid=UID, registered_at_ms=123, state="stopped"),
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        updated_at=NOW,
        state="prepared",
        next_action="execute",
    )


def dispatch(job):
    intent = (
        CloneLeg(actor=ACTOR, dispatched_at=NOW, state="dispatching")
        if isinstance(job, ProvisionJob)
        else PowerLeg(operation="start", actor=ACTOR, dispatched_at=NOW, state="dispatching")
    )
    return job.model_copy(
        update={"state": "dispatching", "next_action": "reconcile", "legs": (intent,)}
    )


def accept(job, *, upid=UPID):
    return job.model_copy(
        update={
            "state": "accepted",
            "legs": (CloneLeg(actor=ACTOR, dispatched_at=NOW, state="accepted", upid=upid),),
        }
    )


def test_provision_policy_normalizes_and_rejects_inconsistent_addresses():
    first = clone_plan().destination
    second = clone_plan(102).destination
    other = TEMPLATE.model_copy(update={"vmid": 104})
    policy = ProvisionPolicy(
        node="pve",
        write_token_file="/private/provision-token",
        templates=(TEMPLATE, other),
        targets=(first, second),
    )
    reordered = policy.model_copy(
        update={"targets": (second, first), "templates": (other, TEMPLATE)}
    )
    assert policy.revision == reordered.revision
    assert policy.target(101) == first
    assert policy.template(103) == TEMPLATE
    assert policy.target(103) is None
    assert policy.template(101) is None
    assert clone_plan().observation.matches(TEMPLATE)

    for changes in (
        {"templates": (TEMPLATE, TEMPLATE)},
        {"targets": (first, first)},
        {"templates": (other,)},
        {"templates": (TEMPLATE, other.model_copy(update={"vmid": first.vmid}))},
    ):
        with pytest.raises(ValidationError):
            ProvisionPolicy.model_validate({**policy.model_dump(), **changes})


def test_exact_clone_profile_and_native_task_affinity():
    plan = clone_plan()
    assert PROFILE.fits(plan.destination)
    for changes in (
        {"vcpus": PROFILE.vcpus + 1},
        {"memory_mib": PROFILE.memory_mib + 1},
        {"disk_bytes": PROFILE.disk_bytes + 1},
        {"swap_mib": PROFILE.swap_mib + 1},
        {"networks": ()},
        {"networks": (NETWORK.model_copy(update={"link_down": False}),)},
    ):
        assert not PROFILE.model_copy(update=changes).fits(plan.destination)
    with pytest.raises(ValidationError):
        ProvisionJob.model_validate({**plan.model_dump(), "name": "vm.example"})
    with pytest.raises(ValidationError):
        ProvisionJob.model_validate(
            {**plan.model_dump(), "source": {"node": "other", "kind": "qemu", "vmid": 103}}
        )
    for mismatch in (
        UPID.replace("qmclone", "vzclone"),
        UPID.replace(":103:", ":101:"),
        UPID.replace(":pve:", ":other:"),
        UPID.replace(ACTOR, "other@pve!clone"),
    ):
        with pytest.raises(ValidationError, match="task does not match source and actor"):
            ProvisionJob.model_validate_json(accept(plan, upid=mismatch).model_dump_json())


def test_public_clone_job_exposes_plan_and_opaque_task_and_generation():
    accepted = accept(dispatch(clone_plan()))
    result = ProvisionedGuest(pve_uid=UID, registered_at_ms=456)
    succeeded = accepted.model_copy(
        update={
            "state": "succeeded",
            "result": result,
            "next_action": None,
            "legs": (accepted.legs[0].model_copy(update={"state": "succeeded"}),),
        }
    )
    public = ProvisionJob.model_validate_json(succeeded.model_dump_json()).public()
    assert public["schema_version"] == 1
    assert public["name"] == "example-vm"
    assert public["source"]["vmid"] == 103
    assert public["target"]["vmid"] == 101
    assert public["pool"] == "allowed-pool"
    assert public["storage"] == "allowed-storage"
    assert public["networks"] == [NETWORK.model_dump(mode="json")]
    assert public["limits"] == LIMITS.model_dump(mode="json")
    assert public["resources"] == PROFILE.model_dump(mode="json", exclude={"networks"})
    assert public["tasks"] == [
        {"operation": "clone", "task_ref": sha256(UPID.encode()).hexdigest(), "state": "succeeded"}
    ]
    assert public["result"] == {"state": "stopped", "generation": result.generation}
    assert not {"binding", "policy_revision", "observation", "legs"} & public.keys()
    assert all(private not in str(public) for private in (UPID, UID, ACTOR, "registered_at_ms"))


@pytest.mark.parametrize("clone_first", [False, True])
def test_power_and_provision_share_existing_database_and_target_fence(tmp_path, clone_first):
    journal = PowerJournal(tmp_path)
    power, clone = power_plan(), clone_plan()
    for plan in (power, clone):
        journal.write(plan, previous=None)
    first, second = (clone, power) if clone_first else (power, clone)
    journal.write(dispatch(first), previous=first)
    reopened = PowerJournal(tmp_path)
    with pytest.raises(PowerJournalError, match="^target_busy$"):
        reopened.write(dispatch(second), previous=second)
    assert reopened.get(power.job_id) == (power if clone_first else dispatch(power))
    assert reopened.get_provision(clone.job_id) == (dispatch(clone) if clone_first else clone)
    assert reopened.get(clone.job_id) is None
    assert reopened.get_provision(power.job_id) is None
    with closing(connect(tmp_path / "power-jobs.sqlite3")) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (1,)
        stored_power = connection.execute(
            "SELECT record FROM jobs WHERE job_id = ?", (power.job_id,)
        ).fetchone()[0]
        assert JobRecord.model_validate_json(stored_power) == reopened.get(power.job_id)


def test_provision_intent_and_task_claim_cannot_be_rebound(tmp_path):
    journal = PowerJournal(tmp_path)
    first, second = clone_plan(), clone_plan(102)
    journal.write(first, previous=None)
    with pytest.raises(PowerJournalError, match="^journal_conflict$"):
        journal.write(first.model_copy(update={"name": "other-name"}), previous=first)

    first_accepted = accept(dispatch(first))
    journal.write(first_accepted, previous=first)
    with pytest.raises(PowerJournalError, match="^journal_conflict$"):
        journal.write(
            accept(first_accepted, upid=UPID.replace("0000000A", "0000000C")),
            previous=first_accepted,
        )

    first_failed = first_accepted.model_copy(update={"state": "failed"})
    journal.write(first_failed, previous=first_accepted)
    second_dispatch = dispatch(second)
    journal.write(second_dispatch, previous=None)
    with pytest.raises(PowerJournalError, match="^task_conflict$"):
        journal.write(accept(second_dispatch), previous=second_dispatch)
    assert journal.get_provision(second.job_id) == second_dispatch
