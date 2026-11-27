from datetime import UTC, datetime, timedelta

import pytest

from steward.core.fleet_adoption_models import (
    LocalPveProfile,
    PveAdoptionEvidence,
    PveBackupSchedule,
)
from steward.core.fleet_enrollment import FleetEnrollment, FleetEnrollmentConflict
from steward.core.fleet_identity import FleetIdentityRegistry
from steward.core.fleet_ownership import OwnershipExchange, OwnershipReceipt
from steward.core.fleet_ownership_coordinator import (
    FleetOwnershipConflict,
    FleetOwnershipCoordinator,
)
from steward.core.fleet_policy_apply import FleetPolicyDenied, FleetPolicyGrant
from steward.core.fleet_power_commands import FleetPowerCommands, _power_owned
from test_fleet_transport import _power_enroll, _power_report, _power_setup, sample_snapshot

_KEY = "11" * 32
_OTHER = "22" * 32
_READER = "33" * 32
_SCHEDULE = "44" * 32
_FINGERPRINT = "55" * 32


@pytest.fixture
def fleet(tmp_path):
    now = [datetime.now(UTC) - timedelta(seconds=2)]
    registry, owner, operator, observer, policy, targets = _power_setup(
        tmp_path, now[0], backup_profile_refs=("daily",)
    )
    (agent, poll), (other_agent, other_poll) = targets
    enrollment = FleetEnrollment(registry)
    for identity, target, key in (
        (agent, poll.target, _KEY),
        (other_agent, other_poll.target, _OTHER),
    ):
        token = _power_enroll(enrollment, identity, key, target, now=now[0])
        enrollment.redeem(token, key_fingerprint=key, now=now[0])
    host = registry.get_agent(agent).host_id
    with registry._connection() as db:
        route_id = db.execute("SELECT id FROM fleet_routes WHERE host_id = ?", (host,)).fetchone()[
            "id"
        ]
    route = registry.get_connector_route(route_id)
    connector = registry.register_agent(host, "handoff-inventory")
    invite = enrollment.issue(
        connector.id,
        key_fingerprint=_READER,
        capability="pve_inventory",
        route_id=route_id,
        now=now[0],
    )
    enrollment.redeem(invite.token.get_secret_value(), key_fingerprint=_READER, now=now[0])
    enrollment.adopt_pve(
        instance_id=route.instance_id,
        route_id=route_id,
        agent_id=connector.id,
        expected_generation=1,
        instance_binding=route.instance_binding,
        local_profile=LocalPveProfile(
            instance_binding=route.instance_binding,
            node=route.node,
            version="1.2.3",
            observed_at=now[0],
        ),
    )
    now[0] += timedelta(seconds=1)
    grant, _, attempt = enrollment.begin_adoption(_READER, now=now[0])
    enrollment.publish_adoption(
        _READER,
        generation=grant.generation,
        attempt=attempt,
        snapshot=sample_snapshot(
            api_name=route.api_name,
            node=route.node,
            observed_at=now[0],
            uid="abcde23456abcde23456",
            registration_ms=1234567890000,
        ),
        evidence=PveAdoptionEvidence(
            observed_at=now[0],
            node=route.node,
            pve_version="9.3.0",
            audit_privileges=("VM.Audit",),
            schedule_state="observed",
            schedules=(
                PveBackupSchedule(job_ref=_SCHEDULE, schedule="03:30", enabled=True, vmids=(190,)),
            ),
        ),
        now=now[0],
    )
    return registry, owner, operator, observer, policy, enrollment, poll, other_poll, now


def _stage(coordinator, actor, poll, *, owner="fleet", key="handoff", epoch=0):
    status = coordinator.request(actor, poll.target, _SCHEDULE, "daily", owner, key, epoch)
    return status, OwnershipExchange(
        target=status.target, transition_id=status.transition_id, digest=status.digest
    )


def _settle(coordinator, exchange, epoch, *, state="committed", fingerprint=_FINGERPRINT):
    report = OwnershipReceipt(state=state, epoch=epoch, schedule_fingerprint=fingerprint)
    return coordinator.exchange(_KEY, exchange.model_copy(update={"receipt": report})).status


def _queue(commands, operator, poll):
    requested = commands.request(operator, poll.target, poll.policy_revision, "start", "request")
    work = commands.poll(_KEY, poll).work
    commands.poll(_KEY, _power_report(poll, work, "prepared"))
    reviewed = commands.status(operator, requested.command_id)
    return commands.approve(operator, reviewed.command_id, reviewed.digest, "approve")


@pytest.mark.parametrize("power_state", ("preparing", "review", "queued"))
def test_staging_refuses_undispatched_power_and_releases_only_exact_plan(fleet, power_state):
    registry, _, actor, observer, _, _, poll, other_poll, now = fleet
    coordinator = FleetOwnershipCoordinator(registry, now=lambda: now[0])
    commands = FleetPowerCommands(registry, now=lambda: now[0])
    pending = commands.request(actor, poll.target, poll.policy_revision, "start", "old")
    work = commands.poll(_KEY, poll).work
    if power_state != "preparing":
        commands.poll(_KEY, _power_report(poll, work, "prepared"))
        pending = commands.status(actor, pending.command_id)
    if power_state == "queued":
        pending = commands.approve(actor, pending.command_id, pending.digest, "approve")
    assert pending.state == power_state

    with pytest.raises(FleetPolicyDenied):
        _stage(coordinator, observer, poll)
    with pytest.raises(FleetPolicyDenied):
        coordinator.request(actor, poll.target, _SCHEDULE, "weekly", "fleet", "wrong-profile", 0)
    with pytest.raises(FleetOwnershipConflict, match="epoch"):
        _stage(coordinator, actor, poll, epoch=1)
    staged, exchange = _stage(coordinator, actor, poll)
    assert (staged.owner, staged.epoch, staged.state) == ("standalone", 0, "pausing")
    assert _stage(coordinator, actor, poll)[0] == staged
    with pytest.raises(FleetOwnershipConflict, match="different transition"):
        _stage(coordinator, actor, poll, epoch=1)
    assert commands.status(actor, pending.command_id).state == "refused"
    assert commands.poll(_KEY, poll).work is None
    with pytest.raises(FleetPolicyDenied):
        commands.request(actor, poll.target, poll.policy_revision, "start", "new")
    assert commands.request(actor, other_poll.target, other_poll.policy_revision, "start", "other")
    with pytest.raises(FleetEnrollmentConflict):
        coordinator.exchange(_OTHER, exchange)
    with pytest.raises(FleetPolicyDenied):
        coordinator.exchange(_KEY, exchange.model_copy(update={"digest": "99" * 32}))
    with pytest.raises(FleetOwnershipConflict, match="released"):
        _settle(coordinator, exchange, 1)
    assert coordinator.exchange(_KEY, exchange).claim is not None


def test_released_and_uncertain_work_drains_through_existing_reconciliation(fleet):
    registry, _, actor, _, _, _, poll, _, now = fleet
    coordinator = FleetOwnershipCoordinator(registry, now=lambda: now[0])
    commands = FleetPowerCommands(registry, now=lambda: now[0])
    pending = _queue(commands, actor, poll)
    work = commands.poll(_KEY, poll).work
    assert work.phase == "execute"
    _, exchange = _stage(coordinator, actor, poll)
    assert coordinator.exchange(_KEY, exchange).claim is None
    commands.poll(_KEY, _power_report(poll, work, "accepted", task_ref="aa" * 32))
    assert coordinator.exchange(_KEY, exchange).claim is None
    reconciliation = commands.poll(_KEY, poll).work
    assert reconciliation.phase == "reconcile"
    commands.poll(_KEY, _power_report(poll, reconciliation, "uncertain", task_ref="aa" * 32))
    assert coordinator.exchange(_KEY, exchange).claim is None
    now[0] += timedelta(seconds=1)
    reconciliation = commands.poll(_KEY, poll).work
    commands.poll(
        _KEY,
        _power_report(
            poll, reconciliation, "succeeded", task_ref="aa" * 32, observed_state="running"
        ),
    )
    assert commands.status(actor, pending.command_id).state == "succeeded"
    assert coordinator.exchange(_KEY, exchange).claim is not None


def test_handoff_survives_delayed_evidence_restart_and_reverse(fleet, tmp_path):
    registry, _, actor, _, _, _, poll, _, now = fleet
    coordinator = FleetOwnershipCoordinator(registry, now=lambda: now[0])
    commands = FleetPowerCommands(registry, now=lambda: now[0])
    staged, exchange = _stage(coordinator, actor, poll)
    assert coordinator.exchange(_KEY, exchange).claim is not None
    now[0] += timedelta(seconds=30)
    restarted = FleetOwnershipCoordinator(
        FleetIdentityRegistry(tmp_path / "fleet.sqlite"), now=lambda: now[0]
    )
    assert restarted.status(actor, staged.transition_id) == staged
    with pytest.raises(FleetOwnershipConflict, match="pending"):
        _settle(restarted, exchange, 2)
    committed = _settle(restarted, exchange, 1)
    assert (committed.owner, committed.epoch, committed.state) == ("fleet", 1, "committed")
    assert restarted.exchange(_KEY, exchange).claim is None
    with pytest.raises(FleetPolicyDenied):
        commands.request(actor, poll.target, poll.policy_revision, "start", "paused")
    with pytest.raises(FleetOwnershipConflict, match="matching"):
        _settle(restarted, exchange, 1, state="active", fingerprint="99" * 32)
    active = _settle(restarted, exchange, 1, state="active")
    assert (active.owner, active.state) == ("fleet", "active")
    assert _settle(restarted, exchange, 1) == active
    assert poll.target in {item.target for item in commands.catalog(actor).targets}

    # Neither a generation change nor a replacement guest can inherit fleet ownership.
    with registry._connection() as db:
        slot = {"instance_id": active.instance_id, "vmid": 190}
        different_generation = poll.target.model_copy(
            update={"generation": poll.target.generation + 1}
        )
        different_identity = poll.target.model_copy(update={"id": "f" * 32})
        assert _power_owned(db, slot, poll.target)
        assert not _power_owned(db, slot, different_generation)
        assert not _power_owned(db, slot, different_identity)

    reverse, back = _stage(restarted, actor, poll, owner="standalone", key="return", epoch=1)
    assert (reverse.owner, reverse.epoch, reverse.state) == ("fleet", 1, "pausing")
    assert restarted.exchange(_KEY, exchange).claim is None
    assert _settle(restarted, exchange, 1, state="active") == active
    assert restarted.exchange(_KEY, back).claim is not None
    assert _settle(restarted, back, 2).owner == "standalone"
    assert _settle(restarted, back, 2, state="active").state == "active"
    with pytest.raises(FleetPolicyDenied):
        commands.request(actor, poll.target, poll.policy_revision, "start", "returned")

    with registry._connection() as db:
        rows = db.execute(
            "SELECT state, owner, epoch FROM fleet_ownership_history ORDER BY id"
        ).fetchall()
    assert [tuple(row) for row in rows] == [
        ("pausing", "standalone", 0),
        ("claim", "standalone", 0),
        ("committed", "fleet", 1),
        ("active", "fleet", 1),
        ("pausing", "fleet", 1),
        ("claim", "fleet", 1),
        ("committed", "standalone", 2),
        ("active", "standalone", 2),
    ]


def test_claim_requires_current_approval_and_grant_but_delayed_receipt_is_evidence(fleet):
    registry, owner, actor, _, policy, enrollment, poll, _, now = fleet
    coordinator = FleetOwnershipCoordinator(registry, now=lambda: now[0])
    _, exchange = _stage(coordinator, actor, poll)
    claim = coordinator.exchange(_KEY, exchange).claim
    assert claim is not None
    now[0] = claim.claim_until + timedelta(seconds=1)
    policy.set_grant(
        owner, FleetPolicyGrant(actor.subject, "write", target=poll.target), enabled=False
    )
    policy.set_grant(owner, FleetPolicyGrant(actor.subject, "read", target=poll.target))
    assert coordinator.exchange(_KEY, exchange).claim is None
    assert _settle(coordinator, exchange, 1).owner == "fleet"

    with registry._connection() as db:
        agent_id = db.execute(
            "SELECT agent_id FROM fleet_agent_grants WHERE fingerprint = ?", (_KEY,)
        ).fetchone()["agent_id"]
    token = _power_enroll(enrollment, agent_id, "66" * 32, poll.target, generation=1, now=now[0])
    enrollment.redeem(token, key_fingerprint="66" * 32, now=now[0])
    with pytest.raises(FleetEnrollmentConflict):
        coordinator.exchange(_KEY, exchange)
    assert coordinator.exchange("66" * 32, exchange).claim is None
    active = OwnershipReceipt(state="active", epoch=1, schedule_fingerprint=_FINGERPRINT)
    assert coordinator.status(actor, exchange.transition_id).state == "committed"
    ready = coordinator.exchange("66" * 32, exchange.model_copy(update={"receipt": active}))
    assert ready.status.state == "active"


def test_staging_requires_current_adoption_schedule(fleet):
    registry, _, actor, _, _, enrollment, poll, _, now = fleet
    coordinator = FleetOwnershipCoordinator(registry, now=lambda: now[0])
    with pytest.raises(FleetOwnershipConflict, match="single-guest"):
        coordinator.request(actor, poll.target, "99" * 32, "daily", "fleet", "wrong-job", 0)
    enrollment.begin_adoption(_READER, now=now[0])
    with pytest.raises(FleetOwnershipConflict, match="fresh standalone"):
        _stage(coordinator, actor, poll)


def test_cancel_restores_confirmed_owner_after_policy_drift_and_rotation(fleet, tmp_path):
    registry, owner, actor, _, policy, enrollment, poll, _, now = fleet
    coordinator = FleetOwnershipCoordinator(registry, now=lambda: now[0])
    _, exchange = _stage(coordinator, actor, poll)
    reply = coordinator.exchange(_KEY, exchange)
    assert reply.claim is not None
    now[0] = reply.claim.claim_until + timedelta(seconds=1)
    original = policy.revision(owner, poll.policy_revision)
    policy.commit(
        owner,
        original.policy.model_copy(
            update={
                "targets": tuple(
                    item for item in original.policy.targets if item.target == poll.target
                )
            }
        ),
        parent=original.id,
    )
    assert coordinator.exchange(_KEY, exchange).claim is None
    new_key = "66" * 32
    token = _power_enroll(
        enrollment, reply.plan.agent_id, new_key, poll.target, generation=1, now=now[0]
    )
    enrollment.redeem(token, key_fingerprint=new_key, now=now[0])
    assert coordinator.exchange(new_key, exchange).claim is None
    canceled = OwnershipReceipt(state="canceled", epoch=0, schedule_fingerprint=_FINGERPRINT)
    cancellation = exchange.model_copy(update={"receipt": canceled})
    with pytest.raises(FleetOwnershipConflict, match="pending"):
        coordinator.exchange(
            new_key,
            cancellation.model_copy(update={"receipt": canceled.model_copy(update={"epoch": 1})}),
        )
    result = coordinator.exchange(new_key, cancellation)
    assert (result.status.owner, result.status.epoch, result.status.state) == (
        "standalone",
        0,
        "canceled",
    )
    committed = canceled.model_copy(update={"state": "committed", "epoch": 1})
    with pytest.raises(FleetOwnershipConflict, match="pending"):
        coordinator.exchange(new_key, exchange.model_copy(update={"receipt": committed}))
    restarted = FleetOwnershipCoordinator(
        FleetIdentityRegistry(tmp_path / "fleet.sqlite"), now=lambda: now[0]
    )
    assert restarted.exchange(new_key, cancellation) == result


def test_canceled_reverse_reopens_fleet_power_and_allows_a_new_plan(fleet):
    registry, _, actor, _, _, _, poll, _, now = fleet
    coordinator = FleetOwnershipCoordinator(registry, now=lambda: now[0])
    commands = FleetPowerCommands(registry, now=lambda: now[0])
    _, first = _stage(coordinator, actor, poll)
    assert coordinator.exchange(_KEY, first).claim is not None
    _settle(coordinator, first, 1)
    with pytest.raises(FleetOwnershipConflict, match="pending"):
        _settle(coordinator, first, 0, state="canceled")
    _settle(coordinator, first, 1, state="active")

    _, reverse = _stage(coordinator, actor, poll, owner="standalone", key="return", epoch=1)
    canceled = _settle(coordinator, reverse, 1, state="canceled")
    assert (canceled.owner, canceled.epoch, canceled.state) == ("fleet", 1, "canceled")
    assert poll.target in {item.target for item in commands.catalog(actor).targets}

    staged, retry = _stage(coordinator, actor, poll, owner="standalone", key="retry", epoch=1)
    assert retry.transition_id != reverse.transition_id
    assert _settle(coordinator, reverse, 1, state="canceled") == canceled
    assert coordinator.status(actor, retry.transition_id) == staged
    assert poll.target not in {item.target for item in commands.catalog(actor).targets}
