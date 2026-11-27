from datetime import UTC, datetime

from steward.core import fleet_policy_target
from steward.core.fleet_enrollment import FleetEnrollment
from steward.core.fleet_identity import FleetIdentityRegistry
from steward.core.fleet_policy import FleetPolicy, FleetPolicyValues, FleetTarget, FleetTargetPolicy
from steward.core.fleet_policy_apply import FleetPolicyActor, FleetPolicyApply
from steward.core.fleet_policy_target import FleetPolicyTargetConfig, FleetPolicyTargetStore


def test_expired_remote_claim_never_applies_and_expired_approval_cannot_issue_claim(
    tmp_path, monkeypatch
):
    registry = FleetIdentityRegistry(tmp_path / "coordinator.db")
    site = registry.register_site("lab")
    host = registry.register_host(site.id, "host")
    agent = registry.register_agent(host.id, "policy")
    target = FleetTarget(kind="host", id=host.id)
    store = FleetPolicyTargetStore.configure(
        tmp_path / "target.db", FleetPolicyTargetConfig(target=target, limits=FleetPolicyValues())
    )
    enrollment = FleetEnrollment(registry)
    key = "a" * 64
    invitation = enrollment.issue(
        agent.id, key_fingerprint=key, capability="policy_target", target=target
    )
    enrollment.redeem(invitation.token.get_secret_value(), key_fingerprint=key)
    now = datetime.now(UTC)
    service = FleetPolicyApply(registry, clock=lambda: now)
    actor = FleetPolicyActor("coordinator", True)
    record = service.commit(
        actor, FleetPolicy(targets=(FleetTargetPolicy(target=target),)), parent=None
    )

    def exchange(request):
        return service.reconcile_target(key, request)

    assert store.reconcile(exchange).outcome is None
    plan = service.preview(actor, record.id, (target,))
    outstanding = service.approve(actor, plan.digest, "outstanding")
    fresh = service.approve(actor, plan.digest, "fresh")

    elapsed = 0.0
    monkeypatch.setattr(fleet_policy_target, "monotonic", lambda: elapsed)

    def return_expired_claim(request):
        nonlocal elapsed
        assert request.receipt is None
        reply = exchange(request)
        assert reply.claim is not None
        elapsed += reply.claim.valid_for_ms / 1000
        return reply

    expired = store.reconcile(return_expired_claim, outstanding.id, plan.digest)
    assert (expired.outcome.status, expired.outcome.reason) == ("pending", "claim_expired")
    assert expired.claim is None
    assert store.state().applied_revision is None
    assert service.approval(actor, outstanding.id).outcomes[0].status == "pending"

    now = plan.expires_at
    outstanding_retry = store.reconcile(exchange, outstanding.id, plan.digest)
    assert outstanding_retry.claim is None
    assert (outstanding_retry.outcome.status, outstanding_retry.outcome.reason) == (
        "rejected",
        "approval_expired",
    )
    assert service.approval(actor, outstanding.id).outcomes[0].status == "rejected"
    fresh_attempt = store.reconcile(exchange, fresh.id, plan.digest)
    assert fresh_attempt.claim is None
    assert (fresh_attempt.outcome.status, fresh_attempt.outcome.reason) == (
        "rejected",
        "approval_expired",
    )
    assert service.approval(actor, fresh.id).outcomes[0].status == "rejected"
    assert store.state().applied_revision is None
