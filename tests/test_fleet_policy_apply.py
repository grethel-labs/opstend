from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from steward.core.fleet_identity import FleetIdentityRegistry
from steward.core.fleet_policy import (
    FleetPolicy,
    FleetPolicyConflict,
    FleetPolicyValues,
    FleetTarget,
)
from steward.core.fleet_policy_apply import (
    FleetPolicyActor,
    FleetPolicyApply,
    FleetPolicyDenied,
    FleetPolicyGrant,
    FleetPolicyNotFound,
)
from steward.core.fleet_policy_target import FleetPolicyTargetConfig, FleetPolicyTargetStore

ADMIN = FleetPolicyActor("coordinator", True)
OPERATOR = FleetPolicyActor("operator")


@pytest.fixture
def fleet(tmp_path):
    directory = tmp_path / "fleet"
    directory.mkdir(mode=0o700)
    registry = FleetIdentityRegistry(directory / "registry.db")
    now = [datetime(2026, 11, 20, tzinfo=UTC)]
    service = FleetPolicyApply(registry, clock=lambda: now[0])
    sites = tuple(registry.register_site(name) for name in ("west", "east"))
    targets = tuple(
        FleetTarget(kind="host", id=registry.register_host(site.id, site.name).id) for site in sites
    )
    stores = tuple(
        FleetPolicyTargetStore.configure(
            directory / f"{target.id}.db",
            FleetPolicyTargetConfig(target=target, limits=FleetPolicyValues()),
        )
        for target in targets
    )
    policy = FleetPolicy.model_validate(
        {
            "groups": {"first": {}, "second": {}},
            "targets": tuple(
                {"target": target, "group_ids": (group,)}
                for target, group in zip(targets, ("first", "second"), strict=True)
            ),
        }
    )
    first = service.commit(ADMIN, policy, parent=None)
    return service, now, sites, targets, stores, first


def test_exact_preview_atomic_approval_and_partial_adoption(fleet, monkeypatch):
    service, _, _, targets, stores, first = fleet
    service.report_local(stores[0])
    plan = service.preview(ADMIN, first.id, targets)
    assert service.preview(ADMIN, first.id, reversed(targets)) == plan
    assert service.preview(ADMIN, first.id, targets[:1]).digest != plan.digest
    approval = service.approve(ADMIN, plan.digest, "request-1")
    assert service.approve(ADMIN, plan.digest, "request-1") == approval
    with pytest.raises(ValueError, match="already in use"):
        different = service.preview(ADMIN, first.id, targets[:1])
        service.approve(ADMIN, different.digest, "request-1")
    assert {item.status for item in approval.outcomes} == {"pending"}

    def fail_after_write(db, effective, approval_id):
        real_apply(db, effective, approval_id)
        raise RuntimeError("simulated storage error")

    real_apply = stores[0].apply
    with monkeypatch.context() as patch:
        patch.setattr(stores[0], "apply", fail_after_write)
        with pytest.raises(RuntimeError, match="simulated storage error"):
            service.adopt_local(stores[0], approval.id, plan.digest)
    assert stores[0].state().applied_revision is None
    assert service.approval(ADMIN, approval.id) == approval

    with pytest.raises(FleetPolicyNotFound):
        service.adopt_local(stores[0], approval.id, "0" * 64)
    applied = service.adopt_local(stores[0], approval.id, plan.digest)
    assert applied.status == "applied"
    assert service.adopt_local(stores[0], approval.id, plan.digest) == applied
    assert stores[0].state().applied_revision == first.id
    offline = next(
        item for item in service.approval(ADMIN, approval.id).outcomes if item.target == targets[1]
    )
    assert offline.status == "pending"
    assert service.adopt_local(stores[1], approval.id, plan.digest).reason == "review_required"
    assert stores[1].state().applied_revision is None


def test_current_scope_is_checked_before_projections_and_adoption(fleet):
    service, _, sites, targets, stores, first = fleet
    service.report_local(stores[0])
    plan = service.preview(ADMIN, first.id, targets)
    site_read = FleetPolicyGrant(OPERATOR.subject, "read", site_id=sites[0].id)
    group_write = FleetPolicyGrant(OPERATOR.subject, "write", group_id="first")
    exact_read = FleetPolicyGrant(OPERATOR.subject, "read", target=targets[1])
    service.set_grant(ADMIN, site_read)
    service.set_grant(ADMIN, group_write)
    with pytest.raises(FleetPolicyNotFound) as forbidden:
        service.preview(OPERATOR, first.id, targets)
    with pytest.raises(FleetPolicyNotFound) as unknown:
        service.preview(OPERATOR, first.id, (FleetTarget(kind="host", id="0" * 32),))
    assert str(forbidden.value) == str(unknown.value)
    service.set_grant(ADMIN, exact_read)
    scoped = service.head(OPERATOR)
    assert {item.target: item.can_write for item in scoped.targets} == {
        targets[0]: True,
        targets[1]: False,
    }
    assert service.preview(OPERATOR, first.id, targets) == plan
    with pytest.raises(FleetPolicyNotFound):
        service.approve(OPERATOR, plan.digest, "whole")
    approval = service.approve(ADMIN, plan.digest, "whole")
    own_plan = service.preview(OPERATOR, first.id, targets[:1])
    own = service.approve(OPERATOR, own_plan.digest, "first")
    service.set_grant(ADMIN, group_write, enabled=False)
    assert (
        service.adopt_local(stores[0], own.id, own_plan.digest).reason == "approval_scope_revoked"
    )
    service.set_grant(ADMIN, site_read, enabled=False)
    assert [item.target for item in service.approval(OPERATOR, approval.id).outcomes] == [
        targets[1]
    ]
    with pytest.raises(FleetPolicyNotFound):
        service.approval(OPERATOR, own.id)
    with pytest.raises(FleetPolicyDenied):
        service.revision(OPERATOR, first.id)
    with pytest.raises(FleetPolicyDenied):
        service.commit(OPERATOR, first.policy, parent=first.id)
    with pytest.raises(FleetPolicyDenied):
        service.rollback(OPERATOR, first.id, parent=first.id)


def test_new_membership_does_not_inherit_old_access_or_desired_roles(fleet):
    service, _, _, targets, _, first = fleet
    service.set_grant(ADMIN, FleetPolicyGrant(OPERATOR.subject, "write", group_id="first"))
    plan = service.preview(OPERATOR, first.id, targets[:1])
    approval = service.approve(OPERATOR, plan.digest, "first")

    policy = FleetPolicy.model_validate(
        {
            "groups": {"first": {}, "second": {}},
            "targets": (
                {
                    "target": targets[0],
                    "group_ids": ("second",),
                    "exception": {
                        "role_assignments": ({"subject": OPERATOR.subject, "role": "operator"},)
                    },
                },
                {"target": targets[1], "group_ids": ("first",)},
            ),
        }
    )
    current = service.commit(ADMIN, policy, parent=first.id)
    assert service.head(OPERATOR).head == current.id
    assert [item.target for item in service.head(OPERATOR).targets] == [targets[1]]
    assert service.head(OPERATOR).approval_ids == ()
    with pytest.raises(FleetPolicyNotFound):
        service.approval(OPERATOR, approval.id)
    with pytest.raises(FleetPolicyNotFound):
        service.approve(OPERATOR, plan.digest, "first")


def test_rollback_is_new_and_offline_cannot_adopt_superseded_revision(fleet):
    service, _, _, targets, stores, first = fleet
    for store in stores:
        service.report_local(store)
    initial = service.preview(ADMIN, first.id, targets)
    approval = service.approve(ADMIN, initial.digest, "initial")
    service.adopt_local(stores[0], approval.id, initial.digest)
    second = service.commit(ADMIN, first.policy, parent=first.id)

    second_plan = service.preview(ADMIN, second.id, targets)
    second_approval = service.approve(ADMIN, second_plan.digest, "second")
    rolled_back = service.rollback(ADMIN, first.id, parent=second.id)
    assert rolled_back.id not in (first.id, second.id)
    assert rolled_back.parent == second.id
    assert rolled_back.policy == first.policy
    with pytest.raises(FleetPolicyConflict):
        service.rollback(ADMIN, first.id, parent=second.id)
    result = service.adopt_local(stores[1], second_approval.id, second_plan.digest)
    assert result.reason == "revision_superseded"
    assert stores[1].state().applied_revision is None
    assert stores[0].state().applied_revision == first.id
    assert {item.target: item.status for item in service.approval(ADMIN, approval.id).outcomes} == {
        targets[0]: "applied",
        targets[1]: "pending",
    }


def test_local_edits_previous_apply_and_expiry_fence_adoption(fleet):
    service, now, _, targets, stores, first = fleet
    for store in stores:
        service.report_local(store)
    plan = service.preview(ADMIN, first.id, targets)
    first_approval = service.approve(ADMIN, plan.digest, "first")
    second_approval = service.approve(ADMIN, plan.digest, "second")
    assert service.adopt_local(stores[0], first_approval.id, plan.digest).status == "applied"
    assert (
        service.adopt_local(stores[0], second_approval.id, plan.digest).reason
        == "applied_revision_changed"
    )
    FleetPolicyTargetStore.configure(
        stores[1]._path,
        FleetPolicyTargetConfig(
            target=targets[1], limits=FleetPolicyValues(backup_profile_refs=("nightly",))
        ),
    )
    assert (
        service.adopt_local(stores[1], first_approval.id, plan.digest).reason
        == "local_revision_changed"
    )
    now[0] += timedelta(minutes=5)
    with pytest.raises(ValueError, match="expired"):
        service.approve(ADMIN, plan.digest, "third")
    assert (
        service.adopt_local(stores[1], second_approval.id, plan.digest).reason == "approval_expired"
    )


def test_browser_coordinator_revocation_fences_its_approved_revision(fleet):
    service, _, _, targets, stores, first = fleet
    browser = FleetPolicyActor("browser-admin", coordinator=True, source="browser")
    with pytest.raises(FleetPolicyDenied):
        service.set_coordinator(browser, browser.subject)
    assert not service.head(browser).can_manage
    service.set_coordinator(ADMIN, browser.subject)
    assert service.head(browser).can_manage
    service.report_local(stores[0])
    plan = service.preview(browser, first.id, targets[:1])
    approval = service.approve(browser, plan.digest, "browser-review")

    service.set_coordinator(ADMIN, browser.subject, enabled=False)
    assert not service.head(browser).can_manage
    assert (
        service.adopt_local(stores[0], approval.id, plan.digest).reason == "approval_scope_revoked"
    )
    assert stores[0].state().applied_revision is None


def test_concurrent_writers_surface_head_conflict(fleet):
    service, _, _, _, _, first = fleet
    with ThreadPoolExecutor(max_workers=2) as executor:
        writes = [
            executor.submit(service.commit, ADMIN, first.policy, parent=first.id) for _ in range(2)
        ]
    failures = [result.exception() for result in writes if result.exception() is not None]
    assert len(failures) == 1 and isinstance(failures[0], FleetPolicyConflict)
    assert failures[0].head == service.head(ADMIN).head
