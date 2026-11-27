from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import uuid4

import pytest
from pydantic import ValidationError

from steward.core.fleet_identity import FleetIdentityRegistry
from steward.core.fleet_policy import (
    FleetLocalPolicy,
    FleetPolicy,
    FleetPolicyStore,
    FleetPolicyValues,
    FleetTarget,
    FleetTargetPolicy,
    RoleAssignment,
)
from steward.core.store import ConflictError
from test_fleet_identity import NEW_UID, REGISTERED, guest, observe, register

NOW = datetime(2026, 11, 25, tzinfo=UTC)
LOCAL_REVISION = "ab" * 32
WINDOW = "Sun 03:00 Europe/Berlin"
ROLE = RoleAssignment(subject="ops", role="operator")
ENV_REF = "env:BACKUP_PASSWORD"
FILE_REF = "file:/run/credentials/backup"


@pytest.fixture
def fleet(tmp_path):
    registry = FleetIdentityRegistry(tmp_path / "fleet.sqlite")
    site, host, instance, route = register(registry)
    return registry, site, FleetTarget(kind="host", id=host.id, generation=1), instance, route


def local_policy(target, limits, *, observed_at=NOW, revision=LOCAL_REVISION):
    return FleetLocalPolicy(
        target=target, limits=limits, observed_at=observed_at, revision=revision
    )


def effective(store, revision, target, local):
    return store.effective(
        revision.id, target, local=local, expected_local_revision=LOCAL_REVISION, now=NOW
    )


def test_effective_values_preserve_each_scope_and_explicit_empty(fleet):
    registry, site, target, _, _ = fleet
    limits = FleetPolicyValues(
        maintenance_windows=(WINDOW,),
        role_assignments=(ROLE,),
        credential_refs=(ENV_REF, FILE_REF),
        backup_profile_refs=("daily",),
    )
    store = FleetPolicyStore(registry)
    policy = FleetPolicy(
        limits=limits,
        defaults=FleetPolicyValues(maintenance_windows=(WINDOW,), credential_refs=(ENV_REF,)),
        sites={site.id: FleetPolicyValues(role_assignments=(ROLE,))},
        groups={
            "ops": FleetPolicyValues(credential_refs=(FILE_REF,)),
            "backup": FleetPolicyValues(credential_refs=(FILE_REF,)),
        },
        targets=(
            FleetTargetPolicy(
                target=target,
                group_ids=("ops", "backup"),
                exception=FleetPolicyValues(backup_profile_refs=("daily",)),
            ),
        ),
    )
    revision = store.commit(policy, parent=None)
    local = local_policy(target, limits)
    plan = effective(store, revision, target, local)
    assert (plan.status, plan.revision, plan.target, plan.issues) == (
        "ready",
        revision.id,
        target,
        (),
    )
    assert plan.values == FleetPolicyValues(
        maintenance_windows=(WINDOW,),
        role_assignments=(ROLE,),
        credential_refs=(FILE_REF,),
        backup_profile_refs=("daily",),
    )
    assert {
        name: {(source.scope, source.id) for source in sources}
        for name, sources in plan.provenance.items()
    } == {
        "maintenance_windows": {("fleet", None)},
        "role_assignments": {("site", site.id)},
        "credential_refs": {("group", "ops"), ("group", "backup")},
        "backup_profile_refs": {("target", target.id)},
    }

    narrowed = FleetTargetPolicy(
        target=target, group_ids=("ops", "backup"), exception=FleetPolicyValues(credential_refs=())
    )
    narrowed_revision = store.commit(
        policy.model_copy(update={"targets": (narrowed,)}), parent=revision.id
    )
    plan = effective(store, narrowed_revision, target, local)
    assert plan.status == "ready"
    assert plan.values.credential_refs == ()
    assert plan.values.maintenance_windows == (WINDOW,)
    assert [(source.scope, source.id) for source in plan.provenance["credential_refs"]] == [
        ("target", target.id)
    ]


def test_conflicting_groups_block_even_with_resource_exception(fleet):
    registry, _, target, _, _ = fleet
    limits = FleetPolicyValues(credential_refs=(ENV_REF,))
    store = FleetPolicyStore(registry)
    revision = store.commit(
        FleetPolicy(
            limits=limits,
            groups={
                "first": FleetPolicyValues(credential_refs=(ENV_REF,)),
                "second": FleetPolicyValues(credential_refs=()),
            },
            targets=(
                FleetTargetPolicy(
                    target=target,
                    group_ids=("second", "first"),
                    exception=FleetPolicyValues(credential_refs=()),
                ),
            ),
        ),
        parent=None,
    )
    plan = effective(store, revision, target, local_policy(target, limits))
    assert plan.status == "pending"
    (issue,) = plan.issues
    assert (issue.code, issue.property) == ("group_conflict", "credential_refs")
    assert set(issue.scope_ids) == {"first", "second"}


@pytest.mark.parametrize("code", ["fleet_limit", "local_limit"])
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("maintenance_windows", WINDOW),
        ("role_assignments", ROLE),
        ("credential_refs", ENV_REF),
        ("backup_profile_refs", "daily"),
    ],
)
def test_limits_fail_closed_for_each_policy_property(fleet, code, field, value):
    registry, _, target, _, _ = fleet
    requested = FleetPolicyValues(**{field: (value,)})
    store = FleetPolicyStore(registry)
    revision = store.commit(
        FleetPolicy(
            limits=requested if code == "local_limit" else FleetPolicyValues(),
            targets=(FleetTargetPolicy(target=target, exception=requested),),
        ),
        parent=None,
    )
    local = local_policy(target, requested if code == "fleet_limit" else FleetPolicyValues())
    plan = effective(store, revision, target, local)
    assert plan.status == "pending"
    assert {(issue.code, issue.property) for issue in plan.issues} == {(code, field)}


@pytest.mark.parametrize(
    ("observation", "age", "issue_code"),
    [
        ("missing", 0, "local_unknown"),
        ("current", 300, None),
        ("current", 301, "local_stale"),
        ("current", -1, "local_stale"),
        ("wrong_target", 0, "local_unknown"),
        ("wrong_revision", 0, "local_unknown"),
    ],
)
def test_local_snapshot_must_match_and_be_fresh(fleet, observation, age, issue_code):
    registry, site, target, _, _ = fleet
    store = FleetPolicyStore(registry)
    values = FleetPolicyValues(role_assignments=(ROLE,))
    revision = store.commit(
        FleetPolicy(defaults=values, limits=values, targets=(FleetTargetPolicy(target=target),)),
        parent=None,
    )
    observed_target = target
    if observation == "wrong_target":
        other_host = registry.register_host(site.id, "other-host")
        observed_target = FleetTarget(kind="host", id=other_host.id, generation=1)
    local = local_policy(
        observed_target,
        values,
        observed_at=NOW - timedelta(seconds=age),
        revision="cd" * 32 if observation == "wrong_revision" else LOCAL_REVISION,
    )
    plan = effective(store, revision, target, None if observation == "missing" else local)
    if issue_code is None:
        assert plan.status == "ready"
        assert plan.values == values
        assert not plan.issues
    else:
        assert plan.status == "pending"
        assert {issue.code for issue in plan.issues} == {issue_code}


def test_policy_target_is_bound_to_registered_guest_generation(fleet):
    registry, _, _, instance, route = fleet
    observe(registry, route, 1, guest())
    (original,) = registry.guest_history(instance.id, 190)
    target = FleetTarget(kind="pve_guest", id=original.id, generation=original.generation)
    wrong_generation = FleetTarget(kind="pve_guest", id=original.id, generation=2)
    store = FleetPolicyStore(registry)
    with pytest.raises(ValueError):
        store.commit(
            FleetPolicy(targets=(FleetTargetPolicy(target=wrong_generation),)), parent=None
        )
    revision = store.commit(FleetPolicy(targets=(FleetTargetPolicy(target=target),)), parent=None)
    local = local_policy(target, FleetPolicyValues())
    assert effective(store, revision, target, local).status == "ready"
    wrong_local = local_policy(wrong_generation, FleetPolicyValues())
    assert effective(store, revision, target, wrong_local).status == "pending"

    observe(registry, route, 3, guest(uid=NEW_UID, registered=REGISTERED + 1000))
    _, replacement = registry.guest_history(instance.id, 190)
    plan = effective(store, revision, target, local)
    assert plan.status == "pending"
    assert "target_unavailable" in {issue.code for issue in plan.issues}
    replacement_target = FleetTarget(
        kind="pve_guest", id=replacement.id, generation=replacement.generation
    )
    assert effective(store, revision, replacement_target, local) is None


@pytest.mark.parametrize("reference", ["target", "site", "group"])
def test_unknown_policy_reference_is_rejected_without_advancing_head(fleet, reference):
    registry, _, target, _, _ = fleet
    store = FleetPolicyStore(registry)
    root = store.commit(FleetPolicy(), parent=None)
    with pytest.raises(ValueError):
        if reference == "target":
            unknown = FleetTarget(kind="host", id=uuid4().hex, generation=1)
            policy = FleetPolicy(targets=(FleetTargetPolicy(target=unknown),))
        elif reference == "site":
            policy = FleetPolicy(sites={uuid4().hex: FleetPolicyValues()})
        else:
            policy = FleetPolicy(
                targets=(FleetTargetPolicy(target=target, group_ids=("unknown",)),)
            )
        store.commit(policy, parent=root.id)
    assert store.head() == root.id


def test_concurrent_policy_cas_and_rollback_keep_immutable_history(fleet, tmp_path):
    registry, _, target, _, _ = fleet
    store = FleetPolicyStore(registry)
    original_policy = FleetPolicy(targets=(FleetTargetPolicy(target=target),))
    first = store.commit(original_policy, parent=None)
    barrier = Barrier(2)

    def write(profile):
        writer = FleetPolicyStore(FleetIdentityRegistry(tmp_path / "fleet.sqlite"))
        parent = writer.head()
        candidate = FleetPolicy(defaults=FleetPolicyValues(backup_profile_refs=(profile,)))
        barrier.wait(timeout=10)
        try:
            return writer.commit(candidate, parent=parent)
        except ConflictError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(write, ("daily", "weekly")))
    (conflict,) = [result for result in results if isinstance(result, ConflictError)]
    (winner,) = [result for result in results if not isinstance(result, ConflictError)]
    assert conflict.head == store.head() == winner.id
    assert winner.parent == first.id
    rollback = store.commit(original_policy, parent=winner.id)

    reopened = FleetPolicyStore(FleetIdentityRegistry(tmp_path / "fleet.sqlite"))
    assert len({first.id, winner.id, rollback.id}) == 3
    assert reopened.head() == rollback.id
    assert reopened.get_revision(first.id) == first
    assert reopened.get_revision(winner.id) == winner
    assert reopened.get_revision(rollback.id).policy == first.policy
    assert rollback.parent == winner.id


def test_policy_revision_serializes_credential_references(fleet):
    registry, site, target, _, _ = fleet
    other_host = registry.register_host(site.id, "no-credentials")
    other_target = FleetTarget(kind="host", id=other_host.id)
    store = FleetPolicyStore(registry)
    values = FleetPolicyValues(credential_refs=(ENV_REF, FILE_REF))
    revision = store.commit(
        FleetPolicy(
            defaults=values,
            limits=values,
            targets=(
                FleetTargetPolicy(target=target),
                FleetTargetPolicy(
                    target=other_target, exception=FleetPolicyValues(credential_refs=())
                ),
            ),
        ),
        parent=None,
    )
    assert (
        store.get_revision(revision.id).policy.defaults.credential_refs
        == revision.policy.defaults.credential_refs
    )
    serialized = revision.export()
    assert ENV_REF in serialized and FILE_REF in serialized
    imported = type(revision).model_validate_json(serialized)
    assert imported.export() == serialized
    restored = store.commit(imported.policy, parent=revision.id)
    inherited = effective(store, restored, target, local_policy(target, values))
    cleared = effective(store, restored, other_target, local_policy(other_target, values))
    assert inherited.status == cleared.status == "ready"
    assert inherited.values.credential_refs == (ENV_REF, FILE_REF)
    assert cleared.values.credential_refs == ()


@pytest.mark.parametrize(
    "payload",
    [
        {"credential_refs": ("plaintext-password",)},
        {"credential_refs": ({"ref": ENV_REF, "value": "plaintext-password"},)},
        {"credential_refs": ("env:BACKUP_PASSWORD=plaintext-password",)},
        {"credentials": {"password": "plaintext-password"}},
        {"maintenance_windows": ("Sun 25:00 Europe/Berlin",)},
        {"backup_profile_refs": ("file:/run/credentials/backup",)},
    ],
)
def test_policy_values_reject_inline_payloads_and_malformed_references(payload):
    with pytest.raises(ValidationError):
        FleetPolicyValues(**payload)
