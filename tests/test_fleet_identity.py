from datetime import UTC, datetime, timedelta

import pytest

from steward.core.fleet_identity import FleetIdentityConflict, FleetIdentityRegistry
from steward.core.pve_inventory_models import Evidence, InventorySnapshot, parse_resources

START = datetime(2026, 11, 24, tzinfo=UTC)
REGISTERED = int(START.timestamp()) * 1000 - 1000
BINDING = "ab" * 32
PIN = "cd" * 32
OTHER_PIN = "ef" * 32
UID = "abcde23456abcde23456"
NEW_UID = "fgpqr23456fgpqr23456"


@pytest.fixture
def registry(tmp_path):
    return FleetIdentityRegistry(tmp_path / "fleet.sqlite")


def route(
    registry, host, instance, *, node="node-a", api="pve-a.internal", binding=BINDING, pin=PIN
):
    return registry.confirm_route(
        instance.id,
        host_id=host.id,
        node=node,
        api_name=api,
        instance_binding=binding,
        transport_fingerprint=pin,
    )


def register(registry, *, kind="standalone"):
    site = registry.register_site("site")
    host = registry.register_host(site.id, "host")
    instance = registry.register_instance(site.id, kind=kind, instance_binding=BINDING)
    return site, host, instance, route(registry, host, instance)


def guest(*, node="node-a", kind="qemu", uid=UID, registered=REGISTERED, name="guest"):
    return {"node": node, "type": kind, "vmid": 190, "name": name, "uid": uid, "rtime": registered}


def observe(
    registry,
    path,
    second,
    *rows,
    api="pve-a.internal",
    state="observed",
    full=False,
    binding=BINDING,
    pin=PIN,
    delay=1,
):
    observed_at = START + timedelta(seconds=second)
    evidence = Evidence(source="cluster_resources", state=state, observed_at=observed_at)
    resources = parse_resources(list(rows), evidence)
    snapshot = InventorySnapshot(
        api_name=api, evidence=evidence, observed_at=observed_at, guests=resources.guests
    )
    return registry.ingest_snapshot(
        snapshot,
        route_id=path.id,
        instance_binding=binding,
        transport_fingerprint=pin,
        full_guest_coverage=full,
        received_at=observed_at + timedelta(seconds=delay),
    )


def test_standalone_instances_keep_same_vmid_separate_across_restart(registry, tmp_path):
    site, host, first, first_route = register(registry)
    agent = registry.register_agent(host.id, "agent")
    second_host = registry.register_host(site.id, "second-host")
    binding = "12" * 32
    second = registry.register_instance(site.id, kind="standalone", instance_binding=binding)
    second_route = route(
        registry, second_host, second, api="pve-b.internal", binding=binding, pin=OTHER_PIN
    )
    observe(registry, first_route, 1, guest())
    observe(
        registry, second_route, 1, guest(), api="pve-b.internal", binding=binding, pin=OTHER_PIN
    )

    reopened = FleetIdentityRegistry(tmp_path / "fleet.sqlite")
    (one,) = reopened.guest_history(first.id, 190)
    (two,) = reopened.guest_history(second.id, 190)
    assert one.id != two.id
    assert (one.instance_id, two.instance_id) == (first.id, second.id)
    assert one.generation == two.generation == 1
    assert one.state == two.state == "present"
    assert (agent.host_id, host.site_id, first.site_id) == (host.id, site.id, site.id)
    assert reopened.get_site(site.id) == site
    assert reopened.get_host(host.id) == host
    assert reopened.get_agent(agent.id) == agent
    assert reopened.get_instance(first.id) == first
    assert reopened.get_route(first_route.id) == first_route


def test_approved_instance_is_unique_and_route_needs_both_bindings(registry):
    site, host, instance, path = register(registry, kind="cluster")
    other_site = registry.register_site("other-site")
    other_host = registry.register_host(other_site.id, "other-host")
    assert (
        registry.register_instance(site.id, kind="cluster", instance_binding=BINDING).id
        == instance.id
    )
    with pytest.raises(FleetIdentityConflict):
        registry.register_instance(other_site.id, kind="cluster", instance_binding=BINDING)
    with pytest.raises(FleetIdentityConflict):
        registry.register_instance(site.id, kind="standalone", instance_binding=BINDING)
    with pytest.raises(FleetIdentityConflict):
        route(registry, other_host, instance)
    with pytest.raises(FleetIdentityConflict):
        route(registry, host, instance, binding="12" * 32)
    with pytest.raises(FleetIdentityConflict):
        route(registry, host, instance, pin=OTHER_PIN)
    with pytest.raises(FleetIdentityConflict):
        observe(registry, path, 1, guest(), api="pve-b.internal")
    with pytest.raises(FleetIdentityConflict):
        observe(registry, path, 1, guest(), pin=OTHER_PIN)
    with pytest.raises(FleetIdentityConflict):
        observe(registry, path, 1, guest(), binding="12" * 32)
    assert registry.guest_history(instance.id, 190) == ()


def test_cluster_migration_preserves_identity_across_independently_approved_paths(registry):
    site, _, instance, path_a = register(registry, kind="cluster")
    host_b = registry.register_host(site.id, "host-b")
    path_b = route(registry, host_b, instance, node="node-b", api="pve-b.internal", pin=OTHER_PIN)
    evidence_a = observe(registry, path_a, 1, guest())
    (original,) = registry.guest_history(instance.id, 190)
    with pytest.raises(FleetIdentityConflict):
        observe(registry, path_b, 2, guest(node="node-b"), api="pve-b.internal")
    evidence_b = observe(
        registry, path_b, 2, guest(node="node-b"), api="pve-b.internal", pin=OTHER_PIN
    )
    (moved,) = registry.guest_history(instance.id, 190)
    assert (evidence_a.route_id, evidence_b.route_id) == (path_a.id, path_b.id)
    assert evidence_b.instance_id == evidence_a.instance_id == instance.id
    assert (moved.id, moved.generation, moved.state, moved.node) == (
        original.id,
        1,
        "present",
        "node-b",
    )

    observe(registry, path_a, 0, guest(name="stale"), delay=5)
    assert registry.guest_history(instance.id, 190) == (moved,)


@pytest.mark.parametrize("kind", ["qemu", "lxc"])
def test_reuse_keeps_generation_history_across_restart(registry, tmp_path, kind):
    _, _, instance, path = register(registry)
    observe(registry, path, 1, guest())
    (original,) = registry.guest_history(instance.id, 190)
    observe(registry, path, 3, guest(uid=NEW_UID, registered=REGISTERED + 1000, kind=kind))

    reopened = FleetIdentityRegistry(tmp_path / "fleet.sqlite")
    previous, current = reopened.guest_history(instance.id, 190)
    assert (previous.id, previous.generation, previous.state, previous.kind) == (
        original.id,
        1,
        "replaced",
        "qemu",
    )
    assert current.id != previous.id
    assert (current.generation, current.state, current.kind) == (2, "present", kind)
    observe(reopened, path, 2, guest(), delay=8)
    assert reopened.guest_history(instance.id, 190) == (previous, current)


def test_authoritative_reuse_resolves_an_older_pending_observation(registry):
    _, _, instance, path = register(registry)
    observe(registry, path, 1, guest())
    (original,) = registry.guest_history(instance.id, 190)
    ambiguous = observe(registry, path, 2, guest(uid=None, registered=None))
    (pending,) = registry.guest_history(instance.id, 190)
    assert (pending.id, pending.state) == (original.id, "continuity_required")

    observe(registry, path, 3, guest(uid=NEW_UID, registered=REGISTERED + 1000))
    previous, current = registry.guest_history(instance.id, 190)
    assert (previous.id, previous.state) == (original.id, "replaced")
    assert (current.generation, current.state) == (2, "present")
    with pytest.raises(FleetIdentityConflict):
        registry.confirm_continuity(
            instance.id, 190, generation=1, observation_id=ambiguous.id, same_guest=True
        )


@pytest.mark.parametrize("conflicting_state", ["observed", "absent"])
def test_conflicting_retry_invalidates_ambiguous_confirmation(registry, conflicting_state):
    _, _, instance, path = register(registry)
    observe(registry, path, 1, guest())
    pending = observe(registry, path, 2, guest(uid=None, registered=None))
    exact_retry = observe(registry, path, 2, guest(uid=None, registered=None), delay=2)
    assert exact_retry.id == pending.id

    replacement = (guest(uid=NEW_UID, registered=REGISTERED + 1000),)
    conflicting_roster = replacement if conflicting_state == "observed" else ()
    with pytest.raises(FleetIdentityConflict):
        observe(registry, path, 2, *conflicting_roster, state=conflicting_state)
    with pytest.raises(FleetIdentityConflict):
        registry.confirm_continuity(
            instance.id, 190, generation=1, observation_id=pending.id, same_guest=True
        )


@pytest.mark.parametrize("returning_uid", [UID, None])
def test_only_full_successful_scope_proves_absence(registry, returning_uid):
    _, _, instance, path = register(registry)
    observe(registry, path, 1, guest())
    (original,) = registry.guest_history(instance.id, 190)
    partial = observe(registry, path, 2)
    failed = observe(registry, path, 4, state="unavailable", full=True)
    assert (partial.coverage, failed.state) == ("token_scope", "unavailable")
    with pytest.raises(ValueError):
        observe(registry, path, 3, full="false")
    assert registry.guest_history(instance.id, 190) == (original,)

    complete = observe(registry, path, 3, full=True)
    assert complete.coverage == "full_guest_coverage"
    (missing,) = registry.guest_history(instance.id, 190)
    assert (missing.id, missing.state, missing.observation_id) == (
        original.id,
        "missing",
        complete.id,
    )
    observe(registry, path, 5, guest(uid=returning_uid))
    (uncertain,) = registry.guest_history(instance.id, 190)
    assert (uncertain.id, uncertain.state) == (original.id, "continuity_required")


@pytest.mark.parametrize("same_guest", [True, False])
@pytest.mark.parametrize("registered", [REGISTERED, REGISTERED - 1000])
def test_ambiguous_reuse_confirmation_binds_current_generation_and_observation(
    registry, same_guest, registered
):
    _, _, instance, path = register(registry)
    observe(registry, path, 1, guest())
    (original,) = registry.guest_history(instance.id, 190)
    first = observe(registry, path, 2, guest(uid=NEW_UID, registered=registered))
    current = observe(registry, path, 3, guest(uid=NEW_UID, registered=registered, name="renamed"))
    (uncertain,) = registry.guest_history(instance.id, 190)
    assert (uncertain.id, uncertain.state, uncertain.observation_id) == (
        original.id,
        "continuity_required",
        current.id,
    )
    for generation, observation_id in [(1, first.id), (2, current.id)]:
        with pytest.raises(FleetIdentityConflict):
            registry.confirm_continuity(
                instance.id,
                190,
                generation=generation,
                observation_id=observation_id,
                same_guest=same_guest,
            )
    confirmed = registry.confirm_continuity(
        instance.id, 190, generation=1, observation_id=current.id, same_guest=same_guest
    )
    assert confirmed.state == "present"
    if same_guest:
        assert confirmed.id == original.id
        assert registry.guest_history(instance.id, 190) == (confirmed,)
    else:
        previous, new = registry.guest_history(instance.id, 190)
        assert previous.id == original.id and previous.state == "replaced"
        assert new == confirmed and new.id != original.id and new.generation == 2
    with pytest.raises(FleetIdentityConflict):
        registry.confirm_continuity(
            instance.id, 190, generation=1, observation_id=current.id, same_guest=same_guest
        )


def test_public_projections_and_repr_omit_private_identity_evidence(registry):
    _, _, instance, path = register(registry)
    observation = observe(registry, path, 1, guest(), delay=5)
    (current,) = registry.guest_history(instance.id, 190)
    assert observation.observed_at == START + timedelta(seconds=1)
    assert observation.received_at == START + timedelta(seconds=6)
    for model in (instance, path, observation, current):
        for projection in (repr(model), model.model_dump_json()):
            for private in (BINDING, PIN, UID, str(REGISTERED)):
                assert private not in projection


def test_relative_database_path_stays_bound_after_working_directory_change(tmp_path, monkeypatch):
    other_directory = tmp_path / "other"
    other_directory.mkdir()
    monkeypatch.chdir(tmp_path)
    registry = FleetIdentityRegistry("fleet.sqlite")
    site = registry.register_site("first")
    monkeypatch.chdir(other_directory)

    assert registry.get_site(site.id) == site
    assert not (other_directory / "fleet.sqlite").exists()


@pytest.mark.parametrize("disappeared", [False, True])
def test_first_guest_without_native_identity_requires_current_confirmation(registry, disappeared):
    _, _, instance, path = register(registry)
    observation = observe(registry, path, 1, guest(uid=None, registered=None))
    (original,) = registry.guest_history(instance.id, 190)
    assert (original.generation, original.state, original.observation_id) == (
        1,
        "continuity_required",
        observation.id,
    )
    confirmation = {"generation": 1, "observation_id": observation.id, "same_guest": True}
    if disappeared:
        observe(registry, path, 2, full=True)
        with pytest.raises(FleetIdentityConflict):
            registry.confirm_continuity(instance.id, 190, **confirmation)
    else:
        confirmed = registry.confirm_continuity(instance.id, 190, **confirmation)
        assert (confirmed.id, confirmed.generation, confirmed.state) == (original.id, 1, "present")
