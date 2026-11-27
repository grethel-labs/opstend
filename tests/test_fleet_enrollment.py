from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest

from steward.core.fleet_enrollment import FleetEnrollment, FleetEnrollmentConflict
from steward.core.fleet_identity import FleetIdentityConflict, FleetIdentityRegistry

KEY = "12" * 32
NEXT_KEY = "34" * 32
START = datetime(2026, 11, 27, tzinfo=UTC)


@pytest.fixture
def target(tmp_path):
    registry = FleetIdentityRegistry(tmp_path / "fleet.sqlite")
    site = registry.register_site("site")
    host = registry.register_host(site.id, "host")
    return registry, registry.register_agent(host.id, "agent")


def test_mismatched_numeric_api_address_does_not_claim_the_standalone_route(target, tmp_path):
    registry, agent = target
    host = registry.get_host(agent.host_id)
    binding = "ab" * 32
    instance = registry.register_instance(host.site_id, kind="standalone", instance_binding=binding)

    def confirm(address):
        return registry.confirm_route(
            instance.id,
            host_id=host.id,
            api_name="192.0.2.10",
            node="node-a",
            instance_binding=binding,
            transport_fingerprint="cd" * 32,
            address=address,
        )

    with pytest.raises(FleetIdentityConflict, match="numeric API name must match"):
        confirm("192.0.2.11")
    route = confirm("192.0.2.10")
    reopened = FleetIdentityRegistry(tmp_path / "fleet.sqlite")
    assert reopened.get_route(route.id) == route
    approved = reopened.get_connector_route(route.id)
    assert approved.api_name == approved.address == "192.0.2.10"


def test_invitation_is_bound_to_current_target_key_and_exact_confirmed_scope(target):
    registry, agent = target
    enrollment = FleetEnrollment(registry)
    binding = "ab" * 32
    pin = "cd" * 32
    other_site = registry.register_site("other")
    other_host = registry.register_host(other_site.id, "other")
    other_instance = registry.register_instance(other_site.id, kind="cluster", instance_binding=pin)
    other_route = registry.confirm_route(
        other_instance.id,
        host_id=other_host.id,
        api_name="pve-other.internal",
        node="node-b",
        instance_binding=pin,
        transport_fingerprint=pin,
        address="192.0.2.11",
    )
    instance = registry.register_instance(
        other_site.id, kind="standalone", instance_binding=binding
    )
    unconfirmed_host = registry.register_host(other_site.id, "unconfirmed")
    unconfirmed = registry.confirm_route(
        instance.id,
        host_id=unconfirmed_host.id,
        api_name="pve-unconfirmed.internal",
        node="node-a",
        instance_binding=binding,
        transport_fingerprint=binding,
    )
    for identity, capability, route in (
        ("unknown", "heartbeat", None),
        (agent.id, "heartbeat", other_route.id),
        (agent.id, "pve_inventory", None),
        (agent.id, "pve_inventory", other_route.id),
        (
            registry.register_agent(unconfirmed_host.id, "unconfirmed-agent").id,
            "pve_inventory",
            unconfirmed.id,
        ),
    ):
        with pytest.raises(FleetEnrollmentConflict):
            enrollment.issue(identity, key_fingerprint=KEY, capability=capability, route_id=route)

    invitation = enrollment.issue(agent.id, key_fingerprint=KEY, capability="heartbeat", now=START)
    token = invitation.token.get_secret_value()
    assert token not in repr(invitation)
    with pytest.raises(FleetEnrollmentConflict):
        enrollment.redeem(token, key_fingerprint=NEXT_KEY, now=START)
    grant = enrollment.redeem(token, key_fingerprint=KEY, now=START)
    assert (grant.agent_id, grant.host_id, grant.generation) == (agent.id, agent.host_id, 1)
    with pytest.raises(FleetEnrollmentConflict):
        enrollment.connector_route(KEY)


def test_racing_single_use_expiry_rotation_and_revoke_survive_restart(target, tmp_path):
    registry, agent = target
    enrollment = FleetEnrollment(registry)
    expired = enrollment.issue(
        agent.id, key_fingerprint=KEY, capability="heartbeat", ttl_seconds=1, now=START
    )
    with pytest.raises(FleetEnrollmentConflict):
        enrollment.redeem(
            expired.token.get_secret_value(), key_fingerprint=KEY, now=START + timedelta(seconds=1)
        )

    invite = enrollment.issue(agent.id, key_fingerprint=KEY, capability="heartbeat", now=START)
    token = invite.token.get_secret_value()
    db = tmp_path / "fleet.sqlite"
    assert token.encode() not in db.read_bytes()
    start_race = Barrier(2)

    def redeem():
        current = FleetEnrollment(FleetIdentityRegistry(db))
        start_race.wait(timeout=5)
        try:
            return current.redeem(token, key_fingerprint=KEY, now=START)
        except FleetEnrollmentConflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        grants = list(pool.map(lambda _: redeem(), range(2)))

    (winner,) = [grant for grant in grants if grant is not None]
    reopened = FleetEnrollment(FleetIdentityRegistry(db))
    assert reopened.authorize(KEY, capability="heartbeat") == winner
    with pytest.raises(FleetEnrollmentConflict):
        reopened.redeem(token, key_fingerprint=KEY, now=START)
    with pytest.raises(FleetEnrollmentConflict):
        reopened.issue(agent.id, key_fingerprint=NEXT_KEY, capability="heartbeat")
    rotation = reopened.issue(
        agent.id,
        key_fingerprint=NEXT_KEY,
        capability="heartbeat",
        expected_generation=1,
        now=START,
    )
    assert (
        reopened.redeem(
            rotation.token.get_secret_value(), key_fingerprint=NEXT_KEY, now=START
        ).generation
        == 2
    )
    with pytest.raises(FleetEnrollmentConflict):
        reopened.authorize(KEY, capability="heartbeat")
    with pytest.raises(FleetEnrollmentConflict):
        reopened.issue(agent.id, key_fingerprint=KEY, capability="heartbeat", expected_generation=2)
    assert reopened.revoke(agent.id, expected_generation=2) == 3
    reopened = FleetEnrollment(FleetIdentityRegistry(db))
    with pytest.raises(FleetEnrollmentConflict):
        reopened.authorize(NEXT_KEY, capability="heartbeat")
    with pytest.raises(FleetEnrollmentConflict):
        reopened.revoke(agent.id, expected_generation=2)
