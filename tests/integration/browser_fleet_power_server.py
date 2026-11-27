"""Run the real Fleet Admin against a disposable coordinator and simulated target reports."""

from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

import uvicorn
from fastapi import HTTPException, Request

from steward.api import app as api
from steward.core.fleet_enrollment import FleetEnrollment
from steward.core.fleet_identity import FleetIdentityRegistry
from steward.core.fleet_policy import (
    FleetPolicy,
    FleetPolicyValues,
    FleetTarget,
    FleetTargetPolicy,
    RoleAssignment,
)
from steward.core.fleet_policy_apply import FleetPolicyActor, FleetPolicyApply
from steward.core.fleet_policy_target import FleetPolicyTargetConfig, FleetPolicyTargetStore
from steward.core.fleet_power import CommandPoll, CommandReport
from steward.core.fleet_power_commands import FleetPowerCommands
from steward.core.pve_inventory_models import Evidence, InventorySnapshot, parse_resources

TOKEN = "browser-fleet-power-fixture-0123456789abcdefghijklmnopqrstuvwxyz"
ORIGIN = "http://localhost:19082"
FINGERPRINT = "9a" * 32


def seed(registry, root):
    now = datetime.now(UTC)
    site = registry.register_site("power-lab")
    host = registry.register_host(site.id, "browser-pve")
    binding, fingerprint = "ab" * 32, "cd" * 32
    instance = registry.register_instance(site.id, kind="standalone", instance_binding=binding)
    route = registry.confirm_route(
        instance.id,
        host_id=host.id,
        node="browser-pve",
        api_name="browser-pve.internal",
        address="192.168.10.10",
        instance_binding=binding,
        transport_fingerprint=fingerprint,
    )
    evidence = Evidence(source="cluster_resources", state="observed", observed_at=now)
    resources = parse_resources(
        [
            {
                "node": route.node,
                "type": "qemu",
                "vmid": 190,
                "name": "power-fixture",
                "uid": "abcde23456abcde23456",
                "rtime": int(now.timestamp()) * 1000 - 1000,
            }
        ],
        evidence,
    )
    registry.ingest_snapshot(
        InventorySnapshot(
            api_name=route.api_name, evidence=evidence, observed_at=now, guests=resources.guests
        ),
        route_id=route.id,
        instance_binding=binding,
        transport_fingerprint=fingerprint,
        full_guest_coverage=True,
        received_at=now,
    )
    (guest,) = registry.guest_history(instance.id, 190)
    target = FleetTarget(kind="pve_guest", id=guest.id, generation=guest.generation)
    actor = FleetPolicyActor(subject="browser-power-fixture", coordinator=True)
    policy = FleetPolicyApply(registry)
    policy.set_coordinator(actor, actor.subject)
    limits = FleetPolicyValues(
        role_assignments=(RoleAssignment(subject=actor.subject, role="operator"),)
    )
    revision = policy.commit(
        actor,
        FleetPolicy(defaults=limits, limits=limits, targets=(FleetTargetPolicy(target=target),)),
        parent=None,
    )
    target_store = FleetPolicyTargetStore.configure(
        root / "target.sqlite", FleetPolicyTargetConfig(target=target, limits=limits)
    )
    policy.report_local(target_store)
    prepared = policy.preview(actor, revision.id, (target,))
    approved = policy.approve(actor, prepared.digest, "browser-fixture-policy")
    policy.adopt_local(target_store, approved.id, prepared.digest)
    local = target_store.state()

    enrollment = FleetEnrollment(registry)
    agent = registry.register_agent(host.id, "browser-power-target")
    invitation = enrollment.issue(
        agent.id, key_fingerprint=FINGERPRINT, capability="pve_power_target", target=target
    )
    enrollment.redeem(invitation.token.get_secret_value(), key_fingerprint=FINGERPRINT)
    return actor, CommandPoll(
        target=target,
        local_revision=local.local.revision,
        policy_revision=revision.id,
        policy_approval=approved.id,
    )


def main():
    with TemporaryDirectory(prefix="opstend-browser-power-") as directory:
        root = Path(directory)
        database = root / "fleet.sqlite"
        registry = FleetIdentityRegistry(database)
        actor, poll = seed(registry, root)
        commands = FleetPowerCommands(registry)
        api.STATIC_DIR = Path(__file__).resolve().parents[2] / "webapp" / "dist"
        app = api.create_app(
            api.Settings(
                state_dir=root / "api",
                allowed_origins=(ORIGIN,),
                token=TOKEN,
                fleet_policy_db=database,
                fleet_policy_subject=actor.subject,
            )
        )

        @app.post("/__browser_fixture__/fleet/power-tick")
        def tick(request: Request):
            if request.headers.get("x-browser-fixture-token") != TOKEN:
                raise HTTPException(403)
            work = commands.poll(FINGERPRINT, poll).work
            if work is None:
                return {"phase": None}
            reports = {
                "prepare": {"state": "prepared"},
                "execute": {"state": "accepted", "task_ref": "ef" * 32},
                "reconcile": {
                    "state": "succeeded",
                    "task_ref": "ef" * 32,
                    "observed_state": "running",
                },
            }
            report = CommandReport(
                command_id=work.spec.command_id,
                claim_id=work.claim_id,
                native_digest=work.native_digest or "dd" * 32,
                **reports[work.phase],
            )
            commands.poll(FINGERPRINT, poll.model_copy(update={"report": report}))
            return {"phase": work.phase}

        uvicorn.run(app, host="127.0.0.1", port=19082, access_log=False, log_level="warning")


if __name__ == "__main__":
    main()
