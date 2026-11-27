"""Disposable coordinator and one co-located target for browser policy checks."""

from pathlib import Path
from tempfile import TemporaryDirectory

import uvicorn
from fastapi import HTTPException, Request

from steward.api import app as api
from steward.core.fleet_identity import FleetIdentityRegistry
from steward.core.fleet_policy import FleetPolicy, FleetPolicyValues, FleetTarget, FleetTargetPolicy
from steward.core.fleet_policy_apply import FleetPolicyActor, FleetPolicyApply
from steward.core.fleet_policy_target import FleetPolicyTargetConfig, FleetPolicyTargetStore

TOKEN = "browser-test-token-" + "0123456789abcdefghijklmnopqrstuvwxyz"


def main():
    with TemporaryDirectory(prefix="opstend-browser-fleet-") as directory:
        root = Path(directory)
        database = root / "fleet.db"
        registry = FleetIdentityRegistry(database)
        policy = FleetPolicyApply(registry)
        actor = FleetPolicyActor(subject="browser-fixture", coordinator=True)
        policy.set_coordinator(actor, actor.subject)
        site = registry.register_site("lab")
        online = FleetTarget(kind="host", id=registry.register_host(site.id, "online").id)
        offline = FleetTarget(kind="host", id=registry.register_host(site.id, "offline").id)
        limits = FleetPolicyValues(credential_refs=("env:FLEET_FIXTURE_REFERENCE",))
        policy.commit(
            actor,
            FleetPolicy(
                defaults=limits,
                limits=limits,
                targets=(FleetTargetPolicy(target=online), FleetTargetPolicy(target=offline)),
            ),
            parent=None,
        )
        target = FleetPolicyTargetStore.configure(
            root / "target.db", FleetPolicyTargetConfig(target=online, limits=limits)
        )
        policy.report_local(target)
        api.STATIC_DIR = Path(__file__).resolve().parents[2] / "webapp" / "dist"
        app = api.create_app(
            api.Settings(
                state_dir=root / "api",
                allowed_origins=("http://localhost:19081",),
                token=TOKEN,
                fleet_policy_db=database,
                fleet_policy_subject=actor.subject,
            )
        )

        @app.post("/__browser_fixture__/fleet/adopt")
        def adopt(request: Request, approval: str, digest: str):
            if request.headers.get("x-browser-fixture-token") != TOKEN:
                raise HTTPException(403)
            return policy.adopt_local(target, approval, digest)

        uvicorn.run(app, host="127.0.0.1", port=19081, access_log=False, log_level="warning")


if __name__ == "__main__":
    main()
