from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from steward.api.app import COOKIE, Settings, StartupError, create_app
from steward.core.fleet_identity import FleetIdentityRegistry
from steward.core.fleet_policy_apply import FleetPolicyActor, FleetPolicyApply, FleetPolicyGrant

ORIGIN = "https://localhost:9443"
TOKEN = "0123456789abcdefghijklmnopqrstuvwxyz" * 2
PREFIX = "/api/fleet/policy"


@pytest.fixture
def coordinator(tmp_path):
    directory = tmp_path / "coordinator"
    directory.mkdir(mode=0o700)
    db = directory / "fleet.db"
    registry = FleetIdentityRegistry(db)
    FleetPolicyApply(registry).set_coordinator(
        FleetPolicyActor("local", coordinator=True), "manager"
    )
    targets = []
    for name in ("north", "south"):
        site = registry.register_site(name)
        host = registry.register_host(site.id, "web")
        targets.append({"kind": "host", "id": host.id, "generation": 1})
        if name == "north":
            FleetPolicyApply(registry).set_grant(
                FleetPolicyActor("local", coordinator=True),
                FleetPolicyGrant("operator", "write", site_id=site.id),
            )
    settings = Settings(
        state_dir=tmp_path / "sessions",
        allowed_origins=(ORIGIN,),
        token=TOKEN,
        start_worker=False,
        fleet_policy_db=db,
        fleet_policy_subject="manager",
    )
    return settings, targets


def login(settings):
    client = TestClient(create_app(settings), base_url=ORIGIN, headers={"Origin": ORIGIN})
    response = client.post("/api/login", json={"token": TOKEN})
    assert response.status_code == 200
    client.headers["X-CSRF-Token"] = response.json()["csrf"]
    return client


def test_policy_revision_preview_approval_and_rollback(coordinator):
    settings, targets = coordinator
    client = login(settings)
    policy = {
        "defaults": {"credential_refs": ["env:FLEET_BACKUP_TOKEN"]},
        "targets": [{"target": target} for target in targets],
    }
    assert client.get("/api/session").json()["fleet_policy"] is True
    first = client.post(PREFIX + "/revisions", json={"policy": policy, "parent": None})
    assert first.status_code == 200
    revision = first.json()["id"]
    exported = client.get(PREFIX + "/revisions/" + revision)
    policy["targets"].sort(key=lambda item: item["target"]["id"])
    assert exported.json() == first.json()
    assert exported.json()["policy"] == policy

    conflict = client.post(PREFIX + "/revisions", json={"policy": {}, "parent": None})
    assert conflict.status_code == 409
    assert conflict.json() == {"head": revision, "message": "fleet policy has changed"}
    assert client.get(PREFIX + "/revisions/" + "f" * 64).status_code == 404

    preview = client.post(PREFIX + "/preview", json={"revision": revision, "targets": targets})
    assert preview.status_code == 200
    digest = preview.json()["digest"]
    body = {"digest": digest}
    assert client.post(PREFIX + "/approve", json=body).status_code == 422
    approval_headers = {"Idempotency-Key": "review-1"}
    approved = client.post(PREFIX + "/approve", json=body, headers=approval_headers)
    assert approved.status_code == 200
    assert approved.json()["revision"] == revision
    assert {item["status"] for item in approved.json()["outcomes"]} == {"pending"}
    replay = client.post(PREFIX + "/approve", json=body, headers=approval_headers)
    assert replay.json() == approved.json()
    approval_id = approved.json()["id"]
    assert client.get(PREFIX + "/approvals/" + approval_id).json() == approved.json()

    second = client.post(PREFIX + "/revisions", json={"policy": {}, "parent": revision}).json()
    assert client.get(PREFIX).json()["approval_ids"] == [approval_id]
    rolled = client.post(PREFIX + "/rollback", json={"revision": revision, "parent": second["id"]})
    assert rolled.status_code == 200
    assert rolled.json()["parent"] == second["id"]
    assert rolled.json()["id"] != revision
    assert rolled.json()["policy"] == policy


def test_scoped_session_permissions_and_request_guards(coordinator):
    settings, targets = coordinator
    manager = login(settings)
    policy = {"targets": [{"target": target} for target in targets]}
    revision = manager.post(PREFIX + "/revisions", json={"policy": policy, "parent": None})
    revision_id = revision.json()["id"]
    scoped_settings = replace(settings, fleet_policy_subject="operator")
    anon = TestClient(create_app(scoped_settings), base_url=ORIGIN)
    assert anon.get(PREFIX).status_code == 401
    anon.cookies.set(COOKIE, manager.cookies.get(COOKIE))
    assert anon.get(PREFIX).status_code == 401

    scoped = login(scoped_settings)
    assert scoped.get("/api/status").status_code == 404
    assert scoped.get("/api/config").status_code == 404
    assert "api/status" not in {route.path.lstrip("/") for route in scoped.app.routes}
    head = scoped.get(PREFIX).json()
    assert head["head"] == revision_id
    assert head["can_manage"] is False
    assert [item["target"] for item in head["targets"]] == targets[:1]
    assert scoped.get(PREFIX + "/revisions/" + revision_id).status_code == 403
    assert (
        scoped.post(PREFIX + "/revisions", json={"policy": policy, "parent": None}).status_code
        == 403
    )

    body = {"revision": revision_id, "targets": targets[:1]}
    assert scoped.post(PREFIX + "/preview", json=body).status_code == 200
    assert scoped.post(PREFIX + "/preview", json={**body, "targets": targets}).status_code == 404
    assert (
        scoped.post(PREFIX + "/preview", json=body, headers={"X-CSRF-Token": ""}).status_code == 403
    )
    assert (
        scoped.post(
            PREFIX + "/preview", json=body, headers={"Origin": "https://other.invalid"}
        ).status_code
        == 403
    )
    assert scoped.get(PREFIX, headers={"Host": "other.invalid"}).status_code == 421


def test_invalid_json_does_not_echo_input(coordinator):
    settings, targets = coordinator
    client = login(settings)
    sensitive = "credential-value-that-must-not-be-returned"
    malformed = '{"policy":{"defaults":{"credential_refs":["' + sensitive + '"]}},"parent":null}'
    duplicate = '{"policy":{"' + sensitive + '":0,"' + sensitive + '":1},"parent":null}'
    response_bodies = [
        client.post(PREFIX + "/revisions", content=malformed),
        client.post(PREFIX + "/revisions", content=duplicate),
        client.post(
            PREFIX + "/preview",
            json={"revision": "a" * 64, "targets": [{**targets[0], "generation": "1"}]},
        ),
        client.post("/api/login", json={"token": [sensitive]}),
        client.get(PREFIX + "/revisions/" + sensitive),
    ]
    for response in response_bodies:
        assert response.status_code == 422
        assert sensitive not in response.text


def test_requires_explicit_private_coordinator_database(coordinator, tmp_path):
    settings, _ = coordinator
    host_settings = replace(settings, fleet_policy_db=None, fleet_policy_subject=None)
    ordinary = login(host_settings)
    assert ordinary.get("/api/session").json()["fleet_policy"] is False
    assert ordinary.get(PREFIX).status_code == 404

    with pytest.raises(StartupError):
        create_app(replace(settings, fleet_policy_subject=None))
    with pytest.raises(StartupError):
        create_app(replace(settings, fleet_policy_db=tmp_path / "missing.db"))
    settings.fleet_policy_db.chmod(0o644)
    with pytest.raises(StartupError):
        create_app(settings)
