import hashlib
import hmac
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from steward import bot
from steward.adapters.queries import DiscordQuery, QueryError, SignedQuery
from steward.core.config import QueryEndpoint

KEY = "s" * 32
NOW = 1000


@pytest.fixture(params=["webhook", "discord"])
def transport(request):
    if request.param == "webhook":
        adapter = SignedQuery(KEY)

        def encode(command="status", id="one", user="alice", tenant="team", now=NOW):
            body = json.dumps(
                {"v": 1, "id": id, "tenant": tenant, "user": user, "command": command}
            ).encode()
            stamp = str(now)
            signature = hmac.new(
                KEY.encode(), stamp.encode() + b"." + body, hashlib.sha256
            ).hexdigest()
            return body, {"x-steward-timestamp": stamp, "x-steward-signature": "v1=" + signature}
    else:
        private = Ed25519PrivateKey.generate()
        adapter = DiscordQuery(private.public_key().public_bytes_raw().hex(), "123")

        def encode(command="status", id="one", user="alice", tenant="team", now=NOW):
            body = json.dumps(
                {
                    "id": id,
                    "type": 2,
                    "application_id": "123",
                    "guild_id": tenant,
                    "member": {"user": {"id": user}},
                    "data": {"name": command},
                }
            ).encode()
            stamp = str(now)
            return body, {
                "x-signature-timestamp": stamp,
                "x-signature-ed25519": private.sign(stamp.encode() + body).hex(),
            }

    return adapter, encode


def service(tmp_path, transport, info=None):
    adapter, encode = transport
    endpoint = QueryEndpoint(
        id="ops",
        adapter="webhook",
        verification_key_ref="env:KEY",
        grants=[
            {"tenant": "team", "user": "alice", "projects": ["notes"]},
        ],
    )
    information = info or bot.Information(tmp_path / "snapshot.json", "no-collector.sock")
    return bot.Service(
        tmp_path / "bot.db", {"ops": adapter}, {"ops": endpoint}, information
    ), encode


def test_contract_authenticates_identity_and_limits_commands(transport):
    adapter, encode = transport
    body, headers = encode()
    query = adapter.decode(body, headers, now=NOW)
    assert (query.tenant, query.user, query.command) == ("team", "alice", "status")
    with pytest.raises(QueryError, match="invalid_signature"):
        adapter.decode(body + b" ", headers, now=NOW)
    with pytest.raises(QueryError, match="expired"):
        adapter.decode(body, headers, now=NOW + 301)
    body, headers = encode(command="restart")
    with pytest.raises(QueryError, match="unknown_command"):
        adapter.decode(body, headers, now=NOW)


def test_authorization_happens_before_any_data_read(tmp_path, transport):
    class ForbiddenReads:
        def answer(self, *args, **kw):
            pytest.fail("unauthorized request reached data reader")

    svc, encode = service(tmp_path, transport, ForbiddenReads())
    for user, tenant in [("mallory", "team"), ("alice", "other")]:
        body, headers = encode(user=user, tenant=tenant)
        with pytest.raises(QueryError, match="forbidden"):
            svc.process("ops", body, headers, now=NOW)


def test_status_scopes_projects_and_reports_staleness(tmp_path, transport):
    svc, encode = service(tmp_path, transport)
    snapshot = {
        "generated_at": NOW,
        "status_ok": True,
        "status": {
            "projects": {
                "notes": {"unit": {"active": "active"}, "health": {"ok": True}},
                "secret-project": {"unit": {"active": "failed"}},
            },
            "kill_switch": True,
        },
    }
    (tmp_path / "snapshot.json").write_text(json.dumps(snapshot))
    body, headers = encode()
    result = json.dumps(svc.process("ops", body, headers, now=NOW))
    assert (
        "notes: active" in result and "secret-project" not in result and "Kill switch" not in result
    )
    body, headers = encode(id="two", now=NOW + 121)
    assert "stale" in json.dumps(svc.process("ops", body, headers, now=NOW + 121))


def test_retry_cache_and_conflicting_request_id_are_persistent(tmp_path, transport):
    svc, encode = service(tmp_path, transport)
    body, headers = encode(command="help")
    result = svc.process("ops", body, headers, now=NOW)
    restarted, _ = service(tmp_path, transport)
    assert restarted.process("ops", body, headers, now=NOW) == result
    body, headers = encode(command="backups")
    with pytest.raises(QueryError, match="replay_conflict"):
        svc.process("ops", body, headers, now=NOW)


def test_rate_limit_is_per_authorized_identity(tmp_path, transport):
    svc, encode = service(tmp_path, transport)
    for i in range(30):
        body, headers = encode(command="help", id=str(i))
        svc.process("ops", body, headers, now=NOW)
    body, headers = encode(command="help", id="too-many")
    with pytest.raises(QueryError, match="rate_limited"):
        svc.process("ops", body, headers, now=NOW)


def test_http_endpoint_validates_body_and_signature(tmp_path, transport, monkeypatch):
    svc, encode = service(tmp_path, transport)
    monkeypatch.setattr(bot.time, "time", lambda: NOW)
    client = TestClient(bot.create_app(svc))
    body, headers = encode(command="help")
    assert client.post("/bot/ops", content=body, headers=headers).status_code == 200
    assert client.post("/bot/ops", content=body + b"x", headers=headers).status_code == 401
    assert client.post("/bot/ops", content=b"x" * 16385).status_code == 413
    assert client.post("/bot/unknown", content=body, headers=headers).status_code == 404


def test_queries_filter_at_collector_boundary_and_do_not_claim_success(
    tmp_path, transport, monkeypatch
):
    svc, encode = service(tmp_path, transport)
    seen = []

    def read(action, params, **kw):
        seen.append(params)
        return {"events": [], "coverage": {"lag_s": 1, "open_gaps": []}}

    monkeypatch.setattr(bot, "call", read)
    for command in ("updates",):
        body, headers = encode(command=command, id=command)
        assert "unknown" in json.dumps(svc.process("ops", body, headers, now=NOW))
    assert all(params["project"] == "notes" for params in seen)
    assert {params["kind_prefix"] for params in seen} == {"vulnerability."}


def test_discord_ping_is_signed_and_does_not_read_data():
    private = Ed25519PrivateKey.generate()
    adapter = DiscordQuery(private.public_key().public_bytes_raw().hex(), "123")
    body = b'{"type":1,"application_id":"123"}'
    headers = {
        "x-signature-timestamp": str(NOW),
        "x-signature-ed25519": private.sign(str(NOW).encode() + body).hex(),
    }
    assert adapter.decode(body, headers, now=NOW).ping


def test_query_contract_metadata_and_health(transport):
    adapter, _ = transport
    assert adapter.version == 1 and adapter.health()
    assert "query.authenticate" in adapter.capabilities
    assert adapter.timeout_s <= 2
    assert adapter.input_schema["type"] == "object"


def test_discord_responses_are_private_and_bounded_in_utf16():
    private = Ed25519PrivateKey.generate()
    adapter = DiscordQuery(private.public_key().public_bytes_raw().hex(), "123")
    response = adapter.response("😀" * 1800)
    assert len(response["data"]["content"].encode("utf-16-le")) <= 3600
    assert response["data"]["flags"] == 64
    assert response["data"]["allowed_mentions"] == {"parse": []}


def test_backup_snapshot_respects_project_grant_and_partial_evidence(tmp_path, transport):
    svc, encode = service(tmp_path, transport)
    snapshot = {
        "generated_at": NOW,
        "status_ok": True,
        "status": {
            "backup_enabled": True,
            "config_revision": "a" * 64,
            "projects": {"notes": {}, "secret-project": {}},
            "backup_schedule_observations": {
                "notes": {
                    "state": "exported",
                    "config_revision": "a" * 64,
                    "capture_id": "b" * 64,
                    "capture_created_at": NOW - 30,
                    "interval_s": 3600,
                    "provenance": "executor_schedule",
                }
            },
        },
        "backup_observations": {
            "notes": {
                "state": "failed",
                "uploaded_at": NOW - 20,
                "integrity_checked_at": NOW - 10,
                "restored_bytes_at": None,
                "worker_provenance": "worker_reported",
            },
            "secret-project": {"state": "reported"},
        },
    }
    (tmp_path / "snapshot.json").write_text(json.dumps(snapshot))
    body, headers = encode(command="backups", id="backup-view")
    result = json.dumps(svc.process("ops", body, headers, now=NOW))
    assert "notes: capture exported" in result and "worker failed" in result
    assert "restored bytes unknown" in result and "application drill unknown" in result
    assert "secret-project" not in result
    body, headers = encode(command="backups", id="backup-stale", now=NOW + 121)
    assert "stale or unavailable" in json.dumps(svc.process("ops", body, headers, now=NOW + 121))
    snapshot["status"]["backup_enabled"] = False
    (tmp_path / "snapshot.json").write_text(json.dumps(snapshot))
    body, headers = encode(command="backups", id="backup-disabled")
    assert "disabled" in json.dumps(svc.process("ops", body, headers, now=NOW))
