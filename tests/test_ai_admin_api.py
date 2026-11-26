"""Admin API for AI onboarding: session/CSRF/idempotency and the read model."""
# ruff: noqa: F811

from __future__ import annotations

import json
import os
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from steward import inference_worker
from steward.adapters import inference
from steward.api.app import MAX_BODY_BYTES, Settings, StartupError, create_app
from steward.core.ai_admin import AdminControl
from steward.core.ai_admin_ipc import CANDIDATE_SCOPE_CODE, MANAGED_SOCKET, AdminPeer
from steward.core.ai_onboarding import Onboarding
from steward.core.config import Ai
from steward.core.fx_rate import FxStore
from steward.core.ipc import MAX_MESSAGE_BYTES
from steward.core.model_selection import SelectionStore
from steward.core.model_sources import SourceStore
from steward.executor import protocol
from steward.executor.protocol import ExecutorError
from test_ai_admin_ipc import (
    admin_peer,  # noqa: F401 (fixture)
    backend_state,  # noqa: F401 (fixture)
    encode,
    make_server,  # noqa: F401 (fixture)
    managed_listener,  # noqa: F401 (fixture)
    serving,
    trust_listener_parent,  # noqa: F401 (fixture)
)
from test_api import ORIGIN, TOKEN, anon, app, client, settings  # noqa: F401  (fixtures)


def key(n):
    return {"Idempotency-Key": f"key-{n:08d}"}


def test_requires_a_session_csrf_and_idempotency_key(app, client, anon):  # noqa: F811
    assert anon.get("/api/ai").status_code == 401
    assert anon.post("/api/ai/auto", json={"enabled": True}).status_code in (401, 403)
    no_csrf = TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN})
    no_csrf.post("/api/login", json={"token": TOKEN})
    assert no_csrf.post("/api/ai/scan", headers=key(1)).status_code == 403
    assert client.post("/api/ai/scan").status_code == 400  # Idempotency-Key required
    assert client.post("/api/ai/scan", headers={"Idempotency-Key": "short"}).status_code == 400


def test_read_model_starts_empty_and_marks_defaults_unverified(client):
    view = client.get("/api/ai").json()
    assert view["status"] == "none" and view["active"] is None and view["report"] is None
    assert view["sources"]["mode"] == "propose_confirm" and view["defaults_status"] == "UNVERIFIED"
    options = {o["id"]: o for o in view["options"]}
    assert not options["claude-subscription"]["available"] and options["anthropic-api"]["available"]
    assert view["exchange_rate"] is None
    assert all(option["runtime_enabled"] is False for option in view["options"])


def test_provider_choice_rejects_literal_keys_and_replays_by_idempotency_key(client):
    bad = client.post("/api/ai/provider", json={"option": "anthropic-api", "key_ref": "sk-live-abc"},
                      headers=key(1))  # fmt: skip
    assert bad.status_code == 422 and bad.json()["detail"]["code"] == "api_key_reference_required"
    ok = client.post("/api/ai/provider", json={"option": "anthropic-api", "key_ref": "env:K"},
                     headers=key(2))  # fmt: skip
    assert ok.status_code == 200 and ok.json()["status"] == "provider_chosen"
    replay = client.post("/api/ai/provider", json={"option": "anthropic-api", "key_ref": "env:K"},
                         headers=key(2))  # fmt: skip
    assert replay.json() == ok.json()
    again = client.post("/api/ai/provider", json={"option": "openai-api", "key_ref": "env:O"},
                        headers=key(3))  # fmt: skip
    assert again.status_code == 422 and again.json()["detail"]["code"] == "provider_already_chosen"
    unknown = client.post("/api/ai/provider", json={"option": "x-y-z", "extra": 1}, headers=key(4))
    assert unknown.status_code == 422


def test_scan_and_best_now_are_recorded_requests_not_provider_calls(client):
    first = client.post("/api/ai/scan", headers=key(1))
    assert first.status_code == 202 and first.json()["state"] == "pending"
    second = client.post("/api/ai/scan", headers=key(2))
    assert second.json()["id"] == first.json()["id"]  # one pending request per kind
    view = client.get("/api/ai").json()
    assert [r["kind"] for r in view["requests"]] == ["scan"]


def test_source_management_in_every_mode_and_audit(client):
    added = client.post("/api/ai/sources", json={"url": "https://a.example.org/p",
                        "parser": "json_comparison_v1"}, headers=key(1))  # fmt: skip
    assert added.status_code == 200
    assert client.post("/api/ai/sources", json={"url": "http://a.example.org/p",
                       "parser": "json_comparison_v1"}, headers=key(2)).status_code == 422  # fmt: skip
    for n, mode in enumerate(("allowlist", "fixed", "automatic", "propose_confirm"), start=10):
        assert (
            client.post("/api/ai/source-mode", json={"mode": mode}, headers=key(n)).status_code
            == 200
        )
    assert (
        client.post("/api/ai/source-mode", json={"mode": "chaos"}, headers=key(20)).status_code
        == 422
    )
    sid = added.json()["id"]
    removed = client.delete(f"/api/ai/sources/{sid}", headers=key(30))
    assert removed.status_code == 200
    view = client.get("/api/ai").json()["sources"]
    assert view["list"] == [] and view["mode"] == "propose_confirm"
    events = [(a["actor"], a["event"]) for a in view["audit"]]
    assert ("operator", "added") in events and ("operator", "removed") in events
    assert events.count(("operator", "mode_changed")) == 4


def test_pin_and_auto_need_a_finished_onboarding(client):
    assert client.post("/api/ai/auto", json={"enabled": True}, headers=key(1)).status_code == 422
    assert client.post("/api/ai/pin", json={"model": "m"}, headers=key(2)).status_code == 422
    assert client.post("/api/ai/best-now", headers=key(3)).status_code == 202  # recorded only


def test_local_download_refusal_uses_real_host_facts_not_client_values(client):
    # the API reads RAM/disk itself: a declaration beyond this host's limits is refused
    body = {"option": "ollama-local", "local": {"model": "m", "sha256": "a" * 64,
            "download_mb": 10**6, "ram_mb": 10**6, "disk_mb": 10**7, "license_ack": True}}  # fmt: skip
    r = client.post("/api/ai/provider", json=body, headers=key(1))
    assert r.status_code == 422 and r.json()["detail"]["code"] == "resource_refused"
    assert client.get("/api/ai").json()["status"] == "none"


def login(application):
    browser = TestClient(application, base_url=ORIGIN, headers={"Origin": ORIGIN})
    response = browser.post("/api/login", json={"token": TOKEN})
    assert response.status_code == 200
    browser.headers["X-CSRF-Token"] = response.json()["csrf"]
    return browser


def fail_if_called(*args, **kwargs):
    pytest.fail("unexpected provider build, secret lookup, or network dispatch")


@pytest.fixture
def offline(monkeypatch):
    monkeypatch.setattr(inference_worker, "build_provider", fail_if_called)
    monkeypatch.setattr(inference, "build_provider", fail_if_called)
    monkeypatch.setattr(inference, "resolve", fail_if_called)
    monkeypatch.setattr(socket, "getaddrinfo", fail_if_called)
    monkeypatch.setattr(inference.PublicHttpsTransport, "request", fail_if_called)
    monkeypatch.setattr(inference.LoopbackTransport, "request", fail_if_called)


def test_remote_routes_require_normal_http_guards(tmp_path, admin_peer, offline):
    application = create_app(settings(tmp_path, ai_peer=admin_peer))
    with TestClient(application, base_url=ORIGIN, headers={"Origin": ORIGIN}) as anonymous:
        assert anonymous.get("/api/ai").status_code == 401
    with login(application) as browser:
        assert (
            browser.post(
                "/api/ai/scan",
                headers=key(1)
                | {
                    "Origin": "https://other.invalid",
                },
            ).status_code
            == 403
        )
        assert (
            browser.post(
                "/api/ai/scan",
                headers=key(1)
                | {
                    "X-CSRF-Token": "invalid",
                },
            ).status_code
            == 403
        )
        assert browser.post("/api/ai/scan").status_code == 400
        oversized = browser.post(
            "/api/ai/auto", content=b"x" * (MAX_BODY_BYTES + 1), headers=key(1)
        )
        assert oversized.status_code == 413
        assert browser.post("/api/ai/scan", headers={"Idempotency-Key": "short"}).status_code == 400
        invalid = browser.post("/api/ai/auto", headers=key(1), json={"enabled": True, "extra": 1})
        assert invalid.status_code == 422
        rejected = browser.post("/api/ai/auto", headers=key(1), json={"enabled": True})
        assert rejected.status_code == 422
        assert rejected.json()["detail"] == {"code": "onboarding_incomplete", "problems": []}
        unavailable_method = browser.post(
            "/api/ai/provider", json={"option": "claude-subscription"}, headers=key(2)
        )
        assert unavailable_method.status_code == 422
        detail = unavailable_method.json()["detail"]
        assert detail["code"] == "method_unavailable"
        assert detail["problems"] == [
            next(
                o["reason"]
                for o in browser.get("/api/ai").json()["options"]
                if o["id"] == "claude-subscription"
            )
        ]

        view = browser.get("/api/ai").json()
        assert view["requests"] == []
        assert all(option["runtime_enabled"] is False for option in view["options"])
    assert not (tmp_path / "api" / "ai").exists()


def test_concurrent_same_key_replays_source_mutation_and_audits_once(
    tmp_path,
    admin_peer,
    offline,
):
    application = create_app(settings(tmp_path, ai_peer=admin_peer))
    payload = {"url": "https://example.org/models", "parser": "json_comparison_v1"}
    ready = threading.Barrier(2)

    def submit(browser):
        ready.wait(timeout=5)
        return browser.post("/api/ai/sources", json=payload, headers=key(1))

    with login(application) as first, login(application) as second:
        with ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(submit, first)
            b = pool.submit(submit, second)
            a, b = a.result(timeout=5), b.result(timeout=5)
        assert a.status_code == b.status_code == 200
        assert a.json() == b.json()

        source_id = a.json()["id"]
        view = first.get("/api/ai").json()["sources"]
        assert [source["id"] for source in view["list"]] == [source_id]
        assert [(entry["actor"], entry["event"]) for entry in view["audit"]] == [
            ("operator", "added"),
        ]
        actions = [
            entry["action"]
            for entry in application.state.audit.read()
            if entry["event"] == "ai_admin_action"
        ]
        assert actions == ["source-add"]

        removed = first.delete(f"/api/ai/sources/{source_id}", headers=key(2))
        assert removed.status_code == 200
        view = first.get("/api/ai").json()["sources"]
        assert view["list"] == []
        assert ("operator", "removed") in [(a["actor"], a["event"]) for a in view["audit"]]
    assert not (tmp_path / "api" / "ai").exists()


def test_remote_api_and_offline_tick_share_worker_queue_only(
    tmp_path,
    admin_peer,
    backend_state,
    offline,
):
    application = create_app(settings(tmp_path, ai_peer=admin_peer))
    model = "fixture:1b"
    local = {"download_mb": 1, "ram_mb": 128, "disk_mb": 1, "license_ack": True}
    policy = inference_worker.AppliedPolicy(
        "fixture-revision", Ai(provider="ollama", model=model, local=local), None
    )
    builds = []

    class OfflineOllama:
        version, name, data_class = 1, "ollama", "local"
        capabilities = ("models.list",)
        timeout_s, max_input_bytes = 5.0, 1000

        def __init__(self, ai):
            self.model = ai.model
            builds.append(ai.model)

        def list_models(self, timeout_s=10.0):
            return [model]

    def tick(applied_policy, builder):
        result = inference_worker.run_once(
            state_dir=backend_state,
            read_policy=lambda: applied_policy,
            kill_switch=lambda: False,
            provider_builder=builder,
        )
        assert result["status"] == "ok"

    with login(application) as browser:
        chosen = browser.post(
            "/api/ai/provider",
            json={"option": "ollama-local", "local": local | {"model": model, "sha256": "a" * 64}},
            headers=key(1),
        )
        assert chosen.status_code == 200, chosen.json()
        added = browser.post(
            "/api/ai/sources",
            json={"url": "https://example.org/models", "parser": "json_comparison_v1"},
            headers=key(6),
        )
        assert added.status_code == 200
        pending = {}
        for index, action in enumerate(("scan", "source-research", "best-now"), start=2):
            response = browser.post(f"/api/ai/{action}", headers=key(index))
            assert response.status_code == 202
            row = response.json()
            assert row["state"] == "pending"
            pending[row["kind"]] = row["id"]
        assert builds == []
        view = browser.get("/api/ai").json()
        assert {row["kind"]: row["id"] for row in view["requests"]} == pending

        assert view["provider"]["runtime_enabled"] is False
        tick(None, fail_if_called)
        view = browser.get("/api/ai").json()
        results = {row["id"]: row["result"] for row in view["requests"]}
        assert results[pending["scan"]] == "applied_policy_unavailable"
        assert results[pending["source_research"]] == "source_research_unavailable"
        assert view["scanned"] is None

        retry = browser.post("/api/ai/scan", headers=key(5))
        assert retry.status_code == 202
        tick(policy, OfflineOllama)
        view = browser.get("/api/ai").json()
        finished = next(row for row in view["requests"] if row["id"] == retry.json()["id"])
        assert finished["state"] == "done"
        assert view["scanned"]["models"] == builds == [model]
        assert [source["id"] for source in view["sources"]["list"]] == [added.json()["id"]]
    assert (backend_state / "onboarding.db").is_file()
    assert not (tmp_path / "api" / "ai").exists()


UNAVAILABLE = {"detail": {"code": "ai_admin_unavailable"}}


def test_managed_backend_env_is_closed_and_pins_root(monkeypatch):
    monkeypatch.delenv("STEWARD_AI_ADMIN_BACKEND", raising=False)
    assert Settings.from_env().ai_peer is None
    monkeypatch.setenv("STEWARD_AI_ADMIN_BACKEND", "managed-local")
    assert Settings.from_env().ai_peer == AdminPeer(MANAGED_SOCKET, expected_peer_uid=0)
    monkeypatch.setenv("STEWARD_AI_ADMIN_BACKEND", "wrong")
    with pytest.raises(StartupError):
        Settings.from_env()


@pytest.mark.parametrize("replacement", ["digest", "generation", None])
def test_managed_candidate_round_trip(
    tmp_path, managed_listener, backend_state, make_server, monkeypatch, replacement
):
    ai = Ai(
        provider="ollama",
        model="fixture:1",
        local={"download_mb": 1, "ram_mb": 128, "disk_mb": 1, "license_ack": True},
    )
    applied = inference_worker.AppliedPolicy("revision", ai, None, "a" * 32, "b" * 64)
    current = applied
    calls = []

    def send(_, endpoint, method, path, headers, body, *, timeout):
        nonlocal current
        calls.append((endpoint.host, endpoint.port, method, path))
        assert 0 < timeout <= 10
        if replacement == "generation":
            current = inference_worker.AppliedPolicy("revision", ai, None, "c" * 32, "b" * 64)
        return inference.HttpResponse(
            200, {}, b'{"models":[{"name":"fixture:1"},{"name":"other:1"}]}'
        )

    monkeypatch.setattr(inference.LoopbackTransport, "request", send)
    monkeypatch.setattr(inference_worker, "STATE_DIR", backend_state)
    monkeypatch.setattr(inference_worker, "_read_candidate", lambda: current)
    monkeypatch.setattr(inference_worker, "read_kill_switch", lambda: False)
    _, path = managed_listener
    peer = AdminPeer(str(path), os.geteuid())
    application = create_app(settings(tmp_path, ai_peer=peer))
    declaration = {
        "option": "ollama-local",
        "local": ai.local.model_dump(exclude={"device"}) | {"model": ai.model, "sha256": "b" * 64},
    }
    refused = {"detail": {"code": CANDIDATE_SCOPE_CODE, "problems": []}}
    with (
        serving(make_server(candidate=True, read_policy=lambda: current)),
        login(application) as browser,
    ):
        assert browser.get("/api/ai").json()["status"] == "none"
        no_choice = browser.post("/api/ai/scan", headers=key(1))
        assert no_choice.status_code == 422 and no_choice.json() == refused
        assert browser.post("/api/ai/best-now", headers=key(2)).json() == refused
        assert (
            browser.post(
                "/api/ai/provider", json={"option": "anthropic-api"}, headers=key(3)
            ).json()
            == refused
        )
        for field, wrong in (("model", "other:1"), ("sha256", "c" * 64), ("ram_mb", 129)):
            payload = declaration | {"local": declaration["local"] | {field: wrong}}
            assert browser.post("/api/ai/provider", json=payload, headers=key(4)).json() == refused
        choose = browser.post("/api/ai/provider", json=declaration, headers=key(4))
        assert choose.status_code == 200
        assert (
            browser.post("/api/ai/provider", json=declaration, headers=key(4)).json()
            == choose.json()
        )
        scan = browser.post("/api/ai/scan", headers=key(5))
        assert scan.status_code == 202
        assert browser.post("/api/ai/scan", headers=key(5)).json() == scan.json()
        assert calls == []

        if replacement == "digest":
            current = inference_worker.AppliedPolicy("revision", ai, None, "c" * 32, "d" * 64)
            assert browser.get("/api/ai").json() == refused
            assert browser.post("/api/ai/scan", headers=key(5)).json() == refused
        outcome = inference_worker._local_candidate_tick()
        result = outcome["requests"][0]
        assert result["id"] == scan.json()["id"]
        if replacement == "digest":
            assert calls == []
            assert result["result"] == "applied_provider_mismatch"
        else:
            assert calls == [("127.0.0.1", 11434, "GET", "/api/tags")]
            view = browser.get("/api/ai").json()
            assert view["requests"][0]["state"] == ("failed" if replacement else "done")
            if replacement:
                assert view["scanned"] is None
                assert result["result"] == "applied_policy_changed"
            else:
                assert view["scanned"]["models"] == ["fixture:1"]
                assert view["active"] is None
                current = inference_worker.AppliedPolicy(
                    applied.revision, ai, applied.weekly_window, "c" * 32, applied.manifest_sha256
                )
                assert (
                    browser.post("/api/ai/provider", json=declaration, headers=key(4)).json()
                    == choose.json()
                )
                assert browser.post("/api/ai/scan", headers=key(5)).json() == scan.json()
                assert inference_worker._local_candidate_tick()["requests"] == []
                assert len(calls) == 1
        current = None
        for response in (
            browser.get("/api/ai"),
            browser.post("/api/ai/best-now", headers=key(6)),
        ):
            assert response.status_code == 503
            assert response.json() == UNAVAILABLE

    assert not (tmp_path / "api" / "ai").exists()


def test_unavailable_selected_peer_leaves_legacy_local_files_unchanged(tmp_path, offline):
    with login(create_app(settings(tmp_path))) as local:
        response = local.post("/api/ai/scan", headers=key(1))
        assert response.status_code == 202
        legacy_request = response.json()

    state = tmp_path / "api" / "ai"

    def files():
        return {p.relative_to(state): p.read_bytes() for p in state.rglob("*") if p.is_file()}

    before = files()
    assert before
    peer = AdminPeer(str(tmp_path / "absent.sock"), os.geteuid())
    with login(create_app(settings(tmp_path, ai_peer=peer))) as remote:
        for response in (
            remote.get("/api/ai"),
            remote.post("/api/ai/best-now", headers=key(2)),
        ):
            assert response.status_code == 503
            assert response.json() == UNAVAILABLE
    assert files() == before
    with login(create_app(settings(tmp_path))) as local:
        assert [r["id"] for r in local.get("/api/ai").json()["requests"]] == [legacy_request["id"]]


def test_lost_mutation_reply_replays_in_the_same_backend(
    tmp_path, managed_listener, make_server, offline
):
    listener, path = managed_listener
    peer = AdminPeer(str(path), os.geteuid())
    application = create_app(settings(tmp_path, ai_peer=peer))
    payload = {"url": "https://example.org/models", "parser": "json_comparison_v1"}

    with make_server() as server, login(application) as browser:

        def commit_and_drop_reply():
            connection, _ = listener.accept()
            with connection, connection.makefile("rb") as reader:
                connection.settimeout(5)
                request = json.loads(reader.readline())
                return server.dispatch(request["action"], request["params"])

        with ThreadPoolExecutor(max_workers=1) as pool:
            committed = pool.submit(commit_and_drop_reply)
            lost = browser.post("/api/ai/sources", json=payload, headers=key(1))
            outcome = committed.result(timeout=5)
        assert lost.status_code == 503
        assert lost.json() == UNAVAILABLE
        assert outcome["status"] == "ok" and outcome["replayed"] is False

        with serving(server):
            replay = browser.post("/api/ai/sources", json=payload, headers=key(1))
            assert replay.status_code == 200
            assert replay.json() == outcome["body"]
            sources = browser.get("/api/ai").json()["sources"]
            assert [entry["id"] for entry in sources["list"]] == [replay.json()["id"]]
        assert all(entry["event"] != "ai_admin_action" for entry in application.state.audit.read())
    assert not (tmp_path / "api" / "ai").exists()


UNTRUSTED = "/private/inference/fixture.db"


def result_frame(**result):
    return encode({"ok": True, "result": result})


@pytest.mark.parametrize(
    ("action", "frame"),
    [
        pytest.param("view", None, id="dropped"),
        pytest.param("view", b'{"ok":true}', id="unterminated"),
        pytest.param("view", b'\n{"ok":true,"result":{}}', id="leading-newline-without-terminator"),
        pytest.param("view", b"x" * MAX_MESSAGE_BYTES + b"\n", id="oversized"),
        pytest.param("view", encode({"ok": "true", "result": {}}), id="outer-type"),
        pytest.param("view", encode({"ok": True, "result": []}), id="outer-result"),
        pytest.param(
            "view",
            encode({"ok": False, "error_class": "internal", "message": UNTRUSTED}),
            id="outer-error",
        ),
        pytest.param("view", result_frame(status="ok", body={"error": UNTRUSTED}), id="bad-view"),
        pytest.param(
            "scan",
            result_frame(
                status="ok",
                body={
                    "id": "a" * 32,
                    "kind": "scan",
                    "created_at": 1.0,
                    "state": "pending",
                    "result": "",
                },
                replayed=1,
            ),
            id="invalid-replay",
        ),
        pytest.param(
            "scan",
            result_frame(status="ok", body={"id": UNTRUSTED}, replayed=False),
            id="invalid-mutation",
        ),
        pytest.param(
            "scan",
            result_frame(status="rejected", code=UNTRUSTED, problems=[]),
            id="unrecognized-domain-code",
        ),
        pytest.param(
            "provider",
            result_frame(status="rejected", code="resource_refused", problems=[UNTRUSTED]),
            id="unsafe-resource-problem",
        ),
        pytest.param(
            "provider",
            result_frame(status="rejected", code="method_unavailable", problems=[UNTRUSTED]),
            id="unsafe-method-problem",
        ),
        pytest.param(
            "provider",
            result_frame(status="rejected", code="method_unavailable", problems=UNTRUSTED),
            id="invalid-problems-type",
        ),
    ],
)
def test_remote_failures_hide_peer_details(tmp_path, managed_listener, action, frame):
    listener, path = managed_listener

    def reply():
        connection, _ = listener.accept()
        with connection, connection.makefile("rb") as reader:
            connection.settimeout(5)
            sent = json.loads(reader.readline())
            if frame is not None:
                connection.sendall(frame)
            return sent

    peer = AdminPeer(str(path), os.geteuid())
    application = create_app(settings(tmp_path, ai_peer=peer))
    with login(application) as browser, ThreadPoolExecutor(max_workers=1) as pool:
        replied = pool.submit(reply)
        if action == "view":
            response = browser.get("/api/ai")
        elif action == "provider":
            response = browser.post(
                "/api/ai/provider", json={"option": "ollama-local"}, headers=key(1)
            )
        else:
            response = browser.post("/api/ai/scan", headers=key(1))
        sent = replied.result(timeout=5)
    assert sent["action"] == action
    params = {
        "view": {},
        "provider": {
            "key": key(1)["Idempotency-Key"],
            "body": {"option": "ollama-local", "key_ref": None, "local": None, "replace": False},
        },
        "scan": {"key": key(1)["Idempotency-Key"], "body": {}},
    }
    assert sent["params"] == params[action]
    assert response.status_code == 503
    assert response.json() == UNAVAILABLE
    assert not (tmp_path / "api" / "ai").exists()


@pytest.mark.parametrize(
    "fields",
    [
        {"api_key": {"token": "fixture-secret"}},
        {"api_key": ["fixture-secret"]},
        {"api_key": "fixture-secret\r\n"},
        {"api_key": "fixture-secret", "extra": "fixture-secret"},
    ],
)
def test_provider_validation_redacts_the_entire_request(client, fields):
    response = client.post(
        "/api/ai/provider",
        json={"option": "openai-compatible", **fields},
        headers=key(1),
    )
    assert response.status_code == 422
    assert response.json() == {"detail": {"code": "invalid_provider_request"}}


def test_legacy_ai_admin_disables_private_provider(client):
    view = client.get("/api/ai").json()
    option = next(row for row in view["options"] if row["id"] == "openai-compatible")
    assert not option["available"]
    assert option["data_class"] == "external"
    assert view["choice_id"] is None and view["pending_provider"] is None
    response = client.post(
        "/api/ai/provider",
        json={
            "option": option["id"],
            "base_url": "https://192.168.0.10:8443/v1",
            "api_key": "fixture-secret",
        },
        headers=key(1),
    )
    assert response.status_code == 422
    assert response.json() == {"detail": {"code": "invalid_provider_request"}}
    assert client.get("/api/ai").json()["provider"] is None


def test_private_provider_handoff_to_pinned_admin_ipc(tmp_path, monkeypatch, offline):
    path = str(tmp_path / "admin.sock")
    app = create_app(settings(tmp_path, ai_peer=AdminPeer(path, os.geteuid())))
    base = tmp_path / "inference"
    base.mkdir()
    onboarding = Onboarding(
        base,
        SelectionStore(base / "selection.db"),
        SourceStore(base / "sources.db", clock=lambda: 0),
    )
    control = AdminControl(
        onboarding, fx_store=FxStore(base / "fx.db"), read_fx=lambda: None,
        private_generation="b" * 32,
    )  # fmt: skip
    base_url = "https://192.168.0.10:8443/v1"
    secret = "fixture-secret"
    choice_id = "a" * 32
    payload = {
        "option": "openai-compatible",
        "base_url": base_url,
        "api_key": secret,
        "replace": True,
        "expected_choice_id": choice_id,
    }

    with onboarding._tx() as db:
        state = onboarding._load(db)
        state.update(
            provider="openai-compatible", choice_id=choice_id, base_url=base_url,
            key_ref="env:LEGACY", status="provider_chosen", generation=control.private_generation,
            private_pending={
                "status": "failed", "error": "untrusted provider diagnostic",
                "key_ref": "private:" + "c" * 32, "generation": control.private_generation,
            },
        )  # fmt: skip
        onboarding._save(db, state)
    requests = []

    def intercept(action, params, *, socket_path, expected_peer_uid, **kwargs):
        assert socket_path == path
        assert expected_peer_uid == os.geteuid()
        assert kwargs["strict_response"] is True
        if action == "provider":
            if params["key"] == key(2)["Idempotency-Key"]:
                raise ExecutorError("unavailable", secret)
            requests.append(params)
            return {
                "status": "ok",
                "body": control._brief(),
                "replayed": False,
            }
        return control.dispatch(action, params)

    monkeypatch.setattr(protocol, "call", intercept)
    with login(app) as browser:
        response = browser.get("/api/ai")
        assert response.status_code == 200
        view = response.json()
        assert view["choice_id"] == choice_id
        assert view["pending_provider"] == {
            "status": "failed",
            "error": "provider_validation_failed",
        }
        assert view["provider"] == {
            "id": "openai-compatible",
            "label": "OpenAI-compatible API",
            "base_url": base_url,
            "data_class": "external",
            "runtime_enabled": False,
        }
        option = next(row for row in view["options"] if row["id"] == payload["option"])
        assert option["available"] and option["reason"] == ""
        assert secret not in response.text

        without_csrf = browser.headers.pop("X-CSRF-Token")
        assert browser.post("/api/ai/provider", json=payload, headers=key(1)).status_code == 403
        assert not requests
        browser.headers["X-CSRF-Token"] = without_csrf
        response = browser.post("/api/ai/provider", json=payload, headers=key(1))
        assert response.status_code == 200
        assert secret not in response.text
        assert requests == [
            {
                "key": key(1)["Idempotency-Key"],
                "body": payload | {"key_ref": None, "local": None},
            }
        ]
        unavailable = browser.post("/api/ai/provider", json=payload, headers=key(2))
        assert unavailable.status_code == 503
        assert unavailable.json() == UNAVAILABLE
    assert secret not in json.dumps(app.state.audit.read())
    assert not (tmp_path / "api" / "ai").exists()
