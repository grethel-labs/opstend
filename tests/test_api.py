import json
import time

import pytest
import yaml
from fastapi.testclient import TestClient

from steward.api import app as api_app
from steward.api.app import COOKIE, Settings, StartupError, create_app
from steward.core.config import effective

TOKEN = "t" * 20 + "0123456789abcdefghijklmnopqrstuvwxyz"

ORIGIN = "https://localhost:9443"


def settings(tmp_path, **overrides):
    values = dict(
        state_dir=tmp_path / "api",
        allowed_origins=(ORIGIN,),
        token=TOKEN,
        desired_config=tmp_path / "desired.json",
        controller_export=tmp_path / "state.json",
        executor_socket=str(tmp_path / "ex.sock"),
        collector_socket=str(tmp_path / "col.sock"),
        start_worker=False,
    )
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def app(tmp_path, cfg):
    (tmp_path / "desired.json").write_text(json.dumps(effective(cfg)))
    return create_app(settings(tmp_path))


@pytest.fixture
def anon(app):
    return TestClient(app, base_url=ORIGIN)


@pytest.fixture
def client(app):
    client = TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN})
    response = client.post("/api/login", json={"token": TOKEN})
    assert response.status_code == 200
    client.headers["X-CSRF-Token"] = response.json()["csrf"]
    return client


# ---- startup ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"token": None},
        {"token": ""},
        {"token": "admin"},
        {"token": "x" * 42},
        {"allowed_origins": ()},
    ],
)
def test_api_does_not_start_without_a_strong_secret(tmp_path, overrides):
    with pytest.raises(StartupError):
        create_app(settings(tmp_path, **overrides))


def test_api_does_not_start_with_missing_token_file(tmp_path):
    with pytest.raises(StartupError):
        create_app(settings(tmp_path, token=None, token_file=tmp_path / "missing"))


# ---- session security -------------------------------------------------------------


def test_everything_is_closed_without_session(anon):
    for path in (
        "/api/session",
        "/api/status",
        "/api/backups",
        "/api/config",
        "/api/config/revisions",
        "/api/jobs",
        "/api/audit",
        "/api/events",
        "/api/scans",
    ):
        assert anon.get(path).status_code == 401, path


def test_login_sets_hardened_cookie_and_never_echoes_the_token(anon):
    response = anon.post("/api/login", json={"token": TOKEN}, headers={"Origin": ORIGIN})
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{COOKIE}=")
    for attribute in ("HttpOnly", "Secure", "SameSite=strict", "Path=/"):
        assert attribute in cookie
    assert "Domain" not in cookie  # required for the __Host- prefix
    assert TOKEN not in response.text and TOKEN not in cookie


def test_wrong_token_is_rejected_and_rate_limited(anon, app):
    for _ in range(api_app.LOGIN_MAX_FAILURES_PER_CLIENT):
        assert (
            anon.post("/api/login", json={"token": "wrong"}, headers={"Origin": ORIGIN}).status_code
            == 401
        )
    blocked = anon.post("/api/login", json={"token": TOKEN}, headers={"Origin": ORIGIN})
    assert blocked.status_code == 429  # even the right token waits out the window
    events = [e["event"] for e in app.state.audit.read()]
    assert events.count("login_failed") == 5 and events[-1] == "login_rate_limited"


def test_unsafe_requests_need_origin_and_csrf_token(client):
    yaml_body = {"yaml": "x: 1"}
    no_origin = client.post("/api/config/validate", json=yaml_body, headers={"Origin": ""})
    assert no_origin.status_code == 403
    foreign = client.post(
        "/api/config/validate", json=yaml_body, headers={"Origin": "https://evil.example"}
    )
    assert foreign.status_code == 403
    no_csrf = client.post("/api/config/validate", json=yaml_body, headers={"X-CSRF-Token": ""})
    assert no_csrf.status_code == 403
    wrong_csrf = client.post("/api/config/validate", json=yaml_body, headers={"X-CSRF-Token": "x"})
    assert wrong_csrf.status_code == 403
    assert client.post("/api/config/validate", json=yaml_body).status_code == 422  # reached logic


def test_private_ip_mutations_require_same_origin_and_csrf(tmp_path):
    lan = "https://192.168.10.7:9443"
    alias = "https://10.10.0.7:9443"
    app = create_app(settings(tmp_path, allowed_origins=(ORIGIN, lan, alias)))
    client = TestClient(app, base_url=lan, headers={"Origin": lan})
    login = client.post("/api/login", json={"token": TOKEN})
    assert login.status_code == 200

    path = "/api/config/validate"
    body = {"yaml": "x: 1"}
    assert client.post(path, json=body).json()["detail"] == "CSRF token missing or wrong"
    client.headers["X-CSRF-Token"] = login.json()["csrf"]
    assert client.post(path, json=body).status_code == 422
    for origin in (ORIGIN, alias, lan.replace("https:", "http:"), lan + "/"):
        assert (
            client.post(
                path, json=body, headers={"Origin": origin, "X-Forwarded-Host": "10.10.0.7:9443"}
            ).json()["detail"]
            == "origin not allowed"
        )


def test_http_dev_origin_is_supported(tmp_path):
    origin = "http://localhost:19080"
    app = create_app(settings(tmp_path, allowed_origins=(origin,)))
    client = TestClient(app, base_url=origin, headers={"Origin": origin})
    assert client.post("/api/login", json={"token": TOKEN}).status_code == 200


def test_unknown_host_header_is_rejected(app):
    rebinding = TestClient(app, base_url="https://attacker.example:9443")
    assert rebinding.get("/api/session").status_code == 421


def test_logout_revokes_the_session_server_side(client):
    stolen = client.cookies.get(COOKIE)
    assert client.post("/api/logout").status_code == 200
    client.cookies.set(COOKIE, stolen)
    assert client.get("/api/session").status_code == 401


def test_token_rotation_revokes_existing_sessions(tmp_path, cfg):
    token_file = tmp_path / "admin_token"
    token_file.write_text(TOKEN + "\n")
    app = create_app(settings(tmp_path, token=None, token_file=token_file))
    client = TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN})
    assert client.post("/api/login", json={"token": TOKEN}).status_code == 200
    assert client.get("/api/session").status_code == 200
    token_file.write_text("r" * 50 + "\n")
    import os

    os.utime(token_file, (time.time() + 5, time.time() + 5))
    assert client.get("/api/session").status_code == 401
    assert client.post("/api/login", json={"token": TOKEN}).status_code == 401
    assert client.post("/api/login", json={"token": "r" * 50}).status_code == 200


def test_expired_session_is_rejected(tmp_path):
    app = create_app(settings(tmp_path, session_ttl_s=0))
    client = TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN})
    client.post("/api/login", json={"token": TOKEN})
    assert client.get("/api/session").status_code == 401


def test_security_headers(anon):
    response = anon.get("/api/session")
    csp = response.headers["content-security-policy"]
    assert (
        "script-src 'self'" in csp
        and "unsafe-inline" not in csp
        and "frame-ancestors 'none'" in csp
    )
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"


def test_oversized_body_is_rejected(client):
    response = client.post("/api/config/validate", json={"yaml": "a" * (600 * 1024)})
    assert response.status_code == 413


def test_static_files_cannot_escape_the_web_root(client):
    for path in ("/../app.py", "/%2e%2e/app.py", "/..%2f..%2fetc/passwd", "/assets/../../app.py"):
        response = client.get(path)
        assert "StartupError" not in response.text and "root:" not in response.text


# ---- configuration ----------------------------------------------------------------


def edited(client, mutate):
    data = client.get("/api/config").json()["config"]
    mutate(data)
    return yaml.safe_dump(data)


def test_private_lan_browser_draft_requires_an_explicit_bind(client):
    proposed = edited(client, lambda cfg: cfg["admin"].update(access="private-lan"))
    response = client.post("/api/config/validate", json={"yaml": proposed})
    assert response.status_code == 422
    assert "admin.lan.interface and admin.lan.bind" in response.json()["detail"]["problems"][0]

    data = yaml.safe_load(proposed)
    data["admin"]["lan"] = {"interface": "ens18", "bind": "192.168.10.7/24"}
    response = client.post("/api/config/validate", json={"yaml": yaml.safe_dump(data)})
    assert response.status_code == 200


def test_applied_configuration_is_imported_as_head(client):
    body = client.get("/api/config").json()
    assert body["head"] == body["applied"] and body["pending"] is False
    assert body["config"]["projects"][0]["resources"]["pids"] == 64
    assert body["config"]["hardening"]["journald"]["retention_days"] == 30  # effective default


def test_validate_returns_diff_and_all_problems(client):
    text = edited(client, lambda c: c["projects"][0]["resources"].update(memory_mb=256))
    result = client.post("/api/config/validate", json={"yaml": text}).json()
    assert result["diff"] == [
        {"path": "projects[notes].resources.memory_mb", "change": "changed", "old": 128, "new": 256}
    ]
    bad = edited(client, lambda c: (c["projects"][0].update(run_as=0), c["admin"].update(port=1)))
    response = client.post("/api/config/validate", json={"yaml": bad})
    assert response.status_code == 422 and len(response.json()["detail"]["problems"]) == 2


def test_commit_creates_pending_revision_and_detects_conflicts(client, app):
    head = client.get("/api/config").json()["head"]
    text = edited(client, lambda c: c["projects"][0]["resources"].update(memory_mb=256))
    first = client.post(
        "/api/config/revisions", json={"yaml": text, "parent": head, "message": "m"}
    )
    assert first.status_code == 200 and first.json()["pending"] is True
    # a second editor still holding the old head must not overwrite
    other = edited(client, lambda c: c["projects"][0]["resources"].update(memory_mb=512))
    conflict = client.post("/api/config/revisions", json={"yaml": other, "parent": head})
    assert (
        conflict.status_code == 409
        and conflict.json()["detail"]["head"] == first.json()["revision"]
    )
    state = client.get("/api/config").json()
    assert state["pending"] is True and state["applied"] == head
    export = json.loads(
        (
            app.state.store._path and (client.app.state.audit.path.parent / "export" / "head.json")
        ).read_text()
    )
    assert export["head"] == first.json()["revision"] and export["applied"] == head
    assert [e["event"] for e in app.state.audit.read()][-1] == "config_commit"


def test_ui_cannot_change_the_deployment_target_or_enable_missing_features(client):
    head = client.get("/api/config").json()["head"]
    moved = edited(client, lambda c: c["server"].update(host="198.51.100.7"))
    response = client.post("/api/config/revisions", json={"yaml": moved, "parent": head})
    assert response.status_code == 422 and "server" in response.json()["detail"]["problems"][0]
    patch = edited(client, lambda c: c["automation"].update(profile="repair"))
    response = client.post("/api/config/revisions", json={"yaml": patch, "parent": head})
    assert response.status_code == 422


def test_yaml_bombs_and_non_mappings_are_rejected(client):
    assert client.post("/api/config/validate", json={"yaml": "- a\n- b"}).status_code == 422
    assert (
        client.post(
            "/api/config/validate", json={"yaml": "!!python/object:os.system x"}
        ).status_code
        == 422
    )


# ---- status, jobs, audit ----------------------------------------------------------


def test_status_marks_missing_and_stale_snapshots(client, tmp_path):
    gap = client.get("/api/status").json()
    assert gap["stale"] is True and gap["status"] is None and "gap" in gap
    (tmp_path / "state.json").write_text(
        json.dumps(
            {"generated_at": time.time() - 3600, "status_ok": True, "status": {}, "findings": []}
        )
    )
    assert client.get("/api/status").json()["stale"] is True
    (tmp_path / "state.json").write_text(
        json.dumps({"generated_at": time.time(), "status_ok": True, "status": {}, "findings": []})
    )
    assert client.get("/api/status").json()["stale"] is False


def test_live_status_reports_executor_outage(client):
    assert client.get("/api/status?live=true").status_code == 503


def test_restart_job_is_idempotent_and_runs_through_the_executor(
    client, app, executor_socket, executor
):
    headers = {"Idempotency-Key": "restart-0001"}
    assert client.post("/api/projects/notes/restart").status_code == 400  # key required
    assert client.post("/api/projects/unknown/restart", headers=headers).status_code == 404
    first = client.post("/api/projects/notes/restart", headers=headers)
    second = client.post("/api/projects/notes/restart", headers=headers)
    assert first.status_code == 202 and first.json()["id"] == second.json()["id"]
    app.state.run_pending_jobs()
    job = client.get("/api/jobs").json()["jobs"][0]
    assert job["state"] == "succeeded"
    assert executor.host.calls == [("restart", "stw-notes", "notes.service")]


def test_denied_job_fails_with_cause_and_is_not_retried(client, app, executor_socket, executor):
    executor.host.killed = True
    client.post("/api/projects/notes/restart", headers={"Idempotency-Key": "restart-0002"})
    app.state.run_pending_jobs()
    job = client.get("/api/jobs").json()["jobs"][0]
    assert job["state"] == "failed" and "kill_switch" in job["error"] and job["attempts"] == 1
    assert executor.host.calls == []


def test_unavailable_executor_is_retried_with_backoff(client, app):
    client.post("/api/projects/notes/restart", headers={"Idempotency-Key": "restart-0003"})
    app.state.run_pending_jobs()
    job = client.get("/api/jobs").json()["jobs"][0]
    assert job["state"] == "queued" and "unavailable" in job["error"]
    assert job["not_before"] > time.time()


def test_audit_view_shows_both_logs_and_names_gaps(client, executor_socket):
    body = client.get("/api/audit").json()
    assert body["api"]["chain_ok"] is True
    assert body["executor"]["chain_ok"] is True


def test_audit_view_without_executor_reports_gap(client):
    assert "gap" in client.get("/api/audit").json()["executor"]


# ---- events -----------------------------------------------------------------------


@pytest.fixture
def event_socket(tmp_path):
    import os
    import threading

    from steward.collector import QueryService
    from steward.core import ipc
    from steward.core.events import Event, EventStore

    store = EventStore(tmp_path / "events.db")
    store.add(
        [
            Event(
                ts=time.time(),
                source="t",
                source_ref="1",
                kind="finding.opened",
                severity="high",
                project="notes",
                correlation_id="c1",
                summary="Unit is failed.",
            ),
            Event(
                ts=time.time(),
                source="t",
                source_ref="2",
                kind="log",
                severity="info",
                summary="<script>alert(1)</script>",
            ),
        ],
        {"last_cycle": time.time()},
    )
    server = ipc.bind(
        str(tmp_path / "col.sock"), QueryService(store, {os.getuid(): "api"}).handle, None
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield
    server.shutdown()
    server.server_close()


def test_events_are_served_with_coverage(client, event_socket):
    body = client.get("/api/events?project=notes&min_severity=high").json()
    assert [e["kind"] for e in body["events"]] == ["finding.opened"]
    assert body["coverage"]["count"] == 2 and body["coverage"]["lag_s"] is not None
    story = client.get("/api/events?correlation_id=c1").json()["events"]
    assert story[0]["delivery"] == "immediate"


def test_event_text_is_returned_as_data(client, event_socket):
    # Rendering escapes it; the API must not interpret or drop it.
    body = client.get("/api/events?kind_prefix=log").json()
    assert body["events"][0]["summary"] == "<script>alert(1)</script>"
    assert client.get("/api/events").headers["content-type"].startswith("application/json")


def test_invalid_event_filter_is_rejected(client, event_socket):
    assert client.get("/api/events?project=../x").status_code == 422
    assert client.get("/api/events?min_severity=urgent").status_code == 422


def test_missing_collector_is_an_explicit_gap(client):
    response = client.get("/api/events")
    assert response.status_code == 503 and "observation gap" in response.json()["detail"]


def test_scan_api_is_read_only_and_rejects_cross_snapshot_pages(client, monkeypatch):
    actions = []

    def scanner(action, params, **kwargs):
        actions.append((action, params))
        if action == "scans_query":
            return {"records": [], "total": 0, "next_offset": None, "snapshot_id": "a" * 64}
        if action == "scans_summary":
            return {"enabled": False, "complete": False, "snapshot_id": "a" * 64}
        assert action == "scans_jobs"
        return {"jobs": []}

    monkeypatch.setattr(api_app, "call", scanner)
    response = client.get("/api/scans?source=osv&offset=10&finding_offset=1")
    assert response.status_code == 200 and response.json()["summary"]["complete"] is False
    assert actions[0][1] == {"source": "osv", "offset": 10, "finding_offset": 1, "limit": 50}
    assert client.post("/api/scans").status_code == 405

    def changed(action, params, **kwargs):
        return {"snapshot_id": "a" * 64 if action == "scans_query" else "b" * 64}

    monkeypatch.setattr(api_app, "call", changed)
    assert client.get("/api/scans").status_code == 409


def test_scan_api_unavailability_and_invalid_filters_are_explicit(client, monkeypatch):
    from steward.executor.protocol import ExecutorError

    for error_class, status in [("unavailable", 503), ("bad_request", 422), ("conflict", 409)]:

        def failure(*args, error_class=error_class, **kwargs):
            raise ExecutorError(error_class, "/private/path with provider credentials")

        monkeypatch.setattr(api_app, "call", failure)
        response = client.get("/api/scans")
        assert response.status_code == status
        assert "credentials" not in response.text and "/private" not in response.text


def test_disabled_scanner_reports_unknown_without_opening_a_socket(tmp_path, monkeypatch):
    monkeypatch.setenv("STEWARD_SCANNER_SOCKET", "")
    configured_socket = Settings.from_env().scanner_socket
    assert configured_socket is None
    app = create_app(settings(tmp_path, scanner_socket=configured_socket))
    client = TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN})
    assert client.get("/api/scans").status_code == 401
    assert client.post("/api/login", json={"token": TOKEN}).status_code == 200

    def no_call(*args, **kwargs):
        pytest.fail("the API contacted a disabled scanner")

    monkeypatch.setattr(api_app, "call", no_call)
    reply = client.get("/api/scans")
    assert reply.status_code == 200
    data = reply.json()
    assert data["records"] == data["jobs"] == [] and data["snapshot_id"] is None
    assert data["summary"]["enabled"] is False and data["summary"]["complete"] is False
    assert data["summary"]["configuration_matches"] is False
    assert client.get("/api/scans?snapshot_id=" + "a" * 64).status_code == 409


def test_backup_view_scopes_projects_and_keeps_partial_evidence(client, tmp_path):
    now = time.time()
    snapshot = {
        "generated_at": now,
        "status_ok": True,
        "status": {
            "backup_enabled": True,
            "config_revision": "a" * 64,
            "projects": {"notes": {}, "private-app": {}},
            "backup_schedule_observations": {
                "notes": {
                    "state": "exported",
                    "config_revision": "a" * 64,
                    "capture_id": "b" * 64,
                    "capture_created_at": now - 60,
                    "interval_s": 3600,
                    "provenance": "executor_schedule",
                }
            },
        },
        "backup_observations": {
            "notes": {
                "state": "failed",
                "job_state": "queued",
                "job_error": "unavailable",
                "repository_id": "c" * 64,
                "snapshot_id": "d" * 64,
                "uploaded_at": now - 50,
                "integrity_checked_at": now - 40,
                "restored_bytes_at": None,
                "application_drill_at": None,
                "worker_provenance": "worker_reported",
                "private_path": "/sensitive",
            }
        },
    }
    (tmp_path / "state.json").write_text(json.dumps(snapshot))
    response = client.get("/api/backups?project=notes")
    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is True and body["freshness"] == "fresh"
    assert [entry["project"] for entry in body["projects"]] == ["notes"]
    record = body["projects"][0]
    assert record["capture_freshness"] == "fresh" and record["worker_state"] == "failed"
    assert record["integrity_checked_at"] is not None and record["restored_bytes_at"] is None
    assert record["application_drill_at"] is None and "/sensitive" not in response.text
    snapshot["status"]["backup_schedule_observations"]["notes"]["capture_created_at"] = now - 7201
    (tmp_path / "state.json").write_text(json.dumps(snapshot))
    assert (
        client.get("/api/backups?project=notes").json()["projects"][0]["capture_freshness"]
        == "stale"
    )
    snapshot["status"]["backup_schedule_observations"]["notes"]["provenance"] = "untrusted"
    (tmp_path / "state.json").write_text(json.dumps(snapshot))
    assert (
        client.get("/api/backups?project=notes").json()["projects"][0]["capture_freshness"]
        == "unknown"
    )
    assert client.get("/api/backups?project=../etc").status_code == 422
    snapshot["generated_at"] = now - 300
    (tmp_path / "state.json").write_text(json.dumps(snapshot))
    assert client.get("/api/backups").json()["freshness"] == "stale"
    snapshot["generated_at"] = now
    snapshot["status"]["backup_enabled"] = False
    (tmp_path / "state.json").write_text(json.dumps(snapshot))
    assert client.get("/api/backups").json()["enabled"] is False
    (tmp_path / "state.json").unlink()
    assert client.get("/api/backups").json()["freshness"] == "unknown"
