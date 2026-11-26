from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from steward.controller import evaluate
from steward.core.canonical import revision_id
from steward.core.config import ConfigError, effective, parse_config
from steward.core.health import classify
from steward.executor.host import Host
from steward.executor.server import probe_health


def host() -> Host:
    return Host.__new__(Host)  # probes below do not use instance state


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---- classification -------------------------------------------------------------------


def test_classification_keeps_plain_results_compatible():
    assert classify({"ok": True, "status": 200})["state"] == "healthy"
    assert classify({"ok": False, "status": 503})["state"] == "unhealthy"
    timed_out = classify({"ok": False, "error": "TimeoutError"})
    assert timed_out["state"] == "timeout" and not timed_out["ok"]


def test_slow_answer_is_not_healthy_but_missing_timing_is_not_slow():
    slow = classify({"ok": True, "elapsed_ms": 900}, max_response_ms=500)
    assert slow["state"] == "slow" and not slow["ok"] and "900 ms" in slow["error"]
    assert classify({"ok": True, "elapsed_ms": 500}, max_response_ms=500)["ok"]
    assert classify({"ok": True}, max_response_ms=500)["ok"]  # no timing, no claim


def test_unknown_stays_unknown_and_never_ok():
    result = classify({"ok": True, "state": "unknown"})
    assert result["state"] == "unknown" and not result["ok"]


# ---- real probes against loopback sockets ---------------------------------------------


def test_tcp_probe_accepts_and_refuses():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        up = host().tcp_health(port, 1.0)
        assert up["ok"] and up["elapsed_ms"] >= 0
    finally:
        server.close()
    down = host().tcp_health(port, 1.0)
    assert not down["ok"] and down["error"] == "ConnectionRefusedError"


def test_http_probe_measures_time_and_times_out_on_a_hung_server():
    class Slow(BaseHTTPRequestHandler):
        def do_GET(self):
            time.sleep(0.3 if self.path == "/slow" else 0)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), Slow)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        fast = classify(host().http_health(port, "/fast", 2.0), 200)
        assert fast["state"] == "healthy"
        slow = classify(host().http_health(port, "/slow", 2.0), 100)
        assert slow["state"] == "slow" and slow["elapsed_ms"] >= 250
        hung = classify(host().http_health(port, "/slow", 0.05), 40)
        assert hung["state"] == "timeout" and not hung["ok"]
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.parametrize(
    ("rc", "state"), [(0, "healthy"), (1, "unhealthy"), (124, "timeout"), (125, "unknown")]
)
def test_container_probe_maps_exit_codes_without_running_anything_else(rc, state):
    h = host()
    seen = []

    def fake(user, argv, timeout):
        seen.append((user, argv, timeout))
        return rc, ""

    h._as_user = fake
    result = classify(h.container_health("stw-notes", "notes", 3.0))
    assert result["state"] == state and result["ok"] is (rc == 0)
    assert seen == [("stw-notes", ["podman", "healthcheck", "run", "notes"], 3)]


# ---- executor dispatch ----------------------------------------------------------------


class Recorder:
    def __init__(self):
        self.calls = []

    def http_health(self, port, path, timeout):
        self.calls.append(("http", port, path, timeout))
        return {"ok": True, "elapsed_ms": 50}

    def tcp_health(self, port, timeout):
        self.calls.append(("tcp", port, timeout))
        return {"ok": True, "elapsed_ms": 900}

    def container_health(self, user, name, timeout):
        self.calls.append(("container", user, name, timeout))
        return {"ok": False, "state": "unknown", "error": "healthcheck unavailable (rc 125)"}


SPEC = {
    "host_port": 20101,
    "health_path": "/healthz",
    "health_timeout_s": 5,
    "user": "stw-notes",
    "container": "notes",
}


def test_older_registry_without_probe_fields_uses_http():
    rec = Recorder()
    assert probe_health(rec, SPEC)["state"] == "healthy"
    assert rec.calls == [("http", 20101, "/healthz", 5)]


def test_registered_probe_kind_and_threshold_are_applied():
    rec = Recorder()
    result = probe_health(rec, {**SPEC, "health_probe": "tcp", "health_max_ms": 500})
    assert result["state"] == "slow" and rec.calls == [("tcp", 20101, 5)]
    result = probe_health(rec, {**SPEC, "health_probe": "container"})
    assert result["state"] == "unknown" and rec.calls[-1] == ("container", "stw-notes", "notes", 5)


# ---- controller rules -----------------------------------------------------------------


def project(health):
    return {
        "deploy": True,
        "unit": {"active": "active"},
        "allow_restart": True,
        "health_retries": 2,
        "health": health,
        "hardening": {"violations": []},
    }


def status(health):
    return {
        "kill_switch": False,
        "firewall": {"managed": False, "loaded": None},
        "platform_units": [],
        "proxy": {"active": "active"},
        "failed_units": [],
        "reboot_required": False,
        "resources": {
            "memory_total_mb": 4000,
            "memory_available_mb": 3000,
            "disk_total_mb": 40000,
            "disk_free_mb": 30000,
        },
        "projects": {"notes": project(health)},
        "deployment_recovery": "clear",
    }


def run(health, failures):
    try:
        return [f.id for f in evaluate(status(health), failures)]
    except KeyError as exc:  # keep the fixture honest about required keys
        raise AssertionError(f"status fixture lacks {exc}") from exc


def test_unknown_health_warns_without_restart_or_failure_count():
    failures: dict[str, int] = {}
    health = classify({"ok": False, "state": "unknown", "error": "no healthcheck"})
    assert run(health, failures) == ["health_unknown:notes"]
    assert failures == {}


def test_timeouts_and_slow_answers_still_lead_to_restart_after_retries():
    failures: dict[str, int] = {}
    timeout = classify({"ok": False, "error": "TimeoutError"})
    assert run(timeout, failures) == ["health_flapping:notes"]
    assert run(timeout, failures) == ["workload_unhealthy:notes"]
    slow = classify({"ok": True, "elapsed_ms": 900}, 500)
    failures.clear()
    assert run(slow, failures) == ["health_flapping:notes"]
    assert run(slow, failures) == ["workload_unhealthy:notes"]


# ---- configuration --------------------------------------------------------------------


def base():
    return {
        "schema_version": 1,
        "server": {"name": "box", "host": "203.0.113.10", "user": "ops"},
        "admin": {"token_ref": "env:T"},
        "projects": [
            {
                "id": "notes",
                "image": "docker.io/library/nginx@sha256:" + "a" * 64,
                "source_revision": "r1",
                "host_port": 20101,
            }
        ],
    }


def test_new_health_fields_do_not_change_existing_revisions():
    cfg = parse_config(base(), allow_unavailable=True)
    assert "probe" not in effective(cfg)["projects"][0]["health"]
    data = base()
    data["projects"][0]["health"] = {"probe": "tcp", "max_response_ms": 800}
    other = parse_config(data, allow_unavailable=True)
    assert effective(other)["projects"][0]["health"]["probe"] == "tcp"
    assert revision_id(effective(cfg)) != revision_id(effective(other))


@pytest.mark.parametrize(
    "health",
    [
        {"probe": "exec"},
        {"max_response_ms": 5000},  # not below the 5 s timeout
        {"max_response_ms": 10},
        {"probe": "tcp", "command": "id"},
    ],
)
def test_invalid_probe_settings_are_rejected(health):
    data = base()
    data["projects"][0]["health"] = health
    with pytest.raises(ConfigError):
        parse_config(data, allow_unavailable=True)
