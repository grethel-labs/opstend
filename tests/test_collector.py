import gc
import json
import os
import threading
import time
import uuid
from types import SimpleNamespace

import pytest

from steward.collector import (
    JOURNAL_BACKLOG_CYCLES,
    LOG_EVENTS_PER_UNIT,
    SNAPSHOT_STALE_S,
    Collector,
    QueryService,
)
from steward.controller import Controller
from steward.core import ipc
from steward.executor import server as executor_server
from steward.executor.protocol import ExecutorError, call

CTL, COL, ME = 4242, 4343, os.getuid()


@pytest.mark.parametrize(
    "kind,outcome,severity",
    [
        ("backup_pause", "prepared", "info"),
        ("backup_resume", "ok", "info"),
        ("backup_resume", "accepted_current", "info"),
        ("backup_resume", "execution_failed", "high"),
        ("backup_schedule", "unavailable", "high"),
    ],
)
def test_backup_pause_lifecycle_maps_to_immediate_project_events(kind, outcome, severity):
    from steward.collector import audit_events

    (event,) = audit_events(
        {
            "event": kind,
            "outcome": outcome,
            "ts": time.time(),
            "hash": "b" * 64,
            "artifact": "a" * 32,
            "project_id": "notes",
        }
    )
    assert event.delivery == "immediate" and event.project == "notes"
    assert event.kind.startswith("backup.") and event.severity == severity


def test_query_threads_release_sqlite_without_garbage_collection(tmp_path):
    from steward.core.events import EventStore

    store = EventStore(tmp_path / "events.db")
    service = QueryService(store, {ME: "api"})
    results = []

    def query():
        results.append(service.handle(b'{"v":1,"action":"events_coverage"}', ME))
        assert getattr(store._local, "conn", None) is None

    enabled = gc.isenabled()
    gc.disable()
    try:
        for _ in range(600):
            thread = threading.Thread(target=query)
            thread.start()
            thread.join()
        assert len(results) == 600 and all(result["ok"] for result in results)
    finally:
        if enabled:
            gc.enable()


def via(executor, uid):
    """Call the executor in-process with the given peer uid."""

    def _call(action, params=None, socket_path=None, request_id=None):
        raw = json.dumps(
            {
                "v": 1,
                "action": action,
                "params": params or {},
                "request_id": request_id or uuid.uuid4().hex,
                "expires_at": time.time() + 60,
            }
        ).encode()
        response = executor.handle(raw, uid)
        if response["ok"]:
            return response["result"]
        raise ExecutorError(response["error_class"], response["message"])

    return _call


@pytest.fixture
def setup(tmp_path, executor):
    (tmp_path / "ctl").mkdir()
    (tmp_path / "col").mkdir()
    controller = Controller(str(tmp_path / "ctl"), executor=via(executor, CTL))
    collector = Collector(
        str(tmp_path / "col"),
        executor=via(executor, COL),
        controller_export=str(tmp_path / "ctl" / "export" / "state.json"),
    )
    return SimpleNamespace(ex=executor, ctl=controller, col=collector, host=executor.host)


def kinds(collector, **query):
    return [e["kind"] for e in reversed(collector.store.query(**query))]


def journal_entry(n, message, uid=-1, priority=3, unit="steward-api.service"):
    ts = time.time() - 600 + n / 1000  # recent, so the retention rule keeps it
    return {
        "__CURSOR": f"c{n:06d}",
        "__REALTIME_TIMESTAMP": str(int(ts * 1e6)),
        "PRIORITY": str(priority),
        "_UID": str(uid),
        "_SYSTEMD_UNIT": unit,
        "MESSAGE": message,
    }


# ---- executor side ------------------------------------------------------------------------


def test_collector_role_may_only_read_logs(setup):
    col = via(setup.ex, COL)
    col("audit_since", {"offset": 0, "prev_hash": "", "limit": 10})
    col("journal_since", {"cursor": None, "limit": 10})
    for action, params in (
        ("workload_restart", {"project_id": "notes", "reason": "x"}),
        ("firewall_reassert", {}),
        ("platform_status", {}),
        ("audit_tail", {}),
    ):
        with pytest.raises(ExecutorError) as exc:
            col(action, params)
        assert exc.value.error_class == "forbidden_role"
    with pytest.raises(ExecutorError) as exc:
        via(setup.ex, ME)("journal_since", {"cursor": None})  # api role
    assert exc.value.error_class == "forbidden_role"
    assert setup.host.calls == []


def test_journal_is_limited_to_registered_components(setup, monkeypatch):
    uids = {"steward-proxy": 21000, "stw-notes": 21001}
    monkeypatch.setattr(
        executor_server.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=uids[name])
    )
    via(setup.ex, COL)("journal_since", {"cursor": "s=1;i=2", "limit": 7})
    matches, cursor, limit, skip = setup.host.journal_calls[-1]
    assert "_UID=21000" in matches and "_UID=21001" in matches
    assert "_SYSTEMD_UNIT=steward-executor.service" in matches
    assert all(m.split("=")[0] in ("_UID", "_SYSTEMD_UNIT", "UNIT") for m in matches)
    assert (cursor, limit, skip) == ("s=1;i=2", 7, False)


def test_journal_lines_are_redacted_before_leaving_the_executor(setup, monkeypatch):
    monkeypatch.setattr(
        executor_server.pwd,
        "getpwnam",
        lambda name: SimpleNamespace(pw_uid={"stw-notes": 21001}.get(name, 1)),
    )
    setup.host.secrets = ("s3cr3t-project-value",)
    setup.host.journal_entries = [
        journal_entry(1, "connect failed with s3cr3t-project-value", uid=21001),
        journal_entry(2, "Authorization: Bearer abc.def password=hunter2"),
        journal_entry(3, [104, 105, 255]),  # non-UTF-8 message as byte array
        journal_entry(4, "x" * 5000),
    ]
    result = via(setup.ex, COL)("journal_since", {"cursor": None, "limit": 10})
    messages = [e["message"] for e in result["entries"]]
    assert "s3cr3t-project-value" not in messages[0] and "[redacted]" in messages[0]
    assert "abc.def" not in messages[1] and "hunter2" not in messages[1]
    assert messages[2].startswith("hi")
    assert len(messages[3]) == executor_server.JOURNAL_MESSAGE_MAX
    assert result["entries"][0]["owner"] == "notes" and result["entries"][1]["owner"] is None


# ---- collection -------------------------------------------------------------------------


def test_actions_and_refusals_become_events_once(setup):
    via(setup.ex, ME)("workload_restart", {"project_id": "notes", "reason": "ui"})
    with pytest.raises(ExecutorError):
        via(setup.ex, 31337)("platform_status")
    setup.col.cycle()
    setup.col.cycle()
    events = setup.col.store.query(kind_prefix="action.")
    assert len(events) == 1 and events[0]["project"] == "notes" and events[0]["outcome"] == "ok"
    denied = setup.col.store.query(kind_prefix="request.")
    assert denied[0]["outcome"] == "unauthorized_peer" and denied[0]["delivery"] == "immediate"


def test_restart_of_the_collector_neither_loses_nor_duplicates(setup, tmp_path):
    via(setup.ex, ME)("workload_restart", {"project_id": "notes", "reason": "a"})
    setup.col.cycle()
    via(setup.ex, ME)("workload_restart", {"project_id": "notes", "reason": "b"})
    again = Collector(
        str(tmp_path / "col"),
        executor=via(setup.ex, COL),
        controller_export=str(tmp_path / "missing.json"),
    )
    again.cycle()
    assert len(again.store.query(kind_prefix="action.")) == 2


def test_kill_switch_and_deployment_records(setup):
    setup.ex.audit.append("kill_switch", state="on", by="operator")
    setup.ex.audit.append("deployment", revision="a" * 64, release="0.1.0", outcome="verified")
    setup.col.cycle()
    on = setup.col.store.query(kind_prefix="kill_switch.")[0]
    assert on["kind"] == "kill_switch.on" and on["delivery"] == "immediate"
    deployment = setup.col.store.query(kind_prefix="deployment")[0]
    assert deployment["delivery"] == "digest" and deployment["data"]["release"] == "0.1.0"
    assert deployment["summary"] == (
        "Deployment of release 0.1.0 applied and verified (configuration aaaaaaaaaaaa)."
    )


def test_finding_remediation_and_resolution_share_one_correlation(setup):
    setup.host.units["notes.service"] = "failed"
    snapshot = setup.ctl.cycle()  # finding opened, restart requested, host recovers
    corr = snapshot["findings"][0]["correlation_id"]
    setup.col.cycle()
    setup.ctl.cycle()  # finding gone
    setup.col.cycle()
    story = setup.col.store.query(correlation_id=corr)
    assert sorted(e["kind"] for e in story) == [
        "action.workload_restart",
        "finding.opened",
        "finding.resolved",
    ]
    opened = next(e for e in story if e["kind"] == "finding.opened")
    assert opened["delivery"] == "immediate" and opened["project"] == "notes"


def test_escalation_is_reported_immediately_once(setup):
    setup.host.restart_user_unit = lambda user, unit: (
        setup.host.calls.append(("restart", user, unit)) or (True, "")
    )  # never recovers
    setup.host.units["notes.service"] = "failed"
    now = time.time()
    for step in range(10):
        setup.ctl.cycle(now=now + step * 121)
        setup.col.cycle(now=now + step * 121)
    escalations = setup.col.store.query(kind_prefix="finding.escalated")
    assert len(escalations) == 1 and escalations[0]["delivery"] == "immediate"
    budget = [
        e
        for e in setup.col.store.query(kind_prefix="action.")
        if e["outcome"] == "budget_exhausted"
    ]
    assert budget and budget[0]["delivery"] == "immediate"


def test_executor_outage_is_one_gap_and_one_recovery(setup):
    down = {"value": True}
    working = via(setup.ex, COL)

    def flaky(*args, **kwargs):
        if down["value"]:
            raise ExecutorError("unavailable", "socket missing")
        return working(*args, **kwargs)

    setup.col.executor = flaky
    for _ in range(3):
        setup.col.cycle()
    down["value"] = False
    setup.col.cycle()
    setup.col.cycle()
    gaps = [e for e in setup.col.store.query() if e["target"] == "executor"]
    assert sorted(e["kind"] for e in gaps) == ["observation_gap", "observation_restored"]
    assert setup.col.store.coverage()["open_gaps"] == [
        g for g in setup.col.store.coverage()["open_gaps"] if g["source"] != "executor"
    ]


def test_stale_controller_snapshot_is_a_gap(setup, tmp_path):
    setup.ctl.cycle()
    setup.col.cycle()
    assert "observation_gap" not in kinds(setup.col)
    setup.col.cycle(now=time.time() + SNAPSHOT_STALE_S + 5)
    gap = setup.col.store.query(kind_prefix="observation_gap")[0]
    assert gap["target"] == "controller" and gap["delivery"] == "immediate"


def test_rewritten_audit_is_reported_as_discontinuity(setup):
    via(setup.ex, ME)("workload_restart", {"project_id": "notes", "reason": "a"})
    setup.col.cycle()
    setup.ex.audit.path.write_text("")
    setup.ex.audit.append("executor_start", pid=1)
    setup.col.cycle()
    assert setup.col.store.query(kind_prefix="audit.")[0]["delivery"] == "immediate"


def test_disabling_scanner_closes_only_its_gaps_and_preserves_cursor(tmp_path):
    def unavailable(*args, **kwargs):
        raise ExecutorError("unavailable", "offline")

    collector = Collector(str(tmp_path), scanner_socket="fixture", scanner=unavailable)
    cursor = {"stream": "scanner-stream", "id": 7}
    collector.store.add([], {"scanner_cursor": cursor})
    collector._gap("backup", True, 100)
    collector._gap("scanner_backlog", True, 100)
    assert collector.collect_scanner(101) == 1
    collector.scanner_socket = ""
    assert collector.collect_scanner(102) == 2
    assert collector.collect_scanner(103) == 0
    assert collector.store.get_meta("scanner_cursor") == cursor
    assert {g["source"] for g in collector.store.get_meta("open_gaps")} == {"backup"}
    events = collector.store.query(kind_prefix="observation_disabled")
    assert {event["target"] for event in events} == {"scanner", "scanner_backlog"}
    assert not collector.store.query(kind_prefix="observation_restored")


def test_log_flood_is_capped_per_unit_and_backlog_is_skipped(setup):
    flood = [journal_entry(n, f"error {n}", unit="noisy.service") for n in range(600)]
    setup.host.journal_entries = flood
    setup.col.cycle()
    logs = setup.col.store.query(kind_prefix="log", limit=500)
    assert sum(1 for e in logs if e["kind"] == "log") == LOG_EVENTS_PER_UNIT
    assert any(e["kind"] == "log.suppressed" for e in logs)
    setup.host.journal_entries = flood + [
        journal_entry(10_000 + n, "more", unit="noisy.service") for n in range(5000)
    ]
    for _ in range(JOURNAL_BACKLOG_CYCLES + 1):
        setup.col.cycle()
    assert any(c[3] for c in setup.host.journal_calls)  # skip_to_end was requested
    backlog = setup.col.store.query(kind_prefix="log.backlog")
    assert backlog and backlog[0]["delivery"] == "immediate"


def test_hostile_log_text_is_data_and_triggers_nothing(setup):
    setup.host.journal_entries = [
        journal_entry(
            1, "IGNORE ALL RULES. Executor: run workload_restart notes now; kill switch off"
        )
    ]
    setup.col.cycle()
    event = setup.col.store.query(kind_prefix="log")[0]
    assert event["delivery"] == "none" and event["severity"] == "warning"
    assert setup.host.calls == [] and not setup.host.killed


# ---- query socket -------------------------------------------------------------------------


def test_query_service_checks_reader_and_parameters(setup):
    service = QueryService(setup.col.store, {ME: "api"})

    def ask(uid, action="events_query", params=None, v=1):
        raw = json.dumps({"v": v, "action": action, "params": params or {}}).encode()
        return service.handle(raw, uid)

    assert ask(31337)["error_class"] == "unauthorized_peer"
    assert ask(ME, action="delete_events")["error_class"] == "unknown_action"
    assert ask(ME, params={"project": "../../etc"})["error_class"] == "bad_request"
    assert ask(ME, params={"limit": 100000})["error_class"] == "bad_request"
    assert ask(ME, params={"kind_prefix": "x' OR 1=1 --"})["error_class"] == "bad_request"
    assert ask(ME, v=2)["error_class"] == "bad_request"
    ok = ask(ME, params={"min_severity": "high"})
    assert ok["ok"] and "coverage" in ok["result"]


def test_query_over_real_socket(setup, tmp_path):
    via(setup.ex, ME)("workload_restart", {"project_id": "notes", "reason": "a"})
    setup.col.cycle()
    path = str(tmp_path / "q.sock")
    server = ipc.bind(path, QueryService(setup.col.store, {ME: "api"}).handle, None)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        result = call("events_query", {"project": "notes"}, socket_path=path)
        assert result["events"][0]["kind"] == "action.workload_restart"
        assert result["coverage"]["count"] >= 1 and result["coverage"]["lag_s"] is not None
    finally:
        server.shutdown()
        server.server_close()


def test_audit_export_is_redacted_at_root_and_preserves_original_hash_anchors(setup):
    setup.host.secrets = ("deployed-credential-value",)
    original = setup.ex.audit.append(
        "request",
        action="workload_restart",
        role="api",
        request_id="abcdefgh",
        outcome="ok",
        params={"project_id": "notes", "reason": "deployed-credential-value password=bad"},
    )
    setup.col.collect_audit(time.time())
    records = setup.col.store.query(kind_prefix="audit.record")
    exported = next(e for e in records if e["source_ref"] == original["hash"])
    assert exported["delivery"] == "none"
    assert exported["data"]["original_hash"] == original["hash"]
    assert exported["data"]["previous_hash"] == original["prev"]
    assert exported["data"]["redacted"]
    serialized = json.dumps(exported)
    assert "deployed-credential-value" not in serialized and "password=bad" not in serialized
    assert setup.ex.audit.verify()[0]  # Original log remains unchanged and verifiable.


def test_signed_receiver_observes_heartbeat_and_audit_discontinuity(setup, tmp_path, monkeypatch):
    import hashlib
    import hmac
    import http.server
    import socket
    import ssl
    import subprocess

    from steward.adapters import notifications
    from steward.core.outbox import Outbox
    from steward.notifier import Worker

    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )
    accepted = {}
    secret = "fixture-key-" * 4

    class Receiver(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            stamp = self.headers["X-Steward-Timestamp"]
            signature = hmac.new(secret.encode(), stamp.encode() + b"." + body, hashlib.sha256)
            if not hmac.compare_digest(
                "v1=" + signature.hexdigest(), self.headers["X-Steward-Signature"]
            ):
                self.send_response(401)
            else:
                message = json.loads(body)
                accepted.setdefault(message["id"], message["payload"])
                self.send_response(204)
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Receiver)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    connect, create_context = socket.create_connection, ssl.create_default_context

    def connect_test_receiver(address, timeout):
        assert address == ("127.0.0.1", 443)
        return connect(("127.0.0.1", server.server_port), timeout)

    # Route only the test transport to loopback, with real certificate verification.
    monkeypatch.setattr(notifications, "public_addresses", lambda _host: ["127.0.0.1"])
    monkeypatch.setattr(socket, "create_connection", connect_test_receiver)
    monkeypatch.setattr(ssl, "create_default_context", lambda: create_context(cafile=str(cert)))
    path = str(tmp_path / "collector.sock")
    events = ipc.bind(path, QueryService(setup.col.store, {ME: "notifier"}).handle, None)
    threads = [threading.Thread(target=x.serve_forever, daemon=True) for x in (server, events)]
    for thread in threads:
        thread.start()

    clock = time.time()
    destination = ("webhook", "receiver")
    box = Outbox(tmp_path / "notifier.db")
    adapter = notifications.SignedWebhook("https://localhost/events", secret)
    worker = Worker(box, {destination: adapter}, path, {destination: 60}, {destination})

    def deliver(now):
        worker.collect(now=now)
        for _ in range(20):
            if not worker.deliver(now=now):
                return
        pytest.fail("fixture outbox did not drain")

    def heartbeat_missing(now):
        latest = max((p["observed_at"] for p in accepted.values() if "observed_at" in p), default=0)
        return now - latest > 60

    try:
        invalid = notifications.SignedWebhook("https://localhost/events", "wrong-fixture-key" * 3)
        assert not invalid.send("invalid", {"summary": "bad signature"}).confirmed
        assert not accepted
        setup.host.secrets = ("private-fixture-value",)
        first = setup.ex.audit.append(
            "request", action="workload_restart", detail="private-fixture-value"
        )
        second = setup.ex.audit.append("executor_start", pid=42)
        setup.col.collect_audit(clock)
        setup.col.store.add([], {"last_cycle": clock})
        deliver(clock + 1)
        heartbeat = next(p for p in accepted.values() if "observed_at" in p)
        assert heartbeat["collector_current"] and heartbeat["observed_at"] == clock + 1
        assert not heartbeat_missing(clock + 61)
        assert heartbeat_missing(clock + 62)
        anchors = {
            p["audit"]["original_hash"]: p["audit"] for p in accepted.values() if "audit" in p
        }
        assert anchors[second["hash"]]["previous_hash"] == first["hash"]
        assert anchors[first["hash"]]["redacted"] and "private-fixture-value" not in json.dumps(
            accepted
        )

        setup.ex.audit.path.write_text("")  # Simulate replacing only the disposable audit fixture.
        setup.ex.audit.append("executor_start", pid=43)
        setup.col.collect_audit(clock + 180)
        # The query service calculates collector lag on its own wall clock.
        setup.col.store.add([], {"last_cycle": clock - 180})
        deliver(clock + 180)
        assert any("no longer continues" in p["summary"] for p in accepted.values())
        assert any(
            p.get("observed_at") == clock + 180 and not p["collector_current"]
            for p in accepted.values()
        )
        assert not heartbeat_missing(clock + 181)
        assert box.counts().keys() == {"delivered"}
    finally:
        for listener in (events, server):
            listener.shutdown()
            listener.server_close()
        for thread in threads:
            thread.join(timeout=2)


def test_oversized_audit_view_keeps_hash_anchors(setup):
    original = setup.ex.audit.append("test", detail="x" * 5000)
    setup.col.collect_audit(time.time())
    exported = setup.col.store.query(kind_prefix="audit.record")[0]
    assert exported["data"]["view"] == {"truncated": True}
    assert exported["data"]["original_hash"] == original["hash"]


def test_legacy_bad_audit_ids_are_redacted_and_do_not_block_later_records(setup):
    setup.ex.audit.append(
        "request",
        action="workload_restart",
        outcome="ok",
        role="api",
        request_id={"legacy": "x" * 100000},
    )
    setup.ex.audit.append(
        "request",
        action="workload_restart",
        outcome="ok",
        role="api",
        request_id="abcdefgh",
        params={"project_id": "notes"},
    )
    for _ in range(150):
        setup.ex.audit.append("legacy", detail="y" * 2500)
    setup.col.collect_audit(time.time())
    assert len(setup.col.store.query(kind_prefix="audit.record", limit=500)) == 152
    assert len(setup.col.store.query(kind_prefix="action.")) == 2
    cursor = setup.col.store.get_meta("audit_cursor")
    assert (
        via(setup.ex, COL)(
            "audit_since", {"offset": cursor["offset"], "prev_hash": cursor["hash"]}
        )["entries"]
        == []
    )
    assert setup.ex.audit.verify()[0]


def test_real_socket_event_byte_budget_preserves_stream_progress(tmp_path):
    from steward.core.events import Event, EventStore

    store = EventStore(tmp_path / "events.db")
    store.add(
        [
            Event(
                ts=1,
                source="journal",
                source_ref=str(i),
                kind="log",
                severity="warning",
                summary="😀" * 500,
            )
            for i in range(200)
        ]
    )
    service = QueryService(store, {os.getuid(): "api"})
    path = str(tmp_path / "q.sock")
    server = ipc.bind(path, service.handle, None)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        cursor, ids = 0, []
        while len(ids) < 200:
            result = call("events_query", {"after_id": cursor, "limit": 200}, socket_path=path)
            assert result["events"]
            assert len(json.dumps(result, ensure_ascii=False).encode()) < ipc.MAX_MESSAGE_BYTES
            ids.extend(e["id"] for e in result["events"])
            cursor = ids[-1]
        assert len(set(ids)) == 200 and ids == sorted(ids)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_capacity_audit_has_fixed_immediate_delivery_and_rejects_unknown_reasons():
    from steward.collector import audit_events

    entry = {
        "event": "backup_capacity",
        "ts": 1,
        "hash": "a" * 64,
        "project_id": "notes",
        "namespace": "import",
        "reason": "space",
    }
    (event,) = audit_events(entry)
    assert event.kind == "backup.capacity" and event.severity == "high"
    assert event.delivery == "immediate" and event.data == {
        "namespace": "import",
        "reason": "space",
    }
    assert audit_events({**entry, "reason": "hostile text"}) == []


@pytest.mark.parametrize(
    "outcome,severity,delivery",
    [
        ("removed", "info", "digest"),
        ("policy_denied", "warning", "digest"),
        ("unavailable", "high", "immediate"),
        ("internal", "high", "immediate"),
    ],
)
def test_retention_audit_reports_refusal_and_failure(outcome, severity, delivery):
    from steward.collector import audit_events

    entry = {
        "event": "backup_retirement",
        "ts": 1,
        "hash": "a" * 64,
        "project_id": "notes",
        "namespace": "import",
        "outcome": outcome,
        "automatic": True,
    }
    (event,) = audit_events(entry)
    assert event.kind == "backup.retirement" and event.project == "notes"
    assert event.severity == severity and event.delivery == delivery
    assert event.data == {"namespace": "import", "automatic": True}
    assert audit_events({**entry, "outcome": "started"}) == []


def test_retirement_event_rejects_untrusted_outcome_text():
    from steward.collector import audit_events

    (event,) = audit_events(
        {
            "event": "backup_retirement",
            "ts": 1,
            "hash": "a" * 64,
            "outcome": ["hostile"],
            "namespace": "arbitrary",
            "automatic": "yes",
        }
    )
    assert event.outcome == "internal" and event.delivery == "immediate"
    assert event.data == {"namespace": "unknown", "automatic": False}
    assert "hostile" not in event.summary


def test_worker_capacity_event_is_explicitly_untrusted_and_requires_attribution():
    from steward.collector import audit_events

    entry = {
        "event": "backup_capacity",
        "ts": 1,
        "hash": "a" * 64,
        "project_id": "notes",
        "namespace": "worker",
        "reason": "limit",
    }
    assert audit_events(entry) == []
    (event,) = audit_events({**entry, "reported_by": "backup"})
    assert event.delivery == "immediate" and event.data["reported_by"] == "backup"
    assert "worker reported" in event.summary
