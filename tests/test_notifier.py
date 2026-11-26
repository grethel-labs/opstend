import pytest

from steward import notifier
from steward.adapters.notifications import Result
from steward.core.outbox import Outbox


def event(id, delivery, **kw):
    return {"id": id, "delivery": delivery, "severity": "info", "summary": "hello", **kw}


def test_ingestion_cursor_and_daily_digest_survive_replay(tmp_path):
    box = Outbox(tmp_path / "outbox.db")
    page = [event(1, "none"), event(2, "digest"), event(3, "immediate")]
    assert box.ingest("webhook", "ops", page, now=10) == 3
    assert box.ingest("webhook", "ops", page, now=11) == 3
    assert box.cursor("webhook", "ops") == 3
    assert box.flush_digests(now=86399) == 0
    assert box.flush_digests(now=86400) == 1
    assert box.flush_digests(now=86401) == 0
    first = box.claim(now=86401)
    assert first.key == "event:3"
    second = box.claim(now=86401)
    assert second.payload["count"] == 1 and second.key == "digest:0"
    assert box.claim(now=86401) is None


def test_bad_page_rolls_back_messages_and_cursor(tmp_path):
    box = Outbox(tmp_path / "outbox.db")
    with pytest.raises(ValueError):
        box.ingest("webhook", "ops", [event(2, "immediate"), event(1, "none")], now=10)
    assert box.counts() == {} and box.cursor("webhook", "ops") == 0


def test_rate_limit_blocks_other_messages_for_destination_only(tmp_path):
    box = Outbox(tmp_path / "outbox.db")
    box.enqueue("webhook", "ops", "a", {}, now=10)
    first = box.claim(now=10)
    box.retry(first, now=11, retry_after_s=30)
    box.enqueue("webhook", "ops", "b", {}, now=12)
    box.enqueue("webhook", "other", "c", {}, now=12)
    assert box.claim(now=12).destination == "other"
    assert box.claim(now=40) is None
    assert box.claim(now=41).destination == "ops"


def test_repeated_worker_crashes_exhaust_attempts(tmp_path):
    box = Outbox(tmp_path / "outbox.db")
    box.enqueue("webhook", "ops", "a", {}, now=10)
    for i in range(8):
        assert box.claim(now=10 + i, lease_s=1).attempt == i + 1
    assert box.claim(now=18) is None
    assert box.counts() == {"failed": 1}


@pytest.mark.parametrize(
    "result, state",
    [
        (Result(confirmed=True), "delivered"),
        (Result(error_class="unavailable"), "pending"),
        (Result(permanent=True), "failed"),
    ],
)
def test_worker_commits_transport_result(tmp_path, result, state):
    box = Outbox(tmp_path / "outbox.db")

    class Adapter:
        def send(self, key, payload):
            return result

    worker = notifier.Worker(box, {("webhook", "ops"): Adapter()})
    box.enqueue("webhook", "ops", "a", {"summary": "hello"}, now=10)
    assert worker.deliver(now=10)
    assert box.counts() == {state: 1}


def test_collect_uses_collector_socket_and_keeps_destinations_separate(tmp_path, monkeypatch):
    box = Outbox(tmp_path / "outbox.db")
    seen = []

    def call(action, params, **kw):
        seen.append((action, params, kw))
        return {"events": [event(1, "immediate")]}

    monkeypatch.setattr(notifier, "call", call)
    worker = notifier.Worker(
        box, {("discord", "ops"): None, ("webhook", "other"): None}, "col.sock"
    )
    worker.collect(now=10)
    assert len(seen) == 2 and seen[0][2]["socket_path"] == "col.sock"
    assert box.counts() == {"pending": 2}


def test_collector_retention_gap_enqueues_alert_with_page_atomically(tmp_path):
    box = Outbox(tmp_path / "outbox.db")
    box.ingest(
        "webhook", "ops", [event(1, "none")], now=10, coverage={"stream_id": "one", "oldest_id": 1}
    )
    page = [event(5, "immediate")]
    coverage = {"stream_id": "one", "oldest_id": 5}
    box.ingest("webhook", "ops", page, now=20, coverage=coverage)
    box.ingest("webhook", "ops", page, now=21, coverage=coverage)
    assert box.cursor("webhook", "ops") == 5
    gap = box.claim(now=21)
    assert "retention exceeded" in gap.payload["summary"]
    assert box.claim(now=21).key == "event:one:5"
    assert box.claim(now=21) is None


def test_collector_replacement_resets_cursor_and_namespaces_event_keys(tmp_path):
    box = Outbox(tmp_path / "outbox.db")
    box.ingest(
        "webhook",
        "ops",
        [event(10, "immediate")],
        now=10,
        coverage={"stream_id": "one", "oldest_id": 10},
    )
    box.ingest("webhook", "ops", [], now=20, coverage={"stream_id": "two", "oldest_id": 1})
    assert box.cursor("webhook", "ops") == 0
    box.ingest(
        "webhook",
        "ops",
        [event(1, "immediate")],
        now=21,
        coverage={"stream_id": "two", "oldest_id": 1},
    )
    assert box.cursor("webhook", "ops") == 1
    messages = [box.claim(now=21) for _ in range(4)]
    assert any(m.key == "event:two:1" for m in messages)
    assert any("stream changed" in m.payload["summary"] for m in messages)


def test_external_heartbeat_reports_collector_gaps_and_coalesces_backlog(tmp_path, monkeypatch):
    from steward.executor.protocol import ExecutorError

    box = Outbox(tmp_path / "queue.db")
    worker = notifier.Worker(
        box, {("webhook", "ops"): None}, heartbeat_intervals={("webhook", "ops"): 60}
    )

    def missing(*args, **kw):
        raise ExecutorError("unavailable", "collector down")

    monkeypatch.setattr(notifier, "call", missing)
    worker.collect(now=1000)
    worker.collect(now=1001)
    assert box.counts() == {"pending": 1}
    worker.collect(now=1100)
    assert box.counts() == {"pending": 1, "failed": 1}
    heartbeat = box.claim(now=1100)
    assert heartbeat.key == "heartbeat:18"
    assert not heartbeat.payload["collector_current"]
    assert "observation gap" in heartbeat.payload["summary"]


def test_external_heartbeat_current_does_not_claim_host_health(tmp_path, monkeypatch):
    box = Outbox(tmp_path / "queue.db")
    worker = notifier.Worker(
        box, {("webhook", "ops"): None}, heartbeat_intervals={("webhook", "ops"): 60}
    )
    monkeypatch.setattr(
        notifier,
        "call",
        lambda *a, **kw: {
            "events": [],
            "coverage": {"lag_s": 1, "last_cycle": 999, "open_gaps": []},
        },
    )
    worker.collect(now=1000)
    heartbeat = box.claim(now=1000)
    assert heartbeat.payload["collector_current"]
    assert heartbeat.payload["collector_last_cycle"] == 999
    assert "host healthy" not in heartbeat.payload["summary"]


def test_audit_export_is_opt_in_and_keeps_dedup_cursor_atomic(tmp_path):
    box = Outbox(tmp_path / "queue.db")
    record = event(
        1,
        "none",
        kind="audit.record",
        data={
            "original_hash": "a" * 64,
            "previous_hash": "0" * 64,
            "redacted": True,
            "view": {"event": "request"},
        },
    )
    box.ingest("webhook", "normal", [record], now=10)
    assert box.counts() == {}
    box.ingest("webhook", "export", [record], now=10, audit_export=True)
    box.ingest("webhook", "export", [record], now=11, audit_export=True)
    assert box.counts() == {"pending": 1}
    delivery = box.claim(now=11)
    assert delivery.payload["audit"]["original_hash"] == "a" * 64
    assert box.cursor("webhook", "export") == 1


def test_worker_wires_audit_export_only_to_configured_destination(tmp_path, monkeypatch):
    box = Outbox(tmp_path / "queue.db")
    record = event(1, "none", kind="audit.record", data={"original_hash": "a" * 64})
    monkeypatch.setattr(notifier, "call", lambda *a, **kw: {"events": [record]})
    worker = notifier.Worker(
        box,
        {("webhook", "normal"): None, ("webhook", "export"): None},
        audit_destinations={("webhook", "export")},
    )
    worker.collect(now=10)
    assert box.counts() == {"pending": 1}
    assert box.claim(now=10).destination == "export"
