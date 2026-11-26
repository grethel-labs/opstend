import json

import pytest

from steward.core.audit import GENESIS, AuditLog
from steward.core.events import Event, EventStore, classify, correlation_from_request


def ev(kind="deployment", severity="info", ref="r1", ts=100.0, **kw):
    return Event(
        ts=ts,
        source="test",
        source_ref=ref,
        kind=kind,
        severity=severity,
        summary=kw.pop("summary", "s"),
        **kw,
    )


@pytest.mark.parametrize(
    "event, expected",
    [
        (ev("kill_switch.on", "warning"), "immediate"),
        (ev("observation_gap", "high"), "immediate"),
        (ev("audit.discontinuity", "high"), "immediate"),
        (ev("finding.opened", "high"), "immediate"),
        (ev("finding.opened", "critical"), "immediate"),
        (ev("finding.opened", "warning"), "digest"),
        (ev("finding.escalated", "high"), "immediate"),
        (ev("finding.resolved", "info"), "digest"),
        (ev("action.workload_restart", "high", outcome="budget_exhausted"), "immediate"),
        (ev("action.workload_restart", "info", outcome="ok"), "digest"),
        (ev("action.workload_restart", "warning", outcome="kill_switch"), "digest"),
        (ev("request.denied", "high", outcome="unauthorized_peer"), "immediate"),
        (ev("request.denied", "warning", outcome="forbidden_role"), "digest"),
        (ev("log", "high"), "none"),
        (ev("deployment"), "digest"),
    ],
)
def test_delivery_classes_follow_fixed_rules(event, expected):
    assert classify(event) == expected


def test_summary_is_redacted_and_bounded():
    event = ev(summary="db password=hunter2 " + "x" * 2000)
    assert "hunter2" not in event.summary and len(event.summary) == 500


def test_unknown_severity_is_rejected():
    with pytest.raises(ValueError):
        ev(severity="urgent")


@pytest.mark.parametrize(
    "request_id, expected",
    [
        ("f0123456789abcdef-1a2b3c4d", "f0123456789abcdef"),  # controller remediation
        ("4f9c0d8e2b7a4c1e9f3d5b6a7c8d9e0f-2", "4f9c0d8e2b7a4c1e9f3d5b6a7c8d9e0f"),  # API job
        ("abcdef0123456789", "abcdef0123456789"),
        (None, None),
    ],
)
def test_correlation_from_request_id(request_id, expected):
    assert correlation_from_request(request_id) == expected


def test_store_ignores_duplicates_and_updates_cursor_atomically(tmp_path):
    store = EventStore(tmp_path / "e.db")
    assert store.add([ev(ref="a"), ev(ref="b")], {"cursor": 2}) == 2
    assert store.add([ev(ref="a"), ev(ref="c")], {"cursor": 3}) == 1
    assert store.get_meta("cursor") == 3
    assert [e["source_ref"] for e in store.query()] == ["c", "b", "a"]


def test_failed_write_leaves_cursor_unchanged(tmp_path):
    store = EventStore(tmp_path / "e.db")
    store.add([], {"cursor": 1})

    class Broken(Event):
        @property
        def delivery(self):
            raise RuntimeError("boom")

    bad = Broken(ts=1, source="t", source_ref="x", kind="k", severity="info", summary="s")
    with pytest.raises(RuntimeError):
        store.add([ev(ref="ok"), bad], {"cursor": 2})
    assert store.get_meta("cursor") == 1 and store.query() == []


def test_query_filters(tmp_path):
    store = EventStore(tmp_path / "e.db")
    store.add(
        [
            ev("log", "warning", "1", ts=10, project="notes"),
            ev("finding.opened", "high", "2", ts=20, project="notes", correlation_id="c1"),
            ev("action.workload_restart", "info", "3", ts=30, project="notes", correlation_id="c1"),
            ev("finding.opened", "critical", "4", ts=40, project="shop"),
            ev("kind_x", "info", "5", ts=50),
            ev("kindyx", "info", "6", ts=60),
        ]
    )
    refs = lambda **kw: [e["source_ref"] for e in store.query(**kw)]  # noqa: E731
    assert refs(project="notes") == ["3", "2", "1"]
    assert refs(min_severity="high") == ["4", "2"]
    assert refs(correlation_id="c1") == ["3", "2"]
    assert refs(since=20, until=40) == ["3", "2"]
    assert refs(kind_prefix="finding.") == ["4", "2"]
    assert refs(kind_prefix="kind_") == ["5"]  # "_" is literal, not a wildcard
    assert refs(delivery="immediate") == ["4", "2"]
    assert refs(after_id=4) == ["5", "6"]  # ascending when paging forward
    assert refs(limit=2) == ["6", "5"]


def test_prune_by_age_and_size_records_coverage(tmp_path):
    store = EventStore(tmp_path / "e.db")
    day = 86400
    store.add([ev(ref=str(i), ts=i * day) for i in range(10)])
    assert store.prune(now=10 * day, retention_days=5, max_events=1000) == 5
    assert store.coverage(now=10 * day)["oldest"] == 5 * day
    assert store.prune(now=10 * day, retention_days=30, max_events=3) == 2
    coverage = store.coverage(now=10 * day)
    assert coverage["count"] == 3 and coverage["pruned_before"] == 7 * day


def test_audit_read_since_pages_with_cursor(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for index in range(5):
        log.append("event", n=index)
    first = log.read_since(0, "", 2)
    assert [e["n"] for e in first["entries"]] == [0, 1] and first["more"]
    second = log.read_since(first["next_offset"], first["next_hash"], 10)
    assert [e["n"] for e in second["entries"]] == [2, 3, 4] and not second["more"]
    empty = log.read_since(second["next_offset"], second["next_hash"], 10)
    assert empty["entries"] == [] and not empty["reset"]
    log.append("event", n=5)
    later = log.read_since(second["next_offset"], second["next_hash"], 10)
    assert [e["n"] for e in later["entries"]] == [5]


def test_audit_read_since_detects_rewritten_or_truncated_file(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for index in range(3):
        log.append("event", n=index)
    cursor = log.read_since(0, GENESIS, 10)
    lines = log.path.read_text().splitlines()
    log.path.write_text("\n".join(lines[:1]) + "\n")  # truncated
    assert log.read_since(cursor["next_offset"], cursor["next_hash"], 10)["reset"]
    log.path.write_text("\n".join(lines) + "\n")
    wrong = log.read_since(cursor["next_offset"], "f" * 64, 10)
    assert wrong["reset"] and wrong["next_hash"] == json.loads(lines[-1])["hash"]


def test_audit_read_since_skips_a_half_written_line(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("event", n=0)
    with open(log.path, "a") as handle:
        handle.write('{"partial": ')
    result = log.read_since(0, "", 10)
    assert len(result["entries"]) == 1 and not result["more"]


def test_audit_read_returns_tail_of_large_file(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for index in range(400):
        log.append("event", n=index, pad="x" * 300)
    assert [e["n"] for e in log.read(3)] == [397, 398, 399]
    assert len(log.read(1000)) == 400


def test_stream_identity_survives_restart_but_not_database_replacement(tmp_path):
    path = tmp_path / "events.db"
    first = EventStore(path).coverage()["stream_id"]
    assert EventStore(path).coverage()["stream_id"] == first
    assert EventStore(tmp_path / "new.db").coverage()["stream_id"] != first


@pytest.mark.parametrize("invalid", [123, {"legacy": "malformed"}, "x" * 1000, "bad\nrequest"])
def test_legacy_malformed_request_ids_never_poison_correlation(invalid):
    assert correlation_from_request(invalid) is None


def test_audit_byte_budget_preserves_exact_continuation_and_large_legacy_lines(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    originals = [log.append("legacy", request_id={"oversized": "x" * 100000})]
    originals.extend(log.append("normal", payload="y" * 2000) for _ in range(30))

    def view(entry):
        return {k: v for k, v in entry.items() if k != "request_id"}

    result = log.read_since(0, "", 500, max_bytes=10000, transform=view)
    assert result["more"] and len(json.dumps(result).encode()) < 11000
    seen = list(result["entries"])
    while result["more"]:
        result = log.read_since(
            result["next_offset"], result["next_hash"], 500, max_bytes=10000, transform=view
        )
        assert not result["reset"]
        seen.extend(result["entries"])
    assert [e["hash"] for e in seen] == [e["hash"] for e in originals]
    assert log.verify() == (True, 31)
