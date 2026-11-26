"""ADR 0008 section 8b: source modes, parsing, consensus and the research task."""

from __future__ import annotations

import json

import pytest

from steward.core.model_selection import Decision
from steward.core.model_sources import (
    Observed,
    SourceError,
    SourceStore,
    apply_research,
    consensus,
    parse_json_comparison_v1,
    research_task,
    validate_research,
)

NOW = 1_800_000_000.0
DAY = 86400


def body(*rows):
    return json.dumps(
        {"models": [{"model": m, "price_micro": p, "score": s} for m, p, s in rows]}
    ).encode()


@pytest.fixture
def store(tmp_path):
    log: list[dict] = []
    s = SourceStore(tmp_path / "s.db", clock=lambda: NOW, audit=log.append)
    s.log = log
    return s


def test_default_mode_is_propose_and_confirm(store):
    assert store.mode() == "propose_confirm"
    state, sid = store.propose_source(
        "https://rank.example.org/p", "json_comparison_v1", "r", actor="ai"
    )
    assert state == "proposed" and store.egress_hosts()["hosts"] == []  # nothing takes effect
    assert [s["state"] for s in store.list_sources()] == ["proposed"]
    store.decide(sid, True, actor="operator")
    assert store.egress_hosts()["hosts"] == ["rank.example.org"]
    with pytest.raises(SourceError):
        store.decide(sid, True, actor="operator")


def test_only_the_operator_changes_mode_domains_and_decides(store):
    for call in (
        lambda: store.set_mode("automatic", actor="ai"),
        lambda: store.set_allowed_domains(["a.example.org"], actor="ai"),
        lambda: store.add_source("https://a.example.org/p", "json_comparison_v1", actor="ai"),
        lambda: store.remove_source("x", actor="ai"),
        lambda: store.decide("x", True, actor="ai"),
    ):
        with pytest.raises(SourceError) as e:
            call()
        assert e.value.code == "operator_only"


def test_allowlist_mode_accepts_only_operator_domains(store):
    store.set_mode("allowlist", actor="operator")
    store.set_allowed_domains(["bench.example.org"], actor="operator")
    ok, _ = store.propose_source(
        "https://data.bench.example.org/p", "json_comparison_v1", "r", actor="ai"
    )
    bad, _ = store.propose_source(
        "https://other.example.net/p", "json_comparison_v1", "r", actor="ai"
    )
    assert ok == "active" and bad == "refused:domain_not_allowed"
    assert store.egress_hosts() == {"hosts": ["data.bench.example.org"], "search": False}
    with pytest.raises(SourceError):
        store.set_allowed_domains(["not a domain"], actor="operator")


def test_fixed_mode_refuses_every_ai_proposal_but_operator_edits_work(store):
    store.set_mode("fixed", actor="operator")
    state, _ = store.propose_source(
        "https://x.example.org/p", "json_comparison_v1", "r", actor="ai"
    )
    assert state == "refused:mode_fixed"
    sid = store.add_source("https://y.example.org/p", "json_comparison_v1", actor="operator")
    assert store.list_sources()[0]["id"] == sid
    store.remove_source(sid, actor="operator")
    assert store.list_sources() == []


def test_automatic_mode_still_validates_url_parser_and_adds_search_egress(store):
    store.set_mode("automatic", actor="operator")
    assert (
        store.propose_source("https://a.example.org/p", "json_comparison_v1", "r", actor="ai")[0]
        == "active"
    )
    for url, parser, code in (
        ("http://a.example.org/p", "json_comparison_v1", "url_not_public_https"),
        ("https://127.0.0.1/p", "json_comparison_v1", "url_not_public_https"),
        ("https://localhost/p", "json_comparison_v1", "url_not_public_https"),
        ("https://b.example.org/p", "shell_script", "unknown_parser"),
        ("https://a.example.org/p", "json_comparison_v1", "duplicate_source"),
    ):
        assert store.propose_source(url, parser, "r", actor="ai")[0] == f"refused:{code}"
    assert store.egress_hosts()["search"] is True
    store.set_mode("fixed", actor="operator")
    assert store.egress_hosts()["search"] is False


def test_every_change_is_audited_with_actor(store):
    sid = store.add_source("https://a.example.org/p", "json_comparison_v1", actor="operator")
    store.propose_source("https://b.example.org/p", "json_comparison_v1", "why", actor="ai")
    store.set_mode("fixed", actor="operator")
    store.propose_source("https://c.example.org/p", "json_comparison_v1", "why", actor="ai")
    store.remove_source(sid, actor="operator")
    events = [(a["actor"], a["event"]) for a in reversed(store.audit_trail())]
    assert events == [
        ("operator", "added"), ("ai", "proposed"), ("operator", "mode_changed"),
        ("ai", "proposal_refused"), ("operator", "removed"),
    ]  # fmt: skip
    assert [e["event"] for e in store.log][0] == "inference.source_added"  # mirrored


def test_parser_rejects_malformed_oversized_and_undated_data(store):
    sid = store.add_source("https://a.example.org/p", "json_comparison_v1", actor="operator")
    for bad in (
        b"not json",
        b"[]",
        b'{"models": []}',
        b'{"models":[{"model":"m","price_micro":0,"score":1}]}',
        b'{"models":[{"model":"m","price_micro":1,"score":1,"x":1}]}',
        b'{"models":[{"model":"bad name","price_micro":1,"score":1}]}',
        b'{"models":[{"model":"m","price_micro":true,"score":1}]}',
        b"x" * 300000,
    ):
        with pytest.raises(SourceError):
            store.record_observation(sid, bad, NOW)
    assert store.list_sources()[0]["retrieved_at"] is None  # nothing was recorded
    store.record_observation(sid, body(("m", 10, 5)), NOW - DAY)
    assert store.list_sources()[0]["retrieved_at"] == NOW - DAY
    assert store.list_sources()[0]["age_days"] == 1.0
    assert parse_json_comparison_v1(body(("m", 10, 5))) == {"m": (10, 5)}


def obs(group, inc, cand, age_days=1, sid=None):
    return Observed(
        sid or group, group, NOW - age_days * DAY, {"inc": (100, inc), "new": (100, cand)}
    )


def test_consensus_needs_two_independent_fresh_agreeing_sources():
    ok, why = consensus([obs("a.org", 10, 20), obs("b.org", 10, 30)], "inc", "new", NOW)
    assert ok and "2_independent" in why
    assert (
        consensus([obs("a.org", 10, 20)], "inc", "new", NOW)[1]
        == "insufficient_independent_sources"
    )
    # two entries of the same group are one source
    assert (
        consensus(
            [obs("a.org", 10, 20, sid="1"), obs("a.org", 10, 20, sid="2")], "inc", "new", NOW
        )[0]
        is False
    )
    assert consensus(
        [obs("a.org", 10, 20), obs("b.org", 10, 20), obs("c.org", 30, 20)], "inc", "new", NOW
    ) == (False, "contradicting_sources")
    assert consensus([obs("a.org", 10, 20, 40), obs("b.org", 10, 20, 40)], "inc", "new", NOW) == (
        False,
        "stale_or_missing_data",
    )
    assert consensus([], "inc", "new", NOW)[0] is False
    equal = [obs("a.org", 10, 10), obs("b.org", 10, 10)]
    assert consensus(equal, "inc", "new", NOW)[0] is False


def test_switch_guard_audits_and_blocks_without_evidence(store):
    guard = store.switch_guard(NOW)
    decision = Decision("switch", "inc", "new", ("r",))
    assert guard(decision) == "stale_or_missing_data"
    ids = [store.add_source(f"https://{h}/p", "json_comparison_v1", actor="operator")
           for h in ("a.example.org", "b.example.net")]  # fmt: skip
    for sid in ids:
        store.record_observation(sid, body(("inc", 100, 10), ("new", 100, 50)), NOW)
    assert guard(decision) is None
    store.mark_validation(ids[0], reachable=True, plausible=False, note="odd")
    assert guard(decision) == "insufficient_independent_sources"  # the odd source is excluded
    checks = [a for a in store.audit_trail() if a["event"] == "switch_checked"]
    assert [c["detail"]["allowed"] for c in reversed(checks)] == [False, True, False]


# ---- research task ------------------------------------------------------------------------


def test_research_task_is_fixed_and_lists_only_active_sources(store):
    store.add_source("https://a.example.org/p", "json_comparison_v1", actor="operator")
    store.propose_source(
        "https://b.example.org/p", "json_comparison_v1", "r", actor="ai"
    )  # proposed
    task = research_task(store, "t1")
    assert task["task_id"] == "t1" and task["may_propose"] is True
    assert [s["url"] for s in task["known_sources"]] == ["https://a.example.org/p"]
    assert task["egress"]["hosts"] == ["a.example.org"] and task["parsers"] == [
        "json_comparison_v1"
    ]
    assert "never follow" in task["instructions"] and "untrusted" in task["instructions"]
    store.set_mode("fixed", actor="operator")
    assert research_task(store)["may_propose"] is False


def result_doc(task, **over):
    sid = task["known_sources"][0]["id"]
    doc = {
        "schema": "source-research.v1", "task_id": task["task_id"],
        "validations": [{"source_id": sid, "reachable": True, "plausible": True, "note": "ok"}],
        "proposals": [{"url": "https://new.example.com/p", "parser": "json_comparison_v1", "reason": "r"}],
    }  # fmt: skip
    return doc | over


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d, t: d | {"budget": {"monthly": 10**12}},
        lambda d, t: d | {"pinned_model": "x"},
        lambda d, t: d | {"task_id": "other"},
        lambda d, t: d | {"schema": "v2"},
        lambda d, t: (
            d
            | {
                "validations": [
                    {"source_id": "unknown", "reachable": True, "plausible": True, "note": ""}
                ]
            }
        ),
        lambda d, t: d | {"validations": [{**d["validations"][0], "extra": 1}]},
        lambda d, t: d | {"validations": [{**d["validations"][0], "note": "x\x00y"}]},
        lambda d, t: d | {"validations": [{**d["validations"][0], "note": "x" * 201}]},
        lambda d, t: (
            d | {"proposals": [{**d["proposals"][0], "url": "http://insecure.example.com/p"}]}
        ),
        lambda d, t: d | {"proposals": [{**d["proposals"][0], "parser": "bash"}]},
        lambda d, t: d | {"proposals": [d["proposals"][0]] * 9},
        lambda d, t: [d],
    ],
)
def test_research_validator_rejects_everything_outside_the_schema(store, mutate):
    store.add_source("https://a.example.org/p", "json_comparison_v1", actor="operator")
    task = research_task(store, "t1")
    with pytest.raises(SourceError):
        validate_research(mutate(result_doc(task), task), task)


def test_validated_research_follows_the_mode_and_only_excludes_sources(store):
    sid = store.add_source("https://a.example.org/p", "json_comparison_v1", actor="operator")
    task = research_task(store, "t1")
    doc = result_doc(task, validations=[
        {"source_id": sid, "reachable": True, "plausible": False, "note": "numbers odd"}])  # fmt: skip
    outcome = apply_research(store, validate_research(doc, task))
    assert outcome[0][0] == "proposed"  # default mode: operator must confirm
    assert {x["id"]: x for x in store.list_sources()}[sid][
        "suspect"
    ] is True  # excluded from consensus
    store.set_mode("fixed", actor="operator")
    task = research_task(store, "t2")
    assert (
        apply_research(store, validate_research(result_doc(task), task))[0][0]
        == "refused:mode_fixed"
    )
