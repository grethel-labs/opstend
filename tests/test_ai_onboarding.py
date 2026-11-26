"""ADR 0008 onboarding: provider choice, scan, initial model, pin, reports, best-now."""

from __future__ import annotations

import dataclasses

import pytest

from steward.core.ai_auth import AUTH_METHODS, Evidence
from steward.core.ai_onboarding import (
    MAX_MODELS,
    HostFacts,
    LocalDownload,
    Onboarding,
    OnboardingError,
    evaluate_model,
)
from steward.core.inference_budget import Ledger, Price
from steward.core.model_selection import RunResult, SelectionStore, WeeklySelection
from steward.core.model_sources import SourceStore
from test_model_selection import HAIKU, IN_WINDOW, SONNET, FakeProvider, Harness, make_ai

SHA = "a" * 64
EVIDENCE = Evidence("https://example.invalid/docs", "2026-11-23", "test evidence")


def with_evidence(*ids):
    return {
        k: (dataclasses.replace(v, evidence=EVIDENCE) if k in ids else v)
        for k, v in AUTH_METHODS.items()
    }


class Lister:
    def __init__(self, name, models):
        self.name, self.models = name, models

    def list_models(self, timeout_s=10.0):
        return list(self.models)


@pytest.fixture
def ob(tmp_path):
    clock = [1_800_000_000.0]
    audit: list[dict] = []
    sources = SourceStore(tmp_path / "sources.db", clock=lambda: clock[0], audit=audit.append)
    o = Onboarding(
        tmp_path / "ai",
        SelectionStore(tmp_path / "selection.db"),
        sources,
        clock=lambda: clock[0],
        audit=audit.append,
        auth_methods=with_evidence("ollama-cloud"),
    )
    o.audit_log, o.clock_box = audit, clock
    return o


def ready(ob, models=("m-a", "m-b", "deepseek-v4.1-flash")):
    ob.choose_provider("anthropic-api", key_ref="env:ANTHROPIC_KEY")
    ob.scan(Lister("anthropic", models))
    return ob.pick_initial("m-a")


def test_subscription_and_signin_are_unavailable_without_evidence(tmp_path):
    clock = lambda: 1.0  # noqa: E731
    o = Onboarding(
        tmp_path / "ai",
        SelectionStore(tmp_path / "s.db"),
        SourceStore(tmp_path / "src.db", clock=clock),
        clock=clock,
    )
    listing = {x["id"]: x for x in o.options()}
    for pid in ("claude-subscription", "codex-subscription", "ollama-cloud"):
        assert not listing[pid]["available"] and "evidence" in listing[pid]["reason"]
        with pytest.raises(OnboardingError) as e:
            o.choose_provider(pid)
        assert e.value.code == "method_unavailable"
    assert all(x["runtime_enabled"] is False for x in listing.values())  # ai.provider gated
    assert all(x["default_status"] == "UNVERIFIED" for x in listing.values())
    assert listing["anthropic-api"]["available"] and listing["ollama-local"]["available"]
    assert listing["ollama-cloud"]["reason"] == AUTH_METHODS["ollama-cloud"].unavailable_reason
    direct = listing["ollama-cloud-api"]
    assert direct["available"] and direct["auth"] == "api_key"
    assert direct["data_class"] == "external"
    assert listing["codex-subscription"]["default_hint"] == "gpt-6.1-terra"
    assert listing["ollama-local"]["default_hint"] == ""


@pytest.mark.parametrize("option", ["anthropic-api", "ollama-cloud-api"])
def test_api_key_needs_a_reference_never_a_literal(ob, option):
    with pytest.raises(OnboardingError):
        ob.choose_provider(option)
    with pytest.raises(OnboardingError):
        ob.choose_provider(option, key_ref="sk-literal-secret-value")
    with pytest.raises(OnboardingError):
        ob.choose_provider("ollama-cloud", key_ref="env:X")
    st = ob.choose_provider(option, key_ref="env:TEST_PROVIDER_KEY")
    assert st["key_ref"] == "env:TEST_PROVIDER_KEY" and st["status"] == "provider_chosen"
    with pytest.raises(OnboardingError) as e:
        ob.choose_provider("openai-api", key_ref="env:O")
    assert e.value.code == "provider_already_chosen"
    ob.choose_provider("openai-api", key_ref="env:O", replace=True)


@pytest.mark.parametrize(
    ("option", "adapter", "key_ref", "exact", "near_matches", "wrong_adapter"),
    [
        (
            "ollama-cloud",
            "ollama-cloud",
            None,
            "deepseek-v4.1-flash:cloud",
            ["deepseek-v4.1-flash", "deepseek-v4.1-flash-cloud", "deepseek-v4.1-flash:cloud-2"],
            "ollama-cloud-api",
        ),
        (
            "ollama-cloud-api",
            "ollama-cloud-api",
            "env:TEST_KEY",
            "deepseek-v4.1-flash",
            ["deepseek-v4.1-flash:cloud", "deepseek-v4.1-flash-preview", "x/deepseek-v4.1-flash"],
            "ollama-cloud",
        ),
        (
            "anthropic-api",
            "anthropic",
            "env:TEST_KEY",
            "claude-sonnet-5-5",
            ["claude-sonnet-5-5-20261125", "claude-sonnet-55", "x/claude-sonnet-5-5"],
            "openai",
        ),
    ],
)
def test_scan_only_lists_the_chosen_provider_and_suggests_a_scanned_default(
    ob, option, adapter, key_ref, exact, near_matches, wrong_adapter, monkeypatch
):
    with pytest.raises(OnboardingError) as e:
        ob.scan(Lister("ollama", ["x"]))
    assert e.value.code == "no_provider_chosen"
    ob.choose_provider(option, key_ref=key_ref)
    wrong = Lister(wrong_adapter, [exact])
    monkeypatch.setattr(wrong, "list_models", lambda: pytest.fail("wrong lister was called"))
    with pytest.raises(OnboardingError) as e:
        ob.scan(wrong)
    assert e.value.code == "scan_provider_mismatch"
    assert ob.scan(Lister(adapter, near_matches))["suggested"] is None
    assert ob.scan(Lister(adapter, [exact]))["suggested"] == exact
    assert ob.view()["suggested"] == exact

    variant = exact.upper()
    listed = [*near_matches, variant]
    out = ob.scan(Lister(adapter, [*listed, "bad name!", variant]))
    assert out == {"models": sorted(listed), "suggested": variant}

    unrelated = [f"B-{i:03d}" for i in range(MAX_MODELS)]
    out = ob.scan(Lister(adapter, [*listed, exact, *unrelated]))
    assert len(out["models"]) == MAX_MODELS
    assert {exact, variant} <= set(out["models"])
    assert out["suggested"] is None
    assert ob.view()["suggested"] is None


def test_initial_model_must_be_scanned_becomes_active_and_owes_one_report(ob):
    ob.choose_provider("anthropic-api", key_ref="env:K")
    with pytest.raises(OnboardingError) as e:
        ob.pick_initial("m-a")
    assert e.value.code == "scan_required"
    ob.scan(Lister("anthropic", ["m-a", "m-b"]))
    with pytest.raises(OnboardingError) as e:
        ob.pick_initial("not-listed")
    assert e.value.code == "model_not_in_scan"
    state = ob.pick_initial("m-a")
    assert state["status"] == "ready" and ob.selection.active()["model"] == "m-a"
    assert state["report_due"] == {"reason": "initial_check", "model": "m-a"}
    calls = []
    report = ob.ensure_report(lambda m: calls.append(m) or {"passed": True})
    assert report["reason"] == "initial_check" and report["model"] == "m-a"
    assert ob.ensure_report(lambda m: calls.append(m) or {}) is None  # nothing more is due
    assert calls == ["m-a"] and report["total_reports"] == 1


def test_failed_check_creates_no_report_and_stays_due(ob):
    ready(ob)

    def boom(model):
        raise OnboardingError("check_failed")

    with pytest.raises(OnboardingError):
        ob.ensure_report(boom)
    assert ob.latest_report() is None and ob.state()["report_due"]


def test_pin_to_other_model_is_a_selection_change_with_one_report(ob):
    ready(ob)
    ob.ensure_report(lambda m: {"ok": 1})
    ob.pin("m-a")  # same model: no change, no report
    assert ob.state()["report_due"] is None and ob.state()["pinned"] == "m-a"
    ob.pin("m-b")
    assert ob.selection.active()["model"] == "m-b" and ob.selection.active()["fallback"] == "m-a"
    assert ob.state()["report_due"]["reason"] == "selection_change"
    assert ob.ensure_report(lambda m: {"ok": 2})["reason"] == "selection_change"
    ob.unpin()  # not a selection change
    assert ob.state()["report_due"] is None and ob.latest_report()["total_reports"] == 2
    with pytest.raises(OnboardingError):
        ob.pin("never-scanned")


def test_guards_pin_and_auto_switch(ob):
    skip = ob.guards(weekly=True).skip
    assert skip() == "onboarding_incomplete"
    ready(ob)
    assert skip() == "auto_selection_disabled"
    assert ob.guards(weekly=False).skip() is None
    ob.set_auto(True)
    assert skip() is None
    ob.pin("m-b")
    assert skip() == "model_pinned" and ob.guards(weekly=False).skip() == "model_pinned"
    ob.unpin()
    ob.set_auto(False)
    assert skip() == "auto_selection_disabled"


def test_local_model_needs_declared_checksum_resources_and_license(ob):
    decl = LocalDownload(
        "local-1", SHA, download_mb=4000, ram_mb=8000, disk_mb=6000, license_ack=True
    )
    host = HostFacts(ram_total_mb=16000, disk_free_mb=50000, reserved_memory_mb=2000)
    with pytest.raises(OnboardingError) as e:
        ob.choose_provider("ollama-local")
    assert e.value.code == "local_download_declaration_required"
    poor = HostFacts(ram_total_mb=4000, disk_free_mb=5000, reserved_memory_mb=2000)
    with pytest.raises(OnboardingError) as e:
        ob.choose_provider("ollama-local", local=decl, host=poor)
    assert e.value.code == "resource_refused" and len(e.value.problems) == 2
    assert ob.state()["provider"] is None  # refusal changes nothing
    with pytest.raises(OnboardingError) as e:
        ob.choose_provider(
            "ollama-local", local=dataclasses.replace(decl, license_ack=False), host=host
        )
    assert "license" in e.value.problems[0]
    with pytest.raises(OnboardingError):
        ob.choose_provider("ollama-local", local=dataclasses.replace(decl, sha256="zz"), host=host)
    ob.choose_provider("ollama-local", local=decl, host=host)
    ob.scan(Lister("ollama", ["local-1"]))
    with pytest.raises(OnboardingError) as e:
        ob.pick_initial("other")
    assert e.value.code == "model_not_the_declared_download"
    assert ob.pick_initial("local-1")["status"] == "awaiting_download"
    assert ob.selection.active() is None  # nothing active before the checked download
    assert ob.request_action("initial_check") is None and ob.requests() == []
    with pytest.raises(OnboardingError) as e:
        ob.confirm_download("b" * 64)
    assert e.value.code == "checksum_mismatch" and ob.selection.active() is None
    assert ob.requests() == []
    assert ob.confirm_download(SHA)["status"] == "ready"
    assert ob.selection.active()["model"] == "local-1"
    assert ob.state()["report_due"]["reason"] == "initial_check"
    assert [(r["kind"], r["state"]) for r in ob.requests()] == [("initial_check", "pending")]


def test_legacy_local_check_waits_for_verified_download(ob):
    decl = LocalDownload("local-1", SHA, 4000, 8000, 6000, True)
    host = HostFacts(ram_total_mb=16000, disk_free_mb=50000, reserved_memory_mb=2000)
    ob.choose_provider("ollama-local", local=decl, host=host)
    queued = ob.request_action("initial_check")
    ob.pick_initial(decl.model)
    handlers = {"initial_check": lambda: ob.ensure_report(lambda _: {"passed": True})}
    assert ob.process_requests(handlers) == []
    ob.confirm_download(SHA)
    assert ob.requests() == [queued]
    assert ob.process_requests(handlers)[0]["state"] == "done"
    assert ob.latest_report()["total_reports"] == 1


def test_declared_download_is_not_offered_for_other_providers(ob):
    decl = LocalDownload("m", SHA, 10, 128, 10, True)
    with pytest.raises(OnboardingError):
        ob.choose_provider("anthropic-api", key_ref="env:K", local=decl)


def test_idempotency_key_replays_the_stored_response(ob):
    calls = []
    first = ob.once("k-12345678", lambda: calls.append(1) or {"n": 1})
    again = ob.once("k-12345678", lambda: calls.append(2) or {"n": 2})
    assert first == ({"n": 1}, False) and again == ({"n": 1}, True) and calls == [1]

    def fail():
        raise OnboardingError("nope")

    with pytest.raises(OnboardingError):
        ob.once("k-fail-0001", fail)
    assert ob.once("k-fail-0001", lambda: {"ok": 1}) == ({"ok": 1}, False)  # retry allowed


def test_requests_are_recorded_deduplicated_and_executed_by_the_service(ob):
    a = ob.request_action("best_now")
    assert ob.request_action("best_now")["id"] == a["id"]
    with pytest.raises(OnboardingError):
        ob.request_action("rm -rf")
    ob.request_action("scan")
    out = ob.process_requests({"best_now": lambda: RunResult("kept"), "scan": lambda: 1 / 0})
    assert {(r["kind"], r["state"], r["result"]) for r in out} == {
        ("best_now", "done", "kept"),
        ("scan", "failed", "ZeroDivisionError"),
    }


# ---- integration with the weekly rule (fake provider, fake clock) -----------------------------


def switching_harness(tmp_path, ob):
    h = Harness(tmp_path, ai=make_ai(SONNET), listed=(SONNET, HAIKU))
    h.store = ob.selection
    return h


def selection(h, ob, *, weekly, work="model_selection"):
    return WeeklySelection(
        ai=h.ai, window_spec="Sun 03:00 Europe/Berlin",
        runs=__import__("steward.core.maintenance_runs", fromlist=["x"]).MaintenanceRuns(h.jobs),
        store=h.store, eval_ledger_path=ob.ledger_path("weekly" if weekly else "best_now"),
        make_provider=lambda m: FakeProvider(m, h.world), clock=lambda: h.now,
        monotonic=lambda: 0.0, audit=h.audit.append, work_id=work,
        guards=ob.guards(weekly=weekly),
    )  # fmt: skip


def two_sources(ob, incumbent, candidate, *, better=True):
    import json

    for host, cand_score in (("a.example.org", 900 if better else 100), ("b.example.net", 900)):
        sid = ob.sources.add_source(f"https://{host}/p", "json_comparison_v1", actor="operator")
        body = json.dumps(
            {"models": [{"model": incumbent, "price_micro": 100, "score": 500},
                        {"model": candidate, "price_micro": 100, "score": cand_score}]}
        ).encode()  # fmt: skip
        ob.sources.record_observation(sid, body, ob.clock_box[0])


def test_switch_needs_two_independent_sources_then_creates_a_change_report(tmp_path, ob):
    ob.clock_box[0] = IN_WINDOW - 86400
    ob.choose_provider("anthropic-api", key_ref="env:K")
    ob.scan(Lister("anthropic", [SONNET, HAIKU]))
    ob.pick_initial(SONNET)
    ob.ensure_report(lambda m: {"ok": 1})
    ob.set_auto(True)
    h = switching_harness(tmp_path, ob)
    h.now = IN_WINDOW
    ob.clock_box[0] = IN_WINDOW
    kept = selection(h, ob, weekly=True).run()  # cheaper candidate, but no source evidence
    assert kept.status == "kept" and any(
        "insufficient" in r or "stale" in r for r in kept.decision.reasons
    )
    assert ob.on_selection_result(kept) is None and ob.latest_report()["total_reports"] == 1
    two_sources(ob, SONNET, HAIKU)
    h.now = IN_WINDOW + 7 * 86400
    ob.clock_box[0] = h.now
    two_sources_refresh(ob, h.now)
    result = selection(h, ob, weekly=True).run()
    assert result.status == "switched" and ob.selection.active()["model"] == HAIKU
    report = ob.on_selection_result(result)
    assert report["reason"] == "selection_change" and report["body"]["chosen"] == HAIKU
    assert ob.on_selection_result(result) is None  # one report per decision
    trail = [a["event"] for a in ob.sources.audit_trail()]
    assert "switch_checked" in trail and "model_activated" in trail


def two_sources_refresh(ob, now):
    import json

    for s in ob.sources.list_sources():
        body = json.dumps(
            {"models": [{"model": SONNET, "price_micro": 100, "score": 500},
                        {"model": HAIKU, "price_micro": 100, "score": 900}]}
        ).encode()  # fmt: skip
        ob.sources.record_observation(s["id"], body, now)


def test_pinned_model_blocks_weekly_run_and_best_now(tmp_path, ob):
    ob.choose_provider("anthropic-api", key_ref="env:K")
    ob.scan(Lister("anthropic", [SONNET, HAIKU]))
    ob.pick_initial(SONNET)
    ob.set_auto(True)
    ob.pin(SONNET)
    h = switching_harness(tmp_path, ob)
    h.now = IN_WINDOW
    r = selection(h, ob, weekly=True).run()
    assert r.status == "skipped" and r.reason == "model_pinned" and h.world["calls"] == []
    with pytest.raises(OnboardingError) as e:
        ob.best_now(lambda g, w, p: selection(h, ob, weekly=False, work=w))
    assert e.value.code == "model_pinned"


def test_best_now_uses_its_own_ledger_and_window_admission(tmp_path, ob):
    ob.choose_provider("anthropic-api", key_ref="env:K")
    ob.scan(Lister("anthropic", [SONNET, HAIKU]))
    ob.pick_initial(SONNET)
    h = switching_harness(tmp_path, ob)
    seen = {}

    def factory(guards, work, ledger):
        seen.update(work=work, ledger=ledger)
        h.now = 0.0  # outside any window
        sel = selection(h, ob, weekly=False, work=work)
        return sel

    r = ob.best_now(factory)
    assert r.status == "not_admitted" and h.world["calls"] == []  # admitted like planned work
    assert seen["work"] == "model_best_now" and seen["ledger"].name == "eval-best_now.db"
    assert seen["ledger"] != ob.ledger_path("weekly")
    h.now = IN_WINDOW
    ob.clock_box[0] = IN_WINDOW
    r = ob.best_now(lambda g, w, p: selection(h, ob, weekly=False, work=w))
    assert r.status == "kept"  # auto is off but best-now still runs; no source evidence: keep
    assert any(a["event"] == "inference.best_now_finished" for a in ob.audit_log)


def test_evaluate_model_reserves_budget_first_and_reports_measurements(tmp_path, ob):
    h = Harness(tmp_path)
    ledger = Ledger(ob.ledger_path("initial_check"), make_ai().budget.__class__(
        monthly={"tokens": 500000}))  # fmt: skip
    body = evaluate_model(
        FakeProvider(SONNET, h.world), ledger, price=Price(1000, 5000),
        share=frozenset({"status"}), clock=lambda: IN_WINDOW,
    )  # fmt: skip
    assert body["complete"] and body["passed"] and body["cost_micro"] > 0
    tiny = Ledger(tmp_path / "tiny.db", make_ai().budget.__class__(monthly={"tokens": 10}))
    denied = evaluate_model(
        FakeProvider(SONNET, h.world), tiny, price=Price(1, 1), share=frozenset({"status"}),
        clock=lambda: IN_WINDOW,
    )  # fmt: skip
    assert not denied["complete"] and not denied["passed"]
    blocked = evaluate_model(FakeProvider(SONNET, h.world), ledger, price=None, share=frozenset())
    assert blocked["error"] == "suite_data_class_not_shared"


def test_stale_exchange_rate_stops_cost_limited_evaluation_and_keeps_the_model(tmp_path, ob):
    h = Harness(tmp_path, ai=make_ai(SONNET, max_eval_cost_micro=10**9))
    h.now = IN_WINDOW

    def run(guard, sub):
        h.tmp = tmp_path / sub
        h.tmp.mkdir()
        sel = h.selection()
        sel.rate_guard = guard
        return sel.run()

    stale = run(lambda now: False, "a")
    assert stale.status == "kept" and "incumbent_evaluation_incomplete" in stale.decision.reasons
    assert h.world["calls"] == []  # denied before any provider call
