"""A05: weekly deterministic model selection against fake providers and a fake clock."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from steward.core.config import Ai, ConfigError, parse_config
from steward.core.inference import Health, InferenceError, RawCompletion, Usage
from steward.core.maintenance_runs import MaintenanceRuns
from steward.core.model_selection import (
    Measurement,
    SelectionStore,
    WeeklySelection,
    decide,
    effective_model,
    price_state,
    rank_key,
)
from steward.core.model_suite import SUITE_REVISION, cases
from steward.core.store import Store

SPEC = "Sun 03:00 Europe/Berlin"
SONNET, SONNET2, HAIKU, HAIKU2 = (
    "claude-sonnet-5-5",
    "claude-sonnet-5-6",
    "claude-haiku-5-5",
    "claude-haiku-5-6",
)


def ts(*a):
    return datetime(*a, tzinfo=UTC).timestamp()


IN_WINDOW = ts(2026, 11, 22, 2, 5)
NEXT_WINDOW = ts(2026, 11, 29, 2, 5)


def answer(system: str, user: str) -> dict:
    items = json.loads(user)["items"]
    if "max_severity" in system:
        levels = ["none", "low", "medium", "high", "critical"]
        found = [
            t.split("severity=")[1].split()[0]
            for t in (i["text"] for i in items)
            if "severity=" in t
        ]
        return {"max_severity": max(found, key=levels.index), "finding_count": len(found)}
    if "instruction_items" in system:
        return {
            "item_count": len(items),
            "instruction_items": sum("ignore" in i["text"].lower() for i in items),
        }
    return {"item_count": len(items), "newest_source": items[0]["source"] if items else ""}


class FakeProvider:
    version, name, data_class = 1, "anthropic", "external"
    capabilities = ("complete.json", "models.list")
    timeout_s, max_input_bytes = 5.0, 60000

    def __init__(self, model, world):
        self.model, self.world = model, world

    def health(self):
        return Health(True)

    def list_models(self, timeout_s=10.0):
        return list(self.world["listed"])

    def complete(self, system, user, *, schema, max_output_tokens, timeout_s):
        behavior = self.world["behavior"].get(self.model, "ok")
        self.world["calls"].append(self.model)
        if isinstance(behavior, InferenceError):
            raise behavior
        data = answer(system, user)
        if behavior == "wrong":
            data = {k: (v if not isinstance(v, int) else v + 1) for k, v in data.items()}
        if behavior == "garbage":
            return RawCompletion("not json", Usage(100, 20), self.model)
        usage = Usage(None, None) if behavior == "nousage" else Usage(1000, 100)
        return RawCompletion(json.dumps(data), usage, self.model)


def policy(**over):
    prices = over.pop(
        "prices",
        {SONNET: 3000, SONNET2: 3000, HAIKU: 1000, HAIKU2: 1000},
    )
    as_of = over.pop("as_of", "2026-11-20")
    base = {
        "families": ["sonnet", "haiku"],
        "max_eval_tokens": 500000,
        "prices": [
            {
                "model": m,
                "input_per_mtok_micro": v,
                "output_per_mtok_micro": v * 5,
                "as_of": as_of,
            }
            for m, v in prices.items()
        ],
    }
    return base | over


def make_ai(model=SONNET, **over):
    return Ai(
        provider="anthropic",
        local_only=False,
        model=model,
        api_key_ref="env:K",
        share=["status"],
        budget={"monthly": {"tokens": 100000}},
        model_policy=policy(**over),
    )


class Harness:
    def __init__(self, tmp_path, ai=None, listed=(SONNET, HAIKU), behavior=None):
        self.world = {"listed": list(listed), "behavior": dict(behavior or {}), "calls": []}
        self.store = SelectionStore(tmp_path / "selection.db")
        self.jobs = Store(tmp_path / "maintenance.db")
        self.now = IN_WINDOW
        self.audit: list[dict] = []
        self.ai = ai or make_ai()
        self.hook = None
        self.tmp = tmp_path

    def selection(self):
        return WeeklySelection(
            ai=self.ai,
            window_spec=SPEC,
            runs=MaintenanceRuns(self.jobs),
            store=self.store,
            eval_ledger_path=self.tmp / "eval.db",
            make_provider=lambda m: FakeProvider(m, self.world),
            clock=lambda: self.now,
            monotonic=lambda: 0.0,
            audit=self.audit.append,
            before_activation=self.hook,
        )

    def run(self):
        return self.selection().run()


@pytest.fixture
def h(tmp_path):
    harness = Harness(tmp_path)
    yield harness
    harness.jobs.close()


def test_switches_to_strictly_cheaper_passing_candidate_and_persists_audit(h):
    result = h.run()
    assert result.status == "switched" and result.decision.chosen == HAIKU
    active = h.store.active()
    assert active["model"] == HAIKU and active["fallback"] == SONNET
    row = h.store.history()[0]
    assert row["state"] == "activated" and row["suite_revision"] == SUITE_REVISION
    assert row["body"]["provenance"]["source"] == "provider_model_list"
    assert (
        row["body"]["measurements"][HAIKU]["cost_micro"]
        < row["body"]["measurements"][SONNET]["cost_micro"]
    )
    assert any(e["event"] == "inference.model_switched" and e["chosen"] == HAIKU for e in h.audit)
    assert effective_model(h.ai, h.store) == HAIKU and effective_model(h.ai, None) == SONNET
    assert set(h.world["calls"]) == {SONNET, HAIKU}  # same provider only; synthetic suite only


def test_runs_only_inside_the_window_and_once_per_window(h):
    h.now = ts(2026, 11, 21, 12)
    assert h.run().status == "not_admitted" and h.world["calls"] == []
    h.now = IN_WINDOW
    assert h.run().status == "switched"
    n = len(h.world["calls"])
    again = h.run()
    assert again.status == "not_admitted" and len(h.world["calls"]) == n
    h.now = NEXT_WINDOW  # a week later: the new accepted model is the incumbent
    assert h.run().status == "kept"
    assert h.store.active()["model"] == HAIKU


def test_equal_cost_keeps_incumbent_and_order_is_deterministic():
    pol = make_ai().model_policy
    a = Measurement(SONNET, "sonnet", 3, 3, 3, 0, 100, 0, True)
    b = Measurement(HAIKU, "haiku", 3, 3, 3, 0, 100, 0, True)
    c = Measurement(HAIKU2, "haiku", 3, 3, 3, 0, 100, 0, True)
    assert decide(pol, SONNET, True, {SONNET: a, HAIKU: b}, {}).action == "keep"
    order = sorted([c, b, a], key=lambda m: rank_key(pol, m))
    assert [m.model for m in order] == [SONNET, HAIKU, HAIKU2]  # family index, then id
    cheaper = Measurement(HAIKU2, "haiku", 3, 3, 3, 0, 50, 0, True)
    d = decide(pol, SONNET, True, {SONNET: a, HAIKU: b, HAIKU2: cheaper}, {})
    assert d.action == "switch" and d.chosen == HAIKU2


def test_disappearing_incumbent_switches_but_disappearing_candidate_does_not(tmp_path):
    h = Harness(tmp_path, listed=(HAIKU,))
    result = h.run()
    assert result.status == "switched" and "incumbent_not_listed" in result.reason
    assert h.store.active()["fallback"] == SONNET
    h.jobs.close()
    h = Harness(
        tmp_path / "b" if (tmp_path / "b").mkdir() is None else tmp_path,
        behavior={HAIKU: InferenceError("model_unavailable", spend="none")},
    )
    result = h.run()
    assert result.status == "kept" and h.store.active() is None
    assert h.store.history()[0]["body"]["measurements"][HAIKU]["error"] == "model_unavailable"
    h.jobs.close()


def test_missing_or_stale_price_prevents_switch_and_skips_evaluation(tmp_path):
    for kw in ({"prices": {SONNET: 3000}}, {"as_of": "2026-09-01"}):
        sub = tmp_path / ("a" if "prices" in kw else "b")
        sub.mkdir()
        h = Harness(sub, ai=make_ai(**kw))
        result = h.run()
        assert result.status == "kept" and h.store.active() is None
        assert HAIKU not in h.world["calls"]
        h.jobs.close()
    pol = make_ai().model_policy
    today = datetime(2026, 11, 22).date()
    assert price_state(pol, "unknown-model", today)[1] == "missing"
    assert price_state(pol, HAIKU, datetime(2027, 3, 1).date())[1] == "stale"


def test_price_change_makes_candidate_dearer_and_keeps_incumbent(tmp_path):
    h = Harness(tmp_path, ai=make_ai(prices={SONNET: 3000, HAIKU: 9000}))
    assert h.run().status == "kept"
    assert h.store.history()[0]["body"]["reasons"] == ["no_strictly_cheaper_candidate"]


@pytest.mark.parametrize("who", [HAIKU, SONNET])
def test_quota_or_rate_limit_leaves_evidence_incomplete_without_switch(tmp_path, who):
    h = Harness(tmp_path, behavior={who: InferenceError("quota", spend="none")})
    assert h.run().status == "kept" and h.store.active() is None
    assert h.store.history()[0]["body"]["measurements"][who]["error"] == "quota"


@pytest.mark.parametrize("bad", ["wrong", "garbage"])
def test_failed_candidate_is_never_chosen(tmp_path, bad):
    h = Harness(tmp_path, behavior={HAIKU: bad})
    assert h.run().status == "kept" and h.store.active() is None
    m = h.store.history()[0]["body"]["measurements"][HAIKU]
    assert m["task_ok"] < m["cases"] or m["schema_ok"] < m["cases"]


def test_failing_incumbent_is_replaced_by_best_passing_candidate(tmp_path):
    h = Harness(
        tmp_path, ai=make_ai(model=HAIKU), behavior={HAIKU: "wrong"}, listed=(HAIKU, SONNET)
    )
    result = h.run()
    assert result.status == "switched" and result.decision.chosen == SONNET


def test_unknown_usage_prevents_switch(tmp_path):
    h = Harness(tmp_path, behavior={HAIKU: "nousage"})
    assert h.run().status == "kept"
    assert h.store.history()[0]["body"]["measurements"][HAIKU]["cost_micro"] is None


def test_interrupted_activation_keeps_old_model_and_redecides_next_window(tmp_path):
    h = Harness(tmp_path)

    def crash(decision_id):
        raise KeyboardInterrupt

    h.hook = crash
    with pytest.raises(KeyboardInterrupt):
        h.run()
    assert h.store.active() is None and h.store.history()[0]["state"] == "pending"
    h.hook = None
    h.now = NEXT_WINDOW
    result = h.run()  # recovery abandons the stale pending record, then decides again
    states = [r["state"] for r in h.store.history()]
    assert "abandoned" in states and result.status == "switched"
    assert h.store.active()["model"] == HAIKU


def test_external_provider_requires_suite_class_to_be_shared(tmp_path):
    ai = make_ai()
    ai = ai.model_copy(update={"share": ["events"]})
    h = Harness(tmp_path, ai=ai)
    result = h.run()
    assert result.status == "skipped" and h.world["calls"] == []


def test_discovery_failure_and_provider_without_listing_skip(tmp_path):
    h = Harness(tmp_path)

    def boom(self, timeout_s=10.0):
        raise InferenceError("auth", spend="none")

    FakeProvider.list_models, orig = boom, FakeProvider.list_models
    try:
        assert h.run().reason == "discovery_failed_auth"
    finally:
        FakeProvider.list_models = orig


def test_suite_cases_are_synthetic_and_have_checkable_answers():
    for case in cases(IN_WINDOW):
        assert all(i.project == "suite-app" for i in case.items)
        assert case.expected  # graded against code, never against a model
    assert answer("max_severity", json.dumps({"items": [{"text": "x severity=high"}]})) == {
        "max_severity": "high",
        "finding_count": 1,
    }


def test_model_policy_config_rules_and_canonical_revisions(raw_config):
    def parse(ai):
        raw_config["ai"] = ai
        return parse_config(raw_config, allow_unavailable=True)

    ai = {
        "provider": "anthropic",
        "local_only": False,
        "model": SONNET,
        "api_key_ref": "env:K",
        "share": ["status"],
        "budget": {"monthly": {"tokens": 1000}},
        "model_policy": policy(),
    }
    cfg = parse(ai)
    assert cfg.ai.model_policy.families == ["sonnet", "haiku"]
    with pytest.raises(ConfigError):
        parse(ai | {"model_policy": policy(families=["sonnet", "sonnet"])})
    with pytest.raises(ConfigError):
        parse(ai | {"model_policy": policy(as_of="2026-13-45")})
    with pytest.raises(ConfigError):
        parse({"provider": "ollama", "model": "m:1b", "model_policy": policy()})
    with pytest.raises(ConfigError):
        parse({"provider": "none", "model_policy": policy()})
