"""Offline integration between AI admin requests and the inference worker."""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime
from itertools import count
from pathlib import Path

import pytest

from steward import inference_worker
from steward.adapters.inference import HttpResponse, TransportError
from steward.core.config import Ai, AiBudget
from steward.core.inference import InferenceError, RawCompletion, Usage
from steward.core.inference_budget import Ledger
from steward.core.inference_deployment import CandidatePolicy, PrivateProviderPolicy
from steward.core.model_selection import SelectionStore
from steward.core.model_sources import SourceStore
from steward.core.model_suite import cases, scope
from steward.inference_worker import AppliedPolicy, build_effective_provider, run_once
from test_api import app, client  # noqa: F401 (fixtures)
from test_model_selection import HAIKU, IN_WINDOW, NEXT_WINDOW, SONNET, SPEC, FakeProvider, make_ai


class TrackedProvider(FakeProvider):
    def list_models(self, timeout_s=10.0):
        self.world["lists"].append(self.model)
        return super().list_models(timeout_s)


@pytest.mark.parametrize("fenced", [False, True])
def test_private_provider_rejects_reflected_credential_after_json_decode(monkeypatch, fenced):
    text = r'{"answer":{"detail":"credential-\u0078"}}'
    if fenced:
        text = f"```json\n{text}\n```"
    usage = Usage(5, 5)
    monkeypatch.setattr(
        inference_worker.OpenAICompatibleProvider,
        "complete",
        lambda *_args, **_kwargs: RawCompletion(text, usage, "model"),
    )
    provider = inference_worker._PrivateProvider(
        "https://10.0.0.4:9444/v1", "model", api_key="credential-x"
    )
    with pytest.raises(InferenceError) as failure:
        provider.complete("system", "user", schema={}, max_output_tokens=10, timeout_s=1)
    assert failure.value.error_class == "invalid_output"
    assert failure.value.usage == usage


@pytest.mark.parametrize(
    "operation", ["initial_check", "selection_change", "cold_change", "best_now", "advice"]
)
def test_managed_private_timeouts(tmp_path, monkeypatch, operation):
    budget = AiBudget(monthly={"tokens": 40_000, "seconds": 180})
    settings = PrivateProviderPolicy(
        base_url="https://10.0.0.4:9444/v1",
        budget=budget,
        evaluation_budget=budget,
        evaluation_window=SPEC,
        share=["status"],
    )
    candidate = CandidatePolicy(
        version=1,
        revision="a" * 64,
        release="a04-test",
        wheel_sha256="b" * 64,
        generation="c" * 32,
        ai=Ai(),
        weekly_window=None,
        private_provider=settings,
        advice=True,
    )
    monkeypatch.setattr(
        inference_worker.inference_deployment, "read_candidate_policy", lambda: candidate
    )
    monkeypatch.setattr(inference_worker, "read_kill_switch", lambda: False)
    elapsed = 0.0
    timeouts = []
    reservations = []
    durations = []
    suite = cases(IN_WINDOW)
    monkeypatch.setattr(time, "monotonic", lambda: elapsed)
    reserve = Ledger.reserve

    def track_reservation(ledger, **kwargs):
        reservations.append(kwargs["seconds"])
        return reserve(ledger, **kwargs)

    monkeypatch.setattr(Ledger, "reserve", track_reservation)

    def clock():
        return IN_WINDOW + elapsed

    class PrivateTransport:
        def __init__(self, *_args, check_admission, **_kwargs):
            self.check_admission = check_admission

        def request(self, _endpoint, method, path, _headers, body, *, timeout):
            nonlocal elapsed
            self.check_admission()
            if method == "GET":
                assert path.endswith("/models")
                return HttpResponse(
                    200,
                    {},
                    json.dumps(
                        {
                            "data": [{"id": model} for model in (SONNET, HAIKU)],
                        }
                    ).encode(),
                )
            assert path.endswith("/chat/completions")
            case_index = len(timeouts)
            timeouts.append(timeout)
            duration = durations[case_index] if durations else 0
            elapsed += min(duration, timeout)
            if duration > timeout:
                raise TransportError("timeout")
            return HttpResponse(
                200,
                {},
                json.dumps(
                    {
                        "model": json.loads(body)["model"],
                        "choices": [
                            {"message": {"content": json.dumps(suite[case_index].expected)}}
                        ],
                        "usage": {"prompt_tokens": 5, "completion_tokens": 5},
                    }
                ).encode(),
            )

    monkeypatch.setattr(inference_worker, "ManagedPrivateHttpsTransport", PrivateTransport)
    onboarding = inference_worker._onboarding(tmp_path, clock)

    def tick():
        result = run_once(
            read_policy=inference_worker._read_candidate,
            candidate_policy=inference_worker._read_candidate(),
            state_dir=tmp_path,
            kill_switch=inference_worker.read_kill_switch,
            clock=clock,
            monotonic=lambda: elapsed,
        )
        assert result["status"] == "ok"
        return result["requests"]

    onboarding.stage_private_provider(
        settings.base_url,
        "fixture-key",
        expected_choice_id=None,
        replace=False,
        generation=candidate.generation,
    )
    tick()
    onboarding.pick_initial(SONNET)
    if operation != "initial_check":
        onboarding.request_action("initial_check")
        assert tick()[0]["result"] == "complete"
        timeouts.clear()
        reservations.clear()

    if operation == "advice":
        durations[:] = [19]
        advice_dir = tmp_path / "advice"
        advice_dir.mkdir(mode=0o700)
        # Leave enough caller time to measure the provider's own advice limit.
        outcome = inference_worker._run_managed_advice(
            advice_dir,
            list(suite[0].items),
            scope(clock()),
            ("controller",),
            time.monotonic() + 60,
        )
        assert timeouts == [8.0]
        assert outcome.error_class == "timeout"
        return

    # The cold call succeeds, leaving 11 seconds for a call that needs 12.
    durations[:] = [12, 4, 3] if operation == "cold_change" else [19, 12]
    if operation in ("selection_change", "cold_change"):
        onboarding.pin(HAIKU)
    onboarding.request_action("best_now" if operation == "best_now" else "initial_check")
    requests = tick()
    assert timeouts == reservations
    if operation == "cold_change":
        assert requests[0]["result"] == "complete"
        assert onboarding.latest_report()["body"]["passed"] is True
        assert elapsed == 19.0
        return
    assert timeouts == [20.0, 11.0]
    assert elapsed == 30.0
    if operation == "best_now":
        assert requests[0]["result"] == "selection_deadline"
    else:
        assert requests[0]["result"] == "incomplete"
        report = onboarding.view()["report"]
        assert report["reason"] == operation
        assert report["model"] == (HAIKU if operation == "selection_change" else SONNET)
        assert report["body"]["error"] == "timeout"


def test_private_send_lock_stops_waiting_at_deadline(tmp_path, monkeypatch):
    first = inference_worker._onboarding(tmp_path, time.time)
    second = inference_worker._onboarding(tmp_path, time.time)
    remaining = iter((0.003, 0.0))
    waits = []
    monkeypatch.setattr(time, "sleep", waits.append)
    with (
        first.control(),
        pytest.raises(TimeoutError),
        second.control(remaining=lambda: next(remaining)),
    ):
        pytest.fail("the contended send lock was acquired")
    assert waits == [0.003]


class WorkerHarness:
    def __init__(self, api_client, tmp_path):
        self.client = api_client
        self.state_dir = tmp_path / "api" / "ai"
        self.desired_config = tmp_path / "desired.json"
        self.now = IN_WINDOW - 3600
        self.policy = AppliedPolicy("fixture-revision", make_ai(), SPEC)
        self.killed = False
        self.keys = count(1)
        self.world = {"listed": [SONNET, HAIKU], "behavior": {}, "calls": [], "lists": []}
        self.selection = SelectionStore(self.state_dir / "selection.db")
        self.sources = SourceStore(self.state_dir / "sources.db", clock=lambda: self.now)

    def post(self, route, body=None, *, status=200):
        response = self.client.post(
            f"/api/ai/{route}",
            json=body,
            headers={"Idempotency-Key": f"worker-test-{next(self.keys)}"},
        )
        assert response.status_code == status, response.json()
        return response.json()

    def view(self):
        response = self.client.get("/api/ai")
        assert response.status_code == 200
        return response.json()

    def request(self, request_id):
        return next(r for r in self.view()["requests"] if r["id"] == request_id)

    def provider(self, ai):
        return TrackedProvider(ai.model, self.world)

    def tick(self, before_activation=None, *, builder=None):
        return run_once(
            read_policy=lambda: self.policy,
            state_dir=self.state_dir,
            provider_builder=builder or self.provider,
            kill_switch=lambda: self.killed,
            clock=lambda: datetime.fromtimestamp(self.now, UTC),
            monotonic=lambda: 0.0,
            before_activation=before_activation,
        )

    def effective_provider(self, policy=None, *, builder=None):
        return build_effective_provider(
            policy=policy or self.policy,
            state_dir=self.state_dir,
            provider_builder=builder or self.provider,
        )

    def choose(self, *, replace_choice=False):
        self.post(
            "provider",
            {"option": "anthropic-api", "key_ref": "env:K", "replace": replace_choice},
        )

    def scan(self):
        request = self.post("scan", status=202)
        assert request["state"] == "pending"
        self.tick()
        assert self.request(request["id"])["state"] == "done"
        assert self.view()["scanned"]["models"] == sorted(self.world["listed"])

    def ready(self, *, auto=False):
        self.choose()
        self.scan()
        self.post("initial-model", {"model": SONNET})
        self.tick()
        assert self.view()["report"]["total_reports"] == 1
        if auto:
            self.post("auto", {"enabled": True})
        self.reset_calls()

    def observe(self, *, two=True):
        rows = json.dumps(
            {
                "models": [
                    {"model": SONNET, "price_micro": 100, "score": 500},
                    {"model": HAIKU, "price_micro": 100, "score": 900},
                ]
            }
        ).encode()
        hosts = ("a.example.org", "b.example.net") if two else ("a.example.org",)
        return [self.record_source(host, rows) for host in hosts]

    def record_source(self, host, rows):
        url = f"https://{host}/p"
        source = next((s["id"] for s in self.sources.list_sources() if s["url"] == url), None)
        if source is None:
            source = self.post("sources", {"url": url, "parser": "json_comparison_v1"})["id"]
        self.sources.record_observation(source, rows, self.now)
        return source

    def reset_calls(self):
        self.world["calls"].clear()
        self.world["lists"].clear()

    def assert_idle(self):
        assert self.world["calls"] == self.world["lists"] == []

    def charged(self, mode):
        path = self.state_dir / f"eval-{mode}.db"
        assert path.is_file()
        with closing(sqlite3.connect(path)) as db:
            return db.execute(
                "SELECT COUNT(*) FROM reservations WHERE state='charged' AND tokens > 0"
            ).fetchone()[0]


@pytest.fixture
def worker(client, tmp_path):  # noqa: F811
    return WorkerHarness(client, tmp_path)


def test_api_scan_initial_report_and_changed_pin_keep_known_unpriced_tokens(worker):
    worker.policy = replace(worker.policy, ai=make_ai(prices={HAIKU: 1000}))
    worker.choose()
    worker.scan()
    assert worker.world["lists"] == [SONNET]
    assert worker.world["calls"] == []
    worker.post("initial-model", {"model": SONNET})
    assert worker.view()["report"] is None
    worker.tick()
    report = worker.view()["report"]
    assert report["reason"] == "initial_check"
    assert report["body"]["passed"]
    assert report["body"]["tokens"] == 1100 * len(worker.world["calls"]) > 0
    assert report["body"]["cost_micro"] is None
    assert worker.charged("initial_check") > 0

    worker.reset_calls()
    worker.post("pin", {"model": HAIKU})
    worker.tick()
    assert set(worker.world["calls"]) == {HAIKU}
    assert worker.world["lists"] == []
    assert worker.view()["pinned"] == HAIKU
    report = worker.view()["report"]
    assert report["reason"] == "selection_change" and report["model"] == HAIKU
    assert report["body"]["cost_micro"] > 0 and report["total_reports"] == 2
    worker.reset_calls()
    worker.tick()
    worker.assert_idle()
    assert worker.view()["report"] == report


def test_best_now_and_weekly_share_durable_slot_but_charge_separate_ledgers(worker):
    worker.ready(auto=True)
    ordinary_path = worker.state_dir / "inference.db"
    Ledger(ordinary_path, worker.policy.ai.budget).close()
    ordinary_bytes = ordinary_path.read_bytes()
    config_bytes = worker.desired_config.read_bytes()
    applied_ai = worker.policy.ai.model_dump_json()

    worker.now = IN_WINDOW
    worker.observe(two=False)
    manual = worker.post("best-now", status=202)
    worker.tick()
    assert worker.request(manual["id"])["result"] == "kept"
    assert worker.world["lists"] == [SONNET]
    assert worker.charged("best_now") > 0
    assert worker.view()["report"]["total_reports"] == 1
    kept = next(r for r in worker.selection.history() if r["state"] == "kept")
    assert any("switch_guard" in reason for reason in kept["body"]["reasons"])

    worker.reset_calls()
    worker.tick()
    worker.assert_idle()
    worker.now = NEXT_WINDOW
    worker.observe()
    worker.tick()
    assert worker.world["lists"] == [SONNET]
    assert worker.charged("weekly") > 0
    assert worker.view()["active"]["model"] == HAIKU
    report = worker.view()["report"]
    assert report["total_reports"] == 2 and report["body"]["chosen"] == HAIKU
    assert report["body"]["measurements"] and report["body"]["reasons"]

    worker.reset_calls()
    manual = worker.post("best-now", status=202)
    worker.tick()
    worker.assert_idle()
    assert worker.request(manual["id"])["result"] == "not_admitted"
    assert worker.view()["report"] == report
    assert ordinary_path.read_bytes() == ordinary_bytes
    assert worker.desired_config.read_bytes() == config_bytes
    assert worker.policy.ai.model_dump_json() == applied_ai


@pytest.mark.parametrize(
    "blocked", ["outside", "late", "unready", "provider", "key_ref", "kill", "pin"]
)
def test_selection_preflight_blocks_discovery_and_completion(worker, blocked):
    if blocked != "unready":
        worker.ready(auto=True)
    worker.now = IN_WINDOW
    manual = worker.post("best-now", status=202)
    if blocked == "outside":
        worker.now -= 3600
    elif blocked == "late":
        worker.now += 30 * 60
    elif blocked == "provider":
        worker.policy = replace(
            worker.policy, ai=make_ai().model_copy(update={"provider": "openai"})
        )
    elif blocked == "key_ref":
        worker.policy = replace(
            worker.policy, ai=make_ai().model_copy(update={"api_key_ref": "env:OTHER"})
        )
    elif blocked == "kill":
        worker.killed = True
    elif blocked == "pin":
        worker.post("pin", {"model": SONNET})

    def unexpected_builder(ai):
        pytest.fail(f"unexpected provider construction for {ai.model}")

    worker.tick(builder=unexpected_builder)
    worker.assert_idle()
    request = worker.request(manual["id"])
    assert request["state"] in {"done", "failed"}
    if blocked in {"outside", "late"}:
        assert request["result"] == "not_admitted"
    if blocked != "unready":
        assert worker.view()["active"]["model"] == SONNET
        assert worker.view()["report"]["total_reports"] == 1


def test_live_pending_is_not_recovered_by_another_tick_then_interruption_is_recovered(worker):
    worker.ready()
    worker.now = IN_WINDOW
    worker.observe()
    manual = worker.post("best-now", status=202)
    pending_id = None

    def interrupt():
        nonlocal pending_id
        pending = next(r for r in worker.selection.history() if r["state"] == "pending")
        assert pending["state"] == "pending"
        pending_id = pending["id"]
        calls = worker.world["calls"].copy()
        lists = worker.world["lists"].copy()
        assert worker.tick()["status"] == "busy"
        assert pending in worker.selection.history()
        assert worker.request(manual["id"])["state"] == "running"
        assert worker.world["calls"] == calls and worker.world["lists"] == lists
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        worker.tick(interrupt)
    assert worker.effective_provider().model == SONNET
    worker.reset_calls()
    worker.tick()
    worker.assert_idle()
    assert (
        next(r for r in worker.selection.history() if r["id"] == pending_id)["state"] == "abandoned"
    )
    assert worker.request(manual["id"])["state"] == "failed"
    assert "interrupt" in worker.request(manual["id"])["result"]
    assert worker.view()["report"]["total_reports"] == 1

    same_window = worker.post("best-now", status=202)
    worker.tick()
    assert same_window["id"] != manual["id"]
    assert worker.request(same_window["id"])["result"] == "not_admitted"
    worker.assert_idle()

    worker.now = NEXT_WINDOW
    worker.observe()
    retry = worker.post("best-now", status=202)
    worker.tick()
    assert retry["id"] != manual["id"]
    assert worker.effective_provider().model == HAIKU
    assert worker.selection.active(provider="anthropic", data_class="local") is None
    mismatch = worker.policy.ai.model_copy(update={"api_key_ref": "env:OTHER"})
    assert worker.effective_provider(replace(worker.policy, ai=mismatch)).model == SONNET

    other = worker.policy.ai.model_copy(update={"provider": "openai", "model": "gpt-5-mini"})

    def openai_builder(ai):
        provider = worker.provider(ai)
        provider.name = "openai"
        return provider

    assert (
        worker.effective_provider(replace(worker.policy, ai=other), builder=openai_builder).model
        == other.model
    )


@pytest.mark.parametrize("change", ["pin", "kill", "revision", "source", "auto", "deadline"])
def test_pending_switch_is_abandoned_when_activation_inputs_change(worker, change):
    worker.ready(auto=True)
    worker.now = IN_WINDOW
    sources = worker.observe()
    seen = []

    def invalidate():
        pending = next(r for r in worker.selection.history() if r["state"] == "pending")
        assert pending["state"] == "pending"
        seen.append(pending["id"])
        if change == "pin":
            worker.post("pin", {"model": SONNET})
        elif change == "kill":
            worker.killed = True
        elif change == "revision":
            worker.policy = replace(worker.policy, revision="replaced")
        elif change == "source":
            response = worker.client.delete(
                f"/api/ai/sources/{sources[0]}", headers={"Idempotency-Key": "remove-source"}
            )
            assert response.status_code == 200
        elif change == "auto":
            worker.post("auto", {"enabled": False})
        else:
            worker.now += 3600

    worker.tick(invalidate)
    assert len(seen) == 1
    decision = next(r for r in worker.selection.history() if r["id"] == seen[0])
    assert decision["state"] == "abandoned"
    assert decision["body"]["abandon_reason"]
    assert worker.view()["active"]["model"] == SONNET
    assert worker.view()["report"]["total_reports"] == 1


def test_replaced_choice_invalidates_queued_scan_even_for_same_option(worker):
    worker.choose()
    stale = worker.post("scan", status=202)
    worker.choose(replace_choice=True)
    worker.tick()
    worker.assert_idle()
    assert worker.request(stale["id"])["state"] == "failed"
    assert worker.request(stale["id"])["result"] == "choice_changed"
    assert worker.view()["scanned"] is None
    worker.scan()
    assert worker.world["lists"] == [SONNET]


def test_worker_returns_stable_source_research_unavailable_result(worker):
    worker.choose()
    request = worker.post("source-research", status=202)
    worker.tick()
    worker.assert_idle()
    assert worker.request(request["id"])["result"] == "source_research_unavailable"


def test_ambiguous_pre_migration_request_does_not_run_and_can_be_resubmitted(worker):
    worker.choose()
    old = worker.post("scan", status=202)
    # Reproduce the queue and in-progress selection from before durable choice IDs.
    with closing(sqlite3.connect(worker.state_dir / "onboarding.db")) as db, db:
        db.executescript("""
            UPDATE state SET body=json_remove(body, '$.choice_id');
            CREATE TABLE old_requests (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, created_at REAL NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('pending','running','done','failed')),
                result TEXT NOT NULL DEFAULT ''
            );
            INSERT INTO old_requests SELECT id, kind, created_at, state, result FROM requests;
            DROP TABLE requests;
            ALTER TABLE old_requests RENAME TO requests;
        """)
    worker.tick()
    worker.assert_idle()
    assert worker.request(old["id"])["state"] == "failed"
    assert worker.request(old["id"])["result"] == "resubmit_required"
    assert worker.view()["scanned"] is None
    worker.scan()
    assert worker.world["lists"] == [SONNET]


def test_legacy_scanned_choice_can_queue_the_initial_report_before_worker_recovery(worker):
    worker.choose()
    worker.scan()
    with closing(sqlite3.connect(worker.state_dir / "onboarding.db")) as db, db:
        db.execute("UPDATE state SET body=json_remove(body, '$.choice_id')")
    worker.post("initial-model", {"model": SONNET})
    worker.tick()
    report = worker.view()["report"]
    assert report["reason"] == "initial_check" and report["body"]["passed"]


def test_a_failing_incumbent_with_unknown_usage_cannot_be_replaced(worker):
    worker.ready(auto=True)
    worker.now = IN_WINDOW
    worker.observe()
    worker.world["behavior"][SONNET] = InferenceError("invalid_output", spend="unknown")
    worker.tick()
    decision = next(row for row in worker.selection.history() if row["state"] == "kept")
    assert "incumbent_price_or_usage_unknown" in decision["body"]["reasons"]
    assert decision["body"]["measurements"][HAIKU]["complete"]
    assert worker.view()["active"]["model"] == SONNET


@pytest.mark.parametrize("when", ["discovery", "activation"])
def test_prices_are_checked_again_when_the_run_crosses_midnight(worker, when):
    worker.policy = replace(
        worker.policy, ai=make_ai(price_max_age_days=1), weekly_window="Sat 23:45 UTC"
    )
    worker.ready(auto=True)
    worker.now = datetime(2026, 11, 21, 23, 50, tzinfo=UTC).timestamp()
    worker.observe()

    def expire_prices():
        worker.now += 10 * 60

    class MidnightProvider(TrackedProvider):
        def list_models(self, timeout_s=10.0):
            if when == "discovery":
                expire_prices()
            return super().list_models(timeout_s)

    worker.tick(
        before_activation=expire_prices if when == "activation" else None,
        builder=lambda ai: MidnightProvider(ai.model, worker.world),
    )
    assert worker.view()["active"]["model"] == SONNET
    if when == "discovery":
        assert not worker.world["calls"]
        decision = next(row for row in worker.selection.history() if row["state"] == "kept")
        assert decision["body"]["skipped"] == {HAIKU: "price_stale", SONNET: "price_stale"}
    else:
        assert set(worker.world["calls"]) == {SONNET, HAIKU}
        decision = next(row for row in worker.selection.history() if row["state"] == "abandoned")
        assert decision["body"]["abandon_reason"] == "price_expired"


def test_provider_timeout_is_capped_to_time_remaining(worker):
    worker.ready(auto=True)
    worker.now = IN_WINDOW
    timeouts = []

    class LateProvider(TrackedProvider):
        def list_models(self, timeout_s=10.0):
            listed = super().list_models(timeout_s)
            worker.now += inference_worker.WORK_SECONDS - 1
            return listed

        def complete(self, system, user, *, schema, max_output_tokens, timeout_s):
            timeouts.append(timeout_s)
            worker.now += 1
            return super().complete(
                system,
                user,
                schema=schema,
                max_output_tokens=max_output_tokens,
                timeout_s=timeout_s,
            )

    worker.tick(builder=lambda ai: LateProvider(ai.model, worker.world))
    assert timeouts == [1.0]
    assert worker.view()["active"]["model"] == SONNET


def test_disappeared_incumbent_still_needs_consensus_and_quota_consumes_window(worker):
    worker.ready(auto=True)
    worker.world["listed"] = [HAIKU]
    worker.now = IN_WINDOW
    worker.observe(two=False)
    worker.tick()
    assert worker.view()["active"]["model"] == SONNET
    assert worker.view()["report"]["total_reports"] == 1
    kept = next(r for r in worker.selection.history() if r["state"] == "kept")
    assert any("switch_guard" in reason for reason in kept["body"]["reasons"])

    worker.now = NEXT_WINDOW
    worker.observe()
    worker.world["behavior"][HAIKU] = InferenceError("quota", spend="none")
    worker.tick()
    assert worker.view()["active"]["model"] == SONNET
    assert worker.view()["report"]["total_reports"] == 1
    del worker.world["behavior"][HAIKU]
    worker.reset_calls()
    worker.tick()
    worker.assert_idle()

    worker.now += 7 * 86400
    worker.observe()
    worker.tick()
    assert worker.view()["active"]["model"] == HAIKU
    assert worker.view()["report"]["total_reports"] == 2


@pytest.mark.parametrize("pin_before_recovery", [False, True])
def test_worker_reconciles_missing_change_report_without_repeating_evaluation(
    worker, pin_before_recovery
):
    worker.ready()
    worker.now = IN_WINDOW
    worker.observe()
    worker.post("best-now", status=202)
    worker.tick()
    report = worker.view()["report"]
    assert report["model"] == HAIKU and report["total_reports"] == 2
    with closing(sqlite3.connect(worker.state_dir / "onboarding.db")) as db, db:
        db.execute("DELETE FROM reports WHERE id=?", (report["id"],))
    assert worker.view()["report"]["total_reports"] == 1

    worker.reset_calls()
    if pin_before_recovery:
        worker.now += 1
        worker.post("pin", {"model": SONNET})
    worker.tick()
    if pin_before_recovery:
        assert not worker.world["lists"] and set(worker.world["calls"]) == {SONNET}
        latest = worker.view()["report"]
        assert latest["model"] == SONNET and latest["total_reports"] == 3
        with closing(sqlite3.connect(worker.state_dir / "onboarding.db")) as db:
            assert (
                db.execute(
                    "SELECT COUNT(*) FROM reports WHERE decision_id=?", (report["decision_id"],)
                ).fetchone()[0]
                == 1
            )
        return
    worker.assert_idle()
    repaired = worker.view()["report"]
    assert repaired["total_reports"] == 2
    assert repaired["decision_id"] == report["decision_id"]
    worker.tick()
    worker.assert_idle()
    assert worker.view()["report"] == repaired


def test_public_cli_uses_fixed_paths_and_stops_at_release_guard(monkeypatch, capsys):
    assert Path("/etc/steward/inference/selection.json") == inference_worker.PROJECTION_PATH
    assert Path("/etc/steward/killswitch") == inference_worker.KILL_SWITCH_PATH
    assert Path("/var/lib/steward-inference") == inference_worker.STATE_DIR

    def unexpected_tick(**kwargs):
        pytest.fail("public CLI entered a guarded worker")

    monkeypatch.setattr(inference_worker, "run_once", unexpected_tick)
    inference_worker.main()
    assert json.loads(capsys.readouterr().out) == {
        "status": "unavailable",
        "reason": "ai_provider_unavailable",
    }


def test_candidate_tick_requires_the_managed_projection_before_opening_state(tmp_path, monkeypatch):
    from steward.core import inference_deployment

    state = tmp_path / "candidate"
    monkeypatch.setattr(inference_worker, "STATE_DIR", state)
    monkeypatch.setattr(inference_deployment, "read_candidate_policy", lambda: None)
    assert inference_worker._local_candidate_tick() == {
        "status": "unavailable",
        "reason": "applied_policy_unavailable",
    }
    assert not state.exists()


def test_missing_projection_and_kill_marker_use_trusted_parent(tmp_path, monkeypatch):
    path = tmp_path / "selection.json"
    marker = tmp_path / "killswitch"
    monkeypatch.setattr(inference_worker, "_trusted_directory", lambda path: path == tmp_path)
    assert inference_worker.read_projection(path) is None
    assert inference_worker.read_kill_switch(marker) is False
    marker.symlink_to(tmp_path / "absent")
    assert inference_worker.read_kill_switch(marker) is True
    assert inference_worker.read_kill_switch(tmp_path / "unknown-parent" / "killswitch") is True
