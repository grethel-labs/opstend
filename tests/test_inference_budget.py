"""A01: transactional budgets (race, restart, quota, ambiguous cost, double settlement)."""

from __future__ import annotations

import threading

import pytest

from inference_fakes import NOW, PRICE
from steward.core.config import AiBudget
from steward.core.inference_budget import BudgetDenied, Ledger, Price, window_key


def ledger(tmp_path, **kw):
    return Ledger(tmp_path / "budget.db", AiBudget(**kw))


def reserve(led, tokens=100, projects=("notes",), now=NOW, price=None, seconds=10.0):
    return led.reserve(projects=projects, tokens=tokens, seconds=seconds, price=price, now=now)


def test_race_never_exceeds_the_token_limit(tmp_path):
    path = tmp_path / "budget.db"
    budget = AiBudget(monthly={"tokens": 1000}, max_concurrent=8)
    Ledger(path, budget)  # create schema once
    granted, denied = [], []
    barrier = threading.Barrier(12)

    def worker():
        led = Ledger(path, budget)  # own connection per thread/process-like worker
        barrier.wait()
        try:
            granted.append(reserve(led, 100))
        except BudgetDenied as exc:
            denied.append(exc.reason)

    threads = [threading.Thread(target=worker) for _ in range(12)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(granted) <= 8 and len(granted) + len(denied) == 12
    assert set(denied) <= {"tokens", "concurrency"}
    assert Ledger(path, budget).usage(now=NOW)["tokens"] == 100 * len(granted) <= 1000


def test_token_limit_is_exact_and_denial_changes_nothing(tmp_path):
    led = ledger(tmp_path, monthly={"tokens": 250}, max_concurrent=8)
    reserve(led, 100)
    reserve(led, 100)
    with pytest.raises(BudgetDenied) as exc:
        reserve(led, 51)
    assert (exc.value.reason, exc.value.scope) == ("tokens", "global")
    assert led.usage(now=NOW)["tokens"] == 200
    reserve(led, 50)


def test_per_project_limits_do_not_leak_across_projects(tmp_path):
    led = ledger(tmp_path, per_project={"tokens": 150}, max_concurrent=8)
    reserve(led, 100, projects=("notes",))
    with pytest.raises(BudgetDenied) as exc:
        reserve(led, 100, projects=("notes", "billing"))
    assert exc.value.scope == "project:notes"
    assert led.usage("project:billing", now=NOW)["tokens"] == 0  # all-or-nothing
    reserve(led, 100, projects=("billing",))


def test_concurrency_slot_and_release_after_rejection(tmp_path):
    led = ledger(tmp_path, max_concurrent=1)
    first = reserve(led)
    with pytest.raises(BudgetDenied) as exc:
        reserve(led)
    assert exc.value.reason == "concurrency"
    assert led.settle(first, outcome="rejected", now=NOW + 1)
    assert led.usage(now=NOW + 1) == {"tokens": 0, "cost_micro": 0, "seconds": 0, "running": 0}
    reserve(led, now=NOW + 1)


def test_restart_expired_worker_stays_charged_and_frees_the_slot(tmp_path):
    led = ledger(tmp_path, monthly={"tokens": 150}, max_concurrent=1)
    res = reserve(led, 100, seconds=10)
    led.close()
    again = ledger(tmp_path, monthly={"tokens": 150}, max_concurrent=1)  # process restart
    with pytest.raises(BudgetDenied) as exc:  # lease still valid: slot taken
        reserve(again, 10, now=NOW + 5)
    assert exc.value.reason == "concurrency"
    assert again.expire(now=NOW + 100) == 2  # global + project row
    with pytest.raises(BudgetDenied) as exc:  # spend is not released
        reserve(again, 100, now=NOW + 101)
    assert exc.value.reason == "tokens"
    reserve(again, 50, now=NOW + 101)
    # a late authoritative report refines it exactly once
    assert again.settle(res, outcome="ok", input_tokens=10, output_tokens=5, now=NOW + 102)
    assert not again.settle(res, outcome="ok", input_tokens=10, output_tokens=5, now=NOW + 103)
    assert again.usage(now=NOW + 103)["tokens"] == 15 + 50


def test_settlement_applies_once_and_cannot_release_charged_spend(tmp_path):
    led = ledger(tmp_path, max_concurrent=4)
    res = reserve(led, 100, price=PRICE)
    assert led.settle(res, outcome="ok", input_tokens=30, output_tokens=10, now=NOW + 2)
    assert not led.settle(res, outcome="rejected", now=NOW + 3)  # cannot free charged spend
    assert not led.settle(res, outcome="ok", input_tokens=1, output_tokens=1, now=NOW + 3)
    usage = led.usage(now=NOW + 3)
    assert usage["tokens"] == 40 and usage["cost_micro"] == 30 * 1 + 10 * 5


def test_usage_overrun_is_recorded_not_hidden(tmp_path):
    led = ledger(tmp_path, monthly={"tokens": 100})
    res = reserve(led, 100)
    led.settle(res, outcome="ok", input_tokens=150, output_tokens=50, now=NOW + 1)
    assert led.usage(now=NOW + 1)["tokens"] == 200
    with pytest.raises(BudgetDenied):
        reserve(led, 1, now=NOW + 2)


def test_missing_usage_keeps_the_reservation_charged(tmp_path):
    led = ledger(tmp_path)
    res = reserve(led, 100)
    led.settle(res, outcome="ok", now=NOW + 1)
    assert led.usage(now=NOW + 1)["tokens"] == 100


def test_ambiguous_timeout_is_charged_and_settles_once(tmp_path):
    led = ledger(tmp_path)
    res = reserve(led, 100)
    assert led.settle(res, outcome="ambiguous", now=NOW + 1)
    assert not led.settle(res, outcome="ambiguous", now=NOW + 2)
    assert led.usage(now=NOW + 2) == {"tokens": 100, "cost_micro": 0, "seconds": 10.0, "running": 0}


def test_cost_budget_needs_a_known_price_and_never_guesses(tmp_path):
    led = ledger(
        tmp_path,
        monthly={"cost_micro": 1000},
        price={"input_per_mtok_micro": 1_000_000, "output_per_mtok_micro": 5_000_000},
    )
    with pytest.raises(BudgetDenied) as exc:
        reserve(led, 100, price=None)
    assert exc.value.reason == "price"
    reserve(led, 100, price=Price(1_000_000, 5_000_000))  # worst case 500
    with pytest.raises(BudgetDenied) as exc:
        reserve(led, 150, price=Price(1_000_000, 5_000_000))  # 750 more -> 1250
    assert exc.value.reason == "cost"


def test_seconds_budget_and_window_rollover(tmp_path):
    led = ledger(tmp_path, monthly={"seconds": 15}, max_concurrent=4)
    reserve(led, 10, seconds=10)
    with pytest.raises(BudgetDenied) as exc:
        reserve(led, 10, seconds=10)
    assert exc.value.reason == "seconds"
    next_month = NOW + 40 * 86400
    assert window_key(next_month) != window_key(NOW)
    reserve(led, 10, seconds=10, now=next_month)  # fresh window


def test_invalid_reservations_and_foreign_owner(tmp_path):
    led = ledger(tmp_path)
    with pytest.raises(ValueError):
        reserve(led, 0)
    with pytest.raises(ValueError):
        reserve(led, 10, seconds=float("nan"))
    res = reserve(led, 10)
    forged = type(res)(res.id, "someone-else", res.scopes, 1, None, 1.0, None, NOW)
    assert not led.settle(forged, outcome="rejected", now=NOW + 1)
    assert led.usage(now=NOW + 1)["tokens"] == 10
