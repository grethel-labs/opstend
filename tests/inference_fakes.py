"""Shared fakes for the inference contract tests (no network, no provider)."""

from __future__ import annotations

import json

from steward.core.config import AiBudget
from steward.core.inference import (
    Health,
    InferenceError,
    InferenceService,
    Policy,
    RawCompletion,
    Usage,
)
from steward.core.inference_budget import Ledger, Price
from steward.core.inference_snapshot import Item, Scope

NOW = 1_800_000_000.0  # 2027-01-15, fixed clock


class FakeProvider:
    version = 1
    capabilities = ("complete.json",)
    timeout_s = 5.0
    max_input_bytes = 60000

    def __init__(self, name="fake", data_class="local", script=None, model="fake-1"):
        self.name, self.data_class, self.model = name, data_class, model
        self.script = list(script or [])
        self.calls: list[tuple[str, str]] = []

    def health(self) -> Health:
        return Health(ok=True)

    def complete(self, system, user, *, schema, max_output_tokens, timeout_s):
        self.calls.append((system, user))
        step = self.script.pop(0) if self.script else "ok"
        if isinstance(step, Exception):
            raise step
        if step == "ok":
            count = len(json.loads(user)["items"])
            text = json.dumps({"item_count": count, "newest_source": "controller"})
            return RawCompletion(text, Usage(100, 20), self.model)
        return RawCompletion(step, Usage(100, 20), self.model)


def make_ledger(tmp_path, **kw) -> Ledger:
    budget = AiBudget(**kw)
    return Ledger(tmp_path / "inference.db", budget)


def make_service(tmp_path, provider=None, *, policy=None, fallbacks=(), prices=None, **kw):
    provider = provider or FakeProvider()
    ledger = kw.pop("ledger", None) or make_ledger(tmp_path)
    service = InferenceService(
        provider,
        ledger,
        policy or Policy(),
        fallbacks=fallbacks,
        prices=prices,
        sleep=lambda s: None,
        clock=lambda: NOW,
        **kw,
    )
    return service, ledger


def scope(*projects, host=False):
    return Scope(frozenset(projects), host, NOW - 3600, NOW)


def item(
    text="ok", *, project="notes", at=NOW - 60, source="controller", cls="status", kind="status"
):
    return Item(source, kind, cls, at, text, project)


def err(cls, **kw):
    return InferenceError(cls, **kw)


PRICE = Price(1_000_000, 5_000_000)  # 1 and 5 micro-units per token
