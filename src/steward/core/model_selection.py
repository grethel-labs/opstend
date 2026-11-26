"""Weekly deterministic model selection (A05, ADR 0002 section 2).

No model takes part in the decision. Inputs: the models the connected provider actually
lists (with provenance), the configured family rule, operator-declared dated prices and
measurements from the fixed synthetic suite (`model_suite.py`) run under a separate
evaluation budget. The rule:

- A candidate must belong to a configured family (`inference_models.family_of`), have a
  price that is declared and fresh, and pass *every* suite case (schema and content).
- Order: measured suite cost (lower is better), then the family's position in the policy,
  then the model id. Runtime is recorded and checked against the window but never decides.
- Switch only when the best candidate is strictly cheaper than the incumbent, or the
  incumbent is gone / fails the suite. Equal cost keeps the incumbent. Unknown price,
  unknown usage, missing or incomplete evidence (quota, budget, deadline, failures of the
  incumbent's own measurement) never switch.
- Same provider and data class only; sharing, provider and plan are never changed here.
- The decision (suite revision, measurements, fallback = previous model) is persisted
  *before* activation; activation is one transaction; an interrupted one is abandoned and
  the previously accepted model stays active. Runs are admitted through the maintenance
  window (`MaintenanceRuns`), once per window, one attempt.
"""

from __future__ import annotations

import contextlib
import datetime
import json
import sqlite3
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC
from pathlib import Path

from .config import Ai, AiBudget, AiModelPolicy, AiScopeLimits
from .inference import InferenceError, InferenceProvider, InferenceService, Policy, Usage
from .inference_budget import Ledger, Price
from .inference_models import family_of
from .maintenance_runs import MaintenanceRuns
from .model_suite import SUITE_DATA_CLASS, SUITE_REVISION, cases, grade, scope

WORK_ID = "model_selection"
WORK_SECONDS = 1800
MAX_CANDIDATES = 8
BLOCKING_ERRORS = {
    "quota", "rate_limited", "budget_denied", "window_deadline", "timeout", "price_expired",
}  # fmt: skip
_UNSPECIFIED = object()
SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    id TEXT PRIMARY KEY, created_at REAL NOT NULL, window_start TEXT NOT NULL,
    provider TEXT NOT NULL, data_class TEXT NOT NULL, incumbent TEXT NOT NULL,
    chosen TEXT NOT NULL, fallback TEXT NOT NULL, action TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending','activated','kept','abandoned')),
    suite_revision TEXT NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS active (
    id INTEGER PRIMARY KEY CHECK (id = 1), model TEXT NOT NULL, fallback TEXT NOT NULL,
    decision_id TEXT NOT NULL, updated_at REAL NOT NULL);
"""


# ---- pure rule ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Measurement:
    model: str
    family: str | None
    cases: int = 0
    schema_ok: int = 0
    task_ok: int = 0
    runtime_s: float = 0.0
    cost_micro: int | None = None  # None: unknown price or usage
    tokens: int = 0
    complete: bool = False  # every case ran to an answer or a definite model failure
    error: str | None = None  # stable class of the first infrastructure failure

    @property
    def passed(self) -> bool:
        return self.complete and self.cases > 0 and self.schema_ok == self.task_ok == self.cases


def price_state(
    policy: AiModelPolicy, model: str, today: datetime.date
) -> tuple[Price | None, str]:
    """(price, status) with status in ok/missing/stale. Never estimates a price."""
    for row in policy.prices:
        if row.model == model:
            age = (today - datetime.date.fromisoformat(row.as_of)).days
            if age < 0 or age > policy.price_max_age_days:
                return None, "stale"
            return Price(row.input_per_mtok_micro, row.output_per_mtok_micro), "ok"
    return None, "missing"


def account_usage(
    usage: Usage, price: Price | None, tokens: int, cost: int | None
) -> tuple[int, int | None]:
    tokens += (usage.input_tokens or 0) + (usage.output_tokens or 0)
    if not usage.known or price is None or cost is None:
        return tokens, None
    assert usage.input_tokens is not None and usage.output_tokens is not None
    return tokens, cost + price.cost(usage.input_tokens, usage.output_tokens)


def rank_key(policy: AiModelPolicy, m: Measurement) -> tuple:
    index = policy.families.index(m.family) if m.family in policy.families else len(policy.families)
    return (m.cost_micro if m.cost_micro is not None else float("inf"), index, m.model)


@dataclass(frozen=True)
class Decision:
    action: str  # "keep" | "switch"
    incumbent: str
    chosen: str
    reasons: tuple[str, ...]


def decide(
    policy: AiModelPolicy,
    incumbent: str,
    incumbent_listed: bool,
    results: dict[str, Measurement],
    skipped: dict[str, str],
) -> Decision:
    """The whole selection rule as a pure function."""
    keep = lambda *why: Decision("keep", incumbent, incumbent, tuple(why))  # noqa: E731
    eligible = [
        m
        for name, m in results.items()
        if name != incumbent
        and m.passed
        and m.cost_micro is not None
        and m.family is not None
        and (policy.max_eval_cost_micro is None or m.cost_micro <= policy.max_eval_cost_micro)
    ]
    best = min(eligible, key=lambda m: rank_key(policy, m), default=None)
    mine = results.get(incumbent)
    if not incumbent_listed:
        if best is None:
            return keep("incumbent_not_listed", "no_eligible_candidate")
        return Decision("switch", incumbent, best.model, ("incumbent_not_listed", _why(best)))
    if mine is None:
        return keep("incumbent_not_evaluated", *skipped.get(incumbent, "").split())
    if not mine.complete:
        return keep("incumbent_evaluation_incomplete", mine.error or "unknown")
    if mine.cost_micro is None:
        return keep("incumbent_price_or_usage_unknown")
    if not mine.passed:
        if best is None:
            return keep("incumbent_failed_suite", "no_eligible_candidate")
        return Decision("switch", incumbent, best.model, ("incumbent_failed_suite", _why(best)))
    if best is None:
        return keep("no_eligible_candidate")
    if best.cost_micro >= mine.cost_micro:  # type: ignore[operator]
        return keep("no_strictly_cheaper_candidate")
    return Decision(
        "switch",
        incumbent,
        best.model,
        (f"cost_micro {best.cost_micro} < {mine.cost_micro}", _why(best)),
    )


def _why(m: Measurement) -> str:
    return f"{m.model} passed {m.task_ok}/{m.cases} cases cost_micro={m.cost_micro}"


# ---- persistence -------------------------------------------------------------------------


class SelectionStore:
    """The inference service's own SQLite file: decisions and the accepted model."""

    def __init__(self, path: Path | str):
        self._path = str(path)
        db = sqlite3.connect(self._path, timeout=10)
        try:
            db.executescript(SCHEMA)
        finally:
            db.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self._path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
            except BaseException:
                db.execute("ROLLBACK")
                raise
            db.execute("COMMIT")
        finally:
            db.close()

    def active(self, *, provider: str | None = None, data_class: str | None = None) -> dict | None:
        with self._tx() as db:
            row = db.execute(
                "SELECT a.*, d.provider, d.data_class, d.body FROM active a "
                "JOIN decisions d ON a.decision_id=d.id WHERE a.id=1 "
                "AND (? IS NULL OR d.provider=?) AND (? IS NULL OR d.data_class=?)",
                (provider, provider, data_class, data_class),
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["body"] = json.loads(item["body"])
        metadata = item["body"].get("metadata", {})
        return item | {"metadata": metadata, "choice_id": metadata.get("choice_id")}

    def latest_activated(self, *, provider: str, data_class: str, choice_id: str) -> dict | None:
        with self._tx() as db:
            row = db.execute(
                "SELECT * FROM decisions WHERE provider=? AND data_class=? AND state='activated' "
                "AND json_extract(body, '$.metadata.choice_id')=? "
                "AND json_extract(body, '$.metadata.mode') IN ('weekly','best_now') "
                "ORDER BY rowid DESC LIMIT 1",
                (provider, data_class, choice_id),
            ).fetchone()
        return dict(row) | {"body": json.loads(row["body"])} if row else None

    def activated_decision(
        self, decision_id: str, *, provider: str, data_class: str, choice_id: str | None
    ) -> dict | None:
        with self._tx() as db:
            row = db.execute(
                "SELECT * FROM decisions WHERE id=? AND provider=? AND data_class=? "
                "AND state='activated' AND json_extract(body, '$.metadata.choice_id') IS ?",
                (decision_id, provider, data_class, choice_id),
            ).fetchone()
        return dict(row) | {"body": json.loads(row["body"])} if row else None

    def bind_choice(self, decision_id: str, choice_id: str) -> bool:
        """Bind an existing active decision to its validated legacy choice."""
        with self._tx() as db:
            return bool(
                db.execute(
                    "UPDATE decisions SET body=json_set(body, '$.metadata.choice_id', ?) "
                    "WHERE id=(SELECT decision_id FROM active WHERE id=1) AND id=? "
                    "AND json_extract(body, '$.metadata.choice_id') IS NULL",
                    (choice_id, decision_id),
                ).rowcount
            )

    def record(
        self,
        decision: Decision,
        *,
        now: float,
        window: str,
        provider: str,
        data_class: str,
        body: dict,
    ) -> str:
        """Persist the decision before anything is activated. A `keep` is final already."""
        did = uuid.uuid4().hex
        state = "pending" if decision.action == "switch" else "kept"
        with self._tx() as db:
            db.execute(
                "INSERT INTO decisions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    did, now, window, provider, data_class, decision.incumbent, decision.chosen,
                    decision.incumbent, decision.action, state, SUITE_REVISION,
                    json.dumps(body, sort_keys=True),
                ),
            )  # fmt: skip
        return did

    def activate(
        self, decision_id: str, *, now: float, expected_active: str | None | object = _UNSPECIFIED
    ) -> bool:
        """One transaction: only a pending switch becomes active; the old model is the fallback."""
        with self._tx() as db:
            row = db.execute("SELECT * FROM decisions WHERE id=?", (decision_id,)).fetchone()
            if row is None or row["state"] != "pending":
                return False
            if expected_active is not _UNSPECIFIED:
                active = db.execute("SELECT decision_id FROM active WHERE id=1").fetchone()
                if (active["decision_id"] if active else None) != expected_active:
                    return False
            db.execute(
                "INSERT INTO active VALUES (1,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                "model=excluded.model, fallback=excluded.fallback, "
                "decision_id=excluded.decision_id, updated_at=excluded.updated_at",
                (row["chosen"], row["fallback"], decision_id, now),
            )
            db.execute("UPDATE decisions SET state='activated' WHERE id=?", (decision_id,))
        return True

    def abandon(self, decision_id: str, reason: str) -> None:
        with self._tx() as db:
            db.execute(
                "UPDATE decisions SET state='abandoned', "
                "body=json_set(body, '$.abandon_reason', ?) WHERE id=? AND state='pending'",
                (reason, decision_id),
            )

    def recover(self) -> int:
        """After a crash: a switch that was persisted but never activated is abandoned;
        the previously accepted model stays active and the next window decides again."""
        with self._tx() as db:
            return db.execute(
                "UPDATE decisions SET state='abandoned', "
                "body=json_set(body, '$.abandon_reason', 'interrupted') WHERE state='pending'"
            ).rowcount

    def history(self, limit: int = 20) -> list[dict]:
        with self._tx() as db:
            rows = db.execute(
                "SELECT * FROM decisions ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["body"] = json.loads(item["body"])
            out.append(item)
        return out


def effective_model(ai: Ai, store: SelectionStore | None) -> str:
    """The model to use: the accepted selection if any, else the configured model."""
    active = (
        store.active(provider=ai.provider, data_class="external" if ai.is_external else "local")
        if store is not None
        else None
    )
    return active["model"] if active else (ai.model or "")


# ---- evaluation --------------------------------------------------------------------------


@dataclass(frozen=True)
class SelectionGuards:
    """Operator-owned limits that deterministic code applies around the rule (ADR 0008).

    `skip` returns a reason when the run must not start (pinned model, automation off);
    `switch` returns a reason when a proposed switch lacks outside confirmation (source
    consensus). Both only ever make the run keep the incumbent."""

    skip: Callable[[], str | None] | None = None
    switch: Callable[[Decision], str | None] | None = None


@dataclass
class RunResult:
    status: str  # not_admitted | skipped | kept | switched | abandoned | failed
    reason: str = ""
    decision: Decision | None = None
    decision_id: str = ""
    body: dict = field(default_factory=dict)


class WeeklySelection:
    def __init__(
        self,
        *,
        ai: Ai,
        window_spec: str,
        runs: MaintenanceRuns,
        store: SelectionStore,
        eval_ledger_path: Path | str,
        make_provider: Callable[[str], InferenceProvider],
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        audit: Callable[[dict], None] | None = None,
        before_activation: Callable[[str], None] | None = None,
        activate_decision: (
            Callable[[str, Decision, str | None, Callable[[float], str | None]], str | None] | None
        ) = None,
        metadata: dict | None = None,
        recover_pending: bool = True,
        worker: str = "model-selection",
        work_id: str = WORK_ID,
        guards: SelectionGuards | None = None,
        rate_guard: Callable[[float], bool] | None = None,
    ):
        if ai.model_policy is None or ai.model is None:
            raise ValueError("ai.model_policy is required")
        self.ai, self.policy = ai, ai.model_policy
        self.window_spec, self.runs, self.store = window_spec, runs, store
        self.eval_ledger_path, self.make_provider = eval_ledger_path, make_provider
        self.clock, self.monotonic, self.audit = clock, monotonic, audit
        self.before_activation, self.worker = before_activation, worker
        self.work_id, self.guards = work_id, guards or SelectionGuards()
        self.activate_decision = activate_decision
        self.metadata, self.recover_pending = metadata, recover_pending
        self.rate_guard = rate_guard  # stale exchange rate: cost-limited evaluation denies

    # -- one admitted run ------------------------------------------------------------

    def _price(self, model: str, now: float) -> tuple[Price | None, str]:
        return price_state(self.policy, model, datetime.datetime.fromtimestamp(now, UTC).date())

    def run(self) -> RunResult:
        now = self.clock()
        if self.recover_pending:
            self.store.recover()
        self.runs.recover(now)
        admission = self.runs.request(
            self.window_spec,
            now,
            work=self.work_id,
            work_seconds=WORK_SECONDS,
            created_by=self.worker,
        )
        if admission.job is None or not admission.created:
            return RunResult("not_admitted", admission.admission.reason)
        job = self.runs.begin(self.worker, now, job_id=admission.job["id"])
        if job is None:
            return RunResult("not_admitted", "window_expired_before_start")
        try:
            result = self._execute(job["payload"]["window_start"], job["payload"]["window_end"])
        except Exception as exc:  # recorded as a failed run; the accepted model is untouched
            self.runs.complete(
                job["id"], self.worker, ok=False, now=self.clock(), error=type(exc).__name__
            )
            return RunResult("failed", type(exc).__name__)
        except BaseException:  # interrupted: close the run as failed, keep the accepted model
            self.runs.complete(
                job["id"], self.worker, ok=False, now=self.clock(), error="interrupted"
            )
            raise
        self.runs.complete(
            job["id"],
            self.worker,
            ok=result.status in ("kept", "switched", "skipped"),
            now=self.clock(),
            result={"status": result.status, "reason": result.reason},
        )
        return result

    def _execute(self, window_start: str, window_end: str) -> RunResult:
        now = self.clock()
        if self.guards.skip is not None and (why := self.guards.skip()):
            return self._skip(why)
        deadline = min(datetime.datetime.fromisoformat(window_end).timestamp(), now + WORK_SECONDS)
        data_class = "external" if self.ai.is_external else "local"
        active = self.store.active()
        expected_id = active["decision_id"] if active else None
        scoped = active and (active["provider"], active["data_class"]) == (
            self.ai.provider,
            data_class,
        )
        incumbent = active["model"] if scoped else self.ai.model
        metadata = self.metadata
        if metadata is None and scoped and active["choice_id"]:
            metadata = {"choice_id": active["choice_id"]}
        if self.clock() >= deadline:
            return self._skip("window_deadline")
        try:
            primary = self.make_provider(incumbent)
        except InferenceError as exc:
            return self._skip(f"discovery_failed_{exc.error_class}")
        if (primary.name, primary.data_class, primary.model) != (
            self.ai.provider,
            data_class,
            incumbent,
        ):
            return self._skip("provider_scope_mismatch")
        if data_class == "external" and SUITE_DATA_CLASS not in self.ai.share:
            return self._skip("suite_data_class_not_shared")
        if "models.list" not in getattr(primary, "capabilities", ()) and not hasattr(
            primary, "list_models"
        ):
            return self._skip("provider_cannot_list_models")
        try:
            listed = sorted(set(primary.list_models()))  # type: ignore[attr-defined]
        except InferenceError as exc:
            return self._skip(f"discovery_failed_{exc.error_class}")
        provenance = {
            "provider": primary.name,
            "listed_at": now,
            "listed_count": len(listed),
            "source": "provider_model_list",
        }
        after_discovery = self.clock()
        candidates: dict[str, str | None] = {}
        skipped: dict[str, str] = {}
        for model in listed:
            family = family_of(primary.name, model)
            if family is None or family not in self.policy.families:
                continue
            _, status = self._price(model, after_discovery)
            if status != "ok" and model != incumbent:
                skipped[model] = f"price_{status}"
                continue
            candidates[model] = family
        listed_set = set(listed)
        incumbent_listed = incumbent in listed_set
        if incumbent_listed:
            candidates.setdefault(incumbent, family_of(primary.name, incumbent))
        names = sorted(candidates, key=lambda m: (m != incumbent, m))[: MAX_CANDIDATES + 1]
        for dropped in sorted(set(candidates) - set(names)):
            skipped[dropped] = "candidate_limit"
        ledger = Ledger(
            self.eval_ledger_path,
            AiBudget(
                monthly=AiScopeLimits(
                    tokens=self.policy.max_eval_tokens, cost_micro=self.policy.max_eval_cost_micro
                )
            ),
            rate_guard=self.rate_guard,
        )
        results: dict[str, Measurement] = {}
        prices_used: dict[str, dict] = {}
        blocking = None
        try:
            for model in names:
                now = self.clock()
                if now >= deadline:
                    blocking = "window_deadline"
                    break
                price, status = self._price(model, now)
                if price is None:
                    skipped[model] = f"price_{status}"
                    continue
                row = next(row for row in self.policy.prices if row.model == model)
                prices_used[model] = row.model_dump()
                measurement = self._measure(
                    model, candidates[model], ledger, price, deadline, data_class
                )
                results[model] = measurement
                if measurement.error in BLOCKING_ERRORS:
                    blocking = measurement.error
                    break
        finally:
            ledger.close()
        decision = decide(self.policy, incumbent, incumbent_listed, results, skipped)
        if blocking and blocking not in decision.reasons:
            decision = Decision("keep", incumbent, incumbent, (*decision.reasons, blocking))
        source_verdict = None
        if decision.action == "switch" and self.guards.switch is not None:
            why = self.guards.switch(decision)
            source_verdict = why or "confirmed"
            if why:
                decision = Decision(
                    "keep", incumbent, incumbent, (*decision.reasons, f"switch_guard:{why}")
                )
        persist_at = self.clock()
        if persist_at >= deadline and "window_deadline" not in decision.reasons:
            decision = Decision(
                "keep", incumbent, incumbent, (*decision.reasons, "window_deadline")
            )
        required_prices = (incumbent, decision.chosen) if incumbent_listed else (decision.chosen,)

        def price_check(at: float) -> str | None:
            if any(self._price(model, at)[0] is None for model in required_prices):
                return "price_expired"
            return None

        if decision.action == "switch" and (reason := price_check(persist_at)):
            decision = Decision("keep", incumbent, incumbent, (*decision.reasons, reason))
        body = {
            "provenance": provenance,
            "suite_revision": SUITE_REVISION,
            "measurements": {m: asdict(v) for m, v in sorted(results.items())},
            "skipped": dict(sorted(skipped.items())),
            "reasons": list(decision.reasons),
            "policy_families": list(self.policy.families),
            "prices": prices_used,
            "source_verdict": source_verdict,
            "metadata": metadata or {},
        }
        did = self.store.record(
            decision,
            now=persist_at,
            window=window_start,
            provider=primary.name,
            data_class=data_class,
            body=body,
        )
        if decision.action == "keep":
            self._emit("kept", did, decision)
            return RunResult("kept", ";".join(decision.reasons), decision, did, body)
        if self.before_activation is not None:
            self.before_activation(did)  # test hook for an interrupted activation
        now = self.clock()
        reason = "window_deadline" if now >= deadline else price_check(now)
        if reason is None:
            if self.activate_decision is not None:
                reason = self.activate_decision(did, decision, expected_id, price_check)
            elif not self.store.activate(did, now=now, expected_active=expected_id):
                reason = "activation_refused"
        if reason:
            self.store.abandon(did, reason)
            body["abandon_reason"] = reason
            self._emit("abandoned", did, decision, reason)
            return RunResult("abandoned", reason, decision, did, body)
        self._emit("switched", did, decision)
        return RunResult("switched", ";".join(decision.reasons), decision, did, body)

    def _skip(self, reason: str) -> RunResult:
        self._emit("skipped", "", None, reason=reason)
        return RunResult("skipped", reason)

    def _emit(self, what: str, did: str, decision: Decision | None, reason: str = "") -> None:
        if self.audit is None:
            return
        event = {"event": f"inference.model_{what}", "decision": did, "suite": SUITE_REVISION}
        if decision is not None:
            event |= {
                "incumbent": decision.incumbent,
                "chosen": decision.chosen,
                "reasons": list(decision.reasons),
            }
        if reason:
            event["reason"] = reason
        with contextlib.suppress(Exception):  # the persisted decision is the record of truth
            self.audit(event)

    def _measure(
        self,
        model: str,
        family: str | None,
        ledger: Ledger,
        price: Price,
        deadline: float,
        data_class: str,
    ) -> Measurement:
        try:
            provider = self.make_provider(model)
            if (provider.name, provider.data_class, provider.model) != (
                self.ai.provider,
                data_class,
                model,
            ):
                return Measurement(model, family, error="provider_scope_mismatch")
            service = InferenceService(
                provider,
                ledger,
                Policy(local_only=False, share=frozenset(self.ai.share))
                if data_class == "external"
                else Policy(),
                prices={provider.name: price},
                max_attempts=1,
                clock=self.clock,
            )
        except InferenceError as exc:
            return Measurement(model, family, error=exc.error_class)
        start = self.monotonic()
        n = schema_ok = task_ok = tokens = 0
        cost: int | None = 0
        error: str | None = None
        complete = True
        now = self.clock()
        for case in cases(now):
            observed_at = self.clock()
            if observed_at >= deadline:
                complete, error = False, "window_deadline"
                break
            if self._price(model, observed_at)[0] is None:
                complete, error = False, "price_expired"
                break
            n += 1
            outcome = service.run(case.task, list(case.items), scope(now))
            tokens, cost = account_usage(outcome.usage, price, tokens, cost)
            if outcome.ok and outcome.data is not None:
                schema_ok += 1
                task_ok += grade(case, outcome.data)
            elif outcome.error_class == "invalid_output":
                pass  # a definite model failure: counts as a failed case
            else:  # quota, budget, auth, unavailable...: evidence is incomplete
                complete, error = False, outcome.error_class
                break
        return Measurement(
            model, family, n, schema_ok, task_ok, round(self.monotonic() - start, 3),
            cost, tokens, complete, error,
        )  # fmt: skip
