"""Transactional inference budgets: reserve before a call, reconcile afterwards.

The ledger is the inference service's own SQLite file (never shared with another
trust domain). Limits come from the typed `ai.budget` configuration. A call
reserves tokens, cost, seconds and a concurrency slot in every affected scope
(`global` plus `project:<id>`) inside one immediate transaction, so concurrent
workers and restarts cannot overspend. Windows are UTC calendar months.

Settlement rules, each applied at most once per reservation:

- `ok` with usage: charge the measured tokens/seconds (and cost when a price is
  known); an overrun beyond the reservation is recorded, not hidden.
- `ok` without usage: the reservation stays charged in full (unknown is not free).
- `rejected` (provider definitively did not process, e.g. 4xx before work): released.
- `ambiguous` (timeout, 5xx, lost connection, expired worker): stays charged at the
  reserved amount; a later authoritative settlement may refine it exactly once.
- A price is never invented. With a cost limit but no known price, reserving fails.
"""

from __future__ import annotations

import math
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .config import AiBudget, AiScopeLimits

GRACE_S = 30.0
COUNTED = ("reserved", "ambiguous", "charged")
SCHEMA = """
CREATE TABLE IF NOT EXISTS reservations (
    id TEXT NOT NULL,
    scope TEXT NOT NULL,
    window TEXT NOT NULL,
    owner TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved','ambiguous','charged','released')),
    tokens INTEGER NOT NULL,
    cost_micro INTEGER,
    seconds REAL NOT NULL,
    usage_known INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    settled_at REAL,
    PRIMARY KEY (id, scope)
);
CREATE INDEX IF NOT EXISTS reservations_scope ON reservations(scope, window, state);
"""


class BudgetDenied(Exception):
    """A reservation was refused; `reason` is one of tokens/cost/seconds/concurrency/price."""

    def __init__(self, reason: str, scope: str):
        super().__init__(f"{reason} budget denied for {scope}")
        self.reason, self.scope = reason, scope


@dataclass(frozen=True)
class Price:
    input_per_mtok_micro: int
    output_per_mtok_micro: int

    def cost(self, input_tokens: int, output_tokens: int) -> int:
        total = (
            input_tokens * self.input_per_mtok_micro + output_tokens * self.output_per_mtok_micro
        )
        return -(-total // 1_000_000)


@dataclass(frozen=True)
class Reservation:
    id: str
    owner: str
    scopes: tuple[str, ...]
    tokens: int
    cost_micro: int | None
    seconds: float
    price: Price | None
    started_at: float


def window_key(now: float) -> str:
    return time.strftime("%Y-%m", time.gmtime(now))


class Ledger:
    def __init__(
        self,
        path: Path | str,
        budget: AiBudget,
        rate_guard: Callable[[float], bool] | None = None,
    ):
        # rate_guard(now) is False when the exchange rate behind cost limits is stale
        # (decision 7): cost-limited reservations then deny instead of guessing.
        self._path, self.budget, self.rate_guard = str(path), budget, rate_guard
        self._local = threading.local()
        self._conn().executescript(SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._path, timeout=10, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            del self._local.conn

    def _limits(self, scope: str) -> AiScopeLimits:
        return self.budget.monthly if scope == "global" else self.budget.per_project

    def _expire(self, db: sqlite3.Connection, now: float) -> int:
        """Reservations of vanished workers stay charged (outcome unknown) but free their slot."""
        return db.execute(
            "UPDATE reservations SET state='ambiguous', settled_at=? "
            "WHERE state='reserved' AND expires_at<=?",
            (now, now),
        ).rowcount

    def expire(self, *, now: float | None = None) -> int:
        """Restart recovery; returns the number of reservation rows made ambiguous."""
        now = time.time() if now is None else now
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            n = self._expire(conn, now)
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")
        return n

    def reserve(
        self,
        *,
        projects: tuple[str, ...],
        tokens: int,
        seconds: float,
        price: Price | None,
        input_tokens: int | None = None,
        now: float | None = None,
        owner: str = "inference",
    ) -> Reservation:
        """Atomically reserve in `global` and each project scope or raise BudgetDenied.

        `tokens` is the worst case (estimated input + maximum output); cost is derived
        from `input_tokens` when given, otherwise every token at the dearer rate.
        """
        now = time.time() if now is None else now
        if tokens < 1 or not math.isfinite(seconds) or seconds <= 0:
            raise ValueError("invalid reservation")
        cost: int | None = None
        if price is not None:
            if input_tokens is None:  # price the worst case at the dearer rate
                rate = max(price.input_per_mtok_micro, price.output_per_mtok_micro)
                cost = Price(rate, rate).cost(tokens, 0)
            else:
                cost = price.cost(input_tokens, tokens - input_tokens)
        scopes = ("global", *(f"project:{p}" for p in sorted(set(projects))))
        window, rid = window_key(now), uuid.uuid4().hex
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            self._expire(conn, now)
            for scope in scopes:
                self._check(conn, scope, window, tokens, cost, seconds, now)
            for scope in scopes:
                conn.execute(
                    "INSERT INTO reservations (id, scope, window, owner, state, tokens, "
                    "cost_micro, seconds, created_at, expires_at) "
                    "VALUES (?,?,?,?,'reserved',?,?,?,?,?)",
                    (
                        rid,
                        scope,
                        window,
                        owner,
                        tokens,
                        cost,
                        seconds,
                        now,
                        now + seconds + GRACE_S,
                    ),
                )
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")
        return Reservation(rid, owner, scopes, tokens, cost, seconds, price, now)

    def _check(self, db, scope, window, tokens, cost, seconds, now) -> None:
        limits = self._limits(scope)
        if limits.cost_micro is not None and cost is None:
            raise BudgetDenied("price", scope)
        if limits.cost_micro is not None and self.rate_guard and not self.rate_guard(now):
            raise BudgetDenied("fx_rate", scope)
        row = db.execute(
            "SELECT COALESCE(SUM(tokens),0) t, COALESCE(SUM(cost_micro),0) c, "
            "COALESCE(SUM(seconds),0) s FROM reservations "
            "WHERE scope=? AND window=? AND state IN ('reserved','ambiguous','charged')",
            (scope, window),
        ).fetchone()
        if limits.tokens is not None and row["t"] + tokens > limits.tokens:
            raise BudgetDenied("tokens", scope)
        if limits.cost_micro is not None and row["c"] + (cost or 0) > limits.cost_micro:
            raise BudgetDenied("cost", scope)
        if limits.seconds is not None and row["s"] + seconds > limits.seconds:
            raise BudgetDenied("seconds", scope)
        if scope == "global":
            running = db.execute(
                "SELECT COUNT(*) FROM reservations WHERE scope='global' AND state='reserved' "
                "AND expires_at>?",
                (now,),
            ).fetchone()[0]
            if running >= self.budget.max_concurrent:
                raise BudgetDenied("concurrency", scope)

    def settle(
        self,
        res: Reservation,
        *,
        outcome: str,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        now: float | None = None,
    ) -> bool:
        """Apply the call's outcome once. Returns False when nothing was left to settle."""
        if outcome not in ("ok", "rejected", "ambiguous"):
            raise ValueError("unknown outcome")
        now = time.time() if now is None else now
        elapsed = max(0.0, now - res.started_at)
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            rows = conn.execute(
                "SELECT scope, state FROM reservations WHERE id=? AND owner=?", (res.id, res.owner)
            ).fetchall()
            states = {r["state"] for r in rows}
            if not rows or not states <= {"reserved", "ambiguous"}:
                conn.execute("ROLLBACK")
                return False
            if outcome == "ambiguous" and states == {"ambiguous"}:
                conn.execute("ROLLBACK")
                return False
            if outcome == "rejected":
                conn.execute(
                    "UPDATE reservations SET state='released', tokens=0, cost_micro=0, "
                    "seconds=0, settled_at=? WHERE id=?",
                    (now, res.id),
                )
            elif outcome == "ambiguous":
                conn.execute(
                    "UPDATE reservations SET state='ambiguous', settled_at=? WHERE id=?",
                    (now, res.id),
                )
            else:
                known = (
                    input_tokens is not None
                    and output_tokens is not None
                    and input_tokens >= 0
                    and output_tokens >= 0
                )
                if known:
                    tokens = input_tokens + output_tokens
                    cost = res.price.cost(input_tokens, output_tokens) if res.price else None
                    seconds = min(elapsed, res.seconds) if elapsed else 0.0
                    conn.execute(
                        "UPDATE reservations SET state='charged', tokens=?, cost_micro=?, "
                        "seconds=?, usage_known=1, settled_at=? WHERE id=?",
                        (tokens, cost, seconds, now, res.id),
                    )
                else:
                    conn.execute(
                        "UPDATE reservations SET state='charged', settled_at=? WHERE id=?",
                        (now, res.id),
                    )
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")
        return True

    def usage(self, scope: str = "global", *, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        row = (
            self._conn()
            .execute(
                "SELECT COALESCE(SUM(tokens),0) t, COALESCE(SUM(cost_micro),0) c, "
                "COALESCE(SUM(seconds),0) s, SUM(state='reserved') r FROM reservations "
                "WHERE scope=? AND window=? AND state IN ('reserved','ambiguous','charged')",
                (scope, window_key(now)),
            )
            .fetchone()
        )
        return {
            "tokens": row["t"],
            "cost_micro": row["c"],
            "seconds": row["s"],
            "running": row["r"] or 0,
        }
