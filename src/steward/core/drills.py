"""Durable records of announced maintenance drills (L11, ADR 0002 section 8).

Three small tables in a private executor database:

- `announcements`: one per regular window. A drill runs only in a window whose
  announcement was recorded early enough beforehand.
- `runs`: one per (drill, service, window): a second request in the same window is
  refused, and a run left `started` by a dead executor is closed as failed.
- `suspensions`: a service that failed to come back healthy after a drill has no
  further drills until an operator releases it or a verified update was applied
  to it after the failure.

Records only; nothing here touches the host.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

DRILLS = ("resources", "restart", "restore")
# Work budget per drill, in seconds; it must fit before the window ends (admission).
BUDGET_S = {"resources": 60, "restart": 300, "restore": 900}
MIN_ANNOUNCE_LEAD_S = 15 * 60
MAX_ANNOUNCE_LEAD_S = 24 * 3600
HOST = "host"  # service name used by drills that are not about one project

SCHEMA = """
CREATE TABLE IF NOT EXISTS announcements (
    window_start TEXT PRIMARY KEY, announced_at REAL NOT NULL, drills TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY, drill TEXT NOT NULL, service TEXT NOT NULL, window_start TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('started','completed','failed')),
    started_at REAL NOT NULL, ended_at REAL, elapsed_s REAL, cause TEXT, result TEXT,
    UNIQUE (drill, service, window_start));
CREATE TABLE IF NOT EXISTS suspensions (
    service TEXT PRIMARY KEY, since REAL NOT NULL, run_id TEXT NOT NULL, cause TEXT NOT NULL);
"""


class DrillLedger:
    def __init__(self, path: str):
        self._path = path
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

    # ---- announcements ------------------------------------------------------------

    def announce(self, window_start: str, drills: list[str], now: float) -> bool:
        with self._tx() as db:
            cur = db.execute(
                "INSERT OR IGNORE INTO announcements VALUES (?,?,?)",
                (window_start, now, json.dumps(sorted(drills))),
            )
            return cur.rowcount == 1

    def announcement(self, window_start: str) -> dict[str, Any] | None:
        with self._tx() as db:
            row = db.execute(
                "SELECT * FROM announcements WHERE window_start=?", (window_start,)
            ).fetchone()
        if row is None:
            return None
        return {"announced_at": row["announced_at"], "drills": json.loads(row["drills"])}

    # ---- runs ---------------------------------------------------------------------

    def begin(self, drill: str, service: str, window_start: str, now: float) -> str | None:
        """Record the start; None if this drill already ran for this service in this window."""
        run_id = uuid.uuid4().hex
        with self._tx() as db:
            cur = db.execute(
                "INSERT OR IGNORE INTO runs (id, drill, service, window_start, state, started_at) "
                "VALUES (?,?,?,?, 'started', ?)",
                (run_id, drill, service, window_start, now),
            )
            return run_id if cur.rowcount == 1 else None

    def finish(
        self,
        run_id: str,
        *,
        ok: bool,
        now: float,
        elapsed_s: float,
        cause: str | None = None,
        result: dict[str, Any] | None = None,
    ) -> None:
        with self._tx() as db:
            db.execute(
                "UPDATE runs SET state=?, ended_at=?, elapsed_s=?, cause=?, result=? "
                "WHERE id=? AND state='started'",
                (
                    "completed" if ok else "failed",
                    now,
                    elapsed_s,
                    cause,
                    json.dumps(result) if result is not None else None,
                    run_id,
                ),
            )

    def recover(self, now: float) -> list[dict[str, Any]]:
        """Close runs a dead executor left started: failed, and the service is suspended."""
        out = []
        with self._tx() as db:
            for row in db.execute("SELECT * FROM runs WHERE state='started'").fetchall():
                db.execute(
                    "UPDATE runs SET state='failed', ended_at=?, cause='interrupted' WHERE id=?",
                    (now, row["id"]),
                )
                if row["service"] != HOST and row["drill"] == "restart":
                    db.execute(
                        "INSERT OR IGNORE INTO suspensions VALUES (?,?,?,?)",
                        (row["service"], now, row["id"], "interrupted"),
                    )
                out.append({"run_id": row["id"], "drill": row["drill"], "service": row["service"]})
        return out

    def runs(self, limit: int = 10) -> list[dict[str, Any]]:
        with self._tx() as db:
            rows = db.execute(
                "SELECT * FROM runs ORDER BY started_at DESC, rowid DESC LIMIT ?", (limit,)
            ).fetchall()
        return [
            {
                "id": r["id"],
                "drill": r["drill"],
                "service": r["service"],
                "window_start": r["window_start"],
                "state": r["state"],
                "elapsed_s": r["elapsed_s"],
                "cause": r["cause"],
            }
            for r in rows
        ]

    # ---- suspensions --------------------------------------------------------------

    def suspend(self, service: str, run_id: str, cause: str, now: float) -> None:
        with self._tx() as db:
            db.execute(
                "INSERT OR IGNORE INTO suspensions VALUES (?,?,?,?)", (service, now, run_id, cause)
            )

    def suspension(self, service: str) -> dict[str, Any] | None:
        with self._tx() as db:
            row = db.execute("SELECT * FROM suspensions WHERE service=?", (service,)).fetchone()
        return dict(row) if row else None

    def suspensions(self) -> list[dict[str, Any]]:
        with self._tx() as db:
            return [dict(r) for r in db.execute("SELECT * FROM suspensions ORDER BY service")]

    def release(self, service: str) -> bool:
        with self._tx() as db:
            return db.execute("DELETE FROM suspensions WHERE service=?", (service,)).rowcount == 1
