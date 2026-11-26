"""Normalized event log.

Every observation and action on the platform becomes one event: time, source,
kind, severity, project/target, correlation id, outcome and a short redacted
summary. The collector is the only writer; readers (admin API, later the info
bot) query it through the collector's socket, never through the database file.

Delivery classes decide how a notification adapter treats an event:
`immediate` (forward at once), `digest` (daily summary), `none` (queryable
only). They are derived from fixed rules here, so the class of an event never
depends on model output or free text.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .ids import valid_request_id
from .secrets import redact

SEVERITIES = ("info", "warning", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
DELIVERY = ("immediate", "digest", "none")
SUMMARY_MAX = 500
DATA_MAX = 4096

# Outcomes of a mutating action that mean "automation could not help".
ESCALATION_OUTCOMES = frozenset({"budget_exhausted", "execution_failed", "internal"})
IMMEDIATE_KINDS = frozenset(
    {
        "kill_switch.on",
        "kill_switch.off",
        "observation_gap",
        "finding.escalated",
        "log.backlog",
        "audit.discontinuity",
        "backup.pause",
        "backup.resume",
        "backup.schedule",
        "backup.capacity",
        "backup.worker_failure",
        "maintenance.window_announced",
        "maintenance.failed",
        "maintenance.drill_failed",
        "update.emergency",
        "update.auto_rollback",
    }
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    source TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    severity_rank INTEGER NOT NULL,
    project TEXT,
    target TEXT,
    correlation_id TEXT,
    outcome TEXT,
    summary TEXT NOT NULL,
    data TEXT NOT NULL,
    delivery TEXT NOT NULL,
    UNIQUE (source, source_ref)
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_project ON events(project, ts);
CREATE INDEX IF NOT EXISTS events_correlation ON events(correlation_id);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


@dataclass
class Event:
    ts: float
    source: str  # executor | controller | journal | collector | audit
    source_ref: str  # unique per source; makes ingestion idempotent
    kind: str
    severity: str
    summary: str
    project: str | None = None
    target: str | None = None
    correlation_id: str | None = None
    outcome: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_RANK:
            raise ValueError(f"unknown severity {self.severity}")
        self.summary = redact(self.summary)[:SUMMARY_MAX]

    @property
    def delivery(self) -> str:
        return classify(self)


def classify(event: Event) -> str:
    """Fixed delivery rules (ADR 0002 §8)."""
    if event.kind in IMMEDIATE_KINDS or event.kind.startswith("incident."):
        return "immediate"
    if event.kind == "backup.retirement" and event.severity in ("high", "critical"):
        return "immediate"
    if event.kind == "finding.opened" and event.severity in ("high", "critical"):
        return "immediate"
    if event.kind.startswith("vulnerability.") and event.kind != "vulnerability.scan_completed":
        return "immediate" if event.severity in ("high", "critical") else "digest"
    if event.kind.startswith("action.") and event.outcome in ESCALATION_OUTCOMES:
        return "immediate"
    if event.kind == "request.denied" and event.outcome == "unauthorized_peer":
        return "immediate"
    if event.kind in ("log", "audit.record"):
        return "none"
    return "digest"


def correlation_from_request(request_id: str | None) -> str | None:
    """`<correlation>-<attempt or nonce>` -> correlation; plain ids map to themselves."""
    if not valid_request_id(request_id):
        return None
    head, sep, _tail = request_id.rpartition("-")
    return head if sep and head else request_id


class EventStore:
    def __init__(self, path: Path | str):
        self._path = str(path)
        self._local = threading.local()
        self._conn().executescript(SCHEMA)
        self._conn().execute(
            "INSERT OR IGNORE INTO meta VALUES ('stream_id', ?)", (json.dumps(uuid.uuid4().hex),)
        )

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._path, timeout=10, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return conn

    def close(self) -> None:
        """Release this thread's connection at its request boundary."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            finally:
                del self._local.conn

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")

    # ---- writing ----------------------------------------------------------------

    def add(self, events: Iterable[Event], meta: dict[str, Any] | None = None) -> int:
        """Insert events and update cursors atomically. Duplicates are ignored."""
        inserted = 0
        with self._tx() as db:
            for event in events:
                data = json.dumps(event.data, sort_keys=True, default=str)
                if len(data) > DATA_MAX:
                    data = json.dumps({"truncated": True})
                cur = db.execute(
                    "INSERT OR IGNORE INTO events (ts, source, source_ref, kind, severity, "
                    "severity_rank, project, target, correlation_id, outcome, summary, data, "
                    "delivery) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        event.ts,
                        event.source,
                        event.source_ref,
                        event.kind,
                        event.severity,
                        SEVERITY_RANK[event.severity],
                        event.project,
                        event.target,
                        event.correlation_id,
                        event.outcome,
                        event.summary,
                        data,
                        event.delivery,
                    ),
                )
                inserted += cur.rowcount
            for key, value in (meta or {}).items():
                db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, json.dumps(value)))
        return inserted

    def prune(self, *, now: float, retention_days: int, max_events: int) -> int:
        """Drop events older than the retention or beyond the size cap."""
        cutoff = now - retention_days * 86400
        with self._tx() as db:
            deleted = db.execute("DELETE FROM events WHERE ts < ?", (cutoff,)).rowcount
            row = db.execute(
                "SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET ?", (max_events,)
            ).fetchone()
            if row is not None:
                deleted += db.execute("DELETE FROM events WHERE id <= ?", (row["id"],)).rowcount
            if deleted:
                oldest = db.execute("SELECT MIN(ts) FROM events").fetchone()[0]
                db.execute(
                    "INSERT OR REPLACE INTO meta VALUES ('pruned_before', ?)",
                    (json.dumps(oldest if oldest is not None else now),),
                )
        return deleted

    # ---- reading ----------------------------------------------------------------

    def get_meta(self, key: str, default: Any = None) -> Any:
        row = self._conn().execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    def query(
        self,
        *,
        since: float | None = None,
        until: float | None = None,
        project: str | None = None,
        min_severity: str = "info",
        kind_prefix: str | None = None,
        correlation_id: str | None = None,
        delivery: str | None = None,
        after_id: int | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        clauses, args = ["severity_rank >= ?"], [SEVERITY_RANK[min_severity]]
        for column, op, value in (
            ("ts", ">=", since),
            ("ts", "<", until),
            ("project", "=", project),
            ("correlation_id", "=", correlation_id),
            ("delivery", "=", delivery),
            ("id", ">", after_id),
        ):
            if value is not None:
                clauses.append(f"{column} {op} ?")
                args.append(value)
        if kind_prefix:
            clauses.append("kind LIKE ? ESCAPE '\\'")
            args.append(
                kind_prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            )
        order = "ASC" if after_id is not None else "DESC"
        rows = self._conn().execute(
            f"SELECT * FROM events WHERE {' AND '.join(clauses)} "  # noqa: S608 - fixed columns
            f"ORDER BY id {order} LIMIT ?",
            (*args, limit),
        )
        out = []
        for row in rows:
            item = dict(row)
            item["data"] = json.loads(item["data"])
            item.pop("severity_rank")
            out.append(item)
        return out

    def coverage(self, now: float | None = None) -> dict[str, Any]:
        """What the log can answer for: time span, size, gaps known to the collector."""
        now = time.time() if now is None else now
        row = (
            self._conn()
            .execute("SELECT MIN(ts), MAX(ts), COUNT(*), MIN(id), MAX(id) FROM events")
            .fetchone()
        )
        last_cycle = self.get_meta("last_cycle")
        return {
            "stream_id": self.get_meta("stream_id"),
            "oldest_id": row[3],
            "newest_id": row[4],
            "oldest": row[0],
            "newest": row[1],
            "count": row[2],
            "pruned_before": self.get_meta("pruned_before"),
            "last_cycle": last_cycle,
            "lag_s": round(now - last_cycle, 1) if last_cycle else None,
            "open_gaps": self.get_meta("open_gaps", []),
        }


def as_dict(event: Event) -> dict[str, Any]:
    return {**asdict(event), "delivery": event.delivery}
