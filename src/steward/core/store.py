"""SQLite persistence: configuration revisions and durable jobs.

Each trust domain owns its own database file; nothing here is shared between
the API and the executor.
"""

from __future__ import annotations

import json
import math
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .canonical import canonical_json, revision_id

SCHEMA = """
CREATE TABLE IF NOT EXISTS revisions (
    id TEXT PRIMARY KEY,
    parent TEXT,
    created_at REAL NOT NULL,
    author TEXT NOT NULL,
    source TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pointers (
    name TEXT PRIMARY KEY CHECK (name IN ('head', 'applied')),
    revision_id TEXT NOT NULL REFERENCES revisions(id)
);
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    payload TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL,
    not_before REAL NOT NULL,
    lease_owner TEXT,
    lease_expires REAL,
    result TEXT,
    error TEXT,
    created_by TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS jobs_state ON jobs(state, not_before);
"""

JOB_STATES = ("queued", "running", "succeeded", "failed")
BACKOFF_BASE_S = 5.0
BACKOFF_MAX_S = 300.0


class CapacityError(Exception):
    """A bounded store cannot admit another distinct job."""


class ConflictError(Exception):
    """The caller's parent revision is not the current head."""

    def __init__(self, head: str | None):
        super().__init__(f"configuration changed concurrently; current head is {head}")
        self.head = head


class Store:
    def __init__(self, path: Path | str):
        self._path = str(path)
        self._local = threading.local()
        self._conn().executescript(SCHEMA)  # executescript manages its own transaction

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._path, timeout=10, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
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

    # ---- configuration revisions -------------------------------------------------

    def _pointer(self, db: sqlite3.Connection, name: str) -> str | None:
        row = db.execute("SELECT revision_id FROM pointers WHERE name=?", (name,)).fetchone()
        return row["revision_id"] if row else None

    def head(self) -> str | None:
        return self._pointer(self._conn(), "head")

    def applied(self) -> str | None:
        return self._pointer(self._conn(), "applied")

    def get_revision(self, rev: str) -> dict[str, Any] | None:
        row = self._conn().execute("SELECT * FROM revisions WHERE id=?", (rev,)).fetchone()
        if row is None:
            return None
        out = dict(row)
        out["body"] = json.loads(out["body"])
        return out

    def list_revisions(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._conn().execute(
            "SELECT id, parent, created_at, author, source, message FROM revisions "
            "ORDER BY created_at DESC, rowid DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in rows]

    def commit_revision(
        self,
        body: dict[str, Any],
        *,
        parent: str | None,
        author: str,
        source: str,
        message: str = "",
        now: float | None = None,
    ) -> str:
        """Append a revision. `parent` must equal the current head (conflict check)."""
        rev = revision_id(body)
        with self._tx() as db:
            head = self._pointer(db, "head")
            if parent != head:
                raise ConflictError(head)
            if rev == head:
                return rev
            db.execute(
                "INSERT OR IGNORE INTO revisions (id, parent, created_at, author, source, "
                "message, body) VALUES (?,?,?,?,?,?,?)",
                (
                    rev,
                    head,
                    time.time() if now is None else now,
                    author,
                    source,
                    message[:500],
                    canonical_json(body),
                ),
            )
            db.execute("INSERT OR REPLACE INTO pointers VALUES ('head', ?)", (rev,))
        return rev

    def record_applied(self, body: dict[str, Any], *, now: float | None = None) -> str:
        """Record what the deployment actually applied to the host.

        The applied state is ground truth. If it is not a known revision it is
        appended; a diverging pending head stays in history but head moves here
        only when head was already applied before (no pending edits are dropped
        from view silently: `pending()` keeps reporting them).
        """
        rev = revision_id(body)
        with self._tx() as db:
            head = self._pointer(db, "head")
            previous = self._pointer(db, "applied")
            db.execute(
                "INSERT OR IGNORE INTO revisions (id, parent, created_at, author, source, "
                "message, body) VALUES (?,?,?,?,?,?,?)",
                (
                    rev,
                    previous,
                    time.time() if now is None else now,
                    "deploy",
                    "controller",
                    "applied by deployment",
                    canonical_json(body),
                ),
            )
            db.execute("INSERT OR REPLACE INTO pointers VALUES ('applied', ?)", (rev,))
            if head is None or head == previous:
                db.execute("INSERT OR REPLACE INTO pointers VALUES ('head', ?)", (rev,))
        return rev

    # ---- durable jobs ------------------------------------------------------------

    @staticmethod
    def _job(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        out = dict(row)
        out["payload"] = json.loads(out["payload"])
        out["result"] = json.loads(out["result"]) if out["result"] else None
        return out

    def enqueue(
        self,
        kind: str,
        target: str,
        payload: dict[str, Any],
        *,
        idempotency_key: str,
        created_by: str,
        max_attempts: int = 3,
        max_total: int | None = None,
        now: float | None = None,
    ) -> tuple[dict[str, Any], bool]:
        """Create a job. Returns (job, created); an existing key returns the old job."""
        now = time.time() if now is None else now
        if max_total is not None and (type(max_total) is not int or max_total < 1):
            raise ValueError("job capacity must be positive")
        with self._tx() as db:
            row = db.execute(
                "SELECT * FROM jobs WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            if row is not None:
                return self._job(row), False  # type: ignore[return-value]
            if (
                max_total is not None
                and db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] >= max_total
            ):
                raise CapacityError("job capacity reached")
            job_id = uuid.uuid4().hex
            db.execute(
                "INSERT INTO jobs (id, kind, target, payload, idempotency_key, state, "
                "max_attempts, not_before, created_by, created_at, updated_at) "
                "VALUES (?,?,?,?,?,'queued',?,?,?,?,?)",
                (
                    job_id,
                    kind,
                    target,
                    canonical_json(payload),
                    idempotency_key,
                    max_attempts,
                    now,
                    created_by,
                    now,
                    now,
                ),
            )
            row = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return self._job(row), True  # type: ignore[return-value]

    def claim(
        self,
        worker: str,
        *,
        lease_s: float = 60.0,
        now: float | None = None,
        job_id: str | None = None,
    ):
        """Lease the oldest runnable job, or only the given job when specified."""
        if not math.isfinite(lease_s) or lease_s <= 0:
            raise ValueError("lease must be positive")
        now = time.time() if now is None else now
        with self._tx() as db:
            row = db.execute(
                "SELECT * FROM jobs j WHERE state='queued' AND not_before<=? "
                "AND (? IS NULL OR j.id=?) AND NOT EXISTS ("
                "  SELECT 1 FROM jobs r WHERE r.state='running' AND r.target=j.target) "
                "ORDER BY created_at, rowid LIMIT 1",
                (now, job_id, job_id),
            ).fetchone()
            if row is None:
                return None
            db.execute(
                "UPDATE jobs SET state='running', attempts=attempts+1, lease_owner=?, "
                "lease_expires=?, updated_at=? WHERE id=?",
                (worker, now + lease_s, now, row["id"]),
            )
            row = db.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone()
        return self._job(row)

    def heartbeat(
        self, job_id: str, worker: str, *, lease_s: float = 60.0, now: float | None = None
    ) -> bool:
        if not math.isfinite(lease_s) or lease_s <= 0:
            raise ValueError("lease must be positive")
        now = time.time() if now is None else now
        with self._tx() as db:
            cur = db.execute(
                "UPDATE jobs SET lease_expires=?, updated_at=? WHERE id=? AND state='running' "
                "AND lease_owner=? AND lease_expires>?",
                (now + lease_s, now, job_id, worker, now),
            )
            return cur.rowcount == 1

    def finish(
        self,
        job_id: str,
        worker: str,
        *,
        ok: bool,
        result: dict[str, Any] | None = None,
        error: str | None = None,
        retryable: bool = False,
        now: float | None = None,
    ) -> str | None:
        """Complete a leased job. Returns the new state, None if the lease was lost."""
        now = time.time() if now is None else now
        with self._tx() as db:
            row = db.execute(
                "SELECT * FROM jobs WHERE id=? AND state='running' "
                "AND lease_owner=? AND lease_expires>?",
                (job_id, worker, now),
            ).fetchone()
            if row is None:
                return None
            if ok:
                state, not_before = "succeeded", row["not_before"]
            elif retryable and row["attempts"] < row["max_attempts"]:
                state = "queued"
                delay = min(BACKOFF_BASE_S * 2 ** (row["attempts"] - 1), BACKOFF_MAX_S)
                not_before = now + delay
            else:
                state, not_before = "failed", row["not_before"]
            db.execute(
                "UPDATE jobs SET state=?, not_before=?, lease_owner=NULL, lease_expires=NULL, "
                "result=?, error=?, updated_at=? WHERE id=?",
                (
                    state,
                    not_before,
                    canonical_json(result) if result is not None else None,
                    (error or "")[:2000] or None,
                    now,
                    job_id,
                ),
            )
        return state

    def reconcile(self, *, now: float | None = None) -> list[str]:
        """Restart recovery: handle running jobs whose lease expired.

        The outcome of an interrupted attempt is unknown, so it counts as an
        attempt. Jobs with attempts left are queued again (handlers must be
        idempotent), the rest fail with an explicit cause.
        """
        now = time.time() if now is None else now
        touched = []
        with self._tx() as db:
            rows = db.execute(
                "SELECT id, attempts, max_attempts FROM jobs WHERE state='running' "
                "AND lease_expires<=?",
                (now,),
            ).fetchall()
            for row in rows:
                if row["attempts"] < row["max_attempts"]:
                    db.execute(
                        "UPDATE jobs SET state='queued', lease_owner=NULL, lease_expires=NULL, "
                        "error='interrupted: lease expired, retrying', updated_at=? WHERE id=?",
                        (now, row["id"]),
                    )
                else:
                    db.execute(
                        "UPDATE jobs SET state='failed', lease_owner=NULL, lease_expires=NULL, "
                        "error='interrupted: lease expired, retry limit reached', updated_at=? "
                        "WHERE id=?",
                        (now, row["id"]),
                    )
                touched.append(row["id"])
        return touched

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        return self._job(
            self._conn().execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        )

    def list_jobs(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._conn().execute(
            "SELECT * FROM jobs ORDER BY created_at DESC, rowid DESC LIMIT ?", (limit,)
        )
        return [self._job(r) for r in rows]  # type: ignore[misc]

    def prune_jobs(self, kind: str, *, now: float, keep: int = 10000) -> None:
        """Expire completed jobs/idempotency keys for an explicitly selected job kind."""
        if keep < 1:
            raise ValueError("keep must be positive")
        with self._tx() as db:
            db.execute(
                "DELETE FROM jobs WHERE kind=? AND state IN ('succeeded','failed') "
                "AND (updated_at<? OR id IN (SELECT id FROM jobs WHERE kind=? "
                "AND state IN ('succeeded','failed') ORDER BY updated_at DESC,rowid DESC "
                "LIMIT -1 OFFSET ?))",
                (kind, now - 30 * 86400, kind, keep),
            )
