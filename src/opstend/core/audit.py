"""Append-only audit log with a hash chain.

Each entry includes the hash of the previous one. Editing or removing an
entry breaks the chain, which `verify()` detects.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(prev: str, record: dict[str, Any]) -> str:
    body = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"{prev}\n{body}".encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS audit (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL,
                actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
                job_id TEXT, outcome TEXT NOT NULL, detail TEXT NOT NULL,
                prev TEXT NOT NULL, hash TEXT NOT NULL)"""
        )
        self._listeners: list[Callable[[dict[str, Any]], None]] = []

    def subscribe(self, listener: Callable[[dict[str, Any]], None]) -> None:
        self._listeners.append(listener)

    def record(
        self,
        actor: str,
        action: str,
        target: str,
        outcome: str = "ok",
        job_id: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            row = self._db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev = row[0] if row else GENESIS
            entry: dict[str, Any] = {
                "at": datetime.now(UTC).isoformat(),
                "actor": actor,
                "action": action,
                "target": target,
                "job_id": job_id,
                "outcome": outcome,
                "detail": detail or {},
            }
            digest = _digest(prev, entry)
            cur = self._db.execute(
                "INSERT INTO audit(at,actor,action,target,job_id,outcome,detail,prev,hash) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    entry["at"],
                    actor,
                    action,
                    target,
                    job_id,
                    outcome,
                    json.dumps(entry["detail"], sort_keys=True),
                    prev,
                    digest,
                ),
            )
            entry = {"seq": cur.lastrowid, **entry, "hash": digest}
        for listener in list(self._listeners):
            listener(entry)
        return entry

    def entries(
        self, limit: int = 200, target: str | None = None, job_id: str | None = None
    ) -> list[dict[str, Any]]:
        query = "SELECT seq,at,actor,action,target,job_id,outcome,detail,hash FROM audit"
        clauses: list[str] = []
        params: list[Any] = []
        if target:
            clauses.append("target LIKE ?")
            params.append(f"{target}%")
        if job_id:
            clauses.append("job_id = ?")
            params.append(job_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY seq DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._db.execute(query, params).fetchall()
        keys = ("seq", "at", "actor", "action", "target", "job_id", "outcome", "detail", "hash")
        out = []
        for r in rows:
            item = dict(zip(keys, r, strict=True))
            item["detail"] = json.loads(item["detail"])
            out.append(item)
        return out

    def verify(self) -> bool:
        prev = GENESIS
        with self._lock:
            rows = self._db.execute(
                "SELECT at,actor,action,target,job_id,outcome,detail,prev,hash "
                "FROM audit ORDER BY seq"
            ).fetchall()
        for at, actor, action, target, job_id, outcome, detail, stored_prev, digest in rows:
            record = {
                "at": at,
                "actor": actor,
                "action": action,
                "target": target,
                "job_id": job_id,
                "outcome": outcome,
                "detail": json.loads(detail),
            }
            if stored_prev != prev or _digest(prev, record) != digest:
                return False
            prev = digest
        return True
