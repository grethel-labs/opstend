"""Versioned document store on SQLite.

The controller applies committed log entries to this store. Every node keeps
a full copy, so any voter can take over when the leader fails. Writes use
optimistic concurrency: a caller that read version N can only write N + 1.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from pydantic import BaseModel


class ConflictError(RuntimeError):
    """The document changed since the caller read it."""


class Store:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self._path = str(path)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self._path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS docs (
                kind TEXT NOT NULL, id TEXT NOT NULL, version INTEGER NOT NULL,
                data TEXT NOT NULL, PRIMARY KEY (kind, id))"""
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            self._db.execute("COMMIT")

    # -- documents -------------------------------------------------------

    def get(self, kind: str, doc_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT data FROM docs WHERE kind=? AND id=?", (kind, doc_id)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def version(self, kind: str, doc_id: str) -> int:
        with self._lock:
            row = self._db.execute(
                "SELECT version FROM docs WHERE kind=? AND id=?", (kind, doc_id)
            ).fetchone()
        return int(row[0]) if row else 0

    def list(self, kind: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT data FROM docs WHERE kind=? ORDER BY id", (kind,)
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def put(
        self,
        kind: str,
        doc_id: str,
        data: dict[str, Any] | BaseModel,
        expect_version: int | None = None,
    ) -> int:
        if isinstance(data, BaseModel):
            data = data.model_dump(mode="json")
        payload = json.dumps(data, sort_keys=True, separators=(",", ":"))
        with self.transaction() as db:
            row = db.execute(
                "SELECT version FROM docs WHERE kind=? AND id=?", (kind, doc_id)
            ).fetchone()
            current = int(row[0]) if row else 0
            if expect_version is not None and expect_version != current:
                raise ConflictError(f"{kind}/{doc_id} is at version {current}")
            db.execute(
                "INSERT INTO docs(kind,id,version,data) VALUES(?,?,?,?) "
                "ON CONFLICT(kind,id) DO UPDATE SET version=excluded.version, data=excluded.data",
                (kind, doc_id, current + 1, payload),
            )
        return current + 1

    def delete(self, kind: str, doc_id: str) -> bool:
        with self.transaction() as db:
            cur = db.execute("DELETE FROM docs WHERE kind=? AND id=?", (kind, doc_id))
        return cur.rowcount > 0

    def replace_kind(self, kind: str, docs: dict[str, dict[str, Any]]) -> None:
        """Replace all documents of one kind, e.g. a fresh inventory snapshot."""
        with self.transaction() as db:
            existing = {
                r[0]: int(r[1])
                for r in db.execute("SELECT id, version FROM docs WHERE kind=?", (kind,))
            }
            for doc_id in set(existing) - set(docs):
                db.execute("DELETE FROM docs WHERE kind=? AND id=?", (kind, doc_id))
            for doc_id, data in docs.items():
                payload = json.dumps(data, sort_keys=True, separators=(",", ":"))
                db.execute(
                    "INSERT INTO docs(kind,id,version,data) VALUES(?,?,?,?) "
                    "ON CONFLICT(kind,id) DO UPDATE SET version=excluded.version, "
                    "data=excluded.data",
                    (kind, doc_id, existing.get(doc_id, 0) + 1, payload),
                )

    # -- metadata --------------------------------------------------------

    def meta(self, key: str, default: str | None = None) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def set_meta(self, key: str, value: str) -> None:
        with self.transaction() as db:
            db.execute(
                "INSERT INTO meta(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    # -- replication -----------------------------------------------------

    def apply(self, command: dict[str, Any]) -> Any:
        """Apply one committed log command. Must be deterministic."""
        op = command.get("op")
        if op == "put":
            return self.put(command["kind"], command["id"], command["data"])
        if op == "delete":
            return self.delete(command["kind"], command["id"])
        if op == "replace":
            self.replace_kind(command["kind"], command["docs"])
            return None
        if op == "meta":
            self.set_meta(command["key"], command["value"])
            return None
        if op == "noop":
            return None
        raise ValueError(f"unknown store command {op!r}")

    def dump(self) -> dict[str, Any]:
        with self._lock:
            docs = self._db.execute("SELECT kind, id, data FROM docs").fetchall()
            meta = self._db.execute("SELECT key, value FROM meta").fetchall()
        out: dict[str, Any] = {"docs": {}, "meta": dict(meta)}
        for kind, doc_id, data in docs:
            out["docs"].setdefault(kind, {})[doc_id] = json.loads(data)
        return out

    def restore(self, snapshot: dict[str, Any]) -> None:
        with self.transaction() as db:
            db.execute("DELETE FROM docs")
            db.execute("DELETE FROM meta")
            for kind, docs in snapshot.get("docs", {}).items():
                for doc_id, data in docs.items():
                    db.execute(
                        "INSERT INTO docs(kind,id,version,data) VALUES(?,?,1,?)",
                        (kind, doc_id, json.dumps(data, sort_keys=True, separators=(",", ":"))),
                    )
            for key, value in snapshot.get("meta", {}).items():
                db.execute("INSERT INTO meta(key,value) VALUES(?,?)", (key, value))

    def close(self) -> None:
        with self._lock:
            self._db.close()
