"""Durable notification queue, independent of transport and security actions.

Callers enqueue already authorized, redacted payloads. Workers claim a lease,
perform I/O outside the transaction, and acknowledge only confirmed delivery.
Delivery is at least once: transports should use the stable message id as an
idempotency key. Digest assembly and event cursors belong to the producer.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

PAYLOAD_MAX = 16384


@dataclass(frozen=True)
class Delivery:
    id: int
    adapter: str
    destination: str  # opaque configured destination id, never a credential or URL
    key: str
    payload: dict
    attempt: int
    lease: str


class Outbox:
    def __init__(self, path: Path | str):
        self.path = str(path)
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS outbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    adapter TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    dedup_key TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    available_at REAL NOT NULL,
                    lease TEXT,
                    lease_until REAL,
                    finished_at REAL,
                    UNIQUE(adapter, destination, dedup_key)
                );
                CREATE TABLE IF NOT EXISTS queue_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS cooldowns (
                    adapter TEXT NOT NULL, destination TEXT NOT NULL, until REAL NOT NULL,
                    PRIMARY KEY(adapter, destination)
                );
                CREATE TABLE IF NOT EXISTS feeds (
                    adapter TEXT NOT NULL, destination TEXT NOT NULL, source_id TEXT NOT NULL,
                    PRIMARY KEY(adapter, destination)
                );
                CREATE TABLE IF NOT EXISTS cursors (
                    adapter TEXT NOT NULL, destination TEXT NOT NULL, cursor INTEGER NOT NULL,
                    PRIMARY KEY(adapter, destination)
                );
                CREATE TABLE IF NOT EXISTS digests (
                    adapter TEXT NOT NULL, destination TEXT NOT NULL, day INTEGER NOT NULL,
                    count INTEGER NOT NULL, high_count INTEGER NOT NULL,
                    PRIMARY KEY(adapter, destination, day)
                );
                CREATE INDEX IF NOT EXISTS outbox_due ON outbox(state, available_at);
            """)

            db.execute(
                "INSERT OR IGNORE INTO queue_meta VALUES ('identity', ?)", (secrets.token_hex(16),)
            )
            self.identity = db.execute(
                "SELECT value FROM queue_meta WHERE key='identity'"
            ).fetchone()[0]

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def enqueue(
        self, adapter: str, destination: str, key: str, payload: dict, *, now: float
    ) -> bool:
        """First payload wins for a destination/key, including after delivery."""
        if any(not value or len(value) > 200 for value in (adapter, destination, key)):
            raise ValueError("adapter, destination and key must contain 1..200 characters")
        encoded = json.dumps(payload, sort_keys=True, allow_nan=False)
        if len(encoded.encode()) > PAYLOAD_MAX:
            raise ValueError("notification payload too large")
        with self._connect() as db:
            return (
                db.execute(
                    "INSERT OR IGNORE INTO outbox "
                    "(adapter, destination, dedup_key, payload, available_at) VALUES (?,?,?,?,?)",
                    (adapter, destination, key, encoded, now),
                ).rowcount
                == 1
            )

    def claim(self, *, now: float, lease_s: float = 60) -> Delivery | None:
        """Atomically reserve one due message, recovering expired worker leases."""
        if lease_s <= 0:
            raise ValueError("lease must be positive")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "UPDATE outbox SET state='failed', finished_at=?, lease=NULL, lease_until=NULL "
                "WHERE state='pending' AND attempts>=8 AND (lease_until IS NULL OR lease_until<=?)",
                (now, now),
            )
            row = db.execute(
                "SELECT * FROM outbox WHERE state='pending' AND available_at <= ? "
                "AND (lease_until IS NULL OR lease_until <= ?) "
                "AND NOT EXISTS (SELECT 1 FROM cooldowns c WHERE c.adapter=outbox.adapter "
                "AND c.destination=outbox.destination AND c.until>?) "
                "ORDER BY CASE WHEN dedup_key LIKE 'heartbeat:%' THEN 0 "
                "WHEN dedup_key LIKE 'gap:%' THEN 1 WHEN dedup_key LIKE 'event:%' THEN 2 "
                "ELSE 3 END, id LIMIT 1",
                (now, now, now),
            ).fetchone()
            if row is None:
                return None
            lease = secrets.token_hex(16)
            db.execute(
                "UPDATE outbox SET attempts=attempts+1, lease=?, lease_until=? WHERE id=?",
                (lease, now + lease_s, row["id"]),
            )
            return Delivery(
                row["id"],
                row["adapter"],
                row["destination"],
                row["dedup_key"],
                json.loads(row["payload"]),
                row["attempts"] + 1,
                lease,
            )

    def acknowledge(self, delivery: Delivery, *, now: float) -> bool:
        """Stale workers cannot acknowledge a reclaimed or expired message."""
        with self._connect() as db:
            return (
                db.execute(
                    "UPDATE outbox SET state='delivered', finished_at=?, lease=NULL, "
                    "lease_until=NULL WHERE id=? AND state='pending' AND lease=? AND lease_until>?",
                    (now, delivery.id, delivery.lease, now),
                ).rowcount
                == 1
            )

    def retry(
        self,
        delivery: Delivery,
        *,
        now: float,
        retry_after_s: float = 0,
        permanent: bool = False,
        max_attempts: int = 8,
    ) -> bool:
        """Bound exponential backoff; honor a transport's longer rate-limit delay.

        Raw transport errors are deliberately not persisted: they can contain
        webhook credentials. Exhausted messages remain inspectable as failed.
        """
        if retry_after_s < 0 or max_attempts < 1:
            raise ValueError("invalid retry policy")
        failed = permanent or delivery.attempt >= max_attempts
        delay = max(retry_after_s, min(3600, 5 * 2 ** min(delivery.attempt - 1, 10)))
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if (
                retry_after_s
                and db.execute(
                    "SELECT 1 FROM outbox WHERE id=? AND state='pending' "
                    "AND lease=? AND lease_until>?",
                    (delivery.id, delivery.lease, now),
                ).fetchone()
            ):
                db.execute(
                    "INSERT INTO cooldowns VALUES (?,?,?) ON CONFLICT(adapter,destination) "
                    "DO UPDATE SET until=MAX(until, excluded.until)",
                    (delivery.adapter, delivery.destination, now + retry_after_s),
                )
            return (
                db.execute(
                    "UPDATE outbox SET state=?, available_at=?, finished_at=?, "
                    "lease=NULL, lease_until=NULL WHERE id=? AND state='pending' "
                    "AND lease=? AND lease_until>?",
                    (
                        "failed" if failed else "pending",
                        now + delay,
                        now if failed else None,
                        delivery.id,
                        delivery.lease,
                        now,
                    ),
                ).rowcount
                == 1
            )

    def counts(self) -> dict[str, int]:
        with self._connect() as db:
            return {
                row[0]: row[1]
                for row in db.execute("SELECT state, COUNT(*) FROM outbox GROUP BY state")
            }

    def prune(self, *, finished_before: float) -> int:
        """Remove completed history; deduplication lasts until this explicit prune."""
        with self._connect() as db:
            return db.execute(
                "DELETE FROM outbox WHERE state IN ('delivered','failed') AND finished_at < ?",
                (finished_before,),
            ).rowcount

    def cursor(self, adapter: str, destination: str) -> int:
        with self._connect() as db:
            row = db.execute(
                "SELECT cursor FROM cursors WHERE adapter=? AND destination=?",
                (adapter, destination),
            ).fetchone()
            return row[0] if row else 0

    def ingest(
        self,
        adapter: str,
        destination: str,
        events: list[dict],
        *,
        now: float,
        coverage: dict | None = None,
        audit_export: bool = False,
    ) -> int:
        """Commit immediate messages, digest counts and the feed cursor together.

        Input must be the collector's ascending, unfiltered event stream. Digest
        days refer to ingestion time (UTC), so late observations are not lost.
        Replayed pages are ignored. Only summaries cross the transport boundary.
        """
        from .secrets import redact

        day = int(now // 86400)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT cursor FROM cursors WHERE adapter=? AND destination=?",
                (adapter, destination),
            ).fetchone()
            cursor = row[0] if row else 0
            source_id = (coverage or {}).get("stream_id", "")
            previous_feed = db.execute(
                "SELECT source_id FROM feeds WHERE adapter=? AND destination=?",
                (adapter, destination),
            ).fetchone()
            reset = previous_feed is not None and previous_feed[0] != source_id
            oldest = (coverage or {}).get("oldest_id")
            if reset or (oldest is not None and oldest > cursor + 1):
                reason = "collector stream changed" if reset else "collector retention exceeded"
                summary = f"Observation gap: {reason}; some events may not have been delivered."
                db.execute(
                    "INSERT OR IGNORE INTO outbox "
                    "(adapter,destination,dedup_key,payload,available_at) VALUES (?,?,?,?,?)",
                    (
                        adapter,
                        destination,
                        f"gap:{source_id}:{cursor}:{oldest}",
                        json.dumps({"summary": summary}),
                        now,
                    ),
                )
            db.execute(
                "INSERT OR REPLACE INTO feeds VALUES (?,?,?)", (adapter, destination, source_id)
            )
            if reset:
                # The caller's page was fetched using the old cursor. Discard it
                # and fetch again from zero on the next cycle.
                cursor, events = 0, []
            pending = db.execute("SELECT COUNT(*) FROM outbox WHERE state='pending'").fetchone()[0]
            if pending + len(events) > 100000:
                raise ValueError("outbox backlog limit reached")
            previous = 0
            for event in events:
                if event["id"] <= previous:
                    raise ValueError("event feed must be strictly ascending")
                previous = event["id"]
                if event["id"] <= cursor:
                    continue
                if audit_export and event.get("kind") == "audit.record":
                    payload = json.dumps({"summary": event["summary"], "audit": event["data"]})
                    db.execute(
                        "INSERT OR IGNORE INTO outbox "
                        "(adapter,destination,dedup_key,payload,available_at) VALUES (?,?,?,?,?)",
                        (adapter, destination, f"audit:{source_id}:{event['id']}", payload, now),
                    )
                elif event["delivery"] == "immediate":
                    payload = json.dumps(
                        {
                            "summary": redact(event["summary"])[:500],
                            "event_id": event["id"],
                            "correlation_id": event.get("correlation_id"),
                        }
                    )
                    db.execute(
                        "INSERT OR IGNORE INTO outbox "
                        "(adapter,destination,dedup_key,payload,available_at) VALUES (?,?,?,?,?)",
                        (
                            adapter,
                            destination,
                            f"event:{source_id + ':' if source_id else ''}{event['id']}",
                            payload,
                            now,
                        ),
                    )
                elif event["delivery"] == "digest":
                    high = int(event["severity"] in ("high", "critical"))
                    db.execute(
                        "INSERT INTO digests VALUES (?,?,?,?,?) "
                        "ON CONFLICT(adapter,destination,day) DO UPDATE SET "
                        "count=count+1, high_count=high_count+excluded.high_count",
                        (adapter, destination, day, 1, high),
                    )
                cursor = event["id"]
            db.execute(
                "INSERT OR REPLACE INTO cursors VALUES (?,?,?)", (adapter, destination, cursor)
            )
            return cursor

    def flush_digests(self, *, now: float) -> int:
        """One bounded count summary per destination/day, with atomic cleanup."""
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT * FROM digests WHERE day < ?", (int(now // 86400),)
            ).fetchall()
            for row in rows:
                payload = json.dumps(
                    {
                        "summary": f"Daily digest (UTC day {row['day']}): {row['count']} events, "
                        f"{row['high_count']} high/critical. Details in the Events page.",
                        "day": row["day"],
                        "count": row["count"],
                        "high_count": row["high_count"],
                    }
                )
                db.execute(
                    "INSERT OR IGNORE INTO outbox "
                    "(adapter,destination,dedup_key,payload,available_at) VALUES (?,?,?,?,?)",
                    (row["adapter"], row["destination"], f"digest:{row['day']}", payload, now),
                )
            db.execute("DELETE FROM digests WHERE day < ?", (int(now // 86400),))
            return len(rows)

    def heartbeat(self, adapter: str, destination: str, bucket: int, payload: dict, *, now: float):
        """Keep only the newest unleased heartbeat; old liveness is not useful."""
        key = f"heartbeat:{bucket}"
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "UPDATE outbox SET state='failed', finished_at=?, lease=NULL, lease_until=NULL "
                "WHERE adapter=? AND destination=? AND dedup_key LIKE 'heartbeat:%' "
                "AND dedup_key!=? AND state='pending' AND (lease_until IS NULL OR lease_until<=?)",
                (now, adapter, destination, key, now),
            )
            db.execute(
                "INSERT OR IGNORE INTO outbox "
                "(adapter,destination,dedup_key,payload,available_at) VALUES (?,?,?,?,?)",
                (adapter, destination, key, json.dumps(payload, allow_nan=False), now),
            )
