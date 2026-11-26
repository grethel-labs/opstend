"""Private scanner observations with an atomic, bounded read-only change feed."""

from __future__ import annotations

import json
import math
import os
import sqlite3
import stat
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .canonical import revision_id
from .intelligence import at_time, context_key
from .intelligence import fingerprint as semantic_finding
from .inventory import Digest
from .vulnerabilities import Component, Data, ScanResult, State

STATES = ("unknown", "stale", "scan_failed", "not_affected", "confirmed")
RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
PAGE_BYTES = 128 * 1024


def priority_rank(findings, now):
    def rank(finding):
        kev, epss = context_key(finding, now)
        return kev * 1000000 + RANK[finding["severity"]] * 100000 + int(epss * 99999)

    return max((rank(f) for f in findings), default=0)


class Observation(ScanResult):
    last_success: ScanResult | None = None

    @model_validator(mode="after")
    def _history(self):
        historical = self.last_success
        if historical and (
            not historical.complete
            or historical.source != self.source
            or historical.subject.key != self.subject.key
            or historical.checked_at > self.checked_at
        ):
            raise ValueError("historical evidence must be a prior success for this subject")
        return self


class KernelObservation(Data):
    release: str = Field(max_length=200)
    state: State
    complete: bool
    reboot_required: bool | None
    basis: str = Field(max_length=500)
    matched_sources: list[
        tuple[Annotated[str, Field(max_length=300)], Annotated[str, Field(max_length=200)]]
    ] = Field(max_length=16)


class Snapshot(Data):
    v: int = Field(1, ge=1, le=1)
    generated_at: float = Field(ge=0)
    enabled: bool
    config_revision: Digest
    inventory_revision: Digest
    running_kernel: str = Field(max_length=200)
    complete: bool
    runtime_images_verified: bool
    source_queries_complete: bool
    kernel: KernelObservation
    counts: dict[State, Annotated[int, Field(ge=0)]]
    results: list[Observation] = Field(max_length=5000)
    context_enabled: dict[Literal["kev", "epss"], bool] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _coverage(self):
        counts = {}
        for result in self.results:
            counts[result.state] = counts.get(result.state, 0) + 1
        queries_complete = bool(self.results) and all(
            r.complete and r.state in ("confirmed", "not_affected") for r in self.results
        )
        if self.counts != counts or self.source_queries_complete != queries_complete:
            raise ValueError("snapshot coverage does not match its evidence")
        if self.complete and not (
            self.enabled
            and queries_complete
            and self.kernel.complete
            and self.runtime_images_verified
        ):
            raise ValueError("incomplete snapshot cannot claim complete coverage")
        return self


class Observations:
    def __init__(self, path: Path):
        self.path = path
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise ValueError("observations must be a regular file owned by the scanner")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        with self.db() as db, db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS observations (
                    source TEXT, subject TEXT, scope TEXT, body TEXT NOT NULL,
                    rank INTEGER NOT NULL, PRIMARY KEY(source,subject)
                );
                CREATE TABLE IF NOT EXISTS groups (
                    scope TEXT,source TEXT,fingerprint TEXT,PRIMARY KEY(scope,source)
                );
                CREATE TABLE IF NOT EXISTS changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,ts REAL,scope TEXT,
                    kind TEXT,severity TEXT,summary TEXT,data TEXT
                );
            """)
            db.execute("INSERT OR IGNORE INTO meta VALUES ('stream',?)", (uuid.uuid4().hex,))

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            yield db
        finally:
            db.close()

    @staticmethod
    def _header(db) -> dict:
        row = db.execute("SELECT value FROM meta WHERE key='header'").fetchone()
        return json.loads(row[0]) if row else {}

    @staticmethod
    def _event(db, now, scope, kind, severity, summary, data):
        db.execute(
            "INSERT INTO changes(ts,scope,kind,severity,summary,data) VALUES (?,?,?,?,?,?)",
            (now, scope, kind, severity, summary[:500], json.dumps(data)),
        )

    @staticmethod
    def _prune(db, now):
        db.execute("DELETE FROM changes WHERE ts<?", (now - 30 * 86400,))
        db.execute(
            "DELETE FROM changes WHERE id IN (SELECT id FROM changes ORDER BY id DESC "
            "LIMIT -1 OFFSET 100000)"
        )

    def publish(self, report: dict) -> bool:
        """Publish one coherent snapshot and transitions in the same transaction.

        Per-provider/project aggregation bounds notifications during a whole
        provider outage. Full subject evidence remains available through queries.
        """
        report = Snapshot.model_validate(report).model_dump(mode="json")
        if len(json.dumps(report, ensure_ascii=False).encode()) > 32 * 1024 * 1024:
            raise ValueError("snapshot exceeds storage budget")
        keys = [
            (r["source"], Component.model_validate(r["subject"]).key) for r in report["results"]
        ]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate scan observations")
        if any(r["inventory_revision"] != report["inventory_revision"] for r in report["results"]):
            raise ValueError("mixed inventory revisions")
        now = report["generated_at"]
        with self.db() as db, db:
            db.execute("BEGIN IMMEDIATE")
            previous = self._header(db)
            if previous.get("generated_at", -1) >= now:
                return False
            if report["enabled"]:
                db.execute("DELETE FROM meta WHERE key='disabled_config'")
            groups = {}
            for record in report.get("results", []):
                subject = Component.model_validate(record["subject"])
                findings = record["findings"] or (record.get("last_success") or {}).get(
                    "findings", []
                )
                rank = max((RANK[f["severity"]] for f in findings), default=0)
                group = groups.setdefault(
                    (subject.scope, record["source"]),
                    {
                        "counts": {},
                        "rank": 0,
                        "ids": set(),
                        "kev": set(),
                        "context_counts": {"kev": {}, "epss": {}},
                        "fingerprints": [],
                    },
                )
                state = record["state"]
                group["counts"][state] = group["counts"].get(state, 0) + 1
                group["rank"] = max(rank, group["rank"])
                group["ids"].update(f["id"] for f in findings)
                for finding in findings:
                    for context in at_time(finding, now)["exploit_context"]:
                        for source_name in ("kev", "epss"):
                            counts = group["context_counts"][source_name]
                            status = context[source_name]["state"]
                            counts[status] = counts.get(status, 0) + 1
                    group["kev"].update(
                        c["cve"]
                        for c in at_time(finding, now)["exploit_context"]
                        if c["kev"]["state"] == "available" and c["kev"]["listed"] is True
                    )
                group["fingerprints"].append(
                    revision_id(
                        {
                            "subject": subject.key,
                            "state": state,
                            "findings": [semantic_finding(f, now) for f in findings],
                            "error_class": record.get("error_class"),
                        }
                    )
                )
            db.execute("DELETE FROM observations")
            for record in report.get("results", []):
                subject = Component.model_validate(record["subject"])
                findings = record["findings"] or (record.get("last_success") or {}).get(
                    "findings", []
                )
                rank = priority_rank(findings, now)
                db.execute(
                    "INSERT INTO observations VALUES (?,?,?,?,?)",
                    (record["source"], subject.key, subject.scope, json.dumps(record), rank),
                )
            previous_groups = {
                (r["scope"], r["source"]): r["fingerprint"]
                for r in db.execute("SELECT * FROM groups")
            }
            db.execute("DELETE FROM groups")
            for (scope, source), group in groups.items():
                fingerprint = revision_id(sorted(group["fingerprints"]))
                old = previous_groups.get((scope, source))
                counts = group["counts"]
                state = next(
                    s
                    for s in ("scan_failed", "stale", "unknown", "confirmed", "not_affected")
                    if counts.get(s)
                )
                severity = (
                    "high"
                    if state in ("scan_failed", "stale")
                    else "warning"
                    if state == "unknown"
                    else next(name for name, value in RANK.items() if value == group["rank"])
                    if state == "confirmed"
                    else "info"
                )
                if severity in ("unknown", "low", "medium"):
                    severity = "warning" if severity == "medium" else "info"
                if group["rank"] >= 3:
                    severity = "critical" if group["rank"] == 4 else "high"
                if group["kev"] and severity != "critical":
                    severity = "high"
                data = {
                    "source": source,
                    "counts": counts,
                    "ids": sorted(group["ids"])[:10],
                    "inventory_revision": report["inventory_revision"],
                    "kev_listed": sorted(group["kev"])[:10],
                    "context_states": group["context_counts"],
                }
                if old != fingerprint:
                    self._event(
                        db,
                        now,
                        scope,
                        f"vulnerability.{state}",
                        severity,
                        f"{source}: {scope}: {state}; {counts}; KEV listed: {len(group['kev'])}. "
                        "Provider matches do not prove exploitability or a running fix.",
                        data,
                    )
                self._event(
                    db,
                    now,
                    scope,
                    "vulnerability.scan_completed",
                    "info",
                    f"{source}: {scope}: scan attempt finished; {counts}.",
                    data,
                )
                db.execute(
                    "INSERT OR REPLACE INTO groups VALUES (?,?,?)", (scope, source, fingerprint)
                )
            if not report.get("enabled") and previous.get("enabled") is not False:
                self._event(
                    db,
                    now,
                    "host",
                    "vulnerability.disabled",
                    "warning",
                    "Vulnerability scanning is disabled; coverage is unknown.",
                    {},
                )
            header = {k: v for k, v in report.items() if k != "results"}
            header["subjects"] = len(report.get("results", []))
            header["snapshot_id"] = revision_id(report)
            db.execute("INSERT OR REPLACE INTO meta VALUES ('header',?)", (json.dumps(header),))
            self._prune(db, now)
        return True

    def snapshot_id(self) -> str | None:
        """Read the current snapshot binding for a later conditional invalidation."""
        with self.db() as db:
            return self._header(db).get("snapshot_id")

    def snapshot_binding(self) -> tuple[str, str, str, list[Component]] | None:
        """Read a snapshot and its image identities from one SQLite snapshot."""
        with self.db() as db:
            db.execute("BEGIN")
            header = self._header(db)
            if not header:
                return None
            images = {}
            for row in db.execute(
                "SELECT body FROM observations WHERE json_extract(body, '$.subject.kind')='image'"
            ):
                subject = Component.model_validate(json.loads(row[0])["subject"])
                previous = images.setdefault(subject.key, subject)
                if previous != subject:
                    raise ValueError("conflicting image identities in snapshot")
            return (
                header["snapshot_id"],
                header["config_revision"],
                header["inventory_revision"],
                sorted(images.values(), key=lambda image: image.key),
            )

    def invalidate_inventory(self, snapshot_id: str | None, *, now: float) -> bool:
        """Mark the observed snapshot stale after a verified inventory change."""
        return self._invalidate(snapshot_id, now=now, reason="inventory_changed")

    def invalidate_unavailable(self, snapshot_id: str | None, *, now: float) -> bool:
        """Mark the observed snapshot unknown when current inventory cannot be checked."""
        return self._invalidate(snapshot_id, now=now, reason="inventory_unavailable")

    def _invalidate(
        self,
        snapshot_id: str | None,
        *,
        now: float,
        reason: Literal["inventory_changed", "inventory_unavailable"],
    ) -> bool:
        # Compare the snapshot binding to avoid downgrading a replacement from
        # another scan. A confirmed change takes precedence over uncertainty.
        if snapshot_id is None:
            return False
        if not math.isfinite(now) or now < 0:
            raise ValueError("invalid invalidation time")
        with self.db() as db, db:
            db.execute("BEGIN IMMEDIATE")
            header = self._header(db)
            if header.get("snapshot_id") != snapshot_id or "invalidated_at" in header:
                return False
            if reason == "inventory_unavailable" and "unverified_at" in header:
                return False
            if reason == "inventory_changed":
                header.pop("unverified_at", None)
                header["invalidated_at"] = now
                kind, severity = "vulnerability.stale", "high"
                message = "Inventory or runtime image changed; previous scan coverage is stale."
            else:
                header["unverified_at"] = now
                kind, severity = "vulnerability.unknown", "warning"
                message = "Current inventory is unavailable; previous scan coverage is unknown."
            header["snapshot_id"] = revision_id(
                {"previous_snapshot": snapshot_id, "reason": reason, "at": now}
            )
            db.execute("UPDATE meta SET value=? WHERE key='header'", (json.dumps(header),))
            self._event(db, now, "host", kind, severity, message, {"reason": reason})
            self._prune(db, now)
            return True

    @staticmethod
    def _state(record, header, now, max_age_s, enabled, config_revision):
        if (
            not enabled
            or not header.get("enabled")
            or header.get("config_revision") != config_revision
        ):
            return "unknown"
        if "unverified_at" in header:
            return "unknown"
        if "invalidated_at" in header:
            return "stale"
        result = ScanResult.model_validate({k: v for k, v in record.items() if k != "last_success"})
        if (
            result.subject.kind == "image"
            and result.subject.runtime_verified
            and result.subject.expected_image_id is None
        ):
            return "unknown"
        return result.state_at(
            now, inventory_revision=header["inventory_revision"], max_age_s=max_age_s
        )

    def disable(self, *, now: float, config_revision: str):
        """Record disabled coverage without deleting prior scan evidence."""
        with self.db() as db, db:
            db.execute("BEGIN IMMEDIATE")
            self._prune(db, now)
            old = db.execute("SELECT value FROM meta WHERE key='disabled_config'").fetchone()
            if old and old[0] == config_revision:
                return
            self._event(
                db,
                now,
                "host",
                "vulnerability.disabled",
                "warning",
                "Vulnerability scanning is disabled; coverage is unknown.",
                {},
            )
            header = self._header(db)
            if header:
                header.update(enabled=False, complete=False)
                db.execute("UPDATE meta SET value=? WHERE key='header'", (json.dumps(header),))
            db.execute("DELETE FROM groups")
            db.execute(
                "INSERT OR REPLACE INTO meta VALUES ('disabled_config',?)", (config_revision,)
            )

    def summary(self, *, now, enabled, config_revision, max_age_s):
        with self.db() as db:
            db.execute("BEGIN")
            header = self._header(db)
            counts = {}
            context_counts = {"kev": {}, "epss": {}}
            runtime_bound = True
            package_states = {}
            for row in db.execute("SELECT body FROM observations"):
                record = json.loads(row[0])
                if record["subject"]["kind"] == "image":
                    runtime_bound = runtime_bound and bool(
                        record["subject"]["runtime_verified"]
                        and record["subject"].get("expected_image_id")
                    )
                state = self._state(record, header, now, max_age_s, enabled, config_revision)
                if record["subject"]["kind"] == "os_package":
                    package_states[(record["subject"]["name"], record["subject"]["version"])] = (
                        state
                    )
                counts[state] = counts.get(state, 0) + 1
                for finding in record["findings"]:
                    for context in at_time(finding, now)["exploit_context"]:
                        for source in ("kev", "epss"):
                            status = context[source]["state"]
                            context_counts[source][status] = (
                                context_counts[source].get(status, 0) + 1
                            )
            unknown = (
                not header
                or not enabled
                or not header.get("enabled")
                or header.get("config_revision") != config_revision
            )
            stale = bool(header) and (
                "invalidated_at" in header or not 0 <= now - header["generated_at"] <= max_age_s
            )
            kernel = header.get("kernel")
            if kernel:
                states = [
                    package_states.get(tuple(s), "unknown") for s in kernel["matched_sources"]
                ]
                if unknown or "unverified_at" in header:
                    kernel.update(state="unknown", complete=False)
                elif stale or "stale" in states:
                    kernel.update(state="stale", complete=False)
                elif kernel["complete"] and (
                    not states or any(s not in ("confirmed", "not_affected") for s in states)
                ):
                    kernel.update(state="unknown", complete=False)
            return {
                **header,
                "enabled": enabled,
                "counts": counts,
                "context_counts": context_counts,
                "stale": stale,
                "configuration_matches": not unknown,
                "runtime_images_verified": bool(header.get("runtime_images_verified"))
                and runtime_bound
                and not unknown
                and "unverified_at" not in header
                and not stale,
                "source_queries_complete": bool(header.get("source_queries_complete"))
                and not unknown
                and not stale
                and not any(counts.get(s) for s in ("unknown", "stale", "scan_failed")),
                "complete": bool(header.get("complete"))
                and bool(counts)
                and bool((kernel or {}).get("complete"))
                and not unknown
                and not stale
                and not any(counts.get(s) for s in ("unknown", "stale", "scan_failed")),
            }

    def query(
        self,
        *,
        now,
        enabled,
        config_revision,
        max_age_s,
        project=None,
        source=None,
        offset=0,
        limit=50,
        subject=None,
        finding_offset=0,
    ):
        if not 1 <= limit <= 200 or offset < 0 or finding_offset < 0:
            raise ValueError("invalid observation page")
        with self.db() as db:
            db.execute("BEGIN")
            header = self._header(db)
            clauses, args = ["1=1"], []
            for column, value in (("scope", project), ("source", source), ("subject", subject)):
                if value is not None:
                    clauses.append(f"{column}=?")
                    args.append(value)
            where = " AND ".join(clauses)
            total = db.execute(f"SELECT COUNT(*) FROM observations WHERE {where}", args).fetchone()[  # noqa: S608
                0
            ]  # noqa: S608
            rows = db.execute(
                f"SELECT body,subject FROM observations WHERE {where} "  # noqa: S608
                "ORDER BY rank DESC,subject,source LIMIT ? OFFSET ?",
                (*args, limit, offset),
            )
            out, size = [], 0
            for row in rows:
                record = json.loads(row[0])
                record["state"] = self._state(
                    record, header, now, max_age_s, enabled, config_revision
                )
                record["complete"] = record["complete"] and record["state"] in (
                    "confirmed",
                    "not_affected",
                )
                record["subject_key"] = row[1]
                if record["subject"]["kind"] == "image" and not record["subject"].get(
                    "expected_image_id"
                ):
                    record["subject"]["runtime_verified"] = False
                record["findings_total"] = len(record["findings"])
                record["findings"] = record["findings"][finding_offset : finding_offset + 1]
                record["findings"] = [at_time(f, now) for f in record["findings"]]
                if record.get("last_success"):
                    historical = record["last_success"]
                    historical["findings_total"] = len(historical["findings"])
                    historical["findings"] = historical["findings"][
                        finding_offset : finding_offset + 1
                    ]
                    historical["findings"] = [at_time(f, now) for f in historical["findings"]]
                length = len(json.dumps(record, ensure_ascii=False).encode())
                if length > PAGE_BYTES and record.get("last_success"):
                    record["last_success"]["findings"] = []
                    record["last_success"]["details_omitted"] = True
                    length = len(json.dumps(record, ensure_ascii=False).encode())
                if size + length > PAGE_BYTES:
                    break
                out.append(record)
                size += length
            return {
                "snapshot_id": header.get("snapshot_id"),
                "records": out,
                "total": total,
                "next_offset": offset + len(out) if offset + len(out) < total else None,
            }

    def changes(self, after_id=0, limit=200):
        if after_id < 0 or not 1 <= limit <= 200:
            raise ValueError("invalid change page")
        with self.db() as db:
            db.execute("BEGIN")
            header = self._header(db)
            bounds = db.execute("SELECT MIN(id),MAX(id) FROM changes").fetchone()
            stream = db.execute("SELECT value FROM meta WHERE key='stream'").fetchone()[0]
            rows = db.execute(
                "SELECT * FROM changes WHERE id>? ORDER BY id LIMIT ?", (after_id, limit)
            )
            out, size = [], 0
            for row in rows:
                item = dict(row)
                item["data"] = json.loads(item["data"])
                length = len(json.dumps(item).encode())
                if size + length > PAGE_BYTES:
                    break
                out.append(item)
                size += length
            return {
                "changes": out,
                "next_id": out[-1]["id"] if out else after_id,
                "coverage": {
                    "stream_id": stream,
                    "oldest_id": bounds[0],
                    "newest_id": bounds[1],
                    "last_run": header.get("generated_at"),
                    "enabled": header.get("enabled"),
                },
            }
