"""Bounded, opt-in CISA KEV and FIRST EPSS context for exact CVE aliases."""

from __future__ import annotations

import json
import math
import os
import re
import sqlite3
import stat
import time
from contextlib import contextmanager
from datetime import UTC, date, datetime
from pathlib import Path
from urllib.parse import urlencode

from ..core.intelligence import CVEContext, Evidence, context_key
from ..core.vulnerabilities import ScanError
from .scanners import api

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}")
CACHE_TTL = 21600
MAX_CVES = 5000


class Cache:
    def __init__(self, path: Path):
        self.path = path
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NONBLOCK | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise ValueError("intelligence cache must be a private owned regular file")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        with self.db() as db, db:
            db.executescript(
                "CREATE TABLE IF NOT EXISTS entries (source TEXT,key TEXT,body TEXT,"
                "checked_at REAL,PRIMARY KEY(source,key));"
                "CREATE TABLE IF NOT EXISTS cooldowns (source TEXT PRIMARY KEY,until REAL);"
            )

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            yield db
        finally:
            db.close()

    def get(self, source, key):
        with self.db() as db:
            row = db.execute(
                "SELECT body FROM entries WHERE source=? AND key=?", (source, key)
            ).fetchone()
            return json.loads(row[0]) if row else None

    def put(self, source, key, body):
        self.put_many(source, {key: body})

    def all(self, source):
        with self.db() as db:
            return {
                key: json.loads(body)
                for key, body in db.execute(
                    "SELECT key,body FROM entries WHERE source=?", (source,)
                )
            }

    def put_many(self, source, bodies):
        if not bodies:
            return
        with self.db() as db, db:
            db.executemany(
                "INSERT INTO entries VALUES (?,?,?,?) ON CONFLICT(source,key) DO UPDATE "
                "SET body=excluded.body,checked_at=excluded.checked_at "
                "WHERE excluded.checked_at>=entries.checked_at",
                [
                    (source, key, json.dumps(body), body["checked_at"])
                    for key, body in bodies.items()
                ],
            )
            newest = max(body["checked_at"] for body in bodies.values())
            db.execute("DELETE FROM entries WHERE checked_at<?", (newest - 30 * 86400,))
            db.execute(
                "DELETE FROM entries WHERE rowid IN (SELECT rowid FROM entries "
                "ORDER BY checked_at DESC,rowid DESC LIMIT -1 OFFSET 10000)"
            )

    def ready_at(self, source):
        with self.db() as db:
            row = db.execute("SELECT until FROM cooldowns WHERE source=?", (source,)).fetchone()
            return row[0] if row else 0

    def defer(self, source, until):
        with self.db() as db, db:
            db.execute(
                "INSERT INTO cooldowns VALUES (?,?) ON CONFLICT(source) DO UPDATE "
                "SET until=MAX(cooldowns.until,excluded.until)",
                (source, until),
            )


class Intelligence:
    def __init__(
        self, cache: Cache, *, kev=False, epss=False, max_requests=100, request=api, clock=time.time
    ):
        if type(max_requests) is not int or not 1 <= max_requests <= 1000:
            raise ValueError("context request budget must be 1..1000")
        self.cache, self.kev, self.epss = cache, kev, epss
        self.max_requests, self.request, self.clock = max_requests, request, clock

    def _request(self, source, url):
        if self.used >= self.max_requests or time.monotonic() >= self.deadline:
            raise ScanError("quota_exhausted")
        if self.cache.ready_at(source) > self.clock():
            raise ScanError("quota_exhausted")
        self.used += 1
        try:
            return self.request("GET", url)
        except ScanError as exc:
            if exc.error_class == "quota_exhausted":
                delay = exc.retry_after_s or 60
                if not isinstance(delay, (int, float)) or not math.isfinite(delay) or delay < 1:
                    delay = 60
                self.cache.defer(source, self.clock() + min(delay, 3153600000))
            raise

    @staticmethod
    def _kev(body, checked_at):
        entries, count, version = body["vulnerabilities"], body["count"], body["catalogVersion"]
        if (
            not isinstance(entries, list)
            or type(count) is not int
            or count != len(entries)
            or not 1 <= count <= 40000
            or not isinstance(version, str)
            or not re.fullmatch(r"[A-Za-z0-9._:-]{1,80}", version)
        ):
            raise ValueError("incomplete KEV catalog")
        released = datetime.fromisoformat(body["dateReleased"].replace("Z", "+00:00"))
        if released.tzinfo is None or released.timestamp() < 0:
            raise ValueError("KEV release must have a valid nonnegative timestamp and timezone")
        ids = [e["cveID"] for e in entries]
        if (
            any(not isinstance(c, str) or not CVE_RE.fullmatch(c) for c in ids)
            or len(set(ids)) != count
        ):
            raise ValueError("invalid KEV identities")
        return {
            "checked_at": checked_at,
            "published_at": released.timestamp(),
            "catalog_version": version,
            "ids": sorted(ids),
        }

    def _kev_context(self, cves):
        now, data, error = self.clock(), self.cache.get("kev", "catalog"), None
        if data is None or not 0 <= now - data["checked_at"] < CACHE_TTL:
            try:
                latest = self._kev(self._request("kev", KEV_URL), self.clock())
                if data and (
                    latest["published_at"] < data["published_at"]
                    or (
                        latest["published_at"] == data["published_at"]
                        and latest["ids"] != data["ids"]
                    )
                ):
                    raise ScanError("evidence_mismatch")
                self.cache.put("kev", "catalog", latest)
                data = latest
            except (ScanError, ValueError, KeyError, TypeError, AttributeError) as exc:
                error = exc.error_class if isinstance(exc, ScanError) else "invalid_response"
        out = {}
        ids = set(data["ids"]) if data else set()
        for cve in cves:
            fields = {k: v for k, v in (data or {}).items() if k != "ids"}
            evidence = Evidence(
                source="kev",
                state="fetch_failed" if error else "available",
                error_class=error,
                listed=cve in ids if data else None,
                **fields,
            )
            evidence.state = evidence.state_at(self.clock())
            out[cve] = evidence
        return out

    def _epss_context(self, cves):
        out, pending = {}, []
        cached = self.cache.all("epss")
        for cve in cves:
            data = cached.get(cve)
            if data and 0 <= self.clock() - data["checked_at"] < CACHE_TTL:
                out[cve] = self._epss_evidence(data)
            else:
                pending.append(cve)
        # 50 maximum-width CVEs stay below FIRST's 2000-character CVE parameter limit.
        for start in range(0, len(pending), 50):
            batch = pending[start : start + 50]
            try:
                body = self._request(
                    "epss", EPSS_URL + "?" + urlencode({"cve": ",".join(batch), "limit": 50})
                )
                rows = body["data"]
                if (
                    body.get("status") != "OK"
                    or body.get("status-code") != 200
                    or type(body.get("total")) is not int
                    or body["total"] > len(batch)
                    or body.get("offset") != 0
                    or type(body.get("offset")) is not int
                    or not isinstance(rows, list)
                    or len(rows) != body["total"]
                ):
                    raise ValueError("incomplete EPSS response")
                parsed = {}
                for row in rows:
                    cve = row["cve"]
                    if (
                        cve not in batch
                        or cve in parsed
                        or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", row["date"])
                    ):
                        raise ValueError("invalid EPSS identity/date")
                    published = datetime.combine(
                        date.fromisoformat(row["date"]), datetime.min.time(), UTC
                    ).timestamp()
                    evidence = Evidence(
                        source="epss",
                        state="available",
                        checked_at=self.clock(),
                        published_at=published,
                        score=row["epss"],
                        percentile=row["percentile"],
                    )
                    old = cached.get(cve)
                    if old and old.get("published_at") and published < old["published_at"]:
                        raise ScanError("evidence_mismatch")
                    parsed[cve] = evidence.model_dump()
                # Validate the entire page before any page data becomes cache evidence.
                for cve in batch:
                    data = parsed.get(cve)
                    if data is None:
                        data = {
                            **(cached.get(cve) or {}),
                            "source": "epss",
                            "state": "unknown",
                            "checked_at": self.clock(),
                            "error_class": None,
                        }
                    parsed[cve] = data
                    out[cve] = self._epss_evidence(data)
                self.cache.put_many("epss", parsed)
                cached.update(parsed)
            except (ScanError, ValueError, KeyError, TypeError, AttributeError) as exc:
                error = exc.error_class if isinstance(exc, ScanError) else "invalid_response"
                for cve in batch:
                    data = cached.get(cve) or {"source": "epss"}
                    out[cve] = Evidence.model_validate(
                        {**data, "state": "fetch_failed", "error_class": error}
                    )
        return out

    def _epss_evidence(self, data):
        evidence = Evidence.model_validate(data)
        evidence.state = evidence.state_at(self.clock())
        return evidence

    def enrich(self, results):
        self.used, self.deadline = 0, time.monotonic() + 180
        ids = set()
        for result in results:
            for finding in result.findings:
                ids.update(c for c in [finding.id, *finding.aliases] if CVE_RE.fullmatch(c))
                if len(ids) > MAX_CVES:
                    # A deterministic bounded subset; omitted aliases remain explicitly unknown.
                    ids = set(sorted(ids)[:MAX_CVES])
        cves = sorted(ids)
        if not cves:
            return results
        kev = self._kev_context(cves) if self.kev else {}
        epss = self._epss_context(cves) if self.epss else {}
        out = []
        for result in results:
            findings = []
            for finding in result.findings:
                aliases = sorted({c for c in [finding.id, *finding.aliases] if CVE_RE.fullmatch(c)})
                contexts = []
                for cve in aliases[:20]:

                    def evidence(source, enabled, data, cve=cve):
                        return data.get(cve) or Evidence(
                            source=source,
                            state="unknown" if enabled else "disabled",
                            error_class="quota_exhausted" if enabled and cve not in ids else None,
                        )

                    contexts.append(
                        CVEContext(
                            cve=cve,
                            kev=evidence("kev", self.kev, kev),
                            epss=evidence("epss", self.epss, epss),
                        )
                    )
                findings.append(
                    finding.model_copy(
                        update={"exploit_context": contexts, "context_truncated": len(aliases) > 20}
                    )
                )
            ranks = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

            def priority(finding, ranks=ranks):
                kev, epss = context_key(finding.model_dump(mode="json"), self.clock())
                return (-kev, -ranks[finding.severity], -epss, finding.id)

            out.append(result.model_copy(update={"findings": sorted(findings, key=priority)}))
        return out
