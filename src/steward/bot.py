"""Read-only information bot; no executor access or mutation tools.

Optional `ask` advice goes through an injected backend (`core/advice.py`); the bot holds no
provider credential, and a failure never affects the deterministic commands."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import math
import os
import sqlite3
import time
import uuid
from pathlib import Path
from time import monotonic
from typing import TYPE_CHECKING

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from .adapters.queries import DiscordQuery, Query, QueryAdapter, QueryError, SignedQuery
from .collector import CONTROLLER_EXPORT, QUERY_SOCKET
from .core.advice import Advisor, gap, gather, read_collector_events
from .core.backup_view import read as read_backup_view
from .core.secrets import redact, resolve
from .executor.protocol import ExecutorError, call

if TYPE_CHECKING:
    from .core.advice_ipc import AdvicePeer

_PENDING = "pending:"
_PENDING_GAP = gap("the original request has no recorded answer")
_MANAGED_REPLAY_GAP = gap("managed advice is only available on the original request")
_DISABLED_ASK = (
    "Advice is not enabled on this server. Deterministic answers remain "
    "available: /status /updates /backups /help."
)
_REQUEST_RETENTION_S = 600


class Information:
    def __init__(self, snapshot: Path, collector_socket: str, advisor=None):
        self.snapshot, self.collector_socket = snapshot, collector_socket
        self.advisor = advisor  # core.advice.Advisor or None (advice not enabled)

    def answer(self, query: Query, grant, *, now: float) -> str:
        if query.command == "help":
            return "/status /updates /backups /help — read-only; no repairs or approvals."
        if query.command == "ask":
            if self.advisor is None:
                return _DISABLED_ASK
            return self.advisor.answer(query.text, grant, now=now)
        if query.command == "status":
            try:
                with self.snapshot.open("rb") as handle:
                    raw = handle.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    raise ValueError
                snapshot = json.loads(raw)
                stamp = float(snapshot["generated_at"])
                if not math.isfinite(stamp) or not 0 <= now - stamp <= 120:
                    return "Observation gap: controller snapshot is stale. Source: controller."
                state = snapshot.get("status") or {}
                rows = [f"Controller snapshot at {stamp:.0f} UTC epoch seconds."]
                if grant.host:
                    rows.append(
                        f"Controller status: {'ok' if snapshot.get('status_ok') else 'degraded'}. "
                        f"Kill switch: {state.get('kill_switch', 'unknown')}."
                    )
                projects = state.get("projects") or {}
                ids = sorted(projects) if grant.host else grant.projects
                for id in ids:
                    project = projects.get(id)
                    if project is None:
                        rows.append(f"{id}: unknown (no observation).")
                    else:
                        active = project.get("unit", {}).get("active", "unknown")
                        health = project.get("health")
                        rows.append(
                            f"{id}: {active}; health "
                            + ("unknown" if not health else "ok" if health.get("ok") else "failed")
                        )
                return "\n".join(rows)[:1800]
            except (OSError, ValueError, TypeError, KeyError, AttributeError):
                return "Observation gap: no valid controller snapshot. Source: controller."
        if query.command == "backups":
            view = read_backup_view(
                self.snapshot, now=now, projects=None if grant.host else grant.projects
            )
            if view["freshness"] != "fresh":
                return "Observation gap: controller backup evidence is stale or unavailable."
            if view["enabled"] is False:
                return (
                    "Scheduled backups are disabled; historical evidence does not "
                    "establish current coverage."
                )
            if view["enabled"] is None:
                return "Backup configuration is unknown; no successful backup is implied."
            rows = ["Backup observations from the controller; worker phases are reported claims."]
            for item in view["projects"]:

                def stamp(value):
                    return "unknown" if value is None else f"{value:.0f} UTC epoch"

                rows.append(
                    f"{item['project']}: capture {item['capture_state']} "
                    f"({item['capture_freshness']}, {stamp(item['capture_created_at'])}); "
                    f"worker {item['worker_state']}; upload {stamp(item['uploaded_at'])}; "
                    f"integrity {stamp(item['integrity_checked_at'])}; "
                    f"restored bytes {stamp(item['restored_bytes_at'])}; "
                    "independent application drill unknown."
                )
            if len(rows) == 1:
                rows.append("No project evidence is available; no successful backup is implied.")
            return "\n".join(rows)[:1800]
        prefix = "vulnerability."
        events = []
        scopes = [None] if grant.host else grant.projects
        try:
            for project in scopes:
                result = call(
                    "events_query",
                    {"project": project, "kind_prefix": prefix, "since": now - 86400, "limit": 5},
                    socket_path=self.collector_socket,
                    timeout=0.2,
                )
                events.extend(result["events"])
                coverage = result["coverage"]
                if (
                    coverage.get("open_gaps")
                    or (
                        coverage.get("pruned_before") is not None
                        and coverage["pruned_before"] > now - 86400
                    )
                    or coverage.get("lag_s") is None
                    or coverage["lag_s"] > 120
                ):
                    return "Observation gap: collector coverage is incomplete or stale."
        except (ExecutorError, KeyError, TypeError):
            return "Observation gap: collector unavailable."
        if not events:
            return (
                f"{query.command}: unknown; no matching observations in the last 24 hours. "
                "No successful scan or backup is implied. Source: collector."
            )
        rows = [
            f"{query.command}: collector observations, UTC epoch {now - 86400:.0f}..{now:.0f}; "
            "at most five records per authorized project."
        ]
        for event in sorted(events, key=lambda e: e["ts"], reverse=True):
            rows.append(
                f"event {event['id']} at {event['ts']:.0f}: {redact(event['summary'])[:200]}"
            )
        return "\n".join(rows)[:1800]


def make_information(
    snapshot: Path,
    collector_socket: str,
    *,
    advice_peer: AdvicePeer | None = None,
    all_projects: tuple[str, ...] = (),
) -> Information:
    if advice_peer is None:
        return Information(snapshot, collector_socket)

    def gather_for(grant, now):
        return gather(
            snapshot,
            grant,
            now,
            events=lambda project: read_collector_events(call, collector_socket, project, now),
        )

    advisor = Advisor(advice_peer, gather_for, all_projects=all_projects, mask_before_infer=True)
    return Information(snapshot, collector_socket, advisor=advisor)


class Service:
    def __init__(
        self,
        database: Path,
        adapters: dict[str, QueryAdapter],
        endpoints: dict,
        information: Information,
        *,
        managed_advice: bool = False,
    ):
        self.database, self.adapters, self.endpoints = database, adapters, endpoints
        self.information = information
        self.managed_advice = managed_advice
        with sqlite3.connect(database) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS requests (
                    endpoint TEXT, id TEXT, body_hash TEXT, actor TEXT,
                    response TEXT, created REAL, PRIMARY KEY(endpoint,id)
                );
            """)

    def process(self, id: str, body: bytes, headers: dict, *, now: float) -> dict:
        adapter = self.adapters.get(id)
        if adapter is None:
            raise QueryError("unknown_endpoint", 404)
        request = adapter.decode(body, headers, now=now)
        if request.ping:
            return {"type": 1}
        grant = next(
            (
                g
                for g in self.endpoints[id].grants
                if (g.tenant, g.user) == (request.tenant, request.user)
            ),
            None,
        )
        if grant is None:
            raise QueryError("forbidden", 403)
        # No snapshot or event query has happened before identity authorization.
        digest = hashlib.sha256(body).hexdigest()
        actor = f"{request.tenant}:{request.user}"
        enabled_ask = request.command == "ask" and self.information.advisor is not None
        managed_ask = request.command == "ask" and self.managed_advice
        started = monotonic()
        db = sqlite3.connect(self.database, timeout=0.2)
        try:
            with db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("DELETE FROM requests WHERE created < ?", (now - _REQUEST_RETENTION_S,))
                row = db.execute(
                    "SELECT body_hash,response FROM requests WHERE endpoint=? AND id=?",
                    (id, request.id),
                ).fetchone()
                if row:
                    if row[0] != digest:
                        raise QueryError("replay_conflict", 409)
                    if row[1].startswith(_PENDING):
                        return adapter.response(_PENDING_GAP)
                    cached = json.loads(row[1])
                    # Older direct backends could store advice text in the replay cache.
                    if managed_ask and cached != adapter.response(_DISABLED_ASK):
                        return adapter.response(_MANAGED_REPLAY_GAP)
                    return cached
                count = db.execute(
                    "SELECT COUNT(*) FROM requests WHERE endpoint=? AND actor=? AND created>=?",
                    (id, actor, now - 60),
                ).fetchone()[0]
                total = db.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
                if count >= 30 or total >= 10000:
                    raise QueryError("rate_limited", 429)
                if enabled_ask:
                    # Store a unique reservation in the response column until finalization.
                    pending = _PENDING + uuid.uuid4().hex
                    stored = pending
                else:
                    text = redact(self.information.answer(request, grant, now=now))[:1800]
                    response = adapter.response(text)
                    stored = json.dumps(response)
                db.execute(
                    "INSERT INTO requests VALUES (?,?,?,?,?,?)",
                    (id, request.id, digest, actor, stored, now),
                )
            if not enabled_ask:
                return response

            text = redact(self.information.answer(request, grant, now=now))[:1800]
            response = adapter.response(text)
            # Persist the replay gap even if the managed backend is later withdrawn.
            replay = adapter.response(_MANAGED_REPLAY_GAP) if managed_ask else response
            # A deterministic updates query can hold the write lock across its collector reads.
            db.execute("PRAGMA busy_timeout=2000")
            try:
                with db:
                    db.execute("BEGIN IMMEDIATE")
                    cutoff = now + (monotonic() - started) - _REQUEST_RETENTION_S
                    updated = db.execute(
                        "UPDATE requests SET response=? "
                        "WHERE endpoint=? AND id=? AND body_hash=? AND response=? AND created>=?",
                        (json.dumps(replay), id, request.id, digest, pending, cutoff),
                    )
                    if updated.rowcount != 1:
                        return adapter.response(_PENDING_GAP)
            except sqlite3.OperationalError as exc:
                if getattr(exc, "sqlite_errorcode", 0) & 0xFF != sqlite3.SQLITE_BUSY:
                    raise
                return adapter.response(_PENDING_GAP)
            return response
        finally:
            db.close()


def create_app(service: Service) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    def health():
        return {"ok": True}

    @app.post("/bot/{id}")
    async def incoming(id: str, request: Request):
        async def read():
            data = bytearray()
            async for chunk in request.stream():
                data.extend(chunk)
                if len(data) > 16384:
                    raise QueryError("too_large", 413)
            return bytes(data)

        try:
            body = await asyncio.wait_for(read(), timeout=0.2)
            result = await run_in_threadpool(
                service.process, id, body, dict(request.headers), now=time.time()
            )
            return JSONResponse(result, headers={"Cache-Control": "no-store"})
        except QueryError as exc:
            return JSONResponse({"error_class": exc.error_class}, status_code=exc.status)
        except TimeoutError:
            return JSONResponse({"error_class": "timeout"}, status_code=408)
        except Exception:  # noqa: BLE001 - never expose raw endpoint/credential errors
            return JSONResponse({"error_class": "unavailable"}, status_code=503)

    return app


def main() -> None:
    from .core.config import Bot

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/steward/bot.json")
    parser.add_argument("--state-dir", default="/var/lib/steward-bot")
    parser.add_argument("--collector-socket", default=QUERY_SOCKET)
    parser.add_argument("--controller-export", default=CONTROLLER_EXPORT)
    parser.add_argument("--advice-socket")
    parser.add_argument("--advice-peer-uid", type=int)
    args = parser.parse_args()
    if (args.advice_socket is None) != (args.advice_peer_uid is None):
        parser.error("--advice-socket and --advice-peer-uid must be supplied together")
    backend = os.environ.get("STEWARD_BOT_ADVICE_BACKEND")
    if backend not in (None, "managed-local"):
        parser.error("invalid bot advice backend")
    advice_peer = None
    if backend == "managed-local":
        from .core.advice_ipc import managed_advice_peer

        if args.advice_socket is not None:
            parser.error("managed advice does not accept explicit socket or peer UID")
        with contextlib.suppress(KeyError, OSError):
            advice_peer = managed_advice_peer("bot")
    elif args.advice_socket is not None:
        from .core.advice_ipc import AdvicePeer

        if not args.advice_socket or not 0 <= args.advice_peer_uid < 2**32 - 1:
            parser.error("invalid advice socket path or peer UID")
        advice_peer = AdvicePeer(args.advice_socket, args.advice_peer_uid)
    os.umask(0o077)
    settings = Bot.model_validate_json(Path(args.config).read_text())
    adapters = {}
    for endpoint in settings.endpoints:
        credentials = os.environ.get("CREDENTIALS_DIRECTORY")
        key = (
            Path(credentials, endpoint.id).read_text().strip()
            if credentials
            else resolve(endpoint.verification_key_ref)
        )
        adapters[endpoint.id] = (
            SignedQuery(key)
            if endpoint.adapter == "webhook"
            else DiscordQuery(key, endpoint.application_id)
        )
    state = Path(args.state_dir)
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    service = Service(
        state / "queries.db",
        adapters,
        {e.id: e for e in settings.endpoints},
        make_information(
            Path(args.controller_export),
            args.collector_socket,
            advice_peer=advice_peer,
            all_projects=tuple(
                sorted(
                    {
                        project
                        for endpoint in settings.endpoints
                        for grant in endpoint.grants
                        for project in grant.projects
                    }
                )
            ),
        ),
        managed_advice=backend == "managed-local",
    )
    uvicorn.run(
        create_app(service),
        host="127.0.0.1",
        port=settings.port,
        log_level="warning",
        access_log=False,
        proxy_headers=False,
        limit_concurrency=32,
    )


if __name__ == "__main__":
    main()
