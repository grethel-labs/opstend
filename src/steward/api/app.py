"""Administration API and web UI host.

Security model:
- starts only with an admin token of sufficient entropy (fails closed);
- the token is exchanged for a revocable server-side session, delivered as a
  `__Host-` cookie (Secure, HttpOnly, SameSite=Strict);
- unsafe requests need a matching Origin and the per-session CSRF token;
- sessions are bound to the token fingerprint, so rotation revokes them;
- the API holds no host privileges: status and actions go through the executor.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import deque
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .. import __version__
from ..adapters.queries import MAX_QUESTION
from ..core import canonical
from ..core.advice import Advisor, gap, gather, read_collector_events
from ..core.advice_ipc import AdvicePeer, managed_advice_peer
from ..core.ai_admin_ipc import MANAGED_SOCKET, AdminPeer
from ..core.audit import AuditLog
from ..core.backup_view import read as read_backup_view
from ..core.config import Config, ConfigError, effective, load_yaml, parse_config
from ..core.config_apply import plan_apply
from ..core.fleet_power_commands import FleetPowerCommands
from ..core.secrets import SecretError, redact, validate_admin_token
from ..core.store import ConflictError, Store
from ..executor.protocol import DEFAULT_SOCKET, ExecutorError, call
from .ai_admin import install as install_ai_admin
from .fleet_policy import install as install_fleet_policy
from .fleet_policy import open_policy
from .fleet_power import install as install_fleet_power

COOKIE = "__Host-steward_session"
LOGIN_WINDOW_S = 300
LOGIN_MAX_FAILURES_PER_CLIENT = 5
LOGIN_MAX_FAILURES_GLOBAL = 30
STATUS_STALE_AFTER_S = 120
MAX_BODY_BYTES = 512 * 1024
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)
STATIC_DIR = Path(__file__).parent / "static"


class StartupError(Exception):
    pass


@dataclass
class Settings:
    state_dir: Path
    allowed_origins: tuple[str, ...]
    token: str | None = None
    token_file: Path | None = None
    desired_config: Path = Path("/etc/steward/config/desired.json")
    controller_export: Path = Path("/var/lib/steward-controller/export/state.json")
    executor_socket: str = DEFAULT_SOCKET
    collector_socket: str = "/run/steward-collector/query.sock"
    scanner_socket: str | None = "/run/steward-scanner/query.sock"
    session_ttl_s: int = 8 * 3600
    start_worker: bool = True
    ai_peer: AdminPeer | None = None
    advice_peer: AdvicePeer | None = None
    fleet_policy_db: Path | None = None
    fleet_policy_subject: str | None = None

    @classmethod
    def from_env(cls) -> Settings:
        env = os.environ
        origins = tuple(
            o.strip() for o in env.get("STEWARD_ALLOWED_ORIGINS", "").split(",") if o.strip()
        )
        token_file = env.get("STEWARD_ADMIN_TOKEN_FILE")
        fleet_db = env.get("STEWARD_FLEET_POLICY_DB")
        backend = env.get("STEWARD_AI_ADMIN_BACKEND")
        if backend not in (None, "managed-local"):
            raise StartupError("invalid AI admin backend")
        advice_backend = env.get("STEWARD_API_ADVICE_BACKEND")
        if advice_backend not in (None, "managed-local"):
            raise StartupError("invalid API advice backend")
        advice_peer = None
        if advice_backend == "managed-local":
            with suppress(KeyError, OSError):
                advice_peer = managed_advice_peer("api")
        return cls(
            state_dir=Path(env.get("STEWARD_STATE_DIR", "/var/lib/steward-api")),
            allowed_origins=origins,
            token=env.get("STEWARD_ADMIN_TOKEN") or None,
            token_file=Path(token_file) if token_file else None,
            desired_config=Path(env.get("STEWARD_DESIRED_CONFIG", cls.desired_config)),
            controller_export=Path(env.get("STEWARD_CONTROLLER_EXPORT", cls.controller_export)),
            executor_socket=env.get("STEWARD_EXECUTOR_SOCKET", DEFAULT_SOCKET),
            collector_socket=env.get(
                "STEWARD_COLLECTOR_SOCKET", "/run/steward-collector/query.sock"
            ),
            scanner_socket=env.get("STEWARD_SCANNER_SOCKET", "/run/steward-scanner/query.sock")
            or None,
            session_ttl_s=int(env.get("STEWARD_SESSION_TTL_MINUTES", "480")) * 60,
            ai_peer=AdminPeer(MANAGED_SOCKET, expected_peer_uid=0) if backend else None,
            advice_peer=advice_peer,
            fleet_policy_db=Path(fleet_db) if fleet_db else None,
            fleet_policy_subject=env.get("STEWARD_FLEET_POLICY_SUBJECT"),
        )


class TokenSource:
    """Admin token from env or file. Only its SHA-256 is kept in memory."""

    def __init__(self, settings: Settings):
        self._file = settings.token_file
        self._mtime: float | None = None
        self._digest = b""
        if self._file is None:
            if not settings.token:
                raise StartupError("no admin token configured (STEWARD_ADMIN_TOKEN[_FILE])")
            self._set(settings.token)
        else:
            self._reload()

    def _set(self, token: str) -> None:
        try:
            validate_admin_token(token)
        except SecretError as exc:
            raise StartupError(str(exc)) from None
        self._digest = hashlib.sha256(token.encode()).digest()

    def _reload(self) -> None:
        assert self._file is not None
        try:
            mtime = self._file.stat().st_mtime
            if mtime != self._mtime:
                self._set(self._file.read_text(encoding="utf-8").strip())
                self._mtime = mtime
        except OSError as exc:
            raise StartupError(f"cannot read admin token file: {exc.strerror}") from None

    def fingerprint(self) -> str:
        if self._file is not None:
            try:
                self._reload()
            except StartupError:
                return "unavailable-" + secrets.token_hex(8)  # nothing can match: fail closed
        return self._digest.hex()

    def authenticate(self, candidate: str) -> str | None:
        fingerprint = self.fingerprint()
        try:
            digest = hashlib.sha256(candidate.encode()).hexdigest()
        except UnicodeError:
            return None
        return fingerprint if hmac.compare_digest(digest, fingerprint) else None


class Sessions:
    def __init__(self, path: Path, ttl_s: int):
        self._path, self._ttl = str(path), ttl_s
        self._lock = threading.Lock()
        with self._db() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS sessions (id_hash TEXT PRIMARY KEY, csrf TEXT, "
                "token_fp TEXT, created_at REAL, expires_at REAL)"
            )

    def _db(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path, timeout=10)

    @staticmethod
    def _hash(session_id: str) -> str:
        return hashlib.sha256(session_id.encode()).hexdigest()

    def create(self, token_fp: str) -> tuple[str, str, float]:
        session_id, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        now = time.time()
        with self._lock, self._db() as db:
            db.execute(
                "DELETE FROM sessions WHERE expires_at < ? OR token_fp != ?", (now, token_fp)
            )
            db.execute(
                "INSERT INTO sessions VALUES (?,?,?,?,?)",
                (self._hash(session_id), csrf, token_fp, now, now + self._ttl),
            )
        return session_id, csrf, now + self._ttl

    def get(self, session_id: str, token_fp: str) -> dict[str, Any] | None:
        with self._lock, self._db() as db:
            row = db.execute(
                "SELECT csrf, expires_at FROM sessions WHERE id_hash=? AND token_fp=? "
                "AND expires_at > ?",
                (self._hash(session_id), token_fp, time.time()),
            ).fetchone()
        return (
            {"csrf": row[0], "expires_at": row[1], "id": self._hash(session_id)[:12]}
            if row
            else None
        )

    def revoke(self, session_id: str) -> None:
        with self._lock, self._db() as db:
            db.execute("DELETE FROM sessions WHERE id_hash=?", (self._hash(session_id),))


class LoginLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._failures: dict[str, deque[float]] = {}
        self._global: deque[float] = deque()

    def _trim(self, queue: deque[float], now: float) -> None:
        while queue and queue[0] < now - LOGIN_WINDOW_S:
            queue.popleft()

    def blocked(self, client: str) -> bool:
        now = time.time()
        with self._lock:
            queue = self._failures.get(client, deque())
            self._trim(queue, now)
            self._trim(self._global, now)
            return (
                len(queue) >= LOGIN_MAX_FAILURES_PER_CLIENT
                or len(self._global) >= LOGIN_MAX_FAILURES_GLOBAL
            )

    def record_failure(self, client: str) -> None:
        now = time.time()
        with self._lock:
            if len(self._failures) > 10000:
                self._failures.clear()
            self._failures.setdefault(client, deque()).append(now)
            self._global.append(now)


class LoginBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=1, max_length=512)


class ConfigBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    yaml: str = Field(max_length=MAX_BODY_BYTES)


class ApplyBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    head: str = Field(pattern=r"^[a-f0-9]{64}$")
    applied: str = Field(pattern=r"^[a-f0-9]{64}$")


class CommitBody(ConfigBody):
    parent: str | None = Field(pattern=r"^[a-f0-9]{64}$")
    message: str = Field("", max_length=500)


class AdviceBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(strict=True, min_length=1, max_length=MAX_QUESTION)


def _unique_advice_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("duplicate advice field")
    return fields


@dataclass(frozen=True)
class _AdminAdviceGrant:
    host: bool = True
    projects: tuple[str, ...] = ()


def create_app(settings: Settings) -> FastAPI:
    if not settings.allowed_origins:
        raise StartupError("STEWARD_ALLOWED_ORIGINS is empty")
    tokens = TokenSource(settings)
    fleet = None
    if settings.fleet_policy_db is not None:
        try:
            fleet = open_policy(settings.fleet_policy_db, settings.fleet_policy_subject)
        except (OSError, ValueError, sqlite3.Error):
            raise StartupError("invalid fleet policy coordinator configuration") from None
    elif settings.fleet_policy_subject is not None:
        raise StartupError("fleet policy principal requires a coordinator database")
    settings.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    session_file = "fleet-sessions.db" if fleet else "sessions.db"
    audit_file = "fleet-audit.jsonl" if fleet else "audit.jsonl"
    sessions = Sessions(settings.state_dir / session_file, settings.session_ttl_s)
    audit = AuditLog(settings.state_dir / audit_file)
    limiter = LoginLimiter()
    allowed_hosts = {o.split("://", 1)[1] for o in settings.allowed_origins}
    applied_mtime: list[float | None] = [None]

    app = FastAPI(
        title="steward admin API",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # ---- helpers ---------------------------------------------------------------

    def session_fingerprint(token_fp: str) -> str:
        if fleet is None:
            return token_fp
        _, actor = fleet
        fingerprint = json.dumps(
            [token_fp, str(settings.fleet_policy_db.absolute()), actor.subject]
        )
        return hashlib.sha256(fingerprint.encode()).hexdigest()

    def executor(action: str, params: dict[str, Any] | None = None, **kwargs: Any):
        return call(action, params, socket_path=settings.executor_socket, **kwargs)

    def write_export() -> None:
        head = store.head()
        export_dir = settings.state_dir / "export"
        export_dir.mkdir(exist_ok=True, mode=0o700)
        body = store.get_revision(head)["body"] if head else None  # type: ignore[index]
        tmp = export_dir / "head.json.tmp"
        tmp.write_text(json.dumps({"head": head, "applied": store.applied(), "config": body}))
        os.replace(tmp, export_dir / "head.json")

    def sync_applied() -> None:
        """Import the configuration the last deployment applied (root-owned file)."""
        try:
            mtime = settings.desired_config.stat().st_mtime
            if mtime == applied_mtime[0]:
                return
            store.record_applied(json.loads(settings.desired_config.read_text(encoding="utf-8")))
            applied_mtime[0] = mtime
            write_export()
        except (OSError, ValueError):
            pass

    def client_of(request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for", "")
        return (
            forwarded.split(",")[-1].strip() or (request.client.host if request.client else "?")
        )[:64]

    def require_session(request: Request) -> dict[str, Any]:
        session_id = request.cookies.get(COOKIE)
        session = (
            sessions.get(session_id, session_fingerprint(tokens.fingerprint()))
            if session_id
            else None
        )
        if session is None:
            raise HTTPException(401, "authentication required")
        if request.method not in ("GET", "HEAD"):
            supplied = request.headers.get("x-csrf-token", "")
            if not hmac.compare_digest(supplied.encode(), session["csrf"].encode()):
                raise HTTPException(403, "CSRF token missing or wrong")
        return session

    def parse_yaml_config(text: str) -> Config:
        try:
            cfg = parse_config(load_yaml(text))
        except ConfigError as exc:
            raise HTTPException(422, detail={"problems": exc.problems}) from None
        if cfg.admin.access == "private-lan" and (
            cfg.admin.lan is None or cfg.admin.lan.bind is None
        ):
            raise HTTPException(
                422,
                detail={
                    "problems": [
                        "Set admin.lan.interface and admin.lan.bind to review this draft, "
                        "or use steward deploy with a local configuration to discover the LAN."
                    ]
                },
            )
        return cfg

    def head_body() -> dict[str, Any] | None:
        head = store.head()
        return store.get_revision(head)["body"] if head else None  # type: ignore[index]

    def gather_advice(grant, now):
        return gather(
            settings.controller_export,
            grant,
            now,
            events=lambda project: read_collector_events(
                call, settings.collector_socket, project, now
            ),
        )

    advisor = (
        Advisor(settings.advice_peer, gather_advice, mask_before_infer=True)
        if settings.advice_peer is not None and fleet is None
        else None
    )

    # ---- middleware ------------------------------------------------------------

    @app.middleware("http")
    async def guard(request: Request, call_next):
        host = request.headers.get("host", "")
        if host not in allowed_hosts:
            return JSONResponse({"detail": "unknown host"}, status_code=421)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin", "")
            if origin not in settings.allowed_origins or origin.partition("://")[2] != host:
                return JSONResponse({"detail": "origin not allowed"}, status_code=403)
            length = request.headers.get("content-length", "0")
            if (
                "transfer-encoding" in request.headers
                or not length.isdigit()
                or int(length) > MAX_BODY_BYTES
            ):
                return JSONResponse({"detail": "body too large or unsized"}, status_code=413)
        response: Response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    # ---- session ---------------------------------------------------------------

    @app.post("/api/login")
    def login(body: LoginBody, request: Request, response: Response):
        client = client_of(request)
        if limiter.blocked(client):
            audit.append("login_rate_limited", client=client)
            raise HTTPException(429, "too many failed logins, try again later")
        token_fp = tokens.authenticate(body.token)
        if token_fp is None:
            limiter.record_failure(client)
            audit.append("login_failed", client=client)
            raise HTTPException(401, "invalid token")
        session_id, csrf, expires_at = sessions.create(session_fingerprint(token_fp))
        response.set_cookie(
            COOKIE,
            session_id,
            max_age=settings.session_ttl_s,
            path="/",
            secure=True,
            httponly=True,
            samesite="strict",
        )
        audit.append("login", client=client)
        return {"csrf": csrf, "expires_at": expires_at}

    @app.post("/api/logout")
    def logout(request: Request, response: Response):
        require_session(request)
        sessions.revoke(request.cookies[COOKIE])
        response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")
        audit.append("logout", client=client_of(request))
        return {"ok": True}

    @app.get("/api/session")
    def session_info(request: Request):
        session = require_session(request)
        return {
            "csrf": session["csrf"],
            "expires_at": session["expires_at"],
            "version": __version__,
            "fleet_policy": fleet is not None,
        }

    def install_spa() -> None:
        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            if path.startswith("api/") or (fleet is not None and path == "api"):
                raise HTTPException(404)
            root = STATIC_DIR.resolve()
            candidate = (root / path).resolve()
            if path and candidate.is_file() and candidate.is_relative_to(root):
                return FileResponse(candidate)
            index = root / "index.html"
            if not index.is_file():
                raise HTTPException(503, "web UI is not part of this build")
            return FileResponse(index, headers={"Cache-Control": "no-store"})

    if fleet is not None:
        policy, actor = fleet
        install_fleet_policy(
            app,
            policy=policy,
            actor=actor,
            require_session=require_session,
            max_body_bytes=MAX_BODY_BYTES,
        )
        install_fleet_power(
            app,
            commands=FleetPowerCommands(policy._registry),
            actor=actor,
            require_session=require_session,
            max_body_bytes=MAX_BODY_BYTES,
        )
        install_spa()
        return app

    store = Store(settings.state_dir / "steward.db")

    @app.get("/api/advice")
    def advice_status(request: Request):
        require_session(request)
        return {"enabled": advisor is not None}

    @app.post("/api/advice")
    async def ask_advice(request: Request):
        await run_in_threadpool(require_session, request)
        if request.scope["query_string"]:
            raise HTTPException(422, "advice does not accept query parameters")
        try:
            raw = (await request.body()).decode("utf-8")
            body = AdviceBody.model_validate(
                json.loads(raw, object_pairs_hook=_unique_advice_fields)
            )
            body.question.encode("utf-8")
        except (ValueError, RecursionError):
            raise HTTPException(422, "invalid advice question") from None
        if not body.question.strip():
            raise HTTPException(422, "invalid advice question")
        if advisor is None:
            return {"text": gap("advice is not enabled on this server")}
        # Every authenticated admin session already has host-wide authority.
        answer = await run_in_threadpool(
            advisor.answer, body.question, _AdminAdviceGrant(), now=time.time()
        )
        return {"text": answer}

    # ---- status ----------------------------------------------------------------

    @app.get("/api/status")
    def status(request: Request, live: bool = False):
        require_session(request)
        if live:
            try:
                return {
                    "source": "executor",
                    "stale": False,
                    "status_ok": True,
                    "generated_at": time.time(),
                    "status": executor("platform_status"),
                    "findings": None,
                }
            except ExecutorError as exc:
                raise HTTPException(503, f"executor: {exc.error_class}") from None
        try:
            snapshot = json.loads(settings.controller_export.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {
                "source": "controller",
                "stale": True,
                "status_ok": False,
                "generated_at": None,
                "status": None,
                "findings": None,
                "gap": "no controller snapshot available - observation gap",
            }
        age = time.time() - float(snapshot.get("generated_at", 0))
        snapshot.update(source="controller", stale=age > STATUS_STALE_AFTER_S, age_s=round(age, 1))
        return snapshot

    @app.get("/api/backups")
    def backup_observations(request: Request, project: str | None = None):
        require_session(request)
        if project is not None and not re.fullmatch(r"[a-z][a-z0-9-]{1,30}[a-z0-9]", project):
            raise HTTPException(422, "invalid project")
        return read_backup_view(
            settings.controller_export, now=time.time(), projects=[project] if project else None
        )

    # ---- configuration ---------------------------------------------------------

    @app.get("/api/config")
    def get_config(request: Request):
        require_session(request)
        sync_applied()
        head, applied = store.head(), store.applied()
        revision = store.get_revision(head) if head is not None else None
        body = revision["body"] if revision else None
        return {
            "head": head,
            "applied": applied,
            "pending": head != applied,
            "config": body,
            "yaml": yaml.safe_dump(body, sort_keys=False) if body else "",
            "schema": Config.model_json_schema(),
        }

    @app.post("/api/config/validate")
    def validate(body: ConfigBody, request: Request):
        require_session(request)
        cfg = parse_yaml_config(body.yaml)
        new = effective(cfg)
        return {
            "revision": canonical.revision_id(new),
            "effective": new,
            "diff": canonical.diff(head_body() or {}, new),
        }

    @app.post("/api/config/revisions")
    def commit(body: CommitBody, request: Request):
        session = require_session(request)
        sync_applied()
        new = effective(parse_yaml_config(body.yaml))
        current = head_body()
        if current is not None and new["server"] != current["server"]:
            raise HTTPException(
                422,
                detail={
                    "problems": [
                        "server: the deployment target can only be changed from the controller"
                    ]
                },
            )
        try:
            rev = store.commit_revision(
                new,
                parent=body.parent,
                author=f"session:{session['id']}",
                source="ui",
                message=body.message,
            )
        except ConflictError as exc:
            raise HTTPException(
                409, detail={"head": exc.head, "message": "configuration changed concurrently"}
            ) from None
        write_export()
        audit.append("config_commit", revision=rev, parent=body.parent, session=session["id"])
        return {"revision": rev, "pending": rev != store.applied()}

    def apply_plan(head: str | None, applied: str | None) -> dict[str, Any] | None:
        if head is None or applied is None or head == applied:
            return None
        old, new = store.get_revision(applied), store.get_revision(head)
        if old is None or new is None:
            return None
        return plan_apply(old["body"], new["body"], release_version=__version__).as_dict()

    @app.get("/api/config/apply-plan")
    def config_apply_plan(
        request: Request, job_id: str | None = Query(None, pattern=r"^[a-f0-9]{32}$")
    ):
        """What a local apply of the pending revision would do; the durable outcome is the job."""
        require_session(request)
        sync_applied()
        head, applied = store.head(), store.applied()
        outcomes = [j for j in store.list_jobs(50) if j["kind"] == "config_apply"][:5]
        response = {
            "head": head,
            "applied": applied,
            "release": __version__,
            "plan": apply_plan(head, applied),
            "jobs": outcomes,
        }
        if job_id is not None:
            job = store.get_job(job_id)
            response["tracked_job"] = job if job and job["kind"] == "config_apply" else None
        return response

    @app.post("/api/config/apply", status_code=202)
    def config_apply(body: ApplyBody, request: Request):
        session = require_session(request)
        key = request.headers.get("idempotency-key", "")
        if not (8 <= len(key) <= 80 and key.replace("-", "").isalnum()):
            raise HTTPException(400, "Idempotency-Key header required")
        sync_applied()
        if (store.head(), store.applied()) != (body.head, body.applied):
            raise HTTPException(
                409,
                detail={
                    "head": store.head(),
                    "applied": store.applied(),
                    "message": "configuration changed; review the pending revision again",
                },
            )
        plan = apply_plan(body.head, body.applied)
        if plan is None or not plan["supported"]:
            raise HTTPException(
                422,
                detail={
                    "problems": [(plan or {}).get("reason") or "nothing to apply"],
                    "message": "this revision needs ./steward deploy",
                },
            )
        job, created = store.enqueue(
            "config_apply",
            "config-apply",
            {"head": body.head, "applied": body.applied, "release": __version__},
            idempotency_key=f"config-apply:{body.head[:16]}:{body.applied[:16]}:{key}",
            created_by=f"session:{session['id']}",
        )
        if created:
            audit.append(
                "config_apply_requested",
                job=job["id"],
                head=body.head,
                applied=body.applied,
                session=session["id"],
            )
        return job

    @app.get("/api/config/revisions")
    def revisions(request: Request):
        require_session(request)
        return {
            "head": store.head(),
            "applied": store.applied(),
            "revisions": store.list_revisions(),
        }

    @app.get("/api/config/revisions/{rev}")
    def revision(rev: str, request: Request):
        require_session(request)
        found = store.get_revision(rev)
        if found is None:
            raise HTTPException(404, "unknown revision")
        parent = store.get_revision(found["parent"]) if found["parent"] else None
        found["diff"] = canonical.diff(parent["body"] if parent else {}, found["body"])
        return found

    # ---- jobs ------------------------------------------------------------------

    @app.post("/api/projects/{project_id}/restart", status_code=202)
    def restart(project_id: str, request: Request):
        session = require_session(request)
        key = request.headers.get("idempotency-key", "")
        if not (8 <= len(key) <= 80 and key.replace("-", "").isalnum()):
            raise HTTPException(400, "Idempotency-Key header required")
        body = store.get_revision(store.applied() or "") or {}
        known = {p["id"] for p in body.get("body", {}).get("projects", [])}
        if project_id not in known:
            raise HTTPException(404, "unknown project")
        job, created = store.enqueue(
            "workload_restart",
            f"project-{project_id}",
            {"project_id": project_id},
            idempotency_key=key,
            created_by=f"session:{session['id']}",
        )
        if created:
            audit.append(
                "job_created",
                job=job["id"],
                kind=job["kind"],
                target=job["target"],
                session=session["id"],
            )
        return job

    @app.get("/api/jobs")
    def jobs(request: Request):
        require_session(request)
        return {"jobs": store.list_jobs()}

    # ---- events ----------------------------------------------------------------

    @app.get("/api/events")
    def events(
        request: Request,
        since: float | None = None,
        until: float | None = None,
        project: str | None = None,
        min_severity: str = "info",
        kind_prefix: str | None = None,
        correlation_id: str | None = None,
        delivery: str | None = None,
        limit: int = 200,
    ):
        require_session(request)
        params = {
            "since": since,
            "until": until,
            "project": project,
            "min_severity": min_severity,
            "kind_prefix": kind_prefix,
            "correlation_id": correlation_id,
            "delivery": delivery,
            "limit": limit,
        }
        try:
            result = call(
                "events_query",
                {k: v for k, v in params.items() if v is not None},
                socket_path=settings.collector_socket,
                timeout=15,
            )
        except ExecutorError as exc:
            if exc.error_class == "bad_request":
                raise HTTPException(422, "invalid filter") from None
            raise HTTPException(
                503, f"event log unavailable ({exc.error_class}) - observation gap"
            ) from None
        return result

    @app.get("/api/scans")
    def scans(
        request: Request,
        project: str | None = None,
        source: str | None = None,
        subject: str | None = None,
        offset: int = 0,
        limit: int = 50,
        finding_offset: int = 0,
        snapshot_id: str | None = None,
    ):
        require_session(request)
        if not settings.scanner_socket:
            if snapshot_id is not None:
                raise HTTPException(409, "scan snapshot changed; refresh the results")
            return {
                "snapshot_id": None,
                "records": [],
                "total": 0,
                "next_offset": None,
                "jobs": [],
                "summary": {
                    "enabled": False,
                    "complete": False,
                    "stale": False,
                    "configuration_matches": False,
                    "counts": {},
                },
            }
        params = {"offset": offset, "limit": limit, "finding_offset": finding_offset}
        if snapshot_id is not None:
            params["snapshot_id"] = snapshot_id
        params.update(
            {
                k: v
                for k, v in {"project": project, "source": source, "subject": subject}.items()
                if v is not None
            }
        )
        try:
            page = call("scans_query", params, socket_path=settings.scanner_socket, timeout=15)
            summary = call("scans_summary", {}, socket_path=settings.scanner_socket, timeout=15)
            if page.get("snapshot_id") != summary.get("snapshot_id"):
                raise HTTPException(409, "scan snapshot changed; refresh the results")
            jobs = call("scans_jobs", {}, socket_path=settings.scanner_socket, timeout=15)
            return {**page, "summary": summary, "jobs": jobs["jobs"]}
        except ExecutorError as exc:
            if exc.error_class == "conflict":
                raise HTTPException(409, "scan snapshot changed; refresh the results") from None
            if exc.error_class == "bad_request":
                raise HTTPException(422, "invalid scanner filter") from None
            raise HTTPException(503, "scanner unavailable; coverage is unknown") from None

    # ---- audit -----------------------------------------------------------------

    @app.get("/api/audit")
    def audit_view(request: Request):
        require_session(request)
        ok, count = audit.verify()
        out: dict[str, Any] = {
            "api": {"chain_ok": ok, "records": count, "entries": audit.read(200)}
        }
        try:
            out["executor"] = executor("audit_tail")
        except ExecutorError as exc:
            out["executor"] = {"gap": f"executor audit unavailable: {exc.error_class}"}
        return json.loads(redact(json.dumps(out)))

    # ---- AI onboarding (ADR 0008) ----------------------------------------------

    install_ai_admin(
        app,
        require_session=require_session,
        audit=audit,
        state_dir=settings.state_dir,
        applied_body=lambda: (store.get_revision(store.applied() or "") or {}).get("body"),
        peer=settings.ai_peer,
    )

    # ---- web UI ----------------------------------------------------------------

    install_spa()

    # ---- job worker ------------------------------------------------------------

    def run_config_apply(job: dict[str, Any], worker: str) -> None:
        payload = job["payload"]
        try:
            result = executor(
                "config_apply",
                {
                    "head_revision": payload["head"],
                    "applied_revision": payload["applied"],
                    "release": payload["release"],
                },
                request_id=f"{job['id']}-{job['attempts']}",
            )
        except ExecutorError as exc:
            store.finish(job["id"], worker, ok=False, error=str(exc), retryable=exc.retryable)
            return
        # Success is the executor's verified readback AND the applied pointer, never submission.
        applied_mtime[0] = None  # re-read desired.json now, not only when its mtime moved
        sync_applied()
        if store.applied() != payload["head"]:
            store.finish(
                job["id"],
                worker,
                ok=False,
                error="applied revision is not visible yet",
                retryable=True,
            )
            return
        store.finish(job["id"], worker, ok=True, result=result)

    def run_job(job: dict[str, Any], worker: str) -> None:
        if job["kind"] == "config_apply":
            run_config_apply(job, worker)
            return
        if job["kind"] != "workload_restart":
            store.finish(job["id"], worker, ok=False, error="unknown job kind")
            return
        try:
            result = executor(
                "workload_restart",
                {
                    "project_id": job["payload"]["project_id"],
                    "reason": f"admin job {job['id'][:12]}",
                },
                request_id=f"{job['id']}-{job['attempts']}",
            )
            store.finish(job["id"], worker, ok=True, result=result)
        except ExecutorError as exc:
            store.finish(job["id"], worker, ok=False, error=str(exc), retryable=exc.retryable)

    def worker_loop(stop: threading.Event) -> None:
        worker = f"api-{os.getpid()}"
        while not stop.is_set():
            try:
                store.reconcile()
                job = store.claim(worker, lease_s=150)
                if job is None:
                    stop.wait(2)
                    continue
                run_job(job, worker)
            except Exception:  # noqa: BLE001 - worker must survive; job lease expiry recovers
                stop.wait(5)

    app.state.store, app.state.sessions, app.state.audit = store, sessions, audit
    app.state.run_pending_jobs = lambda: [
        run_job(j, "inline") for j in iter(lambda: store.claim("inline"), None)
    ]
    sync_applied()
    if settings.start_worker:
        stop = threading.Event()
        threading.Thread(target=worker_loop, args=(stop,), daemon=True, name="jobs").start()
        app.state.stop_worker = stop
    return app
