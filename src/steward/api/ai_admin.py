"""Admin API for AI onboarding (ADR 0008): read model plus operator actions.

Every action needs the admin session and CSRF token (via `require_session`) and an
Idempotency-Key header, exactly like config apply; a replay returns the stored response.
The API never calls a provider or fetches a source. Actions that need one (scan, initial
check, best-now, source research) are recorded as requests that the separate inference
service executes (`Onboarding.process_requests`). AI-sourced proposals can never be made
through this API: it always acts as `operator`.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi import Path as RoutePath
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from ..core.ai_admin import (
    MAX_SOURCE_ID_LENGTH,
    AdminControl,
    AutoBody,
    DecisionBody,
    DomainsBody,
    InvalidAdminRequest,
    LocalBody,
    ModeBody,
    ModelBody,
    ProviderBody,
    SourceBody,
    SourceId,
    valid_key,
)
from ..core.ai_admin_ipc import CANDIDATE_SCOPE_CODE
from ..core.ai_auth import AUTH_METHODS
from ..core.ai_onboarding import SECRET_REF, HostFacts, Onboarding
from ..core.config import AiFx
from ..core.fx_rate import FxStore
from ..core.model_selection import SelectionStore
from ..core.model_sources import DOMAIN, SourceStore
from ..executor.protocol import ExecutorError


class _Result(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


class _Due(_Result):
    model: str
    reason: Literal["initial_check", "selection_change"]


class _Brief(_Result):
    status: Literal["none", "provider_chosen", "scanned", "awaiting_download", "ready"]
    pinned: str | None
    auto_selection: bool
    report_due: _Due | None


class _RequestRow(_Result):
    id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    kind: Literal["scan", "initial_check", "best_now", "source_research"]
    created_at: float
    state: Literal["pending", "running", "done", "failed"]
    result: str


class _Provider(_Result):
    id: str
    label: str
    data_class: str
    runtime_enabled: bool

    @field_validator("runtime_enabled")
    @classmethod
    def setup_only(cls, value: bool) -> bool:
        if value:
            raise ValueError("unexpected runtime activation")
        return value


class _SelectedProvider(_Provider):
    key_ref: str | None

    @field_validator("key_ref")
    @classmethod
    def safe_reference(cls, value: str | None) -> str | None:
        if value is not None and (len(value) > 300 or not SECRET_REF.fullmatch(value)):
            raise ValueError("invalid credential reference")
        return value


class _Option(_Provider):
    auth: str
    available: bool
    reason: str
    default_hint: str | None
    default_status: str


class _Scan(_Result):
    models: list[str]
    at: float


class _Active(_Result):
    model: str
    fallback: str
    since: float


class _Report(_Result):
    id: str
    created_at: float
    provider: str
    model: str
    reason: Literal["initial_check", "selection_change"]
    decision_id: str
    total_reports: int
    body: dict[str, Any]


class _Source(_Result):
    id: str
    url: str
    parser: str
    state: Literal["active", "proposed"]
    origin: Literal["operator", "ai"]
    suspect: bool
    retrieved_at: float | None
    age_days: float | None
    note: str


class _Egress(_Result):
    hosts: list[str]
    search: bool


class _SourceAudit(_Result):
    ts: float
    actor: str
    event: str
    detail: dict[str, Any]


class _Mode(_Result):
    mode: Literal["propose_confirm", "allowlist", "fixed", "automatic"]


class _Domains(_Result):
    domains: list[str] = Field(max_length=32)

    @field_validator("domains")
    @classmethod
    def valid_domains(cls, domains: list[str]) -> list[str]:
        if not all(DOMAIN.fullmatch(domain) for domain in domains):
            raise ValueError("invalid allowed domain")
        return domains


class _Sources(_Mode):
    allowed_domains: list[str]
    list: list[_Source]
    egress: _Egress
    audit: list[_SourceAudit]


class _ExchangeRate(_Result):
    status: Literal["ok", "missing", "stale"]
    mode: Literal["operator", "fetched"]
    max_age_days: int
    rate_ppm: int | None
    as_of: str | None
    source: str | None


class _View(_Brief):
    provider: _SelectedProvider | None
    options: list[_Option]
    local_download: LocalBody | None
    scanned: _Scan | None
    suggested: str | None
    active: _Active | None
    report: _Report | None
    requests: list[_RequestRow]
    sources: _Sources
    exchange_rate: _ExchangeRate | None
    defaults_status: Literal["UNVERIFIED"]


SourcePath = Annotated[str, RoutePath(max_length=MAX_SOURCE_ID_LENGTH)]


class _Added(_Result):
    id: Annotated[str, Field(pattern=r"^[a-f0-9]{12}$")]


class _Removed(_Result):
    removed: SourceId


class _Decision(_Result):
    id: SourceId
    accepted: bool


_RESULTS = {
    "view": _View,
    "provider": _Brief,
    "scan": _RequestRow,
    "initial-model": _Brief,
    "pin": _Brief,
    "unpin": _Brief,
    "auto": _Brief,
    "best-now": _RequestRow,
    "source-add": _Added,
    "source-remove": _Removed,
    "source-decision": _Decision,
    "source-mode": _Mode,
    "source-domains": _Domains,
    "source-research": _RequestRow,
}
_QUEUE_KINDS = {"scan": "scan", "best-now": "best_now", "source-research": "source_research"}
_REFUSALS = {
    "provider": {
        "unknown_provider", "method_unavailable", "api_key_reference_required",
        "key_not_used_by_provider", "local_download_only_for_ollama_local",
        "provider_already_chosen", "local_download_declaration_required",
        "local_download_declaration_invalid", "resource_refused",
    },
    "initial-model": {
        "scan_required", "initial_model_already_chosen", "model_not_the_declared_download",
        "model_not_in_scan",
    },
    "pin": {"onboarding_incomplete", "model_not_in_scan"},
    "auto": {"onboarding_incomplete"},
    "best-now": {"model_pinned"},
    "source-add": {
        "url_not_public_https", "unknown_parser", "too_many_sources", "duplicate_source",
    },
    "source-remove": {"unknown_source"},
    "source-decision": {"not_a_proposal"},
    "source-domains": {"invalid_domain"},
}  # fmt: skip
_METHOD_REASONS = {"no adapter", "method unknown"} | {
    method.unavailable_reason for method in AUTH_METHODS.values() if not method.available
}
_RESOURCE_PROBLEM = re.compile(
    r"the model license has not been accepted \(ai\.local\.license_ack\)"
    r"|insufficient RAM: model needs [0-9]{1,7} MB, -?[0-9]{1,20} free"
    r"|insufficient disk: [0-9]{1,8} MB needed, [0-9]{1,20} free"
)


def _safe_problem_list(code: str, problems: list) -> bool:
    if code == "method_unavailable":
        return len(problems) == 1 and problems[0] in _METHOD_REASONS
    if code == "resource_refused":
        return 1 <= len(problems) <= 3 and all(_RESOURCE_PROBLEM.fullmatch(p) for p in problems)
    return not problems


def _unavailable() -> HTTPException:
    return HTTPException(503, detail={"code": "ai_admin_unavailable"})


def _checked_result(action: str, response: object) -> tuple[dict, bool]:
    if not isinstance(response, dict):
        raise _unavailable()
    if response == {"status": "rejected", "code": CANDIDATE_SCOPE_CODE, "problems": []}:
        raise HTTPException(422, detail={"code": CANDIDATE_SCOPE_CODE, "problems": []})
    if response.get("status") == "rejected" and action != "view":
        code, problems = response.get("code"), response.get("problems")
        if (
            response.keys() != {"status", "code", "problems"}
            or not isinstance(code, str)
            or (code != "request_in_progress" and code not in _REFUSALS.get(action, ()))
            or not isinstance(problems, list)
            or len(problems) > 3
            or not all(isinstance(p, str) and len(p) <= 500 for p in problems)
            or not _safe_problem_list(code, problems)
        ):
            raise _unavailable()
        raise HTTPException(422, detail={"code": code, "problems": problems})

    keys = {"status", "body"} if action == "view" else {"status", "body", "replayed"}
    replayed = response.get("replayed", False)
    body = response.get("body")
    if (
        response.keys() != keys
        or response["status"] != "ok"
        or type(replayed) is not bool
        or not isinstance(body, dict)
    ):
        raise _unavailable()
    try:
        _RESULTS[action].model_validate(body, strict=True)
    except ValidationError:
        raise _unavailable() from None
    if action in _QUEUE_KINDS and (
        body["kind"] != _QUEUE_KINDS[action]
        or body["state"] not in ("pending", "running")
        or body["result"] != ""
    ):
        raise _unavailable()
    return body, replayed


def install(
    app: FastAPI,
    *,
    require_session: Callable[[Request], dict[str, Any]],
    audit: Any,
    state_dir: Path,
    applied_body: Callable[[], dict | None],
    host_facts: Callable[[], HostFacts] | None = None,
    clock: Callable[[], float] = time.time,
    peer: Callable[[str, object], dict] | None = None,
) -> Onboarding | None:
    onboarding = None
    if peer is None:
        base = state_dir / "ai"
        base.mkdir(parents=True, exist_ok=True, mode=0o700)
        sources = SourceStore(base / "sources.db", clock=clock)
        onboarding = Onboarding(
            base, SelectionStore(base / "selection.db"), sources, clock=clock,
            audit=lambda e: audit.append(e.pop("event"), **e),
        )  # fmt: skip

        def read_fx() -> AiFx | None:
            body = applied_body() or {}
            raw = (body.get("ai") or {}).get("fx")
            return AiFx(**raw) if raw is not None else None

        backend = AdminControl(
            onboarding, fx_store=FxStore(base / "fx.db"), read_fx=read_fx,
            clock=clock, host_facts=host_facts,
        ).dispatch  # fmt: skip
    else:
        backend = peer

    def dispatch(name: str, params: dict) -> tuple[dict, bool]:
        try:
            response = backend(name, params)
        except (ExecutorError, InvalidAdminRequest):
            raise _unavailable() from None
        return _checked_result(name, response)

    def act(name: str, request: Request, body: dict | None = None) -> dict:
        session = require_session(request)
        key = request.headers.get("idempotency-key", "")
        if not valid_key(key):
            raise HTTPException(400, "Idempotency-Key header required")
        response, replayed = dispatch(name, {"key": key, "body": body if body is not None else {}})
        if not replayed:
            audit.append("ai_admin_action", action=name, session=session["id"])
        return response

    @app.get("/api/ai")
    def ai_view(request: Request):
        require_session(request)
        return dispatch("view", {})[0]

    @app.post("/api/ai/provider")
    def ai_provider(body: ProviderBody, request: Request):
        return act("provider", request, body.model_dump())

    @app.post("/api/ai/scan", status_code=202)
    def ai_scan(request: Request):
        return act("scan", request)

    @app.post("/api/ai/initial-model")
    def ai_initial(body: ModelBody, request: Request):
        return act("initial-model", request, body.model_dump())

    @app.post("/api/ai/pin")
    def ai_pin(body: ModelBody, request: Request):
        return act("pin", request, body.model_dump())

    @app.post("/api/ai/unpin")
    def ai_unpin(request: Request):
        return act("unpin", request)

    @app.post("/api/ai/auto")
    def ai_auto(body: AutoBody, request: Request):
        return act("auto", request, body.model_dump())

    @app.post("/api/ai/best-now", status_code=202)
    def ai_best_now(request: Request):
        return act("best-now", request)

    @app.post("/api/ai/sources")
    def ai_source_add(body: SourceBody, request: Request):
        return act("source-add", request, body.model_dump())

    @app.delete("/api/ai/sources/{source_id}")
    def ai_source_remove(source_id: SourcePath, request: Request):
        return act("source-remove", request, {"source_id": source_id})

    @app.post("/api/ai/sources/{source_id}/decision")
    def ai_source_decide(source_id: SourcePath, body: DecisionBody, request: Request):
        return act("source-decision", request, {"source_id": source_id, **body.model_dump()})

    @app.post("/api/ai/source-mode")
    def ai_source_mode(body: ModeBody, request: Request):
        return act("source-mode", request, body.model_dump())

    @app.post("/api/ai/source-domains")
    def ai_source_domains(body: DomainsBody, request: Request):
        return act("source-domains", request, body.model_dump())

    @app.post("/api/ai/source-research", status_code=202)
    def ai_source_research(request: Request):
        return act("source-research", request)

    return onboarding
