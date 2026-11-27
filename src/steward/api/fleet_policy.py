"""Authenticated coordinator routes for reviewing and approving fleet policy."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, NoReturn

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import Field, TypeAdapter
from starlette.concurrency import run_in_threadpool

from ..core.fleet_identity import FleetIdentityRegistry
from ..core.fleet_policy import (
    FleetPolicy,
    FleetPolicyConflict,
    FleetPolicyRevision,
    FleetTarget,
    RegistryId,
    RevisionId,
)
from ..core.fleet_policy_apply import (
    FleetPolicyActor,
    FleetPolicyApply,
    FleetPolicyDenied,
    FleetPolicyNotFound,
)
from ..core.pve_inventory_models import Projection

_REVISION = TypeAdapter(RevisionId)
_APPROVAL = TypeAdapter(RegistryId)


class CommitBody(Projection):
    policy: FleetPolicy
    parent: RevisionId | None


class PreviewBody(Projection):
    revision: RevisionId
    targets: Annotated[tuple[FleetTarget, ...], Field(min_length=1)]


class ApproveBody(Projection):
    digest: RevisionId


class RollbackBody(Projection):
    revision: RevisionId
    parent: RevisionId | None


def open_policy(path: Path, subject: str | None) -> tuple[FleetPolicyApply, FleetPolicyActor]:
    if subject is None:
        raise ValueError("fleet policy principal is required")
    actor = FleetPolicyActor(subject=subject, coordinator=True, source="browser")
    path = path.absolute()
    directory = path.parent.lstat()
    database = path.lstat()
    if (
        not stat.S_ISDIR(directory.st_mode)
        or not stat.S_ISREG(database.st_mode)
        or directory.st_uid != os.geteuid()
        or database.st_uid != os.geteuid()
        or stat.S_IMODE(directory.st_mode) != 0o700
        or stat.S_IMODE(database.st_mode) != 0o600
    ):
        raise ValueError("fleet policy requires an owner-only coordinator directory and database")
    return FleetPolicyApply(FleetIdentityRegistry(path)), actor


def _unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("duplicate JSON field")
    return fields


def _reject_constant(_: str) -> NoReturn:
    raise ValueError("invalid JSON constant")


async def _body[Body: Projection](
    request: Request,
    model: type[Body],
    limit: int,
    *,
    invalid_detail: str = "invalid fleet policy request",
) -> Body:
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > limit:
            raise HTTPException(413, "body too large")
        data.extend(chunk)
    try:
        json.loads(
            data.decode("utf-8"), object_pairs_hook=_unique_fields, parse_constant=_reject_constant
        )
        return model.model_validate_json(data)
    except (ValueError, RecursionError):
        raise HTTPException(422, invalid_detail) from None


def _identifier(value: str, adapter: TypeAdapter[str]) -> str:
    try:
        return adapter.validate_python(value)
    except ValueError:
        raise HTTPException(422, "invalid fleet policy identifier") from None


def install(
    app: FastAPI,
    *,
    policy: FleetPolicyApply,
    actor: FleetPolicyActor,
    require_session: Callable[[Request], object],
    max_body_bytes: int,
) -> None:
    prefix = "/api/fleet/policy"

    async def invalid_request(_: Request, __: RequestValidationError) -> JSONResponse:
        return JSONResponse({"detail": "invalid request"}, status_code=422)

    app.add_exception_handler(RequestValidationError, invalid_request)

    def result(operation: Callable, *args, **kwargs) -> JSONResponse:
        try:
            output = operation(actor, *args, **kwargs)
        except FleetPolicyConflict as exc:
            return JSONResponse(
                {"head": exc.head, "message": "fleet policy has changed"}, status_code=409
            )
        except FleetPolicyDenied:
            raise HTTPException(403, "fleet policy access denied") from None
        except FleetPolicyNotFound:
            raise HTTPException(404, "fleet policy resource unavailable") from None
        except ValueError:
            raise HTTPException(422, "invalid fleet policy request") from None
        if isinstance(output, FleetPolicyRevision):
            return JSONResponse(json.loads(output.export()))
        return JSONResponse(output.model_dump(mode="json"))

    async def body[Body: Projection](request: Request, model: type[Body]) -> Body:
        await run_in_threadpool(require_session, request)
        return await _body(request, model, max_body_bytes)

    @app.get(prefix)
    def head(request: Request):
        require_session(request)
        return result(policy.head)

    @app.post(prefix + "/revisions")
    async def commit(request: Request):
        data = await body(request, CommitBody)
        return await run_in_threadpool(result, policy.commit, data.policy, parent=data.parent)

    @app.get(prefix + "/revisions/{revision}")
    def export(request: Request, revision: str):
        require_session(request)
        return result(policy.revision, _identifier(revision, _REVISION))

    @app.post(prefix + "/preview")
    async def preview(request: Request):
        data = await body(request, PreviewBody)
        return await run_in_threadpool(result, policy.preview, data.revision, data.targets)

    @app.post(prefix + "/approve")
    async def approve(request: Request):
        data = await body(request, ApproveBody)
        keys = request.headers.getlist("idempotency-key")
        if len(keys) != 1:
            raise HTTPException(422, "one Idempotency-Key is required")
        return await run_in_threadpool(result, policy.approve, data.digest, keys[0])

    @app.get(prefix + "/approvals/{approval_id}")
    def approval(request: Request, approval_id: str):
        require_session(request)
        return result(policy.approval, _identifier(approval_id, _APPROVAL))

    @app.post(prefix + "/rollback")
    async def rollback(request: Request):
        data = await body(request, RollbackBody)
        return await run_in_threadpool(result, policy.rollback, data.revision, parent=data.parent)
