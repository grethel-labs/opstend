"""Authenticated coordinator routes for single-guest power commands."""

from collections.abc import Callable

from fastapi import FastAPI, HTTPException, Request
from pydantic import TypeAdapter
from starlette.concurrency import run_in_threadpool

from ..core.fleet_policy import FleetPolicyConflict, FleetTarget, RevisionId
from ..core.fleet_policy_apply import FleetPolicyActor, FleetPolicyDenied, FleetPolicyNotFound
from ..core.fleet_power import PowerAction
from ..core.fleet_power_commands import FleetCommandConflict, FleetPowerCommands
from ..core.pve_inventory_models import Projection
from ..core.pve_power import JobId
from .fleet_policy import _body

_COMMAND = TypeAdapter(JobId)
_INVALID = "Invalid fleet command request."


class PreviewBody(Projection):
    target: FleetTarget
    policy_revision: RevisionId
    action: PowerAction


class ApproveBody(Projection):
    digest: RevisionId


def _command_id(value: str) -> str:
    try:
        return _COMMAND.validate_python(value, strict=True)
    except ValueError:
        raise HTTPException(422, "Invalid fleet command ID.") from None


def _idempotency_key(request: Request) -> str:
    keys = request.headers.getlist("idempotency-key")
    if len(keys) != 1:
        raise HTTPException(422, "One Idempotency-Key is required.")
    return keys[0]


def install(
    app: FastAPI,
    *,
    commands: FleetPowerCommands,
    actor: FleetPolicyActor,
    require_session: Callable[[Request], object],
    max_body_bytes: int,
) -> None:
    prefix = "/api/fleet/commands"

    def run(operation: Callable, *args):
        try:
            return operation(actor, *args)
        except (FleetPolicyConflict, FleetCommandConflict):
            raise HTTPException(
                409, "Fleet command evidence changed. Request a new preview."
            ) from None
        except FleetPolicyDenied:
            raise HTTPException(403, "Fleet guest power access denied.") from None
        except FleetPolicyNotFound:
            raise HTTPException(404, "Fleet command unavailable.") from None
        except ValueError:
            raise HTTPException(422, _INVALID) from None

    @app.get(prefix)
    def catalog(request: Request):
        require_session(request)
        return run(commands.catalog)

    @app.post(prefix + "/preview")
    async def preview(request: Request):
        await run_in_threadpool(require_session, request)
        data = await _body(request, PreviewBody, max_body_bytes, invalid_detail=_INVALID)
        key = _idempotency_key(request)
        return await run_in_threadpool(
            run, commands.request, data.target, data.policy_revision, data.action, key
        )

    @app.get(prefix + "/{command_id}")
    def status(request: Request, command_id: str):
        require_session(request)
        return run(commands.status, _command_id(command_id))

    @app.post(prefix + "/{command_id}/approve")
    async def approve(request: Request, command_id: str):
        await run_in_threadpool(require_session, request)
        data = await _body(request, ApproveBody, max_body_bytes, invalid_detail=_INVALID)
        key = _idempotency_key(request)
        return await run_in_threadpool(
            run, commands.approve, _command_id(command_id), data.digest, key
        )
