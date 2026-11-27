"""Fleet handoff requests and the signed native PVE confirmation commands."""

import argparse
import os
import subprocess
from collections.abc import Callable
from pathlib import Path

from pydantic import TypeAdapter

from ..core.fleet_identity import FleetIdentityRegistry
from ..core.fleet_ownership import LocalOwnershipRequest
from ..core.fleet_ownership_coordinator import FleetOwnershipCoordinator
from ..core.fleet_policy import FleetTarget
from ..core.fleet_policy_apply import FleetPolicyActor
from ..core.pve_native_install import InstallError, _locked
from ..core.pve_power import _installed_power_runtime


def register(
    commands: argparse._SubParsersAction,
    operator: Callable[[str, str], argparse.ArgumentParser],
) -> None:
    request = operator("ownership-request", "request a guest and schedule handoff")
    request.add_argument("--target", type=Path, required=True, help="private JSON guest target")
    request.add_argument("--schedule-ref", required=True)
    request.add_argument("--profile", required=True)
    request.add_argument("--owner", choices=("standalone", "fleet"), required=True)
    request.add_argument(
        "--epoch", type=int, required=True, help="expected current ownership epoch"
    )
    request.add_argument("--idempotency-key", required=True)
    status = operator("ownership-status", "read the coordinator's handoff record")
    status.add_argument("--transition-id", required=True)
    local = commands.add_parser(
        "ownership-target", help="review or confirm a handoff as root on native PVE"
    ).add_subparsers(dest="ownership_action", required=True)
    local.add_parser("status", help="read durable local ownership")
    for action, help_text in (
        ("prepare", "verify the current schedule and pause new local guest work"),
        ("confirm", "verify the schedule is drained and commit the owner"),
        ("resume", "verify the same schedule is enabled for the confirmed owner"),
        ("cancel", "confirm the old owner and re-armed schedule before ownership changes"),
    ):
        operation = local.add_parser(action, help=help_text)
        operation.add_argument("--transition-id", required=True)
        operation.add_argument("--digest", required=True)


def run(
    args: argparse.Namespace,
    registry: FleetIdentityRegistry,
    read_target: Callable[[Path, TypeAdapter[FleetTarget]], FleetTarget],
) -> None:
    service = FleetOwnershipCoordinator(registry)
    actor = FleetPolicyActor(subject="local-coordinator", coordinator=True)
    if args.fleet_command == "ownership-request":
        result = service.request(
            actor,
            read_target(args.target, TypeAdapter(FleetTarget)),
            args.schedule_ref,
            args.profile,
            args.owner,
            args.idempotency_key,
            args.epoch,
        )
    else:
        result = service.status(actor, args.transition_id)
    print(result.model_dump_json())


def target(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise ValueError("Native fleet ownership requires local root.")
    request = LocalOwnershipRequest(
        action=args.ownership_action,
        transition_id=getattr(args, "transition_id", None),
        digest=getattr(args, "digest", None),
    )
    try:
        with _locked():
            _, _, python = _installed_power_runtime()
        process = subprocess.run(
            [str(python), "-I", "-B", "-m", "steward.executor.fleet_ownership"],
            input=request.model_dump_json(exclude_none=True).encode(),
            cwd="/",
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            timeout=90,
            check=False,
        )
    except (InstallError, OSError, subprocess.SubprocessError):
        raise ValueError("The active signed native fleet executor is unavailable.") from None
    return 1 if process.returncode else 0
