"""Single-guest command review and the fixed native target tick."""

import argparse
import os
import subprocess
from collections.abc import Callable
from pathlib import Path

from pydantic import TypeAdapter

from ..core.fleet_identity import FleetIdentityRegistry
from ..core.fleet_policy import FleetTarget
from ..core.fleet_policy_apply import FleetPolicyActor
from ..core.fleet_power_commands import FleetPowerCommands
from ..core.pve_native_install import InstallError, _locked
from ..core.pve_power import _installed_power_runtime

TARGET_COMMAND = "command-target-sync"


def register(
    commands: argparse._SubParsersAction, operator: Callable[[str, str], argparse.ArgumentParser]
) -> None:
    operator("command-list", "show scoped guests and fleet commands")
    preview = operator("command-preview", "request a target-prepared guest power preview")
    preview.add_argument("--target", type=Path, required=True, help="private JSON guest target")
    preview.add_argument("--policy-revision", required=True)
    preview.add_argument("--action", choices=("start",), required=True)
    preview.add_argument("--idempotency-key", required=True)
    approve = operator("command-approve", "approve the exact target-prepared preview")
    approve.add_argument("--command-id", required=True)
    approve.add_argument("--digest", required=True)
    approve.add_argument("--idempotency-key", required=True)
    status = operator("command-status", "read the durable fleet command result")
    status.add_argument("--command-id", required=True)
    commands.add_parser(TARGET_COMMAND, help="poll once as the configured native power executor")


def run(
    args: argparse.Namespace,
    registry: FleetIdentityRegistry,
    read_target: Callable[[Path, TypeAdapter[FleetTarget]], FleetTarget],
) -> None:
    service = FleetPowerCommands(registry)
    actor = FleetPolicyActor(subject="local-coordinator", coordinator=True)
    match args.fleet_command:
        case "command-list":
            result = service.catalog(actor)
        case "command-preview":
            target = read_target(args.target, TypeAdapter(FleetTarget))
            result = service.request(
                actor, target, args.policy_revision, args.action, args.idempotency_key
            )
        case "command-approve":
            result = service.approve(actor, args.command_id, args.digest, args.idempotency_key)
        case "command-status":
            result = service.status(actor, args.command_id)
        case _:
            raise ValueError("unknown fleet command operation")
    print(result.model_dump_json())


def sync_target() -> int:
    if os.geteuid() != 0:
        raise ValueError("Native fleet command synchronization requires local root.")
    try:
        with _locked():
            _, _, python = _installed_power_runtime()
        process = subprocess.run(
            [str(python), "-I", "-B", "-m", "steward.executor.fleet_power"],
            stdin=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd="/",
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            timeout=90,
            check=False,
        )
    except (InstallError, OSError, subprocess.SubprocessError):
        raise ValueError("The active signed native fleet executor is unavailable.") from None
    if process.returncode:
        raise ValueError("The signed native fleet executor could not complete its poll.")
    return 0
