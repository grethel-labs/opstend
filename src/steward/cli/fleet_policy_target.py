"""Local provisioning and admission for a co-located fleet policy target."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections.abc import Callable
from pathlib import Path

from ..core import pve_native
from ..core.fleet_identity import FleetIdentityRegistry
from ..core.fleet_policy import FleetPolicyConflict
from ..core.fleet_policy_apply import FleetPolicyApply
from ..core.fleet_policy_target import FleetPolicyTargetConfig, FleetPolicyTargetStore

COMMANDS = {
    "policy-target-configure": "provision the local target and its safety limits",
    "policy-target-show": "read fleet policy metadata stored on the local target",
    "policy-target-report": "report the co-located target's current local policy state",
    "policy-target-adopt": "admit an approved fleet policy at the co-located target",
}


def register(subparsers: argparse._SubParsersAction) -> None:
    for name, description in COMMANDS.items():
        command = subparsers.add_parser(name, help=description)
        command.add_argument("--target-db", type=Path, required=True, help="target-owned database")
        if name == "policy-target-configure":
            command.add_argument("--config", type=Path, required=True, help="private JSON file")
        if name in {"policy-target-report", "policy-target-adopt"}:
            command.add_argument("--db", type=Path, required=True, help="private coordinator DB")
        if name == "policy-target-adopt":
            command.add_argument("--approval", required=True)
            command.add_argument("--digest", required=True)


def run(args: argparse.Namespace, registry: Callable[[Path], FleetIdentityRegistry]) -> int:
    try:
        if args.fleet_command == "policy-target-configure":
            raw = pve_native._read_file(args.config, 65_536, private=True)
            json.loads(raw, object_pairs_hook=pve_native._unique_object)
            config = FleetPolicyTargetConfig.model_validate_json(raw)
            result = FleetPolicyTargetStore.configure(args.target_db, config).state()
        else:
            target = FleetPolicyTargetStore(args.target_db)
            if args.fleet_command == "policy-target-show":
                result = target.state()
            else:
                target.check_coordinator_path(args.db)
                apply = FleetPolicyApply(registry(args.db))
                if args.fleet_command == "policy-target-report":
                    result = apply.report_local(target)
                else:
                    result = apply.adopt_local(target, args.approval, args.digest)
                    if result.status == "rejected":
                        print(result.model_dump_json())
                        return 1
        print(result.model_dump_json())
    except FleetPolicyConflict as exc:
        print(json.dumps({"error": "fleet policy head changed", "head": exc.head}), file=sys.stderr)
        return 1
    except (OSError, ValueError, LookupError, RecursionError, sqlite3.Error):
        print("error: target policy operation failed", file=sys.stderr)
        return 1
    return 0
