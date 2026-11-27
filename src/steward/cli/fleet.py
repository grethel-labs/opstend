"""Local fleet operator commands and outgoing agent commands."""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import stat
import sys
from pathlib import Path

from ..core import pve_native
from ..core.fleet_adoption_models import LocalPveProfile
from ..core.fleet_connector import collect_pve_adoption, collect_pve_inventory, pve_instance_binding
from ..core.fleet_enrollment import FleetEnrollment
from ..core.fleet_identity import FleetIdentityRegistry
from ..core.fleet_native_profile import export_pve_profile
from ..fleet_transport import FleetClient, certificate_fingerprint, create_server

_CAPABILITIES = ("heartbeat", "pve_inventory")
_INVITE_PATTERN = re.compile(rb"[A-Za-z0-9_-]{32,128}\n?")


def _registry(path: Path) -> FleetIdentityRegistry:
    path = path.absolute()
    info = path.parent.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ValueError("fleet DB directory must be coordinator-owned with mode 0700")
    return FleetIdentityRegistry(path)


def _read_invitation(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ValueError("invitation file must be owner-only with mode 0600")
        token = source.read(130)
    if not _INVITE_PATTERN.fullmatch(token):
        raise ValueError("invalid invitation file")
    return token.strip(b"\n").decode("ascii")


def _read_local_profile(path: Path) -> LocalPveProfile:
    try:
        data = pve_native._read_file(path, 4096, private=True)
        json.loads(data.decode("utf-8"), object_pairs_hook=pve_native._unique_object)
        return LocalPveProfile.model_validate_json(data)
    except (OSError, ValueError, RecursionError):
        raise ValueError("invalid private PVE profile") from None


def _issue(enrollment: FleetEnrollment, args: argparse.Namespace) -> None:
    path = args.invite_out
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as destination:
            os.fchmod(destination.fileno(), 0o600)
            issued = enrollment.issue(
                args.agent_id,
                key_fingerprint=args.key_fingerprint,
                capability=args.capability,
                route_id=args.route_id,
                expected_generation=args.generation,
                ttl_seconds=args.ttl,
            )
            destination.write(issued.token.get_secret_value() + "\n")
            destination.flush()
            os.fsync(destination.fileno())
    except (OSError, ValueError, sqlite3.Error):
        path.unlink(missing_ok=True)
        raise
    print(json.dumps({"expires_at": issued.expires_at.isoformat()}))


def _operator(args: argparse.Namespace) -> None:
    registry = _registry(args.db)
    enrollment = FleetEnrollment(registry)
    match args.fleet_command:
        case "register-site":
            result = registry.register_site(args.name)
        case "register-host":
            result = registry.register_host(args.site_id, args.name)
        case "register-agent":
            result = registry.register_agent(args.host_id, args.name)
        case "register-instance":
            result = registry.register_instance(
                args.site_id, kind=args.kind, instance_binding=pve_instance_binding(args.native_id)
            )
        case "confirm-route":
            result = registry.confirm_route(
                args.instance_id,
                host_id=args.host_id,
                api_name=args.api_name,
                node=args.node,
                address=args.address,
                transport_fingerprint=args.leaf_sha256,
                instance_binding=pve_instance_binding(args.native_id),
            )
        case "issue-invite" | "rotate":
            _issue(enrollment, args)
            return
        case "revoke":
            print(
                json.dumps(
                    {
                        "generation": enrollment.revoke(
                            args.agent_id, expected_generation=args.generation
                        )
                    }
                )
            )
            return
        case "adopt-pve":
            result = enrollment.adopt_pve(
                instance_id=args.instance_id,
                route_id=args.route_id,
                agent_id=args.agent_id,
                expected_generation=args.generation,
                instance_binding=pve_instance_binding(args.native_id),
                local_profile=_read_local_profile(args.local_profile)
                if args.local_profile
                else None,
            )
        case "detach-pve":
            result = enrollment.detach_pve(args.instance_id, expected_revision=args.revision)
        case "show-adoption":
            result = enrollment.show_adoption(args.instance_id, history=args.history)
        case "guest-history":
            print(
                json.dumps(
                    [
                        item.model_dump(mode="json")
                        for item in registry.guest_history(args.instance_id, args.vmid)
                    ]
                )
            )
            return
        case "serve":
            with create_server(
                enrollment,
                bind=args.bind,
                port=args.port,
                cert_file=args.cert_file,
                key_file=args.key_file,
                client_ca_file=args.client_ca_file,
            ) as server:
                server.serve_forever()
            return
    print(result.model_dump_json())


def _agent(args: argparse.Namespace) -> None:
    client = FleetClient(
        endpoint=args.endpoint,
        cert_file=args.cert_file,
        key_file=args.key_file,
        server_ca_file=args.server_ca_file,
    )
    match args.fleet_command:
        case "enroll":
            result = client.enroll(_read_invitation(args.invite_file))
        case "heartbeat":
            result = client.heartbeat()
        case "collect-pve":
            generation, route = client.connector_route()
            snapshot = collect_pve_inventory(
                route, ca_file=args.pve_ca_file, token_ref=args.pve_token_ref
            )
            result = client.publish_inventory(generation, snapshot)
        case "collect-pve-adoption":
            generation, route, attempt = client.begin_adoption()
            snapshot, evidence = collect_pve_adoption(
                route, ca_file=args.pve_ca_file, token_ref=args.pve_token_ref
            )
            result = client.publish_adoption(generation, attempt, snapshot, evidence)
    print(result.model_dump_json())


def _run(args: argparse.Namespace) -> int:
    try:
        if args.fleet_command == "key-fingerprint":
            print(certificate_fingerprint(args.cert_file))
        elif args.fleet_command == "export-pve-profile":
            print(export_pve_profile().model_dump_json())
        elif args.fleet_command in {"enroll", "heartbeat", "collect-pve", "collect-pve-adoption"}:
            _agent(args)
        else:
            _operator(args)
    except (OSError, ValueError, sqlite3.Error):
        print(
            "error: fleet operation failed (check local setup, identity and authorization)",
            file=sys.stderr,
        )
        return 1
    return 0


def register(subparsers: argparse._SubParsersAction) -> None:
    fleet = subparsers.add_parser("fleet", help="manage fleet enrollment and scoped inventory")
    commands = fleet.add_subparsers(dest="fleet_command", required=True)

    def operator(name: str, description: str) -> argparse.ArgumentParser:
        command = commands.add_parser(name, help=description)
        command.add_argument("--db", type=Path, required=True, help="private coordinator database")
        return command

    def tls(command: argparse.ArgumentParser) -> None:
        command.add_argument("--cert-file", type=Path, required=True)
        command.add_argument("--key-file", type=Path, required=True)

    site = operator("register-site", "register a fleet site")
    site.add_argument("--name", required=True)
    host = operator("register-host", "register a site host")
    host.add_argument("--site-id", required=True)
    host.add_argument("--name", required=True)
    agent = operator("register-agent", "register an agent for a host")
    agent.add_argument("--host-id", required=True)
    agent.add_argument("--name", required=True)
    instance = operator("register-instance", "register an independently verified PVE instance")
    instance.add_argument("--site-id", required=True)
    instance.add_argument("--kind", choices=("standalone", "cluster"), required=True)
    instance.add_argument("--native-id", required=True)
    route = operator("confirm-route", "confirm a PVE route against independently verified evidence")
    for option in (
        "instance-id",
        "host-id",
        "api-name",
        "node",
        "address",
        "leaf-sha256",
        "native-id",
    ):
        route.add_argument("--" + option, required=True)
    for name, description in (
        ("issue-invite", "issue a new one-use invitation to a private file"),
        ("rotate", "issue a rotation invitation bound to the current grant generation"),
    ):
        issue = operator(name, description)
        issue.add_argument("--agent-id", required=True)
        issue.add_argument("--capability", choices=_CAPABILITIES, required=True)
        issue.add_argument("--route-id")
        issue.add_argument("--key-fingerprint", required=True)
        issue.add_argument("--generation", type=int, required=name == "rotate", default=0)
        issue.add_argument("--ttl", type=int, default=600)
        issue.add_argument("--invite-out", type=Path, required=True)
    revoke = operator("revoke", "revoke a grant at a specified generation")
    revoke.add_argument("--agent-id", required=True)
    revoke.add_argument("--generation", type=int, required=True)
    adopt = operator("adopt-pve", "attach a confirmed standalone PVE route read-only")
    for option in ("instance-id", "route-id", "agent-id", "native-id"):
        adopt.add_argument("--" + option, required=True)
    adopt.add_argument("--generation", type=int, required=True)
    adopt.add_argument("--local-profile", type=Path)
    detach = operator("detach-pve", "detach a PVE instance and fence its connector routes")
    detach.add_argument("--instance-id", required=True)
    detach.add_argument("--revision", type=int, required=True)
    show = operator("show-adoption", "read scoped PVE adoption evidence")
    show.add_argument("--instance-id", required=True)
    show.add_argument("--history", action="store_true")
    commands.add_parser("export-pve-profile", help="export the verified local native PVE profile")
    history = operator("guest-history", "read sanitized guest generations")
    history.add_argument("--instance-id", required=True)
    history.add_argument("--vmid", type=int, required=True)
    serve = operator("serve", "serve the private mTLS fleet endpoints")
    serve.add_argument("--bind", default="127.0.0.1", help="explicit private numeric bind address")
    serve.add_argument("--port", type=int, default=8443)
    serve.add_argument("--client-ca-file", type=Path, required=True)
    tls(serve)
    fingerprint = commands.add_parser("key-fingerprint", help="read the SPKI hash of a client PEM")
    fingerprint.add_argument("--cert-file", type=Path, required=True)
    enroll = commands.add_parser("enroll", help="redeem an invitation over mTLS")
    enroll.add_argument("--invite-file", type=Path, required=True)
    heartbeat = commands.add_parser("heartbeat", help="verify the current heartbeat grant")
    collect = commands.add_parser("collect-pve", help="collect and publish a scoped PVE snapshot")
    adoption_collect = commands.add_parser(
        "collect-pve-adoption", help="collect and publish scoped standalone PVE evidence"
    )
    for command in (collect, adoption_collect):
        command.add_argument("--pve-ca-file", type=Path, required=True)
        command.add_argument("--pve-token-ref", required=True)
    for command in (enroll, heartbeat, collect, adoption_collect):
        command.add_argument("--endpoint", required=True)
        command.add_argument("--server-ca-file", type=Path, required=True)
        tls(command)
    fleet.set_defaults(func=_run)
