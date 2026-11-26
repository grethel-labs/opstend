"""`steward-host`: operator commands on the managed server (run as root).

The kill switch is a plain root-owned file checked by the executor. It works
without the web UI, the controller or any AI component.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

from .controller import evaluate
from .core.audit import AuditLog
from .core.backup_view import read as read_backup_view
from .core.config import ConfigError, load_config_file
from .core.retirement import retire_params
from .executor.host import KILLSWITCH_PATH
from .executor.protocol import DEFAULT_SOCKET, ExecutorError, call
from .executor.server import AUDIT_PATH

EVENT_SOCKET = "/run/steward-collector/query.sock"
BACKUP_SOCKET = "/run/steward-backup/query.sock"


def main() -> None:
    parser = argparse.ArgumentParser(prog="opstend-host")
    parser.add_argument("--socket", default=DEFAULT_SOCKET)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="verified platform status as JSON")
    backup_status = sub.add_parser("backup-status", help="read controller backup evidence as JSON")
    backup_status.add_argument("--project")
    backup_status.add_argument(
        "--controller-export", default="/var/lib/steward-controller/export/state.json"
    )
    receipt = sub.add_parser("backup-receipt", help="read one exact verified worker receipt")
    receipt.add_argument("project_id")
    for option in ("config-revision", "repository-id", "capture-id", "snapshot-id"):
        receipt.add_argument("--" + option, required=True)
    inv = sub.add_parser("inventory", help="revision-bound packages/kernel and registered images")
    inv.add_argument("--project", help="inspect one registered image only")
    kill = sub.add_parser("killswitch", help="stop or resume automatic mutations")
    kill.add_argument("state", choices=["on", "off", "status"])
    restart = sub.add_parser("restart", help="restart a registered workload")
    restart.add_argument("project_id")
    admit = sub.add_parser(
        "maintenance-admit",
        help="run a registered read-only maintenance check if the window admits it",
    )
    admit.add_argument("work_id", choices=["resource_check"])
    scheduled = sub.add_parser("backup-schedule", help="request a revision-bound scheduled capture")
    scheduled.add_argument("project_id")
    scheduled.add_argument("--expected-revision", required=True)
    capture = sub.add_parser(
        "backup-capture", help="pause and capture registered project data locally"
    )
    capture.add_argument("project_id")
    retention = sub.add_parser(
        "backup-retention-status", help="inspect protected local backup metadata"
    )
    retention.add_argument("project_id")
    retention_ack = sub.add_parser(
        "backup-retention-ack", help="acknowledge possible future removal of one verified capture"
    )
    retention_ack.add_argument("project_id")
    retention_ack.add_argument("artifact")
    retention_ack.add_argument("--capture-id", required=True)
    retention_ack.add_argument("--acknowledge-removal", action="store_true", required=True)
    retention_revoke = sub.add_parser(
        "backup-retention-revoke", help="withdraw a capture removal acknowledgement"
    )
    retention_revoke.add_argument("project_id")
    retention_revoke.add_argument("artifact")
    retention_revoke.add_argument("--capture-id", required=True)
    retention_purge = sub.add_parser(
        "backup-retention-purge", help="retire one eligible acknowledged private capture"
    )
    retention_purge.add_argument("project_id")
    retention_purge.add_argument("artifact")
    retention_purge.add_argument("--capture-id", required=True)
    upload_cancel = sub.add_parser(
        "backup-upload-cancel", help="abandon one protected upload while its service is stopped"
    )
    upload_cancel.add_argument("project_id")
    upload_cancel.add_argument("artifact")
    upload_cancel.add_argument("--capture-id", required=True)
    upload_cancel.add_argument("--acknowledge-abandonment", action="store_true", required=True)
    upload_reinstate = sub.add_parser(
        "backup-upload-reinstate", help="reinstate one cancelled protected upload"
    )
    upload_reinstate.add_argument("project_id")
    upload_reinstate.add_argument("artifact")
    upload_reinstate.add_argument("--capture-id", required=True)
    cancellation_forget = sub.add_parser(
        "backup-cancellation-forget", help="reconcile one unreferenced cancellation record"
    )
    cancellation_forget.add_argument("project_id")
    cancellation_forget.add_argument("artifact")
    cancellation_forget.add_argument("--capture-id", required=True)
    cancellation_forget.add_argument("--acknowledge-forget", action="store_true", required=True)
    import_purge = sub.add_parser(
        "backup-import-purge", help="retire one cancelled import while preserving its capture"
    )
    import_purge.add_argument("project_id")
    import_purge.add_argument("artifact")
    import_purge.add_argument("--capture-id", required=True)
    import_purge.add_argument("--acknowledge-import-removal", action="store_true", required=True)
    recover = sub.add_parser("backup-recover", help="resume an interrupted registered backup pause")
    recover.add_argument("project_id")
    export = sub.add_parser(
        "backup-export", help="publish one verified capture read-only for backup upload"
    )
    export.add_argument("project_id")
    export.add_argument("artifact")
    export.add_argument("--capture-id", required=True)
    recover.add_argument(
        "--accept-current",
        action="store_true",
        help="acknowledge an already reconciled state without starting the workload",
    )
    retire = sub.add_parser(
        "application-retire",
        help="archive, verify and release a removed, disabled application (never deletes archives)",
    )
    retire.add_argument("application")
    retire.add_argument(
        "--desired-config",
        required=True,
        help="the exact configuration file that will be deployed next",
    )
    retirement_status = sub.add_parser(
        "application-retirement-status", help="read the archive journal of one application"
    )
    retirement_status.add_argument("application")
    rollback = sub.add_parser(
        "rollback", help="return one applied verified update to its previous image"
    )
    rollback.add_argument("project_id")
    rollback.add_argument("--approval-id", required=True)
    rollback.add_argument("--digest", required=True, help="digest of the update being rolled back")
    rollback.add_argument(
        "--acknowledge-data-restore",
        action="store_true",
        help="allow the exact data restore a migrating update needs (newer data is preserved)",
    )
    update_apply = sub.add_parser(
        "update-apply",
        help="apply one validated update; --emergency-confirm waives only the window",
    )
    update_apply.add_argument("project_id")
    update_apply.add_argument("--approval-id", required=True)
    update_apply.add_argument("--digest", required=True)
    update_apply.add_argument(
        "--emergency-confirm",
        action="store_true",
        help="operator emergency: apply outside the maintenance window (audited, announced)",
    )
    update_apply.add_argument("--reason", help="required with --emergency-confirm (10-200 chars)")
    update_retention = sub.add_parser(
        "update-retention",
        help="list update captures and preserved data trees (read-only; 30-day cleanup candidates)",
    )
    update_retention.add_argument("--project")
    config_apply = sub.add_parser(
        "config-apply", help="apply the exact pending web UI revision (registry-only changes)"
    )
    config_apply.add_argument("--head", required=True, help="reviewed head revision")
    config_apply.add_argument("--applied", required=True, help="applied revision it was based on")
    verify = sub.add_parser("verify", help="exit non-zero unless the platform is fully healthy")
    verify.add_argument("--expect-revision")
    for field in ("operation-id", "run-id", "boot-id"):
        verify.add_argument("--deployment-" + field)
    sub.add_parser("audit-verify", help="verify the executor audit hash chain")
    ai = sub.add_parser("ai", help="guided AI login and credential lifecycle (A04)")
    ai.add_argument("ai_action", choices=["login", "status", "check", "revoke"])
    ai.add_argument("--method", default="")
    ai.add_argument("--relogin", action="store_true")
    events = sub.add_parser("events", help="query the event log (JSON lines, newest first)")
    events.add_argument("--project")
    events.add_argument("--min-severity", default="info")
    events.add_argument("--kind-prefix")
    events.add_argument("--correlation-id")
    events.add_argument("--since-minutes", type=float)
    events.add_argument("--limit", type=int, default=50)
    events.add_argument("--coverage", action="store_true", help="print coverage only")
    record = sub.add_parser("record-deployment", help="log a verified deployment (Ansible)")
    record.add_argument("--revision", required=True)
    record.add_argument("--release", required=True)
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.exit("steward-host must run as root")
    try:
        if args.command == "ai":
            from .aihost import run as ai_run

            sys.exit(ai_run(args.ai_action, args.method, relogin=args.relogin, euid=0))
        if args.command == "status":
            print(json.dumps(call("platform_status", socket_path=args.socket), indent=2))
        elif args.command == "backup-status":
            if args.project and not re.fullmatch(r"[a-z][a-z0-9-]{1,30}[a-z0-9]", args.project):
                parser.error("invalid project")
            print(
                json.dumps(
                    read_backup_view(
                        Path(args.controller_export),
                        now=time.time(),
                        projects=[args.project] if args.project else None,
                    ),
                    indent=2,
                )
            )
        elif args.command == "backup-receipt":
            print(
                json.dumps(
                    call(
                        "backups_receipt",
                        {
                            "project": args.project_id,
                            "config_revision": args.config_revision,
                            "repository_id": args.repository_id,
                            "capture_id": args.capture_id,
                            "snapshot_id": args.snapshot_id,
                        },
                        socket_path=BACKUP_SOCKET,
                        timeout=10,
                    ),
                    indent=2,
                )
            )
        elif args.command == "backup-schedule":
            if not re.fullmatch(r"[a-f0-9]{64}", args.expected_revision):
                parser.error("invalid expected revision")
            print(
                json.dumps(
                    call(
                        "backup_schedule",
                        {
                            "project_id": args.project_id,
                            "expected_revision": args.expected_revision,
                        },
                        socket_path=args.socket,
                        timeout=900,
                    ),
                    indent=2,
                )
            )
        elif args.command == "application-retire":
            if not re.fullmatch(r"[a-z][a-z0-9-]{1,30}[a-z0-9]", args.application):
                parser.error("invalid application")
            try:
                desired = load_config_file(Path(args.desired_config), allow_unavailable=True)
            except ConfigError as exc:
                sys.exit(f"error: {exc}")
            applied = call("platform_status", socket_path=args.socket)["config_revision"]
            print(
                json.dumps(
                    call(
                        "application_retire",
                        retire_params(args.application, applied, desired),
                        socket_path=args.socket,
                        timeout=900,
                    ),
                    indent=2,
                )
            )
        elif args.command == "application-retirement-status":
            if not re.fullmatch(r"[a-z][a-z0-9-]{1,30}[a-z0-9]", args.application):
                parser.error("invalid application")
            print(
                json.dumps(
                    call(
                        "application_retirement_status",
                        {"application": args.application},
                        socket_path=args.socket,
                    ),
                    indent=2,
                )
            )
        elif args.command == "backup-cancellation-forget":
            print(
                json.dumps(
                    call(
                        "backup_cancellation_forget",
                        {
                            "project_id": args.project_id,
                            "artifact": args.artifact,
                            "capture_id": args.capture_id,
                            "acknowledge_forget": args.acknowledge_forget,
                        },
                        socket_path=args.socket,
                        timeout=60,
                    ),
                    indent=2,
                )
            )
        elif args.command == "backup-import-purge":
            print(
                json.dumps(
                    call(
                        "backup_import_purge",
                        {
                            "project_id": args.project_id,
                            "artifact": args.artifact,
                            "capture_id": args.capture_id,
                            "acknowledge_import_removal": args.acknowledge_import_removal,
                        },
                        socket_path=args.socket,
                        timeout=300,
                    ),
                    indent=2,
                )
            )
        elif args.command in ("backup-upload-cancel", "backup-upload-reinstate"):
            params = {
                "project_id": args.project_id,
                "artifact": args.artifact,
                "capture_id": args.capture_id,
            }
            if args.command == "backup-upload-cancel":
                params["acknowledge_abandonment"] = args.acknowledge_abandonment
            print(
                json.dumps(
                    call(
                        "backup_upload_cancel"
                        if args.command == "backup-upload-cancel"
                        else "backup_upload_reinstate",
                        params,
                        socket_path=args.socket,
                        timeout=300,
                    ),
                    indent=2,
                )
            )
        elif args.command == "backup-retention-purge":
            print(
                json.dumps(
                    call(
                        "backup_retention_purge",
                        {
                            "project_id": args.project_id,
                            "artifact": args.artifact,
                            "capture_id": args.capture_id,
                        },
                        socket_path=args.socket,
                        timeout=300,
                    ),
                    indent=2,
                )
            )
        elif args.command == "backup-retention-revoke":
            print(
                json.dumps(
                    call(
                        "backup_retention_revoke",
                        {
                            "project_id": args.project_id,
                            "artifact": args.artifact,
                            "capture_id": args.capture_id,
                        },
                        socket_path=args.socket,
                    ),
                    indent=2,
                )
            )
        elif args.command == "backup-retention-ack":
            print(
                json.dumps(
                    call(
                        "backup_retention_ack",
                        {
                            "project_id": args.project_id,
                            "artifact": args.artifact,
                            "capture_id": args.capture_id,
                            "acknowledge_removal": args.acknowledge_removal,
                        },
                        socket_path=args.socket,
                        timeout=300,
                    ),
                    indent=2,
                )
            )
        elif args.command == "backup-retention-status":
            print(
                json.dumps(
                    call(
                        "backup_retention_status",
                        {"project_id": args.project_id},
                        socket_path=args.socket,
                    ),
                    indent=2,
                )
            )
        elif args.command == "backup-export":
            print(
                json.dumps(
                    call(
                        "backup_export",
                        {
                            "project_id": args.project_id,
                            "artifact": args.artifact,
                            "capture_id": args.capture_id,
                        },
                        socket_path=args.socket,
                        timeout=300,
                    ),
                    indent=2,
                )
            )
        elif args.command in ("backup-capture", "backup-recover"):
            print(
                json.dumps(
                    call(
                        "backup_capture" if args.command == "backup-capture" else "backup_recover",
                        {
                            "project_id": args.project_id,
                            **(
                                {"accept_current": args.accept_current}
                                if args.command == "backup-recover"
                                else {}
                            ),
                        },
                        socket_path=args.socket,
                        timeout=300,
                    ),
                    indent=2,
                )
            )
        elif args.command == "rollback":
            print(
                json.dumps(
                    call(
                        "rollback",
                        {
                            "project_id": args.project_id,
                            "approval_id": args.approval_id,
                            "digest": args.digest,
                            "acknowledge_data_restore": args.acknowledge_data_restore,
                        },
                        socket_path=args.socket,
                        timeout=1800,
                    ),
                    indent=2,
                )
            )
        elif args.command == "update-apply":
            params = {
                "project_id": args.project_id,
                "approval_id": args.approval_id,
                "digest": args.digest,
            }
            if args.emergency_confirm or args.reason:
                params.update(
                    emergency_confirm=args.emergency_confirm, emergency_reason=args.reason
                )
            print(
                json.dumps(
                    call("apply_verified_image", params, socket_path=args.socket, timeout=1800),
                    indent=2,
                )
            )
        elif args.command == "update-retention":
            retention = {"project_id": args.project} if args.project else {}
            print(
                json.dumps(
                    call("update_retention_status", retention, socket_path=args.socket),
                    indent=2,
                )
            )
        elif args.command == "config-apply":
            from . import __version__

            print(
                json.dumps(
                    call(
                        "config_apply",
                        {
                            "head_revision": args.head,
                            "applied_revision": args.applied,
                            "release": __version__,
                        },
                        socket_path=args.socket,
                    ),
                    indent=2,
                )
            )
        elif args.command == "inventory":
            if args.project:
                result = call(
                    "image_inventory", {"project_id": args.project}, socket_path=args.socket
                )
            else:
                from .core.inventory import collect

                inventory = collect(call, socket_path=args.socket)
                result = {
                    "revision": inventory.revision,
                    **inventory.model_dump(mode="json"),
                    "images": [
                        call("image_inventory", {"project_id": project}, socket_path=args.socket)
                        for project in inventory.projects
                    ],
                }
            print(json.dumps(result, indent=2))
        elif args.command == "verify":
            run_fields = (
                args.deployment_operation_id,
                args.deployment_run_id,
                args.deployment_boot_id,
            )
            guarded = any(value is not None for value in run_fields)
            if guarded:
                from .executor.site_deployment import ERRORS, Identity, require_verifier

                if not all(run_fields) or not args.expect_revision or args.socket != DEFAULT_SOCKET:
                    parser.error(
                        "guarded verification requires exact custody, revision and default socket"
                    )
                try:
                    require_verifier(Identity(*run_fields), args.expect_revision)
                except ERRORS as exc:
                    sys.exit(f"error: {exc}")
            status = call("platform_status", socket_path=args.socket)
            # A single probe decides here, so one failed health check already counts.
            failures = {pid: 10**6 for pid in status["projects"]}
            problems = [
                f"{f.severity}: {f.target}: {f.summary}"
                for f in evaluate(status, failures)
                if f.severity in ("high", "critical")
                and not (
                    guarded
                    and status.get("deployment_recovery") == "pending"
                    and f.id == "deployment_recovery"
                )
            ]
            if args.expect_revision and status["config_revision"] != args.expect_revision:
                problems.append("critical: applied configuration revision differs from expected")
            print("\n".join(problems) or "ok: platform verified")
            sys.exit(1 if problems else 0)
        elif args.command == "restart":
            result = call(
                "workload_restart",
                {"project_id": args.project_id, "reason": "operator via steward-host"},
                socket_path=args.socket,
            )
            print(json.dumps(result, indent=2))
        elif args.command == "maintenance-admit":
            result = call("maintenance_admit", {"work_id": args.work_id}, socket_path=args.socket)
            print(json.dumps(result, indent=2))
        elif args.command == "events":
            if args.coverage:
                print(json.dumps(call("events_coverage", socket_path=EVENT_SOCKET), indent=2))
                return
            params = {
                "project": args.project,
                "min_severity": args.min_severity,
                "kind_prefix": args.kind_prefix,
                "correlation_id": args.correlation_id,
                "since": time.time() - args.since_minutes * 60 if args.since_minutes else None,
                "limit": args.limit,
            }
            result = call(
                "events_query",
                {k: v for k, v in params.items() if v is not None},
                socket_path=EVENT_SOCKET,
            )
            for event in result["events"]:
                print(json.dumps(event, sort_keys=True))
            if result.get("truncated"):
                print(
                    "More events match; narrow the filters to view the remaining events.",
                    file=sys.stderr,
                )
        elif args.command == "record-deployment":
            if not re.fullmatch(r"[a-f0-9]{64}", args.revision) or not re.fullmatch(
                r"[A-Za-z0-9.+-]{1,40}", args.release
            ):
                sys.exit("error: invalid revision or release")
            AuditLog(AUDIT_PATH).append(
                "deployment", revision=args.revision, release=args.release, outcome="verified"
            )
        elif args.command == "audit-verify":
            ok, count = AuditLog(AUDIT_PATH).verify()
            print(f"{'ok' if ok else 'BROKEN'}: {count} valid records")
            sys.exit(0 if ok else 1)
        elif args.state == "status":
            print("on" if os.path.lexists(KILLSWITCH_PATH) else "off")
        elif args.state == "on":
            fd = os.open(KILLSWITCH_PATH, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            os.close(fd)
            AuditLog(AUDIT_PATH).append("kill_switch", state="on", by="operator")
            print("kill switch on: automatic mutations stopped, observation and audit continue")
        else:
            if os.path.lexists(KILLSWITCH_PATH):
                os.unlink(KILLSWITCH_PATH)
            AuditLog(AUDIT_PATH).append("kill_switch", state="off", by="operator")
            print("kill switch off")
    except ExecutorError as exc:
        sys.exit(f"error: {exc}")


if __name__ == "__main__":
    main()
