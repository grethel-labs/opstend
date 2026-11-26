"""Operator-local consistent SQLite/Restic backups; no production restore authority."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .adapters.backups import Restic
from .core.backups import BackupError, Binding, Receipt, capture_sqlite, private_json, regular_file


def document(path, model):
    fd, _info = regular_file(path, limit=65536)
    with os.fdopen(fd, "rb") as handle:
        return model.model_validate_json(handle.read(65537))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    capture = sub.add_parser(
        "capture", help="online SQLite capture bound to operator-supplied metadata"
    )
    capture.add_argument("--database", type=Path, required=True)
    capture.add_argument("--binding", type=Path, required=True)
    capture.add_argument("--out-dir", type=Path, required=True)
    capture.add_argument("--max-mib", type=int, default=256)
    capture.add_argument("--timeout", type=int, default=180)
    for name in ("init", "backup", "check", "verify-bytes", "restore-test", "application-drill"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--repository-file", type=Path, required=True)
        cmd.add_argument("--password-file", type=Path, required=True)
        cmd.add_argument("--username-file", type=Path)
        cmd.add_argument("--auth-password-file", type=Path)
        cmd.add_argument("--ca-file", type=Path)
        cmd.add_argument("--state-dir", type=Path, required=True)
        cmd.add_argument("--restic-binary", type=Path)
        cmd.add_argument("--out", type=Path, required=True)
        if name == "backup":
            cmd.add_argument("--capture", type=Path, required=True)
        elif name in ("check", "verify-bytes", "restore-test", "application-drill"):
            cmd.add_argument("--receipt", type=Path, required=True)
        if name in ("restore-test", "application-drill"):
            cmd.add_argument("--spec", type=Path, required=True)
            cmd.add_argument("--app", type=Path, required=True)
    args = parser.parse_args()
    application_drill = args.command in ("application-drill", "restore-test")
    if os.geteuid() == 0:
        parser.error("run backup/capture/restore tests as an unprivileged user")
    os.umask(0o077)
    try:
        if args.command == "capture":
            manifest = capture_sqlite(
                args.database,
                args.out_dir,
                document(args.binding, Binding),
                max_bytes=args.max_mib * 1024 * 1024,
                timeout_s=args.timeout,
            )
            result = {
                "capture_id": manifest.id,
                "size": manifest.size,
                "origin": manifest.origin,
                "database_integrity": manifest.database_integrity,
            }
        else:
            if args.command == "backup" and args.out.resolve().is_relative_to(
                args.capture.resolve()
            ):
                raise BackupError("invalid_input")
            protected = [
                path
                for path in (
                    args.repository_file,
                    args.password_file,
                    args.username_file,
                    args.auth_password_file,
                    args.ca_file,
                    args.restic_binary,
                )
                if path is not None
            ]
            if application_drill:
                protected.extend((args.receipt, args.spec, args.app))
            if args.out.resolve() in {path.resolve() for path in protected}:
                raise BackupError("invalid_input")
            adapter = Restic(
                repository_file=args.repository_file,
                password_file=args.password_file,
                state_dir=args.state_dir,
                username_file=args.username_file,
                auth_password_file=args.auth_password_file,
                ca_file=args.ca_file,
                binary=args.restic_binary,
                read_only=application_drill or args.command == "verify-bytes",
            )
            if args.command == "init":
                result = adapter.initialize()
                private_json(args.out, result)
            elif application_drill:
                from .restore_drill import DrillSpec, PodmanSample, run_drill

                result = run_drill(
                    adapter,
                    document(args.receipt, Receipt),
                    document(args.spec, DrillSpec),
                    args.app,
                    PodmanSample(),
                )
                private_json(args.out, result)
            else:
                receipt = (
                    adapter.backup(args.capture)
                    if args.command == "backup"
                    else getattr(
                        adapter, "restore_test" if args.command == "verify-bytes" else "check"
                    )(document(args.receipt, Receipt))
                )
                private_json(args.out, receipt.model_dump(mode="json"))
                result = {
                    "snapshot_id": receipt.snapshot_id,
                    "capture_id": receipt.capture.id,
                    "integrity_checked": receipt.integrity_checked_at is not None,
                    "restored_data_verified": receipt.restore_verified_at is not None,
                    "application_verified": False,
                    "origin": receipt.capture.origin,
                }
        print(json.dumps(result))
    except BackupError as exc:
        sys.exit("backup operation failed: " + exc.error_class)
    except (ValueError, OSError, TypeError, KeyError):
        sys.exit("backup input/state error; result not replaced")


if __name__ == "__main__":
    main()
