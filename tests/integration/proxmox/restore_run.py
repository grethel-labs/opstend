#!/usr/bin/env python3
"""Run one bound synthetic restore on an independently verified owned guest.

This fixture does not reset a VM, grant production restore authority, or prove
an independent physical failure domain. Credentials are sent over pinned SSH
stdin only. Preserve the private work directory to recover interrupted runs.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import importlib.util
import io
import json
import math
import os
import re
import secrets
import shlex
import stat
import subprocess
import sys
import tarfile
import uuid
from pathlib import Path

from steward.adapters.backups import credential_line
from steward.core.backups import BackupError, FilesystemCapture, Receipt
from steward.restore_drill import SOURCE_REVISION, SOURCE_SHA256, DrillSpec

HERE = Path(__file__).resolve().parent


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


harness = load_module("restore_vm_harness", HERE / "harness.py")
guest = load_module("restore_vm_guest", HERE / "restore_guest.py")
GUEST_CODE = (HERE / "restore_guest.py").read_bytes()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_file(path, *, maximum, private=True, executable=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or (info.st_mode & (0o077 if private else 0o022))
            or (executable and not info.st_mode & 0o100)
            or info.st_size > maximum
        ):
            raise ValueError("unsafe fixture input")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(maximum + 1)
        after = os.fstat(fd)
        if len(data) > maximum or (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("fixture input changed")
        return data
    finally:
        os.close(fd)


def private_dir(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("unsafe private work directory")


def write_new(path, data):
    guest.write_new(path, data)
    guest.sync_dir(path.parent)


def archive_commit(repo, commit):
    if not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit):
        raise ValueError("commit must be a full object ID")
    resolved = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "--verify", commit + "^{commit}"],
        text=True,
        timeout=30,
    ).strip()
    if resolved != commit:
        raise ValueError("commit identity mismatch")
    data = subprocess.check_output(
        ["git", "-C", str(repo), "archive", "--format=tar", commit], timeout=90
    )
    if len(data) > guest.MAX_ARCHIVE:
        raise ValueError("commit archive too large")
    return data


def archive_app_sha(data):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        matches = [item for item in archive if item.name == "sample-app/sample-notes/app.py"]
        if len(matches) != 1 or not matches[0].isfile() or matches[0].size > 1024 * 1024:
            raise ValueError("sample application absent from commit")
        stream = archive.extractfile(matches[0])
        if stream is None:
            raise ValueError("sample application unavailable")
        return digest(stream.read(1024 * 1024 + 1))


def check_fresh_proof(raw, target):
    try:
        proof = json.loads(raw)
        facts = proof["guest"]
        expected_paths = {
            "/etc/steward",
            "/opt/steward",
            "/srv/steward",
            "/var/lib/steward-executor",
            "/var/lib/steward-backup",
            "/var/lib/steward-backup-import",
        }
        expected_users = {"steward-backup", "steward-api", "stw-notes"}
        required = (
            "passed",
            "cloud_init_done",
            "fresh_strict_ssh",
            "node_identity_resource_guard",
            "no_application_or_restore_installed",
        )
        if (
            any(proof[name] is not True for name in required)
            or type(proof["vmid"]) is not int
            or proof["vmid"] != target.state["vmid"]
            or proof["new_uuid"] != harness.recorded_uuid(target.state["smbios1"])
            or facts["uuid"] != proof["new_uuid"]
            or str(uuid.UUID(proof["old_uuid"])) != proof["old_uuid"]
            or str(uuid.UUID(facts["boot_id"])) != facts["boot_id"]
            or proof["old_uuid"] == proof["new_uuid"]
            or set(facts["platform_paths_absent"]) != expected_paths
            or set(facts["platform_users_present"]) != expected_users
            or not all(value is True for value in facts["platform_paths_absent"].values())
            or not all(value is False for value in facts["platform_users_present"].values())
        ):
            raise ValueError("fresh proof mismatch")
        return facts["boot_id"]
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ValueError("invalid fresh guest proof") from None


def validate_binding(receipt_raw, spec_raw, app_sha):
    receipt = Receipt.model_validate_json(receipt_raw)
    spec = DrillSpec.model_validate_json(spec_raw)
    if (
        not isinstance(receipt.capture, FilesystemCapture)
        or receipt.integrity_checked_at is None
        or receipt.repository_id != spec.repository_id
        or receipt.snapshot_id != spec.snapshot_id
        or receipt.capture.id != spec.capture_id
        or receipt.capture.binding != spec.binding
        or spec.binding.source_revision != SOURCE_REVISION
        or spec.app_sha256 != SOURCE_SHA256
        or spec.app_sha256 != app_sha
    ):
        raise ValueError("receipt, specification or application mismatch")
    return receipt, spec


def proxy_inputs(path, target):
    private_dir(path)
    record = json.loads(read_file(path / "ownership.json", maximum=65536))
    if (
        record.get("alias") != target.state["alias"]
        or record.get("ssh_config") != target.state["ssh_config"]
    ):
        raise ValueError("proxy and guest node differ")
    username = read_file(path / "username", maximum=512)
    password = read_file(path / "auth-password", maximum=8192)
    certificate = read_file(path / "ca.pem", maximum=65536)
    repository = read_file(path / "repository", maximum=2048)
    if (
        not isinstance(record.get("port"), int)
        or not 1024 <= record["port"] <= 65535
        or repository != f"rest:https://10.0.2.2:{record['port']}/fixture/fixture/".encode()
        or digest(username + b":" + password) != record["file_sha256"]["reader"]
        or digest(certificate) != record["file_sha256"]["certificate.pem"]
    ):
        raise ValueError("proxy reader binding mismatch")
    output = subprocess.check_output(
        [sys.executable, str(HERE / "restore_proxy_harness.py"), "--workdir", str(path), "status"],
        text=True,
        timeout=90,
    )
    status = json.loads(output)
    if (
        status.get("namespace") != record["namespace"]
        or status.get("active") != "active"
        or status.get("probe", {}).get("unauthenticated") != 401
        or status.get("probe", {}).get("authenticated_read") != 200
        or status.get("probe", {}).get("write_refused") != 405
    ):
        raise ValueError("read-only proxy not verified")
    return record, {
        "repository": repository,
        "username": username,
        "auth-password": password,
        "ca.pem": certificate,
    }


def send(target, state, action, files=None):
    target.guest_identity(state["boot_id"])
    command = target._guest_command(
        int(target.state["local_port"]), "python3 -B -c " + shlex.quote(GUEST_CODE.decode("utf-8"))
    )
    payload = {"action": action, "state": state}
    if files is not None:
        payload["files"] = {name: base64.b64encode(value).decode() for name, value in files.items()}
    result = subprocess.run(
        command, input=json.dumps(payload), text=True, capture_output=True, timeout=720
    )
    if result.returncode:
        raise RuntimeError("guest operation failed; retain the work directory for guarded cleanup")
    try:
        return json.loads(result.stdout)
    except (ValueError, TypeError):
        raise RuntimeError(
            "invalid guest response; retain the work directory for cleanup"
        ) from None


def start(args):
    source_work, target_work, proxy_work = (
        path.resolve() for path in (args.source_workdir, args.target_workdir, args.proxy_workdir)
    )
    for path in (source_work, target_work, proxy_work):
        private_dir(path)
    source_record = json.loads(read_file(source_work / "ownership.json", maximum=65536))
    target_record = json.loads(read_file(target_work / "ownership.json", maximum=65536))
    source, target = harness.Harness(source_work), harness.Harness(target_work)
    if source.state != source_record or target.state != target_record:
        raise ValueError("VM ownership records changed")
    harness.owned_pair(source, target)
    source_identity = source.guest_identity(args.source_boot_id)
    proof_raw = read_file(args.fresh_proof, maximum=65536)
    boot = check_fresh_proof(proof_raw, target)
    receipt_raw = read_file(args.receipt, maximum=65536)
    spec_raw = read_file(args.spec, maximum=65536)
    archive = archive_commit(args.repo.resolve(), args.commit)
    receipt, spec = validate_binding(receipt_raw, spec_raw, archive_app_sha(archive))
    target_facts = target.guest_restore_preflight(boot, spec.binding.image)
    binary = read_file(args.restic_binary, maximum=guest.MAX_BINARY, private=False, executable=True)
    if (
        not re.fullmatch(r"[a-f0-9]{64}", args.restic_sha256)
        or digest(binary) != args.restic_sha256
    ):
        raise ValueError("restic binary hash mismatch")
    repository_password = read_file(args.password_file, maximum=8192)
    try:
        credential_line(repository_password, minimum=32)
    except BackupError:
        raise ValueError("invalid repository password") from None
    proxy, credentials = proxy_inputs(proxy_work, target)
    try:
        reader_password = credential_line(credentials["auth-password"], minimum=32)
        encryption_password = credential_line(repository_password, minimum=32)
    except BackupError:
        raise ValueError("invalid fixture credentials") from None
    if hmac.compare_digest(reader_password, encryption_password):
        raise ValueError("repository and reader passwords must differ")
    files = {
        **credentials,
        "password": repository_password,
        "archive": archive,
        "restic": binary,
        "receipt.json": receipt_raw,
        "spec.json": spec_raw,
    }
    state = {
        "v": 1,
        "token": secrets.token_hex(16),
        "uid": target_facts["uid"],
        "uuid": target_facts["uuid"],
        "boot_id": target_facts["boot_id"],
        "commit": args.commit,
        "files": {name: digest(value) for name, value in files.items()},
    }
    guest.validate_state(state)
    work = args.workdir.absolute()
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    private_dir(work)
    record = {
        "v": 1,
        "state": state,
        "target_workdir": str(target_work),
        "guest_code_sha256": digest(GUEST_CODE),
    }
    write_new(work / "ownership.json", json.dumps(record, sort_keys=True).encode())
    result = send(target, state, "run", files)
    report = result.get("report")
    if (
        result.get("workspace_removed") is not True
        or not isinstance(report, dict)
        or report.get("repository_id") != receipt.repository_id
        or report.get("snapshot_id") != receipt.snapshot_id
        or report.get("capture_id") != receipt.capture.id
        or report.get("binding") != spec.binding.model_dump(mode="json")
        or report.get("app_sha256") != spec.app_sha256
        or report.get("health") != "ok"
        or report.get("note_readback") is not True
        or report.get("attachment_readback") is not True
        or report.get("fresh_vm_proven") is not False
        or report.get("production_restore_authorized") is not False
        or type(report.get("bytes_verified_at")) not in (int, float)
        or type(report.get("application_verified_at")) not in (int, float)
        or not math.isfinite(report["bytes_verified_at"])
        or not math.isfinite(report["application_verified_at"])
        or report["bytes_verified_at"] < 0
        or report["application_verified_at"] < report["bytes_verified_at"]
    ):
        raise RuntimeError("guest report does not match the bound restore")
    evidence = {
        "v": 1,
        "source": source_identity,
        "target": target_facts,
        "fresh_proof_sha256": digest(proof_raw),
        "commit": args.commit,
        "archive_sha256": digest(archive),
        "restic_sha256": digest(binary),
        "proxy_namespace": proxy["namespace"],
        "reader_ca_sha256": digest(credentials["ca.pem"]),
        "receipt_sha256": digest(receipt_raw),
        "spec_sha256": digest(spec_raw),
        "report": report,
        "workspace_removed": True,
        "source_origin_attested": False,
        "physical_independent_failure_domain_proven": False,
        "production_restore_authorized": False,
        "scope": "owned guest restore; source origin is not attested and fresh proof is supplied by the operator",
    }
    write_new(work / "evidence.json", json.dumps(evidence, sort_keys=True, indent=2).encode())
    print(
        json.dumps(
            {"passed": True, "evidence": str(work / "evidence.json"), "workspace_removed": True}
        )
    )


def cleanup(args):
    work = args.workdir.absolute()
    private_dir(work)
    record = json.loads(read_file(work / "ownership.json", maximum=65536))
    if (
        set(record) != {"v", "state", "target_workdir", "guest_code_sha256"}
        or record["v"] != 1
        or record["guest_code_sha256"] != digest(GUEST_CODE)
    ):
        raise ValueError("recorded guest helper differs")
    state = guest.validate_state(record["state"])
    target_work = Path(record["target_workdir"])
    private_dir(target_work)
    result = send(harness.Harness(target_work), state, "cleanup")
    if result != {"cleaned": True}:
        raise ValueError("guest cleanup not confirmed")
    print(json.dumps({"cleaned": True}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    sub = parser.add_subparsers(dest="action", required=True)
    run_parser = sub.add_parser("run")
    for name in (
        "source-workdir",
        "target-workdir",
        "proxy-workdir",
        "fresh-proof",
        "receipt",
        "spec",
        "password-file",
        "repo",
        "restic-binary",
    ):
        run_parser.add_argument("--" + name, type=Path, required=True)
    for name in ("source-boot-id", "commit", "restic-sha256"):
        run_parser.add_argument("--" + name, required=True)
    sub.add_parser("cleanup")
    args = parser.parse_args()
    os.umask(0o077)
    if args.action == "run":
        start(args)
    else:
        cleanup(args)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
        raise SystemExit(
            "restore fixture failed; retain private work directory for guarded cleanup"
        ) from None
