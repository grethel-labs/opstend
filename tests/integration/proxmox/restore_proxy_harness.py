#!/usr/bin/env python3
"""Guard one disposable TLS read-only proxy on an owned Proxmox test node."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shlex
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# Root on the test node receives this fixed program and JSON payload through stdin.
REMOTE = Path(__file__).with_name("proxy_guard.py").read_text(encoding="utf-8")


def private(path: Path, value: bytes):
    with path.open("xb") as handle:
        handle.write(value)
    path.chmod(0o600)


def read_owned(path: Path, *, maximum=65536) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
            or info.st_size > maximum
        ):
            raise ValueError("unsafe private input")
        with os.fdopen(os.dup(fd), "rb") as handle:
            return handle.read(maximum + 1)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    sub = parser.add_subparsers(dest="action", required=True)
    start = sub.add_parser("start")
    start.add_argument("--upstream-workdir", type=Path, required=True)
    start.add_argument("--port", type=int, required=True)
    sub.add_parser("status")
    sub.add_parser("cleanup")
    args = parser.parse_args()
    os.umask(0o077)
    work = args.workdir.resolve()
    if args.action == "start":
        upstream = args.upstream_workdir.resolve()
        info = upstream.lstat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            parser.error("unsafe upstream work directory")
        state = json.loads(read_owned(upstream / "ownership.json"))
        if (
            not re.fullmatch(r"stw-rest-test-[0-9a-f]{24}", state["namespace"])
            or not re.fullmatch(r"[0-9a-f]{64}", state["token"])
            or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", state["alias"])
            or not 1024 <= args.port <= 65535
            or args.port == state["port"]
        ):
            parser.error("invalid fixture ownership or port")
        username = read_owned(upstream / "username", maximum=512)
        writer_password = read_owned(upstream / "auth-password", maximum=8192)
        upstream_ca = read_owned(upstream / "cert.pem")
        if (
            not re.fullmatch(rb"[A-Za-z0-9_-]{1,64}", username)
            or not 32 <= len(writer_password) <= 512
            or any(byte < 33 or byte > 126 or byte == 58 for byte in writer_password)
        ):
            parser.error("invalid upstream fixture credentials")
        try:
            x509.load_pem_x509_certificate(upstream_ca)
        except ValueError:
            parser.error("invalid upstream fixture certificate")
        reader_password = secrets.token_urlsafe(48).encode()
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "steward-read-fixture")])
        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(hours=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ("127.0.0.1", "10.0.2.2")]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        proxy_code = Path(__file__).with_name("read_only_proxy.py").read_bytes()
        files = {
            "proxy.py": proxy_code,
            "certificate.pem": cert.public_bytes(serialization.Encoding.PEM),
            "key.pem": key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            "upstream-ca.pem": upstream_ca,
            "reader": b"reader:" + reader_password,
            "writer": username + b":" + writer_password,
        }
        work.mkdir(mode=0o700, parents=True, exist_ok=False)
        private(work / "username", b"reader")
        private(work / "auth-password", reader_password)
        private(work / "ca.pem", files["certificate.pem"])
        private(work / "repository", f"rest:https://10.0.2.2:{args.port}/fixture/fixture/".encode())
        record = {
            "namespace": "stw-read-test-" + secrets.token_hex(12),
            "token": secrets.token_hex(32),
            "port": args.port,
            "upstream_port": state["port"],
            "ssh_config": state["ssh_config"],
            "alias": state["alias"],
            "upstream_namespace": state["namespace"],
            "upstream_token": state["token"],
            "proxy_sha256": hashlib.sha256(proxy_code).hexdigest(),
            "guard_sha256": hashlib.sha256(REMOTE.encode()).hexdigest(),
            "file_sha256": {
                name: hashlib.sha256(value).hexdigest() for name, value in files.items()
            },
        }
        private(work / "ownership.json", json.dumps(record).encode())
        payload = {
            **record,
            "files": {name: base64.b64encode(value).decode() for name, value in files.items()},
        }
    else:
        info = work.lstat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            parser.error("unsafe private work directory")
        payload = json.loads(read_owned(work / "ownership.json"))
        if payload.get("guard_sha256") != hashlib.sha256(REMOTE.encode()).hexdigest():
            parser.error("fixture guard changed; use the recorded source version")
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", payload["alias"]):
        parser.error("invalid fixture SSH alias")
    payload["action"] = args.action
    result = subprocess.run(
        [
            "ssh",
            "-F",
            payload["ssh_config"],
            "-o",
            "StrictHostKeyChecking=yes",
            payload["alias"],
            "python3 -c " + shlex.quote(REMOTE),
        ],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        timeout=120,
    )
    if result.returncode:
        raise SystemExit("proxy fixture failed; inspect its guarded private state")
    response = json.loads(result.stdout)
    private(
        work / (args.action + "-" + secrets.token_hex(4) + ".json"),
        json.dumps(response, indent=2).encode(),
    )
    print(json.dumps(response, indent=2))


if __name__ == "__main__":
    main()
