#!/usr/bin/env python3
"""Real disposable HTTPS Restic round-trip; no production or root data access."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
import secrets
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from http.server import ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from steward.adapters.backups import Restic
from steward.backupworker import Imports, Runner
from steward.core.backupexport import export_capture
from steward.core.backups import BackupError, Binding, capture_sqlite, database_check, private_json


def private(path, value):
    path.write_bytes(value if isinstance(value, bytes) else value.encode())
    path.chmod(0o600)
    return path


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--restic", type=Path, required=True)
    parser.add_argument("--rest-server", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("run this isolated fixture as an unprivileged user")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="steward-backup-test-") as directory:
        root = Path(directory)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.now(UTC)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        cert = private(root / "cert.pem", certificate.public_bytes(serialization.Encoding.PEM))
        tls_key = private(
            root / "key.pem",
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        auth = secrets.token_urlsafe(32)
        # Rest-server accepts bcrypt/SHA, not Apache MD5. This disposable
        # loopback-only fixture uses a freshly generated 256-bit password.
        hashed = "{SHA}" + base64.b64encode(hashlib.sha1(auth.encode()).digest()).decode()  # noqa: S324 -- disposable protocol fixture
        htpasswd = private(root / "htpasswd", "fixture:" + hashed + "\n")
        server_port = port()
        repository = private(
            root / "repo", f"rest:https://127.0.0.1:{server_port}/fixture/fixture/"
        )
        password = private(root / "password", secrets.token_urlsafe(48))
        username = private(root / "username", "fixture")
        auth_password = private(root / "auth-password", auth)
        server = subprocess.Popen(
            [
                str(args.rest_server.resolve()),
                "--listen",
                f"127.0.0.1:{server_port}",
                "--path",
                str(root / "remote-storage"),
                "--tls",
                "--tls-cert",
                str(cert),
                "--tls-key",
                str(tls_key),
                "--htpasswd-file",
                str(htpasswd),
                "--append-only",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        proxy_process = None
        try:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(cert))),
            )
            deadline = time.monotonic() + 10
            while True:
                try:
                    opener.open(
                        f"https://127.0.0.1:{server_port}/fixture/fixture/config", timeout=1
                    )
                    raise AssertionError("repository accepted unauthenticated request")
                except urllib.error.HTTPError as exc:
                    assert exc.code == 401
                    break
                except urllib.error.URLError:
                    if time.monotonic() > deadline or server.poll() is not None:
                        raise RuntimeError("fixture server unavailable") from None
                    time.sleep(0.05)
            source = root / "source.db"
            writer = sqlite3.connect(source)
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute(
                "CREATE TABLE notes (id INTEGER PRIMARY KEY, created_at REAL, text TEXT)"
            )
            marker = "private-note-" + secrets.token_hex(24)
            writer.execute("INSERT INTO notes VALUES (1,?,?)", (time.time(), marker))
            writer.commit()
            binding = Binding(
                server="fixture-server",
                project="notes",
                config_revision="a" * 64,
                image="docker.io/library/python@sha256:" + "b" * 64,
                source_revision="bundled:sample-notes@0.1.1",
            )
            capture = root / "capture"
            manifest = capture_sqlite(source, capture, binding)
            writer.close()
            adapter = Restic(
                repository_file=repository,
                password_file=password,
                state_dir=root / "state",
                username_file=username,
                auth_password_file=auth_password,
                ca_file=cert,
                binary=args.restic.resolve(),
            )
            initialized = adapter.initialize()
            receipt = adapter.backup(capture)
            retried = adapter.backup(capture)
            assert retried.snapshot_id == receipt.snapshot_id
            assert retried.snapshot_created_at == receipt.snapshot_created_at
            assert initialized["repository_id"] == receipt.repository_id
            assert receipt.integrity_checked_at is receipt.restore_verified_at is None
            checked = adapter.check(receipt)
            restored = adapter.restore_test(checked)
            assert (
                restored.restore_verified_at is not None and restored.application_verified is False
            )
            # Independent real application handler readback from a second empty restore target.
            target = root / "application-restore"
            target.mkdir()
            adapter._run(
                [
                    "restore",
                    receipt.snapshot_id + ":" + receipt.snapshot_path,
                    "--target",
                    str(target),
                    "--verify",
                ]
            )
            # Also exercise a complete quiescent tree, including non-database
            # files and empty directories. The sole writer was closed above.
            from steward.core.filebackups import capture_files

            tree = root / "whole-data"
            tree.mkdir()
            shutil.copyfile(target / manifest.filename, tree / "notes.db")
            attachment = ("attachment-" + marker).encode()
            attachment_id = hashlib.sha256(attachment).hexdigest()
            (tree / "attachments").mkdir()
            (tree / "attachments" / attachment_id).write_bytes(attachment)
            (tree / "empty").mkdir()
            tree_capture = root / "tree-capture"
            tree_manifest = capture_files(tree, tree_capture, binding, is_quiescent=lambda: True)
            imports = root / "imports"
            imports.mkdir(mode=0o750)
            imports.chmod(0o750)
            (imports / "notes").mkdir(mode=0o750)
            (imports / "notes").chmod(0o750)
            exported = imports / "notes" / ("e" * 32)
            assert (
                export_capture(tree_capture, exported, capture_id=tree_manifest.id, gid=os.getgid())
                == tree_manifest
            )
            assert exported.stat().st_mode & 0o777 == 0o550
            worker_state = root / "worker"
            worker = Runner(worker_state, Imports(imports, owner_uid=os.getuid()), adapter)
            outcome = worker.run_once()
            assert outcome["restored_bytes_verified"] and not outcome["application_verified"]
            tree_receipt = worker.jobs.receipt(initialized["repository_id"], tree_manifest.id)
            restarted = Runner(worker_state, Imports(imports, owner_uid=os.getuid()), adapter)
            assert restarted.run_once() is None
            assert tree_receipt.restore_verified_at is not None
            # A distinct credential can only read through a loopback TLS
            # proxy; the proxy alone holds the backend upload credential.
            proxy_port = port()
            if proxy_port == server_port:
                raise RuntimeError("fixture port collision")
            reader_password_value = secrets.token_urlsafe(32)
            reader_user = private(root / "reader-user", "reader")
            reader_password = private(root / "reader-password", reader_password_value)
            reader_pair = private(root / "reader-pair", "reader:" + reader_password_value)
            writer_pair = private(root / "writer-pair", "fixture:" + auth)
            reader_repository = private(
                root / "reader-repo", f"rest:https://127.0.0.1:{proxy_port}/fixture/fixture/"
            )
            proxy_script = Path(__file__).parent / "proxmox/read_only_proxy.py"
            proxy_process = subprocess.Popen(
                [
                    sys.executable,
                    str(proxy_script),
                    "--port",
                    str(proxy_port),
                    "--upstream-port",
                    str(server_port),
                    "--ca",
                    str(cert),
                    "--certificate",
                    str(cert),
                    "--key",
                    str(tls_key),
                    "--reader-credential",
                    str(reader_pair),
                    "--writer-credential",
                    str(writer_pair),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            proxy_base = f"https://127.0.0.1:{proxy_port}/fixture/fixture/"
            deadline = time.monotonic() + 10
            while True:
                try:
                    opener.open(proxy_base + "config", timeout=1)
                    raise AssertionError("proxy accepted unauthenticated request")
                except urllib.error.HTTPError as exc:
                    assert exc.code == 401
                    break
                except urllib.error.URLError:
                    if time.monotonic() > deadline or proxy_process.poll() is not None:
                        raise RuntimeError("read-only proxy unavailable") from None
                    time.sleep(0.05)
            reader_basic = base64.b64encode(("reader:" + reader_password_value).encode()).decode()
            write = urllib.request.Request(  # noqa: S310 - fixed loopback HTTPS fixture
                proxy_base + "config",
                data=b"forbidden",
                method="POST",
                headers={"Authorization": "Basic " + reader_basic},
            )
            try:
                opener.open(write, timeout=5)
                raise AssertionError("read-only proxy accepted a write")
            except urllib.error.HTTPError as exc:
                assert exc.code == 405
            # The client also refuses mutation commands and uses --no-lock.
            reader = Restic(
                repository_file=reader_repository,
                password_file=password,
                state_dir=root / "reader",
                username_file=reader_user,
                auth_password_file=reader_password,
                ca_file=cert,
                binary=args.restic.resolve(),
                read_only=True,
            )
            try:
                reader._run(["backup", str(tree_capture)])
                raise AssertionError("read-only client allowed a mutation command")
            except BackupError as exc:
                assert exc.error_class == "policy_denied"
            # Recreate and revalidate the whole tree in a private temporary
            # workspace before starting any sample application code.
            with reader.restored_tree(tree_receipt) as (restored_data, restored_manifest):
                assert restored_manifest == tree_manifest
                assert (restored_data / "empty").is_dir()
                assert (restored_data / "attachments" / attachment_id).read_bytes() == attachment
                database_check(restored_data / "notes.db")
                app_path = Path(__file__).resolve().parents[2] / "sample-app/sample-notes/app.py"
                spec = importlib.util.spec_from_file_location("restored_sample", app_path)
                app = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(app)
                app.DATA_DIR, app.DB_PATH = str(restored_data), str(restored_data / "notes.db")
                http = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
                thread = threading.Thread(target=http.serve_forever, daemon=True)
                thread.start()
                try:
                    address = f"http://127.0.0.1:{http.server_port}"
                    with opener.open(address + "/healthz", timeout=5) as response:
                        assert json.load(response)["status"] == "ok"
                    with opener.open(address + "/notes", timeout=5) as response:
                        assert json.load(response)[0]["text"] == marker
                    with opener.open(
                        address + "/attachments/" + attachment_id, timeout=5
                    ) as response:
                        assert response.read() == attachment
                finally:
                    http.shutdown()
                    http.server_close()
                    thread.join(5)
            assert not restored_data.exists()
            assert not any(
                marker.encode() in f.read_bytes()
                for f in (root / "remote-storage").rglob("*")
                if f.is_file()
            )
            result = {
                "passed": True,
                "scope": "disposable unprivileged HTTPS fixture; no production or new-VM restore",
                "restic_version": adapter.health()["version"],
                "capture_id": manifest.id,
                "snapshot_id": receipt.snapshot_id,
                "snapshot_idempotent": True,
                "full_data_check": True,
                "restore_sha_and_database_check": True,
                "restored_sample_http_readback": True,
                "restored_attachment_http_readback": True,
                "whole_quiescent_tree_roundtrip": True,
                "private_whole_tree_materialization": True,
                "read_only_client_commands": True,
                "separate_read_only_proxy_identity": True,
                "read_only_capture_export": True,
                "durable_upload_worker": True,
                "plaintext_absent_from_server": True,
                "application_authority_granted": False,
            }
            private_json(args.out, result)
            print(json.dumps(result))
        finally:
            if proxy_process is not None:
                proxy_process.terminate()
                try:
                    proxy_process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proxy_process.kill()
                    proxy_process.wait()
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(
            "backup fixture failed: "
            + type(exc).__name__
            + ":"
            + getattr(exc, "error_class", "unknown"),
            file=sys.stderr,
        )
        raise SystemExit(1) from None
