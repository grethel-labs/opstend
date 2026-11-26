import base64
import importlib.util
import ipaddress
import socket
import ssl
import threading
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

SPEC = importlib.util.spec_from_file_location(
    "readonly_proxy_fixture", Path(__file__).with_name("read_only_proxy.py")
)
proxy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proxy)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def servers(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    calls = []

    class Upstream(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            calls.append((self.command, self.path, self.headers.get("Authorization")))
            if self.path.endswith("/snapshots"):
                self.send_response(302)
                self.send_header("Location", "https://attacker.invalid/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"encrypted fixture data"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    upstream = ThreadingHTTPServer(("127.0.0.1", free_port()), Upstream)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert_path, key_path)
    upstream.socket = tls.wrap_socket(upstream.socket, server_side=True)
    reader, writer = (
        b"Basic " + base64.b64encode(b"reader:readonly"),
        b"Basic " + base64.b64encode(b"writer:upload"),
    )
    server = proxy.Server(free_port(), upstream.server_port, cert_path, reader, writer)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    threads = [
        threading.Thread(target=item.serve_forever, daemon=True) for item in (upstream, server)
    ]
    for thread in threads:
        thread.start()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(cert_path))),
    )
    try:
        yield server, opener, calls, reader, writer
    finally:
        server.shutdown()
        upstream.shutdown()
        server.server_close()
        upstream.server_close()
        for thread in threads:
            thread.join()


def test_read_only_proxy_forwards_only_authorized_safe_reads(servers):
    server, opener, calls, reader, writer = servers
    base = f"https://127.0.0.1:{server.server_port}"
    path = "/fixture/fixture/data/" + "a" * 64
    request = urllib.request.Request(base + path, headers={"Authorization": reader.decode()})  # noqa: S310 - fixed loopback HTTPS
    with opener.open(request, timeout=5) as response:
        assert response.read() == b"encrypted fixture data"
    assert calls == [("GET", path, writer.decode())]
    for method, suffix, auth, status in [
        ("GET", path, None, 401),
        ("GET", "/fixture/fixture/../secrets", reader, 400),
        ("GET", "/fixture/fixture/config?create=true", reader, 400),
        ("GET", "/fixture/fixture/unknown", reader, 400),
        ("POST", path, reader, 405),
        ("PUT", path, reader, 405),
        ("DELETE", path, reader, 405),
        ("PATCH", path, reader, 405),
    ]:
        headers = {"Authorization": auth.decode()} if auth else {}
        request = urllib.request.Request(base + suffix, method=method, headers=headers)  # noqa: S310 - fixed loopback HTTPS
        with pytest.raises(urllib.error.HTTPError) as exc:
            opener.open(request, timeout=5)
        assert exc.value.code == status
    assert len(calls) == 1
    redirect = urllib.request.Request(  # noqa: S310 - fixed loopback HTTPS
        base + "/fixture/fixture/snapshots", headers={"Authorization": reader.decode()}
    )
    with pytest.raises(urllib.error.HTTPError) as error:
        opener.open(redirect, timeout=5)
    assert error.value.code == 502 and error.value.headers.get("Location") is None
    assert len(calls) == 2


def test_proxy_credentials_must_be_private_regular_single_line_files(tmp_path):
    path = tmp_path / "credential"
    value = b"reader:" + b"x" * 48
    path.write_bytes(value)
    path.chmod(0o600)
    assert proxy.private_line(path) == b"Basic " + base64.b64encode(value)
    path.chmod(0o644)
    with pytest.raises(ValueError):
        proxy.private_line(path)
    path.chmod(0o600)
    path.write_bytes(b"reader:secret\nother")
    with pytest.raises(ValueError):
        proxy.private_line(path)
    path.unlink()
    path.symlink_to("/etc/passwd")
    with pytest.raises(OSError):
        proxy.private_line(path)


def test_proxy_rejects_same_password_for_reader_and_writer(tmp_path):
    reader = b"Basic " + base64.b64encode(b"reader:" + b"x" * 48)
    writer = b"Basic " + base64.b64encode(b"writer:" + b"x" * 48)
    port = free_port()
    upstream = port + 1 if port < 65535 else port - 1
    with pytest.raises(ValueError, match="separate"):
        proxy.Server(port, upstream, tmp_path / "unused", reader, writer)


def test_systemd_credential_requires_exact_root_owned_service_acl(tmp_path, monkeypatch):
    import struct
    from types import SimpleNamespace

    path = tmp_path / "reader"
    path.write_bytes(b"reader:" + b"r" * 48)
    path.chmod(0o440)
    actual = path.stat()
    fields = {
        name: getattr(actual, name)
        for name in ("st_mode", "st_uid", "st_gid", "st_nlink", "st_size")
    }
    fields.update(st_uid=0, st_gid=0)
    monkeypatch.setattr(proxy.os, "geteuid", lambda: 32123)
    monkeypatch.setattr(proxy.os, "fstat", lambda fd: SimpleNamespace(**fields))
    nobody = 0xFFFFFFFF
    acl = struct.pack("<I", 2) + b"".join(
        struct.pack("<HHI", *entry)
        for entry in (
            (1, 4, nobody),
            (2, 4, 32123),
            (4, 0, nobody),
            (16, 4, nobody),
            (32, 0, nobody),
        )
    )
    monkeypatch.setattr(proxy.os, "getxattr", lambda fd, name: acl)
    assert proxy.private_line(path).startswith(b"Basic ")
    valid_acl = acl
    acl = acl.replace(struct.pack("<HHI", 2, 4, 32123), struct.pack("<HHI", 2, 4, 32124))
    with pytest.raises(ValueError, match="unsafe private credential"):
        proxy.private_line(path)
    acl = valid_acl
    fields["st_gid"] = 32124
    with pytest.raises(ValueError, match="unsafe private credential"):
        proxy.private_line(path)
    fields["st_gid"] = 0
    fields["st_mode"] |= 0o004
    with pytest.raises(ValueError, match="unsafe private credential"):
        proxy.private_line(path)
