"""OCI adapter contract exercised over disposable loopback TLS."""

import base64
import hashlib
import io
import ipaddress
import json
import os
import socket
import ssl
import tarfile
import time
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from stat import S_IMODE
from threading import Event, Thread
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from steward.adapters import oci_registry as registry_module
from steward.adapters.oci_registry import OciArtifactRegistry, RegistryError, RegistryRepository
from steward.core.artifact_validation import SbomComponent

MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
LAYER = "application/vnd.oci.image.layer.v1.tar"
INDEX = "application/vnd.oci.image.index.v1+json"


def digest(body):
    return "sha256:" + hashlib.sha256(body).hexdigest()


def image():
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tar:
        entry = tarfile.TarInfo("fixture")
        entry.size = 3
        tar.addfile(entry, io.BytesIO(b"oci"))
    layer = archive.getvalue()
    config = json.dumps(
        {
            "os": "linux",
            "architecture": "amd64",
            "rootfs": {"type": "layers", "diff_ids": [digest(layer)]},
        }
    ).encode()
    manifest = {
        "schemaVersion": 2,
        "mediaType": MANIFEST,
        "config": {"mediaType": CONFIG, "digest": digest(config), "size": len(config)},
        "layers": [{"mediaType": LAYER, "digest": digest(layer), "size": len(layer)}],
    }
    return json.dumps(manifest, indent=2).encode() + b"\n", {
        digest(config): config,
        digest(layer): layer,
    }


@dataclass
class Endpoint:
    name: str
    credentials: str
    repository: str = ""
    manifests: dict = field(default_factory=dict)
    blobs: dict = field(default_factory=dict)
    requests: list = field(default_factory=list)
    read_overrides: dict = field(default_factory=dict)
    upload_location: str | None = None
    redirect: str | None = None
    stall: Event | None = None
    chunked: bool = False
    reject_upload_for: str | None = None

    @property
    def prefix(self):
        return f"/v2/{self.name}"

    @property
    def upload_path(self):
        return f"{self.prefix}/blobs/uploads/fixture"

    @property
    def authorization(self):
        encoded = base64.b64encode(self.credentials.encode()).decode()
        return f"Basic {encoded}"

    def ref(self, manifest_digest):
        return f"{self.repository}@{manifest_digest}"


def tls_files(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OCI test fixture")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    x509.DNSName("source.registry.invalid"),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_file = tmp_path / "registry.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file = tmp_path / "registry-key.pem"
    with os.fdopen(os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    return cert_file, key_file


@contextmanager
def serve(endpoint, tls=None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def reply(self, status, body=b"", media=None, content_digest=None, location=None):
            self.send_response(status)
            if endpoint.chunked:
                self.send_header("Transfer-Encoding", "chunked")
            else:
                self.send_header("Content-Length", str(len(body)))
            if media:
                self.send_header("Content-Type", media)
            if content_digest:
                self.send_header("Docker-Content-Digest", content_digest)
            if location:
                self.send_header("Location", location)
            if endpoint.stall is not None:
                self.flush_headers()
                endpoint.stall.wait(3)
                with suppress(OSError):
                    self.end_headers()
                return
            self.end_headers()
            if self.command != "HEAD":
                if endpoint.chunked:
                    with suppress(OSError):
                        self.wfile.write(f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n")
                else:
                    self.wfile.write(body)

        def dispatch(self):
            endpoint.requests.append((self.command, self.path, self.headers.get("Authorization")))
            if self.headers.get("Authorization") != endpoint.authorization:
                return self.reply(401)

            path = urlsplit(self.path)
            if not path.path.startswith(f"{endpoint.prefix}/"):
                return self.reply(404)
            if self.command == "POST" and path.path == f"{endpoint.upload_path.rsplit('/', 1)[0]}/":
                return self.reply(202, location=endpoint.upload_location or endpoint.upload_path)

            group, _, identifier = path.path.removeprefix(f"{endpoint.prefix}/").partition("/")
            stores = {
                "manifests": (endpoint.manifests, MANIFEST),
                "blobs": (endpoint.blobs, "application/octet-stream"),
            }
            if self.command in {"GET", "HEAD"} and group in stores:
                if endpoint.redirect:
                    return self.reply(307, location=endpoint.redirect)
                store, media = stores[group]
                if identifier not in store:
                    return self.reply(404)
                body = endpoint.read_overrides.get((group, identifier), store[identifier])
                return self.reply(200, body, media, identifier)

            if self.command == "PUT":
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                if path.path == endpoint.upload_path:
                    expected = {"digest": [digest(body)]}
                    if endpoint.upload_location:
                        state = urlsplit(endpoint.upload_location).query
                        expected.update(parse_qs(state))
                        if not path.query.startswith(f"{state}&"):
                            return self.reply(400)
                    if parse_qs(path.query) != expected:
                        return self.reply(400)
                    blob_digest = digest(body)
                    if blob_digest == endpoint.reject_upload_for:
                        return self.reply(503)
                    endpoint.blobs[blob_digest] = body
                    return self.reply(201, content_digest=blob_digest)
                if group == "manifests" and identifier == digest(body) and not path.query:
                    if self.headers.get_content_type() != MANIFEST:
                        return self.reply(415)
                    endpoint.manifests[identifier] = body
                    return self.reply(201, content_digest=identifier)
            return self.reply(404)

        do_GET = do_HEAD = do_POST = do_PUT = dispatch

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        if tls is not None:
            server.socket = tls.wrap_socket(server.socket, server_side=True)
        endpoint.repository = f"127.0.0.1:{server.server_port}/{endpoint.name}"
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        thread.start()
        try:
            yield
        finally:
            server.shutdown()
            thread.join()


@dataclass
class RegistryFixture:
    source: Endpoint
    target: Endpoint
    adapter: OciArtifactRegistry
    manifest_digest: str
    make_adapter: partial[OciArtifactRegistry]

    @property
    def source_ref(self):
        return self.source.ref(self.manifest_digest)

    @property
    def target_ref(self):
        return self.target.ref(self.manifest_digest)

    def replace_manifest(self, body):
        self.manifest_digest = digest(body)
        self.source.manifests[self.manifest_digest] = body


@pytest.fixture
def oci_registry(tmp_path, monkeypatch):
    validator_uid = os.geteuid() or 12345
    if os.geteuid() == 0:
        monkeypatch.setattr(registry_module, "geteuid", lambda: validator_uid)
    source = Endpoint("staging/candidate", "fixture-reader:read-secret")
    target = Endpoint("production/accepted", "fixture-writer:write-secret")
    manifest, source.blobs = image()
    manifest_digest = digest(manifest)
    source.manifests[manifest_digest] = manifest
    cert_file, key_file = tls_files(tmp_path)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert_file, key_file)
    monkeypatch.setenv("STEWARD_TEST_OCI_SOURCE", source.credentials)
    target_secret = tmp_path / "target-auth"
    fd = os.open(target_secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as secret_file:
        secret_file.write(target.credentials)
    with ExitStack() as stack:
        stack.enter_context(serve(source, tls))
        stack.enter_context(serve(target, tls))
        source.repository = source.repository.replace("127.0.0.1:", "source.registry.invalid:", 1)
        make_adapter = partial(
            OciArtifactRegistry,
            source=RegistryRepository(
                source.repository, address="127.0.0.1", basic_auth_ref="env:STEWARD_TEST_OCI_SOURCE"
            ),
            target=RegistryRepository(target.repository, basic_auth_ref=f"file:{target_secret}"),
            validator_uid=validator_uid,
            ca_file=cert_file,
        )
        yield RegistryFixture(source, target, make_adapter(), manifest_digest, make_adapter)


@pytest.mark.parametrize("result", ["components", "empty", "unavailable"])
def test_inspect_inventories_exact_bytes_in_private_oci_layout(oci_registry, result):
    fixture = oci_registry
    manifest = fixture.source.manifests[fixture.manifest_digest]
    expected_blobs = {fixture.manifest_digest: manifest, **fixture.source.blobs}
    expected_sbom = {
        "components": [SbomComponent(ecosystem="npm", name="fixture", version="1.0.0")],
        "empty": [],
        "unavailable": None,
    }[result]
    layouts = []

    def inventory(layout):
        assert isinstance(layout, Path)
        layouts.append(layout)
        assert layout.is_dir() and not layout.is_symlink()
        assert S_IMODE(layout.stat().st_mode) == 0o700
        assert layout.stat().st_uid == os.geteuid()
        assert json.loads((layout / "oci-layout").read_bytes()) == {"imageLayoutVersion": "1.0.0"}
        index = json.loads((layout / "index.json").read_bytes())
        assert index["schemaVersion"] == 2
        (descriptor,) = index["manifests"]
        assert descriptor["mediaType"] == MANIFEST
        assert descriptor["digest"] == fixture.manifest_digest
        assert descriptor["size"] == len(manifest)
        blobs = layout / "blobs" / "sha256"
        assert {entry.name for entry in blobs.iterdir()} == {
            blob_digest.removeprefix("sha256:") for blob_digest in expected_blobs
        }
        for blob_digest, contents in expected_blobs.items():
            blob = blobs / blob_digest.removeprefix("sha256:")
            assert blob.is_file() and not blob.is_symlink()
            assert blob.read_bytes() == contents
        assert not any(entry.is_symlink() for entry in layout.rglob("*"))
        return expected_sbom

    facts = fixture.make_adapter(inventory=inventory).inspect(fixture.source_ref)

    assert facts.manifest_digest == fixture.manifest_digest
    assert facts.sbom == expected_sbom
    assert len(layouts) == 1
    assert not layouts[0].exists()
    assert not fixture.target.requests


@pytest.mark.parametrize("damaged", ["manifest", "config", "layer"])
def test_inspect_rejects_corrupt_bytes_before_inventory(oci_registry, damaged):
    fixture = oci_registry
    manifest = fixture.source.manifests[fixture.manifest_digest]
    if damaged == "manifest":
        group, key, body = "manifests", fixture.manifest_digest, manifest
    else:
        parsed = json.loads(manifest)
        descriptor = parsed["config"] if damaged == "config" else parsed["layers"][-1]
        group, key = "blobs", descriptor["digest"]
        body = fixture.source.blobs[key]
    fixture.source.read_overrides[group, key] = b"!" + body[1:]

    def inventory(_layout):
        pytest.fail("inventory ran before all digests were verified")

    with pytest.raises(RegistryError):
        fixture.make_adapter(inventory=inventory).inspect(fixture.source_ref)
    damaged_path = f"{fixture.source.prefix}/{group}/{key}"
    assert any(path == damaged_path for _, path, _ in fixture.source.requests)
    assert not fixture.target.requests


def test_inspect_and_copy_repeat(oci_registry):
    fixture = oci_registry
    target_authority = fixture.target.repository.split("/", 1)[0]
    fixture.target.upload_location = (
        f"https://{target_authority}{fixture.target.upload_path}?_state=signed%2Dtoken%3D"
    )
    facts = fixture.adapter.inspect(fixture.source_ref)
    assert facts.manifest_digest == fixture.manifest_digest
    assert facts.sbom is None
    assert facts.signature is None
    assert facts.base_images == []
    assert not fixture.target.requests

    assert fixture.adapter.copy(fixture.source_ref, fixture.target_ref) == fixture.manifest_digest
    assert fixture.target.manifests == fixture.source.manifests
    assert fixture.target.blobs == fixture.source.blobs
    first_requests = list(fixture.target.requests)
    assert sum(method == "POST" for method, *_ in first_requests) == len(fixture.source.blobs)
    manifest_path = f"{fixture.target.prefix}/manifests/{fixture.manifest_digest}"
    manifest_write = next(
        i for i, item in enumerate(first_requests) if item[:2] == ("PUT", manifest_path)
    )
    assert any(item[:2] == ("GET", manifest_path) for item in first_requests[manifest_write + 1 :])
    for blob_digest in fixture.source.blobs:
        blob_path = f"{fixture.target.prefix}/blobs/{blob_digest}"
        upload = next(
            i
            for i, (method, path, _) in enumerate(first_requests)
            if method == "PUT" and parse_qs(urlsplit(path).query).get("digest") == [blob_digest]
        )
        assert upload < manifest_write
        assert any(item[:2] == ("GET", blob_path) for item in first_requests[upload + 1 :])

    assert fixture.adapter.copy(fixture.source_ref, fixture.target_ref) == fixture.manifest_digest
    assert all(method != "POST" for method, *_ in fixture.target.requests[len(first_requests) :])
    for endpoint in (fixture.source, fixture.target):
        assert endpoint.requests
        assert all(auth == endpoint.authorization for _, _, auth in endpoint.requests)


@pytest.mark.parametrize(
    "damage", ["manifest_digest", "json", "index", "descriptor_size", "config_blob", "layer_blob"]
)
def test_copy_rejects_bad_source_before_target_writes(oci_registry, damage):
    fixture = oci_registry
    original = fixture.source.manifests[fixture.manifest_digest]
    manifest = json.loads(original)
    if damage == "manifest_digest":
        fixture.source.manifests[fixture.manifest_digest] = original + b" "
    elif damage == "json":
        fixture.replace_manifest(b"{")
    elif damage == "index":
        fixture.replace_manifest(
            json.dumps({"schemaVersion": 2, "mediaType": INDEX, "manifests": []}).encode()
        )
    elif damage == "descriptor_size":
        manifest["config"]["size"] += 1
        fixture.replace_manifest(json.dumps(manifest).encode())
    else:
        descriptor = manifest["config"] if damage == "config_blob" else manifest["layers"][0]
        blob = fixture.source.blobs[descriptor["digest"]]
        fixture.source.blobs[descriptor["digest"]] = b"!" + blob[1:]

    with pytest.raises(RegistryError):
        fixture.adapter.copy(fixture.source_ref, fixture.target_ref)
    assert all(method not in {"PUT", "POST"} for method, *_ in fixture.target.requests)


@pytest.mark.parametrize("damage", ["existing_blob", "uploaded_blob", "manifest"])
def test_copy_rejects_corrupt_target(oci_registry, damage):
    fixture = oci_registry
    blob_digest = next(iter(fixture.source.blobs))
    if damage == "existing_blob":
        fixture.target.blobs[blob_digest] = b"corrupt"
    elif damage == "uploaded_blob":
        fixture.target.read_overrides["blobs", blob_digest] = b"corrupt"
    else:
        fixture.target.read_overrides["manifests", fixture.manifest_digest] = b"corrupt"

    with pytest.raises(RegistryError):
        fixture.adapter.copy(fixture.source_ref, fixture.target_ref)


@pytest.mark.parametrize(
    "bad_ref", ["source_repo", "target_repo", "target_digest", "source_tag", "target_tag"]
)
def test_copy_rejects_unbound_refs_without_requests(oci_registry, bad_ref):
    fixture = oci_registry
    source_ref, target_ref = fixture.source_ref, fixture.target_ref
    if bad_ref == "source_repo":
        source_ref = fixture.target_ref
    elif bad_ref == "target_repo":
        target_ref = fixture.source_ref
    elif bad_ref == "target_digest":
        target_ref = fixture.target.ref(digest(b"different manifest"))
    elif bad_ref == "source_tag":
        source_ref = f"{fixture.source.repository}:latest"
    else:
        target_ref = f"{fixture.target.repository}:latest"
    with pytest.raises(RegistryError):
        fixture.adapter.copy(source_ref, target_ref)
    assert not fixture.source.requests
    assert not fixture.target.requests


def test_inspect_refuses_redirect(oci_registry):
    fixture = oci_registry
    host = fixture.target.repository.split("/", 1)[0]
    fixture.source.redirect = f"https://{host}{fixture.target.prefix}/redirect"
    with pytest.raises(RegistryError):
        fixture.adapter.inspect(fixture.source_ref)
    assert len(fixture.source.requests) == 1
    assert not fixture.target.requests


@pytest.mark.parametrize("kind", ["cross_origin", "path", "query"])
def test_copy_rejects_hostile_upload_location(oci_registry, kind):
    fixture = oci_registry
    source_port = fixture.source.repository.split("/", 1)[0].split(":", 1)[1]
    source_host = f"127.0.0.1:{source_port}"
    fixture.target.upload_location = {
        "cross_origin": f"https://{source_host}{fixture.target.upload_path}",
        "path": f"{fixture.target.prefix}/manifests/fixture",
        "query": f"{fixture.target.upload_path}?digest={digest(b'unrelated')}",
    }[kind]
    with pytest.raises(RegistryError):
        fixture.adapter.copy(fixture.source_ref, fixture.target_ref)
    assert any(method == "POST" for method, *_ in fixture.target.requests)
    assert all(method in {"GET", "HEAD", "POST"} for method, *_ in fixture.target.requests)
    assert all(
        method in {"GET", "HEAD"} and auth == fixture.source.authorization
        for method, _, auth in fixture.source.requests
    )
    assert all(auth == fixture.target.authorization for _, _, auth in fixture.target.requests)


def test_copy_refuses_plaintext_upload_location(oci_registry):
    fixture = oci_registry
    sink = Endpoint(fixture.target.name, fixture.target.credentials)
    with serve(sink):
        host = sink.repository.split("/", 1)[0]
        fixture.target.upload_location = f"http://{host}{sink.upload_path}"
        with pytest.raises(RegistryError):
            fixture.adapter.copy(fixture.source_ref, fixture.target_ref)
    assert any(method == "POST" for method, *_ in fixture.target.requests)
    assert not sink.requests


@pytest.mark.parametrize("current_uid", [0, 65432])
def test_operations_require_bound_nonroot_uid(oci_registry, monkeypatch, current_uid):
    fixture = oci_registry
    if registry_module.geteuid() == current_uid:
        current_uid += 1
    monkeypatch.setattr(registry_module, "geteuid", lambda: current_uid)
    with pytest.raises(RegistryError):
        fixture.adapter.inspect(fixture.source_ref)
    with pytest.raises(RegistryError):
        fixture.adapter.copy(fixture.source_ref, fixture.target_ref)
    assert not fixture.source.requests
    assert not fixture.target.requests


@pytest.mark.parametrize("target_auth_ref", [None, "env:STEWARD_TEST_OCI_SOURCE"])
def test_target_requires_distinct_credential_reference(target_auth_ref):
    source = RegistryRepository(
        "127.0.0.1:5001/staging/candidate", basic_auth_ref="env:STEWARD_TEST_OCI_SOURCE"
    )
    target = RegistryRepository(
        "127.0.0.1:5002/production/accepted", basic_auth_ref=target_auth_ref
    )
    with pytest.raises(RegistryError):
        OciArtifactRegistry(source=source, target=target, validator_uid=12345)


@pytest.fixture
def registry_candidate(oci_registry, tmp_path):
    from artifact_testkit import build_candidate
    from repo_testkit import Upstream
    from steward.core.builder import BackendOutcome

    fixture = oci_registry
    fetch_root, build_root = tmp_path / "fetch", tmp_path / "build"
    fetch_root.mkdir(mode=0o700)
    build_root.mkdir(mode=0o700)
    request, record = build_candidate(
        Upstream(tmp_path),
        fetch_root,
        build_root,
        files={
            "package-lock.json": json.dumps(
                {"packages": {"node_modules/locked-fixture": {"version": "2.0.0"}}}
            )
        },
        outcome=BackendOutcome("succeeded", "", fixture.manifest_digest, fixture.source_ref),
    )
    return request, record, build_root


@pytest.mark.parametrize("require_signature", [False, True])
def test_validator_requires_independent_evidence(
    oci_registry, tmp_path, registry_candidate, require_signature
):
    from artifact_testkit import make_validator
    from steward.core.artifact_validation import OriginPolicy
    from update_support import NOW, contract

    fixture = oci_registry
    request, record, build_root = registry_candidate
    validator, _ = make_validator(
        tmp_path / "validate",
        build_root,
        registry=fixture.adapter,
        origin=OriginPolicy(require_signature=require_signature),
    )
    report = validator.validate(
        request,
        record,
        project="shop",
        version="1.4.0",
        policy=contract(repository=fixture.target.repository),
        now=NOW,
    )
    expected = ["inventory:no_sbom"]
    if require_signature:
        expected.insert(0, "origin_policy:signature_missing_or_invalid")
    assert report.failed == expected
    assert not report.accepted and report.attestation is None
    assert report.authorizes == []
    assert not fixture.target.requests


def test_validator_uses_registry_inventory_for_scan_and_promotion(
    oci_registry, tmp_path, registry_candidate
):
    from artifact_testkit import make_validator
    from update_support import NOW, contract

    fixture = oci_registry
    request, record, build_root = registry_candidate
    component = SbomComponent(ecosystem="npm", name="inventory-fixture", version="1.0.0")
    layouts = []

    def inventory(layout):
        layouts.append(layout)
        return [component]

    validator, used = make_validator(
        tmp_path / "validate", build_root, registry=fixture.make_adapter(inventory=inventory)
    )
    report = validator.validate(
        request,
        record,
        project="shop",
        version="1.4.0",
        policy=contract(repository=fixture.target.repository),
        now=NOW,
    )

    assert report.accepted, report.failed
    assert report.attestation is not None
    assert report.image == fixture.target_ref
    assert used["probe"].calls == [False, True]
    assert {
        (subject.ecosystem, subject.name, subject.version)
        for subject in used["scanner"].subjects
        if subject.kind == "dependency"
    } == {
        (component.ecosystem, component.name, component.version),
        ("npm", "locked-fixture", "2.0.0"),
    }
    assert fixture.target.manifests == fixture.source.manifests
    assert fixture.target.blobs == fixture.source.blobs
    assert len(layouts) == 1
    assert not layouts[0].exists()


def test_read_deadline_includes_incomplete_headers(oci_registry, monkeypatch):
    fixture = oci_registry
    fixture.source.stall = Event()
    monkeypatch.setattr(registry_module, "_OPERATION_TIMEOUT", 0.25)
    started = time.monotonic()
    try:
        with pytest.raises(RegistryError, match="deadline"):
            fixture.adapter.inspect(fixture.source_ref)
    finally:
        fixture.source.stall.set()
    assert time.monotonic() - started < 2
    assert len(fixture.source.requests) == 1
    assert not fixture.target.requests


def test_copy_rejects_blob_budget_before_reading_blobs(oci_registry, monkeypatch):
    fixture = oci_registry
    monkeypatch.setattr(registry_module, "_MAX_ARTIFACT_BYTES", 512)
    with pytest.raises(RegistryError, match="size limit"):
        fixture.adapter.copy(fixture.source_ref, fixture.target_ref)
    assert len(fixture.source.requests) == 1
    assert not fixture.target.requests


def test_pinned_ip_still_requires_the_configured_tls_hostname(oci_registry, tmp_path):
    fixture = oci_registry
    repository = fixture.source.repository.replace("source.registry.invalid", "other.invalid", 1)
    adapter = OciArtifactRegistry(
        source=RegistryRepository(repository, address="127.0.0.1"),
        target=RegistryRepository(fixture.target.repository, basic_auth_ref="env:UNUSED"),
        ca_file=tmp_path / "registry.pem",
        validator_uid=registry_module.geteuid(),
    )
    with pytest.raises(RegistryError):
        adapter.inspect(f"{repository}@{fixture.manifest_digest}")
    assert not fixture.source.requests
    assert not fixture.target.requests


def test_transport_deadline_interrupt_keeps_tls_state():
    client, peer = socket.socketpair()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with (
        client,
        peer,
        context.wrap_socket(
            client, server_hostname="registry.invalid", do_handshake_on_connect=False
        ) as wire,
    ):
        tls_state = wire._sslobj
        assert tls_state is not None
        registry_module._interrupt(wire)
        assert wire._sslobj is tls_state
        assert peer.recv(1) == b""


def test_inspect_requires_length_framing(oci_registry):
    fixture = oci_registry
    fixture.source.chunked = True
    with pytest.raises(RegistryError, match="framing"):
        fixture.adapter.inspect(fixture.source_ref)
    assert not fixture.target.requests


def test_copy_retry_reuses_a_verified_blob_after_interruption(oci_registry):
    fixture = oci_registry
    config, layer = fixture.source.blobs
    fixture.target.reject_upload_for = layer
    with pytest.raises(RegistryError, match="blob upload failed"):
        fixture.adapter.copy(fixture.source_ref, fixture.target_ref)
    assert fixture.target.blobs == {config: fixture.source.blobs[config]}
    assert not fixture.target.manifests
    first_attempt_count = len(fixture.target.requests)
    assert sum(method == "POST" for method, *_ in fixture.target.requests) == 2

    fixture.target.reject_upload_for = None
    assert fixture.adapter.copy(fixture.source_ref, fixture.target_ref) == fixture.manifest_digest
    assert fixture.target.blobs == fixture.source.blobs
    assert (
        sum(method == "POST" for method, *_ in fixture.target.requests[first_attempt_count:]) == 1
    )
