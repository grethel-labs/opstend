"""Digest-pinned registry access for the independent R04 validator."""

from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import time
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import dataclass, field
from os import geteuid
from pathlib import Path
from tempfile import TemporaryDirectory, TemporaryFile
from threading import Timer
from typing import BinaryIO, TypeVar
from urllib.parse import unquote_to_bytes

from pydantic import TypeAdapter, ValidationError

from steward.core import secrets
from steward.core.artifact_validation import ArtifactFacts, SbomComponent
from steward.core.builder import DIGEST
from steward.core.config import SecretRef

from .image_inventory import TrivyImageInventory

_OCI = "application/vnd.oci.image.manifest.v1+json"
_DOCKER = "application/vnd.docker.distribution.manifest.v2+json"
_CONFIG_TYPES = {
    _OCI: "application/vnd.oci.image.config.v1+json",
    _DOCKER: "application/vnd.docker.container.image.v1+json",
}
_LAYER_TYPES = {
    _OCI: {
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.oci.image.layer.v1.tar+zstd",
    },
    _DOCKER: {
        "application/vnd.docker.image.rootfs.diff.tar",
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
    },
}
# The budget includes all descriptors, even when a digest is repeated.
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_MAX_DESCRIPTORS = 128
_MAX_BLOB_BYTES = 1024**3
_MAX_ARTIFACT_BYTES = 2 * 1024**3
_CHUNK_BYTES = 64 * 1024
_MAX_LOCATION_BYTES = 8192
_MAX_QUERY_BYTES = 4096
_IO_TIMEOUT = 10.0
_OPERATION_TIMEOUT = 300.0

_NAME_PART = r"[a-z0-9]+(?:(?:[.]|__?|-+)[a-z0-9]+)*"
_NAME = re.compile(rf"{_NAME_PART}(?:/{_NAME_PART})*")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII | re.I)
_AUTHORITY = re.compile(r"(\[[0-9a-fA-F:.]+\]|[a-zA-Z0-9.-]+)(?::([1-9][0-9]{0,4}))?")
_SESSION = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._~-]{0,255}")
_QUERY_KEY = re.compile(r"[A-Za-z0-9_.~-]{1,64}")
_QUERY_VALUE = re.compile(r"(?:[A-Za-z0-9._~-]|%[0-9a-fA-F]{2})+(?:=|%3[dD]){0,2}")
_DECODED_VALUE = re.compile(rb"[A-Za-z0-9._~-]+={0,2}")
_SECRET_REF = TypeAdapter(SecretRef)
_T = TypeVar("_T")


class RegistryError(RuntimeError):
    """A registry operation failed with a message safe to report."""


def _authority(value: str) -> tuple[str, int]:
    match = _AUTHORITY.fullmatch(value)
    if not match:
        raise RegistryError("invalid registry authority")
    host, port_text = match.groups()
    port = int(port_text) if port_text else 443
    if port > 65535:
        raise RegistryError("invalid registry port")
    if host.startswith("["):
        try:
            address = ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            raise RegistryError("invalid registry address") from None
        if address.ipv4_mapped is not None:
            raise RegistryError("ambiguous registry address")
        return f"[{address.compressed}]", port
    host = host.lower()
    if len(host) > 253 or not all(_DNS_LABEL.fullmatch(label) for label in host.split(".")):
        raise RegistryError("invalid registry hostname")
    # libc accepts alternate IPv4 spellings, including octal and short forms.
    try:
        packed = socket.inet_aton(host)
    except OSError:
        if host.rsplit(".", 1)[-1].isdigit():
            raise RegistryError("ambiguous registry address") from None
    else:
        if socket.inet_ntoa(packed) != host:
            raise RegistryError("ambiguous registry address")
    return host, port


@dataclass(frozen=True)
class RegistryRepository:
    """A registry repository and its HTTPS route.

    A DNS name requires a configured IP address. The name remains the TLS and
    HTTP authority. An optional secret reference resolves to a Basic user:password.
    """

    repository: str
    basic_auth_ref: str | None = field(default=None, kw_only=True, repr=False)
    address: str | None = field(default=None, kw_only=True)
    _address: ipaddress.IPv4Address | ipaddress.IPv6Address = field(init=False, repr=False)
    _origin: tuple[str, int] = field(init=False, repr=False)
    _api_path: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.repository, str) or len(self.repository) > 255:
            raise RegistryError("invalid registry repository")
        authority, _, name = self.repository.partition("/")
        if not _NAME.fullmatch(name):
            raise RegistryError("invalid registry repository")
        host, port = _authority(authority)
        address = self.address if self.address is not None else host.strip("[]")
        try:
            if not isinstance(address, str) or "%" in address:
                raise ValueError
            pinned = ipaddress.ip_address(address)
        except ValueError:
            raise RegistryError("registry requires a pinned IP address") from None
        if pinned.is_unspecified or pinned.is_multicast or getattr(pinned, "ipv4_mapped", None):
            raise RegistryError("invalid pinned registry address")
        try:
            literal = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            literal = None
        if literal is not None and literal != pinned:
            raise RegistryError("registry literal and pinned address differ")
        object.__setattr__(self, "_origin", (host, port))
        object.__setattr__(self, "_address", pinned)
        object.__setattr__(self, "_api_path", f"/v2/{name}")
        if self.basic_auth_ref is not None:
            try:
                _SECRET_REF.validate_python(self.basic_auth_ref, strict=True)
            except ValidationError:
                raise RegistryError("invalid registry credential reference") from None
            if any(ord(char) < 32 or ord(char) == 127 for char in self.basic_auth_ref):
                raise RegistryError("invalid registry credential reference")

    def _digest(self, ref: str) -> str:
        if isinstance(ref, str):
            repository, _, digest = ref.partition("@")
            if repository == self.repository and DIGEST.fullmatch(digest):
                return digest
        raise RegistryError("image reference must name the configured repository and digest")

    def _authorization(self) -> str | None:
        if self.basic_auth_ref is None:
            return None
        try:
            value = secrets.resolve(self.basic_auth_ref)
            username, _, password = value.partition(":")
            if (
                not username
                or not password
                or len(value) > 4096
                or any(ord(char) < 32 or ord(char) == 127 for char in value)
            ):
                raise RegistryError("invalid registry credential")
            return "Basic " + base64.b64encode(value.encode("utf-8")).decode("ascii")
        except (secrets.SecretError, OSError, ValueError):
            raise RegistryError("could not resolve registry credential") from None


def _tls_context(ca_file: Path | None) -> ssl.SSLContext:
    # The default context helper honors SSL_CERT_* and SSLKEYLOGFILE.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if ca_file is not None:
        context.load_verify_locations(cafile=os.fspath(ca_file))
    else:
        defaults = ssl.get_default_verify_paths()
        cafile = defaults.openssl_cafile
        capath = defaults.openssl_capath
        context.load_verify_locations(
            cafile=cafile if cafile and os.path.isfile(cafile) else None,
            capath=capath if capath and os.path.isdir(capath) else None,
        )
    return context


def _header(response: http.client.HTTPResponse, name: str) -> str | None:
    values = response.headers.get_all(name, [])
    if len(values) > 1:
        raise RegistryError("registry returned an ambiguous header")
    return values[0] if values else None


def _check_digest_header(response: http.client.HTTPResponse, digest: str) -> None:
    header = _header(response, "Docker-Content-Digest")
    if header is not None and header != digest:
        raise RegistryError("registry digest header mismatch")


def _upload_path(repo: RegistryRepository, location: str | None, digest: str) -> str:
    if (
        not location
        or len(location) > _MAX_LOCATION_BYTES
        or any(not 33 <= ord(char) <= 126 for char in location)
        or "#" in location
        or "\\" in location
    ):
        raise RegistryError("invalid registry upload location")
    if location.startswith("https://"):
        authority, slash, remainder = location[8:].partition("/")
        if not slash or _authority(authority) != repo._origin:
            raise RegistryError("registry upload location changed origin")
        location = "/" + remainder
    path, question, query = location.partition("?")
    prefix = f"{repo._api_path}/blobs/uploads/"
    if (
        not path.startswith(prefix)
        or not _SESSION.fullmatch(path[len(prefix) :])
        or (question and not 0 < len(query) <= _MAX_QUERY_BYTES)
    ):
        raise RegistryError("invalid registry upload location")
    if question:
        seen = set()
        for parameter in query.split("&"):
            key, _, value = parameter.partition("=")
            if (
                not _QUERY_KEY.fullmatch(key)
                or key.lower() == "digest"
                or key.lower() in seen
                or not _QUERY_VALUE.fullmatch(value)
                or not _DECODED_VALUE.fullmatch(unquote_to_bytes(value))
            ):
                raise RegistryError("invalid registry upload query")
            seen.add(key.lower())
    return f"{path}?{query + '&' if question else ''}digest={digest}"


@dataclass(frozen=True)
class _Blob:
    digest: str
    size: int


@dataclass(frozen=True)
class _Manifest:
    body: bytes
    media_type: str
    blobs: tuple[_Blob, ...]


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise RegistryError("registry manifest contains duplicate keys")
    return result


def _invalid_constant(_: str) -> None:
    raise RegistryError("registry manifest contains invalid JSON")


def _sha256(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _descriptor(value: object, media_types: set[str]) -> _Blob:
    if not isinstance(value, dict) or "artifactType" in value:
        raise RegistryError("invalid image descriptor")
    media_type, digest, size = value.get("mediaType"), value.get("digest"), value.get("size")
    if (
        not isinstance(media_type, str)
        or media_type not in media_types
        or not isinstance(digest, str)
        or not DIGEST.fullmatch(digest)
        or type(size) is not int
        or not 0 <= size <= _MAX_BLOB_BYTES
    ):
        raise RegistryError("invalid image descriptor")
    if value.get("urls", []) != []:
        raise RegistryError("external image descriptor URLs are unsupported")
    if "data" in value:
        data = value["data"]
        if not isinstance(data, str):
            raise RegistryError("invalid embedded descriptor data")
        try:
            raw = base64.b64decode(data, validate=True)
        except ValueError:
            raise RegistryError("invalid embedded descriptor data") from None
        if len(raw) != size or _sha256(raw) != digest:
            raise RegistryError("embedded descriptor data mismatch")
    return _Blob(digest, size)


def _parse_manifest(body: bytes, content_type: str) -> _Manifest:
    document = json.loads(
        body.decode("utf-8"), object_pairs_hook=_unique_keys, parse_constant=_invalid_constant
    )
    if (
        not isinstance(document, dict)
        or type(document.get("schemaVersion")) is not int
        or document["schemaVersion"] != 2
        or document.get("mediaType", content_type) != content_type
        or {"artifactType", "subject", "manifests"}.intersection(document)
    ):
        raise RegistryError("registry did not return a single image manifest")
    layers = document.get("layers")
    if not isinstance(layers, list) or len(layers) >= _MAX_DESCRIPTORS:
        raise RegistryError("invalid image layer count")
    config = _descriptor(document.get("config"), {_CONFIG_TYPES[content_type]})
    blobs = [config, *(_descriptor(layer, _LAYER_TYPES[content_type]) for layer in layers)]
    if len(body) + sum(blob.size for blob in blobs) > _MAX_ARTIFACT_BYTES:
        raise RegistryError("image exceeds the registry size limit")
    unique: dict[str, _Blob] = {}
    for blob in blobs:
        if unique.setdefault(blob.digest, blob).size != blob.size:
            raise RegistryError("image descriptor sizes disagree")
    return _Manifest(body, content_type, tuple(unique.values()))


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RegistryError("registry operation deadline exceeded")
    return remaining


def _raw_chunks(response: http.client.HTTPResponse, limit: int) -> Iterator[bytes]:
    encoding = _header(response, "Content-Encoding")
    if encoding not in (None, "identity"):
        raise RegistryError("registry returned an unexpected content encoding")
    # Both direct manifest and blob reads in Distribution carry Content-Length.
    # Refuse transfer encodings, whose framing http.client can accept incompletely.
    length = _header(response, "Content-Length")
    if _header(response, "Transfer-Encoding") is not None or length is None:
        raise RegistryError("registry returned unsupported message framing")
    if not re.fullmatch(r"[0-9]{1,19}", length) or int(length) > limit:
        raise RegistryError("registry payload exceeds its size limit")
    size = 0
    while chunk := response.read1(min(_CHUNK_BYTES, limit + 1 - size)):
        size += len(chunk)
        if size > limit:
            raise RegistryError("registry payload exceeds its size limit")
        yield chunk
    if size != int(length):
        raise RegistryError("registry returned a truncated payload")


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, repo: RegistryRepository, context: ssl.SSLContext, deadline: float):
        host, port = repo._origin
        super().__init__(host, port, context=context)
        self.auto_open = False
        self._address = repo._address
        self._deadline = deadline

    def connect(self) -> None:
        family = socket.AF_INET if self._address.version == 4 else socket.AF_INET6
        with socket.socket(family, socket.SOCK_STREAM) as raw:
            raw.settimeout(min(_IO_TIMEOUT, _remaining(self._deadline)))
            raw.connect((str(self._address), self.port))
            raw.settimeout(min(_IO_TIMEOUT, _remaining(self._deadline)))
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def _interrupt(wire: socket.socket) -> None:
    # SSLSocket.shutdown clears TLS state before shutting down the socket.
    # The request thread can still be sending, so call the base socket method.
    with suppress(OSError):
        socket.socket.shutdown(wire, socket.SHUT_RDWR)


class _Endpoint:
    def __init__(
        self,
        repo: RegistryRepository,
        context: ssl.SSLContext,
        deadline: float,
        authorization: str | None,
    ):
        self.repo = repo
        self._context = context
        self._deadline = deadline
        self._authorization = authorization

    @contextmanager
    def _request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | BinaryIO | None = None,
    ) -> Iterator[http.client.HTTPResponse]:
        request_headers = {"Accept-Encoding": "identity", **(headers or {})}
        if self._authorization is not None:
            request_headers["Authorization"] = self._authorization
        connection = _PinnedHTTPS(self.repo, self._context, self._deadline)
        try:
            connection.connect()
            wire = connection.sock
            assert wire is not None  # connect either installs a verified TLS socket or raises
            wire.settimeout(min(_IO_TIMEOUT, _remaining(self._deadline)))
            # An idle timeout alone permits a peer to dribble headers or payload indefinitely.
            timer = Timer(_remaining(self._deadline), _interrupt, (wire,))
            timer.daemon = True
            timer.start()
            try:
                connection.request(method, path, body=content, headers=request_headers)
                with connection.getresponse() as response:
                    yield response
                _remaining(self._deadline)
            finally:
                timer.cancel()
        finally:
            connection.close()

    def manifest(self, digest: str, *, missing_ok: bool = False) -> _Manifest | None:
        path = f"{self.repo._api_path}/manifests/{digest}"
        with self._request("GET", path, headers={"Accept": f"{_OCI}, {_DOCKER}"}) as response:
            if response.status == 404 and missing_ok:
                return None
            if response.status != 200:
                raise RegistryError("registry manifest read failed")
            _check_digest_header(response, digest)
            media_type = (_header(response, "Content-Type") or "").partition(";")[0].strip()
            if media_type not in _CONFIG_TYPES:
                raise RegistryError("unsupported registry manifest media type")
            body = bytearray()
            for chunk in _raw_chunks(response, _MAX_MANIFEST_BYTES):
                body.extend(chunk)
        raw = bytes(body)
        if _sha256(raw) != digest:
            raise RegistryError("registry manifest digest mismatch")
        return _parse_manifest(raw, media_type)

    def blob(self, blob: _Blob, *, missing_ok: bool = False, spool: BinaryIO | None = None) -> bool:
        path = f"{self.repo._api_path}/blobs/{blob.digest}"
        with self._request("GET", path) as response:
            if response.status == 404 and missing_ok:
                return False
            if response.status != 200:
                raise RegistryError("registry blob read failed")
            _check_digest_header(response, blob.digest)
            size, hashed = 0, hashlib.sha256()
            for chunk in _raw_chunks(response, blob.size):
                hashed.update(chunk)
                size += len(chunk)
                if spool is not None:
                    spool.write(chunk)
            if size != blob.size or "sha256:" + hashed.hexdigest() != blob.digest:
                raise RegistryError("registry blob size or digest mismatch")
        return True

    def put_blob(self, blob: _Blob, spool: BinaryIO) -> None:
        prefix = f"{self.repo._api_path}/blobs/uploads/"
        with self._request("POST", prefix) as response:
            if response.status != 202:
                raise RegistryError("registry upload session creation failed")
            path = _upload_path(self.repo, _header(response, "Location"), blob.digest)
        headers = {"Content-Type": "application/octet-stream", "Content-Length": str(blob.size)}
        spool.seek(0)
        with self._request("PUT", path, headers=headers, content=spool) as resp:
            if resp.status != 201:
                raise RegistryError("registry blob upload failed")
            _check_digest_header(resp, blob.digest)

    def put_manifest(self, digest: str, manifest: _Manifest) -> None:
        path = f"{self.repo._api_path}/manifests/{digest}"
        headers = {"Content-Type": manifest.media_type}
        with self._request("PUT", path, headers=headers, content=manifest.body) as response:
            if response.status != 201:
                raise RegistryError("registry manifest upload failed")
            _check_digest_header(response, digest)


def _verify_spool(spool: BinaryIO, blob: _Blob) -> None:
    size, hashed = 0, hashlib.sha256()
    spool.seek(0)
    while chunk := spool.read(_CHUNK_BYTES):
        size += len(chunk)
        if size > blob.size:
            raise RegistryError("registry spool size mismatch")
        hashed.update(chunk)
    if size != blob.size or "sha256:" + hashed.hexdigest() != blob.digest:
        raise RegistryError("registry spool size or digest mismatch")


class OciArtifactRegistry:
    """Verify and promote single images by digest under the validator's UID.

    HTTPS connects to a configured IP and verifies the repository's hostname.
    Reads require direct, length-framed responses. A call has one deadline and
    performs no internal retries. A repeated copy
    verifies and reuses completed blobs and manifests after an interrupted call.
    """

    def __init__(
        self,
        *,
        source: RegistryRepository,
        target: RegistryRepository,
        validator_uid: int,
        ca_file: Path | None = None,
        inventory: Callable[[Path], list[SbomComponent] | None] | None = None,
    ):
        if source._origin == target._origin or (
            source._address == target._address and source._origin[1] == target._origin[1]
        ):
            raise RegistryError("source and target registry origins must be distinct")
        if target.basic_auth_ref is None or target.basic_auth_ref == source.basic_auth_ref:
            raise RegistryError("target registry requires a distinct credential reference")
        if type(validator_uid) is not int or validator_uid <= 0:
            raise RegistryError("registry access requires a non-root validator UID")
        self._source = source
        self._target = target
        self._validator_uid = validator_uid
        self._ca_file = ca_file
        self._inventory = inventory

    def _require_validator(self) -> None:
        if geteuid() != self._validator_uid:
            raise RegistryError("registry access requires the configured validator UID")

    def inspect(self, ref: str) -> ArtifactFacts:
        self._require_validator()
        digest = self._source._digest(ref)
        return self._run(self._inspect, digest)

    def copy(self, source_ref: str, target_ref: str) -> str:
        self._require_validator()
        digest = self._source._digest(source_ref)
        if digest != self._target._digest(target_ref):
            raise RegistryError("source and target image digests differ")
        return self._run(self._copy, digest, copy=True)

    def _run(
        self,
        operation: Callable[[_Endpoint, _Endpoint | None, str], _T],
        digest: str,
        *,
        copy: bool = False,
    ) -> _T:
        deadline = time.monotonic() + _OPERATION_TIMEOUT
        try:
            context = _tls_context(self._ca_file)
            source_auth = self._source._authorization()
            target_auth = self._target._authorization() if copy or source_auth is not None else None
            if source_auth is not None and source_auth == target_auth:
                raise RegistryError("source and target registry credentials must differ")
            source = _Endpoint(self._source, context, deadline, source_auth)
            target = _Endpoint(self._target, context, deadline, target_auth) if copy else None
            result = operation(source, target, digest)
            _remaining(deadline)
            return result
        except (http.client.HTTPException, OSError, ValueError, RecursionError):
            if time.monotonic() >= deadline:
                raise RegistryError("registry operation deadline exceeded") from None
            raise RegistryError("registry transport or content verification failed") from None

    def _inspect(self, source: _Endpoint, _target: _Endpoint | None, digest: str) -> ArtifactFacts:
        manifest = source.manifest(digest)
        if manifest is None:
            raise RegistryError("source manifest is missing")
        with TemporaryDirectory(prefix="steward-image-") as directory:
            layout = Path(directory)
            blobs = layout / "blobs" / "sha256"
            blobs.mkdir(parents=True)
            for blob in manifest.blobs:
                path = blobs / blob.digest.removeprefix("sha256:")
                fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w+b") as spool:
                    source.blob(blob, spool=spool)
                    _verify_spool(spool, blob)
            (blobs / digest.removeprefix("sha256:")).write_bytes(manifest.body)
            (layout / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}', encoding="utf-8")
            index = {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "mediaType": manifest.media_type,
                        "digest": digest,
                        "size": len(manifest.body),
                    }
                ],
            }
            (layout / "index.json").write_text(json.dumps(index), encoding="utf-8")
            remaining = _remaining(source._deadline)
            if self._inventory is None:
                sbom = TrivyImageInventory()(layout, timeout=remaining)
            else:
                sbom = self._inventory(layout)
            return ArtifactFacts(manifest_digest=digest, sbom=sbom)

    @staticmethod
    def _copy(source: _Endpoint, target: _Endpoint | None, digest: str) -> str:
        assert target is not None
        manifest = source.manifest(digest)
        if manifest is None:
            raise RegistryError("source manifest is missing")
        with ExitStack() as files:
            spools = {}
            for blob in manifest.blobs:
                spool = files.enter_context(TemporaryFile(mode="w+b"))
                source.blob(blob, spool=spool)
                _verify_spool(spool, blob)
                spools[blob.digest] = spool
            for blob in manifest.blobs:
                if not target.blob(blob, missing_ok=True):
                    target.put_blob(blob, spools[blob.digest])
                    target.blob(blob)
            present = target.manifest(digest, missing_ok=True)
            if present is None:
                target.put_manifest(digest, manifest)
                present = target.manifest(digest)
                for blob in manifest.blobs:
                    target.blob(blob)
            if present != manifest:
                raise RegistryError("target manifest differs from the verified source")
        return digest
