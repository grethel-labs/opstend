"""Private one-shot HTTPS transport for outgoing fleet agents."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import sqlite3
import ssl
from hashlib import sha256
from pathlib import Path
from socketserver import BaseRequestHandler, TCPServer
from threading import BoundedSemaphore, Event, Thread
from time import monotonic
from typing import Annotated, Literal
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import Field, SecretStr

from .core.fleet_adoption_models import PveAdoptionEvidence
from .core.fleet_enrollment import FleetEnrollment, FleetGrant
from .core.fleet_identity import InventoryObservation, PveConnectorRoute
from .core.fleet_policy import FleetPolicyConflict
from .core.fleet_policy_apply import FleetPolicyApply, FleetPolicyDenied, FleetPolicyNotFound
from .core.fleet_policy_reconcile import FleetPolicySyncReply, FleetPolicySyncRequest
from .core.pve_inventory_models import (
    MAX_RESOURCES,
    Evidence,
    Guest,
    GuestKind,
    InventorySnapshot,
    Node,
    NodeName,
    Projection,
    ResourceName,
    TimedProjection,
    Vmid,
)

_MAX_BODY = 256 * 1024
_MAX_HEADERS = 8 * 1024
_MAX_LINE = 1024
_HEADER_NAME = re.compile(rb"[A-Za-z0-9!#$%&'*+.^_|~-]+")
_CONTENT_LENGTH = re.compile(rb"0|[1-9][0-9]{0,5}")
_TIMEOUT = 5.0
_DNS_SLOTS = BoundedSemaphore(4)
_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
    )
)

Generation = Annotated[int, Field(ge=1, le=2**63 - 1)]


class FleetTransportError(ValueError):
    """The fleet transport could not complete the requested operation."""


class _Empty(Projection):
    pass


class _Invite(Projection):
    invite: SecretStr = Field(min_length=32, max_length=128)


class _Node(Projection):
    node: NodeName


class _Guest(Projection):
    evidence: Evidence
    node: NodeName
    vmid: Vmid
    kind: GuestKind
    name: ResourceName | None
    pve_uid: str | None = Field(pattern=r"^[a-z2-7]{20}$", repr=False)
    registered_at_ms: int | None = Field(gt=0, le=999_999_999_999_999, repr=False)


class _Snapshot(TimedProjection):
    api_name: Annotated[str, Field(max_length=253)]
    evidence: Evidence
    nodes: tuple[_Node, ...] = Field(max_length=MAX_RESOURCES)
    guests: tuple[_Guest, ...] = Field(max_length=MAX_RESOURCES)

    @classmethod
    def from_inventory(cls, snapshot: InventorySnapshot) -> _Snapshot:
        return cls(
            api_name=snapshot.api_name,
            observed_at=snapshot.observed_at,
            evidence=snapshot.evidence,
            nodes=tuple(_Node(node=item.node) for item in snapshot.nodes),
            guests=tuple(
                _Guest(
                    evidence=item.evidence,
                    node=item.node,
                    vmid=item.vmid,
                    kind=item.kind,
                    name=item.name,
                    pve_uid=item.pve_uid,
                    registered_at_ms=item.registered_at_ms,
                )
                for item in snapshot.guests
            ),
        )

    def to_inventory(self) -> InventorySnapshot:
        return InventorySnapshot(
            api_name=self.api_name,
            observed_at=self.observed_at,
            evidence=self.evidence,
            nodes=tuple(Node(node=item.node, evidence=self.evidence) for item in self.nodes),
            guests=tuple(
                Guest(
                    evidence=item.evidence,
                    node=item.node,
                    vmid=item.vmid,
                    kind=item.kind,
                    name=item.name,
                    pve_uid=item.pve_uid,
                    registered_at_ms=item.registered_at_ms,
                )
                for item in self.guests
            ),
        )


class _Inventory(Projection):
    generation: Generation
    snapshot: _Snapshot


class _Route(Projection):
    generation: Generation
    route: PveConnectorRoute


class _AdoptionRoute(_Route):
    attempt: Generation


class _AdoptionInventory(_Inventory):
    attempt: Generation
    evidence: PveAdoptionEvidence


class _Error(Projection):
    error: Literal["invalid request", "denied", "unavailable"]


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate JSON member")
    return result


def _decode[M: Projection](model: type[M], data: bytes) -> M:
    json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
    return model.model_validate_json(data)


def _spki_fingerprint(certificate: x509.Certificate) -> str:
    return sha256(
        certificate.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    ).hexdigest()


def certificate_fingerprint(cert_file: Path) -> str:
    try:
        with Path(cert_file).open("rb") as source:
            certificate = source.read(64 * 1024 + 1)
        if len(certificate) > 64 * 1024:
            raise ValueError
        return _spki_fingerprint(x509.load_pem_x509_certificate(certificate))
    except (OSError, ValueError):
        raise FleetTransportError("could not read the client certificate") from None


def _context(
    protocol: ssl._SSLMethod, cert_file: Path, key_file: Path, ca_file: Path
) -> ssl.SSLContext:
    context = ssl.SSLContext(protocol)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_TICKET
    if protocol == ssl.PROTOCOL_TLS_SERVER:
        context.num_tickets = 0
    context.hostname_checks_common_name = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=ca_file)
    context.load_cert_chain(cert_file, key_file, password=lambda: b"")
    return context


def _remaining(deadline: float) -> float:
    timeout = deadline - monotonic()
    if timeout <= 0:
        raise TimeoutError
    return timeout


class _Message:
    def __init__(self, stream: ssl.SSLSocket, deadline: float):
        self.stream = stream
        self.deadline = deadline
        self.buffer = bytearray()

    def _receive(self, limit: int) -> None:
        self.stream.settimeout(_remaining(self.deadline))
        data = self.stream.recv(limit)
        if not data:
            raise ValueError("incomplete HTTP message")
        self.buffer.extend(data)

    def read(self, *, require_host: bool = False) -> tuple[bytes, bytes]:
        end = self.buffer.find(b"\r\n\r\n")
        while end < 0:
            if len(self.buffer) == _MAX_HEADERS:
                raise ValueError("HTTP headers exceed size limit")
            self._receive(_MAX_HEADERS - len(self.buffer))
            end = self.buffer.find(b"\r\n\r\n")
        start, *lines = bytes(self.buffer[:end]).split(b"\r\n")
        del self.buffer[: end + 4]
        if len(lines) > 16 or len(start) > _MAX_LINE:
            raise ValueError("invalid HTTP header count or start line")
        fields = {}
        for line in lines:
            name, _, value = line.partition(b":")
            name = name.lower()
            if (
                len(line) > _MAX_LINE
                or not _HEADER_NAME.fullmatch(name)
                or name in fields
                or any(byte < 32 or byte >= 127 for byte in value)
            ):
                raise ValueError("invalid HTTP header")
            fields[name] = value.strip(b" ")
        length = fields.get(b"content-length", b"")
        if (
            not _CONTENT_LENGTH.fullmatch(length)
            or fields.get(b"content-type") != b"application/json"
            or (require_host and not fields.get(b"host"))
            or any(
                forbidden in fields
                for forbidden in (
                    b"transfer-encoding",
                    b"content-encoding",
                    b"expect",
                    b"upgrade",
                    b"trailer",
                )
            )
        ):
            raise ValueError("invalid HTTP body framing")
        size = int(length)
        if not 0 < size <= _MAX_BODY or len(self.buffer) > size:
            raise ValueError("invalid HTTP body length")
        while len(self.buffer) < size:
            self._receive(size - len(self.buffer))
        return start, bytes(self.buffer)

    def write(self, start: bytes, body: bytes, *, host: bytes | None = None) -> None:
        if not 0 < len(body) <= _MAX_BODY:
            raise ValueError("invalid HTTP body length")
        headers = (
            b"Content-Type: application/json\r\nConnection: close\r\nCache-Control: no-store\r\n"
            + b"Content-Length: "
            + str(len(body)).encode("ascii")
            + b"\r\n"
        )
        if host is not None:
            headers += b"Host: " + host + b"\r\n"
        self.stream.settimeout(_remaining(self.deadline))
        self.stream.sendall(start + b"\r\n" + headers + b"\r\n" + body)


class _FleetHandler(BaseRequestHandler):
    server: _FleetServer

    def handle(self) -> None:
        try:
            self.request.settimeout(_TIMEOUT)
            with self.server.context.wrap_socket(self.request, server_side=True) as stream:
                self._serve(stream)
        except (OSError, ValueError):
            pass

    def _serve(self, stream: ssl.SSLSocket) -> None:
        certificate = stream.getpeercert(binary_form=True)
        if certificate is None or stream.session_reused:
            return
        fingerprint = _spki_fingerprint(x509.load_der_x509_certificate(certificate))
        try:
            start, data = _Message(stream, monotonic() + _TIMEOUT).read(require_host=True)
            model, operation = self.server.routes[start]
            request = _decode(model, data)
        except (KeyError, ValueError, RecursionError):
            status, response = b"400 Bad Request", _Error(error="invalid request")
        else:
            try:
                response = operation(fingerprint, request)
            except ValueError:
                status, response = b"403 Forbidden", _Error(error="denied")
            except sqlite3.Error:
                status, response = b"503 Service Unavailable", _Error(error="unavailable")
            else:
                status = b"200 OK"
        _Message(stream, monotonic() + _TIMEOUT).write(
            b"HTTP/1.1 " + status, response.model_dump_json().encode("utf-8")
        )


class _FleetServer(TCPServer):
    allow_reuse_address = True

    def __init__(
        self, address: str, port: int, enrollment: FleetEnrollment, context: ssl.SSLContext
    ):
        self.enrollment = enrollment
        self.policy = FleetPolicyApply(enrollment._registry)
        self.context = context
        self.routes = {
            b"POST /v1/enroll HTTP/1.1": (_Invite, self._enroll),
            b"POST /v1/heartbeat HTTP/1.1": (_Empty, self._heartbeat),
            b"POST /v1/connector-route HTTP/1.1": (_Empty, self._route),
            b"POST /v1/inventory HTTP/1.1": (_Inventory, self._publish),
            b"POST /v1/adoption/begin HTTP/1.1": (_Empty, self._begin_adoption),
            b"POST /v1/adoption/publish HTTP/1.1": (_AdoptionInventory, self._publish_adoption),
            b"POST /v1/policy-target/reconcile HTTP/1.1": (
                FleetPolicySyncRequest,
                self._reconcile_policy,
            ),
        }
        if ipaddress.ip_address(address).version == 6:
            self.address_family = socket.AF_INET6
        super().__init__((address, port), _FleetHandler)

    @property
    def server_port(self) -> int:
        return self.server_address[1]

    def handle_error(self, request, client_address) -> None:
        # The default socketserver handler emits client addresses and tracebacks.
        pass

    def _enroll(self, fingerprint: str, request: _Invite) -> FleetGrant:
        return self.enrollment.redeem(
            request.invite.get_secret_value(), key_fingerprint=fingerprint
        )

    def _heartbeat(self, fingerprint: str, request: _Empty) -> FleetGrant:
        return self.enrollment.authorize(fingerprint, capability="heartbeat")

    def _route(self, fingerprint: str, request: _Empty) -> _Route:
        grant, route = self.enrollment.connector_route(fingerprint)
        return _Route(generation=grant.generation, route=route)

    def _publish(self, fingerprint: str, request: _Inventory) -> InventoryObservation:
        return self.enrollment.publish_inventory(
            fingerprint, generation=request.generation, snapshot=request.snapshot.to_inventory()
        )

    def _begin_adoption(self, fingerprint: str, request: _Empty) -> _AdoptionRoute:
        grant, route, attempt = self.enrollment.begin_adoption(fingerprint)
        return _AdoptionRoute(generation=grant.generation, route=route, attempt=attempt)

    def _publish_adoption(
        self, fingerprint: str, request: _AdoptionInventory
    ) -> InventoryObservation:
        return self.enrollment.publish_adoption(
            fingerprint,
            generation=request.generation,
            attempt=request.attempt,
            snapshot=request.snapshot.to_inventory(),
            evidence=request.evidence,
        )

    def _reconcile_policy(
        self, fingerprint: str, request: FleetPolicySyncRequest
    ) -> FleetPolicySyncReply:
        try:
            return self.policy.reconcile_target(fingerprint, request)
        except (FleetPolicyConflict, FleetPolicyDenied, FleetPolicyNotFound):
            raise FleetTransportError("fleet policy reconciliation denied") from None


def create_server(
    enrollment: FleetEnrollment,
    *,
    bind: str,
    port: int,
    cert_file: Path,
    key_file: Path,
    client_ca_file: Path,
) -> _FleetServer:
    try:
        address = ipaddress.ip_address(bind)
        if not any(address in network for network in _PRIVATE_NETWORKS) or "%" in bind:
            raise ValueError
        context = _context(ssl.PROTOCOL_TLS_SERVER, cert_file, key_file, client_ca_file)
        return _FleetServer(str(address), port, enrollment, context)
    except (OSError, OverflowError, ValueError):
        raise FleetTransportError("fleet coordinator bind or TLS setup failed") from None


def _resolve(host: str, port: int, deadline: float) -> list:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        family = socket.AF_INET if address.version == 4 else socket.AF_INET6
        return [(family, (host, port))]
    if not _DNS_SLOTS.acquire(timeout=_remaining(deadline)):
        raise TimeoutError
    done = Event()
    addresses = []

    def lookup() -> None:
        try:
            addresses.extend(
                (family, address)
                for family, _, _, _, address in socket.getaddrinfo(
                    host, port, type=socket.SOCK_STREAM
                )
            )
        except OSError:
            pass
        finally:
            _DNS_SLOTS.release()
            done.set()

    try:
        Thread(target=lookup, daemon=True).start()
    except RuntimeError:
        _DNS_SLOTS.release()
        raise OSError from None
    if not done.wait(_remaining(deadline)) or not addresses:
        raise OSError
    return addresses


def _connect(host: str, port: int) -> socket.socket:
    deadline = monotonic() + _TIMEOUT
    for family, address in _resolve(host, port, deadline):
        conn = socket.socket(family, socket.SOCK_STREAM)
        try:
            conn.settimeout(_remaining(deadline))
            conn.connect(address)
        except OSError:
            conn.close()
        else:
            return conn
    raise OSError


class FleetClient:
    """Agent-side client with explicit PKI and no redirect or proxy handling."""

    def __init__(self, *, endpoint: str, cert_file: Path, key_file: Path, server_ca_file: Path):
        try:
            if not re.fullmatch(r"https://[A-Za-z0-9.\-:\[\]]{1,260}/?", endpoint):
                raise ValueError
            url = urlsplit(endpoint)
            self.host = url.hostname
            self.port = 443 if url.port is None else url.port
            self.host_header = url.netloc.encode("ascii")
            if self.host is None or self.port == 0:
                raise ValueError
            self.context = _context(ssl.PROTOCOL_TLS_CLIENT, cert_file, key_file, server_ca_file)
        except (OSError, ValueError):
            raise FleetTransportError("fleet endpoint or client TLS setup failed") from None

    def _post[M: Projection](self, path: bytes, payload: bytes, model: type[M]) -> M:
        try:
            with _connect(self.host, self.port) as conn:
                conn.settimeout(_TIMEOUT)
                with self.context.wrap_socket(conn, server_hostname=self.host) as stream:
                    _Message(stream, monotonic() + _TIMEOUT).write(
                        b"POST " + path + b" HTTP/1.1", payload, host=self.host_header
                    )
                    status, data = _Message(stream, monotonic() + _TIMEOUT).read()
            if status != b"HTTP/1.1 200 OK":
                raise ValueError
            return _decode(model, data)
        except (OSError, ValueError, RecursionError):
            raise FleetTransportError("fleet HTTPS request failed or was denied") from None

    def enroll(self, token: str) -> FleetGrant:
        try:
            _Invite(invite=SecretStr(token))
            payload = json.dumps({"invite": token}).encode("utf-8")
        except (TypeError, ValueError):
            raise FleetTransportError("invalid invitation") from None
        return self._post(b"/v1/enroll", payload, FleetGrant)

    def heartbeat(self) -> FleetGrant:
        return self._post(b"/v1/heartbeat", b"{}", FleetGrant)

    def reconcile_policy(self, request: FleetPolicySyncRequest) -> FleetPolicySyncReply:
        return self._post(
            b"/v1/policy-target/reconcile",
            request.model_dump_json().encode(),
            FleetPolicySyncReply,
        )

    def connector_route(self) -> tuple[int, PveConnectorRoute]:
        result = self._post(b"/v1/connector-route", b"{}", _Route)
        return result.generation, result.route

    def publish_inventory(
        self, generation: int, snapshot: InventorySnapshot
    ) -> InventoryObservation:
        try:
            payload = _Inventory(generation=generation, snapshot=_Snapshot.from_inventory(snapshot))
        except (AttributeError, TypeError, ValueError):
            raise FleetTransportError("invalid inventory publication") from None
        return self._post(
            b"/v1/inventory", payload.model_dump_json().encode(), InventoryObservation
        )

    def begin_adoption(self) -> tuple[int, PveConnectorRoute, int]:
        result = self._post(b"/v1/adoption/begin", b"{}", _AdoptionRoute)
        return result.generation, result.route, result.attempt

    def publish_adoption(
        self,
        generation: int,
        attempt: int,
        snapshot: InventorySnapshot,
        evidence: PveAdoptionEvidence,
    ) -> InventoryObservation:
        try:
            payload = _AdoptionInventory(
                generation=generation,
                attempt=attempt,
                snapshot=_Snapshot.from_inventory(snapshot),
                evidence=evidence,
            )
        except (AttributeError, TypeError, ValueError):
            raise FleetTransportError("invalid adoption publication") from None
        return self._post(
            b"/v1/adoption/publish", payload.model_dump_json().encode(), InventoryObservation
        )
