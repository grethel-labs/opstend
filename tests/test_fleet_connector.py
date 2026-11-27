import socket
from contextlib import suppress
from hashlib import sha256
from http.server import BaseHTTPRequestHandler
from threading import Event

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from steward.core import fleet_connector
from steward.core.fleet_connector import PveConnectorError, pve_instance_binding
from steward.core.fleet_identity import PveConnectorRoute
from steward.core.pve_native import PVE_RELEASE, PVE_VERSION
from test_pve_inventory import payload
from test_pve_native import API_NAME, API_TOKEN, PERMISSIONS_PATH, VERSION_PATH
from test_pve_native import pve_api as pve_api
from test_pve_native import pve_tls as pve_tls
from test_pve_native import token_file as token_file

STATUS = "/api2/json/cluster/status"
RESOURCES = "/api2/json/cluster/resources"
NATIVE_ID = "a" * 20
LOCAL_NODE = {"type": "node", "id": "node/node-a", "name": "node-a", "local": 1}


@pytest.fixture
def connector_route():
    return PveConnectorRoute(
        route_id="route",
        instance_id="instance",
        host_id="host",
        api_name=API_NAME,
        address="127.0.0.1",
        node="node-a",
        kind="standalone",
        transport_fingerprint="ab" * 32,
        instance_binding=pve_instance_binding(NATIVE_ID),
    )


def resolve_as(monkeypatch, *addresses):
    def resolve(_name, port, **_options):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port)) for address in addresses
        ]

    monkeypatch.setattr(fleet_connector.socket, "getaddrinfo", resolve)


@pytest.mark.parametrize("mismatch", [None, "dns", "ip", "leaf"])
def test_pve_credentials_are_sent_only_to_the_approved_address_and_tls_leaf(
    mismatch, connector_route, pve_api, token_file, monkeypatch
):
    ca, responses, calls = pve_api
    der = x509.load_pem_x509_certificate(ca.read_bytes()).public_bytes(serialization.Encoding.DER)
    route = connector_route.model_copy(update={"transport_fingerprint": sha256(der).hexdigest()})
    resolve_as(monkeypatch, route.address)
    leaf_disconnected = Event()
    if mismatch == "dns":
        resolve_as(monkeypatch, route.address, "192.0.2.11")
    elif mismatch == "ip":
        route = route.model_copy(update={"api_name": "192.0.2.11"})
    elif mismatch == "leaf":
        route = route.model_copy(update={"transport_fingerprint": "ff" * 32})
        handle_request = BaseHTTPRequestHandler.handle_one_request

        def handle_pin_rejection(handler):
            try:
                with suppress(ConnectionResetError):
                    handle_request(handler)
            finally:
                leaf_disconnected.set()

        monkeypatch.setattr(BaseHTTPRequestHandler, "handle_one_request", handle_pin_rejection)
    else:
        responses.update(
            {
                PERMISSIONS_PATH: payload({"/": {"Sys.Audit": 0}}),
                STATUS: payload([{**LOCAL_NODE, "cluster-id": NATIVE_ID}]),
                RESOURCES: payload([]),
            }
        )
        snapshot = fleet_connector.collect_pve_inventory(
            route, ca_file=ca, token_ref=f"file:{token_file}"
        )
        assert snapshot.evidence.state == "absent"
        assert [path for _, path, _ in calls] == [
            VERSION_PATH,
            PERMISSIONS_PATH,
            STATUS,
            RESOURCES,
            VERSION_PATH,
            PERMISSIONS_PATH,
            RESOURCES,
            STATUS,
        ]
        assert all(
            (method, auth) == ("GET", f"PVEAPIToken={API_TOKEN}") for method, _, auth in calls
        )
        return
    with pytest.raises(PveConnectorError) as error:
        fleet_connector.collect_pve_inventory(route, ca_file=ca, token_ref=f"file:{token_file}")
    if mismatch == "leaf":
        assert leaf_disconnected.wait(timeout=2)
    assert API_TOKEN not in str(error.value)
    assert calls == []


@pytest.mark.parametrize("kind", ["standalone", "cluster"])
@pytest.mark.parametrize("mismatch", [None, "instance", "node", "acl", "changed-during-read"])
def test_connector_checks_native_identity_and_scope_before_publishing(
    kind, mismatch, connector_route, pve_api, token_file, monkeypatch
):
    ca, _, _ = pve_api
    resolve_as(monkeypatch, connector_route.address)
    route = connector_route.model_copy(update={"kind": kind})
    calls = []
    root = {"/": {"Sys.Audit": 0}}

    def read(api_name, _context, token, path, **limits):
        assert api_name == route.api_name
        assert str(limits["_pinned_address"]) == route.address
        assert limits["_leaf_fingerprint"] == route.transport_fingerprint
        assert token == API_TOKEN
        calls.append(path)
        if path == VERSION_PATH:
            return 200, {"version": PVE_VERSION, "release": PVE_RELEASE}
        if path == PERMISSIONS_PATH:
            return 200, {"/": {"Sys.Audit": 1}} if mismatch == "acl" else root
        if path == STATUS:
            node = LOCAL_NODE
            if mismatch == "node":
                node = {**node, "id": "node/node-b", "name": "node-b"}
            wrong_id = mismatch == "instance" or (
                mismatch == "changed-during-read" and calls.count(STATUS) == 2
            )
            binding = {"cluster-id": "b" * 20 if wrong_id else NATIVE_ID}
            if kind == "cluster":
                return 200, [{"type": "cluster", "id": "cluster", **binding}, node]
            return 200, [{**node, **binding}]
        assert path == RESOURCES
        return 200, []

    monkeypatch.setattr(fleet_connector, "_request_api_response", read)
    if mismatch is None:
        snapshot = fleet_connector.collect_pve_inventory(
            route, ca_file=ca, token_ref=f"file:{token_file}"
        )
        assert snapshot.evidence.state == "absent"
        assert snapshot.guests == ()
        assert calls.count(STATUS) == calls.count(RESOURCES) == 2
        return

    with pytest.raises(PveConnectorError):
        fleet_connector.collect_pve_inventory(route, ca_file=ca, token_ref=f"file:{token_file}")
    if mismatch == "changed-during-read":
        assert calls.count(STATUS) == calls.count(RESOURCES) == 2
    else:
        assert RESOURCES not in calls
