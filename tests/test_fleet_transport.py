import ipaddress
import json
import stat
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from threading import Thread

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from steward.cli import fleet as fleet_cli
from steward.cli import main as cli
from steward.core.fleet_enrollment import FleetEnrollment
from steward.core.fleet_identity import FleetIdentityRegistry
from steward.core.pve_inventory_models import Evidence, InventorySnapshot, parse_resources
from steward.fleet_transport import FleetClient, FleetTransportError, create_server


def certificate(directory, name, authority=None, *, server=False):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    parent, signing_key = (subject, key) if authority is None else authority
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(parent)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=authority is None, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()),
            critical=False,
        )
    )
    if authority is None:
        builder = builder.add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, None, None),
            critical=True,
        )
    else:
        use = ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH
        builder = builder.add_extension(x509.ExtendedKeyUsage([use]), critical=False)
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
    cert_path = directory / f"{name}.pem"
    cert_path.write_bytes(
        builder.sign(signing_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
    )
    if authority is None:
        return cert_path, (subject, key)
    key_path = directory / f"{name}.key"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    fingerprint = sha256(
        key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).hexdigest()
    return cert_path, key_path, fingerprint


@pytest.fixture
def tls(tmp_path):
    ca, authority = certificate(tmp_path, "ca")
    outsider_ca, outsider = certificate(tmp_path, "outsider-ca")
    server_cert, server_key, _ = certificate(tmp_path, "server", authority, server=True)
    return {
        "server": (ca, server_cert, server_key),
        "first": certificate(tmp_path, "first", authority),
        "next": certificate(tmp_path, "next", authority),
        "wrong": certificate(tmp_path, "wrong", authority),
        "untrusted": certificate(tmp_path, "untrusted", outsider),
        "wrong_ca": outsider_ca,
    }


@contextmanager
def loopback(enrollment, tls):
    ca, cert, key = tls["server"]
    with create_server(
        enrollment, bind="127.0.0.1", port=0, cert_file=cert, key_file=key, client_ca_file=ca
    ) as server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        thread.start()

        def client(which, *, server_ca=ca):
            client_cert, client_key, fingerprint = tls[which]
            client = FleetClient(
                endpoint=f"https://127.0.0.1:{server.server_port}",
                cert_file=client_cert,
                key_file=client_key,
                server_ca_file=server_ca,
            )
            return client, fingerprint

        try:
            yield client
        finally:
            server.shutdown()
            thread.join(timeout=2)
            assert not thread.is_alive()


def sample_snapshot(*, api_name, node, observed_at, uid=None, registration_ms=None):
    rows = []
    if uid is not None:
        rows.append(
            {
                "node": node,
                "type": "qemu",
                "vmid": 190,
                "name": "guest",
                "uid": uid,
                "rtime": registration_ms,
            }
        )
    evidence = Evidence(
        source="cluster_resources",
        state="observed" if rows else "absent",
        observed_at=observed_at,
    )
    return InventorySnapshot(
        api_name=api_name,
        evidence=evidence,
        observed_at=observed_at,
        guests=parse_resources(rows, evidence).guests,
    )


def test_mtls_rejects_wrong_keys_ca_scope_replay_rotation_and_revoke(tmp_path, tls):
    path = tmp_path / "fleet.sqlite"
    registry = FleetIdentityRegistry(path)
    host = registry.register_host(registry.register_site("site").id, "host")
    agent = registry.register_agent(host.id, "agent")
    enrollment = FleetEnrollment(registry)
    with loopback(enrollment, tls) as client:
        first, first_key = client("first")
        second, second_key = client("next")
        invitation = enrollment.issue(agent.id, key_fingerprint=first_key, capability="heartbeat")
        token = invitation.token.get_secret_value()
        for denied in (
            first.heartbeat,
            lambda: client("wrong")[0].enroll(token),
            lambda: client("untrusted")[0].enroll(token),
            lambda: client("first", server_ca=tls["wrong_ca"])[0].enroll(token),
        ):
            with pytest.raises(FleetTransportError) as error:
                denied()
            assert token not in str(error.value)
        grant = first.enroll(token)
        assert first.heartbeat() == grant
        for denied in (lambda: first.enroll(token), first.connector_route):
            with pytest.raises(FleetTransportError):
                denied()
        rotation = enrollment.issue(
            agent.id, key_fingerprint=second_key, capability="heartbeat", expected_generation=1
        )
        assert second.enroll(rotation.token.get_secret_value()).generation == 2
        with pytest.raises(FleetTransportError):
            first.heartbeat()

    enrollment = FleetEnrollment(FleetIdentityRegistry(path))
    with loopback(enrollment, tls) as client:
        second, _ = client("next")
        assert second.heartbeat().agent_id == agent.id
        assert enrollment.revoke(agent.id, expected_generation=2) == 3
        with pytest.raises(FleetTransportError):
            second.heartbeat()


def test_mtls_inventory_preserves_private_guest_generation_and_token_scope(tmp_path, tls):
    path = tmp_path / "fleet.sqlite"
    registry = FleetIdentityRegistry(path)
    site = registry.register_site("site")
    host = registry.register_host(site.id, "host")
    agent = registry.register_agent(host.id, "connector")
    binding = "ab" * 32
    instance = registry.register_instance(site.id, kind="standalone", instance_binding=binding)
    route = registry.confirm_route(
        instance.id,
        host_id=host.id,
        node="node-a",
        api_name="pve-a.internal",
        instance_binding=binding,
        transport_fingerprint="cd" * 32,
        address="192.0.2.10",
    )
    now = datetime.now(UTC) - timedelta(minutes=1)
    registration_ms = int(now.timestamp() * 1000)
    uid, replacement_uid = "a" * 20, "b" * 20

    def snapshot(offset, guest_uid=None, *, api_name=route.api_name):
        return sample_snapshot(
            api_name=api_name,
            node=route.node,
            observed_at=now + timedelta(seconds=offset),
            uid=guest_uid,
            registration_ms=registration_ms + offset * 100,
        )

    enrollment = FleetEnrollment(registry)
    with loopback(enrollment, tls) as client:
        connector, key = client("first")
        invite = enrollment.issue(
            agent.id, key_fingerprint=key, capability="pve_inventory", route_id=route.id
        )
        connector.enroll(invite.token.get_secret_value())
        generation, approved = connector.connector_route()
        assert (approved.route_id, approved.api_name, approved.address) == (
            route.id,
            route.api_name,
            "192.0.2.10",
        )
        with pytest.raises(FleetTransportError):
            connector.heartbeat()
        with pytest.raises(FleetTransportError):
            connector.publish_inventory(generation + 1, snapshot(1, uid))
        with pytest.raises(FleetTransportError):
            connector.publish_inventory(generation, snapshot(1, uid, api_name="other.internal"))
        assert registry.guest_history(instance.id, 190) == ()
        original = snapshot(1, uid)
        assert uid not in original.model_dump_json()
        receipt = connector.publish_inventory(generation, original)
        assert receipt.coverage == "token_scope"
        assert uid not in receipt.model_dump_json()
        assert str(registration_ms + 100) not in receipt.model_dump_json()
        connector.publish_inventory(generation, snapshot(2))
        (old,) = registry.guest_history(instance.id, 190)
        assert old.state == "present"

    reopened = FleetIdentityRegistry(path)
    enrollment = FleetEnrollment(reopened)
    with loopback(enrollment, tls) as client:
        connector, _ = client("first")
        assert connector.connector_route() == (generation, approved)
        assert connector.publish_inventory(generation, original).id == receipt.id
        assert reopened.guest_history(instance.id, 190) == (old,)
        connector.publish_inventory(generation, snapshot(3, replacement_uid))
        retired, replacement = reopened.guest_history(instance.id, 190)
        assert (retired.id, retired.state, replacement.generation, replacement.state) == (
            old.id,
            "replaced",
            2,
            "present",
        )
        enrollment.revoke(agent.id, expected_generation=generation)
        with pytest.raises(FleetTransportError):
            connector.publish_inventory(generation, snapshot(4, uid))
        assert reopened.guest_history(instance.id, 190) == (retired, replacement)


def test_mtls_inventory_keeps_two_instances_separate_across_confirmed_cluster_routes(tmp_path, tls):
    registry = FleetIdentityRegistry(tmp_path / "fleet.sqlite")
    enrollment = FleetEnrollment(registry)
    site = registry.register_site("site")
    cluster_binding, standalone_binding = "ab" * 32, "cd" * 32
    cluster = registry.register_instance(site.id, kind="cluster", instance_binding=cluster_binding)
    standalone = registry.register_instance(
        site.id, kind="standalone", instance_binding=standalone_binding
    )
    started = datetime.now(UTC) - timedelta(seconds=20)
    register_ms = int(started.timestamp() * 1000)
    with loopback(enrollment, tls) as client:
        for offset, (key, instance, binding) in enumerate(
            (
                ("first", cluster, cluster_binding),
                ("next", standalone, standalone_binding),
                ("wrong", cluster, cluster_binding),
            ),
            start=1,
        ):
            host = registry.register_host(site.id, f"host-{offset}")
            agent = registry.register_agent(host.id, f"connector-{offset}")
            connector, fingerprint = client(key)
            route = registry.confirm_route(
                instance.id,
                host_id=host.id,
                node=f"node-{offset}",
                api_name=f"pve-{offset}.internal",
                instance_binding=binding,
                transport_fingerprint=f"{offset:02x}" * 32,
                address=f"192.0.2.{offset}",
            )
            invitation = enrollment.issue(
                agent.id, key_fingerprint=fingerprint, capability="pve_inventory", route_id=route.id
            )
            connector.enroll(invitation.token.get_secret_value())
            generation, approved = connector.connector_route()
            assert approved.route_id == route.id
            snapshot = sample_snapshot(
                api_name=route.api_name,
                node=route.node,
                observed_at=started + timedelta(seconds=offset),
                uid="a" * 20,
                registration_ms=register_ms,
            )
            receipt = connector.publish_inventory(generation, snapshot)
            assert (receipt.route_id, receipt.instance_id) == (route.id, instance.id)
            if offset == 1:
                (original,) = registry.guest_history(cluster.id, 190)

    (migrated,) = registry.guest_history(cluster.id, 190)
    (separate,) = registry.guest_history(standalone.id, 190)
    assert (migrated.id, migrated.generation, migrated.node) == (original.id, 1, "node-3")
    assert separate.id != original.id
    assert separate.generation == 1
    assert separate.node == "node-2"


def test_cli_operator_to_connector_preserves_private_inventory_fields(
    tmp_path, tls, monkeypatch, capsys
):
    db = tmp_path / "fleet.sqlite"
    invitation = tmp_path / "invite"
    native_id = "a" * 20
    guest_uid = "b" * 20
    observed_at = datetime.now(UTC) - timedelta(seconds=2)
    registered_at = int(observed_at.timestamp() * 1000) - 1000

    def invoke(command, *options, code=0, database=True):
        args = ["fleet", command]
        if database:
            args.extend(("--db", str(db)))
        with pytest.raises(SystemExit) as result:
            cli.main([*args, *map(str, options)])
        assert result.value.code == code
        return capsys.readouterr()

    site = json.loads(invoke("register-site", "--name", "site").out)
    host = json.loads(invoke("register-host", "--site-id", site["id"], "--name", "host").out)
    agent = json.loads(invoke("register-agent", "--host-id", host["id"], "--name", "connector").out)
    instance_record = invoke(
        "register-instance",
        "--site-id",
        site["id"],
        "--kind",
        "standalone",
        "--native-id",
        native_id,
    )
    assert native_id not in instance_record.out
    instance = json.loads(instance_record.out)
    route_record = invoke(
        "confirm-route",
        "--instance-id",
        instance["id"],
        "--host-id",
        host["id"],
        "--api-name",
        "pve-a.internal",
        "--node",
        "node-a",
        "--address",
        "192.0.2.10",
        "--native-id",
        native_id,
        "--leaf-sha256",
        "cd" * 32,
    )
    assert native_id not in route_record.out
    route = json.loads(route_record.out)

    cert, key, fingerprint = tls["first"]
    assert invoke("key-fingerprint", "--cert-file", cert, database=False).out.strip() == fingerprint
    issue_args = (
        "--agent-id",
        agent["id"],
        "--key-fingerprint",
        fingerprint,
        "--capability",
        "pve_inventory",
        "--route-id",
        route["id"],
        "--invite-out",
        invitation,
    )
    issued = invoke("issue-invite", *issue_args)
    token = invitation.read_text().strip()
    assert token and token not in issued.out
    assert stat.S_IMODE(invitation.stat().st_mode) == 0o600
    assert token not in invoke("issue-invite", *issue_args, code=1).err
    assert invitation.read_text().strip() == token

    pve_ca = tmp_path / "pve-ca"
    pve_ref = f"file:{tmp_path / 'pve-token'}"
    collected = []

    def collect(approved, *, ca_file, token_ref):
        assert (approved.route_id, approved.address) == (route["id"], "192.0.2.10")
        assert (ca_file, token_ref) == (pve_ca, pve_ref)
        collected.append(approved)
        return sample_snapshot(
            api_name=approved.api_name,
            node=approved.node,
            uid=guest_uid,
            observed_at=observed_at,
            registration_ms=registered_at,
        )

    monkeypatch.setattr(fleet_cli, "collect_pve_inventory", collect)
    with loopback(FleetEnrollment(FleetIdentityRegistry(db)), tls) as client:
        agent_client, _ = client("first")
        connection = (
            "--endpoint",
            f"https://127.0.0.1:{agent_client.port}",
            "--cert-file",
            cert,
            "--key-file",
            key,
            "--server-ca-file",
            tls["server"][0],
        )
        collect_args = (*connection, "--pve-ca-file", pve_ca, "--pve-token-ref", pve_ref)
        invoke("collect-pve", *collect_args, code=1, database=False)
        assert collected == []
        enroll_args = (*connection, "--invite-file", invitation)
        invitation.chmod(0o644)
        assert token not in invoke("enroll", *enroll_args, code=1, database=False).err
        invitation.chmod(0o600)
        result = invoke("enroll", *enroll_args, database=False)
        assert token not in result.out
        assert json.loads(result.out)["generation"] == 1
        receipt = invoke("collect-pve", *collect_args, database=False)
        assert json.loads(receipt.out)["coverage"] == "token_scope"
        history = invoke("guest-history", "--instance-id", instance["id"], "--vmid", "190")
        assert json.loads(history.out)[0]["state"] == "present"
        for output in (receipt.out, history.out):
            assert guest_uid not in output
            assert str(registered_at) not in output
            assert pve_ref not in output
        invoke("revoke", "--agent-id", agent["id"], "--generation", "1")
        invoke("collect-pve", *collect_args, code=1, database=False)
        assert len(collected) == 1
