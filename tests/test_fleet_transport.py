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
from steward.core.fleet_adoption_models import (
    PveAdoptionEvidence,
    PveBackupSchedule,
    pve_backup_job_ref,
)
from steward.core.fleet_enrollment import FleetEnrollment, FleetEnrollmentConflict
from steward.core.fleet_identity import FleetIdentityRegistry
from steward.core.fleet_ownership import OwnershipExchange, OwnershipReceipt
from steward.core.fleet_ownership_coordinator import FleetOwnershipCoordinator
from steward.core.fleet_policy import (
    FleetPolicy,
    FleetPolicyValues,
    FleetTarget,
    FleetTargetPolicy,
    RoleAssignment,
)
from steward.core.fleet_policy_apply import (
    FleetPolicyActor,
    FleetPolicyApply,
    FleetPolicyDenied,
    FleetPolicyGrant,
    FleetPolicyNotFound,
)
from steward.core.fleet_policy_target import FleetPolicyTargetConfig, FleetPolicyTargetStore
from steward.core.fleet_power import CommandPoll, CommandReport
from steward.core.fleet_power_commands import FleetCommandConflict, FleetPowerCommands
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
        "reader": certificate(tmp_path, "reader", authority),
        "untrusted": certificate(tmp_path, "untrusted", outsider),
        "wrong_ca": outsider_ca,
    }


@contextmanager
def loopback(enrollment, tls, *, include_endpoint=False):
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
            endpoint = f"https://127.0.0.1:{server.server_port}"
            yield (client, endpoint) if include_endpoint else client
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


@pytest.mark.parametrize("receipt_delivered", [False, True], ids=["receipt-lost", "ack-lost"])
def test_mtls_policy_converges_independent_targets_and_recovers_lost_ack(
    tmp_path, tls, capsys, receipt_delivered
):
    registry = FleetIdentityRegistry(tmp_path / "fleet.sqlite")
    site = registry.register_site("site")
    first_host, second_host = (
        registry.register_host(site.id, name) for name in ("first", "second")
    )
    first_agent = registry.register_agent(first_host.id, "policy")
    second_agent = registry.register_agent(second_host.id, "policy")
    reader_agent = registry.register_agent(first_host.id, "reader")
    first_target = FleetTarget(kind="host", id=first_host.id)
    second_target = FleetTarget(kind="host", id=second_host.id)
    first_path, second_path = tmp_path / "first.sqlite", tmp_path / "second.sqlite"
    first_config = FleetPolicyTargetConfig(target=first_target, limits=FleetPolicyValues())
    first_store = FleetPolicyTargetStore.configure(first_path, first_config)
    second_store = FleetPolicyTargetStore.configure(
        second_path, FleetPolicyTargetConfig(target=second_target, limits=FleetPolicyValues())
    )
    actor = FleetPolicyActor("coordinator", True)
    service = FleetPolicyApply(registry)
    enrollment = FleetEnrollment(registry)
    targets = (first_target, second_target)
    policy = FleetPolicy(targets=tuple(FleetTargetPolicy(target=t) for t in targets))
    initial = service.commit(actor, policy, parent=None)

    def target_view(target):
        return next(item for item in service.head(actor).targets if item.target == target)

    def approval_outcomes(approval):
        return {item.target: item.status for item in service.approval(actor, approval.id).outcomes}

    with loopback(enrollment, tls, include_endpoint=True) as (client, endpoint):
        first, first_key = client("first")
        second, second_key = client("wrong")
        reader, reader_key = client("reader")
        for agent, connection, key, target in (
            (first_agent, first, first_key, first_target),
            (second_agent, second, second_key, second_target),
            (reader_agent, reader, reader_key, None),
        ):
            invitation = enrollment.issue(
                agent.id,
                key_fingerprint=key,
                capability="policy_target" if target is not None else "heartbeat",
                target=target,
            )
            connection.enroll(invitation.token.get_secret_value())

        def sync_cli(*args):
            cert, key, _ = tls["first"]
            parsed = cli.build_parser().parse_args(
                [
                    "fleet",
                    "policy-target-sync",
                    "--target-db",
                    str(first_path),
                    "--endpoint",
                    endpoint,
                    "--cert-file",
                    str(cert),
                    "--key-file",
                    str(key),
                    "--server-ca-file",
                    str(tls["server"][0]),
                    *args,
                ]
            )
            result = parsed.func(parsed)
            return result, capsys.readouterr()

        assert target_view(first_target).local_revision is None
        assert sync_cli("--approval-id", "incomplete")[0] == 1
        status, output = sync_cli()
        assert status == 0
        assert json.loads(output.out)["target"] == first_target.model_dump()
        assert second_store.reconcile(second.reconcile_policy).outcome is None
        for wrong_client in (second, reader):
            with pytest.raises(FleetTransportError):
                first_store.reconcile(wrong_client.reconcile_policy)

        plan = service.preview(actor, initial.id, targets)
        assert {item.effective.status for item in plan.targets} == {"ready"}
        approval = service.approve(actor, plan.digest, "initial")
        assert approval_outcomes(approval) == dict.fromkeys(targets, "pending")
        denied = first_store.reconcile(first.reconcile_policy, approval.id, "0" * 64)
        assert denied.outcome.status == "rejected"
        assert first_store.state().applied_revision is None
        assert approval_outcomes(approval) == dict.fromkeys(targets, "pending")

        status, output = sync_cli("--approval-id", approval.id, "--digest", plan.digest)
        assert status == 0
        assert json.loads(output.out)["outcome"]["status"] == "applied"
        assert first_store.state().applied_revision == initial.id
        assert target_view(first_target).applied_revision == initial.id
        assert approval_outcomes(approval) == {first_target: "applied", second_target: "pending"}
        assert second_store.state().applied_revision is None
        late = second_store.reconcile(second.reconcile_policy, approval.id, plan.digest)
        assert late.outcome.status == "applied"
        assert approval_outcomes(approval) == dict.fromkeys(targets, "applied")

        following = service.commit(actor, policy, parent=initial.id)
        plan = service.preview(actor, following.id, targets)
        approval = service.approve(actor, plan.digest, "next")
        captured = []

        def lose_ack(request):
            if request.receipt is not None:
                captured.append(request)
                if receipt_delivered:
                    first.reconcile_policy(request)
                raise FleetTransportError("simulated lost receipt exchange")
            return first.reconcile_policy(request)

        with pytest.raises(FleetTransportError, match="simulated lost"):
            first_store.reconcile(lose_ack, approval.id, plan.digest)
        assert first_store.state().applied_revision == following.id
        assert approval_outcomes(approval)[first_target] == (
            "applied" if receipt_delivered else "pending"
        )

        latest = service.commit(actor, policy, parent=following.id)
        rotated, rotated_key = client("next")
        rotation = enrollment.issue(
            first_agent.id,
            key_fingerprint=rotated_key,
            capability="policy_target",
            target=first_target,
            expected_generation=1,
        )
        assert rotated.enroll(rotation.token.get_secret_value()).generation == 2
        with pytest.raises(FleetTransportError):
            first_store.reconcile(first.reconcile_policy)
        recovered = FleetPolicyTargetStore(first_path).reconcile(rotated.reconcile_policy)
        assert recovered.acknowledged_receipt == captured[0].receipt.claim_id
        assert recovered.outcome.status == "applied"
        assert approval_outcomes(approval)[first_target] == "applied"
        assert first_store.reconcile(rotated.reconcile_policy).outcome is None
        assert target_view(first_target).applied_revision == following.id

        latest_plan = service.preview(actor, latest.id, targets)
        latest_approval = service.approve(actor, latest_plan.digest, "latest")
        result = first_store.reconcile(
            rotated.reconcile_policy, latest_approval.id, latest_plan.digest
        )
        assert result.outcome.status == "applied"
        assert target_view(first_target).applied_revision == latest.id

        drift_plan = service.preview(actor, latest.id, (first_target,))
        drift_approval = service.approve(actor, drift_plan.digest, "drift")
        FleetPolicyTargetStore.configure(
            first_path,
            first_config.model_copy(
                update={"limits": FleetPolicyValues(backup_profile_refs=("daily",))}
            ),
        )
        drift = first_store.reconcile(
            rotated.reconcile_policy, drift_approval.id, drift_plan.digest
        )
        assert drift.outcome.reason == "local_revision_changed"
        assert drift.outcome.conflict_owner == "local_operator"
        assert target_view(first_target).conflict_owner == "local_operator"
        current = target_view(first_target)
        historical = captured[0]
        for sequence in (historical.sequence, drift.sequence + 1):
            replay = rotated.reconcile_policy(historical.model_copy(update={"sequence": sequence}))
            assert replay.acknowledged_receipt == historical.receipt.claim_id
            assert target_view(first_target) == current

        head = service.commit(actor, policy, parent=latest.id)
        head_plan = service.preview(actor, head.id, (first_target,))
        current_approval = service.approve(actor, head_plan.digest, "current-head")
        FleetPolicyTargetStore.configure(first_path, first_config)
        assert first_store.reconcile(rotated.reconcile_policy).outcome is None
        assert target_view(first_target).conflict_owner == "local_operator"
        assert approval_outcomes(current_approval) == {first_target: "pending"}

        assert enrollment.revoke(first_agent.id, expected_generation=2) == 3
        with pytest.raises(FleetTransportError):
            first_store.reconcile(rotated.reconcile_policy)
        assert first_store.state().applied_revision == latest.id


def _power_setup(tmp_path, now, *, backup_profile_refs=()):
    tmp_path.chmod(0o700)
    registry = FleetIdentityRegistry(tmp_path / "fleet.sqlite")
    site = registry.register_site("power-site")
    targets = {}
    for name, binding in (("pve-a", "aa" * 32), ("pve-b", "bb" * 32)):
        host = registry.register_host(site.id, name)
        instance = registry.register_instance(site.id, kind="standalone", instance_binding=binding)
        transport_key = "de" * 32
        route = registry.confirm_route(
            instance.id,
            host_id=host.id,
            node=name,
            api_name=f"{name}.internal",
            address="192.168.10.10",
            instance_binding=binding,
            transport_fingerprint=transport_key,
        )
        snapshot = sample_snapshot(
            api_name=route.api_name,
            node=name,
            observed_at=now,
            uid="abcde23456abcde23456",
            registration_ms=1234567890000,
        )
        registry.ingest_snapshot(
            snapshot,
            route_id=route.id,
            instance_binding=binding,
            transport_fingerprint=transport_key,
            full_guest_coverage=True,
            received_at=now,
        )
        (guest,) = registry.guest_history(instance.id, 190)
        target = FleetTarget(kind="pve_guest", id=guest.id, generation=guest.generation)
        agent = registry.register_agent(host.id, "power")
        targets[target] = agent.id

    owner = FleetPolicyActor("coordinator", True)
    operator = FleetPolicyActor("power-user")
    observer = FleetPolicyActor("observer")
    service = FleetPolicyApply(registry, clock=lambda: now)
    limits = FleetPolicyValues(
        backup_profile_refs=backup_profile_refs,
        role_assignments=(
            RoleAssignment(subject=operator.subject, role="operator"),
            RoleAssignment(subject=observer.subject, role="observer"),
        ),
    )
    body = FleetPolicy(
        defaults=limits,
        limits=limits,
        targets=tuple(FleetTargetPolicy(target=target) for target in targets),
    )
    revision = service.commit(owner, body, parent=None)
    stores = {}
    for target in targets:
        stores[target] = FleetPolicyTargetStore.configure(
            tmp_path / f"{target.id}.sqlite", FleetPolicyTargetConfig(target=target, limits=limits)
        )
        service.report_local(stores[target])
        for actor in (operator, observer):
            service.set_grant(owner, FleetPolicyGrant(actor.subject, "write", target=target))
    plan = service.preview(owner, revision.id, targets)
    approved = service.approve(owner, plan.digest, "policy-key")
    polls = []
    for target, agent_id in targets.items():
        assert service.adopt_local(stores[target], approved.id, plan.digest).status == "applied"
        polls.append(
            (
                agent_id,
                CommandPoll(
                    target=target,
                    local_revision=stores[target].state().local.revision,
                    policy_revision=revision.id,
                    policy_approval=approved.id,
                ),
            )
        )
    return registry, owner, operator, observer, service, tuple(polls)


def _power_enroll(enrollment, agent_id, fingerprint, target, *, generation=0, now=None):
    invitation = enrollment.issue(
        agent_id,
        key_fingerprint=fingerprint,
        capability="pve_power_target",
        target=target,
        expected_generation=generation,
        now=now,
    )
    return invitation.token.get_secret_value()


def _power_report(poll, work, state, **fields):
    report = CommandReport(
        command_id=work.spec.command_id,
        claim_id=work.claim_id,
        state=state,
        native_digest=work.native_digest or "c1" * 32,
        **fields,
    )
    return poll.model_copy(update={"report": report})


def test_mtls_handoff_uses_only_the_exact_power_target_grant(tmp_path, tls):
    now = datetime.now(UTC)
    registry, _, actor, _, _, ((agent, poll), (other_agent, other_poll)) = _power_setup(
        tmp_path, now, backup_profile_refs=("daily",)
    )
    enrollment = FleetEnrollment(registry)
    ownership = FleetOwnershipCoordinator(registry)
    host = registry.get_agent(agent).host_id
    with registry._connection() as db:
        route_id = db.execute("SELECT id FROM fleet_routes WHERE host_id = ?", (host,)).fetchone()[
            "id"
        ]
    route = registry.get_connector_route(route_id)
    connector = registry.register_agent(host, "handoff-inventory")
    schedule_ref = pve_backup_job_ref(route.instance_binding, "existing-job")
    with loopback(enrollment, tls) as client:
        target, target_key = client("first")
        other, other_key = client("wrong")
        reader, reader_key = client("reader")
        target.enroll(_power_enroll(enrollment, agent, target_key, poll.target))
        other.enroll(_power_enroll(enrollment, other_agent, other_key, other_poll.target))
        invitation = enrollment.issue(
            connector.id, key_fingerprint=reader_key, capability="pve_inventory", route_id=route_id
        )
        reader.enroll(invitation.token.get_secret_value())
        enrollment.adopt_pve(
            instance_id=route.instance_id,
            route_id=route_id,
            agent_id=connector.id,
            expected_generation=1,
            instance_binding=route.instance_binding,
        )
        generation, _, attempt = reader.begin_adoption()
        observed_at = datetime.now(UTC)
        reader.publish_adoption(
            generation,
            attempt,
            sample_snapshot(
                api_name=route.api_name,
                node=route.node,
                observed_at=observed_at,
                uid="abcde23456abcde23456",
                registration_ms=1234567890000,
            ),
            PveAdoptionEvidence(
                observed_at=observed_at,
                node=route.node,
                pve_version="9.3.0",
                audit_privileges=("VM.Audit",),
                schedule_state="observed",
                schedules=(
                    PveBackupSchedule(
                        job_ref=schedule_ref, schedule="03:30", enabled=True, vmids=(190,)
                    ),
                ),
            ),
        )
        handoff = ownership.request(actor, poll.target, schedule_ref, "daily", "fleet", "take", 0)
        request = OwnershipExchange(
            target=poll.target, transition_id=handoff.transition_id, digest=handoff.digest
        )
        for connection in (reader, other):
            with pytest.raises(FleetTransportError):
                connection.exchange_ownership(request)
        with pytest.raises(FleetTransportError):
            target.exchange_ownership(request.model_copy(update={"target": other_poll.target}))
        claim = target.exchange_ownership(request)
        assert claim.claim is not None
        assert claim.plan.digest == handoff.digest
        receipt = OwnershipReceipt(state="committed", epoch=1, schedule_fingerprint="d4" * 32)
        committed = target.exchange_ownership(request.model_copy(update={"receipt": receipt}))
        assert (committed.status.owner, committed.status.state) == ("fleet", "committed")
        ready = target.exchange_ownership(
            request.model_copy(update={"receipt": receipt.model_copy(update={"state": "active"})})
        )
        assert (ready.status.owner, ready.status.state) == ("fleet", "active")


def test_mtls_power_is_scoped_and_other_instance_runs_while_first_is_offline(tmp_path, tls):
    registry, owner, actor, observer, _, ((first_id, first_poll), (second_id, second_poll)) = (
        _power_setup(tmp_path, datetime.now(UTC))
    )
    commands = FleetPowerCommands(registry)
    enrollment = FleetEnrollment(registry)
    with loopback(enrollment, tls) as client:
        first, first_key = client("first")
        second, second_key = client("wrong")
        reader, reader_key = client("reader")
        for agent, poll, connection, key in (
            (first_id, first_poll, first, first_key),
            (second_id, second_poll, second, second_key),
        ):
            grant = connection.enroll(_power_enroll(enrollment, agent, key, poll.target))
            assert grant.target == poll.target
            assert grant.capability == "pve_power_target"
            with pytest.raises(FleetTransportError):
                connection.connector_route()

        with pytest.raises(FleetEnrollmentConflict):
            enrollment.issue(
                first_id,
                key_fingerprint=reader_key,
                capability="policy_target",
                target=first_poll.target,
                expected_generation=1,
            )
        with pytest.raises(FleetTransportError):
            reader.poll_power(first_poll)
        with pytest.raises(FleetTransportError):
            first.poll_power(second_poll)

        assert len({item.instance_id for item in commands.catalog(actor).targets}) == 2
        assert not commands.catalog(observer).targets
        with pytest.raises(FleetPolicyDenied):
            commands.request(owner, first_poll.target, first_poll.policy_revision, "start", "owner")
        with pytest.raises(FleetPolicyDenied):
            commands.request(
                observer, first_poll.target, first_poll.policy_revision, "start", "observer"
            )

        def request(poll, key):
            return commands.request(actor, poll.target, poll.policy_revision, "start", key)

        unavailable = request(first_poll, "first")
        active = request(second_poll, "second")
        assert request(second_poll, "second") == active
        with pytest.raises(FleetCommandConflict):
            request(first_poll, "second")
        assert not commands.catalog(observer).commands
        with pytest.raises(FleetPolicyNotFound):
            commands.status(observer, active.command_id)
        work = second.poll_power(second_poll).work
        assert work.phase == "prepare"
        assert work.spec.command_id == active.command_id
        assert second.poll_power(second_poll).work is None
        assert second.poll_power(_power_report(second_poll, work, "prepared")).work is None
        review = commands.status(actor, active.command_id)
        assert review.state == "review"
        with pytest.raises(FleetCommandConflict):
            commands.approve(actor, active.command_id, "c1" * 32, "approval")
        queued = commands.approve(actor, active.command_id, review.digest, "approval")
        assert queued.state == "queued"
        assert commands.approve(actor, active.command_id, review.digest, "approval") == queued
        work = second.poll_power(second_poll).work
        assert work.phase == "execute"
        assert work.native_digest == "c1" * 32
        assert commands.status(actor, active.command_id).state == "released"

        receipt = _power_report(second_poll, work, "accepted", task_ref="a1" * 32)
        second.poll_power(receipt)
        second.poll_power(receipt)
        work = second.poll_power(second_poll).work
        assert work.phase == "reconcile"
        forged = _power_report(
            second_poll, work, "succeeded", task_ref="a2" * 32, observed_state="running"
        )
        with pytest.raises(FleetTransportError):
            second.poll_power(forged)
        second.poll_power(
            _power_report(
                second_poll, work, "succeeded", task_ref="a1" * 32, observed_state="running"
            )
        )
        result = commands.status(actor, active.command_id)
        assert (result.state, result.observed_state, result.task_ref) == (
            "succeeded",
            "running",
            "a1" * 32,
        )
        assert "abcde23456abcde23456" not in result.model_dump_json()
        assert commands.status(actor, unavailable.command_id).state == "preparing"


def test_power_expiry_restart_revocation_and_policy_scope(tmp_path):
    now = datetime.now(UTC)
    registry, owner, actor, _, policy, ((agent_id, poll), (other_id, other_poll)) = _power_setup(
        tmp_path, now
    )
    enrollment = FleetEnrollment(registry)
    for identity, target, fingerprint in (
        (agent_id, poll.target, "11" * 32),
        (other_id, other_poll.target, "22" * 32),
    ):
        token = _power_enroll(enrollment, identity, fingerprint, target, now=now)
        enrollment.redeem(token, key_fingerprint=fingerprint, now=now)
    commands = FleetPowerCommands(registry, now=lambda: now)

    def request(request_poll, key):
        return commands.request(
            actor, request_poll.target, request_poll.policy_revision, "start", key
        )

    def queued(request_poll, key, fingerprint):
        command = request(request_poll, key)
        work = commands.poll(fingerprint, request_poll).work
        commands.poll(fingerprint, _power_report(request_poll, work, "prepared"))
        review = commands.status(actor, command.command_id)
        return commands.approve(actor, command.command_id, review.digest, key)

    first_key = "11" * 32
    first = queued(poll, "first", first_key)
    second_key = "22" * 32
    second = queued(other_poll, "second", second_key)
    issued = commands.poll(first_key, poll).work
    assert issued.phase == "execute"
    now = first.expires_at
    restarted = FleetPowerCommands(
        FleetIdentityRegistry(tmp_path / "fleet.sqlite"), now=lambda: now
    )
    assert restarted.status(actor, first.command_id).state == "uncertain"
    assert restarted.status(actor, second.command_id).state == "expired"
    work = restarted.poll(first_key, poll).work
    assert work.phase == "reconcile"
    assert work.spec.command_id == issued.spec.command_id
    assert restarted.poll(second_key, other_poll).work is None
    with pytest.raises(FleetPolicyDenied):
        restarted.poll(first_key, _power_report(poll, issued, "accepted", task_ref="a1" * 32))
    assert enrollment.revoke(agent_id, expected_generation=1) == 2
    with pytest.raises(FleetEnrollmentConflict):
        restarted.poll(first_key, poll)
    next_key = "33" * 32
    token = _power_enroll(enrollment, agent_id, next_key, poll.target, generation=2, now=now)
    enrollment.redeem(token, key_fingerprint=next_key, now=now)
    assert restarted.poll(next_key, poll).work is None
    with pytest.raises(FleetPolicyDenied):
        restarted.poll(
            next_key,
            _power_report(poll, work, "succeeded", task_ref="a1" * 32, observed_state="running"),
        )
    assert restarted.status(actor, first.command_id).state == "uncertain"
    now = work.claim_until
    rotated = restarted.poll(next_key, poll).work
    assert rotated.phase == "reconcile"
    assert rotated.spec.enrollment_generation == 1
    assert rotated.recipient_generation == 3
    restarted.poll(
        next_key,
        _power_report(poll, rotated, "succeeded", task_ref="a1" * 32, observed_state="running"),
    )
    assert restarted.status(actor, first.command_id).state == "succeeded"
    policy.set_grant(
        owner, FleetPolicyGrant(actor.subject, "write", target=poll.target), enabled=False
    )
    assert all(item.target != poll.target for item in restarted.catalog(actor).commands)


def test_power_revalidates_policy_scope_and_rotation_before_release(tmp_path):
    now = datetime.now(UTC)
    registry, owner, actor, _, policy, ((first, left), (second, right)) = _power_setup(
        tmp_path, now
    )
    enrollment = FleetEnrollment(registry)
    commands = FleetPowerCommands(registry, now=lambda: now)

    def queue(agent_id, poll, fingerprint, key):
        token = _power_enroll(enrollment, agent_id, fingerprint, poll.target, now=now)
        enrollment.redeem(token, key_fingerprint=fingerprint, now=now)
        start = commands.request(actor, poll.target, poll.policy_revision, "start", key)
        prepare = commands.poll(fingerprint, poll).work
        commands.poll(fingerprint, _power_report(poll, prepare, "prepared"))
        review = commands.status(actor, start.command_id)
        assert review.observed_state == "stopped"
        return commands.approve(actor, start.command_id, review.digest, key)

    left_key, right_key, rotated_key = "11" * 32, "22" * 32, "33" * 32
    queued_left = queue(first, left, left_key, "left")
    queued_right = queue(second, right, right_key, "right")

    writable = FleetPolicyGrant(actor.subject, "write", target=left.target)
    readable = FleetPolicyGrant(actor.subject, "read", target=left.target)
    policy.set_grant(owner, readable)
    policy.set_grant(owner, writable, enabled=False)
    assert commands.poll(left_key, left).work is None
    assert commands.status(actor, queued_left.command_id).state == "refused"

    token = _power_enroll(enrollment, second, rotated_key, right.target, generation=1, now=now)
    enrollment.redeem(token, key_fingerprint=rotated_key, now=now)
    with pytest.raises(FleetEnrollmentConflict):
        commands.poll(right_key, right)
    assert commands.poll(rotated_key, right).work is None
    assert commands.status(actor, queued_right.command_id).state == "refused"
    assert commands.request(actor, right.target, right.policy_revision, "start", "fresh").state == (
        "preparing"
    )
