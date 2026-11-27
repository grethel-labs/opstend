import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from steward.cli import fleet as fleet_cli
from steward.cli import main as cli
from steward.core.fleet_adoption_models import LocalPveProfile
from steward.core.fleet_connector import collect_pve_adoption, pve_instance_binding
from steward.core.fleet_enrollment import FleetEnrollment
from steward.core.fleet_identity import FleetIdentityRegistry
from steward.fleet_transport import FleetTransportError
from test_fleet_connector import LOCAL_NODE, NATIVE_ID, RESOURCES, STATUS, resolve_as
from test_fleet_transport import loopback
from test_fleet_transport import tls as tls
from test_pve_inventory import guest, payload
from test_pve_native import API_NAME, API_TOKEN, PERMISSIONS_PATH, VERSION_PATH
from test_pve_native import pve_api as pve_api
from test_pve_native import pve_tls as pve_tls
from test_pve_native import token_file as token_file

BACKUP = "/api2/json/cluster/backup"
VM = "/api2/json/nodes/node-a/qemu/190"
CONFIG = f"{VM}/config?current=1"
RRD = f"{VM}/rrddata?timeframe=hour&cf=AVERAGE"
ACL = {"/": {"Sys.Audit": 0}, "/vms/190": {"VM.Audit": 1}}
UID = "b" * 20
RTIME = 1_700_000_001_000
JOB_ID = "private-job-identifier"
RAW = "private-backup-content"


@pytest.fixture
def adopted_source(pve_api, monkeypatch):
    ca, responses, calls = pve_api
    resolve_as(monkeypatch, "127.0.0.1")
    responses.update(
        {
            STATUS: payload([{**LOCAL_NODE, "cluster-id": NATIVE_ID}]),
            RESOURCES: payload([guest("qemu", 190, node="node-a", uid=UID, rtime=RTIME)]),
            PERMISSIONS_PATH: payload(ACL),
            BACKUP: payload(
                [
                    {
                        "id": JOB_ID,
                        "vmid": "190",
                        "schedule": "mon..fri 02:30",
                        "enabled": 1,
                        "storage": RAW,
                        "notes-template": RAW,
                        "script": RAW,
                    },
                    {"id": "hidden", "vmid": "191"},
                    {"id": "mixed", "vmid": "190,191"},
                    {"id": "all", "vmid": "190", "all": 1},
                    {"id": "pool", "vmid": "190", "pool": RAW},
                    {"id": "exclude", "vmid": "190", "exclude": "191"},
                    {"id": "other-node", "vmid": "190", "node": "node-b"},
                    {"id": "duplicate", "vmid": "190"},
                    {"id": "duplicate", "vmid": "191"},
                ]
            ),
        }
    )
    leaf = x509.load_pem_x509_certificate(ca.read_bytes()).public_bytes(serialization.Encoding.DER)
    return ca, responses, calls, sha256(leaf).hexdigest()


def test_adoption_cli_mtls_detach_and_rejoin(
    tmp_path, tls, adopted_source, token_file, capsys, monkeypatch
):
    pve_ca, responses, calls, leaf = adopted_source
    db = tmp_path / "fleet.sqlite"
    registry = FleetIdentityRegistry(db)
    enrollment = FleetEnrollment(registry)
    site = registry.register_site("site")
    host = registry.register_host(site.id, "host")
    agent = registry.register_agent(host.id, "connector")
    other = registry.register_agent(host.id, "other-connector")
    pending = registry.register_agent(host.id, "pending-connector")
    binding = pve_instance_binding(NATIVE_ID)
    instance = registry.register_instance(site.id, kind="standalone", instance_binding=binding)
    route_options = {
        "host_id": host.id,
        "api_name": API_NAME,
        "node": "node-a",
        "address": "127.0.0.1",
        "transport_fingerprint": leaf,
        "instance_binding": binding,
    }
    route = registry.confirm_route(instance.id, **route_options)

    def invoke(command, *options, code=0, local=True):
        args = ["fleet", command]
        if local:
            args += ["--db", str(db)]
        with pytest.raises(SystemExit) as result:
            cli.main([*args, *map(str, options)])
        assert result.value.code == code
        output = capsys.readouterr()
        for sensitive in (API_TOKEN, str(token_file), RAW, JOB_ID, UID, str(RTIME), NATIVE_ID):
            assert sensitive not in output.out + output.err
        return json.loads(output.out) if code == 0 else None

    def issue(which, agent_id, generation=0, *, code=0):
        invitation = tmp_path / f"{which}.invite"
        invoke(
            "rotate" if generation else "issue-invite",
            "--agent-id",
            agent_id,
            "--capability",
            "pve_inventory",
            "--route-id",
            route.id,
            "--key-fingerprint",
            tls[which][2],
            "--generation",
            generation,
            "--invite-out",
            invitation,
            code=code,
        )
        return invitation

    def connection(client, which):
        cert, key, _ = tls[which]
        return (
            "--endpoint",
            f"https://127.0.0.1:{client.port}",
            "--cert-file",
            cert,
            "--key-file",
            key,
            "--server-ca-file",
            tls["server"][0],
        )

    adopt_options = (
        "--instance-id",
        instance.id,
        "--agent-id",
        agent.id,
        "--route-id",
        route.id,
        "--native-id",
        NATIVE_ID,
    )
    show_options = ("--instance-id", instance.id)
    pve_options = ("--pve-ca-file", pve_ca, "--pve-token-ref", f"file:{token_file}")
    first_invite = issue("first", agent.id)
    other_invite = issue("wrong", other.id)
    pending_invite = issue("next", pending.id)
    profile = LocalPveProfile(
        instance_binding=binding, node="node-a", version="1.2.3", observed_at=datetime.now(UTC)
    )
    monkeypatch.setattr(fleet_cli, "export_pve_profile", lambda: profile)
    profile_path = tmp_path / "pve-profile.json"
    exported = invoke("export-pve-profile", local=False)
    assert exported == profile.model_dump(mode="json")
    profile_path.write_text(profile.model_dump_json())
    profile_path.chmod(0o644)

    with loopback(enrollment, tls) as connect:
        first, _ = connect("first")
        second, _ = connect("wrong")
        next_client, _ = connect("next")
        first_connection = connection(first, "first")
        collect_options = (*first_connection, *pve_options)
        invoke("collect-pve-adoption", *collect_options, code=1, local=False)
        assert calls == []
        enrolled = invoke("enroll", *first_connection, "--invite-file", first_invite, local=False)
        second.enroll(other_invite.read_text().strip())
        assert enrolled["generation"] == 1
        profile_options = ("--generation", 1, "--local-profile", profile_path)
        invoke("adopt-pve", *adopt_options, *profile_options, code=1)
        profile_path.chmod(0o600)
        for trailing in (',"node":"node-a"}', ',"private":"secret"}'):
            profile_path.write_text(profile.model_dump_json()[:-1] + trailing)
            invoke("adopt-pve", *adopt_options, *profile_options, code=1)
        profile_path.write_text(profile.model_dump_json())
        attached = invoke("adopt-pve", *adopt_options, *profile_options)
        assert attached["status"] == "attached"
        with pytest.raises(FleetTransportError):
            second.begin_adoption()

        receipt = invoke("collect-pve-adoption", *collect_options, local=False)
        assert receipt["coverage"] == "token_scope"
        paths = [
            VERSION_PATH,
            PERMISSIONS_PATH,
            STATUS,
            BACKUP,
            RESOURCES,
            CONFIG,
            RRD,
            VERSION_PATH,
            PERMISSIONS_PATH,
            RESOURCES,
            STATUS,
        ]
        assert calls == [("GET", path, f"PVEAPIToken={API_TOKEN}") for path in paths]
        shown = invoke("show-adoption", *show_options)
        assert shown["authority"] == "local"
        assert shown["local_profile"]["installed_roles"] == ["agent", "ui"]
        assert shown["local_profile"]["source"] == "operator_local_export"
        assert "instance_binding" not in shown["local_profile"]
        assert shown["history"] == []
        current = shown["current"]
        assert current["schedule_state"] == "observed"
        assert current["schedule_source"] == "pve_cluster_backup"
        assert current["audit_privileges"] == ["Sys.Audit", "VM.Audit"]
        (job,) = current["schedules"]
        assert job["schedule"] == "mon..fri 02:30" and job["enabled"]
        (guest_id,) = job["guest_ids"]
        (capture_ref,) = current["capture_refs"]
        aged = enrollment.show_adoption(
            instance.id, history=True, now=datetime.now(UTC) + timedelta(seconds=301)
        )
        assert aged.current is None and aged.history[0].capture_refs == (capture_ref,)

        # A failed refresh clears current evidence, including any previous schedules.
        responses[PERMISSIONS_PATH] = (403, b"")
        invoke("collect-pve-adoption", *collect_options, code=1, local=False)
        assert invoke("show-adoption", *show_options)["current"] is None
        responses[PERMISSIONS_PATH] = payload(ACL)
        generation, approved_route, attempt = first.begin_adoption()
        snapshot, evidence = collect_pve_adoption(
            approved_route, ca_file=pve_ca, token_ref=f"file:{token_file}"
        )

        invoke("detach-pve", *show_options, "--revision", 999, code=1)
        detached = invoke("detach-pve", *show_options, "--revision", attached["revision"])
        assert detached["status"] == "detached"
        for client in (first, second):
            with pytest.raises(FleetTransportError):
                client.connector_route()
            with pytest.raises(FleetTransportError):
                client.begin_adoption()
        with pytest.raises(FleetTransportError):
            first.publish_adoption(generation, attempt, snapshot, evidence)
        with pytest.raises(FleetTransportError):
            next_client.enroll(pending_invite.read_text().strip())

    restarted = FleetEnrollment(FleetIdentityRegistry(db))
    historical = invoke("show-adoption", *show_options, "--history")
    assert historical["authority"] == "local"
    assert historical["current"] is historical["local_profile"] is None
    assert historical["history"] == [
        {
            "observation_id": current["observation_id"],
            "observed_at": current["observed_at"],
            "job_refs": [job["job_ref"]],
            "capture_refs": [capture_ref],
        }
    ]
    assert FleetIdentityRegistry(db).confirm_route(instance.id, **route_options).id == route.id
    pending_invite.unlink()
    assert not issue("next", pending.id, code=1).exists()
    new_invite = issue("next", agent.id, detached["grant_generation"])
    with loopback(restarted, tls) as connect:
        new, _ = connect("next")
        fresh_connection = connection(new, "next")
        new_grant = invoke("enroll", *fresh_connection, "--invite-file", new_invite, local=False)
        assert new_grant["generation"] > generation
        with pytest.raises(FleetTransportError):
            new.begin_adoption()
        rejoined = invoke("adopt-pve", *adopt_options, "--generation", new_grant["generation"])
        assert rejoined["revision"] > detached["revision"]
        new.begin_adoption()
        with pytest.raises(FleetTransportError):
            new.publish_adoption(new_grant["generation"], attempt, snapshot, evidence)
        invoke("collect-pve-adoption", *fresh_connection, *pve_options, local=False)
        view = invoke("show-adoption", *show_options, "--history")
        assert view["current"]["schedules"] == [job]
        assert view["current"]["capture_refs"] == [capture_ref]
        assert len(view["history"]) == 2
        history = invoke("guest-history", *show_options, "--vmid", 190)
        assert [item["id"] for item in history] == [guest_id]


@pytest.mark.parametrize("change", ["roster", "permissions", "job-http", "job-invalid"])
def test_pve_schedule_projection_requires_current_token_scope(
    change, adopted_source, token_file, tmp_path
):
    ca, responses, calls, leaf = adopted_source
    registry = FleetIdentityRegistry(tmp_path / "fleet.sqlite")
    site = registry.register_site("site")
    host = registry.register_host(site.id, "host")
    binding = pve_instance_binding(NATIVE_ID)
    instance = registry.register_instance(site.id, kind="standalone", instance_binding=binding)
    confirmed = registry.confirm_route(
        instance.id,
        host_id=host.id,
        api_name=API_NAME,
        node="node-a",
        address="127.0.0.1",
        transport_fingerprint=leaf,
        instance_binding=binding,
    )
    route = registry.get_connector_route(confirmed.id)
    assert route is not None

    if change in {"roster", "permissions"}:
        path = RESOURCES if change == "roster" else PERMISSIONS_PATH
        initial = responses[path]
        final = payload([] if change == "roster" else {"/": {"Sys.Audit": 0}})
        phases = iter((initial, final))
        responses[path] = lambda: next(phases)
    elif change == "job-http":
        responses[BACKUP] = (403, b"")
    else:
        responses[BACKUP] = (200, b"malformed")

    snapshot, evidence = collect_pve_adoption(route, ca_file=ca, token_ref=f"file:{token_file}")
    assert evidence.schedules == ()
    assert (
        evidence.schedule_state
        == {
            "roster": "observed",
            "permissions": "observed",
            "job-http": "restricted",
            "job-invalid": "invalid",
        }[change]
    )
    assert bool(snapshot.guests) == (change in {"job-http", "job-invalid"})
    if change == "permissions":
        assert evidence.audit_privileges == ("Sys.Audit",)
    assert [path for _, path, _ in calls].count(BACKUP) == 1
