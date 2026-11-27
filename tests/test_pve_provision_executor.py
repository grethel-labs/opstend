import json
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path
from subprocess import CompletedProcess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from steward.cli import main as cli
from steward.core import pve_power
from steward.core.audit import AuditLog
from steward.core.pve_provision import ProvisionedGuest, ProvisionPolicy, TemplateEvidence
from steward.executor import pve_provision as executor
from steward.executor.protocol import PROTOCOL_VERSION, ExecutorError

ACTOR = "opstend-clone@pve!provision"
GENERATION_UID = "abcdefghijklmnopqrst"
EPOCH_MS = 1795737600000
NOW = datetime.fromtimestamp(EPOCH_MS / 1000 + 30, UTC)
TEMPLATE_DIGEST = "a" * 40
NETWORK = {"index": 0, "bridge": "vmbr0", "link_down": True}
LIMITS = {
    "max_vcpus": 2,
    "max_memory_mib": 512,
    "max_disk_bytes": 2**31,
    "max_swap_mib": 128,
}


def frame(action, **params):
    return json.dumps(
        {"v": PROTOCOL_VERSION, "action": f"pve_provision_{action}", "params": params}
    ).encode()


@pytest.fixture(params=[("qemu", 194, 196), ("lxc", 195, 197)])
def host(tmp_path, request):
    kind, source, target = request.param
    policy = ProvisionPolicy.model_validate_json(
        json.dumps(
            {
                "schema_version": 1,
                "node": "pve",
                "write_token_file": "/root/clone-token",
                "templates": [
                    {
                        "kind": kind,
                        "vmid": source,
                        "pve_uid": GENERATION_UID,
                        "registered_at_ms": EPOCH_MS,
                        "config_digest": TEMPLATE_DIGEST,
                    }
                ],
                "targets": [
                    {
                        "vmid": target,
                        "template_vmid": source,
                        "pool": "rc2-managed",
                        "storage": "local-lvm",
                        "networks": [NETWORK],
                        "limits": LIMITS,
                    }
                ],
            }
        )
    )
    worker = "qmclone" if kind == "qemu" else "vzclone"
    upid = f"UPID:pve:00000001:00000002:{int(NOW.timestamp()):08X}:{worker}:{source}:{ACTOR}:"
    state = SimpleNamespace(
        authority=executor._Authority(policy, "a" * 64, Mock(actor=ACTOR)),
        kill=False,
        now=NOW,
    )
    evidence = Mock()
    evidence.observe_source.return_value = TemplateEvidence.model_validate_json(
        json.dumps(
            {
                "pve_uid": GENERATION_UID,
                "registered_at_ms": EPOCH_MS,
                "config_digest": TEMPLATE_DIGEST,
                "profile": {
                    "vcpus": 1,
                    "memory_mib": 256,
                    "disk_bytes": 2**30,
                    "swap_mib": 0,
                    "networks": [NETWORK],
                },
            }
        )
    )
    evidence.verify_target.return_value = ProvisionedGuest(
        pve_uid="zyxwvutsrqponmlkjihg", registered_at_ms=EPOCH_MS + 30000
    )
    api = state.authority.api
    api.dispatch.return_value = upid
    api.recent_tasks.return_value = ()
    api.task.return_value = "succeeded"
    api.completion_time.return_value = int(NOW.timestamp()) + 5
    journal = pve_power.PowerJournal(tmp_path)
    audit_path = tmp_path / "audit.jsonl"

    def restart():
        return executor.ProvisionExecutor(
            journal,
            AuditLog(audit_path),
            lambda: state.authority,
            lambda: state.kill,
            evidence,
            now=lambda: state.now,
        )

    def plan(**changes):
        params = {"template_vmid": source, "vmid": target, "name": "approved-clone", **changes}
        return restart().handle(frame("plan", **params))

    return SimpleNamespace(
        api=api,
        audit_path=audit_path,
        evidence=evidence,
        journal=journal,
        plan=plan,
        restart=restart,
        source=source,
        target=target,
        state=state,
        upid=upid,
    )


def test_full_clone_replay_and_readback(host):
    planned = host.plan()["result"]
    job_id = planned["job_id"]
    assert planned["source"]["vmid"] == host.source
    assert planned["target"]["vmid"] == host.target
    assert planned["state"] == "prepared"
    seen_dispatch = []

    def dispatch(job, *, dispatched_at):
        record = host.journal.get_provision(job.job_id)
        seen_dispatch.append((record.state, record.legs[0].prior_upids))
        return host.upid

    host.api.dispatch.side_effect = dispatch
    executed = host.restart().handle(frame("execute", job_id=job_id))["result"]
    assert executed["state"] == "accepted"
    assert seen_dispatch == [("dispatching", ())]
    assert host.restart().handle(frame("execute", job_id=job_id))["result"] == executed

    host.api.task.return_value = "running"
    assert host.restart().handle(frame("reconcile", job_id=job_id))["result"]["state"] == "accepted"
    host.evidence.verify_target.assert_not_called()

    host.api.task.return_value = "succeeded"
    host.evidence.verify_target.side_effect = ExecutorError("conflict", "Readback changed.")
    fenced = host.restart().handle(frame("reconcile", job_id=job_id))["result"]
    assert (fenced["state"], fenced["next_action"], fenced["error_code"]) == (
        "verifying",
        "reconcile",
        "target_mismatch",
    )
    other = host.plan()["result"]["job_id"]
    assert host.restart().handle(frame("execute", job_id=other))["error_class"] == "target_busy"
    host.api.dispatch.assert_called_once()

    host.evidence.verify_target.side_effect = None
    finished = host.restart().handle(frame("reconcile", job_id=job_id))["result"]
    assert finished["state"] == "succeeded"
    assert finished["result"]["state"] == "stopped"
    assert len(finished["result"]["generation"]) == 64
    assert host.restart().handle(frame("status", job_id=job_id))["result"] == finished
    assert host.journal.get(job_id) is None
    private = [ACTOR, host.upid, GENERATION_UID, TEMPLATE_DIGEST, "approved-clone"]
    assert all(item not in host.audit_path.read_text() for item in private)
    assert all(item not in json.dumps(finished) for item in private[:-1])


def test_missing_archived_completion_keeps_destination_fenced(host):
    job_id = host.plan()["result"]["job_id"]
    host.restart().handle(frame("execute", job_id=job_id))
    host.api.completion_time.side_effect = ExecutorError("unavailable", "Task archive unavailable.")
    fenced = host.restart().handle(frame("reconcile", job_id=job_id))["result"]
    assert (fenced["state"], fenced["next_action"], fenced["error_code"]) == (
        "verifying",
        "reconcile",
        "target_unverified",
    )
    host.evidence.verify_target.assert_not_called()
    other = host.plan()["result"]["job_id"]
    assert host.restart().handle(frame("execute", job_id=other))["error_class"] == "target_busy"

    host.api.completion_time.side_effect = None
    result = host.restart().handle(frame("reconcile", job_id=job_id))["result"]
    assert result["state"] == "succeeded"
    assert host.evidence.verify_target.call_args.kwargs == {
        "dispatched_at": NOW.timestamp(),
        "completed_at": int(NOW.timestamp()) + 5,
    }
    host.api.dispatch.assert_called_once()


@pytest.mark.parametrize("change", ["template", "policy", "expired", "kill", "acl"])
def test_execution_rechecks_current_scope(host, change):
    job_id = host.plan()["result"]["job_id"]
    authority = host.state.authority
    if change == "template":
        old = host.evidence.observe_source.return_value
        host.evidence.observe_source.return_value = old.model_copy(
            update={"config_digest": "b" * 40}
        )
    elif change == "policy":
        policy = authority.policy.model_copy(update={"write_token_file": "/root/replacement"})
        host.state.authority = executor._Authority(policy, authority.binding, authority.api)
    elif change == "expired":
        host.state.now += timedelta(minutes=5)
    elif change == "kill":
        host.state.kill = True
    else:
        host.api.validate_permissions.side_effect = ExecutorError("policy_denied", "ACL changed.")
    response = host.restart().handle(frame("execute", job_id=job_id))
    if change in {"kill", "acl"}:
        assert response["error_class"] == {"kill": "kill_switch", "acl": "policy_denied"}[change]
    else:
        assert (
            response["result"]["error_code"]
            == {
                "template": "template_changed",
                "policy": "policy_changed",
                "expired": "confirmation_expired",
            }[change]
        )
    host.api.dispatch.assert_not_called()


def test_lost_reply_requires_exact_completed_native_proof(host):
    job_id = host.plan()["result"]["job_id"]
    host.api.dispatch.side_effect = ExecutorError(
        "unavailable", "Reply lost.", outcome_unknown=True
    )
    lost = host.restart().handle(frame("execute", job_id=job_id))["result"]
    assert (lost["state"], lost["error_code"]) == ("uncertain", "dispatch_unknown")
    for action in ("execute", "reconcile"):
        assert host.restart().handle(frame(action, job_id=job_id))["result"] == lost
    supplied = frame("reconcile", job_id=job_id, upid=host.upid)
    assert host.restart().handle(supplied)["error_class"] == "conflict"
    host.api.recent_tasks.return_value = (host.upid,)
    host.api.verify_task_target.side_effect = ExecutorError("policy_denied", "Wrong target.")
    assert host.restart().handle(supplied)["error_class"] == "policy_denied"
    assert host.journal.get_provision(job_id).legs[0].upid is None
    host.api.verify_task_target.side_effect = None
    assert host.restart().handle(supplied)["result"]["state"] == "succeeded"
    assert host.api.verify_task_target.call_args.args[1] == host.upid
    host.api.dispatch.assert_called_once()


def test_dispatch_interruption_reconciles_without_second_post(host):
    job_id = host.plan()["result"]["job_id"]
    host.api.dispatch.side_effect = KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        host.restart().handle(frame("execute", job_id=job_id))
    for action, expected in (
        ("status", "dispatching"),
        ("execute", "dispatching"),
        ("reconcile", "uncertain"),
    ):
        assert host.restart().handle(frame(action, job_id=job_id))["result"]["state"] == expected
    host.api.dispatch.assert_called_once()


def test_post_permission_denial_keeps_destination_fenced(host):
    job_id = host.plan()["result"]["job_id"]
    host.api.dispatch.side_effect = ExecutorError(
        "policy_denied", "Permissions changed during clone.", outcome_unknown=True
    )
    result = host.restart().handle(frame("execute", job_id=job_id))["result"]
    assert (result["state"], result["error_code"]) == ("uncertain", "dispatch_unknown")
    assert host.restart().handle(frame("execute", job_id=job_id))["result"] == result
    other = host.plan()["result"]["job_id"]
    assert host.restart().handle(frame("execute", job_id=other))["error_class"] == "target_busy"
    host.api.dispatch.assert_called_once()


@pytest.mark.parametrize("native_collision", ["dispatch", "task", "partial"])
def test_pve_owns_collision_and_partial_task_keeps_fence(host, native_collision):
    job_id = host.plan()["result"]["job_id"]
    if native_collision == "dispatch":
        host.api.dispatch.side_effect = ExecutorError("conflict", "Already occupied.")
        result = host.restart().handle(frame("execute", job_id=job_id))["result"]
    else:
        host.restart().handle(frame("execute", job_id=job_id))
        host.api.task.return_value = "failed" if native_collision == "partial" else "vmid_conflict"
        result = host.restart().handle(frame("reconcile", job_id=job_id))["result"]
    expected = (
        ("uncertain", "native_task_failed")
        if native_collision == "partial"
        else ("failed", "vmid_conflict")
    )
    assert (result["state"], result["error_code"]) == expected
    assert host.restart().handle(frame("execute", job_id=job_id))["result"] == result
    host.evidence.verify_target.assert_not_called()
    host.api.dispatch.assert_called_once()


def test_local_frame_and_policy_scope(host, monkeypatch):
    monkeypatch.setattr(executor.install, "_locked", nullcontext)
    monkeypatch.setattr(executor, "_runtime", host.restart)
    assert executor.execute_local(b"{}", uid=1000)["error_class"] == "unauthorized_peer"
    assert executor.execute_local(b" " * 4097, uid=0)["error_class"] == "bad_request"
    duplicate = b'{"v":1,"v":1,"action":"pve_provision_plan","params":{}}'
    assert executor.execute_local(duplicate, uid=0)["error_class"] == "bad_request"
    assert host.plan(vmid="196")["error_class"] == "bad_request"
    assert host.plan(template_vmid=777)["error_class"] == "policy_denied"
    assert host.plan(name="arbitrary / arg")["error_class"] == "bad_request"
    assert (
        host.restart().handle(frame("delete", vmid=host.target))["error_class"] == "unknown_action"
    )
    host.api.dispatch.assert_not_called()


def test_cli_uses_fixed_signed_executor(monkeypatch, capsys):
    python = Path("/signed/release/venv/bin/python")
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(executor.install, "_locked", nullcontext)
    monkeypatch.setattr(pve_power, "_installed_power_runtime", lambda: ({}, {}, python))
    run = Mock(
        return_value=CompletedProcess(
            [], 0, b'{"ok":true,"result":{"schema_version":1,"state":"prepared"}}'
        )
    )
    monkeypatch.setattr(cli.subprocess, "run", run)
    args = cli.build_parser().parse_args(
        [
            "pve-native",
            "provision",
            "plan",
            "--template-vmid",
            "194",
            "--vmid",
            "196",
            "--name",
            "example",
        ]
    )
    assert args.func(args) == 0
    assert run.call_args.args[0] == [
        str(python),
        "-I",
        "-B",
        "-m",
        "steward.executor.pve_provision",
    ]
    assert run.call_args.kwargs["input"] == frame(
        "plan", template_vmid=194, vmid=196, name="example"
    )
    assert json.loads(capsys.readouterr().out)["state"] == "prepared"


@pytest.mark.parametrize("alias", ["health", "inventory", "power-user", "power-file"])
def test_provision_authority_refuses_credential_alias(host, monkeypatch, tmp_path, alias):
    provision = tmp_path / "provision.token"
    health = tmp_path / "health.token"
    inventory = tmp_path / "inventory.token"
    power = tmp_path / "power.token"
    ca = tmp_path / "ca.pem"
    monkeypatch.setattr(executor, "_STATE", tmp_path)
    monkeypatch.setattr(executor.install, "_credential", Mock())
    monkeypatch.setattr(executor.native, "_read_file", Mock(return_value=b"pinned authority"))
    monkeypatch.setattr(executor, "ProvisionApi", Mock())
    by_file = {
        provision: f"{ACTOR}=private",
        health: "health@pve!health=private",
        inventory: "inventory@pve!inventory=private",
        power: "power@pve!power=private",
    }
    if alias in {"health", "inventory", "power-user"}:
        ref = {"health": health, "inventory": inventory, "power-user": power}[alias]
        by_file[ref] = "OPSTEND-CLONE@pve!other=private"
    monkeypatch.setattr(executor.native, "_load_token", by_file.__getitem__)

    def policy_for(path, _model):
        if path.name == "provision.json":
            return host.state.authority.policy.model_copy(
                update={"write_token_file": str(provision)}
            )
        return SimpleNamespace(write_token_file=str(provision if alias == "power-file" else power))

    (tmp_path / "power.json").touch()
    monkeypatch.setattr(executor, "_read_policy", policy_for)
    installed = {
        "intent": {
            "refs": [str(ca), str(health)],
            "inventory_token_file": str(inventory),
            "api_name": "pve.example.test",
        },
        "reservation": "native-install",
    }
    with pytest.raises(ExecutorError) as error:
        executor._authority(installed, {})
    assert error.value.error_class == "policy_denied"
    executor.ProvisionApi.assert_not_called()


def test_cli_rejects_malformed_signed_executor_response(monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(executor.install, "_locked", nullcontext)
    monkeypatch.setattr(
        pve_power, "_installed_power_runtime", lambda: ({}, {}, Path("/signed/bin/python"))
    )
    run = Mock(
        return_value=CompletedProcess(
            [], 0, b'{"ok":true,"result":{"schema_version":1,"schema_version":1}}'
        )
    )
    monkeypatch.setattr(cli.subprocess, "run", run)
    args = cli.build_parser().parse_args(
        ["pve-native", "provision", "execute", "--confirm", "a" * 32]
    )
    with pytest.raises(cli.CliError):
        args.func(args)
