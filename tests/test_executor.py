import json
import os
import subprocess
import sys
import threading
import time
import uuid
from contextlib import contextmanager

import pytest

from steward.executor import server as executor_server
from steward.executor.protocol import ExecutorError, call

ME = os.getuid()


def request(action, params=None, **overrides):
    body = {
        "v": 1,
        "action": action,
        "params": params or {},
        "request_id": uuid.uuid4().hex,
        "expires_at": time.time() + 60,
    }
    body.update(overrides)
    return json.dumps(body).encode()


RESTART = {"project_id": "notes", "reason": "test"}


def test_group_locks_release_partial_acquisition_on_conflict(executor):
    with executor.target_lock("project-zebra"):
        with (
            pytest.raises(ExecutorError) as error,
            executor.target_locks(["project-zebra", "project-alpha"]),
        ):
            pytest.fail("overlapping group must not acquire all locks")
        assert error.value.error_class == "target_busy"
        # The lexically earlier lock acquired before the conflict was released.
        with executor.target_lock("project-alpha"):
            pass
    with executor.target_locks(["project-zebra", "project-alpha"]):
        with pytest.raises(ExecutorError) as error, executor.target_lock("project-alpha"):
            pytest.fail("group lock must exclude a single-target mutation")
        assert error.value.error_class == "target_busy"


def test_group_lock_excludes_other_process(executor):
    probe = (
        "import fcntl,os,sys;fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT,0o600);"
        "fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)"
    )
    path = str(executor.lock_dir / "project-alpha.lock")
    with executor.target_locks(["application-stack", "project-alpha"]):
        result = subprocess.run([sys.executable, "-c", probe, path], capture_output=True)
        assert result.returncode != 0
    result = subprocess.run([sys.executable, "-c", probe, path], capture_output=True)
    assert result.returncode == 0


def test_group_locks_release_after_operation_failure(executor):
    with (
        pytest.raises(RuntimeError, match="operation failed"),
        executor.target_locks(["application-stack", "project-alpha"]),
    ):
        raise RuntimeError("operation failed")
    with executor.target_lock("application-stack"), executor.target_lock("project-alpha"):
        pass


def test_group_lock_order_is_independent_of_request_order(executor, monkeypatch):
    observed = []
    original = executor.target_lock

    @contextmanager
    def recorded(target):
        observed.append(target)
        with original(target):
            yield

    monkeypatch.setattr(executor, "target_lock", recorded)
    with executor.target_locks(["project-zebra", "application-stack", "project-alpha"]):
        pass
    assert observed == ["application-stack", "project-alpha", "project-zebra"]


def test_group_locks_accept_one_application_and_64_services(executor):
    targets = ["application-stack", *(f"project-test{i:02d}" for i in range(64))]
    with executor.target_locks(targets):
        assert len(list(executor.lock_dir.glob("*.lock"))) == 65


@pytest.mark.parametrize(
    "targets",
    [
        [],
        ["project-valid", "project-valid"],
        ["project-../../etc"],
        ["unknown-valid"],
        ["project-valid", None],
        [f"project-test{i:02d}" for i in range(66)],
    ],
)
def test_group_locks_reject_invalid_or_unbounded_targets(executor, targets):
    with (
        pytest.raises(ValueError, match="invalid group lock targets"),
        executor.target_locks(targets),
    ):
        pytest.fail("invalid targets must be rejected before locking")
    assert not list(executor.lock_dir.glob("*.lock"))


def test_status_reports_verified_isolation(executor):
    result = executor.handle(request("platform_status"), ME)
    assert result["ok"]
    project = result["result"]["projects"]["notes"]
    assert project["health"]["ok"] and project["hardening"]["violations"] == []


def test_isolation_drift_is_detected(executor):
    host_config = executor.host.container_info["HostConfig"]
    host_config.update(ReadonlyRootfs=False, Privileged=True, NetworkMode="host", Memory=0)
    executor.host.container_info["Config"]["User"] = ""
    violations = executor.handle(request("platform_status"), ME)["result"]["projects"]["notes"][
        "hardening"
    ]["violations"]
    assert set(violations) == {
        "read_only_rootfs",
        "not_privileged",
        "no_host_network",
        "memory_limit",
        "non_root_user",
    }


def test_unknown_peer_is_rejected_and_audited(executor):
    result = executor.handle(request("platform_status"), 31337)
    assert result["error_class"] == "unauthorized_peer"
    assert executor.audit.read()[-1]["outcome"] == "unauthorized_peer"
    assert executor.audit.read()[-1]["peer_uid"] == 31337


def test_role_cannot_call_actions_outside_its_set(executor):
    # the api role may not touch the firewall; the controller may not read the audit log
    assert executor.handle(request("firewall_reassert"), ME)["error_class"] == "forbidden_role"
    assert executor.handle(request("audit_tail"), 4242)["error_class"] == "forbidden_role"


@pytest.mark.parametrize(
    "action, params",
    [
        ("run_shell", {"cmd": "id"}),
        ("ansible_playbook", {"playbook": "/tmp/x.yml"}),
        ("../platform_status", {}),
    ],
)
def test_unregistered_actions_do_not_exist(executor, action, params):
    assert executor.handle(request(action, params), ME)["error_class"] == "unknown_action"
    assert executor.host.calls == []


@pytest.mark.parametrize(
    "params",
    [
        {"project_id": "notes; reboot", "reason": "x"},
        {"project_id": "../../etc", "reason": "x"},
        {"project_id": "notes", "reason": "x", "unit": "ssh.service"},
        {"project_id": "notes", "reason": "line\nbreak"},
        {"project_id": "notes"},
    ],
)
def test_parameters_are_schema_checked(executor, params):
    assert executor.handle(request("workload_restart", params), ME)["error_class"] == "bad_request"
    assert executor.host.calls == []


def test_restart_runs_for_registered_project_with_contract(executor):
    result = executor.handle(request("workload_restart", RESTART), ME)
    assert result["ok"]
    assert executor.host.calls == [("restart", "stw-notes", "notes.service")]


def test_restart_without_maintenance_contract_is_denied(executor):
    registry = json.loads(executor.registry_file.read_text())
    registry["projects"]["notes"]["allow_restart"] = False
    executor.registry_file.write_text(json.dumps(registry))
    result = executor.handle(request("workload_restart", RESTART), ME)
    assert result["error_class"] == "policy_denied" and executor.host.calls == []


def test_unregistered_project_is_denied(executor):
    result = executor.handle(
        request("workload_restart", {"project_id": "other", "reason": "x"}), ME
    )
    assert result["error_class"] == "policy_denied"


def test_kill_switch_stops_mutations_but_not_observation(executor):
    executor.host.killed = True
    assert executor.handle(request("workload_restart", RESTART), ME)["error_class"] == "kill_switch"
    assert executor.handle(request("platform_status"), ME)["result"]["kill_switch"] is True
    assert executor.host.calls == []
    assert executor.audit.read()[-1]["outcome"] == "kill_switch"  # audit keeps working


def test_replayed_request_is_rejected(executor):
    raw = request("workload_restart", RESTART)
    assert executor.handle(raw, ME)["ok"]
    assert executor.handle(raw, ME)["error_class"] == "replay"
    assert len(executor.host.calls) == 1


def test_expired_or_far_future_requests_are_rejected(executor):
    old = request("workload_restart", RESTART, expires_at=time.time() - 1)
    far = request("workload_restart", RESTART, expires_at=time.time() + 86400)
    assert executor.handle(old, ME)["error_class"] == "expired"
    assert executor.handle(far, ME)["error_class"] == "bad_request"
    assert executor.host.calls == []


def test_restart_budget_is_enforced(executor):
    for _ in range(executor_server.RESTART_BUDGET_PER_HOUR):
        assert executor.handle(request("workload_restart", RESTART), ME)["ok"]
    assert (
        executor.handle(request("workload_restart", RESTART), ME)["error_class"]
        == "budget_exhausted"
    )


def test_concurrent_mutation_of_one_target_is_refused(executor):
    release = threading.Event()
    entered = threading.Event()

    def slow_restart(user, unit):
        entered.set()
        release.wait(5)
        return True, ""

    executor.host.restart_user_unit = slow_restart
    results = []
    thread = threading.Thread(
        target=lambda: results.append(executor.handle(request("workload_restart", RESTART), ME))
    )
    thread.start()
    assert entered.wait(5)
    assert executor.handle(request("workload_restart", RESTART), ME)["error_class"] == "target_busy"
    release.set()
    thread.join()
    assert results[0]["ok"]


def test_registry_writable_by_others_is_refused(executor):
    executor.registry_file.chmod(0o666)
    assert executor.handle(request("platform_status"), ME)["error_class"] == "internal"


def test_registry_symlink_is_refused(executor, tmp_path):
    real = tmp_path / "real.json"
    real.write_text(executor.registry_file.read_text())
    executor.registry_file.unlink()
    executor.registry_file.symlink_to(real)
    assert executor.handle(request("platform_status"), ME)["ok"] is False


def test_malformed_requests(executor):
    assert executor.handle(b"not json", ME)["error_class"] == "bad_request"
    assert executor.handle(request("platform_status", v=2), ME)["error_class"] == "bad_request"
    assert (
        executor.handle(request("platform_status", request_id="x"), ME)["error_class"]
        == "bad_request"
    )


def test_mutations_and_refusals_are_audited_individually_in_an_intact_chain(executor):
    executor.handle(request("platform_status"), ME)
    executor.handle(request("workload_restart", RESTART), ME)
    executor.handle(request("nope"), ME)
    ok, count = executor.audit.verify()
    assert ok and count == 2  # the successful read is counted, not logged one by one
    assert [e["action"] for e in executor.audit.read()] == ["workload_restart", "nope"]


def test_successful_reads_become_one_summary_per_interval(executor):
    start = time.time()
    executor._reads_since = start
    for offset in (1, 2, 3):
        executor.count_read("api", "platform_status", now=start + offset)
    executor.count_read("controller", "platform_status", now=start + 10)
    assert executor.audit.read() == []
    executor.count_read("api", "audit_tail", now=start + executor_server.READ_SUMMARY_INTERVAL_S)
    summary = executor.audit.read()[-1]
    assert summary["event"] == "reads"
    assert summary["counts"] == {
        "api:platform_status": 3,
        "controller:platform_status": 1,
        "api:audit_tail": 1,
    }


def test_refused_reads_are_still_audited(executor):
    assert executor.handle(request("audit_tail"), 4242)["error_class"] == "forbidden_role"
    assert executor.audit.read()[-1]["outcome"] == "forbidden_role"


def test_real_socket_identifies_peer_by_kernel_credentials(executor_socket, executor):
    # The request carries no identity; SO_PEERCRED of this process maps to role `api`.
    status = call("platform_status", socket_path=executor_socket)
    assert "notes" in status["projects"]
    with pytest.raises(ExecutorError) as exc:
        call("firewall_reassert", socket_path=executor_socket)
    assert exc.value.error_class == "forbidden_role"
    assert executor.audit.read()[-1]["peer_uid"] == ME


def test_client_reports_unavailable_executor(tmp_path):
    with pytest.raises(ExecutorError) as exc:
        call("platform_status", socket_path=str(tmp_path / "missing.sock"))
    assert exc.value.error_class == "unavailable" and exc.value.retryable


def test_malformed_request_id_is_audited_without_untrusted_object(executor):
    result = executor.handle(request("platform_status", request_id={"invalid": [1, 2]}), ME)
    assert result["error_class"] == "bad_request"
    entry = executor.audit.read(1)[0]
    assert entry["request_id"] is None
    assert entry["outcome"] == "bad_request"


def test_proxy_restart_is_serialized_and_fenced_during_deployment(executor):
    registry = json.loads(executor.registry_file.read_text())
    base = registry["config_revision"]
    with executor.target_lock("deployment-execution"):
        result = executor.handle(request("proxy_restart"), 0)
        assert result["error_class"] == "target_busy"
    with executor.deployment_execution(base_revision=base, desired_revision="b" * 64) as fence:
        pass
    result = executor.handle(request("proxy_restart"), 0)
    assert result["error_class"] == "target_busy"
    assert executor.host.calls == [] and executor.deployment_fence() == fence


def test_pending_deployment_blocks_firewall_reassertion_before_budget(executor):
    registry = json.loads(executor.registry_file.read_text())
    revision = registry["config_revision"]
    executor.begin_deployment_fence(base_revision=revision, desired_revision=revision)
    executor.host.firewall = False
    response = executor.handle(request("firewall_reassert"), 4242)
    assert response["error_class"] == "target_busy"
    assert executor.host.calls == []
    with executor._db() as db:
        assert db.execute("SELECT count(*) FROM mutations").fetchone() == (0,)
