import json
from contextlib import contextmanager

import pytest

from steward.core.ids import graph_identifier
from steward.core.images import runtime_identity_verified
from steward.core.inventory import Inventory, collect
from steward.executor.host import Host
from steward.executor.protocol import ExecutorError
from test_executor import request

SCANNER = 4545


def test_root_image_cache_binds_exact_manifest_to_content_id():
    host = Host()
    configured = "docker.io/library/python@sha256:" + "a" * 64
    calls = []

    def run(argv):
        calls.append(argv)
        return 0, json.dumps({"id": "b" * 64, "digest": "sha256:" + "a" * 64})

    host._run = run
    identity = host.configured_image_identity(configured)
    assert identity == {"id": "sha256:" + "b" * 64, "manifest_digest": "sha256:" + "a" * 64}
    assert calls[0][-1] == configured and "--format" in calls[0]
    assert "{{json .ID}}" in calls[0][4]
    host._run = lambda argv: (0, json.dumps({"id": "b" * 64, "digest": "sha256:" + "c" * 64}))
    assert host.configured_image_identity(configured) is None
    host._run = lambda argv: (1, "not present")
    assert host.configured_image_identity(configured) is None


def test_oci_transport_digest_difference_needs_root_bound_content_identity():
    observation = {
        "configured_image": "docker.io/library/python@sha256:" + "a" * 64,
        "observed": True,
        "observed_running": True,
        "observed_image_digest": "sha256:" + "c" * 64,
        "observed_image_id": "b" * 64,
    }
    assert not runtime_identity_verified(observation)
    observation["configured_image_identity"] = {
        "id": "sha256:" + "b" * 64,
        "manifest_digest": "sha256:" + "a" * 64,
    }
    assert runtime_identity_verified(observation)
    observation["observed_running"] = False
    assert not runtime_identity_verified(observation)
    observation["observed_running"] = True
    observation["observed_image_id"] = "d" * 64
    assert not runtime_identity_verified(observation)
    observation["observed_image_id"] = "b" * 64
    observation["configured_image_identity"]["manifest_digest"] = "sha256:" + "c" * 64
    assert not runtime_identity_verified(observation)
    observation["observed_image_digest"] = "sha256:" + "a" * 64
    assert runtime_identity_verified(observation)  # legacy exact-digest proof
    observation["observed"] = False
    assert not runtime_identity_verified(observation)


def scanner(executor, action, params=None):
    registry = json.loads(executor.registry_file.read_text())
    registry["peers"]["scanner"] = SCANNER
    executor.registry_file.write_text(json.dumps(registry))
    return executor.handle(request(action, params), SCANNER)


def test_packages_preserve_distribution_source_versions_and_held_installs():
    host = Host()
    rows = (
        "libssl3\t3.0.2-0ubuntu1.20\tamd64\topenssl\t3.0.2-0ubuntu1.20\tii \n"
        "held\t1:2.0~vendor1\tall\t\t\thi \n"
        "removed\t1.0\tall\tremoved\t1.0\trc \n"
    )
    seen = []

    def run(argv):
        seen.append(argv)
        return 0, rows

    host._run = run
    result = host.inventory()
    assert len(result["packages"]) == 2
    assert result["packages"][0]["name"] == "held"
    assert result["packages"][0]["source_version"] == "1:2.0~vendor1"
    assert result["packages"][1]["source_name"] == "openssl"
    assert result["packages"][1]["source_version"] == "3.0.2-0ubuntu1.20"
    assert seen[0][:2] == ["dpkg-query", "--show"] and len(seen[0]) == 3


def test_inventory_revision_binds_all_pages_and_config(executor):
    first = scanner(executor, "inventory_page", {"offset": 0, "limit": 1})
    assert first["ok"] and first["result"]["total"] == 1
    revision = first["result"]["revision"]
    second = scanner(executor, "inventory_page", {"offset": 1, "expected_revision": revision})
    assert second["ok"] and second["result"]["packages"] == []
    executor.host.inventory = lambda: {
        "os_id": "ubuntu",
        "os_version": "26.04",
        "running_kernel": "7.0.1",
        "packages": [],
    }
    changed = scanner(executor, "inventory_page", {"offset": 1, "expected_revision": revision})
    assert not changed["ok"] and changed["error_class"] == "unavailable"


def test_scanner_reads_during_kill_switch_but_cannot_mutate_or_read_audit(executor):
    executor.host.killed = True
    assert scanner(executor, "inventory_page")["ok"]
    for action, params in [
        ("workload_restart", {"project_id": "notes", "reason": "scan"}),
        ("audit_tail", {}),
        ("platform_status", {}),
    ]:
        assert scanner(executor, action, params)["error_class"] == "forbidden_role"
    assert executor.host.calls == []


def test_inventory_rejects_arbitrary_paths_and_unknown_images(executor):
    assert (
        scanner(executor, "inventory_page", {"path": "/etc/shadow"})["error_class"] == "bad_request"
    )
    assert (
        scanner(executor, "image_inventory", {"project_id": "other"})["error_class"]
        == "policy_denied"
    )
    result = scanner(executor, "image_inventory", {"project_id": "notes"})["result"]
    assert "@sha256:" in result["configured_image"]
    assert result["observed_image_digest"] is None  # Missing runtime proof stays unknown.
    assert "Config" not in result and "Env" not in result


@pytest.fixture
def application_inventory(executor):
    registry = json.loads(executor.registry_file.read_text())
    registry["peers"]["scanner"] = SCANNER
    registry["containment"] = {"enabled": True}
    application = "sample"
    services = {}
    for service in ("web", "database", "disabled", "unmanaged"):
        stem = graph_identifier("s", application, service)
        services[service] = {
            "manage": service != "unmanaged",
            "deploy": service != "disabled",
            "user": "stw-" + stem,
            "container": stem,
            "unit": stem + ".service",
            "lock": "project-" + stem,
            "image": registry["projects"]["notes"]["image"],
            "source_revision": "git:sample",
            "routes": ["sample.example.test"] if service == "web" else [],
            "depends_on": ["database"] if service == "web" else [],
        }
    registry["applications"] = {
        application: {
            "isolation": "separate",
            "lock": "application-" + graph_identifier("a", application),
            "services": services,
        },
        "shared": {"isolation": "shared", "services": {"web": services["web"]}},
    }
    executor.registry_file.write_text(json.dumps(registry))
    params = {
        "application": application,
        "service": "web",
        "expected_revision": registry["config_revision"],
    }
    return registry, params


def test_inventory_lists_sorted_active_separate_services(executor, application_inventory):
    registry, _ = application_inventory
    first = scanner(executor, "inventory_page")["result"]
    assert first["metadata"]["application_services"] == ["sample/database", "sample/web"]
    registry["applications"]["sample"]["services"]["web"]["deploy"] = False
    executor.registry_file.write_text(json.dumps(registry))
    assert (
        scanner(executor, "inventory_page", {"expected_revision": first["revision"]})["error_class"]
        == "unavailable"
    )
    registry["applications"]["sample"]["services"]["database"]["deploy"] = False
    executor.registry_file.write_text(json.dumps(registry))
    empty = scanner(executor, "inventory_page")["result"]
    assert "application_services" not in empty["metadata"]
    del registry["containment"]
    del registry["applications"]
    executor.registry_file.write_text(json.dumps(registry))
    assert scanner(executor, "inventory_page")["result"] == empty


@pytest.mark.parametrize("uid", [SCANNER, 0])
def test_application_image_inventory_observes_registered_target_once(
    executor, application_inventory, uid
):
    registry, params = application_inventory
    spec = registry["applications"]["sample"]["services"]["web"]
    calls = []

    def container(user, name):
        calls.append((user, name))
        with (
            pytest.raises(ExecutorError, match="another mutation"),
            executor.target_lock("deployment-execution"),
        ):
            pytest.fail("image inspection did not hold the deployment lock")
        return {"Image": "sha256:" + "a" * 64, "State": {"Running": True}, "Config": {}}

    executor.host.container = container
    result = executor.handle(request("image_inventory", params), uid)["result"]
    assert calls == [(spec["user"], spec["container"])]
    assert result == {
        "application": "sample",
        "service": "web",
        "config_revision": registry["config_revision"],
        "configured_image": spec["image"],
        "source_revision": spec["source_revision"],
        "deploy": True,
        "exposed": True,
        "observed_image_id": "sha256:" + "a" * 64,
        "observed_image_digest": None,
        "observed": True,
        "observed_running": True,
        "configured_image_identity": None,
    }


def test_application_image_inventory_rejects_disallowed_requests(executor, application_inventory):
    registry, params = application_inventory
    executor.host.container = lambda *_: pytest.fail("unexpected runtime inspection")
    assert (
        executor.handle(request("image_inventory", params), 4242)["error_class"] == "forbidden_role"
    )
    without_revision = {key: value for key, value in params.items() if key != "expected_revision"}
    for invalid in (
        without_revision,
        {**params, "project_id": "notes"},
        {**params, "service": "../notes"},
        {**params, "user": "root"},
        {"project_id": "notes", "application": None},
    ):
        assert (
            executor.handle(request("image_inventory", invalid), SCANNER)["error_class"]
            == "bad_request"
        )
    for invalid in (
        {**params, "application": "unknown"},
        {**params, "application": "shared"},
        {**params, "service": "unknown"},
        {**params, "service": "disabled"},
        {**params, "service": "unmanaged"},
    ):
        assert (
            executor.handle(request("image_inventory", invalid), SCANNER)["error_class"]
            == "policy_denied"
        )
    for policy in (None, {"enabled": False}, {"enabled": True, "notice_minutes": 0}):
        registry["containment"] = policy
        executor.registry_file.write_text(json.dumps(registry))
        assert (
            executor.handle(request("image_inventory", params), SCANNER)["error_class"]
            == "policy_denied"
        )
        assert (
            "application_services" not in scanner(executor, "inventory_page")["result"]["metadata"]
        )
    registry["containment"] = {"enabled": True}
    registry["applications"]["sample"]["services"]["web"]["container"] = "notes"
    executor.registry_file.write_text(json.dumps(registry))
    assert (
        executor.handle(request("image_inventory", params), SCANNER)["error_class"] == "unavailable"
    )


def test_application_image_inventory_deployment_races(executor, application_inventory, monkeypatch):
    registry, params = application_inventory
    executor.host.container = lambda *_: pytest.fail("unexpected runtime inspection")
    raw = request("image_inventory", params)
    with executor.target_lock("deployment-execution"):
        assert executor.handle(raw, SCANNER)["error_class"] == "target_busy"
    with monkeypatch.context() as patch:
        patch.setattr(executor, "deployment_fence", lambda: object())
        assert executor.handle(raw, SCANNER)["error_class"] == "target_busy"
    changed = {**registry, "config_revision": "0" * 64}
    executor.registry_file.write_text(json.dumps(changed))
    assert executor.handle(raw, SCANNER)["error_class"] == "conflict"

    lock = executor.target_lock

    @contextmanager
    def replace_before_acquiring(name):
        assert name == "deployment-execution"
        executor.registry_file.write_text(json.dumps(changed))
        with lock(name):
            yield

    executor.registry_file.write_text(json.dumps(registry))
    monkeypatch.setattr(executor, "target_lock", replace_before_acquiring)
    assert executor.handle(raw, SCANNER)["error_class"] == "conflict"


def test_inventory_client_reassembles_and_verifies_content(executor):
    def call(action, params, **kw):
        return scanner(executor, action, params)["result"]

    inventory = collect(call, socket_path="not-used")
    assert inventory.os_id == "ubuntu" and inventory.packages[0].source_name == "openssl"

    def tampered(action, params, **kw):
        result = call(action, params, **kw)
        result["packages"][0]["version"] = "9.9"
        return result

    with pytest.raises(ExecutorError, match="does not match"):
        collect(tampered, socket_path="not-used")


def test_inventory_client_rejects_incomplete_pages():
    def call(*args, **kw):
        return {"revision": "a" * 64, "total": 1, "metadata": {}, "packages": []}

    with pytest.raises(ExecutorError, match="incomplete inventory"):
        collect(call, socket_path="not-used")


def test_real_local_package_inventory_is_read_only_and_schema_valid():
    inventory = Inventory.model_validate({**Host().inventory(), "config_revision": "a" * 64})
    assert inventory.packages and inventory.running_kernel
    assert len(inventory.revision) == 64
