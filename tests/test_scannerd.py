import json
import os
import threading

import pytest

from steward.core import ipc
from steward.core.inventory import Inventory
from steward.core.vulnerabilities import Component, ScanResult
from steward.executor.protocol import ExecutorError, call
from steward.scannerd import QueryService, Runner, RuntimeConfig

NOW = 1800000000
REV = "a" * 64


@pytest.fixture
def runtime(tmp_path):
    clock = [NOW]
    inventory = Inventory(
        os_id="ubuntu",
        os_version="26.04",
        running_kernel="test-kernel",
        config_revision=REV,
        reboot_required=False,
        packages=[
            {
                "name": "linux-image-test-kernel",
                "version": "1.0",
                "architecture": "amd64",
                "source_name": "linux",
                "source_version": "1.0",
            }
        ],
    )
    queries, scans = [], []

    def executor(action, params=None, **kwargs):
        queries.append(action)
        assert action == "inventory_page"
        return {
            "revision": inventory.revision,
            "total": len(inventory.packages),
            "metadata": inventory.model_dump(mode="json", exclude={"packages"}),
            "packages": [p.model_dump() for p in inventory.packages],
        }

    class Provider:
        callback = None

        def scan(self, subjects, *, inventory_revision, now):
            scans.append(inventory_revision)
            if self.callback:
                self.callback()
            return [
                ScanResult(
                    source="osv",
                    subject=s,
                    inventory_revision=inventory_revision,
                    checked_at=now,
                    state="not_affected",
                    complete=True,
                )
                for s in subjects
            ]

    provider = Provider()
    config = RuntimeConfig(
        config_revision=REV, scanning={"enabled": True, "trivy": False, "interval_s": 300}
    )
    runner = Runner(
        tmp_path, config, executor=executor, clock=lambda: clock[0], providers={"osv": provider}
    )
    return runner, clock, inventory, queries, scans, provider


def test_schedule_is_durable_idempotent_and_records_kernel_coverage(runtime):
    runner, clock, inv, queries, scans, provider = runtime
    report = runner.run_once()
    assert report["complete"] and report["kernel"]["state"] == "not_affected"
    assert len(scans) == 1 and len(queries) == 2  # revalidate before caching/publication
    assert runner.jobs.list_jobs()[0]["state"] == "succeeded"
    assert runner.run_once() is None
    restored = Runner(
        runner.state,
        runner.config,
        executor=runner.executor,
        clock=lambda: clock[0],
        providers=runner.providers,
    )
    assert restored.run_once() is None and len(scans) == 1
    clock[0] += 300
    assert restored.run_once()["complete"] and len(scans) == 2


def test_scanner_query_releases_job_connection(runtime):
    runner, clock, *_ = runtime
    service = QueryService(
        runner.observations, runner.jobs, runner.config, {}, clock=lambda: clock[0]
    )
    assert service.handle(b'{"v":1,"action":"scans_jobs"}', 0)["ok"]
    assert getattr(runner.jobs._local, "conn", None) is None
    # Subsequent worker operations reopen their own connection normally.
    assert runner.jobs.list_jobs(limit=20) == []
    assert not service.handle(b'{"v":1,"action":"unknown"}', 0)["ok"]
    assert getattr(runner.jobs._local, "conn", None) is None


def test_disabled_scanner_observes_nothing_and_preserves_historical_evidence(runtime):
    runner, clock, inv, queries, scans, provider = runtime
    runner.run_once()
    runner.config.scanning.enabled = False
    assert runner.run_once() is None
    assert len(scans) == 1 and len(queries) == 2
    service = QueryService(
        runner.observations, runner.jobs, runner.config, {}, clock=lambda: clock[0]
    )
    summary = runner.observations.summary(**service.options())
    assert not summary["complete"] and summary["counts"] == {"unknown": 1}
    assert runner.observations.query(**service.options())["records"]
    before = runner.observations.changes()["next_id"]
    runner.run_once()
    assert runner.observations.changes()["next_id"] == before


def test_changed_inventory_discards_results_and_retries_with_bounds(runtime):
    runner, clock, inv, queries, scans, provider = runtime
    provider.callback = lambda: setattr(inv, "kernel_build", str(clock[0]))
    runner.run_once()
    assert not runner.observations.changes()["changes"]
    assert runner.jobs.list_jobs()[0]["state"] == "queued"
    assert runner.jobs.list_jobs()[0]["error"] == "unavailable"
    for delay in (5, 10):
        clock[0] += delay
        runner.run_once()
    job = runner.jobs.list_jobs()[0]
    assert job["state"] == "failed" and job["attempts"] == 3
    assert not runner.observations.changes()["changes"]


def test_runner_collects_only_advertised_services_and_revalidates_target_inventory(runtime):
    runner, clock, inv, _, _, provider = runtime
    inv.projects = ["notes"]
    inv.application_services = ["notes/api", "notes/web"]
    page = runner.executor
    calls = []

    def executor(action, params, **kwargs):
        if action == "inventory_page":
            return page(action, params, **kwargs)
        assert action == "image_inventory"
        calls.append(params)
        identity = (
            {"project": params["project_id"]}
            if "project_id" in params
            else {"application": params["application"], "service": params["service"]}
        )
        return {
            **identity,
            "config_revision": inv.config_revision,
            "configured_image": "docker.io/library/alpine@sha256:" + "b" * 64,
        }

    runner.executor = executor
    provider.callback = lambda: setattr(inv, "application_services", ["notes/web"])

    assert runner.run_once() is None
    legacy = {"project_id": "notes"}
    api = {"application": "notes", "service": "api", "expected_revision": REV}
    web = {**api, "service": "web"}
    assert calls == [legacy, api, web, legacy, web]
    assert runner.jobs.list_jobs()[0]["state"] == "queued"
    assert runner.jobs.list_jobs()[0]["error"] == "unavailable"
    assert not runner.observations.changes()["changes"]

    provider.callback = None
    clock[0] += 5
    report = runner.run_once()
    assert report is not None
    assert report["inventory_revision"] == inv.revision
    assert {image.scope for image in runner.observations.snapshot_binding()[3]} == {
        "notes",
        "notes/web",
    }


def test_runner_rejects_service_response_for_another_advertised_service(runtime):
    runner, _, inv, _, _, _ = runtime
    inv.application_services = ["notes/api", "notes/web"]
    page = runner.executor

    def executor(action, params, **kwargs):
        if action == "inventory_page":
            return page(action, params, **kwargs)
        return {
            "application": "notes",
            "service": {"api": "web", "web": "api"}[params["service"]],
            "config_revision": REV,
            "configured_image": "docker.io/library/alpine@sha256:" + "b" * 64,
        }

    runner.executor = executor
    with pytest.raises(ExecutorError, match="application service image identity differs"):
        runner.inventory()


def test_changed_runtime_image_discards_scan_before_cache_and_publication(runtime):
    runner, clock, inv, queries, scans, provider = runtime
    image = Component(
        kind="image",
        scope="notes",
        name="docker.io/library/alpine",
        version="sha256:" + "b" * 64,
        image="docker.io/library/alpine@sha256:" + "b" * 64,
        runtime_verified=True,
        expected_image_id="sha256:" + "c" * 64,
    )
    images = [image]
    runner.inventory = lambda: (inv, list(images))

    class ImageProvider:
        def scan(self, subjects, *, inventory_revision, now):
            return [
                ScanResult(
                    source="trivy",
                    subject=subject,
                    inventory_revision=inventory_revision,
                    checked_at=now,
                    state="not_affected",
                    complete=True,
                )
                for subject in subjects
            ]

    runner.providers["trivy"] = ImageProvider()
    # Runtime verification is deliberately excluded from Component.key; a
    # change still invalidates the entire in-flight observation.
    provider.callback = lambda: images.__setitem__(
        0, image.model_copy(update={"runtime_verified": False})
    )

    assert runner.run_once() is None
    assert runner.jobs.list_jobs()[0]["state"] == "queued"
    assert runner.jobs.list_jobs()[0]["error"] == "unavailable"
    assert not runner.observations.changes()["changes"]
    import sqlite3

    with sqlite3.connect(runner.cache.path) as db:
        assert db.execute("SELECT COUNT(*) FROM results").fetchone()[0] == 0

    provider.callback = None
    clock[0] += 5
    report = runner.run_once()
    assert report is not None and not report["complete"]
    assert report["source_queries_complete"]
    assert not report["runtime_images_verified"]
    assert runner.jobs.list_jobs()[0]["state"] == "succeeded"


def test_expired_lease_cannot_publish_or_cache_results(runtime):
    runner, clock, inv, queries, scans, provider = runtime
    provider.callback = lambda: clock.__setitem__(0, clock[0] + 61)
    assert runner.run_once() is None
    assert not runner.observations.changes()["changes"]
    assert runner.jobs.list_jobs()[0]["state"] == "running"  # reconciled on the next cycle
    with runner.cache.path.open("rb"):
        import sqlite3

        with sqlite3.connect(runner.cache.path) as db:
            assert db.execute("SELECT COUNT(*) FROM results").fetchone()[0] == 0


def test_scanner_query_peer_roles_and_real_unix_socket(runtime, tmp_path):
    runner, clock, inv, queries, scans, provider = runtime
    runner.run_once()
    service = QueryService(
        runner.observations,
        runner.jobs,
        runner.config,
        {os.geteuid(): "api", 223344: "collector"},
        clock=lambda: clock[0],
    )
    unauthorized = service.handle(b'{"v":1,"action":"scans_summary"}', 999999)
    assert unauthorized["error_class"] == "unauthorized_peer"
    refused = service.handle(b'{"v":1,"action":"scans_query"}', 223344)
    assert refused["error_class"] == "policy_denied"
    server = ipc.bind(str(tmp_path / "scanner.sock"), service.handle, None)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        kwargs = {"socket_path": str(tmp_path / "scanner.sock")}
        assert call("scans_summary", **kwargs)["complete"]
        assert call("scans_query", **kwargs)["records"][0]["state"] == "not_affected"
        assert call("scans_jobs", **kwargs)["jobs"][0]["state"] == "succeeded"
        with pytest.raises(ExecutorError, match="not allowed"):
            call("scan_now", **kwargs)
        with pytest.raises(ExecutorError) as error:
            call("scans_query", {"limit": 1000}, **kwargs)
        assert error.value.error_class == "bad_request"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.fixture
def controller_query(runtime):
    runner, clock, *_ = runtime
    service = QueryService(
        runner.observations,
        runner.jobs,
        runner.config,
        {223344: "controller"},
        clock=lambda: clock[0],
    )

    def query(action="scans_query", **params):
        raw = json.dumps({"v": 1, "action": action, "params": params}).encode()
        return service.handle(raw, 223344)

    return query


def test_controller_cannot_read_general_scanner_actions(controller_query):
    for action in ("scans_summary", "scans_changes", "scans_jobs", "scan_now"):
        assert controller_query(action)["error_class"] == "policy_denied"


@pytest.mark.parametrize(
    "params",
    [
        {"project": "host"},
        {"project": "notes"},
        {"project": "notes/api/extra"},
        {"project": "notes/Api"},
        {"source": "osv"},
        {"offset": 1},
        {"limit": 2},
        {"subject": REV},
        {"finding_offset": -1},
        {"snapshot_id": "invalid"},
        {"expected_revision": "invalid"},
    ],
)
def test_controller_query_rejects_invalid_filters(controller_query, params):
    request = {"project": "notes/api", "expected_revision": REV} | params
    assert controller_query(**request)["error_class"] == "bad_request"


def test_controller_query_requires_scope_and_current_revision(controller_query):
    assert controller_query(project="notes/api")["error_class"] == "bad_request"
    assert controller_query(expected_revision=REV)["error_class"] == "bad_request"
    assert (
        controller_query(project="notes/api", expected_revision="b" * 64)["error_class"]
        == "conflict"
    )


def test_controller_query_filters_and_pins_qualified_trivy_records(runtime, controller_query):
    runner, clock, *_ = runtime
    report = runner.run_once()
    request = {"project": "notes/api", "expected_revision": REV}
    assert controller_query(**request)["result"]["records"] == []

    def image_result(source, scope, name, findings=()):
        digest = "sha256:" + REV
        return ScanResult(
            source=source,
            subject=Component(
                kind="image",
                scope=scope,
                name=name,
                version=digest,
                image=f"docker.io/library/{name}@{digest}",
            ),
            inventory_revision=report["inventory_revision"],
            checked_at=clock[0],
            state="confirmed" if findings else "not_affected",
            findings=[{"id": item, "summary": item, "severity": "critical"} for item in findings],
            complete=True,
        ).model_dump(mode="json")

    clock[0] += 1
    findings = ("CVE-2026-1000", "CVE-2026-1001")
    report["results"] += [
        image_result("trivy", "notes/api", "api", findings),
        image_result("trivy", "notes/api", "another-image"),
        image_result("osv", "notes/api", "api"),
        image_result("trivy", "notes/web", "web"),
        image_result("trivy", "notes", "legacy"),
    ]
    report.update(
        counts={"confirmed": 1, "not_affected": 5},
        complete=False,
        runtime_images_verified=False,
    )
    assert runner.observations.publish(report | {"generated_at": clock[0]})
    page = controller_query(**request)["result"]
    assert set(page) == {"records", "total", "next_offset", "snapshot_id"}
    assert page["total"] == 2 and page["next_offset"] == 1
    (record,) = page["records"]
    assert record["subject"]["scope"] == "notes/api" and record["source"] == "trivy"
    assert record["state"] == "confirmed" and record["findings_total"] == 2
    assert [finding["id"] for finding in record["findings"]] == [findings[0]]
    pinned = request | {"snapshot_id": page["snapshot_id"], "finding_offset": 1}
    (record,) = controller_query(**pinned)["result"]["records"]
    assert [finding["id"] for finding in record["findings"]] == [findings[1]]
    assert controller_query(**(request | {"project": "notes/absent"}))["result"]["total"] == 0

    clock[0] += runner.config.scanning.max_age_s + 1
    assert controller_query(**pinned)["result"]["records"][0]["state"] == "stale"
    assert runner.observations.publish(report | {"generated_at": clock[0]})
    assert controller_query(**pinned)["error_class"] == "conflict"

    clock[0] += 1
    refreshed = [entry | {"checked_at": clock[0]} for entry in report["results"]]
    assert runner.observations.publish(report | {"generated_at": clock[0], "results": refreshed})
    assert controller_query(**request)["result"]["records"][0]["state"] == "confirmed"
    runner.config.config_revision = "b" * 64
    assert controller_query(**request)["error_class"] == "conflict"
    current = request | {"expected_revision": runner.config.config_revision}
    (record,) = controller_query(**current)["result"]["records"]
    assert record["state"] == "unknown" and not record["complete"]


def test_completed_job_retention_never_removes_active_or_other_kinds(runtime):
    runner, clock, inv, queries, scans, provider = runtime
    runner.run_once()
    runner.jobs.enqueue(
        "vulnerability_scan", "inventory", {}, idempotency_key="queued", created_by="test", now=NOW
    )
    runner.jobs.enqueue(
        "other_kind", "elsewhere", {}, idempotency_key="other", created_by="test", now=NOW
    )
    runner.jobs.prune_jobs("vulnerability_scan", now=NOW + 31 * 86400)
    jobs = runner.jobs.list_jobs()
    assert len(jobs) == 2 and all(j["state"] == "queued" for j in jobs)


def test_scanner_feed_to_collector_is_atomic_and_replayable(runtime, tmp_path, monkeypatch):
    from steward.collector import Collector

    runner, clock, inv, queries, scans, provider = runtime
    runner.run_once()
    service = QueryService(
        runner.observations,
        runner.jobs,
        runner.config,
        {223344: "collector"},
        clock=lambda: clock[0],
    )

    def reader(action, params=None, **kwargs):
        response = service.handle(
            json.dumps({"v": 1, "action": action, "params": params or {}}).encode(), 223344
        )
        if not response["ok"]:
            raise ExecutorError(response["error_class"], response["message"])
        return response["result"]

    directory = tmp_path / "collector"
    directory.mkdir()
    collector = Collector(str(directory), scanner=reader, scanner_socket="fixture")
    original = collector.store.add

    def crashed(events, meta=None):
        raise RuntimeError("injected transaction interruption")

    monkeypatch.setattr(collector.store, "add", crashed)
    with pytest.raises(RuntimeError, match="injected"):
        collector.collect_scanner(clock[0])
    assert collector.store.get_meta("scanner_cursor") is None
    monkeypatch.setattr(collector.store, "add", original)
    assert collector.collect_scanner(clock[0]) == 2
    assert collector.collect_scanner(clock[0]) == 0
    restored = Collector(str(directory), scanner=reader, scanner_socket="fixture")
    assert restored.collect_scanner(clock[0]) == 0
    assert restored.store.coverage()["count"] == 2

    from steward.core.scan_observations import Observations

    replacement = Observations(tmp_path / "replacement.db")
    report = runner.run_once()  # no duplicate scan in the same time slot
    assert report is None
    clock[0] += 300
    report = runner.run_once()
    replacement.publish(report)
    service.observations = replacement
    assert restored.collect_scanner(clock[0]) == 3  # explicit reset gap plus two replayed records
    assert any(e["kind"] == "observation_gap" for e in restored.store.query())


def test_query_snapshot_fence_and_dynamic_kernel_freshness(runtime):
    runner, clock, inv, queries, scans, provider = runtime
    runner.run_once()
    service = QueryService(
        runner.observations, runner.jobs, runner.config, {223344: "api"}, clock=lambda: clock[0]
    )
    response = service.handle(
        json.dumps({"v": 1, "action": "scans_query", "params": {"snapshot_id": "f" * 64}}).encode(),
        223344,
    )
    assert response["error_class"] == "conflict"
    clock[0] += runner.config.scanning.max_age_s + 1
    summary = runner.observations.summary(**service.options())
    assert summary["kernel"]["state"] == "stale" and not summary["kernel"]["complete"]
    assert not summary["complete"] and not summary["source_queries_complete"]


@pytest.mark.skipif(os.geteuid() == 0, reason="daemon must run unprivileged")
def test_real_daemon_starts_disabled_and_serializes_processes(tmp_path):
    import pwd
    import subprocess
    import sys
    import time
    from pathlib import Path

    config = tmp_path / "scanner.json"
    config.write_text(json.dumps({"config_revision": REV, "scanning": {"enabled": False}}))
    socket = str(tmp_path / "q")
    args = [
        sys.executable,
        "-m",
        "steward.scannerd",
        "--config",
        str(config),
        "--state-dir",
        str(tmp_path / "daemon"),
        "--query-socket",
        socket,
        "--query-group",
        "",
        "--reader",
        "api=" + pwd.getpwuid(os.getuid()).pw_name,
    ]
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
    process = subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 15
        while True:
            if process.poll() is not None:
                pytest.fail("daemon exited before its query socket was ready")
            try:
                summary = call("scans_summary", socket_path=socket, timeout=1)
                break
            except ExecutorError:
                if time.monotonic() > deadline:
                    pytest.fail("daemon did not answer its query socket")
                threading.Event().wait(0.05)
        assert summary["enabled"] is False and not summary["complete"]
        assert call("scans_jobs", socket_path=socket)["jobs"] == []
        second = subprocess.run(args, env=env, capture_output=True, timeout=15)
        assert second.returncode != 0
        assert call("scans_summary", socket_path=socket)["enabled"] is False
    finally:
        process.terminate()
        try:
            process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()


def test_inventory_change_invalidates_previous_complete_snapshot_until_success(runtime):
    runner, clock, inv, queries, scans, provider = runtime
    assert runner.run_once()["complete"]
    options = QueryService(
        runner.observations, runner.jobs, runner.config, {}, clock=lambda: clock[0]
    ).options()
    previous = runner.observations.summary(**options)
    assert previous["complete"] and not previous["stale"]
    clock[0] += 300
    provider.callback = lambda: setattr(inv, "kernel_build", "changed")
    assert runner.run_once() is None
    stale = runner.observations.summary(**options | {"now": clock[0]})
    assert stale["stale"] and not stale["complete"] and not stale["source_queries_complete"]
    assert stale["snapshot_id"] != previous["snapshot_id"]
    assert (
        runner.observations.query(**options | {"now": clock[0]})["records"][0]["state"] == "stale"
    )
    assert runner.observations.changes()["changes"][-1]["kind"] == "vulnerability.stale"
    assert runner.jobs.list_jobs()[0]["error"] == "unavailable"
    provider.callback = None
    clock[0] += 5
    assert runner.run_once()["complete"]
    recovered = runner.observations.summary(**options | {"now": clock[0]})
    assert recovered["complete"] and not recovered["stale"]


def test_invalidated_snapshot_rejects_old_page_cursor(runtime):
    runner, clock, inv, queries, scans, provider = runtime
    runner.run_once()
    service = QueryService(
        runner.observations, runner.jobs, runner.config, {}, clock=lambda: clock[0]
    )
    old = service.handle(b'{"v":1,"action":"scans_summary"}', 0)["result"]["snapshot_id"]
    clock[0] += 300
    provider.callback = lambda: setattr(inv, "kernel_build", "changed")
    runner.run_once()
    request = json.dumps({"v": 1, "action": "scans_query", "params": {"snapshot_id": old}}).encode()
    response = service.handle(request, 0)
    assert not response["ok"] and response["error_class"] == "conflict"


def test_runtime_image_change_marks_previous_complete_snapshot_stale(runtime):
    runner, clock, inv, queries, scans, provider = runtime
    image = Component(
        kind="image",
        scope="notes",
        name="docker.io/library/alpine",
        version="sha256:" + "b" * 64,
        image="docker.io/library/alpine@sha256:" + "b" * 64,
        runtime_verified=True,
        expected_image_id="sha256:" + "c" * 64,
    )
    images = [image]
    runner.inventory = lambda: (inv, list(images))

    class ImageProvider:
        def scan(self, subjects, *, inventory_revision, now):
            return [
                ScanResult(
                    source="trivy",
                    subject=subject,
                    inventory_revision=inventory_revision,
                    checked_at=now,
                    state="not_affected",
                    complete=True,
                )
                for subject in subjects
            ]

    runner.providers["trivy"] = ImageProvider()
    assert runner.run_once()["complete"]
    clock[0] += 300
    provider.callback = lambda: images.__setitem__(
        0, image.model_copy(update={"runtime_verified": False})
    )
    assert runner.run_once() is None
    options = QueryService(
        runner.observations, runner.jobs, runner.config, {}, clock=lambda: clock[0]
    ).options()
    summary = runner.observations.summary(**options)
    assert summary["stale"] and not summary["complete"] and not summary["runtime_images_verified"]


def test_changed_inventory_before_scan_invalidates_old_snapshot_before_provider(runtime):
    runner, clock, inv, queries, scans, provider = runtime
    assert runner.run_once()["complete"]
    inv.kernel_build = "changed-before-scan"
    clock[0] += 300
    observed = []

    def during_provider():
        options = QueryService(
            runner.observations, runner.jobs, runner.config, {}, clock=lambda: clock[0]
        ).options()
        observed.append(runner.observations.summary(**options))

    provider.callback = during_provider
    assert runner.run_once()["complete"]
    assert len(observed) == 1 and observed[0]["stale"] and not observed[0]["complete"]
    options = QueryService(
        runner.observations, runner.jobs, runner.config, {}, clock=lambda: clock[0]
    ).options()
    assert runner.observations.summary(**options)["complete"]


def test_changed_image_before_scan_invalidates_old_snapshot_before_provider(runtime):
    runner, clock, inv, queries, scans, provider = runtime
    image = Component(
        kind="image",
        scope="notes",
        name="docker.io/library/alpine",
        version="sha256:" + "b" * 64,
        image="docker.io/library/alpine@sha256:" + "b" * 64,
        runtime_verified=True,
        expected_image_id="sha256:" + "c" * 64,
    )
    images = [image]
    runner.inventory = lambda: (inv, list(images))

    class ImageProvider:
        def scan(self, subjects, *, inventory_revision, now):
            return [
                ScanResult(
                    source="trivy",
                    subject=s,
                    inventory_revision=inventory_revision,
                    checked_at=now,
                    state="not_affected",
                    complete=True,
                )
                for s in subjects
            ]

    runner.providers["trivy"] = ImageProvider()
    assert runner.run_once()["complete"]
    images[0] = image.model_copy(update={"runtime_verified": False})
    clock[0] += 300
    observed = []
    provider.callback = lambda: observed.append(
        runner.observations.summary(
            **QueryService(
                runner.observations, runner.jobs, runner.config, {}, clock=lambda: clock[0]
            ).options()
        )
    )
    assert not runner.run_once()["complete"]
    assert len(observed) == 1 and observed[0]["stale"] and not observed[0]["complete"]


def test_prior_inventory_change_remains_stale_if_new_provider_fails(runtime):
    runner, clock, inv, queries, scans, provider = runtime
    assert runner.run_once()["complete"]
    inv.kernel_build = "changed-before-scan"
    clock[0] += 300

    def fail():
        raise OSError("provider unavailable")

    provider.callback = fail
    assert runner.run_once() is None
    restored = Runner(
        runner.state,
        runner.config,
        executor=runner.executor,
        clock=lambda: clock[0],
        providers=runner.providers,
    )
    options = QueryService(
        restored.observations, restored.jobs, restored.config, {}, clock=lambda: clock[0]
    ).options()
    summary = restored.observations.summary(**options)
    assert summary["stale"] and not summary["complete"]
    assert restored.jobs.list_jobs()[0]["error"] == "OSError"


@pytest.mark.parametrize("failure_point", ["initial", "revalidation", "config_mismatch"])
def test_inventory_unavailable_makes_previous_snapshot_unknown_until_recovery(
    runtime, failure_point
):
    runner, clock, inv, queries, scans, provider = runtime
    assert runner.run_once()["complete"]
    prior = runner.observations.snapshot_id()
    clock[0] += 300
    real_inventory = runner.inventory
    calls = [0]

    def unavailable():
        calls[0] += 1
        if failure_point == "initial" or (failure_point == "revalidation" and calls[0] == 2):
            raise ExecutorError("unavailable", "executor is unavailable")
        inventory, images = real_inventory()
        if failure_point == "config_mismatch":
            inventory = inventory.model_copy(update={"config_revision": "b" * 64})
        return inventory, images

    runner.inventory = unavailable
    assert runner.run_once() is None
    options = QueryService(
        runner.observations, runner.jobs, runner.config, {}, clock=lambda: clock[0]
    ).options()
    restored = type(runner.observations)(runner.observations.path)
    summary = restored.summary(**options)
    assert summary["configuration_matches"] and not summary["complete"]
    assert not summary["source_queries_complete"] and not summary["runtime_images_verified"]
    assert summary["kernel"]["state"] == "unknown" and not summary["kernel"]["complete"]
    assert restored.query(**options)["records"][0]["state"] == "unknown"
    assert summary["snapshot_id"] != prior
    assert restored.changes()["changes"][-1]["kind"] == "vulnerability.unknown"
    runner.inventory = real_inventory
    clock[0] += 5
    assert runner.run_once()["complete"]
    assert runner.observations.summary(**(options | {"now": clock[0]}))["complete"]


def test_worker_without_lease_cannot_mark_prior_snapshot_unknown(runtime, monkeypatch):
    runner, clock, inv, queries, scans, provider = runtime
    assert runner.run_once()["complete"]
    before = runner.observations.snapshot_id()
    clock[0] += 300

    def unavailable():
        raise ExecutorError("unavailable", "executor is unavailable")

    runner.inventory = unavailable
    monkeypatch.setattr(runner.jobs, "heartbeat", lambda *args, **kwargs: False)
    assert runner.run_once() is None
    options = QueryService(
        runner.observations, runner.jobs, runner.config, {}, clock=lambda: clock[0]
    ).options()
    summary = runner.observations.summary(**options)
    assert summary["complete"] and summary["snapshot_id"] == before
    assert all(
        e["kind"] != "vulnerability.unknown" for e in runner.observations.changes()["changes"]
    )
