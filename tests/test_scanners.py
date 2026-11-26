import json
import os
import sqlite3
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from steward.adapters.scanners import OSV, Trivy
from steward.core.inventory import Inventory
from steward.core.process import CommandError, run_bounded
from steward.core.vulnerabilities import Advisory, Component, ScanError, ScanResult, packages
from steward.scanner import ScanStore, load_bundle, parse_bundle, scan, write_private

REV = "a" * 64
NOW = 1800000000
IMAGE = "docker.io/library/alpine@sha256:" + "b" * 64
PACKAGE = Component(
    kind="os_package",
    scope="host",
    name="openssl",
    version="3.0.2-0ubuntu1.20",
    ecosystem="Ubuntu:26.04:LTS",
)
SUBJECT = Component(
    kind="image",
    scope="notes",
    name="docker.io/library/alpine",
    version="sha256:" + "b" * 64,
    image=IMAGE,
)


def advisory(subject=PACKAGE, id="CVE-2026-1234", withdrawn=None):
    return {
        "id": id,
        "summary": "Known package vulnerability",
        "modified": "2026-01-01T00:00:00Z",
        "database_specific": {"severity": "HIGH"},
        "withdrawn": withdrawn,
        "affected": [
            {
                "package": {"name": subject.name, "ecosystem": subject.ecosystem},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.0.2-0ubuntu1.21"}]}],
            }
        ],
    }


def osv_request(method, url, body=None):
    if method == "POST":
        return {"results": [{"vulns": [{"id": "CVE-2026-1234"}]} for _ in body["queries"]]}
    return advisory()


@pytest.fixture(params=["osv", "trivy"])
def provider(request, tmp_path):
    if request.param == "osv":
        return OSV(osv_request), PACKAGE
    provider = Trivy(cache=tmp_path)

    def run(argv):
        if argv[0] == "version":
            return {
                "VulnerabilityDB": {"UpdatedAt": datetime.fromtimestamp(NOW - 10, UTC).isoformat()}
            }
        return {
            "Metadata": {"RepoDigests": [IMAGE]},
            "Results": [
                {
                    "Packages": [{"Name": "openssl"}],
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-1234",
                            "Severity": "HIGH",
                            "PkgName": "openssl",
                            "InstalledVersion": "3.0.2",
                            "FixedVersion": "3.0.3",
                        }
                    ],
                }
            ],
        }

    provider._run = run
    return provider, SUBJECT


def test_shared_scanner_contract_binds_subject_inventory_and_evidence(provider):
    adapter, subject = provider
    result = adapter.scan([subject], inventory_revision=REV, now=NOW)[0]
    assert adapter.version == 1 and adapter.input_schema["type"] == "object"
    assert adapter.capabilities and adapter.timeout_s > 0
    assert result.subject == subject and result.inventory_revision == REV
    assert result.state == "confirmed" and result.complete
    assert result.findings[0].id == "CVE-2026-1234" and result.findings[0].severity == "high"
    assert result.state_at(NOW, inventory_revision="c" * 64) == "unknown"
    assert result.state_at(NOW + 86401, inventory_revision=REV) == "stale"


def test_osv_uses_vendor_source_versions_including_backports():
    seen = []

    def request(method, url, body=None):
        seen.append(body)
        return {"results": [{}]}

    result = OSV(request).scan([PACKAGE], inventory_revision=REV, now=NOW)[0]
    assert result.state == "not_affected" and result.complete and not result.findings
    assert seen[0]["queries"] == [
        {
            "package": {"name": "openssl", "ecosystem": "Ubuntu:26.04:LTS"},
            "version": "3.0.2-0ubuntu1.20",
        }
    ]


def test_osv_follows_per_query_pagination_before_marking_not_affected():
    calls = []

    def request(method, url, body=None):
        if method == "GET":
            return advisory()
        calls.append(body)
        if len(calls) == 1:
            return {"results": [{"next_page_token": "next"}]}
        return {"results": [{"vulns": [{"id": "CVE-2026-1234"}]}]}

    result = OSV(request).scan([PACKAGE], inventory_revision=REV, now=NOW)[0]
    assert result.state == "confirmed" and calls[1]["queries"][0]["page_token"] == "next"


@pytest.mark.parametrize(
    "response", [{}, {"results": []}, {"results": [None]}, {"results": [{"vulns": "invalid"}]}]
)
def test_osv_incomplete_or_malformed_response_is_a_failure(response):
    result = OSV(lambda *a: response).scan([PACKAGE], inventory_revision=REV, now=NOW)[0]
    assert result.state == "scan_failed" and not result.complete


def test_osv_repeated_page_token_cannot_become_a_clean_scan():
    result = OSV(lambda *a: {"results": [{"next_page_token": "repeat"}]}).scan(
        [PACKAGE], inventory_revision=REV, now=NOW
    )[0]
    assert result.error_class == "incomplete" and result.state == "scan_failed"


def test_osv_withdrawn_advisory_does_not_remain_confirmed():
    def request(method, url, body=None):
        return (
            osv_request(method, url, body) if method == "POST" else advisory(withdrawn="2026-01-02")
        )

    result = OSV(request).scan([PACKAGE], inventory_revision=REV, now=NOW)[0]
    assert result.state == "not_affected" and result.complete


def test_osv_wrong_subject_evidence_is_rejected():
    def request(method, url, body=None):
        document = osv_request(method, url, body)
        if method == "GET":
            document["affected"][0]["package"]["name"] = "other"
        return document

    result = OSV(request).scan([PACKAGE], inventory_revision=REV, now=NOW)[0]
    assert result.state == "scan_failed" and result.error_class == "evidence_mismatch"


def test_request_budget_does_not_hide_matched_but_unfetched_advisories():
    result = OSV(osv_request, max_requests=1).scan([PACKAGE], inventory_revision=REV, now=NOW)[0]
    assert result.error_class == "quota_exhausted" and result.state == "scan_failed"


def test_unsupported_inventory_is_unknown_and_never_sent_to_provider():
    def forbidden(*args):
        pytest.fail("unsupported subject reached network")

    subject = PACKAGE.model_copy(update={"ecosystem": None})
    result = OSV(forbidden).scan([subject], inventory_revision=REV, now=NOW)[0]
    assert result.state == "unknown" and result.error_class == "unsupported"


def test_trivy_requires_matching_manifest_and_real_package_coverage(tmp_path):
    adapter = Trivy(cache=tmp_path)
    adapter._run = lambda _: {
        "Metadata": {"RepoDigests": [IMAGE.replace("b" * 64, "c" * 64)]},
        "Results": [],
    }
    result = adapter.scan([SUBJECT], inventory_revision=REV, now=NOW)[0]
    assert result.error_class == "evidence_mismatch"
    adapter._run = lambda _: {"Metadata": {"RepoDigests": [IMAGE]}, "Results": []}
    result = adapter.scan([SUBJECT], inventory_revision=REV, now=NOW)[0]
    assert result.error_class == "incomplete" and result.state == "scan_failed"


def test_trivy_database_freshness_is_required_even_with_no_findings(tmp_path):
    adapter = Trivy(cache=tmp_path)
    adapter._run = lambda argv: (
        {"VulnerabilityDB": {"UpdatedAt": "2020-01-01T00:00:00Z"}}
        if argv[0] == "version"
        else {
            "Metadata": {"RepoDigests": [IMAGE]},
            "Results": [{"Packages": [{"Name": "openssl"}]}],
        }
    )
    result = adapter.scan([SUBJECT], inventory_revision=REV, now=NOW)[0]
    assert result.state == "stale" and not result.complete


def test_scan_failures_keep_last_successful_evidence_after_restart(tmp_path, provider):
    adapter, subject = provider
    store = ScanStore(tmp_path / "scans.db")
    positive = adapter.scan([subject], inventory_revision=REV, now=NOW)[0]
    store.save([positive])
    broken = ScanResult(
        source=positive.source,
        subject=subject,
        inventory_revision=REV,
        checked_at=NOW + 60,
        state="scan_failed",
        error_class="unavailable",
    )
    store.save([broken])
    restarted = ScanStore(tmp_path / "scans.db")
    assert restarted.evidence(broken)["findings"][0]["id"] == "CVE-2026-1234"
    assert restarted.evidence(broken)["checked_at"] == NOW


def test_success_states_cannot_claim_incomplete_or_inconsistent_evidence():
    with pytest.raises(ValidationError):
        ScanResult(
            source="osv",
            inventory_revision=REV,
            subject=PACKAGE,
            checked_at=NOW,
            state="not_affected",
            complete=False,
        )
    with pytest.raises(ValidationError):
        ScanResult(
            source="osv",
            inventory_revision=REV,
            subject=PACKAGE,
            checked_at=NOW,
            state="confirmed",
            complete=True,
        )


def inventory():
    return Inventory(
        os_id="ubuntu",
        os_version="26.04",
        running_kernel="7.0.0",
        config_revision=REV,
        packages=[
            {
                "name": "libssl3",
                "version": PACKAGE.version,
                "architecture": "amd64",
                "source_name": "openssl",
                "source_version": PACKAGE.version,
            }
        ],
    )


def test_scanner_bundle_requires_inventory_and_image_bindings(tmp_path):
    inv = inventory()
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps({"revision": inv.revision, **inv.model_dump(), "images": []}))
    loaded, images = load_bundle(path)
    assert loaded == inv and not images
    assert packages(loaded)[0] == PACKAGE
    document = json.loads(path.read_text())
    document["running_kernel"] = "different"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="revision mismatch"):
        load_bundle(path)


def test_real_scan_pipeline_writes_private_report_and_preserves_failure_evidence(tmp_path):
    inv = inventory()
    store = ScanStore(tmp_path / "scan.db")
    first = scan(inv, [], store, {"osv": OSV(osv_request)}, now=NOW)
    assert first["source_queries_complete"] and first["counts"] == {"confirmed": 1}
    assert not first["complete"] and first["kernel"]["state"] == "unknown"

    def unavailable(*args):
        raise ScanError("unavailable")

    second = scan(inv, [], store, {"osv": OSV(unavailable)}, now=NOW + 60)
    assert not second["complete"] and second["counts"] == {"scan_failed": 1}
    assert second["results"][0]["last_success"]["findings"]
    path = tmp_path / "report.json"
    write_private(path, second)
    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text())["results"][0]["error_class"] == "unavailable"


@pytest.mark.skipif(os.geteuid() == 0, reason="scanner CLI requires an unprivileged user")
def test_scan_cli_publishes_revision_bound_persistent_observations(tmp_path, monkeypatch, capsys):
    from steward import scanner
    from steward.core.scan_observations import Observations

    inv = inventory()
    bundle, output, state = tmp_path / "inventory.json", tmp_path / "out.json", tmp_path / "state"
    bundle.write_text(json.dumps({**inv.model_dump(), "revision": inv.revision, "images": []}))
    monkeypatch.setattr(scanner, "OSV", lambda **kwargs: OSV(osv_request))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "steward-scan",
            "--inventory",
            str(bundle),
            "--out",
            str(output),
            "--state-dir",
            str(state),
        ],
    )
    previous = os.umask(0o077)
    try:
        with pytest.raises(SystemExit) as exit_status:
            scanner.main()
    finally:
        os.umask(previous)
    assert exit_status.value.code == 3  # fixture has no running-kernel package evidence
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["inventory_revision"] == inv.revision
    report = json.loads(output.read_text())
    observations = Observations(state / "observations.db")
    summary = observations.summary(
        now=report["generated_at"],
        enabled=True,
        config_revision=inv.config_revision,
        max_age_s=86400,
    )
    assert summary["counts"] == {"confirmed": 1} and not summary["complete"]
    assert summary["inventory_revision"] == inv.revision
    assert observations.changes()["changes"][0]["kind"] == "vulnerability.confirmed"


def test_bounded_process_reports_output_limit_and_timeout(tmp_path):
    with pytest.raises(CommandError, match="output_limit"):
        run_bounded(
            [sys.executable, "-c", "print('x'*100000)"],
            cwd=tmp_path,
            env={"PATH": "/usr/bin:/bin"},
            timeout=2,
            max_bytes=100,
        )
    with pytest.raises(CommandError, match="timeout"):
        run_bounded(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            cwd=tmp_path,
            env={"PATH": "/usr/bin:/bin"},
            timeout=0.1,
            max_bytes=100,
        )
    assert (
        run_bounded(
            [sys.executable, "-c", "print('ok')"],
            cwd=tmp_path,
            env={"PATH": "/usr/bin:/bin"},
            timeout=2,
            max_bytes=100,
        )
        == b"ok\n"
    )


def test_bounded_process_kills_descendants_that_hold_stdout(tmp_path):
    pidfile = tmp_path / "child.pid"
    script = (
        "import pathlib,subprocess,sys; "
        "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(10)']); "
        f"pathlib.Path({str(pidfile)!r}).write_text(str(p.pid))"
    )
    with pytest.raises(CommandError, match="timeout"):
        run_bounded(
            [sys.executable, "-c", script],
            cwd=tmp_path,
            env={"PATH": "/usr/bin:/bin"},
            timeout=3,
            max_bytes=100,
        )
    pid = int(pidfile.read_text())
    stat = Path(f"/proc/{pid}/stat")
    deadline = time.monotonic() + 2
    while stat.exists() and stat.read_text().split()[2] != "Z" and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not stat.exists() or stat.read_text().split()[2] == "Z"


def test_advisory_summary_is_redacted_and_bounded():
    value = Advisory(id="CVE-2026-1234", summary="password=hunter2 " + "x" * 1000)
    assert "hunter2" not in value.summary and len(value.summary) == 500


def test_running_kernel_requires_matching_packages_and_no_pending_reboot():
    from steward.scanner import assess_kernel

    inv = inventory()
    from steward.core.inventory import Package

    inv.packages.append(
        Package(
            name="linux-image-7.0.0",
            version="7.0.0-1.1",
            architecture="amd64",
            source_name="linux",
            source_version="7.0.0-1.1",
        )
    )
    subjects = packages(inv)
    results = [
        ScanResult(
            source="osv",
            subject=s,
            inventory_revision=inv.revision,
            checked_at=NOW,
            state="not_affected",
            complete=True,
        )
        for s in subjects
    ]
    assert (
        assess_kernel(inv, results, now=NOW)["state"] == "unknown"
    )  # Legacy inventory lacks reboot proof.
    inv.reboot_required = False
    results = [r.model_copy(update={"inventory_revision": inv.revision}) for r in results]
    assert assess_kernel(inv, results, now=NOW)["state"] == "not_affected"
    inv.reboot_required = True
    assert assess_kernel(inv, results, now=NOW)["state"] == "unknown"


def test_pipeline_rejects_missing_or_rebound_provider_results(tmp_path):
    class Incomplete:
        def scan(self, subjects, **kw):
            return []

    with pytest.raises(ValueError, match="every requested subject"):
        scan(inventory(), [], ScanStore(tmp_path / "scan.db"), {"osv": Incomplete()}, now=NOW)


def test_image_runtime_claim_is_not_part_of_content_identity_but_is_checked_by_pipeline():
    verified = SUBJECT.model_copy(update={"runtime_verified": True})
    assert verified.key == SUBJECT.key
    assert verified != SUBJECT


def test_legacy_inventory_revision_remains_valid_without_optional_kernel_metadata():
    from steward.core.canonical import revision_id

    inv = inventory()
    old_body = inv.model_dump(
        mode="json", exclude={"reboot_required", "kernel_build", "application_services"}
    )
    old_revision = revision_id(old_body)
    assert inv.revision == old_revision
    assert (
        Inventory.model_validate({**old_body, "application_services": []}).revision == old_revision
    )


def test_legacy_sqlite_image_evidence_remains_readable(tmp_path):
    from steward.core.canonical import revision_id

    subject = {
        "kind": "image",
        "scope": "notes",
        "name": "docker.io/library/alpine",
        "version": "sha256:" + "b" * 64,
        "ecosystem": None,
        "image": IMAGE,
    }
    key = revision_id(subject)
    old_record = {
        "v": 1,
        "source": "trivy",
        "inventory_revision": REV,
        "subject": {**subject, "runtime_verified": True},
        "checked_at": NOW,
        "state": "not_affected",
        "complete": True,
    }
    store = ScanStore(tmp_path / "scans.db")
    with sqlite3.connect(store.path) as db:
        body = json.dumps(old_record)
        db.execute("INSERT INTO results VALUES (?,?,?,?,?)", ("trivy", key, body, body, NOW))
    result = ScanResult.model_validate(old_record)
    assert result.subject.key == key
    assert store.evidence(result) == old_record


@pytest.mark.parametrize("scope", ["ab/api", "notes/API", "notes/ui", "notes/api/extra"])
def test_inventory_rejects_invalid_application_service_slugs(scope):
    with pytest.raises(ValidationError):
        Inventory.model_validate({**inventory().model_dump(), "application_services": [scope]})


def test_inventory_bounds_combined_targets_and_rejects_duplicate_services():
    body = inventory().model_dump()
    body.update(projects=[f"project-{index}" for index in range(63)])
    assert Inventory.model_validate({**body, "application_services": ["notes/api"]})
    with pytest.raises(ValidationError, match="at most 64"):
        Inventory.model_validate({**body, "application_services": ["notes/api", "notes/web"]})
    with pytest.raises(ValidationError, match="duplicate application service"):
        Inventory.model_validate({**body, "application_services": ["notes/api"] * 2})


def test_application_services_bind_only_image_components():
    with pytest.raises(ValidationError, match="require image subjects"):
        Component.model_validate({**PACKAGE.model_dump(), "scope": "notes/api"})


def test_bundle_binds_exact_legacy_projects_and_application_services():
    inv = Inventory.model_validate(
        {**inventory().model_dump(), "projects": ["notes"], "application_services": ["notes/api"]}
    )
    common = {
        "config_revision": inv.config_revision,
        "configured_image": IMAGE,
        "observed": True,
        "observed_running": True,
        "observed_image_digest": "sha256:" + "b" * 64,
        "observed_image_id": "c" * 64,
    }
    project = {**common, "project": "notes"}
    service = {**common, "application": "notes", "service": "api"}
    body = inv.model_dump(mode="json", exclude_none=True)
    document = {**body, "revision": inv.revision}
    assert inv.revision != Inventory.model_validate({**body, "application_services": []}).revision
    _, images = parse_bundle({**document, "images": [project, service]})
    assert [image.scope for image in images] == ["notes", "notes/api"]
    assert all(image.runtime_verified for image in images)
    assert images[0].key != images[1].key

    for observations, error in (
        ([project], "missing"),
        ([service], "missing"),
        ([project, service, service], "duplicate"),
        ([project, {**service, "service": "web"}], "unregistered"),
        ([project, {**service, "project": "notes"}], "invalid legacy image identity"),
        ([project, {**service, "config_revision": "d" * 64}], "image configuration revision"),
    ):
        with pytest.raises(ValueError, match=error):
            parse_bundle({**document, "images": observations})


def test_bundle_requires_matching_image_config_and_does_not_infer_runtime_identity(tmp_path):
    inv = inventory()
    inv.projects = ["notes"]
    image = {
        "project": "notes",
        "config_revision": inv.config_revision,
        "configured_image": IMAGE,
        "observed": True,
        "observed_image_digest": None,
    }
    body = {"revision": inv.revision, **inv.model_dump(mode="json"), "images": [image]}
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(body))
    assert not load_bundle(path)[1][0].runtime_verified
    image["observed_image_digest"] = "sha256:" + "b" * 64
    image["observed_image_id"] = "c" * 64
    image["observed_running"] = True
    path.write_text(json.dumps(body))
    assert load_bundle(path)[1][0].runtime_verified
    image["config_revision"] = "c" * 64
    path.write_text(json.dumps(body))
    with pytest.raises(ValueError, match="image configuration revision"):
        load_bundle(path)


def test_pipeline_rejects_a_scanner_forging_runtime_verification(tmp_path):
    class Liar:
        def scan(self, subjects, *, inventory_revision, now):
            return [
                ScanResult(
                    source="trivy",
                    subject=subjects[0].model_copy(update={"runtime_verified": True}),
                    inventory_revision=inventory_revision,
                    checked_at=now,
                    state="not_affected",
                    complete=True,
                )
            ]

    with pytest.raises(ValueError, match="every requested subject"):
        scan(inventory(), [SUBJECT], ScanStore(tmp_path / "scan.db"), {"trivy": Liar()}, now=NOW)


def test_scan_state_is_private_and_inventory_fifo_cannot_block_reader(tmp_path):
    import os

    db = tmp_path / "private.db"
    ScanStore(db)
    assert db.stat().st_mode & 0o777 == 0o600
    fifo = tmp_path / "inventory.pipe"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="regular file"):
        load_bundle(fifo)


def test_shared_scanner_failure_cannot_become_a_negative_result(provider):
    adapter, subject = provider

    def unavailable(*args):
        raise ScanError("unavailable")

    if isinstance(adapter, OSV):
        adapter.request = unavailable
    else:
        adapter._run = unavailable
    result = adapter.scan([subject], inventory_revision=REV, now=NOW)[0]
    assert result.state == "scan_failed" and result.error_class == "unavailable"
    assert not result.complete


@pytest.mark.parametrize("stamp", [None, "2026-01-01T00:00:00"])
def test_trivy_keeps_partial_positive_evidence_when_database_proof_is_missing(tmp_path, stamp):
    adapter = Trivy(cache=tmp_path)
    adapter._run = lambda argv: (
        {"VulnerabilityDB": {"UpdatedAt": stamp}}
        if argv[0] == "version"
        else {
            "Metadata": {"RepoDigests": [IMAGE]},
            "Results": [
                {
                    "Packages": [{"Name": "openssl"}],
                    "Vulnerabilities": [{"VulnerabilityID": "CVE-2026-1234", "Severity": "HIGH"}],
                }
            ],
        }
    )
    result = adapter.scan([SUBJECT], inventory_revision=REV, now=NOW)[0]
    assert result.state == "scan_failed" and not result.complete
    assert result.findings[0].id == "CVE-2026-1234"


def test_late_scan_cannot_replace_newer_observation_or_successful_evidence(tmp_path):
    import sqlite3

    store = ScanStore(tmp_path / "scan.db")
    current = ScanResult(
        source="osv",
        subject=PACKAGE,
        inventory_revision=REV,
        checked_at=NOW,
        state="confirmed",
        complete=True,
        findings=[Advisory(id="CVE-2026-9999", summary="new evidence")],
    )
    older = current.model_copy(
        update={
            "checked_at": NOW - 100,
            "findings": [
                Advisory(id="CVE-2026-1234", summary="older evidence"),
            ],
        }
    )
    store.save([current])
    store.save([older])
    assert store.evidence(current)["findings"][0]["id"] == "CVE-2026-9999"
    with sqlite3.connect(store.path) as db:
        latest = json.loads(db.execute("SELECT latest FROM results").fetchone()[0])
    assert latest["checked_at"] == NOW


def test_scanner_transport_rejects_invalid_target_without_exposing_it():
    from steward.adapters.scanners import api

    with pytest.raises(ScanError, match="^invalid_response$"):
        api("GET", "http://user:credential@example.com/private")


@pytest.mark.parametrize("reported", ["sha256:" + "d" * 64, "sha256:" + "e" * 64, None])
def test_trivy_binds_scan_to_root_config_content_id_not_only_manifest_index(tmp_path, reported):
    subject = SUBJECT.model_copy(
        update={"expected_image_id": "sha256:" + "d" * 64, "runtime_verified": True}
    )
    provider = Trivy(cache=tmp_path)
    provider._run = lambda argv: (
        {"VulnerabilityDB": {"UpdatedAt": datetime.fromtimestamp(NOW, UTC).isoformat()}}
        if argv[0] == "version"
        else {
            "Metadata": {"RepoDigests": [IMAGE], "ImageID": reported},
            "Results": [{"Packages": [{"Name": "openssl"}]}],
        }
    )
    result = provider.scan([subject], inventory_revision=REV, now=NOW)[0]
    if reported == subject.expected_image_id:
        assert result.state == "not_affected" and result.complete
    else:
        assert not result.complete and result.error_class == "evidence_mismatch"


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, 60),
        ("invalid", 60),
        ("inf", 60),
        ("120", 120),
        ("-10", 1),
        ("Fri, 15 Jan 2027 08:02:00 GMT", 120),
    ],
)
def test_scanner_retry_after_seconds_and_http_date(value, expected):
    from steward.adapters.scanners import retry_delay

    now = datetime(2027, 1, 15, 8, 0, tzinfo=UTC).timestamp()
    assert retry_delay(value, now=now) == expected


def test_osv_rate_limit_stops_requests_and_survives_worker_restart(tmp_path):
    requests = []
    clock = [100.0]

    def limited(*args):
        requests.append(args)
        clock[0] += 2  # response latency must not shorten the server's requested wait
        raise ScanError("quota_exhausted", retry_after_s=600)

    provider = OSV(limited, monotonic=lambda: clock[0])
    # Multiple batches must not hammer a provider after its first 429.
    subjects = [PACKAGE.model_copy(update={"name": f"package-{i}"}) for i in range(201)]
    results = provider.scan(subjects, inventory_revision=REV, now=NOW)
    assert len(requests) == 1 and len(results) == len(subjects)
    assert all(r.retry_after_s == 602 for r in results)
    state = tmp_path / "scans.db"
    store = ScanStore(state)
    store.save(results)
    assert ScanStore(state).ready_at("osv") == NOW + 602
    # The pipeline enforces the persisted cooldown, not only the adapter instance.
    body = scan(inventory(), [], ScanStore(state), {"osv": provider}, now=NOW + 100)
    assert len(requests) == 1
    assert body["results"][0]["error_class"] == "quota_exhausted"
    assert body["results"][0]["retry_after_s"] == 502
    scan(inventory(), [], ScanStore(state), {"osv": provider}, now=ScanStore(state).ready_at("osv"))
    assert len(requests) == 2


def test_bounded_process_preserves_normal_exit_code_without_stderr(tmp_path):
    with pytest.raises(CommandError, match="unavailable") as error:
        run_bounded(
            [sys.executable, "-c", "import sys; print('secret', file=sys.stderr); sys.exit(11)"],
            cwd=tmp_path,
            env={"PATH": "/usr/bin:/bin"},
            timeout=2,
            max_bytes=100,
        )
    assert error.value.exit_code == 11 and "secret" not in str(error.value)
