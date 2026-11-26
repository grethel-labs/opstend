import copy
import json
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit

import pytest

from steward.adapters.intelligence import CACHE_TTL, KEV_URL, Cache, Intelligence
from steward.core.intelligence import Evidence, context_key
from steward.core.scan_observations import Observations
from steward.core.vulnerabilities import Advisory, ScanError, ScanResult
from steward.scanner import ScanStore, scan
from test_scanners import PACKAGE, REV, inventory

NOW = datetime(2026, 11, 15, 12, tzinfo=UTC).timestamp()
CVE = "CVE-2026-1234"
OTHER = "CVE-2026-5678"


def match(*aliases, id="GHSA-test", severity="high"):
    return ScanResult(
        source="osv",
        inventory_revision=REV,
        subject=PACKAGE,
        checked_at=NOW,
        state="confirmed",
        complete=True,
        findings=[
            Advisory(
                id=id,
                aliases=list(aliases or [CVE]),
                severity=severity,
                summary="Exact version match",
            )
        ],
    )


@pytest.fixture
def intel(tmp_path):
    clock, requests = [NOW], []
    catalog = {
        "count": 1,
        "catalogVersion": "2026.11.15",
        "dateReleased": "2026-11-15T00:00:00Z",
        "vulnerabilities": [{"cveID": CVE}],
    }

    def request(method, url):
        requests.append(url)
        assert method == "GET"
        if url == KEV_URL:
            return copy.deepcopy(catalog)
        cves = parse_qs(urlsplit(url).query)["cve"][0].split(",")
        return {
            "status": "OK",
            "status-code": 200,
            "total": len(cves),
            "offset": 0,
            "data": [
                {"cve": c, "epss": "0.9", "percentile": "0.99", "date": "2026-11-15"} for c in cves
            ],
        }

    cache = Cache(tmp_path / "context.db")
    client = Intelligence(cache, kev=True, epss=True, request=request, clock=lambda: clock[0])
    return client, clock, requests, catalog


def context(client, result=None):
    return client.enrich([result or match()])[0].findings[0].exploit_context[0]


def test_exact_cve_aliases_full_catalog_and_independent_epss_scores(intel):
    client, clock, requests, catalog = intel
    result = client.enrich([match(CVE, OTHER)])[0]
    first, second = result.findings[0].exploit_context
    assert first.kev.listed is True and second.kev.listed is False
    assert first.kev.state == second.kev.state == "available"
    assert first.epss.score == 0.9 and first.epss.percentile == 0.99
    assert first.epss.published_at == datetime(2026, 11, 15, tzinfo=UTC).timestamp()
    assert result.state == "confirmed" and result.complete
    assert result.subject == PACKAGE and result.findings[0].severity == "high"
    assert len(requests) == 2 and all(PACKAGE.name not in url for url in requests)
    context(client)
    assert len(requests) == 2  # successful cache survives another invocation


def test_disabled_and_no_cve_aliases_do_not_make_provider_requests(intel):
    client, clock, requests, catalog = intel
    client.kev = client.epss = False
    value = context(client)
    assert value.kev.state == value.epss.state == "disabled" and not requests
    client.kev = client.epss = True
    result = match("PYSEC-2026-1")
    assert client.enrich([result])[0].findings[0].exploit_context == []
    assert not requests


def test_missing_epss_row_is_unknown_and_not_zero(intel):
    client, clock, requests, catalog = intel
    client.kev = False
    client.request = lambda *args: {
        "status": "OK",
        "status-code": 200,
        "total": 0,
        "offset": 0,
        "data": [],
    }
    evidence = context(client).epss
    assert evidence.state == "unknown" and evidence.score is None and evidence.percentile is None


@pytest.mark.parametrize(
    "bad", ["count", "duplicate", "timezone", "negative_date", "empty", "identity"]
)
def test_invalid_catalog_never_becomes_negative_membership(intel, bad):
    client, clock, requests, catalog = intel
    if bad == "count":
        catalog["count"] = 2
    elif bad == "duplicate":
        catalog["vulnerabilities"] *= 2
        catalog["count"] = 2
    elif bad == "timezone":
        catalog["dateReleased"] = "2026-11-15T00:00:00"
    elif bad == "negative_date":
        catalog["dateReleased"] = "1900-01-01T00:00:00Z"
    elif bad == "empty":
        catalog["count"], catalog["vulnerabilities"] = 0, []
    else:
        catalog["vulnerabilities"][0]["cveID"] = "not-a-cve"
    evidence = context(client).kev
    assert evidence.state == "fetch_failed" and evidence.listed is None
    assert evidence.error_class == "invalid_response"


@pytest.mark.parametrize("bad", ["truncated", "foreign", "duplicate", "nan", "range", "boolean"])
def test_invalid_epss_pages_are_atomic_and_unknown(intel, bad):
    client, clock, requests, catalog = intel
    client.kev = False
    original = client.request

    def request(method, url):
        body = original(method, url)
        if bad == "truncated":
            body["total"] = 2
        elif bad == "foreign":
            body["data"][0]["cve"] = OTHER
        elif bad == "duplicate":
            body["data"] *= 2
            body["total"] = 2
        else:
            body["data"][0]["epss"] = {"nan": "NaN", "range": 1.1, "boolean": True}[bad]
        return body

    client.request = request
    evidence = context(client).epss
    assert evidence.state == "fetch_failed" and evidence.score is None
    assert client.cache.get("epss", CVE) is None


def test_source_failure_retains_historical_values_without_current_proof(intel):
    client, clock, requests, catalog = intel
    context(client)
    clock[0] += CACHE_TTL + 1

    def unavailable(*args):
        raise ScanError("unavailable")

    client.request = unavailable
    value = context(client)
    assert value.kev.listed is True and value.epss.score == 0.9
    assert value.kev.state == value.epss.state == "fetch_failed"
    assert value.kev.checked_at == NOW
    enriched = client.enrich([match()])[0]
    assert enriched.state == "confirmed"  # supplemental failure cannot invent an unaffected result
    assert context_key(enriched.findings[0].model_dump(mode="json"), clock[0]) == (0, 0)


def test_outdated_and_future_publications_are_stale(intel):
    client, clock, requests, catalog = intel
    catalog["dateReleased"] = "2020-01-01T00:00:00Z"
    value = context(client)
    assert value.kev.state == "stale" and value.kev.listed is True
    future = Evidence(
        source="epss",
        state="available",
        checked_at=NOW,
        published_at=NOW + 1,
        score=0.1,
        percentile=0.5,
    )
    assert future.state_at(NOW) == "stale"


def test_quota_cooldown_persists_and_does_not_block_other_source(intel):
    client, clock, requests, catalog = intel
    original = client.request
    calls = []

    def limited(method, url):
        calls.append(url)
        if url == KEV_URL:
            raise ScanError("quota_exhausted", retry_after_s=1800)
        return original(method, url)

    client.request = limited
    value = context(client)
    assert value.kev.state == "fetch_failed" and value.epss.state == "available"
    restored = Intelligence(
        Cache(client.cache.path), kev=True, epss=True, request=limited, clock=lambda: clock[0]
    )
    context(restored)
    assert calls.count(KEV_URL) == 1
    clock[0] += 1800
    restored.request = original
    assert context(restored).kev.state == "available"


def test_request_and_alias_limits_are_explicit_without_false_negatives(intel, monkeypatch):
    client, clock, requests, catalog = intel
    client.max_requests = 1
    value = context(client)
    assert value.kev.state == "available" and value.epss.error_class == "quota_exhausted"
    result = match(*[f"CVE-2026-{n:04d}" for n in range(1000, 1022)])
    enriched = client.enrich([result])[0].findings[0]
    assert len(enriched.exploit_context) == 20 and enriched.context_truncated
    monkeypatch.setattr("steward.adapters.intelligence.MAX_CVES", 1)
    client.max_requests = 100
    enriched = client.enrich([match(CVE, OTHER)])[0].findings[0]
    assert enriched.exploit_context[1].kev.state == "unknown"
    assert enriched.exploit_context[1].kev.listed is None


def test_older_catalog_cannot_overwrite_newer_evidence(intel):
    client, clock, requests, catalog = intel
    context(client)
    clock[0] += CACHE_TTL + 1
    catalog.update(dateReleased="2026-11-14T00:00:00Z", catalogVersion="2026.11.14")
    evidence = context(client).kev
    assert evidence.state == "fetch_failed" and evidence.error_class == "evidence_mismatch"
    assert evidence.catalog_version == "2026.11.15" and evidence.listed is True


def test_pipeline_persists_context_and_avoids_alerts_for_refresh_or_score_drift(intel, tmp_path):
    client, clock, requests, catalog = intel
    from types import SimpleNamespace

    provider = SimpleNamespace(
        scan=lambda subjects, inventory_revision, now: [
            match().model_copy(
                update={"subject": s, "inventory_revision": inventory_revision, "checked_at": now}
            )
            for s in subjects
        ]
    )
    store, observations = (
        ScanStore(tmp_path / "scans.db"),
        Observations(tmp_path / "observations.db"),
    )
    first = scan(inventory(), [], store, {"osv": provider}, now=NOW, enricher=client)
    assert first["results"][0]["findings"][0]["exploit_context"][0]["kev"]["listed"]
    observations.publish(first)
    cursor = observations.changes()["next_id"]
    clock[0] += CACHE_TTL
    second = scan(inventory(), [], store, {"osv": provider}, now=clock[0], enricher=client)
    second["results"][0]["findings"][0]["exploit_context"][0]["epss"]["score"] = 0.8
    observations.publish(second)
    assert [e["kind"] for e in observations.changes(cursor)["changes"]] == [
        "vulnerability.scan_completed"
    ]
    options = {"enabled": True, "config_revision": inventory().config_revision, "max_age_s": 604800}
    page = observations.query(now=clock[0] + 4 * 86400, **options)
    value = page["records"][0]["findings"][0]["exploit_context"][0]
    assert value["kev"]["state"] == value["epss"]["state"] == "stale"
    assert json.loads(json.dumps(page))["records"][0]["state"] == "confirmed"


def test_known_exploitation_prioritizes_without_changing_provider_severity(intel, tmp_path):
    client, clock, requests, catalog = intel
    from types import SimpleNamespace

    inv = inventory()
    inv.packages.append(
        inv.packages[0].model_copy(update={"name": "other", "source_name": "other"})
    )

    def provider(subjects, inventory_revision, now):
        return [
            match(
                CVE if s.name == "openssl" else OTHER,
                severity="low" if s.name == "openssl" else "critical",
            ).model_copy(update={"subject": s, "inventory_revision": inventory_revision})
            for s in subjects
        ]

    store = ScanStore(tmp_path / "scan.db")
    providers = {"osv": SimpleNamespace(scan=provider)}
    body = scan(inv, [], store, providers, now=NOW, enricher=client)
    observations = Observations(tmp_path / "observations.db")
    observations.publish(body)
    first = observations.query(
        now=NOW, enabled=True, config_revision=inv.config_revision, max_age_s=86400, limit=1
    )["records"][0]
    assert first["subject"]["name"] == "openssl"  # KEV before higher provider severity
    assert first["findings"][0]["severity"] == "low"
    low = scan(inventory(), [], store, providers, now=NOW, enricher=client)
    separate = Observations(tmp_path / "low.db")
    separate.publish(low)
    event = separate.changes()["changes"][0]
    assert event["severity"] == "high" and event["data"]["kev_listed"] == [CVE]


def test_epss_orders_equal_severity_without_becoming_local_exploitation_proof(intel):
    client, clock, requests, catalog = intel
    client.kev = False
    original = client.request

    def scored(method, url):
        body = original(method, url)
        for row in body["data"]:
            row["epss"] = "0.1" if row["cve"] == CVE else "0.9"
        return body

    client.request = scored
    result = match().model_copy(
        update={
            "findings": [
                Advisory(id=CVE, severity="medium", summary="first"),
                Advisory(id=OTHER, severity="medium", summary="second"),
            ]
        }
    )
    enriched = client.enrich([result])[0]
    assert [f.id for f in enriched.findings] == [OTHER, CVE]
    assert all(f.severity == "medium" for f in enriched.findings)
    assert all(not c.kev.listed for f in enriched.findings for c in f.exploit_context)
