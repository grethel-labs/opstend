from datetime import UTC, datetime, time, timedelta

import pytest

from opstend.core.audit import AuditLog
from opstend.core.jobs import ActionRegistry, Engine, FunctionAction, JobState
from opstend.core.models import Finding, FindingKind, Node, NodeState, Service, Severity, Update
from opstend.core.policy import Governor, Policy
from opstend.core.store import Store
from opstend.core.windows import Window
from opstend.security import scanner
from opstend.selfmanage.health import Probe, ProbeResult, run_probe
from opstend.selfmanage.reconciler import Observations, Reconciler

# -- security -----------------------------------------------------------------


def test_osv_ecosystems():
    assert scanner.osv_ecosystem("Debian", {"ID": "debian", "VERSION_ID": "13"}) == "Debian:13"
    assert (
        scanner.osv_ecosystem("Debian", {"ID": "ubuntu", "VERSION_ID": "24.04"})
        == "Ubuntu:24.04:LTS"
    )
    assert (
        scanner.osv_ecosystem("Debian", {"ID": "ubuntu", "VERSION_ID": "25.10"}) == "Ubuntu:25.10"
    )
    assert (
        scanner.osv_ecosystem("Alpine", {"ID": "alpine", "VERSION_ID": "3.21.2"}) == "Alpine:v3.21"
    )
    assert scanner.osv_ecosystem("Arch", {"ID": "arch"}) is None


def test_trivy_and_osv_parsing():
    report = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-0001",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.1",
                        "FixedVersion": "3.0.2",
                        "Severity": "CRITICAL",
                        "Title": "Heap overflow",
                    }
                ]
            }
        ]
    }
    f = scanner.parse_trivy(report, "host/a")[0]
    assert f.severity == Severity.CRITICAL and f.fixed == "3.0.2" and "3.0.2" in f.recommendation
    v = {
        "id": "DSA-1",
        "aliases": ["CVE-2026-0002"],
        "summary": "x",
        "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2"}]}]}],
    }
    f2 = scanner.parse_osv_vuln(v, "host/a", "zlib", "1.1")
    assert f2.cve == "CVE-2026-0002" and f2.fixed == "1.2"


def test_prioritize_kev_and_exposure():
    def mk(cve, target, sev=Severity.MEDIUM):
        return Finding(
            id=cve + target,
            target=target,
            kind=FindingKind.VULNERABILITY,
            severity=sev,
            title=cve,
            cve=cve,
        )

    findings = [mk("CVE-1", "service/medien"), mk("CVE-1", "service/intern"), mk("CVE-2", "x")]
    out = scanner.prioritize(
        findings, {"CVE-1"}, {"CVE-2": 0.01}, scanner.Exposure(public={"service/medien"}, lan=set())
    )
    assert out[0].target == "service/medien" and out[0].severity == Severity.CRITICAL
    assert next(f for f in out if f.target == "service/intern").severity == Severity.HIGH


def test_hardening_and_ss_parsing():
    listening = scanner.parse_ss(
        'LISTEN 0 4096 0.0.0.0:6379 0.0.0.0:* users:(("redis-server",pid=1,fd=6))\n'
        "LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\n"
    )
    assert listening[0] == ("0.0.0.0", 6379, "redis-server")
    sshd = scanner.parse_sshd_t("passwordauthentication yes\npermitrootlogin prohibit-password\n")
    found = scanner.hardening_findings("host/a", sshd, "", listening, auto_updates=False)
    titles = {f.title for f in found}
    assert "SSH accepts passwords" in titles and "No default-deny host firewall" in titles
    assert any("redis" in t for t in titles)
    ok = scanner.hardening_findings(
        "host/a",
        {"passwordauthentication": "no"},
        "table inet f { chain input { type filter hook input priority 0; policy drop; } }",
        [],
        auto_updates=True,
    )
    assert ok == []


# -- health and reconciler ----------------------------------------------------


async def test_probe_unknown_is_not_healthy():
    obs = await run_probe(Probe(kind="container", target="x"))
    assert obs.result == ProbeResult.UNKNOWN
    tcp = await run_probe(Probe(kind="tcp", target="127.0.0.1:1", timeout_s=0.5))
    assert tcp.result == ProbeResult.UNHEALTHY


def _reconciler(policy: Policy):
    reg = ActionRegistry()
    for name in (
        "service.restart",
        "cluster.replace_node",
        "publication.withdraw",
        "host.patch",
        "backup.run",
    ):

        async def ok(params, ctx):
            return {}

        reg.register(FunctionAction(name, "x", describe=lambda p, n=name: n, execute=ok))
    engine = Engine(Store(), AuditLog(), reg)
    return Reconciler(Governor(policy), engine), engine


@pytest.fixture
def monday_night():
    return datetime(2026, 11, 30, 2, 30, tzinfo=UTC)


async def test_reconciler_end_to_end(monday_night):
    policy = Policy(
        window=Window(days=["mon"], start=time(2, 0), duration_minutes=60, timezone="UTC")
    )
    rec, engine = _reconciler(policy)
    obs = Observations(
        services=[Service(id="sensorik", name="Sensorik")],
        probes={"sensorik": [ProbeResult.HEALTHY] + [ProbeResult.UNHEALTHY] * 3},
        nodes=[Node(id="n3", name="nuc-c", address="x", state=NodeState.DOWN)],
        findings=[
            Finding(
                id="f",
                target="service/medien",
                kind=FindingKind.VULNERABILITY,
                severity=Severity.CRITICAL,
                title="t",
                cve="CVE-1",
                kev=True,
                exposed=True,
            )
        ],
        updates=[
            Update(
                id="u", target="host/a", kind="package", current="1", available="2", security=True
            )
        ],
        backup_targets={"guest/medien": timedelta(days=1)},
        publications={"medien": "pub-medien"},
    )
    proposals = rec.propose(obs, monday_night)
    cats = sorted(p.category for p in proposals)
    assert cats == ["backup", "patch", "quarantine", "reschedule", "restart"]
    incidents = await rec.act(proposals, monday_night)
    states = {i.title: i.state for i in incidents}
    assert states["Restart Sensorik"] == "handling"
    assert states["Withdraw public access to medien"] == "waiting"  # approval by default
    jobs = {j.title: j for j in engine.list()}
    assert jobs["Restart Sensorik"].state == JobState.SCHEDULED
    assert jobs["Withdraw public access to medien"].state == JobState.AWAITING_APPROVAL
    # A second cycle does not duplicate open jobs.
    await rec.act(rec.propose(obs, monday_night), monday_night)
    assert len(engine.list()) == len(jobs)


async def test_reconciler_escalates_after_budget(monday_night):
    rec, _ = _reconciler(Policy())
    obs = Observations(
        services=[Service(id="s", name="S")], probes={"s": [ProbeResult.UNHEALTHY] * 3}
    )
    for i in range(3):
        rec.governor.spend("restart", "service/s", monday_night - timedelta(minutes=50 - i * 15))
    incidents = await rec.act(rec.propose(obs, monday_night), monday_night)
    assert incidents[0].state == "needs_operator"
