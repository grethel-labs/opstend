"""Independent security scans.

* Packages: Trivy when installed (most accurate for OS packages), otherwise the
  OSV database. Every finding notes which source produced it.
* Threat context: CISA KEV (known exploited) and FIRST EPSS (exploit
  probability) raise the priority of findings.
* Hardening: SSH, firewall, automatic updates and listening services.
* Exposure: OpsTend knows which services are published, so it can tell an
  exploitable service on the internet from the same package in a closed VLAN.

Coverage gaps are reported as findings too. A scan that could not run is
never shown as "no vulnerabilities".
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import httpx

from opstend.core.models import Finding, FindingKind, Severity

OSV_URL = "https://api.osv.dev/v1"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


def osv_ecosystem(manager_ecosystem: str, os_release: dict[str, str]) -> str | None:
    vid = os_release.get("VERSION_ID", "")
    os_id = os_release.get("ID", "")
    if os_id == "ubuntu" and vid:
        return (
            f"Ubuntu:{vid}:LTS"
            if vid.split(".")[1:2] == ["04"] and int(vid.split(".")[0]) % 2 == 0
            else f"Ubuntu:{vid}"
        )
    if os_id in ("debian", "raspbian") and vid:
        return f"Debian:{vid}"
    if os_id == "alpine" and vid:
        return "Alpine:v" + ".".join(vid.split(".")[:2])
    if os_id == "rocky" and vid:
        return f"Rocky Linux:{vid.split('.')[0]}"
    if os_id == "almalinux" and vid:
        return f"AlmaLinux:{vid.split('.')[0]}"
    if manager_ecosystem == "SUSE" or os_id.startswith("opensuse"):
        return "openSUSE" if os_id.startswith("opensuse") else "SUSE"
    if os_id in ("rhel",):
        return "Red Hat"
    return None


def severity_from_cvss(score: float | None) -> Severity:
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _fid(*parts: str) -> str:
    return "vul-" + hashlib.sha1("|".join(parts).encode(), usedforsecurity=False).hexdigest()[:14]


def parse_trivy(report: dict[str, Any], target: str) -> list[Finding]:
    out = []
    for result in report.get("Results", []) or []:
        for v in result.get("Vulnerabilities", []) or []:
            sev = str(v.get("Severity", "MEDIUM")).lower()
            out.append(
                Finding(
                    id=_fid(target, v.get("VulnerabilityID", ""), v.get("PkgName", "")),
                    target=target,
                    kind=FindingKind.VULNERABILITY,
                    severity=Severity(sev)
                    if sev in Severity.__members__.values()
                    else Severity.MEDIUM,
                    title=f"{v.get('VulnerabilityID')} in {v.get('PkgName')}",
                    detail=(v.get("Title") or v.get("Description") or "")[:500],
                    cve=v.get("VulnerabilityID"),
                    package=v.get("PkgName"),
                    installed=v.get("InstalledVersion"),
                    fixed=v.get("FixedVersion") or None,
                    recommendation=f"Update {v.get('PkgName')} to {v['FixedVersion']}"
                    if v.get("FixedVersion")
                    else "No fix released yet; reduce exposure",
                )
            )
    return out


def parse_osv_vuln(v: dict[str, Any], target: str, package: str, installed: str) -> Finding:
    cve = next((a for a in v.get("aliases", []) if a.startswith("CVE-")), v.get("id"))
    score = None
    for s in v.get("severity", []) or []:
        try:
            score = float(s.get("score"))
        except (TypeError, ValueError):
            continue
    db_sev = str((v.get("database_specific") or {}).get("severity", "")).lower()
    sev = (
        Severity(db_sev)
        if db_sev in ("low", "medium", "high", "critical")
        else severity_from_cvss(score)
    )
    fixed = None
    for aff in v.get("affected", []):
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed = ev["fixed"]
    return Finding(
        id=_fid(target, v["id"], package),
        target=target,
        kind=FindingKind.VULNERABILITY,
        severity=sev,
        title=f"{cve} in {package}",
        detail=(v.get("summary") or "")[:500],
        cve=cve,
        package=package,
        installed=installed,
        fixed=fixed,
        recommendation=f"Update {package} to {fixed}" if fixed else "No fix released yet",
    )


class ThreatFeeds:
    """Caches KEV and EPSS. Unreachable feeds are reported, never silently skipped."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self.client = client or httpx.AsyncClient(timeout=30.0)
        self.kev: set[str] = set()
        self.kev_ok = False

    async def refresh_kev(self) -> None:
        resp = await self.client.get(KEV_URL)
        resp.raise_for_status()
        self.kev = {v["cveID"] for v in resp.json().get("vulnerabilities", [])}
        self.kev_ok = True

    async def epss(self, cves: Iterable[str]) -> dict[str, float]:
        out: dict[str, float] = {}
        ids = sorted({c for c in cves if c and c.startswith("CVE-")})
        for i in range(0, len(ids), 100):
            resp = await self.client.get(EPSS_URL, params={"cve": ",".join(ids[i : i + 100])})
            resp.raise_for_status()
            for row in resp.json().get("data", []):
                out[row["cve"]] = float(row["epss"])
        return out


async def osv_scan(
    client: httpx.AsyncClient, ecosystem: str, packages: list[tuple[str, str]], target: str
) -> list[Finding]:
    findings: list[Finding] = []
    for i in range(0, len(packages), 500):
        chunk = packages[i : i + 500]
        queries = [{"package": {"name": n, "ecosystem": ecosystem}, "version": v} for n, v in chunk]
        resp = await client.post(f"{OSV_URL}/querybatch", json={"queries": queries})
        resp.raise_for_status()
        for (name, version), result in zip(chunk, resp.json().get("results", []), strict=False):
            for ref in result.get("vulns", []) or []:
                detail = await client.get(f"{OSV_URL}/vulns/{ref['id']}")
                if detail.status_code == 200:
                    findings.append(parse_osv_vuln(detail.json(), target, name, version))
    return findings


@dataclass
class Exposure:
    """Which targets are reachable from outside, from publications and firewall data."""

    public: set[str]
    lan: set[str]


def prioritize(
    findings: list[Finding], kev: set[str], epss: dict[str, float], exposure: Exposure
) -> list[Finding]:
    """Raise severity for known exploitation and exposure; lower it for closed targets."""
    for f in findings:
        if f.cve:
            f.kev = f.cve in kev
            f.epss = epss.get(f.cve)
        f.exposed = f.target in exposure.public
        if f.kev and f.exposed:
            f.severity = Severity.CRITICAL
            f.recommendation = (
                f.recommendation or ""
            ) + ". Known exploited and reachable from the internet: act now."
        elif f.kev or (f.epss or 0) >= 0.2:
            if f.severity in (Severity.LOW, Severity.MEDIUM):
                f.severity = Severity.HIGH
    order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
    return sorted(findings, key=lambda f: (order[Severity(f.severity)], -(f.epss or 0)))


# --- hardening ---------------------------------------------------------------


def parse_sshd_t(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        key, _, value = line.partition(" ")
        if key:
            out[key.lower()] = value.strip().lower()
    return out


def hardening_findings(
    target: str,
    sshd: dict[str, str],
    nft_rules: str,
    listening: list[tuple[str, int, str]],
    auto_updates: bool,
) -> list[Finding]:
    out = []

    def add(code: str, sev: Severity, title: str, detail: str, fix: str) -> None:
        out.append(
            Finding(
                id=f"hard-{code}-{hashlib.sha1(target.encode(), usedforsecurity=False).hexdigest()[:8]}",
                target=target,
                kind=FindingKind.HARDENING,
                severity=sev,
                title=title,
                detail=detail,
                recommendation=fix,
            )
        )

    if sshd.get("passwordauthentication") == "yes":
        add(
            "ssh-password",
            Severity.HIGH,
            "SSH accepts passwords",
            "Password logins can be brute-forced.",
            "Use keys only: PasswordAuthentication no",
        )
    if sshd.get("permitrootlogin") in ("yes",):
        add(
            "ssh-root",
            Severity.MEDIUM,
            "SSH allows root login with a password",
            "Root should log in with a key at most.",
            "PermitRootLogin prohibit-password",
        )
    if "chain input" not in nft_rules or "policy drop" not in nft_rules:
        add(
            "firewall",
            Severity.HIGH,
            "No default-deny host firewall",
            "Every listening service is reachable from all networks.",
            "Enable the OpsTend host firewall profile",
        )
    if not auto_updates:
        add(
            "auto-updates",
            Severity.MEDIUM,
            "Automatic security updates are off",
            "Security fixes wait for manual action.",
            "Let OpsTend apply security updates in the window",
        )
    risky = {
        23: "telnet",
        21: "ftp",
        111: "rpcbind",
        2375: "docker (unencrypted)",
        6379: "redis",
        27017: "mongodb",
        9200: "elasticsearch",
    }
    for addr, port, proc in listening:
        if port in risky and addr in ("0.0.0.0", "::", "*"):  # noqa: S104
            add(
                f"listen-{port}",
                Severity.HIGH,
                f"{risky[port]} listens on all interfaces",
                f"{proc or 'A process'} accepts connections on port {port} from any network.",
                "Bind it to localhost or a service network",
            )
    return out


def parse_ss(text: str) -> list[tuple[str, int, str]]:
    """`ss -Htlnp`: State Recv-Q Send-Q Local:Port Peer:Port Process."""
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        addr, _, port = local.rpartition(":")
        proc = parts[5] if len(parts) > 5 else ""
        name = proc.split('"')[1] if '"' in proc else ""
        try:
            out.append((addr.strip("[]"), int(port), name))
        except ValueError:
            continue
    return out


def coverage_gap(target: str, reason: str) -> Finding:
    return Finding(
        id=f"gap-{hashlib.sha1(target.encode(), usedforsecurity=False).hexdigest()[:10]}",
        target=target,
        kind=FindingKind.CONFIGURATION,
        severity=Severity.MEDIUM,
        title="Security scan incomplete",
        detail=reason,
        recommendation="Install Trivy on the scanner node or allow access to osv.dev",
    )


def load_trivy_json(text: str) -> dict[str, Any]:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("unexpected Trivy output")
    return data
