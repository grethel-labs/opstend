"""Run the security scans for every managed Linux host (Proxmox hosts included)."""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from opstend.adapters.linux import Linux
from opstend.adapters.runner import CommandError
from opstend.core.models import Finding
from opstend.security import scanner

log = logging.getLogger("opstend.security")


@dataclass
class HostScan:
    target: str
    findings: list[Finding]
    complete: bool


async def scan_host(host: Linux, client: httpx.AsyncClient) -> HostScan:
    """Vulnerabilities (Trivy, else OSV) and hardening for one host."""
    findings: list[Finding] = []
    complete = True
    facts = await host.detect()
    trivy = await host.runner.run(
        ["trivy", "rootfs", "--quiet", "--scanners", "vuln", "--format", "json", "/"],
        check=False,
        timeout=1800,
    )
    if trivy.code == 0 and trivy.stdout.strip():
        findings += scanner.parse_trivy(scanner.load_trivy_json(trivy.stdout), host.host_id)
    else:
        ecosystem, packages = await host.installed()
        osv_eco = scanner.osv_ecosystem(ecosystem, facts.os)
        if osv_eco and packages:
            try:
                findings += await scanner.osv_scan(client, osv_eco, packages, host.host_id)
            except httpx.HTTPError as exc:
                complete = False
                findings.append(scanner.coverage_gap(host.host_id, f"OSV not reachable: {exc}"))
        else:
            complete = False
            findings.append(
                scanner.coverage_gap(
                    host.host_id,
                    f"No vulnerability source for {facts.os.get('PRETTY_NAME', 'this OS')}",
                )
            )
    try:
        sshd = scanner.parse_sshd_t((await host.runner.run(["sshd", "-T"], check=False)).stdout)
        nft = (await host.runner.run(["nft", "list", "ruleset"], check=False)).stdout
        listening = scanner.parse_ss((await host.runner.run(["ss", "-Htlnp"], check=False)).stdout)
        auto = await _auto_updates(host)
        findings += scanner.hardening_findings(host.host_id, sshd, nft, listening, auto)
    except (CommandError, OSError, PermissionError) as exc:
        complete = False
        findings.append(scanner.coverage_gap(host.host_id, f"Hardening checks failed: {exc}"))
    return HostScan(host.host_id, findings, complete)


async def _auto_updates(host: Linux) -> bool:
    m = host.facts.manager
    if m == "apt":
        enabled = await host.runner.run(
            ["systemctl", "is-enabled", "unattended-upgrades.service"], check=False
        )
        return enabled.stdout.strip() == "enabled"
    if m == "dnf":
        enabled = await host.runner.run(
            ["systemctl", "is-enabled", "dnf-automatic.timer"], check=False
        )
        return enabled.stdout.strip() == "enabled"
    # OpsTend itself patches these hosts in the maintenance window.
    return True
