import json

import httpx

from opstend.adapters.linux import Linux
from opstend.adapters.runner import Result
from opstend.agent import check
from opstend.security.run import scan_host

OUT = {
    ("cat", "/etc/os-release"): 'ID=debian\nVERSION_ID="13"\nPRETTY_NAME="Debian 13"\n',
    ("uname", "-n", "-m", "-r"): "pi 6.12 aarch64\n",
    ("nproc",): "4\n",
    ("cat", "/proc/meminfo"): "MemTotal: 8000000 kB\nMemAvailable: 4000000 kB\n",
    ("cat", "/proc/1/comm"): "systemd\n",
    (
        "dpkg-query",
        "-W",
        "-f",
        "${Package}\t${Version}\t${Architecture}\n",
    ): "openssl\t3.0.1\tarm64\n",
    ("sshd", "-T"): "passwordauthentication no\n",
    ("nft", "list", "ruleset"): "table inet f { chain input { policy drop; } }",
    ("ss", "-Htlnp"): "",
    ("systemctl", "is-enabled", "unattended-upgrades.service"): "enabled\n",
}


class Fake:
    async def run(self, argv, **kw):
        if argv[0] == "trivy":
            return Result(argv, 127, "", "not found")
        out = OUT.get(tuple(argv))
        return Result(argv, 0 if out is not None else 1, out or "", "")


async def test_scan_falls_back_to_osv_and_checks_hardening():
    def osv(request: httpx.Request):
        if request.url.path.endswith("querybatch"):
            body = json.loads(request.content)
            assert body["queries"][0]["package"]["ecosystem"] == "Debian:13"
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "DSA-1"}]}]})
        return httpx.Response(
            200,
            json={
                "id": "DSA-1",
                "aliases": ["CVE-2026-1"],
                "summary": "x",
                "affected": [{"ranges": [{"events": [{"fixed": "3.0.2"}]}]}],
            },
        )

    host = Linux("linux:pi", "10.0.0.9", Fake())  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=httpx.MockTransport(osv)) as client:
        result = await scan_host(host, client)
    assert result.complete
    assert [f.cve for f in result.findings] == ["CVE-2026-1"]
    assert result.findings[0].fixed == "3.0.2"


def test_agent_limits_firewall_and_sshd_to_reading():
    check(["nft", "list", "ruleset"])
    check(["sshd", "-T"])
    import pytest

    for bad in (["nft", "flush", "ruleset"], ["sshd", "-D"]):
        with pytest.raises(PermissionError):
            check(bad)
