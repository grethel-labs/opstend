"""Host side of exposure removal (L07 step 3).

Mixed into `Host`. The block lives in its own nftables table, so a firewall
reload or redeployment of the main `inet steward` table never lifts it, and it
only ever names loopback backend ports taken from the root-owned registry. The
only network path to a backend is the reverse proxy's loopback connection, so
rejecting that connection ends exposure for IPv4 and IPv6 clients alike. SSH,
the administrative host services and the proxy's other routes are untouched.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from ..core.render import PROXY_USER

TABLE = "steward_containment"
MIN_PORT, MAX_PORT = 20000, 29999
_DPORT = re.compile(r"tcp dport (?:\{ ([0-9, ]+) \}|([0-9]+))")


def render_containment(ports: list[int]) -> str:
    """Complete ruleset for `inet steward_containment` (an empty list renders nothing)."""
    if (
        not ports
        or len(ports) != len(set(ports))
        or any(type(p) is not int or not MIN_PORT <= p <= MAX_PORT for p in ports)
    ):
        raise ValueError("invalid containment ports")
    clean = sorted(ports)
    members = "{ " + ", ".join(str(p) for p in clean) + " }"
    return "\n".join(
        [
            "#!/usr/sbin/nft -f",
            "# Managed by steward: application exposure removal. Do not edit.",
            f"table inet {TABLE}",
            f"delete table inet {TABLE}",
            "",
            f"table inet {TABLE} {{",
            "    chain output {",
            "        type filter hook output priority -10; policy accept;",
            f'        meta skuid "{PROXY_USER}" oifname "lo" tcp dport {members} '
            "counter reject with tcp reset",
            "    }",
            "    chain input {",
            "        type filter hook input priority -10; policy accept;",
            f'        iifname != "lo" tcp dport {members} counter drop',
            "    }",
            "}",
            "",
        ]
    )


def parse_ports(text: str) -> set[int]:
    result: set[int] = set()
    for match in _DPORT.finditer(text):
        raw = match.group(1) or match.group(2)
        result.update(int(item) for item in raw.replace(" ", "").split(",") if item)
    return result


class ContainmentHostMixin:
    """Requires `_run` of the host it is mixed into."""

    def containment_apply(self, ports: list[int], path: Path) -> tuple[bool, str]:
        """Write the ruleset beside its final name, load it, and report the result."""
        text = render_containment(ports)
        temporary = path.with_name(path.name + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, text.encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        rc, out = self._run(["nft", "-c", "-f", str(path)])
        if rc != 0:
            return False, out.strip()[:300]
        rc, out = self._run(["nft", "-f", str(path)])
        return rc == 0, out.strip()[:300]

    def containment_clear(self) -> tuple[bool, str]:
        if self.containment_ports() is None:
            return True, ""
        rc, out = self._run(["nft", "delete", "table", "inet", TABLE])
        return rc == 0, out.strip()[:300]

    def containment_ports(self) -> set[int] | None:
        """Ports currently rejected, or None when the table is absent."""
        rc, out = self._run(["nft", "list", "table", "inet", TABLE])
        if rc != 0:
            return None
        return parse_ports(out)
