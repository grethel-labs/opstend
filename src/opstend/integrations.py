"""Build adapters from the configuration and collect one inventory snapshot."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opstend.adapters.base import Compute, Inventory
from opstend.adapters.linux import Linux
from opstend.adapters.proxmox import Proxmox
from opstend.adapters.runner import Runner, ssh_prefix
from opstend.adapters.unifi import Unifi
from opstend.config import Config, read_secret

log = logging.getLogger("opstend.integrations")


def _pem(path: str | None) -> str | None:
    return Path(path).read_text() if path else None


@dataclass
class Integrations:
    compute: dict[str, Compute] = field(default_factory=dict)  # host id prefix -> adapter
    linux: dict[str, Linux] = field(default_factory=dict)  # host id -> adapter
    unifi: dict[str, Unifi] = field(default_factory=dict)  # site -> adapter
    proxmox: list[Proxmox] = field(default_factory=list)

    @classmethod
    def from_config(cls, config: Config) -> Integrations:
        out = cls()
        for p in config.integrations.proxmox:
            try:
                pve = Proxmox(
                    p.url,
                    p.token_id,
                    read_secret(p.token_secret_file) or "",
                    cluster=p.cluster,
                    cert_pem=_pem(p.cert_file),
                )
            except (OSError, ValueError) as exc:
                log.error("proxmox %s disabled: %s", p.name, exc)
                continue
            out.proxmox.append(pve)
            out.compute[f"pve:{p.cluster}:"] = pve
        for lx in config.integrations.linux:
            host_id = f"linux:{lx.name}"
            if lx.local:
                from opstend.agent import AgentRunner

                runner: Runner = AgentRunner()
            else:
                runner = Runner(
                    ssh=ssh_prefix(lx.address, lx.ssh_user, lx.ssh_key_file, lx.known_hosts)
                )
            adapter = Linux(host_id, lx.address, runner, site=lx.site)
            out.linux[host_id] = adapter
            out.compute[f"{host_id}:"] = adapter
        for u in config.integrations.unifi:
            try:
                out.unifi[u.site] = Unifi(
                    u.url,
                    u.username,
                    read_secret(u.password_file) or "",
                    site=u.unifi_site,
                    unifi_os=u.unifi_os,
                    cert_pem=_pem(u.cert_file),
                )
            except OSError as exc:
                log.error("unifi %s disabled: %s", u.name, exc)
        return out

    async def collect(self) -> dict[str, dict[str, dict[str, Any]]]:
        merged = Inventory()
        for pve in self.proxmox:
            try:
                inv = await pve.inventory()
            except Exception as exc:
                log.warning("proxmox inventory failed: %s", exc)
                continue
            _merge(merged, inv)
        for lx in self.linux.values():
            _merge(merged, await lx.inventory())
        out: dict[str, dict[str, dict[str, Any]]] = {
            "host": {h.id: h.model_dump(mode="json") for h in merged.hosts},
            "guest": {g.id: g.model_dump(mode="json") for g in merged.guests},
            "bridge": {f"{b.host_id}/{b.name}": b.__dict__ for b in merged.bridges},
            "update": {u.id: u.model_dump(mode="json") for u in merged.updates},
        }
        devices: dict[str, Any] = {}
        clients: dict[str, Any] = {}
        networks: dict[str, Any] = {}
        rules: dict[str, Any] = {}
        for site, unifi in self.unifi.items():
            try:
                snap = await unifi.snapshot()
            except Exception as exc:
                log.warning("unifi %s failed: %s", site, exc)
                continue
            for d in snap["devices"]:
                d.site = site
                devices[d.id] = d.model_dump(mode="json")
            clients.update({c.mac: c.model_dump(mode="json") for c in snap["clients"]})
            networks.update({n.id: n.model_dump(mode="json") for n in snap["networks"]})
            rules.update({r.id: r.model_dump(mode="json") for r in snap["firewall"]})
        if self.unifi:
            out.update(
                {"device": devices, "client": clients, "network": networks, "firewall": rules}
            )
        return out


def _merge(into: Inventory, inv: Inventory) -> None:
    into.hosts += inv.hosts
    into.guests += inv.guests
    into.bridges += inv.bridges
    into.updates += inv.updates
    into.errors += inv.errors
