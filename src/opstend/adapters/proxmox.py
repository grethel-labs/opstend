"""Proxmox VE through its native REST API.

Authentication uses an API token with the least privileges the enabled
features need. Proxmox stays the authority for its resources; every action is
a native task that OpsTend follows until it finishes and then reads back.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import quote

import httpx

from opstend.adapters.base import (
    Bridge,
    Capability,
    GuestAction,
    Inventory,
    Unsupported,
    pinned_context,
)
from opstend.core.models import (
    Guest,
    GuestKind,
    GuestState,
    Health,
    Host,
    Nic,
    Observed,
    Platform,
    Resources,
    Snapshot,
    Update,
    Usage,
)

MB = 1024 * 1024
GB = 1024 * MB


class ProxmoxError(RuntimeError):
    pass


def parse_net(value: str) -> dict[str, str]:
    """Parse `virtio=AA:BB:..,bridge=vmbr0,tag=20,firewall=1` into a dict."""
    out: dict[str, str] = {}
    for part in value.split(","):
        key, _, val = part.partition("=")
        out[key.strip()] = val.strip()
    for model in ("virtio", "e1000", "e1000e", "rtl8139", "vmxnet3"):
        if model in out:
            out["hwaddr"] = out[model]
    return out


def guest_id(cluster: str, vmid: int | str) -> str:
    return f"pve:{cluster}:{vmid}"


class Proxmox:
    name = "proxmox"

    def __init__(
        self,
        url: str,
        token_id: str,
        token_secret: str,
        *,
        cluster: str = "pve",
        cert_pem: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        task_poll: float = 1.0,
        task_timeout: float = 900.0,
    ) -> None:
        if not re.fullmatch(r"[\w.\-]+@[\w.\-]+![\w.\-]+", token_id):
            raise ValueError("token id must look like user@realm!name")
        self.url = url.rstrip("/")
        self.cluster = cluster
        self.task_poll = task_poll
        self.task_timeout = task_timeout
        self._client = httpx.AsyncClient(
            base_url=f"{self.url}/api2/json",
            headers={"Authorization": f"PVEAPIToken={token_id}={token_secret}"},
            verify=pinned_context(cert_pem),
            transport=transport,
            timeout=20.0,
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def _req(self, method: str, path: str, **kw: Any) -> Any:
        resp = await self._client.request(method, path, **kw)
        if resp.status_code >= 400:
            reason = (
                resp.json().get("errors")
                if resp.headers.get("content-type", "").startswith("application/json")
                else resp.text[:200]
            )
            raise ProxmoxError(
                f"{method} {path}: {resp.status_code} {reason or resp.reason_phrase}"
            )
        return resp.json().get("data")

    async def get(self, path: str, **params: Any) -> Any:
        return await self._req("GET", path, params=params or None)

    async def post(self, path: str, **data: Any) -> Any:
        return await self._req("POST", path, data=data)

    async def delete(self, path: str) -> Any:
        return await self._req("DELETE", path)

    async def wait_task(self, node: str, upid: str) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.task_timeout
        while True:
            status = await self.get(f"/nodes/{node}/tasks/{quote(upid, safe='')}/status")
            if status.get("status") == "stopped":
                exit_status = status.get("exitstatus", "")
                if exit_status == "OK" or exit_status.startswith("WARNINGS"):
                    return
                raise ProxmoxError(f"task {upid} failed: {exit_status}")
            if loop.time() > deadline:
                raise ProxmoxError(f"task {upid} did not finish in time")
            await asyncio.sleep(self.task_poll)

    # -- inventory -------------------------------------------------------

    async def inventory(self) -> Inventory:
        inv = Inventory()
        resources = await self.get("/cluster/resources")
        nodes = [r for r in resources if r.get("type") == "node"]
        storages = [r for r in resources if r.get("type") == "storage"]
        for n in nodes:
            node = n["node"]
            disk_total = sum(
                s.get("maxdisk", 0)
                for s in storages
                if s.get("node") == node and s.get("shared", 0) == 0
            )
            disk_used = sum(
                s.get("disk", 0)
                for s in storages
                if s.get("node") == node and s.get("shared", 0) == 0
            )
            online = n.get("status") == "online"
            inv.hosts.append(
                Host(
                    id=f"pve:{self.cluster}:node:{node}",
                    name=node,
                    platform=Platform.PROXMOX,
                    address=self.url,
                    cluster=self.cluster,
                    health=Health.OK if online else Health.CRITICAL,
                    capacity=Resources(
                        cpu_cores=n.get("maxcpu", 0),
                        memory_mb=n.get("maxmem", 0) // MB,
                        disk_gb=disk_total // GB,
                    ),
                    usage=Usage(
                        cpu_pct=round(n.get("cpu", 0) * 100, 1),
                        memory_mb=n.get("mem", 0) // MB,
                        disk_gb=disk_used // GB,
                    ),
                    observed=Observed(source="proxmox-api"),
                )
            )
            if not online:
                inv.errors.append(f"node {node} is offline")
                continue
            try:
                for net in await self.get(f"/nodes/{node}/network"):
                    if net.get("type") in ("bridge", "OVSBridge"):
                        inv.bridges.append(
                            Bridge(
                                host_id=f"pve:{self.cluster}:node:{node}",
                                name=net["iface"],
                                ports=(net.get("bridge_ports") or "").split(),
                                vlan_aware=bool(net.get("bridge_vlan_aware")),
                                address=net.get("cidr") or net.get("address"),
                            )
                        )
                for upd in await self.get(f"/nodes/{node}/apt/update"):
                    inv.updates.append(
                        Update(
                            id=f"pve:{self.cluster}:node:{node}:{upd['Package']}",
                            target=f"pve:{self.cluster}:node:{node}",
                            kind="package",
                            current=upd.get("OldVersion", ""),
                            available=upd.get("Version", ""),
                            security="security"
                            in (upd.get("Origin", "") + upd.get("Section", "")).lower()
                            or "-security" in upd.get("Origin", ""),
                            notes=upd.get("Title", ""),
                        )
                    )
            except ProxmoxError as exc:
                inv.errors.append(str(exc))
        for r in resources:
            if r.get("type") not in ("qemu", "lxc"):
                continue
            try:
                inv.guests.append(await self._guest(r))
            except ProxmoxError as exc:
                inv.errors.append(str(exc))
        return inv

    async def _guest(self, r: dict[str, Any]) -> Guest:
        kind = GuestKind.VM if r["type"] == "qemu" else GuestKind.LXC
        node, vmid = r["node"], r["vmid"]
        config = await self.get(f"/nodes/{node}/{r['type']}/{vmid}/config")
        nics = []
        for key, value in sorted(config.items()):
            if not re.fullmatch(r"net\d+", key):
                continue
            parsed = parse_net(value)
            ip = parsed.get("ip")
            nics.append(
                Nic(
                    name=parsed.get("name", key),
                    mac=parsed.get("hwaddr"),
                    bridge=parsed.get("bridge"),
                    vlan=int(parsed["tag"]) if parsed.get("tag", "").isdigit() else None,
                    ips=[ip] if ip and ip not in ("dhcp", "manual") else [],
                    firewall=parsed.get("firewall") == "1",
                )
            )
        snaps: list[Snapshot] = []
        try:
            for s in await self.get(f"/nodes/{node}/{r['type']}/{vmid}/snapshot"):
                if s.get("name") != "current":
                    snaps.append(Snapshot(name=s["name"], description=s.get("description", "")))
        except ProxmoxError:
            pass
        status = r.get("status", "unknown")
        state = {
            "running": GuestState.RUNNING,
            "stopped": GuestState.STOPPED,
            "paused": GuestState.PAUSED,
        }.get(status, GuestState.UNKNOWN)
        return Guest(
            id=guest_id(self.cluster, vmid),
            host_id=f"pve:{self.cluster}:node:{node}",
            kind=kind,
            native_id=str(vmid),
            name=r.get("name") or f"{kind}-{vmid}",
            state=state,
            capacity=Resources(
                cpu_cores=r.get("maxcpu", 0),
                memory_mb=r.get("maxmem", 0) // MB,
                disk_gb=r.get("maxdisk", 0) // GB,
            ),
            usage=Usage(cpu_pct=round(r.get("cpu", 0) * 100, 1), memory_mb=r.get("mem", 0) // MB),
            nics=nics,
            snapshots=snaps,
            template=bool(r.get("template")),
            tags=[t for t in (r.get("tags") or "").split(";") if t],
            uptime_s=r.get("uptime"),
            observed=Observed(source="proxmox-api"),
        )

    # -- actions ---------------------------------------------------------

    def _path(self, guest: Guest) -> tuple[str, str]:
        node = guest.host_id.rsplit(":", 1)[-1]
        kind = "qemu" if guest.kind == GuestKind.VM else "lxc"
        return node, f"/nodes/{node}/{kind}/{guest.native_id}"

    def capabilities(self, guest: Guest) -> set[Capability]:
        caps = {
            Capability.POWER,
            Capability.SNAPSHOT,
            Capability.BACKUP,
            Capability.CLONE,
            Capability.MIGRATE,
            Capability.CONSOLE,
            Capability.RESIZE,
            Capability.TEMPLATE,
        }
        return caps

    async def power(self, guest: Guest, action: GuestAction) -> None:
        if guest.kind == GuestKind.LXC and action in (GuestAction.SUSPEND, GuestAction.RESUME):
            raise Unsupported("Proxmox LXC", action)
        node, path = self._path(guest)
        upid = await self.post(f"{path}/status/{action}")
        await self.wait_task(node, upid)

    async def state(self, guest: Guest) -> GuestState:
        _, path = self._path(guest)
        cur = await self.get(f"{path}/status/current")
        return (
            GuestState(cur.get("status", "unknown"))
            if cur.get("status") in ("running", "stopped", "paused")
            else GuestState.UNKNOWN
        )

    async def snapshot(self, guest: Guest, name: str, description: str = "") -> None:
        node, path = self._path(guest)
        upid = await self.post(f"{path}/snapshot", snapname=name, description=description)
        await self.wait_task(node, upid)

    async def delete_snapshot(self, guest: Guest, name: str) -> None:
        node, path = self._path(guest)
        await self.wait_task(node, await self.delete(f"{path}/snapshot/{quote(name)}"))

    async def rollback_snapshot(self, guest: Guest, name: str) -> None:
        node, path = self._path(guest)
        await self.wait_task(node, await self.post(f"{path}/snapshot/{quote(name)}/rollback"))

    async def backup(self, guest: Guest, destination: str) -> str:
        node, _ = self._path(guest)
        upid = await self.post(
            f"/nodes/{node}/vzdump",
            vmid=guest.native_id,
            storage=destination,
            mode="snapshot",
            compress="zstd",
        )
        await self.wait_task(node, upid)
        return upid

    async def clone(self, template: Guest, name: str, target_host: str | None = None) -> str:
        node, path = self._path(template)
        newid = str(await self.get("/cluster/nextid"))
        params: dict[str, Any] = {"newid": newid, "full": 1}
        params["hostname" if template.kind == GuestKind.LXC else "name"] = name
        if target_host:
            params["target"] = target_host
        await self.wait_task(node, await self.post(f"{path}/clone", **params))
        return newid

    async def migrate(self, guest: Guest, target_host: str, online: bool = True) -> None:
        node, path = self._path(guest)
        params: dict[str, Any] = {"target": target_host}
        if guest.kind == GuestKind.VM:
            params["online"] = int(online)
        else:
            params["restart"] = 1
        await self.wait_task(node, await self.post(f"{path}/migrate", **params))

    def console_url(self, guest: Guest) -> str | None:
        node, _ = self._path(guest)
        console = "kvm" if guest.kind == GuestKind.VM else "lxc"
        return f"{self.url}/?console={console}&novnc=1&vmid={guest.native_id}&node={quote(node)}"

    async def refresh_updates(self, node: str) -> None:
        await self.wait_task(node, await self.post(f"/nodes/{node}/apt/update"))
