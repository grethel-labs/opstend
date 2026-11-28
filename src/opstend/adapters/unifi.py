"""UniFi Network through the controller API (UniFi OS consoles and legacy controllers).

Read: devices with port tables, LLDP neighbors, uplinks and PoE, clients,
networks (VLANs), port profiles and firewall rules.
Write (as jobs): restart or locate a device, upgrade firmware, power-cycle a
PoE port, assign a port profile, block or reconnect a client.

Use a dedicated local account with the least role that covers the enabled
features. The certificate is pinned during adoption.
"""

from __future__ import annotations

from typing import Any

import httpx

from opstend.adapters.base import pinned_context
from opstend.core.models import (
    Client,
    Device,
    DeviceKind,
    FirewallRule,
    Health,
    Lldp,
    Network,
    Observed,
    Port,
    RuleAction,
)

KIND = {
    "ugw": DeviceKind.GATEWAY,
    "udm": DeviceKind.GATEWAY,
    "uxg": DeviceKind.GATEWAY,
    "usw": DeviceKind.SWITCH,
    "uap": DeviceKind.ACCESS_POINT,
}


class UnifiError(RuntimeError):
    pass


def _norm_mac(mac: str | None) -> str | None:
    return mac.lower() if mac else None


def map_networks(raw: list[dict[str, Any]]) -> list[Network]:
    out = []
    for n in raw:
        if n.get("purpose") in ("wan", "vpn-client", "site-vpn", "remote-user-vpn"):
            continue
        out.append(
            Network(
                id=n["_id"],
                name=n.get("name", ""),
                vlan=int(n["vlan"])
                if n.get("vlan_enabled") and str(n.get("vlan", "")).isdigit()
                else None,
                subnet=n.get("ip_subnet"),
                gateway=(n.get("ip_subnet") or "").split("/")[0] or None,
                dhcp_start=n.get("dhcpd_start"),
                dhcp_stop=n.get("dhcpd_stop"),
                purpose=n.get("purpose", "corporate"),
                isolated=bool(n.get("network_isolation_enabled")),
                source="unifi",
            )
        )
    return out


def map_devices(
    raw: list[dict[str, Any]], networks: list[Network], profiles: list[dict[str, Any]]
) -> list[Device]:
    vlan_of = {n.id: n.vlan or 1 for n in networks}
    all_vlans = sorted({n.vlan or 1 for n in networks})
    prof = {p["_id"]: p for p in profiles}
    devices = []
    for d in raw:
        overrides = {o["port_idx"]: o for o in d.get("port_overrides", []) if "port_idx" in o}
        lldp = {e.get("local_port_idx"): e for e in d.get("lldp_table", [])}
        ports = []
        for p in d.get("port_table", []):
            idx = p.get("port_idx")
            if idx is None:
                continue
            profile_id = overrides.get(idx, {}).get("portconf_id") or p.get("portconf_id")
            profile = prof.get(profile_id or "", {})
            native = profile.get("native_networkconf_id") or p.get("native_networkconf_id")
            forward = profile.get("forward", "all")
            if forward == "all":
                tagged = [v for v in all_vlans if v != vlan_of.get(native or "", 1)]
            elif forward == "customize":
                tagged = sorted(
                    vlan_of[t] for t in profile.get("tagged_networkconf_ids", []) if t in vlan_of
                )
            else:
                tagged = []
            neighbor = lldp.get(idx)
            ports.append(
                Port(
                    index=idx,
                    name=p.get("name") or f"Port {idx}",
                    up=bool(p.get("up")),
                    speed_mbps=p.get("speed") or None,
                    max_speed_mbps=max(
                        (p.get("speed_caps") and _caps_to_speed(p["speed_caps"])) or 0,
                        p.get("speed") or 0,
                    )
                    or None,
                    full_duplex=bool(p.get("full_duplex", True)),
                    poe_enabled=p.get("poe_mode") == "auto" or bool(p.get("poe_enable")),
                    poe_watts=float(p["poe_power"]) if p.get("poe_power") else None,
                    native_vlan=vlan_of.get(native or "", 1 if native is None else None),
                    tagged_vlans=tagged,
                    profile=profile.get("name"),
                    rx_errors=int(p.get("rx_errors", 0)),
                    tx_errors=int(p.get("tx_errors", 0)),
                    lldp=Lldp(
                        chassis=_norm_mac(neighbor.get("chassis_id")) or "",
                        port=str(neighbor.get("port_id", "")),
                        name=neighbor.get("chassis_name"),
                    )
                    if neighbor
                    else None,
                    is_uplink=bool(p.get("is_uplink")),
                )
            )
        uplink = d.get("uplink") or {}
        devices.append(
            Device(
                id=f"unifi:{d['mac'].lower()}",
                name=d.get("name") or d.get("model", d["mac"]),
                kind=KIND.get(d.get("type", ""), DeviceKind.OTHER),
                mac=d["mac"].lower(),
                model=d.get("model", ""),
                address=d.get("ip"),
                firmware=d.get("version", ""),
                upgrade_to=d.get("upgrade_to_firmware") if d.get("upgradable") else None,
                health=Health.OK if d.get("state") == 1 else Health.CRITICAL,
                ports=ports,
                uplink_mac=_norm_mac(uplink.get("uplink_mac")),
                uplink_port=uplink.get("uplink_remote_port"),
                poe_budget_watts=float(d["total_max_power"]) if d.get("total_max_power") else None,
                observed=Observed(source="unifi-api"),
            )
        )
    return devices


def _caps_to_speed(caps: int) -> int:
    # UniFi encodes supported speeds as a bit field. Highest set bit wins.
    table = [
        (0x8000, 100000),
        (0x4000, 40000),
        (0x2000, 25000),
        (0x1000, 10000),
        (0x400, 5000),
        (0x200, 2500),
        (0x20, 1000),
        (0x8, 100),
        (0x2, 10),
    ]
    for bit, speed in table:
        if caps & bit:
            return speed
    return 0


def map_clients(raw: list[dict[str, Any]], networks: list[Network]) -> list[Client]:
    vlan_of = {n.id: n.vlan for n in networks}
    out = []
    for c in raw:
        wired = bool(c.get("is_wired"))
        out.append(
            Client(
                mac=c["mac"].lower(),
                name=c.get("name") or c.get("hostname"),
                ip=c.get("ip"),
                network_id=c.get("network_id"),
                vlan=vlan_of.get(c.get("network_id") or ""),
                device_mac=_norm_mac(c.get("sw_mac") if wired else c.get("ap_mac")),
                port=c.get("sw_port") if wired else None,
                wired=wired,
                signal_dbm=c.get("signal") if not wired else None,
            )
        )
    return out


def map_firewall(raw: list[dict[str, Any]], networks: list[Network]) -> list[FirewallRule]:
    names = {n.id: f"net:{n.name}" for n in networks}
    out = []
    for r in raw:
        src = names.get(r.get("src_networkconf_id") or "") or r.get("src_address") or "any"
        dst = names.get(r.get("dst_networkconf_id") or "") or r.get("dst_address") or "any"
        out.append(
            FirewallRule(
                id=r["_id"],
                name=r.get("name", ""),
                action=RuleAction.ALLOW if r.get("action") == "accept" else RuleAction.DROP,
                src=src,
                dst=dst,
                protocol=r.get("protocol", "all").replace("all", "any"),
                ports=r.get("dst_port") or None,
                enabled=bool(r.get("enabled", True)),
                order=int(r.get("rule_index", 1000)),
                source="unifi",
            )
        )
    return sorted(out, key=lambda r: r.order)


class Unifi:
    name = "unifi"

    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        *,
        site: str = "default",
        unifi_os: bool = True,
        cert_pem: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.url = url.rstrip("/")
        self.site = site
        self.unifi_os = unifi_os
        self._creds = {"username": username, "password": password, "remember": False}
        self._csrf: str | None = None
        self._client = httpx.AsyncClient(
            base_url=self.url, verify=pinned_context(cert_pem), transport=transport, timeout=20.0
        )

    @property
    def _api(self) -> str:
        prefix = "/proxy/network" if self.unifi_os else ""
        return f"{prefix}/api/s/{self.site}"

    async def login(self) -> None:
        path = "/api/auth/login" if self.unifi_os else "/api/login"
        resp = await self._client.post(path, json=self._creds)
        if resp.status_code != 200:
            raise UnifiError(f"login failed with {resp.status_code}")
        self._csrf = resp.headers.get("x-csrf-token")

    async def close(self) -> None:
        await self._client.aclose()

    async def _call(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        headers = {"x-csrf-token": self._csrf} if self._csrf and method != "GET" else {}
        for attempt in range(2):
            resp = await self._client.request(
                method, f"{self._api}{path}", json=body, headers=headers
            )
            if resp.status_code == 401 and attempt == 0:
                await self.login()
                headers = {"x-csrf-token": self._csrf} if self._csrf and method != "GET" else {}
                continue
            break
        if resp.status_code >= 400:
            raise UnifiError(f"{method} {path}: {resp.status_code}")
        if resp.headers.get("x-csrf-token"):
            self._csrf = resp.headers["x-csrf-token"]
        data = resp.json()
        meta = data.get("meta", {})
        if meta.get("rc") not in (None, "ok"):
            raise UnifiError(f"{method} {path}: {meta.get('msg', 'error')}")
        return data.get("data", [])

    async def snapshot(self) -> dict[str, Any]:
        networks = map_networks(await self._call("GET", "/rest/networkconf"))
        profiles = await self._call("GET", "/rest/portconf")
        devices = map_devices(await self._call("GET", "/stat/device"), networks, profiles)
        clients = map_clients(await self._call("GET", "/stat/sta"), networks)
        rules = map_firewall(await self._call("GET", "/rest/firewallrule"), networks)
        return {
            "networks": networks,
            "devices": devices,
            "clients": clients,
            "firewall": rules,
            "profiles": [{"id": p["_id"], "name": p.get("name", "")} for p in profiles],
        }

    # -- actions ---------------------------------------------------------

    async def restart_device(self, mac: str) -> None:
        await self._call("POST", "/cmd/devmgr", {"cmd": "restart", "mac": mac.lower()})

    async def locate_device(self, mac: str, on: bool = True) -> None:
        await self._call(
            "POST",
            "/cmd/devmgr",
            {"cmd": "set-locate" if on else "unset-locate", "mac": mac.lower()},
        )

    async def upgrade_device(self, mac: str) -> None:
        await self._call("POST", "/cmd/devmgr", {"cmd": "upgrade", "mac": mac.lower()})

    async def power_cycle_port(self, mac: str, port: int) -> None:
        await self._call(
            "POST", "/cmd/devmgr", {"cmd": "power-cycle", "mac": mac.lower(), "port_idx": port}
        )

    async def set_port_profile(
        self, device_id: str, port: int, profile_id: str, current_overrides: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Return the previous overrides so the job can roll back."""
        new = [o for o in current_overrides if o.get("port_idx") != port]
        new.append({"port_idx": port, "portconf_id": profile_id})
        await self._call("PUT", f"/rest/device/{device_id}", {"port_overrides": new})
        return current_overrides

    async def raw_device(self, mac: str) -> dict[str, Any]:
        found = await self._call("GET", f"/stat/device/{mac.lower()}")
        if not found:
            raise UnifiError(f"device {mac} not found")
        return found[0]

    async def block_client(self, mac: str, block: bool = True) -> None:
        await self._call(
            "POST",
            "/cmd/stamgr",
            {"cmd": "block-sta" if block else "unblock-sta", "mac": mac.lower()},
        )

    async def reconnect_client(self, mac: str) -> None:
        await self._call("POST", "/cmd/stamgr", {"cmd": "kick-sta", "mac": mac.lower()})
