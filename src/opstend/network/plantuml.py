"""Turn the network graph into PlantUML for excaliplant.

The browser renders the source with excaliplant (`aspectRatio` fits the map
to its panel, `toSvg({interactive: true})` plus `@hook` makes every element
clickable). Each element gets a stable hook id so the UI can open its detail
panel; `@tooltip` carries a one-line summary.
"""

from __future__ import annotations

import re
from collections import defaultdict

from opstend import i18n
from opstend.network.analysis import Insight
from opstend.network.graph import NetworkGraph

LAYERS = ("physical", "network", "access")

SHAPE = {
    "internet": "cloud",
    "gateway": "node",
    "switch": "node",
    "ap": "node",
    "host": "node",
    "guest": "rectangle",
    "client": "card",
    "service": "component",
    "bridge": "rectangle",
    "device": "node",
}

FILL = {
    "ok": "#E6F4EF",
    "warning": "#FFF4DA",
    "critical": "#FDE7E7",
    "maintenance": "#E7EEFB",
    "unknown": "#F1F3F2",
}
FILL_DARK = {
    "ok": "#143A33",
    "warning": "#4A3812",
    "critical": "#4D1E1C",
    "maintenance": "#1C2E4D",
    "unknown": "#223230",
}


def hook_id(vid: str) -> str:
    """PlantUML aliases and excaliplant hook ids allow [A-Za-z_][A-Za-z0-9_-]{0,63}."""
    clean = re.sub(r"[^A-Za-z0-9_-]", "_", vid)
    if not re.match(r"[A-Za-z_]", clean):
        clean = f"n_{clean}"
    if len(clean) > 64:
        import hashlib

        clean = (
            clean[:50] + "_" + hashlib.sha1(vid.encode(), usedforsecurity=False).hexdigest()[:13]
        )
    return clean


def _q(text: str) -> str:
    return text.replace('"', "'").replace("\n", "\\n")


def _speed(mbps: int | None) -> str:
    if not mbps:
        return ""
    return f"{mbps // 1000}G" if mbps >= 1000 else f"{mbps}M"


def render(
    g: NetworkGraph,
    layers: set[str] | None = None,
    insights: list[Insight] | None = None,
    focus: str | None = None,
    show_clients: bool = False,
    dark: bool = False,
) -> str:
    palette = FILL_DARK if dark else FILL
    lang = i18n.current.get()
    layers = layers or {"physical"}
    flagged: dict[str, str] = {}
    for ins in insights or []:
        for obj in ins.objects:
            if ins.severity in ("high", "critical"):
                flagged[obj] = "critical"
            else:
                flagged.setdefault(obj, "warning")

    visible = {
        vid
        for vid, v in g.vertices.items()
        if v.kind in ("internet", "gateway", "switch", "ap", "host", "device")
        or (v.kind == "guest" and "network" in layers)
        or (v.kind == "service" and "access" in layers)
        or (v.kind == "client" and show_clients)
    }
    lines = ["@startuml"]
    for vid in sorted(visible):
        v = g.vertices[vid]
        hid = hook_id(vid)
        lines.append(f"@hook #{hid} alias:{hid} .{v.kind} click-mode:toggle")
        tip = {
            "switch": v.data.get("model"),
            "gateway": v.data.get("model"),
            "ap": v.data.get("model"),
            "host": v.data.get("platform"),
            "guest": v.data.get("kind"),
            "client": v.data.get("ip"),
            "service": "public" if v.data.get("public") else "internal",
        }.get(v.kind)
        if tip:
            lines.append(f'@tooltip alias:{hid} "{_q(str(v.name))} · {_q(str(tip))}"')
    lines.append("@hook .host hover BackgroundColor #D6EFE7")
    lines.append("@hook .guest hover BackgroundColor #DCE8FB")
    if focus and focus in visible:
        lines.append(f"@hook #{hook_id(focus)} click BorderColor #0F766E")
    # Hook and tooltip directives must precede the first diagram line. Top-to-bottom
    # layout reflows well toward wide panels (sites side by side, hosts in a row).

    # Group hosts with their guests; group everything by site.
    by_site: dict[str, list[str]] = defaultdict(list)
    guests_of: dict[str, list[str]] = defaultdict(list)
    for vid in sorted(visible):
        v = g.vertices[vid]
        if v.kind == "guest" and v.data.get("host") in visible:
            guests_of[v.data["host"]].append(vid)
        elif v.kind not in ("internet",):
            by_site[v.site].append(vid)

    def element(vid: str, indent: str) -> list[str]:
        v = g.vertices[vid]
        hid = hook_id(vid)
        state = flagged.get(vid) or str(v.data.get("health") or "ok")
        if v.kind == "guest":
            state = flagged.get(vid) or ("ok" if v.data.get("state") == "running" else "unknown")
        fill = palette.get(state, palette["unknown"])
        subtitle = {
            "switch": "Switch",
            "gateway": "Gateway",
            "ap": "Access Point",
            "host": str(v.data.get("platform", "")).capitalize(),
            "guest": str(v.data.get("kind", "")).upper(),
            "client": "Client",
            "service": "HTTPS",
        }.get(v.kind, "")
        if v.kind == "host" and "network" not in layers:
            count = sum(
                1 for x in g.vertices.values() if x.kind == "guest" and x.data.get("host") == vid
            )
            if count:
                subtitle += f" · {count} {'Gäste' if lang == 'de' else 'guests'}"
        label = _q(f"{v.name}\n{subtitle}" if subtitle else v.name)
        shape = SHAPE.get(v.kind, "rectangle")
        if v.kind == "host" and guests_of.get(vid):
            out = [f'{indent}{shape} "{label}" as {hid} {fill} {{']
            for gid in guests_of[vid]:
                out += element(gid, indent + "  ")
            out.append(f"{indent}}}")
            return out
        return [f'{indent}{shape} "{label}" as {hid} {fill}']

    if "internet" in visible:
        lines.append('cloud "Internet" as internet')
    for site in sorted(by_site):
        lines.append(f'package "{_q(site)}" as {hook_id("site_" + site)} {{')
        for vid in by_site[site]:
            lines += element(vid, "  ")
        lines.append("}")

    for e in g.edges:
        if e.a not in visible or e.b not in visible:
            continue
        a, b = hook_id(e.a), hook_id(e.b)
        if e.kind in ("cable", "uplink"):
            if "physical" not in layers and "network" not in layers:
                continue
            parts = [f"P{e.a_port}" if e.a_port else "", _speed(e.speed_mbps)]
            if "network" in layers and (e.vlans or e.native_vlan):
                vl = ",".join(str(x) for x in e.vlans[:6])
                parts.append(f"VLAN {e.native_vlan or 1}" + (f"+{vl}" if vl else ""))
            label = " · ".join(p for p in parts if p) or e.label
            style = "-[#C2410C,dashed]-" if (e.speed_mbps or 1000) <= 100 else "--"
            lines.append(f"{a} {style} {b}" + (f' : "{_q(label)}"' if label else ""))
        elif e.kind == "wifi" and show_clients:
            lines.append(f'{a} .. {b} : "{_q(e.label)}"')
        elif e.kind == "vnic" and "network" in layers:
            continue  # guests sit inside their host
        elif e.kind == "vpn" and "access" in layers:
            lines.append(f'{a} -[#7C3AED,dashed]- {b} : "{_q(e.label)}"')
        elif e.kind == "publish" and "access" in layers:
            lines.append(f'{a} -[#0F766E]-> {b} : "{_q(e.label)}"')
    for ins in insights or []:
        if ins.code == "vlan-not-carried" and "network" in layers and len(ins.objects) >= 3:
            guest, _host, switch = ins.objects[:3]
            if guest in visible and switch in visible:
                lines.append(
                    f"{hook_id(switch)} -[#B91C1C,dotted]- {hook_id(guest)} : "
                    f'"{_q(ins.fix["summary"] if ins.fix else ins.title)}"'
                )
    lines.append("@enduml")
    return "\n".join(lines)
