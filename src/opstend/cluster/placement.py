"""Place OpsTend roles on the available nodes.

Not every node runs everything. The planner picks voters for the control
state, spreads replicas across sites and zones, reserves resources, keeps
existing assignments where they still fit (to avoid churn) and explains every
decision so the UI can show why a role runs where it does.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from opstend.core.models import Node, NodeState


@dataclass(frozen=True)
class RoleSpec:
    name: str
    replicas: int | str  # a number, "voters" or "per-site"
    cpu: float = 0.1
    memory_mb: int = 128
    needs_label: str | None = None  # e.g. "gpu" or "storage"
    prefer_label: str | None = None
    spread: bool = True  # no two replicas on one node
    description: str = ""


ROLES: tuple[RoleSpec, ...] = (
    RoleSpec("controller", "voters", 0.2, 256, description="Replicated control state (Raft voter)"),
    RoleSpec("web", 2, 0.2, 256, description="Web app and API"),
    RoleSpec(
        "collector",
        "per-site",
        0.2,
        192,
        description="Reads Proxmox, UniFi and Linux inventory of one site",
    ),
    RoleSpec("discovery", "per-site", 0.05, 64, description="Finds new nodes and devices"),
    RoleSpec("scanner", 1, 1.0, 1024, description="Security scans and threat feeds"),
    RoleSpec(
        "backup", 1, 0.5, 512, prefer_label="storage", description="Backup runs and restore tests"
    ),
    RoleSpec(
        "zorec",
        1,
        2.0,
        6144,
        prefer_label="gpu",
        description="Zorec assistant with optional local model",
    ),
)


def voter_count(nodes: int) -> int:
    """Odd voter count: 1, 3 or 5. More voters only slow down commits."""
    if nodes >= 5:
        return 5
    if nodes >= 3:
        return 3
    return 1


@dataclass
class Placement:
    assignments: dict[str, list[str]] = field(default_factory=dict)
    reasons: dict[str, str] = field(default_factory=dict)
    unplaced: dict[str, str] = field(default_factory=dict)
    moves: list[tuple[str, str | None, str]] = field(default_factory=list)

    def roles_on(self, node_id: str) -> list[str]:
        return sorted(r for r, ns in self.assignments.items() if node_id in ns)

    def as_dict(self) -> dict[str, object]:
        return {
            "assignments": self.assignments,
            "reasons": self.reasons,
            "unplaced": self.unplaced,
            "moves": [{"role": r, "from": a, "to": b} for r, a, b in self.moves],
        }


class Planner:
    def __init__(self, roles: tuple[RoleSpec, ...] = ROLES, headroom: float = 0.8) -> None:
        self.roles = roles
        self.headroom = headroom

    def plan(self, nodes: list[Node], current: dict[str, list[str]] | None = None) -> Placement:
        current = current or {}
        eligible = [
            n for n in nodes if NodeState(n.state) in (NodeState.HEALTHY, NodeState.JOINING)
        ]
        eligible.sort(key=lambda n: n.id)
        free_cpu = {
            n.id: n.capacity.cpu_cores * self.headroom
            - (n.usage.cpu_pct or 0) / 100 * n.capacity.cpu_cores
            for n in eligible
        }
        free_mem = {
            n.id: n.capacity.memory_mb * self.headroom - (n.usage.memory_mb or 0) for n in eligible
        }
        by_id = {n.id: n for n in eligible}
        out = Placement()

        def fits(node: Node, role: RoleSpec) -> bool:
            if role.needs_label and role.needs_label not in node.labels:
                return False
            return free_cpu[node.id] >= role.cpu and free_mem[node.id] >= role.memory_mb

        def take(node: Node, role: RoleSpec) -> None:
            free_cpu[node.id] -= role.cpu
            free_mem[node.id] -= role.memory_mb

        def score(node: Node, role: RoleSpec, chosen: list[str]) -> tuple[float, ...]:
            sites = {by_id[c].site for c in chosen}
            zones = {by_id[c].labels.get("zone") for c in chosen}
            return (
                0 if node.id in current.get(role.name, []) else 1,  # stickiness
                1 if node.site in sites else 0,  # spread across sites
                1 if node.labels.get("zone") in zones and node.labels.get("zone") else 0,
                0 if role.prefer_label and role.prefer_label in node.labels else 1,
                -free_mem[node.id],
                -free_cpu[node.id],
            )

        def pick(role: RoleSpec, count: int, pool: list[Node]) -> list[str]:
            chosen: list[str] = []
            for _ in range(count):
                candidates = [
                    n for n in pool if fits(n, role) and (not role.spread or n.id not in chosen)
                ]
                if not candidates:
                    break
                best = min(candidates, key=lambda n: score(n, role, chosen))
                chosen.append(best.id)
                take(best, role)
            return chosen

        # Roles with special needs choose first, then the largest ones.
        ordered = sorted(
            self.roles, key=lambda r: (not (r.needs_label or r.prefer_label), -r.memory_mb)
        )
        for role in ordered:
            if role.replicas == "voters":
                want = voter_count(len(eligible))
                pool = [n for n in eligible if n.labels.get("voter", "yes") != "no"]
                chosen = pick(role, want, pool)
                why = f"{want} voters for {len(eligible)} nodes, spread across sites"
            elif role.replicas == "per-site":
                chosen = []
                for site in sorted({n.site for n in eligible}):
                    chosen += pick(role, 1, [n for n in eligible if n.site == site])
                why = "one per site, close to the systems it reads"
            else:
                want = min(int(role.replicas), len(eligible))
                chosen = pick(role, want, eligible)
                why = (
                    f"{want} replica(s); prefers nodes labeled {role.prefer_label}"
                    if role.prefer_label
                    else f"{want} replica(s) on the least loaded nodes"
                )
            out.assignments[role.name] = chosen
            out.reasons[role.name] = why
            if not chosen:
                out.unplaced[role.name] = "no healthy node has enough free CPU and memory"
            before = set(current.get(role.name, []))
            for gone in sorted(before - set(chosen)):
                out.moves.append((role.name, gone, next(iter(set(chosen) - before), "")))
            for new in sorted(set(chosen) - before):
                if not any(m[0] == role.name and m[2] == new for m in out.moves):
                    out.moves.append((role.name, None, new))
        out.assignments = {r.name: out.assignments[r.name] for r in self.roles}
        return out
