"""Typed read access to the replicated state, plus derived views.

The API, Zorec and the automation read the fleet through this facade, so all
of them see the same facts and the same derived network insights.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cached_property
from typing import Any, TypeVar

from pydantic import BaseModel

from opstend.adapters.base import Bridge
from opstend.core.models import (
    Client,
    Device,
    Finding,
    FirewallRule,
    Guest,
    Host,
    Network,
    Node,
    Publication,
    Service,
    Tunnel,
    Update,
)
from opstend.core.store import Store
from opstend.network import analysis, graph

T = TypeVar("T", bound=BaseModel)


@dataclass
class Fleet:
    store: Store
    _cache: dict[str, Any] = field(default_factory=dict)

    def _all(self, kind: str, model: type[T]) -> list[T]:
        return [model.model_validate(d) for d in self.store.list(kind)]

    def nodes(self) -> list[Node]:
        return self._all("node", Node)

    def hosts(self) -> list[Host]:
        return self._all("host", Host)

    def guests(self) -> list[Guest]:
        return self._all("guest", Guest)

    def devices(self) -> list[Device]:
        return self._all("device", Device)

    def clients(self) -> list[Client]:
        return self._all("client", Client)

    def networks(self) -> list[Network]:
        return self._all("network", Network)

    def firewall(self) -> list[FirewallRule]:
        return self._all("firewall", FirewallRule)

    def services(self) -> list[Service]:
        return self._all("service", Service)

    def findings(self) -> list[Finding]:
        return self._all("finding", Finding)

    def updates(self) -> list[Update]:
        return self._all("update", Update)

    def tunnels(self) -> list[Tunnel]:
        return self._all("tunnel", Tunnel)

    def publications(self) -> list[Publication]:
        return self._all("publication", Publication)

    def bridges(self) -> list[Bridge]:
        return [Bridge(**d) for d in self.store.list("bridge")]

    def voters(self) -> list[str]:
        return [n.host_id for n in self.nodes() if n.voter and n.host_id]

    @cached_property
    def graph(self) -> graph.NetworkGraph:
        return graph.build(
            devices=self.devices(),
            clients=self.clients(),
            networks=self.networks(),
            firewall=self.firewall(),
            hosts=self.hosts(),
            guests=self.guests(),
            bridges=self.bridges(),
            tunnels=self.tunnels(),
            publications=self.publications(),
        )

    @cached_property
    def insights(self) -> list[analysis.Insight]:
        return analysis.analyze(self.graph, self.devices(), self.voters())

    def find(self, text: str) -> list[tuple[str, str, str]]:
        """Search every object by name, id or address. Returns (kind, id, name)."""
        needle = text.lower().strip()
        if not needle:
            return []
        out: list[tuple[str, str, str]] = []
        for kind, items in (
            ("host", self.hosts()),
            ("guest", self.guests()),
            ("device", self.devices()),
            ("service", self.services()),
        ):
            for item in items:
                hay = " ".join(str(getattr(item, a, "") or "") for a in ("id", "name", "address"))
                if needle in hay.lower():
                    out.append((kind, item.id, item.name))
        for c in self.clients():
            if needle in f"{c.mac} {c.name or ''} {c.ip or ''}".lower():
                out.append(("client", f"client:{c.mac}", c.name or c.mac))
        return out
