"""Common interface for compute platforms and helpers shared by adapters."""

from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from opstend.core.models import Guest, Host, Network, Update


class GuestAction(StrEnum):
    START = "start"
    STOP = "stop"  # hard stop
    SHUTDOWN = "shutdown"  # graceful
    REBOOT = "reboot"
    SUSPEND = "suspend"
    RESUME = "resume"


class Capability(StrEnum):
    POWER = "power"
    SNAPSHOT = "snapshot"
    BACKUP = "backup"
    CLONE = "clone"
    MIGRATE = "migrate"
    CONSOLE = "console"
    RESIZE = "resize"
    TEMPLATE = "template"


@dataclass
class Bridge:
    host_id: str
    name: str
    ports: list[str] = field(default_factory=list)
    vlan_aware: bool = False
    address: str | None = None
    mac: str | None = None


@dataclass
class Inventory:
    hosts: list[Host] = field(default_factory=list)
    guests: list[Guest] = field(default_factory=list)
    bridges: list[Bridge] = field(default_factory=list)
    networks: list[Network] = field(default_factory=list)
    updates: list[Update] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class Compute(Protocol):
    """What every compute platform offers. Unsupported features raise `Unsupported`."""

    name: str

    async def inventory(self) -> Inventory: ...
    def capabilities(self, guest: Guest) -> set[Capability]: ...
    async def power(self, guest: Guest, action: GuestAction) -> None: ...
    async def snapshot(self, guest: Guest, name: str, description: str = "") -> None: ...
    async def delete_snapshot(self, guest: Guest, name: str) -> None: ...
    async def rollback_snapshot(self, guest: Guest, name: str) -> None: ...
    async def backup(self, guest: Guest, destination: str) -> str: ...
    async def clone(self, template: Guest, name: str, target_host: str | None = None) -> str: ...
    async def migrate(self, guest: Guest, target_host: str, online: bool = True) -> None: ...
    def console_url(self, guest: Guest) -> str | None: ...


class Unsupported(RuntimeError):
    def __init__(self, platform: str, feature: str) -> None:
        super().__init__(f"{platform} does not support {feature} for this guest")


def pinned_context(pem: str | None) -> ssl.SSLContext | bool:
    """TLS context that trusts exactly the certificate the operator confirmed.

    Proxmox and UniFi ship self-signed certificates. During adoption OpsTend
    shows the fingerprint, the operator confirms it, and from then on only
    that certificate (or the CA that issued it) is accepted.
    """
    if not pem:
        return True  # system trust store
    ctx = ssl.create_default_context(cadata=pem)
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    ctx.check_hostname = False  # the pinned certificate is the identity
    return ctx
