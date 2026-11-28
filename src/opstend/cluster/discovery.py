"""Find new OpsTend nodes, Proxmox hosts, UniFi consoles and Linux servers.

Two mechanisms run side by side:

* Beacons: unjoined OpsTend agents broadcast a small UDP announcement with
  their key fingerprint. Members listen and list them as pending nodes.
* Probes: the discovery role scans private subnets for well-known service
  signatures (Proxmox API, UniFi Network, SSH). Only private ranges are
  scanned, with a host limit, a concurrency limit and short timeouts.

Discovery never changes anything. It produces candidates that an operator
adopts (or that a policy adopts automatically for already trusted subnets).
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import socket
import ssl
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

BEACON_PORT = 47470
AGENT_PORT = 47471
MAX_HOSTS = 1024


@dataclass
class Candidate:
    address: str
    kind: str  # opstend-node | proxmox | unifi | linux
    name: str | None = None
    detail: dict[str, str] = field(default_factory=dict)
    confidence: float = 0.5
    seen_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.address}"


def beacon_payload(
    node_id: str,
    name: str,
    key_fp: str,
    version: str,
    arch: str,
    addresses: list[str],
    member_of: str | None,
) -> bytes:
    return json.dumps(
        {
            "v": 1,
            "kind": "opstend-node",
            "id": node_id,
            "name": name,
            "key": key_fp,
            "version": version,
            "arch": arch,
            "addresses": addresses,
            "cluster": member_of,
        },
        separators=(",", ":"),
    ).encode()


def parse_beacon(data: bytes, sender: str) -> Candidate | None:
    if len(data) > 2048:
        return None
    try:
        msg = json.loads(data)
    except ValueError:
        return None
    if not isinstance(msg, dict) or msg.get("v") != 1 or msg.get("kind") != "opstend-node":
        return None
    if msg.get("cluster"):
        return None  # already a member of some cluster
    key = str(msg.get("key", ""))
    if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
        return None
    return Candidate(
        address=sender,
        kind="opstend-node",
        name=str(msg.get("name", ""))[:64] or None,
        detail={
            "id": str(msg.get("id", ""))[:64],
            "key": key,
            "version": str(msg.get("version", ""))[:32],
            "arch": str(msg.get("arch", ""))[:16],
        },
        confidence=1.0,
    )


class BeaconListener(asyncio.DatagramProtocol):
    def __init__(self, on_candidate: Callable[[Candidate], None]) -> None:
        self.on_candidate = on_candidate

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        cand = parse_beacon(data, addr[0])
        if cand:
            self.on_candidate(cand)


async def listen_beacons(on_candidate: Callable[[Candidate], None]) -> asyncio.DatagramTransport:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: BeaconListener(on_candidate),
        local_addr=("0.0.0.0", BEACON_PORT),  # noqa: S104
        allow_broadcast=True,
    )
    return transport


def send_beacon(payload: bytes) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(payload, ("255.255.255.255", BEACON_PORT))


def scan_targets(cidrs: Iterable[str], limit: int = MAX_HOSTS) -> list[str]:
    """Hosts of private subnets only. Public ranges are refused."""
    hosts: list[str] = []
    for cidr in cidrs:
        net = ipaddress.ip_network(cidr, strict=False)
        if not net.is_private or net.is_loopback or net.is_link_local:
            raise ValueError(
                f"{cidr} is not a private network; discovery only scans private ranges"
            )
        if net.num_addresses > limit * 4:
            raise ValueError(f"{cidr} is too large; split it into smaller ranges")
        for host in net.hosts():
            hosts.append(str(host))
            if len(hosts) >= limit:
                return hosts
    return hosts


def _insecure_tls() -> ssl.SSLContext:
    # Probes only read public banners of devices with self-signed certificates.
    # No credentials are sent and nothing is trusted on this basis.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _http_get(
    host: str, port: int, path: str, timeout: float
) -> tuple[int, dict[str, str], bytes] | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=_insecure_tls()), timeout
        )
    except (OSError, TimeoutError, ssl.SSLError):
        return None
    try:
        writer.write(
            f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: opstend-discovery\r\n\r\n".encode()
        )
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(65536), timeout)
    except (OSError, TimeoutError):
        return None
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        return None
    headers = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    return status, headers, body


async def _ssh_banner(host: str, timeout: float) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, 22), timeout)
    except (OSError, TimeoutError):
        return None
    try:
        line = await asyncio.wait_for(reader.readline(), timeout)
        return line.decode("latin-1").strip()[:120] or None
    except (OSError, TimeoutError):
        return None
    finally:
        writer.close()


def classify_proxmox(resp: tuple[int, dict[str, str], bytes] | None) -> dict[str, str] | None:
    if resp is None:
        return None
    _, headers, _ = resp
    if headers.get("server", "").startswith("pve-api-daemon"):
        return {"server": headers["server"]}
    return None


def classify_unifi(resp: tuple[int, dict[str, str], bytes] | None) -> dict[str, str] | None:
    if resp is None:
        return None
    status, _, body = resp
    if status != 200:
        return None
    try:
        data = json.loads(body)
    except ValueError:
        return None
    meta = data.get("meta", {}) if isinstance(data, dict) else {}
    if meta.get("up") is True and "server_version" in meta:
        return {"version": str(meta["server_version"])}
    return None


class Prober:
    def __init__(self, concurrency: int = 64, timeout: float = 1.5) -> None:
        self.sem = asyncio.Semaphore(concurrency)
        self.timeout = timeout

    async def probe(self, host: str) -> list[Candidate]:
        async with self.sem:
            found: list[Candidate] = []
            pve = classify_proxmox(await _http_get(host, 8006, "/api2/json/version", self.timeout))
            if pve:
                found.append(Candidate(host, "proxmox", detail=pve, confidence=0.95))
            for port, path in ((443, "/proxy/network/status"), (8443, "/status")):
                unifi = classify_unifi(await _http_get(host, port, path, self.timeout))
                if unifi:
                    found.append(
                        Candidate(
                            host, "unifi", detail={**unifi, "port": str(port)}, confidence=0.9
                        )
                    )
                    break
            if not pve:
                banner = await _ssh_banner(host, self.timeout)
                if banner and banner.startswith("SSH-"):
                    found.append(Candidate(host, "linux", detail={"ssh": banner}, confidence=0.4))
            return found

    async def scan(self, cidrs: Iterable[str]) -> list[Candidate]:
        hosts = scan_targets(cidrs)
        results = await asyncio.gather(*(self.probe(h) for h in hosts))
        return [c for group in results for c in group]


def merge(
    existing: dict[str, dict[str, object]], found: Iterable[Candidate], known_addresses: set[str]
) -> dict[str, dict[str, object]]:
    """Keep the candidate list current and drop systems that are already managed."""
    out = dict(existing)
    for cand in found:
        if cand.address in known_addresses:
            continue
        out[cand.key] = asdict(cand)
    return out
