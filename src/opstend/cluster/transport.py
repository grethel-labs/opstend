"""Raft and cluster messages over mutual TLS.

Every node serves `/cluster/*` on its cluster port and accepts only clients
with a certificate from the cluster CA. The node id in the certificate must
match the sender id in the message, so a node cannot speak for another.
"""

from __future__ import annotations

import ssl
from dataclasses import asdict
from pathlib import Path
from typing import Any

import httpx

from opstend.cluster.consensus import (
    AppendRequest,
    AppendResponse,
    Entry,
    SnapshotRequest,
    VoteRequest,
    VoteResponse,
)


def client_context(ca: Path, cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(ca))
    ctx.load_cert_chain(str(cert), str(key))
    ctx.check_hostname = False  # peers are identified by the certificate's node id
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def encode(obj: Any) -> dict[str, Any]:
    return asdict(obj)


def decode_append(data: dict[str, Any]) -> AppendRequest:
    data = dict(data)
    data["entries"] = [Entry(**e) for e in data.get("entries", [])]
    return AppendRequest(**data)


class HttpTransport:
    def __init__(
        self, peers: dict[str, str], ctx: ssl.SSLContext | None, timeout: float = 1.0
    ) -> None:
        self.peers = peers
        self.client = httpx.AsyncClient(verify=ctx if ctx else True, timeout=timeout, cert=None)

    async def _post(self, peer: str, path: str, body: dict[str, Any]) -> dict[str, Any] | None:
        base = self.peers.get(peer)
        if not base:
            return None
        resp = await self.client.post(f"{base}{path}", json=body)
        if resp.status_code != 200:
            return None
        data: dict[str, Any] = resp.json()
        return data

    async def vote(self, peer: str, req: VoteRequest) -> VoteResponse | None:
        data = await self._post(peer, "/cluster/raft/vote", encode(req))
        return VoteResponse(**data) if data else None

    async def append(self, peer: str, req: AppendRequest) -> AppendResponse | None:
        data = await self._post(peer, "/cluster/raft/append", encode(req))
        return AppendResponse(**data) if data else None

    async def snapshot(self, peer: str, req: SnapshotRequest) -> AppendResponse | None:
        data = await self._post(peer, "/cluster/raft/snapshot", encode(req))
        return AppendResponse(**data) if data else None


class LocalTransport:
    """Single-node cluster: no peers to talk to."""

    async def vote(self, peer: str, req: VoteRequest) -> VoteResponse | None:
        return None

    async def append(self, peer: str, req: AppendRequest) -> AppendResponse | None:
        return None

    async def snapshot(self, peer: str, req: SnapshotRequest) -> AppendResponse | None:
        return None
