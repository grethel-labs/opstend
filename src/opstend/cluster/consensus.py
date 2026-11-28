"""Raft consensus for the OpsTend control state.

Voters elect one leader. The leader appends commands to a replicated log and
applies a command once a majority has stored it. If the leader fails, the
remaining majority elects a new one within a few seconds and continues from
the committed log. With one voter the cluster still works, without failover.

The implementation follows the Raft paper (leader election, log replication,
commitment of current-term entries, snapshots for lagging followers). Time is
injected, so tests drive elections and partitions deterministically.
"""

from __future__ import annotations

import asyncio
import json
import random
import sqlite3
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol


class Role(StrEnum):
    FOLLOWER = "follower"
    CANDIDATE = "candidate"
    LEADER = "leader"


@dataclass
class Entry:
    term: int
    command: dict[str, Any]


@dataclass
class VoteRequest:
    term: int
    candidate: str
    last_index: int
    last_term: int


@dataclass
class VoteResponse:
    term: int
    granted: bool


@dataclass
class AppendRequest:
    term: int
    leader: str
    prev_index: int
    prev_term: int
    entries: list[Entry]
    commit: int


@dataclass
class AppendResponse:
    term: int
    success: bool
    match_index: int = 0


@dataclass
class SnapshotRequest:
    term: int
    leader: str
    index: int
    last_term: int
    voters: list[str]
    data: dict[str, Any]


class Transport(Protocol):
    async def vote(self, peer: str, req: VoteRequest) -> VoteResponse | None: ...
    async def append(self, peer: str, req: AppendRequest) -> AppendResponse | None: ...
    async def snapshot(self, peer: str, req: SnapshotRequest) -> AppendResponse | None: ...


class StateMachine(Protocol):
    def apply(self, command: dict[str, Any]) -> Any: ...
    def dump(self) -> dict[str, Any]: ...
    def restore(self, data: dict[str, Any]) -> None: ...


class NotLeader(RuntimeError):
    def __init__(self, leader: str | None) -> None:
        super().__init__(f"not the leader; leader is {leader or 'unknown'}")
        self.leader = leader


class RaftStorage:
    """Durable term, vote and log. Lost state would allow double votes."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS log (idx INTEGER PRIMARY KEY, term INTEGER, cmd TEXT)"
        )

    def load(self) -> tuple[int, str | None, list[tuple[int, Entry]], dict[str, Any]]:
        with self._lock:
            kv = dict(self._db.execute("SELECT k, v FROM kv").fetchall())
            rows = self._db.execute("SELECT idx, term, cmd FROM log ORDER BY idx").fetchall()
        entries = [(i, Entry(t, json.loads(c))) for i, t, c in rows]
        snap = json.loads(kv.get("snapshot", "null")) or {}
        return int(kv.get("term", 0)), kv.get("vote") or None, entries, snap

    def save_state(self, term: int, vote: str | None) -> None:
        with self._lock:
            self._db.execute("BEGIN")
            self._db.execute("INSERT OR REPLACE INTO kv VALUES('term', ?)", (str(term),))
            self._db.execute("INSERT OR REPLACE INTO kv VALUES('vote', ?)", (vote or "",))
            self._db.execute("COMMIT")

    def append(self, start: int, entries: list[Entry]) -> None:
        with self._lock:
            self._db.execute("BEGIN")
            self._db.execute("DELETE FROM log WHERE idx >= ?", (start,))
            self._db.executemany(
                "INSERT INTO log VALUES(?,?,?)",
                [(start + n, e.term, json.dumps(e.command)) for n, e in enumerate(entries)],
            )
            self._db.execute("COMMIT")

    def compact(self, upto: int, snapshot: dict[str, Any]) -> None:
        with self._lock:
            self._db.execute("BEGIN")
            self._db.execute("DELETE FROM log WHERE idx <= ?", (upto,))
            self._db.execute(
                "INSERT OR REPLACE INTO kv VALUES('snapshot', ?)", (json.dumps(snapshot),)
            )
            self._db.execute("COMMIT")


@dataclass
class _Pending:
    index: int
    term: int
    future: asyncio.Future[Any]


@dataclass
class RaftConfig:
    election_min: float = 1.5
    election_max: float = 3.0
    heartbeat: float = 0.4
    rpc_timeout: float = 1.0
    snapshot_every: int = 1000
    max_batch: int = 256


@dataclass
class RaftNode:
    id: str
    voters: list[str]
    transport: Transport
    machine: StateMachine
    storage: RaftStorage = field(default_factory=RaftStorage)
    config: RaftConfig = field(default_factory=RaftConfig)
    clock: Callable[[], float] = time.monotonic
    rng: random.Random = field(default_factory=random.Random)
    on_role_change: Callable[[Role, int], Awaitable[None] | None] | None = None
    learners: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.term, self.voted_for, entries, snap = self.storage.load()
        self.snap_index = int(snap.get("index", 0))
        self.snap_term = int(snap.get("term", 0))
        if snap.get("voters"):
            self.voters = list(snap["voters"])
        if snap.get("data") is not None:
            self.machine.restore(snap["data"])
        self.log: list[Entry] = [e for _, e in entries]
        self.commit_index = self.snap_index
        self.last_applied = self.snap_index
        self.role = Role.FOLLOWER
        self.leader_id: str | None = None
        self.next_index: dict[str, int] = {}
        self.match_index: dict[str, int] = {}
        self._pending: list[_Pending] = []
        self._deadline = self._new_deadline()
        self._next_heartbeat = 0.0
        self._lock = asyncio.Lock()
        for entry in self.log:
            if entry.command.get("op") == "voters":
                self.voters = list(entry.command["voters"])

    # -- log helpers -----------------------------------------------------

    @property
    def last_index(self) -> int:
        return self.snap_index + len(self.log)

    def term_at(self, index: int) -> int:
        if index == self.snap_index:
            return self.snap_term
        if index < self.snap_index or index > self.last_index:
            return -1
        return self.log[index - self.snap_index - 1].term

    def entries_from(self, index: int) -> list[Entry]:
        return self.log[index - self.snap_index - 1 :]

    @property
    def targets(self) -> list[str]:
        """Everyone who receives the log: voters and non-voting learners."""
        return [p for p in dict.fromkeys([*self.voters, *self.learners]) if p != self.id]

    @property
    def peers(self) -> list[str]:
        return [v for v in self.voters if v != self.id]

    @property
    def quorum(self) -> int:
        return len(self.voters) // 2 + 1

    def _new_deadline(self) -> float:
        return self.clock() + self.rng.uniform(self.config.election_min, self.config.election_max)

    async def _set_role(self, role: Role) -> None:
        if role == self.role:
            return
        self.role = role
        if role != Role.LEADER:
            for p in self._pending:
                if not p.future.done():
                    p.future.set_exception(NotLeader(self.leader_id))
            self._pending.clear()
        if self.on_role_change:
            result = self.on_role_change(role, self.term)
            if asyncio.iscoroutine(result):
                await result

    async def _step_down(self, term: int) -> None:
        if term > self.term:
            self.term = term
            self.voted_for = None
            self.storage.save_state(self.term, None)
        await self._set_role(Role.FOLLOWER)
        self._deadline = self._new_deadline()

    # -- timers ----------------------------------------------------------

    async def tick(self) -> None:
        now = self.clock()
        if self.role == Role.LEADER:
            if now >= self._next_heartbeat:
                await self._replicate()
        elif now >= self._deadline and self.id in self.voters:
            await self._elect()

    async def run(self, interval: float = 0.05) -> None:
        while True:
            await self.tick()
            await asyncio.sleep(interval)

    # -- election --------------------------------------------------------

    async def _elect(self) -> None:
        async with self._lock:
            self.term += 1
            self.voted_for = self.id
            self.storage.save_state(self.term, self.id)
            self.leader_id = None
            await self._set_role(Role.CANDIDATE)
            self._deadline = self._new_deadline()
            term = self.term
            req = VoteRequest(term, self.id, self.last_index, self.term_at(self.last_index))
        votes = 1
        results = await asyncio.gather(
            *(self._call(self.transport.vote(p, req)) for p in self.peers)
        )
        for resp in results:
            if resp is None:
                continue
            if resp.term > self.term:
                await self._step_down(resp.term)
                return
            if resp.granted and resp.term == term:
                votes += 1
        if self.role == Role.CANDIDATE and self.term == term and votes >= self.quorum:
            await self._become_leader()

    async def _become_leader(self) -> None:
        self.leader_id = self.id
        for p in self.targets:
            self.next_index[p] = self.last_index + 1
            self.match_index[p] = 0
        await self._set_role(Role.LEADER)
        # A no-op of the current term lets entries from earlier terms commit.
        self._append_local({"op": "noop"})
        await self._replicate()

    async def handle_vote(self, req: VoteRequest) -> VoteResponse:
        async with self._lock:
            if req.term > self.term:
                await self._step_down(req.term)
            up_to_date = (req.last_term, req.last_index) >= (
                self.term_at(self.last_index),
                self.last_index,
            )
            grant = (
                req.term == self.term
                and self.voted_for in (None, req.candidate)
                and up_to_date
                and req.candidate in self.voters
            )
            if grant:
                self.voted_for = req.candidate
                self.storage.save_state(self.term, req.candidate)
                self._deadline = self._new_deadline()
            return VoteResponse(self.term, grant)

    # -- replication -----------------------------------------------------

    def _append_local(self, command: dict[str, Any]) -> int:
        entry = Entry(self.term, command)
        self.log.append(entry)
        self.storage.append(self.last_index, [entry])
        if command.get("op") == "voters":
            self.voters = list(command["voters"])
            for p in self.peers:
                self.next_index.setdefault(p, self.last_index)
                self.match_index.setdefault(p, 0)
        return self.last_index

    async def propose(self, command: dict[str, Any], timeout: float = 5.0) -> Any:
        """Replicate a command and return its result once committed."""
        if self.role != Role.LEADER:
            raise NotLeader(self.leader_id)
        loop = asyncio.get_running_loop()
        index = self._append_local(command)
        pending = _Pending(index, self.term, loop.create_future())
        self._pending.append(pending)
        await self._replicate()
        return await asyncio.wait_for(pending.future, timeout)

    async def _replicate(self) -> None:
        self._next_heartbeat = self.clock() + self.config.heartbeat
        term = self.term
        await asyncio.gather(*(self._send(p, term) for p in self.targets))
        if self.role == Role.LEADER:
            self._advance_commit()
            self._apply()

    async def _send(self, peer: str, term: int) -> None:
        nxt = self.next_index.get(peer, self.last_index + 1)
        if nxt <= self.snap_index:
            req_s = SnapshotRequest(
                term,
                self.id,
                self.snap_index,
                self.snap_term,
                list(self.voters),
                self.machine.dump(),
            )
            resp = await self._call(self.transport.snapshot(peer, req_s))
            if resp and resp.success:
                self.match_index[peer] = self.snap_index
                self.next_index[peer] = self.snap_index + 1
            elif resp and resp.term > self.term:
                await self._step_down(resp.term)
            return
        prev = nxt - 1
        entries = self.entries_from(nxt)[: self.config.max_batch]
        req = AppendRequest(term, self.id, prev, self.term_at(prev), entries, self.commit_index)
        resp = await self._call(self.transport.append(peer, req))
        if resp is None or self.role != Role.LEADER or self.term != term:
            return
        if resp.term > self.term:
            await self._step_down(resp.term)
            return
        if resp.success:
            self.match_index[peer] = max(self.match_index.get(peer, 0), resp.match_index)
            self.next_index[peer] = self.match_index[peer] + 1
        else:
            self.next_index[peer] = max(1, min(nxt - 1, resp.match_index + 1))

    def _advance_commit(self) -> None:
        for n in range(self.last_index, self.commit_index, -1):
            if self.term_at(n) != self.term:
                break
            replicas = 1 + sum(1 for p in self.peers if self.match_index.get(p, 0) >= n)
            if self.id not in self.voters:
                replicas -= 1
            if replicas >= self.quorum:
                self.commit_index = n
                break

    def _apply(self) -> None:
        while self.last_applied < self.commit_index:
            self.last_applied += 1
            entry = self.log[self.last_applied - self.snap_index - 1]
            result = None
            error: BaseException | None = None
            if entry.command.get("op") not in ("noop", "voters"):
                try:
                    result = self.machine.apply(entry.command)
                except Exception as exc:
                    error = exc
            for p in list(self._pending):
                if p.index == self.last_applied:
                    self._pending.remove(p)
                    if p.future.done():
                        continue
                    if p.term != entry.term:
                        p.future.set_exception(NotLeader(self.leader_id))
                    elif error:
                        p.future.set_exception(error)
                    else:
                        p.future.set_result(result)
        if self.last_applied - self.snap_index >= self.config.snapshot_every:
            self._compact()

    def _compact(self) -> None:
        upto = self.last_applied
        term = self.term_at(upto)
        snapshot = {"index": upto, "term": term, "voters": self.voters, "data": self.machine.dump()}
        self.storage.compact(upto, snapshot)
        self.log = self.log[upto - self.snap_index :]
        self.snap_index, self.snap_term = upto, term

    async def handle_append(self, req: AppendRequest) -> AppendResponse:
        async with self._lock:
            if req.term < self.term:
                return AppendResponse(self.term, False, self.last_index)
            if req.term > self.term or self.role != Role.FOLLOWER:
                await self._step_down(req.term)
            self.leader_id = req.leader
            self._deadline = self._new_deadline()
            if req.prev_index > self.last_index:
                return AppendResponse(self.term, False, self.last_index)
            if req.prev_index >= self.snap_index and self.term_at(req.prev_index) != req.prev_term:
                return AppendResponse(self.term, False, max(self.snap_index, req.prev_index - 1))
            index = req.prev_index
            for n, entry in enumerate(req.entries):
                index = req.prev_index + 1 + n
                if index <= self.snap_index:
                    continue
                if index <= self.last_index and self.term_at(index) == entry.term:
                    continue
                keep = index - self.snap_index - 1
                self.log = self.log[:keep] + req.entries[n:]
                self.storage.append(index, req.entries[n:])
                for e in req.entries[n:]:
                    if e.command.get("op") == "voters":
                        self.voters = list(e.command["voters"])
                index = req.prev_index + len(req.entries)
                break
            match = req.prev_index + len(req.entries)
            if req.commit > self.commit_index:
                self.commit_index = min(req.commit, match)
                self._apply()
            return AppendResponse(self.term, True, match)

    async def handle_snapshot(self, req: SnapshotRequest) -> AppendResponse:
        async with self._lock:
            if req.term < self.term:
                return AppendResponse(self.term, False, self.last_index)
            await self._step_down(req.term)
            self.leader_id = req.leader
            if req.index <= self.commit_index:
                return AppendResponse(self.term, True, self.commit_index)
            self.machine.restore(req.data)
            self.voters = list(req.voters)
            self.log = []
            self.snap_index, self.snap_term = req.index, req.last_term
            self.commit_index = self.last_applied = req.index
            self.storage.compact(
                req.index,
                {"index": req.index, "term": req.last_term, "voters": req.voters, "data": req.data},
            )
            self.storage.append(req.index + 1, [])
            return AppendResponse(self.term, True, req.index)

    # -- membership ------------------------------------------------------

    async def change_voters(self, voters: list[str]) -> None:
        """Change the voter set by at most one member per step (Raft single-server change)."""
        current = set(self.voters)
        target = set(voters)
        if len(current ^ target) > 1:
            raise ValueError("change voters one at a time")
        if current == target:
            return
        await self.propose({"op": "voters", "voters": sorted(target)})

    # -- utilities -------------------------------------------------------

    async def _call(self, coro: Awaitable[Any]) -> Any:
        try:
            return await asyncio.wait_for(coro, self.config.rpc_timeout)
        except (TimeoutError, OSError, ConnectionError):
            return None
        except Exception:
            return None

    def status(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "role": self.role,
            "term": self.term,
            "leader": self.leader_id,
            "voters": self.voters,
            "commit_index": self.commit_index,
            "last_index": self.last_index,
        }
