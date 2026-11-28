import random

import pytest

from opstend.cluster.consensus import NotLeader, RaftConfig, RaftNode, Role
from opstend.core.store import Store


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class Net:
    """In-memory transport with partitions."""

    def __init__(self):
        self.nodes: dict[str, RaftNode] = {}
        self.cut: set[frozenset[str]] = set()
        self.down: set[str] = set()
        self.sender = None

    def ok(self, a, b):
        return a not in self.down and b not in self.down and frozenset((a, b)) not in self.cut

    def for_node(self, me):
        net = self

        class T:
            async def vote(self, peer, req):
                return await net.nodes[peer].handle_vote(req) if net.ok(me, peer) else None

            async def append(self, peer, req):
                return await net.nodes[peer].handle_append(req) if net.ok(me, peer) else None

            async def snapshot(self, peer, req):
                return await net.nodes[peer].handle_snapshot(req) if net.ok(me, peer) else None

        return T()


def cluster(n=3, snapshot_every=1000):
    clock, net = Clock(), Net()
    ids = [f"n{i}" for i in range(n)]
    stores = {}
    for i, node_id in enumerate(ids):
        stores[node_id] = Store()
        net.nodes[node_id] = RaftNode(
            node_id,
            list(ids),
            net.for_node(node_id),
            stores[node_id],
            config=RaftConfig(snapshot_every=snapshot_every),
            clock=clock,
            rng=random.Random(i),
        )
    return clock, net, stores


async def run(clock, net, seconds, step=0.1):
    for _ in range(int(seconds / step)):
        clock.t += step
        for node_id, node in net.nodes.items():
            if node_id not in net.down:
                await node.tick()


def leaders(net):
    return [n for i, n in net.nodes.items() if n.role == Role.LEADER and i not in net.down]


async def test_single_leader_elected_and_commands_replicate():
    clock, net, stores = cluster()
    await run(clock, net, 5)
    assert len(leaders(net)) == 1
    leader = leaders(net)[0]
    await leader.propose({"op": "put", "kind": "host", "id": "pve1", "data": {"name": "pve1"}})
    await run(clock, net, 1)
    for store in stores.values():
        assert store.get("host", "pve1") == {"name": "pve1"}


async def test_failover_when_leader_dies():
    clock, net, stores = cluster()
    await run(clock, net, 5)
    old = leaders(net)[0]
    await old.propose({"op": "put", "kind": "k", "id": "1", "data": {"v": 1}})
    net.down.add(old.id)
    await run(clock, net, 6)
    new = leaders(net)
    assert len(new) == 1 and new[0].id != old.id and new[0].term > old.term
    await new[0].propose({"op": "put", "kind": "k", "id": "2", "data": {"v": 2}})
    # The old leader returns, steps down and catches up.
    net.down.clear()
    await run(clock, net, 3)
    assert old.role == Role.FOLLOWER
    assert stores[old.id].get("k", "2") == {"v": 2}


async def test_minority_partition_cannot_commit():
    clock, net, _ = cluster(5)
    await run(clock, net, 6)
    leader = leaders(net)[0]
    others = [i for i in net.nodes if i != leader.id]
    # Isolate the leader with one follower: a minority of 2 out of 5.
    buddy = others[0]
    for a in (leader.id, buddy):
        for b in others[1:]:
            net.cut.add(frozenset((a, b)))
    with pytest.raises((TimeoutError, NotLeader)):
        await leader.propose({"op": "put", "kind": "k", "id": "x", "data": {}}, timeout=0.05)
    await run(clock, net, 6)
    majority_leaders = [n for n in leaders(net) if n.id in others[1:]]
    assert len(majority_leaders) == 1
    net.cut.clear()
    await run(clock, net, 4)
    assert len(leaders(net)) == 1
    # The uncommitted write from the old minority leader is gone everywhere.
    assert all(n.machine.get("k", "x") is None for n in net.nodes.values())


async def test_lagging_follower_receives_snapshot():
    clock, net, stores = cluster(3, snapshot_every=5)
    await run(clock, net, 5)
    leader = leaders(net)[0]
    lagger = next(i for i in net.nodes if i != leader.id)
    net.down.add(lagger)
    for i in range(12):
        await leader.propose({"op": "put", "kind": "k", "id": str(i), "data": {"i": i}})
    assert leader.snap_index > 0
    net.down.clear()
    await run(clock, net, 2)
    assert stores[lagger].get("k", "11") == {"i": 11}


async def test_follower_rejects_proposals():
    clock, net, _ = cluster()
    await run(clock, net, 5)
    follower = next(n for n in net.nodes.values() if n.role == Role.FOLLOWER)
    with pytest.raises(NotLeader) as err:
        await follower.propose({"op": "noop"})
    assert err.value.leader == leaders(net)[0].id


async def test_voter_change_one_at_a_time():
    clock, net, _ = cluster(3)
    await run(clock, net, 5)
    leader = leaders(net)[0]
    with pytest.raises(ValueError):
        await leader.change_voters(["n0"])
    remaining = [v for v in leader.voters if v != next(p for p in leader.peers)]
    await leader.change_voters(remaining)
    await run(clock, net, 1)
    assert sorted(leader.voters) == sorted(remaining)
