from opstend.cluster.placement import Planner, voter_count
from opstend.core.models import Node, NodeState, Resources


def node(i, site="home", cpu=4, mem=8192, state=NodeState.HEALTHY, **labels):
    return Node(
        id=f"n{i}",
        name=f"n{i}",
        address=f"10.0.0.{i}",
        site=site,
        state=state,
        capacity=Resources(cpu_cores=cpu, memory_mb=mem),
        labels=labels,
    )


def test_voter_counts_are_odd():
    assert [voter_count(n) for n in (1, 2, 3, 4, 5, 9)] == [1, 1, 3, 3, 5, 5]


def test_roles_are_spread_not_everywhere():
    nodes = [node(i) for i in range(5)]
    p = Planner().plan(nodes)
    assert len(p.assignments["controller"]) == 5
    assert len(p.assignments["web"]) == 2
    assert len(set(p.assignments["web"])) == 2
    assert len(p.assignments["scanner"]) == 1
    # Not every node runs every role.
    assert any(len(p.roles_on(n.id)) < len(p.assignments) for n in nodes)


def test_gpu_preference_and_capacity_limits():
    nodes = [node(1), node(2, mem=32768, gpu="yes"), node(3, mem=1024, cpu=1)]
    p = Planner().plan(nodes)
    assert p.assignments["zorec"] == ["n2"]
    assert "n3" not in p.assignments["scanner"]


def test_failed_node_roles_move_and_others_stay():
    nodes = [node(i) for i in range(3)]
    first = Planner().plan(nodes)
    victim = first.assignments["scanner"][0]
    nodes = [n if n.id != victim else node(int(victim[1:]), state=NodeState.DOWN) for n in nodes]
    second = Planner().plan(nodes, first.assignments)
    assert victim not in second.assignments["scanner"]
    assert any(m[0] == "scanner" and m[1] == victim for m in second.moves)
    unchanged = [r for r in ("backup", "zorec") if victim not in first.assignments[r]]
    for role in unchanged:
        assert second.assignments[role] == first.assignments[role]


def test_per_site_roles_and_site_spread():
    nodes = [node(1, site="a"), node(2, site="a"), node(3, site="b")]
    p = Planner().plan(nodes)
    sites = {n.id: n.site for n in nodes}
    assert {sites[i] for i in p.assignments["collector"]} == {"a", "b"}
    assert {sites[i] for i in p.assignments["web"]} == {"a", "b"}


def test_unplaced_role_is_reported():
    p = Planner().plan([node(1, cpu=0.2, mem=200)])
    assert "zorec" in p.unplaced
