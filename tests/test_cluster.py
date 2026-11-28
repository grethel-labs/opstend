import pytest

from opstend.cluster import discovery
from opstend.cluster.enrollment import ClusterCA, EnrollmentError, make_csr, new_key, pairing_code
from opstend.cluster.rollout import (
    Constraints,
    PlanError,
    Rollout,
    RolloutState,
    Runner,
    Target,
    TargetKind,
    plan,
)

# -- enrollment ---------------------------------------------------------------


def test_join_token_enrollment_roundtrip():
    ca = ClusterCA.create("home")
    issued = ca.issue_token()
    key = new_key()
    csr = make_csr(key, "node-2", ["10.0.0.2"])
    fp, secret = ClusterCA.parse_token(issued.token)
    assert ca.fingerprint.startswith(fp)
    cert = ca.enroll_with_token(csr, issued.token, ClusterCA.proof(secret, csr))
    assert ca.verify_node_cert(cert) == "node-2"
    # Tokens work once.
    with pytest.raises(EnrollmentError):
        ca.enroll_with_token(csr, issued.token, ClusterCA.proof(secret, csr))


def test_token_proof_and_cluster_checked():
    ca, other = ClusterCA.create("a"), ClusterCA.create("b")
    issued = ca.issue_token()
    csr = make_csr(new_key(), "n", [])
    with pytest.raises(EnrollmentError):
        ca.enroll_with_token(csr, issued.token, "0" * 64)
    with pytest.raises(EnrollmentError):
        other.enroll_with_token(csr, issued.token, ClusterCA.proof(b"x", csr))
    foreign = other.sign(csr)
    with pytest.raises(EnrollmentError):
        ca.verify_node_cert(foreign)


def test_pairing_code_is_stable_six_digits():
    code = pairing_code("a" * 64, "b" * 64)
    assert len(code) == 6 and code.isdigit()
    assert code == pairing_code("a" * 64, "b" * 64)
    assert code != pairing_code("a" * 64, "c" * 64)


# -- discovery ----------------------------------------------------------------


def test_beacon_parsing_rejects_members_and_garbage():
    payload = discovery.beacon_payload(
        "id1", "pi-4", "a" * 64, "0.2.0", "aarch64", ["10.0.0.9"], None
    )
    cand = discovery.parse_beacon(payload, "10.0.0.9")
    assert cand and cand.kind == "opstend-node" and cand.detail["arch"] == "aarch64"
    member = discovery.beacon_payload("id1", "x", "a" * 64, "0.2.0", "x86_64", [], "cluster")
    assert discovery.parse_beacon(member, "10.0.0.9") is None
    assert discovery.parse_beacon(b"not json", "1.2.3.4") is None
    assert discovery.parse_beacon(b'{"v":1,"kind":"opstend-node","key":"zz"}', "1.2.3.4") is None


def test_scan_targets_only_private():
    assert len(discovery.scan_targets(["192.168.1.0/30"])) == 2
    with pytest.raises(ValueError):
        discovery.scan_targets(["8.8.8.0/24"])
    with pytest.raises(ValueError):
        discovery.scan_targets(["10.0.0.0/8"])


def test_classifiers():
    assert discovery.classify_proxmox((401, {"server": "pve-api-daemon/3.0"}, b""))
    assert not discovery.classify_proxmox((200, {"server": "nginx"}, b""))
    body = b'{"meta":{"rc":"ok","up":true,"server_version":"9.0.114"}}'
    assert discovery.classify_unifi((200, {}, body)) == {"version": "9.0.114"}
    assert discovery.classify_unifi((200, {}, b"<html>")) is None


# -- rollout ------------------------------------------------------------------


def fleet():
    return [
        Target(id="gw", name="gateway", kind=TargetKind.UNIFI_GATEWAY, criticality=3),
        Target(
            id="sw",
            name="core-switch",
            kind=TargetKind.UNIFI_SWITCH,
            depends_on=["gw"],
            criticality=2,
        ),
        Target(
            id="ap1", name="ap-living", kind=TargetKind.UNIFI_AP, depends_on=["sw"], criticality=0
        ),
        Target(
            id="ap2", name="ap-office", kind=TargetKind.UNIFI_AP, depends_on=["sw"], criticality=0
        ),
        Target(id="n1", name="pve-a", kind=TargetKind.PROXMOX, voter=True, depends_on=["sw"]),
        Target(id="n2", name="pve-b", kind=TargetKind.PROXMOX, voter=True, depends_on=["sw"]),
        Target(id="n3", name="nuc-c", kind=TargetKind.LINUX, voter=True, depends_on=["sw"]),
    ]


def test_plan_orders_leaves_first_and_keeps_quorum():
    waves = plan(fleet(), Constraints(voters_total=3, max_parallel=3))
    order = [t for w in waves for t in w.targets]
    assert waves[0].reason.startswith("canary")
    assert order.index("sw") > max(order.index(x) for x in ("ap1", "ap2", "n1", "n2", "n3"))
    assert order[-1] == "gw"
    voters = {"n1", "n2", "n3"}
    for w in waves:
        assert len(voters & set(w.targets)) <= 1
        if "sw" in w.targets or "gw" in w.targets:
            assert len(w.targets) == 1


def test_plan_detects_cycles_and_quorum_loss():
    with pytest.raises(PlanError):
        plan(
            [
                Target(id="a", name="a", kind=TargetKind.LINUX, depends_on=["b"]),
                Target(id="b", name="b", kind=TargetKind.LINUX, depends_on=["a"]),
            ],
            Constraints(),
        )
    with pytest.raises(PlanError):
        plan(
            [Target(id="a", name="a", kind=TargetKind.LINUX, voter=True)],
            Constraints(voters_total=2),
        )


class FakeUpdater:
    def __init__(self, broken=()):
        self.broken = set(broken)
        self.done, self.rolled = [], []

    async def precheck(self, t):
        pass

    async def drain(self, t):
        pass

    async def apply(self, t):
        self.done.append(t.id)

    async def healthy(self, t):
        return t.id not in self.broken

    async def rollback(self, t):
        self.rolled.append(t.id)

    async def restore(self, t):
        pass


async def test_runner_pauses_and_rolls_back_on_failed_gate():
    targets = {t.id: t for t in fleet()}
    waves = plan(list(targets.values()), Constraints(voters_total=3))
    up = FakeUpdater(broken={"n2"})
    runner = Runner(updaters={k: up for k in TargetKind}, health_retries=2)
    result = await runner.run(Rollout(id="r", title="t", waves=waves), targets)
    assert result.state == RolloutState.PAUSED
    assert up.rolled == ["n2"]
    assert "gw" not in up.done


async def test_runner_completes():
    targets = {t.id: t for t in fleet()}
    up = FakeUpdater()
    runner = Runner(updaters={k: up for k in TargetKind})
    result = await runner.run(
        Rollout(id="r", title="t", waves=plan(list(targets.values()), Constraints(voters_total=3))),
        targets,
    )
    assert result.state == RolloutState.DONE and len(up.done) == 7
