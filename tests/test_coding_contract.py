"""R05: shared contract cases every CodingAgentRunner and ForgeClient must pass.

Add a factory to ``RUNNERS`` / ``FORGES`` when a real adapter exists; the fakes run here.
"""

from __future__ import annotations

import inspect

import pytest

from coding_testkit import FINDING, FakeAgent, FakeForge, fetched
from repo_testkit import Upstream
from steward.adapters import coding
from steward.core import builder as bd
from steward.core import repair as rp

RUNNERS = [pytest.param(FakeAgent, id="fake")]
FORGES = [pytest.param(FakeForge, id="fake")]


@pytest.fixture
def task(tmp_path):
    for name in ("fetch",):
        (tmp_path / name).mkdir(mode=0o700)
    _, request = fetched(Upstream(tmp_path), tmp_path / "fetch")
    source = tmp_path / "src"
    source.mkdir()
    return rp.build_task(
        request,
        FINDING,
        job_id="a" * 32,
        source_dir=source,
        limits=coding.AgentLimits(),
    )


@pytest.mark.parametrize("make", RUNNERS)
def test_runner_declares_a_known_level_distinct_identity_and_safe_scope(make):
    runner = make()
    assert runner.level in bd.LEVEL_RANK
    assert coding.check_identities(runner, others={"builder": "steward-build"}) is None
    ready, reason = runner.available()
    assert isinstance(ready, bool) and isinstance(reason, str)


@pytest.mark.parametrize("make", RUNNERS)
def test_runner_returns_a_typed_outcome_and_cleanup_is_idempotent(make, task):
    runner = make()
    outcome = runner.run(task)
    assert isinstance(outcome, coding.AgentOutcome) and outcome.status in coding.AGENT_STATUSES
    assert isinstance(outcome.diff, bytes)
    runner.cleanup(task.job_id)
    runner.cleanup(task.job_id)


@pytest.mark.parametrize("make", RUNNERS)
def test_task_gives_the_runner_no_authority(make, task):
    fields = {f for f in task.__dataclass_fields__}
    assert fields == {
        "job_id", "application", "service", "advisory", "instruction", "finding",
        "source_dir", "allowed_paths", "limits", "on_poll",
    }  # fmt: skip
    assert task.allowed_paths and all("*" not in p for p in task.allowed_paths)


@pytest.mark.parametrize("make", FORGES)
def test_forge_can_only_open_and_find_pull_requests(make):
    forge = make()
    public = {n for n, _ in inspect.getmembers(forge, callable) if not n.startswith("_")}
    assert {"find_pull_request", "open_pull_request"} <= public
    assert not any(w in n for n in public for w in ("merge", "approve", "push", "protect"))
    assert forge.find_pull_request("shop-backend", "steward/repair/x") is None
    ref = forge.open_pull_request(
        "shop-backend", base_branch="main", base_commit="a" * 40,
        head_branch="steward/repair/x", expected_head_commit="b" * 40,
        title="t", body="b", patch=b"p",
    )  # fmt: skip
    assert isinstance(ref, coding.PullRequestRef)
    assert ref.head_commit == "b" * 40
    assert ref.head_branch == "steward/repair/x"
    assert ref.repository == "shop-backend"
    assert ref.base_branch == "main"
    assert forge.find_pull_request("shop-backend", "steward/repair/x") == ref
    assert forge.find_pull_request("other-repository", "steward/repair/x") is None
