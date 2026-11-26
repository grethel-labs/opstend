"""R03: build runner contract with a fake backend (no container engine, no network)."""

from __future__ import annotations

import json
import os
import time
from dataclasses import replace

import pytest

from builder_testkit import OUT, FakeBackend, limits, policy, prepare, request_for
from repo_testkit import Symlink, Upstream
from steward.core import builder as bd
from steward.core.canonical import revision_id
from steward.core.config import ConfigError, effective, parse_config
from steward.core.store import Store


@pytest.fixture
def fetch_root(tmp_path):
    path = tmp_path / "fetch"
    path.mkdir(mode=0o700)
    return path


@pytest.fixture
def build_root(tmp_path):
    path = tmp_path / "build"
    path.mkdir(mode=0o700)
    return path


@pytest.fixture
def upstream(tmp_path):
    return Upstream(tmp_path)


@pytest.fixture
def prepared(upstream, fetch_root):
    record, proposal = prepare(upstream, fetch_root)
    assert proposal.state == "suitable"
    return record, proposal


@pytest.fixture
def request_(prepared, fetch_root):
    return request_for(*prepared, fetch_root)


def runner(build_root, backends, **kw):
    return bd.BuildRunner(build_root, kw.pop("policy", policy()), backends, **kw)


# --- inputs ---------------------------------------------------------------------


def test_request_binds_source_contract_and_inventory(request_, prepared):
    record, proposal = prepared
    assert request_.record.source_digest == record.source_digest
    assert request_.contract_digest == proposal.contract_digest
    other = bd.BuildRequest.create(record, proposal, request_.store.parents[2])
    assert other.input_digest == request_.input_digest  # deterministic


@pytest.mark.parametrize(
    "tamper",
    [
        lambda p: setattr(p, "state", "unsuitable"),
        lambda p: setattr(p, "authorizes", []),
        lambda p: setattr(p, "contract_digest", "0" * 64),
        lambda p: setattr(p, "source_digest", "1" * 64),
        lambda p: setattr(p, "inventory", None),
        lambda p: p.contract.update(run_as=0),
        lambda p: p.contract["requirements"].update(privileged=True),
    ],
)
def test_request_refuses_unbound_or_unsafe_inputs(prepared, fetch_root, tamper):
    record, proposal = prepared
    proposal.contract = json.loads(json.dumps(proposal.contract))
    tamper(proposal)
    if proposal.contract is not None:  # keep the digest consistent: only the rules may refuse
        import hashlib

        from steward.core.canonical import canonical_json

        if proposal.contract_digest != "0" * 64:
            proposal.contract_digest = hashlib.sha256(
                canonical_json(proposal.contract).encode()
            ).hexdigest()
    with pytest.raises(bd.BuildError):
        bd.BuildRequest.create(record, proposal, fetch_root)


def test_request_refuses_a_record_whose_digest_does_not_match(prepared, fetch_root):
    record, proposal = prepared
    with pytest.raises(bd.BuildError) as exc:
        bd.BuildRequest.create(replace(record, tree="2" * 40), proposal, fetch_root)
    assert exc.value.code == "bad_source"


# --- isolation selection ----------------------------------------------------------


def test_strongest_ready_level_wins_and_is_recorded(build_root, request_):
    vm, ci, box = (
        FakeBackend("ephemeral_vm"),
        FakeBackend("external_ci"),
        FakeBackend("container_rootless"),
    )
    run = runner(build_root, [box, ci, vm], policy=policy(allow_container_isolation=True))
    record = run.run(request_)
    assert record["isolation"]["level"] == "ephemeral_vm"
    assert record["isolation"]["vm_protection"] is True
    assert vm.jobs and not ci.jobs and not box.jobs


def test_container_tier_needs_explicit_activation_and_is_labelled(build_root, request_):
    box = FakeBackend("container_rootless")
    refused = runner(build_root, [box]).run(request_)
    assert (refused["status"], refused["code"]) == ("failed", "no_isolation_available")
    assert refused["isolation"]["level"] is None and not box.jobs
    allowed = runner(build_root, [box], policy=policy(allow_container_isolation=True)).run(request_)
    assert allowed["isolation"]["level"] == "container_rootless"
    assert allowed["isolation"]["label"] == "container isolation, no VM protection"
    assert allowed["isolation"]["vm_protection"] is False


def test_unready_stronger_level_falls_back_and_says_why(build_root, request_):
    down, box = FakeBackend("ephemeral_vm", ready=False), FakeBackend("container_rootless")
    record = runner(build_root, [down, box], policy=policy(allow_container_isolation=True)).run(
        request_
    )
    assert record["isolation"]["level"] == "container_rootless"
    assert {"level": "ephemeral_vm", "skipped": "unavailable", "detail": "down"} in (
        record["isolation"]["considered"]
    )


def test_minimum_level_refuses_a_weaker_build(build_root, request_):
    box = FakeBackend("container_rootless")
    run = runner(
        build_root, [box], policy=policy(allow_container_isolation=True), minimum="external_ci"
    )
    assert run.run(request_)["code"] == "no_isolation_available"


def test_unknown_level_is_never_used(build_root, request_):
    odd = FakeBackend("vm_but_trust_me")
    assert runner(build_root, [odd]).run(request_)["code"] == "no_isolation_available"


# --- record -----------------------------------------------------------------------


def test_record_is_bound_and_authorizes_nothing(build_root, request_, prepared):
    record = runner(build_root, [FakeBackend()]).run(request_)
    assert record["status"] == "succeeded"
    assert record["output"]["digest"] == OUT
    assert record["source_digest"] == prepared[0].source_digest
    assert record["contract_digest"] == prepared[1].contract_digest
    assert record["input_digest"] == request_.input_digest
    assert record["base_images"] and record["recipe"]["file"] == "Dockerfile"
    assert record["authorizes"] == [] and record["trust"] == "untrusted_candidate"
    assert record["reproducibility"] == "not_measured"
    assert record["limits"]["timeout_s"] == 1800 and record["limits"]["memory_mb"] == 2048
    stored = runner(build_root, []).load_records(request_.input_digest)
    assert [r["job_id"] for r in stored] == [record["job_id"]]
    path = build_root / "records" / request_.input_digest / f"{record['job_id']}.json"
    assert path.stat().st_mode & 0o077 == 0


def test_the_build_sees_exactly_the_committed_tree(build_root, request_):
    backend = FakeBackend()
    runner(build_root, [backend]).run(request_)
    assert set(backend.seen_tree) == {"Dockerfile", "app.py", "steward.contract.yml"}


@pytest.mark.parametrize(
    "outcome",
    [
        bd.BackendOutcome("succeeded", "", "latest"),
        bd.BackendOutcome("succeeded", "", None),
        bd.BackendOutcome("succeeded", "", "sha256:" + "G" * 64),
        bd.BackendOutcome("great", "", OUT),
    ],
)
def test_a_backend_cannot_claim_success_without_a_valid_digest(build_root, request_, outcome):
    record = runner(build_root, [FakeBackend(outcome=outcome)]).run(request_)
    assert record["status"] in ("failed", "crashed") and record["output"]["digest"] is None


def test_a_mutable_tag_is_never_recorded_as_the_artifact(build_root, request_):
    outcome = bd.BackendOutcome("succeeded", "", OUT, "reg.invalid/app:latest")
    record = runner(build_root, [FakeBackend(outcome=outcome)]).run(request_)
    assert record["output"] == {"digest": OUT, "ref": None}


def test_failed_build_output_is_untrusted_text(build_root, request_):
    log = b"\x1b[31mboom\x00 token=ghp_0123456789abcdefghijklmnop\n" + b"x" * 50000
    outcome = bd.BackendOutcome("failed", "Build Failed!", log=log)
    record = runner(build_root, [FakeBackend(outcome=outcome)], limits=limits(log_bytes=2000)).run(
        request_
    )
    assert record["code"] == "buildfailed" and len(record["log"]) <= 2000
    assert "ghp_" not in record["log"] and "\x1b" not in record["log"]


# --- failure and cleanup ----------------------------------------------------------


@pytest.mark.parametrize("status", ["timeout", "limit_exceeded", "failed", "crashed"])
def test_every_ending_cleans_up_and_leaves_no_workdir(build_root, request_, status):
    backend = FakeBackend(outcome=bd.BackendOutcome(status, "x"))
    record = runner(build_root, [backend]).run(request_, job_id="a" * 32)
    assert record["status"] == status and record["cleanup"] == "ok"
    assert backend.cleaned == ["a" * 32]
    assert list((build_root / "work").iterdir()) == []


def test_a_crashing_backend_is_a_crash_not_an_exception(build_root, request_):
    backend = FakeBackend(error=RuntimeError("secret detail"))
    record = runner(build_root, [backend]).run(request_)
    assert (record["status"], record["code"]) == ("crashed", "runtimeerror")
    assert "secret detail" not in json.dumps(record)
    assert backend.cleaned and list((build_root / "work").iterdir()) == []


def test_failing_backend_cleanup_is_reported_not_hidden(build_root, request_):
    class Bad(FakeBackend):
        def cleanup(self, job_id):
            raise OSError("stuck")

    assert runner(build_root, [Bad()]).run(request_)["cleanup"] == "backend_failed"


def test_reconcile_removes_only_marked_owned_orphans(build_root, request_):
    backend = FakeBackend()
    run = runner(build_root, [backend])
    orphan, live, foreign = "c" * 32, "d" * 32, "e" * 32
    for name in (orphan, live):
        (build_root / "work" / name).mkdir()
        (build_root / "work" / name / bd.MARKER).write_text(f"steward-build v1 {name}\n")
    (build_root / "work" / foreign).mkdir()  # no marker: not ours
    (build_root / "work" / "unrelated").mkdir()
    assert run.reconcile(active={live}) == [orphan]
    assert backend.cleaned == [orphan]
    assert {p.name for p in (build_root / "work").iterdir()} == {live, foreign, "unrelated"}


def test_workdir_root_must_be_private(tmp_path):
    loose = tmp_path / "loose"
    (loose / "work").mkdir(parents=True, mode=0o755)
    os.chmod(loose / "work", 0o755)  # noqa: S103
    with pytest.raises(bd.BuildError):
        bd.BuildRunner(loose, policy(), [])


# --- hostile source ------------------------------------------------------------------


@pytest.mark.parametrize(
    "files, code",
    [
        ({"link": Symlink("/etc/passwd")}, "unsafe_symlink"),
        ({"sub/link": Symlink("../../outside")}, "unsafe_symlink"),
    ],
)
def test_links_leaving_the_tree_fail_the_export(build_root, upstream, fetch_root, files, code):
    record, proposal = prepare(upstream, fetch_root, files)
    backend = FakeBackend()
    result = runner(build_root, [backend]).run(request_for(record, proposal, fetch_root))
    assert (result["status"], result["code"]) == ("failed", code)
    assert not backend.jobs and list((build_root / "work").iterdir()) == []


def test_links_inside_the_tree_are_kept(build_root, upstream, fetch_root):
    record, proposal = prepare(upstream, fetch_root, {"alias": Symlink("app.py")})
    backend = FakeBackend()
    runner(build_root, [backend]).run(request_for(record, proposal, fetch_root))
    assert backend.jobs and backend.seen_links == {"alias": "app.py"}


def test_submodules_are_refused(build_root, upstream, fetch_root):
    record, proposal = prepare(upstream, fetch_root, gitlink=True)
    result = runner(build_root, [FakeBackend()]).run(request_for(record, proposal, fetch_root))
    assert result["code"] == "submodule"


def test_export_does_not_expand_attributes(build_root, upstream, fetch_root):
    files = {".gitattributes": "app.py export-subst\n", "app.py": "$Format:%H$\n"}
    record, proposal = prepare(upstream, fetch_root, files)
    backend = FakeBackend()
    runner(build_root, [backend]).run(request_for(record, proposal, fetch_root))
    assert backend.seen_tree["app.py"] == "$Format:%H$\n"


def test_oversized_source_is_refused(build_root, upstream, fetch_root):
    record, proposal = prepare(upstream, fetch_root, {"big.bin": "x" * 5000})
    run = runner(build_root, [FakeBackend()], limits=limits(source_bytes=1000))
    assert run.run(request_for(record, proposal, fetch_root))["code"] == "source_too_large"
    run = runner(build_root, [FakeBackend()], limits=limits(source_files=2))
    assert run.run(request_for(record, proposal, fetch_root))["code"] == "source_too_large"


# --- reuse -----------------------------------------------------------------------------


def test_reuse_is_by_input_digest_and_accepted_output_only(build_root, request_, prepared):
    backend = FakeBackend()
    run = runner(build_root, [backend])
    first = run.run(request_)
    assert run.run(request_)["job_id"] != first["job_id"]  # no acceptance given: rebuild
    assert len(backend.jobs) == 2
    other = run.run(request_, accepted={"sha256:" + "9" * 64})
    assert "reused" not in other and len(backend.jobs) == 3  # not accepted: built again
    reused = run.run(request_, accepted={OUT})
    assert reused["reused"] is True and reused["output"]["digest"] == OUT
    assert len(backend.jobs) == 3  # no new build


def test_changed_commit_or_recipe_does_not_reuse(build_root, upstream, fetch_root):
    record, proposal = prepare(upstream, fetch_root)
    first = request_for(record, proposal, fetch_root)
    run = runner(build_root, [FakeBackend()])
    run.run(first)
    record2, proposal2 = prepare(upstream, fetch_root, {"app.py": "print('two')\n"})
    second = request_for(record2, proposal2, fetch_root)
    assert second.input_digest != first.input_digest
    assert run.find_reusable(second, accepted={OUT}) is None


def test_reuse_respects_the_minimum_isolation(build_root, request_):
    box = FakeBackend("container_rootless")
    weak = runner(build_root, [box], policy=policy(allow_container_isolation=True))
    weak_record = weak.run(request_)
    assert weak.find_reusable(request_, accepted={OUT})["job_id"] == weak_record["job_id"]
    revoked = runner(build_root, [])
    assert revoked.run(request_, accepted={OUT})["code"] == "no_isolation_available"

    backend = FakeBackend()
    strict = runner(
        build_root,
        [backend],
        policy=policy(allow_container_isolation=True, minimum_isolation="external_ci"),
        minimum="container_rootless",
    )
    assert strict.find_reusable(request_, accepted={OUT}) is None
    strong_record = strict.run(request_, accepted={OUT})
    assert strong_record["isolation"]["level"] == "ephemeral_vm"
    assert strong_record["job_id"] != weak_record["job_id"]
    reused = strict.run(request_, accepted={OUT})
    assert reused["reused"] is True and reused["job_id"] == strong_record["job_id"]
    assert len(backend.jobs) == 1


# --- durable jobs --------------------------------------------------------------------------


def test_job_runs_once_per_input_and_reports_the_record(build_root, request_, tmp_path):
    store = Store(tmp_path / "db.sqlite")
    job, created = bd.enqueue_build(store, request_, created_by="test", now=1000)
    again, created_again = bd.enqueue_build(store, request_, created_by="test", now=1001)
    assert created and not created_again and again["id"] == job["id"]
    claimed = store.claim("w1", lease_s=60, now=1002)
    run = runner(build_root, [FakeBackend()])
    state = bd.handle_build_job(store, run, lambda payload: request_, claimed, "w1", now=1003)
    assert state == "succeeded"
    done = store.get_job(job["id"])
    assert done["result"]["output_digest"] == OUT
    assert done["result"]["isolation"] == "ephemeral_vm"
    assert run.load_records(request_.input_digest)[0]["job_id"] == job["id"]


@pytest.mark.parametrize(
    ("configured", "override"),
    [("ephemeral_vm", "external_ci"), ("container_rootless", "ephemeral_vm")],
)
def test_claimed_job_enforces_the_stricter_minimum_before_readiness(
    build_root, request_, tmp_path, raw_config, monkeypatch, configured, override
):
    raw_config["build"] = {"minimum_isolation": configured}
    canonical = effective(parse_config(raw_config, allow_unavailable=True))
    cfg = parse_config(canonical, allow_unavailable=True)
    backend = FakeBackend("external_ci")

    def unexpected_probe():
        pytest.fail("below-policy backend reached the readiness probe")

    monkeypatch.setattr(backend, "available", unexpected_probe)
    store = Store(tmp_path / "db.sqlite")
    job, _ = bd.enqueue_build(store, request_, created_by="test", now=1000)
    claimed = store.claim("w1", lease_s=60, now=1001)
    run = runner(build_root, [backend], policy=cfg.build, minimum=override)
    assert bd.handle_build_job(store, run, lambda payload: request_, claimed, "w1", now=1002) == (
        "failed"
    )
    assert store.get_job(job["id"])["error"] == "no_isolation_available"
    assert backend.jobs == []


def test_only_current_lease_can_reconcile_and_build(build_root, request_, tmp_path):
    store = Store(tmp_path / "db.sqlite")
    bd.enqueue_build(store, request_, created_by="test", now=1000)
    claimed = store.claim("w1", lease_s=60, now=1000)
    backend = FakeBackend()
    run = runner(build_root, [backend])
    stale = tmp_path / "stale"
    # A crashed earlier attempt left a workdir behind; the next attempt reconciles it.
    (build_root / "work" / ("f" * 32)).mkdir()
    (build_root / "work" / ("f" * 32) / bd.MARKER).write_text(f"steward-build v1 {'f' * 32}\n")
    assert stale.exists() is False
    store.reconcile(now=5000)  # lease expired
    assert bd.handle_build_job(store, run, lambda p: request_, claimed, "w1", now=5000) is None
    assert backend.cleaned == [] and backend.jobs == []
    retry = store.claim("w2", lease_s=60, now=5000)
    assert bd.handle_build_job(store, run, lambda p: request_, retry, "w2", now=5000) == "succeeded"
    assert "f" * 32 in backend.cleaned
    assert list((build_root / "work").iterdir()) == []


def test_bad_job_inputs_fail_the_job_not_the_worker(build_root, request_, tmp_path):
    store = Store(tmp_path / "db.sqlite")
    bd.enqueue_build(store, request_, created_by="test", now=1000)
    claimed = store.claim("w1", lease_s=60, now=1000)

    def refuse(payload):
        raise bd.BuildError("not_authorized", "no")

    state = bd.handle_build_job(
        store, runner(build_root, [FakeBackend()]), refuse, claimed, "w1", now=1001
    )
    assert state == "failed"
    assert store.get_job(claimed["id"])["error"] == "not_authorized"


# --- bounded process runner ------------------------------------------------------------------


def run_sh(tmp_path, script, **kw):
    spool = tmp_path / "spool"
    spool.mkdir(exist_ok=True)
    return bd.run_bounded(
        ["/bin/sh", "-c", script], env={"PATH": "/usr/bin:/bin"}, cwd=tmp_path, spool=spool,
        timeout_s=kw.pop("timeout_s", 10), log_bytes=kw.pop("log_bytes", 1000), **kw,
    )  # fmt: skip


def test_runner_enforces_time_log_and_disk_limits(tmp_path):
    started = time.monotonic()
    assert run_sh(tmp_path, "sleep 30", timeout_s=0.6).reason == "timeout"
    assert time.monotonic() - started < 5
    flood = run_sh(tmp_path, "yes x | head -c 100000; sleep 30", log_bytes=500)
    assert flood.reason == "log_limit" and len(flood.log) <= 500
    work = tmp_path / "w"
    work.mkdir()
    disk = run_sh(
        tmp_path, f"head -c 200000 /dev/zero > {work}/f; sleep 30", watch=work, max_watch_bytes=1000
    )
    assert disk.reason == "disk_limit"
    stop = run_sh(tmp_path, "sleep 30", on_poll=lambda: False)
    assert stop.reason == "lost_lease"
    ok = run_sh(tmp_path, "echo fine")
    assert (ok.returncode, ok.reason, ok.log.strip()) == (0, None, b"fine")


# --- configuration ---------------------------------------------------------------------------


def test_build_policy_is_unavailable_and_defaults_to_no_container_tier(raw_config):
    assert parse_config(raw_config).build is None
    raw_config["build"] = {"allow_container_isolation": True}

    with pytest.raises(ConfigError, match="build: not available"):
        parse_config(raw_config)
    cfg = parse_config(raw_config, allow_unavailable=True)
    assert cfg.build.allow_container_isolation is True and cfg.build.timeout_s == 1800


def test_minimum_isolation_validates_and_preserves_legacy_canonical_config(raw_config):
    raw_config["build"] = {"allow_container_isolation": True}
    omitted = effective(parse_config(raw_config, allow_unavailable=True))
    assert "minimum_isolation" not in omitted["build"]

    raw_config["build"]["minimum_isolation"] = None
    explicit_null = effective(parse_config(raw_config, allow_unavailable=True))
    assert revision_id(explicit_null) == revision_id(omitted)

    raw_config["build"]["minimum_isolation"] = "external_ci"
    configured = effective(parse_config(raw_config, allow_unavailable=True))
    assert configured["build"]["minimum_isolation"] == "external_ci"
    assert revision_id(configured) != revision_id(omitted)

    raw_config["build"]["minimum_isolation"] = "bare_metal"
    with pytest.raises(ConfigError, match=r"build\.minimum_isolation"):
        parse_config(raw_config, allow_unavailable=True)
