"""W40 repository source publication and builder admission using only local Git."""

from __future__ import annotations

import fcntl
import os
import struct
from contextlib import contextmanager
from dataclasses import replace

import pytest

from builder_testkit import FILES, OUT, FakeBackend, policy
from repo_testkit import POLICY, Upstream, repository
from steward.core import repository_source_handoff as handoff
from steward.core.builder import BuildError, BuildRequest, BuildRunner
from steward.core.canonical import canonical_json, revision_id
from steward.core.config import WorkloadContract
from steward.core.repositories import fetch_repository, load_record
from steward.core.repository_contract import propose_contract

INVOCATION = "a" * 32
RAW_FILE = b"\x00\xc3\xa9\r\nraw\n"


@pytest.fixture
def candidate(tmp_path, monkeypatch):
    fetch = handoff.fetch
    uid, gid = os.geteuid(), os.getegid()
    assert uid != 0
    for name in ("store", "runtime", "publication", "builder"):
        (tmp_path / name).mkdir(mode=0o700)
    store = tmp_path / "store"
    monkeypatch.setattr(fetch, "STORE", store)
    monkeypatch.setattr(handoff, "RUNTIME", tmp_path / "runtime")
    monkeypatch.setattr(handoff, "DIRECTORY", tmp_path / "publication")
    monkeypatch.setenv("INVOCATION_ID", INVOCATION)

    upstream = Upstream(tmp_path)
    commit = upstream.commit({**FILES, "raw.bin": RAW_FILE})
    operator = WorkloadContract(container_port=7000)
    local_repo = repository(upstream.file_url, revision=commit, contract=operator)
    record = fetch_repository(local_repo, store, policy=POLICY)
    assert record.requested_revision == commit
    local_record = load_record(store, record.application, record.service, commit)
    assert local_record == record
    assert local_record.url == upstream.file_url
    legacy_proposal = propose_contract(local_repo, local_record, store, policy=POLICY)
    legacy_request = BuildRequest.create(local_record, legacy_proposal, store)

    # Configure production URL authority after the only fetch, which used file://.
    repo = local_repo.model_copy(update={"url": "https://git.example.org/shop/backend.git"})
    manifest = fetch.Manifest(
        version=1,
        base_revision="b" * 64,
        firewall_sha256="c" * 64,
        endpoint="93.184.216.34",
        credential_required=False,
        repository=fetch.RepositoryInput(
            **repo.model_dump(include=set(fetch.RepositoryInput.model_fields))
        ),
        handoff=fetch.HandoffInput(contract=operator, generation="d" * 32),
    )
    namespace = store / repo.application / repo.service
    (namespace / f"{commit}.json").write_text(
        canonical_json(replace(record, url=repo.url).persisted()), encoding="utf-8"
    )

    # Replace privileged checks only. Keep actual file/link checks and pack IO.
    private_directory = handoff._private_directory
    monkeypatch.setattr(
        handoff,
        "_private_directory",
        lambda path, owner: private_directory(path, uid if owner == 0 else owner),
    )
    monkeypatch.setattr(handoff.boot, "safe_directory", lambda path: None)
    monkeypatch.setattr(fetch, "_directory", lambda group: None)
    monkeypatch.setattr(fetch, "_read_active", lambda group: manifest)
    monkeypatch.setattr(handoff, "_reader_gid", lambda: gid)
    monkeypatch.setattr(handoff, "_custody", lambda group: None)
    monkeypatch.setattr(handoff.os, "fchown", lambda fd, user, group: None)
    monkeypatch.setattr(handoff.boot, "protected", lambda path, mode, group: path.open("rb"))
    return handoff._authority(manifest), legacy_request, namespace, tmp_path / "builder"


def publish(authority):
    handoff._seal(authority, INVOCATION, os.geteuid(), os.getegid())


@pytest.fixture
def prepared(candidate):
    handoff._prepare(os.geteuid(), os.getegid())
    return candidate


@pytest.fixture
def published(prepared):
    publish(prepared[0])
    return prepared


def test_published_source_builds_exact_bytes_with_operator_contract(published):
    authority, legacy, _, build_root = published

    class ByteBackend(FakeBackend):
        def build(self, job):
            self.raw = (job.source_dir / "raw.bin").read_bytes()
            self.has_workspace = job.request.store.is_relative_to(job.work_dir)
            self.import_pack_gone = not list(job.work_dir.glob(f"handoff-*/{handoff.STAGE_PACK}"))
            return super().build(job)

    backend = ByteBackend()
    runner = BuildRunner(build_root, policy(), [backend])
    result = runner.run_handoff(
        authority.expected(), job_id="e" * 32, input_digest=legacy.input_digest
    )
    request = backend.jobs[0].request
    assert request.record.url == authority.repository.url
    assert request.record.source_digest == legacy.record.source_digest
    assert request.contract == legacy.contract
    assert request.contract["container_port"] == 7000
    assert request.inventory == legacy.inventory
    assert request.input_digest == legacy.input_digest
    assert request.store != legacy.store
    assert backend.has_workspace and backend.import_pack_gone
    assert not list((build_root / "work").iterdir())
    assert result["status"] == "succeeded"
    assert result["output"]["digest"] == OUT
    assert result["input_digest"] == legacy.input_digest
    assert backend.raw == RAW_FILE
    assert backend.seen_tree == {**FILES, "raw.bin": "\x00é\nraw\n"}


def test_interrupted_handoff_workspace_is_reconcilable(published):
    authority, _, _, build_root = published
    runner = BuildRunner(build_root, policy(), [FakeBackend()])
    job_id = "e" * 32
    work = build_root / "work" / job_id
    work.mkdir(mode=0o700)
    runner._mark_workdir(work, job_id)
    with handoff._open_handoff(authority.expected(), work) as request:
        assert request.store.is_relative_to(work)
        assert runner.reconcile(active={job_id}) == []
        assert request.store.is_dir()
        assert runner.reconcile() == [job_id]
        assert not work.exists()


def test_builder_never_starts_after_losing_lease_during_import(published):
    authority, _, _, build_root = published
    backend = FakeBackend()
    runner = BuildRunner(build_root, policy(), [backend])
    lease = iter([True, False])
    with pytest.raises(BuildError, match="lease_lost"):
        runner.run_handoff(authority.expected(), job_id="e" * 32, on_poll=lambda: next(lease))
    assert backend.jobs == []
    assert not list((build_root / "work").iterdir())


@pytest.mark.parametrize(
    ("changes", "digest"),
    [
        ({"generation": "e" * 32}, None),
        ({"service": "other"}, None),
        ({}, "0" * 64),
    ],
)
def test_builder_rejects_input_outside_requested_authority(published, changes, digest):
    authority, _, _, build_root = published
    expected = authority.expected().model_copy(update=changes)
    with (
        pytest.raises(BuildError, match="differs from the requested input"),
        handoff._open_handoff(expected, build_root, input_digest=digest),
    ):
        pytest.fail("unexpected builder admission")


@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("inventory", "reconstructed build input differs"),
        ("source_digest", "source identity differs"),
    ],
)
def test_builder_checks_bound_metadata_against_objects(published, field, message):
    authority, _, _, build_root = published
    ready = handoff.DIRECTORY / handoff.READY
    with ready.open("rb") as handle:
        sealed = handoff._read_header(handle)
        pack = handle.read()
    metadata = sealed.model_dump(mode="json")
    inputs = metadata["inputs"]
    if field == "inventory":
        inputs["inventory"]["components"].append(
            {
                "ecosystem": "pip",
                "name": "uncommitted",
                "version": "1.0",
                "path": "requirements.txt",
            }
        )
        inputs["inventory_digest"] = revision_id(inputs["inventory"])
    else:
        inputs[field] = "1" * 64
    header = canonical_json(metadata).encode()
    ready.write_bytes(handoff.MAGIC + struct.pack("!I", len(header)) + header + pack)
    with (
        pytest.raises(BuildError, match=message),
        handoff._open_handoff(authority.expected(), build_root),
    ):
        pytest.fail("unexpected builder admission")


@pytest.mark.parametrize("damage", ["symlink", "hardlink", "truncation"])
def test_sealer_rejects_damaged_stage_pack(prepared, damage):
    authority, _, _, _ = prepared
    pack = handoff.RUNTIME / handoff.STAGE_PACK
    alias = pack.with_name("alias")
    if damage == "symlink":
        pack.rename(alias)
        pack.symlink_to(alias.name)
    elif damage == "hardlink":
        os.link(pack, alias)
    else:
        pack.write_bytes(pack.read_bytes()[:-1])

    with pytest.raises((BuildError, OSError)):
        publish(authority)
    assert not (handoff.DIRECTORY / handoff.READY).exists()


def test_interrupted_publication_can_retry(prepared, monkeypatch):
    authority, legacy, _, build_root = prepared
    ready = handoff.DIRECTORY / handoff.READY

    def interrupt(source, destination):
        assert destination == ready
        assert source.is_file()
        raise InterruptedError("before publishing READY")

    with monkeypatch.context() as patch:
        patch.setattr(handoff.os, "replace", interrupt)
        with pytest.raises(InterruptedError, match="before publishing READY"):
            publish(authority)
    assert not ready.exists()
    with (
        pytest.raises(BuildError, match="cannot verify source capsule"),
        handoff._open_handoff(authority.expected(), build_root),
    ):
        pytest.fail("interrupted publication admitted a build")
    publish(authority)
    with handoff._open_handoff(authority.expected(), build_root) as request:
        assert request.input_digest == legacy.input_digest


@pytest.mark.parametrize("withdraw", [True, False])
def test_builder_checks_current_publication_after_import(published, monkeypatch, withdraw):
    authority, _, _, build_root = published
    import_pack = handoff.import_pack

    def change_after_import(*args):
        result = import_pack(*args)
        handoff.withdraw_ready()
        if not withdraw:
            replacement = authority.model_copy(update={"generation": "e" * 32})
            staged = handoff.RUNTIME / handoff.STAGE_JSON
            metadata = handoff.Staged.model_validate_json(staged.read_bytes())
            staged.write_bytes(
                handoff._encoded(
                    metadata.model_copy(update={"authority_digest": handoff._digest(replacement)})
                )
            )
            publish(replacement)
        return result

    # A replacement only needs to change the header seen at final admission.
    monkeypatch.setattr(handoff, "import_pack", change_after_import)
    message = "cannot verify source capsule" if withdraw else "changed during import"
    with (
        pytest.raises(BuildError, match=message),
        handoff._open_handoff(authority.expected(), build_root),
    ):
        pytest.fail("stale publication admitted a build")


def test_prepare_refuses_a_busy_source_namespace(candidate):
    _, _, namespace, _ = candidate
    with (namespace / ".lock").open("rb") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BuildError) as error:
            handoff._prepare(os.geteuid(), os.getegid())
    assert error.value.code == "handoff_busy"
    assert not (handoff.RUNTIME / handoff.STAGE_PACK).exists()


def test_publication_checks_deployment_marker_inside_lock(candidate, monkeypatch, tmp_path):
    uid, gid = os.geteuid(), os.getegid()
    marker = tmp_path / "deploy-run.json"
    marker.touch()
    monkeypatch.setattr(handoff.fetch, "MARKER", marker)

    @contextmanager
    def lock(*, timeout, create):
        assert timeout > 0 and create is False
        with pytest.raises(handoff.boot.BootError, match="site deployment is pending"):
            yield

    def unexpected(_):
        pytest.fail("active authority read while deployment is pending")

    monkeypatch.setattr(handoff.boot, "deployment_lock", lock)
    monkeypatch.setattr(handoff.fetch, "_read_active", unexpected)
    with monkeypatch.context() as patch:
        patch.setattr(handoff.os, "geteuid", lambda: 0)
        handoff._root_command("publish", uid, gid)
    assert not (handoff.DIRECTORY / handoff.READY).exists()
