"""Offline admission tests for the repository build-input verifier."""

from __future__ import annotations

import os
from contextlib import contextmanager

import pytest

from steward.core import repository_build_verify as verify
from steward.core import repository_source_handoff as handoff
from steward.core.builder import BuildError
from steward.core.store import Store
from test_repository_source_handoff import INVOCATION
from test_repository_source_handoff import candidate as candidate
from test_repository_source_handoff import prepared as prepared
from test_repository_source_handoff import published as published

pytestmark = pytest.mark.usefixtures("verification_state")


@pytest.fixture
def verification_state(tmp_path, monkeypatch):
    state = tmp_path / "verify"
    state.mkdir(mode=0o700)
    monkeypatch.setattr(verify, "STATE", state)
    return state


@pytest.fixture
def admission(published):
    authority, request, _, _ = published
    with (handoff.DIRECTORY / handoff.READY).open("rb") as capsule:
        sealed = handoff._read_header(capsule)
    ticket = verify.Admission(
        invocation=INVOCATION,
        release="1.2.3",
        expected=authority.expected(),
        input_digest=request.input_digest,
        capsule_digest=handoff._digest(sealed),
    )
    verify._write_admission(ticket)
    return ticket


def test_repeat_verifies_current_authority_without_reimport(admission, monkeypatch):
    open_handoff = handoff._open_handoff
    imports = []

    @contextmanager
    def track_import(expected, root, *, input_digest):
        with open_handoff(expected, root, input_digest=input_digest) as request:
            imports.append((request.input_digest, root))
            assert request.store.is_relative_to(root)
            yield request

    monkeypatch.setattr(handoff, "_open_handoff", track_import)

    assert verify._verify_job(admission) is None
    next_invocation = admission.model_copy(update={"invocation": "f" * 32, "confirmed": True})
    verify._write_admission(next_invocation)
    assert verify._verify_job(next_invocation) is None

    assert [digest for digest, _ in imports] == [admission.input_digest]
    assert not imports[0][1].exists()


@pytest.mark.parametrize("field", ["input_digest", "generation", "service"])
def test_import_refuses_capsule_outside_admitted_binding(admission, monkeypatch, field):
    monkeypatch.setattr(verify, "_require_current_capsule", lambda ticket: None)
    updates = {"input_digest": "0" * 64}
    if field != "input_digest":
        expected = admission.expected.model_copy(
            update={field: {"generation": "e" * 32, "service": "other"}[field]}
        )
        updates = {"expected": expected}

    with pytest.raises(BuildError):
        verify._verify_job(admission.model_copy(update=updates))


@pytest.mark.parametrize("prior_success", [False, True])
def test_verify_rechecks_current_capsule_even_after_success(admission, prior_success):
    if prior_success:
        assert verify._verify_job(admission) is None
    (handoff.DIRECTORY / handoff.READY).write_bytes(b"invalid capsule")

    with pytest.raises(BuildError):
        verify._verify_job(admission)


def test_verify_refuses_wrong_capsule_fingerprint(admission):
    wrong = admission.model_copy(update={"capsule_digest": "0" * 64})
    verify._write_admission(wrong)
    with pytest.raises(BuildError, match="capsule was replaced"):
        verify._verify_job(wrong)


def test_cached_proof_refuses_pack_corruption_under_unchanged_header(admission):
    verify._verify_job(admission)
    admission = admission.model_copy(update={"confirmed": True})
    verify._write_admission(admission)
    ready = handoff.DIRECTORY / handoff.READY
    with ready.open("r+b") as capsule:
        handoff._read_header(capsule)
        offset = capsule.tell()
        first = capsule.read(1)
        capsule.seek(offset)
        capsule.write(bytes([first[0] ^ 1]))
    with pytest.raises(BuildError, match="pack digest differs"):
        verify._verify_job(admission)


@pytest.mark.parametrize("seeded", [False, True])
def test_unconfirmed_ledger_success_cannot_skip_a_fresh_import(
    admission, monkeypatch, verification_state, seeded
):
    if seeded:
        key = verify.revision_id(admission.binding())
        with verify._job_state(key) as ledger:
            store = verify._open_store(ledger)
            try:
                job = verify._enqueue_job(store, admission, key)
                assert store.claim("seed", job_id=job["id"]) is not None
                assert (
                    store.finish(job["id"], "seed", ok=True, result=admission.proof())
                    == "succeeded"
                )
            finally:
                store.close()
    else:
        # Run the worker without its final root hook.
        verify._verify_job(admission)

    def refuse_import(*args, **kwargs):
        raise BuildError("bad_handoff", "fresh import required")

    monkeypatch.setattr(handoff, "_open_handoff", refuse_import)
    with pytest.raises(BuildError, match="fresh import required"):
        verify._verify_job(admission)
    (ledger,) = verification_state.glob("*.sqlite")
    store = Store(ledger)
    try:
        (job,) = store.list_jobs()
        assert job["state"] == "failed"
    finally:
        store.close()
    assert not verify._read_admission().confirmed


@pytest.mark.parametrize("stale", [False, True])
def test_root_derives_expected_input_from_active_manifest(admission, published, monkeypatch, stale):
    authority, _, _, _ = published
    manifest = verify.fetch._read_active(1)
    if stale:
        manifest = manifest.model_copy(
            update={"handoff": manifest.handoff.model_copy(update={"generation": "e" * 32})}
        )
    monkeypatch.setattr(verify, "_release", lambda: admission.release)
    monkeypatch.setattr(verify.fetch, "_account", lambda: (1, 1))
    monkeypatch.setattr(verify.fetch, "_require_no_marker", lambda: None)
    monkeypatch.setattr(verify.fetch, "_read_active", lambda gid: manifest)
    checked = []
    monkeypatch.setattr(verify.fetch, "_require_scope", lambda manifest, uid: checked.append(uid))
    monkeypatch.setattr(
        verify.fetch, "_require_applied", lambda manifest: checked.append(manifest.base_revision)
    )
    if stale:
        with pytest.raises(BuildError, match="authority differs"):
            verify._current(admission.invocation)
    else:
        assert verify._current(admission.invocation) == admission
    assert checked == [1, authority.base_revision]


class WorkerStopped(BaseException):
    """Simulate a process stopping immediately after acquiring its lease."""


@pytest.mark.parametrize("interruptions", [1, 2])
def test_only_one_retry_after_expired_worker_lease(admission, monkeypatch, interruptions):
    monkeypatch.setattr(verify, "_require_current_capsule", lambda ticket: None)
    enqueue, claim, reconcile = Store.enqueue, Store.claim, Store.reconcile
    clock = 1000
    acquired = []

    def stop_after_claim(store, *args, **kwargs):
        job = claim(store, *args, **kwargs, now=clock)
        assert job is not None
        acquired.append((job["id"], job["attempts"]))
        raise WorkerStopped

    with monkeypatch.context() as patch:
        patch.setattr(
            Store,
            "enqueue",
            lambda store, *args, **kwargs: enqueue(store, *args, **kwargs, now=clock),
        )
        patch.setattr(Store, "reconcile", lambda store: reconcile(store, now=clock))
        patch.setattr(Store, "claim", stop_after_claim)
        for _ in range(interruptions):
            with pytest.raises(WorkerStopped):
                verify._verify_job(admission)
            clock += verify.LEASE_SECONDS + 1

    assert len({job_id for job_id, _ in acquired}) == 1
    assert [attempts for _, attempts in acquired] == list(range(1, interruptions + 1))
    if interruptions == 1:
        assert verify._verify_job(admission) is None
    else:
        with pytest.raises(BuildError):
            verify._verify_job(admission)


def test_state_directory_symlink_is_refused(admission, verification_state, monkeypatch):
    target = verification_state.with_name("unowned")
    target.mkdir(mode=0o700)
    verification_state.rmdir()
    verification_state.symlink_to(target, target_is_directory=True)
    monkeypatch.setattr(verify, "_require_current_capsule", lambda ticket: None)

    with pytest.raises(verify.boot.BootError, match="unsafe builder verification state"):
        verify._verify_job(admission)
    assert verification_state.is_symlink()
    assert list(target.iterdir()) == []


def test_new_authority_replaces_old_ledger_and_cleans_stale_work(
    admission, published, verification_state
):
    assert verify._verify_job(admission) is None
    (old_ledger,) = verification_state.glob("*.sqlite")
    stale_work = verification_state / f"job-{'1' * 32}-12345678"
    stale_work.mkdir(mode=0o700)
    (stale_work / "incomplete").touch()
    other = verification_state / "unrelated"
    other.touch()

    authority, _, _, _ = published
    replacement = authority.model_copy(update={"generation": "e" * 32})
    ready = handoff.DIRECTORY / handoff.READY
    with ready.open("rb") as handle:
        sealed = handoff._read_header(handle)
        pack = handle.read()
    replacement_seal = sealed.model_copy(update={"authority": replacement})
    header = handoff._encoded(replacement_seal)
    ready.write_bytes(handoff.MAGIC + len(header).to_bytes(4, "big") + header + pack)
    next_admission = admission.model_copy(
        update={
            "expected": replacement.expected(),
            "capsule_digest": handoff._digest(replacement_seal),
        }
    )
    verify._write_admission(next_admission)

    with pytest.raises(BuildError, match="authority was withdrawn"):
        verify._verify_job(admission)
    assert verify._verify_job(next_admission) is None
    (new_ledger,) = verification_state.glob("*.sqlite")
    assert new_ledger != old_ledger
    assert not old_ledger.exists()
    assert not stale_work.exists()
    assert other.is_file()


@pytest.mark.parametrize("authority_changed", [False, True])
def test_root_finish_rechecks_admission_before_emitting_proof(
    admission, monkeypatch, capsys, authority_changed
):
    uid, gid = os.geteuid(), os.getegid()
    current = admission
    if authority_changed:
        current = admission.model_copy(update={"release": "1.2.4"})
    monkeypatch.setattr(verify, "_identity", lambda: (uid, gid))
    monkeypatch.setattr(verify, "_require_invocation", lambda command: INVOCATION)

    locked = False

    @contextmanager
    def deployment_lock(*, timeout, create):
        nonlocal locked
        assert timeout > 0 and create is False
        locked = True
        try:
            yield
        finally:
            locked = False

    def read_current(invocation):
        assert locked
        assert invocation == INVOCATION
        return current

    monkeypatch.setattr(verify.boot, "deployment_lock", deployment_lock)
    monkeypatch.setattr(verify, "_current", read_current)
    monkeypatch.setattr(verify.os, "geteuid", lambda: 0)
    ticket = handoff.DIRECTORY / verify.ADMISSION
    if authority_changed:
        with pytest.raises(BuildError, match="authority changed"):
            verify._root_command("finish")
        assert capsys.readouterr().out == ""
        assert ticket.is_file()
    else:
        verify._root_command("finish")
        assert capsys.readouterr().out == verify.canonical_json(admission.proof()) + "\n"
        assert verify._read_admission() == admission.model_copy(update={"confirmed": True})


def test_withdrawal_after_final_worker_check_leaves_only_an_import_result(
    admission, monkeypatch, verification_state
):
    finish = Store.finish

    def withdraw_before_completion(store, *args, **kwargs):
        verify.withdraw_admission()
        return finish(store, *args, **kwargs)

    monkeypatch.setattr(Store, "finish", withdraw_before_completion)
    verify._verify_job(admission)

    with pytest.raises(FileNotFoundError):
        verify._read_admission()
    (ledger,) = verification_state.glob("*.sqlite")
    store = Store(ledger)
    try:
        (job,) = store.list_jobs()
        assert job["result"] == {"status": "capsule_imported"}
    finally:
        store.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [("invocation", "../invocation"), ("input_digest", "0"), ("capsule_digest", "g" * 64)],
)
def test_malformed_admission_is_refused(admission, field, value):
    path = handoff.DIRECTORY / verify.ADMISSION
    body = {**admission.model_dump(mode="json"), field: value}
    path.write_text(verify.canonical_json(body), encoding="utf-8")
    with pytest.raises(ValueError, match=field):
        verify._read_admission()


def test_withdrawal_during_import_cannot_record_success(admission, verification_state, monkeypatch):
    open_handoff = handoff._open_handoff

    @contextmanager
    def withdraw_after_import(*args, **kwargs):
        with open_handoff(*args, **kwargs) as request:
            verify.withdraw_admission()
            yield request

    monkeypatch.setattr(handoff, "_open_handoff", withdraw_after_import)
    with pytest.raises((BuildError, FileNotFoundError)):
        verify._verify_job(admission)

    (ledger,) = verification_state.glob("*.sqlite")
    store = Store(ledger)
    try:
        (job,) = store.list_jobs()
    finally:
        store.close()
    assert job["state"] != "succeeded"
    assert job["result"] is None
    assert not list(verification_state.glob("job-*"))
