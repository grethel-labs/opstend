import pytest

from steward.core.audit import AuditLog
from steward.core.store import ConflictError, Store


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "db.sqlite")


def test_revision_commit_requires_current_head(store):
    first = store.commit_revision({"a": 1}, parent=None, author="x", source="ui")
    second = store.commit_revision({"a": 2}, parent=first, author="x", source="ui")
    with pytest.raises(ConflictError) as exc:
        store.commit_revision({"a": 3}, parent=first, author="y", source="ui")
    assert exc.value.head == second
    assert store.head() == second


def test_applied_revision_does_not_hide_pending_ui_revision(store):
    applied = store.record_applied({"a": 1})
    assert store.head() == applied == store.applied()
    pending = store.commit_revision({"a": 2}, parent=applied, author="x", source="ui")
    store.record_applied({"a": 1})
    assert store.head() == pending and store.applied() == applied
    newer = store.record_applied({"a": 5})
    assert store.applied() == newer and store.head() == pending  # still visible as pending


def test_idempotency_key_returns_the_same_job(store):
    job, created = store.enqueue("k", "t", {}, idempotency_key="key-1", created_by="x")
    again, created_again = store.enqueue("k", "t", {}, idempotency_key="key-1", created_by="x")
    assert created and not created_again and job["id"] == again["id"]


def test_no_two_running_jobs_for_one_target(store):
    store.enqueue("k", "project-a", {}, idempotency_key="a1", created_by="x", now=1)
    store.enqueue("k", "project-a", {}, idempotency_key="a2", created_by="x", now=2)
    store.enqueue("k", "project-b", {}, idempotency_key="b1", created_by="x", now=3)
    first = store.claim("w1", now=10)
    second = store.claim("w2", now=10)
    assert first["target"] == "project-a" and second["target"] == "project-b"
    assert store.claim("w3", now=10) is None
    store.finish(first["id"], "w1", ok=True, now=11)
    assert store.claim("w3", now=12)["idempotency_key"] == "a2"


def test_retry_uses_backoff_and_stops_at_limit(store):
    store.enqueue("k", "t", {}, idempotency_key="r", created_by="x", max_attempts=2, now=0)
    job = store.claim("w", now=0)
    assert store.finish(job["id"], "w", ok=False, error="boom", retryable=True, now=0) == "queued"
    assert store.claim("w", now=1) is None  # backoff not elapsed
    job = store.claim("w", now=10)
    assert job["attempts"] == 2
    assert store.finish(job["id"], "w", ok=False, error="boom", retryable=True, now=10) == "failed"


def test_non_retryable_failure_is_final(store):
    store.enqueue("k", "t", {}, idempotency_key="n", created_by="x", now=0)
    job = store.claim("w", now=0)
    assert store.finish(job["id"], "w", ok=False, error="denied", now=0) == "failed"


def test_lost_lease_cannot_complete_and_restart_reconciles(store):
    store.enqueue("k", "t", {}, idempotency_key="l", created_by="x", max_attempts=2, now=0)
    job = store.claim("dead-worker", lease_s=60, now=0)
    assert store.reconcile(now=30) == []  # lease still valid
    assert store.reconcile(now=100) == [job["id"]]
    assert store.finish(job["id"], "dead-worker", ok=True, now=101) is None
    retry = store.claim("w2", lease_s=60, now=101)
    assert retry["attempts"] == 2
    store.reconcile(now=500)
    final = store.get_job(job["id"])
    assert final["state"] == "failed" and "retry limit" in final["error"]


def test_heartbeat_extends_lease(store):
    store.enqueue("k", "t", {}, idempotency_key="h", created_by="x", now=0)
    job = store.claim("w", lease_s=60, now=0)
    assert store.heartbeat(job["id"], "w", lease_s=60, now=50)
    assert store.reconcile(now=100) == []
    assert not store.heartbeat(job["id"], "other", now=60)


def test_audit_chain_detects_tampering(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for index in range(5):
        log.append("event", n=index)
    assert log.verify() == (True, 5)
    lines = log.path.read_text().splitlines()
    log.path.write_text(
        "\n".join([lines[0], lines[1].replace('"n": 1', '"n": 9'), *lines[2:]]) + "\n"
    )
    assert log.verify() == (False, 1)
    log.path.write_text("\n".join([lines[0], *lines[2:]]) + "\n")  # record removed
    assert log.verify() == (False, 1)


def test_audit_refuses_symlink(tmp_path):
    target = tmp_path / "elsewhere"
    target.write_text("")
    (tmp_path / "audit.jsonl").symlink_to(target)
    with pytest.raises(OSError):
        AuditLog(tmp_path / "audit.jsonl").append("event")


def test_expired_owner_cannot_reanimate_or_finish_before_reconciliation(store):
    store.enqueue("scan", "host", {}, idempotency_key="expired", created_by="scanner", now=0)
    job = store.claim("old", lease_s=10, now=0)
    assert not store.heartbeat(job["id"], "old", now=10)
    assert store.finish(job["id"], "old", ok=True, now=10) is None
    assert store.reconcile(now=10) == [job["id"]]
    retry = store.claim("new", lease_s=10, now=10)
    assert retry["attempts"] == 2
    assert not store.heartbeat(job["id"], "old", now=11)
    assert store.finish(job["id"], "old", ok=True, now=11) is None
    assert store.finish(job["id"], "new", ok=True, now=11) == "succeeded"


@pytest.mark.parametrize("lease", [0, -1, float("inf"), float("nan")])
def test_invalid_lease_durations_cannot_reserve_a_job(store, lease):
    store.enqueue("scan", "host", {}, idempotency_key="lease", created_by="scanner", now=0)
    with pytest.raises(ValueError, match="positive"):
        store.claim("worker", lease_s=lease, now=0)
    job = store.claim("worker", lease_s=10, now=0)
    with pytest.raises(ValueError, match="positive"):
        store.heartbeat(job["id"], "worker", lease_s=lease, now=1)


def test_job_capacity_is_atomic_and_preserves_idempotent_existing_jobs(store):
    from steward.core.store import CapacityError

    first, created = store.enqueue("k", "t", {}, idempotency_key="one", created_by="x", max_total=1)
    assert created
    existing, created = store.enqueue(
        "k", "t", {}, idempotency_key="one", created_by="x", max_total=1
    )
    assert not created and existing["id"] == first["id"]
    with pytest.raises(CapacityError):
        store.enqueue("k", "t", {}, idempotency_key="two", created_by="x", max_total=1)
    assert store.claim("worker")["id"] == first["id"]
    assert len(store.list_jobs()) == 1


def test_concurrent_capacity_admission_never_exceeds_limit(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from steward.core.store import CapacityError

    path = tmp_path / "bounded.sqlite"
    stores = [Store(path), Store(path)]
    barrier = Barrier(2)

    def submit(pair):
        index, store = pair
        barrier.wait()
        try:
            store.enqueue(
                "backup_upload",
                "notes",
                {},
                idempotency_key=str(index),
                created_by="backup",
                max_total=1,
            )
            return "accepted"
        except CapacityError:
            return "full"
        finally:
            store.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(submit, enumerate(stores)))
    assert sorted(outcomes) == ["accepted", "full"]
    assert len(stores[0].list_jobs()) == 1
