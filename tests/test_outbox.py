from concurrent.futures import ThreadPoolExecutor

import pytest

from steward.core.outbox import Outbox


def enqueue(box, key="event:1", destination="ops"):
    return box.enqueue("webhook", destination, key, {"summary": "redacted"}, now=10)


def test_deduplication_survives_restart_and_delivery(tmp_path):
    path = tmp_path / "outbox.db"
    box = Outbox(path)
    assert enqueue(box)
    delivery = box.claim(now=10)
    assert box.acknowledge(delivery, now=11)
    restarted = Outbox(path)
    assert not enqueue(restarted)
    assert restarted.claim(now=100) is None
    assert enqueue(restarted, destination="other")
    assert restarted.counts() == {"delivered": 1, "pending": 1}


def test_expired_lease_recovers_without_stale_acknowledgement(tmp_path):
    box = Outbox(tmp_path / "outbox.db")
    enqueue(box)
    first = box.claim(now=10, lease_s=5)
    assert box.claim(now=14) is None
    assert not box.acknowledge(first, now=15)
    second = box.claim(now=15)
    assert second.id == first.id and second.attempt == 2 and second.lease != first.lease
    assert not box.acknowledge(first, now=16)
    assert not box.retry(first, now=16)
    assert box.acknowledge(second, now=16)


def test_retry_backoff_rate_limit_and_exhaustion(tmp_path):
    box = Outbox(tmp_path / "outbox.db")
    enqueue(box)
    first = box.claim(now=10)
    assert box.retry(first, now=11, retry_after_s=30)
    assert box.claim(now=40) is None
    second = box.claim(now=41)
    assert box.retry(second, now=42, max_attempts=2)
    assert box.claim(now=1000) is None
    assert box.counts() == {"failed": 1}


def test_permanent_failure_and_pruning_preserve_pending_messages(tmp_path):
    box = Outbox(tmp_path / "outbox.db")
    enqueue(box)
    assert box.retry(box.claim(now=10), now=11, permanent=True)
    enqueue(box, key="event:2")
    assert box.prune(finished_before=12) == 1
    assert box.counts() == {"pending": 1}
    assert enqueue(box)  # explicit retention boundary also ends deduplication


def test_concurrent_workers_cannot_claim_same_message(tmp_path):
    box = Outbox(tmp_path / "outbox.db")
    for i in range(12):
        enqueue(box, key=str(i))
    with ThreadPoolExecutor(max_workers=4) as workers:
        deliveries = list(workers.map(lambda _: box.claim(now=10), range(16)))
    ids = [d.id for d in deliveries if d is not None]
    assert len(ids) == len(set(ids)) == 12


def test_payload_and_identity_limits(tmp_path):
    box = Outbox(tmp_path / "outbox.db")
    with pytest.raises(ValueError):
        box.enqueue("webhook", "ops", "k", {"text": "x" * 20000}, now=10)
    with pytest.raises(ValueError):
        box.enqueue("", "ops", "k", {}, now=10)
    assert box.counts() == {}


def test_queue_identity_persists_and_separates_independent_hosts(tmp_path):
    path = tmp_path / "queue.db"
    first = Outbox(path).identity
    assert Outbox(path).identity == first
    assert Outbox(tmp_path / "other.db").identity != first
