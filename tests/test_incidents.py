"""Durable incident record, legal transitions and the nft containment ruleset (L07/L08)."""

import os

import pytest

from steward.core import incidents as inc
from steward.executor.containment_host import parse_ports, render_containment


def new(application="shop", opened_at=1000.0, **kw):
    value = dict(
        id=inc.incident_id(application, opened_at),
        application=application,
        seq=1,
        phase="notice",
        opened_at=opened_at,
        deadline=opened_at + 3600,
        config_revision="a" * 64,
        findings=[{"service": "database", "advisory": "CVE-2026-0001", "verdict": "critical"}],
        exposers=["frontend"],
        ports=[21003],
    )
    return inc.Incident.model_validate(value | kw)


@pytest.fixture
def store(tmp_path):
    return inc.IncidentStore(tmp_path / "incidents")


def walk(store, incident, *phases):
    for phase in phases:
        incident = store.transition(incident, phase, 2000.0)
    return incident


def test_identity_is_application_scoped_and_stable():
    assert inc.incident_id("shop", 1.5) == inc.incident_id("shop", 1.5)
    assert inc.incident_id("shop", 1.5) != inc.incident_id("shop", 2.5)
    assert inc.incident_id("shop", 1.5) != inc.incident_id("blog", 1.5)
    assert new().correlation_id == new().id


def test_full_path_and_restart_keep_deadline_and_phase(store):
    opened = store.open(new())
    assert opened.history[0].phase == "notice"
    reloaded = inc.IncidentStore(store.dir).get("shop")  # a new process
    assert (reloaded.phase, reloaded.deadline, reloaded.id) == ("notice", 4600.0, opened.id)
    done = walk(
        store,
        reloaded,
        "disconnecting",
        "disconnected",
        "backup_pending",
        "backup_verified",
        "stopping",
        "quarantined",
        "fix_verification",
        "reactivating",
        "reactivated",
    )
    assert done.phase == "reactivated" and store.get("shop") is None
    assert store.closed("shop").id == done.id
    assert [s.phase for s in done.history][-1] == "reactivated"


@pytest.mark.parametrize(
    ("start", "target"),
    [
        ("notice", "quarantined"),
        ("notice", "backup_pending"),
        ("disconnected", "stopping"),  # no stop without the backup phases
        ("backup_pending", "stopping"),
        ("backup_failed", "stopping"),
        ("backup_failed", "quarantined"),
        ("stopping", "reactivated"),
        ("quarantined", "reactivating"),  # no route restore without fix verification
        ("quarantined", "reactivated"),
        ("quarantined", "resolved"),
        ("fix_verification", "reactivated"),
        ("reactivated", "notice"),
    ],
)
def test_illegal_transitions_are_refused(store, start, target):
    path = {
        "notice": [],
        "disconnected": ["disconnecting", "disconnected"],
        "backup_pending": ["disconnecting", "disconnected", "backup_pending"],
        "backup_failed": ["disconnecting", "disconnected", "backup_pending", "backup_failed"],
        "stopping": [
            "disconnecting", "disconnected", "backup_pending", "backup_verified", "stopping",
        ],
        "quarantined": [
            "disconnecting", "disconnected", "backup_pending", "backup_verified", "stopping",
            "quarantined",
        ],
        "fix_verification": [
            "disconnecting", "disconnected", "backup_pending", "backup_verified", "stopping",
            "quarantined", "fix_verification",
        ],
        "reactivated": [
            "disconnecting", "disconnected", "backup_pending", "backup_verified", "stopping",
            "quarantined", "fix_verification", "reactivating", "reactivated",
        ],
    }  # fmt: skip
    current = walk(store, store.open(new()), *path[start])
    if start == "reactivated":
        with pytest.raises(inc.IncidentError):  # closed: the record is gone
            store.transition(current, target, 3000.0)
        return
    with pytest.raises(inc.IncidentError) as error:
        store.transition(current, target, 3000.0)
    assert error.value.error_class == "illegal_transition"
    assert store.get("shop").phase == start


def test_failure_phases_retry_and_a_failed_backup_stays_contained(store):
    current = walk(store, store.open(new()), "disconnecting", "disconnected", "backup_pending")
    current = store.transition(current, "backup_failed", 2100.0, error_class="unavailable")
    assert current.contained and current.error_class == "unavailable"
    current = walk(store, current, "backup_pending", "backup_verified", "stopping", "stop_failed")
    assert current.contained
    failed = walk(store, store.get("shop"), "stopping", "quarantined", "fix_verification")
    failed = walk(store, failed, "reactivating", "reactivation_failed")
    assert failed.contained  # a failed route restore never lifts the block
    assert walk(store, failed, "reactivating").phase == "reactivating"


def test_notice_incident_is_not_contained_and_resolves_only_from_notice(store):
    opened = store.open(new())
    assert not opened.contained
    resolved = store.transition(opened, "resolved", 1500.0)
    assert store.get("shop") is None and store.closed("shop").phase == "resolved"
    again = store.open(new(opened_at=9000.0))  # a new incident after a closed one
    assert again.id != resolved.id


def test_stale_writers_and_second_open_are_rejected(store):
    first = store.open(new())
    store.update(first, exploited=True)
    with pytest.raises(inc.IncidentError) as error:
        store.transition(first, "disconnecting", 2000.0)  # stale sequence
    assert error.value.error_class == "stale_incident"
    with pytest.raises(inc.IncidentError) as error:
        store.open(new(opened_at=5000.0))
    assert error.value.error_class == "exists"
    with pytest.raises(inc.IncidentError):
        store.open(new(application="blog", phase="disconnected", opened_at=1.0))


def test_corrupt_unsafe_or_foreign_records_fail_closed(store):
    store.open(new())
    path = store.dir / "shop.json"
    path.write_text("{not json")
    with pytest.raises(inc.IncidentError) as error:
        store.get("shop")
    assert error.value.error_class == "corrupt_record"
    with pytest.raises(inc.IncidentError):
        store.all()  # never skipped: unknown state is not "no incident"
    path.write_text(new(application="blog").model_dump_json())
    with pytest.raises(inc.IncidentError):
        store.get("shop")  # content names another application
    path.write_text(new().model_dump_json())
    path.chmod(0o644)
    with pytest.raises(inc.IncidentError) as error:
        store.get("shop")
    assert error.value.error_class == "unsafe_record"
    with pytest.raises(inc.IncidentError):
        store.get("../etc")
    (store.dir / "stray.txt").write_text("x")
    path.chmod(0o600)
    with pytest.raises(inc.IncidentError) as error:
        store.all()
    assert error.value.error_class == "unexpected_file"


def test_unsafe_directory_is_refused(tmp_path):
    directory = tmp_path / "incidents"
    directory.mkdir(mode=0o755)
    with pytest.raises(inc.IncidentError):
        inc.IncidentStore(directory).open(new())


def test_leftover_terminal_record_is_archived_on_next_open(store):
    done = walk(
        store,
        store.open(new()),
        "disconnecting", "disconnected", "backup_pending", "backup_verified", "stopping",
        "quarantined", "fix_verification", "reactivating",
    )  # fmt: skip
    # Simulate a crash after the terminal write but before the unlink.
    closed = done.model_copy(update={"phase": "reactivated", "seq": done.seq + 1})
    store._write(store._path("shop"), closed)
    assert store.contained() == []
    reopened = store.open(new(opened_at=7000.0))
    assert reopened.phase == "notice" and store.closed("shop").phase == "reactivated"


def test_summary_is_bounded_and_secret_free(store):
    data = inc.summary(store.open(new()))
    assert set(data) <= {
        "id", "application", "phase", "opened_at", "deadline", "exploited", "on_critical",
        "escalated_at", "exposers", "findings", "disconnected_at", "backup", "error_class",
        "history",
    }  # fmt: skip
    assert os.fspath(store.dir) not in str(data)


# ---- nft ruleset ---------------------------------------------------------------------


def test_ruleset_names_only_proxy_loopback_and_validated_ports():
    text = render_containment([21003, 21001])
    assert (
        "table inet steward_containment" in text and "delete table inet steward_containment" in text
    )
    assert 'meta skuid "steward-proxy" oifname "lo" tcp dport { 21001, 21003 }' in text
    assert "reject with tcp reset" in text
    assert 'iifname != "lo" tcp dport { 21001, 21003 } counter drop' in text
    # nothing that could touch ssh, the host's other services or the main table
    for forbidden in ("dport 22", "tcp dport 80", "table inet steward {", "flush", "policy drop"):
        assert forbidden not in text
    assert parse_ports(text) == {21001, 21003}
    assert parse_ports("tcp dport 21005 counter drop") == {21005}


@pytest.mark.parametrize(
    "ports", [[], [22], [80, 21001], [19999], [30000], [21001, 21001], ["21001"]]
)
def test_ruleset_rejects_unsafe_ports(ports):
    with pytest.raises(ValueError):
        render_containment(ports)
