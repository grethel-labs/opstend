from dataclasses import replace

import pytest

from steward.core.backupretention import MIN_AGE_S, RetentionItem, classify
from steward.core.backups import BackupError


def artifact(index, age, *, now, **kwargs):
    return RetentionItem(
        artifact=f"{index:032x}",
        capture_id=f"{index:064x}",
        created_at=now - age,
        complete=True,
        **kwargs,
    )


def test_keep_two_newest_and_all_younger_than_seven_days():
    now = 10_000_000
    items = [
        artifact(1, MIN_AGE_S * 4, now=now, independent_restore=True),
        artifact(2, MIN_AGE_S * 3, now=now, independent_restore=True),
        artifact(3, MIN_AGE_S - 1, now=now, independent_restore=True),
        artifact(4, 1, now=now, independent_restore=True),
    ]
    assert [d.reason for d in classify(items, now=now)] == [
        "eligible",
        "eligible",
        "newest",
        "newest",
    ]
    items.insert(2, artifact(5, MIN_AGE_S - 2, now=now, independent_restore=True))
    assert classify(items, now=now)[3].reason == "recent"


def test_protection_age_and_root_authority_all_gate_cleanup():
    now = 10_000_000
    old = artifact(1, MIN_AGE_S * 2, now=now)
    newer = [artifact(2, 20, now=now), artifact(3, 10, now=now)]
    assert classify([old, *newer], now=now)[0].reason == "missing_authority"
    assert classify([replace(old, operator_acknowledged=True), *newer], now=now)[0].eligible
    assert (
        classify([replace(old, independent_restore=True, protected=True), *newer], now=now)[
            0
        ].reason
        == "protected"
    )
    assert (
        classify([replace(old, complete=False, operator_acknowledged=True), *newer], now=now)[
            0
        ].reason
        == "protected"
    )
    assert (
        classify([replace(old, created_at=None, independent_restore=True), *newer], now=now)[
            0
        ].reason
        == "unknown_age_or_identity"
    )
    assert (
        classify([replace(old, created_at=now + 1, independent_restore=True), *newer], now=now)[
            0
        ].reason
        == "unknown_age_or_identity"
    )


@pytest.mark.parametrize(
    ("age", "reason"),
    [(MIN_AGE_S - 1, "recent"), (MIN_AGE_S, "eligible"), (MIN_AGE_S + 1, "eligible")],
)
def test_acknowledged_capture_reaches_retention_age_at_seven_days(age, reason):
    now = 10_000_000
    candidate = artifact(1, age, now=now, operator_acknowledged=True)
    newer = [artifact(2, 20, now=now), artifact(3, 10, now=now)]

    decision = classify([candidate, *newer], now=now)[0]

    assert decision.reason == reason
    assert decision.eligible is (reason == "eligible")


def test_ten_artifact_limit_counts_incomplete_and_rejects_ambiguous_state():
    now = 10_000_000
    items = [artifact(i, MIN_AGE_S + i, now=now, independent_restore=True) for i in range(10)]
    items[0] = replace(items[0], complete=False)
    decisions = classify(items, now=now)
    assert len(decisions) == 10 and not decisions[0].eligible
    assert sum(d.eligible for d in decisions) == 7
    with pytest.raises(BackupError):
        classify(items + [artifact(10, 1, now=now)], now=now)
    with pytest.raises(BackupError):
        classify(items + [items[0]], now=now)
    with pytest.raises(BackupError):
        classify([replace(items[0], artifact="../foreign")], now=now)


def test_clock_rollback_never_ages_a_capture():
    now = 10_000_000
    items = [artifact(i, MIN_AGE_S + i * 100, now=now, independent_restore=True) for i in range(3)]
    assert sum(d.eligible for d in classify(items, now=now)) == 1
    assert not any(d.eligible for d in classify(items, now=now - 1000))


def test_duplicate_capture_ids_do_not_replace_distinct_recovery_points():
    now = 10_000_000
    items = [artifact(i, MIN_AGE_S * 2 + i, now=now, independent_restore=True) for i in range(3)]
    items[1] = replace(items[1], capture_id=items[0].capture_id, created_at=items[0].created_at)
    assert not any(decision.eligible for decision in classify(items, now=now))


def test_untyped_truthy_values_cannot_grant_retention_authority():
    now = 10_000_000
    old = artifact(1, MIN_AGE_S * 2, now=now)
    newer = [artifact(2, 20, now=now), artifact(3, 10, now=now)]
    assert not classify([replace(old, independent_restore="yes"), *newer], now=now)[0].eligible
    assert not classify([replace(old, protected=None, independent_restore=True), *newer], now=now)[
        0
    ].eligible


def test_host_cli_requests_registered_retention_status(monkeypatch, capsys):
    import json
    import sys

    from steward import hostcli

    calls = []
    monkeypatch.setattr(hostcli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        hostcli,
        "call",
        lambda action, params, *, socket_path: (
            calls.append((action, params, socket_path)) or {"project_id": "notes"}
        ),
    )
    monkeypatch.setattr(sys, "argv", ["steward-host", "backup-retention-status", "notes"])
    hostcli.main()
    assert json.loads(capsys.readouterr().out) == {"project_id": "notes"}
    assert calls == [("backup_retention_status", {"project_id": "notes"}, hostcli.DEFAULT_SOCKET)]


def test_host_cli_ack_requires_explicit_flag_and_sends_exact_identity(monkeypatch, capsys):
    import json
    import sys

    from steward import hostcli

    calls = []
    monkeypatch.setattr(hostcli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        hostcli,
        "call",
        lambda action, params, **kwargs: calls.append((action, params)) or {"deleted": False},
    )
    base = ["steward-host", "backup-retention-ack", "notes", "a" * 32, "--capture-id", "b" * 64]
    monkeypatch.setattr(sys, "argv", base)
    with pytest.raises(SystemExit):
        hostcli.main()
    assert calls == []
    monkeypatch.setattr(sys, "argv", [*base, "--acknowledge-removal"])
    hostcli.main()
    assert json.loads(capsys.readouterr().out) == {"deleted": False}
    assert calls == [
        (
            "backup_retention_ack",
            {
                "project_id": "notes",
                "artifact": "a" * 32,
                "capture_id": "b" * 64,
                "acknowledge_removal": True,
            },
        )
    ]


def test_host_cli_purge_uses_exact_capture_identity(monkeypatch, capsys):
    import json
    import sys

    from steward import hostcli

    calls = []
    monkeypatch.setattr(hostcli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        hostcli,
        "call",
        lambda action, params, **kwargs: calls.append((action, params)) or {"outcome": "removed"},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["steward-host", "backup-retention-purge", "notes", "a" * 32, "--capture-id", "b" * 64],
    )
    hostcli.main()
    assert json.loads(capsys.readouterr().out) == {"outcome": "removed"}
    assert calls == [
        (
            "backup_retention_purge",
            {"project_id": "notes", "artifact": "a" * 32, "capture_id": "b" * 64},
        )
    ]


def test_host_cli_upload_cancellation_requires_explicit_abandonment(monkeypatch, capsys):
    import json
    import sys

    from steward import hostcli

    calls = []
    monkeypatch.setattr(hostcli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        hostcli,
        "call",
        lambda action, params, **_kwargs: calls.append((action, params)) or {"deleted": False},
    )
    base = ["steward-host", "backup-upload-cancel", "notes", "a" * 32, "--capture-id", "b" * 64]
    monkeypatch.setattr(sys, "argv", base)
    with pytest.raises(SystemExit):
        hostcli.main()
    assert not calls
    monkeypatch.setattr(sys, "argv", [*base, "--acknowledge-abandonment"])
    hostcli.main()
    assert json.loads(capsys.readouterr().out) == {"deleted": False}
    assert calls[0] == (
        "backup_upload_cancel",
        {
            "project_id": "notes",
            "artifact": "a" * 32,
            "capture_id": "b" * 64,
            "acknowledge_abandonment": True,
        },
    )


def test_host_cli_import_purge_requires_explicit_removal_acknowledgement(monkeypatch, capsys):
    import json
    import sys

    from steward import hostcli

    calls = []
    monkeypatch.setattr(hostcli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        hostcli,
        "call",
        lambda action, params, **_kwargs: calls.append((action, params)) or {"outcome": "removed"},
    )
    base = ["steward-host", "backup-import-purge", "notes", "a" * 32, "--capture-id", "b" * 64]
    monkeypatch.setattr(sys, "argv", base)
    with pytest.raises(SystemExit):
        hostcli.main()
    assert not calls
    monkeypatch.setattr(sys, "argv", [*base, "--acknowledge-import-removal"])
    hostcli.main()
    assert json.loads(capsys.readouterr().out) == {"outcome": "removed"}
    assert calls == [
        (
            "backup_import_purge",
            {
                "project_id": "notes",
                "artifact": "a" * 32,
                "capture_id": "b" * 64,
                "acknowledge_import_removal": True,
            },
        )
    ]


def test_host_cli_forget_requires_explicit_acknowledgement(monkeypatch, capsys):
    import json
    import sys

    from steward import hostcli

    calls = []
    monkeypatch.setattr(hostcli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        hostcli,
        "call",
        lambda action, params, **_kwargs: calls.append((action, params)) or {"forgotten": True},
    )
    base = [
        "steward-host",
        "backup-cancellation-forget",
        "notes",
        "a" * 32,
        "--capture-id",
        "b" * 64,
    ]
    monkeypatch.setattr(sys, "argv", base)
    with pytest.raises(SystemExit):
        hostcli.main()
    assert not calls
    monkeypatch.setattr(sys, "argv", [*base, "--acknowledge-forget"])
    hostcli.main()
    assert json.loads(capsys.readouterr().out) == {"forgotten": True}
    assert calls == [
        (
            "backup_cancellation_forget",
            {
                "project_id": "notes",
                "artifact": "a" * 32,
                "capture_id": "b" * 64,
                "acknowledge_forget": True,
            },
        )
    ]


def test_host_backup_status_reads_scoped_snapshot_without_executor(monkeypatch, tmp_path, capsys):
    import json
    import sys
    import time

    from steward import hostcli

    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text(
        json.dumps(
            {
                "generated_at": time.time(),
                "status_ok": True,
                "status": {"backup_enabled": False, "projects": {"notes": {}, "other": {}}},
            }
        )
    )
    monkeypatch.setattr(hostcli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        hostcli, "call", lambda *args, **kwargs: pytest.fail("unexpected executor call")
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "steward-host",
            "backup-status",
            "--project",
            "notes",
            "--controller-export",
            str(snapshot),
        ],
    )
    hostcli.main()
    result = json.loads(capsys.readouterr().out)
    assert result["enabled"] is False and result["freshness"] == "fresh"
    assert [record["project"] for record in result["projects"]] == ["notes"]


def test_host_backup_schedule_sends_only_project_and_expected_revision(monkeypatch, capsys):
    import json
    import sys

    from steward import hostcli

    requests = []
    monkeypatch.setattr(hostcli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        hostcli,
        "call",
        lambda action, params, **kw: requests.append((action, params, kw)) or {"uploaded": False},
    )
    monkeypatch.setattr(
        sys, "argv", ["steward-host", "backup-schedule", "notes", "--expected-revision", "a" * 64]
    )
    hostcli.main()
    assert json.loads(capsys.readouterr().out) == {"uploaded": False}
    assert requests == [
        (
            "backup_schedule",
            {"project_id": "notes", "expected_revision": "a" * 64},
            {"socket_path": hostcli.DEFAULT_SOCKET, "timeout": 900},
        )
    ]
