"""An independent rollback timer or service must block deployment recovery."""

import pytest

from steward.executor.host import Host


@pytest.mark.parametrize(
    ("replace", "clear"),
    [
        ({}, True),
        (
            {
                "steward-ssh-rollback.timer": "LoadState=loaded\nActiveState=active\nSubState=waiting\n"
            },
            False,
        ),
        (
            {
                "steward-firewall-rollback.service": "LoadState=loaded\nActiveState=activating\nSubState=start\nMainPID=12\nControlGroup=/x\n"
            },
            False,
        ),
        (
            {
                "steward-ssh-rollback.service": "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlGroup=/x\n"
            },
            False,
        ),
        (
            {
                "steward-firewall-rollback.timer": "LoadState=error\nActiveState=inactive\nSubState=dead\n"
            },
            False,
        ),
        (
            {
                "steward-ssh-rollback.service": "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
            },
            False,
        ),
        (
            {
                "steward-ssh-rollback.timer": "LoadState=not-found\nActiveState=failed\nSubState=failed\n"
            },
            False,
        ),
        (
            {
                "steward-ssh-rollback.timer": "LoadState=loaded\nActiveState=inactive\nSubState=dead\nJob=42\n"
            },
            False,
        ),
        ({"steward-firewall-rollback.service": None}, False),
    ],
)
def test_rollback_guard_fails_closed_on_busy_or_unknown_systemd(monkeypatch, replace, clear):
    host = Host()
    calls = []

    def run(argv, timeout=30):
        unit = argv[2]
        calls.append(unit)
        if unit in replace:
            if replace[unit] is None:
                return 1, "unavailable"
            value = replace[unit]
            return 0, value if "Job=" in value else value + "Job=\n"
        suffix = "MainPID=0\nControlGroup=\n" if unit.endswith(".service") else ""
        return 0, "LoadState=not-found\nActiveState=inactive\nSubState=dead\nJob=\n" + suffix

    monkeypatch.setattr(host, "_run", run)
    assert host.deployment_rollbacks_quiescent() is clear
    if clear:
        assert len(calls) == 4
