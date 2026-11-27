from contextlib import contextmanager
from pathlib import Path
from subprocess import CompletedProcess
from uuid import uuid4

from steward.cli import fleet_ownership, main
from steward.core.fleet_ownership import LocalOwnershipRequest


def test_target_handoff_uses_fixed_signed_root_runtime(monkeypatch):
    calls = []
    python = Path("/signed/releases/active/venv/bin/python")

    @contextmanager
    def lock():
        calls.append("locked")
        yield
        calls.append("unlocked")

    def verify():
        assert calls == ["locked"]
        calls.append("verified")
        return {}, {}, python

    def launch(argv, **options):
        assert calls == ["locked", "verified", "unlocked"]
        calls.append((argv, options))
        return CompletedProcess(argv, 0)

    monkeypatch.setattr(fleet_ownership, "_locked", lock)
    monkeypatch.setattr(fleet_ownership, "_installed_power_runtime", verify)
    monkeypatch.setattr(fleet_ownership.subprocess, "run", launch)
    parser = main.build_parser()
    transfer, digest = uuid4().hex, "c1" * 32
    args = parser.parse_args(
        [
            "fleet",
            "ownership-target",
            "confirm",
            "--transition-id",
            transfer,
            "--digest",
            digest,
        ]
    )
    monkeypatch.setattr(fleet_ownership.os, "geteuid", lambda: 1000)
    assert args.func(args) == 1
    assert calls == []
    monkeypatch.setattr(fleet_ownership.os, "geteuid", lambda: 0)
    assert args.func(args) == 0
    argv, options = calls[-1]
    assert argv == [str(python), "-I", "-B", "-m", "steward.executor.fleet_ownership"]
    assert options["cwd"] == "/"
    assert options["env"] == {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    assert LocalOwnershipRequest.model_validate_json(options["input"]) == LocalOwnershipRequest(
        action="confirm", transition_id=transfer, digest=digest
    )
