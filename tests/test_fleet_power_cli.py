from contextlib import contextmanager
from pathlib import Path
from subprocess import CompletedProcess

from steward.cli import fleet_power, main


def test_native_fleet_cli_launches_only_the_verified_fixed_runtime(monkeypatch):
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

    monkeypatch.setattr(fleet_power, "_locked", lock)
    monkeypatch.setattr(fleet_power, "_installed_power_runtime", verify)
    monkeypatch.setattr(fleet_power.subprocess, "run", launch)
    parser = main.build_parser()
    args = parser.parse_args(["fleet", "command-target-sync"])
    monkeypatch.setattr(fleet_power.os, "geteuid", lambda: 1000)
    assert args.func(args) == 1
    assert calls == []
    monkeypatch.setattr(fleet_power.os, "geteuid", lambda: 0)
    assert args.func(args) == 0
    argv, options = calls[-1]
    assert argv == [str(python), "-I", "-B", "-m", "steward.executor.fleet_power"]
    assert options["cwd"] == "/"
    assert options["stdin"] == fleet_power.subprocess.DEVNULL
    assert options["env"] == {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
