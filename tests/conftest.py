from __future__ import annotations

import copy
import json
import os
import threading
from pathlib import Path

import pytest
import yaml

from run_guardrails import load_checks
from steward.core import render
from steward.core.config import parse_config
from steward.executor import server as executor_server

ROOT = Path(__file__).resolve().parents[1]


def pytest_addoption(parser):
    parser.addoption(
        "--exclude-guardrails",
        action="store_true",
        help="Run the rest of the suite after a successful dedicated guardrail run",
    )


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--exclude-guardrails"):
        return

    _, selectors = load_checks()
    guardrails = set(selectors)
    remaining, deselected = [], []
    for item in items:
        node, _, _ = item.nodeid.partition("[")
        if node in guardrails:
            deselected.append(item)
        else:
            remaining.append(item)
    items[:] = remaining
    config.hook.pytest_deselected(items=deselected)


@pytest.fixture
def raw_config() -> dict:
    data = yaml.safe_load((ROOT / "examples" / "server.api.yml").read_text())
    return copy.deepcopy(data)


@pytest.fixture
def cfg(raw_config):
    return parse_config(raw_config)


class FakeHost:
    """In-memory stand-in for the real host. Records mutations."""

    def __init__(self):
        self.units = {"notes.service": "active", "proxy.service": "active"}
        self.health_ok = True
        self.firewall = True
        self.killed = False
        self.calls: list[tuple] = []
        self.journal_entries: list[dict] = []  # raw journald JSON, cursors sort as strings
        self.journal_calls: list[tuple] = []
        self.secrets: tuple[str, ...] = ()
        self.container_info = {
            "Config": {"User": "10001:10001"},
            "EffectiveCaps": None,
            "AppArmorProfile": "containers-default-0.62.0",
            "HostConfig": {
                "ReadonlyRootfs": True,
                "SecurityOpt": ["no-new-privileges"],
                "Privileged": False,
                "NetworkMode": "pasta",
                "Memory": 128 * 2**20,
                "PidsLimit": 64,
            },
        }

    def system_unit(self, unit):
        return {"unit": unit, "load": "loaded", "active": "active", "sub": "running"}

    def user_unit(self, user, unit):
        return {
            "unit": unit,
            "load": "loaded",
            "active": self.units.get(unit, "inactive"),
            "sub": "running",
            "restarts": 0,
        }

    def service_user_uid(self, user):
        import os

        return os.geteuid()

    def group_users_within_systemd_slices(self, users):
        return bool(users)

    def restart_user_unit(self, user, unit):
        self.calls.append(("restart", user, unit))
        self.units[unit] = "active"
        self.health_ok = True
        return True, ""

    def container(self, user, name):
        return self.container_info

    def http_health(self, port, path, timeout):
        return {"ok": True, "status": 200} if self.health_ok else {"ok": False, "status": 503}

    def firewall_loaded(self):
        return self.firewall

    def firewall_reassert(self):
        self.calls.append(("firewall_reassert",))
        self.firewall = True
        return True, ""

    def failed_units(self):
        return []

    def resources(self):
        return {
            "memory_total_mb": 4000,
            "memory_available_mb": 3000,
            "disk_total_mb": 40000,
            "disk_free_mb": 30000,
        }

    def reboot_required(self):
        return False

    def journal(self, matches, cursor, limit, skip_to_end):
        self.journal_calls.append((tuple(matches), cursor, limit, skip_to_end))
        if skip_to_end:
            last = self.journal_entries[-1]["__CURSOR"] if self.journal_entries else cursor
            return [], last, False
        pending = [e for e in self.journal_entries if cursor is None or e["__CURSOR"] > cursor]
        batch = pending[:limit]
        return batch, batch[-1]["__CURSOR"] if batch else cursor, len(pending) > limit

    def configured_image_identity(self, image):
        return None

    def inventory(self):
        return {
            "os_id": "ubuntu",
            "os_version": "26.04",
            "running_kernel": "7.0.0-test",
            "packages": [
                {
                    "name": "libssl3",
                    "version": "3.5.1-1ubuntu2",
                    "architecture": "amd64",
                    "source_name": "openssl",
                    "source_version": "3.5.1-1ubuntu2",
                }
            ],
        }

    def known_secret_values(self):
        return self.secrets

    def deployment_rollbacks_quiescent(self):
        return True

    def kill_switch(self):
        return self.killed


@pytest.fixture
def executor(tmp_path, cfg):
    """Executor with a fake host; the test process is registered as role `api`."""
    registry = render.render_registry(cfg)
    registry["peers"] = {"api": os.getuid(), "controller": 4242, "collector": 4343}
    registry_path = tmp_path / "executor.json"
    registry_path.write_text(json.dumps(registry))
    registry_path.chmod(0o600)
    (tmp_path / "state").mkdir()
    ex = executor_server.Executor(
        registry_path=str(registry_path),
        state_dir=str(tmp_path / "state"),
        audit_path=str(tmp_path / "audit.jsonl"),
        lock_dir=str(tmp_path / "locks"),
        host=FakeHost(),
    )
    ex.registry_file = registry_path
    return ex


@pytest.fixture
def executor_socket(tmp_path, executor, monkeypatch):
    path = str(tmp_path / "ex.sock")
    listening = threading.Event()
    bind = executor_server.ipc.bind

    def ready_bind(*args, **kwargs):
        server = bind(*args, **kwargs)
        listening.set()
        return server

    monkeypatch.setattr(executor_server.ipc, "bind", ready_bind)
    thread = threading.Thread(
        target=executor_server.serve, args=(executor, path, None), daemon=True
    )
    thread.start()
    assert listening.wait(2), "executor socket did not start listening"
    return path
