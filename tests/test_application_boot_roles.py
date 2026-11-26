import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ANSIBLE = Path(__file__).resolve().parents[1] / "ansible"
ROLES = ANSIBLE / "roles"
SYSTEM_UNITS = "/etc/systemd/system"
BOOT_AUTHORITY = "/var/lib/steward/application-boot.json"
BOOT_HOLD = "/run/steward-applications/hold"
BOOT_MANIFEST = "/var/lib/steward/application-units.json"
LEGACY_UID = 20000


def tasks(role, name):
    return yaml.safe_load((ROLES / role / "tasks" / f"{name}.yml").read_text())


def sandbox_tasks(tasks_to_run, root, shim):
    """Keep the production Ansible conditions and rendering, and isolate host mutations."""
    output = []
    for original_task in tasks_to_run:
        task = {
            key: (
                json.loads(
                    json.dumps(value)
                    .replace(SYSTEM_UNITS, str(root / "system"))
                    .replace(BOOT_AUTHORITY, str(root / "application-boot.json"))
                    .replace(BOOT_HOLD, str(root / "hold"))
                    .replace(BOOT_MANIFEST, str(root / "application-units.json"))
                )
                if isinstance(value, (dict, list, str))
                else value
            )
            for key, value in original_task.items()
        }
        if module := task.get("ansible.builtin.command"):
            if isinstance(module["argv"], str):
                module["argv"] = module["argv"].replace(
                    "'/opt/steward/current/venv/bin/python', '-m', 'steward.application_boot'",
                    ", ".join(repr(value) for value in (sys.executable, str(shim), "coordinator")),
                )
            else:
                module["argv"][:3] = [sys.executable, str(shim), "coordinator"]
        if module := task.pop("ansible.builtin.systemd_service", None):
            task["ansible.builtin.command"] = {
                "argv": [sys.executable, str(shim), "systemd", json.dumps(module)]
            }
            task["changed_when"] = False
        for name in ("file", "copy", "template"):
            if module := task.get(f"ansible.builtin.{name}"):
                module.pop("owner", None)
                module.pop("group", None)
                if name == "template":
                    module["src"] = str(ROLES / "verify" / "templates" / module["src"])
        output.append(task)
    return output


@pytest.fixture
def ansible_sandbox(tmp_path):
    executable = Path(sys.executable).parent / "ansible-playbook"
    if not executable.exists():
        pytest.skip("controller Ansible environment is not installed")
    system = tmp_path / "system"
    system.mkdir()
    shim = tmp_path / "sandbox.py"
    log = tmp_path / "operations.jsonl"
    shim.write_text(
        "import json, pathlib, sys\n"
        "component, *arguments = sys.argv[1:]\n"
        "data = sys.stdin.read() if component == 'coordinator' and arguments[0] == 'publish' else ''\n"
        f"with pathlib.Path({str(log)!r}).open('a') as log:\n"
        "    log.write(json.dumps([component, arguments, json.loads(data) if data else None]))\n"
        "    log.write('\\n')\n"
        "print(json.dumps({'changed': False}))\n"
    )

    def run(vars_, *, check=False):
        site = yaml.safe_load((ANSIBLE / "playbooks" / "site.yml").read_text())
        assert site[0]["pre_tasks"][1]["ansible.builtin.import_role"]["name"] == "preflight"
        before_roles = next(
            task["when"]
            for task in site[1]["pre_tasks"]
            if task.get("ansible.builtin.include_role", {}).get("tasks_from")
            == "application-boot-inhibit.yml"
        )
        verify = tasks("verify", "main")
        publish = next(
            task
            for task in verify
            if task.get("ansible.builtin.include_tasks") == "application-boot.yml"
        )
        cleanup = next(
            task
            for task in verify
            if task.get("ansible.builtin.include_tasks") == "application-boot-cleanup.yml"
        )
        manager = next(
            task
            for task in tasks("workloads", "applications")
            if task.get("ansible.builtin.include_tasks") == "application-boot-managers.yml"
        )
        steps = [
            (before_roles, "identities", "application-boot-inhibit"),
            (["not ansible_check_mode", manager["when"]], "workloads", "application-boot-managers"),
            (publish["when"], "verify", "application-boot"),
            (cleanup["when"], "verify", "application-boot-cleanup"),
        ]
        play = tmp_path / "site-fixture.yml"
        play.write_text(
            yaml.safe_dump(
                [
                    {
                        "hosts": "localhost",
                        "gather_facts": False,
                        "vars": vars_,
                        "tasks": [
                            {
                                "block": sandbox_tasks(tasks(role, filename), tmp_path, shim),
                                "when": condition,
                            }
                            for condition, role, filename in steps
                        ],
                    }
                ]
            )
        )
        log.unlink(missing_ok=True)
        env = os.environ.copy()
        env.update(
            ANSIBLE_CONFIG=str(ANSIBLE / "ansible.cfg"),
            ANSIBLE_LOCAL_TEMP=str(tmp_path / "ansible-local"),
            ANSIBLE_NOCOLOR="1",
            ANSIBLE_PIPELINING="true",
            ANSIBLE_ALLOW_BROKEN_CONDITIONALS="false",
        )
        result = subprocess.run(
            [
                str(executable),
                "-i",
                "localhost,",
                "-c",
                "local",
                str(play),
                *(["--check"] if check else []),
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        operations = (
            [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        )
        return result.stdout, operations

    return system, run


@pytest.mark.parametrize("shared", [False, True])
def test_real_ansible_authorizes_only_active_candidate_managers(ansible_sandbox, shared):
    system, run = ansible_sandbox
    services = [
        {"user": "db", "deploy": True},
        {"user": "db" if shared else "web", "deploy": True},
        {"user": "db" if shared else "inactive", "deploy": False},
    ]
    generation_inputs = {
        "revision": "config",
        "release": {"version": "1.0.0", "files": {"artifact": "content-sha"}},
    }
    variables = {
        "steward_applications": [
            {"isolation": "shared" if shared else "separate", "services": services}
        ],
        "steward_uids": {"db": 30000, "web": 30001, "inactive": 30002, "legacy": LEGACY_UID},
        "steward_config_revision": generation_inputs["revision"],
        "steward_release": generation_inputs["release"],
        "steward_nftables": "a verified firewall\n",
    }
    if shared:
        # Resume a first deployment that acquired its hold before installing the unit.
        (system.parent / "hold").touch()
    _, operations = run(variables)
    expected_uids = {30000} if shared else {30000, 30001}
    assert {
        int(path.name.split("@")[1].split(".")[0]) for path in system.glob("user@*.service.d")
    } == (expected_uids)
    for uid in expected_uids:
        ordering = (system / f"user@{uid}.service.d/90-steward-applications.conf").read_text()
        assert "After=steward-firewall.service\n" in ordering
        assert "BindsTo=steward-firewall.service\n" in ordering
        assert "[Install]" not in ordering

    unit = (system / "steward-applications.service").read_text().splitlines()
    assert "After=steward-firewall.service" in unit
    assert {line for line in unit if line.startswith("After=user@")} == {
        f"After=user@{uid}.service" for uid in expected_uids
    }
    assert "BindsTo=steward-firewall.service" in unit
    assert f"After=user@{LEGACY_UID}.service" not in unit
    assert "WantedBy=multi-user.target" in unit
    assert "Type=oneshot" in unit and "RemainAfterExit=yes" in unit
    for directive, operation in (
        ("ExecStart", "start"),
        ("ExecStop", "stop"),
        ("ExecStopPost", "recover-start"),
    ):
        assert (
            f"{directive}=/opt/steward/current/venv/bin/python -m steward.application_boot {operation}"
            in unit
        )

    generation = hashlib.sha256(json.dumps(generation_inputs, sort_keys=True).encode()).hexdigest()
    expected_publish = [
        "coordinator",
        ["publish", generation],
        {
            **generation_inputs,
            "source": hashlib.sha256(variables["steward_nftables"].encode()).hexdigest(),
        },
    ]
    inhibit = ["coordinator", ["inhibit", generation], None]
    reload = ["systemd", ['{"daemon_reload": true}'], None]
    expected_last = [
        reload,
        expected_publish,
        ["systemd", ['{"name": "steward-applications.service", "state": "started"}'], None],
        ["systemd", ['{"name": "steward-applications.service", "enabled": true}'], None],
    ]
    assert operations == [*([inhibit, reload] if shared else [reload, inhibit]), *expected_last]

    if not shared:
        output, repeat = run(variables)
        assert repeat == [inhibit, reload, *expected_last]
        assert "changed=0" in output


def test_routed_application_coordinator_drains_before_proxy_manager_stop(ansible_sandbox):
    system, run = ansible_sandbox
    run(
        {
            "steward_applications": [
                {"isolation": "shared", "services": [{"user": "app", "deploy": True}]}
            ],
            "steward_uids": {"app": 30000, "steward-proxy": LEGACY_UID},
            "steward_proxy": {"application_runtime": "/run/steward-proxy-dynamic"},
            "steward_config_revision": "config",
            "steward_release": {"version": "1.0.0", "files": {"artifact": "content-sha"}},
            "steward_nftables": "a verified firewall\n",
        }
    )
    unit = (system / "steward-applications.service").read_text().splitlines()
    assert f"After=user@{LEGACY_UID}.service" in unit
    assert not any(line.startswith("Wants=user@") for line in unit)
    assert not (system / f"user@{LEGACY_UID}.service.d").exists()


def test_first_private_application_inhibits_before_any_workload_task(ansible_sandbox):
    _, run = ansible_sandbox
    credentials = [
        "--deployment-operation-id",
        "operation",
        "--deployment-run-id",
        "run",
        "--deployment-boot-id",
        "boot",
        "--deployment-revision",
        "config",
    ]
    _, operations = run(
        {
            "site_private_application": True,
            "site_application_boot_arguments": credentials,
            "steward_applications": [
                {"isolation": "shared", "services": [{"user": "app", "deploy": True}]}
            ],
            "steward_uids": {"app": 30000},
            "steward_config_revision": "config",
            "steward_release": {"version": "1.0.0", "files": {"artifact": "content-sha"}},
            "steward_nftables": "a verified firewall\n",
        }
    )
    assert [args[0] for component, args, _ in operations if component == "coordinator"] == [
        "inhibit",
        "publish",
    ]
    inhibit, _, _, publish, *_ = operations
    assert inhibit[0] == "coordinator"
    assert inhibit[1][2:] == publish[1][2:] == credentials
    assert inhibit[1][1] == publish[1][1]


def test_executor_preserves_runtime_directory_across_stops():
    unit = (ROLES / "platform" / "templates" / "steward-executor.service.j2").read_text()
    assert "RuntimeDirectory=steward-executor" in unit.splitlines()
    assert "RuntimeDirectoryPreserve=yes" in unit.splitlines()


def test_real_ansible_retires_prior_boot_without_activating_inactive_or_legacy_apps(
    ansible_sandbox,
):
    system, run = ansible_sandbox
    variables = {
        "steward_config_revision": "legacy",
        "steward_release": {"version": "1.0.0", "files": {}},
        "steward_nftables": "legacy firewall",
    }
    output, operations = run(variables)
    assert "changed=0" in output
    assert operations == []
    assert list(system.iterdir()) == []

    unit = system / "steward-applications.service"
    unit.touch()
    retired = system / "user@30000.service.d/90-steward-applications.conf"
    retired.parent.mkdir()
    retired.touch()
    unrelated = system / f"user@{LEGACY_UID}.service.d/90-steward-applications.conf"
    unrelated.parent.mkdir()
    unrelated.touch()
    variables["steward_applications"] = [{"services": [{"user": "inactive", "deploy": False}]}]

    output, operations = run(variables, check=True)
    assert "changed=0" in output
    assert operations == []
    assert unit.exists() and retired.exists()

    _, operations = run(variables)
    assert operations[0][1][0] == "inhibit"
    assert json.loads(operations[1][1][0]) == {
        "name": "steward-applications.service",
        "state": "stopped",
    }
    assert operations[2] == ["coordinator", ["stop"], None]
    assert json.loads(operations[3][1][0]) == {
        "name": "steward-applications.service",
        "enabled": False,
    }
    assert operations[4][1] == ["publish", operations[0][1][1]]
    assert not unit.exists() and not retired.exists()
    assert unrelated.exists()


@pytest.mark.parametrize(
    ("private", "state", "check", "operations"),
    [
        (True, "quiescent", False, ["guarded", "identity", "manager", "sockets", "firewall"]),
        (True, "active", False, ["guarded", "identity", "manager"]),
        (True, "unknown", False, ["guarded", "identity", "manager"]),
        (True, "unchanged", False, ["guarded", "firewall"]),
        (False, "legacy", False, ["legacy", "firewall"]),
        (True, "active", True, []),
    ],
)
def test_read_only_application_transition_gates_firewall(
    tmp_path, private, state, check, operations
):
    executable = Path(sys.executable).parent / "ansible-playbook"
    if not executable.exists():
        pytest.skip("controller Ansible environment is not installed")
    log = tmp_path / "operations"
    shim = tmp_path / "retirement.py"
    shim.write_text(
        """import importlib.util, pathlib, sys
from steward import application_boot
from steward.executor.host import Host

log, scenario, path, *mode = sys.argv[1:]
def record(event):
    with pathlib.Path(log).open("a") as trace:
        print(event, file=trace)

if scenario == "firewall":
    record(scenario)
    sys.exit(0)

record("guarded" if mode == ["--guarded-retirement"] else "legacy")
spec = importlib.util.spec_from_file_location("transition", path)
transition = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transition)
user = "stw-a" + "1" * 20
identity = {"uid": 30000, "gid": 30000, "subuid": [200000, 65536], "subgid": [200000, 65536]}
entry = {"uid": identity["uid"], "user": user, "identity": identity,
         "unit": "test.service", "port": 19000}

def inspect_identity(username):
    assert username == user
    record("identity")
    return identity

def quiescent(self, uid, subuid):
    assert (uid, subuid) == (identity["uid"], identity["subuid"])
    record("manager")
    if scenario == "unknown":
        raise OSError("manager state unavailable")
    return scenario == "quiescent"

def sockets():
    record("sockets")
    return []

application_boot.inspect_identity = inspect_identity
Host.application_manager_quiescent = quiescent
Host._tcp_sockets = staticmethod(sockets)
transition.load_previous = lambda: [entry]
transition.listener_uids = lambda: {}
transition.manager_state = transition.unit_state = lambda _: "inactive"
transition.process_uids = set
sys.argv[:] = [path, *mode]
transition.main()
"""
    )

    install, inspect = tasks("identities", "application-transition")
    copy = install["ansible.builtin.copy"]
    original = ROLES / "identities" / "files" / copy["src"]
    helper = tmp_path / original.name
    copy.update(src=str(original), dest=str(helper))
    copy.pop("owner")
    copy.pop("group")

    command = inspect["ansible.builtin.command"]
    argv = " ".join(command["argv"].split())
    prefix = [sys.executable, str(shim), str(log), state, str(helper)]
    guarded = (
        "'/opt/steward/current/venv/bin/python', '-I', '/var/lib/steward/application-transition.py'"
    )
    legacy = "'/usr/bin/python3', '/var/lib/steward/application-transition.py'"
    assert guarded in argv and legacy in argv
    rendered_prefix = ", ".join(repr(value) for value in prefix)
    command["argv"] = argv.replace(guarded, rendered_prefix).replace(legacy, rendered_prefix)

    firewall = {
        "ansible.builtin.command": {
            "argv": [sys.executable, str(shim), str(log), "firewall", str(helper)],
        },
        "when": "not ansible_check_mode",
    }
    variables = {"site_private_application": private}
    expected_units = 0
    if state == "unchanged":
        user = "stw-a" + "1" * 20
        identity = {
            "uid": 30000,
            "gid": 30000,
            "subuid": [200000, 65536],
            "subgid": [200000, 65536],
        }
        variables["steward_application_ids"] = {user: identity}
        variables["steward_applications"] = [
            {"pod": None, "services": [{"user": user, "unit": "test.service", "host_port": 19000}]}
        ]
        expected_units = 1
    play = tmp_path / "play.yml"
    play.write_text(
        yaml.safe_dump(
            [
                {
                    "hosts": "localhost",
                    "gather_facts": False,
                    "vars": variables,
                    "tasks": [
                        install,
                        inspect,
                        {
                            "ansible.builtin.assert": {
                                "that": [
                                    f"identities_application_transition.stdout | from_json | length == {expected_units}"
                                ],
                            },
                            "when": "not ansible_check_mode",
                        },
                        firewall,
                    ],
                }
            ]
        )
    )
    result = subprocess.run(
        [
            str(executable),
            "-i",
            "localhost,",
            "-c",
            "local",
            str(play),
            *(["--check"] if check else []),
        ],
        env={
            **os.environ,
            "ANSIBLE_LOCAL_TEMP": str(tmp_path / "ansible-local"),
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_ALLOW_BROKEN_CONDITIONALS": "false",
        },
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    output = result.stdout + result.stderr
    failed = not check and state in {"active", "unknown"}
    assert bool(result.returncode) == failed, output
    assert (log.read_text().splitlines() if log.exists() else []) == operations, output
    if failed:
        assert "Stop the user manager and all remaining workloads separately" in output
