"""Run production site routing with real Ansible and an isolated SSH endpoint."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from steward.core.repository_fetch_package import Publication

ROOT = Path(__file__).resolve().parents[1]
ANSIBLE = ROOT / "ansible"
REVISION = "a" * 64
BASE = "b" * 64
IDENTITY = {
    "operation_id": "c" * 32,
    "run_id": "d" * 32,
    "boot_id": "12345678-1234-1234-1234-123456789abc",
    "desired_revision": REVISION,
}
GATE = [
    "/usr/bin/python3",
    "-I",
    "/usr/local/libexec/steward/deployment-v1/launch.py",
    "--operation-id",
    IDENTITY["operation_id"],
    "--run-id",
    IDENTITY["run_id"],
    "--boot-id",
    IDENTITY["boot_id"],
    "--",
]
PREFLIGHT_TASKS = (
    "Look for foreign platform layouts",
    "Index path results",
    "Require trusted directory and marker before reading installation ownership",
    "Read install marker",
    "Read the trusted installation identity",
    "Refuse a server that belongs to another configuration",
    "Determine site transport from the trusted installation marker",
    "Reset private LAN candidates for this preflight",
    "Discover and verify the private admin LAN",
    "Require schema 2 for selection of the private application entrypoint",
    "Select the root private application entrypoint when requested",
    "Read the exact deployment status from the protected installation",
    "Require graph-free site deployment before any host changes",
)
VERIFY_TASKS = (
    "Activate pending service changes before verification",
    "Verify platform through the host executor",
    "Record the verified deployment",
    "Mark installation complete after successful verification",
)
PATHS = (
    "/etc/steward",
    "/var/lib/steward",
    "/run/steward",
    "/etc/systemd",
    "/srv/",
    "/run/docker.sock",
)


@pytest.fixture
def isolated_site(tmp_path):
    pytest.importorskip("ansible")
    remote = tmp_path / "host"
    marker = remote / "etc/steward/install.json"
    marker.parent.mkdir(parents=True, mode=0o755)
    (marker.parent / "config").mkdir(mode=0o755)  # installed hosts have desired.json here
    log = tmp_path / "operations.jsonl"
    ssh_log = tmp_path / "ssh.jsonl"
    ssh = tmp_path / "ssh"
    ssh.write_text(
        f"#!{sys.executable}\n"
        "import json, os, shlex, sys\n"
        "arguments = shlex.split(sys.argv[-1])\n"
        f"guarded = arguments[:-1] == {GATE!r}\n"
        f"with open({str(ssh_log)!r}, 'a') as log:\n"
        "    print(json.dumps([guarded, arguments, sys.argv[1:-1]]), file=log)\n"
        "if '-O' in sys.argv:\n"
        "    sys.exit(0)\n"
        "if not guarded and 'deployment-v1/launch.py' in sys.argv[-1]:\n"
        "    sys.exit('Invalid deployment gate invocation')\n"
        "os.environ['TEST_SITE_GUARDED'] = str(guarded)\n"
        "os.execv('/bin/sh', ['/bin/sh', '-c', arguments[-1] if guarded else sys.argv[-1]])\n"
    )
    ssh.chmod(0o755)
    shim = tmp_path / "coordinator"
    shim.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "action, *arguments = sys.argv[1:]\n"
        "if action == '-I' and arguments[0] == '-c':\n"
        "    if 'deploy-run.json' in arguments[1]:\n"
        "        from pathlib import Path\n"
        f"        marker_path = Path({str(marker.parent / 'config/deploy-run.json')!r})\n"
        "        record = json.load(sys.stdin)\n"
        "        if 'store(marker, record)' in arguments[1]:\n"
        "            assert not {'inference_run', 'repository_fetch_run'} & record.keys() "
        "or not marker_path.exists()\n"
        "            marker_path.write_text(json.dumps(record))\n"
        "        else:\n"
        "            assert json.loads(marker_path.read_text()) == record\n"
        "            marker_path.unlink()\n"
        "        sys.exit(0)\n"
        "    print(os.environ.get('TEST_SITE_APPLIED_APPLICATIONS', '[]'))\n"
        "    sys.exit(0)\n"
        "if action == '-I':\n"
        "    module = arguments[1]\n"
        "    action, *arguments = arguments[2:]\n"
        "    if module == 'steward.core.repository_fetch_package':\n"
        "        action = 'fetch-' + action\n"
        "data = json.load(sys.stdin) if action in "
        "('begin', 'resume', 'begin-private', 'resume-private', 'stage', 'publish', "
        "'fetch-seal', 'fetch-publish') else None\n"
        f"marker = {str(marker.parent / 'config/deploy-run.json')!r}\n"
        "if action.startswith('fetch-'):\n"
        "    from pathlib import Path\n"
        "    run_marker = Path(marker)\n"
        "    active = run_marker.parent.parent / 'repository-fetch/active.json'\n"
        "    if action == 'fetch-withdraw':\n"
        "        data = json.loads(run_marker.read_text()) if run_marker.exists() else None\n"
        "        if active.exists():\n"
        "            active.unlink()\n"
        "    if action == 'fetch-publish':\n"
        "        assert json.loads(run_marker.read_text()) == data['marker']\n"
        "if action in ('withdraw-probe', 'stage', 'publish'):\n"
        "    import pathlib\n"
        "    run_marker = pathlib.Path(marker)\n"
        "    observed = json.loads(run_marker.read_text()) if run_marker.exists() else None\n"
        "    if action == 'withdraw-probe':\n"
        "        data = observed\n"
        "    else:\n"
        "        assert observed == {'base_revision': data['candidate']['revision'], "
        "'desired_revision': data['candidate']['revision'], 'inference_run': data['run_id']}\n"
        f"with open({str(log)!r}, 'a') as log:\n"
        "    print(json.dumps([action, os.environ['TEST_SITE_GUARDED'] == 'True', arguments, data]), file=log)\n"
        "if os.environ.get('TEST_SITE_FAILURE') == 'old-wheel' and data and 'retirement_protocol' in data:\n"
        "    sys.exit('unsupported request')\n"
        "if os.environ.get('TEST_SITE_FAILURE') == action:\n"
        "    sys.exit('simulated failure')\n"
        "if action == 'fetch-publish':\n"
        "    active.write_text(json.dumps(data['manifest']))\n"
        "if action in ('publish', 'fetch-publish'):\n"
        "    run_marker.unlink()\n"
        "if action == 'status' and os.environ.get('TEST_SITE_FAILURE') == 'legacy-status':\n"
        "    sys.exit(2)\n"
        "if action in ('begin', 'resume', 'begin-private', 'resume-private', 'status', 'finish'):\n"
        f"    result = {IDENTITY!r}\n"
        "    if os.environ.get('TEST_SITE_FAILURE') == 'invalid':\n"
        "        result['run_id'] = 123\n"
        "    if os.environ.get('TEST_SITE_FAILURE') == 'wrong-operation':\n"
        "        result['operation_id'] = '0' * 32\n"
        "    if action in ('begin-private', 'resume-private') and ("
        "data.get('retirement_protocol') == 1 or os.environ.get('TEST_SITE_RETIREMENT_RESUME') == 'True'):\n"
        "        result['retirement_required'] = True\n"
        "    if action == 'finish':\n"
        "        result['state'] = 'complete'\n"
        "    print(json.dumps(result))\n"
        "if action == '_retire':\n"
        "    print(json.dumps({'changed': True}))\n"
    )
    shim.chmod(0o755)
    role_path = tmp_path / "roles"

    def rewrite(tasks):
        serialized = json.dumps(tasks)
        for prefix in PATHS:
            serialized = serialized.replace(prefix, f"{remote}{prefix}")
        return json.loads(
            serialized.replace(".uid == 0", f".uid == {os.getuid()}")
            .replace("/opt/steward/current/venv/bin/steward-host", str(shim))
            .replace("/opt/steward/current/venv/bin/python", str(shim))
        )

    def install_tasks(role, filename, tasks):
        path = role_path / role / "tasks" / f"{filename}.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(rewrite(tasks)))

    def install_subset(role, task_names):
        originals = yaml.safe_load((ANSIBLE / "roles" / role / "tasks/main.yml").read_text())
        selected = [task for task in originals if task["name"] in task_names]
        assert len(selected) == len(task_names)
        if role == "verify":
            for task in selected:
                if task.get("retries"):
                    task.update(retries=0, delay=0)
                if module := task.get("ansible.builtin.copy"):
                    module.pop("owner")
                    module.pop("group")
        install_tasks(role, "main", selected)

    install_subset("preflight", PREFLIGHT_TASKS)
    lan_tasks = yaml.safe_load((ANSIBLE / "roles/preflight/tasks/admin-lan.yml").read_text())
    # Supply isolated guest command output while running the real filters and assertions.
    guest_tasks = {task["name"]: task for task in lan_tasks}
    for name, variable in (
        ("Read the guest's IPv4 addresses", "test_guest_addresses"),
        ("Read the guest's directly connected IPv4 routes", "test_guest_routes"),
    ):
        guest_tasks[name]["ansible.builtin.command"] = {
            "argv": ["/bin/cat"],
            "stdin": "{{ " + variable + " | to_json }}",
        }
    parser = guest_tasks["Check private LAN support in the installed guarded admission parser"]
    parser["ansible.builtin.command"] = {"argv": ["/bin/true"]}
    site_gate = guest_tasks["Require the reviewed LAN scope on the native site path"]
    site_gate["block"][1]["environment"] = {"SSH_CONNECTION": "{{ test_guest_ssh_connection }}"}
    install_tasks("preflight", "admin-lan", lan_tasks)
    install_subset("verify", VERIFY_TASKS)
    for role in ("bootstrap", "base", "identities", "firewall", "platform", "proxy", "workloads"):
        install_tasks(role, "main", [])
    install_tasks("identities", "application-boot-inhibit", [])
    install_tasks(
        "platform",
        "repository-fetch",
        [
            {
                "name": "Observe the marker at repository fetch withdrawal",
                "ansible.builtin.command": {"argv": [str(shim), "fetch-withdraw"]},
                "when": [
                    "platform_repository_fetch_phase == 'withdraw'",
                    "test_repository_fetch is defined",
                ],
            },
        ],
    )
    install_tasks(
        "platform",
        "inference",
        [
            {
                "name": "Observe the actual site marker at inference withdrawal",
                "ansible.builtin.command": {"argv": [str(shim), "withdraw-probe"]},
                "when": "steward_inference_candidate is defined",
            },
        ],
    )
    install_tasks(
        "platform",
        "main",
        [
            {
                "name": "Stage a platform mutation",
                "ansible.builtin.copy": {
                    "content": "data\n",
                    "dest": str(remote / "payload"),
                },
                "notify": "Activate test platform",
            },
            {
                "name": "Seal the staged repository fetch scope through the helper",
                "ansible.builtin.command": {
                    "argv": [
                        "/opt/steward/current/venv/bin/python",
                        "-I",
                        "-m",
                        "steward.core.repository_fetch_package",
                        "seal",
                    ],
                    "stdin": "{{ steward_repository_fetch.manifest | to_json }}",
                },
                "register": "platform_repository_fetch_seal",
                "when": "steward_repository_fetch is defined and not ansible_check_mode",
            },
            {
                "name": "Observe the staged repository fetch unit source check",
                "ansible.builtin.command": {"argv": [str(shim), "fetch-source"]},
                "register": "platform_repository_fetch_source",
                "when": "steward_repository_fetch is defined and not ansible_check_mode",
            },
            {
                "name": "Model a successful installation and prepublication activation",
                "when": "steward_inference_candidate is defined and not ansible_check_mode",
                "block": [
                    {
                        "name": "Capture this candidate's deployment payload",
                        "ansible.builtin.set_fact": {
                            "platform_inference_payload": (
                                "{{ {'candidate': steward_inference_candidate, "
                                "'run_id': site_inference_run} | combine("
                                "{'ollama': steward_ollama_local, "
                                f"'models': '{remote / 'models'}'"
                                "} if steward_ollama_local is defined else {}) }}"
                            ),
                        },
                    },
                    {
                        "name": "Stage the candidate through a temporary helper",
                        "ansible.builtin.command": {
                            "argv": [
                                "/opt/steward/current/venv/bin/python",
                                "-I",
                                "-m",
                                "steward.core.inference_deployment",
                                "stage",
                            ],
                            "stdin": "{{ platform_inference_payload | to_json }}",
                        },
                        "register": "platform_inference_staged",
                    },
                    {
                        "name": "Record synthetic startup success",
                        "ansible.builtin.set_fact": {"platform_inference_started": True},
                    },
                ],
            },
        ],
    )
    handlers = role_path / "platform" / "handlers"
    handlers.mkdir()
    (handlers / "main.yml").write_text(
        yaml.safe_dump(
            [
                {
                    "name": "Activate test platform",
                    "ansible.builtin.command": {"argv": [str(shim), "handler"]},
                },
            ]
        )
    )
    playbook = tmp_path / "site.yml"
    playbook.write_text(
        yaml.safe_dump(rewrite(yaml.safe_load((ANSIBLE / "playbooks/site.yml").read_text())))
    )
    preflight = tmp_path / "preflight.yml"
    preflight_plays = yaml.safe_load((ANSIBLE / "playbooks/preflight.yml").read_text())
    report = next(
        task
        for task in yaml.safe_load((ANSIBLE / "roles/preflight/tasks/main.yml").read_text())
        if task["name"] == "Store remote state on the controller"
    )
    report["when"] = "test_guest_addresses is defined"
    report["vars"].update(
        preflight_ssh={"stdout": "{{ test_guest_ssh_connection }}"},
        steward_local_dir=str(tmp_path),
        ansible_facts={"memtotal_mb": 1024, "architecture": "x86_64", "kernel": "test"},
    )
    preflight_plays[0]["post_tasks"] = rewrite([report])
    preflight.write_text(yaml.safe_dump(preflight_plays))
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "all": {
                    "hosts": {
                        "test": {
                            "ansible_host": "192.0.2.1",
                            "ansible_connection": "local",
                            "ansible_user": "root",
                            "ansible_ssh_executable": str(ssh),
                            "ansible_scp_executable": str(ssh),
                            "ansible_sftp_executable": str(ssh),
                            "ansible_ssh_transfer_method": "piped",
                            "ansible_python_interpreter": sys.executable,
                            "ansible_remote_tmp": str(tmp_path / "remote-tmp"),
                            "ansible_ssh_use_tty": False,
                        }
                    }
                }
            }
        )
    )

    def run(
        *,
        schema=2,
        install_state="installed",
        check=False,
        failure="",
        desired_graph=False,
        existing_graph=None,
        extra=None,
        preflight_only=False,
        applied_applications=(),
        retirement_resume=False,
    ):
        marker.unlink(missing_ok=True)
        if schema is not None:
            marker.write_text(
                json.dumps(
                    {"schema_version": schema, "server_name": "test", "state": install_state}
                )
            )
            marker.chmod(0o644)
        if existing_graph == "registry":
            registry = marker.parent / "executor.json"
            registry.write_text(json.dumps({"applications": {"owned": {}}}))
            registry.chmod(0o600)
        elif existing_graph:
            artifact = remote / existing_graph.lstrip("/")
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.touch()
        variables = {
            "steward_generated": True,
            "steward_config_revision": REVISION,
            "steward_server_name": "test",
            "steward_base_revision": BASE,
            "steward_desired_config": {
                "applications": [{"id": "desired"}] if desired_graph else []
            },
            "steward_release": {
                "version": "1",
                "files": {"wheel": "digest"},
                "wheel": "wheel",
                "dir": "/controller",
            },
        } | (extra or {})
        cli = Path(sys.executable).with_name("ansible-playbook")
        env = {key: value for key, value in os.environ.items() if not key.startswith("ANSIBLE_")}
        env.update(
            ANSIBLE_CONFIG=str(ANSIBLE / "ansible.cfg"),
            ANSIBLE_CONNECTION_PLUGINS=str(ANSIBLE / "connection_plugins"),
            ANSIBLE_ROLES_PATH=str(role_path),
            ANSIBLE_LOCAL_TEMP=str(tmp_path / "local-tmp"),
            ANSIBLE_SSH_CONTROL_PATH_DIR=str(tmp_path / "control"),
            TEST_SITE_FAILURE=failure,
            TEST_SITE_APPLIED_APPLICATIONS=json.dumps(applied_applications),
            TEST_SITE_RETIREMENT_RESUME=str(retirement_resume),
        )
        result = subprocess.run(
            [
                str(cli),
                "-i",
                str(inventory),
                "-e",
                json.dumps(variables),
                str(preflight if preflight_only else playbook),
                *(["--check"] if check else []),
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=300,
            check=False,
        )
        operations = (
            [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        )
        ssh_calls = (
            [json.loads(line) for line in ssh_log.read_text().splitlines()]
            if ssh_log.exists()
            else []
        )
        return result, operations, ssh_calls

    return run, marker, remote / "payload"


def test_guarded_site_runs_roles_transfers_handlers_and_verification_through_gate(isolated_site):
    run, marker, payload = isolated_site
    result, operations, ssh_calls = run()
    assert result.returncode == 0, result.stdout + result.stderr
    begin, handler, verify, finish = operations
    assert begin == [
        "begin",
        False,
        [],
        {
            "config": {"applications": []},
            "base_revision": BASE,
            "release": {"version": "1", "files": {"wheel": "digest"}, "wheel": "wheel"},
        },
    ]
    assert f"Guarded deployment {IDENTITY['operation_id']} admitted" in result.stdout
    assert IDENTITY["run_id"] not in result.stdout
    assert handler == ["handler", True, [], None]
    assert verify == [
        "verify",
        True,
        [
            "--expect-revision",
            REVISION,
            "--deployment-operation-id",
            IDENTITY["operation_id"],
            "--deployment-run-id",
            IDENTITY["run_id"],
            "--deployment-boot-id",
            IDENTITY["boot_id"],
        ],
        None,
    ]
    assert finish == ["finish", False, GATE[3:-1], None]
    assert any(guarded and "dd of=" in command[-1] for guarded, command, _ in ssh_calls)
    assert payload.read_text() == "data\n"
    assert json.loads(marker.read_text())["schema_version"] == 2


@pytest.mark.parametrize(
    "check,bind,guest_address,operstate,ssh_port,expected",
    [
        (False, "10.0.0.4/24", "10.0.0.4", "UP", 22, None),
        (True, "10.0.0.4/24", "10.0.0.4", "UP", 22, None),
        (True, None, "10.0.0.4", "UP", 22, "must match an up IPv4 interface"),
        (False, "10.0.0.4/25", "10.0.0.4", "UP", 22, "must match an up IPv4 interface"),
        (False, "10.0.0.4/24", "10.0.0.4", "DOWN", 22, "must match an up IPv4 interface"),
        (False, "100.64.0.4/24", "100.64.0.4", "UP", 22, "must match an up IPv4 interface"),
        (True, "10.0.0.4/24", "10.0.0.4", "UP", 8443, "actual guest SSH port"),
    ],
)
def test_native_site_checks_lan_before_admission_or_preview(
    isolated_site, check, bind, guest_address, operstate, ssh_port, expected
):
    run, _, payload = isolated_site
    result, operations, _ = run(
        check=check,
        extra={
            "steward_admin": {
                "access": "private-lan",
                "port": 8443,
                "lan": {"interface": "eth0", "bind": bind} if bind else None,
            },
            "test_guest_addresses": [
                {
                    "ifname": "eth0",
                    "flags": ["BROADCAST", "UP"],
                    "link_type": "ether",
                    "operstate": operstate,
                    "addr_info": [
                        {
                            "family": "inet",
                            "scope": "global",
                            "local": guest_address,
                            "prefixlen": 24,
                        }
                    ],
                }
            ],
            "test_guest_routes": [{"dev": "eth0", "dst": "10.0.0.0/24"}],
            "test_guest_ssh_connection": f"10.0.0.2 12345 {guest_address} {ssh_port}",
        },
    )
    if expected:
        assert result.returncode != 0
        assert expected in result.stdout
        assert operations == []
        assert not payload.exists()
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert payload.exists() is not check


def test_report_allows_deferred_lan_and_returns_only_usable_candidates(isolated_site, tmp_path):
    run, _, payload = isolated_site
    guest = {
        "ifname": "eth0",
        "flags": ["BROADCAST", "UP"],
        "link_type": "ether",
        "operstate": "UP",
        "addr_info": [
            {"family": "inet", "scope": "global", "local": address, "prefixlen": 24, **flags}
            for address, flags in (
                ("10.0.0.4", {}),
                ("10.0.0.255", {}),
                ("192.168.5.4", {"tentative": True}),
                ("192.168.6.4", {}),
                ("100.64.0.4", {}),
                ("172.16.0.4", {"preferred_life_time": 0}),
            )
        ],
    }
    result, operations, _ = run(
        preflight_only=True,
        extra={
            "steward_admin": {"access": "private-lan", "port": 8443, "lan": None},
            "test_guest_addresses": [
                guest,
                {**guest, "ifname": "eth1", "operstate": "DOWN"},
                {**guest, "ifname": "lo", "flags": ["LOOPBACK", "UP"], "operstate": "UNKNOWN"},
            ],
            "test_guest_routes": [
                {"dev": "eth0", "dst": network}
                for network in ("10.0.0.0/24", "192.168.5.0/24", "100.64.0.0/24", "172.16.0.0/24")
            ],
            "test_guest_ssh_connection": "10.0.0.2 12345 10.0.0.4 22",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads((tmp_path / "remote-state.json").read_text())
    assert report["admin_lan_candidates"] == [{"interface": "eth0", "bind": "10.0.0.4/24"}]
    assert report["ssh_port"] == 22
    assert operations == []
    assert not payload.exists()


@pytest.mark.parametrize("resume", [False, True])
def test_private_selector_only_selects_native_root_admission(isolated_site, resume):
    run, _, payload = isolated_site
    extra = {"steward_private_application_deployment": True}
    if resume:
        extra.update(
            steward_resume_deployment=IDENTITY["operation_id"],
            steward_observed_revision=REVISION,
        )
    action = "resume-private" if resume else "begin-private"
    result, operations, _ = run(extra=extra, desired_graph=True, failure=action)

    assert result.returncode != 0
    assert not payload.exists()
    [(observed, guarded, arguments, request)] = operations
    assert observed == action
    assert guarded is False
    assert request["config"]["applications"] == [{"id": "desired"}]
    assert request.get("observed_revision") == (REVISION if resume else None)
    assert arguments == (["--operation-id", IDENTITY["operation_id"]] if resume else [])


def test_private_selector_refuses_a_schema_one_host_before_native_admission(isolated_site):
    run, _, payload = isolated_site
    result, operations, _ = run(
        schema=1, desired_graph=True, extra={"steward_private_application_deployment": True}
    )
    assert result.returncode != 0
    assert "schema 2 host" in result.stdout
    assert operations == []
    assert not payload.exists()


@pytest.mark.parametrize("failure", ["", "resume", "wrong-operation"])
def test_exact_site_recovery_uses_the_same_operation_and_protected_transport(
    isolated_site, failure
):
    run, _, payload = isolated_site
    result, operations, _ = run(
        failure=failure,
        extra={
            "steward_resume_deployment": IDENTITY["operation_id"],
            "steward_observed_revision": REVISION,
        },
    )
    assert operations[0] == [
        "resume",
        False,
        ["--operation-id", IDENTITY["operation_id"]],
        {
            "config": {"applications": []},
            "base_revision": BASE,
            "observed_revision": REVISION,
            "release": {"version": "1", "files": {"wheel": "digest"}, "wheel": "wheel"},
        },
    ]
    if failure:
        assert result.returncode != 0
        assert len(operations) == 1
        assert not payload.exists()
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert [operation[:2] for operation in operations[1:]] == [
            ["handler", True],
            ["verify", True],
            ["finish", False],
        ]


@pytest.mark.parametrize(
    "failure, message",
    [
        ("", "Decode protected deployment status"),
        ("legacy-status", "The active host release rejected the exact deployment status request"),
        ("status", "Exact deployment status is unavailable"),
    ],
)
def test_exact_preflight_checks_active_release_without_mutating(isolated_site, failure, message):
    run, _, payload = isolated_site
    result, operations, _ = run(
        preflight_only=True,
        failure=failure,
        extra={"steward_resume_deployment": IDENTITY["operation_id"]},
    )
    assert (result.returncode != 0) == bool(failure), result.stdout + result.stderr
    assert message in result.stdout
    assert operations == [["status", False, ["--operation-id", IDENTITY["operation_id"]], None]]
    assert IDENTITY["run_id"] not in result.stdout
    assert not payload.exists()


@pytest.mark.parametrize("schema,check", [(1, False), (None, False), (1, True), (2, True)])
def test_ordinary_site_and_preview_do_not_admit_or_complete(isolated_site, schema, check):
    run, marker, payload = isolated_site
    result, operations, ssh_calls = run(schema=schema, check=check)
    assert result.returncode == 0, result.stdout + result.stderr
    assert all(not guarded for guarded, _, _ in ssh_calls)
    if check:
        assert operations == []
        assert not payload.exists()
        assert json.loads(marker.read_text())["schema_version"] == schema
    else:
        assert [operation[0] for operation in operations] == [
            "handler",
            "verify",
            "record-deployment",
        ]
        assert operations[1][2] == ["--expect-revision", REVISION]
        assert json.loads(marker.read_text())["schema_version"] == 1


@pytest.mark.parametrize(
    "options,expected",
    [
        ({"desired_graph": True}, []),
        ({"schema": 1, "existing_graph": "registry"}, []),
        ({"existing_graph": "/run/steward-applications/route-drain.json"}, []),
        ({"existing_graph": "/run/steward-applications/route-publication.json"}, []),
        ({"schema": 1, "existing_graph": "/etc/steward/proxy/dynamic/applications.yml"}, []),
        ({"extra": {"ansible_connection": "local"}}, []),
        ({"extra": {"steward_base_revision": None}}, []),
        ({"failure": "invalid"}, ["begin"]),
        ({"failure": "handler"}, ["begin", "handler"]),
        ({"failure": "verify"}, ["begin", "handler", "verify"]),
        ({"failure": "finish"}, ["begin", "handler", "verify", "finish"]),
    ],
)
def test_site_fails_closed(isolated_site, options, expected):
    run, marker, payload = isolated_site
    result, operations, _ = run(**options)
    assert result.returncode != 0, result.stdout + result.stderr
    assert [operation[0] for operation in operations] == expected, result.stdout
    assert payload.exists() == ("handler" in expected)
    assert json.loads(marker.read_text())["schema_version"] == options.get("schema", 2)


@pytest.mark.parametrize("failure", ["", "old-wheel", "_retire"])
def test_private_removal_protocol_precedes_role_mutations(isolated_site, failure):
    run, _, payload = isolated_site
    result, operations, _ = run(
        extra={"steward_private_application_deployment": True},
        applied_applications=["removed"],
        failure=failure,
    )
    action, guarded, args, request = operations[0]
    assert (action, guarded, args) == ("begin-private", False, [])
    assert request["retirement_protocol"] == 1
    assert request["config"]["applications"] == []
    if failure == "old-wheel":
        assert len(operations) == 1
    else:
        assert operations[1] == ["_retire", True, list(IDENTITY.values()), None]
    assert payload.exists() == (failure == "")
    assert (result.returncode == 0) == (failure == "")


@pytest.mark.parametrize("private", [False, True])
def test_old_wheel_can_admit_nonremovals(isolated_site, private):
    run, _, payload = isolated_site
    result, operations, _ = run(
        extra={"steward_private_application_deployment": private},
        desired_graph=private,
        applied_applications=["desired"] if private else [],
        failure="old-wheel",
    )
    assert result.returncode == 0, result.stdout
    assert operations[0][0] == ("begin-private" if private else "begin")
    assert "retirement_protocol" not in operations[0][3]
    assert all(operation[0] != "_retire" for operation in operations)
    assert payload.exists()


def test_private_resume_uses_bound_retirement_without_fresh_marker(isolated_site):
    run, _, payload = isolated_site
    result, operations, _ = run(
        extra={
            "steward_private_application_deployment": True,
            "steward_resume_deployment": IDENTITY["operation_id"],
            "steward_observed_revision": BASE,
        },
        retirement_resume=True,
    )
    assert result.returncode == 0, result.stdout
    assert operations[0][0] == "resume-private"
    assert "retirement_protocol" not in operations[0][3]
    assert operations[1] == ["_retire", True, list(IDENTITY.values()), None]
    assert payload.exists()


@pytest.fixture
def legacy_inference_withdrawal(tmp_path):
    pytest.importorskip("ansible")
    host = tmp_path / "host"
    authority = host / "etc/steward/inference"
    stage = authority.with_name("config") / "inference-stage.json"
    stage.parent.mkdir(parents=True)
    calls = tmp_path / "commands.jsonl"
    helper = tmp_path / "installed-python"
    systemctl = tmp_path / "systemctl"

    def stub(path, body):
        path.write_text(
            f"#!{sys.executable}\n"
            "import json, sys\n"
            f"with open({str(calls)!r}, 'a') as log:\n"
            "    print(json.dumps(sys.argv), file=log)\n" + body
        )
        path.chmod(0o755)

    def run(*, helper_status=None):
        if helper_status is not None:
            stub(helper, f"sys.exit({helper_status})\n")
        stub(
            systemctl,
            "assert sys.argv[1:3] == ['show', '--all']\n"
            "print('LoadState=not-found\\nActiveState=inactive\\nFragmentPath=\\nDropInPaths=')\n",
        )
        source = (ANSIBLE / "roles/platform/tasks/inference.yml").read_text()
        # Use the fixture owner's UID for the root ownership check on unprivileged runners.
        tasks = (
            source.replace("/etc/steward", f"{host}/etc/steward")
            .replace("/etc/systemd", f"{host}/etc/systemd")
            .replace(".uid == 0", f".uid == {os.getuid()}")
            .replace("/opt/steward/current/venv/bin/python", str(helper))
            .replace("/usr/bin/systemctl", str(systemctl))
        )
        playbook = tmp_path / "withdraw.yml"
        playbook.write_text(
            yaml.safe_dump(
                [
                    {
                        "hosts": "localhost",
                        "connection": "local",
                        "gather_facts": False,
                        "vars": {
                            "ansible_python_interpreter": sys.executable,
                            "ansible_remote_tmp": str(tmp_path / "remote-tmp"),
                            "platform_inference_phase": "withdraw",
                        },
                        "tasks": yaml.safe_load(tasks),
                    }
                ],
                sort_keys=False,
            )
        )
        env = {key: value for key, value in os.environ.items() if not key.startswith("ANSIBLE_")}
        env.update(
            ANSIBLE_CONFIG=str(ANSIBLE / "ansible.cfg"),
            ANSIBLE_LOCAL_TEMP=str(tmp_path / "local-tmp"),
        )
        result = subprocess.run(
            [
                str(Path(sys.executable).with_name("ansible-playbook")),
                "-i",
                "localhost,",
                str(playbook),
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=300,
            check=False,
        )
        commands = (
            [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
        )
        return result, commands

    return run, authority, stage, helper, systemctl


@pytest.mark.parametrize(
    ("leaf", "helper_status"),
    [
        (None, None),
        ("selection", 0),
        ("dangling-selection", 0),
        ("stage", 0),
        ("dangling-stage", 0),
        ("selection", 23),
    ],
)
def test_legacy_inference_withdrawal_checks_authority_leaves(
    legacy_inference_withdrawal, leaf, helper_status
):
    run, authority, stage, helper, systemctl = legacy_inference_withdrawal
    if leaf not in ("stage", "dangling-stage"):
        authority.mkdir(mode=0o750)
        authority.chmod(0o750)
    selection = authority / "selection.json"
    if leaf == "selection":
        selection.touch()
    elif leaf == "dangling-selection":
        selection.symlink_to(authority / "missing.json")
    elif leaf == "stage":
        stage.touch()
    elif leaf == "dangling-stage":
        stage.symlink_to(stage.with_name("missing.json"))

    result, commands = run(helper_status=helper_status)
    output = result.stdout + result.stderr
    assert result.returncode == (2 if helper_status else 0), output
    if leaf is not None:
        assert commands[0] == [
            str(helper),
            "-I",
            "-m",
            "steward.core.inference_deployment",
            "revoke",
        ]
        commands = commands[1:]
    if helper_status:
        assert '"rc": 23' in output
        assert "Check optional inference unit files" not in output
        assert commands == []
    else:
        assert [command[-1] for command in commands] == [
            "steward-inference-advice-bot.socket",
            "steward-inference-advice-api.socket",
            "steward-inference-advice.service",
            "steward-inference-tick.timer",
            "steward-inference-tick.service",
            "steward-inference-admin.socket",
            "steward-inference-admin.service",
            "steward-inference-egress.socket",
            "steward-inference-egress.service",
        ]
        assert all(command[:2] == [str(systemctl), "show"] for command in commands)


@pytest.mark.parametrize("unsafe", ["symlink", "group-writable", "world-writable", "file"])
def test_legacy_inference_withdrawal_rejects_unsafe_directory(legacy_inference_withdrawal, unsafe):
    run, authority, stage, _, _ = legacy_inference_withdrawal
    if unsafe == "symlink":
        target = authority.with_name("other-directory")
        target.mkdir(mode=0o750)
        authority.symlink_to(target, target_is_directory=True)
    elif unsafe == "file":
        authority.touch()
    else:
        authority.mkdir()
        authority.chmod(0o770 if unsafe == "group-writable" else 0o752)
    stage.touch()

    result, commands = run(helper_status=0)
    output = result.stdout + result.stderr
    assert result.returncode == 2, output
    assert "Require a trusted inference authority directory" in output
    assert "Inspect the inference projection" not in output
    assert "Inspect staged inference proof" not in output
    assert commands == []


def inference_candidate_vars(private=False):
    variables = {
        "steward_base_revision": REVISION,
        "steward_ollama_local": {"ai": {"provider": "ollama"}, "reserved_memory_mb": 128},
        "steward_inference_candidate": {
            "version": 1,
            "revision": REVISION,
            "release": "1",
            "wheel_sha256": "e" * 64,
            "manifest_sha256": "f" * 64,
        },
        "steward_release": {
            "version": "1",
            "files": {"wheel": "e" * 64},
            "wheel": "wheel",
            "dir": "/controller",
        },
    }

    if private:
        del variables["steward_ollama_local"]
        candidate = variables["steward_inference_candidate"]
        del candidate["manifest_sha256"]
        candidate["private_provider"] = {
            "base_url": "https://192.168.10.20:8443/v1",
            "budget": {"monthly": {"tokens": 10_000, "seconds": 120}},
        }
    return variables


@pytest.mark.parametrize(
    ("failure", "private"),
    [(failure, False) for failure in ("", "check-base", "stage", "verify", "record-deployment")]
    + [
        pytest.param("", True, id="private-https"),
        pytest.param("verify", True, id="private-verify-failure"),
    ],
)
def test_inference_site_publication_follows_verification_and_recording(
    isolated_site, failure, private
):
    run, marker, payload = isolated_site
    result, operations, _ = run(schema=1, extra=inference_candidate_vars(private), failure=failure)
    assert result.returncode == (2 if failure else 0), result.stdout + result.stderr
    expected = [
        "withdraw-probe",
        "check-base",
        "stage",
        "handler",
        "verify",
        "record-deployment",
        "publish",
    ]
    if failure:
        expected = expected[: expected.index(failure) + 1]
    assert [operation[0] for operation in operations] == expected
    assert not any(operation[1] for operation in operations)
    deployment_marker = marker.parent / "config/deploy-run.json"
    withdrawn_marker = operations[0][3]
    assert len(withdrawn_marker["inference_run"]) == 32
    if failure:
        assert json.loads(deployment_marker.read_text()) == withdrawn_marker
    else:
        staged = operations[2][3]
        assert staged == operations[-1][3]
        assert {"ollama", "models"} & staged.keys() == (set() if private else {"ollama", "models"})
        assert not deployment_marker.exists()
        assert payload.exists()


@pytest.mark.parametrize(
    ("schema", "install_state", "base_revision"),
    [
        (2, "installed", REVISION),
        (None, "installed", REVISION),
        (1, "initializing", REVISION),
        (1, "installed", BASE),
    ],
)
def test_inference_candidate_rejects_unowned_or_changing_deployment(
    isolated_site, schema, install_state, base_revision
):
    run, marker, payload = isolated_site
    extra = inference_candidate_vars() | {"steward_base_revision": base_revision}
    result, operations, _ = run(schema=schema, install_state=install_state, extra=extra)
    assert result.returncode == 2, result.stdout + result.stderr
    assert operations == []
    assert not payload.exists()
    assert not (marker.parent / "config/deploy-run.json").exists()


def repository_fetch_candidate_vars():
    return {
        "test_repository_fetch": True,
        "steward_base_revision": REVISION,
        "steward_hardening": {"firewall": {"manage": True}},
        "steward_repository_fetch": {
            "manifest": {
                "version": 1,
                "base_revision": REVISION,
                "firewall_sha256": "f" * 64,
                "endpoint": "93.184.216.34",
                "credential_required": False,
                "repository": {
                    "id": "shop-backend",
                    "application": "shop",
                    "service": "backend",
                    "url": "https://git.example.org/shop/backend.git",
                    "ref": "refs/heads/main",
                    "revision": "e" * 40,
                    "host_key": None,
                    "allow_private_network": False,
                },
            },
            "credential": None,
        },
    }


@pytest.mark.parametrize(
    "failure",
    [
        "",
        "check-base",
        "fetch-seal",
        "fetch-source",
        "verify",
        "record-deployment",
        "fetch-publish",
    ],
)
def test_repository_fetch_site_publication_is_last(isolated_site, failure):
    run, marker, _ = isolated_site
    active = marker.parent / "repository-fetch/active.json"
    active.parent.mkdir()
    active.write_text('{"old": true}')
    extra = repository_fetch_candidate_vars()
    result, operations, _ = run(schema=1, extra=extra, failure=failure)
    assert result.returncode == (2 if failure else 0), result.stdout + result.stderr
    expected = [
        "fetch-withdraw",
        "check-base",
        "fetch-seal",
        "fetch-source",
        "handler",
        "verify",
        "record-deployment",
        "fetch-publish",
    ]
    if failure:
        expected = expected[: expected.index(failure) + 1]
    assert [operation[0] for operation in operations] == expected
    assert not any(operation[1] for operation in operations)
    withdrawn_marker = operations[0][3]
    assert withdrawn_marker.keys() == {"base_revision", "desired_revision", "repository_fetch_run"}
    assert len(withdrawn_marker["repository_fetch_run"]) == 32
    marker_path = marker.parent / "config/deploy-run.json"
    if failure:
        assert json.loads(marker_path.read_text()) == withdrawn_marker
        assert not active.exists()
    else:
        manifest = extra["steward_repository_fetch"]["manifest"]
        assert operations[2][3] == manifest
        assert operations[-1][3] == {"manifest": manifest, "marker": withdrawn_marker}
        Publication.model_validate(operations[-1][3])
        assert json.loads(active.read_text()) == manifest
        assert not marker_path.exists()


@pytest.mark.parametrize(
    ("schema", "install_state", "base_revision"),
    [
        (2, "installed", REVISION),
        (None, "installed", REVISION),
        (1, "initializing", REVISION),
        (1, "installed", BASE),
    ],
)
def test_repository_fetch_requires_unchanged_installed_schema_one(
    isolated_site, schema, install_state, base_revision
):
    run, marker, payload = isolated_site
    extra = repository_fetch_candidate_vars() | {"steward_base_revision": base_revision}
    result, operations, _ = run(schema=schema, install_state=install_state, extra=extra)
    assert result.returncode == 2
    assert operations == []
    assert not payload.exists()
    assert not (marker.parent / "config/deploy-run.json").exists()


def test_ordinary_schema_one_site_withdraws_repository_fetch(isolated_site):
    run, marker, _ = isolated_site
    active = marker.parent / "repository-fetch/active.json"
    active.parent.mkdir()
    active.write_text('{"old": true}')
    result, operations, _ = run(schema=1, extra={"test_repository_fetch": True})
    assert result.returncode == 0, result.stdout + result.stderr
    assert operations[0][0] == "fetch-withdraw"
    assert [operation[0] for operation in operations] == [
        "fetch-withdraw",
        "handler",
        "verify",
        "record-deployment",
    ]
    assert not active.exists()
    assert not (marker.parent / "config/deploy-run.json").exists()


@pytest.mark.parametrize(
    ("authority", "mark", "failure", "marker_status", "locked_status"),
    [
        (None, True, "", "ok", "ok"),
        ("active.json", True, "", "changed", "ok"),
        ("ready", True, "", "changed", "ok"),
        ("incoming", True, "", "changed", "ok"),
        ("selection.json", True, "", "changed", "ok"),
        ("active.json", False, "", None, "changed"),
        ("build-verify.json", True, "", "ok", "changed"),
        ("active.json", True, "withdrawal", "fatal", None),
        ("active.json", False, "withdrawal", None, "fatal"),
        (None, True, "superseded", "ok", "ok"),
    ],
)
def test_unguarded_withdrawal_reports_durable_authority_removal(
    tmp_path, authority, mark, failure, marker_status, locked_status
):
    pytest.importorskip("ansible")
    marker = tmp_path / "etc/steward/config/deploy-run.json"
    marker.parent.mkdir(parents=True)
    active = marker.parent.parent / "repository-fetch/active.json"
    selection = marker.parent.parent / "inference/selection.json"
    custody = tmp_path / "var/lib/steward-repository-source-handoff"
    repository_authority = [
        active,
        custody / "ready",
        custody / ".staging/incoming",
        custody / "build-verify.json",
        custody / ".build-verify.incoming",
    ]
    for path in [*repository_authority, selection]:
        if path.name == authority:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()

    # Run the command bodies unchanged apart from redirecting fixed paths and imports.
    package = tmp_path / "steward"
    core = package / "core"
    core.mkdir(parents=True)
    for directory in (package, core):
        (directory / "__init__.py").touch()
    (package / "application_boot.py").write_text(
        "import json, os\n"
        "from contextlib import contextmanager\n"
        "locked = False\n"
        "@contextmanager\n"
        "def deployment_lock(*, timeout):\n"
        "    global locked\n"
        "    assert timeout == 30 and not locked\n"
        "    locked = True\n"
        "    try:\n"
        "        yield\n"
        "    finally:\n"
        "        locked = False\n"
        "def require(condition, message):\n"
        "    assert locked\n"
        "    if not condition:\n"
        "        raise RuntimeError(message)\n"
        "def sync_directory(path):\n"
        "    assert locked\n"
        "    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)\n"
        "    try:\n"
        "        os.fsync(fd)\n"
        "    finally:\n"
        "        os.close(fd)\n"
        "def store(path, record):\n"
        "    assert locked\n"
        "    if record.get('site_run') and " + repr(failure == "superseded") + ":\n"
        "        record = dict(record, site_run='superseding run')\n"
        "    path.write_text(json.dumps(record))\n"
        "    sync_directory(path.parent)\n"
        "def read_optional(path):\n"
        "    assert locked\n"
        "    return json.loads(path.read_text()) if path.exists() else None\n"
        "def remove(paths):\n"
        "    assert locked\n"
        "    for path in paths:\n"
        "        if path.exists():\n"
        "            path.unlink()\n"
        "            sync_directory(path.parent)\n"
    )
    (core / "repository_fetch_package.py").write_text(
        "from pathlib import Path\n"
        "from steward import application_boot as boot\n"
        "def withdraw_active():\n"
        f"    if {failure == 'withdrawal'!r}:\n"
        "        raise RuntimeError('withdrawal failed')\n"
        f"    boot.remove(map(Path, {[str(path) for path in repository_authority]!r}))\n"
    )
    (core / "inference_deployment.py").write_text(
        "from pathlib import Path\n"
        "from steward import application_boot as boot\n"
        "def revoke_for_desired(path):\n"
        f"    assert path == Path({str(marker.with_name('desired.json'))!r})\n"
        f"    boot.remove([Path({str(selection)!r})])\n"
    )

    site = yaml.safe_load((ANSIBLE / "playbooks/site.yml").read_text())
    repository = yaml.safe_load((ANSIBLE / "roles/platform/tasks/repository-fetch.yml").read_text())
    mark_name = "Mark the unguarded deployment run"
    clear_name = "Clear the unguarded deployment run marker"
    detect_name = "Detect installed or interrupted source handoff"
    locked_name = "Revoke ready source and withdraw the active manifest under the deployment lock"
    site_tasks = {
        task.get("name"): task
        for play in site
        for section in ("pre_tasks", "tasks", "post_tasks")
        for task in play.get(section, [])
    }
    repository_tasks = {task["name"]: task for task in repository[0]["block"]}
    tasks = [
        *([site_tasks[mark_name]] if mark else []),
        repository_tasks[detect_name],
        repository_tasks[locked_name],
        *([site_tasks[clear_name]] if mark else []),
    ]
    for task in tasks:
        if "ansible.builtin.command" in task:
            argv = task["ansible.builtin.command"]["argv"]
            assert argv[1:3] == ["-I", "-c"]
            argv[0] = sys.executable
            script = (
                argv[3]
                .replace("/etc/steward", f"{tmp_path}/etc/steward")
                .replace("/var/lib/steward-repository-source-handoff", str(custody))
            )
            argv[3] = (
                f"import sys\nsys.dont_write_bytecode = True\n"
                f"sys.path.insert(0, {str(tmp_path)!r})\n" + script
            )

    def stat_results(*present):
        return {"results": [{"stat": {"exists": exists}} for exists in present]}

    playbook = tmp_path / "report.yml"
    playbook.write_text(
        yaml.safe_dump(
            [
                {
                    "hosts": "localhost",
                    "connection": "local",
                    "gather_facts": False,
                    "vars": {
                        "ansible_python_interpreter": sys.executable,
                        "ansible_remote_tmp": str(tmp_path / "remote-tmp"),
                        "preflight_guarded": False,
                        "steward_base_revision": REVISION,
                        "site_run_marker": {
                            "base_revision": REVISION,
                            "desired_revision": REVISION,
                            "site_run": "e" * 32,
                        },
                        # An installed source-handoff fragment keeps the later task eligible.
                        "platform_repository_fetch_fragments": stat_results(False, True, False),
                        "platform_repository_fetch_paths": stat_results(*([False] * 10)),
                    },
                    "tasks": tasks,
                }
            ]
        )
    )
    env = {key: value for key, value in os.environ.items() if not key.startswith("ANSIBLE_")}
    env.update(
        ANSIBLE_CONFIG=str(ANSIBLE / "ansible.cfg"),
        ANSIBLE_LOCAL_TEMP=str(tmp_path / "local-tmp"),
        ANSIBLE_NOCOLOR="1",
    )
    result = subprocess.run(
        [
            str(Path(sys.executable).with_name("ansible-playbook")),
            "-i",
            "localhost,",
            str(playbook),
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    output = result.stdout + result.stderr
    assert result.returncode == (2 if failure else 0), output
    if not failure:
        expected_changed = [marker_status, locked_status].count("changed")
        assert f"changed={expected_changed} " in output.rsplit("PLAY RECAP", 1)[-1], output
    clear_status = {"": "ok", "superseded": "fatal"}.get(failure) if mark else None
    for name, status in [
        (mark_name, marker_status),
        (locked_name, locked_status),
        (clear_name, clear_status),
    ]:
        if status is None:
            assert f"TASK [{name}]" not in output, output
        else:
            assert (
                f"{status}: [localhost]"
                in output.split(f"TASK [{name}]", 1)[1].split("\nTASK [", 1)[0]
            ), output
    assert active.exists() == (failure == "withdrawal")
    assert not any(path.exists() for path in [*repository_authority[1:], selection])
    assert marker.exists() == (failure == "superseded")
    if failure == "withdrawal":
        assert "withdrawal failed" in output
    if failure == "superseded":
        assert "site deployment was superseded" in output
