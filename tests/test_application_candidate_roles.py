import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from jinja2 import Environment

from steward import application_boot, application_layout
from steward.executor.host import Host

ROLES = Path(__file__).resolve().parents[1] / "ansible/roles"


def helper(role, name):
    path = ROLES / role / "files" / f"application-{name}.py"
    spec = importlib.util.spec_from_file_location(f"application_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tasks(role, name):
    return yaml.safe_load((ROLES / role / "tasks" / f"{name}.yml").read_text())


@pytest.fixture
def firewall():
    return helper("workloads", "firewall")


def table_with_dispatch(uid, chain):
    return {
        "nftables": [
            {
                "rule": {
                    "family": "inet",
                    "table": "steward",
                    "chain": "output",
                    "expr": [
                        {
                            "vmap": {
                                "key": {"meta": {"key": "skuid"}},
                                "data": {"set": [[uid, {"jump": {"target": chain}}]]},
                            },
                        }
                    ],
                }
            }
        ]
    }


def test_verified_firewall_matches_live_numeric_dispatch(firewall):
    policy = {
        "state": "verified",
        "source": "wanted",
        "runtime": "live",
        "verified_runtime": "live",
    }
    firewall.require_verified_firewall(
        policy, "wanted", {"30000": "egress_app"}, table_with_dispatch(30000, "egress_app")
    )


@pytest.mark.parametrize(
    ("state", "source", "live", "uid", "chain", "failure"),
    [
        ("legacy", "wanted", "live", 30000, "egress_app", "verified application policy"),
        ("verified", "other", "live", 30000, "egress_app", "verified application policy"),
        ("verified", "wanted", "drift", 30000, "egress_app", "verified application policy"),
        ("verified", "wanted", "live", 30001, "egress_app", "expected verdict"),
        ("verified", "wanted", "live", "30000", "egress_app", "numerical UID"),
        ("verified", "wanted", "live", 30000, "other", "expected verdict"),
    ],
)
def test_reject_unverified_or_wrong_application_dispatch(
    firewall, state, source, live, uid, chain, failure
):
    policy = {"state": state, "source": source, "runtime": live, "verified_runtime": "live"}
    with pytest.raises(ValueError, match=failure):
        firewall.require_verified_firewall(
            policy, "wanted", {"30000": "egress_app"}, table_with_dispatch(uid, chain)
        )


def test_data_leaf_type_mode_and_owner_are_verified_without_mutation(tmp_path):
    leaf = tmp_path / "data"
    uid, gid = os.getuid(), os.getgid()
    assert application_layout.exact_directory(leaf, uid, gid, 0o700, create=True)
    (leaf / "file").write_text("keep")
    assert not application_layout.exact_directory(leaf, uid, gid, 0o700, create=True)
    with pytest.raises(ValueError, match="ownership"):
        application_layout.exact_directory(leaf, uid + 1, gid, 0o700, create=True)
    leaf.chmod(0o755)
    with pytest.raises(ValueError, match="mode"):
        application_layout.exact_directory(leaf, uid, gid, 0o700, create=True)
    assert (leaf / "file").read_text() == "keep"
    assert leaf.stat().st_mode & 0o777 == 0o755
    symlink = tmp_path / "unexpected"
    symlink.symlink_to(leaf)
    with pytest.raises(ValueError, match="type"):
        application_layout.exact_directory(symlink, uid, gid, 0o755, create=True)


def test_persistent_subid_ranges_are_unique_and_disjoint(tmp_path):
    identity = helper("identities", "identity")
    path = tmp_path / "subuid"
    path.write_text("30000:200000:65536\nother:265536:65536\n")
    assert identity.validate_ranges(path, "app", 30000, {30000}) == [200000, 65536]
    path.write_text("app:200000:65536\nother:265535:65536\n")
    with pytest.raises(ValueError, match="overlapping subordinate"):
        identity.validate_ranges(path, "app", 30000, {30000})
    path.write_text("app:200000:65536\n")
    with pytest.raises(ValueError, match="overlaps a local identity"):
        identity.validate_ranges(path, "app", 30000, {30000, 200000})


@pytest.fixture
def entry():
    return {
        "uid": 30000,
        "user": "app",
        "unit": "svc.service",
        "port": 19000,
        "identity": {
            "uid": 30000,
            "gid": 30000,
            "subuid": [200000, 65536],
            "subgid": [200000, 65536],
        },
    }


def test_preflight_allows_only_owned_existing_port(entry):
    transition = helper("identities", "transition")

    def inactive(_):
        return "inactive"

    transition.verify_transition([entry], [entry], {19000: {30000}}, inactive, inactive, {30000})
    with pytest.raises(ValueError, match="unexpected listener"):
        transition.verify_transition([], [entry], {19000: {30000}}, inactive, inactive, {30000})
    with pytest.raises(ValueError, match="unexpected listener"):
        transition.verify_transition([entry], [entry], {19000: {30000, 0}}, inactive, inactive, {0})


def test_preflight_rejects_identity_drift_or_active_dropped_uid(entry):
    transition = helper("identities", "transition")

    def active(_):
        return "active"

    def inactive(_):
        return "inactive"

    changed = {**entry, "identity": {**entry["identity"], "subuid": [300000, 65536]}}
    with pytest.raises(ValueError, match="subordinate ranges changed"):
        transition.verify_transition([entry], [changed], {}, inactive, inactive, set())
    with pytest.raises(ValueError, match="stop the user manager"):
        transition.verify_transition([entry], [], {}, inactive, active, set())
    with pytest.raises(ValueError, match="all processes"):
        transition.verify_transition([entry], [], {}, inactive, inactive, {30000})
    with pytest.raises(ValueError, match="stop svc.service"):
        transition.verify_transition([entry], [], {}, active, inactive, set())
    transition.verify_transition([entry], [], {}, inactive, inactive, set())


def test_guarded_proof_only_checks_managers_for_whole_uid_removals(entry):
    transition = helper("identities", "transition")
    other_unit = {**entry, "unit": "other.service", "port": None}

    def inactive(_):
        return "inactive"

    # The remaining unit keeps the same UID, so no retired account proof is needed.
    transition.verify_transition(
        [entry, other_unit], [other_unit], {}, inactive, inactive, (), guarded=True
    )


def test_guarded_transition_requires_pinned_identity_exact_quiescence_and_empty_port(
    entry, monkeypatch
):
    transition = helper("identities", "transition")
    user = "stw-a" + "1" * 20
    entry["user"] = user
    identity = entry["identity"]
    checks = []
    sockets = []

    def inspect_identity(username):
        assert username == user
        return identity

    def quiescent(_host, uid, subuid):
        checks.append((uid, subuid))
        return len(checks) > 1

    def inactive(_):
        return "inactive"

    def tcp_sockets():
        assert len(checks) > 1
        return sockets

    monkeypatch.setattr(application_boot, "inspect_identity", inspect_identity)
    monkeypatch.setattr(Host, "application_manager_quiescent", quiescent)
    monkeypatch.setattr(Host, "_tcp_sockets", staticmethod(tcp_sockets))

    def verify(previous):
        transition.verify_transition(previous, [], {}, inactive, inactive, (), guarded=True)

    with pytest.raises(ValueError, match="Stop the user manager"):
        verify([entry])
    for port, owner in (
        (entry["port"], 0),
        (entry["port"] + 1, identity["uid"]),
        (entry["port"] + 1, identity["subuid"][0]),
    ):
        sockets[:] = [("0100007F", port, owner, "0A")]
        with pytest.raises(ValueError, match="have no TCP listeners"):
            verify([entry])
    sockets[:] = [("0100007F", entry["port"] + 1, 0, "0A")]
    verify([entry])
    assert checks == [(identity["uid"], identity["subuid"])] * 5

    with pytest.raises(ValueError, match="conflicting identities"):
        verify([entry, {**entry, "user": "stw-s" + "2" * 20}])
    with pytest.raises(ValueError, match="cannot prove"):
        verify([{**entry, "user": "../untrusted"}])
    assert len(checks) == 5


def test_raw_application_secret_value_is_used_for_copy_and_digest():
    secret_tasks = tasks("workloads", "application-secrets")
    digest = secret_tasks[3]
    copy = tasks("workloads", "application-secrets-install")[0]
    assert digest["no_log"] and copy["no_log"] and copy["diff"] is False
    template = digest["vars"]["application_environment"]
    assert (
        "application_environment | hash('sha256')"
        in digest["ansible.builtin.set_fact"]["workload_application_secrets"]
    )
    assert (
        "'content': application_environment"
        in digest["ansible.builtin.set_fact"]["workload_application_secret_payloads"]
    )
    assert copy["ansible.builtin.copy"]["content"] == (
        "{{ workload_application_secret_payloads[application_service.id].content }}"
    )
    env = Environment(trim_blocks=True, keep_trailing_newline=True)  # noqa: S701
    secret = 'literal="quoted"\\value'
    rendered = env.from_string(template).render(workload_service_secret_values={"TOKEN": secret})
    assert rendered == f"TOKEN={secret}\n"


def test_failed_or_interrupted_activation_replays_independent_of_copy_results():
    role = tasks("workloads", "application")
    by_name = {task["name"]: task for task in role}
    replay = by_name["Determine whether application activation must be replayed"]
    expr = replay["ansible.builtin.set_fact"]["workload_application_replay"]
    env = Environment(autoescape=True)
    env.filters["b64decode"] = lambda value: value
    template = env.from_string(expr)
    wanted = {"workload_application_fingerprint": "wanted"}
    assert template.render(workload_application_activated={}, **wanted) == "True"
    assert (
        template.render(workload_application_activated={"content": "previous"}, **wanted) == "True"
    )
    assert (
        template.render(workload_application_activated={"content": "wanted"}, **wanted) == "False"
    )

    reverse_stop = by_name[
        "Stop changed or explicitly stopped services in reverse dependency order"
    ]
    assert "workload_application_replay" in reverse_stop["when"]
    assert "| reverse" in reverse_stop["loop"]
    names = list(by_name)
    assert names.index("Recheck the firewall before starting this application's user managers") < (
        names.index("Start application user managers for this boot")
    )
    drain = names.index("Drain previous application routes before replay changes an application")
    assert names.index("Determine whether application activation must be replayed") < drain
    assert drain < names.index(
        "Materialize protected application environment files after route drain"
    )
    assert drain < names.index(
        "Stop changed or explicitly stopped services in reverse dependency order"
    )
    assert names.index("Verify the loaded sources of the managed Quadlets") < (
        names.index("Activate and health-check enabled services in dependency order")
    )
    assert (
        names.index("Start and verify the shared pod before starting its enabled services")
        < (names.index("Prepare data mapped through the running shared pod"))
        < names.index("Activate and health-check enabled services in dependency order")
    )
    assert names.index("Activate and health-check enabled services in dependency order") < (
        names.index("Verify desired state for every managed service")
    )
    assert names[-1] == "Record successful application activation"

    activation = tasks("workloads", "application-start")
    assert activation[0]["ansible.builtin.include_tasks"] == "application-firewall.yml"
    assert "ansible.builtin.uri" in activation[2]


def test_app_unit_authority_rejects_user_unit_and_dropins():
    role = tasks("workloads", "application-authority")[0]
    template = Environment(autoescape=True).from_string("{{ " + role["failed_when"] + " }}")
    expected = [
        "LoadState=loaded",
        "UnitFileState=generated",
        "DropInPaths=",
        "SourcePath=/etc/containers/systemd/users/30000/app.container",
    ]

    def fails(lines, *, allow_missing=False):
        return (
            template.render(
                application_allow_missing_unit=allow_missing,
                application_unit={"user": "app", "filename": "app.container"},
                steward_uids={"app": 30000},
                workload_application_authority={"rc": 0, "stdout_lines": lines},
            )
            == "True"
        )

    assert not fails(expected)
    assert fails([*expected[:-1], "SourcePath=/srv/steward/application-users/app/app.container"])
    assert fails([*expected[:2], "DropInPaths=/tmp/override.conf", expected[3]])
    assert fails([expected[0], "UnitFileState=enabled", *expected[2:]])
    assert fails(["LoadState=not-found"])
    assert not fails(["LoadState=not-found"], allow_missing=True)


def test_optional_pod_task_conditions_under_real_ansible(tmp_path):
    executable = Path(sys.executable).parent / "ansible-playbook"
    if not executable.exists():
        pytest.skip("controller Ansible environment is not installed")

    pod_tasks = {
        task["name"]: task["when"]
        for task in tasks("workloads", "application")
        if task.get("vars", {}).get("application_unit") == "{{ application.pod }}"
    }
    probes = [
        {
            "name": name,
            "ansible.builtin.debug": {"msg": name},
            "when": condition,
            "register": f"pod_probe_{index}",
        }
        for index, (name, condition) in enumerate(pod_tasks.items())
    ]
    assert len(probes) == 3
    shared_pod = {"unit": "shared-pod.service"}
    cases = [
        (None, [], True, (False, False, False)),
        (None, ["service"], False, (False, False, False)),
        (shared_pod, ["service"], False, (False, True, True)),
        (shared_pod, ["service"], True, (True, True, True)),
        (shared_pod, [], False, (True, False, True)),
    ]
    blocks = []
    for pod, enabled, replay, expected in cases:
        comparisons = [
            f"(pod_probe_{index} is skipped) == {'false' if runs else 'true'}"
            for index, runs in enumerate(expected)
        ]
        blocks.append(
            {
                "vars": {
                    "application": {"pod": pod},
                    "workload_application_enabled": enabled,
                    "workload_application_replay": replay,
                },
                "block": [*probes, {"ansible.builtin.assert": {"that": comparisons}}],
            }
        )
    playbook = tmp_path / "play.yml"
    playbook.write_text(
        yaml.safe_dump([{"hosts": "localhost", "gather_facts": False, "tasks": blocks}])
    )
    env = os.environ.copy()
    env.update(
        ANSIBLE_LOCAL_TEMP=str(tmp_path / "ansible-local"),
        ANSIBLE_NOCOLOR="1",
        ANSIBLE_ALLOW_BROKEN_CONDITIONALS="false",
    )
    result = subprocess.run(
        [str(executable), "-i", "localhost,", "-c", "local", str(playbook)],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_mapped_data_role_checks_before_children_and_cleans_up_only_its_empty_pod(tmp_path):
    executable = Path(sys.executable).parent / "ansible-playbook"
    if not executable.exists():
        pytest.skip("controller Ansible environment is not installed")

    stop = tmp_path / "stop.yml"
    stop.write_text("- ansible.builtin.set_fact:\n    pod_stopped: true\n")
    shim = tmp_path / "mapped_layout.py"
    shim.write_text(
        "import json, sys\n"
        "payload = json.load(sys.stdin)\n"
        "assert payload['application']['id'] == 'example'\n"
        "print('{\"changed\": false}')\n"
        "raise SystemExit(int(sys.argv[1]))\n"
    )
    mapping_file = tmp_path / "mapped.yml"
    [mapping_block] = tasks("workloads", "application-mapped-data")
    mapping_block["block"][0]["ansible.builtin.command"]["argv"] = [
        sys.executable,
        str(shim),
        "{{ mapping_result }}",
    ]
    inspect, stop_pod = mapping_block["rescue"][0]["block"]
    inspect["ansible.builtin.command"]["argv"] = ["/bin/echo", "{{ pod_inspect | to_json }}"]
    inspect.pop("become")
    inspect.pop("become_user")
    stop_pod["ansible.builtin.include_tasks"] = str(stop)
    mapping_file.write_text(yaml.safe_dump([mapping_block]))

    mapping = next(
        task
        for task in tasks("workloads", "application")
        if task.get("ansible.builtin.include_tasks") == "application-mapped-data.yml"
    )
    mapping["ansible.builtin.include_tasks"] = str(mapping_file)
    pod = {"user": "example", "filename": "apppod.pod", "unit": "apppod-pod.service"}
    blocks = []
    for mapped, result, freshly_started, foreign, refused, stopped in (
        (False, 1, False, False, False, False),
        (True, 0, False, False, False, False),
        (True, 1, True, False, True, True),
        (True, 1, False, False, True, False),
        (True, 1, True, True, True, False),
    ):
        members = [{"Id": "a" * 64}]
        if foreign:
            members.append({"Id": "b" * 64})
        blocks.append(
            {
                "vars": {
                    "application": {"id": "example", "pod": pod if mapped else None},
                    "steward_application_ids": {},
                    "steward_uids": {"example": 30000},
                    "workload_application_enabled": [{"data_needs_mapped_owner": mapped}],
                    "workload_application_started": {"changed": freshly_started},
                    "mapping_result": result,
                    "pod_inspect": [
                        {
                            "Name": "steward-apppod",
                            "Labels": {"PODMAN_SYSTEMD_UNIT": pod["unit"]},
                            "InfraContainerID": members[0]["Id"],
                            "Containers": members,
                        }
                    ],
                },
                "block": [
                    {
                        "ansible.builtin.set_fact": {
                            "pod_stopped": False,
                            "activation_refused": False,
                        }
                    },
                    {
                        "block": [mapping],
                        "rescue": [
                            {
                                "ansible.builtin.set_fact": {
                                    "activation_refused": "{{ ansible_failed_task.action == 'ansible.builtin.fail' }}"
                                }
                            }
                        ],
                    },
                    {
                        "ansible.builtin.assert": {
                            "that": [
                                f"pod_stopped == {json.dumps(stopped)}",
                                f"activation_refused == {json.dumps(refused)}",
                            ]
                        }
                    },
                ],
            }
        )
    play = tmp_path / "play.yml"
    play.write_text(
        yaml.safe_dump([{"hosts": "localhost", "gather_facts": False, "tasks": blocks}])
    )
    env = {
        **os.environ,
        "ANSIBLE_LOCAL_TEMP": str(tmp_path / "ansible-local"),
        "ANSIBLE_NOCOLOR": "1",
        "ANSIBLE_ALLOW_BROKEN_CONDITIONALS": "false",
    }
    result = subprocess.run(
        [str(executable), "-i", "localhost,", "-c", "local", str(play)],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("private", [False, True])
def test_replay_drains_routes_before_replacing_exact_secret_under_real_ansible(tmp_path, private):
    executable = Path(sys.executable).parent / "ansible-playbook"
    if not executable.exists():
        pytest.skip("controller Ansible environment is not installed")

    old_env = tmp_path / "secret.env"
    old_env.write_text("TOKEN=old\n")
    marker = tmp_path / "drained"
    drain = tmp_path / "drain.py"
    drain.write_text(
        "import json, pathlib, sys\n"
        "assert pathlib.Path(sys.argv[1]).read_text() == 'TOKEN=old\\n'\n"
        "assert sys.argv[4:] == json.loads(sys.argv[3])\n"
        "pathlib.Path(sys.argv[2]).touch(exist_ok=False)\n"
        "print('{\"changed\": true}')\n"
    )
    plans = tasks("workloads", "application-secrets")
    (tmp_path / "application-secrets.yml").write_text(yaml.safe_dump(plans))
    install = tasks("workloads", "application-secrets-install")[0]
    copy = install["ansible.builtin.copy"]
    copy["dest"] = str(old_env)
    copy.pop("owner")
    copy.pop("group")
    (tmp_path / "application-secrets-install.yml").write_text(yaml.safe_dump([install]))
    by_name = {task["name"]: task for task in tasks("workloads", "application")}
    observe = by_name["Drain previous application routes before replay changes an application"]
    argv = observe["ansible.builtin.command"]["argv"].strip()
    observe["ansible.builtin.command"]["argv"] = "{{ test_prefix + (" + argv[2:-2] + ") }}"
    private_arguments = [
        "--deployment-operation-id",
        "a" * 32,
        "--deployment-run-id",
        "b" * 32,
        "--deployment-boot-id",
        "12345678-1234-1234-1234-123456789abc",
        "--deployment-revision",
        "c" * 64,
    ]
    expected = [
        "/opt/steward/current/venv/bin/python",
        "-m",
        "steward.application_boot",
        "drain-routes",
        "d" * 64,
    ] + (private_arguments if private else [])
    play = [
        {
            "hosts": "localhost",
            "gather_facts": False,
            "vars": {
                "application": {
                    "id": "test-app",
                    "services": [
                        {
                            "id": "backend",
                            "user": "app",
                            "deploy": True,
                            "secrets": [
                                {"name": "TOKEN", "kind": "env", "target": "TEST_APP_SECRET"}
                            ],
                        }
                    ],
                },
                "steward_release": {"files": {}},
                "steward_nftables": "verified policy",
                "steward_proxy": {"application_runtime": "/run/steward-proxy-dynamic"},
                "identities_application_boot_previous": True,
                "identities_application_boot_generation": "d" * 64,
                "site_private_application": private,
                "site_application_boot_arguments": private_arguments,
                "test_prefix": [
                    sys.executable,
                    str(drain),
                    str(old_env),
                    str(marker),
                    json.dumps(expected),
                ],
            },
            "tasks": [
                by_name["Prepare per-application activation inputs"],
                by_name["Read and hash planned protected application environment files"],
                by_name["Calculate desired application activation fingerprint"],
                by_name["Determine whether application activation must be replayed"],
                observe,
                by_name["Materialize protected application environment files after route drain"],
                {
                    "ansible.builtin.assert": {
                        "that": ["workload_application_routes_drained is changed"]
                    }
                },
            ],
        }
    ]
    playbook = tmp_path / "play.yml"
    playbook.write_text(yaml.safe_dump(play))
    secret = 'literal="quoted"\\value'
    env = {
        **os.environ,
        "ANSIBLE_LOCAL_TEMP": str(tmp_path / "ansible-local"),
        "ANSIBLE_NOCOLOR": "1",
        "ANSIBLE_ALLOW_BROKEN_CONDITIONALS": "false",
        "TEST_APP_SECRET": secret,
    }
    result = subprocess.run(
        [str(executable), "-i", "localhost,", "-c", "local", "--diff", str(playbook)],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert marker.exists()
    assert old_env.read_text() == f"TOKEN={secret}\n"
    assert "quoted" not in result.stdout + result.stderr


def test_project_image_archive_is_keyed_by_image_and_tag():
    """Projects sharing one digest need separate archives: each carries its own tag."""
    from pathlib import Path

    text = (
        Path(__file__).resolve().parents[1] / "ansible/roles/workloads/tasks/project.yml"
    ).read_text()
    assert "[project.image, project.image_tag] | to_json | hash('sha256')" in text
