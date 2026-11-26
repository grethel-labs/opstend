import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from steward.core.config import Ai, ConfigError, effective, parse_config
from steward.core.render import (
    _render_local_ai_candidate_vars,
    _render_local_ai_selection_candidate_vars,
    render_vars,
)
from steward.executor.site_deployment import config_from

PLATFORM = Path(__file__).resolve().parents[1] / "ansible/roles/platform"
RENDER_ARGS = {"release": {"version": "0.1.0"}, "ssh_port": 22}
WHEEL = "steward-0.1.0-py3-none-any.whl"
SELECTION_ARGS = {
    **RENDER_ARGS,
    "release": {"version": "0.1.0", "wheel": WHEEL, "files": {WHEEL: "a" * 64}},
    "manifest_sha256": "b" * 64,
}


@pytest.fixture
def candidate_raw(raw_config):
    return {
        **raw_config,
        "profile": "local-ai",
        "ai": {
            "provider": "ollama",
            "model": "fixture:tiny",
            "local_only": True,
            "local": {"download_mb": 1, "ram_mb": 128, "disk_mb": 2, "license_ack": True},
        },
    }


def test_candidate_adds_only_local_overlay(candidate_raw):
    cfg = parse_config(candidate_raw, allow_unavailable=True)
    base = render_vars(cfg.model_copy(update={"profile": "api", "ai": Ai()}), **RENDER_ARGS)
    result = _render_local_ai_candidate_vars(cfg, **RENDER_ARGS)
    assert result.pop("steward_ollama_local") == {
        "ai": cfg.ai.model_dump(mode="json"),
        "reserved_memory_mb": base["steward_required_memory_mb"],
    }
    assert result == base
    assert config_from(result["steward_desired_config"]).profile == "api"


@pytest.mark.parametrize(
    ("changes", "ai_changes", "reason"),
    [
        ({"profile": "api"}, {}, "local-ai profile"),
        ({}, {"provider": "none"}, "ollama provider"),
        ({}, {"local_only": False}, "local_only"),
        ({}, {"local": None}, "ai.local"),
        ({}, {"model": None}, "ai.model"),
        ({}, {"base_url": "http://127.0.0.1:11435"}, "fixed loopback"),
    ],
)
def test_candidate_rejects_invalid_local_settings(candidate_raw, changes, ai_changes, reason):
    cfg = parse_config(candidate_raw, allow_unavailable=True)
    cfg = cfg.model_copy(update={**changes, "ai": cfg.ai.model_copy(update=ai_changes)})
    with pytest.raises(ValueError, match=reason):
        _render_local_ai_candidate_vars(cfg, **RENDER_ARGS)


def test_candidate_requires_license_ack(candidate_raw):
    candidate_raw["ai"]["local"]["license_ack"] = False
    cfg = parse_config(candidate_raw, allow_unavailable=True)
    with pytest.raises(ValueError, match="license_ack"):
        _render_local_ai_candidate_vars(cfg, **RENDER_ARGS)


def test_candidate_rejects_other_unavailable_features(candidate_raw):
    candidate_raw["automation"] = {"profile": "patch"}
    cfg = parse_config(candidate_raw, allow_unavailable=True)
    with pytest.raises(ValueError, match=r"automation\.patch"):
        _render_local_ai_candidate_vars(cfg, **RENDER_ARGS)


def test_local_candidate_leaves_release_guards_in_place(candidate_raw):
    cfg = parse_config(candidate_raw, allow_unavailable=True)
    for validator in (parse_config, config_from):
        with pytest.raises(ConfigError) as rejected:
            validator(effective(cfg))
        assert any(
            "profile.local-ai: not available" in problem for problem in rejected.value.problems
        )
        assert any("ai.provider: not available" in problem for problem in rejected.value.problems)


def test_platform_invokes_fixed_helper_without_download_tasks():
    tasks = yaml.safe_load((PLATFORM / "tasks/ollama.yml").read_text())
    blocks = [task for task in tasks if "block" in task]
    block = next(task for task in blocks if "steward_ollama_local is defined" in task["when"])
    main = yaml.safe_load((PLATFORM / "tasks/main.yml").read_text())
    include = next(
        task for task in main if task.get("ansible.builtin.include_tasks") == "ollama.yml"
    )
    for task in tasks + block["block"]:
        assert "ansible.builtin.get_url" not in task and "ansible.builtin.uri" not in task
    install_task, *after_install = block["block"]
    installer = install_task["ansible.builtin.command"]
    assert installer["argv"] == [
        "/opt/steward/current/venv/bin/python",
        "-I",
        "-m",
        "steward.core.ollama_install",
    ]
    assert installer["stdin"] == "{{ steward_ollama_local | to_json }}"

    # A command's nonzero exit fails the block by default. The role must
    # preserve that behavior and put every activation write after the command.
    for task in (include, block, install_task):
        assert "failed_when" not in task
        assert "ignore_errors" not in task
    assert "rescue" not in block
    assert "always" not in block
    for module in ("group", "user", "template", "systemd_service", "copy"):
        action = f"ansible.builtin.{module}"
        assert any(action in task for task in after_install)
        if module != "systemd_service":
            assert not any(action in task for task in tasks)
    for task in tasks:
        if "ansible.builtin.systemd_service" in task:
            assert "steward_ollama_local is undefined" in task["when"]
            assert task["ansible.builtin.systemd_service"]["state"] == "stopped"


def test_ollama_unit_has_private_network_and_devices():
    text = (PLATFORM / "templates/steward-ollama.service.j2").read_text()
    for line in (
        "User=steward-ai",
        "PrivateNetwork=yes",
        "PrivateDevices=yes",
        "Environment=OLLAMA_NO_CLOUD=1",
        "Environment=OLLAMA_NOPRUNE=1",
        "Environment=OLLAMA_HOST=127.0.0.1:11434",
        "Environment=OLLAMA_NUM_PARALLEL=1",
    ):
        assert line in text.splitlines()
    assert "platform_ollama_artifacts.models" in text


@pytest.mark.parametrize("scenario", ["owned", "foreign", "override"])
def test_ollama_service_ownership_with_ansible(tmp_path, scenario):
    executable = Path(sys.executable).parent / "ansible-playbook"
    if not executable.exists():
        pytest.skip("controller Ansible environment is not installed")
    systemd = pytest.importorskip("ansible.modules.systemd_service")
    jinja = pytest.importorskip("jinja2")
    unit = tmp_path / "steward-ollama.service"
    overlay = {"ai": {"local": {"ram_mb": 128}}, "reserved_memory_mb": 128}
    template = jinja.Environment(keep_trailing_newline=True).from_string(
        (PLATFORM / "templates/steward-ollama.service.j2").read_text()
    )
    rendered = template.render(
        platform_ollama_artifacts={"binary": tmp_path / "ollama", "models": tmp_path / "models"},
        steward_ollama_local=overlay,
    )
    if scenario == "foreign":
        rendered = rendered.replace("# Generated by steward - do not edit.", "# Foreign service")
    unit.write_text(rendered)
    unit.chmod(0o644)

    systemctl = tmp_path / "systemctl"
    systemctl.write_text(
        f"#!{sys.executable}\n"
        f"UNIT = {str(unit)!r}\n"
        f"OVERRIDE = {scenario == 'override'!r}\n"
        """\
import sys
from pathlib import Path

root = Path(__file__).parent
verb, *args = sys.argv[1:]
assert Path(UNIT).name in args, args
with (root / "systemctl.log").open("a") as log:
    print(verb, file=log)
disabled = root / "disabled"
stopped = root / "stopped"
if verb == "show":
    print("LoadState=loaded")
    print(f"FragmentPath={UNIT}")
    print(f"DropInPaths={UNIT}.d/override.conf" if OVERRIDE else "DropInPaths=")
    print("NeedDaemonReload=no")
    print("PrivateNetwork=yes")
    print("NetworkNamespacePath=")
    print("JoinsNamespaceOf=")
    print("ActiveState=inactive" if stopped.exists() else "ActiveState=active")
elif verb == "is-enabled":
    print("disabled" if disabled.exists() else "enabled")
    sys.exit(int(disabled.exists()))
elif verb == "disable":
    disabled.touch(exist_ok=False)
elif verb == "stop":
    stopped.touch(exist_ok=False)
else:
    sys.exit(f"unexpected systemctl command: {verb}")
"""
    )
    systemctl.chmod(0o700)

    # Bind both systemctl callers to the temporary executable. The stock module's
    # executable search can fall back to system directories even with PATH set.
    library = tmp_path / "library"
    library.mkdir()
    module_source = Path(systemd.__file__).read_text()
    lookup = "systemctl = module.get_bin_path('systemctl', True)"
    assert module_source.count(lookup) == 1
    (library / "ollama_test_systemd_service.py").write_text(
        module_source.replace(lookup, f"systemctl = {str(systemctl)!r}")
    )

    # Include only inspection and deactivation. Candidate installation and
    # activation tasks are excluded before Ansible loads the playbook.
    tasks = []
    for task in yaml.safe_load((PLATFORM / "tasks/ollama.yml").read_text()):
        if "block" in task:
            continue
        for action in ("ansible.builtin.stat", "ansible.builtin.slurp"):
            if action in task:
                assert task[action]["path"] == "/etc/systemd/system/steward-ollama.service"
                task[action]["path"] = str(unit)
        if "ansible.builtin.command" in task:
            argv = task["ansible.builtin.command"]["argv"]
            assert argv[0] == "/usr/bin/systemctl"
            argv[0] = str(systemctl)
        if "ansible.builtin.systemd_service" in task:
            task["ollama_test_systemd_service"] = task.pop("ansible.builtin.systemd_service")
        if "platform_ollama_expected_source" in task.get("ansible.builtin.set_fact", {}):
            facts = task["ansible.builtin.set_fact"]
            facts["platform_ollama_expected_source"] = facts[
                "platform_ollama_expected_source"
            ].replace("/etc/systemd/system/steward-ollama.service", str(unit))
        if task.get("register") == "platform_ollama_unit_content":
            task["when"] = [
                condition.replace("stat.uid == 0", f"stat.uid == {os.getuid()}")
                for condition in task["when"]
            ]
        tasks.append(task)

    variables = {
        "ansible_python_interpreter": sys.executable,
        "ansible_remote_tmp": str(tmp_path / "remote"),
    }
    if scenario == "foreign":
        variables.update(
            steward_ollama_local=overlay,
            steward_required_memory_mb=128,
            steward_desired_config={"profile": "api", "ai": {"provider": "none"}},
            ansible_facts={"architecture": "x86_64"},
        )
    playbook = tmp_path / "test.yml"
    playbook.write_text(
        yaml.safe_dump(
            [
                {
                    "hosts": "localhost",
                    "connection": "local",
                    "gather_facts": False,
                    "vars": variables,
                    "tasks": tasks,
                }
            ]
        )
    )
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\n")

    def run_playbook():
        return subprocess.run(
            [str(executable), "-i", "localhost,", str(playbook)],
            cwd=tmp_path,
            env={
                "PATH": f"{executable.parent}:/usr/bin:/bin",
                "HOME": str(tmp_path),
                "ANSIBLE_CONFIG": str(config),
                "ANSIBLE_LIBRARY": str(library),
                "ANSIBLE_LOCAL_TEMP": str(tmp_path / "local"),
            },
            capture_output=True,
            text=True,
            timeout=90,
        )

    result = run_playbook()
    log = tmp_path / "systemctl.log"
    calls = log.read_text().splitlines() if log.exists() else []
    if scenario == "owned":
        assert result.returncode == 0, result.stdout + result.stderr
        assert calls == ["show", "show", "is-enabled", "disable", "stop"], result.stdout
        assert "changed=1" in result.stdout
        log.unlink()
        retry = run_playbook()
        assert retry.returncode == 0, retry.stdout + retry.stderr
        assert "changed=0" in retry.stdout
        assert log.read_text().splitlines() == ["show", "show", "is-enabled"]
    elif scenario == "foreign":
        assert result.returncode == 2, result.stdout + result.stderr
        assert "TASK [Refuse to replace a foreign Ollama service file]" in result.stdout
        assert "not platform_ollama_unit_file.stat.exists or platform_ollama_owned" in result.stdout
        assert calls == []
    else:
        assert result.returncode == 2, result.stdout + result.stderr
        assert "The managed Ollama service has a foreign systemd source or overrides." in (
            result.stdout
        )
        assert calls == ["show"]
    assert unit.read_text() == rendered


def test_selection_candidate_adds_only_release_and_manifest_binding(candidate_raw):
    cfg = parse_config(candidate_raw, allow_unavailable=True)
    result = _render_local_ai_selection_candidate_vars(cfg, **SELECTION_ARGS)
    assert result.pop("steward_inference_candidate") == {
        "version": 1,
        "revision": result["steward_config_revision"],
        "release": "0.1.0",
        "wheel_sha256": "a" * 64,
        "manifest_sha256": "b" * 64,
    }
    assert result == _render_local_ai_candidate_vars(
        cfg, release=SELECTION_ARGS["release"], ssh_port=SELECTION_ARGS["ssh_port"]
    )
    with pytest.raises(ValueError):
        _render_local_ai_selection_candidate_vars(
            cfg, **(SELECTION_ARGS | {"manifest_sha256": "B" * 64})
        )
    cfg.ai.model = "registry.example/fixture:tiny"
    with pytest.raises(ValueError, match="invalid managed local"):
        _render_local_ai_selection_candidate_vars(cfg, **SELECTION_ARGS)


def test_selection_candidate_advice_is_private_and_explicit(candidate_raw):
    candidate_raw["ai"]["budget"] = {"monthly": {"tokens": 10_000, "seconds": 60}}
    cfg = parse_config(candidate_raw, allow_unavailable=True)
    scan = _render_local_ai_selection_candidate_vars(cfg, **SELECTION_ARGS)
    advice = _render_local_ai_selection_candidate_vars(cfg, **SELECTION_ARGS, advice=True)
    assert "advice" not in scan["steward_inference_candidate"]
    assert advice == scan | {
        "steward_inference_candidate": scan["steward_inference_candidate"] | {"advice": True}
    }
    with pytest.raises(ConfigError):
        config_from(effective(cfg))


@pytest.mark.parametrize(
    "budget",
    [
        None,
        {"monthly": {"tokens": 10_000}},
        {"monthly": {"seconds": 60}},
        {"monthly": {"tokens": 20_001, "seconds": 60}},
        {"monthly": {"tokens": 10_000, "seconds": 121}},
        {"monthly": {"tokens": 10_000, "seconds": 60}, "max_concurrent": 2},
        {
            "monthly": {"tokens": 10_000, "seconds": 60, "cost_micro": 1},
            "price": {"input_per_mtok_micro": 0, "output_per_mtok_micro": 0},
        },
        {
            "monthly": {"tokens": 10_000, "seconds": 60},
            "per_project": {"cost_micro": 1},
            "price": {"input_per_mtok_micro": 0, "output_per_mtok_micro": 0},
        },
        {
            "monthly": {"tokens": 10_000, "seconds": 60},
            "price": {"input_per_mtok_micro": 0, "output_per_mtok_micro": 0},
        },
    ],
)
def test_selection_candidate_advice_rejects_unbounded_or_cost_budget(candidate_raw, budget):
    candidate_raw["ai"]["budget"] = budget
    cfg = parse_config(candidate_raw, allow_unavailable=True)
    scan = _render_local_ai_selection_candidate_vars(cfg, **SELECTION_ARGS)
    assert "advice" not in scan["steward_inference_candidate"]
    with pytest.raises(ValueError, match="advice budget"):
        _render_local_ai_selection_candidate_vars(cfg, **SELECTION_ARGS, advice=True)


@pytest.mark.parametrize(
    ("candidate", "has_run", "check_mode", "enabled"),
    [
        (None, False, False, False),
        ({}, True, False, False),
        ({"advice": "true"}, True, False, False),
        ({"advice": True}, False, False, False),
        ({"advice": True}, True, True, False),
        ({"advice": True}, True, False, True),
    ],
)
def test_managed_advice_service_backends_require_live_opt_in(
    candidate, has_run, check_mode, enabled
):
    jinja = pytest.importorskip("jinja2")
    env = jinja.Environment(  # noqa: S701 -- systemd units
        loader=jinja.FileSystemLoader(str(PLATFORM / "templates")),
        undefined=jinja.StrictUndefined,
    )
    env.filters["regex_replace"] = lambda value, pattern, replacement: re.sub(
        pattern, replacement, value
    )
    variables = {
        "ansible_check_mode": check_mode,
        "steward_admin": {
            "backend_port": 8000,
            "hostname": "admin.example",
            "port": 443,
            "session_ttl_minutes": 30,
        },
        "steward_bot_secrets": [],
        "steward_scanning": {"enabled": False},
    }
    if candidate is not None:
        variables["steward_inference_candidate"] = candidate
    if has_run:
        variables["site_inference_run"] = "d" * 32

    for role in ("api", "bot"):
        unit = env.get_template(f"steward-{role}.service.j2").render(variables)
        prefix = f"Environment=STEWARD_{role.upper()}_ADVICE_BACKEND="
        settings = [line for line in unit.splitlines() if line.startswith(prefix)]
        assert settings == ([prefix + "managed-local"] if enabled else [])
        if role == "api":
            assert (
                "Environment=STEWARD_ALLOWED_ORIGINS="
                "https://localhost:443,https://127.0.0.1:443,https://admin.example:443"
            ) in unit.splitlines()


def test_admin_api_unit_uses_only_rendered_origins_for_private_lan():
    jinja = pytest.importorskip("jinja2")
    env = jinja.Environment(  # noqa: S701 -- systemd units
        loader=jinja.FileSystemLoader(str(PLATFORM / "templates")),
        undefined=jinja.StrictUndefined,
    )
    template = env.get_template("steward-api.service.j2")
    admin = {"access": "private-lan", "backend_port": 9080, "session_ttl_minutes": 30}
    with pytest.raises(jinja.UndefinedError, match="allowed_origins"):
        template.render(steward_admin=admin, steward_scanning={"enabled": False})
    admin["allowed_origins"] = ["https://localhost:9443", "https://192.168.10.7:9443"]
    unit = template.render(steward_admin=admin, steward_scanning={"enabled": False})
    assert "Environment=STEWARD_ALLOWED_ORIGINS=" + ",".join(admin["allowed_origins"]) in (
        unit.splitlines()
    )


def test_managed_advice_socket_units_use_role_groups_and_one_worker():
    templates = PLATFORM / "templates"
    service = "steward-inference-advice.service"
    sockets = []
    for role in ("bot", "api"):
        socket_unit = f"steward-inference-advice-{role}.socket"
        sockets.append(socket_unit)
        lines = (templates / f"{socket_unit}.j2").read_text().splitlines()
        assert {
            f"ListenStream=/run/steward-inference-advice/{role}.sock",
            f"FileDescriptorName={role}",
            f"Service={service}",
            f"SocketGroup=steward-{role}",
            "SocketUser=root",
            "SocketMode=0660",
            "Accept=no",
        } <= set(lines)
    worker = (templates / f"{service}.j2").read_text().splitlines()
    inherited = [
        line.removeprefix("Sockets=").split() for line in worker if line.startswith("Sockets=")
    ]
    assert len(inherited) == 1
    assert sorted(inherited[0]) == sorted(sockets)
    assert "JoinsNamespaceOf=steward-ollama.service" in worker
    for dependency in ("After", "Requisite", "PartOf"):
        expected = " ".join(("steward-ollama.service", *sockets))
        assert f"{dependency}={expected}" in worker
    assert any(
        line.startswith("ExecStartPost=") and line.endswith(" _wait-for-advice-ready")
        for line in worker
    )
    assert any(line.startswith("{% include 'inference-sandbox.j2' %}") for line in worker)
