"""Contract checks for the installed repository fetch service."""

import json
import os
import stat
from contextlib import contextmanager, nullcontext
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from steward.core import repository_fetch_package as package

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "ansible/roles/platform/templates"
COMMAND = "/opt/steward/current/venv/bin/python -I -m steward.core.repository_fetch_package"


@pytest.mark.parametrize("credential_required", [False, True])
def test_packaged_fetch_unit_separates_verification_and_fetch_identity(credential_required):
    env = Environment(
        loader=FileSystemLoader(TEMPLATES), undefined=StrictUndefined, autoescape=True
    )
    unit = env.get_template("steward-repository-fetch.service.j2").render(
        steward_repository_fetch={"manifest": {"credential_required": credential_required}}
    )
    lines = unit.splitlines()
    assert "User=steward-repo-fetch" in lines
    assert "Group=steward-repo-fetch" in lines
    assert "Requisite=steward-firewall.service" in lines
    assert "StopPropagatedFrom=steward-firewall.service" in lines
    assert "After=steward-firewall.service systemd-tmpfiles-setup.service" in lines
    assert f"ExecStartPre=+{COMMAND} verify" in lines
    assert f"ExecStart={COMMAND} run" in lines
    assert "RuntimeDirectory=steward-repository-fetch" in lines
    assert "RuntimeDirectoryMode=0700" in lines
    assert "ProtectSystem=strict" in lines
    assert "ReadWritePaths=/var/lib/steward-repository-fetch /run/steward-repository-fetch" in lines
    assert [line for line in lines if line.startswith("LoadCredential=")] == (
        ["LoadCredential=git:/etc/steward/repository-fetch/credential"]
        if credential_required
        else []
    )


@pytest.fixture
def manifest_data():
    return {
        "version": 1,
        "base_revision": "a" * 64,
        "firewall_sha256": "b" * 64,
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
    }


def test_runtime_uses_fixed_endpoint_and_paths(monkeypatch, manifest_data):
    manifest = package.Manifest.model_validate(manifest_data)
    uid, gid = os.geteuid(), os.getegid()
    monkeypatch.setattr(package, "_directory", lambda gid: None)
    monkeypatch.setattr(package, "_read_active", lambda gid: manifest)
    fetches = []

    def observe_fetch(repo, store, *, resolve_secret, policy, scratch):
        assert repo.url == manifest_data["repository"]["url"]
        assert store == Path("/var/lib/steward-repository-fetch")
        assert scratch == Path("/run/steward-repository-fetch")
        assert policy.resolver("git.example.org", 443) == [manifest_data["endpoint"]]
        assert repo.credential is None
        fetches.append(repo)

    monkeypatch.setattr(package, "fetch_repository", observe_fetch)
    package._run(uid, gid)
    assert len(fetches) == 1
    with pytest.raises(package.boot.BootError, match="identity"):
        package._run(uid + 1, gid)

    def withdrawn(gid):
        raise FileNotFoundError

    monkeypatch.setattr(package, "_read_active", withdrawn)
    with pytest.raises(FileNotFoundError):
        package._run(uid, gid)
    assert len(fetches) == 1


def test_runtime_uses_only_the_systemd_git_credential(tmp_path, monkeypatch):
    key = tmp_path / "git"
    key.write_text("fixture credential\n")
    key.chmod(0o400)
    monkeypatch.setattr(package, "CREDENTIAL_DIRECTORY", tmp_path)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path.parent))
    with pytest.raises(package.boot.BootError, match="invalid systemd credentials directory"):
        package._credential(package.CREDENTIAL_REF)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    assert package._credential(package.CREDENTIAL_REF) == "fixture credential"
    with pytest.raises(package.boot.BootError, match="invalid repository credential reference"):
        package._credential("file:/other")

    key.chmod(0o440)
    with pytest.raises(package.boot.BootError, match="unsafe systemd credential"):
        package._credential(package.CREDENTIAL_REF)
    key.rename(tmp_path / "other")
    key.symlink_to(tmp_path / "other")
    with pytest.raises(OSError):
        package._credential(package.CREDENTIAL_REF)


@pytest.mark.parametrize("field", ["url", "id", "application", "service", "uid"])
def test_scope_seal_survives_and_rejects_rebinding(tmp_path, monkeypatch, manifest_data, field):
    seal = tmp_path / "scope.json"
    monkeypatch.setattr(package, "SCOPE", seal)
    monkeypatch.setattr(package.boot, "safe_directory", lambda path: None)
    monkeypatch.setattr(
        package.boot,
        "read_optional",
        lambda path: json.loads(path.read_text()) if path.exists() else None,
    )
    manifest = package.Manifest.model_validate(manifest_data)
    package._require_scope(manifest, 1234, create=True)
    before = seal.read_bytes()
    assert stat.S_IMODE(seal.stat().st_mode) == 0o600
    package._require_scope(manifest, 1234, create=True)

    uid = 1234
    if field == "uid":
        uid += 1
    elif field == "url":
        manifest_data["repository"][field] = "https://git.example.org/other.git"
    else:
        manifest_data["repository"][field] = "other"
    with pytest.raises(package.boot.BootError, match="scope differs"):
        package._require_scope(package.Manifest.model_validate(manifest_data), uid, create=True)
    assert seal.read_bytes() == before


def test_firewall_check_uses_fixed_argv(monkeypatch, manifest_data):
    helper = Path("/etc/steward/nftables/firewall-policy.py")
    calls = []

    def protected(path, mode):
        assert (path, mode) == (helper, 0o700)
        return nullcontext()

    def run(argv, **kwargs):
        calls.append(argv)
        assert kwargs["check"] is True

    monkeypatch.setattr(package.boot, "protected", protected)
    monkeypatch.setattr(package.subprocess, "run", run)
    package._require_firewall(package.Manifest.model_validate(manifest_data))
    assert calls == [
        ["/usr/bin/python3", "-I", str(helper), "require-active", manifest_data["firewall_sha256"]]
    ]


@pytest.fixture
def authority(tmp_path, monkeypatch, manifest_data):
    manifest = package.Manifest.model_validate(manifest_data)
    marker = {
        "base_revision": manifest.base_revision,
        "desired_revision": manifest.base_revision,
        "repository_fetch_run": "c" * 32,
    }
    marker_path = tmp_path / "deploy-run.json"
    active = tmp_path / "active.json"
    monkeypatch.setattr(package, "MARKER", marker_path)
    monkeypatch.setattr(package, "_account", lambda: (1234, 1234))
    monkeypatch.setattr(package, "_directory", lambda gid: None)
    monkeypatch.setattr(package, "_read_active", lambda gid: manifest)
    monkeypatch.setattr(package.os, "geteuid", lambda: 0)
    monkeypatch.setattr(package.boot, "read_optional", lambda path: json.loads(path.read_text()))

    calls = []
    locked = False

    @contextmanager
    def lock(*, timeout, create):
        nonlocal locked
        assert not locked
        locked = True
        try:
            yield
        finally:
            locked = False

    def check(name):
        def observed(*args):
            assert locked
            assert args[0] == manifest
            calls.append(name)

        return observed

    def write(value, gid):
        assert gid == 1234
        assert locked
        calls.append("write")
        assert json.loads(marker_path.read_text()) == marker
        active.write_text(
            value.model_dump_json(exclude={"handoff"} if value.handoff is None else None)
        )

    def sync(path):
        assert locked and path == tmp_path
        assert active.exists()
        assert not marker_path.exists()
        calls.append("sync")

    monkeypatch.setattr(package.boot, "deployment_lock", lock)
    monkeypatch.setattr(package.boot, "sync_directory", sync)
    monkeypatch.setattr(package, "_require_scope", check("scope"))
    monkeypatch.setattr(package, "_require_applied", check("applied"))
    monkeypatch.setattr(package, "_require_firewall", check("firewall"))
    monkeypatch.setattr(package, "_write_active", write)

    def quiescent(unit, *, allow_absent):
        assert locked and unit == package.HANDOFF_UNIT and allow_absent
        calls.append("quiescent")

    monkeypatch.setattr(package, "require_unit_quiescent", quiescent)
    return marker, marker_path, active, calls


@pytest.mark.parametrize("failure", [None, "marker", "applied", "firewall"])
def test_publication_checks_authority_and_clears_marker_last(
    monkeypatch, manifest_data, authority, failure
):
    marker, marker_path, active, calls = authority
    on_disk_marker = marker | ({"repository_fetch_run": "d" * 32} if failure == "marker" else {})
    marker_path.write_text(json.dumps(on_disk_marker))
    body = json.dumps({"manifest": manifest_data, "marker": marker}).encode()
    monkeypatch.setattr(package.sys, "stdin", SimpleNamespace(buffer=BytesIO(body)))

    if failure in {"applied", "firewall"}:
        name = "_require_" + failure
        original = getattr(package, name)

        def refuse(manifest):
            original(manifest)
            raise package.boot.BootError("fixture authority mismatch")

        monkeypatch.setattr(package, name, refuse)

    assert package.main(["publish"]) == int(failure is not None)
    expected = ["scope", "applied", "firewall", "write", "sync"]
    if failure:
        assert calls == ([] if failure == "marker" else expected[: expected.index(failure) + 1])
        assert json.loads(marker_path.read_text()) == on_disk_marker
        assert not active.exists()
    else:
        assert calls == expected
        assert json.loads(active.read_text()) == manifest_data
        assert not marker_path.exists()


def test_verification_refuses_pending_deployment_before_authority_checks(authority):
    marker, marker_path, _, calls = authority
    marker_path.write_text(json.dumps(marker))
    assert package.main(["verify"]) == 1
    assert calls == []
    marker_path.unlink()
    assert package.main(["verify"]) == 0
    assert calls == ["quiescent", "scope", "applied", "firewall"]


def test_startup_verifier_does_not_create_the_deployment_lock(tmp_path, monkeypatch):
    parent = tmp_path / "locks"
    monkeypatch.setattr(package.boot, "DEPLOYMENT_LOCK", parent / "deployment-execution.lock")
    monkeypatch.setattr(package.boot, "safe_directory", lambda path: path.stat())
    monkeypatch.setattr(package.os, "geteuid", lambda: 0)
    monkeypatch.setattr(package, "_account", lambda: (1234, 1234))
    assert package.main(["verify"]) == 1
    assert not parent.exists()


@pytest.mark.parametrize(("schema", "host"), [(2, "my-server"), (1, "foreign-host")])
def test_authority_refuses_a_different_installation(monkeypatch, manifest_data, cfg, schema, host):
    from steward.core.canonical import revision_id
    from steward.core.config import effective
    from steward.executor import site_deployment

    revision = revision_id(effective(cfg))
    manifest_data["base_revision"] = revision
    manifest = package.Manifest.model_validate(manifest_data)
    monkeypatch.setattr(package, "_require_installed_release", lambda: "fixture")
    monkeypatch.setattr(
        site_deployment, "read_marker", lambda: {"schema_version": schema, "server_name": host}
    )
    monkeypatch.setattr(
        site_deployment, "installed_config", lambda: (cfg, {"config_revision": revision})
    )
    with pytest.raises(package.boot.BootError, match="schema 1|applied revision"):
        package._require_applied(manifest)


def test_role_stages_root_only_credential_after_sealing_scope():
    role = yaml.safe_load((TEMPLATES.parent / "tasks/repository-fetch.yml").read_text())
    withdraw, stage = role
    tasks = {task["name"]: task for task in stage["block"]}
    authority = tasks["Create the protected repository fetch authority directory"]
    assert authority["ansible.builtin.file"] == {
        "path": "/etc/steward/repository-fetch",
        "state": "directory",
        "owner": "root",
        "group": "steward-repo-fetch",
        "mode": "0750",
    }

    seal = tasks["Seal repository scope before managing the private store"]
    assert (
        seal["ansible.builtin.command"]["stdin"]
        == "{{ steward_repository_fetch.manifest | to_json }}"
    )
    credential = tasks["Install the selected root-only Git credential"]
    assert credential["no_log"] is True
    assert credential["diff"] is False
    assert credential["when"] == "steward_repository_fetch.manifest.credential_required"
    copy = credential["ansible.builtin.copy"]
    assert (copy["dest"], copy["owner"], copy["group"], copy["mode"]) == (
        "/etc/steward/repository-fetch/credential",
        "root",
        "root",
        "0600",
    )
    assert stage["block"].index(seal) < stage["block"].index(credential)

    withdrawal_tasks = {task["name"]: task for task in withdraw["block"]}
    manifest = withdrawal_tasks["Withdraw the active repository fetch manifest"]
    revoke = withdrawal_tasks[
        "Revoke ready source and withdraw the active manifest under the deployment lock"
    ]
    stop = withdrawal_tasks[
        "Stop the managed repository cgroups before touching firewall or credentials"
    ]
    credential_removal = withdrawal_tasks["Remove the withdrawn repository fetch credential"]
    assert manifest["ansible.builtin.file"]["state"] == "absent"
    assert stop["ansible.builtin.command"]["argv"] == [
        "/usr/bin/systemctl",
        "stop",
        "{{ item.item.item.unit }}",
    ]
    assert {entry["unit"] for entry in withdraw["vars"]["platform_repository_fetch_units"]} == {
        package.UNIT,
        package.HANDOFF_UNIT,
        package.BUILD_VERIFY_UNIT,
    }
    assert credential_removal["ansible.builtin.file"]["state"] == "absent"
    ordered = withdraw["block"]
    assert ordered.index(revoke) < ordered.index(manifest) < ordered.index(stop)
    drain = withdrawal_tasks[
        "Verify the stopped build verifier cgroup has drained before removing its fragment"
    ]
    assert drain["block"][0]["ansible.builtin.command"]["argv"] == [
        "/usr/bin/systemctl",
        "show",
        "--all",
        "--property=Id,ActiveState,SubState,ControlGroup,Job,MainPID,ControlPID",
        package.BUILD_VERIFY_UNIT,
    ]
    population = drain["block"][-1]["block"]
    assert population[0]["ansible.builtin.slurp"]["src"].endswith("/cgroup.events")
    assert "'populated 0'" in population[1]["ansible.builtin.assert"]["that"][0]
    retirement = withdrawal_tasks["Remove the retired repository unit fragments"]
    assert ordered.index(stop) < ordered.index(drain) < ordered.index(retirement)
    assert ordered.index(retirement) < ordered.index(credential_removal)
    handoff = tasks["Stage the manual repository source handoff"]["block"]
    assert [
        task["ansible.builtin.group"] for task in handoff if "ansible.builtin.group" in task
    ] == [{"name": "steward-build-input", "system": True}]
    assert not any("ansible.builtin.user" in task for task in handoff)
    custody = next(
        task["ansible.builtin.file"] for task in handoff if "ansible.builtin.file" in task
    )
    assert custody == {
        "path": "/var/lib/steward-repository-source-handoff",
        "state": "directory",
        "owner": "root",
        "group": "steward-build-input",
        "mode": "0750",
    }


def test_retiring_a_removed_fragment_can_resume_without_fetch_authority():
    role = yaml.safe_load((ROOT / "ansible/roles/platform/tasks/repository-fetch.yml").read_text())
    withdraw = next(
        task for task in role if task["when"] == "platform_repository_fetch_phase == 'withdraw'"
    )
    check = next(
        task
        for task in withdraw["block"]
        if task["name"] == "Refuse foreign repository unit sources, overrides and activation"
    )
    env = Environment(undefined=StrictUndefined, autoescape=True)
    env.filters["difference"] = lambda left, right: list(set(left).difference(right))
    accepts = env.compile_expression(check["ansible.builtin.assert"]["that"][0])
    fragment = f"/etc/systemd/system/{package.HANDOFF_UNIT}"
    status = [
        "LoadState=loaded",
        "ActiveState=inactive",
        "DropInPaths=",
        "NeedDaemonReload=yes",
        f"FragmentPath={fragment}",
    ]
    item = {"item": {"stat": {"exists": False}}, "stdout_lines": status}
    assert accepts(item=item, unit_path=fragment)
    item["stdout_lines"] = [line for line in status if line != "DropInPaths="]
    assert not accepts(item=item, unit_path=fragment)


def test_active_manifest_is_published_atomically_with_fetch_group_read_access(
    tmp_path, monkeypatch, manifest_data
):
    active = tmp_path / "active.json"
    fetch_gid = 1234
    manifest = package.Manifest.model_validate(manifest_data)
    original_replace = os.replace
    owners = []
    replacements = []

    def fchown(fd, uid, gid):
        assert stat.S_ISREG(os.fstat(fd).st_mode)
        owners.append((uid, gid))

    def replace(staged, destination):
        assert not active.exists()
        assert Path(staged).parent == tmp_path
        assert stat.S_IMODE(Path(staged).stat().st_mode) == 0o640
        assert json.loads(Path(staged).read_text()) == manifest_data
        replacements.append(destination)
        original_replace(staged, destination)

    def protected(path, mode, gid):
        assert (path, mode, gid) == (active, 0o640, fetch_gid)
        return active.open("rb")

    monkeypatch.setattr(package, "DIRECTORY", tmp_path)
    monkeypatch.setattr(package, "ACTIVE", active)
    monkeypatch.setattr(package.os, "fchown", fchown)
    monkeypatch.setattr(package.os, "replace", replace)
    monkeypatch.setattr(package.boot, "protected", protected)
    package._write_active(manifest, fetch_gid)
    assert owners == [(0, fetch_gid)]
    assert replacements == [active]
    assert package._read_active(fetch_gid) == manifest
    assert list(tmp_path.iterdir()) == [active]


def test_manual_handoff_unit_uses_offline_fetch_identity():
    unit = (
        Environment(loader=FileSystemLoader(TEMPLATES), autoescape=True)
        .get_template(f"{package.HANDOFF_UNIT}.j2")
        .render()
    )
    command = "/opt/steward/current/venv/bin/python -I -m steward.core.repository_source_handoff"
    assert {
        f"ExecStartPre=+{command} verify",
        f"ExecStart={command} prepare",
        f"ExecStartPost=+{command} publish",
        "User=steward-repo-fetch",
        "Group=steward-repo-fetch",
        "RuntimeDirectory=steward-repository-source-handoff",
        "RuntimeDirectoryMode=0700",
        "ReadOnlyPaths=/var/lib/steward-repository-fetch",
        "ReadWritePaths=/run/steward-repository-source-handoff",
        "ProtectSystem=strict",
        "PrivateNetwork=yes",
        "PrivateTmp=yes",
        "RestrictAddressFamilies=none",
        "SystemCallArchitectures=native",
        "TimeoutStartSec=5min",
        "CPUQuota=100%",
        "MemoryMax=1G",
        "TasksMax=32",
        "LimitFSIZE=272M",
    }.issubset(unit.splitlines())
    inaccessible = next(line for line in unit.splitlines() if line.startswith("InaccessiblePaths="))
    assert "-/etc/steward/repository-fetch/credential" in inaccessible.split("=", 1)[1].split()
    assert "-/run/credentials" in inaccessible.split("=", 1)[1].split()
    assert "[Install]" not in unit and "LoadCredential=" not in unit


def test_manual_build_verifier_is_offline_and_only_root_hooks_hold_authority():
    unit = (TEMPLATES / f"{package.BUILD_VERIFY_UNIT}.j2").read_text()
    env = "/usr/bin/env -i INVOCATION_ID=${INVOCATION_ID}"
    verifier = "/opt/steward/current/venv/bin/python -I -m steward.core.repository_build_verify"
    assert {
        f"ExecStartPre=+{env} {verifier} admit",
        f"ExecStart={env} {verifier} verify",
        f"ExecStartPost=+{env} {verifier} finish",
        "User=steward-repo-build",
        "Group=steward-repo-build",
        "SupplementaryGroups=steward-build-input",
        "ReadOnlyPaths=/var/lib/steward-repository-source-handoff",
        "ReadWritePaths=/var/lib/steward-repository-build-verify",
        "PrivateNetwork=yes",
        "RestrictAddressFamilies=none",
        "NoNewPrivileges=yes",
        "KillMode=control-group",
        "TimeoutStartSec=5min",
    }.issubset(unit.splitlines())
    assert "[Install]" not in unit and "LoadCredential" not in unit


@pytest.mark.parametrize("incoming", [{}, {"generation": None}, {"generation": "d" * 32}])
def test_generation_is_assigned_only_by_publication(
    monkeypatch, manifest_data, authority, incoming
):
    marker, marker_path, active, _ = authority
    marker_path.write_text(json.dumps(marker))
    manifest_data["handoff"] = {"contract": {"container_port": 8080}, **incoming}
    body = json.dumps({"manifest": manifest_data, "marker": marker}).encode()
    monkeypatch.setattr(package, "_check_authority", lambda *args: None)
    monkeypatch.setattr(package.sys, "stdin", SimpleNamespace(buffer=BytesIO(body)))

    assert package.main(["publish"]) == bool(incoming)
    if incoming:
        assert marker_path.exists()
        assert not active.exists()
    else:
        handoff = package.Manifest.model_validate_json(active.read_bytes()).handoff
        assert handoff.contract.container_port == 8080
        assert handoff.generation == marker["repository_fetch_run"]


def test_manifest_input_caps_preserve_legacy_and_bound_handoff(manifest_data):
    with pytest.raises(package.boot.BootError, match="fetch input exceeds"):
        package._decode(json.dumps(manifest_data).encode().ljust(package.INPUT_LIMIT + 1))
    manifest_data["handoff"] = {"contract": "ü" * (package.HANDOFF_LIMIT // 2)}
    with pytest.raises(package.boot.BootError, match="handoff input exceeds"):
        package._decode(json.dumps(manifest_data, ensure_ascii=False).encode())
    manifest_data["handoff"] = {"contract": None}
    manifest_data["repository"]["url"] += "a" * package.INPUT_LIMIT
    with pytest.raises(package.boot.BootError, match="fetch input exceeds"):
        package._decode(json.dumps(manifest_data).encode())


@pytest.mark.parametrize(
    ("is_present", "allow_absent", "override", "events", "error"),
    [
        (True, False, {}, None, None),
        (True, False, {"ActiveState": "failed", "SubState": "failed"}, "populated 0", None),
        (False, True, {}, None, None),
        (False, False, {}, None, "missing"),
        (True, False, {"ActiveState": "activating"}, None, "quiescent"),
        (True, False, {"DropInPaths": "/override"}, None, "quiescent"),
        (True, False, {"NeedDaemonReload": "yes"}, None, "quiescent"),
        (True, False, {"Job": "123"}, None, "quiescent"),
        (True, False, {"ControlGroup": "/other.slice/unit"}, None, "quiescent"),
        (False, True, {}, "populated 1", "populated"),
        (True, False, {}, "", "populated"),
    ],
)
def test_quiescence_checks_fixed_unit_and_recursive_population(
    tmp_path, monkeypatch, is_present, allow_absent, override, events, error
):
    unit = package.HANDOFF_UNIT
    cg = tmp_path / "cgroup"
    cg.mkdir()
    (cg / "cgroup.controllers").touch()
    if events is not None:
        service_cg = cg / "system.slice" / unit
        service_cg.mkdir(parents=True)
        (service_cg / "cgroup.events").write_text(events)

    def protected(path, mode):
        assert (path, mode) == (package.UNIT_DIRECTORY / unit, 0o644)
        if not is_present:
            raise FileNotFoundError
        return BytesIO(
            b"# Generated by steward - do not edit.\n[Unit]\n"
            b"Description=Steward repository source handoff\n"
        )

    def systemctl(argv, **kwargs):
        assert argv[:4] == ["/usr/bin/systemctl", "--system", "show", "--all"]
        assert argv[-1] == unit and kwargs["timeout"] == 10
        values = {
            "Id": unit,
            "LoadState": "loaded" if is_present else "not-found",
            "FragmentPath": str(package.UNIT_DIRECTORY / unit) if is_present else "",
            "UnitFileState": "static" if is_present else "",
            "DropInPaths": "",
            "NeedDaemonReload": "no",
            "ActiveState": "inactive",
            "SubState": "dead",
            "MainPID": "0",
            "ControlPID": "0",
            "ControlGroup": "",
            "Job": "",
        } | override
        return SimpleNamespace(
            stdout="\n".join(f"{name}={value}" for name, value in values.items()),
            returncode=int(not is_present),
        )

    monkeypatch.setattr(package, "CGROUP", cg)
    monkeypatch.setattr(package.boot, "protected", protected)
    monkeypatch.setattr(package.subprocess, "run", systemctl)
    if error:
        with pytest.raises(package.boot.BootError, match=error):
            package.require_unit_quiescent(unit, allow_absent=allow_absent)
    else:
        package.require_unit_quiescent(unit, allow_absent=allow_absent)


def test_fetch_verification_requires_installed_handoff_for_new_manifests(
    monkeypatch, manifest_data, authority
):
    manifest_data["handoff"] = {"contract": None, "generation": "c" * 32}
    manifest = package.Manifest.model_validate(manifest_data)
    monkeypatch.setattr(package, "_read_active", lambda gid: manifest)
    monkeypatch.setattr(package, "_check_authority", lambda *args: None)
    checked = []

    def quiescent(unit, *, allow_absent):
        checked.append((unit, allow_absent))

    monkeypatch.setattr(package, "require_unit_quiescent", quiescent)
    assert package.main(["verify"]) == 0
    assert checked == [(package.HANDOFF_UNIT, False)]


def test_withdraw_revokes_ready_before_unlinking_active(tmp_path, monkeypatch):
    from steward.core import repository_source_handoff as handoff

    active = tmp_path / "active.json"
    active.touch()
    calls = []

    def withdraw_ready():
        calls.append(active.exists())

    monkeypatch.setattr(handoff, "withdraw_ready", withdraw_ready)
    monkeypatch.setattr(package, "ACTIVE", active)
    monkeypatch.setattr(package, "DIRECTORY", tmp_path)
    monkeypatch.setattr(package, "_account", lambda: (1234, 1234))
    monkeypatch.setattr(package, "_directory", lambda gid: None)
    monkeypatch.setattr(package.boot, "protected", lambda *args: nullcontext())
    monkeypatch.setattr(package.boot, "sync_directory", lambda path: calls.append(active.exists()))

    package.withdraw_active()
    package.withdraw_active()
    assert calls == [True, False, False]
