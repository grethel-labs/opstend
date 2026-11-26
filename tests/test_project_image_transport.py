"""Exercise ordinary project deployment with isolated Podman and systemd stores."""

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
import yaml

from steward.core import image_transport

ROLES = Path(__file__).resolve().parents[1] / "ansible" / "roles"
CONFIG = json.dumps(
    {
        "architecture": "amd64",
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": []},
        "config": {"Healthcheck": {"Test": ["CMD", "/health"], "Interval": 1000000000}},
    }
).encode()
EXPECTED_ID = "sha256:" + hashlib.sha256(CONFIG).hexdigest()
LEGACY_CONFIG = json.dumps(
    {
        "architecture": "amd64",
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": []},
        "config": {},
    }
).encode()
OLD_ID = "sha256:" + hashlib.sha256(LEGACY_CONFIG).hexdigest()
LAYER_NAME = "layer/layer.tar"
LAYER = b"synthetic layer bytes"


def _archive(path, tag, image_id, *, format_, corrupt=False):
    with tarfile.open(path, "w") as archive:
        if format_ == "docker-archive":
            config_name = f"{image_id[7:]}.json"
            manifest = [{"Config": config_name, "RepoTags": [tag], "Layers": [LAYER_NAME]}]
            members = {
                "manifest.json": json.dumps(manifest).encode(),
                config_name: CONFIG,
                LAYER_NAME: b"X" + LAYER[1:] if corrupt else LAYER,
            }
        else:
            config = _descriptor(LEGACY_CONFIG)
            manifest = json.dumps({"schemaVersion": 2, "config": config, "layers": []}).encode()
            entry = _descriptor(manifest)
            entry["annotations"] = {"org.opencontainers.image.ref.name": tag}
            members = {
                "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
                "index.json": json.dumps({"manifests": [entry]}).encode(),
                "blobs/sha256/" + config["digest"][7:]: LEGACY_CONFIG,
                "blobs/sha256/" + entry["digest"][7:]: manifest,
            }
        for name, value in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(value)
            archive.addfile(info, io.BytesIO(value))


def _descriptor(payload):
    return {"digest": "sha256:" + hashlib.sha256(payload).hexdigest(), "size": len(payload)}


def _podman(root, args):
    state_file = root / "state.json"
    state = json.loads(state_file.read_text())
    user = "XDG_RUNTIME_DIR" in os.environ
    store = state["user" if user else "root"]
    with (root / "operations.jsonl").open("a") as log:
        print(json.dumps(["user" if user else "root", args]), file=log)

    match args:
        case ["systemd-stub", action]:
            running = state["running"]
            if action == "stopped":
                state["running"] = None
            elif action == "restarted" or (action == "started" and running is None):
                state["running"] = store[state["tag"]]
            print("changed" if action == "restarted" or running != state["running"] else "ok")
        case ["pull", *_, ref]:
            if not state["online"]:
                return 125
            store[ref] = EXPECTED_ID
        case ["tag", source, target]:
            store[target] = store[source]
        case ["save", *_]:
            path = Path(args[args.index("--output") + 1])
            format_ = args[args.index("--format") + 1]
            _archive(path, args[-1], store[args[-1]], format_=format_)
        case ["load", *_]:
            if state["load_result"] == "permission":
                print("Permission denied", file=sys.stderr)
                return 125
            path = Path(args[args.index("--input") + 1])
            with tarfile.open(path) as archive:
                if "manifest.json" in archive.getnames():
                    manifest = json.load(archive.extractfile("manifest.json"))
                    config = archive.extractfile(manifest[0]["Config"]).read()
                    (layer,) = manifest[0]["Layers"]
                    if archive.extractfile(layer).read() != LAYER:
                        print("Layer digest mismatch", file=sys.stderr)
                        return 125
                    loaded = "sha256:" + hashlib.sha256(config).hexdigest()
                else:
                    loaded = OLD_ID
            if state["load_result"] != "missing":
                store[state["tag"]] = state["load_result"] or loaded
            else:
                store.pop(state["tag"], None)
            print(f"Loaded image: {state['tag']}")
        case ["image", "exists", ref]:
            return 0 if ref in store else 1
        case ["container", "exists", _]:
            return 0 if state["running"] else 1
        case ["image" | "container", "inspect", *_] | ["inspect", *_]:
            return _inspect(state, store, args)
        case _:
            raise AssertionError(f"Unexpected Podman arguments: {args!r}")
    state_file.write_text(json.dumps(state))
    return 0


def _inspect(state, store, args):
    format_ = args[args.index("--format") + 1] if "--format" in args else ""
    positionals = args[(2 if args[0] in ("image", "container") else 1) :]
    if "--format" in positionals:
        index = positionals.index("--format")
        del positionals[index : index + 2]
    (ref,) = positionals
    container = args[0] == "container" or ref == state["project"]
    image_id = state["running"] if container else store.get(ref)
    if image_id is None:
        print(f"Error: {ref}: no such {'container' if container else 'image'}", file=sys.stderr)
        return 125
    bare_id = image_id.removeprefix("sha256:")
    if container:
        # Container Id is unrelated to the image config ID.
        entry = {"Id": "c" * 64, "Image": bare_id, "State": {"Running": True}}
    else:
        entry = {
            "Id": bare_id,
            "Digest": "sha256:" + "d" * 64,
            "ManifestType": "application/vnd.docker.distribution.manifest.v2+json",
            "Config": {"Entrypoint": ["tini", "--", "/init.sh"]},
        }
        if image_id == EXPECTED_ID:
            entry["Healthcheck"] = json.loads(CONFIG)["config"]["Healthcheck"]
    if format_:
        field = format_.removeprefix("{{").removesuffix("}}").strip().removeprefix(".")
        print(entry["Id" if field == "ID" else field])
    else:
        print(json.dumps([entry]))
    return 0


def _sandbox_tasks(tasks, podman, helper):
    for task in tasks:
        task.pop("become", None)
        task.pop("become_user", None)
        for key in ("block", "rescue", "always"):
            if key in task:
                _sandbox_tasks(task[key], podman, helper)
        if command := task.get("ansible.builtin.command"):
            argv = command.get("argv")
            if isinstance(argv, list) and argv[:4] == [
                sys.executable,
                "-I",
                "-m",
                "steward.core.image_transport",
            ]:
                argv[:4] = [sys.executable, str(helper)]
        if module := task.get("ansible.builtin.copy"):
            module.pop("owner", None)
            module.pop("group", None)
        if module := task.pop("ansible.builtin.systemd_service", None):
            task["ansible.builtin.command"] = {
                "argv": [str(podman), "systemd-stub", module.get("state", "daemon-reload")],
            }
            task["register"] = "systemd_stub"
            task["changed_when"] = "systemd_stub.stdout == 'changed'"


@pytest.fixture
def project_role(tmp_path, raw_config):
    from steward.core.config import parse_config
    from steward.core.render import render_vars

    executable = Path(sys.executable).with_name("ansible-playbook")
    if not executable.exists():
        pytest.skip("controller Ansible environment is not installed")

    podman = tmp_path / "podman"
    podman.write_text(
        f"#!{sys.executable}\n"
        "import runpy, sys\n"
        "from pathlib import Path\n"
        f"stub = runpy.run_path({str(Path(__file__).resolve())!r})\n"
        "sys.exit(stub['_podman'](Path(__file__).parent, sys.argv[1:]))\n"
    )
    podman.chmod(0o755)
    helper = tmp_path / "image_transport.py"
    helper.write_text(
        """import io
import os
import runpy
import subprocess
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from steward.core import image_transport

root = Path(__file__).parent
stub = runpy.run_path(TEST_FILE)["_podman"]
image_transport.ARCHIVE_DIR = root / "images"
actual_uid = os.geteuid()
protected = image_transport.protected

def local_custody(info, *, directory=False):
    assert info.st_uid == actual_uid
    protected(SimpleNamespace(st_uid=0, st_mode=info.st_mode), directory=directory)

def local_podman(argv, **kwargs):
    assert argv[0] == "/usr/bin/podman"
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = stub(root, argv[1:])
    return subprocess.CompletedProcess(argv, code, stdout.getvalue(), stderr.getvalue())

image_transport.protected = local_custody
image_transport.subprocess.run = local_podman
image_transport.os.geteuid = lambda: 0
image_transport.main()
""".replace("TEST_FILE", repr(str(Path(__file__).resolve())))
    )
    for role in ("common", "workloads"):
        destination = tmp_path / "roles" / role / "tasks"
        destination.mkdir(parents=True)
        for source in (ROLES / role / "tasks").glob("*.yml"):
            content = (
                source.read_text()
                .replace("/etc/containers/systemd/users", str(tmp_path / "quadlets"))
                .replace("/etc/steward/secrets/projects", str(tmp_path / "secrets"))
                .replace("/var/lib/steward/images", str(tmp_path / "images"))
                .replace("/opt/steward/current/venv/bin/python", sys.executable)
                .replace("argv: [podman,", f"argv: [{podman},")
            )
            tasks = yaml.safe_load(content)
            if role == "workloads" and source.name == "project.yml":
                activation = next(
                    index
                    for index, task in enumerate(tasks)
                    if "ansible.builtin.systemd_service" in task
                )
                tasks.insert(
                    activation,
                    {
                        "ansible.builtin.fail": {"msg": "Interrupted before systemd"},
                        "when": "interrupt_before_systemd | default(false)",
                    },
                )
            _sandbox_tasks(tasks, podman, helper)
            (destination / source.name).write_text(yaml.safe_dump(tasks))
    (tmp_path / "images").mkdir()
    (tmp_path / "images").chmod(0o755)
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\nroles_path = roles\ndisplay_skipped_hosts = False\n")
    state_file = tmp_path / "state.json"
    log = tmp_path / "operations.jsonl"

    def run(*, probe="container", prior="fresh", deploy=True, load=None):
        if probe:
            raw_config["projects"][0]["health"] = {"probe": probe}
        raw_config["projects"][0]["deploy"] = deploy
        cfg = parse_config(raw_config)
        variables = render_vars(cfg, release={"version": "1.0.0"}, ssh_port=22)
        (project,) = variables["steward_projects"]
        tag = project["image_tag"]
        image = project["image"]
        key = hashlib.sha256(json.dumps([image, tag]).encode()).hexdigest()
        archive = tmp_path / "images" / f"{key}.tar"
        unit_dir = tmp_path / "quadlets" / "30000"
        unit_dir.mkdir(parents=True, exist_ok=True)
        unit = unit_dir / f"{project['id']}.container"
        existing = prior not in ("fresh", "offline-empty", "no-healthcheck-new")
        source_id = OLD_ID if prior.startswith("no-healthcheck") else EXPECTED_ID
        state = {
            "root": (
                {image: source_id}
                if prior
                in ("legacy", "incomplete", "corrupt", "no-healthcheck", "no-healthcheck-new")
                else {}
            ),
            "user": {},
            "running": OLD_ID if existing else None,
            "tag": tag,
            "project": project["id"],
            "online": prior in ("fresh", "legacy-root-miss"),
            "load_result": load,
        }
        if existing:
            unit.write_text(project["quadlet"])
            unit.chmod(0o644)
            if prior in ("preseed", "corrupt", "corrupt-offline"):
                _archive(
                    archive, tag, EXPECTED_ID, format_="docker-archive", corrupt=prior != "preseed"
                )
            elif prior in ("incomplete", "disabled-offline-incomplete"):
                archive.write_bytes(b"interrupted save")
            else:
                _archive(archive, tag, OLD_ID, format_="oci-archive")
            archive.chmod(0o644)
            state["user"][tag] = OLD_ID
        if prior == "offline-alias":
            state["root"][tag] = EXPECTED_ID
        state_file.write_text(json.dumps(state))
        playbook = tmp_path / "play.yml"
        playbook.write_text(
            yaml.safe_dump(
                [
                    {
                        "hosts": "localhost",
                        "gather_facts": False,
                        "vars": {
                            "steward_projects": [project],
                            "steward_registry": variables["steward_registry"],
                            "steward_uids": {project["user"]: 30000},
                            "ansible_python_interpreter": sys.executable,
                        },
                        "roles": ["workloads"],
                    }
                ]
            )
        )

        def apply(*, fails=False, check=False, interrupt=False):
            log.unlink(missing_ok=True)
            env = {key: value for key, value in os.environ.items() if key != "XDG_RUNTIME_DIR"}
            env.update(
                ANSIBLE_CONFIG=str(config),
                ANSIBLE_HOME=str(tmp_path / "ansible-home"),
                ANSIBLE_LOCAL_TEMP=str(tmp_path / "ansible-local"),
                ANSIBLE_REMOTE_TEMP=str(tmp_path / "ansible-remote"),
                ANSIBLE_NOCOLOR="1",
                ANSIBLE_PIPELINING="true",
                PATH=f"{tmp_path}:{os.environ['PATH']}",
                PYTHONPATH=str(ROLES.parents[1] / "src"),
                PYTHONDONTWRITEBYTECODE="1",
            )
            command = [str(executable), "-i", "localhost,", "-c", "local", str(playbook)]
            if check:
                command.append("--check")
            if interrupt:
                command.extend(["--extra-vars", '{"interrupt_before_systemd": true}'])
            result = subprocess.run(
                command,
                cwd=tmp_path,
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
                umask=0o022,
                check=False,
            )
            output = result.stdout + result.stderr
            assert result.returncode == (2 if fails or interrupt else 0), output
            operations = (
                [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            )
            installed = json.loads(state_file.read_text())
            return output, operations, installed

        return apply, archive

    return run


def _actions(operations):
    return [args[1] for scope, args in operations if scope == "user" and args[0] == "systemd-stub"]


def _mutations(operations):
    return [
        (scope, args[0]) for scope, args in operations if args[0] in {"pull", "tag", "save", "load"}
    ]


@pytest.mark.parametrize(
    ("prior", "deploy", "mutations", "action"),
    [
        (
            "fresh",
            True,
            [("root", "pull"), ("root", "tag"), ("root", "save"), ("user", "load")],
            "restarted",
        ),
        ("legacy", True, [("root", "tag"), ("root", "save"), ("user", "load")], "restarted"),
        (
            "legacy-root-miss",
            True,
            [("root", "pull"), ("root", "tag"), ("root", "save"), ("user", "load")],
            "restarted",
        ),
        ("incomplete", True, [("root", "tag"), ("root", "save"), ("user", "load")], "restarted"),
        ("legacy", False, [("root", "tag"), ("root", "save"), ("user", "load")], "stopped"),
    ],
)
def test_container_probe_preserves_health_and_reconciles_running_image(
    project_role, prior, deploy, mutations, action
):
    apply, archive = project_role(prior=prior, deploy=deploy)
    _, operations, state = apply()
    assert _mutations(operations) == mutations
    if prior in ("fresh", "legacy-root-miss"):
        (pull,) = [args for scope, args in operations if scope == "root" and args[0] == "pull"]
        assert pull == ["pull", "--quiet", "--retry=0", next(iter(state["root"]))]
    assert _actions(operations) == [action]
    with tarfile.open(archive) as saved:
        (manifest,) = json.load(saved.extractfile("manifest.json"))
        config = json.load(saved.extractfile(manifest["Config"]))
        assert config["config"]["Healthcheck"] == json.loads(CONFIG)["config"]["Healthcheck"]
    assert state["user"][state["tag"]] == EXPECTED_ID
    assert state["running"] == (EXPECTED_ID if deploy else None)
    if not deploy:
        assert not any(args[0] == "container" for _, args in operations)
        assert operations[0] == ["user", ["systemd-stub", "stopped"]]


def test_disabled_container_stops_before_an_offline_transfer_failure(project_role):
    apply, archive = project_role(prior="disabled-offline-incomplete", deploy=False)
    before = archive.read_bytes()
    output, operations, state = apply(fails=True)
    assert "Podman pull exited 125" in output
    assert operations[0] == ["user", ["systemd-stub", "stopped"]]
    assert _actions(operations) == ["stopped"]
    assert _mutations(operations) == [("root", "pull")]
    assert state["running"] is None
    assert archive.read_bytes() == before


def test_container_probe_recreates_once_after_interruption_before_systemd(project_role):
    apply, archive = project_role(prior="legacy")
    output, interrupted, state = apply(interrupt=True)
    assert "Interrupted before systemd" in output
    assert _mutations(interrupted) == [("root", "tag"), ("root", "save"), ("user", "load")]
    assert _actions(interrupted) == []
    assert state["user"][state["tag"]] == EXPECTED_ID
    assert state["running"] == OLD_ID
    saved = archive.read_bytes()

    _, resumed, state = apply()
    assert _mutations(resumed) == []
    assert _actions(resumed) == ["restarted"]
    assert state["running"] == EXPECTED_ID
    assert archive.read_bytes() == saved

    output, repeated, state = apply()
    assert "changed=0" in output
    assert _actions(repeated) == ["started"]
    assert _mutations(repeated) == []
    assert state["running"] == EXPECTED_ID


@pytest.mark.parametrize(
    ("probe", "deploy"), [("container", True), ("container", False), (None, True)]
)
def test_check_mode_leaves_podman_and_systemd_untouched(project_role, probe, deploy):
    apply, archive = project_role(probe=probe, deploy=deploy)
    _, operations, state = apply(check=True)
    assert operations == []
    assert state["root"] == state["user"] == {}
    assert state["running"] is None
    assert not archive.exists()


@pytest.mark.parametrize("probe", [None, "http", "tcp"])
def test_other_probes_keep_legacy_transport(project_role, probe):
    apply, archive = project_role(probe=probe)
    _, operations, state = apply()
    assert _mutations(operations) == [
        ("root", "pull"),
        ("root", "tag"),
        ("root", "save"),
        ("user", "load"),
    ]
    with tarfile.open(archive) as saved:
        assert "index.json" in saved.getnames()
    assert not any(args[0] == "container" or "inspect" in args for _, args in operations)
    assert state["running"] == OLD_ID


@pytest.mark.parametrize(
    ("prior", "image_id", "mutations", "action"),
    [
        ("offline-alias", OLD_ID, [("root", "pull")], "started"),
        ("preseed", EXPECTED_ID, [("user", "load")], "restarted"),
        ("no-healthcheck", OLD_ID, [], "started"),
    ],
)
def test_container_probe_reuses_compatible_archive(
    project_role, prior, image_id, mutations, action
):
    apply, archive = project_role(prior=prior)
    before = archive.read_bytes()
    output, operations, state = apply()
    if prior != "preseed":
        assert "changed=0" in output
    assert _mutations(operations) == mutations
    assert _actions(operations) == [action]
    assert state["user"][state["tag"]] == image_id
    assert state["running"] == image_id
    assert archive.read_bytes() == before
    assert ("cannot be verified or recovered without the pinned source" in output) == (
        prior == "offline-alias"
    )
    if prior in ("offline-alias", "preseed"):
        assert state["online"] is False
        (source_lookup, *pulls) = [args for scope, args in operations if scope == "root"]
        source = source_lookup[-1]
        assert source_lookup == ["image", "exists", source]
        assert "@sha256:" in source
        assert source not in state["root"]
        assert pulls == (
            [["pull", "--quiet", "--retry=0", source]] if prior == "offline-alias" else []
        )


def test_container_probe_without_a_healthcheck_keeps_oci_transport(project_role):
    apply, archive = project_role(prior="no-healthcheck-new")
    _, operations, state = apply()
    assert _mutations(operations) == [("root", "tag"), ("root", "save"), ("user", "load")]
    with tarfile.open(archive) as saved:
        index = json.load(saved.extractfile("index.json"))
        (descriptor,) = index["manifests"]
        manifest_path = "blobs/" + descriptor["digest"].replace(":", "/")
        manifest = json.load(saved.extractfile(manifest_path))
        config_path = "blobs/" + manifest["config"]["digest"].replace(":", "/")
        config = json.load(saved.extractfile(config_path))
        assert "Healthcheck" not in config["config"]
    assert _actions(operations) == ["restarted"]
    assert state["running"] == OLD_ID


def test_no_source_or_cached_archive_prevents_activation(project_role):
    apply, archive = project_role(prior="offline-empty")
    output, operations, state = apply(fails=True)
    assert "Podman pull exited 125" in output
    assert _mutations(operations) == [("root", "pull")]
    assert _actions(operations) == []
    assert state["running"] is None
    assert not archive.exists()


@pytest.mark.parametrize("loaded", [OLD_ID, "missing", EXPECTED_ID[:19], "permission"])
def test_container_probe_rejects_a_bad_loaded_id_before_activation(project_role, loaded):
    apply, _ = project_role(prior="legacy", load=loaded)
    output, operations, state = apply(fails=True)
    expected_error = {
        OLD_ID: "loaded tag does not match",
        "missing": "loaded tag does not match",
        EXPECTED_ID[:19]: "expected a full sha256 image",
        "permission": "Permission denied",
    }
    assert expected_error[loaded] in output
    assert _mutations(operations) == [
        ("root", "tag"),
        ("root", "save"),
        ("user", "load"),
        ("root", "tag"),
        ("root", "save"),
        ("user", "load"),
    ]
    assert _actions(operations) == []
    assert state["running"] == OLD_ID


@pytest.mark.parametrize("offline", [False, True])
def test_container_probe_rebuilds_a_corrupted_layer_only_from_the_pinned_source(
    project_role, offline
):
    apply, archive = project_role(prior="corrupt-offline" if offline else "corrupt")
    before = archive.read_bytes()
    output, operations, state = apply(fails=offline)
    assert "Layer digest mismatch" in output
    if offline:
        assert _mutations(operations) == [("user", "load"), ("root", "pull")]
        assert _actions(operations) == []
        assert state["running"] == OLD_ID
        assert archive.read_bytes() == before
    else:
        assert _mutations(operations) == [
            ("user", "load"),
            ("root", "tag"),
            ("root", "save"),
            ("user", "load"),
        ]
        assert _actions(operations) == ["restarted"]
        assert state["running"] == EXPECTED_ID
        with tarfile.open(archive) as saved:
            assert saved.extractfile(LAYER_NAME).read() == LAYER


def test_exact_source_uses_stock_podman_healthcheck(monkeypatch):
    ref = (
        "docker.io/filebrowser/filebrowser@"
        "sha256:1bc61f3b452ae458c0f5be7867fcc0c78476bbd48c5546b41d7d66a6df04db71"
    )
    config_id = "b3983274c0375dda1722f8e2b65c30d1b9001435e441f0a34855c2e5f8da462e"
    inspect = {
        "Id": config_id,
        "Digest": ref.split("@")[1],
        "ManifestType": "application/vnd.docker.distribution.manifest.v2+json",
        "Config": {"Entrypoint": ["tini", "--", "/init.sh"]},
        "Healthcheck": {
            "Test": ["CMD-SHELL", "/healthcheck.sh"],
            "StartPeriod": 2000000000,
            "Interval": 5000000000,
            "Timeout": 3000000000,
        },
    }

    def podman(*args, **options):
        if args == ("image", "exists", ref):
            assert options["allow_absent"]
            return ""
        assert args == ("image", "inspect", ref)
        return json.dumps([inspect])

    monkeypatch.setattr(image_transport, "podman", podman)
    assert image_transport.exact_source(ref) == ("sha256:" + config_id, True)

    inspect["Config"]["Healthcheck"] = {"Test": ["NONE"]}
    assert image_transport.exact_source(ref) == ("sha256:" + config_id, True)
    inspect.pop("Healthcheck")
    assert image_transport.exact_source(ref) == ("sha256:" + config_id, False)
