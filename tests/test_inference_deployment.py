import json
import os
import subprocess
from types import SimpleNamespace

import pytest

from steward import application_boot as boot
from steward.core import inference_deployment as module
from steward.core import ollama_install
from steward.core.config import Ai
from steward.executor import server


@pytest.fixture
def run(request):
    advice = getattr(request, "param", False)
    ai = Ai(
        provider="ollama",
        model="fixture:tiny",
        local={"download_mb": 1, "ram_mb": 128, "disk_mb": 2, "license_ack": True},
        budget={"monthly": {"tokens": 10_000, "seconds": 60}} if advice else None,
    )
    return module._Run.model_validate(
        {
            "candidate": {
                "version": 1,
                "revision": "a" * 64,
                "release": "0.1.0",
                "wheel_sha256": "b" * 64,
                "manifest_sha256": "c" * 64,
                **({"advice": True} if advice else {}),
            },
            "ollama": {"ai": ai.model_dump(mode="json"), "reserved_memory_mb": 1024},
            "run_id": "d" * 32,
            "models": "/var/lib/steward/ollama/" + "e" * 64,
        }
    )


@pytest.fixture
def world(tmp_path, monkeypatch, run):
    marker = tmp_path / "deploy-run.json"
    proof = tmp_path / "inference-stage.json"
    projection = tmp_path / "selection.json"
    desired = tmp_path / "desired.json"
    registry = tmp_path / "executor.json"
    desired.touch()
    registry.touch()
    marker.write_text(
        json.dumps(
            {
                "base_revision": run.candidate.revision,
                "desired_revision": run.candidate.revision,
                "inference_run": run.run_id,
            }
        )
    )
    policy = module.CandidatePolicy(
        **run.candidate.model_dump(),
        generation=run.run_id,
        ai=run.ollama.ai,
        weekly_window=None,
    )
    monkeypatch.setattr(module, "DESIRED_PATH", desired)
    monkeypatch.setattr(module, "PROJECTION_PATH", projection)
    monkeypatch.setattr(server, "REGISTRY_PATH", str(registry))
    monkeypatch.setattr(boot, "safe_directory", lambda directory: None)
    monkeypatch.setattr(boot, "protected", lambda path, mode, gid=0: path.open("rb"))
    monkeypatch.setattr(module, "_applied_policy", lambda run: policy)
    monkeypatch.setattr(module, "_installed_model", lambda run, policy: [[1, 2, 3]])
    monkeypatch.setattr(
        module, "_project", lambda policy: projection.write_text(policy.model_dump_json())
    )
    checked = []

    def verify(argv, *, check, timeout):
        assert marker.exists() and proof.exists() and not projection.exists()
        assert check and timeout
        checked.append(argv)

    monkeypatch.setattr(module.subprocess, "run", verify)
    return SimpleNamespace(
        marker=marker,
        proof=proof,
        projection=projection,
        desired=desired,
        policy=policy,
        checked=checked,
    )


def operate(action, run, world):
    module._stage_or_publish(action, run, world.marker, world.proof)


@pytest.mark.parametrize("run", [False, True], indirect=True, ids=["scan", "advice"])
def test_stage_proof_private_and_publish_verifies_then_clears(run, world, monkeypatch):
    advice_flag = {"advice": True} if run.ollama.ai.budget else {}
    operate("stage", run, world)
    assert world.proof.stat().st_mode & 0o777 == 0o600
    assert world.marker.exists() and not world.projection.exists()
    staged_candidate = json.loads(world.proof.read_text())["run"]["candidate"]
    assert staged_candidate == {
        "version": 1,
        "revision": "a" * 64,
        "release": "0.1.0",
        "wheel_sha256": "b" * 64,
        "manifest_sha256": "c" * 64,
        **advice_flag,
    }
    operate("publish", run, world)
    assert world.checked == [
        [
            "/opt/steward/current/venv/bin/steward-host",
            "verify",
            "--expect-revision",
            run.candidate.revision,
        ]
    ]
    assert not world.marker.exists() and not world.proof.exists()
    projected = json.loads(world.projection.read_text())
    assert projected == world.policy.model_dump(mode="json")
    assert {key: value for key, value in projected.items() if key == "advice"} == advice_flag
    monkeypatch.setattr(module, "_projection_group", lambda directory: 1234)
    assert module.read_candidate_policy(world.projection) == world.policy


@pytest.mark.parametrize(
    "changed", ["marker", "proof", "install", "desired", "verify", "superseded_during_verify"]
)
def test_publish_refuses_failed_or_superseded_attempt(run, world, monkeypatch, changed):
    operate("stage", run, world)
    if changed == "marker":
        world.marker.write_text(json.dumps({"base_revision": run.candidate.revision}))
    elif changed == "proof":
        world.proof.unlink()
    elif changed == "install":
        monkeypatch.setattr(module, "_installed_model", lambda run, policy: [[1, 2, 4]])
    elif changed == "desired":
        world.desired.write_text("{}")
    elif changed == "verify":

        def fail(*args, **kwargs):
            raise subprocess.CalledProcessError(1, args[0])

        monkeypatch.setattr(module.subprocess, "run", fail)
    marker = world.marker.read_text()
    if changed == "superseded_during_verify":
        marker = json.dumps({"site_run": "a" * 32})

        def supersede(*args, **kwargs):
            world.marker.write_text(marker)

        monkeypatch.setattr(module.subprocess, "run", supersede)
    with pytest.raises((boot.BootError, FileNotFoundError, subprocess.CalledProcessError)):
        operate("publish", run, world)
    assert not world.projection.exists()
    assert world.marker.read_text() == marker


@pytest.mark.parametrize("run", [True], indirect=True)
def test_publish_refuses_advice_opt_in_added_after_stage(run, world):
    scan_run = module._Run.model_validate(
        run.model_dump(mode="json") | {"candidate": run.candidate.model_dump(exclude={"advice"})}
    )
    operate("stage", scan_run, world)
    with pytest.raises(boot.BootError, match="proof changed"):
        operate("publish", run, world)
    assert world.marker.exists() and world.proof.exists()
    assert not world.projection.exists()
    assert not world.checked


def test_socket_preflight_refuses_existing_or_unsafe_paths(tmp_path, monkeypatch):
    parent = tmp_path / "socket"
    path = parent / "admin.sock"
    monkeypatch.setattr(boot, "safe_directory", lambda directory: None)
    module._socket_preflight(path)
    parent.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(boot.BootError):
        module._socket_preflight(path)
    parent.unlink()
    parent.mkdir(mode=0o755)
    real_lstat = type(path).lstat

    def root_lstat(path):
        info = real_lstat(path)
        return SimpleNamespace(st_uid=0, st_gid=0, st_mode=info.st_mode)

    monkeypatch.setattr(type(path), "lstat", root_lstat)
    module._socket_preflight(path)
    path.symlink_to(parent / "missing")
    with pytest.raises(boot.BootError):
        module._socket_preflight(path)


def test_installed_manifest_binds_to_projected_digest(run, tmp_path, monkeypatch):
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:" + "a" * 64,
                "size": 1,
            },
            "layers": [
                {"mediaType": ollama_install.MODEL_LAYER, "digest": "sha256:" + "b" * 64, "size": 1}
            ],
        }
    ).encode()
    digest = boot.digest(manifest)
    receipt = json.dumps(
        {
            "model": run.ollama.ai.model,
            "manifest_sha256": digest,
            "license": "fixture",
            "license_source": "fixture",
        }
    ).encode()
    installed = ollama_install.parse_staged_model(run.ollama.ai.model, receipt, manifest)
    root = tmp_path / installed.key
    manifest_path = root / installed.relative_manifest
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_bytes(manifest)
    (root / ollama_install.RECEIPT).write_bytes(receipt)
    monkeypatch.setattr(ollama_install, "MODEL_ROOT", tmp_path)
    monkeypatch.setattr(ollama_install, "_read_staged", lambda path: path.read_bytes())
    monkeypatch.setattr(boot, "safe_directory", lambda directory: None)
    monkeypatch.setattr(boot, "protected", lambda path, mode, gid=0: path.open("rb"))
    run = run.model_copy(update={"models": str(root)})
    policy = module.CandidatePolicy(
        **(run.candidate.model_dump() | {"manifest_sha256": digest}),
        generation=run.run_id,
        ai=run.ollama.ai,
        weekly_window=None,
    )
    assert len(module._installed_model(run, policy)) == 3
    wrong = policy.model_copy(update={"manifest_sha256": "0" * 64})
    with pytest.raises(boot.BootError, match="model differs"):
        module._installed_model(run, wrong)


def test_projection_reader_rejects_duplicate_fields_and_link(world, monkeypatch):
    monkeypatch.setattr(module, "_projection_group", lambda directory: 1234)

    def protected(path, mode, gid):
        return os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb")

    monkeypatch.setattr(boot, "protected", protected)
    path = world.projection
    assert module.read_candidate_policy(path) is None
    valid = world.policy.model_dump_json()
    path.write_text(valid)
    assert module.read_candidate_policy(path) == world.policy
    path.write_text('{"version":1,' + valid[1:])
    assert module.read_candidate_policy(path) is None
    path.unlink()
    path.symlink_to(world.desired)
    world.desired.write_text(valid)
    assert module.read_candidate_policy(path) is None


@pytest.mark.parametrize("advice", [True, False, "true", 1, None])
def test_projection_reader_refuses_unbudgeted_or_malformed_advice(world, monkeypatch, advice):
    monkeypatch.setattr(module, "_projection_group", lambda directory: 1234)
    payload = world.policy.model_dump(mode="json") | {"advice": advice}
    world.projection.write_text(json.dumps(payload))
    assert module.read_candidate_policy(world.projection) is None


@pytest.fixture
def private_provider():
    return {
        "base_url": "https://192.168.10.20:8443/v1",
        "budget": {"monthly": {"tokens": 10_000, "seconds": 120}},
        "share": ["status"],
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"base_url": "https://provider.lan:8443/v1"},
        {"base_url": "https://192.168.10.20/v1"},
        {"budget": {"monthly": {"tokens": 100}}},
        {"budget": {"monthly": {"tokens": 100, "seconds": 30}, "max_concurrent": 9}},
        {"share": ["status", "status"]},
        {"ca_pem": "-----BEGIN PRIVATE KEY-----\nexample\n-----END PRIVATE KEY-----"},
        {"credential": "forbidden"},
    ],
)
def test_private_policy_rejects_unapproved_inputs(private_provider, changes):
    with pytest.raises(ValueError):
        module.PrivateProviderPolicy.model_validate(private_provider | changes)


def test_private_overlay_preserves_canonical_api_config(cfg, private_provider):
    from steward.core.render import _render_private_ai_selection_candidate_vars, render_vars

    wheel = "steward-0.1.0-py3-none-any.whl"
    args = {
        "release": {"version": "0.1.0", "wheel": wheel, "files": {wheel: "b" * 64}},
        "ssh_port": 22,
    }
    private = module.PrivateProviderPolicy.model_validate(private_provider)
    result = _render_private_ai_selection_candidate_vars(cfg, **args, private_provider=private)
    assert result.pop("steward_inference_candidate") == {
        "version": 1,
        "revision": result["steward_config_revision"],
        "release": "0.1.0",
        "wheel_sha256": "b" * 64,
        "private_provider": private.model_dump(mode="json"),
    }
    assert result == render_vars(cfg, **args)


@pytest.mark.parametrize("access", ["private-lan", "private-loopback"])
def test_private_advice_preserves_private_admin_profile(cfg, private_provider, access):
    from steward.core.render import _render_private_ai_selection_candidate_vars, render_vars

    cfg = cfg.model_copy(update={"admin": cfg.admin.model_copy(update={"access": access})})
    wheel = "steward-0.1.0-py3-none-any.whl"
    args = {
        "release": {"version": "0.1.0", "wheel": wheel, "files": {wheel: "b" * 64}},
        "ssh_port": 22,
    }
    private = module.PrivateProviderPolicy.model_validate(
        private_provider | {"evaluation_window": "Sun 03:00 UTC"}
    )
    result = _render_private_ai_selection_candidate_vars(
        cfg, **args, private_provider=private, advice=True
    )
    assert result.pop("steward_inference_candidate")["advice"] is True
    assert result == render_vars(cfg, **args)
    with pytest.raises(ValueError, match="private admin access"):
        module._validate_advice_routes(cfg)


def test_private_stage_publish_binds_relay_and_skips_ollama(
    run, world, private_provider, tmp_path, monkeypatch
):
    from pathlib import Path

    from jinja2 import Environment, FileSystemLoader, StrictUndefined

    candidate = run.candidate.model_dump(exclude={"manifest_sha256"}) | {
        "private_provider": module.PrivateProviderPolicy.model_validate(
            private_provider
        ).model_dump(mode="json"),
        "advice": True,
    }
    private_run = module._Run.model_validate({"candidate": candidate, "run_id": run.run_id})
    assert private_run.model_dump(mode="json") == {"candidate": candidate, "run_id": run.run_id}
    policy = module.CandidatePolicy(**candidate, generation=run.run_id, ai=Ai(), weekly_window=None)
    with pytest.raises(ValueError, match="empty canonical AI"):
        module.CandidatePolicy(
            **candidate, generation=run.run_id, ai=run.ollama.ai, weekly_window=None
        )
    monkeypatch.setattr(module, "_applied_policy", lambda run: policy)
    monkeypatch.setattr(module, "SYSTEMD_DIR", tmp_path)
    activations = []

    def systemctl(action, *units):
        assert world.projection.exists()
        activations.append((action, units))

    monkeypatch.setattr(module, "_systemctl", systemctl)

    def reject_ollama(*args):
        pytest.fail("private candidate tried to use an Ollama model receipt")

    monkeypatch.setattr(module, "_installed_model", reject_ollama)
    templates = Path(__file__).resolve().parents[1] / "ansible/roles/platform/templates"
    env = Environment(
        loader=FileSystemLoader(templates), undefined=StrictUndefined, autoescape=True
    )
    for name in module.EGRESS_UNITS:
        unit = env.get_template(f"{name}.j2").render(
            platform_inference_egress_target=SimpleNamespace(stdout="192.168.10.20 8443"),
        )
        (tmp_path / name).write_text(unit)
    proxy = tmp_path / module.EGRESS_UNITS[1]
    contents = proxy.read_text()
    operate("stage", private_run, world)
    assert not activations
    proxy.write_text(contents.replace(":8443", ":443"))
    with pytest.raises(boot.BootError, match="approved endpoint"):
        operate("publish", private_run, world)
    assert not world.projection.exists()
    proxy.write_text(contents)
    with pytest.raises(boot.BootError, match="proof changed"):
        operate("publish", private_run, world)
    operate("stage", private_run, world)
    operate("publish", private_run, world)
    assert json.loads(world.projection.read_text()) == policy.model_dump(mode="json")
    assert activations == [
        ("start", module.EGRESS_UNITS),
        ("start", ("steward-inference-advice.service",)),
        ("enable", (module.EGRESS_UNITS[0], module.PRIVATE_TICK_TIMER)),
        ("start", (module.PRIVATE_TICK_TIMER,)),
    ]
    for name in ("tick", "advice"):
        unit = env.get_template(f"steward-inference-{name}.service.j2").render(
            platform_inference_private=True,
        )
        assert "PrivateNetwork=yes" in unit
        assert "RestrictAddressFamilies=AF_UNIX" in unit
        assert f"BindReadOnlyPaths={module.EGRESS_SOCKET_PATH}" in unit
        assert "steward-ollama.service" not in unit
        assert ("_private-candidate-tick" if name == "tick" else "_managed-private-advice") in unit
    admin = env.get_template("steward-inference-admin.service.j2").render()
    assert str(module.EGRESS_SOCKET_PATH) not in admin
    assert "SystemCallFilter=~socket socketpair connect bind listen" in admin


def test_revocation_stops_private_relay_before_unlinking(tmp_path, monkeypatch):
    desired = tmp_path / "config" / "desired.json"
    projection = tmp_path / "inference" / module.PROJECTION_PATH.name
    projection.parent.mkdir()
    projection.touch()
    for unit in module.EGRESS_UNITS:
        (tmp_path / unit).touch()
    monkeypatch.setattr(module, "DESIRED_PATH", desired)
    monkeypatch.setattr(module, "SYSTEMD_DIR", tmp_path)
    monkeypatch.setattr(module, "_projection_group", lambda path: 42)
    monkeypatch.setattr(boot, "protected", lambda path, mode, gid: path.open("rb"))
    calls = []

    def systemctl(action, *units):
        assert projection.exists()
        calls.append((action, units))

    monkeypatch.setattr(module, "_systemctl", systemctl)
    module.revoke_for_desired(desired)
    assert calls == [("stop", module.EGRESS_UNITS)]
    assert not projection.exists()
