"""L10: apply a pending UI revision through the version-bound executor action.

Fake host and temporary files only: this proves planning, binding, ordering and the
refusal cases. The real separate-UID path and the second unchanged deployment are
the host gate (tests/integration/gates/m5_l10_l11.md).
"""

from __future__ import annotations

import copy
import json
import os
import time
import uuid

import pytest
import yaml
from fastapi.testclient import TestClient

from conftest import FakeHost
from steward import __version__, hostcli
from steward.adapters.remediation import Paths
from steward.api.app import create_app
from steward.core import render
from steward.core.canonical import revision_id
from steward.core.config import effective, parse_config
from steward.core.config_apply import plan_apply
from steward.executor import config_apply as module
from steward.executor import server as executor_server
from test_api import ORIGIN, TOKEN, settings

OPERATOR = 0
ME = os.getuid()


def edited(body, mutate):
    out = copy.deepcopy(body)
    mutate(out)
    return effective(parse_config(out))


def window(body):
    body["maintenance"] = {"weekly_window": "Sun 03:00 Europe/Berlin"}


@pytest.fixture
def base(raw_config):
    raw = copy.deepcopy(raw_config)
    window(raw)
    return effective(parse_config(raw))


# ---- the plan --------------------------------------------------------------------------


def test_registry_only_changes_are_supported(base):
    head = edited(base, lambda b: b["maintenance"].update(weekly_window="Mon 04:00 UTC"))
    plan = plan_apply(base, head, release_version="1")
    assert plan.supported and plan.areas == ("maintenance",)
    assert plan.operations == ("desired_config", "executor_registry")
    head = edited(base, lambda b: b["projects"][0]["maintenance"].update(allow_restart=False))
    assert plan_apply(base, head, release_version="1").supported
    head = edited(base, lambda b: b["projects"][0]["health"].update(retries=5))
    assert plan_apply(base, head, release_version="1").supported


@pytest.mark.parametrize(
    "mutate, reason",
    [
        (lambda b: b["projects"][0]["resources"].update(memory_mb=256), "generated_inputs"),
        (lambda b: b["projects"][0].update(host_port=20999), "generated_inputs"),
        (lambda b: b["projects"].clear(), "generated_inputs"),
        (lambda b: b["hardening"]["firewall"].update(manage=False), "area_needs_deployment"),
        (lambda b: b["channels"].append({"id": "ops", "kind": "webhook"}), "invalid_configuration"),
        (lambda b: b["admin"].update(port=9555), "area_needs_deployment"),
        (lambda b: b["server"].update(name="other-server"), "server_changed"),
    ],
)
def test_everything_else_needs_a_deployment(base, mutate, reason):
    try:
        head = edited(base, mutate)
    except Exception:  # an invalid revision cannot even be built
        head = copy.deepcopy(base)
        mutate(head)
    plan = plan_apply(base, head, release_version="1")
    assert not plan.supported and plan.reason.startswith(reason) and plan.operations == ()


def test_admin_lan_access_and_scope_require_site_deployment(base):
    deferred = edited(base, lambda b: b["admin"].update(access="private-lan"))
    resolved = edited(
        deferred,
        lambda b: b["admin"].update(lan={"interface": "ens1", "bind": "192.168.1.3/24"}),
    )
    for old, new in ((base, deferred), (deferred, resolved)):
        plan = plan_apply(old, new, release_version="1")
        assert not plan.supported
        assert plan.reason == "area_needs_deployment:admin"
        assert plan.areas == ("admin",)
        assert plan.operations == ()


def test_unavailable_features_and_non_canonical_heads_never_apply(base):
    drills = copy.deepcopy(base)
    drills["maintenance"]["drills"] = ["resources"]
    assert plan_apply(base, drills, release_version="1").reason == "invalid_configuration"
    sloppy = copy.deepcopy(base)
    del sloppy["hardening"]  # valid input, but not the canonical form
    assert plan_apply(base, sloppy, release_version="1").reason == "not_canonical"
    assert plan_apply(base, base, release_version="1").reason == "no_change"


# ---- the executor action ----------------------------------------------------------------


class World:
    pass


@pytest.fixture
def world(tmp_path, base):
    cfg = parse_config(base)
    registry = render.render_registry(cfg)
    registry["peers"] = {"api": 4242, "controller": 4343}
    root = tmp_path / "host"
    (root / "config").mkdir(parents=True)
    (root / "state").mkdir()
    paths = Paths(registry=root / "executor.json", desired=root / "config" / "desired.json")
    paths.registry.write_text(
        json.dumps(registry, indent=4, sort_keys=True, separators=(",", ": ")) + "\n"
    )
    paths.registry.chmod(0o600)
    paths.desired.write_text(json.dumps(base, sort_keys=True) + "\n")
    paths.desired.chmod(0o640)
    ex = executor_server.Executor(
        registry_path=str(paths.registry),
        state_dir=str(root / "state"),
        audit_path=str(root / "audit.jsonl"),
        lock_dir=str(root / "locks"),
        host=FakeHost(),
    )
    w = World()
    w.ex, w.paths, w.base, w.root = ex, paths, base, root
    w.export = root / "head.json"
    ex.config_apply_paths, ex.config_apply_export = paths, w.export
    return w


def publish(w, head_body, *, head=None, claimed=None):
    rev = revision_id(head_body)
    w.export.write_text(
        json.dumps({"head": head or rev, "applied": revision_id(w.base), "config": head_body})
    )
    return rev


def call(w, head, applied=None, *, release=__version__, uid=OPERATOR):
    raw = json.dumps(
        {
            "v": 1,
            "action": "config_apply",
            "params": {
                "head_revision": head,
                "applied_revision": applied or revision_id(w.base),
                "release": release,
            },
            "request_id": uuid.uuid4().hex,
            "expires_at": time.time() + 60,
        }
    ).encode()
    return w.ex.handle(raw, uid)


def files(w):
    return (
        json.loads(w.paths.desired.read_text()),
        json.loads(w.paths.registry.read_text()),
    )


def good_head(w):
    return edited(w.base, lambda b: b["projects"][0]["maintenance"].update(allow_restart=False))


def test_apply_installs_exactly_the_planned_files(world):
    head_body = good_head(world)
    head = publish(world, head_body)
    result = call(world, head)
    assert result["ok"], result
    done = result["result"]
    assert done["state"] == "applied" and done["verified"] is True
    assert done["operations"] == ["desired_config", "executor_registry"]
    desired, registry = files(world)
    assert desired == head_body and revision_id(desired) == head
    assert registry["config_revision"] == head and registry["peers"] == {
        "api": 4242,
        "controller": 4343,
    }
    assert registry["projects"]["notes"]["allow_restart"] is False
    assert world.ex.host.calls == []  # no restart, no unit change
    again = call(world, head)  # repeating after completion is a no-op
    assert again["ok"] and again["result"]["state"] == "already_applied"
    audit = [json.loads(line) for line in (world.root / "audit.jsonl").read_text().splitlines()]
    assert any(e.get("event") == "config_apply" and e.get("head") == head for e in audit)


def test_api_role_may_apply_but_the_kill_switch_stops_it(world):
    head = publish(world, good_head(world))
    world.ex.host.killed = True
    assert call(world, head, uid=4242)["error_class"] == "kill_switch"
    assert files(world)[0] == world.base
    world.ex.host.killed = False
    assert call(world, head, uid=4242)["ok"]
    assert call(world, head, uid=4343)["error_class"] == "forbidden_role"  # controller: never


def test_version_and_revision_bindings(world):
    head = publish(world, good_head(world))
    assert call(world, head, release="9.9.9")["error_class"] == "conflict"
    assert call(world, head, applied="a" * 64)["error_class"] == "conflict"
    # a second browser edit moved the head after the caller reviewed another revision
    newer = edited(world.base, lambda b: b["maintenance"].update(weekly_window="Tue 01:00 UTC"))
    publish(world, newer)
    assert call(world, head)["error_class"] == "conflict"
    # an export whose body does not hash to its head is never trusted
    tampered = good_head(world)
    world.export.write_text(
        json.dumps({"head": head, "applied": "x", "config": tampered | {"x": 1}})
    )
    assert call(world, head)["error_class"] == "conflict"
    world.export.unlink()
    assert call(world, head)["error_class"] == "unavailable"
    assert files(world)[0] == world.base  # nothing changed on any refusal


def test_a_revision_that_needs_deployment_changes_nothing(world):
    head = publish(
        world, edited(world.base, lambda b: b["projects"][0]["resources"].update(memory_mb=256))
    )
    refused = call(world, head)
    assert refused["error_class"] == "policy_denied" and "generated_inputs" in refused["message"]
    assert files(world)[0] == world.base


def test_drift_between_registry_and_applied_configuration_is_a_conflict(world):
    head = publish(world, good_head(world))
    registry = json.loads(world.paths.registry.read_text())
    registry["projects"]["notes"]["memory_mb"] = 1
    world.paths.registry.write_text(json.dumps(registry))
    assert call(world, head)["error_class"] == "conflict"


def test_deployment_fence_blocks_and_the_lock_is_exclusive(world, monkeypatch):
    head = publish(world, good_head(world))
    monkeypatch.setattr(world.ex, "deployment_fence", lambda: object())
    assert call(world, head)["error_class"] == "target_busy"
    monkeypatch.undo()
    with world.ex.target_lock("deployment-execution"):
        assert call(world, head)["error_class"] == "target_busy"


@pytest.mark.parametrize("crash_after", [0, 1])
def test_every_crash_point_is_finished_by_repeating_the_call(world, monkeypatch, crash_after):
    """Registry is written first, desired.json (the commit point) last."""
    head_body = good_head(world)
    head = publish(world, head_body)
    real, written = module._write_atomic, []

    class Crash(BaseException):
        pass

    def crashing(path, text, **kwargs):
        if len(written) == crash_after:
            raise Crash
        written.append(path.name)
        real(path, text, **kwargs)

    monkeypatch.setattr(module, "_write_atomic", crashing)
    with pytest.raises(Crash):
        call(world, head)
    desired, registry = files(world)
    assert desired == world.base  # never "applied" before the registry matches
    assert registry["config_revision"] == (head if crash_after else revision_id(world.base))
    monkeypatch.setattr(module, "_write_atomic", real)
    done = call(world, head)
    assert done["ok"] and done["result"]["state"] == "applied"
    assert files(world)[0] == head_body and files(world)[1]["config_revision"] == head


def test_host_cli_passes_the_installed_release(monkeypatch, capsys):
    seen = {}

    def fake_call(action, params=None, **kwargs):
        seen.update(action=action, params=params)
        return {"state": "applied"}

    monkeypatch.setattr(hostcli, "call", fake_call)
    monkeypatch.setattr(hostcli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        "sys.argv", ["steward-host", "config-apply", "--head", "a" * 64, "--applied", "b" * 64]
    )
    hostcli.main()
    assert seen["action"] == "config_apply"
    assert seen["params"] == {
        "head_revision": "a" * 64,
        "applied_revision": "b" * 64,
        "release": __version__,
    }


# ---- API: plan, CSRF, conflicts, durable outcome ------------------------------------------


@pytest.fixture
def api(tmp_path, cfg):
    (tmp_path / "desired.json").write_text(json.dumps(effective(cfg)))
    app = create_app(settings(tmp_path))
    client = TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN})
    login = client.post("/api/login", json={"token": TOKEN})
    client.headers["X-CSRF-Token"] = login.json()["csrf"]
    client.app_ref = app
    return client


def commit(client, mutate):
    state = client.get("/api/config").json()
    data = state["config"]
    mutate(data)
    response = client.post(
        "/api/config/revisions", json={"yaml": yaml.safe_dump(data), "parent": state["head"]}
    )
    assert response.status_code == 200, response.text
    return response.json()["revision"]


def allow_restart_off(data):
    data["projects"][0]["maintenance"]["allow_restart"] = False


def post(client, body, key="apply-0001", headers=None):
    return client.post(
        "/api/config/apply", json=body, headers={"Idempotency-Key": key, **(headers or {})}
    )


def test_config_yaml_uses_the_captured_head(api, monkeypatch):
    original = api.get("/api/config").json()["head"]
    newer = commit(api, allow_restart_off)
    # The head changes between reading the pointer and loading the revision body.
    heads = iter([original, newer])
    monkeypatch.setattr(api.app_ref.state.store, "head", lambda: next(heads))

    state = api.get("/api/config").json()
    assert state["head"] == revision_id(state["config"]) == original
    assert revision_id(yaml.safe_load(state["yaml"])) == original


def test_plan_is_shown_for_a_pending_revision(api):
    assert api.get("/api/config/apply-plan").json()["plan"] is None
    head = commit(api, allow_restart_off)
    shown = api.get("/api/config/apply-plan").json()
    assert shown["plan"]["supported"] is True and shown["plan"]["head"] == head
    assert shown["plan"]["areas"] == ["projects"] and shown["release"] == __version__
    assert shown["plan"]["diff"][0]["path"].endswith("allow_restart")
    commit(api, lambda d: d["projects"][0]["resources"].update(memory_mb=256))
    unsupported = api.get("/api/config/apply-plan").json()["plan"]
    assert unsupported["supported"] is False and "generated_inputs" in unsupported["reason"]


def test_apply_request_is_guarded_and_version_bound(api):
    head = commit(api, allow_restart_off)
    applied = api.get("/api/config").json()["applied"]
    body = {"head": head, "applied": applied}
    assert api.post("/api/config/apply", json=body).status_code == 400  # key required
    assert post(api, body, headers={"X-CSRF-Token": "x"}).status_code == 403
    assert post(api, body, headers={"Origin": "https://evil.example"}).status_code == 403
    assert post(api, {**body, "extra": 1}).status_code == 422
    # another browser tab committed meanwhile: the reviewed head is stale
    newer = commit(api, lambda d: d.update(maintenance={"weekly_window": "Mon 01:00 UTC"}))
    stale = post(api, body)
    assert stale.status_code == 409 and stale.json()["detail"]["head"] == newer
    assert api.get("/api/jobs").json()["jobs"] == []  # nothing was queued


def test_unsupported_revision_is_refused_before_a_job_exists(api):
    head = commit(api, lambda d: d["projects"][0]["resources"].update(memory_mb=256))
    applied = api.get("/api/config").json()["applied"]
    refused = post(api, {"head": head, "applied": applied})
    assert refused.status_code == 422 and "deploy" in refused.json()["detail"]["message"]
    assert api.get("/api/jobs").json()["jobs"] == []


def test_tracked_apply_job_is_returned_outside_recent_jobs(api):
    head = commit(api, allow_restart_off)
    applied = api.get("/api/config").json()["applied"]
    body = {"head": head, "applied": applied}
    submitted = post(api, body)
    assert submitted.status_code == 202
    job_id = submitted.json()["id"]
    for number in range(5):
        assert post(api, body, key=f"apply-new-{number}").status_code == 202

    response = api.get("/api/config/apply-plan", params={"job_id": job_id})
    assert response.status_code == 200
    shown = response.json()
    assert len(shown["jobs"]) == 5
    assert all(job["id"] != job_id for job in shown["jobs"])
    assert shown["tracked_job"] == submitted.json()


def test_job_success_means_the_applied_pointer_moved(
    api, tmp_path, base, executor, executor_socket
):
    head = commit(api, allow_restart_off)
    applied = api.get("/api/config").json()["applied"]
    executor.config_apply_paths = Paths(
        registry=executor.registry_file, desired=tmp_path / "desired.json"
    )
    executor.config_apply_export = tmp_path / "api" / "export" / "head.json"
    first = post(api, {"head": head, "applied": applied})
    again = post(api, {"head": head, "applied": applied})
    assert first.status_code == 202 and first.json()["id"] == again.json()["id"]
    assert api.get("/api/config").json()["pending"] is True  # submission is not success
    api.app_ref.state.run_pending_jobs()
    job = api.get("/api/jobs").json()["jobs"][0]
    assert job["state"] == "succeeded", job["error"]
    assert job["result"]["state"] == "applied"
    state = api.get("/api/config").json()
    assert state["pending"] is False and state["applied"] == head == state["head"]
    assert json.loads((tmp_path / "desired.json").read_text())["projects"][0]["maintenance"] == {
        "allow_backup_pause": False,
        "allow_restart": False,
    }
    shown = api.get("/api/config/apply-plan").json()
    assert shown["plan"] is None and shown["jobs"][0]["state"] == "succeeded"


def test_queued_config_apply_survives_api_recreation(api, tmp_path, executor, executor_socket):
    executor.config_apply_paths = Paths(
        registry=executor.registry_file, desired=tmp_path / "desired.json"
    )
    executor.config_apply_export = tmp_path / "api" / "export" / "head.json"
    with api:
        head = commit(api, allow_restart_off)
        applied = api.get("/api/config").json()["applied"]
        submitted = post(api, {"head": head, "applied": applied})
        assert submitted.status_code == 202, submitted.text
        job_id = submitted.json()["id"]

    reopened = create_app(settings(tmp_path))
    with TestClient(reopened, base_url=ORIGIN, headers=api.headers, cookies=api.cookies) as client:
        response = client.get("/api/jobs")
        assert response.status_code == 200, response.text
        (job,) = response.json()["jobs"]
        assert (job["id"], job["kind"], job["state"]) == (job_id, "config_apply", "queued")
        assert client.get("/api/config").json()["applied"] == applied

        reopened.state.run_pending_jobs()
        (job,) = client.get("/api/jobs").json()["jobs"]
        assert job["id"] == job_id and job["state"] == "succeeded", job["error"]
        assert job["result"]["state"] == "applied"
        state = client.get("/api/config").json()
        assert state["pending"] is False and state["head"] == state["applied"] == head


def test_cli_deployment_in_between_fails_the_job_with_its_cause(
    api, tmp_path, executor, executor_socket
):
    head = commit(api, allow_restart_off)
    applied = api.get("/api/config").json()["applied"]
    executor.config_apply_paths = Paths(
        registry=executor.registry_file, desired=tmp_path / "desired.json"
    )
    executor.config_apply_export = tmp_path / "api" / "export" / "head.json"
    post(api, {"head": head, "applied": applied})
    # a CLI deployment replaced the applied configuration before the job ran
    other = json.loads((tmp_path / "desired.json").read_text())
    other["maintenance"] = {"weekly_window": "Wed 02:00 UTC"}
    (tmp_path / "desired.json").write_text(json.dumps(other))
    api.app_ref.state.run_pending_jobs()
    job = api.get("/api/jobs").json()["jobs"][0]
    assert job["state"] == "failed" and "conflict" in job["error"] and job["attempts"] == 1


# ---- CLI --------------------------------------------------------------------------------


def test_cli_apply_is_bound_to_the_reviewed_head(cfg, tmp_path, monkeypatch, capsys):
    from steward.cli import main as cli

    head, applied = "a" * 64, "b" * 64
    server = {"head": head, "applied": applied}
    calls = []
    (tmp_path / "vars.json").write_text("{}")
    monkeypatch.setattr(cli, "load", lambda _: cfg)
    monkeypatch.setattr(cli, "generate", lambda *_: tmp_path)

    def ansible(playbook, connection, out, **kwargs):
        calls.append((playbook, json.loads((out / "vars.json").read_text())))
        if playbook == "config-pull.yml":
            (out / "remote-state.json").write_text(json.dumps({"head": server}))
        else:
            (out / "config-apply-result.json").write_text(
                json.dumps({"state": "applied", "config_revision": head, "verified": True})
            )

    monkeypatch.setattr(cli, "ansible", ansible)

    def parse(rev):
        return cli.build_parser().parse_args(
            ["config", "apply", "--config", "c.yml", "--limit", cfg.server.name, "--head", rev]
        )

    with pytest.raises(cli.CliError, match="not the reviewed") as caught:
        cli.cmd_config_apply(parse("c" * 64))  # the server head moved after the review
    assert caught.value.code == cli.EXIT_CONFLICT and [c[0] for c in calls] == ["config-pull.yml"]
    assert cli.cmd_config_apply(parse(head)) == 0
    assert calls[-1] == (
        "config-apply.yml",
        {"steward_apply_head": head, "steward_apply_applied": applied},
    )
    assert "config pull" in capsys.readouterr().out


# D1: an unguarded site deployment holds no fence or lock across its run. It leaves a durable
# marker for the whole run; its own writes are compare-and-set against the starting revision.


def test_a_running_site_deployment_blocks_apply_without_side_effects(world):
    head = publish(world, good_head(world))
    marker = world.paths.desired.parent / module.RUN_MARKER
    marker.write_text("{}\n")
    refused = call(world, head)
    assert refused["error_class"] == "target_busy"
    assert files(world)[0] == world.base and "applied" not in json.dumps(files(world)[1])
    audit = [json.loads(x) for x in (world.root / "audit.jsonl").read_text().splitlines()]
    assert not any(e.get("event") == "config_apply" for e in audit)
    marker.unlink()  # the run finished (or the next deployment cleared it)
    assert call(world, head)["ok"]


def test_deployment_writes_are_compare_and_set(world, monkeypatch, capsys):
    from contextlib import nullcontext

    from steward import application_boot as boot

    monkeypatch.setattr(boot, "deployment_lock", lambda **_: nullcontext())
    start = revision_id(world.base)
    args = dict(desired=world.paths.desired, registry=world.paths.registry)
    module.check_base(start, **args)  # unchanged: the deployment may write
    head = publish(world, good_head(world))
    assert call(world, head)["ok"]  # the executor applied a revision meanwhile
    with pytest.raises(SystemExit) as stop:
        module.check_base(start, **args)
    assert stop.value.code == 3
    assert module.MOVED in capsys.readouterr().err
    module.check_base(head, **args)
    registry = json.loads(world.paths.registry.read_text())
    registry["config_revision"] = start  # registry alone behind desired.json
    world.paths.registry.write_text(json.dumps(registry))
    with pytest.raises(SystemExit):
        module.check_base(head, **args)
    world.paths.desired.unlink()
    with pytest.raises(SystemExit) as gone:
        module.check_base(start, **args)
    assert gone.value.code != 3 and gone.value.code != 0


def test_cli_turns_a_moved_revision_into_exit_4(monkeypatch, tmp_path, cfg):
    from steward.cli import main as cli

    class Proc:
        returncode = 2
        stdout = iter(["fatal: [h]: FAILED! STEWARD_CONFIG_MOVED applied=ab registry=ab\n"])

        def __init__(self, *a, **k):
            pass

        def wait(self):
            pass

    monkeypatch.setattr(cli.subprocess, "Popen", Proc)
    with pytest.raises(cli.CliError) as err:
        cli.ansible("site.yml", cfg, tmp_path)
    assert err.value.code == cli.EXIT_CONFLICT and "config pull" in str(err.value)


def test_site_playbook_marks_the_whole_run_and_guards_the_writes():
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent / "ansible"
    site = (root / "playbooks" / "site.yml").read_text()
    platform = (root / "roles" / "platform" / "tasks" / "main.yml").read_text()
    mark = site.index("Mark the unguarded deployment run")
    clear = site.index("Clear the unguarded deployment run marker")
    assert site.index("import_role") < mark < site.index("Deploy steward platform")
    assert clear > site.index("Complete the protected site deployment")
    assert site.count("deploy-run.json") == 2 and module.RUN_MARKER in site
    cas = platform.index("check-base")
    assert platform.index("Activate release") < cas < platform.index("Write desired configuration")
    assert cas < platform.index("Write executor registry")


def test_apply_withdraws_before_write_and_noop_keeps_authority(world, monkeypatch):
    from steward import application_boot as boot
    from steward.core import inference_deployment as inference

    path = world.root / "inference" / "selection.json"
    path.parent.mkdir()
    path.write_text("{}")
    monkeypatch.setattr(inference, "_projection_group", lambda directory: 1234)
    monkeypatch.setattr(boot, "protected", lambda path, mode, gid: path.open("rb"))
    real = module._write_atomic

    def atomic(path_to_write, text, **kwargs):
        assert not path.exists()
        real(path_to_write, text, **kwargs)

    monkeypatch.setattr(module, "_write_atomic", atomic)
    head = publish(world, good_head(world))
    assert call(world, head)["result"]["state"] == "applied"
    assert not path.exists()
    path.write_text("{}")
    assert call(world, head)["result"]["state"] == "already_applied"
    assert path.exists()
