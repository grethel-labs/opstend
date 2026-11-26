"""Live A04 acceptance using STEWARD_TEST_PRIVATE_INFERENCE=1 and the LAB_AI inputs."""

from __future__ import annotations

import errno
import json
import os
import select
import socket
import socketserver
import time
from contextlib import ExitStack, suppress
from datetime import UTC, datetime
from itertools import count
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from steward import inference_worker as worker
from steward.api.app import create_app
from steward.core import inference_deployment
from steward.core.advice import _GAPS, gap
from steward.core.advice_ipc import AdvicePeer, AdviceServer
from steward.core.ai_admin_ipc import AdminPeer
from steward.core.config import Ai, AiBudget
from steward.core.inference import ERROR_CLASSES
from steward.core.inference_budget import Ledger
from steward.core.inference_deployment import CandidatePolicy, PrivateProviderPolicy
from steward.core.inference_endpoint import parse
from steward.core.maintenance_runs import MaintenanceRuns
from steward.core.model_suite import cases
from steward.core.store import Store
from test_ai_admin_api import login
from test_ai_admin_ipc import serving
from test_api import settings

WINDOW = "Sun 03:00 UTC"
NOW = datetime(2026, 11, 29, 3, 1, tzinfo=UTC).timestamp()


class RelayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.connections += 1
        try:
            upstream = socket.create_connection(self.server.target, timeout=5)
        except OSError as exc:
            self.server.connect_error = exc.errno
            return
        with upstream:
            self.request.settimeout(12)
            peers = {self.request: upstream, upstream: self.request}
            try:
                while peers:
                    readable, _, _ = select.select(list(peers), [], [], 12)
                    if not readable:
                        return
                    for source in readable:
                        target = peers[source]
                        chunk = source.recv(65536)
                        if chunk:
                            target.sendall(chunk)
                        else:
                            del peers[source]
                            target.shutdown(socket.SHUT_WR)
            except OSError:
                return


class FixedRelay(socketserver.UnixStreamServer):
    connections = 0
    connect_error = None

    def handle_error(self, request, client_address):
        # Never emit transport frames or exception context.
        self.connect_error = errno.EIO


class LabAdviceServer(AdviceServer):
    """Use local UID pinning without the systemd worker-activation prelude."""

    def __init__(self, listener, uid, base):
        self._base = base
        worker._private_state_dir(base / "advice")
        self._init_listener(listener, uid, managed=False)

    def _run(self, items, scope, sources, deadline):
        return worker._run_managed_advice(self._base / "advice", items, scope, sources, deadline)


def require(condition, message):
    if not condition:
        pytest.fail(message, pytrace=False)


def listener(stack, path):
    sock = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
    sock.bind(str(path))
    sock.listen()
    return sock


def usage(base, db, budget, now):
    ledger = Ledger(base / db, budget)
    try:
        return ledger.usage(now=now)
    finally:
        ledger.close()


def run_lab(tmp_path, monkeypatch, endpoint, ca_pem, api_key):
    runtime = AiBudget(monthly={"tokens": 40_000, "seconds": 180})
    evaluation = AiBudget(monthly={"tokens": 30_000, "seconds": 180})
    private = PrivateProviderPolicy(
        base_url=endpoint,
        budget=runtime,
        evaluation_budget=evaluation,
        evaluation_window=WINDOW,
        ca_pem=ca_pem,
        share=["status"],
    )
    candidate = CandidatePolicy(
        version=1,
        revision="a" * 64,
        release="a04-lab",
        wheel_sha256="b" * 64,
        generation="c" * 32,
        ai=Ai(),
        weekly_window=None,
        private_provider=private,
        advice=True,
    )
    base = tmp_path / "worker"
    (tmp_path / "state.json").write_text(
        json.dumps(
            {
                "generated_at": time.time(),
                "status_ok": True,
                "status": {"kill_switch": False, "projects": {}},
            }
        )
    )
    paths = {name: tmp_path / f"{name}.sock" for name in ("admin", "advice", "relay")}
    monkeypatch.setattr(inference_deployment, "read_candidate_policy", lambda: candidate)
    monkeypatch.setattr(worker, "read_kill_switch", lambda: False)
    monkeypatch.setattr(worker, "EGRESS_SOCKET_PATH", paths["relay"])
    # The production factory requires root-owned ancestors. Trust only this test directory.
    monkeypatch.setattr(worker, "_trusted_directory", lambda path: path == tmp_path)
    uid = os.geteuid()
    sequence = count()

    def tick():
        result = worker.run_once(
            read_policy=worker._read_candidate,
            state_dir=base,
            kill_switch=worker.read_kill_switch,
            clock=lambda: NOW,
            candidate_policy=worker._read_candidate(),
        )
        require(result["status"] == "ok", "Private worker tick failed")
        return result

    with ExitStack() as stack:
        relay = FixedRelay(str(paths["relay"]), RelayHandler)
        address = parse(private.base_url)
        relay.target = (address.hostname, address.port)
        stack.enter_context(serving(relay))
        admin = worker.make_admin_server(
            listener(stack, paths["admin"]),
            socket_path=paths["admin"],
            state_dir=base,
            admin_uid=uid,
            read_policy=worker._read_candidate,
            clock=lambda: NOW,
            candidate=True,
        )
        stack.enter_context(serving(admin))
        advice = LabAdviceServer(listener(stack, paths["advice"]), uid, base)
        stack.enter_context(serving(advice))
        app = create_app(
            settings(
                tmp_path,
                ai_peer=AdminPeer(str(paths["admin"]), uid),
                advice_peer=AdvicePeer(str(paths["advice"]), uid),
            )
        )
        browser = stack.enter_context(login(app))

        def unpack(response, status, label):
            require(api_key not in response.text, "API response exposed the lab credential")
            require(response.status_code == status, f"Unexpected HTTP status for {label}")
            return response.json()

        def post(action, body=None, status=200):
            response = browser.post(
                f"/api/ai/{action}",
                json=body,
                headers={"Idempotency-Key": f"a04-lab-{next(sequence):08d}"},
            )
            return unpack(response, status, action)

        def view():
            return unpack(browser.get("/api/ai"), 200, "AI view")

        payload = {"option": "openai-compatible", "api_key": api_key}
        denied = post("provider", payload | {"base_url": private.base_url + "/other"}, 422)
        require(denied["detail"]["code"] == "endpoint_mismatch", "Endpoint mismatch was accepted")
        require(view()["pending_provider"] is None, "Rejected endpoint staged a provider")
        require(relay.connections == 0, "Rejected endpoint reached the relay")

        post("provider", payload | {"base_url": endpoint})
        require(view()["pending_provider"]["status"] == "pending", "Setup was not staged")
        require(relay.connections == 0, "Admin setup contacted the gateway before the worker tick")
        tick()
        if relay.connect_error is not None:
            error = errno.errorcode.get(relay.connect_error, "UNKNOWN")
            pytest.fail(
                f"Fixed relay could not open the lab gateway connection ({error})", pytrace=False
            )
        verified = view()
        require(verified["status"] == "scanned", "Gateway setup verification did not publish")
        require(verified["provider"]["base_url"] == private.base_url, "Wrong provider published")

        post("scan", status=202)
        scan = tick()["requests"]
        require(
            any(row["kind"] == "scan" and row["result"] == "ok" for row in scan),
            "Worker did not complete the live model scan",
        )
        models = view()["scanned"]["models"]
        require(bool(models), "The gateway listed no eligible models")
        model = models[0]
        post("initial-model", {"model": model})
        tick()
        ready = view()
        require(ready["active"]["model"] == model, "Selected model is not active")
        report = ready["report"]["body"]
        error = report.get("error")
        require(
            report["model"] == model
            and report["complete"]
            and report["cases"] == len(cases(NOW))
            and report["tokens"] > 0,
            "Initial report lacks measured suite evidence"
            + (f" ({error})" if error in ERROR_CLASSES else ""),
        )
        require(
            usage(base, "private-ledger.db", runtime, NOW)["tokens"] == 0,
            "Initial report spent from the advice ledger",
        )

        rotation = {"base_url": endpoint, "replace": True, "expected_choice_id": ready["choice_id"]}
        post("provider", payload | rotation | {"api_key": "fixture-rejected-key"})
        tick()
        rejected = view()
        require(rejected["pending_provider"]["status"] == "failed", "A bad key was accepted")
        require(rejected["active"] == ready["active"], "A bad key changed the selected model")
        require(rejected["report"] == ready["report"], "A bad key changed the model report")
        post("provider", payload | rotation)
        tick()
        rotated = view()
        require(rotated["choice_id"] != ready["choice_id"], "Rotation did not advance the choice")
        require(rotated["active"] == ready["active"], "Rotation changed the selected model")
        require(rotated["report"] == ready["report"], "Rotation discarded the model report")
        post("provider", payload | rotation, 422)

        post("pin", {"model": model})
        require(view()["pinned"] == model, "Model pin was not published")
        post("best-now", status=422)
        post("unpin")
        require(view()["pinned"] is None, "Model pin remained after unpin")
        post("auto", {"enabled": True})
        require(view()["auto_selection"] is True, "Auto selection is disabled")

        incumbent = view()["active"]
        post("best-now", status=202)
        evaluation_tick = tick()
        evaluated = evaluation_tick["requests"]
        require(
            any(
                row["kind"] == "best_now"
                and row["state"] == "done"
                and row["result"] == "comparison_sources_unavailable"
                for row in evaluated
            ),
            "Best-now did not complete and keep the incumbent without comparison evidence",
        )
        require(
            evaluation_tick["weekly"]["reason"] == "already_recorded_in_window",
            "Weekly selection did not honor the best-now maintenance run",
        )
        store = Store(base / "maintenance.db")
        try:
            runs = MaintenanceRuns(store).history()
        finally:
            store.close()
        require(
            len(runs) == 1
            and runs[0]["payload"]["work_seconds"] == worker.PRIVATE_EVALUATION_SECONDS
            and runs[0]["result"]["mode"] == "best_now"
            and runs[0]["result"]["model"] == model
            and runs[0]["result"]["complete"],
            "Maintenance history lacks one bounded best-now measurement",
        )
        require(api_key not in json.dumps(runs), "Evaluation evidence exposed the credential")
        measured = usage(base, "private-evaluation.db", evaluation, NOW)
        require(
            0 < measured["tokens"] <= evaluation.monthly.tokens
            and 0 <= measured["seconds"] <= evaluation.monthly.seconds
            and measured["running"] == 0,
            "Best-now usage was not settled within its private evaluation budget",
        )
        require(view()["active"] == incumbent, "Best-now changed the incumbent")

        # An explicit operator pin can select another model served by the same endpoint.
        require(len(models) > 1, "A second real model is required to exercise the change report")
        other = next(candidate for candidate in models if candidate != model)
        post("pin", {"model": other})
        tick()
        changed = view()
        require(changed["active"]["model"] == other, "Operator pin did not change the model")
        require(
            changed["report"]["reason"] == "selection_change"
            and changed["report"]["body"]["model"] == other
            and changed["report"]["body"]["tokens"] > 0,
            "Model change did not produce a measured report",
        )
        # Use the original model for advice so evaluation of the alternate
        # remains independent of the alternate's advisory quality.
        post("pin", {"model": model})
        before_eval = usage(base, "private-evaluation.db", evaluation, NOW)
        require(
            usage(base, "private-ledger.db", runtime, NOW)["tokens"] == 0,
            "A model evaluation spent from the advice ledger",
        )

        before = view()
        response = browser.post(
            "/api/advice",
            json={"question": "Summarize the available status evidence and its gaps."},
        )
        answer = unpack(response, 200, "read-only advice")
        recognized = next(
            (code for code, message in _GAPS.items() if answer["text"] == gap(message)),
            "unknown",
        )
        require(
            answer["text"].startswith("Advice (AI-generated"),
            f"Gateway advice was unavailable ({recognized})",
        )
        require(
            all(
                label in answer["text"]
                for label in ("Sources in snapshot", "Time range", "Missing data")
            ),
            "Advice lacked source, time, or missing-data coverage",
        )
        require(
            usage(base, "private-ledger.db", runtime, NOW)["tokens"] > 0, "Advice usage missing"
        )
        require(
            usage(base, "private-evaluation.db", evaluation, NOW) == before_eval,
            "Advice spent from the evaluation ledger",
        )
        require(view() == before, "Advice changed the provider or selection state")
        require(
            api_key not in json.dumps(app.state.audit.read()), "API audit exposed the credential"
        )


@pytest.mark.skipif(
    os.environ.get("STEWARD_TEST_PRIVATE_INFERENCE") != "1",
    reason="requires the authorized private inference lab gateway and credential files",
)
def test_private_inference_runtime(monkeypatch):
    api_key, ca_pem = None, None
    endpoint = os.environ.get("STEWARD_LAB_AI_URL")
    with suppress(KeyError, OSError, UnicodeError):
        api_key = Path(os.environ["STEWARD_LAB_AI_KEY_FILE"]).read_text().strip()
        ca_pem = Path(os.environ["STEWARD_LAB_AI_CA_FILE"]).read_text()
    require(endpoint and ca_pem and api_key, "Lab endpoint, CA and credential files are required")

    failure = None
    try:
        # Onboarding stages the real credential. Remove the private runtime tree on exit.
        with TemporaryDirectory(prefix="a04-") as directory:
            run_lab(Path(directory), monkeypatch, endpoint, ca_pem, api_key)
    except PermissionError:
        failure = "Lab runtime permission denied while creating local state or Unix listeners"
    except Exception:
        failure = "Unexpected error in the private inference lab test"
    # Fail outside the handler so pytest cannot render the original exception context.
    if failure:
        pytest.fail(failure, pytrace=False)
