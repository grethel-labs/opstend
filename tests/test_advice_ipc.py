"""Local advice transport checks with kernel credentials and a private A01 ledger."""

from __future__ import annotations

import json
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, suppress
from dataclasses import replace
from threading import Thread

import pytest

from inference_fakes import NOW, FakeProvider, err, item, make_ledger
from steward import inference_worker
from steward.core import advice_ipc
from steward.core.advice import ADVICE_TASK, WINDOW_S
from steward.core.advice_ipc import AdvicePeer
from steward.core.inference import Policy
from steward.core.inference_snapshot import Scope

UID = os.geteuid()
WRONG_UID = UID ^ 1
SCOPE = Scope(frozenset({"notes"}), False, NOW - WINDOW_S, NOW)
ITEMS = (item(), item("question sentinel", at=NOW, source="operator", kind="question"))
DATA = {
    "answer": "notes is running.",
    "sources": ["controller"],
    "missing_data": [],
    "recommendations": [],
}
COVERAGE = {
    "window": {"since": NOW - WINDOW_S, "until": NOW},
    "sources": ["controller", "operator"],
    "missing_sources": [],
    "withheld_classes": [],
    "oldest": NOW - 60,
    "newest": NOW,
    "truncated": False,
    "omitted_size": 0,
}


@contextmanager
def serving_advice(tmp_path, provider, *, bot_uid=UID, audit=None, monthly=None, policy=None):
    path = str(tmp_path / "advice.sock")
    ledger = make_ledger(tmp_path, monthly=monthly or {})
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(path)
            listener.listen(2)
            with inference_worker.make_advice_server(
                listener,
                bot_uid=bot_uid,
                provider=provider,
                ledger=ledger,
                policy=policy if policy is not None else Policy(),
                audit=audit,
                clock=lambda: NOW,
            ) as server:
                thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
                thread.start()
                try:
                    yield AdvicePeer(path, UID), ledger
                finally:
                    server.shutdown()
                    thread.join(timeout=3)
                    assert not thread.is_alive()
    finally:
        ledger.close()


def ask(peer, task=ADVICE_TASK, *, expected_sources=("controller", "collector")):
    return peer(
        task,
        list(ITEMS),
        SCOPE,
        expected_sources=expected_sources,
        all_projects=("notes", "catalog-secret"),
    )


def receive(conn):
    with conn.makefile("rb") as reader:
        return reader.read()


def encode(doc):
    return json.dumps(doc).encode() + b"\n"


def request(*, delay=3):
    return {
        "v": 1,
        "expires_at": time.monotonic() + delay,
        "expected_sources": ["controller", "collector"],
        "scope": {"projects": ["notes"], "host": False, "since": SCOPE.since, "until": SCOPE.until},
        "items": [vars(value).copy() for value in ITEMS],
    }


def raw_exchange(path, payload):
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(3)
        conn.connect(path)
        # An oversized input may have caused the receiver to close mid-write.
        with suppress(BrokenPipeError, ConnectionResetError):
            conn.sendall(payload)
            conn.shutdown(socket.SHUT_WR)
        try:
            return receive(conn)
        except ConnectionResetError:
            return b""


def test_real_socket_round_trip_and_budget_exhaustion(tmp_path):
    provider = FakeProvider(script=[json.dumps(DATA)])
    monthly_tokens = 3000
    with serving_advice(tmp_path, provider, monthly={"tokens": monthly_tokens}) as (peer, ledger):
        outcome = ask(peer)
        assert outcome.ok, outcome
        assert outcome.data == DATA
        assert outcome.coverage == COVERAGE | {"missing_sources": ["collector"]}
        assert ledger.usage(now=NOW)["tokens"] == 120
        # Spend the remaining capacity through the same A01 ledger.
        remaining = monthly_tokens - 120
        reservation = ledger.reserve(
            projects=("notes",), tokens=remaining, seconds=1, price=None, now=NOW
        )
        ledger.settle(reservation, outcome="ok", input_tokens=remaining, output_tokens=0, now=NOW)
        denied = ask(peer)
        assert not denied.ok and denied.error_class == "budget_denied"
        assert ledger.usage(now=NOW)["tokens"] == monthly_tokens
        assert ledger.usage(now=NOW)["running"] == 0
    assert len(provider.calls) == 1


def test_worker_rejects_wrong_client_uid_before_reading_or_reserving(tmp_path, monkeypatch):
    provider = FakeProvider()
    with serving_advice(tmp_path, provider, bot_uid=WRONG_UID) as (_, ledger):
        calls = []

        def unexpected(*args, **kwargs):
            calls.append("read or reserve")
            raise ValueError("wrong client UID reached frame reading or the ledger")

        monkeypatch.setattr(ledger, "reserve", unexpected)
        monkeypatch.setattr(advice_ipc, "_read_frame", unexpected)
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(3)
            conn.connect(str(tmp_path / "advice.sock"))
            # Do not send a request or half-close. Rejection must precede the frame read.
            assert conn.recv(1) == b""
        assert calls == provider.calls == []
        assert ledger.usage(now=NOW)["tokens"] == 0


@contextmanager
def scripted_listener(path, script):
    with socket.socket(socket.AF_UNIX) as listener, ThreadPoolExecutor() as executor:
        listener.bind(path)
        listener.listen(2)
        listener.settimeout(3)

        def serve():
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(3)
                return script(conn)

        future = executor.submit(serve)
        yield listener, future


def test_wrong_server_pin_sends_zero_bytes_even_after_socket_appears_or_is_replaced(tmp_path):
    path = tmp_path / "advice.sock"
    peer = AdvicePeer(str(path), WRONG_UID)
    assert ask(peer).error_class == "unavailable"
    for _ in range(2):
        with scripted_listener(str(path), receive) as (_, served):
            assert ask(peer).error_class == "unavailable"
            assert served.result(timeout=3) == b""
        path.unlink()


def test_client_only_sends_fixed_task_payload_and_omits_project_catalog(tmp_path):
    path = str(tmp_path / "advice.sock")

    def reply_to(conn):
        received = receive(conn)
        conn.sendall(encode({"v": 1, "ok": True, "data": DATA, "coverage": COVERAGE}))
        return received

    with scripted_listener(path, reply_to) as (listener, served):
        peer = AdvicePeer(path, UID)
        bogus_task = replace(ADVICE_TASK)
        assert not ask(peer, bogus_task).ok
        assert ask(peer, expected_sources=("controller",)).ok
        raw = served.result(timeout=3)
        assert raw.endswith(b"\n") and raw.count(b"\n") == 1
        assert b"catalog-secret" not in raw
        doc = json.loads(raw)
        expected = request()
        expected["expected_sources"] = ["controller"]
        assert time.monotonic() < doc["expires_at"] <= time.monotonic() + 10
        assert doc == expected | {"expires_at": doc["expires_at"]}
        listener.setblocking(False)
        with pytest.raises(BlockingIOError):
            listener.accept()


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(lambda d: b"\xff\n", id="utf8"),
        pytest.param(lambda d: b"{\n", id="json"),
        pytest.param(lambda d: b"[]\n", id="shape"),
        pytest.param(lambda d: b'{"v":1,' + encode(d)[1:], id="duplicate"),
        pytest.param(lambda d: encode(d | {"expires_at": float("nan")}), id="non-finite"),
        pytest.param(lambda d: encode(d | {"v": True}), id="boolean-version"),
        pytest.param(lambda d: encode(d | {"task": "advice.answer"}), id="task"),
        pytest.param(lambda d: encode(d | {"tool": "events_query"}), id="tool"),
        pytest.param(lambda d: encode(d | {"schema": {}}), id="schema"),
        pytest.param(lambda d: encode(d | {"credential": "synthetic"}), id="credential"),
        pytest.param(lambda d: encode(d | {"scope": d["scope"] | {"uid": UID}}), id="claimed-uid"),
        pytest.param(
            lambda d: encode(d | {"scope": d["scope"] | {"projects": ["notes", "notes"]}}),
            id="duplicate-project",
        ),
        pytest.param(
            lambda d: encode(d | {"scope": d["scope"] | {"since": NOW - 60}}),
            id="wrong-window",
        ),
        pytest.param(
            lambda d: encode(d | {"items": [d["items"][0] | {"project": "other"}, d["items"][1]]}),
            id="wrong-project",
        ),
        pytest.param(
            lambda d: encode(
                d | {"items": [d["items"][0] | {"source": "operator"}, d["items"][1]]}
            ),
            id="wrong-source",
        ),
        pytest.param(
            lambda d: encode(d | {"items": [d["items"][0] | {"project": None}, d["items"][1]]}),
            id="host-item-in-project-scope",
        ),
        pytest.param(
            lambda d: encode(d | {"items": [d["items"][0], d["items"][1] | {"text": "x" * 501}]}),
            id="question-too-long",
        ),
        pytest.param(lambda d: encode(d)[:-1], id="incomplete"),
        pytest.param(lambda d: encode(d) * 2, id="extra-frame"),
        pytest.param(lambda d: b" " * advice_ipc.MAX_REQUEST_BYTES + encode(d), id="oversize"),
    ],
)
def test_worker_rejects_malformed_frames_before_provider_or_charge(tmp_path, payload, monkeypatch):
    provider = FakeProvider()
    with serving_advice(tmp_path, provider) as (_, ledger):

        def reserve(*args, **kwargs):
            pytest.fail("invalid request reached the ledger")

        monkeypatch.setattr(ledger, "reserve", reserve)
        frame = payload(request())
        result = raw_exchange(str(tmp_path / "advice.sock"), frame)
        # A size rejection may reset the stream with unread bytes still queued.
        if result or len(frame) <= advice_ipc.MAX_REQUEST_BYTES:
            assert json.loads(result) == {"v": 1, "ok": False, "error_class": "bad_request"}
        assert provider.calls == []
        assert ledger.usage(now=NOW)["tokens"] == 0


def test_expired_request_does_not_dispatch(tmp_path):
    provider = FakeProvider()
    with serving_advice(tmp_path, provider) as (_, ledger):
        result = raw_exchange(str(tmp_path / "advice.sock"), encode(request(delay=-1)))
        assert result == b""
        assert provider.calls == []
        assert ledger.usage(now=NOW)["tokens"] == 0


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(b"", id="peer-close"),
        pytest.param(b"\xff\n", id="utf8"),
        pytest.param(b"{\n", id="json"),
        pytest.param(b"[]\n", id="shape"),
        pytest.param(b'{"v":1,"v":1,"ok":false,"error_class":"auth"}\n', id="duplicate"),
        pytest.param(b'{"v":1,"ok":false,"error_class":"credential detail"}\n', id="unknown-gap"),
        pytest.param(b'{"v":1,"ok":false,"error_class":"auth","detail":"private"}\n', id="detail"),
        pytest.param(encode({"v": 1, "ok": False, "error_class": "auth"})[:-1], id="incomplete"),
        pytest.param(encode({"v": 1, "ok": False, "error_class": "auth"}) * 2, id="extra-frame"),
        pytest.param(
            b" " * advice_ipc.MAX_REPLY_BYTES
            + encode({"v": 1, "ok": False, "error_class": "auth"}),
            id="oversize",
        ),
        pytest.param(
            encode({"v": 1, "ok": True, "data": DATA | {"approve": True}, "coverage": COVERAGE}),
            id="unknown-answer-field",
        ),
        pytest.param(
            encode(
                {"v": 1, "ok": True, "data": DATA, "coverage": COVERAGE | {"newest": float("inf")}}
            ),
            id="non-finite",
        ),
        pytest.param(
            encode(
                {"v": 1, "ok": True, "data": DATA, "coverage": COVERAGE | {"sources": ["fake"]}}
            ),
            id="fabricated-coverage",
        ),
    ],
)
def test_client_reports_bad_or_dropped_reply_without_retry(tmp_path, payload):
    path = str(tmp_path / "advice.sock")

    def reply_to(conn):
        received = receive(conn)
        with suppress(BrokenPipeError, ConnectionResetError):
            conn.sendall(payload)
        return received

    with scripted_listener(path, reply_to) as (listener, served):
        outcome = ask(AdvicePeer(path, UID))
        assert not outcome.ok and outcome.error_class == "unavailable"
        assert b"question sentinel" in served.result(timeout=3)
        listener.setblocking(False)
        with pytest.raises(BlockingIOError):
            listener.accept()


def test_client_deadline_covers_reply_wait(tmp_path, monkeypatch):
    from threading import Event

    path = str(tmp_path / "advice.sock")
    release = Event()
    monkeypatch.setattr(advice_ipc, "CLIENT_TIMEOUT_S", 0.2)

    def wait_for_release(conn):
        received = receive(conn)
        assert release.wait(3)
        return received

    with scripted_listener(path, wait_for_release) as (_, served):
        try:
            outcome = ask(AdvicePeer(path, UID))
            assert not outcome.ok and outcome.error_class == "timeout"
        finally:
            release.set()
        assert b"question sentinel" in served.result(timeout=3)


@pytest.mark.parametrize(
    ("step", "error_class", "tokens"),
    [
        ("malformed", "invalid_output", 120),
        (err("timeout", retryable=True, spend="unknown"), "timeout", None),
    ],
)
def test_worker_forwards_remaining_timeout_and_settles_single_attempt(
    tmp_path, step, error_class, tokens
):
    timeouts = []

    class TimedProvider(FakeProvider):
        def complete(self, *args, timeout_s, **kwargs):
            timeouts.append(timeout_s)
            return super().complete(*args, timeout_s=timeout_s, **kwargs)

    provider = TimedProvider(script=[step, json.dumps(DATA)])
    with serving_advice(tmp_path, provider) as (_, ledger):
        result = raw_exchange(str(tmp_path / "advice.sock"), encode(request(delay=2)))
        assert json.loads(result) == {"v": 1, "ok": False, "error_class": error_class}
        assert len(timeouts) == len(provider.calls) == 1
        assert 0 < timeouts[0] <= 2
        usage = ledger.usage(now=NOW)
        assert usage["running"] == 0
        if tokens is None:
            assert usage["tokens"] > ADVICE_TASK.max_output_tokens
        else:
            assert usage["tokens"] == tokens


def test_managed_prelude_authenticates_the_kernel_sender():
    worker, caller = socket.socketpair()
    with worker, caller:
        caller.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        deadline = time.monotonic() + 2
        advice_ipc._send_prelude(worker, deadline)
        advice_ipc._read_prelude(caller, UID, deadline)
        assert caller.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 0


@pytest.mark.parametrize("case", ["wrong_uid", "trailing", "truncated", "extra_ancillary"])
def test_managed_prelude_rejects_untrusted_frames(case):
    from array import array

    worker, caller = socket.socketpair()
    with worker, caller:
        caller.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        uid = WRONG_UID if case == "wrong_uid" else UID
        deadline = time.monotonic() + 2
        if case == "trailing":
            worker.sendall(advice_ipc._PRELUDE + b"x")
        elif case == "truncated":
            worker.shutdown(socket.SHUT_WR)
        elif case == "extra_ancillary":
            worker.sendmsg(
                [advice_ipc._PRELUDE],
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", [worker.fileno()]))],
            )
        else:
            advice_ipc._send_prelude(worker, deadline)
        with pytest.raises(PermissionError):
            advice_ipc._read_prelude(caller, uid, deadline)


def test_managed_worker_rejects_wrong_caller_before_sending_prelude(tmp_path):
    def unexpected(*args):
        pytest.fail("wrong caller reached advice admission")

    path = str(tmp_path / "managed.sock")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(path)
        listener.listen(2)
        with (
            advice_ipc.ManagedAdviceServer(listener, WRONG_UID, unexpected) as server,
            socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as caller,
        ):
            caller.settimeout(2)
            caller.connect(path)
            server.handle_request()
            assert caller.recv(1) == b""


@pytest.mark.parametrize(
    ("scenario", "expected_error", "calls", "tokens"),
    [
        ("valid", None, 1, 120),
        ("scan_only", "policy_denied", 0, 0),
        ("pending_withdrawal", "policy_denied", 0, 0),
        ("generation_changed", "policy_denied", 1, 120),
        ("tiny_budget", "budget_denied", 0, 0),
        ("context_reservation", "budget_denied", 0, 0),
        ("missing_model", "model_unavailable", 1, 120),
        ("wrong_model", "model_unavailable", 1, 120),
    ],
)
def test_managed_advice_authority_transport_and_ledger(
    tmp_path, monkeypatch, scenario, expected_error, calls, tokens
):
    from functools import partial

    from steward.adapters.inference import OLLAMA_URL, Endpoint, HttpResponse, OllamaProvider
    from steward.core.config import Ai
    from steward.core.inference_budget import Ledger
    from steward.core.inference_deployment import CandidatePolicy

    monthly_tokens = {"tiny_budget": 1, "context_reservation": 8_192}.get(scenario, 20_000)
    ai = Ai(
        provider="ollama",
        model="fixture:tiny",
        local={"download_mb": 1, "ram_mb": 128, "disk_mb": 2, "license_ack": True},
        budget={"monthly": {"tokens": monthly_tokens, "seconds": 60}},
    )
    fields = {
        "version": 1,
        "revision": "a" * 64,
        "release": "0.1.0",
        "wheel_sha256": "b" * 64,
        "manifest_sha256": "c" * 64,
        "generation": "d" * 32,
        "weekly_window": None,
        "ai": ai,
    }
    if scenario != "scan_only":
        fields["advice"] = True
    current = CandidatePolicy.model_validate(fields)
    monkeypatch.setattr("steward.core.inference_deployment.read_candidate_policy", lambda: current)
    monkeypatch.setattr(inference_worker, "read_kill_switch", lambda: False)

    class RecordedOllama:
        requests = []

        def request(self, endpoint, method, path, headers, body, *, timeout):
            nonlocal current
            assert endpoint == Endpoint.from_url(OLLAMA_URL)
            assert (method, path) == ("POST", "/api/chat")
            assert "Authorization" not in headers
            assert 0 < timeout <= advice_ipc.WORKER_TIMEOUT_S
            payload = json.loads(body)
            assert payload["model"] == ai.model and payload["stream"] is False
            assert "tools" not in payload
            self.requests.append(payload)
            if scenario == "generation_changed":
                current = current.model_copy(update={"generation": "e" * 32})
            response = {
                "message": {"content": json.dumps(DATA)},
                "done": True,
                "prompt_eval_count": 100,
                "eval_count": 20,
            }
            if scenario != "missing_model":
                response["model"] = "unexpected:other" if scenario == "wrong_model" else ai.model
            return HttpResponse(200, {}, json.dumps(response).encode())

    class WithdrawingAudit(inference_worker.AuditLog):
        def append(self, event, **fields):
            nonlocal current
            record = super().append(event, **fields)
            if event == "inference.start" and scenario == "pending_withdrawal":
                current = None
            return record

    transport = RecordedOllama()
    monkeypatch.setattr(
        inference_worker, "OllamaProvider", partial(OllamaProvider, transport=transport)
    )
    monkeypatch.setattr(inference_worker, "AuditLog", WithdrawingAudit)
    now = time.time()
    items = [replace(entry, observed_at=now + (entry.observed_at - NOW)) for entry in ITEMS]
    scope = Scope(SCOPE.projects, SCOPE.host, now - WINDOW_S, now)
    outcome = inference_worker._run_managed_advice(
        tmp_path, items, scope, ("controller",), time.monotonic() + 2
    )
    assert (outcome.error_class, outcome.ok) == (expected_error, expected_error is None)
    assert outcome.data == (DATA if expected_error is None else None)
    assert len(transport.requests) == calls
    db = tmp_path / "ledger.db"
    if scenario == "scan_only":
        assert not db.exists()
    else:
        ledger = Ledger(db, ai.budget)
        try:
            assert ledger.usage()["tokens"] == tokens
            assert ledger.usage()["running"] == 0
        finally:
            ledger.close()


def test_managed_transport_keeps_deadline_during_buffered_http_read(monkeypatch):
    from http.client import HTTPResponse

    from steward.adapters.inference import _DeadlineSocket

    now = 1.0
    monkeypatch.setattr("steward.adapters.inference.time.monotonic", lambda: now)
    reader, writer = socket.socketpair()
    with (
        reader,
        writer,
        _DeadlineSocket(2.0, fileno=reader.detach()) as client,
        HTTPResponse(client) as response,
    ):
        writer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\na")
        response.begin()
        assert response.read(1) == b"a"
        writer.sendall(b"bc")
        now = 2.0
        with pytest.raises(TimeoutError):
            response.read()


def test_managed_transport_charges_uncertain_writes(monkeypatch):
    from steward.adapters.inference import OllamaProvider, _ManagedOllamaTransport
    from steward.core.inference import InferenceError

    class Connection:
        def connect(self):
            pass

        def request(self, *args):
            raise BrokenPipeError

        def close(self):
            pass

    monkeypatch.setattr(_ManagedOllamaTransport, "_connection", lambda *args: Connection())
    provider = OllamaProvider("fixture:tiny", require_exact_model=True)
    with pytest.raises(InferenceError) as failure:
        provider.complete(
            "system", "user", schema=ADVICE_TASK.schema, max_output_tokens=5, timeout_s=1
        )
    assert (failure.value.error_class, failure.value.spend) == ("unavailable", "unknown")


def test_managed_ready_requires_this_invocation_and_safe_file(tmp_path, monkeypatch):
    ready = tmp_path / "listener-ready"
    monkeypatch.setenv("INVOCATION_ID", "a" * 32)
    inference_worker._publish_advice_ready(tmp_path)
    assert ready.stat().st_mode & 0o777 == 0o600
    inference_worker._wait_for_advice_ready(tmp_path, timeout=0.01)
    monkeypatch.setenv("INVOCATION_ID", "b" * 32)
    with pytest.raises(TimeoutError):
        inference_worker._wait_for_advice_ready(tmp_path, timeout=0.01)
    ready.chmod(0o644)
    with pytest.raises(PermissionError):
        inference_worker._wait_for_advice_ready(tmp_path, timeout=0.01)
