"""Decision 7: exchange rate for budgets, fail closed when stale."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime
from decimal import localcontext
from unittest.mock import Mock
from urllib.parse import urlsplit

import pytest

from steward import inference_worker
from steward.adapters.inference import Endpoint, HttpResponse, PublicHttpsTransport
from steward.core.audit import AuditLog
from steward.core.config import ECB_FX_URL, Ai, AiBudget, AiFx, effective, parse_config
from steward.core.fx_rate import (
    MAX_BYTES,
    WORK_ID,
    FxError,
    FxStore,
    convert_price,
    fetch_in_window,
    fetch_rate,
    make_rate_guard,
    parse_ecb_daily_xml_v1,
    parse_json_rate_v1,
    pinned_https_fetcher,
    rate_state,
)
from steward.core.inference_budget import BudgetDenied, Ledger, Price
from steward.core.maintenance_runs import MaintenanceRuns
from steward.core.store import Store
from test_model_selection import Harness as SelectionHarness


def ts(*a):
    return datetime(*a, tzinfo=UTC).timestamp()


NOW = ts(2026, 11, 22, 2, 5)  # Sunday, inside the Sun 03:00 Berlin window
SPEC = "Sun 03:00 Europe/Berlin"
SRC = "https://rates.example.org/eur-usd"
FETCHED = AiFx(mode="fetched", source_url=SRC, parser="json_rate_v1", max_age_days=3)
ECB = AiFx(mode="fetched", source_url=ECB_FX_URL, parser="ecb_daily_xml_v1", max_age_days=3)
OPERATOR = AiFx(mode="operator", rate_ppm=920_000, as_of="2026-11-20", max_age_days=7)


def doc(rate="0.92", date="2026-11-22"):
    return json.dumps({"rate": rate, "date": date}).encode()


def ecb_doc(rate="1.0963", date="2026-11-20"):
    return f"""<?xml version="1.0"?>
<gesmes:Envelope xmlns:gesmes="http://www.gesmes.org/xml/2002-08-01"
                 xmlns="http://www.ecb.int/vocabulary/2002-08-01/eurofxref">
  <gesmes:subject>Reference rates</gesmes:subject>
  <gesmes:Sender><gesmes:name>European Central Bank</gesmes:name></gesmes:Sender>
  <Cube>
    <Cube time="{date}">
      <Cube currency="JPY" rate="168.98"/>
      <Cube currency="USD" rate="{rate}"/>
      <Cube currency="GBP" rate="0.8328"/>
    </Cube>
  </Cube>
</gesmes:Envelope>""".encode()


@pytest.mark.parametrize(
    "url",
    [
        SRC,
        ECB_FX_URL + "/",
        ECB_FX_URL + "?v=1",
        "https://www.example.org" + urlsplit(ECB_FX_URL).path,
        ECB_FX_URL.replace("https://", "http://", 1),
    ],
)
def test_ecb_config_requires_the_exact_source(url):
    with pytest.raises(ValueError):
        AiFx(mode="fetched", source_url=url, parser="ecb_daily_xml_v1")


def test_ecb_parser_reads_the_official_namespaced_envelope():
    with localcontext(prec=3):
        assert parse_ecb_daily_xml_v1(ecb_doc(), NOW) == (912_160, "2026-11-20")


@pytest.mark.parametrize(
    "body",
    [
        b"<broken",
        ecb_doc().replace(b"http://www.ecb.int/", b"https://example.org/"),
        ecb_doc().replace(b'<Cube currency="USD" rate="1.0963"/>', b""),
        ecb_doc().replace(b'rate="1.0963"', b""),
        ecb_doc().replace(b'rate="1.0963"', b'rate="&#49;.0963"'),
        ecb_doc().replace(b"<gesmes:Sender>", b'<gesmes:Sender extra="1">'),
        ecb_doc().replace(b'rate="1.0963"/>', b'rate="1.0963">extra</Cube>'),
        ecb_doc().replace(b"</gesmes:Sender>", b"</gesmes:Sender>extra"),
        ecb_doc().replace(b'time="2026-11-20"', b""),
        ecb_doc().replace(b'currency="GBP"', b'currency="USD"'),
        ecb_doc().replace(
            b"  </Cube>",
            b'  </Cube><Cube time="2026-11-20"><Cube currency="USD" rate="1.0963"/></Cube>',
            1,
        ),
        ecb_doc(date="2026-02-30"),
        ecb_doc(date="2026-11-23"),
        ecb_doc() + b" " * MAX_BYTES,
    ],
    ids=[
        "malformed",
        "wrong-namespace",
        "missing-usd",
        "missing-rate",
        "character-reference",
        "unexpected-attribute",
        "unexpected-quote-text",
        "unexpected-tail",
        "missing-date",
        "duplicate-usd",
        "duplicate-date",
        "invalid-date",
        "future-date",
        "oversized",
    ],
)
def test_ecb_parser_rejects_invalid_documents(body):
    with pytest.raises(FxError):
        parse_ecb_daily_xml_v1(body, NOW)


@pytest.mark.parametrize("rate", ["0", "-1", "NaN", "Infinity", "1e10000", "1e-10000"])
def test_ecb_parser_rejects_invalid_rates(rate):
    with pytest.raises(FxError):
        parse_ecb_daily_xml_v1(ecb_doc(rate=rate), NOW)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-be", "utf-32"])
@pytest.mark.parametrize("entity", [False, True], ids=["doctype", "entity"])
def test_ecb_parser_rejects_dtd_and_entities_even_in_encoded_documents(encoding, entity):
    declaration = "<!DOCTYPE gesmes:Envelope>"
    body = ecb_doc().decode()
    if entity:
        declaration = '<!DOCTYPE gesmes:Envelope [<!ENTITY usd "1.0963">]>'
        body = body.replace('rate="1.0963"', 'rate="&usd;"')
    body = body.replace("<gesmes:Envelope", declaration + "\n<gesmes:Envelope", 1)
    with pytest.raises(FxError):
        parse_ecb_daily_xml_v1(body.encode(encoding), NOW)


def test_config_validation_and_canonical_revision_unchanged_while_unset(raw_config):
    base = parse_config(raw_config)
    assert "fx" not in effective(base)["ai"]
    for bad in (
        {"mode": "operator"},
        {"mode": "operator", "rate_ppm": 1, "as_of": "2026-13-01"},
        {"mode": "operator", "rate_ppm": 1, "as_of": "2026-11-01", "source_url": SRC},
        {"mode": "fetched", "source_url": "http://x.example.org/r", "parser": "json_rate_v1"},
        {"mode": "fetched", "source_url": "https://127.0.0.1/r", "parser": "json_rate_v1"},
        {"mode": "fetched", "source_url": SRC, "parser": "json_rate_v1", "rate_ppm": 5},
    ):
        with pytest.raises(ValueError):
            AiFx(**bad)
    assert Ai(provider="none").fx is None
    with pytest.raises(ValueError):
        Ai(provider="none", fx=OPERATOR)


def test_operator_rate_is_fresh_then_stale():
    assert rate_state(OPERATOR, None, ts(2026, 11, 22))[1] == "ok"
    assert rate_state(OPERATOR, None, ts(2026, 11, 27))[1] == "ok"
    assert rate_state(OPERATOR, None, ts(2026, 11, 28))[1] == "stale"
    assert rate_state(None, None, NOW)[1] == "not_configured"
    assert rate_state(FETCHED, None, NOW)[1] == "missing"


def test_stale_rate_makes_cost_limited_reservations_deny_but_tokens_still_work(tmp_path):
    budget = AiBudget(monthly={"tokens": 10000, "cost_micro": 10**9}, price={
        "input_per_mtok_micro": 10, "output_per_mtok_micro": 10})  # fmt: skip
    price = Price(10, 10)
    store = FxStore(tmp_path / "fx.db")
    ledger = Ledger(tmp_path / "l.db", budget, rate_guard=make_rate_guard(FETCHED, store))
    with pytest.raises(BudgetDenied) as e:  # no rate yet
        ledger.reserve(projects=(), tokens=100, seconds=5, price=price, now=NOW)
    assert e.value.reason == "fx_rate"
    fetch_rate(FETCHED, store, lambda u, m, t: doc(), NOW)
    ledger.reserve(projects=(), tokens=100, seconds=5, price=price, now=NOW)
    with pytest.raises(BudgetDenied) as e:  # four days later the 3-day limit is exceeded
        ledger.reserve(projects=(), tokens=100, seconds=5, price=price, now=NOW + 4 * 86400)
    assert e.value.reason == "fx_rate"
    # a budget without a cost limit is unaffected
    token_only = Ledger(tmp_path / "t.db", AiBudget(monthly={"tokens": 1000}),
                        rate_guard=make_rate_guard(FETCHED, store))  # fmt: skip
    token_only.reserve(projects=(), tokens=100, seconds=5, price=None, now=NOW + 40 * 86400)


def test_no_fx_configuration_changes_nothing(tmp_path):
    guard = make_rate_guard(None, None)
    assert guard(NOW)
    ledger = Ledger(tmp_path / "l.db", AiBudget(monthly={"tokens": 1000, "cost_micro": 10**6},
                    price={"input_per_mtok_micro": 1, "output_per_mtok_micro": 1}), rate_guard=guard)  # fmt: skip
    ledger.reserve(projects=(), tokens=10, seconds=1, price=Price(1, 1), now=NOW)


def test_fixed_parser_rejects_everything_else():
    assert parse_json_rate_v1(doc("0.9234"), NOW) == (923_400, "2026-11-22")
    assert (
        parse_json_rate_v1(json.dumps({"rate": 1, "date": "2026-11-22"}).encode(), NOW)[0]
        == 1_000_000
    )
    for bad in (
        b"nope", b"[]", b'{"rate": "0.9"}', doc("0"), doc("-1"), doc("nan"), doc("1e30"),
        doc("0.9", "2026-12-30"), doc("0.9", "yesterday"), b"x" * 20000,
        json.dumps({"rate": True, "date": "2026-11-22"}).encode(),
        json.dumps({"rate": 1, "date": "2026-11-22", "extra": 1}).encode(),
    ):  # fmt: skip
        with pytest.raises(FxError):
            parse_json_rate_v1(bad, NOW)


def test_fetch_rejects_stale_source_data_and_implausible_jumps_and_keeps_old_rate(tmp_path):
    store = FxStore(tmp_path / "fx.db")
    fetch_rate(FETCHED, store, lambda u, m, t: doc("0.92"), NOW)
    for body, code in (
        (doc("0.92", "2026-11-10"), "source_data_stale"),
        (doc("2.5"), "implausible_jump"),
    ):
        with pytest.raises(FxError) as e:
            fetch_rate(FETCHED, store, lambda u, m, t, b=body: b, NOW)
        assert e.value.code == code
    assert store.current().rate_ppm == 920_000

    def down(u, m, t):
        raise OSError("network down")

    with pytest.raises(FxError) as e:
        fetch_rate(FETCHED, store, down, NOW)
    assert e.value.code == "fetch_failed"
    with pytest.raises(FxError):
        fetch_rate(OPERATOR, store, lambda u, m, t: doc(), NOW)


def test_fetch_uses_only_the_one_configured_source(tmp_path):
    seen = []
    store = FxStore(tmp_path / "fx.db")
    fetch_rate(FETCHED, store, lambda u, m, t: seen.append(u) or doc(), NOW)
    assert seen == [SRC] and store.current().source == SRC


def test_ecb_fetch_staleness_strict_replay_and_jump_keep_the_last_good_rate(tmp_path):
    store = FxStore(tmp_path / "fx.db")
    audit = Mock()
    current = fetch_rate(ECB, store, Mock(return_value=ecb_doc()), NOW, audit=audit)
    assert (current.rate_ppm, current.as_of, current.source) == (912_160, "2026-11-20", ECB_FX_URL)
    assert rate_state(ECB, store, ts(2026, 11, 23)) == (current, "ok")
    assert rate_state(ECB, store, ts(2026, 11, 24)) == (current, "stale")
    assert not make_rate_guard(ECB, store)(ts(2026, 11, 24))

    for body, code in (
        (ecb_doc(date="2026-11-18"), "source_data_stale"),
        (ecb_doc(date="2026-11-19"), "source_data_replayed"),
        (ecb_doc(), "source_data_replayed"),
        (ecb_doc(rate="1.2"), "source_data_replayed"),
        (ecb_doc(rate="3", date="2026-11-21"), "implausible_jump"),
    ):
        with pytest.raises(FxError) as error:
            fetch_rate(ECB, store, Mock(return_value=body), NOW, audit=audit)
        assert error.value.code == code
        assert store.current() == current
    audit.assert_called_once_with(
        {
            "event": "inference.fx_rate_updated",
            "rate_ppm": 912_160,
            "as_of": "2026-11-20",
            "source": ECB_FX_URL,
        }
    )

    newer = fetch_rate(ECB, store, Mock(return_value=ecb_doc(date="2026-11-21")), NOW)
    assert newer.as_of == "2026-11-21"


@pytest.mark.parametrize("url", [SRC, ECB_FX_URL])
def test_fx_source_switch_keeps_legacy_singleton_scoped_to_its_json_source(tmp_path, url):
    legacy_config = AiFx(mode="fetched", source_url=url, parser="json_rate_v1")
    path = tmp_path / "fx.db"
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE fx_rate (id INTEGER PRIMARY KEY CHECK (id = 1), "
            "rate_ppm INTEGER NOT NULL, as_of TEXT NOT NULL, source TEXT NOT NULL, "
            "retrieved_at REAL NOT NULL)"
        )
        db.execute(
            "INSERT INTO fx_rate VALUES (1, ?, ?, ?, ?)", (3_000_000, "2026-11-22", url, NOW)
        )
    store = FxStore(path)
    legacy, status = rate_state(legacy_config, store, NOW)
    assert status == "ok" and legacy is not None
    assert (legacy.rate_ppm, legacy.source) == (3_000_000, url)
    assert rate_state(ECB, store, NOW) == (None, "missing")
    assert not make_rate_guard(ECB, store)(NOW)

    updated = fetch_rate(ECB, store, Mock(return_value=ecb_doc()), NOW)
    assert rate_state(ECB, store, NOW) == (updated, "ok")
    assert rate_state(legacy_config, store, NOW) == (legacy, "ok")


def test_ecb_pinned_fetcher_uses_only_the_configured_xml_get():
    body = ecb_doc()
    transport = Mock()
    transport.request.return_value = HttpResponse(200, {}, body)
    fetch = pinned_https_fetcher(transport)
    assert fetch(ECB_FX_URL, MAX_BYTES, 2.5) == body
    transport.request.assert_called_once()
    endpoint, method, path, headers, payload = transport.request.call_args.args
    url = urlsplit(ECB_FX_URL)
    assert endpoint == Endpoint("https", url.hostname, 443, "")
    assert (method, path, payload) == ("GET", url.path, None)
    assert headers == {"Accept": "application/xml"}
    assert transport.request.call_args.kwargs["timeout"] == 2.5


def test_pinned_fetcher_preserves_json_accept_for_json_configuration(tmp_path):
    transport = Mock()
    transport.request.return_value = HttpResponse(200, {}, doc())
    config = AiFx(mode="fetched", source_url=ECB_FX_URL, parser="json_rate_v1")
    store = FxStore(tmp_path / "fx.db")
    assert fetch_rate(config, store, pinned_https_fetcher(transport), NOW).rate_ppm == 920_000
    transport.request.assert_called_once()
    assert transport.request.call_args.args[3] == {"Accept": "application/json"}


@pytest.mark.parametrize(
    ("response", "code"),
    [
        (
            HttpResponse(302, {"Location": "https://other.example/private"}, b"private"),
            "http_status",
        ),
        (HttpResponse(200, {}, b"x" * (MAX_BYTES + 1)), "too_large"),
    ],
)
def test_ecb_pinned_fetcher_rejects_redirects_and_large_bodies(response, code):
    transport = Mock()
    transport.request.return_value = response
    with pytest.raises(FxError) as error:
        pinned_https_fetcher(transport)(ECB_FX_URL, MAX_BYTES + 1, 2.5)
    assert error.value.code == str(error.value) == code
    transport.request.assert_called_once()


def test_ecb_fetch_sanitizes_transport_failure(tmp_path):
    transport = Mock()
    transport.request.side_effect = OSError("private transport details")
    store = FxStore(tmp_path / "fx.db")
    audit = Mock()
    with pytest.raises(FxError) as error:
        fetch_rate(ECB, store, pinned_https_fetcher(transport), NOW, audit=audit)
    assert error.value.code == str(error.value) == "fetch_failed"
    assert store.current() is None
    audit.assert_not_called()


@pytest.mark.parametrize("withdraw_at", ["dns", "tls"])
def test_ecb_pinned_transport_rechecks_policy_before_connect_and_get(
    tmp_path, monkeypatch, withdraw_at
):
    allowed = True
    connection = Mock()

    def withdraw():
        nonlocal allowed
        allowed = False

    def resolve(_self, _endpoint, _timeout):
        if withdraw_at == "dns":
            withdraw()
        return connection

    if withdraw_at == "tls":
        connection.connect.side_effect = withdraw
    monkeypatch.setattr(PublicHttpsTransport, "_connection", resolve)
    with closing(Store(tmp_path / "m.db")) as jobs:
        assert fetch_in_window(
            ECB,
            FxStore(tmp_path / "fx.db"),
            MaintenanceRuns(jobs),
            SPEC,
            pinned_https_fetcher(),
            clock=lambda: NOW,
            guard=lambda: None if allowed else "kill_switch",
        ) == ("failed", "kill_switch")
    assert connection.connect.call_count == (1 if withdraw_at == "tls" else 0)
    connection.request.assert_not_called()
    connection.close.assert_called_once()


def test_ecb_pinned_transport_stops_reading_at_the_body_limit(tmp_path, monkeypatch):
    connection = Mock()
    response = connection.getresponse.return_value
    response.status = 200
    response.read.return_value = b"x" * (MAX_BYTES + 1)
    monkeypatch.setattr(PublicHttpsTransport, "_connection", lambda *_args: connection)
    store = FxStore(tmp_path / "fx.db")
    with pytest.raises(FxError, match="^too_large$"):
        fetch_rate(ECB, store, pinned_https_fetcher(), NOW)
    response.read.assert_called_once_with(MAX_BYTES + 1)
    connection.close.assert_called_once()
    assert store.current() is None


def test_ecb_window_fetch_leaves_an_older_unrelated_job_queued(tmp_path):
    jobs = Store(tmp_path / "m.db")
    runs = MaintenanceRuns(jobs)
    queued = runs.request(SPEC, NOW - 1, work="unrelated_work", work_seconds=60).job
    assert queued is not None
    assert queued["state"] == "queued"
    store = FxStore(tmp_path / "fx.db")
    fetcher = Mock(return_value=ecb_doc())

    assert fetch_in_window(ECB, store, runs, SPEC, fetcher, clock=lambda: NOW) == ("updated", "")
    assert jobs.get_job(queued["id"]) == queued
    (fx_job,) = (job for job in runs.history() if job["payload"]["work"] == WORK_ID)
    assert fx_job["state"] == "succeeded"
    fetcher.assert_called_once_with(ECB_FX_URL, MAX_BYTES, 15.0)
    jobs.close()


def test_weekly_selection_leaves_an_older_fx_job_queued(tmp_path):
    selection = SelectionHarness(tmp_path)
    with closing(selection.jobs) as jobs:
        runs = MaintenanceRuns(jobs)
        fx_job = runs.request(SPEC, selection.now - 1, work=WORK_ID, work_seconds=300).job
        assert fx_job is not None
        assert selection.run().status == "switched"
        assert jobs.get_job(fx_job["id"]) == fx_job


@pytest.mark.parametrize(
    ("initial_allowed", "expected"),
    [(False, ("not_admitted", "kill_switch")), (True, ("failed", "kill_switch"))],
)
def test_ecb_window_guard_rejection_or_withdrawal_keeps_rate(tmp_path, initial_allowed, expected):
    jobs = Store(tmp_path / "m.db")
    runs = MaintenanceRuns(jobs)
    store = FxStore(tmp_path / "fx.db")
    old = fetch_rate(ECB, store, Mock(return_value=ecb_doc()), NOW)
    allowed = initial_allowed
    audit = Mock()

    def fetcher(url, max_bytes, timeout):
        nonlocal allowed
        allowed = False
        return ecb_doc(date="2026-11-21")

    fetch = Mock(side_effect=fetcher)
    assert (
        fetch_in_window(
            ECB,
            store,
            runs,
            SPEC,
            fetch,
            clock=lambda: NOW,
            audit=audit,
            guard=lambda: None if allowed else "kill_switch",
        )
        == expected
    )
    assert store.current_source("ecb_daily_xml_v1", ECB_FX_URL) == old
    audit.assert_not_called()
    if initial_allowed:
        fetch.assert_called_once()
        (job,) = runs.history()
        assert (job["state"], job["error"]) == ("failed", "kill_switch")
    else:
        fetch.assert_not_called()
        assert runs.history() == []
    jobs.close()


def test_fetch_runs_inside_the_window_once_and_is_audited(tmp_path):
    jobs = Store(tmp_path / "m.db")
    runs, store, audit, seen = MaintenanceRuns(jobs), FxStore(tmp_path / "fx.db"), [], []
    fetcher = lambda u, m, t: seen.append(u) or doc()  # noqa: E731
    outside = fetch_in_window(
        FETCHED, store, runs, SPEC, fetcher, clock=lambda: ts(2026, 11, 21, 12)
    )
    assert outside[0] == "not_admitted" and seen == []
    assert fetch_in_window(
        FETCHED, store, runs, SPEC, fetcher, clock=lambda: NOW, audit=audit.append
    ) == ("updated", "")
    assert (
        fetch_in_window(FETCHED, store, runs, SPEC, fetcher, clock=lambda: NOW)[0] == "not_admitted"
    )
    assert len(seen) == 1 and audit[0]["event"] == "inference.fx_rate_updated"
    jobs.close()


def test_price_conversion_rounds_up_and_never_to_zero_for_positive_prices():
    from steward.core.fx_rate import FxRate

    assert convert_price(Price(1000, 5000), FxRate(920_000, "2026-11-22", "operator")) == Price(
        920, 4600
    )
    assert convert_price(Price(1, 1), FxRate(1, "2026-11-22", "operator")) == Price(1, 1)


def test_general_worker_refreshes_applied_ecb_rate_once(tmp_path, monkeypatch):
    state = tmp_path / "ai"
    policy = inference_worker.AppliedPolicy(
        "applied", Ai(provider="ollama", model="fixture", fx=ECB, local_only=False), SPEC
    )
    fetch = Mock(return_value=ecb_doc())
    monkeypatch.setattr(inference_worker, "pinned_https_fetcher", lambda: fetch)

    for _ in range(2):
        result = inference_worker.run_once(
            read_policy=lambda: policy,
            state_dir=state,
            kill_switch=lambda: False,
            clock=lambda: NOW,
        )
        assert result["status"] == "ok"

    fetch.assert_called_once()
    assert fetch.call_args.args[0] == ECB_FX_URL
    rate, status = rate_state(ECB, FxStore(state / "fx.db"), NOW)
    assert status == "ok" and rate.rate_ppm == 912_160
    audit = [
        event
        for event in AuditLog(state / "worker-audit.jsonl").read()
        if event["event"] == "inference.fx_rate_updated"
    ]
    (entry,) = audit
    assert (entry["source"], entry["rate_ppm"], entry["as_of"]) == (
        ECB_FX_URL,
        912_160,
        "2026-11-20",
    )


def test_general_worker_refuses_to_publish_after_applied_revision_changes(tmp_path, monkeypatch):
    state = tmp_path / "ai"
    policy = inference_worker.AppliedPolicy(
        "applied", Ai(provider="ollama", model="fixture", fx=ECB, local_only=False), SPEC
    )

    def fetch(*_args):
        nonlocal policy
        policy = replace(policy, revision="superseded")
        return ecb_doc()

    monkeypatch.setattr(inference_worker, "pinned_https_fetcher", lambda: fetch)
    result = inference_worker.run_once(
        read_policy=lambda: policy,
        state_dir=state,
        kill_switch=lambda: False,
        clock=lambda: NOW,
    )

    assert result["status"] == "ok"
    assert rate_state(ECB, FxStore(state / "fx.db"), NOW) == (None, "missing")
    with closing(Store(state / "maintenance.db")) as jobs:
        (job,) = MaintenanceRuns(jobs).history()
        assert (job["state"], job["error"]) == ("failed", "applied_policy_changed")


@pytest.mark.parametrize(
    ("fx", "killed", "candidate", "local_only"),
    [
        (None, False, False, False),
        (FETCHED, False, False, False),
        (OPERATOR, False, False, False),
        (ECB, True, False, False),
        (ECB, False, False, True),
        (None, False, True, True),
    ],
)
def test_worker_does_not_fetch_without_allowed_ecb_policy(
    tmp_path, monkeypatch, fx, killed, candidate, local_only
):
    ai = Ai(
        provider="ollama",
        model="fixture",
        local={"download_mb": 1, "ram_mb": 128, "disk_mb": 1, "license_ack": True},
        fx=fx,
        local_only=local_only,
    )
    policy = inference_worker.AppliedPolicy(
        "applied", ai, SPEC, "a" * 32 if candidate else None, "b" * 64 if candidate else None
    )
    fetch = Mock(return_value=ecb_doc())
    monkeypatch.setattr(inference_worker, "pinned_https_fetcher", lambda: fetch)
    if candidate:
        monkeypatch.setattr(
            inference_worker._Tick,
            "refresh_ecb_rate",
            Mock(side_effect=AssertionError("candidate entered the general FX refresh")),
        )

    result = inference_worker.run_once(
        read_policy=lambda: policy,
        state_dir=tmp_path / "ai",
        kill_switch=lambda: killed,
        clock=lambda: NOW,
        candidate_policy=policy if candidate else None,
    )
    assert result["status"] == "ok"
    fetch.assert_not_called()
