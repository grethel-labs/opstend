"""Exchange rate for inference budgets (operator decision 7, card A01).

Budgets stay in abstract units with dated prices. With `ai.fx`, the operator sets
a dated rate or configures a fixed parser and HTTPS source to read during the
maintenance window. The ledger denies a cost-limited reservation when the
configured rate is missing or stale. Token and duration limits are unaffected.
"""

from __future__ import annotations

import datetime
import json
import re
import sqlite3
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC
from decimal import Decimal, InvalidOperation
from pathlib import Path

from .config import ECB_FX_URL, AiFx
from .inference_budget import Price
from .inference_endpoint import parse, public_https_url
from .maintenance_runs import MaintenanceRuns

WORK_ID = "fx_rate_fetch"
WORK_SECONDS = 300
MAX_BYTES = 16_384
MAX_JUMP = 2  # a fetched rate more than 2x away from the previous one is not accepted
JSON_PARSER = "json_rate_v1"
ECB_PARSER = "ecb_daily_xml_v1"
GESMES = "{http://www.gesmes.org/xml/2002-08-01}"
ECB_CUBE = "{http://www.ecb.int/vocabulary/2002-08-01/eurofxref}Cube"
ECB_DECIMAL = re.compile(r"[0-9]{1,18}(?:\.[0-9]{1,18})?")
SCHEMA = """
CREATE TABLE IF NOT EXISTS fx_rate (
    id INTEGER PRIMARY KEY CHECK (id = 1), rate_ppm INTEGER NOT NULL, as_of TEXT NOT NULL,
    source TEXT NOT NULL, retrieved_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS fx_source_rate (
    parser TEXT NOT NULL, source TEXT NOT NULL, rate_ppm INTEGER NOT NULL,
    as_of TEXT NOT NULL, retrieved_at REAL NOT NULL, PRIMARY KEY (parser, source));
"""

Fetcher = Callable[[str, int, float], bytes]  # (url, max_bytes, timeout_s) -> body


class FxError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class FxRate:
    rate_ppm: int
    as_of: str
    source: str  # "operator" or the source URL

    def age_days(self, now: float) -> int:
        today = datetime.datetime.fromtimestamp(now, UTC).date()
        return (today - datetime.date.fromisoformat(self.as_of)).days


def parse_json_rate_v1(body: bytes, now: float) -> tuple[int, str]:
    """Fixed parser: {"rate": <positive number or decimal string>, "date": "YYYY-MM-DD"}."""
    if len(body) > MAX_BYTES:
        raise FxError("too_large")
    try:
        doc = json.loads(body)
    except (ValueError, RecursionError):
        raise FxError("unparsable") from None
    if not isinstance(doc, dict) or set(doc) != {"rate", "date"}:
        raise FxError("unexpected_shape")
    raw, date = doc["rate"], doc["date"]
    if isinstance(raw, bool) or not isinstance(raw, int | float | str):
        raise FxError("unexpected_shape")
    try:
        rate = Decimal(str(raw))
        day = datetime.date.fromisoformat(date) if isinstance(date, str) else None
    except (InvalidOperation, ValueError):
        raise FxError("unparsable") from None
    if day is None or not rate.is_finite() or rate <= 0:
        raise FxError("unexpected_shape")
    ppm = int(rate * 1_000_000)
    if not 1 <= ppm <= 10**12:
        raise FxError("out_of_range")
    if day > datetime.datetime.fromtimestamp(now, UTC).date() + datetime.timedelta(days=1):
        raise FxError("date_in_future")
    return ppm, day.isoformat()


def parse_ecb_daily_xml_v1(body: bytes, now: float) -> tuple[int, str]:
    """Read the ECB daily USD-per-EUR quote and return EUR per USD, rounded up in ppm."""
    if len(body) > MAX_BYTES:
        raise FxError("too_large")
    try:
        xml = body.decode("utf-8-sig")
        if "\0" in xml or "<!DOCTYPE" in xml or "<!ENTITY" in xml or "&" in xml:
            raise FxError("unparsable")
        # Force the same encoding used to reject DTDs before passing input to Expat.
        root = ET.fromstring(xml, parser=ET.XMLParser(encoding="utf-8"))  # noqa: S314
    except (UnicodeError, ET.ParseError, ValueError):
        raise FxError("unparsable") from None
    subject, sender, container = GESMES + "subject", GESMES + "Sender", ECB_CUBE
    name = GESMES + "name"
    if root.tag != GESMES + "Envelope" or sorted(node.tag for node in root) != sorted(
        (subject, sender, container)
    ):
        raise FxError("unexpected_shape")
    subject_node = root.find(subject)
    sender_node = root.find(sender)
    outer = root.find(container)
    assert subject_node is not None and sender_node is not None and outer is not None
    if (
        any(node.attrib for node in (root, subject_node, sender_node, outer))
        or len(subject_node)
        or subject_node.text != "Reference rates"
        or [node.tag for node in sender_node] != [name]
        or sender_node[0].attrib
        or len(sender_node[0])
        or sender_node[0].text != "European Central Bank"
        or len(outer) != 1
    ):
        raise FxError("unexpected_shape")
    daily = outer[0]
    if daily.tag != ECB_CUBE or set(daily.attrib) != {"time"}:
        raise FxError("unexpected_shape")
    for node in root.iter():
        if (node.tail or "").strip() or (
            node.tag not in (subject, name) and (node.text or "").strip()
        ):
            raise FxError("unexpected_shape")
    date = daily.attrib["time"]
    try:
        day = datetime.date.fromisoformat(date)
    except ValueError:
        raise FxError("unparsable") from None
    if day.isoformat() != date:
        raise FxError("unparsable")
    if day > datetime.datetime.fromtimestamp(now, UTC).date():
        raise FxError("date_in_future")
    quotes = {}
    for row in daily:
        if row.tag != ECB_CUBE or len(row) or set(row.attrib) != {"currency", "rate"}:
            raise FxError("unexpected_shape")
        currency, quote = row.attrib["currency"], row.attrib["rate"]
        if (
            not re.fullmatch(r"[A-Z]{3}", currency)
            or currency in quotes
            or not ECB_DECIMAL.fullmatch(quote)
        ):
            raise FxError("unexpected_shape")
        rate = Decimal(quote)
        if rate.is_zero():
            raise FxError("out_of_range")
        quotes[currency] = rate
    if "USD" not in quotes:
        raise FxError("unexpected_shape")
    # Use the exact decimal ratio so ambient Decimal precision cannot undercharge.
    numerator, denominator = quotes["USD"].as_integer_ratio()
    scaled = 1_000_000 * denominator
    if not numerator <= scaled <= 10**12 * numerator:
        raise FxError("out_of_range")
    return -(-scaled // numerator), date


PARSERS = {JSON_PARSER: parse_json_rate_v1, ECB_PARSER: parse_ecb_daily_xml_v1}


def _check_guard(guard: Callable[[], str | None] | None) -> None:
    if guard is not None and (reason := guard()) is not None:
        raise FxError(reason)


class FxStore:
    """Holds the most recent fetched observation for each parser and URL."""

    def __init__(self, path: Path | str):
        self._path = str(path)
        with self._db() as db:
            db.executescript(SCHEMA)

    def _db(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path, timeout=10)

    def current(self) -> FxRate | None:
        """Return the most recently retrieved observation for unscoped inspection."""
        with self._db() as db:
            row = db.execute(
                "SELECT rate_ppm, as_of, source, retrieved_at FROM fx_source_rate "
                "UNION ALL SELECT rate_ppm, as_of, source, retrieved_at FROM fx_rate "
                "ORDER BY retrieved_at DESC LIMIT 1"
            ).fetchone()
        return FxRate(*row[:3]) if row else None

    @staticmethod
    def _current_source(db: sqlite3.Connection, parser: str, url: str) -> FxRate | None:
        row = db.execute(
            "SELECT rate_ppm, as_of, source FROM fx_source_rate WHERE parser=? AND source=?",
            (parser, url),
        ).fetchone()
        if row is None and parser == JSON_PARSER:
            row = db.execute(
                "SELECT rate_ppm, as_of, source FROM fx_rate WHERE id=1 AND source=?", (url,)
            ).fetchone()
        return FxRate(*row) if row else None

    def current_source(self, parser: str, url: str) -> FxRate | None:
        with self._db() as db:
            return self._current_source(db, parser, url)

    def put(
        self,
        rate: FxRate,
        now: float,
        *,
        parser: str = JSON_PARSER,
        guard: Callable[[], str | None] | None = None,
    ) -> None:
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            old = self._current_source(db, parser, rate.source)
            if old is not None:
                if rate.as_of < old.as_of:
                    raise FxError("source_data_replayed")
                if (
                    rate.rate_ppm * MAX_JUMP < old.rate_ppm
                    or rate.rate_ppm > old.rate_ppm * MAX_JUMP
                ):
                    raise FxError("implausible_jump")
                if rate.as_of == old.as_of:
                    raise FxError("source_data_replayed")
            _check_guard(guard)
            db.execute(
                "INSERT INTO fx_source_rate (parser, source, rate_ppm, as_of, retrieved_at) "
                "VALUES (?,?,?,?,?) ON CONFLICT(parser, source) DO UPDATE SET "
                "rate_ppm=excluded.rate_ppm, as_of=excluded.as_of, "
                "retrieved_at=excluded.retrieved_at",
                (parser, rate.source, rate.rate_ppm, rate.as_of, now),
            )


def current_rate(fx: AiFx | None, store: FxStore | None) -> FxRate | None:
    if fx is None:
        return None
    if fx.mode == "operator":
        assert fx.rate_ppm is not None and fx.as_of is not None
        return FxRate(fx.rate_ppm, fx.as_of, "operator")
    if store is None or fx.parser is None or fx.source_url is None:
        return None
    return store.current_source(fx.parser, fx.source_url)


def rate_state(fx: AiFx | None, store: FxStore | None, now: float) -> tuple[FxRate | None, str]:
    """(rate, status) with status in ok / missing / stale / not_configured."""
    if fx is None:
        return None, "not_configured"
    rate = current_rate(fx, store)
    if rate is None:
        return None, "missing"
    age = rate.age_days(now)
    if age < 0 or age > fx.max_age_days:
        return rate, "stale"
    return rate, "ok"


def make_rate_guard(fx: AiFx | None, store: FxStore | None) -> Callable[[float], bool]:
    """For `Ledger(rate_guard=...)`. Without `ai.fx` no conversion exists, so nothing blocks;
    with it, only a fresh rate allows cost-limited reservations."""

    def guard(now: float) -> bool:
        _, status = rate_state(fx, store, now)
        return status in ("ok", "not_configured")

    return guard


def convert_price(price: Price, rate: FxRate) -> Price:
    def scale(value: int) -> int:
        return -(-value * rate.rate_ppm // 1_000_000)

    return Price(scale(price.input_per_mtok_micro), scale(price.output_per_mtok_micro))


def fetch_rate(
    fx: AiFx,
    store: FxStore,
    fetcher: Fetcher,
    now: float,
    *,
    timeout_s: float = 15.0,
    audit: Callable[[dict], None] | None = None,
    guard: Callable[[], str | None] | None = None,
) -> FxRate:
    """Read the one configured source and store the rate. Raises FxError; the old rate stays."""
    if fx.mode != "fetched" or fx.source_url is None or fx.parser is None:
        raise FxError("not_a_fetched_rate")
    if not public_https_url(fx.source_url):
        raise FxError("source_not_public_https")
    parser = PARSERS.get(fx.parser)
    if parser is None:
        raise FxError("unsupported_parser")
    if fx.parser == ECB_PARSER and fx.source_url != ECB_FX_URL:
        raise FxError("source_mismatch")
    _check_guard(guard)
    max_bytes = MAX_BYTES if fx.parser == ECB_PARSER else MAX_BYTES + 1
    try:
        if isinstance(fetcher, _PinnedHttpsFetcher):
            body = fetcher(fx.source_url, max_bytes, timeout_s, parser=fx.parser, guard=guard)
        else:
            body = fetcher(fx.source_url, max_bytes, timeout_s)
    except FxError:
        raise
    except Exception:
        raise FxError("fetch_failed") from None
    ppm, as_of = parser(body, now)
    new = FxRate(ppm, as_of, fx.source_url)
    if new.age_days(now) > fx.max_age_days:
        raise FxError("source_data_stale")
    store.put(new, now, parser=fx.parser, guard=guard)
    if audit is not None:
        audit({"event": "inference.fx_rate_updated", "rate_ppm": ppm, "as_of": as_of,
               "source": fx.source_url})  # fmt: skip
    return new


def fetch_in_window(
    fx: AiFx,
    store: FxStore,
    runs: MaintenanceRuns,
    window_spec: str,
    fetcher: Fetcher,
    *,
    clock: Callable[[], float] = time.time,
    worker: str = "fx-rate",
    audit: Callable[[dict], None] | None = None,
    guard: Callable[[], str | None] | None = None,
) -> tuple[str, str]:
    """Admit through the maintenance window (once per window), then fetch. -> (status, reason)."""
    runs.recover(clock())
    if guard is not None and (reason := guard()) is not None:
        return "not_admitted", reason
    decision = runs.request(
        window_spec, clock(), work=WORK_ID, work_seconds=WORK_SECONDS, created_by=worker
    )
    if decision.job is None or not decision.created:
        return "not_admitted", decision.admission.reason
    job = runs.begin(worker, clock(), job_id=decision.job["id"])
    if job is None:
        return "not_admitted", "window_expired_before_start"
    job_id = job["id"]
    window_start = datetime.datetime.fromisoformat(job["payload"]["window_start"]).timestamp()
    window_end = datetime.datetime.fromisoformat(job["payload"]["window_end"]).timestamp()

    def check_admission() -> str | None:
        if guard is not None and (reason := guard()) is not None:
            return reason
        current = runs.store.get_job(job_id)
        observed = clock()
        if (
            current is None
            or current["state"] != "running"
            or current["lease_owner"] != worker
            or current["lease_expires"] <= observed
        ):
            return "lease_lost"
        if not window_start <= observed < window_end:
            return "window_expired"
        return None

    try:
        fetch_rate(fx, store, fetcher, clock(), audit=audit, guard=check_admission)
    except FxError as exc:
        runs.complete(job_id, worker, ok=False, now=clock(), error=exc.code)
        return "failed", exc.code
    runs.complete(job_id, worker, ok=True, now=clock(), result={"status": "updated"})
    return "updated", ""


class _PinnedHttpsFetcher:
    def __init__(self, transport):
        self.transport = transport

    def __call__(
        self,
        url: str,
        max_bytes: int,
        timeout_s: float,
        *,
        parser: str | None = None,
        guard: Callable[[], str | None] | None = None,
    ) -> bytes:
        from ..adapters.inference import Endpoint, PublicHttpsTransport, TransportError

        if not public_https_url(url):
            raise FxError("source_not_public_https")
        selected = parser or (ECB_PARSER if url == ECB_FX_URL else JSON_PARSER)
        if selected == ECB_PARSER and url != ECB_FX_URL:
            raise FxError("source_mismatch")
        accept = "application/xml" if selected == ECB_PARSER else "application/json"
        parts = parse(url)
        endpoint = Endpoint.from_url(f"{parts.scheme}://{parts.netloc}")
        limit = min(max_bytes, MAX_BYTES)
        transport = self.transport or PublicHttpsTransport(
            max_response_bytes=limit, check_admission=lambda: _check_guard(guard)
        )
        try:
            response = transport.request(
                endpoint, "GET", parts.path or "/", {"Accept": accept}, None, timeout=timeout_s
            )
        except TransportError as exc:
            if exc.kind == "too_large":
                raise FxError("too_large") from None
            raise
        if response.status != 200:
            raise FxError("http_status")
        if len(response.body) > limit:
            raise FxError("too_large")
        return response.body


def pinned_https_fetcher(transport=None) -> Fetcher:
    """GET over the public-address-pinned HTTPS transport with no redirects."""
    return _PinnedHttpsFetcher(transport)
