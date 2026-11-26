"""AI onboarding: provider choice, initial model, pin / automatic selection, test reports.

ADR 0008 sections 1-6 and decisions 8/8b as deterministic state, no provider call of its
own. Provider access is injected (a lister for the scan, a check function for the report),
so every rule is testable offline and no network code lives here.

Flow: `choose_provider` -> `scan` (only that provider's models) -> `pick_initial` (the
operator's choice becomes the active model) -> `ensure_report` (one test report for the
initial check). Later reports exist only when the selection changes: a switch made by the
deterministic selection (`on_selection_result`) or an operator pin to a different model.
Pinning wins over automatic selection; "pick best now" is admitted like planned work
(maintenance window, budget reserved first, its own evaluation ledger).

Safety: the active model lives in the inference service's `SelectionStore` (same switch
transaction as the weekly rule). Credentials are references only. Subscription and sign-in
methods stay unavailable until `ai_auth.AUTH_METHODS` records dated official evidence.
Provider names, auth details and the intended default models are UNVERIFIED (see
`inference_models.PROVIDER_OPTIONS` and gate m6_onboarding.md).
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import sqlite3
import time
import uuid
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .ai_auth import AUTH_METHODS, MethodSpec
from .config import Ai, AiLocal
from .inference import InferenceError, InferenceService, Policy
from .inference_budget import Ledger, Price
from .inference_local import LocalInstallRejected, plan_local_install
from .inference_models import HINTS_STATUS, PROVIDER_OPTIONS, family_of, suggest_default
from .model_selection import (
    Decision,
    Measurement,
    RunResult,
    SelectionGuards,
    SelectionStore,
    WeeklySelection,
    account_usage,
)
from .model_sources import SourceStore
from .model_suite import SUITE_DATA_CLASS, SUITE_REVISION, cases, grade, scope

MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
SECRET_REF = re.compile(r"^(env:[A-Za-z_][A-Za-z0-9_]*|file:[^\x00\n]+)$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
MAX_MODELS = 200
MAX_REPORT_BYTES = 32_768
REQUEST_KINDS = ("scan", "initial_check", "best_now", "source_research")
SCHEMA = """
CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK (id = 1), body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY, created_at REAL NOT NULL, provider TEXT NOT NULL, model TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (reason IN ('initial_check','selection_change')),
    decision_id TEXT NOT NULL DEFAULT '', body TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS reports_decision ON reports(decision_id) WHERE decision_id != '';
CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY, kind TEXT NOT NULL, created_at REAL NOT NULL, state TEXT NOT NULL
    CHECK (state IN ('pending','running','done','failed')), result TEXT NOT NULL DEFAULT '');
"""
IDEM_SCHEMA = """
CREATE TABLE IF NOT EXISTS idem (
    key TEXT PRIMARY KEY, state TEXT NOT NULL, response TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL);
"""


class OnboardingError(Exception):
    def __init__(self, code: str, problems: list[str] | None = None):
        super().__init__(code)
        self.code, self.problems = code, problems or []


@dataclass(frozen=True)
class HostFacts:
    ram_total_mb: int
    disk_free_mb: int
    reserved_memory_mb: int


@dataclass(frozen=True)
class LocalDownload:
    """Operator-declared download of the one local model (ADR 0008: checksum, size, limits)."""

    model: str
    sha256: str
    download_mb: int
    ram_mb: int
    disk_mb: int
    license_ack: bool


def _empty_state() -> dict[str, Any]:
    return {
        "provider": None, "status": "none", "key_ref": None, "local": None, "scanned": None,
        "auto": False, "pinned": None, "report_due": None, "initial_checked": False,
        "download_confirmed": False, "choice_id": None,
    }  # fmt: skip


class Onboarding:
    def __init__(
        self,
        base_dir: Path | str,
        selection: SelectionStore,
        sources: SourceStore,
        *,
        clock: Callable[[], float] = time.time,
        audit: Callable[[dict], None] | None = None,
        auth_methods: Mapping[str, MethodSpec] | None = None,
    ):
        self.base = Path(base_dir)
        self.base.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.selection, self.sources, self.clock, self._audit = selection, sources, clock, audit
        self.auth_methods = auth_methods if auth_methods is not None else AUTH_METHODS
        self._path = str(self.base / "onboarding.db")
        self._idem_path = str(self.base / "idempotency.db")
        for path, schema in ((self._path, SCHEMA), (self._idem_path, IDEM_SCHEMA)):
            db = sqlite3.connect(path, timeout=10)
            try:
                db.executescript(schema)
            finally:
                db.close()

        with self._tx() as db:
            for table in ("requests", "reports"):
                if "choice_id" not in {
                    r["name"] for r in db.execute(f"PRAGMA table_info({table})")
                }:
                    db.execute(f"ALTER TABLE {table} ADD COLUMN choice_id TEXT")

    @contextmanager
    def control(self):
        """Serialize short control changes and publication across processes."""
        fd = os.open(self.base / ".control.lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    @contextmanager
    def _publication(self, guard: Callable[[], str | None] | None):
        with self.control() if guard is not None else contextlib.nullcontext():
            if guard is not None and (reason := guard()):
                raise OnboardingError(reason)
            with self._tx() as db:
                yield db

    # ---- plumbing ---------------------------------------------------------------------

    @contextmanager
    def _tx(self, path: str | None = None):
        db = sqlite3.connect(path or self._path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
            except BaseException:
                db.execute("ROLLBACK")
                raise
            db.execute("COMMIT")
        finally:
            db.close()

    def _load(self, db) -> dict[str, Any]:
        row = db.execute("SELECT body FROM state WHERE id=1").fetchone()
        return {**_empty_state(), **json.loads(row["body"])} if row else _empty_state()

    def _save(self, db, state: dict[str, Any]) -> None:
        db.execute(
            "INSERT INTO state VALUES (1,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body",
            (json.dumps(state, sort_keys=True),),
        )

    def state(self, *, bind_legacy: bool = False) -> dict[str, Any]:
        with self._tx() as db:
            state = self._load(db)
            if bind_legacy:
                self._bind_legacy_choice(db, state)
            return state

    def _emit(self, event: str, **fields: Any) -> None:
        if self._audit is not None:
            with contextlib.suppress(Exception):  # state is the record; the mirror is best effort
                self._audit({"event": f"inference.{event}", **fields})

    def ledger_path(self, name: str) -> Path:
        """Own evaluation ledgers (never the production inference ledger)."""
        if name not in ("weekly", "best_now", "initial_check"):
            raise ValueError("unknown ledger")
        return self.base / f"eval-{name}.db"

    # ---- idempotent operator actions (as config apply) ---------------------------------

    def once(self, key: str, fn: Callable[[], Any]) -> tuple[Any, bool]:
        """Run `fn` once per Idempotency-Key. Returns (response, replayed)."""
        with self._tx(self._idem_path) as db:
            row = db.execute("SELECT state, response FROM idem WHERE key=?", (key,)).fetchone()
            if row is not None and row["state"] == "done":
                return json.loads(row["response"]), True
            if row is not None:
                raise OnboardingError("request_in_progress")
            db.execute("INSERT INTO idem VALUES (?, 'running', '', ?)", (key, self.clock()))
        try:
            response = fn()
        except BaseException:
            with self._tx(self._idem_path) as db:  # a failed action may be retried
                db.execute("DELETE FROM idem WHERE key=?", (key,))
            raise
        with self._tx(self._idem_path) as db:
            db.execute(
                "UPDATE idem SET state='done', response=? WHERE key=?",
                (json.dumps(response, default=str), key),
            )
        return response, False

    # ---- options and provider choice ---------------------------------------------------

    def options(self) -> list[dict[str, Any]]:
        out = []
        for o in PROVIDER_OPTIONS.values():
            reason = ""
            if o.auth in ("signin", "subscription"):
                spec = self.auth_methods.get(o.auth_method)
                if spec is None or not spec.available:
                    reason = spec.unavailable_reason if spec else "method unknown"
            elif not o.adapter:
                reason = "no adapter"
            out.append(
                {
                    "id": o.id, "label": o.label, "auth": o.auth, "data_class": o.data_class,
                    "available": not reason, "reason": reason, "default_hint": o.default_hint,
                    "default_status": HINTS_STATUS,
                    # Runtime activation stays behind ai.provider (UNAVAILABLE_FEATURES).
                    "runtime_enabled": False,
                }
            )  # fmt: skip
        return out

    def choose_provider(
        self,
        option_id: str,
        *,
        key_ref: str | None = None,
        local: LocalDownload | None = None,
        host: HostFacts | None = None,
        replace: bool = False,
    ) -> dict[str, Any]:
        option = PROVIDER_OPTIONS.get(option_id)
        if option is None:
            raise OnboardingError("unknown_provider")
        listed = next(o for o in self.options() if o["id"] == option_id)
        if not listed["available"]:
            raise OnboardingError("method_unavailable", [listed["reason"]])
        if option.auth == "api_key" and not (key_ref and SECRET_REF.fullmatch(key_ref)):
            raise OnboardingError("api_key_reference_required")
        if option.auth != "api_key" and key_ref is not None:
            raise OnboardingError("key_not_used_by_provider")
        plan: dict[str, Any] | None = None
        if option.id == "ollama-local":
            plan = self._plan_local(local, host)
        elif local is not None:
            raise OnboardingError("local_download_only_for_ollama_local")
        with self._tx() as db:
            state = self._load(db)
            if state["provider"] is not None and not replace:
                raise OnboardingError("provider_already_chosen")
            state = _empty_state() | {
                "provider": option.id, "status": "provider_chosen", "key_ref": key_ref,
                "local": plan, "choice_id": uuid.uuid4().hex,
            }  # fmt: skip
            db.execute(
                "UPDATE requests SET state='failed', result=CASE WHEN choice_id IS NULL "
                "THEN 'resubmit_required' ELSE 'choice_changed' END WHERE state='pending'"
            )
            self._save(db, state)
        self._emit("provider_chosen", provider=option.id, data_class=option.data_class)
        return state

    @staticmethod
    def _plan_local(local: LocalDownload | None, host: HostFacts | None) -> dict[str, Any]:
        if local is None or host is None:
            raise OnboardingError("local_download_declaration_required")
        if not MODEL_NAME.fullmatch(local.model) or not SHA256.fullmatch(local.sha256):
            raise OnboardingError("local_download_declaration_invalid")
        try:
            ai = Ai(
                provider="ollama",
                model=local.model,
                local=AiLocal(
                    download_mb=local.download_mb, ram_mb=local.ram_mb, disk_mb=local.disk_mb,
                    license_ack=local.license_ack,
                ),
            )  # fmt: skip
            plan_local_install(
                ai,
                ram_total_mb=host.ram_total_mb,
                disk_free_mb=host.disk_free_mb,
                reserved_memory_mb=host.reserved_memory_mb,
            )
        except LocalInstallRejected as exc:
            raise OnboardingError("resource_refused", exc.problems) from None
        except ValueError:
            raise OnboardingError("local_download_declaration_invalid") from None
        return asdict(local)

    # ---- scan and initial model ---------------------------------------------------------

    def scan(
        self, lister: Any, *, publish_guard: Callable[[], str | None] | None = None
    ) -> dict[str, Any]:
        """List the models of the chosen provider only; any other lister is refused."""
        state = self.state()
        option = PROVIDER_OPTIONS.get(state["provider"] or "")
        if option is None:
            raise OnboardingError("no_provider_chosen")
        if getattr(lister, "name", None) != option.adapter:
            raise OnboardingError("scan_provider_mismatch")
        try:
            names = lister.list_models()
        except InferenceError as exc:
            raise OnboardingError(f"scan_failed_{exc.error_class}") from None
        valid = {n for n in names if isinstance(n, str) and MODEL_NAME.fullmatch(n)}
        hint = option.default_hint.casefold()
        # Keep hint candidates ahead of unrelated IDs at the scan limit so case
        # variants still make the suggestion ambiguous in both API responses.
        ranked = sorted(valid, key=lambda name: (name.casefold() != hint, name))
        models = sorted(ranked[:MAX_MODELS])
        choice_id = state["choice_id"]
        with self._publication(publish_guard) as db:
            state = self._load(db)
            if state["provider"] != option.id or state["choice_id"] != choice_id:
                raise OnboardingError("provider_changed_during_scan")
            state["scanned"] = {"models": models, "at": self.clock()}
            if state["status"] == "provider_chosen":
                state["status"] = "scanned"
            self._save(db, state)
        self._emit("models_scanned", provider=option.id, count=len(models))
        return {"models": models, "suggested": suggest_default(option.id, models)}

    def pick_initial(self, model: str) -> dict[str, Any]:
        state = self.state(bind_legacy=True)
        if state["provider"] is None or (
            state["status"] == "provider_chosen" and state["provider"] != "ollama-local"
        ):
            raise OnboardingError("scan_required")
        if state["status"] in ("ready", "awaiting_download"):
            raise OnboardingError("initial_model_already_chosen")
        local = state["local"]
        if state["provider"] == "ollama-local":
            if local is None or model != local["model"]:
                raise OnboardingError("model_not_the_declared_download")
        elif model not in (state["scanned"] or {}).get("models", []):
            raise OnboardingError("model_not_in_scan")
        if not local:  # activate first: "ready" must never exist without an active model
            self._activate(model, "initial_model")
        with self._tx() as db:
            state = self._load(db)
            state["status"] = "awaiting_download" if local else "ready"
            state["initial_model"] = model
            if not local:
                state["report_due"] = {"reason": "initial_check", "model": model}
            self._save(db, state)
        self._emit("initial_model_chosen", model=model, provider=state["provider"])
        return self.state()

    def confirm_download(self, observed_sha256: str) -> dict[str, Any]:
        """The explicit download step reports the checksum it measured; only a match activates."""
        state = self.state(bind_legacy=True)
        if state["status"] != "awaiting_download" or not state["local"]:
            raise OnboardingError("no_download_pending")
        if observed_sha256 != state["local"]["sha256"]:
            self._emit("download_checksum_mismatch", model=state["local"]["model"])
            raise OnboardingError("checksum_mismatch")
        model = state["local"]["model"]
        self._activate(model, "initial_model")
        with self._tx() as db:
            state = self._load(db)
            state |= {
                "status": "ready",
                "download_confirmed": True,
                "report_due": {"reason": "initial_check", "model": model},
            }
            self._save(db, state)
            request, created = self._queue_request(db, "initial_check")
        if created:
            self._emit("action_requested", kind="initial_check", request=request["id"])
        return self.state()

    def _activate(self, model: str, reason: str) -> str:
        """Make `model` active through the selection store; returns the decision id."""
        state = self.state()
        option = PROVIDER_OPTIONS[state["provider"]]
        current = (self._scoped_active(state) or {}).get("model", "")
        decision = Decision("switch", current, model, (reason,))
        did = self.selection.record(
            decision, now=self.clock(), window="operator", provider=option.adapter,
            data_class=option.data_class, body={
                "source": reason, "operator": True,
                "metadata": {"choice_id": state["choice_id"], "mode": "operator"},
            },
        )  # fmt: skip
        self.selection.activate(did, now=self.clock())
        self.sources.audit_event("operator", "model_activated", model=model, reason=reason,
                                 previous=current)  # fmt: skip
        return did

    # ---- pin, automatic selection --------------------------------------------------------

    def pin(self, model: str) -> dict[str, Any]:
        """Pin one model permanently: automatic switching stops. A different model is a
        selection change and therefore owes a report."""
        state = self.state(bind_legacy=True)
        if state["status"] != "ready":
            raise OnboardingError("onboarding_incomplete")
        known = set((state["scanned"] or {}).get("models", []))
        if state["local"]:
            known = {state["local"]["model"]}
        if model not in known:
            raise OnboardingError("model_not_in_scan")
        current = (self._scoped_active(state) or {}).get("model", "")
        if model != current:
            self._activate(model, "operator_pin")
        with self._tx() as db:
            state = self._load(db)
            state["pinned"] = model
            if model != current:
                state["report_due"] = {"reason": "selection_change", "model": model}
            self._save(db, state)
        self._emit("model_pinned", model=model)
        return self.state()

    def unpin(self) -> dict[str, Any]:
        with self._tx() as db:
            state = self._load(db)
            state["pinned"] = None
            self._save(db, state)
        self._emit("model_unpinned")
        return self.state()

    def set_auto(self, enabled: bool) -> dict[str, Any]:
        with self._tx() as db:
            state = self._load(db)
            if state["status"] != "ready":
                raise OnboardingError("onboarding_incomplete")
            state["auto"] = bool(enabled)
            self._save(db, state)
        self._emit("auto_selection_set", enabled=bool(enabled))
        return self.state()

    def _scoped_active(self, state: dict[str, Any]) -> dict | None:
        option = PROVIDER_OPTIONS.get(state["provider"] or "")
        if option is None or state["status"] != "ready":
            return None
        active = self.selection.active(provider=option.adapter, data_class=option.data_class)
        if active is None or active["choice_id"] != state["choice_id"]:
            return None
        due = state["report_due"]
        if state["choice_id"] is None and due and due["model"] != active["model"]:
            return None
        return active

    # ---- reports -------------------------------------------------------------------------

    def _store_report(
        self,
        db,
        state,
        model: str,
        reason: str,
        body: dict,
        decision_id: str = "",
        *,
        created_at: float | None = None,
    ):
        text = json.dumps(body, sort_keys=True, default=str)
        if len(text.encode()) > MAX_REPORT_BYTES:
            raise OnboardingError("report_too_large")
        rid = uuid.uuid4().hex
        db.execute(
            "INSERT INTO reports (id, created_at, provider, model, reason, decision_id, body, "
            "choice_id) VALUES (?,?,?,?,?,?,?,?)",
            (
                rid,
                self.clock() if created_at is None else created_at,
                state["provider"],
                model,
                reason,
                decision_id,
                text,
                state["choice_id"],
            ),
        )
        return rid

    def ensure_report(
        self, check: Callable[[str], dict], *, publish_guard: Callable[[], str | None] | None = None
    ) -> dict[str, Any] | None:
        """Create the report that is due (initial check or operator selection change).

        `check(model)` runs the toolkit's evaluation suite and returns the report body. When
        nothing is due, no check runs and no report is created."""
        state = self.state()
        due = state["report_due"]
        if not due:
            return None
        if due["reason"] == "initial_check" and state["initial_checked"]:
            return None
        choice_id = state["choice_id"]
        active_id = (self._scoped_active(state) or {}).get("decision_id")
        body = check(due["model"])
        with self._publication(publish_guard) as db:
            state = self._load(db)
            if state["choice_id"] != choice_id:
                raise OnboardingError("choice_changed")
            if state["report_due"] != due or (
                publish_guard is not None
                and (self._scoped_active(state) or {}).get("decision_id") != active_id
            ):
                if publish_guard is not None:
                    raise OnboardingError("report_due_changed")
                return None  # another worker produced it
            rid = self._store_report(db, state, due["model"], due["reason"], body)
            state["report_due"] = None
            if due["reason"] == "initial_check":
                state["initial_checked"] = True
            self._save(db, state)
        self._emit("report_created", report=rid, reason=due["reason"], model=due["model"])
        return self.latest_report()

    def on_selection_result(self, result: RunResult) -> dict[str, Any] | None:
        """A deterministic switch creates its report from the measurements (no extra run);
        a kept model, a skip or a failure creates none."""
        if result.status != "switched" or result.decision is None or not result.decision_id:
            return None
        with self._tx() as db:
            state = self._load(db)
            option = PROVIDER_OPTIONS.get(state["provider"] or "")
            if option is None or state["status"] != "ready":
                return None
            decided = self.selection.activated_decision(
                result.decision_id,
                provider=option.adapter,
                data_class=option.data_class,
                choice_id=state["choice_id"],
            )
            if decided is None or decided["chosen"] != result.decision.chosen:
                return None
            if db.execute("SELECT 1 FROM reports WHERE decision_id=?",
                          (result.decision_id,)).fetchone():  # fmt: skip
                return None
            evidence = decided["body"]
            body = {
                "suite_revision": decided["suite_revision"],
                "incumbent": decided["incumbent"],
                "chosen": decided["chosen"],
                "reasons": evidence.get("reasons", []),
                "measurements": evidence.get("measurements", {}),
                "provenance": evidence.get("provenance", {}),
                "prices": evidence.get("prices", {}),
                "source_verdict": evidence.get("source_verdict"),
            }
            self._store_report(
                db,
                state,
                result.decision.chosen,
                "selection_change",
                body,
                result.decision_id,
                created_at=decided["created_at"],
            )
        self._emit("report_created", reason="selection_change", model=result.decision.chosen)
        return self.latest_report()

    def latest_report(self) -> dict[str, Any] | None:
        with self._tx() as db:
            state = self._load(db)
            if self._scoped_active(state) is None:
                return None
            scope = (state["provider"], state["choice_id"])
            row = db.execute(
                "SELECT * FROM reports WHERE provider=? AND choice_id IS ? "
                "ORDER BY created_at DESC, rowid DESC LIMIT 1",
                scope,
            ).fetchone()
            count = db.execute(
                "SELECT COUNT(*) FROM reports WHERE provider=? AND choice_id IS ?", scope
            ).fetchone()[0]
        if row is None:
            return None
        fields = {k: row[k] for k in row.keys() if k not in ("body", "choice_id")}  # noqa: SIM118
        return {**fields, "body": json.loads(row["body"]), "total_reports": count}

    # ---- selection guards, best-now ------------------------------------------------------

    def guards(self, *, weekly: bool) -> SelectionGuards:
        def skip() -> str | None:
            state = self.state()
            if state["status"] != "ready":
                return "onboarding_incomplete"
            if state["pinned"]:
                return "model_pinned"
            if weekly and not state["auto"]:
                return "auto_selection_disabled"
            return None

        return SelectionGuards(skip=skip, switch=self.sources.switch_guard(self.clock()))

    def best_now(
        self, make_selection: Callable[[SelectionGuards, str, Path], WeeklySelection]
    ) -> RunResult:
        """Operator action 'pick the best model now': admitted through the maintenance
        window like planned work; the evaluation budget is reserved first (the ledger denies
        before any call) and lives in its own ledger. A pin always wins."""
        state = self.state()
        if state["status"] != "ready":
            raise OnboardingError("onboarding_incomplete")
        if state["pinned"]:
            raise OnboardingError("model_pinned")
        selection = make_selection(
            self.guards(weekly=False), "model_best_now", self.ledger_path("best_now")
        )
        result = selection.run()
        with self.control():
            self.on_selection_result(result)
        self._emit("best_now_finished", status=result.status, reason=result.reason[:200])
        return result

    # ---- requests (API records; the inference service executes) -------------------------

    def _queue_request(self, db: sqlite3.Connection, kind: str) -> tuple[dict[str, Any], bool]:
        choice_id = self._load(db)["choice_id"]
        row = db.execute(
            "SELECT * FROM requests WHERE kind=? AND choice_id IS ? "
            "AND (state='pending' OR (kind!='initial_check' AND state='running'))",
            (kind, choice_id),
        ).fetchone()
        if row is not None:
            return self._public_request(row), False
        rid = uuid.uuid4().hex
        db.execute(
            "INSERT INTO requests (id,kind,created_at,state,choice_id) VALUES (?,?,?,'pending',?)",
            (rid, kind, self.clock(), choice_id),
        )
        row = db.execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()
        return self._public_request(row), True

    @staticmethod
    def _public_request(row: sqlite3.Row) -> dict[str, Any]:
        return {k: row[k] for k in ("id", "kind", "created_at", "state", "result")}

    def request_action(self, kind: str) -> dict[str, Any] | None:
        if kind not in REQUEST_KINDS:
            raise OnboardingError("unknown_request")
        with self._tx() as db:
            state = self._load(db)
            if kind == "initial_check" and state["status"] == "awaiting_download":
                return None  # confirm_download queues the check with the report requirement
            self._bind_legacy_choice(db, state)
            request, created = self._queue_request(db, kind)
        if created:
            self._emit("action_requested", kind=kind, request=request["id"])
        return request

    def recover_requests(self) -> None:
        """Recover while the caller holds the tick and control locks."""
        with self._tx() as db:
            db.execute(
                "UPDATE requests SET state='failed', result='interrupted' WHERE state='running'"
            )
            db.execute(
                "UPDATE requests SET state='failed', result='resubmit_required' "
                "WHERE state='pending' AND choice_id IS NULL"
            )
            self._bind_legacy_choice(db, self._load(db))

    def _bind_legacy_choice(self, db: sqlite3.Connection, state: dict[str, Any]) -> None:
        option = PROVIDER_OPTIONS.get(state["provider"] or "")
        if state["choice_id"] is not None or option is None:
            return
        if state["status"] in ("provider_chosen", "scanned", "awaiting_download"):
            # Preserve setup progress. Old requests remain unbound and must be resubmitted.
            state["choice_id"] = uuid.uuid4().hex
            self._save(db, state)
            return
        if state["status"] != "ready":
            return
        active = self.selection.active(provider=option.adapter, data_class=option.data_class)
        due = state["report_due"]
        if active is None or (due and due["model"] != active["model"]):
            return
        # The stable ID makes recovery repeatable after an interrupted migration.
        choice_id = active["decision_id"]
        if active["choice_id"] is None:
            if not self.selection.bind_choice(active["decision_id"], choice_id):
                return
        elif active["choice_id"] != choice_id:
            return
        state["choice_id"] = choice_id
        db.execute(
            "UPDATE reports SET choice_id=? WHERE choice_id IS NULL AND provider=? "
            "AND model=? AND (decision_id=? OR (decision_id='' AND created_at>=?))",
            (
                choice_id,
                state["provider"],
                active["model"],
                active["decision_id"],
                active["updated_at"],
            ),
        )
        self._save(db, state)

    def process_requests(
        self,
        handlers: Mapping[str, Callable[..., Any]],
        *,
        limit: int | None = None,
        bind_choice: bool = False,
    ) -> list[dict]:
        """Claim requests before calling handlers. Bound dispatch uses one snapshot."""
        done = []
        snapshot = None
        if bind_choice or limit is not None:
            with self._tx() as db:
                snapshot = db.execute(
                    "SELECT MIN(rowid) AS ticket FROM requests WHERE state='pending' "
                    "AND (kind != 'initial_check' OR NOT ?) GROUP BY kind ORDER BY ticket LIMIT ?",
                    (
                        self._load(db)["status"] == "awaiting_download",
                        max(0, min(4, limit)) if limit is not None else 4,
                    ),
                ).fetchall()
        tickets = iter(snapshot or [])
        while True:
            claim_lock = self.control() if bind_choice else contextlib.nullcontext()
            with claim_lock, self._tx() as db:
                awaiting_download = self._load(db)["status"] == "awaiting_download"
                ticket = next(tickets, None)
                if snapshot is not None and ticket is None:
                    return done
                row = db.execute(
                    "SELECT * FROM requests WHERE state='pending' "
                    "AND (kind != 'initial_check' OR NOT ?) AND (? IS NULL OR rowid=?) "
                    "ORDER BY created_at, rowid LIMIT 1",
                    (
                        awaiting_download,
                        ticket["ticket"] if ticket else None,
                        ticket["ticket"] if ticket else None,
                    ),
                ).fetchone()
                if row is None:
                    if snapshot is None:
                        return done
                    continue
                error = self._request_choice_error(db, row) if bind_choice else None
                db.execute("UPDATE requests SET state='running' WHERE id=?", (row["id"],))
            handler = handlers.get(row["kind"])
            try:
                if error:
                    raise OnboardingError(error)
                if handler is None:
                    raise OnboardingError("no_handler")
                outcome = handler(dict(row) | {"state": "running"}) if bind_choice else handler()
                state, text = "done", str(getattr(outcome, "status", outcome or "ok"))[:200]
            except OnboardingError as exc:
                state, text = "failed", exc.code
            except Exception as exc:
                state, text = "failed", type(exc).__name__
            with self._tx() as db:
                if bind_choice and (error := self._request_choice_error(db, row)):
                    state, text = "failed", error
                db.execute(
                    "UPDATE requests SET state=?, result=? WHERE id=? AND state='running'",
                    (state, text, row["id"]),
                )
            done.append({"id": row["id"], "kind": row["kind"], "state": state, "result": text})

    def _request_choice_error(self, db: sqlite3.Connection, row: sqlite3.Row) -> str | None:
        if row["choice_id"] is None:
            return "resubmit_required"
        if row["choice_id"] != self._load(db)["choice_id"]:
            return "choice_changed"
        return None

    def requests(self, limit: int = 20) -> list[dict]:
        with self._tx() as db:
            rows = db.execute(
                "SELECT * FROM requests ORDER BY created_at DESC, rowid DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._public_request(r) for r in rows]

    # ---- read model ----------------------------------------------------------------------

    def view(self, fx_state: Callable[[], dict] | None = None) -> dict[str, Any]:
        with self.control():
            state = self.state()
            active = self._scoped_active(state)
            report = self.latest_report()
        option = PROVIDER_OPTIONS.get(state["provider"] or "")
        scanned = state["scanned"]
        return {
            "status": state["status"],
            "provider": None if option is None else {
                "id": option.id, "label": option.label, "data_class": option.data_class,
                "key_ref": state["key_ref"], "runtime_enabled": False,
            },
            "options": self.options(),
            "local_download": state["local"],
            "scanned": scanned,
            "suggested": (
                suggest_default(option.id, scanned["models"]) if option and scanned else None
            ),
            "active": None if active is None else {
                "model": active["model"], "fallback": active["fallback"],
                "since": active["updated_at"],
            },
            "pinned": state["pinned"],
            "auto_selection": state["auto"],
            "report_due": state["report_due"],
            "report": report,
            "requests": self.requests(),
            "sources": {
                "mode": self.sources.mode(),
                "allowed_domains": self.sources.allowed_domains(),
                "list": self.sources.list_sources(),
                "egress": self.sources.egress_hosts(),
                "audit": self.sources.audit_trail(30),
            },
            "exchange_rate": fx_state() if fx_state else None,
            "defaults_status": "UNVERIFIED",
        }  # fmt: skip


def evaluate_model(
    provider: Any,
    ledger: Ledger,
    *,
    price: Price | None,
    share: frozenset[str] = frozenset(),
    clock: Callable[[], float] = time.time,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Run the fixed synthetic suite against one provider and return a report body.

    The ledger is the caller's evaluation ledger; every call reserves budget first."""
    external = provider.data_class == "external"
    if external and SUITE_DATA_CLASS not in share:
        return {"suite_revision": SUITE_REVISION, "model": provider.model, "complete": False,
                "error": "suite_data_class_not_shared"}  # fmt: skip
    service = InferenceService(
        provider, ledger,
        Policy(local_only=False, share=share) if external else Policy(),
        prices={provider.name: price}, max_attempts=1, clock=clock,
    )  # fmt: skip
    start, n, schema_ok, task_ok, tokens = monotonic(), 0, 0, 0, 0
    cost: int | None = 0
    complete, error = True, None
    now = clock()
    for case in cases(now):
        n += 1
        outcome = service.run(case.task, list(case.items), scope(now))
        tokens, cost = account_usage(outcome.usage, price, tokens, cost)
        if outcome.ok and outcome.data is not None:
            schema_ok += 1
            task_ok += grade(case, outcome.data)
        elif outcome.error_class != "invalid_output":
            complete, error = False, outcome.error_class
            break
    m = Measurement(
        provider.model, family_of(provider.name, provider.model), n, schema_ok, task_ok,
        round(monotonic() - start, 3), cost, tokens, complete, error,
    )  # fmt: skip
    return {"suite_revision": SUITE_REVISION, **asdict(m), "passed": m.passed}
