# Implementation work queue

This is the scope reference for the [roadmap](roadmap.md). Task cards define
what each feature must do and how its completion is checked. **Order, budgets
and stopping rules are in [goal.md](goal.md)**; where this file and `goal.md`
disagree about sequencing or effort, `goal.md` wins. [STATUS.md](STATUS.md)
holds the current card states and prior acceptance summaries. Check the current
source before starting a card that may already be done.

Follow [AGENTS.md](../AGENTS.md) for the lead/worker workflow. Each card's
*Check/done* line is the acceptance bar. Do not add steps to a card; record
extra findings in [backlog.md](backlog.md).

## Read and work in this order

1. Read `goal.md`, the card table in `STATUS.md`, and `CONTRIBUTING.md`. Read
   applicable `AGENTS.md` files if present.
2. Take the first open milestone in `goal.md` and the first unfinished step of
   its card. B08 is a time-gated lane: check its dates at the start of each
   session, and do not wait for it before starting L03. L04 onward needs B08.
3. Open only the card's detail file, its cited ADR sections, entry points and
   tests. Use `rg` to find definitions; do not load the whole repository or the
   original `PROMPT.md`.
4. State the task ID, expected behavior and files to change. Implement the
   selected step and run focused local checks. Coordinate an authorized VM
   batch per milestone for gates that need real host effects.
5. Update the `STATUS.md` card row and add at most 15 lines of evidence.
   Commit each verified step. A design task ends with a documented contract and
   carries no runtime-test claim.
6. If a required VM, provider, waiting period or verification is unavailable,
   record the specific blocker and date, finish any work still possible, and
   continue with the next milestone.

Authority: [ADR 0001](adr/0001-architecture.md) defines trust boundaries;
[ADR 0002](adr/0002-repositories-ai-and-application-lifecycle.md) defines the
accepted target behavior. This queue specifies implementation order. If a task
needs a product choice those documents do not settle, first record the question,
chosen narrow behavior and compatibility impact in a focused ADR change. Do not
silently turn a planning assumption into an enabled capability.

## Existing foundations to reuse

| Area | Read first | Preserve |
|---|---|---|
| Configuration | `src/steward/core/config.py`, `core/render.py`, `core/schema.py` | One typed schema; canonical revisions; generated artifacts |
| Jobs | `src/steward/core/store.py`, `backupworker.py`, `scannerd.py` | Target locks, durable leases, retry checkpoints, stale-worker fencing |
| Privileged actions | `src/steward/executor/server.py`, `executor/host.py`, [extending](extending.md) | Peer UID, registered action/role, narrow input, root policy, audit |
| Backups | [foundation](backup-foundation.md), `adapters/backups.py`, `core/backups.py`, `core/filebackups.py`, `core/backupexport.py` | Capture/pause recovery/export and upload/check/restore already exist |
| Vulnerabilities | `core/inventory.py`, `core/vulnerabilities.py`, `core/scan_observations.py`, `core/intelligence.py`, `scannerd.py` | Exact revision/runtime binding; unknown/stale/failed remain distinct |
| Messaging | `collector.py`, `notifier.py`, `bot.py`, `adapters/queries.py` | Separate identities; scoped read-only queries; acknowledged delivery |

Source paths without a leading directory in this table are relative to
`src/steward/`. A file labeled **new** in a task card is a proposed artifact,
not an existing API. Look for an equivalent implementation before creating it.

## Ordered queue and dependencies

The [post-RC1 queue](post-rc1.md#ziel-und-reihenfolge) starts at M9 with native
Proxmox support and extends through fleet management and RC2.

Milestones M1–M8 in [goal.md](goal.md) fix the order. L02 is accepted for
`isolation: separate`; Shared-group mutation is deferred (X1), so L03 starts now.
Dependencies below remain binding for the cards that name them.

| Order | Tasks | Prerequisites | Detail |
|---|---|---|---|
| 1. Backups | B01–B08: integrate scheduled off-site backups | Existing capture/export/upload foundation | [Backups](plans/backups.md) |
| Independent acceptance | V01: CLI recovery; V02: messaging; V03: host scanner | Implemented feature and authorized fixture for the selected gate | [Acceptance](plans/acceptance.md) |
| Stage 3, data model | L01–L03: service graph, grouped operations, maintenance | B08 before grouped backup integration; see individual cards | [Lifecycle](plans/lifecycle.md) |
| Stage 3, updates | L04–L06: verified artifacts, apply, recovery | B08, L01–L03; V03 for scanner-driven decisions | [Lifecycle](plans/lifecycle.md) |
| Stage 3, containment | L07–L08: exposure removal, quarantine/reactivation | L01–L06; V02 before channel acceptance claims | [Lifecycle](plans/lifecycle.md) |
| Stage 3, remaining | L09: retirement/archive; L10: UI apply; L11: drills | See individual cards; no archive deletion shortcut | [Lifecycle](plans/lifecycle.md) |
| Stage 4 | A01–A06: inference, providers, login, model selection, advice | L06; inference remains optional | [AI](plans/ai.md) |
| Stage 5 | R01–R05: repositories, isolated builds, validator, repair | L05–L06; A06 for AI-assisted tasks | [Repositories and release](plans/repositories-release.md) |
| Stage 6 | S01–S03: signed release, platform support, public admin | Accepted feature subset and per-card gates | [Repositories and release](plans/repositories-release.md) |

## Rules that every implementation must preserve

- No production mutation from the API, bot, scanner, inference or builder process
  directly. Use the executor's existing authorization path. New automatic
  mutations also check the kill switch, budget, target lock and current contract.
- No shell strings or caller-selected filesystem paths in privileged requests.
  Resolve registered IDs through root-owned configuration.
- No shared writable database or data directory across trust domains. Exchange
  bounded authenticated snapshots/IPC, with explicit freshness and coverage.
- Treat logs, repositories, provider text and AI output as untrusted input.
  Proposals and severity scores do not constitute approval or local vulnerability
  proof. Missing evidence is unknown, never a successful scan/backup/restore.
- Keep secret values out of configuration revisions, generated plans, audit,
  receipts, command arguments and browser bundles. Use references and existing
  credential transfer patterns.
- Preserve `observe`, disabled features, pending UI revisions, SSH access and
  existing data. Do not remove an availability guard merely to pass a test.
- No runtime/provider/VM claim from a fake fixture. Record partial acceptance by
  gate. Documentation work does not authorize deployment or external messages.

## Checks to run for a task

Run commands from the repository root unless a working directory is specified.
Use the existing environment; install missing dependencies as described in
[CONTRIBUTING.md](../CONTRIBUTING.md) and [testing.md](testing.md).

| Change | Required checks |
|---|---|
| Docs only | `git diff --check`; verify changed relative links, task dependencies and claims against source; no application test run needed |
| Python | `uv run pytest tests/test_<area>.py` for the actual affected files, then `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .` |
| Schema | Python checks; `uv run python -m steward.core.schema`; include `tests/test_config.py` and `tests/test_render.py`; inspect generated JSON diff |
| Roles, units or rendering | Python/render checks; from `ansible/`, `ANSIBLE_COLLECTIONS_PATH=../.steward/collections uv run ansible-lint playbooks roles`; local rootless/VM gates appropriate to changed behavior |
| Web UI/API | Relevant Python/API tests; from `webapp/`, `npm run build` and `npm run test:e2e` when UI behavior changes |
| Privileges, isolation or host integration | Allow/deny/failure/restart cases locally, plus real separate-UID and host/firewall data-path checks on an authorized disposable VM before declaring host acceptance |

`tests/test_<area>.py` is a placeholder: substitute the existing filenames listed
in the selected card. If tooling or a target is unavailable, record the exact
unrun check and keep its acceptance gate open. Do not weaken a check to obtain a
green result. Changes to CI, lint/test configuration or policy files require the
separate review described in `CONTRIBUTING.md`.

## Handoff after each task or interrupted subtask

Use this small record in the change description; put durable evidence in
`STATUS.md`. Do not store private fixture details or credentials in Git.

```text
Task: B02 (complete / partial / blocked by <specific prerequisite>)
Behavior and files: <what changed>
Checks: <exact commands, outcomes, local/VM/live-provider scope>
Evidence: <sanitized result; private receipt path if applicable>
Still open: <unimplemented steps, unavailable checks, known limits>
Next: <one task ID or numbered step and the first file to read>
```
