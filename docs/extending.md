# Extending

Use the [working guide](working-guide.md) to pick the skill for the affected
boundary. [STATUS](STATUS.md#card-state) tracks availability and host evidence
for the implementation paths below.

## What can be extended today

### New executor action

Privileged capabilities must be registered actions in the repository, never
parameters, plugins, or configuration values.

1. Add a parameter model in `src/steward/executor/server.py`
   (`extra="forbid"`, narrow patterns; no paths or commands).
2. Write a handler: check registry policy, use `target_lock`, call
   `spend_budget` for automatic callers, and access the host only through
   `executor/host.py` methods with fixed `argv`.
3. Register it in `ACTIONS` with the smallest possible set of roles.
4. Add tests in `tests/test_executor.py`: allowed request, wrong role, schema
   violation, policy denial, kill switch.
5. Update the table in `docs/architecture.md`.

### New controller rule

Create a `Finding` in `controller.evaluate`; set `remediation` only when a
registered action exists. Test in `tests/test_controller.py`.
Rules read structured status fields, never free text.

### New configuration field

Add the field in `core/config.py` with a narrow type/pattern, rendering in
`core/render.py`, tests in `test_config.py` (including an injection attempt)
and `test_render.py`, then run `uv run python -m steward.core.schema` to update
`schemas/config.v1.schema.json`.

## Notification adapters (v1)

Implement `NotificationAdapter` from `adapters/notifications.py`: version,
local health check and `send(key, payload) -> Result`. Never report confirmed
without a transport acknowledgment. Return stable errors without endpoint URLs
or credentials; use `retry_after_s` for rate limits. Keep I/O outside queue
transactions. Add the implementation to the shared tests in
`tests/test_notifications.py`. The notifier runs separately from the executor.

## Query adapters (v1)

Implement `QueryAdapter` from `adapters/queries.py`: version, capabilities,
bounded input schema, local health and timeout, `decode` and `response`.
`decode` verifies signature and timestamp before producing an identity. The bot
then authorizes endpoint/tenant/user before any snapshot or collector access.
Keep commands in the fixed read-only command set. Errors use `QueryError` with
stable error classes and never include raw requests or signing keys. Shared
contract tests are in `tests/test_bot.py`. Returning a proposed repair must never
turn into an executor request from this process.

## Scanner adapters (v1)

Implement `ScannerAdapter` in `adapters/scanners.py` against `Component` and
`ScanResult` in `core/vulnerabilities.py`: version, capabilities, input schema,
local health, timeout and bounded scans. Return exactly one result for every
subject, preserving inventory revision and all subject/runtime metadata. The
pipeline checks these bindings independently. Success requires complete evidence;
a failure or unsupported input never means no vulnerability. Keep provider text
redacted, bounded and separate from mutation authority. Shared contract/state/
failure tests are in `tests/test_scanners.py`.

Optional CISA/FIRST context is implemented separately in
`adapters/intelligence.py` and `core/intelligence.py`. Bind it only to explicit
CVE aliases, preserve dates/unknown/failure states and keep it independent from
affected-version evidence. The read-only scanner role gains no mutation or
approval authority from context. Source and semantic-change tests are in
`tests/test_intelligence.py`.

## Backup adapters (v1)

`BackupAdapter` v1 already exists in `adapters/backups.py` with its Restic
implementation and tests in `tests/test_backups.py`; see the
[backup foundation](backup-foundation.md) for evidence and host integration limits.

## Remediation adapters (v1)

`RemediationAdapter` in `adapters/remediation.py` performs the host effects of one
verified image update: `plan`, `prepare` (fetch by digest, verify identity, load
for the service user), `install` (applied configuration, registry and Quadlet
unit move together; idempotent in both directions), `restart`, `observe`. It
never decides whether an update is allowed: the executor validates the signed
evidence (`core/update_evidence.py`), locks the target and journals every phase
(`executor/image_update.py`). Keep parameters to bound identifiers, run host
commands only through fixed-argv `Host` methods (`executor/image_host.py`), and
refuse any file that is neither its previous nor its new content. Shared tests:
`tests/test_remediation.py`; evidence tests: `tests/test_update_evidence.py`.
`present` reports a verified image that is already loaded for the service user, so a
rollback needs no registry. Recovery (L06) is in `executor/update_recovery.py` and
`executor/data_restore.py`: the signed migration kind (`none`, `reversible`,
`restore_required`) decides whether the previous image is enough or an exact data
capture is taken first and restored (see `core/update_recovery.py`); the operator
action `rollback` and the interrupted-update recovery use the same journaled steps.
Tests: `tests/test_update_recovery.py`, `tests/test_patch_profile.py`.
The update contract (`projects[].update`) and the `patch` profile are unavailable in
this release.

## Inference providers (v1)

`InferenceProvider` is specified in [ADR 0007](adr/0007-inference-contract.md) and
implemented in `core/inference.py`; adapters live in `adapters/inference.py`.
Return a `RawCompletion` or raise `InferenceError` with a stable class and the
right `spend` value; never include URLs, bodies or credentials in errors. Do not
register provider-chosen tools or schemas: tasks are code-defined. Add the adapter
to the shared cases in `tests/test_inference_adapters.py`. The output is untrusted
data and carries no executor authority. `ai.provider` stays unavailable until the
provider gates pass.

## Artifact validation (R04)

`core/artifact_validation.py` is the validator of builder output. It uses three small
contracts, each with fakes in `tests/artifact_testkit.py`: `ArtifactRegistry`
(`inspect`/`copy` by digest, validator identity only), `ArtifactProbe` (runs the
prescribed tests in a separate environment) and a scanner. It signs an attestation (L04);
`issue_approval` signs the approval with a different identity; `core/repository_deploy.py`
hands both to `update_validate`/`apply_verified_image` and nothing else. Real registry and
probe adapters are not implemented yet. Tests: `tests/test_artifact_validation.py`,
`tests/test_repository_deploy.py`.

## Login, model selection and advice (A04-A06)

`core/ai_auth.py` holds the login state machine (`pending/active/expired/revoked`) and
the closed `AUTH_METHODS` registry: a method is usable only when it carries dated
official `Evidence`; all three subscription methods are unavailable and their program
names are UNVERIFIED. The host entry is `steward-host ai ...` (`aihost.py`), the
controller entry `steward ai ...` (fixed SSH argv, `cli/ai_login.py`). `core/model_selection.py`
(rule, store, weekly run through `MaintenanceRuns`) and `core/model_suite.py` (versioned
synthetic suite) choose models without any model involvement; `ai.model_policy` carries
families, dated prices and the evaluation budget. `core/advice.py` answers `ask` from
grant-scoped snapshots; coverage text is computed by code. Tests: `test_ai_auth.py`,
`test_model_selection.py`, `test_advice.py`.

## Coding-agent contract (R05)

`core/repair.py` bounds the `CodingAgentRunner` contract to an isolated
candidate run. `core/repair_diff.py` checks the plain-text diff against
protected paths before validation. Publication uses a PR-only forge contract.
The real runner and forge client remain acceptance work. See the [R05 card](plans/repositories-release.md#r05--isolated-coding-agent-repair-with-pull-request-output).

The core adapters use explicitly registered implementations. Target OS checks
are part of Ansible preflight.

## Critical-risk response (L07/L08)

`core/critical_risk.py` holds the fixed decision table (no model, unknown evidence
never clean), `core/incidents.py` the durable per-application incident record and
legal phase transitions, `executor/containment.py` the registered actions
`incident_open`, `incident_advance`, `incident_reactivate`, `incident_status` and
`containment_reassert`, and `core/risk_cycle.py` the controller driver.
Active services in separately isolated applications use `application/service`
scan scopes. The scanner gives the controller a bounded, revision-scoped read
over its UID-checked Unix socket. The executor binds automatic notices and
route restoration to the current configuration and running image. The block
lives in its own nft table (`executor/containment_host.py`). The root registry
must enable `containment`, and `applications.on_critical` stays unavailable
in the released configuration. Tests:
`test_critical_risk.py`, `test_incidents.py`, `test_containment.py`,
`test_risk_cycle.py`. See the L07–L08 host acceptance criteria in the [work queue](implementation-plan.md).

## UI apply and maintenance drills (L10/L11)

`core/config_apply.py` plans and `executor/config_apply.py` performs the registered
action `config_apply`: it installs a pending UI revision locally only when every
generated Ansible input is unchanged and only `maintenance`/`projects` differ (registry
first, `desired.json` last as the commit point); anything else needs `./steward deploy`.
`core/drills.py` (ledger) and `executor/drills.py` (`drill_announce`, `drill_run`,
`drill_release`, `drill_status`) implement announced drills; `core/drill_cycle.py` is the
controller driver. `maintenance.drills` stays an unavailable feature. Tests:
`test_config_apply.py`, `test_drills.py`. See the L10–L11 host acceptance criteria in the [work queue](implementation-plan.md).
