# Status

Last updated: 2026-11-26 · Candidate source version 0.1.0rc1 · Branch `stage-1-vertical-slice`

This file is the current summary. Keep it short: one table row per card, and at
most 15 lines of evidence per completed card step (appended under "Evidence log").
The full history up to `8553ba1` (≈3,600 lines, mostly German) is frozen in
[status-archive.md](status-archive.md); link to its headings instead of copying.
The delivery plan and milestone burndown live in [goal.md](goal.md).

**2026-11-24:** [M9–M15](post-rc1.md) added as planned work after RC1. This
entry records the roadmap and its acceptance criteria. The mixed reference
profile includes eight PVE hosts, a local NAS and two external Ubuntu 26.04
LTS hosts.

[Post-RC1 research and architecture](plans/infrastructure-design/README.md)
records comparisons, design assumptions, planned acceptance, and five
optional follow-up iterations.

States: **accepted** = real host/provider evidence for the card's gates;
**local** = implemented and unit/contract/rootless tested only; **partial** = at
least one named gate still open; **open** = not started.

## Verified baseline

| Check | Result | Scope |
|---|---|---|
| Full suite on CI runner VM102 (Ruff, production Ansible lint, pytest-xdist) | 4,116 passed, 7 skipped | `b713338`, including private OpenAI-compatible onboarding, bounded cold-start evaluation and deployment recap. All 148 guardrail cases passed |
| `uv run pytest` (workstation, earlier) | 1742 passed | Development machine, Python 3.14 |
| `uv run ruff check .`, `ruff format --check .` | Clean | Same |
| Production `ansible-lint` | Clean (73 files) | ansible-core 2.20 |
| Fresh Proxmox/KVM install, second deploy `changed=0`, isolation, reboot | Passed on `31f0eff` | VM101 on `cn-0001`, 4 vCPU / 8 GiB; repeated after guarded reset |

VM101 on `cn-0001` is reserved for retention. VM102 runs CI and VM103/VM104
host disposable acceptance batches. Harness and reset guards are in
`tests/integration/proxmox/README.md`. Private receipts live under `.steward/`.

## Card state

| Card | State | What is proven | First open gate |
|---|---|---|---|
| Stage 1 core | accepted | KVM install, idempotency, isolation, reboot | — |
| B01–B07 | local + VM | capture, export, Restic upload/check/restore, scheduling, lock recovery. B07 passed on a fresh guest with separate reader credentials and application readback | [historical cross-guest receipts](status-archive.md#b07-partial-restore-test-vm-proof-and-output-protection) |
| **B08** | retention and RC1 single-host recovery accepted; managed activation partially tested and deferred from RC1 | VM103 rebooted on the private activation candidate and uploaded a verified scheduled snapshot. An independently encrypted copy on the separate PC passed offline repository, exact tree, SQLite note and attachment checks | 2026-11-26: resume when a planned activation batch has an exact signed candidate, an authorized HTTPS repository and an empty restore VM. Verify the unchanged repeat, VM restore and remaining integrated checks. `backup.enabled` stays guarded |
| V01 | accepted on VM104 (`161bfbe` recovery gates, `4daa44b` SSH and output re-check) | read-only `plan`; pending-UI and stale-config conflicts exit 4; config pulls retain references; wrong server, changed export and existing output fail safely; a dedicated SSH trust store is enforced and new output directories are private | — |
| V02 | partial; same-site CT 9212 checks passed on 2026-11-25 | signed bot queries over TLS. Steward Collector, outbox and both adapters exercised the lab's signed receipt replay and Discord simulation with persisted cooldown | released public HTTPS and real Discord delivery to authorized destinations, independent heartbeat and audit-anchor checks |
| V03 | accepted for the bounded scanner baseline | VM103 live OSV outage/recovery through scanner, collector and API, cold Trivy and dated KEV/EPSS; prior installed fixtures exercised persisted cooldown and inventory/image changes | aggregate coverage on VM103 remains incomplete (100 OSV timeouts and one stale image after recovery); new application-service scanning belongs to M4 acceptance |
| L01 | accepted (local) | graph validation, deterministic order, render contract | — |
| **L02** | accepted for `isolation: separate` through the private guarded renderer | guarded group stop/start with checkpoints and boot reconciliation, deploy transport, private and internal-HTTPS routed stacks, firewall transitions and local group capture re-verified on VM101 | public validation and deployment rendering still block application stacks. Shared group mutation custody is deferred to X1 |
| L03 | accepted on VM103 except G8 | window model, durable admission, lifecycle events, bounded HTTP/TCP and the container `unknown` path. W55 preserves the built-in health check through project image transport and reconciles stale containers | G8 healthy variant deferred for RC1 after two VM103 custody failures before installation. Needs a fresh guest with working disk custody and an unchanged repeat |
| Private LAN admin | accepted on VM104 for the routed IPv4 test path | automatic bind on VM104, protected loopback and API, trusted numeric-IP TLS, session and CSRF, and authentic access from the configured laptop CIDR through the scoped Proxmox relay | direct bridged home-client coverage remains untested. The VM104 relay is leased through 2026-11-27 07:44 UTC |
| S01 | partial; owner approval, protected build and operator signature pending | the public draft stack passed hosted CI. The exact test-signed copy passed isolated archive verification, ten pre-transport rejection cases and the VM103 staging inputs. An encrypted KeePassXC test attachment was used for network-isolated signing | owner approval of the documented sole-maintainer policy, protected default branch and exact-ref build environment, selected hosted candidate, operator signature and out-of-band public key, exact-archive host acceptance |
| L04–L05 | host gates passed on VM104 (4b6fa22 + guard-lift patch); stays behind `projects.update` until B08 passes and the guard is lifted deliberately | update contract, Ed25519 attestation + separate approval, single-use ledger, `update_validate` / `apply_verified_image` / `update_status`, image-only recovery; behind `projects.update` in UNAVAILABLE_FEATURES | M3 host gate `m3_l05.md` (needs that line removed on the tested commit); L06 recovery/patch profile |
| A01–A03 | partial; local contracts, Ollama packaging and direct Cloud API-key adapter | redacted inputs and reserved budgets, guarded CPU-only Ollama, strict `ollama-cloud-api`, opt-in ECB rates verified through the native HTTPS fetch | A02 G2 verified on VM104 with the private candidate renderer. A03 needs authorized live provider requests, and A02 runtime integration remains pending; `ai.provider` and `profile.local-ai` stay unavailable |
| L09 | partial; VM103 manual retire/re-add evidence and local guarded deployment path (W21) | reviewed removal of a fully managed separate application triggers guarded stop, verified archive and working-area release before registry cutover; exact resume preserves pending UI edits and re-add verifies archive before start | automatic-path VM batch, D1 host re-check and B08 acceptance; Shared remains unavailable |
| R01–R02 | partial; VM104 at `16dc93d` proved separate-UID SSH/TLS, redirect and address policy, kill-and-resume and contract outcomes. W37 packaged fetch passed locally | exact-revision fetch, canonical SSH input, pinned addresses, scoped application instructions, fixed suitability rules and a guarded one-shot unit with per-UID egress | two installed SSH batch attempts exhausted at the fresh base deploy's admin proxy check. The disposable proxy namespace could not reach its backend alias. Installed unit, egress, custody, reboot and withdrawal stay open. `repositories` stays unavailable |
| L06 | host gates G1–G9 passed on VM104 (4b6fa22 + guard-lift patch); `automation.patch` stays unavailable until the guard is lifted deliberately | recovery contract by migration kind (`none`/`reversible` image-only; `restore_required` captures, rehearses restore, then installs), revert and data restore with preserved newer data, operator `rollback` action and CLI, deterministic patch controller path (window, health, single-use approval); `projects.update` and `automation.patch` stay unavailable | gate `m3_l06.md` G1–G9 on a VM (real readback, SIGKILL at every phase, patch profile) |
| W15 hardening (decisions 5, 14–17, 20) | host gates G10–G14 and G8b passed on VM104 (217db6f + patch), G12(e) unknown-probe open; three behaviour defects routed to a fix lane | operator-only emergency apply outside the window (`emergency_confirm` + reason, audited, immediate `update.emergency`), `reversible` migrations take an update-time capture, executor-derived automatic rollback only for migration `none` within `update.rollback_window_s` (one attempt, 1/h), read-only retention status with 30-day candidate and limit hints (nothing deleted), 30-minute stability gate for the patch path, explicit `stateless` application marker so containment may skip the backup | host gates `m3_l06.md` G10–G14 and `m4_l07_l08.md` G8b |
| L07–L08 | partial; VM103 containment and reactivation with supplied scan evidence; qualified scanner handoff covered locally (W19) | deterministic exposure and incident policy, backup-before-stop and exact running-image reactivation; controller binds scanner results to application/service and active revision through authenticated IPC | wired VM batch, latest SIGKILL at `stopping`, notifier outbox and full B08 acceptance; `applications.on_critical` stays unavailable |
| L10 | partial; installed browser-to-host Apply passed on VM104 at `4885943` | version-bound plan and durable UI outcome, consistent host config and executor revision, unchanged workload invocations. Prior host API/CLI and G1c receipts still apply | G2 exhausted two live attempts without a mid-write kill. G3.4 needs `projects.update` after B08 |
| L11 | partial (code complete, local) | drill ledger, `drill_announce/run/release/status`, announced >= 15 min ahead, resources/restart/restore (private workspace) drills, suspension on failure, controller driver, no reboot path; `maintenance.drills` stays unavailable | host gates passed on VM104 (7c2b7df + guard-lift patch); application-group drills refused; off-site restore needs B08; `maintenance.drills` stays unavailable |
| A07 onboarding (ADR 0008) | partial; installed private-API browser evidence on VM104 | provider selection and return, approved URL and write-only key, provider-scoped scan, initial report, pin and auto controls, report deduplication, and bounded live evaluation of two models | real comparison-source qualification and research environment remain open. Native cloud and subscription gates stay pending |
| A04–A06 | partial, managed private API exercised on VM104 | The installed OpenAI-compatible profile verified Admin URL and write-only key setup, model discovery and reports, windowed evaluation, and Admin and signed bot advice against a real two-model endpoint | Native subscription login and revoke, qualified independent comparison sources and wider provider availability remain open. The private profile requires a verified deployment policy |
| R03 | partial; unmodified VM103 G1 blocked after two attempts | shared isolation floor, sealed source and dedicated offline verifier, rootless build library checks kernel memory, swap, CPU and task limits before execution, `authorizes: []` | `m7_r03.md` G1–G11; VM103 refused undelegated limits. Packaged execution needs trusted per-job write isolation and a kernel storage bound. Installed verification and egress remain open. `build` stays unavailable |
| R04 | partial; digest promotion and inventory passed in a stock loopback registry fixture | separate-identity validator and approval, exact offline inventory, validator-signed compatibility and scan enforced at approval and apply | gate `m7_r04.md` G1–G14; bounded validator runtime and trusted observation, installed application update mapping and automatic approval authority |
| R05 | partial; local repair and PR binding | bounded diffs and protected paths, independent validation of a derived commit, private handoff with exact source/base/head/branch, `authorizes: []` | gate `m7_r05.md` G1–G11; qualified runner and deployed validation, authoritative host-branch custody and authorized forge test. `automation.repair` stays unavailable |
| S02, S03 | deferred for RC1 | — | additional target profiles require exact OS/architecture installation evidence. Public administration requires the OIDC/MFA contract and host acceptance. Both remain unsupported |

## RC1 scope decisions

The [release subset](../release/accepted-subset.yml) governs support claims.
Exact signed-archive acceptance and numeric-IP private LAN access are release
gates under M8. The card rows above give the next gate for each deferred claim.

| Gates deferred from the supported subset | Reason and dependency |
|---|---|
| B08 activation and backup-dependent L04–L11 paths | Full integrated backup and recovery acceptance is still required. Keep `backup.enabled`, `projects.update`, `automation.patch`, `applications.on_critical` and `maintenance.drills` guarded. The private L02 renderer and L09 automatic retirement path still need their public and host gates. |
| V02 real delivery | No authorized external destination or independent recipient for the delivery and heartbeat evidence. |
| L03 G8, L10 G2 and G3.4 | Healthy container and mid-write interruption exhausted their host attempts. G3.4 needs the guarded `projects.update` path. |
| A01–A07 | The installed private API passed its bounded acceptance. Local and native provider gates, independent comparison sources and the research environment remain incomplete. The general AI availability guards stay in place. |
| R01–R05 | Installed fetch, delegated build limits, validator authority and Forge publication remain unqualified. Repository deployment, build and repair stay guarded. |
| S02, S03 and X1 | Additional target profiles, public OIDC/MFA admin and Shared custody require separate host qualifications. |

## Evidence log

Append new entries here, newest last, using the handoff record from
[implementation-plan.md](implementation-plan.md).

### 2026-11-21 — delivery reset

Task: planning/process (no runtime claim).
Behavior and files: froze the long status history into `status-archive.md`;
added `docs/goal.md` with the finite milestone plan and anti-loop rules; deferred
Shared-group mutation custody out of the critical path (ADR 0006 addendum).
Checks: `git diff --check`; relative links in changed docs.
Still open: everything marked open above.
Next: M1 / L03 step 1.

### 2026-11-21 — L03 step 1: maintenance window model

Task: L03 step 1 (complete, local only).
Behavior and files: `core/maintenance.py` (one-hour weekly window in a named zone,
DST gap/ambiguity rules, admission that requires the work to fit, emergency
window only for critical reasons after notice, known-exploited exception needing
exploited + reachable facts); optional top-level `maintenance` in `core/config.py`
(omitted from `effective()` when unset, so existing revisions are unchanged;
`drills` stay unavailable until L11); regenerated schema.
Checks: `uv run pytest` 1711 passed; `ruff check`, `ruff format --check` clean;
`tests/test_maintenance.py` covers DST, window boundaries, notice deadline,
reboot consent, clock inconsistency, config round-trip and revision stability.
Still open: durable state (step 2), probes (step 3), VM check.
Next: L03 step 2 — record runs as jobs keyed by window start in `core/store.py`.

### 2026-11-21 — L03 step 2: durable maintenance runs

Task: L03 step 2 (complete, local only).
Behavior and files: `core/maintenance_runs.py` records each admitted run as a job
keyed by work ID and window start in a dedicated `Store`: one run per work item
and window (also after failure), single attempt, interrupted runs end `failed`
with an explicit cause, a run claimed after its window closes is failed without
starting, stale workers cannot complete. Records only; no host action.
`controller.py` does not import the maintenance modules, so ordinary health
restarts are unchanged (asserted by a test).
Checks: `tests/test_maintenance_runs.py` (13 cases, real SQLite store, reopen).
Still open: wiring the policy from rendered config into the controller.
Next: L03 step 3.

### 2026-11-21 — L03 step 3: bounded health probes

Task: L03 step 3 (complete, local only; real container probe needs the VM batch).
Behavior and files: `core/health.py` classifies probe results as healthy / slow /
unhealthy / timeout / unknown (`ok` only for healthy). `executor/host.py` gains
`tcp_health` (loopback accept) and `container_health` (runs the container's own
`podman healthcheck run`; rc 125 = unknown); `http_health` reports elapsed time.
`executor/server.py:probe_health` dispatches by the registered kind (older
registries default to http). `Health.probe` / `Health.max_response_ms` in config,
stripped from canonical data while unset, so existing revisions are unchanged.
Controller: `unknown` warns without restart; timeout and slow keep the retry then
restart path. No operator or model command is executed.
Checks: `uv run pytest` 1742 passed; ruff clean; `tests/test_health_probes.py`
uses real loopback sockets/HTTP server for TCP refusal, hung-server timeout, slow
answer. Application services in groups still use their HTTP boot probe.
Next: M1 VM batch (probe timeout/health on VM101), policy wiring.

### 2026-11-21 — parallel lanes: pool, W1 (L03 rest), W6 (S01)

Task: process + L03 remainder + S01 (local only, no host claim).
VM pool on `cn-0001`: VM102 `steward-ci` (12 vCPU/8 GiB), VM103/VM104 acceptance
targets (2 vCPU/4 GiB, fresh Ubuntu, no Steward yet); VM100/VM101 untouched.
`tests/integration/proxmox/ci/` (`ci-run.sh`, `tunnel.sh`, `POOL.md`) runs the full
suite on the runner: 13 min on the workstation → 37 s.
W1 (`d44c5b5`): maintenance policy rendered into the executor registry only when
set; `platform_status.maintenance`; operator action `maintenance_admit` (fixed
`resource_check`, kill switch, target lock, once per window, never reboots);
`maintenance.*` events; M1 gate spec. W6 (`b4bdd84`): `release.py`, `release
verify|pack|keygen`, `docs/release.md`, gate spec `m8_s01.md`.
Checks: merged `a1dc285` on the runner: 1859 passed, 1 skipped, ruff, format and
production ansible-lint clean.
Still open: gates M1 (G0–G9) and S01 on VM103/VM104; product questions in goal.md.

### 2026-11-21 — S01 release gate on VM104

Task: S01 host gate (partial acceptance: verification only).
Commit 0d43fa2, version 0.1.0.dev0; fresh Ubuntu 26.04 VM104 (reset afterwards);
build host = clean clone, throwaway Ed25519 test key (deleted, never on the VM).
A: two packs have identical sha256 859dc179…db0d; local verify exit 0. B: only the
archive and public key reached the VM. C: verify on the VM exit 0, subset
grouped-operations-separate, service-graph, stage1-core, 6 file hashes, SBOM with
97 components. D1–D12: wheel byte, unsigned, wrong key, extra file, edited manifest,
SBOM, provenance, subset, missing file, symlink, truncated and hostile archive all
exit 1 with the expected reason; the original archive verified again afterwards.
E: unsigned build prints UNSIGNED and fails verify. Spec fix: the VM needs
`apt-get update` and `python3.14-venv` before the `./steward` bootstrap.
Not covered: archive install/upgrade, unchanged second deploy, reboot, CI release
job, real key custody, rotation/revocation, deploy-time enforcement.
Receipts: `.steward/pool/104/receipts/s01/` (private).

### 2026-11-21 — W2: L04 verified update evidence, L05 apply (local)

Task: L04 + L05 (code complete, local only; host gate open).
Behavior and files: `projects[].update` contract (`core/config.py`, canonical form
unchanged while unset); `core/update_evidence.py` (attestation and independent
approval bound to server, project, config/policy revision, digest, test revision,
scan evidence, expiry; single-use `UpdateLedger`); `adapters/remediation.py`;
`executor/image_update.py` + `image_host.py` register `update_validate`,
`apply_verified_image`, `update_status`. Apply rechecks evidence, kill switch,
window, backup freshness, revision, target lock and budget; success only after the
observed running image, health and isolation; failure restores the previous image.
Gate: `projects.update` is in UNAVAILABLE_FEATURES, so no production config carries
it. Merge `04c5054` (render conflict resolved: W1's full maintenance policy kept).
Checks: CI runner 1950 passed. A timing race in
`test_restic_process_journal` failed once and passed on rerun (backlog).
Open: M3 gate `m3_l05.md`; L06; scanner-driven approvals; product questions in report.

### 2026-11-21 — W4: A01–A03 inference (local)

Task: A01, A02, A03 (code complete, local; no provider or host claim).
Files: `core/inference.py` (provider contract, stable errors, spend states, closed
output schemas), `inference_snapshot.py` (scope/class filtering, redaction, size
bounds), `inference_budget.py` (atomic reservation of tokens/cost/seconds/slot per
global and project scope, single settlement), `inference_endpoint.py`,
`inference_models.py` (only place with model IDs; replaced by A05),
`inference_local.py`, `adapters/inference.py`; optional `ai` fields omitted from
canonical data while unset; ADR 0007. `local_only` blocks every external call,
including retries and fallbacks; private DNS results are refused.
Checks: merged `e61348f`, CI runner 2114 passed, ruff/format clean.
Open: gates `m6_ai.md`; A02 Ansible role; real request per method (G3); A04–A06.

### 2026-11-21 — W3: L09 retire, archive, re-add (local)

Task: L09 steps 1–3 (code complete, local; no host claim).
Behavior and files: `core/retirement.py` plans retirement only for applications in
the applied registry and absent from the desired one (legacy projects,
`manage: false`, pending UI revisions and Shared never qualify); `core/app_archive.py`
+ `executor/retirement.py`: verify stopped and boot-disabled, archive data and
images, re-read every byte, check data unchanged, release images/data/managers,
fsync'd journal resumes at every crash point; accounts and UIDs stay reserved; no
archive deletion function; `application_archive.py` restores on re-add (hooked into
`ansible/roles/workloads/tasks/application.yml`, staged + NOREPLACE swap).
Checks: merged `ca44946`, CI runner 2198 passed. Open: gate `m5_l09.md` (real
chown, ENOSPC, reboot, image-cache file name), B08 for acceptance.

### 2026-11-21 — W5: R01–R02 repository fetch and contract (local)

Task: R01 + R02 (code complete, local; no host claim).
Files: `core/repositories.py` (fetch component, `python -m steward.core.repositories
fetch`, not wired into the CLI), `core/repository_contract.py` (git-plumbing
inspection without checkout, inventory bound to commit and tree, `ContractProposer`
interface, fixed suitability rules; a suitable result authorizes only
`isolated_build`), `Repository`/`WorkloadContract` models, `repositories` in
UNAVAILABLE_FEATURES, empty section omitted from canonical data.
Checks: CI runner on merged tree 2336 passed. Real git and a loopback smart-HTTP
server are used for fetch, redirect, wrong-token and hostile-content cases; ssh only
against a fake script (wiring, not evidence).
Open: gate `m7_r01_r02.md`; fetch identity/unit/egress rule; R03–R05.

### 2026-11-21 — M1 / L03 host gate on VM103 (commit 0d43fa2)

Fresh VM103 (`steward-acc-a`): first deploy changed=68, second changed=0.
G0 baseline: maintenance `{configured: false}`, `maintenance-admit` refused
(`policy_denied`). G1: policy rendered, `outside_window`, state dir 700 root, one
`maintenance.window_announced`. G2: refused outside the window, nothing recorded.
G3: admitted once (`resource_check` completed), then `already_recorded_in_window`
twice, also after an executor restart; one run, no reboot, audit chain valid, kill
switch refused. G4: controller restarted a stopped `notes` in ~17 s. G6: tcp refused
→ unhealthy → controller restart; frozen `notes` → `timeout` (status in 1.7 s) →
restart in ~100 s. G7: container probe without HEALTHCHECK → `unknown`, warning
finding, no restart. G9: reverted, final deploy changed=0.
G5 FAILED: two projects sharing one image digest could not deploy (archive keyed by
image only, tag per project; unit exit 125 "image not known"). G6/G7 ran only after
a manual per-user tag workaround. Fixed in `ansible/roles/workloads/tasks/project.yml`
(archive keyed by image and tag; first deploy after upgrade re-archives once).
G8 open: no digest-pinned HEALTHCHECK image. Spec fix: G1 quoting over ssh.
Open: re-run G5–G8 on the fixed commit without workaround.

### 2026-11-21 — W7: L06 update recovery and patch controller path (local)

Task: L06 (code complete, local; no host claim). Merge `00247f9` (conflicts in
`docs/architecture.md` and `hostcli.py` were additive; both sides kept).
Behavior: signed migration kind decides recovery; `restore_required` stops, captures,
rehearses the restore in a private workspace, then installs; failed start/health/
isolation reverts, with data restored first; a death during capture or before install
resumes the old workload; an interrupted migrating update is reverted, never
repeated. `data.preserved-<token>` keeps newer data (max 8, never auto-deleted).
`rollback` is operator-only, journaled and idempotent. `core/patch_profile.py` +
controller hook call only `update_status` and `apply_verified_image`.
Checks: CI runner 2480 passed incl. ansible-lint; a mutation check (removing the
restore-before-revert call) failed 4 tests.
Open: gate `m3_l06.md`; lifting the two availability guards is a separate decision.

### 2026-11-21 — M1 / L03 re-run G5–G9 on VM103 (commit c48fdc2)

Image-archive fix verified without workaround: upgrade deploy changed=8, repeat 0.
G5 pass: probe revision (notes 1 s http, probe-tcp, probe-ctr) deployed first try
(changed=21), repeat 0, each project has its own image tag. G6 pass: stopped
probe-tcp → unhealthy → controller restart; frozen notes → timeout (status in
1.5 s) → restart, old PID gone. G7 pass for the probe logic: probe-ctr `unknown`
(rc 125), warning finding, no restart after the deploy finished. G8 open: no
digest-pinned HEALTHCHECK image. G9 revert pass: no maintenance key, kill switch
off, audit chain valid (51 records), final deploy changed=0. G0–G4 passed earlier on
`0d43fa2` and were not repeated. Receipts: `.steward/pool/103/receipts/m1/` (private).
Observed: re-enabling a stopped project can trigger one failed controller restart
while the deploy is still loading its image (backlog).

### 2026-11-21 — W8: L07 decision and L08 quarantine (local)

Task: L07 + L08 (code complete, local; no host claim; fast-forward merge of
`lane-w8-l07-l08`). `core/critical_risk.py` fixed table; `core/incidents.py`
fsync'd per-application records; `executor/containment.py` actions
`incident_open|advance|reactivate|status` and `containment_reassert` (startup too);
`executor/containment_host.py` loads table `inet steward_containment` so a main
reload cannot lift the block; one stage per `advance`: notice, disconnect, backup
(verified), announce, stop in reverse dependency order, quarantined; a failed backup
leaves the stack running, disconnected and escalated. Crash injected before/after all
nine transitions still reaches verified reactivation (18 runs).
Checks: CI runner 2597 passed incl. ansible-lint. Open: gate `m4_l07_l08.md`.

### 2026-11-22 — M3 / L05+L06 host gates on VM104 (191ce2c + guard-lift patch)

Patch (receipts `guard-lift.patch`): removed `projects.update` and `automation.patch`
from UNAVAILABLE_FEATURES and filtered `unavailable_features()` by it; the repo was not
changed. Fresh VM104, loopback registry; deploys: platform 68, shop 20 then 0.
L05 passed: ten evidence refusal codes, role denials, missing/stale backup, busy
target, failed v3 reverted with byte-identical files, v1→v2 applied and host-verified
(image ID, health, isolation), replay refused, SIGKILL at `installed` recovered.
L06 G1–G4, G6, G7 passed: failed migration restored exact data, CLI rollback kept
newer data in a preserved tree, image-only rollback touched no data, previous image
unavailable then retried, damaged capture failed visibly. G5: kills after
capturing/captured/installing/installed recovered. G8: expired, kill switch. G9:
blocked outside the window; inside, one controller `apply_verified_image` applied v5;
kill switch → no request; failing v6 recovered, not retried.
Not run: pending-UI-edit checks, interrupted rollback, G9 expired/unhealthy negatives.
Defects found only on the host (routed to the fix lane): (1) `call()` client timeout
60 s equals `verify_timeout_s`, so a failing update reports `unavailable` while the
executor still reverts (also in the controller patch path); (2) a stale controller
config is not a plan conflict, so a deploy would silently downgrade an applied update;
(3) a killed executor yields `internal`/"malformed response", not `unavailable`;
(4) `update_status` lacks the data-restore field; (5) spool capture limit (10) hit
without guidance. Spec/behaviour differences: rollback of a non-applied approval
returns `replay`; "already current" precedes `revision_mismatch`; any redeploy
invalidates approvals. Receipts: `.steward/pool/104/receipts/m3/` (private).

### 2026-11-22 — M3 re-run on VM104 (4b6fa22 + guard-lift patch)

Same patch as before (`projects.update`, `automation.patch` removed from
UNAVAILABLE_FEATURES, `unavailable_features()` filtered); fresh VM104, loopback
registry. Deploys: platform 68, shop 19 then 0.
L05 passed in full: refusals, failed v3 reverted byte-identical, v1→v2 applied and
host-verified, plan exits 4 after an executor-applied update (recovery: config
pull / adoption deploy), pending UI head preserved, SIGKILL at `installed` recovered.
L06 G2/G3 passed (exact data restore, `data_restore: restored`, CLI rollback, UI head
unchanged). G5: kills at prepare, capturing, captured, installing, installed and an
interrupted rollback all recovered; new image started 0 times. G8 passed. G9: blocked
outside the window; one controller `apply_verified_image` applied v5; kill switch,
expired approval and failed health each produced no request; failing v6 returned
`execution_failed` to the controller, was recovered with data restored and not retried.
Fixed and confirmed: dropped connection now `unavailable`; controller no longer reports
`unavailable` for a failing update.
Remaining: spec `xcall` helper still uses a 60 s client timeout (needs >= 780 s);
`config pull` returns the UI head, so recovery with a pending edit needs the applied
`desired.json` plus `--discard-pending`; a changed config after an applied update needs
one adoption deploy first. Receipts: `.steward/pool/104/receipts/m3b/` (private).

### 2026-11-22 — M4 / L07+L08 host gates on VM103 (4b6fa22 + patch)

Patch (receipts `m4-acceptance.patch`; repo unchanged): `applications.on_critical`
removed from UNAVAILABLE_FEATURES, `unavailable_features()` filtered, and
`containment {enabled, notice_minutes: 15}` rendered when an application sets
`on_critical`. Fresh VM103, private application path; platform deploy 61 then 0;
`shop` (database/backend/frontend, routed) 60 then 0.
Passed: G1–G4 (notice 900 s; one advance gave `disconnected` in 0.35 s; IPv4 and IPv6
via netns both 502; ssh/admin intact; proxy uid refused; backup verified, ordered stop
frontend→backend→database, one correlation id), G7 twice (no evidence → needs
evidence; stale, wrong image ID, old digest refused; `confirmed` re-quarantined; good
evidence reactivated, 200, marker intact), G8 (host scope escalates only; notify never
disconnects), G9 (changed=0). G5: a real spool fault left the stack running and
disconnected with an escalation. G6 executor SIGKILL at `backup_pending`/`stopping`
resumed with one capture.
FAILED G6 reboot (D1): block restored, but all services ran again ~5 s after boot until
a manual `containment_reassert` ~2 min later. D2: a deploy while quarantined starts the
stack (block holds). D3: one group capture per hour, failed attempts count, so a retry
returns `budget_exhausted` for up to 1 h. D4: spool fault reported as `internal`.
Open: notifier outbox (no channel in fixture), mid-capture kill. Receipts:
`.steward/pool/103/receipts/m4/` (private).

### 2026-11-22 — W10: R03 isolated build runner (local)

Task: R03 (code complete, local; no host claim). Fast-forward merge of `lane-w10-r03`.
`core/builder.py` + `builder_podman.py`: request bound to source/contract/recipe/
inventory digests, exact-tree export without `export-subst`, fixed-argv bounded runs
(time, log, disk, process group), digest-only output, record `authorizes: []`;
container tier is opt-in and labelled "container isolation, no VM protection".
Checks: CI runner (with ansible-lint) 2682 passed. Open: gate `m7_r03.md`; R04.

### 2026-11-22 — W9: L10 local apply, L11 announced drills (local)

Task: L10 + L11 (code complete, local; no host claim; UI not built).
L10: `core/config_apply.py`, `executor/config_apply.py` (`config_apply`, roles operator
and api): trusts only the head content hash, re-validates the body, recomputes the
plan, takes `deployment-execution`, refuses during a deployment fence, writes the
registry first and `desired.json` last (repeat finishes any crash point), success only
after read-back; API 409 when head or applied moved, 422 for unsupported plans.
L11: `core/drills.py` ledger (unique per drill, service, window), `executor/drills.py`,
`core/drill_cycle.py`; runs only with kill switch off, drill configured, inside an
announced regular window with the budget fitting; failure suspends that service's
drills; interrupted runs closed as failed.
Checks: CI runner with ansible-lint 2722 passed. Open: gate `m5_l10_l11.md` G1–G8,
`npm run build` and a Playwright case, application-group drills.

### 2026-11-22 — M4 re-run on VM103 (1a59d14 + patch)

Patch as before (`m4-acceptance.patch`; repo unchanged). Fresh VM103: base deploy 61
then 0; shop stack 60 then 0.
G5 pass: spool fault injected before the disconnect → `backup_failed`,
`spool_unwritable` (escalated audit, controller finding, stack up, 502 on both
families); after removing the fault the next advance verified the backup and reached
`quarantined` with no hour wait; second and third incident within the hour also got a
capture. G6 reboot pass: table present at 7 s uptime, 150 s of 1 Hz polling showed zero
`shop` processes, units inactive, probes 404. SIGKILL 8 s into a capture: block stayed,
one transient `backup_failed` (`unavailable`), retry verified and quarantined with one
new capture. G7 end to end twice (no/stale/wrong-image evidence refused, good evidence
reactivated, 200, marker intact). G9 revert: deploy 12 then 0.
D2 pass with caveat: a deploy while quarantined started the stack late in the deploy;
periodic reassertion stopped it ~52 s later (~27 s after the deploy ended; the
executor waits on the deploy lock) with an `incident.quarantine_reasserted` audit; the
block was present in all 224 samples. Not re-run: SIGKILL at `stopping`; notifier
outbox. Observation: `steward-applications.service` shows `failed` after boot with a
quarantined stack until reactivation. Receipts: `.steward/pool/103/receipts/m4/`.

### 2026-11-22 — W12: R04 independent validation and deployment (local)

Task: R04 (code complete, local; no host claim). `core/artifact_validation.py`,
`core/repository_deploy.py`: validator refuses shared identity/UID/dir/key with the
builder; re-binds the build record to inputs it derives itself; inspects the artifact
by digest; runs prescribed probes clean and against previous data (isolation, health,
data compatibility); scans all components; promotes by digest and signs its own L04
attestation; approval signed by a different identity and refuses widened egress
without operator confirmation. Deploy only via `update_validate` then
`apply_verified_image`; a rejected report never reaches the executor.
Checks: CI runner with ansible-lint 2784 passed. Open: gate `m7_r04.md`; real
registry/probe adapters; R05.

### 2026-11-22 — W11: A04–A06 login, model selection, advice (local)

Task: A04, A05, A06 (code complete, local; no provider/host claim).
A04: `core/ai_auth.py` state machine (pending/active/expired/revoked), protected state
store (wrong owner, loose modes, symlinks refused; no token stored), official program
run with fixed argv under the inference UID; `steward ai login|status|check|revoke`
over `ssh -tt` with `StrictHostKeyChecking=yes`; all subscription methods unavailable
until dated official evidence exists (program names and exit codes marked UNVERIFIED).
A05: optional `ai.model_policy` (operator-declared dated prices; omitted from canonical
data while unset), versioned synthetic suite graded in code, pure `decide` rule
(strictly cheaper or incumbent gone/failing; ties keep the incumbent), once per window
through `MaintenanceRuns`, interrupted activation keeps the old model.
A06: closed advice task, grant-scoped gathering before any snapshot, sources and time
range computed by code, model-cited sources outside the snapshot dropped, inert output,
explicit "Advice gap:" on every failure; bot `ask` (500 chars, no credential in the bot).
Checks: CI runner with ansible-lint 2829 passed at `f5d625d`. Open: gate
`m6_a04_a06.md`; scheduler, bot→inference IPC, API/UI view.

### 2026-11-22 — M5 / L10+L11 host gates on VM104 (7c2b7df + guard-lift patch)

Patch (receipts `guard-lift.patch`): `maintenance.drills` removed from
UNAVAILABLE_FEATURES, `unavailable_features()` filtered; repo unchanged. Fresh VM104,
deploys 74 then 0; projects `notes` and `shop`. Web UI not built or browser-tested.
L10 passed: apply of a pending revision (job succeeded, canonical hash of
`desired.json` equals the status revision, project units not restarted, one audit
entry, repeat 409), unsupported change 422 without a job, stale head 409, CSRF and
foreign Origin 403, CLI `config apply` (wrong head exit 4, executor not called),
executor SIGKILL around apply and an API restart left consistent files (the kill never
landed mid-write; crash points stay covered by fakes). First deploy after an apply
changed=5 (platform reconcile only), second 0.
L11 passed: one announcement per window, `outside_window` deferral, kill switch blocks,
restart drill recovered in 2.156 s with one restart, isolated restore left data and
units unchanged, `no_verified_capture`, failed drill (298 s, immediate event, service
suspended, controller repaired it, `drill_release` works, controller refused),
interrupted drill closed as failed and suspended, `does_not_fit_before_window_end`;
enabling drills alone acts on nothing; no reboot.
DEFECT D1: a UI apply during a running site deployment succeeds and the deploy then
overwrites registry and `desired.json` with its stale local revision (spec expects
`target_busy`). Open: UI gates, G3.4. Receipts: `.steward/pool/104/receipts/m5/`.

### 2026-11-22 — W13: fix for the L10 lost update (local; host re-check G1c open)

Defect D1 (UI apply during a deploy overwritten by the deploy). Root cause from the
code: a guarded deployment already holds `deployment-execution` and the fence for the
whole run; an unguarded one (install marker schema 1) had neither, so the apply saw
nothing and the deploy wrote its stale local revision. (Inferred for VM104; not
confirmed there.)
Fix `1dad961` (merged): unguarded runs write `/etc/steward/config/deploy-run.json`
before the platform play and clear it in the last task; `config_apply` returns
`target_busy` while it exists (interrupted run keeps it until a deploy finishes);
before the two writes the playbook runs `config_apply check-base --expected <base>`
under the `deployment-execution` lock (compare-and-set against desired.json and
registry), mismatch → `STEWARD_CONFIG_MOVED`, CLI exit 4 pointing to `config pull`.
Docs: pending UI head blocks `deploy`.
Checks: CI runner with ansible-lint 2833 passed. Open: gate G1c on a host (slowed
platform phase, apply race, killed controller), guarded-path claim has no host evidence.

### 2026-11-23 — W14: R05 repair agent with pull-request output (local)

Task: R05 (code complete, local; no host or provider claim). Merge `8e9e226`.
`adapters/coding.py`, `core/repair_diff.py`, `core/repair.py`: agent identity must
differ from builder, validator, approver and forge identity and have no production
credential scope; diff must be plain text without renames, modes, symlinks,
submodules or binaries, and the real change set is recomputed from the two trees;
protected paths always win; the patched tree is committed as a child in a new store and
validated through the real R03 build and R04 validator; publication needs an explicit
`Publication` and a distinct forge identity, otherwise `patch_ready`; PR text is
toolkit-generated. Checks: CI runner with ansible-lint 2907 passed. Open: gate
`m7_r05.md`, real runner and forge client.

### 2026-11-23 — D1 re-check (G1c) and R01+R02 host gates on VM104 (16dc93d)

G1c (16dc93d + two file-driven "hold" tasks, receipts `hold.patch`): unguarded host:
apply during a slowed deploy → `target_busy` (marker `deploy-run.json` present,
`desired.json` unchanged, marker removed after the deploy); apply between preflight and
the compare-and-set → deploy stops with `STEWARD_CONFIG_MOVED`, CLI exit 4, applied
revision kept; controller killed mid-deploy → marker stays, apply refused, repeated
deploy removes it. Guarded host (schema 2): `target_busy` from the fence, no marker.
D1 closed. Finding: a guarded apply between preflight and admission succeeds and the
deploy then fails generically (exit 1, no `config pull` hint); an unguarded repeat
deploy can never be `changed=0` (marker tasks count).
R01+R02 (plain 16dc93d, fetch as a real `steward-fetch` UID, real sshd and nginx TLS):
fetch modes 700/600 and probe UID denied; repeat unchanged; exact pin, bogus pin fails
closed; wrong TLS name and wrong SSH host key refused; credential separation; redirect
and http/git/file/ext/scp URLs refused; private and link-local addresses refused; kill
and resume sweeps `.tmp`; hostile hooks/filters/submodules never run. R02:
suitable, missing_contract, unsuitable, invalid as specified; proposer opens no
connection. Receipts: `.steward/pool/104/receipts/g1c-r01/` (private).

### 2026-11-23 — W16: AI onboarding, source modes, FX rate, admin API (local)

Task: ADR 0008 and decisions 7, 8, 8b (code complete, local; no provider/host claim;
fast-forward merge). `core/ai_onboarding.py`, `core/model_sources.py`,
`core/fx_rate.py`, `api/ai_admin.py`, minimal untested `webapp/src/pages/Ai.tsx`.
Selection switches need >= 2 independent fresh source groups ranking the candidate
strictly better and none worse; research output is schema-validated and cannot touch
budget, provider, pin or kill switch; a stale exchange rate denies cost-limited
reservations (`fx_rate`); local model becomes active only after the measured sha256
matches the declaration. Checks: CI runner with ansible-lint 2962 passed. Open: gate
`m6_onboarding.md`; service wiring; Ollama adapter and family rule; real source parsers.

### 2026-11-23 — W15: update hardening (decisions 5, 14, 15, 16, 17, 20) (local)

Task: five update decisions plus the stateless marker (code complete, local; no host
claim). Merge of `lane-w15-update-hardening` into the W16 tree; combined CI runner run
with ansible-lint 2994 passed.
Emergency apply: only role `operator`, strict `emergency_confirm` plus a 10–200 char
reason, only the window check is waived (evidence, approval, backup age, locks,
journal unchanged), audited before `update_apply started`, announced as `update.emergency`;
controller/api refused with `policy_denied` and an audit entry. Reversible: capture without
restore rehearsal; failed update reverts image-only first, falls back to restoring the
capture only if the old image cannot run on the new data. Auto-rollback: executor
re-derives profile, migration `none`, `applied` state, age and a fresh health probe;
journal marker makes it one attempt per update. Retention: `update_retention_status`,
nothing deleted. Stability: durable `stability.json`, any unhealthy/unknown observation
or a gap > 300 s restarts the clock. Stateless: `Application.stateless` only when every
service has no `data_path`; containment audits `backup_skipped` (`stateless_contract`).
Open: gates G10–G14, G8b; updates applied before this change are never auto-rolled back.

### 2026-11-23 — M5 / L09 host gates on VM103 (16dc93d + snapshot patch)

Host evidence only (B08 still gates acceptance). Private application path, schema 2
enrolment: platform deploy 61 then 2; fixture (`database` + `web`) 44 then 0.
FAILED on 16dc93d (D1): `application_retire` after the accepted all-disabled deployment
returned `unavailable: application boot has not completed`, because that deployment
removes `steward-applications.service`. Fixed afterwards in `executor/retirement.py`
(`_boot_settled`: an absent boot unit counts only when every registered service is
disabled; regression test added); not yet re-run on a host.
Passed with the snapshot patch: S1–S2, R1–R6 (audit chain intact, identities and pins
unchanged, both services released), A1–A6 (data hashes equal after two reboots and two
cycles), N1–N9: ENOSPC → `insufficient_space` with data intact; corrupt archive and
UID change stop re-add before any start; kills in build/verified/releasing resume or
cancel as specified; changed data → `conflict`; a planted file blocks re-add; no
delete or purge action exists. N10 open (shared isolation not deployable).
Findings: archive tree is `root:steward-exec` (spec says `root:root`, modes 0600/0700);
a private-path repeat deploy of a config without applications fails at "Admit the
protected site deployment" with censored output; failed or killed private deploys
leave a fence (recovery: `site_deployment revoke`, then `--resume-deployment`).
Receipts: `.steward/pool/103/receipts/m5-l09/` (private).

### 2026-11-23 — W15 host gates G10–G14, G8b on VM104 (217db6f + patch)

Patches (receipts `guard-lift.patch`, `g8b-containment.patch`; repo unchanged except two
gate specs): `projects.update`, `automation.patch` (G8b also `applications.on_critical`)
removed from UNAVAILABLE_FEATURES, `unavailable_features()` filtered, containment rendered.
Fresh VM104, loopback registry; deploys platform 68, shop 21, repeat 2 (marker tasks only).
G10 passed: outside the window `policy_denied`; confirm without reason `bad_request`, with
reason applied, `update_emergency` audit before `update_apply`, immediate event, repeat
`replay`; controller denied and audited; empty spool `missing_backup`; no maintenance
section refused. G11 passed: reversible update takes a capture; plain rollback leaves data;
retry with acknowledgement restores exactly; failing update reverts and restores; 10
artifacts → `unavailable`. G12 passed: one `auto_rollback` after a restart; hand-made
controller/operator calls denied; `restore_required`, window 300/0, kill switch → no
rollback; (e) unknown probe open. G13 passed: hints at 6–8 of 8/10, 30-day candidates after
a +31 day clock shift (restored, NTP ok), nothing deleted. G14 passed on attempt 2: clock
`since` fixed, resets on a gap > 5 min and on an unhealthy observation, apply 1800 s after
`since`. G8b passed: stateless app stopped without capture (`backup_skipped
stateless_contract`), unmarked app → `backup_failed`, marker removed → `stop_failed
no_backup`, reactivation verified.
Defects: (1) controller attempts `rollback` for an older applied approval after a newer
unhealthy update (executor refuses `conflict`); (2) a `backup-capture` restart resets the
stability clock; (3) `update-retention` omits plain `backup-capture` artifacts.
Receipts: `.steward/pool/104/receipts/w15/` (private).

### 2026-11-23 — W17: fixes for the three W15 host defects (local; host re-check G15 open)

Fast-forward merge of `lane-w17-w15-fixes` (`7bfd3d4`). (1) `rollback_selection` picks the
newest applied update of a project by `applied_at` (fallback `updated_at`) and returns a
candidate only if that row itself is eligible (state `applied`, migration `none`, inside
the window, no `auto_rollback` marker); an older eligible row never stands in for a newer
ineligible one; a skip records its reason and makes no `rollback` call. (2) A planned
backup restart is neutral for the stability clock: `platform_status.backup_planned_restarts`
comes from the executor's own audit (`backup_resume` ok), a pause counts as planned for 300 s
and a resume for 180 s; unplanned, stale, errored or other-project observations still reset
the clock. (3) `update-retention` lists, ages and counts every spool artifact
(`bound_to_update` true/false); nothing is deleted.
Checks: CI runner with ansible-lint 3001 passed. Open: host re-check gate G15 in
`m3_l06.md`; a workload slower than 180 s to become healthy after a capture still resets the
clock; application-group captures are not in the planned signal.

### 2026-11-23 — B08 retention: `protected` phase on VM101

VM101 clock equalled the workstation clock (18:40:24 UTC). Phase `check` before (18:26) and
after: 6 captures, 3 imports, audit chain valid, existing captures and imports preserved,
`steward-backup.service` inactive, notes active, no open pause or cleanup intent.
Phase `protected` at 18:40:35 UTC, 76 s after the oldest capture passed 7 days
(`protected_due` 18:39:18.89 UTC): the oldest upload-protected capture was REFUSED deletion
(`exact_pending_upload_denial: true`, `policy_denied` for pending upload/schedule); nothing
was acknowledged or removed; `protected-result.json` written (gate for `retire`).
Not yet evidenced: phase `retire` (due 2026-11-25 21:13:22 UTC by the VM clock, only the
new local test copy), geographically independent restore, and the remaining B08 gates of
plan steps 2–5; `backup.enabled` stays guarded. Receipts (private):
`.steward/b08-candidate-private/retention-age-vm101/receipts-2026-11-23/`.

### 2026-11-23 — W17 re-check G15 and V01 on VM104 (161bfbe)

G15 (161bfbe + guard-lift patch; repo unchanged except spec text) passed on attempt 1:
spool listing count equals the directory count (1, then 8 of 10 with the hint) with plain
captures `bound_to_update:false`; three `backup-capture` restarts left the stability
clock `since` unchanged while an unplanned stop outside the 180 s grace moved it; with an
older applied `none` update and a newer applied `restore_required` update turning
unhealthy the controller recorded `skipped: newest update has a data migration` and the
executor audit holds 0 `rollback`, 0 `update_auto_rollback`, 0 `conflict`.
V01 (unpatched 161bfbe, fresh VM104, deploy changed=70; host snapshots compared after
every read-only step, no diff): `plan` unchanged exit 0 / local edit shows the diff; a
pending UI revision makes `plan` and `deploy` exit 4 with revision and edit intact;
`config pull --config` adopts it (mode 600, server block and refs kept); after a
server-side apply the old file exits 4; a fresh-checkout pull writes mode 600 with `file:`
refs only and no secret value; wrong `--limit` exit 1, wrong host key (cold) exit 1,
modified `head.json` exit 4 (restored byte-identical), existing file or dangling symlink
exit 4 with content and mode unchanged.
DEFECT (security): `config pull --known-hosts-file <other key>` within 60 s of an earlier
connection to the same host succeeded (Ansible ControlPersist socket keyed by
host/port/user), so the given trust store was not enforced; it fails safely when cold.
Other: intermediate directories of `--out a/b/c.yml` get the umask mode; the check-mode
preview reports pip/restart tasks as changed on an unchanged host; the first repeat deploy
after a server-side apply restarts platform services once.
Receipts: `.steward/pool/104/receipts/g15-v01/` (private).

### 2026-11-24 — V01 / W18: isolate SSH host trust per playbook

Each Ansible playbook uses a short-lived, private SSH control directory with a unique
socket path. A new playbook establishes SSH under its own host-key policy. A configured
known-hosts path with spaces is preserved through Ansible and OpenSSH. `config pull`
creates each missing output directory with mode 0700 or stricter and preserves the mode
of existing directories. Regression tests cover socket separation and cleanup on
success and failure, host-key options, nested directories and 0600 output.
Checks: seven targeted CLI tests, offline OpenSSH option parsing, one diff review.
VM102 ran the full snapshot suite: 3002 passed, 3 skipped (git checkout required),
Ruff and production Ansible-Lint passed. The workstation suite exceeded its 90-second
limit. VM104 re-check remains open.

### 2026-11-24 — M2 / V03: VM103 scanner evidence reconciled

Installed scanner modules matched `161bfbe`. OSV completed 283 of 449 package checks
and timed out on 166. The only Trivy image result was stale; overall coverage stayed
incomplete. Scanner attempts and failures reached the collector. Cold Trivy acquisition
refilled about 1.69 GiB in a 12.1 s sampled window; memory reached the 768 MiB service
limit. Traffic counters are guest-wide. Live KEV and EPSS context included source dates.
Focused scanner, adapter, inventory and observation suite: 113 passed. The current fixture
lacks attributable outage/recovery, cooldown across restart, in-flight inventory change
and authenticated UI evidence; earlier controlled receipts retain their original scope.
Private handoff: `.steward/pool/103/receipts/r03-v03/reconcile.uELvPtpj/handoff.md`.

### 2026-11-24 — M7 / R03: VM103 build evidence reconciled

Both unmodified G1 attempts refused the host with `host_not_ready` and
`limits_not_delegated`; the precise source commit is unavailable. Seven diagnostic G1
runs exceeded the gate budget. One produced a registry digest with patched code and
left its work directory. G7/G8 diagnostic receipts show reconciliation and cleanup
failures. The current VM103 read-only probe found no active builder fixture remnants.
`build` remains unavailable. See the private V03/R03 handoff above.

### 2026-11-24 — V01 / W18: VM104 re-check passed

Fresh owned VM104 was installed with the same `161bfbe` fixture (143 OK, 70 changed,
0 failed); the controller CLI and playbook tested were from `4daa44b`. Bootstrap
`config pull` with an empty dedicated known-hosts file refused the untrusted key
(exit 1, no output). The pinned known-hosts file with spaces in its path succeeded
(exit 0); new directories were 0700 and `server.yml` was 0600. Hashes of the server
identity and exported head matched before and after both requests. The existing
`161bfbe` invalid-export, conflict and credential-reference results still apply.
Exact invocations and receipts: `.steward/pool/104/receipts/v01-w18/` (private).

### 2026-11-24 — M4 / L07 step 2: application scan evidence wired locally

The executor exports qualified, active application service images only under the
root containment policy. The scanner binds each observation to the registered
service and inventory revision. Legacy project identities and cache keys carry
forward. The controller reads bounded, same-snapshot evidence over UID-checked IPC,
reports incomplete coverage, and advances existing incidents during scanner failure.
The executor checks the live revision, deployment fence and exact running image for
automatic admission and route restoration. The existing release guard stays in place.
The focused suite passed 364 tests after one independent diff review. On VM102,
3084 tests passed, 3 required a checkout, and Ruff and production Ansible-Lint passed.
The wired VM batch, B08 and V03 acceptance, and notifier evidence remain open.

### 2026-11-24 — M5 / L10 step 3: version-bound Apply in the browser

The configuration page refreshes after Save and Apply, shows the full head and
applied revisions and the release bound to the plan, and tracks the submitted job
to its durable outcome by ID. Polling and conflicts preserve unsaved YAML and the
change note. Playwright passed seven browser cases against the actual API with a
disposable executor fixture. The Apply case covered 409, 403 and 422 refusals,
queued to running to succeeded, and outcome after reload. The focused API/apply
suite passed 68 tests, including queued-job recovery after app recreation.
VM102 completed 3087 tests, skipped 3 requiring a checkout, and passed Ruff and Ansible-Lint.
Prior VM104 evidence covers host apply, adoption and G1c. Both G2 attempts left
consistent files and missed the mid-write window. G3.4 still needs `projects.update`.
The 2026-11-25 preflight found the restored VM104 `notes` fixture. VM103 and VM104
list only their live state. The installed browser gate awaits a fresh disposable `shop`
fixture with a verified restoration path for durable revision, job and audit records.

### 2026-11-24 — M2 / V03: owned VM103 provider outage and recovery

On the installed `161bfbe` scanner the second, OSV-only outage attempt blocked five
scanner-UID connections. All 452 OSV subjects were unavailable, and the scanner,
collector and authenticated API agreed on the snapshot and incomplete coverage.
The temporary table was removed, the original firewall hash matched and the next
ordinary job recovered 352 checks on the same inventory and scanner PID. The API
and installed Chromium view showed the remaining 100 timeouts and one stale image.
The browser harness exited on a post-logout check; the API audit logged both browser
logouts, and the scripted API session independently verified revocation. No notifier
was active. The controlled HTTP 429/restart, inventory/image and source-failure
receipts retain their [archived scope](status-archive.md#v03-provider-cooldown-im-installierten-dienst-über-neustart).
Private receipts: `.steward/pool/103/receipts/r03-v03/outage2.FGlehhuy/`.

### 2026-11-25 — M5 / L09 step 2: guarded deployment retirement

Private schema 2 deployment derives the removal roster from the reviewed
applied and desired registries. It inhibits boot, drains routes and stops
the removed application before archiving. Verified release receipts gate
cutover and terminal verification. Exact resume reuses the bound archive
and preserves pending UI edits. The installed host needs the retirement-capable
release before removal. Ordinary upgrades and manual retirement retain their paths.
The focused suite passed 232 Python tests plus the boot-role and guarded Ansible
cases after one independent review. On VM102 3118 tests passed, 3 required a Git
checkout, and Ruff and production Ansible-Lint passed. The automatic-path host
gate remains open and B08 still gates acceptance.

### 2026-11-25 — M6 / A02 step 1: package the local Ollama profile

The guarded platform render path installs the fixed amd64 Ollama archive and an
explicitly selected offline model bundle. The installer verifies the published
runtime SHA-256, exact manifest bytes and every referenced blob before publishing
root-owned artifacts. The dedicated CPU service is isolated in a private network
namespace with cloud features disabled. Public activation requires release
acceptance. The controller verified and extracted the official v0.40.18
archive (1.65 GB compressed, 2.67 GB regular files) and verified all six
`smollm2:135m` fixture blobs. The focused suite passed 268 tests with 2 skips after
one review. VM102 completed 3140 tests, skipped 3 requiring a checkout, and passed
Ruff and production Ansible-Lint. The integrated refusal and VM inference gates
remain open.

### 2026-11-25 — M6 / A02 step 2: installer refusal checks

Eight fixed-entry-point cases use temporary staging and synthetic host facts.
They cover RAM, runtime and model disk space, missing configuration or bundle,
wrong tag, requested pull and GPU access. Every refusal emits a diagnostic and
leaves the artifact trees empty. The role test binds installer success to unit
installation and service activation. The focused suite passed 65 tests after
one independent review. VM102 passed 3148 tests, skipped 3 requiring a checkout,
and passed Ruff and production Ansible-Lint. Runtime isolation and inference
still need VM evidence.

### 2026-11-25 — M6 / A03 step 3: direct Ollama Cloud API key

The guarded `ollama-cloud-api` config requires an external data-sharing scope,
monthly token budget, key reference and explicit model. The adapter uses fixed
HTTPS endpoints and Bearer authentication. The inference contract validates
the response locally and records bounded usage. Ollama's public catalog returned
25 entries including `deepseek-v4.1-flash`. Chat with measured usage and a
credential-redaction check needs an authorized live provider gate.
The focused contract suite passed 296 tests with 4 skips after one review.
Schema generation added one provider enum value. VM102 passed 3189 tests with
5 skips, Ruff and production Ansible-Lint.

### 2026-11-25 — W25: A04 provider eligibility and login contract

G4.0 checked official docs and tagged code. Ollama native login needs an isolated
cloud-enabled daemon and verified account/disconnect. Claude and ChatGPT subscription
eligibility for this workload remains unconfirmed. Each method has a distinct refusal
and no executable command or assumed exit-code mapping. G4.1–G4.3 still need an eligible
integration and authorized live login/revoke. Local and direct API-key paths are separate.
VM102: 3,195 passed, five skipped. Ruff and Ansible lint passed.

### 2026-11-25 — W26: A02 local model store and disable corrections

VM104 G2 attempt 1 (`9f3ad30`) installed the checked binary and six model blobs and
started Ollama as `steward-ai` in its loopback-only namespace. The stopped probe
returned `unavailable` with zero tokens. Model listing returned HTTP 500 because
v0.40.18 requires `manifests-v2/` in the read-only store. The base role also missed
its own unit because Ansible preserved literal backslash-n in the marker.
VM104 was restored and its executor audit validated. Private receipt
`.steward/pool/104/receipts/m6-local/attempt-1.b5WrjM/g2-results.md`.
W26 verifies or repairs the empty v2 directory, disables startup pruning and compares
the unit header as three lines. VM102: 3,198 passed, five skipped, Ruff and Ansible lint.
Attempt 2 remains open. A disposable controller probe with a longer deadline counted
the clean items correctly, and the hostile test returned an incorrect count.

### 2026-11-25 — W27: A05/A07 initial provider setup in the admin UI

The page saves a chosen provider through the session-bound, CSRF-protected API.
Ollama Cloud API-key setup uses the A03 adapter. Native sign-in and subscriptions
show the recorded refusal reason. Remote scans and report requests display their
queue state. A model suggestion requires a unique exact match in that provider's
scan. Local setup requires an explicit artifact declaration and queues its initial
check after checksum verification. The page supports first setup. Provider
replacement remains a separate open lifecycle issue.
VM102 reported 3,202 passed and five skipped, with Ruff and Ansible lint green.
Production web build and eight Chromium tests passed with a real local API and an
offline catalog. Live inference, downloads and report execution still need wiring.

### 2026-11-25 — A02 G2 CPU candidate verified on VM104

Attempt 2 used merged `321b259`, normal site deployment and the private renderer
overlay for Ollama. The pinned v0.40.18 local service listed the exact checked
`smollm2:135m` digest and ran as `steward-ai` in its loopback-only namespace.
The clean answer passed in 1.76 s, the ledger matched 1,361 tokens across both calls,
and service peak was 954,273,792 bytes. Host IPv4/IPv6 and second-host NIC access
failed. Process traces found zero non-loopback calls. Stopped and missing-model
cases were denied with no tokens or fallback. The repeated installer was unchanged,
and the unit and model stayed stable. Normal base deployment disabled Ollama.
The original fixture and Proxmox forwarding were confirmed restored, with 17 valid
audit records. Two observer wrapper errors were reconciled from direct attestation
and raw captures. The hostile count was wrong and the live at-limit case remains
undemonstrated. The public guards remain. Private evidence:
`.steward/pool/104/receipts/m6-local/attempt-2.PUHErZ/g2-results.md`.

### 2026-11-25 — W28: A05 scheduled model selection worker

The one-shot worker consumes local admin requests with an applied-policy and provider
binding. Weekly and best-now share one durable evaluation slot per maintenance window
and keep separate evaluation ledgers. Activation rechecks the pin, kill switch,
source consensus, window and active decision. Reports preserve measured tokens when
the cost is unknown. Older valid setup state is retained. Unbound pending and
interrupted requests require resubmission.
VM102 passed 3,231 tests, with five skipped. Ruff, Ansible lint, the web build and all
eight Chromium tests passed. This uses synthetic providers. Host work needs the
trusted projection writer, isolated identity and credential, authenticated API
handoff and timer. Live G5 depends on G3, bounded authorized spend and fresh sources.

### 2026-11-25 — W29: A05 admin handoff to the isolated worker

A selected Unix peer owns the request queue and read model. Both directions use kernel
UID checks with bounded framing. Peer failure yields HTTP 503 and keeps the selected
backend. Replaying the same key after a lost reply uses the worker's original durable
result. A managed listener is adopted without replacing the socket path.
VM102 passed 3,281 tests with five skipped, plus Ruff and Ansible lint. The web build
passed. All eight Chromium cases passed across runs. Two existing configuration tests
timed out in the first full run and both passed a focused rerun with the same code.
Local isolation tests used one UID and separate data directories. Host policy publication,
managed service and timer, and the different-UID acceptance gate are still pending.

### 2026-11-25 — W30: guarded local inference deployment

The private schema-1 candidate binds its policy to the unchanged applied revision,
verified release and staged CPU model. The site publishes after installed-object
checks and verification. The shared deployment lock serializes marker updates,
withdrawal and compare-and-clear. Baseline deployment withdraws the policy and
disables managed starts. The control service adopts the manager-owned socket under
a distinct identity. A minutely tick joins Ollama's private network and keeps its
own temporary mounts. Its only candidate provider operation is listing the pinned model.
VM102 passed 3,319 tests with five skipped. Ruff, Ansible lint, the web build and all
eight Chromium tests passed. The public AI release guards remain in place.

### 2026-11-25 — W30: VM104 deployment and inventory evidence

Attempt 1 on merged `2dc1b77` deployed the guarded candidate at the unchanged canonical
revision. Systemd identities, both kernel peer UIDs and the file-access denials were
measured. An authenticated TLS admin scan ran on the timer in Ollama's private loopback
namespace, listed exactly `smollm2:135m` and replayed without a second runtime call.
Same-SHA withdrawal stopped the worker and Ollama and removed the policy and listener.
Restoration to `161bfbe` matched the protected, release and Ollama hashes, and the audit
chain grew from 22 to 28 valid records. Normal cleanup retained disabled managed files,
private synthetic worker state and a migration of the empty API onboarding schema.
The scoped live result covers deployment and inventory. Wrong-UID peer, selected socket
outage, runtime stop/restart, stale publication and lost reply were not exercised live.
G5 external evaluation stays open. Private receipt:
`.steward/pool/104/receipts/m6-local/g-deploy-prep/attempt-1.HhfX1LkH/attempt-notes.md`.

### 2026-11-25 — W31: signed bot advice over local inference IPC

The signed bot route checks identity and grants before gathering. A separate UID-pinned
Unix listener accepts only the bounded `advice.answer` contract. Scoped observations,
question masking and partial collector gaps are handled before inference. The worker
enforces sharing policy before budget reservation. A pending reservation prevents a
replay from repeating inference and keeps the deterministic commands available.
Local signed HTTP and real Unix socket checks with a synthetic provider and real
ledger passed (222 tests). VM102 passed 3,376 tests, five skipped, plus Ruff and
production Ansible lint. The local socket uses the test account. Installed distinct
UIDs, actual provider advice and browser rendering remain G6 work. Advice is off by
default and public AI guards remain in place.

### 2026-11-25 — W32: read-only admin advice and hostile-text browser check

The authenticated Overview submits only the bounded question. The API derives the
existing host-wide admin scope after Origin, session and CSRF checks. The shared
collector reader detects overflow and keeps incomplete evidence visible. The UI
renders the existing advice and gaps as text. G6.5 passed through the real browser,
HTTP API, Unix listener and budget ledger with a synthetic provider. Tests exercised
hostile content, rejected input before gathering, exhausted budget, listener outage,
deterministic views and zero advice-triggered executor calls. The production build,
all nine Chromium tests and 3,378 VM102 tests passed, with five skipped on VM102.
Ruff and production Ansible lint passed. An initial suite assertion treated the six-row
advice overflow probe and five-row deterministic query as identical. The corrected
suite verified both. The installed advice peer and actual provider gate remain open.

### 2026-11-25 — M2 / V02: same-site independent lab receiver

The real Collector redacted a synthetic export and served it through Unix IPC.
Separate notifier processes used its durable outbox and both normal adapter codecs.
A process-local HTTPS seam reached only CT 9212 through pinned TLS. The signed receiver
stored the acknowledgment, then recognized the same body and ID after interruption.
The Discord simulator returned 429, and the persisted cooldown survived restart before
the retry received a simulated message ID. Replaying the source added no deliveries.
The released public destination policy, real Discord, and independent heartbeat and
audit-anchor gates remain open. Private receipt: `.steward/v02-sidecar-4naw9afO/receipt.json`.

### 2026-11-25 — W33: package the guarded local Ollama advice candidate

An explicit opt-in wires the signed bot and authenticated API to separate, kernel
credential-checked sockets and one serial Ollama worker with a shared A01 ledger.
The verified deployment, installed manifest, exact response model and kill switch
fence admission, dispatch and reply. Managed bot replay preserves its original request
record and returns a gap without dispatch. Publication verifies both listeners, and
their lifecycle changes recycle the worker. The existing advice deadlines apply.
The combined code passed 3,430 VM102 tests with five skipped, Ruff, production Ansible
lint, 146 executable guardrail cases and all nine Chromium checks. The lead's local
site syntax check lacked `ansible.posix`. The runner's production playbook lint passed.
Public AI guards remain.

### 2026-11-26 — M6 / A06: W33 installed boundaries on VM104

Exact `6236194` base, private candidate and same-release withdrawal deployed through
the normal site. Four service UIDs were distinct. Both advice sockets rejected the
wrong UID. The worker and Ollama shared a private namespace. Bot and worker probes
verified denied access to the recorded state and executor paths. Pinned TLS and
admin login/logout passed. The first attempt stopped before deploy on a fixture
path type error. In the second, the Collector seeder hit a root-only DMI UUID
read before writing either fixture event, so zero native model calls ran. G6.1
positive exchange and G6.2–G6.4 remain open after two attempts. Withdrawal cleared
the sockets and staging state. Native restore reproduced the original 24 GiB
disk hash before boot, then verified the SSH pin, baseline services and audit prefix.
Private receipt: `.steward/pool/104/receipts/m6-w33-g6-6236194-r2/attempt-notes.md`.

### 2026-11-25 — M2 / B08: same-site Restic worker and restore

Unmodified `78b7b44` ran in private VM103 scratch as UID 1000, using the native
endpoint pin, verified Restic 0.19.1 and TLS to CT 9211. The real export, imports,
worker and ledger used a synthetic capture and fixture permit. One encrypted snapshot
passed `check --read-data` and exact restore verification. A separate read-only client
compared 1,326 bytes and the empty directory. Worker replay preserved the ledger and
adapter replay reused the snapshot with no extra packs. Wrong pin was refused before
connection, wrong credentials and passphrase failed, and wrong CA timed out after 30 s.
The harness resumed the verified empty repository after that timeout. VM103's staged
files were removed and independently checked. Deployed admission, retention and
geographic scope remain separate. Private receipt: `.steward/b08-vm103-7q9MKP9iNvVs/receipt.md`.

### 2026-11-25 — M5 / L10: installed browser Apply on VM104

Stock offline deployment of the exact `4885943` UI and runtime passed on the fresh
disposable fixture. Installed Chromium applied `shop.maintenance.allow_restart: false`.
The exact plan bound both revisions. The job stayed `succeeded` after reload, and UI,
desired state, registry and executor agreed. Both workload invocations, PIDs and
restart counters stayed unchanged. The audit contained one applied entry. Logout
revoked the browser session. Native restore matched the original 24 GiB disk digest
before boot, followed by pinned SSH, durable state, audit prefix and service checks.
Boot ID and `vmgenid` changed as expected. The first checker misread the VMA description
comment. A corrected check and fresh verified archive preceded the reset. Both private
archives were retained. G2 mid-write and G3.4 remain open. Private receipt:
`.steward/pool/104/receipts/m5-browser-4885943.VHwYoHQA/attempt-notes.md`.

### 2026-11-25 — W34: fixed ECB source for budget exchange rates

The explicit ECB parser accepts the exact daily HTTPS URL and a bounded XML feed.
Source and parser bind the stored observation. The guarded general worker only
refreshes with external access enabled and rechecks policy, kill switch, window and
lease. FX and weekly selection claim their exact maintenance jobs. The controller
probe made one TLS connection to a checked public address, stored `912160` ppm
dated `2026-11-24`, and refused a second fetch in the same window. Cost-limited
reservations deny stale or missing rates. Applying conversion to price arithmetic
needs explicit price currency. The deployed scheduler remains behind the AI guard.
VM102 passed 3,487 tests, five skipped, plus Ruff and production Ansible lint. All 146
current guardrail cases passed in the refreshed locked environment. Schema matched.

### 2026-11-25 — W35: R01 canonical SSH repository URLs

SCP-style input is normalized before effective config and revision hashing. Relative
paths use `ssh://user@host/~/path`, and absolute paths retain their location. An
absolute `/~` SCP path is refused because it would change meaning in Git's SSH URL.
The canonical URL is visible in effective config and diff. SSH host-key and credential
requirements and the repository availability guard still apply. Six local Git calls
resolved the expected refs. Regenerated schema matched. VM102 passed 3,498 tests,
five skipped, plus Ruff, production Ansible lint and all 146 guardrail cases.

### 2026-11-25 — M2 / B08: VM101 timed retirement

The saved VM receipt shows the exact acknowledged `notes` test copy removed at
21:13:32.145 UTC, 9.915 seconds after its seven-day threshold. The retire phase
verified the post-operation inventory and audit chain. The wrapper's final `check`
failed because it expected pre-retirement inventory. A separate read-only VM check
at 23:06:23 UTC found exactly five captures (three originals and two controls),
all three original imports, the target absent, no open intents, and 809 valid audit
records. `notes` stayed active and the backup service stayed inactive. The
geographically independent restore and remaining activation gates remain open.
Private receipt: `.steward/b08-candidate-private/retention-age-vm101/receipts-2026-11-25-retire/`.

### 2026-11-26 — W36: scoped application instructions for repository proposals

The optional operator instruction comes from the configured application and exact
source receipt. Repository additions and documents are redacted, lower priority and
untrusted. Deterministic contract precedence and canonical revisions with the field
unset are preserved. Review fixes bind inspection to the stored receipt and let a
repository rename refresh its receipt while keeping the same Git object store. The
full suite exposed a repair compatibility regression. Repair receipts now bind the
candidate to its fetched parent and enforce the configured pin against that parent.
Regenerated schema matched. VM102 passed 3,517 tests, five skipped, plus Ruff and
production Ansible lint. All 146 guardrail cases passed on the larger test filesystem.

### 2026-11-26 — W37: package the scoped repository fetch candidate

The manual, non-root one-shot binds one repository, full commit and numeric TCP
endpoint to the installed revision and verified live nftables policy. Normal
deployment revokes and drains the unit and removes its credential before changing
policy. The private source store is kept. A local network namespace verified per-UID
IPv4 and IPv6 destination and port limits, including rejection after DNAT. The lead
ran 546 focused checks and 12 Ansible fixture cases. VM102 passed 3,566 tests with
five skipped, Ruff and production Ansible lint. All 146 guardrail cases passed.
Installed unit, credential and reboot checks remain part of the M7 host batch.

### 2026-11-26 — M7: installed SSH batch attempt 1 on VM104

The stock, isolated guest at `8187c6c` booted over pinned SSH and passed
offline staging and preflight. The base deploy reached host verification
at 03:34:40 UTC. The admin proxy check exhausted six retries and the
saved final response was 502 instead of 401. Ansible recorded 138 OK,
54 changed, one failure and zero
unreachable. W37, W40 and W41 repository checks were unexercised. An
independent readback confirmed the restored original's cold disk hash,
hardware, pinned SSH, baseline revision, live notes and proxy health,
and the 53-record audit prefix. A retry needs captured API, proxy and
local network evidence before reset. The cause of the 502 remains open.
Private receipt: `.steward/pool/104/receipts/m7-8187c6c/attempt-notes.md`.

### 2026-11-26 — W38: scoped operator egress rules for repository approval

R04 approval checks the validator signature and the exact validated workload
contract against the current canonical config for the mapped application service.
Every proposed CIDR, protocol and port must be covered by repository-scoped
operator rules or existing managed egress to waive a one-off confirmation. Older
attestations without signed egress evidence need explicit confirmation. With the
new rules unset, revisions and renderer output are preserved. Schema regeneration
matched. The lead ran 294 focused checks. VM102 passed 3,613 tests with five
skipped, Ruff and production Ansible lint. All 146 guardrail cases passed.
Registry/probe integration and the deployed approval path remain open.

### 2026-11-26 — W39: shared minimum build isolation

`build.minimum_isolation` is shared by backend selection, build reuse, validation
and cached acceptance. Callers can impose a stricter floor. Revoking the container
opt-in rejects that recorded tier. The unset field preserves canonical revisions.
Schema parity, 146 local guardrails and 3,474 remaining local tests passed, four
skipped. The first VM102 run hit an API fixture SQLite open error. The unchanged
tree rerun with a disk-backed pytest base passed 3,619 tests, five skipped, Ruff
and production Ansible lint. The installed R03 and R04 paths remain open.

### 2026-11-26 — W40: exact offline source handoff to the builder

The manual handoff reads one pinned commit under the fetch UID. Root seals a
bounded copy in a new read-only file. Withdrawal revokes it under the deployment
lock and drains the services after releasing that lock. The builder independently
verifies Git objects, re-derives the contract and dependency inventory and checks
the input digest before build or reuse. Legacy fetch and repair paths are covered.
The lead fixed two review findings. On the exact combined tree VM102 passed 3,674
tests with five skipped, Ruff and production Ansible lint. All 146 local guardrail
cases passed. The installed builder must supply the current job binding and lease.

### 2026-11-26 — W41: packaged offline builder input verification

The one-shot verifies the exact W40 handoff under the dedicated builder UID and
binds its proof to the installed release, applied revision, scope, generation and
input digest. A private job ledger supports one lease-expiry retry. Final proof
requires a current root readback under the deployment lock and has `authorizes: []`.
Withdrawal revokes authority, then drains the service and verifies its cgroup.
The lead ran 166 focused checks and 12 site fixtures. VM102 passed 3,698 tests,
five skipped, Ruff and production Ansible lint. All 146 local guardrails passed.
Installed verification and stock engine execution remain open.

### 2026-11-26 — W42: rootless build job scope verification

The rootless backend checks the configured account and user-manager sockets and
uses a full-job-ID scope for Podman. The scope helper checks its own cgroup and
kernel memory, swap, CPU and task limits before invoking the fixed engine.
Lease loss prevents further work. Cleanup proves that the job scopes are empty
and keeps a workspace that still needs reconciliation. Local fixtures passed
123 builder and 239 adjacent tests. VM102 passed 3,751 tests with five skipped,
Ruff and production Ansible lint. All 146 local guardrails passed. Disk usage is
still polled, so packaged execution needs a kernel-enforced per-job quota.

### 2026-11-26 — R03: packaged execution storage prerequisite

The current Podman launch can reach shared rootless runtime state. A fresh,
root-controlled launch boundary must restrict every build and helper write to a
kernel-bounded job filesystem, including source export, spool, runtime and graph.
The stock candidate needs a provisioned storage slot and trusted job assignment,
verified block and inode limits and exclusive writable paths. VM103 readback
showed its ordinary ext4 root with no separate builder storage or installed builder
egress attestation. G1 already exhausted both attempts. `build` remains guarded.

### 2026-11-26 — W44: digest-only OCI registry adapter

The validator adapter verifies exact manifests and blobs over pinned, separate
HTTPS endpoints, then independently reads back the promotion target by digest.
The target credential and caller UID are scoped to the validator. Fixture cases
cover redirects, replacement, framing, deadlines and idempotent retry. The lead
passed 140 focused checks with a loopback HTTPS registry mock. VM102 passed 3,783
tests with five skipped, Ruff and production Ansible lint. All 146 local guardrail
cases passed. The adapter supplies digest evidence. Independent inventory,
signature policy, runtime probes and live registry interoperability remain open.

### 2026-11-26 — W45: verify an independent image inventory offline

The OCI adapter verifies compressed blob digests and uncompressed layer hashes,
then runs pinned Trivy against a private OCI layout in a socket-free sandbox.
The manifest-bound package inventory joins the exact lockfile inventory. Missing,
unsupported or failed scans withhold inventory and block promotion. Current
support covers plain and gzip layers and requires Bubblewrap with user namespaces.
The native Trivy 0.76.2 fixture detected Alpine, npm and PyPI packages. The lead
passed 238 focused checks. VM102 passed 3,812 tests with six skipped, Ruff and
production Ansible lint. All 146 local guardrails and the native test passed on
the final tree. Runtime probes and live registry acceptance remain open.

### 2026-11-26 — W46: reject unobserved repository migration

A stateful candidate with unknown migration evidence or a compatibility probe
timeout cannot be promoted, signed or reused. Older ambiguous cached reports need
revalidation. The lead passed 112 focused tests, with one independent review.
VM102 passed 3,816 tests with six skipped, Ruff and production Ansible lint. All
146 local guardrail cases passed. The runtime probe needs a pre-provisioned slot
with a distinct credential-free UID, verified cgroup limits, exclusive bounded
scratch, exact OCI handoff and trusted process and network observation. Host
acceptance remains open.

### 2026-11-26 — R04: stock registry interoperability fixture

Two stock Ubuntu Distribution `2.8.3+ds1` processes used separate Basic credentials
and pinned loopback TLS on the controller. The adapter inspected an exact synthetic
OCI image and cached Trivy 0.76.2 found the two expected packages. Promotion and
same-digest retry succeeded. An independent TLS GET returned the exact OCI manifest
at the otherwise empty target. Both fixtures and credential paths were removed.
Installed identity and application runtime/deployment remain open. Private receipt:
`.steward/r04-stock-registry.uahbGEp8/result.log`.

### 2026-11-26 — W47: bind repository compatibility and scans to the validator

Approval issuance and executor validation/apply require the validator's explicit
signed compatibility and matching fresh scan for repository evidence. Historical
ambiguous repository evidence needs revalidation. Unmarked L04 evidence retains
its existing path. G14 exercises denial before a claim or workload change. The
lead passed 326 focused checks on a disk-backed rerun. VM102 passed 3,839 tests
with six skipped, Ruff and production Ansible lint. All 148 guardrails passed.
Decision 25 still needs installed application-service update targets, trusted
health and backup evidence, an independent automation key and atomic withdrawal
of pending approvals. `repositories` and `projects.update` remain guarded.

### 2026-11-26 — W48: bind repair publication to the tested Git commit

New and existing pull requests must match the exact independently validated
head commit, deterministic repair branch, base branch and repository. An exact
retry reuses the PR. A conflicting or incomplete forge response preserves the
local patch and fails publication. The lead passed 86 focused cases and one
independent review. VM102 passed 3,847 tests, six skipped, Ruff and production
Ansible lint. All 148 local guardrails passed. Live forge and runner are open.

### 2026-11-26 — W49: private repair handoff for an exact PR head

After independent validation, the existing private repair record retains the
fetched repository and ref, base and validated head commits and deterministic
head branch. The publication path uses this same branch. A local handoff carries
`authorizes: []`. GitHub PR creation takes mutable branch names. A live test
requires custody of the exact prepared head and an authorized destination. The
lead passed 86 focused checks and one independent review. VM102 passed 3,847
tests with six skipped, Ruff and production Ansible lint. All 148 guardrail
cases passed. The installed repair path stays gated.

### 2026-11-26 — M2 / B08: recovery scope and site prerequisite

The saved B07 acceptance at `a8ee3d2` passed VM100 → encrypted repository → fresh
VM101 with separate read-only proxy credentials, exact tree and SQLite verification,
and health, note and attachment readback. The reusable driver passed on the same
owned guest pair. Both guests and the repository shared `cn-0001`. The operator
confirmed that no second site is available. The offline PC recovery evidence and
the RC1 scope decision are recorded below.

### 2026-11-26 — requested small cross-guest backup after the host reboot

VM103 uploaded four synthetic files with Restic 0.19.1 to an encrypted, append-only
fixture in CT 9211 on `cn-0001` `local-lvm`. VM104 verified the same repository and
snapshot over pinned TLS 1.3, ran `check --read-data`, restored the exact snapshot
with `--verify` and compared 9,246 bytes, two SQLite rows and an empty directory.
Both guest scratch paths were removed and independently checked over pinned SSH.
The test used a one-run passphrase and the shared lab endpoint account. Independent
site recovery remains open. Private receipt: `.steward/backup-short-cross-guest.E9LrV9X6/result.log`.

### 2026-11-26 — requested B08 controller backup and offline restore

VM103 created a small encrypted Restic 0.19.1 snapshot. Pinned SSH carried the
encrypted repository to the controller's local SATA disk. VM103's scratch was
removed before recovery. The controller had a distinct machine identity and ran
`check --read-data`, exact verified restore, SHA-256 and SQLite checks in a
loopback-only namespace. A fresh QEMU guest on the controller with no NIC repeated
the full repository check and verified the same 9,264 bytes and empty directory.
The first guest hit its limit after the file hashes passed, before its final marker.
The retry exited cleanly, and both restore workspaces were removed. The operator
accepted this result for the RC1 off-host recovery gate on 2026-11-26. It covers
loss of `cn-0001` and its storage for the synthetic copy. A site-wide outage
is outside the tested scope. The installed activation gates remain open.
Private receipt: `.steward/b08-pc-offhost.KjcgMGka/offline-vm-result.log`.

### 2026-11-26 — private CT9213 stock ROCm/GTT fixture

Unprivileged CT 9213 on `cn-0001` used stock ROCm 7.2 and Ollama 0.40.18 on
`gfx1151`. The pinned Gemma 4 26B image answered the single synthetic chat and
the runner logged all 31 layers on the GPU. Device GTT rose by 17.608 GiB, dedicated
VRAM by 0.691 MiB. Both returned to baseline after unload. Host memory stayed at
least 87.424 GiB available. The sampler recorded device-wide counters and the
runner journal. CT 9213 stays running with an empty model list and guest-loopback
access only. Product G6 remains open. Private receipt: `.steward/lxc-validation/ollama/preflight-2026-11-26/own/runtime.jsonl`.

### 2026-11-26 — W50: offline signing of a prepared release archive

`release sign` verifies the prepared unsigned payload, retains the exact
manifest, and writes a deterministic archive with an Ed25519 signature. The
existing verifier checks it against a separately supplied public key. Two
offline runs on the exact `8187c6c` development archive produced byte-identical
signed archives with a disposable key and preserved the original archive.
VM102 passed 3,873 tests, with six skipped, plus Ruff and production Ansible
lint. All 148 guardrail cases passed. The operator's RC1 signature and mandatory
deploy verification still await their own gates.

### 2026-11-26 — W51: verify the release archive before deployment

Starting at RC1, ordinary deploy and exact resume require a matching signed
archive and an independently supplied public key before remote preflight.
The existing development path is available by explicit exception. The
private verified payload stays in scope through Ansible and exact resume
keeps its release binding. The independent review identified Ansible's
automatic Vault decryption. Verified deploy refuses Vault-formatted bundle
files so the copied files match the signed bytes. VM102 ran 3,905 passing
tests, six skips, Ruff and production Ansible lint. All 148 guardrail cases
passed. The exact development archive passed the offline CLI smoke with
disposable keys. The real signed RC1 host batch remains open.

### 2026-11-26 — W52: RC1 version and candidate scope

The controller runtime, wheel metadata and root lock entry use
`0.1.0rc1`. The dependency pins and exported controller hashes are
identical. The candidate lists the prior Stage 1 single-host baseline,
configuration recovery, the bounded scanner baseline and measured
maintenance and health paths. The L02 private renderer evidence remains
recorded. S02 additional profiles and S03 public administration are
unsupported. VM102 passed 3,905 tests with six skips, Ruff and production
Ansible lint. All 148 guardrails passed. The operator-signed RC1 archive
and its host acceptance remain open.

### 2026-11-26 — S01: exact unsigned RC1 candidate built offline

The clean `743d7214b277a69ab3b807bbe30239f0843ad030` checkout packaged
`steward-0.1.0rc1-unsigned.tar.gz` twice with identical bytes. SHA-256
`a357621d01982ac2910053070dd45746ca724e8fca4a65769998b2dabd837cc2`.
The archive matched every manifest hash, wheel metadata, bundled UI,
97-component SBOM and source provenance. A disposable offline signature
verified. Actual RC1 deploy and resume rejected absent signatures,
unsigned artifacts and a wrong key before configuration or host preflight.
A valid signature reached local config loading. The test keys and signed
copy were temporary. Private receipt: `.steward/rc1-0.1.0rc1/build-receipt.json`.
The operator signature and exact-archive host acceptance remain open.

### 2026-11-26 — W53: protected-ref unsigned release build job

The manually dispatched GitHub job requires the canonical repository's
protected default branch and checks out the full event SHA. It builds an
unsigned archive, checks frozen exports and provenance, and records the inner
archive digest separately from the GitHub artifact wrapper digest. All action
references and build constraints are pinned. The independent review, Actionlint,
GitHub expression evaluator and a clean local build and pack smoke passed.
The parent also verified the frozen `743d721` archive with the workflow helper.
VM102 passed 3,924 tests with six skips, Ruff and production Ansible lint.
All 148 guardrail cases passed. Hosted protection and execution remain open.
The operator keeps the signing key offline.

### 2026-11-26 — M7: second installed SSH attempt and route diagnosis

At `8187c6c`, the restricted disposable VM104 again finished the base
admin check with HTTP 502. W37, W40 and W41 were unexercised. The active
API answered the direct loopback probe with HTTP 421 for its Host header.
Traefik's live namespace returned `ENETUNREACH` for `169.254.1.3:9080`,
with no observed firewall counter movement. The restored original guest
had a route to the alias and returned HTTP 401 through its proxy. The
disposable namespace's missing route is proven. Its cause is unverified.
Independent readback verified exact restored cold disk, hardware,
revision, pinned SSH, healthy services and the 54-record audit prefix.
Both native archives were retained. The M7 attempt budget is exhausted.
Private receipt: `.steward/pool/104/receipts/m7-8187c6c-r2/attempt-notes.md`.

### 2026-11-26 — W54: pinned healthy-container fixture and transport defect

The G8 runbook now uses the upstream File Browser v2.63.23 linux/amd64 digest
with the stock entrypoint and healthcheck. Rootless Podman returned healthy and
exit 0 with networking disabled and a previously empty config volume. The
normal controller renderer and Quadlet dry-run passed. On stock Podman 5.7, the
same image lost its embedded healthcheck in Steward's OCI save format. A
Docker archive retained the exact command and timings. G8 remains open on
the installed path. Receipts are under `.steward/l03-g8-upstream-fixture/`.
VM102 passed 3,924 tests with six skips, Ruff and production Ansible lint.
All 148 guardrail cases passed.

### 2026-11-26 — W55: preserve container health checks in project image transport

Ordinary projects with the container probe use an archive that preserves the
exact image config ID. The project checks the rootless tag after loading and
recreates a running container that still uses the old ID. Protected offline
archives remain usable. A legacy OCI archive without its pinned source can
still lack the original health check. A failed load gets one rebuild from that
source. A disabled project stops before image transfer.
Stock Podman formats and stale-tag migration were checked locally. VM102
passed 3,966 tests with six skips, Ruff, production Ansible lint and all 148
guardrail cases. The fresh guest G8 gate remains open. Private evidence is
in `.steward/w55-parent/` and `.steward/l03-g8-upstream-fixture/`.

### 2026-11-26 — L03: G8 VM103 attempts exhausted before deployment

Both attempts stopped before any disposable disk or deployment. The first
custody run refused the single space Proxmox returns for the detached boot
order. The parent reattached the exact LV and verified its cold SHA-256,
revision, service health and audit prefix. On the second attempt QEMU still
held the command lock inherited during that recovery. The shutdown call
exited before a Proxmox task was created. VM103 was verified running on the
original LV with the same boot ID and application revision. G8 remains
deferred for RC1. The next applicable fresh-guest batch needs custody that
does not pass its lock descriptor to QEMU. Private receipts are in
`.steward/rc1-0.1.0rc1/m8-prep/g8-attempt-1/` and `g8-live-r2/`.

### 2026-11-26 — private LAN administration for RC1

The new deployment quick start discovers one directly connected private IPv4
address or uses an explicit interface and prefix. It binds HTTPS to that address
and admits the configured client CIDRs. Numeric IP TLS works with the server CA.
The loopback tunnel and private bot route remain available under their existing
authority. The old configuration and revision keep their existing meaning.
VM102 passed 4,025 tests with six skips, Ruff, production Ansible lint and all
148 guardrail cases. Nine production-bundle Chromium tests passed. Isolated
network tests checked IPv4 and IPv6 denial and withdrawal of live connections.
The VM104 acceptance and final release signing remain open.

### 2026-11-26 — legacy inference withdrawal on release upgrades

The VM104 upgrade stopped before bootstrap because its old release had an
empty root-owned inference directory without the revocation module. The
site role now checks the two protected authority files before requesting
revocation. Either file still requires successful revocation, and an unsafe
authority directory stops deployment. VM102 passed 4,035 tests with six
skips, Ruff, production Ansible lint and all 148 guardrail cases. The first
VM104 attempt left the old applied revision and its deployment marker intact.
Private evidence is in `.steward/admin-lan/`.

### 2026-11-26 — private LAN admin acceptance on VM104

The exact `4ad5ab2` test archive upgraded the existing installation and
resolved its attached IPv4 interface on the normal LAN deploy. VM104 kept its
original boot, Notes database, CA and audit prefix. The API stays on loopback.
Laptop traffic from `10.80.155.113` reached `10.10.1.3:9443` through the
source-scoped Proxmox relay. TLS verified the IP without SNI. Login, session
and logout passed. Incorrect Host, Origin and CSRF cases were refused.
The relay admitted the expected laptop source and counted a drop on the wrong
ingress interface. The home prefix is configured. A direct bridged home client
remains untested. The test lease expires at 07:44 UTC on 2026-11-27.
Private receipts are in `.steward/admin-lan/live-vm104/`.

### 2026-11-26 — S01: clean unsigned RC1 candidate with private LAN admin

Commit `5765ef12362963e18c2189aa111673d17b2e6832` built offline. Two packs
matched byte for byte. The unsigned archive SHA-256 is
`49ea8e915120ef864c94995248a8e14365480c1adf1d1c4ba0ddfe3256bfa996`.
All manifest artifacts and attestations matched. The wheel contained the
exact checked runtime source and production UI. Its 97-component SBOM and
provenance match the archive and record a clean checkout. S01's offline input
check verified the saved upgrade cache and equivalent baseline config.
The operator signature and signed-archive VM batch remain open.
Private receipt: `.steward/rc1-0.1.0rc1-5765ef12362963e18c2189aa111673d17b2e6832/build-receipt.json`.

### 2026-11-25 — repository working guide and guardrails

Task: repository guidance and local CI verification.
Behavior: eight skills, working guidelines, three editable Excalidraw diagrams,
and 18 CI guardrails linked to pytest node IDs. Repair diffs protect the new
agent instructions and policy files.
Checks: 146 guardrail cases and 81 focused regression cases passed locally.
Production Ansible lint, Ruff,
controller lock export, the web build and nine Chromium tests passed. Skills,
relative links and generated diagrams were validated.

### 2026-11-25 — parallel Python CI

The Python CI job runs the guardrails first, then the remaining suite in
parallel. Collection matched all 3,435 cases without gaps or duplicates.
VM102 ran the two stages in 59 seconds including transfer and Ruff. The
guardrails passed 146 cases in 4.50 seconds. The second stage passed 3,284
cases and skipped five in 51.29 seconds. The Git-checkout-only case also
passed locally. The controller requirements export is unchanged.

### 2026-11-26 — A04–A06 private OpenAI-compatible setup and advice

VM104 installed the test-signed `6916530` and `71a77c8` candidates. Chromium
reopened provider choice, saved the approved HTTPS URL and key, verified discovery,
and kept the active model and report after a rejected replacement. Model pin,
reload and report deduplication passed. Admin and signed bot advice returned
source, time and coverage evidence. Bot authentication, scope, replay and conflict
checks passed. Best-now and the next weekly window kept the incumbent when
comparison sources were unavailable. On the installed fix the small model passed
3/3, and the larger model cold-start run evaluated all three cases, scoring 2/3
in 10.734 seconds. The key stayed in worker-owned 0600 storage. VM104 Notes data
and health matched baseline. VM102 passed 4,106 tests and 148 guardrail cases,
with Ruff and production Ansible lint. Native subscription and comparison-source
gates remain open. Private receipts are under `.steward/ai-api-cn-0001/`.

### 2026-11-26 — S01 public draft and local packaging rehearsal

The public draft head `ad9d514` passed hosted Python, Ansible and web CI and
packed reproducibly from a clean checkout. Its `TEST-ONLY` signature verified
against a disposable Ed25519 public key. All unsigned payload bytes matched.
Both deploy and resume rejected wrong key, unsigned archive, changed signature,
manifest and wheel under network isolation, before config loading or SSH.
The stock upgrade payload, all 57 cache entries, both sets of wheel hashes
and the common Notes config passed. Read-only VM103 inspection confirmed its
original disk, guest and thin-pool capacity. Private receipt:
`.steward/rc1-test-only-ad9d514256f1/m8-test-only-offline.log`.
The isolated VM102 verifier accepted that same archive before and after D1–D12
and the unsigned-build check. It rejected all 13 inputs and removed its scratch.
The protected workflow requires the configured repository and environment approvals.
Install, upgrade, unchanged repeat, reboot and recovery still require the
selected operator-signed archive. The disposable private key was removed.

### 2026-11-26 — B08 installed scheduled backup and independent encrypted copy

VM103 deployed and rebooted on the private test-signed activation candidate
`5f439f2`. Its unchanged repeat reported two transient fence tasks as changed.
After the reboot the regular scheduler captured new Notes data at 09:43:12 UTC.
The encrypted append-only HTTPS upload passed full-data and byte-restore checks
within 17 seconds. The normal controller command exported the bound receipt.
A separate TLS reader copied that snapshot into an independently encrypted
repository on the PC. In a loopback-only namespace, a full repository check
and exact restore verified 15,632 bytes, three entries, and the seeded SQLite
note and attachment. A rootless Notes container then verified health, note and
attachment over loopback with an explicit PC-only UID mapping. Empty-VM
recovery and the remaining activation gates are open. Private receipts are
under `.steward/rc1-0.1.0rc1/m8-prep/b08-shadow/`. VM103 returned to its
original disk and runtime. The lab reader/writer were stopped, with the
separate encrypted PC repository retained.

### 2026-11-26 — S01 / B08 deployment recap

`b713338` reports marker-only work as unchanged and counts durable authority
withdrawal under the existing lock. An independent review and ten focused
Ansible recap cases covered zero changes, actual withdrawal, and failure
handling. VM102 passed 4,116 tests, with seven skipped, all 148 guardrail cases,
Ruff and production Ansible lint. Exact signed host replay is still pending.

### 2026-11-26 — S01 sole-maintainer review and vault signing rehearsal

`e8b8bd6` documents the protected sole-maintainer path with green PR checks
and explicit approval of the exact unsigned build by the existing owner.
PR #6 holds the policy and PR #7 stages the full series against `main` so the
three required checks can run on the initial integration. VM102 passed 4,116
tests, seven skipped, all 148 guardrails, Ruff and production Ansible lint.
In a disposable KeePassXC database, an encrypted Ed25519 attachment signed
the draft archive in a loopback-only namespace. The key was imported from
memory and the resulting signature verified. The scratch database was removed.
Owner approval, the real operator vault and the protected build are pending.
