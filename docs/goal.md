# Delivery goal

Written 2026-11-21 after a progress review. This is the single finite plan for
the remaining roadmap. [implementation-plan.md](implementation-plan.md) still
defines each card's scope; this file defines **order, budget, stopping rules and
what "done" means**, so work cannot circle on one card again.

## Why the previous run stalled

- 213 commits in six days, but the last ~25 all concern one sub-problem of
  L02 step 2: guarded deployment transport, route fences and custody of Shared
  pods (including a patched Podman build). Cards L03–L11, A01–A06, R01–R05 and
  S01–S03 are untouched.
- Every discovered hazard became a new design step, ADR section and VM
  acceptance run instead of a backlog entry.
- Acceptance was demanded per micro-change, with up to three review rounds
  each, so one card step consumed days. `STATUS.md` grew to ~3,600 lines and
  became unusable as context.
- Time-gated work (B08 retention) was not used as a parallel lane.

## The goal

Deliver a **first release candidate (RC1)** for private single-host operation.
The [release subset](../release/accepted-subset.yml) defines the supported
installation, configuration recovery, scanner, maintenance, health and
administration paths. The exact signed archive needs the S01 acceptance.
The milestones below retain the wider work queue. [STATUS.md](STATUS.md#rc1-scope-decisions)
records the evidence and explicit deferrals for paths outside the release subset.

## Rules that prevent circling

1. **One card step, at most two commits:** implementation (with tests) and, if
   host evidence is required, an evidence commit. A third commit on the same step
   needs a defect that violates the step's own *Check/done* line.
2. **New findings go to [backlog.md](backlog.md), not into the plan.** One line:
   what, why it matters, which card it belongs to. A finding becomes work only if
   (a) it breaks the current card's *Check/done*, or (b) it is a data-loss or
   privilege-escalation defect in already-accepted behavior. "More robust" is not
   a reason.
3. **No design-only steps for decided matters.** An ADR change is allowed only
   when the cards and ADR 0001/0002 do not settle a product choice. Specifying an
   already-decided contract in more detail is not a step.
4. **Review budget:** one independent review per step, applied to the diff.
   Fix confirmed correctness/security defects in the changed code; do not
   re-review the fixes.
5. **Evidence is proportional; VMs are separate from implementation.** Pure logic (windows, admission, ordering,
   parsing) is accepted with local fake-clock/contract tests. A VM run is
   required only for real host effects (units, firewall, UIDs, network paths,
   reboot, restore). Run **one VM batch per milestone**, after all local checks
   are green, covering every gate of that milestone together. Max two attempts
   per gate; after the second failure record the blocker and move on.
6. **No experimental infrastructure on the critical path.** Patched distro
   packages, forked tools or custom build chains are not allowed to gate a
   milestone. If a feature needs one, the feature is deferred (see X1).
7. **`STATUS.md` stays short:** a table row per card plus at most 15 lines per
   completed step. Details belong in private receipts under `.steward/`.
8. **Parallel lanes:** a time-, host- or provider-gated check never blocks
   independent work. Record the proven scope, last check date and the missing
   prerequisite in `STATUS.md`. Mark the wider profile partially tested or
   deferred and continue. Resume the open check when the prerequisite becomes
   available or a concrete fix addresses the recorded failure, and the
   profile is in scope for a planned release. Reuse the applicable evidence.
9. **Safety invariants do not loosen.** The rules in the work queue (no
   production mutation outside the executor, no shell strings, secrets by
   reference, fail closed, no claims from fakes) apply unchanged. This file
   limits *extra* guard layers beyond a card, not the card's own negative tests.
10. **Progress check:** every parent turn ends with a closed card step or a
    recorded blocker. If a turn closes neither, stop and re-read this file.

## Milestones

Burndown: update the **State** column only when exit criteria are met.
The [post-RC1 plan](post-rc1.md) defines the subsequent milestones M9–M15.

| # | Cards | Exit criteria (all) | State |
|---|---|---|---|
| M0 | Reset | `STATUS.md` compact, archive frozen, Shared deferred in ADR 0006, this plan and `backlog.md` committed | done 2026-11-21 |
| M1 | L03 | Weekly window model with DST/clock tests; deterministic admission with durable started/completed/failed state; TCP and registered container health probes with response-time thresholds; controller self-healing unchanged; fake-clock tests; one VM check of probe timeout/health | **done 2026-11-21** (VM103; G8 healthy-container variant deferred for RC1 after two custody failures before deployment) |
| M2 | B08, V01–V03 | Retention and independent single-host recovery evidence, V01 negative cases and bounded V03 OSV/cold-DB. V02 requires an authorized destination for external delivery. Scheduled backup activation requires full B08 evidence. | retention, independent recovery, V01 and bounded V03 proven; wider activation and delivery deferred from RC1 |
| M3 | L04–L06 | Verified update artifact and bound approval; `apply_verified_image` through the executor; failed update recovers with data readback; patch profile accepted on a VM | **host gates passed 2026-11-22 on VM104**; guards `projects.update`/`automation.patch` stay until B08 passes |
| M4 | L07–L08 | Deterministic critical-risk decision; exposure removal with real IPv4/IPv6/proxy data-path check; quarantine requires successful backup; verified reactivation; interruption test at each transition | open |
| M5 | L09–L11 | Retire/archive/reactivate without deletion shortcut; version-bound UI apply; announced drill with window | open |
| M6 | A01–A06 | Inference contract with reserved budgets; local Ollama accepted; one external provider; login flow; weekly model selection; advisory answers with sources. Everything optional and off by default; no deterministic feature may depend on it | open |
| M7 | R01–R05 | Repository fetch, workload proposal, isolated build, validator, deployment by digest; repair profile produces a pull request only | open |
| M8 | S01–S03 | Signed release with SBOM/provenance for the accepted subset, including private numeric-IP IPv4 administration. Further OS/arch profiles and public admin have separate gates. | private routed IPv4 proven on the earlier VM104 candidate; operator signature and exact-archive acceptance open |
| RC1 | all above | M1–M8 exit criteria met or explicitly deferred in `STATUS.md` with reason | — |
| X1 | optional | Shared-group mutation custody (ADR 0006 custody sections, `tests/integration/podman_custody/`). Starts only after RC1 | deferred |

L02 is accepted for `isolation: separate` (see [STATUS.md](STATUS.md)). Shared
group mutation stays rejected until X1.

For RC1, the operator accepts the encrypted Restic copy on the separate PC and
the offline restore in a fresh VM there as B08 evidence for loss of `cn-0001`
and its storage. Retention and this recovery scope are closed for RC1.
The managed backup activation profile is partially tested and stays deferred
from RC1. Resume its open checks when the authorized target and empty restore
VM are ready for a planned activation batch. Site-wide recovery has its own
evidence scope.

## Parallel lanes and VM roles (2026-11-21)

Implementation and host acceptance are separate activities with separate owners.

| Role | Does | Never does |
|---|---|---|
| **Implementation lane** (one git worktree + branch per card group) | Code, unit/contract tests, focused local checks, one commit per card step on its lane branch | Touch any VM, run the full suite locally, edit another lane's files beyond a merge-trivial hunk, push |
| **CI runner VM** (VM102 on `cn-0001`) | Runs the full suite, ruff and ansible-lint for a given worktree/commit in parallel (`pytest -n`), so the 2-core workstation is not the bottleneck | Hold secrets, deploy Steward |
| **Acceptance VMs** (VM103, VM104; 2 vCPU / 4 GiB each) | Run a milestone's gate script against a committed, merged commit; reset between runs | Run unmerged lane code |
| **VM101** | Long-lived B08/retention fixture; leave untouched except for B08 gates | Be used for per-feature experiments |
| **VM100** | Not ours to change | Anything |
| **Parent** | Merges lane branches in dependency order, regenerates the schema after config merges, runs the full suite on the runner, commits, hands the merged commit to the acceptance lane, updates `STATUS.md` | Implement features itself while lanes run |

Lane rules: disjoint write scopes per lane; lanes only start code for cards whose
*code* prerequisites exist (acceptance prerequisites such as B08 gate the
card's acceptance, not its code); a lane stops at its card's last step or at its
first real blocker and reports; conflicts in `schemas/config.v1.schema.json` are
resolved by regenerating it (`python -m steward.core.schema`), never by hand.
Allowed target-VM budget on `cn-0001`: VMIDs 102-104 only, memory total ≤ 16 GiB
for new VMs, so VM100/VM101 and the node stay healthy.

## How to run a milestone

1. Parent picks the first open milestone whose prerequisites hold and its first
   unfinished card step. Time-gated lanes (M2) are checked at the start of each
   session against the current date.
2. A lead agent (per [AGENTS.md](../AGENTS.md)) returns the plan **in the same
   run it implements it** when the step touches at most about eight files;
   larger or privileged steps keep the separate read-only plan phase. The parent
   reviews the plan against the card and the rules above.
3. Workers implement and test with disjoint write scopes. Local checks per the
   work queue's check table.
4. Parent verifies the merged diff, runs the full local suite, commits.
5. When every code step of a milestone is committed, run the milestone's single
   VM batch, record at most 15 lines of evidence per card, commit, mark the
   burndown row.
6. Move to the next milestone. Do not reopen an accepted card except for a
   rule-2 defect.

## Open product questions (collected from lanes; none block current work)

Answer in an ADR change when the owning card starts; until then the stated
default applies.

| # | Question | Default until answered | Card |
|---|---|---|---|
| 1 | Release key custody (CI secret, offline workstation, hardware token) and public-key publication/rotation | local test keys only; no real key exists | S01 |
| 2 | Signing tool: built-in Ed25519 (`cryptography`) or cosign/minisign/GPG | built-in Ed25519 | S01 |
| 3 | Should `deploy` refuse an unverified release by default | opt-in verification command | S01 |
| 4 | Build timestamp in the signed statement | omitted (determinism) | S01 |
| 5 | Operator update outside the maintenance window | refused (fail closed, all roles) | L05 |
| 6 | Manual operator update before the `patch` profile is accepted | `projects.update` stays unavailable | L05 |
| 7 | Inference budget currency (abstract cost units vs explicit EUR + FX) | abstract units with declared price | A01 |
| 8 | Local model install: pull with declared checksum, or operator pre-places | no implicit pull | A02 |
| 9 | Per-project budgets mandatory for external providers | optional, default unlimited | A01 |
| 10 | Accept scp-style `git@host:path` repository URLs | only `ssh://` | R01 |
| 11 | `steward.contract.yml` as the in-repo operator contract name/location | as implemented | R02 |
| 12 | May an AI-sourced proposal widen egress (e.g. `public-web`) | **no**: a proposal never applies by itself; any egress beyond the safe default needs operator confirmation in R04 | R02/R04 |
| 13 | Repository `instruction` per application (ADR example) instead of per repository/service | per repository/service | R01 |
| 14 | Should `reversible` migrations also take an update-time capture | image-only | L06 |
| 15 | Automatic rollback of a verified-healthy update that later degrades | operator-only | L06 |
| 16 | Retention of preserved trees and update captures (who removes them) | kept until an operator removes them, cap 8 trees | L06 |
| 17 | Minimum healthy time before the patch path updates | "healthy now" | L06 |
| 18 | Off-site (Restic) restore required for `restore_required` approvals | local executor spool; Restic is the manual fallback | L06 |
| 19 | `critical` rule: critical severity unless KEV and EPSS available and low (EPSS < 0.10) | as implemented | L07 |
| 20 | Applications without registered data (no backup possible) | never shut down; disconnected and escalated | L08 |
| 21 | Builder isolation: ephemeral VM first-class, or rootless container tier acceptable as the only RC1 level | container tier, opt-in, labelled weaker | R03 |
| 22 | Where the build output registry lives (builder-local vs shared with the validator) | not decided; R04 must validate independently | R03/R04 |
| 23 | Build reuse across isolation levels | any level at or above the configured minimum | R03 |
| 24 | Unsigned build artifacts acceptable by default (`OriginPolicy.require_signature`) | off (unsigned accepted); decide before RC1 | R04 |
| 25 | Approver for automatic repository deployments: operator only or a configured automation identity | operator only | R04 |
| 26 | Model-policy price source: operator-declared dated prices (no discovery); evaluation has its own budget ledger | as implemented | A05 |
| 27 | `ask` as a fifth read-only bot command, text capped at 500 chars | as implemented | A06 |

## Decisions taken (2026-11-23, operator)

| # | Decision |
|---|---|
| 1 | Release key lives offline on an operator-controlled machine; releases are signed by hand after the build. No CI signing secret. |
| 2 | Built-in Ed25519 stays the signing mechanism. |
| 3 | Release verification is opt-in until RC1, then mandatory for `deploy` (explicit developer exception). |
| 4 | No build timestamp in the signed statement (reproducible builds). |
| 5 | An operator may apply a update outside the window with an explicit emergency confirmation (audited and announced). Implementation is new work (backlog), the current fail-closed behavior stays until it exists. |
| 6 | Manual operator updates (`projects.update`) are released after B08 passes; `automation.patch` is a separate later release. |
| 7 | Budgets stay in abstract units with dated prices; additionally a configurable exchange rate, either set by the operator or fetched from a fixed secure source; a stale rate makes the budget deny (fail closed). New work (backlog). |
| 8 | New requirements package: see [ADR 0008](adr/0008-ai-onboarding-and-model-selection.md). |
| 9 | External AI providers: a global monthly limit is mandatory, project limits optional. |
| 10 | Git URLs: `https://` and `ssh://`; the scp form `git@host:path` is converted to `ssh://` at entry and shown. |
| 11 | Contract: operator contract in the server configuration wins; `steward.contract.yml` in the repository root is a proposal; then AI proposal. |
| 12 | Egress: a proposal widening egress needs single confirmation, except extensions matching an operator-approved fixed rule pattern (new work: rule list). |
| 13 | Bot instruction: an application-wide instruction plus optional additional instructions in the repositories; repository text is untrusted data and never overrides the operator's instruction. |
| 14 | `reversible` migrations also take an update-time capture (exact fallback). |
| 15 | Automatic rollback of a verified-healthy update that degrades within a short window after apply, **only for updates without data migration** (migrations keep escalating to the operator). Window length is a setting. New work. |
| 16 | Update captures and preserved data trees are kept at least 30 days; afterwards the bot reports them as cleanup candidates; nothing is deleted automatically; hint before the 8-tree / 10-capture limits. New work. |
| 17 | The patch profile updates a service only after 30 minutes of continuous health (setting). New work. |
| 18 | Local capture is the rollback source; Restic is the manual fallback; no mandatory off-site backup before a migrating update. |
| 19 | Critical rule as implemented (critical unless KEV and EPSS available and low). |
| 20 | An application may be shut down without a backup only if its contract explicitly marks it stateless; an application that merely has no registered data stays disconnected and escalated. New work (contract field). |
| 21 | Build: container tier is the regular level (VServers cannot nest VMs); a VM/CI backend must stay possible as an option; the build must avoid Docker-in-Docker (daemonless builders: rootless podman/buildah; verify user namespaces and overlay storage on VServers). New work. |
| 22 | Builder-local registry; promotion by digest into the production repository by the validator only. |
| 23 | Reuse of a build only at the same or a stronger isolation level; builder and validator minimum merged into one setting. New work. |
| 24 | Unsigned build artifacts are accepted when the validator accepts them (own L04 attestation); external base images can get a per-source `require_signature`. |
| 25 | Automatic repository deployment approval is the default, switchable off in the admin UI, by a separate automation identity (never validator or builder), only in the window, after validator acceptance, with fresh backup, healthy service and kill switch; disabling takes effect immediately. New work. |
| 26 | Superseded by 8/8b: price/performance sources follow ADR 0008. |
| 27 | Bot command `ask` as implemented (500 chars, read-only, sources and time range). |

## New work packages from the decisions (card in brackets)

Operator emergency confirmation for updates outside the window (L05); FX rate setting for
budgets (A01); provider onboarding, source modes, "best now", change-triggered report
and admin view per ADR 0008 (A02/A04/A05 + UI); scp URL conversion (R01); egress rule
patterns (R02/R04); application bot instruction (R01/A06); update-time capture for
reversible migrations, auto-rollback window, 30-day retention hints, 30-minute stability
gate (L06); explicit stateless marker (L08); daemonless builder verification and VM
option (R03); merged isolation minimum (R03/R04); automation approval identity with admin
UI switch (R04). Release: lift `projects.update` after B08 passes (decision 6); verified
deploy mandatory at RC1 (decision 3).
