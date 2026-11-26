# R01–R05 and S01–S03: repositories, repair and release

Read the [work queue](../implementation-plan.md) first. Repository deployment
follows [ADR 0002 §§3–4](../adr/0002-repositories-ai-and-application-lifecycle.md).
These are future capabilities, not current CLI commands or configuration fields.
Source paths below are relative to `src/steward/` unless stated otherwise.

## R01 — fetch an exact repository revision with scoped credentials

**Needs:** L01 and L05–L06. **Files:** `core/config.py`, `core/secrets.py`,
`core/store.py`; **new** unprivileged fetch component, unit and tests.

1. Add validated repository/service bindings and read-only per-repository secret
   references. Define allowed protocols, host verification, redirect/submodule/
   Git hook behavior and credential separation before spawning Git.
2. Fetch into that application's namespace with fixed argument construction,
   limits and timeouts. Record resolved commit and immutable build-input identity.
   Never run repository scripts/hooks or use a production data directory.
3. Support an operator-written workload contract without AI. Without a contract
   or authenticated AI, report "missing contract" rather than guessing ports,
   exposing a service or calling an undeclared provider.

**Check/done:** disposable Git fixtures for wrong host/key, cross-repository
credential access, malicious URL/ref, interruption and repeated same commit;
real separate-UID fetch acceptance. No build or production deploy yet.

## R02 — propose a workload contract and check suitability

**Needs:** R01 and A06 for the AI-assisted branch. **Files:** inference snapshots,
configuration validator; **new** bounded repository inspection/proposal tests.

1. Bound files/bytes/time for inspection; pass repository content as untrusted
   data alongside the operator's instruction. Produce only a typed proposal for
   build, port, health, data, egress, resources, update and backup requirements.
2. Validate fixed suitability rules: non-root, read-only rootfs, no host network,
   engine socket, privileged devices or production secrets. The independent
   validator must reject these even when the model marks a proposal safe.
3. Treat operator-written contracts through the same checks. Include dependency/
   lockfile inventory bound to exact commit; unresolved requirements stay visible.

**Check/done:** malicious instructions, huge/binary files, unsafe build proposals,
missing contract and provider outage cases. A valid proposal authorizes only the
isolated build stage; it grants no host executor capability.

## R03 — run an isolated build and record the isolation level

**Needs:** R01–R02. **Files:** `core/store.py`, config/resource policies;
**new** builder runner/unit/tests, disposable VM/CI build harness.

1. Implement ephemeral VM or approved external ephemeral CI first. Add rootless
   dedicated-user fallback only under explicit
   `build.allow_container_isolation: true`; label "container isolation, no VM
   protection" in evidence/UI as required by ADR 0002.
2. Consume exact immutable inputs, restrict build egress/package sources, bound
   CPU/RAM/disk/process/time and keep production credentials/data unavailable.
   Repository-controlled Dockerfiles/tests execute only inside this boundary.
3. Persist source/build recipe/dependency/toolchain/output digest and isolation
   level. Reconcile lost leases and destroy only owned ephemeral resources after
   success/failure. Reuse an accepted artifact for identical inputs, not a mutable
   image tag; reproducibility claims require separate measurement.

**Check/done:** actual hostile build cannot reach production sockets/data or
other projects; crash/resource-limit/cleanup cases pass for each enabled level.
Output is an untrusted candidate image until R04 validates it.

## R04 — independently validate and deploy a repository artifact

**Needs:** R03, L04–L06 and L02 for multi-service fixtures.
**Files:** update evidence/validator from L04, remediation adapter, inventory,
workload rendering; **new** repository deployment integration cases.

1. Independently validate candidate digest, source/build bindings, signature/
   origin policy, vulnerability/dependency inventory and prescribed tests in a
   separate environment. Builder output cannot attest to its own acceptance.
2. Bind the resulting approval to the application, current revisions, tests,
   digest and expiry. Deploy only through `apply_verified_image`; record the
   accepted digest in desired state and observe the running image/health/data.
3. Test changed commit/recipe, failed validator, incompatible migration,
   interrupted rollout and artifact replacement. Identical accepted build inputs
   and digest must not restart running services on a repeat deployment.

**Check/done:** real fetch→build→independent validation→deploy→HTTP/data readback
on an owned single-service and then multi-service fixture; second unchanged
deploy `changed=0`, plus verified failure recovery. AI is optional when an
operator supplied the contract.

## R05 — isolated coding agent repair with pull request output

**Needs:** R04, A06 and accepted L06 recovery. **Files:** **new**
`adapters/coding.py` (`CodingAgentRunner`) and runner tests; builder/validator,
job store and config/profile handling; [CONTRIBUTING](../../CONTRIBUTING.md).

1. Integrate an officially supported runner under a distinct identity and
   credential scope. Treat its working copy as untrusted; reserve budgets and
   prohibit production secrets/data, host shell tools and unrestricted executor
   access. Verify subscription terms before relying on a subscription path.
2. Implement shared runner contract cases, bounded proposed diffs, independent
   tests and default PR output. An agent cannot approve its own patch or weaken
   CI, test/policy configuration or approval checks to make its patch pass.
3. Enable `repair` only for accepted runner/build/validation paths. Publication of
   a PR or an automatic deployment uses explicitly configured repository/automation
   authority; preparing a local patch does not imply publication permission.

**Check/done:** synthetic repair success/failure, malicious repo, secret access,
policy-file modification, timeout and concurrent-job cases; actual isolated
runner/validator integration and an authorized test PR. No model-only approval.

## S01 — verifiable signed release for an accepted feature subset

**Needs:** accepted scope explicitly listed in `STATUS.md`; its local, VM and
provider gates passed. Later optional adapters need not delay a core release if
they remain unavailable and are documented accurately.
**Files:** `cli/main.py` release build, packaging metadata, `requirements/`,
`CHANGELOG.md`, support/security docs; separate work on `.github/` release jobs.

1. Define release contents and verify version, dependency/tool pins and license
   attribution. Build artifacts, checksums, SBOM and provenance for those contents.
2. Prepare signing and verification under protected jobs with minimal permissions.
   Keep signing keys/production credentials away from untrusted PR execution.
   Submit CI/policy changes separately for the review required by CONTRIBUTING.
3. Test install/upgrade from the actual archive, signature/hash rejection,
   unchanged second deploy, reboot and documented recovery. Keep publishing as
   a distinct authorized action after the artifacts and notes are reviewable.

**Check/done:** exact candidate archive and verification evidence recorded;
README/status/support claims match the tested subset. A successful source-tree
test run alone does not prove release-archive installation.

## S02 — add one OS/architecture profile at a time

**Needs:** S01 baseline. **Files:** preflight/config/rendering, host commands,
tool pins, `ansible/roles/`, `docs/support-matrix.md`; **new** profile contract
only alongside the first additional real implementation.

1. Select one new OS/architecture and enumerate actual package, systemd,
   Podman/Quadlet, firewall, MAC and tool/archive differences. Reject unsupported
   combinations explicitly; do not reuse an amd64 pin for arm64.
2. Implement `OSProfile` with the real second profile, preserving fixed executor
   operations and host key/rollback/migration guards.
3. Run that profile on fresh hardware-virtualized guests or suitable real hosts:
   install, second deploy, reboot, UID/isolation/IPv6/metadata, backup/restore and
   the release subset's other gates. Measure resources under named workloads.

**Check/done:** profile-specific real evidence before changing support claims;
one architecture's results do not establish another's support.

## S03 — explicit public administration with OIDC/MFA

**Needs:** S01 and accepted existing session/CSRF/private-admin behavior.
**Files:** `api/app.py`, `api/server.py`, proxy/access configuration, web login;
auth/role/browser integration tests, operations and threat model.

1. Record the chosen OIDC provider/auth model, role mapping, MFA requirements,
   session lifetime and local recovery access in an ADR before opening a route.
2. Implement issuer/audience/state/nonce/PKCE and key-rotation validation as
   required by that flow; preserve origin/CSRF/session revocation and rate limits.
   Public admin remains an explicit TLS/DNS/access opt-in.
3. Test denied identities, wrong token bindings, expired/revoked sessions,
   provider outage and recovery. Run real TLS/OIDC/MFA acceptance on an authorized
   test domain. New deployments use private LAN administration by default.
   Existing tunnel configurations and explicit loopback access remain supported.

**Check/done:** browser/API/auth failures and real-provider acceptance recorded;
no unauthenticated dashboard or route exposed as a substitute for administration.
