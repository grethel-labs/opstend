# L01–L11: application lifecycle and remediation

Read the [work queue](../implementation-plan.md) first and check
[STATUS](../STATUS.md) for completed milestones.
Follow [ADR 0002 §§4–8](../adr/0002-repositories-ai-and-application-lifecycle.md#4-service-interaction)
and reuse backup evidence from B01–B08. Source paths below are relative to
`src/steward/`; repository paths such as `ansible/` and `tests/` are explicit.
Each card includes negative cases; security changes require those tests.

## L01 — model applications and validate the service graph

**Needs:** current configuration/revision behavior. **Files:** `core/config.py`,
`core/render.py`, `core/schema.py`, `tests/test_config.py`, `tests/test_render.py`;
schema and example configs after generation.

1. Specify compatibility between existing single-project configurations and
   applications/services before adding fields. Preserve existing canonical
   revisions or document an explicit migration/conflict procedure.
2. Add typed application/service IDs, `isolation: shared | separate` and
   `depends_on`. Validate unique IDs, known dependencies and an acyclic graph.
3. Derive deterministic start order, reverse stop order and transitive dependents.
   Render registered units, users, ports and data bindings for both isolation
   modes. Preserve current removal behavior until L09 is accepted.

**Check/done:** config/render/schema checks; graph tests cover cycles, missing
references, stable ordering and unchanged legacy examples. No free-form command
or additional public port introduced by declaring a dependency.

## L02 — deploy and operate a stack with bounded group locks

**Needs:** L01 for steps 1 and 2. Step 3 requires B08 for coordinated captures.
**Files:** `core/render.py`, `executor/server.py`, `executor/host.py`,
`controller.py`, `ansible/roles/workloads/`, firewall/verify roles.

1. Implement shared Podman network/user versus separate UID/data/loopback-port
   rules exactly as ADR 0002 §4. Limit allowed network edges to the declared graph.
2. Add registered group operations with a deterministic lock order and a
   root-derived transitive target set. Stop dependents first, start dependencies
   first, and retain a durable per-service checkpoint after interruption.
3. Prevent controller restart races with planned pauses. Coordinate capture of
   all relevant data writers using B08; partial group capture is not a verified
   application backup. Preserve previous running/stopped intent on failure.

**Check/done:** executor/controller/render cases for partial failure, concurrent
operations, crash recovery and disabled services; real two-service VM fixture,
separate-UID/network negative controls, second deploy `changed=0` and reboot.

## L03 — maintenance windows and bounded health checks

**Needs:** all L02 steps complete, including coordinated capture.
**Files:** `core/config.py`, `controller.py`, `executor/server.py`,
`executor/host.py`, `core/events.py`, relevant config/controller/executor tests.

1. Add the ADR's timezone-aware one-hour weekly window, explicit reboot consent,
   emergency notice and known-exploited exception. Test DST, clock changes,
   notice deadlines and work that cannot fit before window end.
2. Implement deterministic admission and durable started/completed/failed state.
   Ordinary controller health restarts keep their existing behavior; maintenance
   policy must not silently disable self-healing.
3. Add TCP and registered container health probes plus bounded response-time
   thresholds. No arbitrary operator/model shell command in root health requests.
   Report timeouts/unknown separately from verified health success.

**Check/done:** fake-clock admission/expiry and probe failure tests; actual VM
timeout/health checks; no scheduled drill or reboot without its contract.

## L04 — validate update artifacts and bound approval evidence

**Needs:** B08, L03 and V03 for scanner-driven updates. **Files:**
`core/images.py`, `core/store.py`, `core/config.py`, `executor/protocol.py`;
**new** typed update-evidence module/tests; [extending](../extending.md).

1. Define exact version ranges, source/image digest, independent test revision,
   expected signer/signature policy and backup/migration compatibility contract.
   Implement image-origin/signature verification with explicit expected identity.
2. Define an approval bound to target, configuration/policy revision, digest,
   tests and expiry. Its authenticity must be checked independently of model/
   builder claims. Persist idempotency and invalidate on any binding change.
3. Implement the validator for an operator-provided candidate image first.
   Untrusted test prose, a scanner score or self-reported build success cannot
   create a valid approval. Keep `patch` unavailable until L05–L06 acceptance.

**Check/done:** unit/contract cases for mismatched digest/signer/revision/target,
expired or replayed approval, stale scan and missing backup; a real disposable
signed-image allow/deny fixture. Record external tool pins and verification.

## L05 — apply one verified image through the executor

**Needs:** L04. **Files:** **new** `adapters/remediation.py` with its first real
implementation; `executor/server.py`, `executor/host.py`, `core/render.py`,
`core/store.py`, `controller.py`; relevant executor/render/job tests.

1. Add `RemediationAdapter` contract tests alongside the implementation, and
   registered `apply_verified_image` parameters limited to bound identifiers.
   Independently recheck L04 evidence, maintenance, backup age, kill switch,
   revision, lock and budget at execution time.
2. Use a durable prepare/apply/verify journal. Persist the approved digest in
   desired state with revision conflict checks so the next Ansible run keeps it.
   Verify the actual running image, health and isolation before reporting success.
3. Exercise failed start, changed pending UI head, interrupted apply and stale
   worker. Do not label an action accepted at the socket as a successful update.

**Check/done:** shared adapter, authorization and restart tests plus a real VM
old→new image transition, observed image binding and repeat deploy `changed=0`.
If recovery is not yet accepted, `patch` stays unavailable until L06.

## L06 — recover a failed update and accept the patch profile

**Needs:** L05 and actual B07 fresh-VM restore evidence. **Files:**
`adapters/remediation.py`, `core/backups.py`, `executor/server.py`,
`executor/host.py`, `cli/main.py`, `core/config.py`; backup/update integration tests.

1. Define when image-only rollback is compatible with current data and when an
   exact backup restore is required. A migration without a verified reverse/
   restore contract is refused before update admission.
2. Implement registered rollback/recovery against the journaled image and exact
   capture/repository/snapshot binding. Reconcile after process death without
   blindly repeating a data migration. Failure remains visible and bounded.
3. Wire `rollback` CLI and enable `patch` only after successful update, failed
   health, failed restore, incompatible migration and crash scenarios pass on
   disposable VMs. Update README/operations/schema/status with precise limits.

**Check/done:** real application readback after rollback, preserved user data,
correct desired revision, denial under wrong/expired approval and no loss of
pending UI edits. A successful file-copy restore alone is insufficient.

## L07 — deterministic critical-risk decision and exposure removal

**Needs:** L01–L06 and V03. **Files:** `core/config.py`, `core/vulnerabilities.py`,
`core/intelligence.py`, `controller.py`, `executor/server.py`, `core/render.py`,
`executor/host.py`; controller/executor/firewall/proxy tests.

1. Specify and test a fixed decision table combining affected-version/runtime
   evidence, severity, reachability, KEV/EPSS and notice deadline. Resolve any
   numeric threshold not set by ADR 0002 before implementation; no AI decision.
2. Compute direct/indirect exposure from L01's graph. Persist deadline and
   application-scoped incident ID, including restart, stale/unknown inputs and
   `on_critical: notify`. Apply the ADR's actively exploited exception precisely.
3. Add narrow registered route/firewall containment with durable desired state.
   At deadline, end exposure even when backup or delivery fails. This operation
   precedes shutdown and must not wait for backup or notification acknowledgment.
4. Keep SSH/administrative host services reachable under ADR 0002's host boundary;
   missing safe source restrictions escalates instead of shutting down sshd.

**Check/done:** table/clock/authorization tests and real IPv4/IPv6/proxy data-path
denial on a disposable stack, including an indirectly exposed database. No
shutdown or automatic reactivation is implied by this first containment task.

## L08 — complete quarantine and verified reactivation

**Needs:** L07, B08, L02 and L06; V02 for actual channel acceptance claims.
**Files:** `controller.py`, `core/store.py`, `executor/server.py`,
`adapters/remediation.py`, `core/events.py`, `notifier.py`; lifecycle tests.

1. Implement durable states: exposed/notice → disconnected → backup pending →
   quarantined → fix verification → healthy/reactivated, plus explicit failures.
   A failed backup leaves the stack running but disconnected and escalated.
2. Enqueue announcement, then stop the stack in reverse dependency order only
   with sufficient backup evidence. Delivery failure remains visible and cannot
   prevent containment. Increase scans within existing resource/provider limits.
3. Apply/verify a fix while disconnected, start in dependency order and restore
   routes only after runtime-bound finding verification. Reboots/crashes must
   preserve disconnection and must not let ordinary self-healing undo quarantine.

**Check/done:** interruption test at every transition; real stack backup-failure,
shutdown, fix and reactivation scenarios with HTTP/data readback and correlation
IDs. Neither a model statement nor stale scan clears quarantine.

## L09 — retire, archive and reactivate removed applications

**Needs:** B08 and L02. **Files:** config diff/rendering in `core/`,
`ansible/roles/workloads/`, `executor/server.py`, `executor/host.py`;
**new** archive lifecycle implementation/tests; operations and migration docs.

1. Add an explicit compatibility/migration plan for replacing v0.1's removed-
   project behavior. Compare applied and desired registries; never infer removal
   from `manage: false`, an incomplete read or a pending UI revision.
2. Stop, disable autostart/user manager, archive exact data/image bindings under
   `/srv/steward/archive/<id>/`, verify readability and only then release the
   working area/images. Reserve user/sub-IDs and persist checkpoints.
3. On re-addition, verify and restore the archive before starting. Distinguish
   retirement from permanent deletion; this task adds no automatic delete command.

**Check/done:** full disk, corrupt archive, changed UID and crash-before-release
cases; actual VM remove/re-add cycle preserving data, restart/reboot behavior and
no accidental retirement of unmanaged projects.

## L10 — apply a pending UI revision through a version-bound local action

**Needs:** L05–L06. **Files:** `api/app.py`, `core/store.py`, `executor/server.py`,
`cli/main.py`, `webapp/src/pages/Config.tsx`, `ConfigFields.tsx`, `api.ts`;
API/executor tests and `webapp/e2e/admin.spec.ts`.

1. Define a registered apply action tied to the installed release and exact
   validated head/applied revisions. Only supported generated operations may run;
   no uploaded playbook, arbitrary command, dependency install or mutable path.
2. Reuse conflict checks, job fencing, target lock, audit and verification.
   Handle a second browser edit, CLI deployment and process restart safely.
3. Display the plan, revision and durable outcome. Preserve the existing
   `config pull` + controller deployment path and its recovery semantics.

**Check/done:** real API/browser conflict/CSRF/restart cases and disposable VM
apply with unchanged second deployment. Job submission is not applied success.

## L11 — announced maintenance drills

**Needs:** B08, L02–L03, L06 and L08. **Files:** `controller.py`, `core/store.py`,
`core/events.py`, backup/lifecycle operations; controller/notifier/backup tests.

1. Schedule only configured resource/restart/restore drills in the weekly window.
   Announce, check admission/resource/backup state and record elapsed time.
2. Restart groups through L02; restore only in B07's isolated environment.
   Keep host reboots behind explicit consent. Defer work that cannot fit and
   complete or recover already-started operations.
3. Suspend drills for a service failing to recover until explicit reconciliation
   or a verified fix. Export results through events/status/daily digest.

**Check/done:** fake-clock no-window/overrun/failure cases and actual announced
restart/isolated restore drill on a disposable stack; no automatic host reboot
or production data replacement from enabling drills.
