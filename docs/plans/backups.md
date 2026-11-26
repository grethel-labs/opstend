# B01–B08: scheduled backups

Read the [work queue](../implementation-plan.md) first. Goal: turn the existing
root capture/export and unprivileged upload worker into a deployed, observable,
bounded pipeline. `backup.enabled` is currently rejected. `BackupAdapter` v1
already exists in `src/steward/adapters/backups.py`; do not create another one.

Existing evidence: the latest backup milestones in [STATUS](../STATUS.md),
[backup foundation](../backup-foundation.md), and
[ADR 0002 §§5, 8](../adr/0002-repositories-ai-and-application-lifecycle.md).
Upload success, full-data integrity, restored bytes and application readback
are four different claims. None authorizes production rollback by itself.

## B01 — write the host integration contract

**Needs:** existing foundation only. **Change:** extend
`docs/backup-foundation.md`; update `docs/STATUS.md`. This is a design task.

1. Read `core/config.py` (`Backup`, `BackupEndpoint`, availability checks),
   `core/render.py` (backup variables and peer registry), `backupworker.py`,
   `executor/server.py` (`backup_schedule`) and the platform/identity roles.
   Source paths here and below are relative to `src/steward/` unless specified.
2. Specify the scheduler identity, fixed IPC request/response, eligible projects,
   cadence, lease ownership and each restart checkpoint. Reuse root-owned rolling
   capture admission; the worker must not calculate a new pause entitlement.
3. Specify credential installation/rotation, repository initialization as an
   explicit operator step, TLS/address pins, binary verification and disabled
   behavior. Define how repository changes affect pending jobs.
4. Settle local retention counts/age/space, protected recovery artifacts and
   pruning authority. Specify remote retention ownership separately: the
   append-only upload identity cannot gain prune/delete authority. Where the
   source leaves values unspecified, document a bounded policy and its rationale
   in a focused ADR change as part of B01; do not leave defaults for B04 to guess.
5. Define a bounded observation record: project/config/capture/repository/snapshot
   IDs, original capture time, phase timestamps, error, freshness and coverage.
   Name exact B08 acceptance gates, including recovery onto an empty VM.

**Check/done:** each boundary has one owner, explicit inputs, failure/retry
behavior and a checkable acceptance case. No writable state crosses identities.
The remaining cards can be implemented without inventing permissions or retention
policy. Check documentation links and diff; no runtime claim.

## B02 — deploy the upload service, credentials and pinned target

**Needs:** B01. **Entry points:** `core/tools.py`, `core/render.py`,
`cli/main.py`; `ansible/roles/platform/{tasks,templates}/`,
`ansible/roles/identities/tasks/main.yml`, `ansible/roles/firewall/tasks/main.yml`.
Use the scanner install/unit and notifier credential patterns as references.

1. Install the already pinned/hash-verified Restic binary. Add a dedicated
   hardened upload unit (**new template**) around `steward-backupd`, using its
   existing private state and protected read-only import namespace.
2. Transfer only declared secret references into private service credentials;
   verify repository descriptor versus TLS hostname/port before starting.
   Make rotation restart only the affected unit. Never auto-initialize a target.
3. Apply the prepared hosts mapping and exact IPv4/IPv6 address/port policy to
   this service. Test DNS, alternate ports/addresses and local/metadata denial.
4. Keep the schema availability guard. With backups disabled, no upload unit is
   active, no credentials are installed and backup egress remains denied.

**Check:** `tests/test_backup_policy.py`, `tests/test_render.py`,
`tests/test_platform_activation.py`, configuration/CLI tests and Ansible lint.
Use isolated candidate fixtures for enabled rendering; do not add a production
validation bypass. **Done:** local service/render/rotation failure cases pass;
actual separate-UID/TLS/firewall acceptance remains explicitly reserved for B08.

## B03 — connect scheduling to root admission

**Needs:** B02. **Entry points:** `backupworker.py`, `core/store.py`,
`core/ipc.py`, `core/render.py`, `executor/server.py`, `executor/protocol.py`;
the B02 unit and `ansible/roles/identities/tasks/main.yml`.

1. Implement the B01 scheduler loop as the specified unprivileged process.
   Request only registered project IDs through `backup_schedule`; feed completed
   protected imports into the existing upload worker.
2. Register the backup peer and socket access only for the configured service.
   Its role may schedule admitted captures; it must not invoke operator-only
   capture/export/recover or arbitrary workload actions.
3. Reuse capture IDs, repository-bound jobs and phase receipts after restart.
   Test crashes before/after capture, export, upload receipt and final commit;
   no retry may refresh the capture age or cause another pause in the interval.
4. Preserve disabled policy, pause consent, kill switch, target lock, clock
   rollback and lost-lease denial. One failed project must not starve all others.

**Check:** `tests/test_backup_executor.py`, `tests/test_backupworker.py`,
`tests/test_executor.py`, `tests/test_render.py`; add focused scheduler cases to
the existing worker tests or a **new** `tests/test_backupscheduler.py` if separate.
**Done:** deterministic fake-clock/restart tests demonstrate one admitted pause,
reused capture and fenced publication; no feature gate removed.

## B04 — implement bounded retention without losing recovery artifacts

**Needs:** B01's settled retention policy and B03. **Entry points:**
`core/backupexport.py`, `core/filebackups.py`, `executor/server.py`,
`backupworker.py`, `core/config.py`; B01 contract.

1. Add typed retention fields only where the contract requires them. Implement
   local cleanup under the owner of each namespace; no worker-selected root
   paths or broad recursive deletion requests.
2. Protect pending pause recovery, incomplete investigations and active jobs;
   keep the policy's last recoverable captures. Prove deletion eligibility from
   trusted state; unprivileged receipt text alone cannot authorize root cleanup.
3. Handle full disk, unlink failure, interruption and stale/concurrent jobs.
   Never free space by deleting the only protected recovery point.
4. Keep remote prune credentials separate. Implement the selected B01 remote
   retention procedure or document the explicit operator-managed contract and
   capacity alerts; upload credentials stay append-only.

**Check:** extend `tests/test_backup_export.py`, `tests/test_backup_executor.py`,
`tests/test_backupworker.py`, config/render tests if fields change. Exercise the
current ten-artifact limit and long-running cadence. **Done:** retention/capacity
is bounded and restart-safe, with each refused cleanup observable.

## B05 — publish backup observations without new mutation privileges

**Needs:** B03–B04. **Entry points:** `backupworker.py`, `core/ipc.py`,
`collector.py`, `core/events.py`, `controller.py`; use `scannerd.py`'s private
query/feed pattern and atomic collector cursor ingestion.

1. Publish the B01 record over a bounded, peer-authenticated read-only interface
   (**new backup query/feed implementation**). Separate worker-owned phase
   evidence from root capture provenance; do not share a writable database.
2. Emit deduplicated phase failures/recovery and observation gaps. Keep original
   capture time when a retry completes today. Retention/cursor loss is a gap.
3. Report late/missing backups and pending pause recovery with fixed controller
   findings; observations cannot authorize restore, prune or rollback.

**Check:** worker, collector, events and controller tests; add peer-role, stale
snapshot, cursor replay and partial-phase cases. **Done:** a failed upload, stale
backup and failed restore remain distinguishable through the real local IPC path.

## B06 — expose backup evidence in API, UI, bot and CLI

**Needs:** B05. **Entry points:** `api/app.py`, `bot.py`, `hostcli.py`,
`cli/main.py`, `webapp/src/api.ts`, `webapp/src/App.tsx`,
`webapp/src/pages/` (**new backup page**), `webapp/e2e/admin.spec.ts`.

1. Add scoped read-only project/host views of phase receipts, age and failures.
   Update `/backups` from this evidence; absence of an event is not backup success.
2. Wire the planned top-level `backup` request to the registered operator path
   with explicit project selection; keep availability tied to B08. Do not expose
   arbitrary repository/restore paths or a browser shell.
3. Preserve API session/CSRF checks and bot project grants. Show disabled,
   unknown, stale, failed and checked states accurately; include evidence times.

**Check:** API, bot and CLI tests plus UI build/browser acceptance. Include a
partly restored job, unavailable worker, unauthorized project and hostile text.
**Done:** all readers agree on the same bound evidence without mutation authority
for bot/collector or a misleading combined "backup verified" badge.

## B07 — implement a repeatable fresh-VM restore drill

**Needs:** B02–B06. **Entry points:** `backup.py`, `adapters/backups.py`,
`core/backups.py`, `cli/main.py`, `tests/integration/backup_restore.py`,
`tests/integration/proxmox/`; [testing](../testing.md).

1. Extend the existing real encrypted HTTPS fixture into a documented restore
   procedure on a second, owned empty VM. Select an exact repository/snapshot/
   capture binding, not "whatever is latest"; use read credentials only.
2. Restore into an isolated data area, verify complete tree and database
   integrity, then start the registered sample application and check its health
   and saved note/attachment through HTTP. Keep production routes detached.
3. Persist separate byte and application readback evidence, including source
   revision/image and time. Add missing credentials, corrupt snapshot, wrong
   binding, incompatible image and interrupted-drill cases.
4. Implement `restore-test` as this isolated workflow; production data replacement
   and `rollback` remain unavailable until L06. Document exact setup/cleanup in
   the integration README, with ownership guards for both VMs.

**Check/done:** a repeatable harness and local negative cases exist; record actual
fresh-VM execution separately. A directory restore on the controller machine
does not satisfy this gate. If no VM is available, keep that execution open.

## B08 — accept the integrated pipeline before enabling it

**Needs:** B01–B07 local checks and a specifically authorized disposable host,
external HTTPS repository and empty restore VM. No production fixture assumed.

The RC1 off-host recovery criterion covers loss of the source host and its
storage. The operator accepts the measured offline Restic restore on the
physically separate PC and in its fresh QEMU guest for that criterion. The installed
HTTPS pipeline and application-level restore still require the evidence below.
Recovery from a site-wide outage remains outside the tested scope.

1. Prepare an activation candidate: full configuration validation, schema,
   examples and documentation. Removing `backup.enabled` from unavailable
   features is accepted only with the following gates; do not introduce a public
   bypass flag. If acceptance cannot run, retain the released availability guard.
2. Deploy, repeat with `changed=0`, reboot and observe a scheduled admitted capture
   → protected export → encrypted external upload → full-data check → restore.
   Verify actual UIDs, file modes/ACLs, credentials and IPv4/IPv6 data-path denial.
3. Exercise executor/worker termination, lost lease, failed TLS/auth, repository
   change, failed resume, kill switch, full disk and retention over multiple
   intervals. Confirm no repeated pause and no fabricated successful receipt.
4. Run B07 on the empty VM and compare application data. Verify B06 views and
   failure events against the actual receipts; test secret rotation and disable.
5. Record commit, fixture scope, commands, outcomes, private receipt locations
   and remaining limits in `STATUS.md`. Update foundation, roadmap, operations
   and README claims together. Keep `rollback` blocked until L06.

**Check:** full Python suite, Ruff, schema generation, Ansible lint, UI build/
browser tests and the actual VM/HTTPS/restore gates above.
**Done:** every named gate has actual evidence, the normal enabled configuration
passes without a test bypass, and the disabled default remains inert. Otherwise
mark this task partial and name the first unpassed gate; do not claim scheduled
off-site backups are accepted.
