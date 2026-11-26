# Consistent data capture and Restic foundation

The backup path includes operator-local tools, registered executor
capture/export/recovery and an unprivileged Restic upload worker. Capture,
upload, integrity and restore each produce their own evidence.
`backup.enabled` is guarded until [B08](plans/backups.md#b08--accept-the-integrated-pipeline-before-enabling-it)
passes in full. [STATUS](STATUS.md#card-state) tracks retention and independent
restore gates. Deployment rollback and application verification use their own
admission checks.

`steward-backup` (or `PYTHONPATH=src .venv/bin/python -m steward.backup`) runs as
an unprivileged user. Its `capture` command uses SQLite's online backup API,
including committed WAL contents, then validates the resulting database and
hashes it. It refuses an existing destination, symlink/FIFO sources, oversized
databases and timed-out captures. The database and manifest form one bounded,
content-addressed capture. Binding metadata supplied by an operator is not a
root-attested inventory or proof of application consistency for other engines.

## Registered quiescent data capture

`steward-host backup-capture PROJECT` adds an operator-only executor action. A
project must explicitly set `maintenance.allow_backup_pause: true` and have a
persistent data mount. The executor uses only the registered project's fixed data
directory, under the same project lock as restarts. It records the root registry's
server/configuration/image/source binding, stops a previously active unit,
checks its inactive state and successful rootless Podman inventory, and copies
the complete data tree. It checks quiescence again before accepting the capture.
Configured image metadata does not prove which image last wrote stopped data.

The complete tree includes database journal/WAL files and other application
files. Regular files and directories are supported; symlinks, hardlinks and
special files are refused. Traversal uses directory descriptors and no-follow
opens, validates source inode/size/timestamps during and after copying, and
limits bytes, elapsed time, entries, depth and open directories. It does not
parse databases as root. The trusted caller must ensure this dedicated workload
is the only writer and hold its mutation lock for the whole capture.

The action always attempts to resume a previously active workload, including
after capture errors; an already stopped workload stays stopped. A failed resume
is an error. Root-private artifacts are retained in
`/var/lib/steward-executor/captures/PROJECT/ARTIFACT`, limited to ten per project;
capture requires the configured source byte limit plus bounded TAR metadata
capacity and a 512 MiB free-space reserve. Root may export these artifacts
for unprivileged Restic upload. No pruning or arbitrary caller path is accepted.
The manifest deliberately retains `origin: operator_local`: a JSON field cannot
substitute for provenance from the root-owned spool and authenticated IPC.

Before stopping a previously active workload, it commits a pause intent to the
root-private executor SQLite database. On executor startup a background recovery
worker resumes it only under its original active project/configuration contract,
with the kill switch off. The worker does not block the query socket. A previously
stopped workload never gets such an intent and is not started by recovery.

The intent remains until unit start is confirmed, including after failed starts.
New captures and ordinary restarts of that project are blocked while it remains.
The controller reports the pause without attempting an ordinary restart; errors
or a pause lasting over five minutes produce high-priority findings. Root audit
pause/resume events enter the collector with immediate delivery classification.
These are lifecycle events, not proof of successful upload or restore.

An operator may run `steward-host backup-recover PROJECT` to retry recovery
explicitly, including while the automatic kill switch is on. If the contract
changed, it refuses to resume the old workload. After reconciling the workload
with its current contract, `steward-host backup-recover PROJECT --accept-current`
can acknowledge the pending intent without starting anything. The project user
and unit must still match; a desired-running workload must already be active,
and a desired-stopped workload must pass the quiescence probe. Raw captures are
retained and never promoted to successful backups by this acknowledgement.

A real local SIGKILL regression proves that committed intent survives process
death and is consumed by a fresh executor's recovery. Actual managed-VM
crash/restart recovery has also passed, as recorded in STATUS.md. Protected export
and the standalone upload worker now exist. The B08 candidate milestones in
STATUS.md record the follow-on integration checks and remaining release gates.

## Prepared target policy

The backup configuration can describe a TLS hostname, port and explicit IPv4 or
IPv6 address pins, together with secret references for repository, encryption
password and optional HTTP authentication and CA. The repository descriptor is
checked against the configured host and port before use. Generated nftables rules
allow only those pinned addresses and that port; loopback, local, link-local and
multicast destinations are rejected. Disabled backups retain default-deny egress.
The isolated backup service uses the generated hosts mapping and managed
credentials in the B08 candidate. The released configuration continues to
reject `backup.enabled` pending full B08 acceptance.

Local namespace tests send actual IPv4 and IPv6 packets through the generated
policy, with reachable negative controls for alternate addresses and ports.
They do not establish managed-VM or off-site backup acceptance.

## Protected capture export

`steward-host backup-export PROJECT ARTIFACT --capture-id CAPTURE_SHA256`
publishes one exact completed capture from the executor's private spool to
`/var/lib/steward-backup-import/PROJECT/ARTIFACT`. This operator-only action accepts
registered identifiers and a bound capture ID, not source/destination paths.
It refuses pending pause recovery, unsealed/tampered sources, an unexpected
existing export or insufficient free space. Retrying the same export preserves
its capture identity and existing directory. Exported data is not an upload.

Ansible creates a separate `steward-backup` identity without executor/query groups
and a root-owned import root. Root owns every published object; the backup group
gets read/traverse permissions only (directories `0550`, files `0440`), while
project import parents remain root-owned `0750`. Inherited named POSIX ACLs are
removed on the newly created private objects before publication, so opening the
group mask cannot accidentally grant another user access. Existing exports with
unexpected ACLs or write permissions are refused. Partial copies remain private
and are cleaned on ordinary errors. New exports require their byte size plus
512 MiB free space and are limited to ten per project, without implicit pruning.

The local real HTTPS fixture uploads directly from this read-only export, checks
Restic data, restores the complete capture and reads the sample app over HTTP.
Local permission, ACL and atomic-error tests passed, along with distinct-UID
managed-VM export checks. Later B08 milestones cover the credential-bearing
service and leave real retention and geographically independent restore open.

## Durable upload worker

`steward-backupd` consumes the protected import namespace as the unprivileged
backup identity. It has no executor socket access or workload-stop authority.
Its separate private state directory is `/var/lib/steward-backup`; imports must
remain outside that writable state. Production import ownership is fixed to
root and the backup primary group, with the exact read-only modes above. The
worker rejects additional files, writable/linked objects, unexpected ACLs and
manifest/project mismatches before uploading data.

The worker opens only an already initialized, explicitly selected REST/HTTPS
repository. It never auto-initializes a target. A private persistent job is bound
to repository identity and immutable capture ID. An exclusive worker lock and
renewed job leases fence concurrent or late workers. Upload, full-data check and
restored-byte verification each save a separate receipt checkpoint; a succeeded
job and its final receipt are committed in the same SQLite transaction. Expired
leases cannot publish success. Snapshot identity cannot change between phases.

After a failed restore or process restart, a saved snapshot receipt is reused,
instead of uploading again. An upload interrupted before its receipt is saved
has an unknown remote outcome; retry discovers/reuses the existing capture tag
where available. This does not promise exactly-once remote effects under an
arbitrary crash. Capture creation and native snapshot creation timestamps remain
separate and are not freshened by a retry. Failed jobs retain their partial
evidence, and `application_verified` remains false.

For a manually provisioned pinned Restic binary and private credential files,
run as `steward-backup`:

```bash
steward-backupd --repository-file /private/backup/repository \
  --password-file /private/backup/password --once
```

Optional REST username/auth-password and CA files use the corresponding flags.
Credential files must be readable by this identity with private permissions;
passwords are single-line values (one terminal LF/CRLF is accepted), with at
least 32 meaningful bytes for repository encryption. Embedded extra lines are
refused so ignored password-file lines cannot satisfy the length requirement.
The worker refuses root execution and emits no credential values.

Ten worker regression cases cover partial-phase restart, lost/expired leases,
repository changes, snapshot mismatches, unsafe imports and locking. The real
HTTPS fixture runs this worker against Restic/rest-server, verifies all phases,
restarts it without creating more work and reads the restored app over HTTP.
This fixture verifies the standalone worker locally. The B08 milestones in
STATUS.md cover host integration and the remaining acceptance gates.

Example binding file:

```json
{
  "server": "test-server",
  "project": "notes",
  "config_revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "image": "docker.io/library/python@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "source_revision": "bundled:sample-notes@0.1.0"
}
```

Use the actual revision/image values when testing your own data:

```bash
steward-backup capture --database /private/notes.db \
  --binding /private/binding.json --out-dir /private/new-capture
steward-backup --help
steward-backup backup --help
```

The Restic adapter pins version 0.19.1 and accepts only explicit
`rest:https://host/repository/` descriptors. Repository and encryption-password
files must be private regular files; the encryption password needs at least
32 bytes. Optional username/auth-password files configure REST authentication.
Credentials are passed through private temporary files/environment, never
command-line values. Proxy/backend/password-command settings are not inherited.
Custom CA files are supported with certificate verification enabled.

`init` is explicit. `backup` reuses a matching immutable snapshot on retry and
`check` performs `check --read-data`. `verify-bytes` restores the exact snapshot
subtree into a temporary directory, checks its hashes and checks SQLite integrity
for SQLite captures, then removes the directory. It uses read-only repository
access and does not verify an application. The former byte-only `restore-test` invocation is now named
`verify-bytes`; `restore-test` requires a bound specification and application
source, then runs the isolated application drill. State/credentials and output
must stay outside the captured source. Upload, repository integrity and restored
data have separate timestamps. No production restore target, prune/forget
operation or rollback action is exposed by this adapter. Whole-tree captures use
a bounded validated `data.tar` artifact; restore checks its complete hash and
structure without extracting arbitrary archive paths.

## Executed integration proof

`tests/integration/backup_restore.py` starts a disposable authenticated,
append-only HTTPS rest-server on loopback with its own CA and random credentials.
With hash-verified official Restic 0.19.1 and rest-server 0.14.0 binaries, it
passed capture/upload/retry/full-data-check/restore and an independent second
restore followed by actual sample-app `/healthz` and `/notes` HTTP readback.
It also passed a complete quiescent-tree roundtrip with a database, attachment
and empty directory; sample-app HTTP readback used that restored tree's database.
The private note marker was absent from server-side repository plaintext.

```bash
PYTHONPATH=src .venv/bin/python tests/integration/backup_restore.py \
  --restic /path/to/restic --rest-server /path/to/rest-server \
  --out .steward/backup-proof.json
```

This is real Restic/network/application evidence in disposable local directories,
not an off-site deployment, an executor-authorized capture, or a fresh-VM restore
drill. Restic's [backup](https://restic.readthedocs.io/en/stable/040_backup.html),
[restore](https://restic.readthedocs.io/en/stable/050_restore.html) and
[repository](https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html)
documentation define the underlying operations.

## B01 host integration contract

This contract specifies the boundaries for B02–B08.
`steward-backup` is the sole scheduler/uploader identity. With backups enabled,
give it `steward-exec` for the executor socket and `steward-obs` for its read-only
observation socket; register its numeric UID as the `backup` peer. It may invoke
only `backup_schedule`, never operator capture, export, recovery or workload
actions. Its private state belongs to that identity; root owns the capture spool
and read-only imports. No database or writable directory crosses identities.

The scheduler reads a root-owned, backup-group-readable configuration containing
the configuration revision and managed projects with a data mount and explicit
`allow_backup_pause`. It requests only `{v: 1, action: "backup_schedule", params:
{project_id}, request_id, expires_at}` over the existing authenticated IPC. The
root response supplies project, artifact, capture ID, import directory, original
capture time/configuration revision, `uploaded: false`, reuse flag and next
capture time. Root alone determines admission and its rolling interval; the
worker persists next-due hints and does not grant itself another pause. After a
restart it retries unknown responses with a fresh request ID and validates the
root-owned import against the returned binding. A busy target, kill switch,
disabled policy or pending pause recovery is a bounded retry and observable gap;
one project cannot block scheduling of the others.

Upload jobs remain keyed by repository ID and capture ID, with one worker lock,
renewed leases and ownership-fenced checkpoints. Reconcile expired leases before
claiming; an unknown remote outcome is resolved by finding the existing capture
tag. Save upload, full-read check and restored-byte receipts separately; commit
the final receipt and job success atomically. Preserve original capture and
native snapshot times. A changed repository ID fails old pending jobs as
`repository_changed`; new jobs for the new repository are separately bound.
Neither worker receipts nor a successful byte restore authorize rollback.

Install the pinned Restic archive only after its SHA256 matches the architecture
manifest; execute the fixed binary without shell or inherited proxy/backend
settings. An operator explicitly initializes the selected repository before
enabling the service; lookup failure never initializes it. Transfer only
declared repository, password, optional paired HTTP credentials and optional CA
references into root-private files and systemd credentials. Never log values;
rotation changes the activation fingerprint and restarts the affected service.
Validate the repository URL host and port against the declared endpoint. Bind the
service's hosts file to the generated address mapping and allow outbound TCP only
to the explicit pinned addresses and port, rejecting loopback, local and metadata
destinations. TLS verification remains enabled. When disabled, stop/disable the
upload unit, install no backup credentials, deny new backup egress and report
disabled, not healthy; preserve prior evidence as historical.

Apply the local and remote retention decision in [ADR 0003](adr/0003-backup-retention.md).
Expose a bounded read-only observation per project: project, configuration,
capture, repository and snapshot IDs; capture creation and snapshot creation
times; upload, integrity, restored-byte and independent application-drill times;
phase state/error; observation time, freshness and feed coverage. Limit pages to
200 records and summaries to 64 projects, with cursor gaps explicit. States are
disabled, unknown, stale, failed or evidenced per phase; an empty feed is never
success. Scoped API/bot readers only see authorized projects. Observations grant
no mutation, retention or recovery authority.

B08 requires, on owned VMs and an explicitly selected HTTPS target: fresh deploy,
unchanged second deploy and reboot; distinct-UID/egress/credential denial;
scheduled capture and real encrypted upload, full check and restored bytes;
interrupted capture, lease and upload recovery; changed repository, full disk and
retention refusal; then a separate empty-VM restore with application health and
saved-data readback. Record each proof separately. Only after these and the B02–B07
local checks pass may the availability guard be removed. A local directory restore,
warm cache or loopback fixture alone does not satisfy fresh-VM/off-site acceptance.

## Prepared automatic capture admission

The registered `backup_schedule` action is limited to the operator and a prepared
backup role. It checks the current root-owned `backup.enabled` setting, persistent
data mount and explicit per-project pause contract. `backup.interval_s` defaults
to 86,400 seconds (minimum one hour, maximum seven days); `backup.max_mib` defaults
to 256 MiB of source bytes (range 1–1,024). The source limit also applies to manual
captures; bounded archive metadata and the free-space reserve are additional.

Root-private schedule records bind one generated artifact to the configuration
and actual capture-attempt time. A repeated request in the rolling interval
returns the same export, not another pause. Failed or ambiguous attempts cannot
be abused into repeated downtime. Failures before capture starts, such as low
capacity, may retry safely; the rolling interval begins only at actual attempt
admission. Export failure or interruption after a complete capture resumes the
same artifact without stopping the app again. Pending pause recovery blocks
planning. Root keeps normal pause/resume and failed-schedule audit events.

The scheduler candidate registers the backup identity as an executor peer when
enabled and restricts new outbound traffic to the configured repository target.
The disabled configuration leaves the peer unregistered and backup egress
denied. The released controller rejects `backup.enabled` until all B08
acceptance gates pass.

## Upload cancellation contract refinement

[ADR 0004](adr/0004-upload-cancellation.md) extends the B01 backup-peer contract
with the read-only `backup_upload_permit` operation. A managed worker holds the
root-owned import's shared lock while it checks the exact registered binding and
uses the import. An operator can cancel or reinstate that upload only after the
fixed service is confirmed stopped and an exclusive lock on the same import is
held. A cancellation retains the original root protection and files; it neither
proves upload/restore success nor authorizes their deletion. Unavailable permits
and cancellations defer jobs without consuming their upload-attempt budget.
Standalone worker mode is outside this managed cancellation contract.

## Cancelled import retirement

An operator may separately acknowledge removal of a cancelled, old import with
`steward-host backup-import-purge PROJECT ARTIFACT --capture-id ID
--acknowledge-import-removal`. The root executor requires the service stopped,
the matching root registration and cancellation, an intact root capture, an
exclusive import lock and the seven-day/two-newest retention protections. It
journals inode-bound removal and resumes an interrupted intent only when the
service is stopped again. The private root capture remains intact. Once the
import is retired, the root cancellation tombstone blocks re-export and the old
worker job; reinstatement is no longer available through the cancellation
command. This is not evidence of an upload or restore.

## Bounded automatic retention

When backups are enabled, the executor periodically considers root-acknowledged
private captures using the same locked, full-data retention checks as the operator
command. It processes at most one expensive candidate per host per five-minute
cycle and rotates projects and candidates after failures. The kill switch and
current project contract remain authoritative. A cancelled-upload tombstone
is removed only in the transaction finishing its separately acknowledged root
capture retirement, after matching imports and registrations were checked absent;
an unregistered stale worker still receives no permit. Cancellation records are
capped at 128 per project and saturation refuses further cancellations and emits
a capacity alert. Existing uncertain records are never silently discarded.

## Retention wake hints

[ADR 0005](adr/0005-retention-wake-hints.md) adds one narrowly scoped backup-peer
operation to wake the root retention sweep after an upload receipt is committed.
The managed worker persists and retries bounded, coalescible hints. They confer no
deletion authority or integrity/restore claim; the root sweep applies its normal
five-minute host limit and all independent retention checks.

## Historical cancellation reconciliation

The operator-only `steward-host backup-cancellation-forget PROJECT ARTIFACT
--capture-id ID --acknowledge-forget` reconciles a historical cancellation record
only after the executor verifies that the fixed backup service is stopped and that
no matching or ambiguous capture, import, registration, acknowledgement, pause,
schedule or retirement intent remains. The action removes no backup data or
worker-owned state. Existing cancellation identifiers are visible, in a bounded
list, through `backup-retention-status`. A stale worker has no permit without a
new root registration. See [ADR 0004](adr/0004-upload-cancellation.md).

## Worker job-capacity bound

The private backup-worker ledger admits at most 1280 distinct jobs. Existing
idempotent jobs remain usable at the limit, including queued and investigation
states; new jobs are refused rather than deleting history or pending evidence.
The worker can continue processing existing runnable jobs and reports saturation
through ADR 0005's parameterless, explicitly worker-attributed capacity report,
including when its import is unregistered. The root executor
rate-limits the resulting immediate alert and never treats the
report as deletion authority. An older ledger already over the limit is retained
and refuses additional distinct jobs. Durable observation and eventual safe
worker-ledger pruning remain later work.

## Worker-owned backup query projection

The managed backup worker exposes a peer-authenticated read-only `backups_query`
Unix socket to the operator, API and collector identities. It projects at most
1,280 worker jobs, with pages of at most 200 and a snapshot digest that rejects
pagination across changed evidence. The `ledger_coverage` field describes only
whether this bounded worker-ledger projection was truncated; it does not assert
that every scheduled capture exists or succeeded. The socket returns no receipt
paths. Root capture provenance remains separate and every projected row is
explicitly `worker_reported`.

Capture age is derived from the receipt's original capture time, with a stale
threshold of twice the configured interval; absent or future capture times are
unknown. Upload, integrity and restored-byte timestamps remain separate, and an
independent application drill remains unknown. A failed job can retain completed
phase timestamps. This query provides no cleanup, recovery or mutation authority.

## Worker change feed and collector cursor

The backup job ledger records bounded worker-owned transitions in the same SQLite
transaction as the corresponding job update. The feed retains at most 10,000
changes and gives a stream identifier and sequence coverage to the collector.
Existing jobs are imported as a baseline, with prior history explicitly unknown.
The collector reads through the peer-authenticated socket and atomically commits
failure/recovery events with its cursor. Stream replacement, missing sequence
numbers, a pruned prefix and a historical baseline generate observation-gap
events. Worker claims carry their phase timestamps and are never root provenance
or authorization to clean up, restore or roll back. Duplicate polls and collector
restarts do not duplicate events. The collector only monitors the backup socket
when backups are configured enabled; a missing enabled worker creates a gap.

The feed reports worker failure and recovery. Independent application restore
evidence comes from a separate [drill](#isolated-application-drill-building-blocks).

## Root-owned schedule observations

`platform_status` includes a bounded projection of the executor's root-owned
schedule record for each eligible project while backups are enabled. It exposes
only the recorded phase, configuration revision, capture ID and original
capture time, with `executor_schedule` provenance; missing or invalid records are
explicit. A record describes the last scheduling attempt, not the existence of a
remote snapshot or a verified restore.

The controller reports fixed, non-remediating findings when the record is
missing, unreadable, from another configuration, failed, in the future or more
than two configured intervals old. These findings do not authorize cleanup or
recovery. The controller correlates the worker's upload evidence separately.

## Root and worker evidence correlation

When enabled, the controller may read the worker's bounded query socket using
its own peer identity. It reads a complete, snapshot-fenced worker ledger and
joins records only to the root schedule's current project, capture ID,
configuration revision and original capture time. A changed, unavailable,
truncated, ambiguous or inconsistent worker snapshot remains unknown. Root and
worker provenance stay separately identified, and the worker's repository,
upload, integrity and restored-byte claims are never treated as independent
application-drill evidence or as permission to mutate anything.

For a current exported capture, a missing worker record or incomplete phase
older than one configured interval creates a fixed finding; a reported job
failure creates a high-severity finding. These findings state what the worker
reported and do not assert that an absent record proves that no remote snapshot
exists. The controller only connects when backup policy is enabled. The query
uses bounded pages and fails closed if the snapshot changes between pages.

## Backup evidence views

The authenticated `GET /api/backups` endpoint, Backups page, read-only bot
`/backups` command and root `steward-host backup-status` command consume the
same bounded controller-snapshot projection. The API supports a project filter;
the bot applies the caller's project grants before constructing output. Missing
or stale controller data stays unknown or explicitly historical, and disabled
backup policy is shown separately. The view keeps root capture provenance and
worker-reported upload, full-data check and restored-byte times separate, and
shows the independent application drill as unknown. It exposes no paths or
mutation authority. A displayed capture freshness does not establish upload or
restore success.

The UI follows the same `backup.enabled` availability guard. Use the separate
capture request and restore-drill entry points below.

## Operator request for a scheduled capture

`steward backup --config FILE --limit SERVER --project PROJECT` is wired through
an Ansible `argv` invocation of the root host command and the registered
`backup_schedule` executor action. The command binds the project and the local
configuration revision; the executor rejects a different active revision and
will not reuse or resume a still-bound older-revision schedule on that request.
It preserves the existing per-project cadence and pause contract. The response
means a capture was prepared or reused for upload, not that upload, integrity,
restored bytes or an application drill have succeeded.

The standard configuration availability guard still rejects `backup.enabled`
until B08, and disabled backup policy rejects this request. The operator path
does not enable the scheduler or modify the gate. Existing explicit operator
semantics for the kill switch remain unchanged.

## Private restore-tree primitive

The Restic adapter can now expose an exact, verified capture to a scoped
consumer inside an automatically removed private temporary directory. For a
whole-tree capture, it can materialize data only in a new empty private
workspace, reject unsafe archive members and data over 1 GiB, then re-capture
the complete tree and compare its archive hash, size, entry count and data size
with the original capture. This checks restored files, empty directories and
portable modes before the consumer sees them. Temporary capture and tree areas
are removed even if the consumer fails; no caller-selected production target is
used.

This is a data verification primitive, not an independent application drill or a
fresh-VM restore. It does not authorize replacing production data. The complete
application drill checks the matching image and source plus health, note and
attachment readback; the controller command is still subject to the normal
backup availability gate. Fresh-VM evidence remains a separate claim.

## Isolated application drill building blocks

The unprivileged `steward-backup application-drill` command accepts a private
receipt and a separate drill specification binding repository ID, snapshot ID,
capture ID, full capture binding, sample-app source SHA256, note SHA256 and
attachment SHA256. Its Restic adapter is restricted to read operations and uses
`--no-lock`; a server-side read-only credential is still required. It verifies
the restored complete tree and SQLite database before starting the exact pinned
sample image with rootless Podman, no network, a read-only container root and no
capabilities. The app file is copied into a private temporary directory and
hash-checked before and after readback. Health, the expected note and the
content-addressed attachment are read through HTTP inside that isolated network
namespace. The sample application revision is now `bundled:sample-notes@0.1.1`;
its attachment endpoint accepts only SHA256 names and rejects links, oversized
files and content mismatches.

A successful local drill writes separate byte and application timestamps in a
private atomic report, without note contents or repository credentials. The
report explicitly leaves fresh-VM proof and production-restore authority false;
it cannot authorize a production rollback or replace live data. Container
cleanup checks a random ownership label and fails closed if ownership or cleanup
cannot be confirmed. A fixture-only TLS proxy under `tests/integration/proxmox`
provides a separate reader credential and forwards only GET/HEAD to the fixed
loopback repository; write methods and upstream redirects are refused. It is not
a general-purpose backup service.

The controller `restore-test` runs the isolated application workflow on the
machine where it is invoked, using explicit reader credentials and the configured
repository endpoint. It selects an exact checked receipt and specification and
writes new private evidence. The normal availability gate remains closed pending
B08; a local application result does not prove fresh-VM provenance or authorize
production restore. Separate owned-VM fixture runs are recorded in `STATUS.md`.
