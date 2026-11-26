# ADR 0003: backup retention and deletion authority

Status: accepted for implementation · 2026-11-16

The fixed ten-capture limit prevents unbounded local growth but eventually stops
daily backups. Unverified worker output cannot authorize deletion of root-owned
recovery data. Remote storage also needs a retention owner independent of the
append-only uploader.

Keep at least the two newest complete root captures per project and every capture
less than seven days old, using original capture time. Keep pending/ambiguous
captures, pause-recovery artifacts and artifacts referenced by active jobs
regardless of age. Retain at most ten local captures and ten imports per project;
when these rules leave no eligible space, refuse the new capture and emit an
immediate capacity finding. Maintain the existing source-size plus archive
overhead plus 512 MiB capture reserve, and the export-size plus 512 MiB reserve.
Clock rollback never makes an artifact older; unknown timestamps are protected.

Only the root executor deletes its own spool/import objects, by registered
project and artifact identifiers under the project lock. It verifies root-owned
metadata, expected identity and containment immediately before deletion. The
backup worker never supplies paths or proof sufficient by itself to authorize
root deletion. Before deleting an eligible complete capture, require either a
root-recorded independent restore-drill result bound to that exact repository,
snapshot and capture, or an explicit operator action acknowledging its removal.
If evidence is unavailable or contradictory, retain the artifact and alert.
Incomplete investigation artifacts require explicit operator resolution; they
are never automatically removed. Cleanup is idempotent across interruption and
never follows links or deletes an unrecognized object.

These conservative defaults preserve recent local recovery points while making
capacity failure visible. They can delay backups during a prolonged outage; no
automatic deletion of the only recovery points is permitted to hide that gap.
Local retention runs after each successful upload and at startup, and retries
failed deletions with bounded backoff; an operator can resolve a full spool.

Remote retention is operator-managed with separately provisioned prune credentials
and an independently scheduled Restic `forget`/`prune` procedure. The upload
identity remains append-only for backup data. It has no authority to prune,
delete snapshots, or run a repository-wide unlock. Monitor remote capacity and
failed uploads; missing capacity information is an observation gap, not proof
that space remains. No automated remote pruning or retention window is claimed
by this decision.

During upload recovery, the worker may remove an individually verified lock from the
configured HTTPS repository. The worker must have observed and journaled that
lock while its Restic child was alive. Before deletion it rechecks the lock
contents, repository, job, capture and boot identity, verifies that the original
process is absent, holds the protected import binding and has a current job
lease. The root executor must still permit the exact registered capture and the
kill switch must be clear. Unobserved locks, locks from another boot and locks
owned by other processes remain outside this recovery path. This is lock
recovery only; it does not change local or remote retention authority.
