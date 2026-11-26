# ADR 0004: explicit cancellation of pending backup uploads

Status: accepted for implementation · 2026-11-16

A root-recorded pending upload must remain protected until its lifecycle has
been resolved. The unprivileged worker's receipts are observations, not root
authority to delete a capture or declare an independent restore successful.
An operator may deliberately abandon an upload, including after failure, but a
queued worker must not later restart it merely because the service restarts.

The root executor records an exact project/artifact/capture cancellation only
for a registered, root-owned protected import, after an explicit operator
request. It refuses unless the fixed backup service is confirmed stopped with no
remaining service cgroup, and the worker's root-owned import directory can be locked
exclusively. Unknown systemd or lock state is denial. The cancellation is a
separate durable root record, not a successful upload, a restore proof, or a
removal acknowledgement. The original capture, import, pending-protection record
and any private worker job remain intact until independently authorized cleanup.

For automatic recovery of a repository lock, the worker must hold the same
shared import lock and request the separate read-only
`backup_lock_cleanup_permit` for the exact project/artifact/capture. This permit
applies the upload-registration checks and additionally denies when the kill
switch is present. It does not authorize deleting arbitrary repository objects:
the worker must separately verify the recorded job, repository, lock identity,
boot and absence of the original process immediately before targeting that lock.
An unknown executor, lock or process state remains a denial.

The backup peer may additionally call the read-only `backup_upload_permit` IPC
operation with only registered project/artifact/capture identifiers. Immediately
before processing an upload, the managed worker holds a shared lock on that root-owned import
directory and asks root for that exact permit. Root denies unknown, disabled,
mismatched or cancelled records; an unavailable executor is retryable. This
extends B01's backup peer contract by one narrow, non-mutating lookup. The root
cancellation transaction holds an exclusive lock on that same root-owned directory, so it
cannot race a managed worker between permit and processing. Standalone operator-run worker mode retains
its existing behavior and is outside the managed retention contract.

Cancellation must never by itself permit deletion, infer that uploaded bytes
exist, or release protection. Import cleanup requires separate operator
acknowledgement, an intact root capture, stopped-service and exclusive-lock
checks, and journaled recovery. Existing unknown or legacy imports fail closed until a
registered export establishes their exact root-owned binding. An operator can
later explicitly reinstate a cancelled upload under the same stopped-service and
lock checks while its import and registration remain. After a separately
acknowledged import retirement, the cancellation tombstone remains and prevents
re-export or reinstatement. After the separately acknowledged root capture is
retired and matching imports and registrations are absent, the executor can
remove the tombstone in the same transaction as its retirement intent; an old
worker still cannot obtain a permit without a new root registration. Neither
operation modifies worker-owned state.

To bound root metadata without discarding uncertain history, the executor accepts
at most 128 cancellation records per project. At the limit it refuses a new
cancellation and emits a capacity alert. Historical orphan records require
explicit operator reconciliation. The executor removes one only while the fixed
service is confirmed stopped, under the project lock, after bounded root-owned
capture/import inventories contain no matching or ambiguous artifacts and no
matching upload registration, acknowledgement, pause, schedule or retirement
intent remains. Unknown ownership, incomplete inventory or a changed stop state
refuses reconciliation. A stale worker still has no permit without a new root
registration. No backup data or worker-owned state is deleted by reconciliation.
