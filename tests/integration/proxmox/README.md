# Disposable Proxmox acceptance

This harness creates one explicitly selected VM with hardware KVM, a private
Ubuntu cloud-init seed, and QEMU user networking. SSH is forwarded only on the
Proxmox host's loopback interface. It does not edit bridges, host firewall rules,
existing SSH configuration, or existing deployment keys.

Use a dedicated authorized VMID, free forwarding ports and sufficient capacity.
The default guest has 4 vCPU, 8 GiB RAM and a 24 GiB disk; autostart is disabled.
The controller needs the toolkit environment, Git, `ssh`, `ssh-keygen`, `xorriso`,
Node/npm and the normal release build tools. The node needs `qm`, `pvesh`,
`pvesm`, KVM and the QEMU `user` network backend.

Use a private test configuration based on `examples/server.api.yml`, retaining
its `notes` example workload and standard guest ports. The shared acceptance
assertions target that fixture; arbitrary production configurations need their
own workload assertions.

Inspect the intended node read-only through its existing SSH configuration:

```bash
ssh -F /path/to/ssh/config NODE_ALIAS 'qm list; pvesm status; free -m; test -c /dev/kvm; ss -Htln'
```

Download the official Ubuntu 26.04 amd64 cloud image and verify its SHA256
against the official release `SHA256SUMS`. Supply that exact local image and
verified digest below. The harness verifies it before provisioning and verifies
the uploaded private cached copy before every reset.

```bash
W=.steward/proxmox-target
pve_test() { .venv/bin/python tests/integration/proxmox/harness.py --workdir "$W" "$@"; }
pve_test init \
  --ssh-config /path/to/ssh/config --alias NODE_ALIAS --node NODE_NAME \
  --vmid FREE_VMID --name steward-acceptance-8gb --tag steward-acceptance-8gb \
  --server-name steward-test-target --local-port 2224 --remote-port 22223 \
  --repo . --commit REVIEWED_COMMIT --venv .venv --collections .steward/collections \
  --identity /path/to/existing/deployment_key --config /path/to/private/server.yml \
  --base /path/to/verified/ubuntu-cloud.img --base-sha256 VERIFIED_SHA256
pve_test provision
```

`init` snapshots only the selected commit, builds its release, and creates
separate configuration, generated files and CLI state for this VM. It derives
the deployment public key without replacing the existing private key. A new
**guest host key** is generated inside the private work directory and pinned
before the first guest connection. Private seed/key/ownership files stay outside
Git under `.steward`; do not publish them or their contents.

Keep the tunnel running in a separate terminal:

```bash
pve_test tunnel
```

Wait for the new guest using a genuinely fresh TCP connection:

```bash
ssh -i "$W/id_test" -p 2224 -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$W/known_hosts" \
  -o ControlMaster=no -o ControlPath=none deploy@127.0.0.1 \
  'cloud-init status --wait; sudo dpkg --audit; hostname; free -m; nproc'
pve_test cli doctor
pve_test cli deploy --yes --verbose
pve_test checks
pve_test measure
```

The standard VM checks are reused with only the snapshot root, server name and
forwarded SSH port adapted. They prove second deployment `changed=0`, platform
health, workload/secret/socket isolation, IPv4/IPv6/metadata/DNS egress refusal,
self-healing, event correlation/redaction, kill switch, reboot and data
persistence. Keep the complete output and exit status as evidence. The checks
intentionally mutate only the disposable guest.

`measure` writes private `measurements.json` with the observed vCPU count,
memory and disk use, boot identity, and per-service active/restart/RSS/cgroup
memory/CPU counters. Compare measurements at similar idle points; the default
disabled scanner does not measure a full provider/container scanning workload.

For the private bot/notifier fixture, the adjacent
[`../vm/messaging.py`](../vm/messaging.py) runs with the installed guest venv as
root. `--restart-bot` additionally proves that the same request ID/body with a
fresh signature returns the original cached response after a real bot service
restart. Use only an owned disposable guest and a loopback-only refused
notification destination; never configure external recipients for this test.

## Repeat a fresh installation

After saving the previous logs and measurements:

```bash
pve_test reset
# Keep/reopen the same loopback tunnel; repeat fresh SSH/cloud-init, doctor,
# deployment and checks above.
```

`reset` is destructive **only to this recorded disposable VM**. It first requires
an exact match of the private ownership record's SMBIOS UUID, name, ownership
tag and complete disk list. A changed identity or unexpected disk causes refusal
before shutdown. The local base and any existing remote base cache must also
pass their SHA256 checks before shutdown or deletion. It shuts down that VM, destroys its configured own disk,
imports the SHA-checked base again, and recreates it with a new recorded UUID.
Other VMs, disks and host networking are untouched. A missing/partially
provisioned VM requires inspection; the harness does not adopt unknown layouts.

This is fresh-install acceptance, not production backup restoration. Public
ACME routes, other architectures and recovery of real user data need separate
acceptance evidence.

Before using an owned guest as a restore target, recheck its recorded node
identity and the boot ID from its separately saved fresh-install proof:

```bash
pve_test restore-preflight --boot-id RECORDED_FRESH_BOOT_ID \
  --image EXACT_IMAGE_REFERENCE_WITH_SHA256_DIGEST
```

The command uses a new pinned SSH connection, checks the guest UUID and boot
again, and refuses known Steward paths, accounts, registered or loaded system
units, or existing containers in the deployment user's rootless Podman store.
It requires rootless Podman and the exact image to be present without a pull.
These checks do not establish that every possible workload or filesystem path
is empty, and they do not replace a fresh-install proof or a restore test.

## Temporary external HTTPS Restic endpoint

`restic_server.py` creates a separate, short-lived rest-server 0.14.0 fixture
on the selected SSH node. Use an independently verified upstream Linux amd64
archive and a free unprivileged port. The archive hash is checked before SSH or
any remote mutation. The SSH configuration and existing keys are reused without
modification and strict host-key checking remains enabled.

```bash
R=.steward/restic-endpoint
.venv/bin/python tests/integration/proxmox/restic_server.py --workdir "$R" start \
  --ssh-config /path/to/ssh/config --alias NODE_ALIAS \
  --archive /path/to/rest-server_0.14.0_linux_amd64.tar.gz \
  --archive-sha256 VERIFIED_UPSTREAM_SHA256 --port FREE_LOOPBACK_PORT
.venv/bin/python tests/integration/proxmox/restic_server.py --workdir "$R" status
```

The randomly named systemd service listens exclusively on `127.0.0.1`. It uses
DynamicUser, an empty capability set, NoNewPrivileges, PrivateTmp, PrivateDevices,
ProtectSystem=strict, a 256 MiB memory limit and a 24-hour runtime limit. Its own
StateDirectory contains the repository, limited by rest-server to 1 GiB per
repository. Append-only mode, private repositories and upload verification remain
enabled. The service is not enabled for boot. No firewall, bridge or VM settings
are changed.

A fresh private certificate authority valid for one day covers loopback and
QEMU user-network gateway `10.0.2.2`. The node receives its TLS key and a hash of
a random Basic Auth password through stdin into root-owned private files;
systemd passes these via LoadCredential. Request logging is disabled. Client
files `repository`, `username`, `auth-password` and `cert.pem` stay inside the
private controller workdir. Pass these as file references to the client. No
Restic encryption password is generated or sent to the server: create and keep
that exclusively on the client. Never commit the private workdir.

Start and status perform real certificate-verified HTTPS requests: unauthenticated
access must return 401 and authenticated access to the empty repository must
return 404. These probes do not initialize a repository or upload data. From a
QEMU user-network guest, `10.0.2.2:PORT` may reach the node loopback listener;
verify this separately from the intended service UID. Successful connectivity
as the SSH deployment user does not prove that the backup UID's outbound policy
allows it. This fixture grants no guest firewall exception. An endpoint on the
same physical node is external to the guest but is not an independent physical
failure domain.

```bash
.venv/bin/python tests/integration/proxmox/restic_server.py --workdir "$R" cleanup
```

Status and cleanup require the private ownership token and exact root-owned
namespace, unit hash and executable hash. Cleanup stops only the matching unit,
removes that unit and its TLS/auth source files, and reloads systemd. It retains
the ownership marker, binary and own encrypted repository for review; it never
recursively deletes state or touches the executor's capture spool. Cleanup is
intentionally one-shot; keep its receipt and provision a new random namespace
for another run. If start fails after creating the namespace, the same ownership
file permits guarded cleanup. Existing namespaces and occupied ports are refused.

Guard tests and actual Node acceptance receipts cover invalid scope and archive
hash, wrong-token cleanup refusal with the live service unchanged, authenticated
TLS, and successful cleanup of a separate disposable fixture. Receipts contain
no passwords, keys or Restic encryption secrets.

## Isolated application-drill building blocks

`steward-backup application-drill` is an unprivileged, local guest primitive;
it does not reset a VM or prove that its guest is fresh. Before invoking it,
independently establish the owned guest identity and fresh-boot evidence. Use a
separate read-only repository identity and place the repository descriptor,
Restic password, optional TLS/basic-auth files, exact upload receipt and drill
specification in a private directory owned by the drill user. Do not transfer
the uploader's write credential to the restore guest. The sample application
source file must be the committed `sample-app/sample-notes/app.py` for revision
`bundled:sample-notes@0.1.1`; the exact digest-pinned Python image must already
be present in that user's rootless Podman store. The drill never pulls an image.

`steward-backup restore-test` runs the same isolated application workflow and
requires both `--spec` and `--app`. For a byte-only check, use the explicitly
named `steward-backup verify-bytes`; it uses read-only repository access and
does not verify an application. This replaces the previous byte-only meaning of
`restore-test`. The top-level `steward restore-test` runs the same isolated
workflow on the machine where the command is invoked. It requires a registered
sample project, exact receipt identifiers and private reader credentials; the
repository host and port must match the configured backup endpoint. Use a
repository account restricted to read access by the server: the client's own
read-only command restriction does not prove server-side permissions. The
normal `backup.enabled` availability guard remains in force until B08.

The private specification is a JSON object containing `v: 1`, the exact
`repository_id`, `snapshot_id`, `capture_id`, the full `binding` from the receipt,
`app_sha256`, `note_sha256` (UTF-8 bytes of the expected note), and
`attachment_sha256`. All hashes are lowercase SHA256 strings. The restored
sample tree must have `notes.db` and `attachments/<attachment_sha256>`. Avoid
putting note text or credentials in shell arguments or public test results.

On an installed host with the backup worker enabled, root can request an exact
completed worker receipt using `steward-host backup-receipt PROJECT` with
`--config-revision`, `--repository-id`, `--capture-id` and `--snapshot-id`.
Each value must match a completed, data-checked and byte-restored job. The
result is worker-reported evidence and can include a private snapshot path;
the `receipt` member is the input expected by the restore fixture and must be
saved only to an operator-private file. API, collector and controller peers
cannot use this detailed receipt query. This does not enable backup scheduling
or authorize production recovery.

The controller also provides `steward backup-receipt` with an explicit
`--project`, `--config-revision`, `--repository-id`, `--capture-id`,
`--snapshot-id` and a new `--out` file. It verifies the returned binding again,
stores only the receipt with mode `0600`, and refuses an existing output path.
The normal `backup.enabled` availability guard still applies; this command does
not bypass the B08 acceptance gate.

Once the normal backup gate is available, invoke the controller command on the
separate unprivileged restore host with explicit inputs:

```bash
steward restore-test --config server.yml --limit SERVER --project notes \
  --config-revision REVISION_SHA256 --repository-id REPOSITORY_SHA256 \
  --capture-id CAPTURE_SHA256 --snapshot-id SNAPSHOT_SHA256 \
  --receipt PRIVATE_RECEIPT --spec PRIVATE_DRILL_SPEC --app REVIEWED_SAMPLE_APP \
  --repository-file PRIVATE_READER_REPOSITORY --password-file PRIVATE_REPOSITORY_PASSWORD \
  --reader-username-file PRIVATE_READER_USER --reader-password-file PRIVATE_READER_PASSWORD \
  --ca-file PRIVATE_CA --state-dir PRIVATE_WORK_DIR --out NEW_PRIVATE_EVIDENCE
```

The reader and encryption passwords must differ. The command checks the sample
revision and its bundled source hash, exact receipt and specification bindings,
and an integrity-checked receipt before it accesses the repository. The drill
independently verifies the restored bytes, even when no earlier restore exists. It never
replaces an existing output. Its evidence still states `fresh_vm_proven=false`
and `production_restore_authorized=false`; a separate owned-VM proof is needed
for fresh-VM acceptance.

```bash
steward-backup application-drill \
  --repository-file /private/repository --password-file /private/password \
  --username-file /private/reader-user --auth-password-file /private/reader-password \
  --ca-file /private/ca.pem --receipt /private/receipt.json --spec /private/spec.json \
  --app /private/committed/sample-app/sample-notes/app.py \
  --state-dir /private/drill-state --out /private/drill-evidence.json
```

The operation uses only Restic read commands with `--no-lock`, verifies the
receipt's repository/snapshot/capture binding and full restored tree, and runs a
rootless container with no network, no capabilities, and a read-only container
root. Only the private restored data directory is writable. A random container
ownership label is checked before cleanup; an unconfirmed cleanup is a failure.
The report includes separate byte and application times and sets
`fresh_vm_proven` and `production_restore_authorized` to false. A separate
ownership-guarded harness receipt must bind that report to the fresh VM.

### Reusable owned-guest restore run

`restore_run.py` transfers one already uploaded, integrity-checked snapshot to
an owned restore guest using the guarded reader proxy. It requires private
ownership work directories for two distinct recorded VMs, an independent
fresh-guest proof, a full Git commit, the SHA256-pinned Restic binary, and the
exact receipt and drill specification. Both VM identities and boot IDs, the
target preflight, proxy read-only behavior and all bindings are checked before
credentials are sent. The target receives only the proxy reader credentials and
repository encryption password; no uploader credential or plaintext fixture
data is transferred. The selected commit must contain the bound sample source
and hash-pinned Python requirements. The repository encryption password must
also differ from the proxy reader password.

```bash
RUN=.steward/owned-restore-run
.venv/bin/python tests/integration/proxmox/restore_run.py --workdir "$RUN" run \
  --source-workdir SOURCE_VM_WORKDIR --source-boot-id SOURCE_BOOT_ID \
  --target-workdir TARGET_VM_WORKDIR --fresh-proof PRIVATE_FRESH_PROOF \
  --proxy-workdir ACTIVE_READ_PROXY_WORKDIR --password-file PRIVATE_REPOSITORY_PASSWORD \
  --receipt PRIVATE_CHECKED_RECEIPT --spec PRIVATE_DRILL_SPEC \
  --repo . --commit FULL_REVIEWED_COMMIT --restic-binary VERIFIED_RESTIC_BINARY \
  --restic-sha256 VERIFIED_RESTIC_SHA256
```

The guest creates a private token-scoped workspace, installs only hash-pinned
runtime dependencies and runs `steward-backup restore-test` with the read-only
identity. On success the workspace is removed and private `evidence.json`
retains separate byte and application timestamps. The evidence binds the
operator-supplied fresh proof but does not attest that the selected source VM
created the snapshot or prove physical failure-domain independence. The inner
report does not authorize production recovery.

If interrupted or unsuccessful, retain the controller work directory and run
the same committed helper revision with:

```bash
.venv/bin/python tests/integration/proxmox/restore_run.py --workdir "$RUN" cleanup
```

Cleanup rechecks target ownership and boot, requires the original helper hash
and token-bound marker, and refuses an active workspace lock or any remaining
rootless container. It never removes a container on the operator's behalf; an
unconfirmed cleanup requires inspection of that owned test guest.

`read_only_proxy.py` is a test-only, loopback-bound TLS proxy for the fixed
`/fixture/fixture/` repository path. It requires two distinct owner-private
credential files containing `username:password` without a newline. The reader
credential goes to the restore guest; only the proxy identity receives the
backend writer credential. It forwards GET/HEAD only, verifies the upstream
TLS CA, refuses writes and redirects, and does not log request contents. Run it
only in an explicitly owned disposable fixture with independently guarded
lifecycle and cleanup. The client-side `read_only=True` restriction is an
additional check; it does not by itself prove server-side read-only access.

### Guarded test-proxy lifecycle

`restore_proxy_harness.py` can provision the preceding test-only read proxy on
the same SSH node as an existing owned `restic_server.py` fixture. It verifies
the upstream namespace, ownership token, port, executable and unit hashes on
the node before creating a separately named, short-lived DynamicUser service.
It generates a new reader password and TLS CA in an owner-private controller
work directory; the writer credential is sent only to the proxy service. It
checks unauthenticated denial, authenticated read and write refusal. Use a free
loopback port and never reuse the writer credential as the reader credential.

```bash
P=.steward/restore-read-proxy
.venv/bin/python tests/integration/proxmox/restore_proxy_harness.py --workdir "$P" start \
  --upstream-workdir .steward/restic-endpoint --port FREE_LOOPBACK_PORT
.venv/bin/python tests/integration/proxmox/restore_proxy_harness.py --workdir "$P" status
# Transfer only P/repository, P/username, P/auth-password and P/ca.pem to the
# owned restore guest; transfer the encryption password separately.
.venv/bin/python tests/integration/proxmox/restore_proxy_harness.py --workdir "$P" cleanup
```

The service listens only on node loopback, which QEMU user-network guests may
reach through `10.0.2.2`. Cleanup verifies its private token, every present
file hash and the exact service-unit hash before stopping or removing anything;
it never edits the upstream fixture. It removes the proxy's TLS key and both
proxy credentials after the owned service is confirmed inactive. The private
ownership record and non-secret source/certificate files remain for review.
Setup publishes files atomically without overwriting existing paths. Cleanup
checks the loaded unit and cgroup before deleting credentials and recovers only
token-bound, recognizable interrupted operations. The guard source hash is
pinned to the controller record, so lifecycle commands must use the same guard
revision. The service has a two-hour runtime limit. The controller-side work directory
still contains the reader credential and ownership token and must remain private.
