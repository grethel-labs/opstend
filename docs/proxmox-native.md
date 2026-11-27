# Native OpsTend on Proxmox VE

The first native profile targets **Proxmox VE 9.3 with `pve-manager 9.3.1` on
Debian 13 amd64** for lab qualification. The installed package and the API
must agree on the approved version. Additional package versions require
qualification with the same host and API checks. See the PX01 card for the
remaining installation, upgrade, reboot, and removal gates.
[PX01](plans/proxmox.md#px01--native-installation-und-preflight)

## Run on the PVE node

Use the `opstend` executable from an existing OpsTend Python environment. Pass
a CA file that trusts the certificate served by the local PVE API and set
`--api-name` to a name on that certificate. The connection goes to
`127.0.0.1:8006` and uses the supplied name for TLS verification.

Create a dedicated PVE API token with privilege separation enabled. Preflight
checks that the token has no effective privileges at the time of the request.
Store the full token on one line in a private file readable by the invoking
account with mode `0600` or `0400`. The format is `<user>@<realm>!<token>=<UUID>`. Pass the file
path to `--token-file` to keep the credential out of the command line. The only
API requests are GETs for the token's effective permissions and the API
version. [PVE user and token management](https://github.com/proxmox/pve-docs/blob/master/pveum.adoc) ·
[PVE API viewer](https://pve.proxmox.com/pve-docs/api-viewer/)

```sh
opstend pve-native preflight --mode standalone --api-name pve.example.net \
  --ca-file /path/to/pve-ca.pem --token-file /path/to/pve-token
opstend pve-native plan --mode agent --api-name pve.example.net \
  --ca-file /path/to/pve-ca.pem --token-file /path/to/pve-token
```

Both commands print JSON. `preflight` reports readiness and individual checks
for the host, package version, resources, conflicts, listener, TLS,
permissions, and API version. `plan` adds the prospective layout under
`install_plan`, including when a readiness check fails. Exit `0` indicates
readiness, `2` indicates invalid input, and `3` indicates a failed readiness
check. The commands only read local host state and query the local API.

The minimum is one CPU, 256 MiB of available RAM, and 1 GiB of available space
for each of the install and state paths. When those paths share a filesystem,
it needs 2 GiB available. The installation, state, configuration, and systemd
unit locations must be on writable filesystems. The passive port check treats
an IPv6 wildcard listener as a possible conflict with the standalone port.

## Installation

Both modes use `/opt/opstend-pve` for installed files, `/etc/opstend-pve` for
configuration, and `/var/lib/opstend-pve` for state. Both run the
`opstend-pve-agent.service` unit as `opstend-pve-agent`, with outbound access
to the local PVE API on port 8006.

| Mode | Services and listeners |
|---|---|
| `agent` | Agent service with zero inbound listeners. |
| `standalone` | Agent service plus `opstend-pve-ui.service` as `opstend-pve-ui`, serving authenticated HTTPS on `127.0.0.1:8447`. |

The operator provides the node's Debian CPython and its working `venv` module
(`python3` and `python3-venv`). Use a separately trusted, root-owned bootstrap
environment containing the native installer and its dependencies. The examples
assume you are already root and the bootstrap environment is at
`/opt/admin/opstend-bootstrap`. Use its Python directly in isolated mode.

Obtain the Ed25519 release verification key through an independent trusted
channel. Verify the exact signed archive with that key before staging the
bundle and dependencies. Build an offline wheelhouse from the verified
archive's `requirements.txt` on a compatible Debian amd64 system with the
same CPython version as the node. Use an empty wheelhouse directory and
download one compatible wheel per signed pin. The installer verifies the
release signature and wheel hashes and installs using the local wheelhouse.
[Signed release verification](release.md#build-pack-sign-verify)

```sh
/opt/admin/opstend-bootstrap/bin/python -I -m steward.cli.main release verify \
  /root/opstend-inputs/opstend-release.tar.gz \
  --public-key /root/opstend-inputs/release-key.pub
# On the matching staging system, after verifying and unpacking the archive
python3 -m pip download --require-hashes --only-binary=:all: \
  --dest /path/to/empty-wheelhouse -r /path/to/verified/requirements.txt
```

Stage the archive, verification key, wheelhouse and credentials under
root-owned directories protected from writes by other users. Put the PVE
token and the standalone admin token and TLS private key in individual
root-owned regular files with mode `0400` or `0600`. Use absolute paths
consisting of letters, digits, underscores, periods, hyphens and slashes.
Systemd supplies credentials only to the service that needs them. Preserve
the credential files at the supplied paths for subsequent starts. When you
replace a credential at the same path, restart the unit that uses it to load
the replacement.

Run the installer as root. For agent-only installation use `--mode agent`
and omit all three standalone options at the end. For standalone, supply a
random, independent admin token of 32 to 128 ASCII letters, digits, underscores
or hyphens on one line. Supply a separate PEM TLS certificate whose IP SAN
includes `127.0.0.1`, and its matching unencrypted PEM private key. Make its
trust anchor available to the browser through your trusted channel.

```sh
/opt/admin/opstend-bootstrap/bin/python -I -m steward.cli.main pve-native install \
  --mode standalone --api-name pve.example.net \
  --ca-file /root/opstend-inputs/pve-ca.pem \
  --token-file /root/opstend-inputs/pve-token \
  --release-archive /root/opstend-inputs/opstend-release.tar.gz \
  --release-public-key /root/opstend-inputs/release-key.pub \
  --wheelhouse /root/opstend-inputs/wheels \
  --admin-token-file /root/opstend-inputs/admin-token \
  --ui-cert-file /root/opstend-inputs/ui-cert.pem \
  --ui-key-file /root/opstend-inputs/ui-key.pem
```

Repeat the exact invocation with the same inputs to verify an unchanged
installation (`changed=0`) or resume an interrupted install. If a host or
`useradd` failure leaves only part of a reserved OS account in the password,
group, or shadow database, the installer pauses for the operator to reconcile
the account. Preflight and plan can run before an archive is available.
See [STATUS](STATUS.md) for recorded host acceptance.

## Upgrade and rollback

Use the root-owned bootstrap environment. Stage the newer signed archive and
its own offline wheelhouse using the installation procedure. The upgrade uses
the recorded profile and credential paths and verifies the archive with the
same release signing key that the installation recorded.

```sh
/opt/admin/opstend-bootstrap/bin/python -I -m steward.cli.main pve-native upgrade \
  --release-archive /root/opstend-inputs/next/opstend-release.tar.gz \
  --release-public-key /root/opstend-inputs/release-key.pub \
  --wheelhouse /root/opstend-inputs/next/wheels
```

The upgrade installs into a separate version directory, stops the native
services briefly, switches the release pointer and waits for the services to
report readiness. It preserves the installed units and configuration. An
exact repeat of the active signed release reports `changed=0`. To resume an
interrupted upgrade, repeat the same command with the same signed inputs.

If the new release fails activation, the upgrade reports failure and attempts
to restore the previous verified release. Use `rollback` with the previous
version from your installation record to restore it explicitly or retry an
interrupted restoration. Rollback changes the active code and preserves the
native data directory. If an explicit rollback target fails readiness, the
host attempts to restore the release that was active before that rollback.

```sh
/opt/admin/opstend-bootstrap/bin/python -I -m steward.cli.main pve-native rollback \
  --to 0.1.0rc1
```

## Remove the native installation

Use the bootstrap environment as root for the removal plan and apply. The
plan shows the owned unit files, enablement links and installed releases,
along with the data, service identities and operator credential paths to
retain. Planning and removal work with the PVE API or credentials unavailable,
including after an interrupted upgrade.

```sh
/opt/admin/opstend-bootstrap/bin/python -I -m steward.cli.main pve-native remove --plan
/opt/admin/opstend-bootstrap/bin/python -I -m steward.cli.main pve-native remove \
  --export-config /root/opstend-pve-config.json
```

Omit `--export-config` if you have no need for an export. To export, choose a
new absolute filename under a root-controlled directory. The private JSON
contains the profile configuration and references to credential files. Repeat
the removal with the same options after an interruption.

Removal stops and removes the native services and package files. It retains
the native state under `/var/lib/opstend-pve`, the service identities, a
root-only removal record under `/etc/opstend-pve`, and the operator-held
credentials. To revoke PVE access, remove the dedicated token in Proxmox VE
using the operator account. [PVE user and token management](https://github.com/proxmox/pve-docs/blob/master/pveum.adoc)

## Read status

On the node, use the installed CLI with root's existing operating system
authentication.

```sh
/opt/opstend-pve/current/venv/bin/python -I -B -m steward.cli.main pve-native status
```

For the standalone UI, browse to `https://127.0.0.1:8447/` on the node or
open an SSH local forward from your workstation and use the same URL there.
Sign in as `admin` with the independent admin token when prompted by the
browser. The status JSON is also available at `/status` after authentication.

```sh
ssh -N -L 127.0.0.1:8447:127.0.0.1:8447 operator@pve.example.net
```

Status reports the latest local TLS, token permission and API version
checks and their observation timestamp. An observation becomes stale after
90 seconds or a reboot. Missing or unreadable observations are unavailable.

## Read the PVE inventory

Inventory is optional in both native modes. For the signed install, add
`--inventory-token-file /root/opstend-inputs/pve-inventory-token`. Use a
different privilege-separated token from the health token. Give inventory only
the audit permissions needed for its scope (`VM.Audit`, `Sys.Audit`,
`Datastore.Audit`, and `Pool.Audit`). The token and its PVE user must both have
the intended access. Use a private root-owned file as for the health token.
Only the agent receives it. [PVE user and token management](https://github.com/proxmox/pve-docs/blob/master/pveum.adoc)

On a PX01 installation, upgrade to an inventory-capable signed release. Use
the matching native installer in the trusted bootstrap environment to repeat
the signed `install` invocation with the active release and matching
wheelhouse, the existing installation options, and the additional inventory
token file. The installer records the reference and restarts the native
agent. Repeat the same invocation to resume an interruption. Later upgrades
and install repeats preserve the reference. To rotate the token, replace the
contents at the same protected path and restart the native agent. Keep it a
private regular file with one valid token line. A missing file or a malformed
token line of at most 1 KiB leaves the health check available. If a root change
makes systemd's credential loader fail, for example by replacing the token
with a file larger than systemd's 1 MiB credential limit, the agent cannot
restart until the source is restored or removed.
[systemd 257 credential loader](https://github.com/systemd/systemd/blob/v257/src/core/exec-credential.c#L595-L619)

```sh
/opt/opstend-pve/current/venv/bin/python -I -B -m steward.cli.main pve-native inventory
/opt/opstend-pve/current/venv/bin/python -I -B -m steward.cli.main pve-native inventory --vmid 123
```

These commands require root and return JSON. Standalone mode links to
`/inventory` from the authenticated home page and to each visible guest's
`/guests/<vmid>` page from that inventory. Send `Accept: application/json` on
either authenticated HTTPS route to get the same JSON as the CLI. The routes
return HTTP 200 for inventory read outcomes, with `status` indicating
`observed`, `absent`, `restricted`, `unavailable`, or `stale`. An empty
observed inventory describes the token's scope. A guest outside it and a
guest ID that was never observed have the same detail response.

The agent keeps one bounded snapshot. Unavailable or restricted reads suppress
the previous resource rows. A snapshot older than 90 seconds or from a prior
boot is stale and shows no resource rows. Nodes with `Sys.Audit` can include up
to an hour of CPU fractions and memory and root filesystem measurements in
bytes. Guest details show PVE evidence for network attachments, measurements
and matching tasks where supported by the observed privileges and guest
registration. Guest OS and in-guest details are unverified in this profile.

### Inventory API qualification

The inventory token must receive `release: "9.3"` and `version: "9.3.1"` from
`GET /api2/json/version` over the registered TLS connection. The collector
checks that exact pair before the initial and final scope reads. The installed
package is checked by native preflight. Inventory independently checks the
API reply using its own credential. Every other version pair is unsupported.
The first scoped read on real PVE 9.3.1 covered QEMU and LXC, bridge and storage
data, RRD, tasks, and LXC permission removal and restoration.
[PVE 9.3.1 read evidence](https://github.com/grethel-labs/opstend/pull/12)

All paths below are GETs relative to `/api2/json` on PVE 9.3.1. Use
privilege-separated credentials with narrowly scoped grants for both the PVE
user and the token. Effective permission reports must contain only
`VM.Audit`, `Sys.Audit`, `Pool.Audit`, and `Datastore.Audit`; use custom roles
when a built-in role includes other privileges.
[PVE user and token management](https://github.com/proxmox/pve-docs/blob/master/pveum.adoc) · [PVE API viewer](https://pve.proxmox.com/pve-docs/api-viewer/)

| Path | Required visibility | Projected evidence |
|---|---|---|
| `/version` | Authenticated token | Exact version pair for qualification; extra fields such as the build repository identifier are ignored. |
| `/access/permissions` and `/access/permissions?path=/nodes/{node}` | Token's own effective ACL, with an exact path check for node audit | Checks token scope and rejects unexpected privileges. ACL contents and principals stay out of the projection. |
| `/cluster/resources` | `VM.Audit` on `/vms/{vmid}`, `Sys.Audit` on `/nodes/{node}`, `Pool.Audit` on `/pool/{pool}`, `Datastore.Audit` on `/storage/{store}` | Scoped node and guest identities and supported counters, visible pool names and guest pool links, and per-node datastore type, content kinds, sharing flag and capacity. Pool membership and aggregate counters, storage usage and volumes, and other resource types are not projected. |
| `/nodes/{node}/{qemu\|lxc}/{vmid}/config?current=1` | Visible guest and `VM.Audit` on `/vms/{vmid}` | Interface index, bridge name and explicit VLAN tag from `netN`. Guest IP and MAC addresses, full config, guest OS, agent capabilities and in-guest state are not collected as evidence. |
| `/nodes/{node}/rrddata?timeframe=hour&cf=AVERAGE` | Exact effective `Sys.Audit` on `/nodes/{node}` | CPU fraction, memory and root filesystem usage and capacity in bytes. |
| `/nodes/{node}/{qemu\|lxc}/{vmid}/rrddata?timeframe=hour&cf=AVERAGE` | Visible guest, `VM.Audit` and PVE's guest identity and registration time | Guest CPU fraction and capacity, memory and disk in bytes, and disk and network rates in bytes per second. Only buckets after the registration and interpolation window are eligible. |
| `/nodes/{node}/tasks?vmid={vmid}&source=all&limit=20` | Visible guest, its PVE identity and registration time, and exact effective `Sys.Audit` on `/nodes/{node}` | Selected lifecycle operations for the matching guest kind and ID, with times and a normalized status. Usernames, UPIDs, task logs and raw diagnostics are not projected. |

The agent makes each request within a two-second limit and each collection
within a ten-second limit. It uses a separate time reserve for rechecking
version and scope at the end. The first HTTP 429 ends that inventory
collection with `status: unavailable` and `evidence.state: rate_limited`
at the affected source. It sends no further inventory GETs for that
collection. The next scheduled refresh starts a new collection independently
of any `Retry-After` header. A different version pair also leaves the
inventory unavailable, with `api_version` evidence in state `unsupported`.
A malformed version, ACL or resource roster refuses the snapshot with
`invalid` evidence. A malformed optional detail leaves its items empty with
`invalid` evidence. The existing CLI and HTTPS status values also apply
to these results.

### Rotate the PVE API trust anchor

Confirm the new trust anchor with the operator responsible for the PVE API.
Compare its SHA-256 fingerprint against a trusted out-of-band copy and
check the new endpoint chain for the registered API name. Keep that name
in the new certificate's SAN. Replace the PEM at the original protected
`--ca-file` path with the confirmed anchor. Restart
`opstend-pve-agent.service` so systemd reloads its `pve-ca` credential.
For standalone mode restart `opstend-pve-ui.service` as well, then check
`pve-native status` and `pve-native inventory` for fresh observations. A
direct adapter call loads its explicit CA file for each new collection.
Systemd's per-start credential remains fixed during a running agent.
[PVE certificate management](https://pve.proxmox.com/pve-docs/chapter-sysadmin.html#sysadmin_certificate_management) · [systemd service credentials](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#LoadCredential=ID:PATH)

An untrusted chain fails TLS before the token is sent. A collection clears
the previous snapshot before its first inventory GET. If the agent stops
during the read, the CLI sees unavailable inventory until a fresh
collection publishes a complete snapshot.

The [PX02 qualification procedure](../tests/integration/gates/m9-px02.md)
covers the installed CLI and authenticated HTTPS surface, an actual
PVE permission change, and isolated fault injection for the M9 batch.

## Confirm native guest power operations

Power management is opt-in on native PVE 9.3.1. Start from the trusted native
operator CLI. It verifies the active signed release before starting the
executor from its versioned path. Provision one dedicated PVE token with
privilege separation enabled. Give its PVE user and token a custom role with
exactly `VM.Audit` and `VM.PowerMgmt` on each registered `/vms/{vmid}` path.
Keep the token separate from the native health and inventory credentials in a
root-owned regular file with mode `0400` or `0600`. The executor checks the
token's effective ACL against the full registry. [PVE user and token management](https://github.com/proxmox/pve-docs/blob/master/pveum.adoc)

Create `/var/lib/opstend-pve-executor` as `root:root` with mode `0700` and
place `power.json` there as `root:root` with mode `0600`. Use the actual local
PVE node name, guest type, and the guest's `uid` and millisecond `rtime` from
the PVE resource roster. To read that roster, run
`pvesh --noproxy get /cluster/resources --type vm --output-format json` on the
node. Register a replacement guest explicitly when its generation changes.
This example registers one QEMU guest.

```json
{
  "schema_version": 1,
  "node": "pve",
  "write_token_file": "/root/opstend-inputs/pve-power-token",
  "guests": [
    {
      "kind": "qemu",
      "vmid": 190,
      "pve_uid": "abcdefghijklmnopqrst",
      "registered_at_ms": 1795737600000,
      "operations": ["start", "shutdown", "reboot"]
    }
  ]
}
```

Use `lxc` as the kind for a container. The executor checks live generation,
power state, HA assignment, locks, templates, and pending configuration.
It also reads the exact local pending configuration under root because PVE's
scoped API can suppress pending options. Only the safety outcome crosses the
executor boundary. The native power method addresses the VMID, so coordinate
PVE changes made through other tools during confirmation and dispatch.

Run the following commands on the registered PVE host. Replace `JOB_ID` with
the identifier returned by the plan. Review the guest and observed state
before confirming. Each confirmation expires in five minutes.

```sh
/opt/opstend-pve/current/venv/bin/python -I -B -m steward.cli.main pve-native power plan --vmid 190 --operation reboot
/opt/opstend-pve/current/venv/bin/python -I -B -m steward.cli.main pve-native power execute --confirm JOB_ID
/opt/opstend-pve/current/venv/bin/python -I -B -m steward.cli.main pve-native power reconcile --job-id JOB_ID
```

Reconciliation checks the recorded PVE task and the actual guest state.
Run it again while `next_action` is `reconcile`. For reboot, the first leg
uses graceful shutdown. After reconciliation verifies that task and observes
the guest stopped, `next_action` becomes `execute`. Confirm the start leg with
`pve-native power execute --confirm JOB_ID --continue-reboot`, then reconcile
the start task. If the plan expires between legs, the job reports failure and
the guest may remain stopped. Review its current state with a new plan.

Use `pve-native power status --job-id JOB_ID` to read the local journal. A lost
response or interrupted dispatch leaves the job `uncertain` after reconciliation
and holds the VMID for that job. If you can identify the exact task in PVE,
use `pve-native power reconcile --job-id JOB_ID --upid UPID` to verify and bind it.
The executor compares a bounded PVE task history against its durable
pre-dispatch baseline and requires one new matching task. Incomplete or
ambiguous task history keeps the VMID fenced. Reserve the token for this
executor so its PVE tasks identify OpsTend dispatches.
Replaying a confirmation returns the current job once that leg is dispatched.
Creating `kill-switch` in the executor directory stops dispatch. The native
remove command preserves the executor directory, including its audit and job
history. The PVE operator manages credential revocation.

### Power job JSON

The CLI returns the same versioned job object for planning, execution, status,
and reconciliation. The fields are `schema_version` (currently `1`), `job_id`,
`operation` (`start`, `shutdown`, `reboot`), and `target` (`node`, `kind`, `vmid`).
`created_at`, `expires_at`, and `updated_at` are UTC timestamps. `observed_state`
records the plan's `running` or `stopped` state. `desired_state` records the
intended final state, and `current_state` holds the latest state known to the
job or `null`.

`state` is `prepared`, `dispatching`, `accepted`, `verifying`, `succeeded`,
`failed`, or `uncertain`. `next_action` is `execute`, `reconcile`, or `null`.
`error_code` is a machine-readable reason or `null`. `tasks` contains one
entry per bound native task with `operation` (`start` or `shutdown`),
`task_ref` (an opaque SHA-256 reference), and `state` (`accepted`, `running`,
`succeeded`, or `failed`). The public object keeps native UPIDs and PVE
principals private. The root-only CLI reports refused requests separately
from job results.

## Confirm a native full clone

Native provisioning uses the signed root-only executor for a stopped,
same-node full clone from a registered QEMU or unprivileged LXC template.
Register each destination VMID with exactly one source VMID and an approved
pool, storage, network profile, and resource limits. Use a dedicated non-root
PVE user and privilege-separated token. Keep its credential in a root-owned
regular file with mode `0400` or `0600`, with a separate file and PVE user
from power, inventory, and health.

Use a clean template configuration with no snapshots and ordinary
PVE-managed QEMU disks or an unprivileged LXC root filesystem. The destination
storage must be enabled and offer `images` for QEMU or `rootdir` for LXC.
The inherited network must use an active conventional bridge with the exact
registered VLAN and link state. The inherited CPU, memory, disk, and swap
must fit the policy's explicit limits.

Give the provisioning user and token only the following non-propagating
effective ACLs. The executor checks the complete set against the policy.

| Exact PVE ACL path | Privileges |
| --- | --- |
| `/vms/{template_vmid}` | `VM.Clone`, optionally `VM.Audit` |
| `/vms/{destination_vmid}` | `VM.Allocate`, optionally `VM.Audit` |
| `/storage/{storage}` | `Datastore.AllocateSpace`, optionally `Datastore.Audit` |
| `/sdn/zones/localnetwork/{bridge}` | `SDN.Use` for an untagged bridge |
| `/sdn/zones/localnetwork/{bridge}/{tag}` | `SDN.Use` for a tagged bridge |

The executor reads local evidence as root to check pool, storage, resource and
network eligibility. Use the pool only as an approved destination in the
policy. The token's allocation grant is restricted to the exact destination
VMID. Keep the token exclusive to the executor so its native tasks can be
attributed during reconciliation.

Place `provision.json` in `/var/lib/opstend-pve-executor`, with the directory
owned by `root:root` at mode `0700` and the file owned by `root:root` at mode
`0600`. Use the template's `uid` and millisecond `rtime` from the local
resource roster described above, and its native configuration `digest` from
`pvesh --noproxy get /nodes/pve/qemu/194/config --current 1 --output-format json`.
Use the `lxc` API path for an LXC template. Review the template before
registering its generation and digest. This example permits VMID 196 from
QEMU template 194. To add an unprivileged LXC template 195, register its own
generation and digest and a distinct destination such as VMID 197.

```json
{
  "schema_version": 1,
  "node": "pve",
  "write_token_file": "/root/opstend-inputs/pve-provision-token",
  "templates": [
    {
      "kind": "qemu",
      "vmid": 194,
      "pve_uid": "abcdefghijklmnopqrst",
      "registered_at_ms": 1795737600000,
      "config_digest": "0123456789abcdef0123456789abcdef01234567"
    }
  ],
  "targets": [
    {
      "vmid": 196,
      "template_vmid": 194,
      "pool": "rc2-managed",
      "storage": "local-lvm",
      "networks": [{"index": 0, "bridge": "vmbr0", "link_down": true}],
      "limits": {
        "max_vcpus": 2,
        "max_memory_mib": 1024,
        "max_disk_bytes": 8589934592,
        "max_swap_mib": 0
      }
    }
  ]
}
```

On the registered PVE host, review the plan before confirming its exact job
ID within five minutes. The plan returns the source, target, name, pool,
storage, `resources` observed on the template, `networks`, and `limits`.
Use the same CLI entry point for all four operations.

```sh
/opt/opstend-pve/current/venv/bin/python -I -B -m steward.cli.main pve-native provision plan --template-vmid 194 --vmid 196 --name example-vm
/opt/opstend-pve/current/venv/bin/python -I -B -m steward.cli.main pve-native provision execute --confirm JOB_ID
/opt/opstend-pve/current/venv/bin/python -I -B -m steward.cli.main pve-native provision status --job-id JOB_ID
/opt/opstend-pve/current/venv/bin/python -I -B -m steward.cli.main pve-native provision reconcile --job-id JOB_ID
```

Confirming the same job again returns its recorded state. The durable dispatch
intent reserves the destination among local power and provision jobs. PVE
decides whether the destination VMID is occupied at clone time. A confirmed
collision returns `vmid_conflict`. Before sending the clone, the executor
checks current permissions, policy, and source evidence again. Coordinate
external changes to the template during dispatch because the PVE clone method
cannot condition the write on the template digest.

Use `status` to read the job and `reconcile` to verify a native task. A job
succeeds after PVE archives task completion and local readback verifies a
stopped guest with the expected name, pool, storage, network and resource
profile. The executor correlates the guest registration time with task
completion at the one-second granularity of the PVE task archive. Coordinate
external changes to the target while the job is verifying. The result
includes an opaque guest generation, and task references are also opaque.
Unavailable completion evidence or a temporary readback error leaves the
job `verifying` with an `error_code` and allows another reconciliation.

After a lost reply, the job can become `uncertain` and keep its VMID reserved.
Use `pve-native provision reconcile --job-id JOB_ID --upid UPID` with the
completed native task from PVE. The executor requires a unique new task
relative to the pre-dispatch baseline, with a recorded worker start within
30 seconds of the dispatch second. It verifies the exact template and
destination in the completed PVE log before binding the task. Unproven tasks and
potential partial clones keep the destination reserved for operator
investigation. The executor issues one clone POST per confirmed job and has
no guest cleanup action. The existing executor-directory `kill-switch`
also stops provisioning dispatches.

The [PX03 qualification procedure](../tests/integration/gates/m9-px03.md)
checks lifecycle and full clones on the signed M9 test installation and
reproduces response loss with an isolated TLS fixture.
