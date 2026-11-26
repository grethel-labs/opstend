# ADR 0006: Application graph compatibility

Status: accepted for L01 design · Date: 2026-11-16

## Context

Existing schema-v1 `projects` describe independent single-service workloads.
Their full effective representation is content-addressed and compared with the
root desired revision and the API's pending revision. Adding an empty field to
that representation would change every existing revision and could turn an
unchanged deployment into a conflict. ADR 0002 defines applications with
service dependencies and shared or separate isolation; group operations and
network enforcement are not yet accepted.

## Decision

- Keep `projects` unchanged. Add `applications` as an optional list of named
  application graphs; omitting it and supplying an empty list have the same
  meaning. Omit the empty list from the effective representation so existing
  project-only configuration revisions remain byte-for-byte unchanged.
- Application IDs are unique in the application list. Service IDs are unique
  within their application; dependencies name services in that same application.
  Reject duplicate edges, missing dependencies, self-dependencies and cycles.
  Use deterministic lexical tie-breaking for the dependency order. Stop order
  is its reverse; affected dependents are the transitive reverse closure.
- Do not implicitly migrate a legacy project into an application or silently
  reinterpret its user, data, network or removal semantics. An operator who
  chooses to migrate must plan an explicit configuration change and preserve
  existing data; until lifecycle migration is implemented this conversion is
  unavailable.
- Shared isolation means one application user and shared Podman network;
  separate isolation means distinct service users and data with only declared
  dependency edges. Rendered identifiers must be deterministic, bounded and
  collision checked against legacy projects and one another. A dependency by
  itself does not publish a port or create a root shell interface.
- Services in a shared network namespace require distinct container ports.
  [Podman registers containers sharing a pod network under the pod name](https://docs.podman.io/en/latest/markdown/podman-network.1.html),
  so service-name resolution needs explicit mappings rather than assuming
  container names are registered individually. Prepare each shared service
  name as a mapping to `127.0.0.1`; a shared pod can install these using
  [Podman's host mappings](https://docs.podman.io/en/v5.5.2/markdown/podman-systemd.unit.5.html).
  The graph alone does not install these mappings. L02 must validate the
  generated units, user namespace, connectivity and firewall enforcement on
  each supported profile. The tested Ubuntu 26.04 pod setup required both
  `passt` and `catatonit`; installing and verifying these remains L02 work.
- A nonempty application graph is not deployable until its registered units,
  lifecycle operations, isolation enforcement and VM checks exist. Validate and
  render its prepared representation under the established unavailable-feature
  policy; never silently ignore it or claim it was deployed.
- The inert Quadlet preview uses a stable shared `keep-id` mapping to container
  UID/GID 10001. A service using another container UID requires a separately
  verified mapped data-directory owner before it can run. The preview does not
  use Podman's recursive `:U` ownership change and does not boot-enable units;
  existing data must never be silently reowned to make a preview deployable.
  Separate services map the host loopback alias only when they declare a
  dependency. These unit files do not enforce the dependency edges: L02 must
  implement and verify UID-based firewall rules and group lifecycle first.
- The separate-isolation firewall preview grants only TCP loopback ports of
  direct, managed and deployed dependencies. Replies to incoming connections
  remain permitted, but established outbound connections must still match the
  current policy after a change. The preview is not installed by
  the deployment.
- Services sharing an application UID cannot have separate host egress rules.
  Their shared egress policy is the union of the explicitly configured policies
  of the managed, deployed services: if any permits public web, all share that
  access; any explicit network rule is available to all of them. Loopback and
  metadata restrictions continue to apply. This is a consequence of selecting
  shared isolation and must be visible before deployment; it is not an assertion
  that individual services are isolated. Disabled or unmanaged services do not
  add allowances. The policy applies to every process with that UID, including
  any unmanaged process that still exists. A managed but fully stopped stack
  retains a default-deny chain; a wholly unmanaged stack is left untouched.
  Established outbound traffic must still match the current union after a policy
  change. The preview is not installed by the deployment.
- The application-registry candidate records derived user, unit, container,
  lock and data bindings without secret values. Group impact is computed from
  its direct dependencies and a matching configuration revision, not supplied
  as a caller-chosen list. The impact planner validates derived identities,
  rejects cycles and unmanaged affected services or prerequisites, and locks
  both affected services and transitive prerequisites in a fixed order. The
  plan records desired state. Before a group operation, the executor fences
  configuration changes, verifies prerequisite readiness, snapshots actual
  running intent, and persists interruption checkpoints under the derived locks.

### Guarded group operations during L02

The root operator may stop the transitive group rooted at a registered service
of a routeless, separately isolated application on an enrolled guarded host.
An explicit resume restores the services that were running when the stop began.
Both operations require the installed revision. Resume also requires the exact
operation ID and checkpoint generation. A subsequent stop may replace its exact
terminal predecessor while retaining that predecessor in the existing history.

A completed pause survives executor restart and system boot. For an interrupted
transition, boot reconstructs the state permitted by confirmed checkpoint
progress. A pending stop remains off during boot, and a pending start stays off
until the executor observes and reconciles it. Boot leaves the checkpoint intact.
Missing, inconsistent, or unrecognized active group evidence blocks application
activation. Earlier internal checkpoints keep their original executor semantics.

### Custody required for guarded Shared group operations

Shared group mutation remains gated. A workload process whose container UID
maps to the shared host account is confined by the container namespaces and
the configured mounts. A foreign process executing as that account in the
host namespace can access the rootless Podman store and user manager. It can
create or replace an object with a registered name, join a Pod, queue a job,
or alter user-owned evidence. The group lock orders Steward operations. The
runtime contract must also protect foreign Pod and container objects against
these competing actions. This isolation requires evidence beyond account login
and lingering settings.

The authorized runner must use collision-failing creation. Names can identify
creation conflicts. Start, stop, and removal must select the exact full IDs
recorded for the operation, with no lookup fallback to names or ID prefixes.
The runner must bind the Pod, infrastructure container and service IDs to their
creation, and verify the expected live process, cgroup and namespaces before
accepting a running object. Labels and files writable by the host service UID
cannot authorize adoption. If that UID can rewrite or substitute authoritative
runtime state, the backend must enforce a protected custody boundary before
Shared mutation can be enabled.

A member can join after an observation. Pod removal must refuse every foreign
member before any effect, including one that is merely created, stopped, or
joining concurrently. The membership test and removal must be atomic with
respect to membership changes. An empty Pod can be removed along with its
verified infrastructure container. The runner targets only owned service
containers during a group transition and preserves other services and their
data. The same rules apply to starts, automatic restart and cleanup, failed
starts, manager and host shutdown, boot and recovery. Host effects that
continue after the runner exits have the same custody requirement. Name-based
replacement, forced cleanup and cleanup by label are excluded.

The root-owned journal must survive reboot and bind the operation to the
installed revision and release, application and service identities, exact
runtime IDs, and the checkpoint generation. Persist intent before a runtime
effect and commit a creation-bound receipt for each returned ID before starting
it or taking dependent actions. Compare the authority, operation, pending step
and generation before each journal transition. Interruption before a verifiable
receipt, a stale generation, or contradictory runtime evidence keeps recovery
pending. A failed start or removal can already have changed runtime state.
Recovery reconciles the exact effects and any residual processes before
repeating an operation. Boot derives each service's allowed state from its
durable progress and starts the Pod only when an eligible service requires it.
Boot confirms live process identity in the current boot.

The backend choice remains open. Podman 5.7.0's CLI and REST Pod removal pass
through a mode that can remove stopped members even when the caller omits
force. The SQLite name-or-ID lookup can match a name ahead of a full ID.
The versioned Podman source has an exact-ID getter and a lower-level removal
mode that refuses non-infrastructure members under the same Pod lock used by
member admission. A supported integration still needs a versioned interface
and package compatibility evidence.
[CLI removal](https://github.com/containers/podman/blob/v5.7.0/pkg/domain/infra/abi/pods.go#L277-L291),
[REST removal](https://github.com/containers/podman/blob/v5.7.0/pkg/api/handlers/libpod/pods.go#L240-L263),
[SQLite lookup](https://github.com/containers/podman/blob/v5.7.0/libpod/sqlite_state.go#L1370-L1438),
[exact Pod lookup and removal lock](https://github.com/containers/podman/blob/v5.7.0/libpod/runtime_pod.go#L32-L57),
[empty-Pod condition](https://github.com/containers/podman/blob/v5.7.0/libpod/runtime_pod_common.go#L191-L212),
[member admission lock](https://github.com/containers/podman/blob/v5.7.0/libpod/runtime_ctr.go#L590-L601).

Before integration, verify the exact backend and protocol on each supported
package build, architecture, storage and lock configuration. Bind any helper
binary and its version contract to the root-verified release manifest and its
build inputs. Shared operations require exact backend compatibility in
addition to the general minimum Podman version. An unsupported backend or
untested package upgrade keeps Shared mutations gated until a compatible
protected release can continue from existing receipts. Read-only status must
remain available. Demonstrate a versioned backend and its artifact
verification. Use the contender roles below to test creation collisions,
joining during removal, and refusal with running, created or stopped members.

### Shared runtime identity and namespace continuity

[ADR 0002 §4](0002-repositories-ai-and-application-lifecycle.md#4-service-interaction)
defines the single Shared service user for workloads. Each Shared
application requires its own protected rootless runtime UID and GID, distinct
from its pinned workload UID, GID and subordinate ranges. Root controls access
to the runtime account, its namespace, Podman storage, configuration, sockets,
and any manager or helper that can mutate them. The Shared pod's namespace
must exclude the protected runtime UID and GID from every mapping. Processes
running under the legacy workload account, its subordinate IDs or another
application's IDs must lack authority to enter or mutate the protected
runtime from outside the pod. Verify process control and state access as
well as namespace entry. This also applies to open descriptors and control
sockets inherited by or mounted into workloads.

Preserve the existing Shared pod's complete workload ID footprint, including
the composed keep-id slot and subordinate mappings. On a clean installation,
derive the intended footprint from the pinned workload allocation and the
existing Shared mapping rules. Each mapped container UID and GID must
translate to the same initial-host-namespace ID as before, as observed in the
live process and in the ownership of each data directory and its contents.
Root must check both composed maps for exact continuity, runtime
ID exclusion and overlap with other account allocations. Cross-grants in
`/etc/subuid` or `/etc/subgid`, changes to data ownership, and
reinterpretation of the installed revision's pinned identity are prohibited.
This contract applies only to Shared applications. Separate isolation and
legacy single-service deployments retain their established identity and
checkpoint contracts.

The design hypothesis is a root-provisioned outer user namespace mapping the
protected runtime UID and GID to outer zero and admitting precisely the
legacy workload ID footprint for the child. The child pod maps only the
legacy workload IDs through that outer namespace. The composed maps must
preserve live host process credentials and on-disk ownership together.
Whether the supported Podman build can operate inside and rejoin the outer
namespace and keep the exact maps through namespace refresh remains open.
Verify cgroup behavior, that runtime helpers run without root authority in
the initial host namespace, and mount access for existing and newly created
data. Before launch, install and verify the declared firewall policy for the
recorded workload UID and the expected runtime socket UID. Before admitting
traffic or declaring readiness, confirm that the actual host-side `pasta`
listener and egress sockets have the expected owner UID and that the firewall
enforces the declared policy. Preserve existing loopback binds and network edges.
An idmapped bind approach that changes the live host identity would require
an explicit product decision.

The existing exact-ID and atomic membership requirements apply inside the
protected runtime. A prior experimental artifact verified exact Pod and
infrastructure lookup and member-removal locking for one package and
SQLite/VFS/file-lock configuration.

Protected runtime identity and namespace continuity require separate evidence
on the supported stack. Exercise exact lookup and removal with an independent
contender running under the protected runtime UID within the test runtime.
From outside that boundary, verify that an external process under the legacy
workload account cannot acquire runtime membership or control or substitute
runtime state. Verify exclusion of protected IDs from live pod and service
mappings across restarts. Shared group mutation stays gated pending that
evidence and lifecycle integration.

Migration from the generated Shared Quadlets requires a guarded deployment
with verified quiescence of the legacy units, children and Pod. The transition
must retire the old mutating hooks without using them to resolve an ambiguous
object. It preserves UID and sub-ID bindings, data, network policy and the
existing separate-isolation checkpoint format. An unresolved legacy object,
open checkpoint, or incompatible runtime journal keeps the transition fenced.
Check compatibility before changing the current release pointer, unit
definitions or manager authority. Downgrade requires verified quiescence and
a compatible reader for durable state. A fenced, exact recovery of the legacy
runtime to an older release remains valid when new Shared custody has yet to
be established and the previous recovery contract permits it. Acceptance
covers a clean installation, rejection of a live or ambiguous legacy runtime,
interrupted migration and downgrade, repeated deployment, and executor or host
restart between runtime effects and confirmation.

Before switching authority, verify the pinned identity and allocation
continuity, the exact legacy maps and data ownership, and the protected
runtime's identity, map contract and backend compatibility. The root-owned
journal must bind those checks, both runtime authorities and the permitted
transition to the source and target revisions and releases and the checkpoint
generation.
Record intent before provisioning, retiring the old mutating hooks or
switching authority. Record verified completion of each effect before the
next dependent effect. Fence activation and further mutations while any
effect remains uncertain, including after executor or host restart.
Recovery must verify the current authority, exact objects, maps and receipts
before retrying, continuing or permitting downgrade. A mismatch blocks
runtime mutation and leaves read-only status available.

### Guarded deployments with internal HTTPS routes

An enrolled host may deploy or withdraw application routes with `tls: internal`
through the existing private site entrypoint. A version 2 root grant adds
`application_routes: internal` to the version 1 grant's exact server, base
revision, desired revision and release binding. It covers a transition with
declared internal application routes in the base or target configuration,
including disabling or removing those routes. Version 1 remains valid for
routeless transitions. Recovery must present the original grant and exact
transition. Every declared application route must use internal TLS, including
routes of disabled services. The internal CA authenticates the server. Route
reachability follows the existing Traefik and firewall configuration. The
coordinator and its stop hook use the release active at admission. A routed
deployment that reuses that version must supply the same release bytes.

The protected deployment erects the boot hold and withdraws the previous
application route file before a material change. It waits for the previous
proxy and its connections to be evicted before reconciling the workload and
firewall. An unchanged deployment may retain existing routes when their
generation, proxy and targets still pass verification. The coordinator may
publish new routes only after draining its deployment transport and verifying
the target revision, release, boot authority, firewall, proxy and backend
listeners. Only the volatile Traefik provider may contain application routes.

The coordinator records the exact run and approved route digest in protected
runtime state before making new routes visible. The atomic deployment receipt
and fence release confirm that publication. If the coordinator exits before
that transaction commits, its systemd stop hook reconciles the recorded run
and withdraws any unconfirmed publication, independently of the executor
daemon. A failed drain keeps recovery fenced. Reboot clears volatile routes;
boot checks the durable deployment fence before republishing them.

Ordinary graph deployments, application ACME routes, shared or routed group
mutations, and coordinated capture retain their lifecycle acceptance gates.

### Deferral of Shared group mutation (2026-11-21)

The two custody sections above describe what Shared group *mutation* would
need. Meeting them requires a patched Podman build or a separate rootless
runtime identity, and roughly two weeks of custody work produced a test
artifact but no accepted backend. That work no longer blocks the delivery plan.

Decision: L02 is accepted for `isolation: separate`. `isolation: shared`
remains a valid, validated and renderable configuration, but registered group
stop/start/capture on a Shared application stays rejected (fail closed), exactly
as today. No Shared mutation path is enabled by the executor, controller,
maintenance, update, quarantine or drill logic; those features either handle
`separate` applications or report Shared groups as unsupported. The custody
material (`tests/integration/podman_custody/`, this ADR's custody sections) is
retained as the starting point of the optional card **X1** in
[goal.md](../goal.md). X1 reopens only after the first release candidate, and
adds no step to the critical path.

## Consequences

Existing examples, saved revisions, pending UI work and project removal behavior
remain unchanged. An application graph is an explicit revision-changing opt-in
and requires L02 before it can run. Repository access, builds, maintenance,
coordinated backups and automated remediation retain their own later gates.
