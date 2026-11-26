# Experimental Podman custody artifact

The initial fixture profile is `resolute-amd64-sqlite-vfs-file`. It identifies
Ubuntu Resolute (26.04) amd64 Podman `5.7.0+ds2-3build1` with an SQLite state
database, the vfs storage driver and file locks. The profile describes the
fixture configuration. The runner must establish those settings on a fresh
store before using it. This experiment leaves Shared group mutation gated.

## Build from Ubuntu's native source inputs

Use a disposable, unprivileged Ubuntu Resolute amd64 builder with the package's
native build dependencies already installed, Python 3, `gpgv`,
`ubuntu-keyring`, `patch` and permission to create a private network namespace.
Use the `Build-Depends` and `Build-Conflicts` in the extracted source's
`debian/control` and provision the builder only from authenticated packages.
Keep the builder dedicated to this build so the package dependency inventory is
meaningful.

Populate a private input directory with these unchanged archive files from the
repository and relative paths in [resolute-amd64.json](resolute-amd64.json).

- `dists/resolute/InRelease`
- `dists/resolute/universe/source/Sources.xz`
- `dists/resolute/universe/binary-amd64/Packages.xz`
- The three source files from `pool/universe/p/podman` with their published names

From a trusted checkout run the following command with a new, private absolute
output path.

```bash
python3 tests/integration/podman_custody/build.py /path/to/inputs /path/to/new-bundle
```

For authentication without a build or an output bundle, run:

```bash
python3 tests/integration/podman_custody/build.py --authenticate-only /path/to/inputs
```

The build verifies the pinned InRelease with the system Ubuntu archive keyring
and requires the pinned signer. It verifies both compressed index hashes
against the signed Release and cross-checks the exact package and source
checksums in those indexes. Those checks authenticate the `.dsc`, the original
source archive, and the Debian packaging archive before extraction. The recipe
applies the in-tree custody and documentation patches to the extracted Ubuntu
source and runs `dpkg-buildpackage -B -us -uc` in a new network namespace.
The build limits
parallelism to one job and skips the distribution test suite with
`DEB_BUILD_OPTIONS="parallel=1 nocheck"`. It runs the rebuilt executable's
protocol discovery command in a private network namespace as an unprivileged
user. The package output and build tree are temporary. The private bundle
contains the rebuilt Podman ELF, the native `.buildinfo`, and a manifest
binding those files to the lock, both patches, recipe, package and protocol.

The documentation patch shortens the two absolute `IgnoreFile` examples in a
single `podman-systemd.unit(5)` table row. With the pinned Ubuntu source and
the builder's `go-md2man` 2.0.4-1, the original row caused the manpage width
check to fail. The full `make docs docker-docs` targets passed with the shorter
examples and the width check enabled.

The native `.buildinfo` reports the builder architecture, source, version, and
actual installed build package versions, including the packaged toolchain.
The result depends on the contents and package state of the pre-provisioned
builder. The recipe neither compares two independent builds nor establishes
byte-for-byte reproducibility against the Ubuntu build farm.

## Verify before fixture execution

Use a trusted checkout on the fixture host. As root, admit the three bundle
files only after reviewing the build, and deploy them under root-owned,
non-group-writable and non-world-writable directories at an absolute path such
as `/run/steward-custody-test/bundle`. Ancestors under `/tmp` or an
unprivileged checkout fail this check. Use modes `0755` for the ELF and
`0644` or tighter for the manifest and buildinfo. Record the reviewed
manifest SHA-256 through an independent root-controlled channel. Computing the
expected value from the bundle on the fixture host at admission time defeats
the separate trust input.

`verify_runtime_package()` checks the host OS and architecture, the installed
package identity and the hash of the stock `/usr/bin/podman`. The stock ELF
digest in the lock comes from extracting the archive `.deb` after verifying its
hash against the signed Packages index. The stock binary does not provide the
experimental protocol.

`verify_bundle(bundle, expected_manifest_sha256, expected_profile)` verifies
the three root-protected files and returns an open descriptor for the rebuilt
ELF. Pass it to a child that drops all root privileges and switches to the
dedicated fixture UID before executing that same descriptor. The runtime
profile and `steward-pod-custody-v1` protocol still require a live fixture
check. This bundle verifies build provenance and file identity under the
operator's root trust. Runtime shared libraries, OCI helpers, startup refresh,
other lock configurations and architectures, a protected store, and the
production release loader require their own evidence.

## Run the disposable host fixture

Provision a dedicated `stw-custody-*` account and matching primary group with
valid subordinate UID and GID allocations. Use the verified candidate and a
trusted statically linked BusyBox already on the host. The probe starts and
removes containers only in its private graph and run directories and uses the
ordinary Podman binary for the independently launched competing process.

```bash
sudo python3 tests/integration/podman_custody/probe.py \
  --bundle /run/steward-custody-test/bundle \
  --manifest-sha256 "$trusted_manifest_sha256" \
  --uid "$fixture_uid" --gid "$fixture_gid" --busybox /usr/bin/busybox
```

Record the complete output and exit status. The probe checks exact ID lookup,
name collision behavior, removal with only the recorded inactive infra present,
and preservation of created, stopped and running foreign members. Its race
requires the stock admission and candidate removal processes to be observed
waiting for the same POSIX Pod lock inode before the lock is released.

## Protected Shared runtime identity experiment

Seven prior fixture checks established exact Pod and infrastructure
container lookup, collision refusal, and atomic empty-Pod removal with foreign
member preservation for the locked package and SQLite/VFS/file-lock profile.
Both Podman processes in that fixture use the same host account and store. A
separate experiment must establish the runtime boundary defined in
[ADR 0006](../../../docs/adr/0006-application-graph-compatibility.md#shared-runtime-identity-and-namespace-continuity).
Use disposable Shared applications on an authorized host fixture and record
the exact package, artifact, kernel, storage and lock settings, filesystem,
OCI and networking helpers, and systemd and firewall configuration. Keep
fixtures isolated from installed workloads. Archive the root-controlled
recipe, artifact and probe digests, machine-readable observations, exit
statuses and cleanup result.

The candidate to test uses a dedicated runtime UID and GID for each
application. Root provisions an outer user namespace with that identity at
outer UID/GID zero and the legacy workload IDs available for the child Pod.
The child maps the existing workload IDs and excludes the runtime IDs. This
layout is a hypothesis. Podman 5.7.0's libpod rootless check requires a
positive rootless UID even when the storage layer detects a nested user
namespace. Namespace setup can also exit early for effective UID zero with
the requisite capability or an already configured namespace. Support for an
external bootstrap is unproven. A candidate must demonstrate that the exact
build selects the intended store, helper behavior and namespace paths during
creation, reentry and refresh. Linux limits a child's maps to IDs
represented in the parent, and map output depends on
the reader's user namespace. An idmapped mount can change the ownership seen
through that mount, so mount observations alone cannot establish kernel
process identity.
[Podman rootless setup](https://github.com/containers/podman/blob/v5.7.0/pkg/rootless/rootless_linux.go),
[Podman vendored storage namespace check](https://github.com/containers/podman/blob/v5.7.0/vendor/go.podman.io/storage/pkg/unshare/unshare_linux.go#L392-L425),
[Linux user namespaces](https://man7.org/linux/man-pages/man7/user_namespaces.7.html),
[Linux filesystem idmappings](https://docs.kernel.org/filesystems/idmappings.html).

### Evidence required

1. Establish a legacy baseline from the same installed graph bindings used
   by the candidate. Include a service using the keep-id slot and a service
   using a different mapped UID/GID, with existing data for each. Capture
   the full live UID/GID maps, real/effective/saved/filesystem credentials and
   supplemental groups, plus host ownership, mode, inode and byte digests
   for both data directories and their contents. Record both allocations
   and host account file digests. Include another application's IDs as
   cross-application controls.
2. Observe the candidate from the initial host namespace and within each
   relevant namespace. Identify the supervisor, Podman, pause and OCI
   helpers, infra and service processes and pasta by boot ID, PID, start
   time, namespace handles and cgroup. Record namespace ownership and
   parentage, both UID/GID maps, supplementary groups, capabilities and
   real/effective/saved/filesystem IDs. Compose the parent and child maps
   against the legacy baseline in both directions. Require the same entire
   host workload UID/GID footprint, no runtime UID or GID in any workload
   map, no host root in the workload maps, and no new cross-grants or
   allocation overlaps. Require Podman and runtime helpers to have unprivileged
   initial-host credentials and capabilities outside the root provisioning and
   observation processes. Correlate process credentials and the mounted and
   on-disk ownership for both data identities. Each must read its existing
   markers and create separate test files with the expected host ownership.
   Existing ownership, inodes and bytes must agree before and after transition.
3. Run independent foreign processes with the real old UID and primary
   GID in the initial host namespace, with representative legacy subordinate
   UIDs and GIDs, and with another application's IDs. Exercise representative
   mapped identities from inside the candidate workload as well. Verify
   their credentials and supply a permitted positive control for each
   class of check. Record denial of access to protected state and mutation
   paths, including the graph and run roots, SQLite and lock files,
   startup environment and configuration, manager and API sockets,
   namespace handles, runtime helpers and their control descriptors, and
   writable cgroup interfaces. Include the direct path and the paths
   exposed through live processes or inherited descriptors. Test access
   with legacy groups as well as legacy UIDs. Check process control,
   namespace entry and manager job submission against the protected
   runtime using live targets. Account for effects such as signaling that
   the preserved host credentials still permit on workload processes and
   verify that those effects grant no runtime authority. Verify the
   authorized root-controlled path succeeds and compare exact Pod, infra
   and member IDs, state and evidence before and after the denial checks.
   Independently repeat the seven backend checks against the protected store
   using a fixture-only, authorized contender inside the protected runtime
   and under its credentials. [Linux signal permissions](https://man7.org/linux/man-pages/man2/kill.2.html).
4. Before launch, record how the fixture's admission and firewall policy
   binds the previous workload UID and the expected socket owner to the
   application. Use actual pasta traffic. Record the host listener address,
   port, socket inode and owning process, network namespace, cgroup and
   kernel-observed socket UID for listener and outbound flows. Correlate
   those observations with the identity selected by the firewall and rule
   counters for each test flow. Confirm exactly the expected IPv4 loopback
   listener and absence of extra wildcard or IPv6 listeners. Verify that a listener
   belonging to a foreign process under the old UID cannot satisfy the
   readiness check. Confirm Shared service names resolve to the expected
   addresses and work across both services on their shared loopback.
   Confirm egress to a declared private destination and denial for an
   undeclared private destination, host loopback and metadata endpoints.
   Include IPv6 egress checks and confirm
   an unrelated application's traffic cannot use the grant. Confirm denial
   of the next packet on the established allowed flow when its grant is
   removed while the workloads remain alive. Repeat the firewall check with
   the application stopped, including stale helper traffic if a helper
   outlives the service transition. A discrepancy between socket attribution
   and the admitted identity leaves the experiment incomplete.
   [Podman pasta setup](https://github.com/containers/podman/blob/v5.7.0/libpod/networking_pasta_linux.go),
   [Podman vendored pasta helper launch](https://github.com/containers/podman/blob/v5.7.0/vendor/go.podman.io/common/libnetwork/pasta/pasta_linux.go#L48-L65).
5. Repeat the observations after runtime and manager restart and after a
   host reboot. Track exact object IDs and current-boot process, namespace
   and cgroup identities, and verify maps, protected authority, data access
   and network policy before allowing services to become ready. Exercise
   a deliberately inconsistent or incomplete fixture state and verify
   activation is refused without adopting legacy objects, changing data
   ownership or granting the old account control. Verify an intended
   stopped service remains stopped across restart.

A missing observation leaves the corresponding check open. Failure to
compose either map, to start or reenter with the protected identity, to
enforce the control boundary, or to preserve data and network policy rejects
the candidate. Record the failing phase and the observed identities, state
and errors before fixture cleanup. Successful results would cover only this
identity experiment on the recorded configuration. Deployment migration,
production loader and lifecycle integration, registered group recovery,
routed Shared operations and the B08-dependent coordinated capture remain
separate acceptance work. Shared mutation and the deployment guards retain
their existing gating.

## Evidence in the development workspace

The archive signature, both compressed index hashes, all three source hashes
and the stock package and ELF hashes were checked against the locked values.
The local checkout host has the matching stock Podman package. Its native
builder lacks `golang-go`, `debhelper-compat (= 13)`, `dh-golang`, and the
packaged Go dependency set. A successful native build and host fixture run
require a provisioned builder and separate verification.
