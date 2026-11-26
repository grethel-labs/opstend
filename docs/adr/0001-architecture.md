# ADR 0001: Core architecture

Status: accepted (stage 1) · Date: 2026-11-14

## Context

The platform should harden a Linux server, run isolated applications, and manage
itself within configured limits, with a connected LLM but also effectively
without one. A compromised or mistaken component (web, AI, workload) must not
automatically gain control of the host.

## Decision

1. **Trust domains are operating system identities.** Each component runs as a
   separate process with its own user, database, and directory. There are no
   directories writable by multiple components.

   | Component | Identity | Privileges |
   |---|---|---|
   | Host executor | root (systemd unit) | Only privileged component |
   | Admin API + web UI | `steward-api` | No host privileges, no network egress |
   | Self-management controller | `steward-ctl` | No host privileges, no network |
   | Event collector (added in stage 2) | `steward-col` | No host privileges, no network; reads logs only through executor actions |
   | Reverse proxy (Traefik) | `steward-proxy`, Rootless Podman | Loopback backends only |
   | Each project | `stw-<id>`, Rootless Podman | Dedicated data area and egress rules |

2. **The executor is small and makes its own decisions.** Over a Unix socket,
   it accepts only registered actions with schemas, identifies callers through
   `SO_PEERCRED` (not request claims), checks role, policy from a root-owned
   registry, kill switch, expiry, replay, target lock, and budget, and writes
   its own hash-chained audit. No external shell strings, paths, playbooks,
   or unrestricted variables.

3. **Self-management is deterministic first.** The controller derives findings
   from verified actual state using fixed rules and requests registered repairs.
   An LLM (later stage) may only submit proposals to the same pipeline; it
   cannot expand the set of actions.

4. **Platform services use hardened systemd units; workloads use Rootless Podman
   Quadlets.** Quadlet files are root-owned in
   `/etc/containers/systemd/users/<UID>/`; service users cannot change their
   own units. The executor must run on the host anyway; API and controller
   share its release (one wheel, hash-locked dependencies).

5. **Network isolation uses nftables by socket owner.** Rootless containers
   reach the network through their user's `pasta` process; `meta skuid` therefore
   identifies the service for IPv4 and IPv6. Backends listen on host loopback
   and rules allow only root (health checks) and proxy access; loopback alone
   is not isolation.

6. **Images arrive as archives, not through the service's registry access.**
   Root pulls by digest, assigns a local tag derived from the digest, and saves
   an archive; the service user loads it. No workload needs registry egress.

7. **One declarative configuration, content-addressed revisions.** CLI and UI
   use the same Pydantic schema. Python renders security-critical artifacts
   (nftables, Traefik, Quadlet) as pure, tested functions; Ansible only copies
   them. The applied host revision is authoritative; UI changes remain pending
   until the next deployment and are retrieved on the controller machine using
   `config pull`.

8. **Stack:** Python 3.12+, FastAPI/Pydantic, SQLite, Ansible (ansible-core 2.20),
   React/Vite/TypeScript, Podman ≥ 5.4 with Quadlet, Traefik 3, nftables.
   No Kubernetes, Redis, or external database service.

## Rejected alternatives

- **Containerized API with Podman socket:** rejected; an engine socket is
  equivalent to root.
- **One shared rootful Podman with per-project networks:** rejected; a daemon
  flaw would affect all projects, and services would run under one identity.
- **Ansible directly from web UI:** rejected; arbitrary playbooks/variables in a
  root process contradict the executor model. A local apply path tied to a
  specific version is planned as a registered action for stage 3.
- **Lower `ip_unprivileged_port_start` so proxy can bind 80/443:** rejected;
  nftables instead redirects 80/443 to unprivileged proxy ports without relaxing
  kernel protection.

## Consequences

- UI status queries and actions always pass through the executor; if it fails,
  the UI shows an observation gap rather than unmarked stale values.
- Target servers need access to PyPI and image registry (as root) during
  installation. An offline bundle remains open.
- Client source addresses behind the rootless proxy are not always the real
  address (pasta). Admin API rate limits therefore also include a global limit.
