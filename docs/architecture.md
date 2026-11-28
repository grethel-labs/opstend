# Architecture

## One node

Each machine runs two processes:

| Process | User | Purpose |
| --- | --- | --- |
| `opstend serve` | `opstend` | Web app, API, Raft, job engine, self-management, collectors, Zorec |
| `opstend agent` | root | Runs allowlisted commands for `opstend serve` over `/run/opstend/agent.sock`; no network |

Hosts that are not OpsTend nodes are managed over their APIs (Proxmox, UniFi) or SSH
with a pinned host key (Linux).

## State and jobs

- **Replicated state** (`core/store.py`): a versioned document store on SQLite. Every
  node keeps a full copy. Writes are Raft log entries; followers forward writes to
  the leader over mutual TLS.
- **Jobs** (`core/jobs.py`): every change. Preview with a fingerprint of the facts it
  depends on → approval (person or policy) → run on the leader, fenced by the Raft
  term → readback → rollback of completed steps on failure. All transitions go to the
  hash-chained audit log (`core/audit.py`).
- **Policy** (`core/policy.py`): autonomy per category (report, propose, do it),
  budgets and cooldowns per target, maintenance windows in local time, kill switch.

## Cluster

- **Raft** (`cluster/consensus.py`): leader election, log replication, snapshots,
  single-member voter changes, non-voting learners.
- **Placement** (`cluster/placement.py`): 1, 3 or 5 voters spread across sites;
  web (2), collector and discovery (one per site), scanner, backup and Zorec
  (prefers GPU) on the nodes with room. Existing placements stay where possible.
- **Membership** (`runtime.py`): heartbeats; nodes silent for 30 s are suspect,
  for 90 s down; roles move and the voter set follows the plan one member at a time.
- **Enrollment** (`cluster/enrollment.py`, `cluster/node.py`): the first node
  creates the cluster CA. A join token carries the CA fingerprint, a one-time secret
  and the issuer's address. The joining node pins the CA, proves the token with an
  HMAC over its certificate request and accepts only a certificate for its own key.
- **Discovery** (`cluster/discovery.py`): beacons from new agents and scans of
  configured private subnets for Proxmox, UniFi and SSH.
- **Rollouts** (`cluster/rollout.py`): waves with canary, dependency order (leaves
  before core devices), quorum safety and a health gate; failures pause and roll back.

## Integrations

| Adapter | Reads | Acts |
| --- | --- | --- |
| Proxmox VE (REST, API token) | nodes, storage, guests, NICs/VLANs, snapshots, bridges, apt updates | power, snapshots, vzdump backup, clone, migrate, console link |
| Linux (agent or SSH) | OS, arch, package manager, init, bridges, Podman, libvirt, updates, installed packages | power, libvirt snapshots, restic backups, clone, live migration, package upgrades |
| UniFi Network | devices, ports, LLDP, PoE, uplinks, clients, networks, port profiles, firewall | restart, locate, firmware, PoE cycle, port profile, block client |

## Network model

`network/graph.py` joins all of the above by MAC address, LLDP and uplink data into one
graph. `network/analysis.py` checks it (VLAN not carried, bridge not VLAN-aware, slow
or faulty links, PoE budget, voters behind one switch, duplicate IPs, wrong subnet,
weak Wi-Fi, open segmentation) and `network/graph.explain` follows a path through
VLANs and the gateway firewall. `network/plantuml.py` turns the graph into PlantUML
with `@hook` and `@tooltip` directives; the browser renders it with excaliplant.

## Zorec

`zorec/assistant.py` answers from a bounded snapshot of the fleet. Without a model it
uses rules for the common questions. With Claude (Anthropic SDK) or a local model
server it answers freely; suggested changes are validated against the action registry
and become job previews.
