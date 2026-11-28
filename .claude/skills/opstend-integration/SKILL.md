---
name: opstend-integration
description: How to add or change a platform integration (Proxmox, Linux, UniFi or a new one) so it appears in inventory, network graph, actions and rollouts. Use when connecting OpsTend to another system or extending what an adapter can do.
---

# Adding an integration

1. **Model first.** Map the system to `core/models.py` types (Host, Guest, Device,
   Port, Network, Client, FirewallRule, Update). Add a field only if the UI or the
   automation will use it.
2. **Adapter.** Put it in `src/opstend/adapters/<name>.py`:
   - HTTP APIs use `httpx.AsyncClient` with `pinned_context(cert_pem)`; accept a
     `transport` argument so tests can pass `httpx.MockTransport`.
   - Command-line tools go through `Runner` (argument lists, allowlist). Add new
     programs to `ALLOWED` only if read-only or necessary, and add deny rules to
     `agent.DENIED_ARGS` for dangerous sub-commands.
   - Long operations: follow the native task until it finishes, then read back.
   - Implement the `Compute` protocol for anything with guests, so the UI offers the
     same actions. Raise `Unsupported` for what the platform cannot do and reflect it
     in `capabilities()`.
3. **Parsers are pure functions** with tests based on real output samples.
4. **Config.** Add a model in `config.py` (secrets as `*_file`), build it in
   `integrations.py` and merge its inventory in `collect()`.
5. **Network graph.** If the system knows links (LLDP, MAC tables, bridges, tunnels),
   feed them into `network/graph.build` so insights and the topology see them.
6. **Actions.** Add job actions in `actions.py` (both backends) and, for updates,
   a `TargetKind` and ordering in `cluster/rollout.py`.
7. **Demo data.** Extend `demo/fixtures.py` so the feature is visible without hardware.
8. **Tests.** Unit tests for parsers and adapter calls; API flow test; e2e if visible.

Never claim an integration is verified on real hardware unless you ran it there; say
so in the PR and in `ROADMAP.md`.
