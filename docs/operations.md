# Operations

## Install

```sh
curl -fsSL https://github.com/grethel-labs/opstend/releases/latest/download/install.sh | sudo sh
```

The installer detects architecture, distribution and init system, verifies the release
(checksum; Sigstore signature when `cosign` is installed), installs into
`/opt/opstend/releases/<version>` with its own Python, creates the `opstend` user and
starts `opstend` and `opstend-agent`. Re-running it upgrades and keeps the previous
version for rollback. Options: `--version X`, `--join <token>`, `--demo`,
`--wheel <file>` (air-gapped), `--no-service`.

Open `https://<host>:8443`. The first visit creates the admin account.

## Connect systems

Edit `/etc/opstend/opstend.yaml` (see `packaging/opstend.example.yaml`) and put each
secret in its own file under `/etc/opstend/secrets/` with mode 0600:

- **Proxmox:** create a user `opstend@pve` and an API token; grant `PVEAuditor` for
  read-only, add `PVEVMAdmin` for power, snapshot and clone actions, `PVEDatastoreUser`
  for backups.
- **UniFi:** create a local account with the role your features need (view-only for
  inventory and insights).
- **Linux:** for this machine set `local: true`; for others create an `opstend` user
  with an SSH key and pin its host key in `/etc/opstend/known_hosts`.

Restart with `systemctl restart opstend`.

## Add nodes

Under **Cluster und Rollen** create a join command (valid 30 minutes) and run it on the
new machine. The node joins, receives the state and takes the roles the planner gives
it. Three or more nodes keep working when one fails.

## Updates

OpsTend checks for signed releases. Security patches for hosts install in the
maintenance window; everything else (OpsTend, Proxmox, firmware) runs as one
coordinated rollout you start under **Updates**. On a single node you can run
`sudo /opt/opstend/current/bin/opstend self-update`.

## Troubleshooting

| Symptom | Look at |
| --- | --- |
| Web app not reachable | `systemctl status opstend`, `journalctl -u opstend` |
| Actions fail with "not allowed through the agent" | the command is not on the allowlist – by design |
| Node stays "suspect" | the node can reach the leader's cluster port (47471/tcp, mutual TLS)? |
| No leader | at least a majority of voters must be up; see **Cluster und Rollen** |
