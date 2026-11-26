# Acceptance test on a fresh VM

This test provides the actual evidence for a release. It needs no root, but
realistically requires a machine with KVM (`/dev/kvm`). Without KVM, `boot.sh`
falls back to software emulation (direct kernel boot with extended device
timeouts). This works, but is orders of magnitude slower: a full run then takes
several hours. Set `STEWARD_VM_SLOWDOWN=3` and `ANSIBLE_TIMEOUT=180` in that case.
Repeat individual sections with `STEWARD_VM_SECTIONS="platform reboot"`.

Prerequisites: `qemu-system-x86_64`, `qemu-img`, `xorriso`, `ssh`, `curl`,
~3 GB free RAM, ~5 GB disk space, internet access.

```bash
W=~/.cache/steward-vm                  # on real disk, not tmpfs (/tmp is often RAM)

# 1. Start disposable VM (Ubuntu 26.04 cloud image, checksum verified)
tests/integration/vm/boot.sh "$W"

# 2. Configure the VM
sed -e 's/name: my-server .*/name: steward-vm/' \
    -e 's/host: 203.0.113.10 .*/host: 127.0.0.1/' \
    -e 's/^  port: 22$/  port: 2222/' \
    -e "s#user: deploy .*#user: deploy\n  known_hosts_file: $W/known_hosts#" \
    -e "s#file:~/.config/steward/my-server/admin_token#file:$W/admin_token#" \
    examples/server.api.yml > "$W/server.yml"
./steward secrets init-admin-token --config "$W/server.yml"
./steward release build

# 3. Initial installation
export STEWARD_SSH_PRIVATE_KEY_FILE="$W/id_test"
./steward deploy --config "$W/server.yml" --limit steward-vm --yes

# 4. Acceptance checks (second run changed=0, isolation, egress including IPv6
#    and metadata, self-healing, kill switch, reboot, state persistence)
tests/integration/vm/checks.sh "$W" "$W/server.yml"

# 5. Clean up
kill "$(cat "$W/qemu.pid")"; rm -rf "$W"
```

The VM uses QEMU user networking: SSH goes through port forwarding
`127.0.0.1:2222 → 22`. This also checks that the firewall opens the port sshd
actually listens on (22), rather than the configured connection port (2222).

Not covered: public routes with ACME, arm64, recovery onto an empty VM
(backups are not implemented yet).
