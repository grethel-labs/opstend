#!/usr/bin/env bash
# Boot a throwaway Ubuntu 26.04 VM for the acceptance test. No root needed.
# Uses KVM when /dev/kvm is usable, otherwise software emulation (very slow).
#
#   tests/integration/vm/boot.sh <workdir>      # leaves the VM running
#
# SSH: deploy@127.0.0.1 port 2222, key <workdir>/id_test, passwordless sudo.
set -euo pipefail
W="$(mkdir -p "$1" && cd "$1" && pwd)"
BASE_URL=https://cloud-images.ubuntu.com/releases/26.04/release
IMG=ubuntu-26.04-server-cloudimg-amd64.img

cd "$W"
if [ ! -f base.img ]; then
    curl -fsSL -O "$BASE_URL/SHA256SUMS"
    curl -fsSL -o base.img "$BASE_URL/$IMG"
    echo "$(grep " \*\?$IMG\$" SHA256SUMS | cut -d' ' -f1)  base.img" | sha256sum -c
fi
[ -f id_test ] || ssh-keygen -q -t ed25519 -N '' -f id_test -C steward-vm-test </dev/null
mkdir -p seed
cat >seed/user-data <<SEED
#cloud-config
hostname: steward-vm
users:
  - name: deploy
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true
    ssh_authorized_keys:
      - $(cat id_test.pub)
ssh_pwauth: false
SEED
printf 'instance-id: steward-vm-%s\nlocal-hostname: steward-vm\n' "$(date +%s)" >seed/meta-data
xorriso -as mkisofs -quiet -o seed.iso -V cidata -J -r seed/user-data seed/meta-data
rm -f disk.qcow2 console.log
qemu-img create -q -f qcow2 -b base.img -F qcow2 disk.qcow2 20G

if [ "$(stat -f -c %T "$W")" = tmpfs ]; then
    echo "$W is on tmpfs: the VM disk would fill RAM. Use a directory on a real disk." >&2
    exit 1
fi

ACCEL=kvm
BOOT=()
if [ ! -w /dev/kvm ]; then
    # Software emulation is too slow for systemd's 90 s device timeouts with the
    # stock boot path. Boot the published kernel directly and raise the timeouts.
    ACCEL="tcg,thread=multi"
    U="$BASE_URL/unpacked"
    if [ ! -f vmlinuz ]; then
        curl -fsSL -o SHA256SUMS.unpacked "$U/SHA256SUMS"
        for f in vmlinuz initrd; do
            curl -fsSL -o "$f" "$U/ubuntu-26.04-server-cloudimg-amd64-$f-generic"
            echo "$(grep "amd64-$f-generic\$" SHA256SUMS.unpacked | cut -d' ' -f1)  $f" | sha256sum -c
        done
    fi
    BOOT=(-kernel "$W/vmlinuz" -initrd "$W/initrd" -append
        "root=LABEL=cloudimg-rootfs ro console=ttyS0 systemd.default_device_timeout_sec=1800 systemd.default_timeout_start_sec=1800 rd.systemd.default_device_timeout_sec=1800")
fi
echo "booting with accel=$ACCEL; console: $W/console.log"
qemu-system-x86_64 -machine q35 -accel "$ACCEL" -cpu max -smp 2 -m 2048 -display none \
    -serial "file:$W/console.log" -daemonize -pidfile "$W/qemu.pid" "${BOOT[@]}" \
    -drive "file=$W/disk.qcow2,if=virtio,format=qcow2" \
    -drive "file=$W/seed.iso,if=virtio,format=raw,readonly=on" \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net-pci,netdev=n0 \
    -device virtio-rng-pci

echo "waiting for SSH and cloud-init (can take 20+ minutes without KVM)"
for _ in $(seq 1 360); do
    if ssh -i "$W/id_test" -o IdentitiesOnly=yes -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=120 -o LogLevel=ERROR deploy@127.0.0.1 'cloud-init status --wait' 2>/dev/null; then
        # The acceptance test itself uses strict host key checking against this file.
        ssh-keyscan -T 120 -p 2222 127.0.0.1 2>/dev/null >"$W/known_hosts"
        echo "VM ready"
        exit 0
    fi
    sleep 10
done
echo "VM did not come up; see $W/console.log" >&2
exit 1
