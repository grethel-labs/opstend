#!/bin/sh
# Disposable OpsTend test lab on one Proxmox VE host.
#
#   sudo sh scripts/lab/proxmox-lab.sh up        # bridge, NAT, 3 Debian 13 VMs
#   sudo sh scripts/lab/proxmox-lab.sh down      # remove VMs, bridge and NAT
#   sudo sh scripts/lab/proxmox-lab.sh status
#
# The lab gets its own bridge with NAT to the internet. Lab VMs cannot reach the
# host's LAN (private ranges are dropped), so experiments stay contained.
# Settings via environment: LAB_VMID (9401), LAB_COUNT (3), LAB_BRIDGE (vmbr9400),
# LAB_NET (10.94.0), LAB_UPLINK (vmbr0), LAB_STORAGE (local-lvm), LAB_MEM (6144),
# LAB_CORES (4), LAB_DISK (32G), LAB_KEY (~/.ssh/opstend-lab.pub of the caller).
set -eu
VMID="${LAB_VMID:-9401}"
COUNT="${LAB_COUNT:-3}"
BRIDGE="${LAB_BRIDGE:-vmbr9400}"
NET="${LAB_NET:-10.94.0}"
UPLINK="${LAB_UPLINK:-vmbr0}"
STORAGE="${LAB_STORAGE:-local-lvm}"
MEM="${LAB_MEM:-6144}"
CORES="${LAB_CORES:-4}"
DISK="${LAB_DISK:-32G}"
KEY="${LAB_KEY:-}"
IMG_DIR=/var/lib/vz/template/opstend-lab
IMG="$IMG_DIR/debian-13-genericcloud-amd64.qcow2"
IMG_URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"

say() { printf 'lab: %s\n' "$*"; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
command -v qm >/dev/null || { echo "this is not a Proxmox VE host"; exit 1; }

bridge_up() {
  if [ ! -f "/etc/network/interfaces.d/opstend-lab" ]; then
    cat > /etc/network/interfaces.d/opstend-lab <<IF
auto $BRIDGE
iface $BRIDGE inet static
    address $NET.1/24
    bridge-ports none
    bridge-stp off
    bridge-fd 0
IF
  fi
  ip link show "$BRIDGE" >/dev/null 2>&1 || ifup "$BRIDGE"
  sysctl -q -w net.ipv4.ip_forward=1
  nft -f - <<NFT
table inet opstend_lab
delete table inet opstend_lab
table inet opstend_lab {
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname "$BRIDGE" ip daddr $NET.0/24 accept
    iifname "$BRIDGE" ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 } drop
    iifname "$BRIDGE" oifname "$UPLINK" accept
    oifname "$BRIDGE" ct state established,related accept
  }
  chain postrouting {
    type nat hook postrouting priority 100;
    ip saddr $NET.0/24 oifname "$UPLINK" masquerade
  }
}
NFT
  say "bridge $BRIDGE ($NET.0/24) with NAT via $UPLINK"
}

image() {
  mkdir -p "$IMG_DIR"
  [ -f "$IMG" ] || curl -fsSL -o "$IMG" "$IMG_URL"
}

vm_up() {
  i=0
  while [ "$i" -lt "$COUNT" ]; do
    id=$((VMID + i)); n=$((i + 1)); ip="$NET.$((10 + n))"
    if qm status "$id" >/dev/null 2>&1; then i=$((i + 1)); continue; fi
    qm create "$id" --name "opstend-lab-$n" --memory "$MEM" --cores "$CORES" --cpu host \
      --machine q35 --scsihw virtio-scsi-single --net0 "virtio,bridge=$BRIDGE" \
      --serial0 socket --vga serial0 --agent enabled=1 --ostype l26 \
      --tags opstend-lab --description "OpsTend test lab node $n (disposable)"
    qm set "$id" --scsi0 "$STORAGE:0,import-from=$IMG,discard=on,ssd=1" >/dev/null
    qm resize "$id" scsi0 "$DISK" >/dev/null
    qm set "$id" --ide2 "$STORAGE:cloudinit" --boot order=scsi0 \
      --ipconfig0 "ip=$ip/24,gw=$NET.1" --nameserver 9.9.9.9 --ciuser opstend \
      --sshkeys "$KEY" >/dev/null
    qm start "$id"
    say "started opstend-lab-$n ($id) at $ip"
    i=$((i + 1))
  done
}

down() {
  i=0
  while [ "$i" -lt "$COUNT" ]; do
    id=$((VMID + i))
    if qm status "$id" >/dev/null 2>&1; then qm stop "$id" >/dev/null 2>&1 || true; qm destroy "$id" --purge >/dev/null; say "removed $id"; fi
    i=$((i + 1))
  done
  nft delete table inet opstend_lab 2>/dev/null || true
  ifdown "$BRIDGE" 2>/dev/null || true
  rm -f /etc/network/interfaces.d/opstend-lab
}

case "${1:-status}" in
  up)
    [ -n "$KEY" ] && [ -f "$KEY" ] && KEY_FILE="$KEY" || { echo "set LAB_KEY to an SSH public key file"; exit 1; }
    KEY="$KEY_FILE"
    bridge_up; image; vm_up ;;
  down) down ;;
  status) qm list | awk 'NR==1 || /opstend-lab/' ;;
  *) echo "usage: $0 up|down|status"; exit 2 ;;
esac
