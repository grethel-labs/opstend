#!/usr/bin/env bash
# Acceptance checks against a VM that was deployed with the example configuration.
#
#   tests/integration/vm/checks.sh <workdir> <config>
#
# Every check prints PASS/FAIL; the script exits non-zero if any check failed.
# Checks marked [mutating] disturb the system on purpose to prove self-healing.
set -uo pipefail
W="$(cd "$1" && pwd)"
CONFIG="$2"
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
FAILED=0
OUT="$(mktemp -d)/check.out"
ONLY="${STEWARD_VM_SECTIONS:-idempotence platform isolation egress selfheal events killswitch reboot}"
want() { case " $ONLY " in *" $1 "*) return 0 ;; esac; return 1; }
SSH=(ssh -i "$W/id_test" -p 2222 -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$W/known_hosts"
    -o IdentitiesOnly=yes -o ConnectTimeout=120 -o LogLevel=ERROR deploy@127.0.0.1)
SLOW="${STEWARD_VM_SLOWDOWN:-1}"   # multiply waits, e.g. 4 under software emulation
export STEWARD_SSH_PRIVATE_KEY_FILE="$W/id_test"

r() { "${SSH[@]}" "$@"; }
check() { # check <name> <command...>   passes when the command succeeds
    local name="$1"; shift
    if "$@" >"$OUT" 2>&1; then echo "PASS  $name"; else
        echo "FAIL  $name"; sed 's/^/        /' "$OUT" | tail -8; FAILED=1; fi
}
refuse() { # refuse <name> <command...>  passes when the command fails
    local name="$1"; shift
    if "$@" >"$OUT" 2>&1; then echo "FAIL  $name (unexpectedly succeeded)"; FAILED=1
    else echo "PASS  $name"; fi
}
wait_for() { # wait_for <seconds> <command...>
    local limit="$(($1 * SLOW))"; shift
    local start=$SECONDS
    until "$@" >/dev/null 2>&1; do [ $((SECONDS - start)) -ge "$limit" ] && return 1; sleep 5; done
}
NOTES='sudo -u stw-notes env -C / XDG_RUNTIME_DIR=/run/user/$(id -u stw-notes)'
probe() { # run a python snippet inside the workload container
    r "$NOTES podman exec notes python -c \"$1\""
}
connect() { echo "import socket,sys; s=socket.socket(socket.AF_INET6 if ':' in '$1' else socket.AF_INET); s.settimeout(8); s.connect(('$1', $2))"; }
healthy() { r 'sudo curl -fsS -o /dev/null http://127.0.0.1:20080/healthz'; }
steward() { "$ROOT/steward" "$@" --config "$CONFIG" --limit steward-vm; }

if want idempotence; then
echo "== idempotence"
out="$(steward deploy --yes 2>&1)"; echo "$out" | tail -3
check "second deployment reports changed=0" grep -q 'deployed and verified: changed=0' <<<"$out"
check "status is ok" steward status

fi

if want platform; then
echo "== platform"
check "firewall table loaded" r 'sudo nft list table inet steward'
check "input policy is drop" r 'sudo nft list chain inet steward input | grep -q "policy drop"'
check "admin API answers 401 through proxy with internal CA" r \
    'sudo curl -s -o /dev/null -w "%{http_code}\n" --cacert /etc/steward/pki/ca.crt https://localhost:9443/api/session | grep -qx 401'
check "admin token file is root-only" r 'test "$(sudo stat -c %a:%U /etc/steward/secrets/admin_token)" = 600:root'
check "executor audit chain intact" r 'sudo /opt/steward/current/venv/bin/steward-host audit-verify'
check "no public listener besides ssh" r \
    '! sudo ss -Htln | grep -v -e "127\.0\.0\.\|\[::1\]" | grep -v ":22 "'
refuse "admin backend not reachable by an ordinary user" r 'curl -s -m 8 http://127.0.0.1:9080/api/session'

fi

if want isolation; then
echo "== workload isolation"
check "workload healthy (root via loopback)" healthy
refuse "workload backend not reachable by an ordinary user" r 'curl -s -m 8 http://127.0.0.1:20080/healthz'
check "runs as uid 10001" r "test \"\$($NOTES podman exec notes id -u)\" = 10001"
refuse "root filesystem is read-only" r "$NOTES podman exec notes touch /probe"
refuse "application bundle is read-only" r "$NOTES podman exec notes touch /app/probe"
check "data volume is writable" r "$NOTES podman exec notes touch /data/probe"
check "memory limit 128 MiB in cgroup" r "test \"\$($NOTES podman exec notes cat /sys/fs/cgroup/memory.max)\" = 134217728"
check "pids limit 64 in cgroup" r "test \"\$($NOTES podman exec notes cat /sys/fs/cgroup/pids.max)\" = 64"
check "no capabilities, no new privileges" r \
    "$NOTES podman exec notes grep -E '^(CapEff:\s+0000000000000000|NoNewPrivs:\s+1)' /proc/1/status | wc -l | grep -qx 2"
check "seccomp filter active" r "$NOTES podman exec notes grep -qE '^Seccomp:\s+2' /proc/1/status"
refuse "service user cannot modify its own unit" r \
    'sudo -u stw-notes sh -c "echo x >> /etc/containers/systemd/users/$(id -u stw-notes)/notes.container"'
refuse "service user cannot read another service's secrets dir listing" r \
    'sudo -u stw-notes ls /etc/steward/secrets/projects/'
refuse "service user cannot read the admin token" r 'sudo -u stw-notes cat /etc/steward/secrets/admin_token'
refuse "service user cannot use the executor socket" r \
    'sudo -u stw-notes python3 -c "import socket; s=socket.socket(socket.AF_UNIX); s.connect(\"/run/steward-executor/executor.sock\")"'

fi

if want egress; then
echo "== egress (mode none)"
refuse "no IPv4 internet egress" probe "$(connect 1.1.1.1 443)"
refuse "no IPv6 internet egress" probe "$(connect 2606:4700:4700::1111 443)"
refuse "no cloud metadata access" probe "$(connect 169.254.169.254 80)"
refuse "no access to host loopback alias" probe "$(connect 169.254.1.3 9080)"
refuse "no access to the host's own address" probe "$(connect 10.0.2.15 22)"
refuse "no access to the gateway / private net" probe "$(connect 10.0.2.2 2222)"
refuse "no DNS resolution" probe "import socket; socket.getaddrinfo('example.org', 443)"
check "host itself still has egress (control)" r 'curl -fsS -m 20 -o /dev/null https://archive.ubuntu.com/'

fi

if want selfheal; then
echo "== self-management without AI [mutating]"
r 'sudo -u stw-notes env -C / XDG_RUNTIME_DIR=/run/user/$(id -u stw-notes) systemctl --user stop notes.service'
refuse "workload is down after manual stop" healthy
check "controller restarts the stopped workload" wait_for 240 healthy
r 'sudo nft delete table inet steward'
check "controller reloads the deleted firewall" wait_for 240 r 'sudo nft list table inet steward'
check "remediations are in the executor audit" r \
    'sudo grep -c "\"action\": \"\(workload_restart\|firewall_reassert\)\".*\"outcome\": \"ok\".*\"role\": \"controller\"" /var/log/steward-executor/audit.jsonl | grep -qv "^0$"'

fi

if want events; then
echo "== event log"
EV='sudo /opt/steward/current/venv/bin/steward-host events'
check "collector is active" r 'systemctl is-active steward-collector.service'
check "notifier is active" r 'systemctl is-active steward-notifier.service'
check "read-only bot is active" r 'systemctl is-active steward-bot.service'
refuse "bot cannot access executor socket" r \
    'sudo -u steward-bot python3 -c "import socket; s=socket.socket(socket.AF_UNIX); s.connect(\"/run/steward-executor/executor.sock\")"'
refuse "notifier cannot access executor socket" r \
    'sudo -u steward-notify python3 -c "import socket; s=socket.socket(socket.AF_UNIX); s.connect(\"/run/steward-executor/executor.sock\")"'
check "deployment is recorded as event" wait_for 120 r "$EV --kind-prefix deployment | grep -q verified"
check "self-healing story is one correlation (opened, restart, resolved)" wait_for 300 r "
    corr=\$($EV --kind-prefix finding.opened --project notes --limit 1 | python3 -c 'import json,sys; print(json.loads(sys.stdin.readline())[\"correlation_id\"])') &&
    $EV --correlation-id \$corr | grep -c -e action.workload_restart -e finding.opened -e finding.resolved | grep -qx 3"
r 'sudo -u stw-notes logger -p user.err "steward-vm-check db password=hunter2 failed"'
check "workload error line reaches the event log" wait_for 120 r "$EV --kind-prefix log --project notes | grep -q steward-vm-check"
refuse "secret in the log line is redacted" r "$EV --kind-prefix log --project notes | grep -q hunter2"
refuse "service user cannot query the event log" r \
    'sudo -u stw-notes python3 -c "import socket; s=socket.socket(socket.AF_UNIX); s.connect(\"/run/steward-collector/query.sock\")"'
refuse "collector has no network" r \
    'sudo nsenter -t $(systemctl show -p MainPID --value steward-collector) -n ip -brief link | grep -v "^lo"'
fi

if want killswitch; then
echo "== kill switch [mutating]"
steward killswitch on >/dev/null 2>&1
r 'sudo -u stw-notes env -C / XDG_RUNTIME_DIR=/run/user/$(id -u stw-notes) systemctl --user stop notes.service'
sleep $((150 * SLOW))
refuse "kill switch prevents the automatic restart" healthy
check "observation continues: status still readable" r 'sudo /opt/steward/current/venv/bin/steward-host status >/dev/null'
steward killswitch off >/dev/null 2>&1
check "automation resumes after kill switch off" wait_for 300 healthy

fi

if want reboot; then
echo "== state and reboot [mutating]"
r 'sudo curl -fsS -X POST --data "survives reboot" http://127.0.0.1:20080/notes' >/dev/null
r 'sudo systemctl reboot' || true
sleep 60
check "VM is back after reboot" wait_for 1800 r true
check "platform healthy after reboot" wait_for 900 r 'sudo /opt/steward/current/venv/bin/steward-host verify'
check "firewall loaded after reboot" r 'sudo nft list table inet steward'
check "application state survived reboot" r 'sudo curl -fsS http://127.0.0.1:20080/notes | grep -q "survives reboot"'
check "status is ok after reboot" steward status

fi

[ "$FAILED" = 0 ] && echo "ALL CHECKS PASSED" || echo "SOME CHECKS FAILED"
exit "$FAILED"
