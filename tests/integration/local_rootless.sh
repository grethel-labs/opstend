#!/usr/bin/env bash
# Local integration test with real rootless Podman (no root, no VM).
#
# Runs the generated Quadlet units of the example configuration as the current
# user: sample workload, Traefik with the generated routes, and the admin API.
# Proves: image-by-archive flow, container hardening flags as inspected at
# runtime, health, persistent state, proxy -> API path, closed-by-default API.
#
# It does NOT prove: nftables isolation, per-service users, systemd units,
# boot behaviour. Those need the VM test (docs/testing.md).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="$ROOT/.venv/bin/python"
T="$(mktemp -d)"
N=steward-it
cleanup() {
    podman rm -f "$N-notes" "$N-proxy" >/dev/null 2>&1 || true
    [ -n "${API_PID:-}" ] && kill "$API_PID" 2>/dev/null || true
    podman unshare rm -rf "$T" 2>/dev/null || rm -rf "$T"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
step() { echo "--- $*"; }

cd "$ROOT"
mkdir -p "$T"/{q,data,proxy/dynamic,proxy/certs,state,api,images}
"$PY" -c 'import secrets; print(secrets.token_urlsafe(48))' >"$T/admin_token"
chmod 600 "$T/admin_token"
sed -e "s#file:~/.config/steward/my-server/admin_token#file:$T/admin_token#" \
    -e 's/port: 9443/port: 29443\n  backend_port: 29080/' -e 's/host_port: 20080/host_port: 28080/' \
    examples/server.api.yml >"$T/server.yml"

step "render configuration"
STEWARD_ROOT="$T/work" PYTHONPATH=src "$PY" - "$T" <<'PYEOF'
import json, pathlib, sys
from steward.core import render
from steward.core.config import load_config_file
t = pathlib.Path(sys.argv[1])
cfg = load_config_file(t / "server.yml")
v = render.render_vars(cfg, release={"version": "it", "dir": "", "files": {}, "wheel": ""}, ssh_port=22)
(t / "q/notes.container").write_text(v["steward_projects"][0]["quadlet"])
(t / "q/proxy.container").write_text(v["steward_proxy"]["quadlet"])
(t / "proxy/traefik.yml").write_text(v["steward_proxy"]["static"])
(t / "proxy/dynamic/routes.yml").write_text(v["steward_proxy"]["dynamic"])
(t / "vars.json").write_text(json.dumps({
    "notes": [v["steward_projects"][0]["image"], v["steward_projects"][0]["image_tag"]],
    "proxy": [v["steward_proxy"]["image"], v["steward_proxy"]["image_tag"]]}))
PYEOF

step "image flow: pull by digest -> local tag -> archive -> load"
for name in notes proxy; do
    ref="$("$PY" -c "import json;print(json.load(open('$T/vars.json'))['$name'][0])")"
    tag="$("$PY" -c "import json;print(json.load(open('$T/vars.json'))['$name'][1])")"
    podman pull --quiet "$ref" >/dev/null
    podman tag "$ref" "$tag"
    podman save --quiet --format oci-archive --output "$T/images/$name.tar" "$tag"
    podman rmi "$tag" >/dev/null
    podman load --quiet --input "$T/images/$name.tar" >/dev/null
    podman image exists "$tag" || fail "tag $tag missing"
done

step "self-signed certificate"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
    -subj /CN=localhost -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -keyout "$T/proxy/certs/internal.key" -out "$T/proxy/certs/internal.crt" 2>/dev/null
chmod 644 "$T/proxy/certs/internal.key"

run_unit() { # turn the Quadlet-generated ExecStart into a plain podman run
    QUADLET_UNIT_DIRS="$T/q" /usr/libexec/podman/quadlet --user --dryrun 2>/dev/null \
        | grep "^ExecStart=.*--name $1 " | sed -e 's/^ExecStart=//' \
        -e "s#--name $1 #--name $N-$1 #" -e 's/ --sdnotify=conmon//' -e 's/ --cgroups=split//' \
        -e 's/ --log-driver journald//' \
        -e "s#/srv/steward/projects/notes/data#$T/data#" \
        -e "s#/opt/steward/releases/it/bundles#$ROOT/sample-app#" \
        -e "s#/etc/steward/proxy#$T/proxy#g" -e "s#/srv/steward/proxy/state#$T/state#"
}

step "start admin API (closed by default)"
STEWARD_ADMIN_TOKEN_FILE="$T/admin_token" STEWARD_STATE_DIR="$T/api" \
    STEWARD_ALLOWED_ORIGINS="https://localhost:29443" STEWARD_EXECUTOR_SOCKET="$T/none.sock" \
    STEWARD_DESIRED_CONFIG="$T/none.json" STEWARD_CONTROLLER_EXPORT="$T/none-state.json" \
    PYTHONPATH=src "$PY" -m steward.api.server --port 29080 &
API_PID=$!

step "start workload and proxy from generated units"
eval "$(run_unit notes)" >/dev/null
eval "$(run_unit proxy)" >/dev/null

wait_http() { for _ in $(seq 1 40); do curl -fsS -o /dev/null "$@" 2>/dev/null && return 0; sleep 0.5; done; return 1; }
wait_http http://127.0.0.1:28080/healthz || { podman logs "$N-notes" | tail -5; fail "workload health"; }

step "workload: health, state write, state survives restart"
curl -fsS -X POST --data 'integration note' http://127.0.0.1:28080/notes >/dev/null
podman restart "$N-notes" >/dev/null
wait_http http://127.0.0.1:28080/healthz || fail "health after restart"
curl -fsS http://127.0.0.1:28080/notes | grep -q 'integration note' || fail "state lost after restart"

step "workload: isolation as inspected at runtime"
"$PY" - "$N-notes" <<'PYEOF'
import json, subprocess, sys
sys.path.insert(0, "src")
from steward.executor.server import _container_hardening
info = json.loads(subprocess.check_output(["podman", "container", "inspect", sys.argv[1]]))[0]
result = _container_hardening(info, {"memory_mb": 128, "pids": 64})
print("    ", result)
sys.exit(1 if result["violations"] else 0)
PYEOF
podman exec "$N-notes" sh -c 'touch /app/x 2>/dev/null || touch /x 2>/dev/null' && fail "rootfs or /app writable"
podman exec "$N-notes" id -u | grep -qx 10001 || fail "not running as 10001"
podman exec "$N-notes" python -c "
import urllib.request as u, sys
try: u.urlopen('http://169.254.1.3:29080/api/session', timeout=3); sys.exit(1)
except Exception as e: sys.exit(0 if 'HTTP Error' not in str(e) else 1)" || fail "workload can reach host loopback"

step "proxy: admin API through Traefik, TLS, closed without session"
code="$(for _ in $(seq 1 40); do c="$(curl -s -o /dev/null -w '%{http_code}' --cacert "$T/proxy/certs/internal.crt" https://localhost:29443/api/session || true)"; [ "$c" = 401 ] && break; sleep 0.5; done; echo "$c")"
[ "$code" = 401 ] || { podman logs "$N-proxy" 2>&1 | tail -5; fail "expected 401 through proxy, got $code"; }
jar="$T/jar"
curl -fsS --cacert "$T/proxy/certs/internal.crt" -c "$jar" -H 'Origin: https://localhost:29443' \
    -H 'Content-Type: application/json' --data "{\"token\": \"$(cat "$T/admin_token")\"}" \
    https://localhost:29443/api/login >/dev/null || fail "login through proxy"
curl -fsS --cacert "$T/proxy/certs/internal.crt" -b "$jar" https://localhost:29443/api/session >/dev/null \
    || fail "session through proxy"
headers="$(curl -s --cacert "$T/proxy/certs/internal.crt" -D - -o /dev/null https://localhost:29443/api/session)"
for h in strict-transport-security content-security-policy x-content-type-options; do
    grep -qi "^$h:" <<<"$headers" || fail "header $h missing"
done
podman exec "$N-proxy" sh -c 'touch /etc/traefik/x 2>/dev/null' && fail "proxy config writable"

echo "PASS: local rootless integration"
