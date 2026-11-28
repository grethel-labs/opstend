#!/bin/sh
# OpsTend installer for any Linux distribution and CPU architecture.
#
#   curl -fsSL https://github.com/grethel-labs/opstend/releases/latest/download/install.sh | sudo sh
#   sudo sh install.sh --version 0.3.0 --join opstend1.<fingerprint>.<secret>
#
# What it does, in order:
#   1. detects architecture (amd64, arm64, armv7, ppc64le, s390x, riscv64, 386), distribution
#      and init system (systemd or OpenRC),
#   2. downloads the release wheel and SHA256SUMS from GitHub and verifies the checksum;
#      with cosign installed it also verifies the Sigstore signature of SHA256SUMS,
#   3. installs uv and a standalone Python 3.13 into /opt/opstend (nothing system-wide),
#   4. creates the unprivileged user `opstend`, the data and config directories,
#   5. installs and starts the services: `opstend` (web app, API, automation; unprivileged)
#      and `opstend-agent` (root, Unix socket only).
# Re-running the script upgrades in place and keeps the previous release for rollback.
set -eu

REPO="grethel-labs/opstend"
PREFIX="/opt/opstend"
CONF="/etc/opstend"
DATA="/var/lib/opstend"
VERSION="latest"
JOIN=""
DEMO="no"
WHEEL_FILE=""
SERVICE="yes"

say() { printf '\033[1;36mopstend\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mopstend\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --join) JOIN="$2"; shift 2 ;;
    --demo) DEMO="yes"; shift ;;
    --wheel) WHEEL_FILE="$2"; shift 2 ;;        # install a local wheel (CI, air-gapped)
    --no-service) SERVICE="no"; shift ;;        # install only; do not set up services
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done

[ "$(id -u)" = "0" ] || die "run as root (sudo sh install.sh)"

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64; UVARCH=x86_64 ;;
  aarch64|arm64) ARCH=arm64; UVARCH=aarch64 ;;
  armv7l|armv7) ARCH=armv7; UVARCH=armv7 ;;
  ppc64le) ARCH=ppc64le; UVARCH=powerpc64le ;;
  s390x) ARCH=s390x; UVARCH=s390x ;;
  riscv64) ARCH=riscv64; UVARCH=riscv64gc ;;
  i686|i386) ARCH=386; UVARCH=i686 ;;
  *) die "architecture $(uname -m) is not supported" ;;
esac

LIBC=gnu
ldd --version 2>&1 | grep -qi musl && LIBC=musl
for f in /lib/ld-musl-*; do [ -e "$f" ] && LIBC=musl; done
[ "$ARCH" = "armv7" ] && UVTRIPLE="armv7-unknown-linux-${LIBC}eabihf" || UVTRIPLE="${UVARCH}-unknown-linux-${LIBC}"

. /etc/os-release 2>/dev/null || die "cannot read /etc/os-release"
if [ -d /run/systemd/system ]; then INIT=systemd; elif command -v rc-service >/dev/null 2>&1; then INIT=openrc; elif [ "$SERVICE" = "no" ]; then INIT=none; else die "neither systemd nor OpenRC found"; fi
say "${PRETTY_NAME:-Linux} · $ARCH ($LIBC) · $INIT"

need() { command -v "$1" >/dev/null 2>&1; }
REFRESHED=no
pkg_install() {
  if [ "$REFRESHED" = "no" ]; then
    if need apt-get; then apt-get update -q >/dev/null
    elif need pacman; then pacman -Sy --noconfirm >/dev/null; fi
    REFRESHED=yes
  fi
  if need apt-get; then DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@" >/dev/null
  elif need dnf; then dnf install -y -q "$@" >/dev/null
  elif need zypper; then zypper -n -q install "$@" >/dev/null
  elif need apk; then apk add -q --no-cache "$@" >/dev/null
  elif need pacman; then pacman -S --noconfirm --needed "$@" >/dev/null
  else die "no supported package manager to install $*"; fi
}
need curl || pkg_install curl
need tar || pkg_install tar
need gzip || pkg_install gzip
need sha256sum || pkg_install coreutils

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
if [ -n "$WHEEL_FILE" ]; then
  WHEEL="$(basename "$WHEEL_FILE")"
  VERSION="$(printf '%s' "$WHEEL" | sed -n 's/^opstend-\([^-]*\)-.*/\1/p')"
  cp "$WHEEL_FILE" "$TMP/$WHEEL"
  say "installing local wheel $WHEEL"
else
  if [ "$VERSION" = "latest" ]; then
    VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -n1)"
    [ -n "$VERSION" ] || die "could not find the latest release"
  fi
  BASE="https://github.com/$REPO/releases/download/v$VERSION"
  WHEEL="opstend-$VERSION-py3-none-any.whl"
  say "downloading OpsTend $VERSION"
  curl -fsSL -o "$TMP/$WHEEL" "$BASE/$WHEEL"
  curl -fsSL -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS"
  curl -fsSL -o "$TMP/SHA256SUMS.sigstore.json" "$BASE/SHA256SUMS.sigstore.json" || true
  if need cosign && [ -s "$TMP/SHA256SUMS.sigstore.json" ]; then
    cosign verify-blob --bundle "$TMP/SHA256SUMS.sigstore.json" \
      --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/heads/main" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com "$TMP/SHA256SUMS" >/dev/null \
      || die "signature of SHA256SUMS is not valid"
    say "signature verified (Sigstore)"
  fi
  (cd "$TMP" && grep " $WHEEL\$" SHA256SUMS | sha256sum -c - >/dev/null) || die "checksum mismatch for $WHEEL"
  say "checksum verified"
fi

# uv and a standalone Python: identical behaviour on every distribution and architecture.
mkdir -p "$PREFIX/bin" "$PREFIX/releases" "$PREFIX/python"
if [ ! -x "$PREFIX/bin/uv" ]; then
  curl -fsSL -o "$TMP/uv.tar.gz" "https://github.com/astral-sh/uv/releases/latest/download/uv-$UVTRIPLE.tar.gz"
  tar -xzf "$TMP/uv.tar.gz" -C "$TMP"
  install -m 0755 "$TMP/uv-$UVTRIPLE/uv" "$PREFIX/bin/uv"
fi
export UV_PYTHON_INSTALL_DIR="$PREFIX/python" UV_CACHE_DIR="$PREFIX/cache"
"$PREFIX/bin/uv" python install -q 3.13

case "$ARCH" in amd64|arm64) ;; *)
  # Some dependencies ship no prebuilt wheels for these architectures; build them locally.
  say "installing build tools for $ARCH"
  if need apt-get; then pkg_install build-essential libssl-dev libffi-dev cargo
  elif need dnf; then pkg_install gcc openssl-devel libffi-devel cargo
  elif need apk; then pkg_install build-base openssl-dev libffi-dev cargo
  elif need zypper; then pkg_install gcc libopenssl-devel libffi-devel cargo
  elif need pacman; then pkg_install base-devel openssl libffi rust; fi ;;
esac

REL="$PREFIX/releases/$VERSION"
if [ ! -x "$REL/bin/opstend" ]; then
  "$PREFIX/bin/uv" venv -q --python 3.13 "$REL"
  EXTRA_INDEX=""
  [ "$ARCH" = "armv7" ] && EXTRA_INDEX="--extra-index-url https://www.piwheels.org/simple"
  # shellcheck disable=SC2086
  VIRTUAL_ENV="$REL" "$PREFIX/bin/uv" pip install -q $EXTRA_INDEX "$TMP/${WHEEL}[signing]"
fi
PREV="$(readlink "$PREFIX/current" 2>/dev/null || true)"
ln -sfn "$REL" "$PREFIX/current.new" && mv -T "$PREFIX/current.new" "$PREFIX/current"

if [ "$SERVICE" = "no" ]; then
  "$REL/bin/opstend" --version
  say "installed without services: $REL"
  exit 0
fi

if ! id opstend >/dev/null 2>&1; then
  if need useradd; then useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin opstend
  else adduser -S -D -H -h "$DATA" -s /sbin/nologin opstend; addgroup -S opstend 2>/dev/null || true; fi
fi
install -d -m 0750 -o opstend -g opstend "$DATA"
install -d -m 0750 -o root -g opstend "$CONF" "$CONF/secrets"
if [ ! -f "$CONF/opstend.yaml" ]; then
  cat > "$CONF/opstend.yaml" <<YAML
node:
  name: $(cat /proc/sys/kernel/hostname)
  site: default
listen:
  web: 0.0.0.0:8443
data_dir: $DATA
YAML
  chown root:opstend "$CONF/opstend.yaml"; chmod 0640 "$CONF/opstend.yaml"
fi
if [ ! -f "$CONF/tls.key" ]; then
  "$REL/bin/python" - "$CONF" <<'PY'
import sys, datetime, socket
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
d = Path(sys.argv[1]); key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, socket.gethostname())])
now = datetime.datetime.now(datetime.UTC)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(socket.gethostname())]), False)
        .sign(key, hashes.SHA256()))
(d / "tls.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
(d / "tls.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
PY
  chown root:opstend "$CONF/tls.key" "$CONF/tls.crt"; chmod 0640 "$CONF/tls.key"
fi

SRC="https://raw.githubusercontent.com/$REPO/v$VERSION/packaging"
if [ "$INIT" = "systemd" ]; then
  for unit in opstend.service opstend-agent.service; do
    curl -fsSL -o "/etc/systemd/system/$unit" "$SRC/systemd/$unit"
  done
  [ "$DEMO" = "yes" ] && sed -i 's|serve --config|serve --demo --config|' /etc/systemd/system/opstend.service
  systemctl daemon-reload
  systemctl enable -q --now opstend-agent.service opstend.service
  systemctl restart opstend-agent.service opstend.service
else
  for svc in opstend opstend-agent; do
    curl -fsSL -o "/etc/init.d/$svc" "$SRC/openrc/$svc"; chmod 0755 "/etc/init.d/$svc"
    rc-update add "$svc" default >/dev/null
    rc-service "$svc" restart >/dev/null
  done
fi

ok=no
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsk -o /dev/null https://127.0.0.1:8443/api/session; then ok=yes; break; fi
  sleep 2
done
if [ "$ok" != "yes" ]; then
  if [ -n "$PREV" ]; then
    say "new release did not start; switching back to $(basename "$PREV")"
    ln -sfn "$PREV" "$PREFIX/current.new" && mv -T "$PREFIX/current.new" "$PREFIX/current"
    [ "$INIT" = "systemd" ] && systemctl restart opstend.service || rc-service opstend restart
  fi
  die "OpsTend did not answer on port 8443; see the service log"
fi

if [ -n "$JOIN" ]; then
  printf '%s\n' "$JOIN" > "$CONF/secrets/join-token"; chmod 0600 "$CONF/secrets/join-token"
  chown opstend "$CONF/secrets/join-token"
  say "join token stored; the node joins on its next start"
fi
ADDR="$(hostname -I 2>/dev/null | awk '{print $1}')"
say "ready: https://${ADDR:-$(hostname)}:8443  (first visit creates the admin account)"
