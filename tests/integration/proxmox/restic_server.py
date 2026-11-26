#!/usr/bin/env python3
"""Own disposable loopback HTTPS rest-server fixture; never receives a Restic key."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import ipaddress
import json
import os
import re
import secrets
import shlex
import subprocess
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# Executed as root via the caller's unchanged SSH configuration. Payload is stdin.
REMOTE = r"""
import base64, hashlib, hmac, json, os, pathlib, re, socket, ssl, stat, subprocess, sys, urllib.request, urllib.error
p=json.load(sys.stdin)
n=p['namespace']
assert re.fullmatch(r'stw-rest-test-[0-9a-f]{24}', n)
assert re.fullmatch(r'[0-9a-f]{64}', p['token'])
assert 1024 <= p['port'] <= 65535
root=pathlib.Path('/opt')/n
marker=root/'ownership.json'
unit=pathlib.Path('/etc/systemd/system')/(n+'.service')
state=pathlib.Path('/var/lib/private')/n

def digest(data): return hashlib.sha256(data).hexdigest()
def run(*args): return subprocess.run(args,check=True,capture_output=True,text=True).stdout.strip()
def safe(path, mode=None):
    s=path.lstat()
    assert not stat.S_ISLNK(s.st_mode) and s.st_uid==0
    assert s.st_mode & 0o022 == 0
    if mode is not None: assert stat.S_IMODE(s.st_mode)==mode

def probe():
    context=ssl.create_default_context(cafile=str(root/'cert.pem'))
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
    codes=[]
    for authenticated in (False,True):
        req=urllib.request.Request('https://127.0.0.1:%d/fixture/config'%p['port'])
        if authenticated: req.add_header('Authorization','Basic '+p['basic'])
        try:
            with opener.open(req,timeout=5) as response: codes.append(response.status)
        except urllib.error.HTTPError as e: codes.append(e.code)
    assert codes==[401,404],codes
    return {'unauthenticated':codes[0],'authenticated_empty_repository':codes[1]}

if p['action']=='start':
    assert not root.exists() and not root.is_symlink() and not unit.exists() and not state.exists()
    assert not (pathlib.Path('/var/lib')/n).exists()
    with socket.socket() as sock: sock.bind(('127.0.0.1',p['port']))
    files={k:base64.b64decode(v,validate=True) for k,v in p['files'].items()}
    assert set(files)=={'rest-server','key.pem','cert.pem','htpasswd'}
    assert digest(files['rest-server'])==p['binary_sha256']
    root.mkdir(mode=0o700)
    for name,data in files.items():
        dest=root/name
        with dest.open('xb') as f: f.write(data)
        dest.chmod(0o755 if name=='rest-server' else 0o600)
    content=f'''[Unit]
Description=Disposable Steward HTTPS Restic acceptance fixture
[Service]
Type=simple
DynamicUser=yes
StateDirectory={n}
StateDirectoryMode=0700
LoadCredential=tls-key:{root}/key.pem
LoadCredential=tls-cert:{root}/cert.pem
LoadCredential=htpasswd:{root}/htpasswd
ExecStartPre=/usr/bin/mkdir -p /var/lib/{n}/repo
ExecStart={root}/rest-server --listen 127.0.0.1:{p['port']} --path /var/lib/{n}/repo --tls --tls-key %d/tls-key --tls-cert %d/tls-cert --htpasswd-file %d/htpasswd --append-only --private-repos --max-size 1073741824
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_UNIX
UMask=0077
MemoryMax=256M
TasksMax=64
LimitNOFILE=1024
RuntimeMaxSec=86400
StandardOutput=null
StandardError=null
'''.encode()
    # Traverse-only directory permits DynamicUser execution; secrets remain root0600.
    root.chmod(0o711)
    unit.write_bytes(content); unit.chmod(0o644)
    m={'namespace':n,'token':p['token'],'port':p['port'],'unit_sha256':digest(content),'binary_sha256':p['binary_sha256']}
    marker.write_text(json.dumps(m)); marker.chmod(0o600)
    run('systemctl','daemon-reload'); run('systemctl','start',n+'.service')
    import time
    for attempt in range(50):
        try: result=probe(); break
        except (OSError,urllib.error.URLError):
            if attempt==49: raise
            time.sleep(.1)
    print(json.dumps({'namespace':n,'port':p['port'],'probe':result,'active':run('systemctl','is-active',n+'.service')}))
else:
    # Same guards as start ownership, including exact unit and executable hashes.
    safe(root,0o711); safe(marker,0o600); safe(unit,0o644); safe(root/'rest-server',0o755)
    for filename in ('cert.pem','key.pem','htpasswd'): safe(root/filename,0o600)
    m=json.loads(marker.read_text())
    assert hmac.compare_digest(m['token'],p['token']) and m['namespace']==n and m['port']==p['port']
    assert digest(unit.read_bytes())==m['unit_sha256']
    assert digest((root/'rest-server').read_bytes())==m['binary_sha256']
    if p['action']=='status':
        result={'namespace':n,'active':run('systemctl','is-active',n+'.service'),'probe':probe()}
        result['sandbox']=run('systemctl','show',n+'.service','--property=DynamicUser,NoNewPrivileges,CapabilityBoundingSet,ProtectSystem,MemoryMax,MainPID,StateDirectory')
        print(json.dumps(result))
    elif p['action']=='cleanup':
        run('systemctl','stop',n+'.service')
        unit.unlink(); run('systemctl','daemon-reload')
        # Keep own encrypted repository and ownership marker for review. No recursive deletion.
        (root/'key.pem').unlink(); (root/'htpasswd').unlink()
        print(json.dumps({'namespace':n,'stopped':True,'repository_retained':True,'credentials_removed':True}))
    else: raise ValueError('unsupported action')
"""


def private(path: Path, data: bytes):
    with path.open("xb") as stream:
        stream.write(data)
    path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    sub = parser.add_subparsers(dest="action", required=True)
    start = sub.add_parser("start")
    start.add_argument("--ssh-config", type=Path, required=True)
    start.add_argument("--alias", required=True)
    start.add_argument("--archive", type=Path, required=True)
    start.add_argument("--archive-sha256", required=True)
    start.add_argument("--port", type=int, required=True)
    sub.add_parser("status")
    sub.add_parser("cleanup")
    args = parser.parse_args()
    os.umask(0o077)
    work = args.workdir.resolve()
    if args.action == "start":
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", args.alias):
            parser.error("invalid SSH host alias")
        if not re.fullmatch(r"[0-9a-f]{64}", args.archive_sha256):
            parser.error("expected a verified lowercase SHA256")
        archive = args.archive.read_bytes()
        if hashlib.sha256(archive).hexdigest() != args.archive_sha256:
            parser.error("archive SHA256 mismatch; no remote changes made")
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            candidates = [m for m in tar if m.isfile() and Path(m.name).name == "rest-server"]
            if len(candidates) != 1:
                parser.error("archive must contain exactly one rest-server binary")
            binary = tar.extractfile(candidates[0]).read()
        if not 1024 <= args.port <= 65535:
            parser.error("choose an unprivileged loopback port")
        work.mkdir(mode=0o700, parents=True, exist_ok=False)
        namespace = "stw-rest-test-" + secrets.token_hex(12)
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, namespace)])
        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ("127.0.0.1", "10.0.2.2")]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        password = secrets.token_urlsafe(32)
        username = "fixture"
        hashed = "{SHA}" + base64.b64encode(hashlib.sha1(password.encode()).digest()).decode()  # noqa: S324 -- random disposable Basic Auth
        files = {
            "rest-server": binary,
            "cert.pem": cert.public_bytes(serialization.Encoding.PEM),
            "key.pem": key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            "htpasswd": f"{username}:{hashed}\n".encode(),
        }
        for name in ("key.pem", "cert.pem", "htpasswd"):
            private(work / name, files[name])
        private(work / "username", username.encode())
        private(work / "auth-password", password.encode())
        private(
            work / "repository", f"rest:https://10.0.2.2:{args.port}/{username}/fixture/".encode()
        )
        state = {
            "namespace": namespace,
            "token": secrets.token_hex(32),
            "port": args.port,
            "ssh_config": str(args.ssh_config.resolve()),
            "alias": args.alias,
            "archive_sha256": args.archive_sha256,
            "binary_sha256": hashlib.sha256(binary).hexdigest(),
        }
        private(work / "ownership.json", json.dumps(state).encode())
        payload = {**state, "files": {k: base64.b64encode(v).decode() for k, v in files.items()}}
    else:
        for path in (work, work / "ownership.json", work / "username", work / "auth-password"):
            st = path.lstat()
            if path.is_symlink() or st.st_uid != os.getuid() or st.st_mode & 0o077:
                parser.error("local ownership/permission guard failed")
        state = json.loads((work / "ownership.json").read_text())
        payload = dict(state)
    payload["action"] = args.action
    payload["basic"] = base64.b64encode(
        (work / "username").read_bytes() + b":" + (work / "auth-password").read_bytes()
    ).decode()
    command = [
        "ssh",
        "-F",
        state["ssh_config"],
        "-o",
        "StrictHostKeyChecking=yes",
        state["alias"],
        "python3 -c " + shlex.quote(REMOTE),
    ]
    result = subprocess.run(command, input=json.dumps(payload), capture_output=True, text=True)
    if result.returncode:
        # Python tracebacks contain paths/assertions, never serialized credentials.
        raise SystemExit(result.stderr)
    receipt = json.loads(result.stdout)
    private(
        work / (args.action + "-" + secrets.token_hex(4) + ".json"),
        json.dumps(receipt, indent=2).encode(),
    )
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
