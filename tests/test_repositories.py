"""R01: fetch an exact repository revision with scoped credentials (local fixtures)."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import time
from pathlib import Path

import pytest

from repo_testkit import (
    CLEAN_ENV,
    GIT,
    POLICY,
    Upstream,
    fake_ssh,
    git,
    logging_git,
    repository,
    serve_http,
)
from steward.core import canonical
from steward.core import repositories as repos
from steward.core.config import ConfigError, Repository, effective, parse_config
from steward.core.repositories import (
    FetchError,
    FetchLimits,
    FetchPolicy,
    fetch_repository,
    load_record,
    source_digest,
)


@pytest.fixture
def root(tmp_path):
    path = tmp_path / "fetch"
    path.mkdir(mode=0o700)
    return path


@pytest.fixture
def upstream(tmp_path):
    source = Upstream(tmp_path)
    source.first = source.commit({"README.md": "hello\n", "app.py": "print('hi')\n"}, "one")
    return source


def stored(root: Path) -> list[str]:
    return sorted(
        p.name for p in (root / "shop" / "backend").iterdir() if not p.name.startswith(".")
    )


# --- exact revision, record, idempotency --------------------------------------


def test_fetch_records_exact_commit_tree_and_digest(root, upstream):
    record = fetch_repository(repository(upstream.file_url), root, policy=POLICY)
    assert record.commit == upstream.first
    assert record.tree == upstream.tree(upstream.first)
    assert record.source_digest == source_digest(record.commit, record.tree)
    assert record.changed is True and record.store == f"{record.commit}.git"
    store = repos.store_path(root, record)
    assert git("rev-parse", "--is-bare-repository", cwd=store) == "true"
    # content is retrievable without any checkout
    assert git("show", f"{record.commit}:app.py", cwd=store) == "print('hi')"
    assert not (store / "hooks").exists() or not list((store / "hooks").iterdir())
    loaded = load_record(root, "shop", "backend", record.commit)
    assert loaded.source_digest == record.source_digest and loaded.changed is False
    data = json.loads((root / "shop/backend" / f"{record.commit}.json").read_text())
    assert data["schema"] == 1 and "changed" not in data
    for entry in (root / "shop", root / "shop/backend", store):
        assert stat.S_IMODE(entry.stat().st_mode) == 0o700


def test_packaged_fetch_refuses_reusing_a_store_missing_a_reachable_blob(root, upstream, tmp_path):
    scratch = tmp_path / "runtime"
    scratch.mkdir(mode=0o700)
    configured = repository(upstream.file_url, revision=upstream.first)
    first = fetch_repository(configured, root, policy=POLICY, scratch=scratch)
    assert fetch_repository(configured, root, policy=POLICY, scratch=scratch) == first
    store = repos.store_path(root, first)
    blob = git("rev-parse", f"{first.commit}:README.md", cwd=store)
    pack_dir = store / "objects" / "pack"
    saved_packs = pack_dir.rename(tmp_path / "saved-packs")
    # Unpack with the original packs out of the object search path.
    for pack in sorted(saved_packs.glob("*.pack")):
        with pack.open("rb") as stream:
            subprocess.run(
                [GIT, "unpack-objects"],
                cwd=store,
                env=CLEAN_ENV,
                stdin=stream,
                umask=0o077,
                check=True,
            )
    (store / "objects" / blob[:2] / blob[2:]).unlink()
    assert git("rev-parse", f"{first.commit}^{{tree}}", cwd=store) == first.tree

    with pytest.raises(FetchError, match="retained repository is corrupt"):
        fetch_repository(configured, root, policy=POLICY, scratch=scratch)
    assert load_record(root, "shop", "backend", first.commit) == first


def test_repeating_the_same_commit_changes_nothing(root, upstream):
    first = fetch_repository(repository(upstream.file_url), root, policy=POLICY)
    store = repos.store_path(root, first)
    before = (store.stat().st_ino, (root / "shop/backend" / f"{first.commit}.json").read_bytes())
    again = fetch_repository(
        repository(upstream.file_url), root, policy=POLICY, clock=lambda: pytest.fail("clock")
    )
    assert again.changed is False and again.commit == first.commit
    assert again.fetched_at == first.fetched_at
    assert (
        store.stat().st_ino,
        (root / "shop/backend" / f"{again.commit}.json").read_bytes(),
    ) == before
    assert stored(root) == sorted([f"{first.commit}.git", f"{first.commit}.json"])


def test_new_upstream_commit_is_a_new_immutable_store(root, upstream):
    first = fetch_repository(repository(upstream.file_url), root, policy=POLICY)
    second_commit = upstream.commit({"app.py": "print('v2')\n"}, "two")
    second = fetch_repository(repository(upstream.file_url), root, policy=POLICY)
    assert second.commit == second_commit != first.commit and second.changed
    assert git("show", f"{first.commit}:app.py", cwd=repos.store_path(root, first)) == "print('hi')"
    assert f"{first.commit}.git" in stored(root)


def test_pinned_revision_wins_over_the_moving_ref(root, upstream):
    upstream.commit({"app.py": "print('v2')\n"}, "two")
    record = fetch_repository(
        repository(upstream.file_url, revision=upstream.first), root, policy=POLICY
    )
    assert record.commit == upstream.first and record.requested_revision == upstream.first


def test_unavailable_pinned_revision_fails_closed_without_residue(root, upstream):
    missing = "0123456789abcdef0123456789abcdef01234567"
    with pytest.raises(FetchError) as exc:
        fetch_repository(repository(upstream.file_url, revision=missing), root, policy=POLICY)
    assert exc.value.code == "git_failed"
    assert stored(root) == [] and not list((root / "shop/backend").glob(".tmp-*"))


def test_annotated_tag_resolves_to_its_commit(root, upstream):
    git("tag", "-a", "-m", "release", "v1", upstream.first, cwd=upstream.work)
    git("push", "-q", str(upstream.bare), "refs/tags/v1", cwd=upstream.work)
    upstream.commit({"app.py": "later\n"}, "later")
    record = fetch_repository(
        repository(upstream.file_url, ref="refs/tags/v1"), root, policy=POLICY
    )
    assert record.commit == upstream.first


# --- hostile repository content and environment --------------------------------


def test_fetching_never_runs_repository_or_ambient_hooks(root, upstream, tmp_path, monkeypatch):
    marker = tmp_path / "hook-ran"
    template = tmp_path / "template"
    (template / "hooks").mkdir(parents=True)
    hook = template / "hooks" / "reference-transaction"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
    hook.chmod(0o755)
    # control: the ambient template would run a hook for a normal Git invocation
    control = tmp_path / "control"
    git("init", "-q", "--bare", str(control), cwd=tmp_path, env={"GIT_TEMPLATE_DIR": str(template)})
    subprocess.run(
        [GIT, "--git-dir", str(control), "fetch", "-q", upstream.file_url, "main:refs/x"],
        env={**CLEAN_ENV, "GIT_ALLOW_PROTOCOL": "file"},
        check=True,
    )
    assert marker.exists()
    marker.unlink()
    # hostile content in the repository and in the caller's environment
    upstream.commit(
        {
            ".gitmodules": '[submodule "x"]\n\tpath = x\n\turl = file:///etc\n',
            ".gitattributes": "* filter=evil\n* export-subst\n",
            ".githooks/post-checkout": f"#!/bin/sh\ntouch {marker}\n",
            "steward.contract.yml": "container_port: 8080\n",
        },
        "hostile",
    )
    for name, value in {
        "GIT_TEMPLATE_DIR": str(template),
        "GIT_SSH_COMMAND": f"touch {marker}",
        "GIT_EXEC_PATH": str(tmp_path),
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.hooksPath",
        "GIT_CONFIG_VALUE_0": str(template / "hooks"),
        "GIT_DIR": str(tmp_path / "elsewhere"),
    }.items():
        monkeypatch.setenv(name, value)
    record = fetch_repository(repository(upstream.file_url), root, policy=POLICY)
    assert not marker.exists()
    assert not (tmp_path / "elsewhere").exists()
    assert not (root / "shop/backend" / "x").exists()
    assert record.changed


def test_git_environment_is_built_from_scratch_and_hardened(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_ASKPASS", "/evil")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid")
    env = repos.git_env(FetchPolicy(), tmp_path)
    assert set(env) <= {
        "PATH", "HOME", "LC_ALL", "LANG", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL",
        "GIT_TERMINAL_PROMPT", "GIT_ALLOW_PROTOCOL", "GIT_ASKPASS", "GIT_OPTIONAL_LOCKS",
    }  # fmt: skip
    assert env["GIT_ASKPASS"] == "/bin/false" and env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_ALLOW_PROTOCOL"] == "https:ssh"
    args = repos.hardening_args(FetchPolicy())
    flat = " ".join(args)
    for expected in (
        "core.hooksPath=/dev/null", "protocol.allow=never", "protocol.https.allow=always",
        "protocol.ssh.allow=always", "http.followRedirects=false", "http.sslVerify=true",
        "fetch.recurseSubmodules=false", "credential.helper=", "transfer.fsckObjects=true",
    ):  # fmt: skip
        assert expected in flat
    assert "protocol.file.allow" not in flat and "protocol.http.allow" not in flat


@pytest.mark.parametrize(
    "url",
    [
        "http://git.example.org/a.git",
        "git://git.example.org/a.git",
        "file:///srv/repo.git",
        "ext::sh -c touch /tmp/x",
        "https://user:secret@git.example.org/a.git",
        "https://git.example.org/a.git?x=1",
        "https://git.example.org/../a.git",
        "https://git.example.org/a/./b.git",
        "https://git.example.org/a/.git/config",
        "https://git.example.org//a.git",
        "https://-oProxyCommand=x/a.git",
        "git@git.example.org:a/b.git",
        "ssh://git@git.example.org/a.git",  # no host key / credential
        "https://git.example.org/a b.git",
    ],
)
def test_malicious_or_unsupported_urls_are_rejected_by_the_model(url):
    with pytest.raises(ValueError):
        Repository.model_validate(
            {"id": "x-repo", "application": "shop", "service": "backend", "url": url}
        )


@pytest.mark.parametrize(
    "ref",
    [
        "main",
        "refs/remotes/origin/main",
        "refs/heads/../x",
        "refs/heads/a..b",
        "refs/heads/x.lock",
        "refs/heads/-x",
        "refs/heads/.hidden",
        "--upload-pack=touch /tmp/x",
        "refs/heads/a b",
        "refs/heads/a:b",
        "refs/heads/a/",
        "refs/heads/x\nrefs/heads/y",
    ],
)
def test_malicious_refs_are_rejected_by_the_model(ref):
    with pytest.raises(ValueError):
        Repository.model_validate(
            {
                "id": "x-repo", "application": "shop", "service": "backend",
                "url": "https://git.example.org/a.git", "ref": ref,
            }
        )  # fmt: skip


def test_revision_must_be_a_full_lowercase_sha1():
    for value in ("abc123", "A" * 40, "g" * 40, "a" * 64, "--all"):
        with pytest.raises(ValueError):
            Repository.model_validate(
                {
                    "id": "x-repo", "application": "shop", "service": "backend",
                    "url": "https://git.example.org/a.git", "revision": value,
                }
            )  # fmt: skip


def test_production_policy_revalidates_and_refuses_relaxed_transports(root, upstream):
    with pytest.raises(FetchError) as exc:
        fetch_repository(repository(upstream.file_url), root)
    assert exc.value.code == "policy"
    with pytest.raises(FetchError) as exc:
        fetch_repository(repository("http://127.0.0.1:1/a.git"), root)
    assert exc.value.code == "policy"
    assert not (root / "shop").exists()


# --- host policy ---------------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.1.2.3", "192.168.0.9", "169.254.169.254", "100.64.0.1", "::1",
     "fe80::1", "fd00::1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "2002:a00:1::1", "0.0.0.0"],
)  # fmt: skip
def test_non_public_addresses_are_refused_before_git_runs(root, address):
    policy = FetchPolicy(resolver=lambda host, port: ["93.184.216.34", address])
    with pytest.raises(FetchError) as exc:
        fetch_repository(repository("https://git.example.org/a.git"), root, policy=policy)
    assert exc.value.code == "non_public_address"
    assert list((root / "shop/backend").glob(".tmp-*")) == []


@pytest.mark.parametrize(
    "address, allowed",
    [("10.1.2.3", True), ("192.168.0.9", True), ("127.0.0.1", True), ("fd00::1", True),
     ("::1", True), ("100.64.0.1", True), ("169.254.169.254", False), ("fe80::1", False),
     ("0.0.0.0", False), ("224.0.0.1", False), ("::ffff:169.254.169.254", False),
     ("64:ff9b::a00:1", False), ("93.184.216.34", True)],
)  # fmt: skip
def test_private_network_opt_in_never_reaches_link_local_or_metadata(address, allowed):
    policy = FetchPolicy(resolver=lambda host, port: [address])
    if allowed:
        assert repos.public_addresses("git.corp.example", 443, policy, True) == [address]
    else:
        with pytest.raises(FetchError) as exc:
            repos.public_addresses("git.corp.example", 443, policy, True)
        assert exc.value.code == "non_public_address"


def test_private_host_needs_the_explicit_repository_option(root):
    policy = FetchPolicy(resolver=lambda h, p: ["10.9.8.7"], git_binary="/nonexistent/git")
    with pytest.raises(FetchError) as exc:
        fetch_repository(repository("https://git.corp.example/a.git"), root, policy=policy)
    assert exc.value.code == "non_public_address"
    with pytest.raises(FetchError) as exc:  # passes the host policy, then git cannot start
        fetch_repository(
            repository("https://git.corp.example/a.git", allow_private_network=True),
            root,
            policy=policy,
        )
    assert exc.value.code == "git_unavailable"


def test_resolution_failure_and_public_pinning(root):
    def broken(host, port):
        raise OSError("nope")

    with pytest.raises(FetchError) as exc:
        fetch_repository(
            repository("https://git.example.org/a.git"), root, policy=FetchPolicy(resolver=broken)
        )
    assert exc.value.code == "resolve_failed"
    assert repos.public_addresses(
        "git.example.org", 443, FetchPolicy(resolver=lambda h, p: ["93.184.216.34"])
    ) == ["93.184.216.34"]
    assert repos.pin_args("https", "git.example.org", 443, ["93.184.216.34", "2606:4700::1"]) == [
        "-c",
        "http.curloptResolve=git.example.org:443:93.184.216.34,[2606:4700::1]",
    ]
    assert repos.pin_args("ssh", "git.example.org", 22, ["93.184.216.34"]) == []


# --- credentials: scope, separation, secrecy ------------------------------------


def secret_resolver(values: dict[str, str], asked: list[str]):
    def resolve(ref: str) -> str:
        asked.append(ref)
        return values[ref]

    return resolve


def test_https_token_is_used_only_after_a_challenge_and_never_in_argv_or_env(
    root, upstream, tmp_path
):
    token = "tok-0123456789-abcdef"
    server = serve_http(upstream.root, token=token)
    log = tmp_path / "git.log"
    asked: list[str] = []
    try:
        record = fetch_repository(
            repository(server.url("app.git"), credential="env:SHOP_BACKEND_TOKEN"),
            root,
            resolve_secret=secret_resolver({"env:SHOP_BACKEND_TOKEN": token}, asked),
            policy=logging_git(tmp_path / "bin", log),
        )
    finally:
        server.stop()
    assert record.commit == upstream.first and asked == ["env:SHOP_BACKEND_TOKEN"]
    assert server.requests[0]["auth"] is None  # no preemptive credential
    assert any(r["auth"] for r in server.requests[1:])
    seen = log.read_text()
    assert "ARGV" in seen and token not in seen
    # nothing of the credential remains on disk
    assert token not in "".join(
        p.read_text(errors="ignore") for p in root.rglob("*") if p.is_file()
    )
    assert not list((root / "shop/backend").glob(".tmp-*"))


def test_wrong_token_fails_and_error_text_has_no_secret(root, upstream):
    server = serve_http(upstream.root, token="right-token-123456")
    try:
        with pytest.raises(FetchError) as exc:
            fetch_repository(
                repository(server.url("app.git"), credential="env:T"),
                root,
                resolve_secret=lambda ref: "wrong-token-654321",
                policy=POLICY,
            )
    finally:
        server.stop()
    assert exc.value.code == "git_failed"
    assert "wrong-token-654321" not in str(exc.value) and "right-token" not in str(exc.value)
    assert stored(root) == []


def test_a_repository_only_ever_asks_for_its_own_credential(root, upstream, tmp_path):
    (tmp_path / "o").mkdir()
    other = Upstream(tmp_path / "o", "other")
    other.commit({"x": "1"}, "x")
    server_a = serve_http(upstream.root, token="token-for-a-123456")
    server_b = serve_http(other.root, token="token-for-b-123456")
    values = {"env:A": "token-for-a-123456", "env:B": "token-for-b-123456"}
    asked: list[str] = []
    try:
        fetch_repository(
            repository(server_a.url("app.git"), credential="env:A"),
            root,
            resolve_secret=secret_resolver(values, asked),
            policy=POLICY,
        )
        # B's credential must not open A's repository, and A's repository never reads B's ref
        with pytest.raises(FetchError):
            fetch_repository(
                repository(
                    server_a.url("app.git"), credential="env:B", id="other-repo", service="other"
                ),
                root,
                resolve_secret=secret_resolver(values, asked),
                policy=POLICY,
            )
        fetch_repository(
            repository(
                server_b.url("other.git"), credential="env:B", id="other-repo", service="other"
            ),
            root,
            resolve_secret=secret_resolver(values, asked),
            policy=POLICY,
        )
    finally:
        server_a.stop()
        server_b.stop()
    assert asked == ["env:A", "env:B", "env:B"]
    import base64

    def tokens(server):
        return {
            base64.b64decode(r["auth"].split()[1]).decode().split(":", 1)[1]
            for r in server.requests
            if r["auth"]
        }

    assert tokens(server_b) == {"token-for-b-123456"}  # A's token never reached B


def test_redirect_is_an_error_and_credentials_do_not_follow(root, upstream, tmp_path):
    target = serve_http(upstream.root, token="tok-redirect-123456")
    start = serve_http(
        upstream.root, redirect=f"http://127.0.0.1:{target.server.server_address[1]}"
    )
    try:
        with pytest.raises(FetchError) as exc:
            fetch_repository(
                repository(start.url("app.git"), credential="env:T"),
                root,
                resolve_secret=lambda ref: "tok-redirect-123456",
                policy=POLICY,
            )
    finally:
        start.stop()
        target.stop()
    assert exc.value.code == "git_failed"
    assert target.requests == []
    assert stored(root) == []


def test_credential_errors_do_not_start_git_and_never_show_values(root, upstream, tmp_path):
    key = tmp_path / "token"
    key.write_text("looks-secret-value\n")
    key.chmod(0o644)
    with pytest.raises(FetchError) as exc:
        fetch_repository(
            repository("https://git.example.org/a.git", credential=f"file:{key}"),
            root,
            resolve_secret=repos.secretlib.resolve,
            policy=FetchPolicy(resolver=lambda h, p: ["93.184.216.34"]),
        )
    assert exc.value.code == "credential" and "looks-secret-value" not in str(exc.value)
    with pytest.raises(FetchError) as exc:
        fetch_repository(
            repository("https://git.example.org/a.git", credential="env:STEWARD_UNSET_TOKEN"),
            root,
            policy=FetchPolicy(resolver=lambda h, p: ["93.184.216.34"]),
        )
    assert exc.value.code == "credential"
    with pytest.raises(FetchError):
        fetch_repository(
            repository("https://git.example.org/a.git", credential="env:X"),
            root,
            resolve_secret=lambda ref: "line\nbreak",
            policy=FetchPolicy(resolver=lambda h, p: ["93.184.216.34"]),
        )


SERVER_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIServerKeyServerKeyServerKey00"
OTHER_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherKeyOtherKeyOtherKeyOtherK1"
PRIVATE = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA-fixture-key\n-----END OPENSSH PRIVATE KEY-----"


def ssh_repository(host_key: str):
    return repository(
        "ssh://git@git.example.org/app.git",
        host_key=host_key,
        credential="env:SHOP_KEY",
    )


def test_ssh_pins_the_host_key_and_uses_a_private_key_file(root, upstream, tmp_path):
    log = tmp_path / "ssh.log"
    policy = fake_ssh(
        tmp_path / "fake", server_key=SERVER_KEY, private_key=PRIVATE,
        root=upstream.root, log=log,
    )  # fmt: skip
    policy = FetchPolicy(
        relaxed_for_tests=True,
        ssh_binary=policy.ssh_binary,
        resolver=lambda host, port: ["93.184.216.34"],
    )
    record = fetch_repository(
        ssh_repository(SERVER_KEY), root, resolve_secret=lambda ref: PRIVATE, policy=policy
    )
    # the fake serves /app.git from the fixture root
    assert record.commit == upstream.first
    call = eval(log.read_text().splitlines()[0])  # noqa: S307 - our own fixture log
    opts = call["opts"]
    assert opts["StrictHostKeyChecking"] == "yes" and opts["BatchMode"] == "yes"
    assert opts["GlobalKnownHostsFile"] == os.devnull and opts["IdentitiesOnly"] == "yes"
    assert opts["IdentityAgent"] == "none" and opts["HostKeyAlgorithms"] == "ssh-ed25519"
    assert opts["Hostname"] == "93.184.216.34" and opts["-F"] == os.devnull
    assert call["host"] == "git@git.example.org"
    # key material only lived in the private per-run directory
    assert PRIVATE not in "".join(
        p.read_text(errors="ignore") for p in root.rglob("*") if p.is_file()
    )


def test_wrong_host_key_and_wrong_private_key_fail_closed(root, upstream, tmp_path):
    base = fake_ssh(
        tmp_path / "fake", server_key=SERVER_KEY, private_key=PRIVATE,
        root=upstream.root, log=tmp_path / "ssh.log",
    )  # fmt: skip
    policy = FetchPolicy(
        relaxed_for_tests=True, ssh_binary=base.ssh_binary, resolver=lambda h, p: ["93.184.216.34"]
    )
    with pytest.raises(FetchError) as exc:
        fetch_repository(
            ssh_repository(OTHER_KEY), root, resolve_secret=lambda ref: PRIVATE, policy=policy
        )
    assert exc.value.code == "git_failed" and "Host key verification failed" in exc.value.message
    with pytest.raises(FetchError) as exc:
        fetch_repository(
            ssh_repository(SERVER_KEY),
            root,
            resolve_secret=lambda ref: PRIVATE.replace("fixture", "wrongkey"),
            policy=policy,
        )
    assert "wrongkey" not in str(exc.value) and "Permission denied" in exc.value.message
    with pytest.raises(FetchError) as exc:
        fetch_repository(
            ssh_repository(SERVER_KEY),
            root,
            resolve_secret=lambda ref: "not a key",
            policy=policy,
        )
    assert exc.value.code == "credential" and "not a key" not in str(exc.value)
    assert stored(root) == []


def test_ssh_command_is_fixed_and_quoted(tmp_path):
    command = repos.ssh_command(
        FetchPolicy(), tmp_path / "id", tmp_path / "kh", "ssh-ed25519", None
    )
    assert command.startswith("/usr/bin/ssh -F /dev/null -i ")
    assert "StrictHostKeyChecking=yes" in command and "ProxyCommand=none" in command
    assert "Hostname=" not in command


# --- limits, interruption, concurrency -------------------------------------------


def test_timeout_leaves_no_partial_store_and_retry_succeeds(root, upstream):
    slow = serve_http(upstream.root, delay=3)
    started = time.monotonic()
    try:
        with pytest.raises(FetchError) as exc:
            fetch_repository(
                repository(slow.url("app.git")), root, policy=POLICY,
                limits=FetchLimits(timeout_s=0.6, poll_s=0.05),
            )  # fmt: skip
    finally:
        slow.server.shutdown()
        slow.server.server_close()
    assert exc.value.code == "timeout" and time.monotonic() - started < 2.5
    assert stored(root) == [] and not list((root / "shop/backend").glob(".tmp-*"))
    assert fetch_repository(repository(upstream.file_url), root, policy=POLICY).changed


def test_size_limit_stops_and_cleans_up(root, upstream):
    upstream.commit({"blob.bin": os.urandom(3 * 2**20)}, "big")
    with pytest.raises(FetchError) as exc:
        fetch_repository(
            repository(upstream.file_url), root, policy=POLICY,
            limits=FetchLimits(max_bytes=200_000, poll_s=0.02),
        )  # fmt: skip
    assert exc.value.code == "too_large"
    assert stored(root) == [] and not list((root / "shop/backend").glob(".tmp-*"))


def test_stale_in_progress_directories_are_swept(root, upstream):
    (root / "shop").mkdir(mode=0o700)
    (root / "shop/backend").mkdir(mode=0o700)
    stale = root / "shop/backend" / ".tmp-crashed"
    stale.mkdir(mode=0o700)
    (stale / "pack").write_bytes(b"x" * 1000)
    fetch_repository(repository(upstream.file_url), root, policy=POLICY)
    assert not stale.exists()


def test_concurrent_fetch_of_one_service_is_refused(root, upstream):
    import fcntl

    namespace = root / "shop" / "backend"
    fetch_repository(repository(upstream.file_url), root, policy=POLICY)
    fd = os.open(namespace / ".lock", os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with pytest.raises(FetchError) as exc:
            fetch_repository(repository(upstream.file_url), root, policy=POLICY)
        assert exc.value.code == "busy"
    finally:
        os.close(fd)


def test_services_have_separate_namespaces(root, upstream, tmp_path):
    (tmp_path / "second").mkdir()
    other = Upstream(tmp_path / "second", "x")
    other.commit({"f": "1"}, "x")
    a = fetch_repository(repository(upstream.file_url), root, policy=POLICY)
    b = fetch_repository(
        repository(other.file_url, id="other-repo", service="frontend"), root, policy=POLICY
    )
    assert repos.store_path(root, a).parent != repos.store_path(root, b).parent
    assert b.commit not in stored(root) and load_record(root, "shop", "frontend", b.commit)
    with pytest.raises(FetchError):
        load_record(root, "shop", "backend", b.commit)


def test_unsafe_roots_are_refused(tmp_path, upstream):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real)
    open_root = tmp_path / "open"
    open_root.mkdir()
    open_root.chmod(0o777)
    spaced = tmp_path / "with space"
    spaced.mkdir(mode=0o700)
    for bad in (link, open_root, spaced, tmp_path / "missing"):
        with pytest.raises(FetchError) as exc:
            fetch_repository(repository(upstream.file_url), bad, policy=POLICY)
        assert exc.value.code == "bad_store"
    # a namespace directory that was replaced by a link is not followed
    root = tmp_path / "ok"
    root.mkdir(mode=0o700)
    (root / "shop").symlink_to(real)
    with pytest.raises(FetchError) as exc:
        fetch_repository(repository(upstream.file_url), root, policy=POLICY)
    assert exc.value.code == "bad_store" and list(real.iterdir()) == []


def test_sha256_repositories_are_not_accepted(root, tmp_path):
    source = tmp_path / "sha256"
    source.mkdir()
    git("init", "-q", "--object-format=sha256", "-b", "main", cwd=source)
    (source / "a").write_text("a")
    git("add", "a", cwd=source)
    git("commit", "-q", "-m", "x", cwd=source)
    with pytest.raises(FetchError):
        fetch_repository(repository(f"file://{source}"), root, policy=POLICY)
    assert stored(root) == []


# --- configuration -----------------------------------------------------------------


def with_repository(raw_config, **fields):
    from test_application_graph import graph

    graph(raw_config)
    raw_config["repositories"] = [
        {
            "id": "shop-backend", "application": "shop", "service": "backend",
            "url": "https://git.example.org/shop/backend.git", **fields,
        }
    ]  # fmt: skip
    return raw_config


def test_repositories_are_valid_but_unavailable(raw_config):
    raw = with_repository(raw_config, credential="env:SHOP_BACKEND_TOKEN")
    with pytest.raises(ConfigError, match="repositories.*not available"):
        parse_config(raw)
    cfg = parse_config(raw, allow_unavailable=True)
    assert cfg.repositories[0].scheme == "https"
    assert "repositories" in effective(cfg)


@pytest.mark.parametrize(
    ("scp_path", "ssh_path"),
    [
        ("shop/backend.git", "/~/shop/backend.git"),
        ("/srv/shop/backend.git", "/srv/shop/backend.git"),
        ("~/shop/backend.git", "/~/shop/backend.git"),
        ("~deploy/shop/backend.git", "/~deploy/shop/backend.git"),
    ],
)
def test_scp_repository_url_matches_explicit_ssh(raw_config, scp_path, ssh_path):
    import jsonschema

    authority = "git@git.example.org"
    raw = with_repository(
        raw_config,
        url=f"{authority}:{scp_path}",
        host_key=SERVER_KEY,
        credential="env:SHOP_BACKEND_KEY",
    )
    schema_path = Path(__file__).resolve().parents[1] / "schemas/config.v1.schema.json"
    jsonschema.Draft202012Validator(json.loads(schema_path.read_text())).validate(raw)
    with pytest.raises(ConfigError, match="repositories.*not available"):
        parse_config(raw)

    parsed = parse_config(raw, allow_unavailable=True)
    explicit_url = f"ssh://{authority}{ssh_path}"
    assert parsed.repositories[0].url == explicit_url
    assert parsed.repositories[0].scheme == "ssh"
    normalized = effective(parsed)

    raw["repositories"][0]["url"] = explicit_url
    explicit = effective(parse_config(raw, allow_unavailable=True))
    assert normalized == explicit
    assert canonical.revision_id(normalized) == canonical.revision_id(explicit)
    assert canonical.diff(normalized, explicit) == []


@pytest.mark.parametrize("missing", ["host_key", "credential"])
def test_scp_repository_url_requires_ssh_trust_and_credential(raw_config, missing):
    raw = with_repository(
        raw_config,
        url="git@git.example.org:shop/backend.git",
        host_key=SERVER_KEY,
        credential="env:SHOP_BACKEND_KEY",
    )
    del raw["repositories"][0][missing]
    with pytest.raises(ConfigError, match="ssh repositories require host_key and credential"):
        parse_config(raw, allow_unavailable=True)


@pytest.mark.parametrize(
    "url",
    [
        "git@git.example.org:shop/../backend.git",
        "git:password@git.example.org:shop/backend.git",
        "-git@git.example.org:shop/backend.git",
        "git@git.example.org:-backend.git",
        "git@git.example.org:/~deploy/shop/backend.git",
    ],
)
def test_malformed_scp_repository_urls_are_rejected(raw_config, url):
    raw = with_repository(
        raw_config,
        url=url,
        host_key=SERVER_KEY,
        credential="env:SHOP_BACKEND_KEY",
    )
    with pytest.raises(ConfigError, match=r"repositories\.0\.url"):
        parse_config(raw, allow_unavailable=True)


def test_empty_repositories_keep_existing_revisions(raw_config):
    before = canonical.revision_id(effective(parse_config(raw_config)))
    raw_config["repositories"] = []
    assert canonical.revision_id(effective(parse_config(raw_config))) == before
    assert "repositories" not in effective(parse_config(raw_config))


@pytest.mark.parametrize(
    "mutate, needle",
    [
        (lambda c: c["repositories"][0].update(service="missing"), "unknown application service"),
        (lambda c: c["repositories"].append(dict(c["repositories"][0], id="second")), "only one"),
        (
            lambda c: c["repositories"].append(
                dict(c["repositories"][0], id="second", service="database")
            ),
            "",
        ),
        (lambda c: c["repositories"][0].update(host_key=SERVER_KEY), "host_key applies"),
        (lambda c: c["repositories"][0].update(url="ssh://git@git.example.org/a.git"), "ssh"),
    ],
)
def test_binding_and_transport_rules(raw_config, mutate, needle):
    raw = with_repository(raw_config)
    mutate(raw)
    if needle:
        with pytest.raises(ConfigError, match=needle):
            parse_config(raw, allow_unavailable=True)
    else:
        parse_config(raw, allow_unavailable=True)  # second service, distinct binding is fine


def test_credential_references_are_not_shared_between_repositories(raw_config):
    raw = with_repository(raw_config, credential="env:SHARED")
    raw["repositories"].append(
        dict(raw["repositories"][0], id="second", service="database", credential="env:SHARED")
    )
    with pytest.raises(ConfigError, match="share a credential"):
        parse_config(raw, allow_unavailable=True)
    raw["repositories"][1]["credential"] = "env:OTHER"
    parse_config(raw, allow_unavailable=True)


def test_inline_secret_values_do_not_fit_the_credential_field(raw_config):
    raw = with_repository(raw_config, credential="ghp_" + "a" * 36)
    with pytest.raises(ConfigError):
        parse_config(raw, allow_unavailable=True)


def test_component_cli_reports_errors_without_fetching(tmp_path, raw_config, capsys):
    import yaml

    path = tmp_path / "c.yml"
    raw = with_repository(raw_config)
    path.write_text(yaml.safe_dump(raw))
    root = tmp_path / "r"
    root.mkdir(mode=0o700)
    assert (
        repos.main(["fetch", "--config", str(path), "--repository", "nope", "--root", str(root)])
        == 2
    )
    assert json.loads(capsys.readouterr().out)["code"] == "unknown_repository"
    assert (
        repos.main(
            ["fetch", "--config", str(tmp_path / "x.yml"), "--repository", "a", "--root", str(root)]
        )
        == 2
    )
    capsys.readouterr()
    # a name resolving to loopback is refused by the public-address rule (no network used)
    raw["repositories"][0]["url"] = "https://localhost/shop/backend.git"
    path.write_text(yaml.safe_dump(raw))
    code = repos.main(
        ["fetch", "--config", str(path), "--repository", "shop-backend", "--root", str(root)]
    )
    assert code == 1 and json.loads(capsys.readouterr().out)["code"] in {
        "non_public_address",
        "resolve_failed",
    }


@pytest.mark.parametrize("endpoint", ["93.184.216.34", "2606:4700::1111"])
def test_fixed_endpoint_accepts_numeric_pins_without_resolving(endpoint, monkeypatch):
    def unexpected_resolution(*args, **kwargs):
        pytest.fail("fixed endpoint must not consult DNS")

    monkeypatch.setattr(repos.socket, "getaddrinfo", unexpected_resolution)
    assert (
        repos.validate_endpoint(repository("https://git.example.org/a.git"), endpoint) == endpoint
    )


@pytest.mark.parametrize(
    "endpoint", ["git.example.org", "10.0.0.1", "169.254.169.254", "2606:4700:0:0:0:0:0:1111"]
)
def test_fixed_endpoint_rejects_unsafe_or_noncanonical_pins(endpoint):
    with pytest.raises((ValueError, FetchError)):
        repos.validate_endpoint(repository("https://git.example.org/a.git"), endpoint)
