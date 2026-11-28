import hashlib
from pathlib import Path

import pytest

from opstend.agent import check
from opstend.updates.selfupdate import (
    Layout,
    UpdateError,
    expected_hash,
    newer,
    parse_version,
    pick_release,
)


def rel(tag, prerelease=False, complete=True):
    v = tag.lstrip("v")
    names = [f"opstend-{v}-py3-none-any.whl", "SHA256SUMS"]
    if complete:
        names.append("SHA256SUMS.sigstore.json")
    return {
        "tag_name": tag,
        "prerelease": prerelease,
        "assets": [{"name": n, "browser_download_url": f"https://x/{n}"} for n in names],
    }


def test_versions():
    assert newer("0.3.0", "0.2.9") and not newer("0.2.0-rc.1", "0.2.0")
    assert parse_version("v1.2.3-rc.2") < parse_version("1.2.3")


def test_release_needs_signature_and_respects_channel():
    releases = [rel("v0.4.0", complete=False), rel("v0.3.1"), rel("v0.5.0-rc.1", prerelease=True)]
    assert pick_release(releases).version == "0.3.1"
    assert pick_release(releases, "preview").version == "0.5.0-rc.1"


def test_expected_hash():
    digest = hashlib.sha256(b"x").hexdigest()
    sums = f"{digest}  opstend-0.3.1-py3-none-any.whl\n{'0' * 64}  install.sh\n"
    assert expected_hash(sums, "opstend-0.3.1-py3-none-any.whl") == digest
    with pytest.raises(UpdateError):
        expected_hash(sums, "other.whl")


def test_layout_switch_is_atomic_and_prunes(tmp_path: Path):
    layout = Layout(tmp_path)
    for v in ("0.1.0", "0.2.0", "0.3.0", "0.4.0"):
        (layout.releases / v).mkdir(parents=True)
    assert layout.switch("0.3.0") is None
    assert layout.switch("0.4.0") == "0.3.0"
    assert layout.active_version() == "0.4.0"
    layout.prune(keep=2)
    assert sorted(p.name for p in layout.releases.iterdir()) == ["0.3.0", "0.4.0"]


def test_agent_allows_only_plain_self_update():
    check(["/opt/opstend/current/bin/opstend", "self-update", "--version", "0.3.1"])
    for bad in (
        ["opstend", "serve"],
        ["opstend", "self-update", "--version", "1; rm -rf /"],
        ["opstend", "self-update", "--channel", "x"],
    ):
        with pytest.raises(PermissionError):
            check(bad)
