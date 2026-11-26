from concurrent.futures import ThreadPoolExecutor

import pytest

from steward.core.backup_credentials import MARKER, claim


def test_claim_is_private_and_idempotent(tmp_path):
    assert claim(tmp_path)
    target = tmp_path / "backup"
    assert target.stat().st_mode & 0o777 == 0o700
    marker = target / ".steward-owned"
    assert marker.read_text() == MARKER
    assert marker.stat().st_mode & 0o777 == 0o600
    assert not claim(tmp_path)


def test_claim_never_adopts_foreign_directory_or_symlink(tmp_path):
    target = tmp_path / "backup"
    target.mkdir(mode=0o700)
    (target / "foreign").write_text("keep")
    with pytest.raises((ValueError, FileNotFoundError)):
        claim(tmp_path)
    assert (target / "foreign").read_text() == "keep"
    (target / "foreign").unlink()
    target.rmdir()
    target.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError):
        claim(tmp_path)
    assert target.is_symlink()


def test_claim_rejects_foreign_marker(tmp_path):
    assert claim(tmp_path)
    marker = tmp_path / "backup" / ".steward-owned"
    marker.write_text("foreign\n")
    with pytest.raises(ValueError):
        claim(tmp_path)
    assert marker.read_text() == "foreign\n"


def test_concurrent_claims_do_not_replace_existing_directory(tmp_path):
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(claim, [tmp_path, tmp_path]))
    assert sorted(results) == [False, True]
    assert (tmp_path / "backup" / ".steward-owned").read_text() == MARKER
    assert sorted(p.name for p in tmp_path.iterdir()) == ["backup"]
