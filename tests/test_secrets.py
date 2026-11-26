import os
import stat

import pytest

from steward.core.secrets import (
    SecretError,
    check_env_value,
    generate_admin_token,
    redact,
    resolve,
    validate_admin_token,
)


def test_env_reference_reads_only_the_named_variable():
    assert resolve("env:A", {"A": "value", "B": "other"}) == "value"
    with pytest.raises(SecretError):
        resolve("env:MISSING", {})


def test_file_reference_requires_private_permissions(tmp_path):
    path = tmp_path / "secret"
    path.write_text("value\n")
    path.chmod(0o644)
    with pytest.raises(SecretError, match="permissions too open"):
        resolve(f"file:{path}")
    path.chmod(0o600)
    assert resolve(f"file:{path}") == "value"


def test_generated_admin_token_is_private_long_and_not_overwritten(tmp_path):
    path = tmp_path / "dir" / "admin_token"
    generate_admin_token(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    first = path.read_text().strip()
    validate_admin_token(first)
    with pytest.raises(SecretError):
        generate_admin_token(path)
    generate_admin_token(path, force=True)
    assert path.read_text().strip() != first


def test_short_admin_token_is_rejected():
    with pytest.raises(SecretError):
        validate_admin_token("changeme")


def test_env_values_cannot_inject_lines():
    with pytest.raises(SecretError):
        check_env_value("A", "x\nB=y")


def test_redaction_removes_secret_material():
    text = (
        "Authorization: Bearer abc.def.ghi password=hunter2 api_key: 'k123' "
        "token sk-abcdefghijklmnopqrstu ghp_abcdefghijklmnopqrstuvwx known-value-1"
    )
    out = redact(text, ("known-value-1",))
    for leaked in (
        "abc.def.ghi",
        "hunter2",
        "k123",
        "sk-abcdefghijklmnop",
        "ghp_",
        "known-value-1",
    ):
        assert leaked not in out
