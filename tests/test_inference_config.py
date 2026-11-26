"""A01-A03: `ai` configuration validation, canonical revisions and endpoint rules."""

from __future__ import annotations

import pytest
import yaml

from conftest import ROOT
from steward.core import canonical
from steward.core.config import ConfigError, effective, parse_config
from steward.core.inference_endpoint import loopback_url, public_https_url

SHARE = ["status", "events"]
EXTERNAL = {
    "provider": "anthropic",
    "local_only": False,
    "model": "test-model",
    "api_key_ref": "env:TEST_KEY",
    "share": SHARE,
    "budget": {"monthly": {"tokens": 1000}},
}
OLLAMA_CLOUD = {
    **EXTERNAL,
    "provider": "ollama-cloud-api",
    "model": "deepseek-v4.1-flash",
}
LOCAL = {"download_mb": 2000, "ram_mb": 3000, "disk_mb": 4000, "license_ack": True}


def build(raw_config, ai):
    raw_config["ai"] = ai
    return parse_config(raw_config, allow_unavailable=True)


def test_unset_inference_settings_do_not_change_canonical_revisions(raw_config, cfg):
    assert effective(cfg)["ai"] == {"provider": "none", "local_only": True}
    assert canonical.revision_id(effective(cfg)) == canonical.revision_id(effective(cfg))
    # the default example keeps exactly the pre-A01 shape
    raw = yaml.safe_load((ROOT / "examples" / "server.api.yml").read_text())
    assert effective(parse_config(raw))["ai"] == {"provider": "none", "local_only": True}


def test_ai_provider_stays_unavailable_for_users(raw_config):
    for ai in (
        {"provider": "ollama", "model": "test-model:1b"},
        EXTERNAL,
        OLLAMA_CLOUD,
        {"provider": "openai-compatible", "base_url": "http://127.0.0.1:8000/v1", "model": "m"},
    ):
        raw_config["ai"] = ai
        with pytest.raises(ConfigError, match="ai.provider: not available"):
            parse_config(raw_config)


@pytest.mark.parametrize(
    "ai, needle",
    [
        ({"provider": "none", "model": "m"}, "require ai.provider"),
        ({"provider": "ollama"}, "explicitly configured ai.model"),
        ({"provider": "ollama", "model": "m", "base_url": "http://192.0.2.5:11434"}, "loopback"),
        ({"provider": "ollama", "model": "m", "base_url": "https://127.0.0.1:11434"}, "loopback"),
        ({"provider": "ollama", "model": "m", "api_key_ref": "env:K"}, "API key"),
        ({**EXTERNAL, "local_only": True}, "local_only forbids"),
        ({**EXTERNAL, "share": []}, "explicit ai.share"),
        ({**EXTERNAL, "share": ["status", "status"]}, "duplicate"),
        ({**EXTERNAL, "share": ["secrets"]}, "share"),
        ({**EXTERNAL, "budget": None}, "budget.monthly.tokens"),
        ({**EXTERNAL, "api_key_ref": None}, "api_key_ref"),
        ({**EXTERNAL, "api_key_ref": "sk-live-abcdef"}, "api_key_ref"),  # value, not a reference
        ({**EXTERNAL, "base_url": "https://api.example"}, "fixed official endpoint"),
        ({**EXTERNAL, "model": "x; rm -rf /"}, "model"),
        ({**EXTERNAL, "provider": "openai-compatible"}, "base_url"),
        (
            {**EXTERNAL, "provider": "openai-compatible", "base_url": "http://api.example/v1"},
            "https URL",
        ),
        (
            {**EXTERNAL, "provider": "openai-compatible", "base_url": "https://u:p@api.example"},
            "https URL",
        ),
        (
            {**EXTERNAL, "budget": {"monthly": {"tokens": 10, "cost_micro": 5}}},
            "ai.budget.price",
        ),
        ({"provider": "ollama", "model": "m", "share": ["status"]}, "external providers only"),
    ],
)
def test_invalid_ai_settings_are_rejected(raw_config, ai, needle):
    with pytest.raises(ConfigError, match=needle):
        build(raw_config, ai)


@pytest.mark.parametrize(
    "override, needle",
    [
        ({"model": None}, "explicitly configured ai.model"),
        ({"api_key_ref": None}, "api_key_ref"),
        ({"api_key_ref": "test-key-value"}, "api_key_ref"),
        ({"local_only": True}, "local_only forbids"),
        ({"share": []}, "explicit ai.share"),
        ({"budget": {"per_project": {"tokens": 1000}}}, "budget.monthly.tokens"),
        ({"base_url": "https://ollama.com/api/chat"}, "fixed official endpoint"),
        ({"base_url": "http://localhost:11434"}, "fixed official endpoint"),
        ({"local": LOCAL}, "ollama only"),
        (
            {"model_policy": {"families": ["deepseek"], "max_eval_tokens": 1000}},
            "model family rule",
        ),
        ({"provider": "ollama-cloud"}, "ai.provider"),
    ],
)
def test_ollama_cloud_api_rejects_invalid_settings(raw_config, override, needle):
    with pytest.raises(ConfigError, match=needle):
        build(raw_config, {**OLLAMA_CLOUD, **override})


def test_ollama_cloud_api_round_trips_as_external(raw_config):
    cfg = build(raw_config, OLLAMA_CLOUD)
    assert cfg.ai.is_external
    data = effective(cfg)
    assert data["ai"]["provider"] == "ollama-cloud-api"
    assert data["ai"]["model"] == "deepseek-v4.1-flash"
    assert data["ai"]["api_key_ref"] == "env:TEST_KEY"
    assert "base_url" not in data["ai"]
    assert parse_config(data, allow_unavailable=True).ai == cfg.ai


def test_valid_settings_round_trip_in_canonical_form(raw_config):
    cfg = build(raw_config, EXTERNAL)
    assert cfg.ai.is_external
    data = effective(cfg)["ai"]
    assert data["api_key_ref"] == "env:TEST_KEY" and data["share"] == SHARE
    assert "sk-" not in str(data)  # references only
    local = build(
        raw_config,
        {
            "provider": "openai-compatible",
            "model": "m",
            "base_url": "http://localhost:8000/v1",
        },
    )
    assert not local.ai.is_external and local.ai.local_only  # loopback keeps local_only usable


def test_endpoint_classification():
    assert loopback_url("http://127.0.0.1:11434") and loopback_url("http://localhost:1/v1")
    assert loopback_url("http://[::1]:11434/") and not loopback_url("http://127.0.0.1.evil.example")
    assert not loopback_url("http://10.254.253.20") and not loopback_url("ftp://127.0.0.1")
    assert not loopback_url("http://127.0.0.1:99999")
    assert public_https_url("https://api.example.com/v1")
    for bad in (
        "http://api.example.com",
        "https://api.example.com:8443",
        "https://127.0.0.1",
        "https://10.0.0.1/v1",
        "https://localhost/v1",
        "https://a.localhost",
        "https://u@api.example.com",
        "https://api.example.com/v1?x=1",
        "https://api.example.com/v1#f",
        "https://api.example.com/%2e%2e",
        "https://api.example.com/a b",
        "https://[::1]/",
    ):
        assert not public_https_url(bad), bad


# ---- A02: local install planning -----------------------------------------------------------


def local_ai(**override):
    from steward.core.config import Ai

    return Ai(provider="ollama", model="test-model:1b", local={**LOCAL, **override})


def plan(ai, **facts):
    from steward.core.inference_local import plan_local_install

    base = {"ram_total_mb": 8192, "disk_free_mb": 20000, "reserved_memory_mb": 512}
    return plan_local_install(ai, **{**base, **facts})


def test_local_install_plan_is_loopback_only_cpu_and_never_pulls_implicitly():
    result = plan(local_ai())
    assert result.listen.startswith("127.0.0.1:") and result.device == "cpu"
    assert result.model == "test-model:1b" and result.allow_pull is False


@pytest.mark.parametrize(
    "ai, facts, needle",
    [
        (local_ai(), {"ram_total_mb": 3500}, "insufficient RAM"),
        (local_ai(), {"disk_free_mb": 6000}, "insufficient disk"),
        (local_ai(license_ack=False), {}, "license"),
        (local_ai(), {"gpu_requested": True}, "GPU"),
    ],
)
def test_local_install_is_rejected_for_resources_license_and_devices(ai, facts, needle):
    from steward.core.inference_local import LocalInstallRejected

    with pytest.raises(LocalInstallRejected, match=needle):
        plan(ai, **facts)


def test_local_install_requires_declared_model_and_limits():
    from steward.core.config import Ai
    from steward.core.inference_local import LocalInstallRejected

    for ai, needle in (
        (Ai(provider="ollama", model="m"), "limits are not declared"),
        (Ai(), "not ollama"),
        (Ai.model_construct(provider="ollama", model=None, local=None), "not configured"),
    ):
        with pytest.raises(LocalInstallRejected, match=needle):
            plan(ai)


def test_local_settings_are_validated_and_gpu_is_not_expressible(raw_config):
    with pytest.raises(ConfigError, match="device"):
        build(raw_config, {"provider": "ollama", "model": "m", "local": {**LOCAL, "device": "gpu"}})
    with pytest.raises(ConfigError, match="ollama only"):
        build(raw_config, {**EXTERNAL, "local": LOCAL})
    cfg = build(raw_config, {"provider": "ollama", "model": "m", "local": LOCAL})
    assert effective(cfg)["ai"]["local"]["license_ack"] is True
