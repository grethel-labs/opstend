"""The only module that names concrete provider model IDs or tiers.

Configuration always carries an explicit `ai.model`; nothing here selects a model
at runtime. This registry exists for family classification and for the suggested
IDs used in documentation and acceptance gates. A05 uses discovery from the
provider's model list, price freshness and the family rule of ADR 0002 section 2.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

AS_OF = "2026-11-21"

# family name -> pattern over provider model IDs
FAMILIES: dict[str, dict[str, re.Pattern]] = {
    # Claude: current Sonnet or Haiku tier (ADR 0002 section 2).
    "anthropic": {
        "sonnet": re.compile(r"^claude-sonnet-[0-9][0-9a-z.-]*$"),
        "haiku": re.compile(r"^claude-haiku-[0-9][0-9a-z.-]*$"),
    },
    # OpenAI: the two cheapest tiers or their successors. Tier names are an
    # unverified assumption; A05 ranks by listed price instead.
    "openai": {
        "mini": re.compile(r"^gpt-[0-9][0-9.]*-mini(-[0-9-]+)?$"),
        "nano": re.compile(r"^gpt-[0-9][0-9.]*-nano(-[0-9-]+)?$"),
    },
}

# Suggested IDs (not defaults): used by docs and the provider gate specification.
SUGGESTED: dict[str, dict[str, str]] = {
    "anthropic": {"sonnet": "claude-sonnet-5-5", "haiku": "claude-haiku-5-5"},
    "openai": {"mini": "gpt-5-mini", "nano": "gpt-5-nano"},
}


def family_of(provider: str, model_id: str) -> str | None:
    for name, pattern in FAMILIES.get(provider, {}).items():
        if pattern.fullmatch(model_id):
            return name
    return None


# ---- onboarding options (ADR 0008) --------------------------------------------------------
# Official model ID references checked 2026-11-25:
# https://ollama.com/library/deepseek-v4.1-flash — direct API ID and native CLI :cloud ID.
# https://platform.claude.com/docs/en/models/overview — Claude API Sonnet ID.
# https://learn.chatgpt.com/docs/models — Codex CLI Terra ID.
# Account availability remains UNVERIFIED until G-PROV/G-SCAN. Hints only suggest
# a unique matching ID from a scoped scan and require an operator pick.

HINTS_STATUS = "UNVERIFIED"
PRIVATE_PROVIDER = "openai-compatible"


@dataclass(frozen=True)
class ProviderOption:
    id: str
    label: str
    auth: str  # "signin" | "api_key" | "subscription" | "none" (local, explicit download)
    data_class: str  # "external" | "local"
    adapter: str  # provider name used by adapters/inference.py ("" = no adapter yet)
    auth_method: str = ""  # key into ai_auth.AUTH_METHODS when a login is needed
    default_hint: str = ""  # exact model ID from documentation
    default_kind: str = ""  # "model" for an exact ID


PROVIDER_OPTIONS: dict[str, ProviderOption] = {
    o.id: o
    for o in (
        ProviderOption("ollama-cloud", "Ollama (cloud models)", "signin", "external",
                       "ollama-cloud", "ollama-cloud", "deepseek-v4.1-flash:cloud", "model"),
        ProviderOption("ollama-cloud-api", "Ollama Cloud (API key)", "api_key", "external",
                       "ollama-cloud-api", "", "deepseek-v4.1-flash", "model"),
        ProviderOption("ollama-local", "Ollama (local model, explicit download)", "none",
                       "local", "ollama"),
        ProviderOption("anthropic-api", "Claude API (API key)", "api_key", "external",
                       "anthropic", "", "claude-sonnet-5-5", "model"),
        ProviderOption("openai-api", "OpenAI API (API key)", "api_key", "external",
                       "openai", "", "", ""),
        ProviderOption(PRIVATE_PROVIDER, "OpenAI-compatible API", "api_key", "external", ""),
        ProviderOption("claude-subscription", "Claude subscription", "subscription",
                       "external", "", "claude-subscription", "claude-sonnet-5-5", "model"),
        ProviderOption("codex-subscription", "Codex subscription", "subscription",
                       "external", "", "chatgpt-subscription", "gpt-6.1-terra", "model"),
    )
}  # fmt: skip


def suggest_default(option_id: str, scanned: list[str]) -> str | None:
    """The scanned model that matches the option's intended default, if any (never invented)."""
    option = PROVIDER_OPTIONS.get(option_id)
    if option is None or not option.default_hint:
        return None
    want = option.default_hint.casefold()
    matches = {model for model in scanned if model.casefold() == want}
    return next(iter(matches)) if len(matches) == 1 else None
