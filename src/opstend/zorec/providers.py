"""Model providers for Zorec. All optional: without a provider Zorec answers with rules.

* `anthropic`: Claude through the official Anthropic SDK (`pip install opstend[anthropic]`).
* `local`: a model server on your own hardware (Ollama, llama.cpp server, vLLM)
  through its chat endpoint. Nothing leaves the network.

Providers only produce text. They never execute anything; actions Zorec
suggests become job previews that a person (or the policy) approves.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import httpx


@dataclass
class Reply:
    text: str
    model: str
    refused: bool = False


class Provider(Protocol):
    name: str
    model: str

    async def complete(
        self, system: str, messages: list[dict[str, str]], max_tokens: int = 4000
    ) -> Reply: ...


class ProviderError(RuntimeError):
    pass


class AnthropicProvider:
    """Claude via the Anthropic SDK. The API key comes from the environment or a secret file."""

    name = "anthropic"

    def __init__(
        self, model: str = "claude-opus-5-5", api_key: str | None = None, effort: str = "medium"
    ) -> None:
        try:
            import anthropic
        except ImportError as exc:
            raise ProviderError("install opstend[anthropic] to use Claude") from exc
        self._anthropic = anthropic
        self.client = (
            anthropic.AsyncAnthropic(api_key=api_key) if api_key else anthropic.AsyncAnthropic()
        )
        self.model = model
        self.effort = effort

    async def complete(
        self, system: str, messages: list[dict[str, str]], max_tokens: int = 4000
    ) -> Reply:
        a = self._anthropic
        try:
            # Server-side fallback keeps answers flowing if a request is declined;
            # the final stop_reason still tells us when the whole chain refused.
            response = await self.client.beta.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system,
                messages=messages,  # type: ignore[arg-type,unused-ignore]
                output_config={"effort": self.effort},
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
            )
        except a.RateLimitError as exc:
            raise ProviderError("Claude is rate limited; try again shortly") from exc
        except a.AuthenticationError as exc:
            raise ProviderError("the Anthropic API key is not valid") from exc
        except a.APIStatusError as exc:
            raise ProviderError(f"Claude returned {exc.status_code}") from exc
        except a.APIConnectionError as exc:
            raise ProviderError("Claude is not reachable from this node") from exc
        if response.stop_reason == "refusal":
            return Reply("", response.model, refused=True)
        text = "".join(b.text for b in response.content if b.type == "text")
        return Reply(text, response.model)


class LocalProvider:
    """A model server in your network with an Ollama-style `/api/chat` endpoint."""

    name = "local"

    def __init__(
        self,
        url: str,
        model: str,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 120.0,
    ) -> None:
        self.url = url.rstrip("/")
        self.model = model
        self.client = httpx.AsyncClient(timeout=timeout, transport=transport)

    async def models(self) -> list[str]:
        resp = await self.client.get(f"{self.url}/api/tags")
        resp.raise_for_status()
        return sorted(m["name"] for m in resp.json().get("models", []))

    async def complete(
        self, system: str, messages: list[dict[str, str]], max_tokens: int = 4000
    ) -> Reply:
        body: dict[str, Any] = {
            "model": self.model,
            "stream": False,
            "messages": [{"role": "system", "content": system}, *messages],
            "options": {"num_predict": max_tokens},
        }
        try:
            resp = await self.client.post(f"{self.url}/api/chat", json=body)
        except httpx.HTTPError as exc:
            raise ProviderError(f"local model at {self.url} is not reachable") from exc
        if resp.status_code != 200:
            raise ProviderError(f"local model returned {resp.status_code}")
        data = resp.json()
        return Reply(data.get("message", {}).get("content", ""), data.get("model", self.model))


def from_settings(settings: dict[str, Any]) -> Provider | None:
    kind = settings.get("provider", "none")
    if kind == "anthropic":
        return AnthropicProvider(
            model=settings.get("model") or "claude-opus-5-5", api_key=settings.get("api_key")
        )
    if kind == "local":
        return LocalProvider(settings["url"], settings.get("model") or "llama3.1")
    return None
