"""Concrete BYOK adapters.

* :class:`OpenAICompatibleProvider` — OpenAI, Groq, Mistral, Ollama, OpenRouter
  (all speak ``/chat/completions`` with ``tools``).
* :class:`AnthropicProvider` — native Messages API with ``tool_use`` blocks.
* :class:`OfflineProvider` — air-gapped placeholder; never performs network I/O.

No SDKs. Pure HTTPX so the dependency surface (and supply-chain risk) stays small —
a real concern for regulated environments.
"""

from __future__ import annotations

import json
import time
from typing import Any

import httpx

from anjali.core.config import ProviderConfig
from anjali.core.errors import AuthError, ProviderError, RateLimitError
from anjali.providers.base import (
    LLMProvider,
    LLMResponse,
    Message,
    ToolCall,
    ToolSpec,
)

RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504}


def _post_json(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str],
    *,
    timeout: float,
    max_retries: int,
) -> dict[str, Any]:
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(url, json=payload, headers=headers)
            if resp.status_code in (401, 403):
                raise AuthError(
                    f"Provider rejected credentials (HTTP {resp.status_code}).",
                    hint="Check your key: anjali providers --test",
                )
            if resp.status_code == 429:
                retry_after = float(resp.headers.get("retry-after", "2") or 2)
                if attempt < max_retries:
                    time.sleep(min(retry_after, 8) * (attempt + 1))
                    continue
                raise RateLimitError("Provider rate limit reached; retries exhausted.")
            if resp.status_code in RETRYABLE_STATUS and attempt < max_retries:
                time.sleep(0.6 * (2**attempt))
                continue
            if resp.status_code >= 400:
                body = resp.text[:600]
                raise ProviderError(f"Provider error HTTP {resp.status_code}: {body}")
            return resp.json()
        except httpx.HTTPError as exc:  # network / timeout
            last_exc = exc
            if attempt < max_retries:
                time.sleep(0.6 * (2**attempt))
                continue
    raise ProviderError(
        f"Could not reach provider: {last_exc}",
        hint="If air-gapped, use `--provider offline` or run Ollama locally.",
    )


class OpenAICompatibleProvider(LLMProvider):
    """Works with any ``/chat/completions`` endpoint."""

    def _url(self) -> str:
        base = (self.config.base_url or "").rstrip("/")
        if not base:
            raise ProviderError(f"No base_url configured for {self.name}.")
        if base.endswith("/chat/completions"):
            return base
        return f"{base}/chat/completions"

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        if self.name == "openrouter":
            headers["HTTP-Referer"] = "https://github.com/sriroopchakraborty1991-lang/ANJALI-v1.0"
            headers["X-Title"] = "ANJALI-AI"
        return headers

    def _invoke(
        self,
        messages: list[Message],
        tools: list[ToolSpec],
        *,
        system: str | None,
        temperature: float,
        max_tokens: int,
    ) -> LLMResponse:
        wire: list[dict[str, Any]] = []
        if system:
            wire.append({"role": "system", "content": system})
        wire.extend(m.as_openai() for m in messages)
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": wire,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = [t.as_openai() for t in tools]
            payload["tool_choice"] = "auto"

        data = _post_json(
            self._url(),
            payload,
            self._headers(),
            timeout=self.config.timeout_s,
            max_retries=self.config.max_retries,
        )
        choices = data.get("choices") or [{}]
        choice = choices[0] or {}
        msg = choice.get("message") or {}
        calls: list[ToolCall] = []
        for i, tc in enumerate(msg.get("tool_calls") or []):
            fn = tc.get("function") or {}
            calls.append(
                ToolCall.from_json(
                    tc.get("id") or f"call_{i}", fn.get("name", ""), fn.get("arguments") or "{}"
                )
            )
        return LLMResponse(
            text=(msg.get("content") or "").strip(),
            tool_calls=calls,
            usage=data.get("usage") or {},
            finish_reason=choice.get("finish_reason", "stop"),
            raw=data,
        )


class AnthropicProvider(LLMProvider):
    """Native Anthropic Messages API (system is a top-level field, not a message)."""

    def _invoke(
        self,
        messages: list[Message],
        tools: list[ToolSpec],
        *,
        system: str | None,
        temperature: float,
        max_tokens: int,
    ) -> LLMResponse:
        base = (self.config.base_url or "https://api.anthropic.com/v1").rstrip("/")
        wire: list[dict[str, Any]] = []
        for m in messages:
            if m.role == "system":
                continue
            if m.role == "tool":
                wire.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": m.tool_call_id or "",
                                "content": m.content,
                            }
                        ],
                    }
                )
            elif m.role == "assistant" and m.tool_calls:
                blocks: list[dict[str, Any]] = []
                if m.content:
                    blocks.append({"type": "text", "text": m.content})
                for tc in m.tool_calls:
                    blocks.append(
                        {"type": "tool_use", "id": tc.id, "name": tc.name, "input": tc.arguments}
                    )
                wire.append({"role": "assistant", "content": blocks})
            else:
                wire.append({"role": "user" if m.role != "assistant" else "assistant",
                             "content": m.content})

        payload: dict[str, Any] = {
            "model": self.config.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": wire,
        }
        if system:
            payload["system"] = system
        if tools:
            payload["tools"] = [t.as_anthropic() for t in tools]

        headers = {
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        if self.config.api_key:
            headers["x-api-key"] = self.config.api_key

        data = _post_json(
            f"{base}/messages",
            payload,
            headers,
            timeout=self.config.timeout_s,
            max_retries=self.config.max_retries,
        )
        text_parts: list[str] = []
        calls: list[ToolCall] = []
        for i, block in enumerate(data.get("content") or []):
            btype = block.get("type")
            if btype == "text":
                text_parts.append(block.get("text", ""))
            elif btype == "tool_use":
                calls.append(
                    ToolCall.from_json(
                        block.get("id") or f"call_{i}",
                        block.get("name", ""),
                        block.get("input") or {},
                    )
                )
        usage_raw = data.get("usage") or {}
        usage = {
            "prompt_tokens": usage_raw.get("input_tokens", 0),
            "completion_tokens": usage_raw.get("output_tokens", 0),
            "total_tokens": int(usage_raw.get("input_tokens", 0))
            + int(usage_raw.get("output_tokens", 0)),
        }
        return LLMResponse(
            text="\n".join(text_parts).strip(),
            tool_calls=calls,
            usage=usage,
            finish_reason=data.get("stop_reason", "stop"),
            raw=data,
        )


class OfflineProvider(LLMProvider):
    """Deterministic, air-gapped mode.

    The agent detects ``is_offline`` and routes to the rule-based analyst instead of
    pretending to call a model. This keeps offline answers honest: they are marked
    ``offline: true`` and cite retrieved provisions directly.
    """

    def _invoke(
        self,
        messages: list[Message],
        tools: list[ToolSpec],
        *,
        system: str | None,
        temperature: float,
        max_tokens: int,
    ) -> LLMResponse:  # pragma: no cover - guarded by base.complete
        raise ProviderError("Offline provider performs no generation.")

    def health(self) -> tuple[bool, str]:
        return True, "deterministic analyst available"


def build_provider(config: ProviderConfig) -> LLMProvider:
    name = config.name
    if name == "offline":
        return OfflineProvider(config)
    if name == "anthropic":
        return AnthropicProvider(config)
    if name in {"openai", "groq", "mistral", "ollama", "openrouter"}:
        return OpenAICompatibleProvider(config)
    raise ProviderError(f"Unsupported provider: {name}")


def provider_from_settings(settings: Any) -> LLMProvider:
    return build_provider(settings.provider)


def tool_result_payload(payload: Any, *, max_chars: int = 6000) -> str:
    """Serialise a tool result for the model, bounded to keep context small."""
    if isinstance(payload, str):
        text = payload
    else:
        text = json.dumps(payload, default=str, ensure_ascii=False)
    if len(text) > max_chars:
        text = text[:max_chars] + "\n…[truncated by ANJALI context guard]"
    return text
