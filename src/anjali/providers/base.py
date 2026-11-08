"""Provider-neutral chat/tool protocol.

The agent loop speaks this dialect only; each adapter translates to a vendor wire
format. This is what makes BYOK genuinely pluggable instead of "OpenAI-shaped".
"""

from __future__ import annotations

import abc
import json
from dataclasses import dataclass, field
from typing import Any

from anjali.core.config import ProviderConfig
from anjali.core.errors import ProviderError
from anjali.core.util import truncate


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, id_: str, name: str, raw: str | dict[str, Any]) -> ToolCall:
        if isinstance(raw, dict):
            args = raw
        else:
            try:
                args = json.loads(raw) if raw and raw.strip() else {}
            except json.JSONDecodeError:
                args = {"_raw": raw}
        if not isinstance(args, dict):
            args = {"value": args}
        return cls(id=id_, name=name, arguments=args)


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]

    def as_openai(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def as_anthropic(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.parameters,
        }


@dataclass
class Message:
    role: str  # system | user | assistant | tool
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None

    def as_openai(self) -> dict[str, Any]:
        if self.role == "tool":
            return {
                "role": "tool",
                "tool_call_id": self.tool_call_id or "",
                "content": self.content,
            }
        if self.role == "assistant" and self.tool_calls:
            return {
                "role": "assistant",
                "content": self.content or None,
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
                    }
                    for tc in self.tool_calls
                ],
            }
        return {"role": self.role, "content": self.content}


@dataclass
class LLMResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)
    finish_reason: str = "stop"
    raw: dict[str, Any] | None = None

    @property
    def total_tokens(self) -> int:
        return int(self.usage.get("total_tokens", 0))


def estimate_tokens(text: str) -> int:
    """Cheap ~4 chars/token heuristic — used for budget display, not billing."""
    return max(1, len(text) // 4)


class LLMProvider(abc.ABC):
    """Base adapter. Subclasses implement :meth:`_invoke`."""

    def __init__(self, config: ProviderConfig) -> None:
        self.config = config

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def model(self) -> str:
        return self.config.model

    @property
    def is_offline(self) -> bool:
        return self.config.is_offline

    def complete(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        *,
        system: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        if self.is_offline:
            raise ProviderError(
                "Offline provider cannot generate text; ANJALI's deterministic analyst "
                "pipeline handles this path.",
                hint="Set a provider: anjali config set provider openai",
            )
        return self._invoke(
            messages,
            tools or [],
            system=system,
            temperature=self.config.temperature if temperature is None else temperature,
            max_tokens=self.config.max_tokens if max_tokens is None else max_tokens,
        )

    @abc.abstractmethod
    def _invoke(
        self,
        messages: list[Message],
        tools: list[ToolSpec],
        *,
        system: str | None,
        temperature: float,
        max_tokens: int,
    ) -> LLMResponse: ...

    def health(self) -> tuple[bool, str]:
        try:
            resp = self.complete(
                [Message(role="user", content="Reply with the single word: ready")],
                max_tokens=8,
                temperature=0.0,
            )
            return True, truncate(resp.text or "ok", 80)
        except ProviderError as exc:
            return False, exc.message
