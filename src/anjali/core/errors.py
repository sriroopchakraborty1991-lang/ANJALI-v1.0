"""Typed exceptions — the CLI maps each of these to a clean exit code."""

from __future__ import annotations


class AnjaliError(Exception):
    """Base class. `exit_code` is used by the CLI wrapper."""

    exit_code = 1

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint


class ConfigError(AnjaliError):
    exit_code = 2


class ProviderError(AnjaliError):
    exit_code = 3


class AuthError(ProviderError):
    exit_code = 3


class RateLimitError(ProviderError):
    exit_code = 4
    """Retryable — the agent loop backs off rather than crashing."""


class RetrievalError(AnjaliError):
    exit_code = 5


class IngestError(AnjaliError):
    exit_code = 6


class ComplianceError(AnjaliError):
    exit_code = 7


class GuardrailError(AnjaliError):
    exit_code = 8
