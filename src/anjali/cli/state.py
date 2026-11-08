"""Shared CLI state and helpers."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import date

import typer

from anjali.audit.trail import AuditTrail
from anjali.cli.render import console, err_console, print_json_or  # noqa: F401 (re-exported)
from anjali.core.config import Settings, load_settings, resolve_provider
from anjali.core.db import Database
from anjali.core.errors import AnjaliError
from anjali.providers.base import LLMProvider
from anjali.providers.llm import build_provider


@dataclass
class State:
    settings: Settings
    json: bool = False
    actor: str = "analyst"
    as_of: date | None = None
    quiet: bool = False
    no_audit: bool = False
    provider_name: str | None = None
    _db: Database | None = field(default=None, repr=False)

    @property
    def db(self) -> Database:
        if self._db is None:
            self.settings.ensure_home()
            self._db = Database(self.settings.db_path)
        return self._db

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None

    def audit(self) -> AuditTrail | None:
        if self.no_audit:
            return None
        self.settings.ensure_home()
        return AuditTrail(self.settings.audit_path, db=self.db, actor=self.actor)

    def provider(self) -> LLMProvider:
        if self.provider_name:
            if self.provider_name == "offline":
                from anjali.core.config import ProviderConfig

                return build_provider(ProviderConfig(name="offline", model="anjali-offline-analyst"))
            config = resolve_provider(self.provider_name, self.settings)
            if not config.api_key and config.name != "ollama":
                raise AnjaliError(
                    f"No API key configured for '{config.name}'.",
                    hint=f"Set it with: anjali config set-key {config.name}",
                )
            return build_provider(config)
        return build_provider(self.settings.provider)


def get_state(ctx: typer.Context) -> State:
    if ctx.obj is None:  # pragma: no cover - callback always sets this
        ctx.obj = State(settings=load_settings())
    return ctx.obj  # type: ignore[return-value]


@contextmanager
def errors() -> Iterator[None]:
    """Map typed errors to clean terminal output and a meaningful exit code."""
    try:
        yield
    except AnjaliError as exc:
        err_console.print(f"[bold red]error[/bold red] {exc.message}")
        if exc.hint:
            err_console.print(f"[dim]hint[/dim]  {exc.hint}")
        raise typer.Exit(exc.exit_code) from exc
    except KeyboardInterrupt:  # pragma: no cover
        err_console.print("\n[dim]interrupted[/dim]")
        raise typer.Exit(130) from None


def parse_as_of(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise AnjaliError(f"Invalid date '{value}'. Use YYYY-MM-DD.") from exc


def build_agent_context(state: State, *, jurisdictions: list[str] | None = None, case_id: str | None = None):
    from anjali.agent.tools import AgentContext
    from anjali.analysis.sanctions import SanctionsScreener
    from anjali.rag.store import open_kb

    kb = open_kb(state.settings)
    screener = SanctionsScreener(state.db)
    return AgentContext(
        settings=state.settings,
        kb=kb,
        db=state.db,
        screener=screener,
        audit=state.audit(),
        as_of=state.as_of,
        jurisdictions=jurisdictions or state.settings.default_jurisdictions,
        case_id=case_id,
    )


def require_kb_documents(state: State) -> int:
    count = int(state.db.scalar("SELECT COUNT(*) FROM documents") or 0)
    if count == 0:
        raise AnjaliError(
            "The regulatory corpus is empty.",
            hint="Run `anjali init` (or `anjali kb ingest`) to load it.",
        )
    return count


def confirm(prompt: str, *, default: bool = False, assume_yes: bool = False) -> bool:
    if assume_yes:
        return True
    return typer.confirm(prompt, default=default)
