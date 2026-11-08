"""ANJALI-AI command line entry point."""

from __future__ import annotations

import os
import platform
import sqlite3
import sys
from pathlib import Path

import typer
from rich.table import Table
from rich.text import Text

from anjali import __version__
from anjali.cli.render import (
    console,
    kv_panel,
    print_banner,
)
from anjali.cli.state import State, errors, get_state, print_json_or
from anjali.core.config import (
    DEFAULT_MODELS,
    PROVIDER_ENV,
    available_providers,
    clear_key,
    load_settings,
    resolve_provider,
    store_key,
)
from anjali.core.db import Database
from anjali.core.errors import AnjaliError
from anjali.rag.store import open_kb

app = typer.Typer(
    name="anjali",
    help=(
        "ANJALI-AI — AI-Navigated Judgment & Audit for Legal Integrity.\n\n"
        "A local-first, BYOK, citation-backed financial-crime compliance agent for the "
        "terminal: US BSA/AML, OFAC, EU AMLD6/AMLR, UK MLR/POCA and the FATF standards."
    ),
    no_args_is_help=False,
    rich_markup_mode="rich",
    add_completion=True,
)


# --------------------------------------------------------------------------- #
# Global callback
# --------------------------------------------------------------------------- #
@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    home: Path | None = typer.Option(None, "--home", help="Override ANJALI_HOME."),
    provider: str | None = typer.Option(None, "--provider", help="Override the configured LLM provider."),
    as_of: str | None = typer.Option(None, "--as-of", help="Resolve regulations as in force on this date (YYYY-MM-DD)."),
    actor: str | None = typer.Option(None, "--actor", help="Actor name recorded in the audit trail."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress non-essential output."),
    no_audit: bool = typer.Option(False, "--no-audit", help="Do not write audit records (not recommended)."),
    version: bool = typer.Option(False, "--version", "-V", help="Print the version and exit."),
) -> None:
    if version:
        console.print(f"ANJALI-AI {__version__}")
        raise typer.Exit(0)

    settings = load_settings(home) if home else load_settings()
    state = State(
        settings=settings,
        json=json_out,
        actor=actor or os.environ.get("ANJALI_ACTOR", "analyst"),
        as_of=None,
        quiet=quiet,
        no_audit=no_audit,
        provider_name=provider,
    )
    if as_of:
        from anjali.cli.state import parse_as_of

        with errors():
            state.as_of = parse_as_of(as_of)
    ctx.obj = state

    if ctx.invoked_subcommand is None:
        print_banner()
        _print_next_steps(state)
        raise typer.Exit(0)


def _print_next_steps(state: State) -> None:
    db_exists = state.settings.db_path.exists()
    docs = 0
    if db_exists:
        try:
            with Database(state.settings.db_path) as db:
                docs = int(db.scalar("SELECT COUNT(*) FROM documents") or 0)
        except Exception:
            docs = 0
    if docs == 0:
        console.print("[yellow]No corpus loaded yet.[/yellow] Start here:\n")
        console.print("  [bold cyan]anjali init[/bold cyan]        load the regulatory corpus and demo lists")
        console.print("  [bold cyan]anjali doctor[/bold cyan]      check your environment")
        return
    console.print("[bold]Common next steps[/bold]\n")
    rows = [
        ('anjali ask "When must a SAR be filed in the US?"', "ask a cited compliance question"),
        ("anjali analyze --dataset demo", "run typology detectors on a case"),
        ("anjali screen \"Mohammed Al-Rashid\"", "sanctions screening with corroboration"),
        ("anjali conflicts list", "US/EU/UK conflicts with authorities"),
        ("anjali simulate", "red-team your controls against injected typologies"),
    ]
    for cmd, desc in rows:
        console.print(f"  [cyan]{cmd}[/cyan]\n    [dim]{desc}[/dim]")
    console.print("\n[dim]anjali --help for the full command tree.[/dim]")


# --------------------------------------------------------------------------- #
# init
# --------------------------------------------------------------------------- #
@app.command()
def init(
    ctx: typer.Context,
    provider: str | None = typer.Option(None, "--provider", help="Provider to configure (openai, anthropic, ollama, …)."),
    force: bool = typer.Option(False, "--force", help="Re-ingest even if a corpus is present."),
    demo: bool = typer.Option(True, "--demo/--no-demo", help="Load the sample case data."),
) -> None:
    """Initialise the workspace: config, corpus, sanctions fixtures and demo case."""
    state: State = get_state(ctx)
    with errors():
        state.settings.ensure_home()
        settings = state.settings
        settings.provider.name = provider or settings.provider.name
        if provider:
            settings.provider.model = DEFAULT_MODELS.get(provider, settings.provider.model)
        settings.save()
        console.print(f"[green]✓[/green] workspace ready at [bold]{settings.home}[/bold]")

        from anjali.analysis.sanctions import seed_database
        from anjali.kb.loader import load_documents

        kb = open_kb(settings)
        existing = int(state.db.scalar("SELECT COUNT(*) FROM documents") or 0)
        if existing and not force:
            console.print(f"[dim]·[/dim] corpus already present ({existing} documents) — skipping")
        else:
            docs = load_documents(home_corpus=settings.home / "corpus")
            counts = kb.ingest(docs, show_progress=True)
            console.print(
                f"[green]✓[/green] corpus ingested: {counts['documents']} documents, "
                f"{counts['chunks']} chunks, index [bold]{kb.index_digest()}[/bold]"
            )

        seeded = seed_database(state.db)
        console.print(
            f"[green]✓[/green] sanctions fixtures: {seeded['entries']} entries "
            f"(version {seeded['version']}, synthetic={seeded['synthetic']})"
        )

        if demo:
            from anjali.analysis.engine import analyze, build_context
            from anjali.analysis.ingest import load_customers, load_transactions, persist

            data_dir = Path(__file__).resolve().parents[3] / "data" / "samples"
            txns, _ = load_transactions(data_dir / "demo_transactions.csv", dataset="demo")
            customers, _ = load_customers(data_dir / "demo_customers.csv")
            persist(state.db, txns, customers, dataset="demo")
            ctx_analysis = build_context(txns, customers)
            result = analyze(ctx_analysis, kb=kb, case_id="demo-2026", db=state.db)
            console.print(
                f"[green]✓[/green] demo case loaded: {len(txns)} transactions, "
                f"{len(customers)} customers, {len(result.findings)} findings, "
                f"risk {result.risk.overall} ({result.risk.band.value})"
            )

        audit = state.audit()
        if audit:
            audit.append("workspace.init", subject=str(settings.home),
                         details={"version": __version__, "provider": settings.provider.name})

        console.print()
        console.print("[bold]Try:[/bold]")
        console.print('  [cyan]anjali analyze --dataset demo[/cyan]')
        console.print('  [cyan]anjali ask "Do we need to file a SAR for structuring?"[/cyan]')
        console.print('  [cyan]anjali simulate[/cyan]')
        if settings.provider.name == "offline":
            console.print(
                "\n[yellow]No LLM configured — ANJALI runs in deterministic offline mode.[/yellow]\n"
                "[dim]Add a key for richer synthesis: [/dim][cyan]anjali config set-key openai[/cyan]"
            )
        state.close()


# --------------------------------------------------------------------------- #
# doctor
# --------------------------------------------------------------------------- #
@app.command()
def doctor(
    ctx: typer.Context,
    network: bool = typer.Option(False, "--network", help="Probe the configured provider endpoint."),
) -> None:
    """Check the environment, corpus, credentials and audit-chain integrity."""
    state: State = get_state(ctx)
    rows: list[tuple[str, str, str]] = []

    def add(name: str, ok: bool, detail: str) -> None:
        rows.append((name, "PASS" if ok else "FAIL", detail))

    add("python", sys.version_info >= (3, 10), platform.python_version())
    try:
        state.settings.ensure_home()
        probe = state.settings.home / ".write-test"
        probe.write_text("ok")
        probe.unlink()
        add("workspace", True, str(state.settings.home))
    except OSError as exc:
        add("workspace", False, f"not writable: {exc}")

    fts = False
    try:
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE VIRTUAL TABLE t USING fts5(x)")
        conn.close()
        fts = True
    except sqlite3.Error:
        fts = False
    add("sqlite FTS5", fts, sqlite3.sqlite_version)

    try:
        db = state.db
        docs = int(db.scalar("SELECT COUNT(*) FROM documents") or 0)
        chunks = int(db.scalar("SELECT COUNT(*) FROM chunks") or 0)
        add("corpus", docs > 0, f"{docs} documents / {chunks} chunks")
        sanctions = int(db.scalar("SELECT COUNT(*) FROM sanctions") or 0)
        version = db.get_meta("sanctions_version", "none")
        add("sanctions lists", sanctions > 0, f"{sanctions} names (version {version})")
        txns = int(db.scalar("SELECT COUNT(*) FROM transactions") or 0)
        add("case data", txns > 0, f"{txns} transactions")
    except Exception as exc:  # pragma: no cover
        add("database", False, str(exc))

    creds = available_providers(state.settings.home)
    configured = state.settings.provider.name
    entry = next((c for c in creds if c["provider"] == configured), None)
    ready = bool(entry and entry["ready"])
    add(
        "provider",
        ready,
        f"{configured} / {state.settings.provider.model}"
        + ("" if ready else " (no key — offline mode)"),
    )

    audit = state.audit()
    if audit:
        verification = audit.verify()
        add("audit chain", verification.valid, f"{verification.records} records, head {verification.head_hash[:12]}")

    if network:
        from anjali.providers.llm import build_provider

        try:
            ok, message = build_provider(state.settings.provider).health()
            add("provider probe", ok, message)
        except AnjaliError as exc:
            add("provider probe", False, exc.message)

    if print_json_or(state, {"rows": [{"check": r[0], "status": r[1], "detail": r[2]} for r in rows]}):
        return

    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Detail")
    for name, status, detail in rows:
        style = "green" if status == "PASS" else "red"
        table.add_row(name, Text(status, style=style), detail)
    console.print()
    console.print("[bold]ANJALI environment[/bold]")
    console.print(table)
    failures = [r for r in rows if r[1] != "PASS"]
    if failures:
        console.print("\n[yellow]Some checks failed.[/yellow] "
                      "If the corpus is missing, run [cyan]anjali init[/cyan].")
    else:
        console.print("\n[green]All checks passed.[/green]")
    state.close()


# --------------------------------------------------------------------------- #
# providers
# --------------------------------------------------------------------------- #
@app.command()
def providers(
    ctx: typer.Context,
    test: bool = typer.Option(False, "--test", help="Send a minimal request to each configured provider."),
) -> None:
    """List supported BYOK providers and whether a key is present."""
    state: State = get_state(ctx)
    rows = available_providers(state.settings.home)
    if test:
        from anjali.providers.llm import build_provider

        for row in rows:
            if not row["ready"]:
                row["probe"] = "skipped (no key)"
                continue
            try:
                config = resolve_provider(row["provider"], state.settings)
                ok, message = build_provider(config).health()
                row["probe"] = ("ok: " + message) if ok else f"failed: {message}"
            except AnjaliError as exc:
                row["probe"] = f"failed: {exc.message}"
    if print_json_or(state, {"providers": rows, "configured": state.settings.provider.name}):
        return
    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("Provider")
    table.add_column("Default model")
    table.add_column("Key")
    table.add_column("Env var")
    table.add_column("Ready")
    if test:
        table.add_column("Probe")
    for row in rows:
        cells = [
            row["provider"] + (" [dim](local)[/dim]" if row["local"] else ""),
            row["model"],
            Text("present", style="green") if row["key_present"] else Text("—", style="dim"),
            row["env_var"] or "—",
            Text("yes", style="green") if row["ready"] else Text("no", style="dim"),
        ]
        if test:
            cells.append(row.get("probe", "—"))
        table.add_row(*cells)
    console.print(table)
    console.print(
        f"\nConfigured: [bold]{state.settings.provider.name}[/bold] "
        f"({state.settings.provider.model})"
    )
    console.print("[dim]Keys are read from ANJALI_HOME/keys.toml, environment variables, or .env — "
                  "never from the command line, never logged.[/dim]")


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #
config_app = typer.Typer(help="Inspect and change configuration (BYOK keys included).", no_args_is_help=True)
app.add_typer(config_app, name="config")


@config_app.command("show")
def config_show(ctx: typer.Context) -> None:
    """Show the effective configuration."""
    state: State = get_state(ctx)
    payload = state.settings.to_dict()
    payload["home"] = str(state.settings.home)
    payload["db"] = str(state.settings.db_path)
    payload["provider"]["key_present"] = bool(state.settings.provider.api_key)
    if print_json_or(state, payload):
        return
    console.print(f"[bold]Config file[/bold] {state.settings.config_file}")
    console.print(f"[bold]Keys file[/bold]   {state.settings.keys_file}")
    console.print(f"[bold]Database[/bold]    {state.settings.db_path}\n")
    kv_panel(
        {
            "provider": state.settings.provider.name,
            "model": state.settings.provider.model,
            "api key": "present" if state.settings.provider.api_key else "absent (offline mode)",
            "temperature": state.settings.provider.temperature,
            "rag.top_k": state.settings.rag.top_k,
            "rag.embedder": state.settings.rag.embedder,
            "as-of default": state.settings.rag.as_of or "today",
            "jurisdictions": ", ".join(state.settings.default_jurisdictions),
            "max agent steps": state.settings.max_agent_steps,
            "require citations": state.settings.require_citations,
        },
        title="Configuration",
    )


@config_app.command("set")
def config_set(
    ctx: typer.Context,
    key: str = typer.Argument(..., help="Dotted key, e.g. provider.name or rag.top_k."),
    value: str = typer.Argument(..., help="New value."),
) -> None:
    """Set a configuration value (provider.name, provider.model, rag.top_k, …)."""
    state: State = get_state(ctx)
    settings = state.settings
    mapping = {
        "provider": "provider.name",
        "provider.name": "provider.name",
        "model": "provider.model",
        "provider.model": "provider.model",
        "temperature": "provider.temperature",
        "provider.temperature": "provider.temperature",
        "provider.base_url": "provider.base_url",
        "rag.top_k": "rag.top_k",
        "rag.embedder": "rag.embedder",
        "rag.mmr_lambda": "rag.mmr_lambda",
        "rag.as_of": "rag.as_of",
        "max_agent_steps": "max_agent_steps",
        "require_citations": "require_citations",
        "audit_enabled": "audit_enabled",
    }
    if key == "provider.base_url":
        settings.provider.base_url = value
    elif key not in mapping:
        raise typer.BadParameter(
            f"Unknown key '{key}'. Known: {', '.join(sorted(mapping))}"
        )
    else:
        target = mapping[key]
        obj: object = settings
        parts = target.split(".")
        for part in parts[:-1]:
            obj = getattr(obj, part)
        attr = parts[-1]
        current = getattr(obj, attr)
        if isinstance(current, bool):
            converted: object = value.lower() in {"1", "true", "yes", "on"}
        elif isinstance(current, int):
            converted = int(value)
        elif isinstance(current, float):
            converted = float(value)
        else:
            converted = value
        setattr(obj, attr, converted)
        if key in ("provider", "provider.name"):
            settings.provider.model = DEFAULT_MODELS.get(value, settings.provider.model)
    settings.save()
    console.print(f"[green]✓[/green] {key} = {value}")


@config_app.command("set-key")
def config_set_key(
    ctx: typer.Context,
    provider: str = typer.Argument(..., help="Provider name (openai, anthropic, groq, mistral, …)."),
    key: str | None = typer.Option(
        None, "--key", help="Key value. Omit to be prompted securely (recommended)."
    ),
) -> None:
    """Store a BYOK API key with 0600 permissions (prompted, never echoed)."""
    state: State = get_state(ctx)
    if provider not in PROVIDER_ENV:
        raise typer.BadParameter(f"Unknown provider '{provider}'. Choose: {', '.join(PROVIDER_ENV)}")
    if not key:
        import getpass

        key = getpass.getpass(f"{provider} API key (input hidden): ").strip()
    if not key:
        raise typer.BadParameter("Empty key.")
    path = store_key(provider, key, state.settings.home)
    console.print(f"[green]✓[/green] key stored for {provider} in {path} (mode 0600)")
    console.print("[dim]Prefer environment variables in CI. Keys are never written to logs or the audit trail.[/dim]")


@config_app.command("clear-key")
def config_clear_key(ctx: typer.Context, provider: str = typer.Argument(...)) -> None:
    """Remove a stored key."""
    state: State = get_state(ctx)
    if clear_key(provider, state.settings.home):
        console.print(f"[green]✓[/green] removed key for {provider}")
    else:
        console.print(f"[yellow]No stored key for {provider}.[/yellow]")


@config_app.command("path")
def config_path(ctx: typer.Context) -> None:
    """Print the paths ANJALI uses."""
    state: State = get_state(ctx)
    console.print(f"home     {state.settings.home}")
    console.print(f"config   {state.settings.config_file}")
    console.print(f"keys     {state.settings.keys_file}")
    console.print(f"database {state.settings.db_path}")
    console.print(f"audit    {state.settings.audit_path}")


@app.command()
def version() -> None:
    """Print version and build information."""
    console.print(f"ANJALI-AI [bold]{__version__}[/bold]")
    console.print("AI-Navigated Judgment & Audit for Legal Integrity")
    console.print(f"python {platform.python_version()} · sqlite {sqlite3.sqlite_version} · {platform.system()}")


# --------------------------------------------------------------------------- #
# Register sub-command groups (imported late to keep import time low)
# --------------------------------------------------------------------------- #
def _register() -> None:
    from anjali.cli.case_cmds import (
        analyze,
        ctr,
        data_app,
        investigate,
        render_risk,
        sanctions_app,
        screen,
    )
    from anjali.cli.compliance_cmds import audit_app, cases_app, conflicts_app, sar, simulate
    from anjali.cli.kb_cmds import ask, chat, kb_app

    app.add_typer(kb_app, name="kb")
    app.add_typer(data_app, name="data")
    app.add_typer(sanctions_app, name="sanctions")
    app.add_typer(conflicts_app, name="conflicts")
    app.add_typer(audit_app, name="audit")
    app.add_typer(cases_app, name="cases")
    app.command("ask")(ask)
    app.command("chat")(chat)
    app.command("analyze")(analyze)
    app.command("risk")(render_risk)
    app.command("screen")(screen)
    app.command("investigate")(investigate)
    app.command("sar")(sar)
    app.command("ctr")(ctr)
    app.command("simulate")(simulate)


_register()


def cli() -> None:  # pragma: no cover - console-script shim
    app()


if __name__ == "__main__":  # pragma: no cover
    app()
