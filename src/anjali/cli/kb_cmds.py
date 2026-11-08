"""Knowledge-base commands, the agent (`ask`) and the interactive shell (`chat`)."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import typer
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from anjali.cli.render import (
    citations_panel,
    console,
    err_console,
    print_banner,
    print_json_or,
    risk_bar,
)
from anjali.cli.state import State, build_agent_context, errors, get_state, require_kb_documents
from anjali.core.models import AgentResult
from anjali.kb.loader import corpus_manifest, document_from_text_file, load_documents
from anjali.kb.resolve import verify_citation
from anjali.rag.store import open_kb

kb_app = typer.Typer(help="Regulatory corpus: ingest, search, inspect, verify.", no_args_is_help=True)


# --------------------------------------------------------------------------- #
# kb ingest / add / stats / list
# --------------------------------------------------------------------------- #
@kb_app.command("ingest")
def kb_ingest(
    ctx: typer.Context,
    path: Path | None = typer.Option(None, "--path", help="Extra corpus directory or YAML file."),
    force: bool = typer.Option(False, "--force", help="Re-ingest even if documents exist."),
) -> None:
    """Load the bundled corpus (plus ANJALI_HOME/corpus) into the local index."""
    state: State = get_state(ctx)
    with errors():
        kb = open_kb(state.settings)
        existing = int(state.db.scalar("SELECT COUNT(*) FROM documents") or 0)
        if existing and not force:
            console.print(f"[yellow]{existing} documents already indexed.[/yellow] "
                          "Use --force to rebuild.")
            return
        docs = load_documents(
            home_corpus=state.settings.home / "corpus",
            extra_paths=[path] if path else None,
        )
        counts = kb.ingest(docs, show_progress=True)
        if print_json_or(state, {**counts, "index_digest": kb.index_digest()}):
            return
        console.print(
            f"[green]✓[/green] {counts['documents']} documents → {counts['chunks']} chunks "
            f"(index {kb.index_digest()})"
        )
        audit = state.audit()
        if audit:
            audit.append("kb.ingest", details={**counts, "digest": kb.index_digest()})
        state.close()


@kb_app.command("add")
def kb_add(
    ctx: typer.Context,
    path: Path = typer.Argument(..., help="Markdown, text, or YAML file to add."),
    jurisdiction: str = typer.Option("INTL", "--jurisdiction", help="US, EU, UK, FATF or INTL."),
    citation: str | None = typer.Option(None, "--citation", help="Citation label for plain text."),
    title: str | None = typer.Option(None, "--title", help="Document title."),
) -> None:
    """Add an internal policy or guidance document to the searchable corpus."""
    state: State = get_state(ctx)
    with errors():
        kb = open_kb(state.settings)
        if path.suffix.lower() in {".yaml", ".yml"}:
            docs = load_documents(extra_paths=[path])
        else:
            docs = [document_from_text_file(path, jurisdiction=jurisdiction, citation=citation, title=title)]
        counts = kb.ingest(docs)
        console.print(f"[green]✓[/green] added {counts['documents']} document(s), {counts['chunks']} chunks")
        for doc in docs:
            console.print(f"  · {doc.citation} — {doc.title}")
        state.close()


@kb_app.command("stats")
def kb_stats(ctx: typer.Context) -> None:
    """Corpus size, coverage and index state."""
    state: State = get_state(ctx)
    with errors():
        kb = open_kb(state.settings)
        stats = kb.stats()
        if print_json_or(state, stats):
            return
        console.print(f"[bold]Corpus[/bold] {stats['documents']} documents · "
                      f"{stats['chunks']} chunks · embedder {stats['embedder']}")
        console.print(f"[bold]Index[/bold] digest {stats['index_digest']} · last built {stats['indexed_at']}")
        table = Table(show_header=True, header_style="bold", box=None, title="Coverage by jurisdiction")
        table.add_column("Jurisdiction")
        table.add_column("Documents", justify="right")
        for juris, count in sorted(stats["by_jurisdiction"].items()):
            table.add_row(juris, str(count))
        console.print(table)
        status_table = Table(show_header=True, header_style="bold", box=None, title="Document status")
        status_table.add_column("Status")
        status_table.add_column("Documents", justify="right")
        for status, count in sorted(stats["by_status"].items()):
            status_table.add_row(status, str(count))
        console.print(status_table)
        state.close()


@kb_app.command("list")
def kb_list(
    ctx: typer.Context,
    jurisdiction: str | None = typer.Option(None, "--jurisdiction", "-j"),
    status: str | None = typer.Option(None, "--status"),
    limit: int = typer.Option(200, "--limit"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """List indexed documents."""
    state: State = get_state(ctx)
    with errors():
        kb = open_kb(state.settings)
        rows = kb.list_documents(jurisdiction=jurisdiction, status=status, limit=limit)
        if print_json_or(state, {"documents": rows}, json_out):
            return
        table = Table(show_header=True, header_style="bold", box=None)
        table.add_column("Citation")
        table.add_column("Title")
        table.add_column("Juris")
        table.add_column("Status")
        table.add_column("Effective")
        for row in rows:
            table.add_row(
                row["citation"],
                row["title"][:60],
                row["jurisdiction"],
                row["status"],
                f"{row['effective_from']}"
                + (f" → {row['effective_to']}" if row["effective_to"] else ""),
            )
        console.print(table)
        console.print(f"[dim]{len(rows)} document(s)[/dim]")
        state.close()


# --------------------------------------------------------------------------- #
# kb search / show / verify / timeline
# --------------------------------------------------------------------------- #
@kb_app.command("search")
def kb_search(
    ctx: typer.Context,
    query: str = typer.Argument(..., help="Search query."),
    jurisdiction: list[str] = typer.Option([], "--jurisdiction", "-j", help="Repeatable jurisdiction filter."),
    top_k: int = typer.Option(8, "--top-k", "-k"),
    include_superseded: bool = typer.Option(False, "--include-superseded", help="Include provisions no longer in force."),
    show_text: bool = typer.Option(False, "--text", help="Print the full chunk text."),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Hybrid (BM25 + dense) search over the corpus, temporally filtered."""
    state: State = get_state(ctx)
    with errors():
        require_kb_documents(state)
        kb = open_kb(state.settings)
        hits = kb.search(
            query,
            top_k=top_k,
            jurisdictions=jurisdiction or None,
            as_of=state.as_of,
            include_superseded=include_superseded,
        )
        payload = [
            {
                "citation": h.chunk.citation,
                "title": h.chunk.title,
                "jurisdiction": h.chunk.jurisdiction.value,
                "doc_id": h.chunk.doc_id,
                "section": h.chunk.section,
                "score": round(h.score, 4),
                "lexical_rank": h.lexical_rank,
                "vector_score": round(h.vector_score, 4),
                "stale": h.stale,
                "not_yet_in_force": h.future,
                "text": h.chunk.text,
            }
            for h in hits
        ]
        if print_json_or(state, {"query": query, "results": payload}, json_out):
            return
        if not hits:
            console.print("[yellow]No provisions matched.[/yellow] Try fewer, more specific words.")
            return
        for hit in hits:
            flags = Text()
            if hit.stale:
                flags.append(" [superseded]", style="dim")
            if hit.future:
                flags.append(" [not yet in force]", style="yellow")
            console.print(
                f"\n[bold]{hit.chunk.citation}[/bold] "
                f"[{hit.chunk.jurisdiction.value}] [dim]{hit.score:.3f}[/dim]{flags}"
            )
            console.print(f"[italic]{hit.chunk.title}[/italic]")
            if show_text:
                console.print(hit.chunk.text)
            else:
                console.print(Text(hit.chunk.text.replace("\n", " ")[:420] + "…", style="dim"))
        console.print(
            f"\n[dim]{len(hits)} result(s) · as-of {(state.as_of or date.today()).isoformat()} · "
            f"index {kb.index_digest()}[/dim]"
        )
        state.close()


@kb_app.command("show")
def kb_show(
    ctx: typer.Context,
    citation: str = typer.Argument(..., help="Citation or doc_id."),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Show a provision in full."""
    state: State = get_state(ctx)
    with errors():
        kb = open_kb(state.settings)
        doc = kb.get_document(citation)
        if doc is None:
            matches = kb.find_by_citation(citation)
            doc = matches[0] if matches else None
        if doc is None:
            err_console.print(f"[red]No provision matches '{citation}'.[/red]")
            raise typer.Exit(1)
        if print_json_or(state, dict(doc), json_out):
            return
        console.print()
        console.print(Panel(
            Text(doc["text"], style=""),
            title=f"[bold]{doc['citation']}[/bold] — {doc['title']}",
            subtitle=(
                f"{doc['jurisdiction']} · {doc['regulator']} · {doc['status']} · "
                f"effective {doc['effective_from']}"
                + (f" → {doc['effective_to']}" if doc["effective_to"] else "")
            ),
            border_style="blue",
        ))
        if doc.get("source_url"):
            console.print(f"[dim]source: {doc['source_url']}[/dim]")
        state.close()


@kb_app.command("verify")
def kb_verify(
    ctx: typer.Context,
    citation: str = typer.Argument(..., help="Citation to check."),
    as_of: str | None = typer.Option(None, "--on", help="Check against this date (YYYY-MM-DD)."),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Verify a citation exists and whether it is in force on a given date."""
    state: State = get_state(ctx)
    with errors():
        kb = open_kb(state.settings)
        as_of_date = date.fromisoformat(as_of) if as_of else (state.as_of or date.today())
        verdict = verify_citation(kb, citation, as_of=as_of_date)
        if print_json_or(state, verdict, json_out):
            # Exit non-zero even in JSON mode so the check composes into CI.
            raise typer.Exit(0 if verdict["found"] else 1)
        if not verdict["found"]:
            console.print(f"[red]✗[/red] '{citation}' is not in the corpus.")
            raise typer.Exit(1)
        for doc in verdict["documents"]:  # type: ignore[union-attr]
            mark = "[green]✓ in force[/green]" if doc["in_force_at_as_of"] else "[yellow]✗ not in force[/yellow]"
            console.print(f"{mark} [bold]{doc['citation']}[/bold] — {doc['title']}")
            console.print(
                f"    {doc['jurisdiction']} · status {doc['status']} · "
                f"effective {doc['effective_from']}"
                + (f" → {doc['effective_to']}" if doc["effective_to"] else " → present")
                + f" · checked on {as_of_date.isoformat()}"
            )
            if doc["source_url"]:
                console.print(f"    [dim]{doc['source_url']}[/dim]")
        state.close()


@kb_app.command("timeline")
def kb_timeline(ctx: typer.Context) -> None:
    """Corpus coverage by year and upcoming regulatory changes."""
    state: State = get_state(ctx)
    with errors():
        kb = open_kb(state.settings)
        histogram = kb.as_of_dates()
        upcoming = state.db.query(
            "SELECT citation, title, jurisdiction, effective_from FROM documents "
            "WHERE effective_from > ? ORDER BY effective_from LIMIT 12",
            (date.today().isoformat(),),
        )
        recently_lapsed = state.db.query(
            "SELECT citation, title, jurisdiction, effective_to FROM documents "
            "WHERE effective_to IS NOT NULL AND effective_to >= ? ORDER BY effective_to LIMIT 12",
            (date.today().isoformat(),),
        )
        if print_json_or(state, {
            "by_year": histogram,
            "upcoming": [dict(r) for r in upcoming],
            "lapsing": [dict(r) for r in recently_lapsed],
        }):
            return
        console.print("[bold]Documents by year of effect[/bold]")
        for year, count in histogram.items():
            bar = "█" * min(count, 40)
            console.print(f"  {year}  {bar} [dim]{count}[/dim]")
        if upcoming:
            console.print("\n[bold]Upcoming changes (not yet in force)[/bold]")
            for row in upcoming:
                console.print(f"  {row['effective_from']}  [{row['jurisdiction']}] {row['citation']} — {row['title'][:70]}")
        state.close()


@kb_app.command("corpus")
def kb_corpus(ctx: typer.Context) -> None:
    """Show the bundled corpus manifest (files and counts)."""
    state: State = get_state(ctx)
    manifest = corpus_manifest()
    if print_json_or(state, {"files": manifest, "total": sum(m["documents"] for m in manifest)}):
        return
    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("File")
    table.add_column("Docs", justify="right")
    table.add_column("Jurisdictions")
    for row in manifest:
        table.add_row(row["file"], str(row["documents"]), ", ".join(row["jurisdictions"]))
    console.print(table)
    console.print(f"[dim]{sum(m['documents'] for m in manifest)} bundled documents[/dim]")


@kb_app.command("export")
def kb_export(
    ctx: typer.Context,
    out: Path = typer.Option(Path("anjali_corpus.json"), "--out", "-o"),
) -> None:
    """Export the corpus with full metadata for archival or review."""
    state: State = get_state(ctx)
    with errors():
        kb = open_kb(state.settings)
        rows = state.db.query("SELECT * FROM documents ORDER BY jurisdiction, citation")
        import json

        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps([dict(r) for r in rows], indent=2, default=str) + "\n", encoding="utf-8")
        console.print(f"[green]✓[/green] exported {len(rows)} documents to {out}")
        console.print(f"[dim]index digest {kb.index_digest()}[/dim]")
        state.close()


# --------------------------------------------------------------------------- #
# ask
# --------------------------------------------------------------------------- #
def ask(
    ctx: typer.Context,
    question: str = typer.Argument(..., help="Your compliance question."),
    jurisdiction: list[str] = typer.Option([], "--jurisdiction", "-j"),
    trace: bool = typer.Option(False, "--trace", help="Show the agent's reasoning and tool calls."),
    max_steps: int | None = typer.Option(None, "--max-steps"),
    offline: bool = typer.Option(False, "--offline", help="Force deterministic offline synthesis."),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Ask a compliance question. Cited, reasoned, and audited."""
    state: State = get_state(ctx)
    with errors():
        require_kb_documents(state)
        agent_ctx = build_agent_context(state, jurisdictions=jurisdiction or None)

        def on_step(kind: str, text: str) -> None:
            if kind == "tool":
                console.print(f"  [dim]→ {text}[/dim]")
            elif kind == "thought":
                console.print(Panel(Text(text, style="dim"), border_style="dim", title="reasoning"))

        provider = None
        if not offline:
            try:
                provider = state.provider()
            except Exception:
                provider = None

        from anjali.agent.loop import run

        result = run(
            question,
            agent_ctx,
            provider=provider,
            max_steps=max_steps or state.settings.max_agent_steps,
            audit=state.audit(),
            verbose=on_step if trace else None,
        )
        if print_json_or(state, result.model_dump(mode="json"), json_out):
            return
        _render_answer(result, show_trace=trace, corpus_digest=agent_ctx.kb.index_digest())
        state.close()


def _render_answer(result: AgentResult, *, show_trace: bool, corpus_digest: str = "") -> None:
    console.print()
    console.print(Panel(
        Text(result.answer),
        title="[bold]ANJALI[/bold]",
        subtitle=(
            f"{result.provider} · {result.model}"
            + (" · [yellow]offline deterministic synthesis[/yellow]" if result.offline else "")
            + (f" · confidence {result.confidence:.0%}" if result.confidence else "")
        ),
        border_style="cyan",
    ))
    if result.citations:
        citations_panel(result.citations, title="Authorities cited")
    if show_trace and result.steps:
        console.print("\n[bold]Trace[/bold]")
        for step in result.steps:
            if step.kind == "tool_call":
                console.print(f"  {step.step:02d} [cyan]{step.tool}[/cyan] "
                              f"[dim]{step.observation or ''}[/dim] ({step.duration_ms}ms)")
            elif step.kind == "guardrail":
                console.print(f"  {step.step:02d} [yellow]guardrail[/yellow] {step.content}")
    if result.audit_ref:
        console.print(f"\n[dim]audit {result.audit_ref[:16]} · corpus {corpus_digest}[/dim]")
    console.print("[dim]ANJALI drafts and advises. A named human must approve any filing, block or exit.[/dim]")


# --------------------------------------------------------------------------- #
# chat
# --------------------------------------------------------------------------- #
def chat(
    ctx: typer.Context,
    jurisdiction: list[str] = typer.Option([], "--jurisdiction", "-j"),
) -> None:
    """Interactive analyst shell. Ctrl-D or /exit to leave."""
    state: State = get_state(ctx)
    with errors():
        require_kb_documents(state)
        print_banner()
        agent_ctx = build_agent_context(state, jurisdictions=jurisdiction or None)
        provider = None
        try:
            provider = state.provider()
        except Exception:
            provider = None
        mode = "offline (deterministic)" if provider is None or provider.is_offline else f"{provider.name}/{provider.model}"
        console.print(f"[dim]mode: {mode} · jurisdictions: {', '.join(agent_ctx.jurisdictions)} · "
                      f"as-of {(state.as_of or date.today()).isoformat()}[/dim]")
        console.print("[dim]/help for commands, /exit to quit[/dim]\n")

        from anjali.agent.loop import run

        while True:
            try:
                line = console.input("[bold cyan]anjali ›[/bold cyan] ").strip()
            except (EOFError, KeyboardInterrupt):
                console.print("\n[dim]bye[/dim]")
                break
            if not line:
                continue
            if line.startswith("/"):
                command = line[1:].strip().lower()
                if command in {"exit", "quit", "q"}:
                    break
                if command == "help":
                    console.print(
                        "  /case <path>   load a CSV/JSON case\n"
                        "  /analyze       run detectors on the loaded case\n"
                        "  /kb <query>    quick corpus search\n"
                        "  /provider      show provider status\n"
                        "  /exit          quit\n"
                    )
                    continue
                if command.startswith("kb "):
                    hits = agent_ctx.kb.search(command[3:], top_k=5, as_of=state.as_of)
                    for hit in hits:
                        console.print(f"  [bold]{hit.chunk.citation}[/bold] [dim]{hit.score:.3f}[/dim]")
                        console.print(f"    {hit.chunk.text[:200]}…")
                    continue
                if command == "provider":
                    console.print(f"  {mode}")
                    continue
                if command == "analyze":
                    result = agent_ctx.ensure_analysis()
                    if result is None:
                        console.print("  [yellow]No case data loaded. Use /case <path>.[/yellow]")
                    else:
                        console.print(f"  risk {risk_bar(result.risk.overall)} · "
                                      f"{len(result.findings)} findings")
                        for finding in result.findings[:6]:
                            console.print(f"   {finding.severity.value:8s} {finding.typology}: "
                                          f"{finding.summary[:110]}")
                    continue
                if command.startswith("case "):
                    path = Path(command[5:].strip())
                    from anjali.analysis.ingest import load_transactions, persist

                    if not path.exists():
                        console.print(f"  [red]No such file: {path}[/red]")
                        continue
                    txns, report = load_transactions(path)
                    persist(agent_ctx.db, txns, dataset="chat")
                    agent_ctx.analysis = None
                    agent_ctx.analysis_ctx = None
                    agent_ctx.graph = None
                    console.print(f"  [green]loaded {report.rows_loaded} transactions[/green] "
                                  f"({report.rows_rejected} rejected)")
                    continue
                console.print(f"  [yellow]unknown command '/{command}'[/yellow]")
                continue
            result = run(line, agent_ctx, provider=provider, audit=state.audit())
            _render_answer(result, show_trace=False, corpus_digest=agent_ctx.kb.index_digest())
            console.print()
        state.close()


__all__ = ["ask", "chat", "kb_app", "kb_ingest", "kb_search", "kb_show", "kb_verify"]
