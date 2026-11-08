"""Compliance output commands: SARs, conflicts, adversarial simulation, audit and cases."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from anjali.analysis.engine import analyze as run_analysis
from anjali.analysis.engine import build_context, list_cases, load_case
from anjali.analysis.ingest import fetch_accounts, fetch_customers, fetch_transactions
from anjali.cli.render import (
    BAND_STYLE,
    console,
    err_console,
    print_json_or,
    severity_badge,
)
from anjali.cli.state import State, errors, get_state, require_kb_documents
from anjali.compliance.conflicts import (
    all_conflicts,
    coverage_by_topic,
    matrix,
    memo,
    relevant_to_findings,
)
from anjali.compliance.conflicts import (
    find as find_conflicts,
)
from anjali.compliance.conflicts import (
    get as get_conflict,
)
from anjali.compliance.goaml import to_goaml
from anjali.compliance.sar import SARInput, build_report, quality_check, to_markdown
from anjali.core.errors import AnjaliError
from anjali.core.models import Finding, Jurisdiction, Severity
from anjali.core.util import today
from anjali.kb.resolve import resolve
from anjali.rag.store import open_kb

conflicts_app = typer.Typer(help="Cross-jurisdiction conflict analysis (US / EU / UK).", no_args_is_help=True)
audit_app = typer.Typer(help="Tamper-evident audit trail.", no_args_is_help=True)
cases_app = typer.Typer(help="Saved analysis cases.", no_args_is_help=True)


# --------------------------------------------------------------------------- #
# conflicts
# --------------------------------------------------------------------------- #
@conflicts_app.command("list")
def conflicts_list(
    ctx: typer.Context,
    topic: str | None = typer.Option(None, "--topic", "-t"),
    jurisdiction: list[str] = typer.Option([], "--jurisdiction", "-j"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """List the conflicts ANJALI knows about."""
    state: State = get_state(ctx)
    rows = find_conflicts(topic, jurisdictions=jurisdiction or None) if (topic or jurisdiction) else all_conflicts()
    payload: dict[str, object] = {
        "conflicts": [
            {
                "id": c.id,
                "title": c.title,
                "topic": c.topic,
                "severity": c.severity.value,
                "jurisdictions": c.jurisdictions,
                "summary": c.summary,
                "divergence": c.divergence,
                "resolution": c.resolution,
            }
            for c in rows
        ],
    }
    if not (topic or jurisdiction):
        payload["topics"] = coverage_by_topic()
    if print_json_or(state, payload, json_out):
        return
    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("ID")
    table.add_column("Topic")
    table.add_column("Jurisdictions")
    table.add_column("Severity")
    table.add_column("Conflict")
    for conflict in rows:
        table.add_row(
            conflict.id,
            conflict.topic,
            ", ".join(conflict.jurisdictions),
            severity_badge(conflict.severity),
            conflict.summary[:100] + "…",
        )
    console.print(table)
    console.print(f"\n[dim]{len(rows)} conflict(s). Inspect one with "
                  f"[cyan]anjali conflicts show <id>[/cyan][/dim]")


@conflicts_app.command("show")
def conflicts_show(
    ctx: typer.Context,
    conflict_id: str = typer.Argument(...),
    markdown_out: bool = typer.Option(False, "--markdown", help="Render the full memo as markdown."),
    out: Path | None = typer.Option(None, "--out", "-o", help="Write the memo to a file."),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Show one conflict, the authority on each side, and the resolution."""
    state: State = get_state(ctx)
    with errors():
        conflict = get_conflict(conflict_id)
        if conflict is None:
            err_console.print(f"[red]No conflict '{conflict_id}'.[/red] "
                              f"Try: {', '.join(c.id for c in all_conflicts()[:3])}…")
            raise typer.Exit(1)
        kb = open_kb(state.settings)
        text = memo(conflict, kb, as_of=state.as_of)
        if out:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text, encoding="utf-8")
            console.print(f"[green]✓[/green] memo written to {out}")
            return
        if print_json_or(state, {
            "id": conflict.id,
            "title": conflict.title,
            "severity": conflict.severity.value,
            "positions": [
                {"jurisdiction": p.jurisdiction, "rule": p.rule, "doc_ids": p.doc_ids,
                 "effect": p.practical_effect}
                for p in conflict.positions
            ],
            "divergence": conflict.divergence,
            "resolution": conflict.resolution,
            "memo": text,
        }, json_out):
            return
        if markdown_out:
            console.print(Markdown(text))
            return
        console.print(Panel(
            Text(conflict.summary),
            title=f"[bold]{conflict.title}[/bold] ({conflict.severity.value})",
            border_style="red" if conflict.severity is Severity.CRITICAL else "yellow",
        ))
        for position in conflict.positions:
            console.print(f"\n[bold]{position.jurisdiction}[/bold] — {position.rule}")
            console.print(f"  [dim]Effect: {position.practical_effect}[/dim]")
            for cit in resolve(kb, position.doc_ids, as_of=state.as_of):
                console.print(f"  [blue]• {cit.citation}[/blue] — {cit.title}")
        console.print(f"\n[bold]Divergence[/bold]\n  {conflict.divergence}")
        console.print("\n[bold]Resolution[/bold]")
        for i, step in enumerate(conflict.resolution, 1):
            console.print(f"  {i}. {step}")
        console.print(f"\n[dim]{conflict.confidence:.0%} confidence · decision support, not legal advice[/dim]")
        state.close()


@conflicts_app.command("matrix")
def conflicts_matrix(ctx: typer.Context, out: Path | None = typer.Option(None, "--out", "-o")) -> None:
    """Export the conflict matrix as markdown (useful for a control framework doc)."""
    rows = matrix()
    lines = ["# Cross-jurisdiction conflict matrix", ""]
    lines.append("| ID | Topic | Jurisdictions | Severity | Summary |")
    lines.append("|----|-------|---------------|----------|---------|")
    for row in rows:
        lines.append(
            f"| `{row['id']}` | {row['topic']} | {row['jurisdictions']} | {row['severity']} | "
            f"{row['summary'].replace('|', '/')} |"
        )
    text = "\n".join(lines) + "\n"
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        console.print(f"[green]✓[/green] matrix written to {out}")
        return
    console.print(Markdown(text))


@conflicts_app.command("relevant")
def conflicts_relevant(
    ctx: typer.Context,
    case_id: str | None = typer.Option(None, "--case"),
    dataset: str | None = typer.Option(None, "--dataset", "-d"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Show which conflicts a given case actually triggers."""
    state: State = get_state(ctx)
    with errors():
        payload = load_case(state.db, case_id) if case_id else None
        if payload:
            findings = [Finding.model_validate(f) for f in payload["findings"]]
        else:
            txns = fetch_transactions(state.db, dataset)
            if not txns:
                err_console.print("[red]No case data.[/red]")
                raise typer.Exit(1)
            kb = open_kb(state.settings)
            result = run_analysis(
                build_context(txns, fetch_customers(state.db, dataset), fetch_accounts(state.db, dataset)),
                kb=kb, as_of=state.as_of,
            )
            findings = result.findings
        hits = relevant_to_findings(findings, state.settings.default_jurisdictions)
        if print_json_or(state, {"conflicts": [{"id": c.id, "title": c.title,
                                                "severity": c.severity.value,
                                                "jurisdictions": c.jurisdictions,
                                                "resolution": c.resolution} for c in hits]}, json_out):
            return
        if not hits:
            console.print("[green]No cross-jurisdiction conflict is triggered by these findings.[/green]")
            return
        table = Table(show_header=True, header_style="bold", box=None)
        table.add_column("ID")
        table.add_column("Severity")
        table.add_column("Title")
        table.add_column("Why triggered")
        for conflict in hits:
            table.add_row(conflict.id, severity_badge(conflict.severity), conflict.title,
                          ", ".join(conflict.trigger_typologies))
        console.print(table)
        state.close()


# --------------------------------------------------------------------------- #
# SAR
# --------------------------------------------------------------------------- #
def sar(
    ctx: typer.Context,
    dataset: str | None = typer.Option(None, "--dataset", "-d"),
    case_id: str | None = typer.Option(None, "--case", help="Saved case to report on."),
    jurisdiction: str = typer.Option("US", "--jurisdiction", "-j", help="US, UK or EU."),
    filing_type: str = typer.Option("initial", "--filing-type", help="initial | continuing | corrected"),
    polish: bool = typer.Option(False, "--polish", help="Rewrite the narrative with the configured LLM (facts unchanged)."),
    out: Path | None = typer.Option(None, "--out", "-o"),
    format: str = typer.Option("markdown", "--format", help="markdown | json | goaml"),
    quality: bool = typer.Option(True, "--quality/--no-quality", help="Run the narrative checklist."),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Draft a SAR/STR with a FinCEN-structured narrative from the case evidence."""
    state: State = get_state(ctx)
    with errors():
        require_kb_documents(state)
        kb = open_kb(state.settings)
        txns = fetch_transactions(state.db, dataset)
        if case_id:
            payload = load_case(state.db, case_id)
            if payload is None:
                raise AnjaliError(f"Case '{case_id}' not found.", hint="List cases with `anjali cases list`.")
            evidence_ids = {
                txn_id
                for finding in payload["findings"]
                for txn_id in finding.get("evidence_txn_ids", [])
            }
            if evidence_ids:
                txns = [t for t in txns if t.txn_id in evidence_ids] or txns
        if not txns:
            raise AnjaliError("No transactions available to report on.",
                              hint="Load data first: anjali data load <file>")

        analysis_ctx = build_context(txns, fetch_customers(state.db, dataset), fetch_accounts(state.db, dataset))
        analysis = run_analysis(analysis_ctx, kb=kb, case_id=case_id, as_of=state.as_of)
        if not analysis.findings:
            console.print("[yellow]No findings — a SAR normally requires at least one suspicious-activity "
                          "rationale. Generating a draft anyway with the available data.[/yellow]")

        narrative_hook = None
        if polish:
            provider = state.provider()
            if provider.is_offline:
                console.print("[yellow]Offline mode: narrative polish skipped (deterministic draft kept).[/yellow]")
            else:
                from anjali.agent.prompts import SAR_POLISH_PROMPT
                from anjali.providers.base import Message

                def narrative_hook(sections, inp):  # type: ignore[misc]
                    facts = "\n".join(f"{k.upper()}: {v}" for k, v in sections.items() if v)
                    response = provider.complete(
                        [Message(role="user", content=f"FACTS\n{facts}\n\nRewrite as instructed.")],
                        system=SAR_POLISH_PROMPT,
                        temperature=0.1,
                    )
                    return response.text

        report = build_report(
            SARInput(
                case_id=case_id or f"{dataset or 'all'}-{today().isoformat()}",
                findings=analysis.findings,
                transactions=txns,
                customers=fetch_customers(state.db, dataset),
                accounts=fetch_accounts(state.db, dataset),
                risk=analysis.risk,
                jurisdiction=Jurisdiction(jurisdiction.upper()),
                filing_type=filing_type,
            ),
            citations=resolve(kb, [
                "us-31cfr-1020-320", "us-31cfr-1010-306", "us-fincen-sar-narrative",
                "us-sar-continuing", *[c.doc_id for c in analysis.risk.citations][:3],
            ], as_of=state.as_of),
            narrative_hook=narrative_hook,
        )
        checks = quality_check(report)
        audit = state.audit()
        if audit:
            audit.append(
                "sar.draft",
                subject=report.report_id,
                details={
                    "jurisdiction": report.jurisdiction.value,
                    "filing_type": report.filing_type,
                    "typologies": report.typologies,
                    "total_amount": str(report.total_amount),
                    "quality_score": checks["score"],
                    "polished_by_llm": bool(narrative_hook),
                    "case": report.report_id,
                },
            )

        format = format.lower()
        if format == "goaml":
            text = to_goaml(report, txns)
        elif format == "json":
            text = json.dumps({**report.model_dump(mode="json"), "quality": checks}, indent=2, default=str)
        else:
            text = to_markdown(report)

        if out:
            extension = {"markdown": "md", "json": "json", "goaml": "xml"}[format]
            destination = out if out.suffix else out.with_suffix("." + extension)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text, encoding="utf-8")
            console.print(f"[green]✓[/green] wrote {format} to {destination}")
            if quality:
                console.print(f"[bold]Narrative quality[/bold] {checks['score']}/100 (grade {checks['grade']})")
                if checks["recommendations"]:
                    console.print(f"[yellow]Improve:[/yellow] {', '.join(checks['recommendations'])}")
            return
        if print_json_or(state, {**report.model_dump(mode="json"), "quality": checks}, json_out):
            return
        if format == "markdown":
            console.print(Markdown(text))
        else:
            # Machine payloads (JSON, goAML XML) are written raw. Rich would hard-wrap
            # them at the console width and inject newlines inside string values,
            # producing output that no parser can read.
            sys.stdout.write(text.rstrip() + "\n")
            if quality:
                # Keep stdout parseable: the checklist is a reviewer aid, not part of
                # the filed artefact, so it goes to stderr.
                err_console.print(
                    f"[dim]Narrative checklist {checks['score']}/100 "
                    f"(grade {checks['grade']}, {checks['passed']}/{checks['total']})[/dim]"
                )
            state.close()
            return
        if quality:
            style = "green" if checks["score"] >= 80 else "yellow" if checks["score"] >= 60 else "red"
            console.print()
            console.print(f"[{style}]Narrative checklist: {checks['score']}/100 "
                          f"(grade {checks['grade']}, {checks['passed']}/{checks['total']})[/{style}]")
            for check in checks["checks"]:
                mark = "[green]✓[/green]" if check["pass"] else "[red]✗[/red]"
                console.print(f"  {mark} {check['check']} [dim]({check['detail']})[/dim]")
        state.close()


# --------------------------------------------------------------------------- #
# simulate
# --------------------------------------------------------------------------- #
def simulate(
    ctx: typer.Context,
    seed: int = typer.Option(7, "--seed", help="RNG seed — identical seed, identical case."),
    scenario: list[str] = typer.Option([], "--scenario", "-s", help="Run only these scenarios (repeatable)."),
    out: Path | None = typer.Option(None, "--out", "-o", help="Write the report here (.md or .json)."),
    fail_under: float | None = typer.Option(None, "--fail-under", help="Exit 1 if recall is below this (0-1)."),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Red-team the monitoring configuration with injected typologies."""
    state: State = get_state(ctx)
    with errors():
        from anjali.sim.adversary import SCENARIOS, run, to_markdown

        unknown = [s for s in scenario if s not in SCENARIOS]
        if unknown:
            raise typer.BadParameter(f"Unknown scenario(s): {', '.join(unknown)}. "
                                     f"Options: {', '.join(SCENARIOS)}")
        kb = open_kb(state.settings) if int(state.db.scalar("SELECT COUNT(*) FROM documents") or 0) else None
        result = run(seed=seed, scenarios=scenario or None, kb=kb)
        audit = state.audit()
        if audit:
            audit.append("simulation.run", subject=f"seed:{seed}", details={
                "recall": result.overall["recall"],
                "precision": result.overall["precision_estimate"],
                "scenarios": result.overall["scenarios"],
                "missed": [m["scenario"] for m in result.overall["missed"]],
            })
        text = to_markdown(result)
        if out:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(
                json.dumps(result.to_dict(), indent=2, default=str) if out.suffix == ".json" else text,
                encoding="utf-8",
            )
            console.print(f"[green]✓[/green] report written to {out}")
        if print_json_or(state, result.to_dict(), json_out):
            _sim_fail(result, fail_under)
            return
        console.print()
        overall = result.overall
        console.print(Panel(
            Text.assemble(
                ("Recall  ", "bold"), f"{overall['recall']:.0%}",
                f"   ({overall['detected']}/{overall['injected']} injected scenarios)\n",
                ("Precision estimate  ", "bold"), f"{overall['precision_estimate']:.0%}",
                f"   ({overall['false_positives']} false positives on benign traffic)\n",
                ("Verdict  ", "bold"), overall["verdict"],
            ),
            title=f"[bold]Adversarial control test[/bold] · seed {seed}",
            border_style="cyan",
        ))
        table = Table(show_header=True, header_style="bold", box=None)
        table.add_column("Typology")
        table.add_column("Recall", justify="left")
        table.add_column("Injected", justify="right")
        table.add_column("Detected", justify="right")
        for typology, bucket in sorted(result.per_typology.items(), key=lambda kv: kv[1]["recall"]):
            bar = "█" * int(bucket["recall"] * 10) + "░" * (10 - int(bucket["recall"] * 10))
            style = "green" if bucket["recall"] >= 0.9 else "yellow" if bucket["recall"] >= 0.5 else "red"
            table.add_row(typology, Text(bar, style=style), str(bucket["injected"]), str(bucket["detected"]))
        console.print(table)
        missed = overall["missed"]
        if missed:
            console.print("\n[bold red]Control gaps[/bold red]")
            for row in missed:
                console.print(f"  [red]✗[/red] {row['scenario']} ({row['typology']}, {row['difficulty']})")
                console.print(f"    {row['description']}")
        else:
            console.print("\n[green]No gaps against the injected scenarios.[/green]")
        console.print(f"\n[dim]Reproduce any case with: anjali simulate --seed {seed} "
                      f"--scenario <name>[/dim]")
        _sim_fail(result, fail_under)
        state.close()


def _sim_fail(result, fail_under: float | None) -> None:
    if fail_under is None:
        return
    recall = result.overall["recall"]
    if recall < fail_under:
        err_console.print(f"[red]Recall {recall:.0%} is below the {fail_under:.0%} gate.[/red]")
        raise typer.Exit(1)


# --------------------------------------------------------------------------- #
# audit
# --------------------------------------------------------------------------- #
@audit_app.command("stats")
def audit_stats(ctx: typer.Context, json_out: bool = typer.Option(False, "--json")) -> None:
    """Audit trail size, action breakdown and chain status."""
    state: State = get_state(ctx)
    audit = state.audit()
    if audit is None:
        console.print("[yellow]Audit disabled for this run.[/yellow]")
        return
    payload = audit.stats()
    if print_json_or(state, payload, json_out):
        return
    console.print(f"[bold]Audit trail[/bold] {payload['path']}")
    console.print(f"records {payload['records']} · chain "
                  f"{'[green]VALID[/green]' if payload['valid'] else '[red]BROKEN[/red]'} · "
                  f"head [dim]{payload['head_hash'][:16]}[/dim]")
    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("Action")
    table.add_column("Count", justify="right")
    for action, count in payload["actions"].items():
        table.add_row(action, str(count))
    console.print(table)


@audit_app.command("verify")
def audit_verify(ctx: typer.Context, json_out: bool = typer.Option(False, "--json")) -> None:
    """Verify the hash chain end-to-end."""
    state: State = get_state(ctx)
    audit = state.audit()
    if audit is None:
        raise typer.Exit(0)
    result = audit.verify()
    if print_json_or(state, result.to_dict(), json_out):
        if not result.valid:
            raise typer.Exit(1)
        return
    if result.valid:
        console.print(f"[green]✓[/green] chain intact — {result.records} records, "
                      f"head {result.head_hash[:16]}")
    else:
        console.print(f"[red]✗[/red] chain broken at record {result.first_break}")
        for issue in result.issues or []:
            console.print(f"  {issue}")
        raise typer.Exit(1)


@audit_app.command("log")
def audit_log(
    ctx: typer.Context,
    limit: int = typer.Option(20, "--limit", "-n"),
    action: str | None = typer.Option(None, "--action"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Show recent audit records."""
    state: State = get_state(ctx)
    audit = state.audit()
    if audit is None:
        return
    records = audit.records(limit=limit, action=action)
    if print_json_or(state, {"records": records}, json_out):
        return
    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("Seq", justify="right")
    table.add_column("Timestamp")
    table.add_column("Actor")
    table.add_column("Action")
    table.add_column("Subject")
    for record in records:
        table.add_row(str(record.get("seq")), str(record.get("timestamp"))[:19],
                      record.get("actor", ""), record.get("action", ""),
                      (record.get("subject") or "—")[:44])
    console.print(table)


@audit_app.command("export")
def audit_export(
    ctx: typer.Context,
    out: Path = typer.Option(Path("anjali_audit.md"), "--out", "-o"),
    format: str = typer.Option("markdown", "--format", help="markdown | json"),
) -> None:
    """Export the audit trail for a regulator or an internal review."""
    state: State = get_state(ctx)
    audit = state.audit()
    if audit is None:
        raise typer.Exit(0)
    if format == "json":
        path = audit.export_json(out.with_suffix(".json"))
    else:
        path = audit.export_markdown(out)
    console.print(f"[green]✓[/green] exported to {path}")
    verification = audit.verify()
    console.print(f"[dim]chain {'valid' if verification.valid else 'BROKEN'} · "
                  f"{verification.records} records[/dim]")


@audit_app.command("retention")
def audit_retention(
    ctx: typer.Context,
    years: int = typer.Option(5, "--years"),
) -> None:
    """Show records past the statutory retention period."""
    state: State = get_state(ctx)
    from anjali.audit.trail import retention_report

    audit = state.audit()
    if audit is None:
        return
    payload = retention_report(state.db, audit.records(), years=years)
    console.print(json.dumps(payload, indent=2))


# --------------------------------------------------------------------------- #
# cases
# --------------------------------------------------------------------------- #
@cases_app.command("list")
def cases_list(ctx: typer.Context, json_out: bool = typer.Option(False, "--json")) -> None:
    """List saved case analyses."""
    state: State = get_state(ctx)
    rows = list_cases(state.db)
    if print_json_or(state, {"cases": rows}, json_out):
        return
    if not rows:
        console.print("[yellow]No saved cases.[/yellow] Run [cyan]anjali analyze[/cyan] first.")
        return
    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("Case")
    table.add_column("Status")
    table.add_column("Created")
    table.add_column("Updated")
    for row in rows:
        table.add_row(row["case_id"], row["status"], str(row["created_at"])[:19], str(row["updated_at"])[:19])
    console.print(table)


@cases_app.command("show")
def cases_show(
    ctx: typer.Context,
    case_id: str = typer.Argument(...),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Show a saved case: findings, risk and provenance."""
    state: State = get_state(ctx)
    payload = load_case(state.db, case_id)
    if payload is None:
        err_console.print(f"[red]Case '{case_id}' not found.[/red]")
        raise typer.Exit(1)
    if print_json_or(state, payload, json_out):
        return
    summary = payload.get("summary", {})
    console.print(f"[bold]Case {case_id}[/bold] · generated {payload.get('generated_at')}")
    console.print(f"[dim]corpus digest {payload.get('corpus_digest')}[/dim]")
    console.print(f"\ntransactions {summary.get('transactions')} · accounts {summary.get('accounts')} · "
                  f"total {summary.get('total_value')} · findings {summary.get('findings_total')}")
    risk = payload.get("risk", {})
    band = risk.get("band", "—")
    console.print(f"risk {risk.get('overall')} "
                  f"[{BAND_STYLE.get(band, 'white')}]{band}[/{BAND_STYLE.get(band, 'white')}]")
    findings = [Finding.model_validate(f) for f in payload.get("findings", [])]
    if findings:
        from anjali.cli.render import findings_table

        console.print()
        console.print(findings_table(findings))


__all__ = [
    "audit_app",
    "cases_app",
    "conflicts_app",
    "sar",
    "simulate",
]
