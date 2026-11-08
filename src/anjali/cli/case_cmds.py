"""Case data, analysis, screening and graph investigation commands."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.table import Table

from anjali.analysis.engine import analyze as run_analysis
from anjali.analysis.engine import build_context, detector_catalogue
from anjali.analysis.ingest import (
    datasets as list_datasets,
)
from anjali.analysis.ingest import (
    fetch_accounts,
    fetch_customers,
    fetch_transactions,
    load_customers,
    load_transactions,
    persist,
    sample_csv_template,
)
from anjali.analysis.patterns import DETECTORS
from anjali.analysis.sanctions import SanctionsScreener, import_csv, seed_database
from anjali.cli.render import (
    citations_panel,
    console,
    err_console,
    findings_table,
    print_finding_detail,
    print_json_or,
    risk_panel,
    screening_panel,
)
from anjali.cli.state import State, errors, get_state, require_kb_documents
from anjali.core.models import Severity
from anjali.core.util import today
from anjali.graph.entity_graph import EntityGraph, link_analysis
from anjali.rag.store import open_kb

data_app = typer.Typer(help="Case data: load, inspect, clear.", no_args_is_help=True)
sanctions_app = typer.Typer(help="Sanctions lists and screening.", no_args_is_help=True)


# --------------------------------------------------------------------------- #
# data
# --------------------------------------------------------------------------- #
@data_app.command("load")
def data_load(
    ctx: typer.Context,
    path: Path | None = typer.Argument(None, help="Transactions CSV/JSON/JSONL."),
    customers: Path | None = typer.Option(None, "--customers", help="Customer master CSV/JSON."),
    dataset: str = typer.Option("default", "--dataset", "-d"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Load transactions (and optionally customers) into the local case database."""
    state: State = get_state(ctx)
    with errors():
        if path is None and customers is None:
            raise typer.BadParameter("Provide a transactions file, --customers, or both.")
        result: dict[str, object] = {"dataset": dataset}
        reports = {}
        txns, custs = [], []
        if path:
            txns, report = load_transactions(path)
            reports["transactions"] = report.to_dict()
        if customers:
            custs, creport = load_customers(customers)
            reports["customers"] = creport.to_dict()
        counts = persist(state.db, txns, custs, dataset=dataset)
        result.update({"loaded": counts, "reports": reports})
        audit = state.audit()
        if audit:
            audit.append("data.load", subject=dataset, details={"loaded": counts})
        if print_json_or(state, result, json_out):
            return
        console.print(f"[green]✓[/green] dataset [bold]{dataset}[/bold]: "
                      f"{counts['transactions']} transactions, {counts['customers']} customers")
        for kind, report in reports.items():
            if report["rows_rejected"]:  # type: ignore[index]
                console.print(f"  [yellow]{kind}: {report['rows_rejected']} row(s) rejected[/yellow]")
                for error in report["errors"][:5]:  # type: ignore[index]
                    console.print(f"    [dim]{error}[/dim]")
            if report["unmapped_columns"]:  # type: ignore[index]
                console.print(f"  [dim]{kind}: ignored columns {', '.join(report['unmapped_columns'][:8])}[/dim]")  # type: ignore[index]
        console.print("\n[dim]Next: anjali analyze --dataset " + dataset + "[/dim]")
        state.close()


@data_app.command("list")
def data_list(ctx: typer.Context, json_out: bool = typer.Option(False, "--json")) -> None:
    """List loaded datasets."""
    state: State = get_state(ctx)
    rows = list_datasets(state.db)
    if print_json_or(state, {"datasets": rows}, json_out):
        return
    if not rows:
        console.print("[yellow]No data loaded.[/yellow] Create a template with "
                      "[cyan]anjali data sample --out case.csv[/cyan]")
        return
    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("Dataset")
    table.add_column("Transactions", justify="right")
    table.add_column("From")
    table.add_column("To")
    for row in rows:
        table.add_row(row["dataset"], str(row["n"]), str(row["first_ts"])[:19], str(row["last_ts"])[:19])
    console.print(table)


@data_app.command("sample")
def data_sample(
    ctx: typer.Context,
    out: Path = typer.Option(Path("transactions_template.csv"), "--out", "-o"),
) -> None:
    """Write a CSV template showing the expected columns."""
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(sample_csv_template(), encoding="utf-8")
    console.print(f"[green]✓[/green] template written to {out}")
    console.print("[dim]Required: an amount and a timestamp. Everything else is optional and "
                  "matched by alias.[/dim]")


@data_app.command("clear")
def data_clear(
    ctx: typer.Context,
    dataset: str | None = typer.Option(None, "--dataset", "-d"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Delete case data (all datasets, or one)."""
    state: State = get_state(ctx)
    if not yes and not typer.confirm(f"Delete data for {dataset or 'ALL datasets'}?", default=False):
        raise typer.Exit(0)
    with state.db.tx() as conn:
        if dataset:
            conn.execute("DELETE FROM transactions WHERE dataset=?", (dataset,))
            conn.execute("DELETE FROM customers WHERE dataset=?", (dataset,))
            conn.execute("DELETE FROM accounts WHERE dataset=?", (dataset,))
        else:
            conn.execute("DELETE FROM transactions")
            conn.execute("DELETE FROM customers")
            conn.execute("DELETE FROM accounts")
            conn.execute("DELETE FROM findings")
    console.print("[green]✓[/green] case data cleared")


# --------------------------------------------------------------------------- #
# analyze
# --------------------------------------------------------------------------- #
def analyze(
    ctx: typer.Context,
    dataset: str | None = typer.Option(None, "--dataset", "-d", help="Dataset to analyse (default: all)."),
    detector: list[str] = typer.Option([], "--detector", help="Run only these detectors (repeatable)."),
    jurisdiction: str | None = typer.Option(None, "--jurisdiction", help="Weight the risk score for US/EU/UK."),
    detail: bool = typer.Option(False, "--detail", help="Print full explanations for top findings."),
    fail_on: str | None = typer.Option(None, "--fail-on", help="Exit 1 if any finding is at least this severe (LOW/MEDIUM/HIGH/CRITICAL)."),
    save: bool = typer.Option(True, "--save/--no-save", help="Persist the case for later reporting."),
    list_detectors: bool = typer.Option(False, "--detectors", help="List available detectors and exit."),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Run typology detectors and produce an explainable, cited risk assessment."""
    state: State = get_state(ctx)
    with errors():
        if list_detectors:
            catalogue = detector_catalogue()
            if print_json_or(state, {"detectors": catalogue}, json_out):
                return
            table = Table(show_header=True, header_style="bold", box=None)
            table.add_column("Detector")
            table.add_column("What it finds")
            for row in catalogue:
                table.add_row(row["name"], row["description"])
            console.print(table)
            return

        require_kb_documents(state)
        unknown = [d for d in detector if d not in DETECTORS]
        if unknown:
            raise typer.BadParameter(f"Unknown detector(s): {', '.join(unknown)}")

        txns = fetch_transactions(state.db, dataset)
        if not txns:
            err_console.print("[red]No transactions loaded.[/red]")
            err_console.print("[dim]Try: anjali data load data/samples/demo_transactions.csv "
                              "--customers data/samples/demo_customers.csv[/dim]")
            raise typer.Exit(1)

        customers = fetch_customers(state.db, dataset)
        accounts = fetch_accounts(state.db, dataset)
        kb = open_kb(state.settings)
        analysis_ctx = build_context(txns, customers, accounts)
        case_id = f"{dataset or 'all'}-{today().isoformat()}"

        result = run_analysis(
            analysis_ctx,
            kb=kb,
            detectors=detector or None,
            jurisdiction=jurisdiction,
            case_id=case_id,
            db=state.db if save else None,
            as_of=state.as_of,
        )
        audit = state.audit()
        if audit:
            audit.append(
                "analysis.run",
                subject=case_id,
                details={
                    "dataset": dataset or "all",
                    "transactions": len(txns),
                    "findings": len(result.findings),
                    "risk": result.risk.overall,
                    "detectors": result.detectors_run,
                    "corpus_digest": result.corpus_digest,
                },
            )

        if print_json_or(state, result.to_dict(), json_out):
            _maybe_fail(result.findings, fail_on)
            return

        summary = result.summary
        console.print()
        console.print(f"[bold]Case[/bold] {case_id}  [dim]· {summary['transactions']} transactions "
                      f"· {summary['accounts']} accounts · {summary['total_value']} total[/dim]")
        console.print(f"[dim]detectors: {', '.join(result.detectors_run)}[/dim]")
        if result.findings:
            console.print()
            console.print(findings_table(result.findings))
        else:
            console.print("\n[green]No typology findings.[/green] "
                          "[dim]Absence of alerts is not evidence of absence — "
                          "check data coverage with `anjali simulate`.[/dim]")
        risk_panel(result.risk)

        if detail:
            for finding in result.findings[:3]:
                print_finding_detail(finding)
        if result.citation_keys:
            from anjali.kb.resolve import resolve

            citations_panel(resolve(kb, result.citation_keys[:8], as_of=state.as_of))
        if save:
            console.print(f"\n[dim]saved as case '{case_id}' · "
                          f"report with: anjali sar --case {case_id}[/dim]")
        _maybe_fail(result.findings, fail_on)
        state.close()


def _maybe_fail(findings, fail_on: str | None) -> None:
    if not fail_on:
        return
    try:
        threshold = Severity(fail_on.upper())
    except ValueError:
        raise typer.BadParameter("--fail-on must be one of LOW, MEDIUM, HIGH, CRITICAL") from None
    triggered = [f for f in findings if f.severity.rank >= threshold.rank]
    if triggered:
        err_console.print(
            f"[red]{len(triggered)} finding(s) at or above {threshold.value} — failing as requested.[/red]"
        )
        raise typer.Exit(1)


# --------------------------------------------------------------------------- #
# risk
# --------------------------------------------------------------------------- #
def render_risk(
    ctx: typer.Context,
    dataset: str | None = typer.Option(None, "--dataset", "-d"),
    jurisdiction: str | None = typer.Option(None, "--jurisdiction"),
    explain: bool = typer.Option(False, "--explain", help="Show every factor and citation."),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Show only the risk assessment, with the factors behind each dimension."""
    state: State = get_state(ctx)
    with errors():
        require_kb_documents(state)
        txns = fetch_transactions(state.db, dataset)
        if not txns:
            err_console.print("[red]No transactions loaded.[/red]")
            raise typer.Exit(1)
        kb = open_kb(state.settings)
        ctx_analysis = build_context(txns, fetch_customers(state.db, dataset), fetch_accounts(state.db, dataset))
        result = run_analysis(
            ctx_analysis,
            kb=kb,
            jurisdiction=jurisdiction,
            case_id=f"risk-{today().isoformat()}",
            as_of=state.as_of,
        )
        if print_json_or(state, result.risk.model_dump(mode="json"), json_out):
            return
        risk_panel(result.risk)
        if explain:
            for dim in result.risk.dimensions:
                console.print(f"\n[bold]{dim.dimension}[/bold] — {dim.score:.0f}/100 "
                              f"(weight {dim.weight:.0%})")
                console.print(f"  {dim.rationale}")
                for driver in dim.drivers:
                    console.print(f"  • {driver}")
                if dim.citations:
                    console.print(f"  [dim]{', '.join(c.citation for c in dim.citations)}[/dim]")
        state.close()


# --------------------------------------------------------------------------- #
# screen
# --------------------------------------------------------------------------- #
def screen(
    ctx: typer.Context,
    name: str | None = typer.Argument(None, help="Name to screen."),
    dob: str | None = typer.Option(None, "--dob", help="ISO date of birth for corroboration."),
    country: str | None = typer.Option(None, "--country", help="ISO-2 country for corroboration."),
    customer_id: str | None = typer.Option(None, "--customer-id", help="Screen a stored customer and its beneficial owners."),
    file: Path | None = typer.Option(None, "--file", help="Bulk CSV with a 'name' column."),
    threshold: float = typer.Option(0.85, "--threshold", help="Review threshold (0-1)."),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Fuzzy sanctions screening with corroboration and the 50% ownership rule."""
    state: State = get_state(ctx)
    with errors():
        if not (name or customer_id or file):
            raise typer.BadParameter("Provide a name, --customer-id, or --file.")
        screener = SanctionsScreener(state.db, threshold=threshold)
        if screener.size == 0:
            raise typer.BadParameter(
                "No sanctions list is loaded.",
                # typer.BadParameter has no hint kwarg; keep the message self-contained
            )
        import csv

        payloads = []
        if customer_id:
            customer = next((c for c in fetch_customers(state.db) if c.customer_id == customer_id), None)
            if customer is None:
                raise typer.BadParameter(f"Customer '{customer_id}' not found.")
            result = screener.screen_customer(customer, threshold=threshold)
            payloads.append(result)
        elif file:
            rows = list(csv.DictReader(file.read_text(encoding="utf-8").splitlines()))
            for row in rows[:500]:
                query = row.get("name") or row.get("Name")
                if query:
                    payloads.append(
                        screener.screen(
                            query,
                            dob=row.get("dob") or row.get("DOB"),
                            country=row.get("country") or row.get("Country"),
                            threshold=threshold,
                        )
                    )
        else:
            payloads.append(screener.screen(name or "", dob=dob, country=country, threshold=threshold))

        audit = state.audit()
        if audit:
            for result in payloads:
                audit.append(
                    "sanctions.screen",
                    subject=result.query,
                    details={
                        "disposition": result.disposition.value,
                        "matches": [
                            {"name": m.matched_name, "list": m.list_name, "score": m.score}
                            for m in result.matches[:5]
                        ],
                        "list_version": screener.version,
                    },
                )
        if print_json_or(state, {
            "results": [r.model_dump(mode="json") for r in payloads],
            "list_version": screener.version,
            "lists": screener.lists(),
        }, json_out):
            return
        for result in payloads:
            screening_panel(result, list_version=screener.version)
            if result.ownership_hits:
                console.print("\n[bold]Beneficial ownership analysis[/bold]")
                for hit in result.ownership_hits:
                    blocked = "BLOCKED (US 50% rule)" if hit.get("us_50_percent_rule_blocked") else "review"
                    console.print(f"  • {hit['matched_name']} — aggregate ownership "
                                  f"{hit['aggregate_ownership_pct']}% → {blocked}")
        from anjali.kb.resolve import resolve

        citations_panel(resolve(open_kb(state.settings), [
            "us-31cfr-501-603", "us-ofac-50-percent-rule", "fatf-r6-7-sanctions", "eu-sanctions-ownership-control",
        ], as_of=state.as_of))
        state.close()


# --------------------------------------------------------------------------- #
# sanctions sub-app
# --------------------------------------------------------------------------- #
@sanctions_app.command("list")
def sanctions_list(ctx: typer.Context, json_out: bool = typer.Option(False, "--json")) -> None:
    """Show loaded lists and their version stamp."""
    state: State = get_state(ctx)
    screener = SanctionsScreener(state.db)
    payload = screener.version_stamp()
    if print_json_or(state, payload, json_out):
        return
    console.print(f"[bold]List version[/bold] {payload['version']}  "
                  f"[dim]loaded {payload['loaded_at']}[/dim]")
    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("List")
    table.add_column("Entries", justify="right")
    for row in payload["lists"]:
        table.add_row(row["list_name"], str(row["n"]))
    console.print(table)
    console.print("[dim]The bundled fixture is synthetic. Import an operational list with "
                  "`anjali sanctions import`.[/dim]")


@sanctions_app.command("seed")
def sanctions_seed(ctx: typer.Context) -> None:
    """Load the bundled (synthetic) fixture list — for testing only."""
    state: State = get_state(ctx)
    with errors():
        result = seed_database(state.db)
        console.print(f"[green]✓[/green] {result['entries']} entries loaded "
                      f"(version {result['version']}, synthetic={result['synthetic']})")
        if result["synthetic"]:
            console.print("[yellow]Fixture data — not valid for an actual screening decision.[/yellow]")


@sanctions_app.command("import")
def sanctions_import(
    ctx: typer.Context,
    source: str = typer.Argument(..., help="A label, e.g. 'OFAC SDN', 'EU Consolidated', 'UK OFSI'."),
    file: Path = typer.Option(..., "--file", "-f", help="CSV export of the list."),
    list_name: str | None = typer.Option(None, "--list-name"),
    name_column: str | None = typer.Option(None, "--name-column"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Import an operational sanctions list from a CSV export."""
    state: State = get_state(ctx)
    with errors():
        result = import_csv(
            state.db,
            file,
            list_name=list_name or source,
            name_columns=(name_column,) if name_column else ("SDN_Name", "name", "Name", "caption", "Caption"),
        )
        audit = state.audit()
        if audit:
            audit.append("sanctions.import", subject=list_name or source, details=result)
        if print_json_or(state, result, json_out):
            return
        console.print(f"[green]✓[/green] imported {result['entries']} entries into "
                      f"[bold]{list_name or source}[/bold]")
        console.print(f"[dim]columns used: {result['columns']}[/dim]")
        if result["unmapped"]:
            console.print(f"[dim]unmapped columns: {', '.join(result['unmapped'][:10])}[/dim]")


# --------------------------------------------------------------------------- #
# investigate
# --------------------------------------------------------------------------- #
def investigate(
    ctx: typer.Context,
    dataset: str | None = typer.Option(None, "--dataset", "-d"),
    subject: str | None = typer.Option(None, "--subject", "-s", help="Account, customer, name or node to centre on."),
    target: str | None = typer.Option(None, "--target", "-t", help="Find the shortest path to this node."),
    export: str | None = typer.Option(
        None, "--export", "--format", help="Write the graph as dot | mermaid | json (use --out for the path)."
    ),
    out: Path | None = typer.Option(None, "--out", "-o"),
    depth: int = typer.Option(2, "--depth"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Build the entity graph and run link analysis."""
    state: State = get_state(ctx)
    with errors():
        txns = fetch_transactions(state.db, dataset)
        if not txns:
            err_console.print("[red]No transactions loaded.[/red]")
            raise typer.Exit(1)
        analysis_ctx = build_context(txns, fetch_customers(state.db, dataset), fetch_accounts(state.db, dataset))
        graph = EntityGraph.from_context(analysis_ctx)
        graph.persist(state.db, dataset=dataset or "default")

        if export:
            if export == "dot":
                text = graph.to_dot()
            elif export == "mermaid":
                text = graph.to_mermaid()
            elif export == "json":
                text = json.dumps(graph.to_dict(), indent=2, default=str)
            else:
                raise typer.BadParameter("--export/--format must be dot, mermaid or json")
            destination = out or Path(f"anjali_graph.{export if export != 'mermaid' else 'mmd'}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text, encoding="utf-8")
            console.print(f"[green]✓[/green] wrote {destination} ({graph.node_count} nodes, "
                          f"{graph.edge_count} edges)")
            return

        if subject:
            payload = graph.ego_network(subject, depth=depth)
            if target:
                payload.update(link_analysis(graph, subject, target))
            if print_json_or(state, payload, json_out):
                return
            if "error" in payload:
                console.print(f"[red]{payload['error']}[/red]")
                raise typer.Exit(1)
            center = payload["center"]
            console.print(f"\n[bold]Ego network[/bold] {center} → depth {depth}")
            console.print(f"  nodes {len(payload['nodes'])} · edges {len(payload['edges'])}")
            table = Table(show_header=True, header_style="bold", box=None)
            table.add_column("Node")
            table.add_column("Kind")
            table.add_column("Degree", justify="right")
            table.add_column("Flow in / out")
            for node in sorted(payload["nodes"], key=lambda n: n["degree"], reverse=True)[:20]:
                table.add_row(
                    node["label"], node["kind"], str(node["degree"]),
                    f"{node['flow']['in']} / {node['flow']['out']}",
                )
            console.print(table)
            if "connection" in payload:
                connection = payload["connection"]
                console.print(f"\n[bold]Connection to {connection['target']}[/bold] "
                              f"({connection['hops']} hops)")
                console.print(f"  {connection['narrative']}")
            return

        summary = graph.summary()
        if print_json_or(state, summary, json_out):
            return
        console.print(f"\n[bold]Entity graph[/bold] {summary['nodes']} nodes · "
                      f"{summary['edges']} edges")
        console.print(f"[dim]{summary['node_kinds']}[/dim]\n")
        table = Table(show_header=True, header_style="bold", box=None, title="Structural hubs (flow-weighted PageRank)")
        table.add_column("Node")
        table.add_column("Kind")
        table.add_column("PR", justify="right")
        table.add_column("Degree", justify="right")
        table.add_column("In / Out")
        for hub in summary["hubs"]:
            table.add_row(hub["label"], hub["kind"], f"{hub['pagerank']:.5f}",
                          str(hub["degree"]), f"{hub['flow']['in']} / {hub['flow']['out']}")
        console.print(table)
        if summary["clusters"]:
            console.print("\n[bold]Communities[/bold]")
            for cluster in summary["clusters"]:
                composition = ", ".join(f"{k} {v}" for k, v in cluster["composition"].items())
                console.print(
                    f"  cluster {cluster['cluster_id']} · {cluster['size']} nodes · "
                    f"internal flow {cluster['internal_flow']} · {composition}"
                )
        if summary["cycles"]:
            console.print("\n[bold]Cycles (round-tripping candidates)[/bold]")
            for cycle in summary["cycles"]:
                console.print(f"  {' → '.join(cycle)}")
        state.close()


# --------------------------------------------------------------------------- #
# ctr
# --------------------------------------------------------------------------- #
def ctr(
    ctx: typer.Context,
    dataset: str | None = typer.Option(None, "--dataset", "-d"),
    threshold: float = typer.Option(10000.0, "--threshold"),
    out: Path | None = typer.Option(None, "--out", "-o"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Aggregate currency activity and draft CTR worksheets."""
    state: State = get_state(ctx)
    with errors():
        from decimal import Decimal

        from anjali.compliance.goaml import build_ctr, ctr_to_markdown

        txns = fetch_transactions(state.db, dataset)
        if not txns:
            err_console.print("[red]No transactions loaded.[/red]")
            raise typer.Exit(1)
        payload = build_ctr(txns, threshold=Decimal(str(threshold)))
        if out:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(
                json.dumps(payload, indent=2, default=str) if out.suffix == ".json"
                else ctr_to_markdown(payload),
                encoding="utf-8",
            )
            console.print(f"[green]✓[/green] wrote {out}")
            return
        if print_json_or(state, payload, json_out):
            return
        from rich.markdown import Markdown

        console.print(Markdown(ctr_to_markdown(payload)))
        state.close()


__all__ = [
    "analyze",
    "ctr",
    "data_app",
    "investigate",
    "render_risk",
    "sanctions_app",
    "screen",
]
