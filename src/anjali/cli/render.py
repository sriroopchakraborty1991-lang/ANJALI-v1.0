"""Terminal rendering. Rich for humans, JSON for machines.

Every human-facing view has a ``--json`` counterpart that emits the same data as the
model layer, so the CLI composes into pipelines (`jq`, CI gates) without scraping colour.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from anjali.core.models import Citation, Finding, RiskAssessment, ScreeningResult, Severity

console = Console()
err_console = Console(stderr=True)

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
BAND_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "green",
}
JURISDICTION_STYLE = {"US": "bold blue", "EU": "bold magenta", "UK": "bold green", "FATF": "bold yellow", "INTL": "bold cyan"}

BANNER = r"""
   █████╗ ███╗   ██╗     ██╗ █████╗ ██╗     ██╗
  ██╔══██╗████╗  ██║     ██║██╔══██╗██║     ██║
  ███████║██╔██╗ ██║     ██║███████║██║     ██║
  ██╔══██║██║╚██╗██║██   ██║██╔══██║██║     ██║
  ██║  ██║██║ ╚████║╚█████╔╝██║  ██║███████╗██║
  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚════╝ ╚═╝  ╚═╝╚══════╝╚═╝
"""


def print_banner() -> None:
    console.print(Text(BANNER, style="bold cyan"))
    console.print(
        "  [bold]AI-Navigated Judgment & Audit for Legal Integrity[/bold]\n"
        "  [dim]Local-first · BYOK · citation-backed financial-crime compliance[/dim]\n"
    )


def emit_json(payload: Any) -> None:
    sys.stdout.write(json.dumps(payload, indent=2, default=str, ensure_ascii=False) + "\n")


def print_json_or(state: Any, payload: Any, local_flag: bool = False) -> bool:
    """Emit JSON when requested and tell the caller to skip rich rendering."""
    if getattr(state, "json", False) or local_flag:
        emit_json(payload)
        return True
    return False


def severity_badge(severity: Severity | str) -> Text:
    sev = severity if isinstance(severity, Severity) else Severity(str(severity))
    return Text(f" {sev.value} ", style=SEVERITY_STYLE[sev])


def jurisdiction_badge(code: str) -> Text:
    return Text(f" {code} ", style=JURISDICTION_STYLE.get(code.upper(), "bold white"))


def risk_bar(score: float, width: int = 20) -> Text:
    filled = round(score / 100 * width)
    colour = "red" if score >= 80 else "yellow" if score >= 60 else "cyan" if score >= 35 else "green"
    text = Text()
    text.append("█" * filled, style=colour)
    text.append("░" * (width - filled), style="dim")
    text.append(f"  {score:.1f}/100", style=f"bold {colour}")
    return text


def citations_panel(citations: Sequence[Citation], *, title: str = "Authorities") -> None:
    if not citations:
        return
    lines = Text()
    for cit in citations:
        flag = ""
        if cit.stale:
            flag = " [dim](superseded)[/dim]"
        elif cit.future:
            flag = " [dim](not yet in force)[/dim]"
        lines.append(f"• {cit.citation}", style="bold")
        lines.append(f" — {cit.title}{flag}\n", style="")
        if cit.source_url:
            lines.append(f"  {cit.source_url}\n", style="dim")
    console.print(Panel(lines, title=f"[bold]{title}[/bold]", border_style="blue", expand=False))


def findings_table(findings: Sequence[Finding], *, show_evidence: bool = False) -> Table:
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Typology", no_wrap=True)
    table.add_column("Finding")
    table.add_column("Conf", justify="right", no_wrap=True)
    table.add_column("Evidence", justify="right", no_wrap=True)
    for finding in findings:
        table.add_row(
            severity_badge(finding.severity),
            finding.typology,
            finding.summary,
            f"{finding.confidence:.0%}",
            str(len(finding.evidence_txn_ids)),
        )
    return table


def print_finding_detail(finding: Finding) -> None:
    console.print()
    console.rule(f"[bold]{finding.typology}[/bold] · {finding.finding_id}")
    console.print(f"{severity_badge(finding.severity)}  confidence {finding.confidence:.0%}")
    console.print(f"\n[bold]{finding.title}[/bold]")
    console.print(finding.summary)
    console.print("\n[bold]How this was determined[/bold]")
    for i, step in enumerate(finding.explanation, 1):
        console.print(f"  {i}. {step}")
    if finding.metrics:
        console.print("\n[bold]Metrics[/bold]")
        for key, value in finding.metrics.items():
            console.print(f"  {key}: {value}")
    if finding.evidence_txn_ids:
        console.print(f"\n[bold]Evidence[/bold] ({len(finding.evidence_txn_ids)} transactions)")
        console.print("  " + ", ".join(finding.evidence_txn_ids[:12]))
        if len(finding.evidence_txn_ids) > 12:
            console.print(f"  [dim]… and {len(finding.evidence_txn_ids) - 12} more[/dim]")
    if finding.recommended_actions:
        console.print("\n[bold]Recommended next steps[/bold]")
        for action in finding.recommended_actions:
            console.print(f"  → {action}")
    if finding.regulatory_refs:
        citations_panel(finding.regulatory_refs, title="Regulatory basis")


def risk_panel(assessment: RiskAssessment) -> None:
    console.print()
    console.print(Panel(
        Text.assemble(
            ("Composite risk  ", "bold"), risk_bar(assessment.overall), "\n",
            ("Band  ", "bold"),
            Text(f" {assessment.band.value} ", style=BAND_STYLE.get(assessment.band.value, "white")),
            f"   confidence {assessment.confidence:.0%}",
        ),
        title="[bold]Risk assessment[/bold]",
        border_style="red" if assessment.band.value in ("CRITICAL", "HIGH") else "yellow",
    ))
    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("Dimension")
    table.add_column("Score", justify="right")
    table.add_column("Weight", justify="right")
    table.add_column("Rationale")
    for dim in sorted(assessment.dimensions, key=lambda d: d.score * d.weight, reverse=True):
        table.add_row(dim.dimension, f"{dim.score:.0f}", f"{dim.weight:.0%}", dim.rationale)
    console.print(table)
    drivers = [d for dim in assessment.dimensions for d in dim.drivers][:8]
    if drivers:
        console.print("[bold]Key drivers[/bold]")
        for driver in drivers:
            console.print(f"  • {driver}")
    if assessment.jurisdiction_views:
        views = "   ".join(f"{j}: {v:.0f}" for j, v in assessment.jurisdiction_views.items())
        console.print(f"\n[bold]Jurisdiction-weighted views[/bold]  {views}")
    console.print(f"\n[dim]{assessment.narrative}[/dim]")


def screening_panel(result: ScreeningResult, *, list_version: str = "") -> None:
    style = {
        "CLEAR": "green", "WEAK": "dim", "POTENTIAL": "yellow", "STRONG": "red", "EXACT": "bold white on red",
    }.get(result.disposition.value, "white")
    header = f" Screening: {result.query} "
    console.print()
    console.print(Panel(
        Text.assemble(
            ("Disposition  ", "bold"), Text(f" {result.disposition.value} ", style=style),
            f"\nMatches {len(result.matches)} · threshold {result.threshold:.2f}"
            + (f" · list {list_version}" if list_version else ""),
        ),
        title=header,
        border_style=style.split()[-1] if style else "white",
    ))
    if not result.matches:
        console.print("[green]No match at or above the review threshold.[/green]")
        return
    if result.disposition.requires_review:
        console.print("[bold white on red] [SANCTIONS ALERT] [/bold white on red] "
                      "Escalate to the sanctions team. Blocking is strict-liability and time-bound.")
    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("Tier")
    table.add_column("Matched name")
    table.add_column("List")
    table.add_column("Score", justify="right")
    table.add_column("Corroboration")
    for match in result.matches:
        corr = ", ".join(f"{k}={v}" for k, v in match.corroboration.items()) or "—"
        table.add_row(
            Text(f" {match.tier.value} ", style=style),
            match.matched_name,
            f"{match.list_name}" + (f" ({match.list_id})" if match.list_id else ""),
            f"{match.score:.3f}",
            corr,
        )
    console.print(table)
    for match in result.matches[:3]:
        if match.notes:
            console.print(f"\n[bold]{match.matched_name}[/bold]")
            for note in match.notes:
                console.print(f"  • {note}")


def kv_panel(pairs: dict[str, Any], *, title: str) -> None:
    lines = Text()
    for key, value in pairs.items():
        lines.append(f"{key}: ", style="bold")
        lines.append(f"{value}\n")
    console.print(Panel(lines, title=f"[bold]{title}[/bold]", border_style="blue", expand=False))
