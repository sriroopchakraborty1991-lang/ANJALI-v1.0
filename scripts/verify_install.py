#!/usr/bin/env python3
"""Post-install verification.

Runs the same commands a new user runs, against a throwaway workspace, and fails loudly if any
of them stops behaving. CI calls this after installing the wheel; you can run it locally to check
an install before shipping.

    python scripts/verify_install.py [--home PATH] [--keep]

Every check prints one line. The exit code is 0 only if all of them pass.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

BASE: list[str] = []


def run(args: list[str], *, expect: int = 0, capture: bool = True) -> str:
    """Run an ANJALI command. `args` are the arguments *after* the program name."""
    command = [*BASE, *args]
    try:
        completed = subprocess.run(
            command,
            capture_output=capture,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except FileNotFoundError as exc:  # pragma: no cover - install problem
        fail(f"{args[0]} is not on PATH ({exc})")
        raise SystemExit(1) from exc
    if completed.returncode != expect:
        fail(f"`{' '.join(command)}` exited {completed.returncode}, expected {expect}")
        print(completed.stdout[-2000:] or completed.stderr[-2000:], file=sys.stderr)
        raise SystemExit(1)
    return completed.stdout if capture else ""


def ok(label: str) -> None:
    print(f"  PASS  {label}")


def fail(label: str) -> None:
    print(f"  FAIL  {label}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify an ANJALI install end to end.")
    parser.add_argument("--home", type=Path, default=None, help="Workspace to use (default: temp).")
    parser.add_argument("--keep", action="store_true", help="Keep the temporary workspace.")
    options = parser.parse_args()

    home = options.home or Path(tempfile.mkdtemp(prefix="anjali-verify-"))
    if home.exists() and options.keep:
        shutil.rmtree(home, ignore_errors=True)
    os.environ["ANJALI_HOME"] = str(home)
    # Rich writes box-drawing characters and legal citations; make sure the child process and
    # this one agree on the encoding (Windows defaults to cp1252 on a pipe).
    os.environ.setdefault("PYTHONUTF8", "1")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    global BASE
    executable = shutil.which("anjali")
    BASE = [executable] if executable else [sys.executable, "-m", "anjali.cli.main"]
    print(f"verifying {' '.join(BASE)}\nworkspace {home}\n")

    version = run(["--version"])
    ok(f"version — {version.strip()}")

    run(["--quiet", "init"])
    ok("init — workspace, corpus, sanctions fixtures, demo case")

    doctor = run(["doctor"])
    ok("doctor — " + ("all checks passed" if "All checks passed" in doctor else "reported issues"))

    analysis = json.loads(run(["analyze", "--dataset", "demo", "--json"]))
    findings = analysis["findings"]
    assert findings, "no findings on the demo case"
    assert all(f["regulatory_refs"] for f in findings), "a finding has no regulatory reference"
    ok(
        f"analyze — {len(findings)} findings, risk {analysis['risk']['overall']} "
        f"({analysis['risk']['band']}), every finding cited"
    )

    screening = json.loads(run(["screen", "Mohammed Al-Rashid", "--country", "SY", "--json"]))
    top = screening["results"][0]
    assert top["matches"], "a listed name produced no match"
    ok(f"screen — disposition {top['disposition']} at score {top['matches'][0]['score']}")

    conflicts = json.loads(run(["conflicts", "relevant", "--json"]))
    ok(f"conflicts — {len(conflicts['conflicts'])} raised by this case")

    sar_path = home / "sar.md"
    run(["--quiet", "sar", "--dataset", "demo", "-o", str(sar_path)])
    assert sar_path.exists() and sar_path.stat().st_size > 2000, "SAR artefact was not written"
    ok(f"sar — wrote {sar_path.stat().st_size} bytes with a quality gate")

    simulation = json.loads(run(["simulate", "--fail-under", "0.9", "--json"]))
    overall = simulation["overall"]
    ok(
        f"simulate — recall {overall['recall']:.0%} on {overall['injected']} injected scenarios, "
        f"{overall['false_positives']} false positives"
    )

    audit = json.loads(run(["audit", "verify", "--json"]))
    assert audit["valid"] is True, "audit chain failed verification"
    ok(f"audit — chain intact, {audit['records']} records, head {audit['head_hash'][:12]}")

    answer = run(["ask", "When must a SAR be filed in the US?", "--offline"])
    assert "31 CFR" in answer or "31 USC" in answer, "offline answer carried no citation"
    ok("ask — offline answer is cited")

    if not options.keep:
        shutil.rmtree(home, ignore_errors=True)
    print("\nAll install checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
