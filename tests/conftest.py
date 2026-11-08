"""Shared fixtures.

The suite runs against a real workspace (SQLite + FTS5 + corpus ingest) rather than heavy
mocking, because the parts most likely to break are the parts that touch state: the index,
the audit chain and the case database.
"""

from __future__ import annotations

import csv
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

DEMO = REPO_ROOT / "data" / "samples"


@pytest.fixture(scope="session")
def workspace(tmp_path_factory) -> Path:
    home = tmp_path_factory.mktemp("anjali-home")
    os.environ["ANJALI_HOME"] = str(home)
    from typer.testing import CliRunner

    from anjali.cli.main import app

    result = CliRunner().invoke(app, ["--quiet", "init"])
    assert result.exit_code == 0, result.output
    return home


@pytest.fixture(scope="session")
def settings(workspace):
    from anjali.core.config import load_settings

    return load_settings()


@pytest.fixture(scope="session")
def db(settings):
    from anjali.core.db import Database

    db = Database(settings.db_path)
    yield db


@pytest.fixture(scope="session")
def kb(settings):
    from anjali.rag.store import open_kb

    return open_kb(settings)


@pytest.fixture(scope="session")
def demo_csv(tmp_path_factory) -> tuple[Path, Path]:
    return DEMO / "demo_transactions.csv", DEMO / "demo_customers.csv"


@pytest.fixture(scope="session")
def demo_context(demo_csv):
    from anjali.analysis.engine import build_context
    from anjali.analysis.ingest import load_customers, load_transactions

    txn_path, cust_path = demo_csv
    txns, _ = load_transactions(txn_path)
    customers, _ = load_customers(cust_path)
    return build_context(txns, customers)


@pytest.fixture(scope="session")
def demo_result(demo_context, kb):
    from anjali.analysis.engine import analyze

    return analyze(demo_context, kb=kb)


@pytest.fixture()
def runner():
    from typer.testing import CliRunner

    return CliRunner()


def write_csv(path: Path, rows: list[dict[str, object]], columns: list[str]) -> Path:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    return path
