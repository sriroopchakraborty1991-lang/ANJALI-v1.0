"""SQLite store: one portable file holds the corpus, vectors, case data and graph.

Why SQLite: a compliance artefact must be a *file you can hand to an examiner*.
No server, no retained cloud copy, no vendor to subpoena. WAL mode keeps concurrent
reads fast while an analyst annotates a case.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from anjali.core.errors import AnjaliError

SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS documents (
    doc_id TEXT PRIMARY KEY,
    citation TEXT NOT NULL,
    title TEXT NOT NULL,
    jurisdiction TEXT NOT NULL,
    regulator TEXT,
    doc_type TEXT,
    status TEXT,
    effective_from TEXT,
    effective_to TEXT,
    amended_by TEXT,
    supersedes TEXT,
    obligations TEXT,
    penalties TEXT,
    source_url TEXT,
    tags TEXT,
    text TEXT,
    digest TEXT,
    updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_docs_juris ON documents(jurisdiction, status);

CREATE TABLE IF NOT EXISTS chunks (
    chunk_id TEXT PRIMARY KEY,
    doc_id TEXT NOT NULL,
    citation TEXT NOT NULL,
    title TEXT NOT NULL,
    jurisdiction TEXT NOT NULL,
    regulator TEXT,
    doc_type TEXT,
    status TEXT,
    effective_from TEXT,
    effective_to TEXT,
    source_url TEXT,
    tags TEXT,
    section TEXT,
    ordinal INTEGER DEFAULT 0,
    text TEXT NOT NULL,
    embedder TEXT,
    vec BLOB
);
CREATE INDEX IF NOT EXISTS idx_chunks_doc ON chunks(doc_id);
CREATE INDEX IF NOT EXISTS idx_chunks_temporal ON chunks(status, effective_from, effective_to);

CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
    chunk_id UNINDEXED,
    text,
    citation,
    title,
    tags,
    tokenize = 'porter unicode61'
);

CREATE TABLE IF NOT EXISTS transactions (
    txn_id TEXT PRIMARY KEY,
    dataset TEXT,
    ts TEXT,
    amount TEXT,
    currency TEXT,
    direction TEXT,
    txn_type TEXT,
    from_account TEXT,
    to_account TEXT,
    from_name TEXT,
    to_name TEXT,
    country_from TEXT,
    country_to TEXT,
    channel TEXT,
    payload TEXT
);
CREATE INDEX IF NOT EXISTS idx_txn_ts ON transactions(ts);
CREATE INDEX IF NOT EXISTS idx_txn_from ON transactions(from_account);
CREATE INDEX IF NOT EXISTS idx_txn_to ON transactions(to_account);

CREATE TABLE IF NOT EXISTS customers (
    customer_id TEXT PRIMARY KEY,
    dataset TEXT,
    name TEXT,
    payload TEXT
);

CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY,
    dataset TEXT,
    customer_id TEXT,
    payload TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    case_id TEXT,
    severity TEXT,
    typology TEXT,
    created_at TEXT,
    payload TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id);

CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    title TEXT,
    created_at TEXT,
    updated_at TEXT,
    status TEXT,
    payload TEXT
);

CREATE TABLE IF NOT EXISTS nodes (
    node_id TEXT PRIMARY KEY,
    dataset TEXT,
    label TEXT,
    kind TEXT,
    attrs TEXT
);
CREATE INDEX IF NOT EXISTS idx_nodes_label ON nodes(label);

CREATE TABLE IF NOT EXISTS edges (
    edge_id TEXT PRIMARY KEY,
    dataset TEXT,
    src TEXT,
    dst TEXT,
    kind TEXT,
    weight REAL DEFAULT 1.0,
    txn_id TEXT,
    ts TEXT,
    amount TEXT
);
CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst);

CREATE TABLE IF NOT EXISTS sanctions (
    list_name TEXT NOT NULL,
    list_id TEXT,
    name TEXT NOT NULL,
    normalised TEXT NOT NULL,
    entity_type TEXT,
    country TEXT,
    dob TEXT,
    programme TEXT,
    payload TEXT,
    PRIMARY KEY (list_name, list_id, normalised)
);
CREATE INDEX IF NOT EXISTS idx_sanctions_norm ON sanctions(normalised);
CREATE INDEX IF NOT EXISTS idx_sanctions_name ON sanctions(name);

CREATE TABLE IF NOT EXISTS audit_index (
    seq INTEGER PRIMARY KEY,
    timestamp TEXT,
    actor TEXT,
    action TEXT,
    subject TEXT,
    hash TEXT
);
"""


class Database:
    """Thin, explicit wrapper. No ORM magic — every query is reviewable."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.conn = sqlite3.connect(str(self.path), timeout=30.0)
        except sqlite3.Error as exc:  # pragma: no cover
            raise AnjaliError(f"Cannot open database {self.path}: {exc}") from exc
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.init_schema()

    # -- lifecycle -------------------------------------------------------- #
    def init_schema(self) -> None:
        self.conn.executescript(SCHEMA)
        row = self.conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if row is None:
            self.conn.execute(
                "INSERT INTO meta(key, value) VALUES('schema_version', ?)", (str(SCHEMA_VERSION),)
            )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Database:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self.conn
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    # -- generic ---------------------------------------------------------- #
    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        return self.conn.execute(sql, params)

    def query(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchall()

    def one(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        return self.conn.execute(sql, params).fetchone()

    def scalar(self, sql: str, params: tuple[Any, ...] = ()) -> Any:
        row = self.conn.execute(sql, params).fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self.tx() as conn:
            conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        row = self.one("SELECT value FROM meta WHERE key=?", (key,))
        return row["value"] if row else default

    def counts(self) -> dict[str, int]:
        tables = [
            "documents", "chunks", "transactions", "customers", "accounts",
            "findings", "nodes", "edges", "sanctions", "cases",
        ]
        return {t: int(self.scalar(f"SELECT COUNT(*) FROM {t}") or 0) for t in tables}

    def vacuum(self) -> None:
        self.conn.execute("VACUUM")
