"""Case-data ingestion: CSV / JSON / JSONL with real-world column aliases.

Analysts do not control the column names their core banking system exports, so the
loader maps a generous alias set onto the canonical schema and *reports what it could
not map* rather than silently dropping rows. A silent drop in an AML pipeline is a
false negative, i.e. the exact failure the regulator penalises.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from anjali.core.db import Database
from anjali.core.errors import IngestError
from anjali.core.models import Account, Customer, Transaction
from anjali.core.util import money, read_json

TXN_ALIASES: dict[str, tuple[str, ...]] = {
    "txn_id": ("txn_id", "id", "transaction_id", "txn", "reference_id", "ref"),
    "timestamp": ("timestamp", "date", "datetime", "time", "transaction_date", "value_date", "booking_date"),
    "amount": ("amount", "value", "amt", "transaction_amount", "local_amount"),
    "currency": ("currency", "ccy", "currency_code"),
    "direction": ("direction", "dr_cr", "debit_credit", "dc"),
    "txn_type": ("txn_type", "type", "transaction_type", "payment_type", "product"),
    "from_account": ("from_account", "sender_account", "originator_account", "debit_account", "payer_account", "account_from"),
    "to_account": ("to_account", "receiver_account", "beneficiary_account", "credit_account", "payee_account", "account_to"),
    "from_name": ("from_name", "sender_name", "originator_name", "payer_name"),
    "to_name": ("to_name", "receiver_name", "beneficiary_name", "payee_name"),
    "channel": ("channel", "delivery_channel", "channel_type"),
    "country_from": ("country_from", "originator_country", "sender_country", "from_country"),
    "country_to": ("country_to", "beneficiary_country", "receiver_country", "to_country"),
    "branch": ("branch", "branch_code", "branch_id", "location"),
    "device_id": ("device_id", "device", "device_fingerprint"),
    "ip_address": ("ip_address", "ip", "source_ip"),
    "description": ("description", "narrative", "memo", "details", "remittance_info"),
    "reference": ("reference", "payment_reference", "end_to_end_id"),
    "status": ("status", "state", "txn_status"),
    "goods_description": ("goods_description", "goods", "commodity", "goods_desc"),
    "hs_code": ("hs_code", "hscode", "tariff_code"),
    "quantity": ("quantity", "qty", "units"),
    "unit_price": ("unit_price", "price", "declared_price"),
    "benchmark_price": ("benchmark_price", "market_price", "reference_price"),
    "vessel": ("vessel", "carrier", "shipping_line"),
    "route": ("route", "shipping_route", "port_of_loading"),
}

CUSTOMER_ALIASES: dict[str, tuple[str, ...]] = {
    "customer_id": ("customer_id", "id", "client_id", "cust_id"),
    "name": ("name", "customer_name", "client_name", "full_name"),
    "customer_type": ("customer_type", "type", "entity_type"),
    "country": ("country", "country_code", "domicile"),
    "residency": ("residency", "residence"),
    "dob": ("dob", "date_of_birth", "birth_date"),
    "occupation": ("occupation", "job", "profession"),
    "industry": ("industry", "sector", "business_sector"),
    "naics": ("naics", "naics_code", "sic"),
    "pep": ("pep", "is_pep", "politically_exposed"),
    "risk_rating": ("risk_rating", "risk", "risk_level"),
    "onboarded_at": ("onboarded_at", "onboarded", "account_opened", "relationship_start"),
    "expected_monthly_volume": ("expected_monthly_volume", "expected_volume", "expected_turnover"),
    "expected_txn_count": ("expected_txn_count", "expected_transactions"),
    "source_of_funds": ("source_of_funds", "sof"),
    "accounts": ("accounts", "account_ids", "account_numbers", "linked_accounts"),
    "kyc_verified_at": ("kyc_verified_at", "kyc_date"),
    "edd_completed": ("edd_completed", "edd"),
    "notes": ("notes", "comments"),
}

_TRUE = {"1", "true", "yes", "y", "t", "pep"}


@dataclass
class LoadReport:
    rows_read: int = 0
    rows_loaded: int = 0
    rows_rejected: int = 0
    unmapped_columns: list[str] = field(default_factory=list)
    missing_required: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "rows_read": self.rows_read,
            "rows_loaded": self.rows_loaded,
            "rows_rejected": self.rows_rejected,
            "unmapped_columns": self.unmapped_columns,
            "missing_required": self.missing_required,
            "errors": self.errors[:20],
        }


def _canonical_row(row: dict[str, Any], aliases: dict[str, tuple[str, ...]]) -> tuple[dict[str, Any], list[str]]:
    lowered = {str(k).strip().lower(): v for k, v in row.items() if k is not None}
    out: dict[str, Any] = {}
    used: set[str] = set()
    for canonical, names in aliases.items():
        for name in names:
            if name in lowered and lowered[name] not in (None, ""):
                out[canonical] = lowered[name]
                used.add(name)
                break
    unmapped = [k for k in lowered if k not in used and lowered[k] not in (None, "")]
    return out, unmapped


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in _TRUE


def _coerce_direction(raw: Any, amount: Any) -> str:
    if raw is None:
        try:
            return "credit" if float(str(amount).replace(",", "")) >= 0 else "debit"
        except (TypeError, ValueError):
            return "debit"
    text = str(raw).strip().lower()
    if text.startswith(("c", "cr", "credit", "in", "+")):
        return "credit"
    return "debit"


def _normalise_currency_unsigned(amount: Any) -> Any:
    """Amounts in exports are frequently signed; direction carries the sign instead."""
    try:
        value = float(str(amount).replace(",", "").replace("$", ""))
        return abs(value)
    except (TypeError, ValueError):
        return amount


def load_transactions(path: Path, *, dataset: str | None = None) -> tuple[list[Transaction], LoadReport]:
    path = Path(path)
    if not path.exists():
        raise IngestError(f"No such file: {path}")
    report = LoadReport(source=str(path))
    suffix = path.suffix.lower()

    if suffix in {".csv", ".tsv"}:
        raw_rows = _read_csv(path)
    elif suffix in {".json", ".jsonl", ".ndjson"}:
        raw_rows = _read_json_rows(path)
    else:
        raise IngestError(
            f"Unsupported file type '{suffix}'. Use .csv, .tsv, .json or .jsonl.",
            hint="PDF/OFX support is on the roadmap; export to CSV from your core system.",
        )

    txns: list[Transaction] = []
    unmapped_all: set[str] = set()
    for idx, raw in enumerate(raw_rows, 1):
        report.rows_read += 1
        canonical, unmapped = _canonical_row(raw, TXN_ALIASES)
        unmapped_all.update(unmapped)
        if "amount" not in canonical or "timestamp" not in canonical:
            report.rows_rejected += 1
            if len(report.errors) < 20:
                missing = [f for f in ("amount", "timestamp") if f not in canonical]
                report.errors.append(f"row {idx}: missing {', '.join(missing)}")
            continue
        try:
            canonical["amount"] = _normalise_currency_unsigned(canonical["amount"])
            canonical["direction"] = _coerce_direction(canonical.get("direction"), canonical["amount"])
            canonical.setdefault("txn_id", f"row-{idx:06d}")
            canonical["amount"] = money(canonical["amount"])
            txns.append(Transaction.model_validate(canonical))
        except Exception as exc:
            report.rows_rejected += 1
            if len(report.errors) < 20:
                report.errors.append(f"row {idx}: {str(exc).splitlines()[0][:160]}")
    report.rows_loaded = len(txns)
    report.unmapped_columns = sorted(unmapped_all)
    if not txns:
        raise IngestError(
            f"No valid transactions in {path.name}.",
            hint="Required columns: an amount and a timestamp. Run `anjali data sample` for a template.",
        )
    return txns, report


def _read_csv(path: Path) -> list[dict[str, Any]]:
    delimiter = "\t" if path.suffix.lower() == ".tsv" else ","
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    sample = text[:4096]
    if delimiter == "," and sample.count(";") > sample.count(","):
        delimiter = ";"
    return list(csv.DictReader(io.StringIO(text), delimiter=delimiter))


def _read_json_rows(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                rows.append(json.loads(line))
        return rows
    data = read_json(path)
    if isinstance(data, dict):
        for key in ("transactions", "rows", "data", "items"):
            if isinstance(data.get(key), list):
                return data[key]
        raise IngestError(f"{path.name}: JSON object has no 'transactions' array.")
    if isinstance(data, list):
        return data
    raise IngestError(f"{path.name}: expected a JSON array or an object with 'transactions'.")


def load_customers(path: Path) -> tuple[list[Customer], LoadReport]:
    path = Path(path)
    if not path.exists():
        raise IngestError(f"No such file: {path}")
    report = LoadReport(source=str(path))
    rows = _read_json_rows(path) if path.suffix.lower() in {".json", ".jsonl"} else _read_csv(path)
    customers: list[Customer] = []
    unmapped_all: set[str] = set()
    for idx, raw in enumerate(rows, 1):
        report.rows_read += 1
        canonical, unmapped = _canonical_row(raw, CUSTOMER_ALIASES)
        unmapped_all.update(unmapped)
        if "name" not in canonical:
            report.rows_rejected += 1
            report.errors.append(f"row {idx}: missing name")
            continue
        canonical.setdefault("customer_id", f"cust-{idx:05d}")
        canonical["pep"] = _truthy(canonical.get("pep", False))
        if isinstance(canonical.get("accounts"), str):
            canonical["accounts"] = [
                part.strip()
                for part in canonical["accounts"].replace(";", "|").replace(",", "|").split("|")
                if part.strip()
            ]
        canonical["edd_completed"] = _truthy(canonical.get("edd_completed", False))
        if canonical.get("customer_type"):
            ctype = str(canonical["customer_type"]).strip().lower()
            canonical["customer_type"] = "business" if ctype.startswith(("b", "c", "corp")) else "individual"
        if canonical.get("beneficial_owners") is None:
            canonical.pop("beneficial_owners", None)
        try:
            customers.append(Customer.model_validate(canonical))
        except Exception as exc:
            report.rows_rejected += 1
            report.errors.append(f"row {idx}: {str(exc).splitlines()[0][:160]}")
    report.rows_loaded = len(customers)
    report.unmapped_columns = sorted(unmapped_all)
    return customers, report


def persist(
    db: Database,
    transactions: Sequence[Transaction] = (),
    customers: Sequence[Customer] = (),
    accounts: Sequence[Account] = (),
    *,
    dataset: str = "default",
) -> dict[str, int]:
    with db.tx() as conn:
        for txn in transactions:
            conn.execute(
                """
                INSERT INTO transactions(
                    txn_id, dataset, ts, amount, currency, direction, txn_type, from_account,
                    to_account, from_name, to_name, country_from, country_to, channel, payload
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(txn_id) DO UPDATE SET payload=excluded.payload, dataset=excluded.dataset
                """,
                (
                    txn.txn_id,
                    dataset,
                    txn.timestamp.isoformat(),
                    str(txn.amount),
                    txn.currency,
                    txn.direction.value,
                    txn.txn_type,
                    txn.from_account,
                    txn.to_account,
                    txn.from_name,
                    txn.to_name,
                    txn.country_from,
                    txn.country_to,
                    txn.channel,
                    json.dumps(txn.to_dict(), default=str),
                ),
            )
        for cust in customers:
            conn.execute(
                "INSERT INTO customers(customer_id, dataset, name, payload) VALUES(?,?,?,?) "
                "ON CONFLICT(customer_id) DO UPDATE SET payload=excluded.payload, name=excluded.name",
                (cust.customer_id, dataset, cust.name, json.dumps(cust.to_dict(), default=str)),
            )
        for acct in accounts:
            conn.execute(
                "INSERT INTO accounts(account_id, dataset, customer_id, payload) VALUES(?,?,?,?) "
                "ON CONFLICT(account_id) DO UPDATE SET payload=excluded.payload",
                (acct.account_id, dataset, acct.customer_id, json.dumps(acct.to_dict(), default=str)),
            )
    return {"transactions": len(transactions), "customers": len(customers), "accounts": len(accounts)}


def fetch_transactions(db: Database, dataset: str | None = None) -> list[Transaction]:
    sql = "SELECT payload FROM transactions"
    params: tuple[Any, ...] = ()
    if dataset:
        sql += " WHERE dataset=?"
        params = (dataset,)
    sql += " ORDER BY ts"
    out: list[Transaction] = []
    for row in db.query(sql, params):
        try:
            out.append(Transaction.model_validate_json(row["payload"]))
        except Exception:  # pragma: no cover - tolerate partially written payloads
            continue
    return out


def fetch_customers(db: Database, dataset: str | None = None) -> list[Customer]:
    sql = "SELECT payload FROM customers"
    params: tuple[Any, ...] = ()
    if dataset:
        sql += " WHERE dataset=?"
        params = (dataset,)
    out: list[Customer] = []
    for row in db.query(sql, params):
        try:
            out.append(Customer.model_validate_json(row["payload"]))
        except Exception:  # pragma: no cover
            continue
    return out


def fetch_accounts(db: Database, dataset: str | None = None) -> list[Account]:
    sql = "SELECT payload FROM accounts"
    params: tuple[Any, ...] = ()
    if dataset:
        sql += " WHERE dataset=?"
        params = (dataset,)
    out: list[Account] = []
    for row in db.query(sql, params):
        try:
            out.append(Account.model_validate_json(row["payload"]))
        except Exception:  # pragma: no cover
            continue
    return out


def datasets(db: Database) -> list[dict[str, Any]]:
    rows = db.query(
        "SELECT dataset, COUNT(*) AS n, MIN(ts) AS first_ts, MAX(ts) AS last_ts "
        "FROM transactions GROUP BY dataset ORDER BY dataset"
    )
    return [dict(r) for r in rows]


def sample_csv_template() -> str:
    header = [
        "txn_id", "timestamp", "amount", "currency", "direction", "txn_type",
        "from_account", "to_account", "from_name", "to_name", "channel",
        "country_from", "country_to", "branch", "description",
    ]
    rows = [
        ["T0001", "2026-01-04T10:12:00Z", "9500.00", "USD", "credit", "cash_deposit",
         "", "ACC-1001", "", "Ravi Menon", "branch", "US", "US", "BR-07", "Cash deposit"],
        ["T0002", "2026-01-04T14:40:00Z", "8900.00", "USD", "credit", "cash_deposit",
         "", "ACC-1001", "", "Ravi Menon", "branch", "US", "US", "BR-12", "Cash deposit"],
    ]
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    writer.writerows(rows)
    return buf.getvalue()
