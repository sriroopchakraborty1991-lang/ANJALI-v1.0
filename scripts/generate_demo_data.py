#!/usr/bin/env python3
"""Generate the deterministic demo dataset.

The dataset is synthetic but deliberately structured so that each detector fires on a
realistic pattern, and so that corroboration logic has something to work with (a customer
whose name matches a sanctions entry but whose date of birth and country do not).

Run:  python scripts/generate_demo_data.py
"""

from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "src" / "anjali" / "data" / "samples"
START = datetime(2025, 10, 1, 9, 0)
RNG = random.Random(20261108)

COLUMNS = [
    "txn_id", "timestamp", "amount", "currency", "direction", "txn_type",
    "from_account", "to_account", "from_name", "to_name", "channel",
    "country_from", "country_to", "branch", "device_id", "ip_address", "description",
    "goods_description", "hs_code", "quantity", "unit_price", "benchmark_price",
    "vessel", "route",
]

rows: list[dict[str, object]] = []
_counter = 0


def add(
    *,
    ts: datetime,
    amount: float,
    txn_type: str,
    direction: str = "debit",
    from_account: str = "",
    to_account: str = "",
    from_name: str = "",
    to_name: str = "",
    channel: str = "online",
    country_from: str = "US",
    country_to: str = "US",
    branch: str = "",
    device_id: str = "",
    ip_address: str = "",
    description: str = "",
    **extra: object,
) -> None:
    global _counter
    _counter += 1
    rows.append(
        {
            "txn_id": f"T{_counter:05d}",
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "amount": f"{amount:.2f}",
            "currency": "USD",
            "direction": direction,
            "txn_type": txn_type,
            "from_account": from_account,
            "to_account": to_account,
            "from_name": from_name,
            "to_name": to_name,
            "channel": channel,
            "country_from": country_from,
            "country_to": country_to,
            "branch": branch,
            "device_id": device_id,
            "ip_address": ip_address,
            "description": description,
            "goods_description": extra.get("goods_description", ""),
            "hs_code": extra.get("hs_code", ""),
            "quantity": extra.get("quantity", ""),
            "unit_price": extra.get("unit_price", ""),
            "benchmark_price": extra.get("benchmark_price", ""),
            "vessel": extra.get("vessel", ""),
            "route": extra.get("route", ""),
        }
    )


# --------------------------------------------------------------------------- #
# 1. Structuring — Ravi Menon (ACC-1001)
# --------------------------------------------------------------------------- #
structuring_total = 0.0
for i in range(9):
    amount = round(RNG.uniform(8100, 9850), 2)
    structuring_total += amount
    add(
        ts=START + timedelta(days=i * 2, hours=10 + (i % 4)),
        amount=amount,
        txn_type="cash_deposit",
        direction="credit",
        to_account="ACC-1001",
        to_name="Ravi Menon",
        channel="teller",
        branch=f"BR-{7 if i % 2 else 12:02d}",
        description="Cash deposit — consulting fees",
    )

# A velocity burst late in the period on the same account.
for i in range(14):
    add(
        ts=START + timedelta(days=70, minutes=i * 11),
        amount=round(RNG.uniform(1800, 4200), 2),
        txn_type="p2p",
        from_account="ACC-1001",
        to_account=f"ACC-P2P-{i % 4}",
        from_name="Ravi Menon",
        channel="mobile",
        device_id="DEV-RAVI-1",
        ip_address="198.51.100.23",
        description="Outbound P2P transfer",
    )

# --------------------------------------------------------------------------- #
# 2. Layering + TBML + high-risk geography — Acme Global Trading (ACC-2001)
# --------------------------------------------------------------------------- #
for i in range(4):
    t0 = START + timedelta(days=12 + i * 9, hours=9)
    add(
        ts=t0,
        amount=round(RNG.uniform(95000, 130000), 2),
        txn_type="wire",
        direction="credit",
        from_account=f"ACC-AE-{i:02d}",
        to_account="ACC-2001",
        from_name="Gulf Bridge General Trading FZE",
        to_name="Acme Global Trading LLC",
        channel="branch",
        country_from="AE",
        country_to="US",
        branch="BR-02",
        description="Inbound wire — 'equipment supply'",
    )
    inbound = float(rows[-1]["amount"])
    add(
        ts=t0 + timedelta(hours=3),
        amount=round(inbound * 0.97, 2),
        txn_type="wire",
        from_account="ACC-2001",
        to_account=f"ACC-TR-{i:02d}",
        from_name="Acme Global Trading LLC",
        to_name="Bosphorus Textiles AS",
        channel="online",
        country_from="US",
        country_to="TR",
        description="Onward wire — 'consulting'",
    )
    add(
        ts=t0 + timedelta(hours=6),
        amount=round(inbound * 0.955, 2),
        txn_type="wire",
        from_account=f"ACC-TR-{i:02d}",
        to_account=f"ACC-IR-{i:02d}",
        to_name="Persian Gulf Metals Co",
        channel="online",
        country_from="TR",
        country_to="IR",
        description="Layering leg",
    )

# Trade-finance invoice with a large price deviation (TBML).
for i in range(2):
    add(
        ts=START + timedelta(days=30 + i * 20),
        amount=210000.00,
        txn_type="letter_of_credit",
        from_account="ACC-2001",
        to_account="ACC-HK-01",
        from_name="Acme Global Trading LLC",
        to_name="Golden Lotus Holdings Ltd",
        channel="branch",
        country_from="US",
        country_to="HK",
        branch="BR-02",
        description="LC settlement — industrial press bearings",
        goods_description="Industrial press bearings",
        hs_code="8482.10",
        quantity="1000",
        unit_price="210.00",
        benchmark_price="78.00",
        vessel="MV Eastern Star",
        route="CNSHA-HKHKG-AEJEA",
    )

# --------------------------------------------------------------------------- #
# 3. Round-tripping — Blue Harbor Holdings (ACC-3001 → 3002 → 3003 → 3001)
# --------------------------------------------------------------------------- #
for i in range(3):
    t0 = START + timedelta(days=40 + i * 14, hours=10)
    amount = 250000.0 - i * 1000
    add(ts=t0, amount=amount, txn_type="wire", from_account="ACC-3001", to_account="ACC-3002",
        from_name="Blue Harbor Holdings Ltd", to_name="Coral Reef Ventures Ltd",
        channel="online", country_to="AE", description="Investment tranche")
    add(ts=t0 + timedelta(days=3), amount=amount - 2500, txn_type="wire",
        from_account="ACC-3002", to_account="ACC-3003", from_name="Coral Reef Ventures Ltd",
        to_name="Silverline Nominees Ltd", channel="online", country_from="AE", country_to="CY",
        description="Nominee allocation")
    add(ts=t0 + timedelta(days=7), amount=amount - 5000, txn_type="wire",
        direction="credit", from_account="ACC-3003", to_account="ACC-3001",
        from_name="Silverline Nominees Ltd", to_name="Blue Harbor Holdings Ltd",
        channel="online", country_from="CY", country_to="US", description="Return of capital")

# --------------------------------------------------------------------------- #
# 4. Mule cluster — five accounts on one device and IP
# --------------------------------------------------------------------------- #
for i in range(18):
    acct = f"ACC-40{i % 5 + 1:02d}"
    add(
        ts=START + timedelta(days=50 + i // 3, hours=9 + i % 9),
        amount=round(RNG.uniform(350, 1900), 2),
        txn_type="p2p",
        direction="credit",
        from_account=f"ACC-VICTIM-{i:02d}",
        to_account=acct,
        from_name=f"Retail Payer {i}",
        to_name=f"Holder {i % 5}",
        channel="mobile",
        device_id="DEV-SHARED-77",
        ip_address="203.0.113.77",
        description="Marketplace payout",
    )

# --------------------------------------------------------------------------- #
# 5. Dormant reactivation — Sofia Almeida (ACC-6001)
# --------------------------------------------------------------------------- #
for i in range(4):
    add(ts=START + timedelta(days=i * 4), amount=round(RNG.uniform(120, 380), 2),
        txn_type="card", from_account="ACC-6001", to_account="MERCHANT-01",
        from_name="Sofia Almeida", description="Card purchase")
for i in range(3):
    add(
        ts=START + timedelta(days=250 + i),
        amount=52000.0 + i * 3000,
        txn_type="wire",
        from_account="ACC-6001",
        to_account="ACC-PA-01",
        from_name="Sofia Almeida",
        to_name="Meridian Capital Partners SA",
        channel="online",
        country_to="PA",
        description="Property investment",
    )

# --------------------------------------------------------------------------- #
# 6. Travel-rule threshold avoidance — Pavel Novak (ACC-7001)
# --------------------------------------------------------------------------- #
for i in range(6):
    add(ts=START + timedelta(days=18 + i * 3, hours=11), amount=round(RNG.uniform(2600, 2950), 2),
        txn_type="wire", from_account="ACC-7001", to_account=f"ACC-DE-{i:02d}",
        from_name="Pavel Novak", to_name="Rhein Handel GmbH", channel="online",
        country_to="DE", description="Supplier payment — split invoice")

# --------------------------------------------------------------------------- #
# 7. Cash intensity — Vikram Cash Business (ACC-8001) vs peers
# --------------------------------------------------------------------------- #
for i in range(12):
    add(ts=START + timedelta(days=i * 2, hours=15), amount=round(RNG.uniform(1400, 2600), 2),
        txn_type="cash_withdrawal", from_account="ACC-8001", to_account="MERCHANT-03",
        from_name="Vikram Cash Business", channel="branch", branch="BR-01",
        description="Cash withdrawal")

# --------------------------------------------------------------------------- #
# 7b. A clean CTR trigger — one reportable cash deposit, no structuring
# --------------------------------------------------------------------------- #
add(
    ts=START + timedelta(days=64, hours=11),
    amount=14250.00,
    txn_type="cash_deposit",
    direction="credit",
    to_account="ACC-9001",
    to_name="Nadia Haddad",
    channel="teller",
    branch="BR-05",
    description="Cash deposit — sale of vehicle",
)

# --------------------------------------------------------------------------- #
# 8. Benign traffic for peers (drives the peer-group baseline)
# --------------------------------------------------------------------------- #
for name, acct in [("Priya Sharma", "ACC-5001"), ("Daniel Okafor", "ACC-5002"), ("Elena Rossi", "ACC-5003")]:
    for day in range(0, 90, 2):
        add(ts=START + timedelta(days=day, hours=8), amount=2450.00, txn_type="ach",
            direction="credit", from_account="ACC-PAYROLL", to_account=acct,
            from_name="Northwind Payroll Inc", to_name=name, channel="ach",
            description="Salary")
        add(ts=START + timedelta(days=day, hours=13), amount=round(RNG.uniform(35, 240), 2),
            txn_type="card", from_account=acct, to_account="MERCHANT-02", from_name=name,
            channel="card", description="Card purchase")
    if acct == "ACC-5002":
        for day in range(0, 90, 30):
            add(ts=START + timedelta(days=day, hours=10), amount=1450.00, txn_type="ach",
                from_account=acct, to_account="LANDLORD-LLC", from_name=name, channel="ach",
                description="Rent")

# --------------------------------------------------------------------------- #
# Customers
# --------------------------------------------------------------------------- #
CUSTOMERS = [
    ("CUST-1001", "Ravi Menon", "individual", "US", "1990-11-04", "consulting", "no", "high",
     "2023-04-12", "12000", "18", "consulting fees", "ACC-1001"),
    ("CUST-2001", "Acme Global Trading LLC", "business", "US", "", "industrial equipment", "no", "high",
     "2022-08-30", "150000", "25", "equipment trading", "ACC-2001"),
    ("CUST-3001", "Blue Harbor Holdings Ltd", "business", "US", "", "holding company", "no", "high",
     "2024-02-14", "200000", "10", "investment returns", "ACC-3001|ACC-3002|ACC-3003"),
    ("CUST-4001", "Holder 0", "individual", "US", "1996-03-22", "gig work", "no", "medium",
     "2025-08-01", "2500", "30", "marketplace income", "ACC-4001"),
    ("CUST-4002", "Holder 1", "individual", "US", "1994-01-11", "gig work", "no", "medium",
     "2025-08-03", "2500", "30", "marketplace income", "ACC-4002"),
    ("CUST-4003", "Holder 2", "individual", "US", "1991-06-07", "gig work", "no", "medium",
     "2025-08-04", "2500", "30", "marketplace income", "ACC-4003"),
    ("CUST-4004", "Holder 3", "individual", "US", "1998-10-02", "gig work", "no", "medium",
     "2025-08-06", "2500", "30", "marketplace income", "ACC-4004"),
    ("CUST-4005", "Holder 4", "individual", "US", "1987-03-19", "gig work", "no", "medium",
     "2025-08-08", "2500", "30", "marketplace income", "ACC-4005"),
    ("CUST-6001", "Sofia Almeida", "individual", "US", "1979-07-14", "architect", "no", "medium",
     "2020-01-09", "8000", "20", "salary", "ACC-6001"),
    ("CUST-7001", "Pavel Novak", "individual", "US", "1988-12-01", "import/export", "no", "medium",
     "2021-11-23", "20000", "15", "trading income", "ACC-7001"),
    ("CUST-8001", "Vikram Cash Business", "individual", "US", "1983-05-30", "consulting", "no", "high",
     "2023-09-05", "15000", "25", "cash sales", "ACC-8001"),
    ("CUST-9001", "Nadia Haddad", "individual", "US", "1986-08-12", "teacher", "no", "low",
     "2022-05-18", "4000", "10", "salary", "ACC-9001"),
    ("CUST-5001", "Priya Sharma", "individual", "US", "1992-02-18", "teacher", "no", "low",
     "2019-06-11", "3000", "20", "salary", "ACC-5001"),
    ("CUST-5002", "Daniel Okafor", "individual", "US", "1985-09-09", "engineer", "no", "low",
     "2018-03-27", "4000", "18", "salary", "ACC-5002"),
    ("CUST-5003", "Elena Rossi", "individual", "US", "1994-04-25", "designer", "no", "low",
     "2021-07-19", "3500", "22", "salary", "ACC-5003"),
]

CUSTOMER_COLUMNS = [
    "customer_id", "name", "customer_type", "country", "dob", "industry", "pep", "risk_rating",
    "onboarded_at", "expected_monthly_volume", "expected_txn_count", "source_of_funds", "accounts",
]


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / "demo_transactions.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(OUT / "demo_customers.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(CUSTOMER_COLUMNS)
        writer.writerows(CUSTOMERS)
    print(f"wrote {len(rows)} transactions and {len(CUSTOMERS)} customers to {OUT}")


if __name__ == "__main__":
    main()
