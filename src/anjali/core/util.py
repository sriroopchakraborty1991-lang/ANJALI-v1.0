"""Shared helpers: time, money, normalisation, statistics, JSON I/O.

Deliberately dependency-free (stdlib only) so the air-gapped build stays tiny.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import tempfile
import unicodedata
from collections.abc import Iterable, Sequence
from datetime import date, datetime, timezone
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Any, TypeVar

T = TypeVar("T")

CENT = Decimal("0.01")


# --------------------------------------------------------------------------- #
# Time
# --------------------------------------------------------------------------- #
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def today() -> date:
    return datetime.now(timezone.utc).date()


def parse_date(value: Any) -> date | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value).strip()
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%Y%m%d"):
        try:
            return datetime.strptime(text[: len(fmt) + 2].strip(), fmt).date()
        except ValueError:
            continue
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        return None


def business_days_between(start: date, end: date) -> int:
    """Inclusive Mon-Fri day count — used for DAML / filing clock maths."""
    if end < start:
        return 0
    days = 0
    cur = start
    while cur <= end:
        if cur.weekday() < 5:
            days += 1
        cur = date.fromordinal(cur.toordinal() + 1)
    return days


def add_business_days(start: date, n: int) -> date:
    cur, added = start, 0
    while added < n:
        cur = date.fromordinal(cur.toordinal() + 1)
        if cur.weekday() < 5:
            added += 1
    return cur


# --------------------------------------------------------------------------- #
# Money
# --------------------------------------------------------------------------- #
def money(value: Any) -> Decimal:
    if isinstance(value, Decimal):
        return value.quantize(CENT, rounding=ROUND_HALF_UP)
    return Decimal(str(value)).quantize(CENT, rounding=ROUND_HALF_UP)


def fmt_money(value: Decimal | float | int, currency: str = "") -> str:
    q = money(value)
    body = f"{q:,.2f}"
    return f"{currency} {body}".strip() if currency else body


# --------------------------------------------------------------------------- #
# Text normalisation
# --------------------------------------------------------------------------- #
_DIACRITICS = re.compile(r"[\u0300-\u036f]")
_NON_ALNUM = re.compile(r"[^a-z0-9 ]+")
_WS = re.compile(r"\s+")

# Corporate suffixes stripped before name matching so "Acme Ltd" ≈ "ACME LIMITED".
CORP_SUFFIXES = {
    "ltd", "limited", "llc", "l l c", "inc", "incorporated", "corp", "corporation",
    "co", "company", "gmbh", "ag", "sa", "s a", "bv", "nv", "plc", "pte", "pty",
    "oy", "ab", "as", "spa", "srl", "kg", "se", "holding", "holdings", "group",
    "international", "intl", "trading", "enterprises", "imports", "exports",
}

# Honorifics / generational markers that add noise to individual matching.
NAME_NOISE = {
    "mr", "mrs", "ms", "miss", "dr", "prof", "shri", "sri", "smt", "haji", "hajji",
    "sheikh", "shaikh", "bin", "binti", "bint", "al", "el", "jr", "sr", "ii", "iii",
    "iv", "phd", "md",
}


def strip_accents(text: str) -> str:
    return _DIACRITICS.sub("", unicodedata.normalize("NFKD", text))


def normalise_name(name: str, *, drop_noise: bool = True) -> str:
    """Aggressive but deterministic normalisation used by screening + graph keys."""
    text = strip_accents(str(name)).lower()
    text = text.replace("&", " and ")
    text = _NON_ALNUM.sub(" ", text)
    tokens = [t for t in text.split() if t]
    if drop_noise:
        tokens = [t for t in tokens if t not in NAME_NOISE and t not in CORP_SUFFIXES]
    return _WS.sub(" ", " ".join(tokens)).strip()


def name_tokens(name: str) -> list[str]:
    return [t for t in normalise_name(name).split() if t]


def slug(text: str, max_len: int = 60) -> str:
    return _WS.sub("-", _NON_ALNUM.sub(" ", strip_accents(str(text)).lower())).strip("-")[:max_len]


def truncate(text: str, n: int = 400, ellipsis: str = "…") -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1].rstrip() + ellipsis


def tokenize(text: str) -> list[str]:
    return re.findall(r"[a-z0-9§.]+", strip_accents(str(text)).lower())


STOPWORDS = {
    "a", "an", "the", "of", "to", "in", "on", "for", "and", "or", "is", "are", "be",
    "by", "with", "as", "at", "from", "that", "this", "it", "its", "any", "all",
    "must", "shall", "may", "such", "under", "which", "who", "where", "when", "what",
    "how", "than", "then", "also", "not", "no", "if", "into", "their", "has", "have",
    # question scaffolding — never useful retrieval signal
    "can", "could", "should", "would", "will", "we", "our", "us", "you", "your", "i",
    "my", "me", "do", "does", "did", "need", "needs", "please", "tell", "show", "give",
    "about", "there", "these", "those", "was", "were", "been", "being", "so", "but",
    "get", "got", "make", "made", "just", "only", "very", "more", "most", "much",
    "long", "many", "some", "other", "same", "own", "up", "out", "over", "after",
    "before", "during", "between", "within", "without", "per", "via", "each", "both",
}


def content_tokens(text: str) -> list[str]:
    return [t for t in tokenize(text) if t not in STOPWORDS and len(t) > 1]


# --------------------------------------------------------------------------- #
# Hashing / ids
# --------------------------------------------------------------------------- #
def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def stable_id(*parts: Any, prefix: str = "", length: int = 12) -> str:
    joined = "|".join(str(p) for p in parts)
    digest = sha256_hex(joined)[:length]
    return f"{prefix}{digest}" if prefix else digest


# --------------------------------------------------------------------------- #
# Statistics (small, robust estimators — no numpy)
# --------------------------------------------------------------------------- #
def median(values: Sequence[float]) -> float:
    vals = sorted(float(v) for v in values)
    n = len(vals)
    if n == 0:
        return 0.0
    mid = n // 2
    return float(vals[mid]) if n % 2 else (vals[mid - 1] + vals[mid]) / 2.0


def mean(values: Sequence[float]) -> float:
    return float(sum(values)) / len(values) if values else 0.0


def stdev(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0
    mu = mean(values)
    return math.sqrt(sum((v - mu) ** 2 for v in values) / (len(values) - 1))


def mad(values: Sequence[float]) -> float:
    """Median absolute deviation — robust to outliers, unlike stdev."""
    if not values:
        return 0.0
    med = median(values)
    return median([abs(v - med) for v in values])


def modified_zscore(value: float, baseline: Sequence[float]) -> float:
    """Iglewicz–Hoaglin robust z-score. >3.5 conventionally signals an outlier."""
    if len(baseline) < 3:
        return 0.0
    med = median(baseline)
    dispersion = mad(baseline)
    if dispersion == 0:
        dispersion = stdev(baseline) or 1e-9
    return 0.6745 * (value - med) / dispersion


def percentile(values: Sequence[float], pct: float) -> float:
    if not values:
        return 0.0
    vals = sorted(values)
    k = (len(vals) - 1) * (pct / 100.0)
    lo, hi = math.floor(k), math.ceil(k)
    if lo == hi:
        return float(vals[int(k)])
    return float(vals[lo] * (hi - k) + vals[hi] * (k - lo))


def shannon_entropy(values: Iterable[Any]) -> float:
    counts: dict[Any, int] = {}
    total = 0
    for v in values:
        counts[v] = counts.get(v, 0) + 1
        total += 1
    if total <= 1 or len(counts) <= 1:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


def safe_div(num: float, den: float, default: float = 0.0) -> float:
    return default if not den else num / den


# --------------------------------------------------------------------------- #
# Files
# --------------------------------------------------------------------------- #
def atomic_write(path: Path, content: str, *, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_json(path: Path) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path: Path, payload: Any, *, indent: int = 2) -> None:
    atomic_write(path, json.dumps(payload, indent=indent, default=str, ensure_ascii=False) + "\n")


def which(cmd: str) -> str | None:
    from shutil import which as _which

    return _which(cmd)
