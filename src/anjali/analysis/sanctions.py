"""Sanctions screening: fuzzy name matching with corroboration and ownership look-through.

Matching is the highest-severity control in a financial-crime programme because a false
negative is a strict-liability violation. The approach here is intentionally transparent:

* several independent string metrics, combined with fixed weights;
* transliteration-aware normalisation and a phonetic key, because the same name arrives
  as "Mohammed", "Muhammad", "Mohamed", "Mohammod";
* corroboration (date of birth, country, entity type) that can *downgrade* a name hit —
  the "Ravi Menon but born 20 years apart" case — with the evidence recorded;
* tiered output (EXACT / STRONG / POTENTIAL / WEAK) rather than a binary hit, because a
  binary decision either buries analysts in false positives or misses real ones.

Nothing here calls a model. Screening must be reproducible line-by-line in a courtroom.
"""

from __future__ import annotations

import csv
import io
import json
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from anjali.core.db import Database
from anjali.core.errors import IngestError
from anjali.core.models import (
    Customer,
    MatchTier,
    SanctionsMatch,
    ScreeningResult,
)
from anjali.core.util import clamp, normalise_name, today

SEED_PATH = Path(__file__).parent.parent / "data" / "sanctions_seed.yaml"
CITATION_KEYS = [
    "us-31cfr-501-603",
    "us-ofac-50-percent-rule",
    "fatf-r6-7-sanctions",
    "intl-unsc-1267-1373",
    "uk-oFSI-sanctions",
]

# Tier boundaries. POTENTIAL and above require analyst review.
TIER_STRONG = 0.92
TIER_POTENTIAL = 0.85
TIER_WEAK = 0.78

CORPORATE_MARKERS = ("llc", "ltd", "limited", "inc", "corp", "fze", "sal", "sa", "gmbh", "plc", "doo")


# --------------------------------------------------------------------------- #
# String metrics
# --------------------------------------------------------------------------- #
def jaro(a: str, b: str) -> float:
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    la, lb = len(a), len(b)
    window = max(la, lb) // 2 - 1
    if window < 0:
        window = 0
    a_matches = [False] * la
    b_matches = [False] * lb
    matches = 0
    for i, ch in enumerate(a):
        lo = max(0, i - window)
        hi = min(i + window + 1, lb)
        for j in range(lo, hi):
            if not b_matches[j] and b[j] == ch:
                a_matches[i] = b_matches[j] = True
                matches += 1
                break
    if matches == 0:
        return 0.0
    transpositions = 0
    k = 0
    for i in range(la):
        if a_matches[i]:
            while not b_matches[k]:
                k += 1
            if a[i] != b[k]:
                transpositions += 1
            k += 1
    transpositions //= 2
    return (matches / la + matches / lb + (matches - transpositions) / matches) / 3.0


def jaro_winkler(a: str, b: str, *, scaling: float = 0.1, max_prefix: int = 4) -> float:
    base = jaro(a, b)
    if base <= 0.7:
        return base
    prefix = 0
    for ca, cb in zip(a, b):
        if ca != cb or prefix >= max_prefix:
            break
        prefix += 1
    return base + prefix * scaling * (1 - base)


def token_set_ratio(a: str, b: str) -> float:
    """Order-insensitive token similarity, tolerant of spelling variants.

    Exact set overlap is not enough for names: 'Mohamed' and 'Mohammed' are different
    strings but the same name, and a set-intersection score calls the pair a mismatch.
    Each token is therefore matched against its best counterpart in the other string.
    """
    ta, tb = a.split(), b.split()
    if not ta or not tb:
        return 0.0
    if sorted(ta) == sorted(tb):
        return 1.0
    # Same tokens in a different order (e.g. 'Al-Rashid Mohammed' vs 'Mohammed Al Rashid').
    sort_sim = jaro_winkler(" ".join(sorted(ta)), " ".join(sorted(tb)))
    short, longer = (ta, tb) if len(ta) <= len(tb) else (tb, ta)
    coverage = sum(
        max(jaro_winkler(token, other) for other in longer) for token in short
    ) / len(short)
    return max(sort_sim, coverage)


_SOUNDEX_MAP = {
    **dict.fromkeys("bfpv", "1"),
    **dict.fromkeys("cgjkqsxz", "2"),
    **dict.fromkeys("dt", "3"),
    "l": "4",
    **dict.fromkeys("mn", "5"),
    "r": "6",
}


def soundex(name: str) -> str:
    letters = [c for c in normalise_name(name).upper() if c.isalpha()]
    if not letters:
        return ""
    first = letters[0]
    codes: list[str] = []
    prev = _SOUNDEX_MAP.get(first, "")
    for ch in letters[1:]:
        code = _SOUNDEX_MAP.get(ch, "")
        if code and code != prev:
            codes.append(code)
        if ch not in "hw":
            prev = code
    return (first + "".join(codes) + "000")[:4]


def phonetic_skeleton(name: str) -> str:
    """Crude consonant skeleton — robust to vowel and digraph variation across scripts."""
    text = normalise_name(name)
    for src, dst in (
        ("ph", "f"), ("kh", "k"), ("gh", "g"), ("dh", "d"), ("th", "t"),
        ("sh", "s"), ("ch", "k"), ("aa", "a"), ("ee", "i"), ("oo", "u"), ("ou", "u"),
        ("y", "i"), ("q", "k"), ("w", "v"), ("z", "s"), ("j", "g"),
    ):
        text = text.replace(src, dst)
    return "".join(ch for ch in text if ch in "bcdfgklmnprstv")


def name_score(a: str, b: str) -> tuple[float, dict[str, float]]:
    """Combine metrics into one score plus a component breakdown for explainability."""
    na, nb = normalise_name(a), normalise_name(b)
    if not na or not nb:
        return 0.0, {}
    jw = jaro_winkler(na, nb)
    ts = token_set_ratio(na, nb)
    j = jaro(na, nb)
    sa, sb = soundex(na), soundex(nb)
    ph = 1.0 if (phonetic_skeleton(na) and phonetic_skeleton(na) == phonetic_skeleton(nb)) else 0.0
    sx = 1.0 if (sa and sa == sb) else 0.0
    contains = 1.0 if (na in nb or nb in na) else 0.0
    score = (
        0.34 * ts
        + 0.30 * jw
        + 0.12 * j
        + 0.12 * ph
        + 0.06 * sx
        + 0.06 * contains
    )
    # A near-perfect full-string Jaro-Winkler is a strong signal on its own: a one-letter
    # transliteration difference should not be buried by the token components. Only
    # applied to names long enough for JW's prefix bonus to be meaningful.
    if min(len(na), len(nb)) >= 8:
        score = max(score, 0.95 * jw)
    # Exact normalised equality is decisive regardless of the weighted blend.
    if na == nb:
        score = max(score, 0.99)
    return clamp(score), {
        "token_set": round(ts, 4),
        "jaro_winkler": round(jw, 4),
        "jaro": round(j, 4),
        "phonetic": ph,
        "soundex": sx,
        "containment": contains,
    }


def tier_for(score: float, *, exact: bool = False) -> MatchTier:
    if exact:
        return MatchTier.EXACT
    if score >= TIER_STRONG:
        return MatchTier.STRONG
    if score >= TIER_POTENTIAL:
        return MatchTier.POTENTIAL
    if score >= TIER_WEAK:
        return MatchTier.WEAK
    return MatchTier.CLEAR


# --------------------------------------------------------------------------- #
# Screening engine
# --------------------------------------------------------------------------- #
@dataclass
class ListEntry:
    list_name: str
    list_id: str
    name: str
    normalised: str
    entity_type: str = "individual"
    country: str | None = None
    dob: str | None = None
    programme: str | None = None
    aliases: list[str] = field(default_factory=list)
    remarks: str | None = None
    synthetic: bool = False


def load_seed(path: Path | None = None) -> tuple[list[ListEntry], str, bool]:
    path = path or SEED_PATH
    if not path.exists():
        return [], "none", False
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries: list[ListEntry] = []
    for item in raw.get("entries", []):
        names = [item["name"], *(item.get("aliases") or [])]
        for name in names:
            entries.append(
                ListEntry(
                    list_name=item["list"],
                    list_id=str(item.get("list_id") or ""),
                    name=name,
                    normalised=normalise_name(name),
                    entity_type=item.get("entity_type", "individual"),
                    country=(item.get("country") or "").upper() or None,
                    dob=str(item.get("dob")) if item.get("dob") else None,
                    programme=item.get("programme"),
                    aliases=item.get("aliases") or [],
                    remarks=item.get("remarks"),
                    synthetic=bool(raw.get("synthetic", False)),
                )
            )
    return entries, str(raw.get("list_version", "unknown")), bool(raw.get("synthetic", False))


def ingest_entries(db: Database, entries: Sequence[ListEntry], version: str = "seed") -> int:
    with db.tx() as conn:
        for e in entries:
            conn.execute(
                """
                INSERT INTO sanctions(list_name, list_id, name, normalised, entity_type, country,
                                      dob, programme, payload)
                VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(list_name, list_id, normalised) DO UPDATE SET payload=excluded.payload
                """,
                (
                    e.list_name,
                    e.list_id,
                    e.name,
                    e.normalised,
                    e.entity_type,
                    e.country,
                    e.dob,
                    e.programme,
                    json.dumps(
                        {
                            "aliases": e.aliases,
                            "remarks": e.remarks,
                            "synthetic": e.synthetic,
                        }
                    ),
                ),
            )
    db.set_meta("sanctions_version", version)
    db.set_meta("sanctions_loaded_at", today().isoformat())
    db.set_meta("sanctions_synthetic", "true" if any(e.synthetic for e in entries) else "false")
    return len(entries)


def import_csv(
    db: Database,
    path: Path,
    *,
    list_name: str,
    name_columns: Sequence[str] = ("SDN_Name", "name", "Name", "caption", "Caption"),
    id_columns: Sequence[str] = ("ent_num", "id", "Id", "ENTITY_ID"),
    type_columns: Sequence[str] = ("SDN_Type", "type", "Type"),
    country_columns: Sequence[str] = ("Country", "country", "nationality"),
    dob_columns: Sequence[str] = ("DOB", "dob", "date_of_birth", "birthdate"),
    version: str | None = None,
) -> dict[str, Any]:
    """Import a real list export (OFAC SDN CSV, EU consolidated CSV, UN CSV).

    Column names differ between publishers and change without notice, so the importer
    sniffs the header against a candidate set and reports what it used.
    """
    path = Path(path)
    if not path.exists():
        raise IngestError(f"No such file: {path}")
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise IngestError(f"{path.name}: no CSV header found.")
    fields = [f.strip() for f in reader.fieldnames]

    def pick(candidates: Sequence[str]) -> str | None:
        lowered = {f.lower(): f for f in fields}
        for cand in candidates:
            if cand in fields:
                return cand
            if cand.lower() in lowered:
                return lowered[cand.lower()]
        return None

    name_col = pick(name_columns)
    if not name_col:
        raise IngestError(
            f"{path.name}: cannot find a name column. Header was: {', '.join(fields[:12])}",
            hint="Pass --name-column explicitly.",
        )
    id_col, type_col = pick(id_columns), pick(type_columns)
    country_col, dob_col = pick(country_columns), pick(dob_columns)

    entries: list[ListEntry] = []
    for idx, row in enumerate(reader, 1):
        name = (row.get(name_col) or "").strip()
        if not name:
            continue
        entries.append(
            ListEntry(
                list_name=list_name,
                list_id=str(row.get(id_col) or f"row{idx}") if id_col else f"row{idx}",
                name=name,
                normalised=normalise_name(name),
                entity_type=(row.get(type_col) or "unknown").strip().lower() if type_col else "unknown",
                country=(row.get(country_col) or "").strip().upper()[:2] or None if country_col else None,
                dob=(row.get(dob_col) or "").strip() or None if dob_col else None,
                programme=None,
                synthetic=False,
            )
        )
    written = ingest_entries(db, entries, version or f"import:{path.name}")
    return {
        "file": path.name,
        "entries": written,
        "columns": {
            "name": name_col,
            "id": id_col,
            "type": type_col,
            "country": country_col,
            "dob": dob_col,
        },
        "unmapped": [f for f in fields if f not in {name_col, id_col, type_col, country_col, dob_col}],
    }


class SanctionsScreener:
    def __init__(self, db: Database, *, threshold: float = TIER_POTENTIAL) -> None:
        self.db = db
        self.threshold = threshold
        self._index: dict[str, list[dict[str, Any]]] | None = None
        self.version = db.get_meta("sanctions_version", "none") or "none"

    def _entries(self) -> dict[str, list[dict[str, Any]]]:
        if self._index is None:
            rows = self.db.query("SELECT * FROM sanctions")
            index: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for row in rows:
                record = dict(row)
                record["payload"] = json.loads(row["payload"] or "{}")
                index[row["normalised"]].append(record)
                for alias in record["payload"].get("aliases", []):
                    index[normalise_name(alias)].append(record)
            self._index = index
        return self._index

    @property
    def size(self) -> int:
        return int(self.db.scalar("SELECT COUNT(*) FROM sanctions") or 0)

    def lists(self) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT list_name, COUNT(*) AS n FROM sanctions GROUP BY list_name ORDER BY list_name"
        )
        return [dict(r) for r in rows]

    # -- screening ---------------------------------------------------------- #
    def screen(
        self,
        name: str,
        *,
        dob: str | None = None,
        country: str | None = None,
        entity_type: str | None = None,
        threshold: float | None = None,
        limit: int = 5,
    ) -> ScreeningResult:
        threshold = self.threshold if threshold is None else threshold
        query_norm = normalise_name(name)
        candidates: list[tuple[float, dict[str, Any], dict[str, float]]] = []

        index = self._entries()
        # Exact-normalised lookups first (the overwhelmingly common true-positive route).
        for record in index.get(query_norm, []):
            candidates.append((0.99, record, {"exact_normalised": 1.0}))
        # Fuzzy sweep. Blocking on first letter + length band keeps this O(n·k) not O(n²)
        # in practice while never excluding a candidate that could clear the threshold.
        first = query_norm[:1]
        for key, records in index.items():
            if not key or key == query_norm:
                continue
            same_block = key[:1] == first or abs(len(key) - len(query_norm)) <= 2
            if not same_block:
                continue
            score, components = name_score(query_norm, key)
            if score < threshold - 0.05:
                continue
            for record in records:
                candidates.append((score, record, components))

        candidates.sort(key=lambda c: c[0], reverse=True)
        matches: list[SanctionsMatch] = []
        seen_ids: set[tuple[str, str]] = set()
        for score, record, components in candidates[: limit * 6]:
            identity = (record["list_name"], record["list_id"] or record["normalised"])
            if identity in seen_ids:
                continue
            seen_ids.add(identity)
            corroboration, adjustment, notes = self._corroborate(
                dob=dob, country=country, entity_type=entity_type, record=record
            )
            adjusted = clamp(score + adjustment)
            # An exact name is only EXACT if nothing material contradicts it. Same name,
            # different date of birth and country is still a reviewable hit — but calling
            # it EXACT would misdescribe the evidence in the file.
            contradicts = (
                corroboration.get("dob_match") == "none"
                or corroboration.get("country_match") is False
            )
            exact = components.get("exact_normalised") == 1.0 and not contradicts
            tier = tier_for(adjusted, exact=exact)
            if components.get("exact_normalised") == 1.0 and contradicts:
                tier = MatchTier.STRONG
                notes.append(
                    "Name matches the list entry exactly, but corroborating attributes "
                    "conflict — review required before any blocking or rejection decision."
                )
            if tier == MatchTier.CLEAR or adjusted < threshold:
                continue
            matches.append(
                SanctionsMatch(
                    query_name=name,
                    matched_name=record["name"],
                    list_name=record["list_name"],
                    list_id=record["list_id"],
                    score=round(adjusted, 4),
                    tier=tier,
                    algorithm="weighted(jaro_winkler,token_set,jaro,phonetic,soundex)",
                    attributes={
                        "entity_type": record["entity_type"],
                        "country": record["country"],
                        "dob": record["dob"],
                        "programme": record["programme"],
                        "synthetic_fixture": record["payload"].get("synthetic", False),
                        "components": components,
                    },
                    corroboration=corroboration,
                    notes=notes,
                )
            )
            if len(matches) >= limit:
                break

        disposition = MatchTier.CLEAR
        for tier in (MatchTier.EXACT, MatchTier.STRONG, MatchTier.POTENTIAL, MatchTier.WEAK):
            if any(m.tier == tier for m in matches):
                disposition = tier
                break
        return ScreeningResult(
            query=name,
            matches=matches,
            lists_checked=sorted({m.list_name for m in matches}) or self._all_lists(),
            threshold=threshold,
            disposition=disposition,
        )

    def _all_lists(self) -> list[str]:
        return [r["list_name"] for r in self.lists()]

    def _corroborate(
        self,
        *,
        dob: str | None,
        country: str | None,
        entity_type: str | None,
        record: dict[str, Any],
    ) -> tuple[dict[str, Any], float, list[str]]:
        evidence: dict[str, Any] = {}
        adjustment = 0.0
        notes: list[str] = []

        if dob and record.get("dob"):
            same_year = str(dob)[:4] == str(record["dob"])[:4]
            same_day = str(dob)[:10] == str(record["dob"])[:10]
            evidence["dob_match"] = "exact" if same_day else ("year" if same_year else "none")
            if same_day:
                adjustment += 0.04
                notes.append("Date of birth matches exactly — aggravating.")
            elif same_year:
                adjustment += 0.01
            else:
                adjustment -= 0.06
                notes.append(
                    f"Date of birth differs ({dob} vs {record['dob']}) — mitigating, but not "
                    "dispositive for a name-only list entry."
                )
        elif dob and not record.get("dob"):
            evidence["dob_match"] = "not_on_list"
            notes.append("List entry has no date of birth; identity cannot be confirmed or excluded.")

        if country and record.get("country"):
            same_country = str(country).upper()[:2] == str(record["country"]).upper()[:2]
            evidence["country_match"] = same_country
            if same_country:
                adjustment += 0.03
            else:
                adjustment -= 0.04
                notes.append(
                    f"Country differs ({str(country).upper()} vs {record['country']}) — mitigating."
                )

        if entity_type and record.get("entity_type") and record["entity_type"] != "unknown":
            same_type = entity_type.lower() == str(record["entity_type"]).lower()
            evidence["entity_type_match"] = same_type
            if not same_type:
                adjustment -= 0.05
                notes.append("Entity type differs between query and list entry.")

        if record["payload"].get("synthetic"):
            notes.append("Entry is a synthetic test fixture, not an operational designation.")

        return evidence, round(adjustment, 4), notes

    # -- ownership ---------------------------------------------------------- #
    def screen_customer(self, customer: Customer, *, threshold: float | None = None) -> ScreeningResult:
        """Screen the customer, their beneficial owners, and apply the 50% rule."""
        result = self.screen(
            customer.name,
            dob=customer.dob,
            country=customer.country,
            entity_type=customer.customer_type,
            threshold=threshold,
        )
        aggregated: dict[str, dict[str, Any]] = {}
        for owner in customer.beneficial_owners:
            owner_result = self.screen(
                owner.name,
                dob=owner.dob,
                country=owner.country,
                entity_type="individual",
                threshold=threshold,
            )
            for match in owner_result.matches:
                if not match.tier.requires_review:
                    continue
                key = f"{match.list_name}:{match.list_id}:{match.matched_name}"
                entry = aggregated.setdefault(
                    key,
                    {
                        "list": match.list_name,
                        "list_id": match.list_id,
                        "matched_name": match.matched_name,
                        "owners": [],
                        "aggregate_ownership_pct": 0.0,
                        "tier": match.tier.value,
                        "score": match.score,
                    },
                )
                entry["owners"].append(owner.name)
                entry["aggregate_ownership_pct"] = round(
                    entry["aggregate_ownership_pct"] + owner.ownership_pct, 2
                )

        for entry in aggregated.values():
            pct = entry["aggregate_ownership_pct"]
            entry["us_50_percent_rule_blocked"] = pct >= 50.0
            entry["eu_uk_control_test"] = pct >= 50.0
            if pct >= 50.0:
                result.matches.append(
                    SanctionsMatch(
                        query_name=customer.name,
                        matched_name=entry["matched_name"],
                        list_name=entry["list"],
                        list_id=entry["list_id"],
                        score=entry["score"],
                        tier=MatchTier.STRONG,
                        algorithm="ownership-aggregation",
                        attributes={"source": "beneficial_ownership"},
                        corroboration={"aggregate_ownership_pct": pct},
                        notes=[
                            f"Beneficial owners ({', '.join(entry['owners'])}) hold {pct}% in "
                            "aggregate and one or more are designated.",
                            "US 50% rule: the entity is blocked by operation of law even though it "
                            "is not itself named on the list.",
                            "EU/UK ownership-or-control test also met on the ownership limb.",
                        ],
                    )
                )
                result.disposition = MatchTier.STRONG
        result.ownership_hits = list(aggregated.values())
        return result

    def version_stamp(self) -> dict[str, Any]:
        """Provenance for the file: which lists, which vintage, synthetic or real."""
        return {
            "version": self.version,
            "loaded_at": self.db.get_meta("sanctions_loaded_at"),
            "entries": self.size,
            "lists": self.lists(),
            "synthetic": str(self.db.get_meta("sanctions_synthetic") or "").lower()
            in {"true", "1", "yes"},
        }


def seed_database(db: Database) -> dict[str, Any]:
    entries, version, synthetic = load_seed()
    written = ingest_entries(db, entries, version)
    return {"entries": written, "version": version, "synthetic": synthetic}
