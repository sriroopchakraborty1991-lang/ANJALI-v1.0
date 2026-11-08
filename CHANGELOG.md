# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses semantic
versioning.

## [0.1.0] — 2026-11-08

First public release. Everything below is new; the notes describe what the release actually does
rather than what it aspires to.

### Added

**Corpus and retrieval**
- 76 regulatory provisions across the US (30), EU (18), UK (10), FATF (11) and international (7)
  collections, each with citation, regulator, effective dates, successors, obligations, source URL
  and full text.
- Temporal retrieval: `--as-of` scoping, amendment/successor tracking, and `[NOT-YET-IN-FORCE]`
  labelling for instruments adopted but not yet applicable (AMLD6, AMLR).
- SQLite FTS5 index with ontology expansion, tag/title boosts, jurisdiction multipliers and MMR
  (`max 2 chunks per document`), plus a local `hashtfidf-v1` embedder — no network, no model
  downloads.
- `kb ingest/add/search/show/verify/timeline/stats/corpus/export`, and key-level citation
  resolution with `strict` mode used as a test invariant.

**Detection and risk**
- 11 deterministic detectors: structuring, smurfing, layering, round-tripping, mule networks, TBML
  price deviation, velocity anomaly, dormant reactivation, high-risk geography, threshold
  avoidance, cash intensity — each with reasoning steps, actions and citation keys.
- Five-dimension weighted risk (geographic 0.22, product 0.16, customer 0.18, behavioral 0.30,
  channel 0.14), per-jurisdiction multipliers, stated severity floors.
- Entity graph with flow-weighted PageRank, communities, cycles up to 5 hops and DOT/mermaid
  export.

**Screening**
- Fuzzy screening across OFAC SDN / EU Consolidated / UN / UK OFSI shapes: token-set,
  Jaro-Winkler, Jaro, phonetic, Soundex and containment, plus a full-string Jaro-Winkler floor for
  transliteration variants.
- Corroboration on DOB, country and entity type; exact names with contradicting attributes are
  reported as STRONG, not EXACT.
- Beneficial-owner screening with the 50% ownership rule; bulk CSV screening; list provenance in
  every result.
- Synthetic seed list (24 entries, 4 list shapes) and `sanctions import` for real data.

**Compliance artefacts**
- 10 encoded US/EU/UK conflicts with positions, divergence and operational resolution, mapped to
  case typologies.
- SAR/STR drafting with subject attribution through the customer master, six-element FinCEN/FFIEC
  narrative, jurisdiction-specific due dates, goAML export and a 10-gate quality score.
- CTR worksheet aggregating cash per account and business day with a 15-day due date.

**Adversarial simulation**
- 11 injected typologies plus a benign baseline containing deliberate near-misses (cash café,
  landlord fan-in, parity-priced invoices, shared family device).
- Recall per typology, false-positive count, reproducibility by seed, remediation notes for gaps
  and a CI gate (`--fail-under`).

**Agent**
- 10 tools, an offline deterministic pipeline and a bounded ReAct loop for BYOK providers.
- System prompt encoding the ten output rules (cite, reason, risk level, `[SANCTIONS ALERT]`,
  confidence, audit, cross-jurisdiction, FATF risk-based approach, SAR narrative, human sign-off),
  enforced outside the model by a citation guardrail.

**Audit**
- Hash-chained JSONL trail with `verify`, `stats`, `log`, `export` and a five-year retention
  report; head hash printed in command output.

**CLI**
- 20+ commands with `--json` throughout; `--fail-on` (analysis) and `--fail-under` (simulation) CI
  gates; `doctor` health check; `init` one-command workspace setup.
- Demo dataset (363 transactions, 15 customers) generated deterministically by
  `scripts/generate_demo_data.py`.

**Project**
- 116 tests covering retrieval, detection, screening, compliance artefacts, audit integrity,
  agent contract and end-to-end CLI behaviour; ruff clean; CI matrix on Linux, macOS and Windows
  across Python 3.10–3.12 with an end-to-end smoke run and a control-test gate.

### Known limitations
- Sanctions lists are synthetic until `sanctions import` is run.
- US state law, MiCA detail, sector-specific guidance and case law are out of scope.
- Audit records hash their details but store them in clear and do not scrub PII.
- The simulator measures the configuration against injected patterns, not a production population.
