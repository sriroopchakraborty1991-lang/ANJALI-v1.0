# Architecture

ANJALI is a single-process Python application. There is no server, no daemon and no queue: a
command opens the workspace, does its work, writes an audit record and exits. That is a
deliberate constraint — the tool must be auditable on a laptop in an air-gapped room.

```
core/        models.py  util.py  errors.py  config.py  db.py
providers/   base.py    llm.py            (OpenAI-compatible, Anthropic, Offline)
rag/         embedder.py  chunker.py  store.py  ontology.py
kb/          loader.py  resolve.py  corpus/*.yaml
analysis/    ingest.py  patterns.py  risk.py  sanctions.py  engine.py
graph/       entity_graph.py
compliance/  conflicts.py  sar.py  goaml.py
audit/       trail.py
sim/         adversary.py
agent/       prompts.py  tools.py  loop.py
cli/         main.py  state.py  render.py  kb_cmds.py  case_cmds.py  compliance_cmds.py
```

## 1. Workspace and state

`ANJALI_HOME` (default `~/.anjali`) holds `config.json`, `keys.toml` (0600), `anjali.db`,
`audit.jsonl` and `cache/`. Only SQLite — WAL mode, FTS5, `schema_version` in `meta` — is used
for state. No vector database is required: the corpus is 76 documents, and a local TF-IDF
embedder (`hashtfidf-v1`, feature-hashed, no download) keeps the install offline-capable. The
`KnowledgeBase` API is embedder-agnostic, so an API embedder can be configured without changing
the retrieval code.

## 2. Ingestion

`analysis/ingest.py` accepts CSV and JSON with a wide alias table (`amount`, `value`, `amt`,
`transaction_amount`, `local_amount`, …). Rows are canonicalised through pydantic models;
unparseable rows are *rejected and reported*, never silently dropped or coerced to zero. Currency
signs are normalised into `direction`, money is quantised to cents, and timestamps are forced to
UTC. Customers may declare `accounts` as a delimited string (`ACC-1|ACC-2`), which is what links
a transaction to the person a reviewer has to talk to.

## 3. Retrieval (the "temporal" part)

1. **Chunking** — by provision-level boundaries with overlap, preserving the citation header so a
   chunk can never be quoted without its own authority.
2. **Lexical search** — SQLite FTS5 with stopword removal and an ontology expansion step
   (`rag/ontology.py`): querying "structuring" also reaches "evade reporting requirement",
   "smurfing" and "31 USC 5324".
3. **Scoring** — BM25 plus tag/title boosts, jurisdiction multipliers, an MMR pass with at most
   two chunks per document, and a penalty for instruments not in force.
4. **As-of filtering** — `--as-of` (and every internal call) filters on `effective_from`/
   `effective_to`, so a question about 2015 law is answered from 2015 law.
5. **Future detection** — instruments adopted but not yet applicable are returned *flagged*, never
   silently promoted to current obligations.

`kb/resolve.resolve(kb, keys, strict=True)` is the only way a citation enters a finding. Keys are
stable document IDs (`us-31cfr-1010-311`, `fatf-r1-rba`). Tools and detectors declare keys; the
resolver turns them into title, source URL and in-force status. A key that does not resolve is a
test failure, not a footnote.

## 4. Detection

Eleven detectors in `analysis/patterns.py`, each a pure function `AnalysisContext -> [Detection]`.
`Detection` carries the `Finding` plus the citation keys, so the same detector output can be
rendered, scored, exported and re-verified.

Thresholds live in one frozen `DetectorConfig`:

| Setting | Default | Setting | Default |
|---|---|---|---|
| `currency_threshold` | 10,000 | `layering_hours` | 24 |
| `structuring_band_low` | 0.80 × threshold | `layering_retention` | 0.85 |
| `structuring_min_count` | 2 | `layering_min_hops` | 2 |
| `structuring_window_days` | 30 | `velocity_z` | 3.5 |
| `travel_rule_threshold` | 3,000 | `velocity_window_days` | 7 |
| `travel_rule_band_low` | 0.85 | `baseline_days` | 90 |
| `smurf_min_senders` | 5 | `dormant_days` | 180 |
| `smurf_window_days` | 7 | `dormant_multiple` | 3.0 |
| `mule_min_accounts` | 3 | `tbml_price_deviation` | 0.50 |
| `cash_intensity_multiple` | 2.5 | `cycle_max_len` / `cycle_max_days` | 5 / 45 |

Design rules the detectors follow:

- **One pattern, one finding.** Rolling windows are de-duplicated into non-overlapping evidence;
  repeated invoices for the same goods/HS code are merged.
- **Alert quality over volume.** Smurfing requires the inflow to leave the account again; cash
  intensity requires a non-zero peer baseline, material value and a declared-business exemption;
  mule clusters count only the institution's own accounts when a customer master exists.
- **Silence is allowed.** A detector that cannot establish a baseline returns nothing and says so
  in its reasoning rather than firing on a single data point.
- **Every finding explains itself** — ordered reasoning steps plus the actions a reviewer should
  take, and its citation keys.

## 5. Risk

Five dimensions — geographic 0.22, product 0.16, customer 0.18, behavioral 0.30, channel 0.14 —
each with drivers and citations, adjusted by jurisdiction multipliers (EU geographic ×1.12, US
product ×1.08, US behavioral ×1.05, UK customer ×1.10). Bands: CRITICAL ≥80, HIGH ≥60, MEDIUM ≥35.

A weighted mean can dilute a critical finding, so severity floors are applied and *stated*:
≥1 critical → at least 68 (HIGH); ≥3 critical → at least 80 (CRITICAL); ≥3 high → at least 55.

## 6. Screening

Six algorithms combined into a score, then corroboration adjustments, then a tier. The blocking
index is a normalised-name hash map with a first-letter + length-band sweep, so the fuzzy pass is
O(n·k) rather than O(n²). An exact name is only reported as EXACT when the corroborating
attributes do not contradict it; a name hit with conflicting DOB and country is STRONG, which is
what the evidence supports. Ownership is handled by `screen_customer` (beneficial owners, 50%
rule) and every result records which lists were actually searched and which list version.

## 7. Graph

`graph/entity_graph.py` builds a directed, flow-weighted multigraph over accounts, customers,
counterparties, devices, IPs and countries. PageRank is computed over amount-weighted edges — a
structural hub is where value actually concentrates, not where the degree count is highest.
Communities (label propagation), cycles up to length 5 within 45 days, and bounded path search
support the investigation narrative; DOT and mermaid exports the analyst can paste into a case
file.

## 8. Compliance artefacts

- **Conflicts** (`compliance/conflicts.py`) — 10 encoded US/EU/UK collisions, each with per-
  jurisdiction positions (rule, document IDs, practical effect), the divergence, and an
  operational resolution. `relevant_to_findings` maps a case's typologies onto the conflicts it
  raises, which is what turns "we found layering" into "and here is the cross-border problem".
- **SAR** (`compliance/sar.py`) — subjects resolved through the customer master to their actual
  accounts, a six-element narrative in chronological order, FinCEN/FFIEC style, jurisdiction-
  specific due dates (30 days US, 7 UK, 30 EU), and a 10-gate quality score. Narratives never
  conclude criminal liability and never refer to the report itself.
- **CTR and goAML** (`compliance/goaml.py`) — cash aggregated per account and business day with
  separate in/out totals, a 15-day due date, and a goAML-shaped XML export.

## 9. Agent

`agent/loop.py` has two paths with one output contract:

- **Offline** — a fixed pipeline (retrieve → analyse → conflicts → sanctions → compose) that never
  invents a provision. Answers are assembled from retrieved text and the case, with steps logged.
- **LLM** — a bounded ReAct loop over 10 tools, with the system prompt carrying the ten output
  rules. The provider is chosen by configuration; nothing is sent unless a remote provider is
  configured.

Both paths pass through the citation guardrail: regulatory claims without a resolved citation are
flagged, and a sanctions hit must carry `[SANCTIONS ALERT]`. The prompt asks; the code enforces.

## 10. Audit

`audit/trail.py` writes one JSONL record per action:

```
sha256( seq | timestamp | actor | action | subject | payload_digest | prev_hash )
```

`GENESIS` is 64 zeros, `prev_hash` chains the log, and `verify()` reports the first break plus the
head hash. Records are mirrored into `audit_index` for querying; `export` renders a markdown
attestation for a regulator, and `retention` computes the five-year cutoff with a warning that
legal hold overrides it. Command output prints the head hash so a report can be tied to the log
state it was produced from.

## 11. Why SQLite and not X

Because the workspace has to be inspectable with tools that already exist on the machine. An
examiner can open `anjali.db` with the SQLite CLI, read `audit.jsonl` with `less`, and diff a
corpus file in git. Nothing in the trust story depends on a service being up.
