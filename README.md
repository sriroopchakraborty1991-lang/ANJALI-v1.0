# ANJALI-AI

**AI-Navigated Judgment & Audit for Legal Integrity** — a local-first, BYOK, citation-backed
financial-crime compliance analyst that lives in your terminal.

[![CI](https://github.com/sriroopchakraborty1991-lang/ANJALI-v1.0/actions/workflows/ci.yml/badge.svg)](https://github.com/sriroopchakraborty1991-lang/ANJALI-v1.0/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

ANJALI reads your transactions, finds the typologies an examiner would ask about, scores the
risk with a documented weighting, retrieves the *actual* provision in force on the date you
care about, and drafts a filing-grade narrative — with every claim traceable to a citation and
every action written to a tamper-evident audit log.

It runs on your laptop with no internet connection and no vendor account. When you do give it
a model key, the model chooses tools and writes prose; the detection, scoring, screening and
citation resolution stay deterministic and auditable.

```
$ anjali analyze --dataset demo

Case demo-2026-11-08  · 363 transactions · 64 accounts · 4,735,000.77 total

Severity   Typology              Finding                                        Conf  Evidence
 CRITICAL  tbml                  Declared unit price 210.00 for 'Industrial      95%         2
                                 press bearings' is +169% versus the benchmark
                                 78.00 (HS 8482.10) across 2 invoice(s) …
 CRITICAL  round_tripping        A 3-hop cycle (ACC-3001 → ACC-3002 →           94%         9
                                 ACC-3003 → ACC-3001) moved 2,218,500.00
                                 within 35 days, with 97% value consistency …
 CRITICAL  mule_network          5 accounts (5 customers) share device          90%        18
                                 'DEV-SHARED-77' and participate in 18
                                 transactions with 18 external senders.
 CRITICAL  layering              Account Acme Global Trading LLC received       89%         8
                                 and immediately re-sent 455,679.34 across 4
                                 matched in/out pairs, retaining only 97% …
 CRITICAL  structuring           9 cash credits totalling 81,670.22 were made   80%         9
                                 by Ravi Menon within 30 days, each below the
                                 10,000.00 reporting threshold but aggregating
                                 above it.
 …

Risk 80.0/100 (CRITICAL) · 8 findings · corpus 74 docs · audit 3f9c1ab22d4e
```

---

## Why this is not another alert dashboard

Most AML tooling gives you a queue and a score you cannot interrogate. ANJALI is built for the
two questions a regulator actually asks: *what is your evidence* and *why this threshold*.

| Differentiator | What it means in practice |
|---|---|
| **Adversarial simulation** | `anjali simulate` builds 11 injected typologies **plus** an adversarial benign baseline (a café taking cash, a landlord's fan-in, parity-priced invoices, a shared family phone) and runs your *production* detectors over them. You get recall per typology and the false positives, with a CI gate (`--fail-under`). |
| **Cross-jurisdiction conflict resolver** | 10 encoded US/EU/UK collisions — SAR confidentiality vs intra-group disclosure, the 50% ownership rule, travel-rule thresholds, retention vs GDPR erasure, automated decisions — each with the divergence and an operational resolution. Findings are matched to the conflicts they raise. |
| **Temporal RAG** | Every provision carries an effective date, amendments and successors. Retrieval is `as-of` scoped, and anything not yet in force is flagged `[NOT-YET-IN-FORCE]` instead of being presented as current law. |
| **Explainable risk** | Five weighted dimensions (geographic, product, customer, behavioral, channel) with per-jurisdiction multipliers, a published floor rule for critical findings, and the citation behind each driver. |
| **Citation guardrail** | The citation rules are enforced *outside* the model: a claim without a resolved authority is flagged, not printed as fact. This holds for the offline path too. |
| **Regulator-ready audit trail** | Hash-chained JSONL (SHA-256, `prev_hash` per record) with `verify`, `export` and a retention report, written on every command that touches data. |
| **Air-gapped mode** | The full deterministic pipeline — analysis, screening, conflicts, SAR, CTR, audit — needs no network at all. Point it at a local Ollama model for synthesis and it still never leaves the host. |
| **BYOK, no SDKs** | Plain HTTP to OpenAI, Anthropic, Groq, Mistral, OpenRouter or Ollama. Your key, your endpoint, your logs. |

## Install

```bash
git clone https://github.com/sriroopchakraborty1991-lang/ANJALI-v1.0
cd ANJALI-v1.0
python -m venv .venv && . .venv/bin/activate
pip install -e .
anjali --version
```

Python 3.10+. The only runtime dependencies are `typer`, `rich`, `pydantic`, `httpx` and
`PyYAML` — no SDKs, no telemetry, no background services.

## Sixty seconds

```bash
anjali init                                   # workspace, corpus index, sanctions fixtures, demo case
anjali analyze --dataset demo                 # typologies + scored risk + citations
anjali screen "Mohammed Al-Rashid" --country SY   # fuzzy screening, corroborated
anjali ask "Can we share a SAR with our EU parent?"
anjali conflicts show sar-group-disclosure    # the US/EU divergence, and how to resolve it
anjali sar --dataset demo -o out/sar.md       # FinCEN-format narrative + quality gate
anjali simulate --fail-under 0.9              # red-team the detectors, fail CI if recall drops
anjali audit verify                           # prove the log has not been altered
```

`anjali init` is self-contained: it ingests the 74-document corpus into SQLite FTS5, loads the
synthetic sanctions fixtures, and imports the demo case (363 transactions, 15 customers).

## Command map

| Command | Purpose |
|---|---|
| `init`, `doctor` | Workspace setup and an 8-point health check (FTS5, corpus, lists, provider, audit chain). |
| `config show\|set\|set-key\|clear-key\|path` | BYOK management; keys are stored 0600 and redacted in all output. |
| `providers` | Which providers are usable and which key each one is looking for. |
| `data load\|list\|sample\|clear` | Import transactions/customers/accounts from CSV or JSON, or print a template. |
| `analyze` | Run the detector suite; `--json`, `--detectors`, `--fail-on {critical,high,medium}`, `--as-of`. |
| `risk` | The five-dimension score, its drivers and per-jurisdiction views. |
| `screen` | Sanctions screening by name, `--customer-id` (including beneficial owners) or `--file` bulk CSV. |
| `sanctions list\|seed\|import` | List provenance, or load a real SDN/consolidated CSV. |
| `investigate` | Knowledge graph: PageRank hubs, communities, cycles, paths, DOT/mermaid export. |
| `ctr` | CTR worksheet: per-account, business-day aggregation and a 15-day due date. |
| `kb ingest\|add\|search\|show\|verify\|timeline\|stats\|corpus\|export` | Corpus management and citation verification. |
| `ask`, `chat` | The agent (LLM when configured, deterministic pipeline otherwise). |
| `conflicts list\|show\|matrix\|relevant` | Cross-jurisdiction conflicts. |
| `sar` | SAR/STR draft: six-element narrative, quality gate, markdown/JSON/goAML. |
| `simulate` | Adversarial control test with recall, false positives and a CI gate. |
| `audit stats\|verify\|log\|export\|retention` | The hash chain. |
| `cases list\|show` | Stored analyses. |

Every command takes `--json` for pipelines; global flags are `--home`, `--provider`, `--as-of`,
`--actor`, `--quiet`, `--no-audit`.

## How it works

```
                ┌───────────────┐   CSV / JSON   ┌──────────────────┐
   your data ──▶│  ingest       │───────────────▶│  SQLite (WAL)    │
                └───────────────┘   normalised   │  cases, audit,   │
                                                │  FTS5 corpus     │
   74 provisions ──▶ chunk ──▶ hashtfidf-v1 ────▶│  index           │
                                                └────────┬─────────┘
                                                         │
   ┌─────────────────────────────────────────────────────┴────────────────────────┐
   │  detectors (11, deterministic)  →  risk (5 dims, weighted, cited)            │
   │  screening (4 lists, 6 algorithms, corroboration)  →  graph (PageRank, cycles)│
   └─────────────────────────────────────┬────────────────────────────────────────┘
                                         │
             ┌───────────────────────────┼─────────────────────────────┐
             ▼                           ▼                             ▼
     citation resolution         SAR / CTR / goAML              adversarial sim
     (as-of, key-level)          (quality-gated)                (recall + FPs)
             │                           │                             │
             └───────────────┬───────────┴──────────────┬──────────────┘
                             ▼                          ▼
                     agent (LLM or offline)      hash-chained audit
                     guarded by citations        (SHA-256, verify)
```

Detection is arithmetic, not inference: every threshold lives in a `DetectorConfig` you can
override, and every finding carries its evidence transaction IDs, a reasoning trace, and the
citation keys that back the typology.

## What is in the corpus

74 provisions, indexed with effective dates and successors (`kb stats`):

| Jurisdiction | Docs | Examples |
|---|---|---|
| US | 28 | 31 CFR § 1010.311/.313/.314/.380/.410/.430, § 1020.320, 31 USC § 5318(g)(2)/§ 5318A, 31 USC § 5324, OFAC 50% rule, FinCEN SAR narrative guidance |
| EU | 18 | AMLD5 (2018/843), AMLD6 (2024/1640, from 2027), AMLR/AMLA, PSD2, TFR 2023/1113, GDPR arts. 5/6/15/17/22, DORA, AI Act, EU Blocking Statute |
| UK | 10 | POCA 2002 ss. 330/333A, MLR 2017 regs. 18/19/27/28/33/40, SAMLA/OFSI, FCA SYSC 6.3, NCA SAR guidance |
| FATF | 11 | Recs. 1, 6/7, 10–13, 15, 16, 20, TBML typologies, digital identity |
| International | 7 | UNSCR 1267/1373, Wolfsberg (correspondent banking, trade), Basel, Egmont, ISO 20022, third-party payments |

Provisions not yet applicable (AMLD6, AMLR) are stored with `status: proposed` and a future
effective date. Retrieval ranks them below in-force instruments and labels them
`[NOT-YET-IN-FORCE]`, so an answer about today's obligations cannot accidentally cite 2027 law.

## Detection and scoring, stated plainly

**Detectors** (all deterministic, all configurable): structuring, smurfing, layering,
round-tripping, mule networks, TBML price deviation, velocity anomaly, dormant reactivation,
high-risk geography, threshold avoidance, cash intensity.

Compound detectors deliberately avoid alert spam: structuring keeps one non-overlapping window
per party rather than one per rolling day; smurfing requires the inflow to *leave again*
(a merchant's daily takings are not a mule ring); TBML merges invoices describing the same
deviation; cash intensity requires a non-zero peer baseline and material value.

**Risk** — weights: geographic 0.22, product 0.16, customer 0.18, behavioral 0.30, channel 0.14,
with jurisdiction multipliers (EU geographic ×1.12, US product ×1.08 / behavioral ×1.05, UK
customer ×1.10). Bands: CRITICAL ≥80, HIGH ≥60, MEDIUM ≥35. A weighted average can dilute a
critical finding, so any critical finding floors the score at HIGH (68) and three or more floor
it at CRITICAL (80) — the floor is stated in the output rather than folded silently into a
number.

**Screening** — 0.34 token-set (fuzzy-token), 0.30 Jaro-Winkler, 0.12 Jaro, 0.12 phonetic,
0.06 Soundex, 0.06 containment, plus a full-string Jaro-Winkler floor for transliteration
variants, then corroboration on DOB, country and entity type. An exact name whose DOB *and*
country both conflict is reported as STRONG, not EXACT — because calling it exact would
misdescribe the evidence in the file.

## Honest limits

Read these before relying on any output.

- **The sanctions lists are synthetic fixtures.** 76 invented entries (68 unique names once
  duplicates across the four lists are collapsed, 168 aliases in total) in the shape of OFAC SDN,
  EU Consolidated, UN and UK OFSI records, with `synthetic: true` in every record and stamped in
  the audit log. Load real lists with `anjali sanctions import`.
- **The corpus is a working library, not a licensed database.** It covers the provisions the
  detectors cite, with source URLs, but it is not maintained by a legal data vendor. Verify
  before filing.
- **ANJALI drafts and advises. It does not file, block, exit or clear.** Every SAR, CTR and
  screening disposition requires a named human. Sign-off lines are printed into the artefact.
- **The simulator measures your configuration against *injected* patterns.** 100% recall there
  is evidence about those 11 scenarios, not fitness for your population; back-test against your
  own historical alerts.
- **Not legal advice.** Where a question turns on interpretation, the output says so.

## BYOK and air-gapped operation

```bash
anjali config set-key openai          # or ANJALI_OPENAI_API_KEY / OPENAI_API_KEY
anjali config set provider.model claude-sonnet-4-5
anjali --provider ollama ask "What is the travel-rule threshold?"   # fully local model
```

Precedence: explicit flag → environment variable → `keys.toml` (0600) → offline.

Nothing is sent anywhere unless you configure a remote provider, and only retrieved snippets,
findings and the question are ever sent — never your transaction file. `anjali doctor` shows the
effective provider. With no provider configured, every command still works; `ask` falls back to
the deterministic pipeline rather than pretending to be a model.

## Development

```bash
pip install -e ".[dev]"
pytest                 # 116 tests, ~3s
ruff check src tests
python scripts/generate_demo_data.py   # regenerate data/samples deterministically
```

Layout: `core` (models, config, db) · `providers` (HTTP LLM clients) · `rag` (embedder, chunker,
store) · `kb` (loader, resolver, corpus YAML) · `analysis` (ingest, detectors, risk, screening,
engine) · `graph` · `compliance` (conflicts, SAR, goAML) · `audit` · `sim` · `agent` · `cli`.

Design notes, module-by-module behaviour and the reasoning behind the trade-offs are in
[`docs/`](docs): [architecture](docs/architecture.md) ·
[regulatory coverage](docs/regulatory-coverage.md) · [CLI reference](docs/cli-reference.md) ·
[design decisions](docs/design-decisions.md).

## License

MIT. See [LICENSE](LICENSE).
