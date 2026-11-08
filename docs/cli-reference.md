# CLI reference

Global options come **before** the subcommand:

```bash
anjali [--json] [--home PATH] [--provider NAME] [--as-of YYYY-MM-DD] [--actor NAME] [--quiet] [--no-audit] <command>
```

Every command that produces data also accepts `--json`, and exits non-zero when the thing it
checks fails — so every verb composes into CI.

## Workspace

```bash
anjali init [--provider NAME] [--force] [--demo/--no-demo]
anjali doctor [--network]
anjali providers
anjali config show | set KEY VALUE | set-key PROVIDER | clear-key PROVIDER | path
anjali version
```

`doctor` checks Python, workspace, SQLite FTS5, corpus (documents/chunks), sanctions lists, case
data, provider and audit-chain integrity. `--network` additionally probes the configured endpoint.

## Data

```bash
anjali data sample [--out DIR]                 # CSV templates for transactions and customers
anjali data load PATH... [--dataset NAME] [--replace]
anjali data list
anjali data clear [--dataset NAME]
```

Accepted columns are alias-tolerant (`amount|value|amt|transaction_amount|local_amount`,
`timestamp|date|time|posted_at|booking_date`, travel-rule and trade-finance fields, …). Unparsed
rows are reported with reasons, never dropped silently.

## Analysis

```bash
anjali analyze [--dataset NAME] [--detector NAME ...] [--jurisdiction US]
               [--detail] [--fail-on critical|high|medium] [--save/--no-save] [--as-of DATE]
anjali analyze --detectors                       # catalogue of the 11 detectors and their thresholds
anjali risk [--dataset NAME]
anjali investigate [--dataset NAME] [--format dot|mermaid] [-o FILE]
```

`--fail-on` makes the command exit 1 when a finding at or above that severity exists — the CI gate
for "do not ship a build that stops catching structuring".

## Screening

```bash
anjali screen NAME [--dob YYYY-MM-DD] [--country XX] [--threshold 0.85]
anjali screen --customer-id CUST-1001             # customer + beneficial owners, 50% rule
anjali screen --file parties.csv                  # bulk; expects a 'name' column
anjali sanctions list | seed | import PATH --list-name "OFAC SDN"
```

Tiers: EXACT (exact name, no contradicting attributes), STRONG (≥0.92), POTENTIAL (≥0.85), WEAK
(≥0.78). Anything at POTENTIAL or above prints `[SANCTIONS ALERT]`.

## Knowledge base

```bash
anjali kb ingest [--force]
anjali kb add FILE.yaml
anjali kb search "query" [-k 8] [--jurisdiction US] [--as-of DATE] [--include-superseded]
anjali kb show DOC_ID
anjali kb verify "31 CFR § 1010.311" [--on YYYY-MM-DD]
anjali kb timeline
anjali kb stats
anjali kb corpus
anjali kb export -o FILE [--format json|yaml]
```

`kb verify` exits 1 for a citation the corpus does not hold, so a citation can be gated in CI.

## Agent

```bash
anjali ask "Can we share a SAR with our EU parent?" [--offline]
anjali chat                                      # interactive shell; /help, /exit
```

Without a configured provider, both fall back to the deterministic offline pipeline — which
retrieves, analyses, resolves conflicts and cites, but does not invent prose.

## Compliance artefacts

```bash
anjali conflicts list [--topic TEXT] [--jurisdiction US]
anjali conflicts show sar-group-disclosure
anjali conflicts matrix
anjali conflicts relevant [--dataset NAME]
anjali sar [--dataset NAME | --case CASE_ID] [--jurisdiction US|EU|UK] [--filing-type initial|continuing] \
           [--format markdown|json|goaml] [-o FILE] [--quality/--no-quality] [--polish]
anjali ctr [--dataset NAME] [--threshold 10000]
```

SAR due dates follow the filing jurisdiction (30 days US, 7 UK, 30 EU). The quality gate scores
the narrative against the ten FinCEN/FFIEC elements and prints an itemised checklist; in machine
formats the checklist goes to stderr so stdout stays parseable.

## Adversarial simulation

```bash
anjali simulate [--seed 7] [--scenario NAME ...] [--fail-under 0.9] [-o FILE] [--json]
```

11 injected typologies plus an adversarial benign baseline. Same seed, same case — every gap is
reproducible.

## Audit

```bash
anjali audit stats
anjali audit verify
anjali audit log [-n 50] [--action sar.draft]
anjali audit export -o FILE [--format markdown|json]
anjali audit retention [--years 5]
```

## Cases

```bash
anjali cases list
anjali cases show CASE_ID
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | A gate failed (`--fail-on`, `--fail-under`) or a check did not pass (citation not found, broken audit chain) |
| 2 | Usage or configuration error |
| 3 | Provider or authentication error (missing/invalid key) |
| 4 | Rate limit — retry, the agent loop backs off |
| 5 | Retrieval error (corpus missing or empty) |
| 6 | Data error (unparseable file, empty dataset) |
| 7 | Compliance artefact error (SAR/CTR cannot be built) |
| 8 | Guardrail tripped (answer without authority, blocked action) |
