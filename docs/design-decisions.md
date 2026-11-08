# Design decisions

Every non-obvious choice, and the alternative that was rejected. If you disagree with one of
these, this page tells you where to argue.

## 1. CLI, not a dashboard

A web UI is where compliance tools go to die: it becomes the system of record, needs an owner, an
SSO story, a patching cadence and a data-protection assessment before anyone can answer a
question. ANJALI answers questions from a terminal, produces artefacts a human signs, and keeps
its state in files you can copy, diff and archive. `--json` on every command means the pipeline
story is still available — you can drive it from CI, a notebook or a Jupyter kernel without a
browser.

**Rejected:** a FastAPI + React console. It would have doubled the surface area and halved the
auditability.

## 2. Detection is arithmetic, generation is the model's job

An LLM that decides what is suspicious cannot be validated, tuned, back-tested or defended in an
exam. So the split is explicit: eleven deterministic detectors with published thresholds and
reasoning traces decide *what* is suspicious; the model, when configured, helps explain it,
draft it and answer questions about it. The citation guardrail runs on the output either way.

**Consequence:** the tool is useful with no model at all. That is the air-gapped path, and it is
the default when no key is present — not a degraded mode with a fallback that pretends.

## 3. Citation keys, resolved at the edge

Detectors and tools declare document keys (`us-31cfr-1010-314`), never free-text citations. A
single resolver turns keys into title, URL, in-force status and `as_of` correctness. This makes
citation drift a test failure rather than a typo in a report: `resolve(..., strict=True)` is
asserted over every detector and every conflict in the suite.

**Rejected:** letting the model quote provisions from parametric memory. It is fluent, confident
and occasionally two amendments behind — the worst possible property in a filing.

## 4. Temporal correctness over recall

AMLD6 and the AMLR apply from 10 July 2027. They are in the corpus (an analyst must be able to
plan for them) but marked `status: proposed` with `effective_from: 2027-07-10`. Retrieval ranks
them below in-force instruments and labels them `[NOT-YET-IN-FORCE]`. Slightly lower recall on
future-law questions is a good trade for never presenting 2027 obligations as today's.

## 5. SQLite FTS5 instead of a vector database

74 documents do not justify an embedding service. A feature-hashed TF-IDF embedder plus FTS5 with
ontology expansion gets the retrieval quality that matters here (exact citation lookup, typology
terms, jurisdiction filtering) with zero network dependency and a single file to back up. The
`KnowledgeBase` interface is embedder-agnostic: point it at an API embedder and the rest of the
system is unchanged.

## 6. Screening scores must not overstate the evidence

An exact name with a contradicting date of birth and country is reported as STRONG, not EXACT. It
is still an alert, still reviewed, still audited — but the disposition describes the evidence.
The same logic drives the token-set rewrite: a single-letter transliteration variant
(`Mohamed` / `Mohammed`) previously scored 0.64 and would have been missed entirely; fuzzy token
matching plus a full-string Jaro-Winkler floor puts it at 0.967 STRONG.

## 7. Alert quality is a feature, not a nicety

Four decisions exist purely to stop the tool crying wolf, each discovered by running the
adversarial baseline:

| Symptom | Fix |
|---|---|
| Structuring fired 8 near-identical findings for one pattern | Keep the strongest non-overlapping windows only |
| A café taking cash was flagged at "100% vs peer median 0%" | Require a non-zero peer baseline, material value, and honour a declared cash business within expected turnover |
| A landlord's rent fan-in looked like smurfing | Require ≥50% of the inflow to leave the account within the week — a conduit, not a merchant |
| A branch-booked letter of credit counted as cash | Cash means physical currency; channel `branch` is not evidence of it |

## 8. Severity floors, stated in the output

A weighted average of five dimensions can drop a case with three critical findings into MEDIUM.
Rather than inflate every dimension, the score is floored by finding severity and the floor is
printed: ≥1 critical → 68, ≥3 critical → 80, ≥3 high → 55. Anyone reading the number can see why.

## 9. The audit trail is chained, not just appended

Each record's hash covers `seq|timestamp|actor|action|subject|payload_digest|prev_hash`. Deleting
a record or editing a detail breaks the chain at that point, and `verify()` reports the first
break. The head hash is printed in command output so a report can be tied to the log state that
produced it.

**Known limitation:** details are hashed but stored in clear, and there is no PII scrubber before
write. Run the workspace on an encrypted volume if the log will contain customer data.

## 10. Sanctions fixtures are synthetic and say so

Shipping real SDN data inside a repository is a licensing problem and a staleness trap. The seed
contains 76 invented entries in the shape of real lists, marked `synthetic: true` on every record,
stamped in `version_stamp()` and recorded in the audit log. `anjali sanctions import` takes a real
CSV, with configurable name/ID/type/country/DOB columns.

## 11. One pattern, one finding

Duplicate alerts are how genuine ones get buried. Rolling windows are de-duplicated; invoices for
the same goods and HS code are merged; cash intensity is suppressed when it cannot establish a
baseline. The simulator's false-positive count is the guard rail: it was 4 before these fixes and
0 afterwards, against a baseline that deliberately contains near-misses.

## 12. Reproducible adverarial cases

`anjali simulate --seed 7` builds the same transactions every time, with a fixed base date. A
reported gap is therefore reproducible by someone else on another machine — the minimum bar for a
control-test finding anyone will act on.

## 13. What was deliberately not built

- **Auto-filing.** No API integration to FinCEN, the NCA or an FIU. A tool that files is a tool
  whose bugs are enforcement actions.
- **Automatic blocking or exit.** Screening produces a disposition and an alert; a human decides.
- **A general-purpose chatbot.** `ask` is a compliance analyst with tools, not a chat window with
  a model behind it.
- **A hosted version.** Local-first is the product, not a deployment option.
