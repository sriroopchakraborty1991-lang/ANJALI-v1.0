# Regulatory coverage

76 provisions across five collections. This page is the map of what ANJALI can cite, and — just
as importantly — what it cannot.

Refresh with `anjali kb corpus` (manifest) and `anjali kb timeline` (coverage by year, plus what is
about to change).

## United States (30)

| Instrument | Why it is in the corpus |
|---|---|
| 31 CFR § 1010.311, § 1010.313 | CTR filing obligation and the aggregation rule |
| 31 CFR § 1010.314 | Structuring prohibition — the citation behind every structuring finding |
| 31 USC § 5324 | Criminal structuring statute |
| 31 CFR § 1010.306 | SAR/CTR deadlines (30 / 60 days, 120-day continuing cycle) |
| 31 CFR § 1020.320, § 1020.320(b)(3) | Bank SAR obligation and continuing-activity review |
| 31 CFR § 1022.320 | MSB SAR obligation |
| 31 USC § 5318(g)(2) | SAR confidentiality — the source of the intra-group conflict |
| 31 CFR § 1010.540 | Section 314(b) information sharing, and its limits |
| 31 CFR § 1010.520 | Section 314(a) requests |
| 31 CFR § 1010.410(e), (f) | Recordkeeping / travel-rule data on funds transfers |
| 31 CFR § 1010.430 | Five-year record retention |
| 31 CFR § 1010.230, § 1010.380 | Beneficial ownership (CDD rule and the 2024 registry rule) |
| 31 CFR § 1020.210 / 31 USC § 5318(h) | AML programme requirements |
| 31 CFR § 1020.220 | Customer identification programme |
| 31 USC § 5318A / Part 1010 Subpart F | Special measures (primary money-laundering concern) |
| 31 CFR § 1010.610 / Dodd-Frank § 312 | Enhanced due diligence for foreign correspondent accounts, incl. ownership |
| 31 CFR § 1010.520 / Dodd-Frank § 314(a) | FinCEN information requests to financial institutions |
| 31 CFR § 501.603 | OFAC reports on blocked property (strict liability, 10 business days) |
| OFAC 50 Percent Rule | Ownership-based designation |
| OFAC Compliance Commitments (2019), advisory on ransomware (2021) | Enforcement expectations |
| 50 USC § 1705 | IEEPA civil and criminal penalties |
| FinCEN SAR narrative guidance (FFIEC manual) | The six narrative elements |
| FFIEC EDD/PEP manual, FinCEN advisories (elder exploitation, 2019-A003) | Typology and EDD expectations |

## European Union (18)

AMLD5 (2018/843), AMLD6 (2024/1640 — applies 10 July 2027), AMLR (2024/1624) and AMLA
(2024/1620), PSD2 (2015/2366), the Transfer of Funds Regulation (2023/1113), the EU Blocking
Statute (2271/96), the Council ownership-and-control guidance for restrictive measures, GDPR
articles 5, 6, 15, 17, 22 and 15/23, DORA (2022/2554), the AI Act (2024/1689) and the high-risk
third-country delegated regulation (2016/1675).

AMLD6 and the AMLR are stored with `status: proposed` and an effective date of 2027-07-10.
Retrieval ranks them below in-force instruments and labels them `[NOT-YET-IN-FORCE]`. This is the
temporal-RAG guarantee: an answer about today's obligations must not cite a directive that member
states have until 2027 to transpose.

## United Kingdom (10)

POCA 2002 ss. 330 (failure to disclose) and 333A (tipping off), Terrorism Act 2000 s. 21A, MLR
2017 regs. 18–19 (risk assessment and controls), 27 (CDD), 28 (EDD/PEPs), 33 (record keeping) and
40 (five-year retention), SAMLA 2018 with OFSI guidance, FCA SYSC 6.3, and NCA UKFIU SAR
guidance including the DAML procedure.

## FATF (11)

Recommendations 1 (risk-based approach), 6 and 7 (targeted financial sanctions), 10 (CDD), 11
(record keeping), 12 (PEPs), 13 (correspondent banking), 15 (new technologies), 16 (travel rule),
20 (STR reporting), plus the FATF/APG trade-based money laundering typologies and the digital
identity guidance.

## International (7)

UN Security Council Resolutions 1267 and 1373, Wolfsberg correspondent-banking and trade-finance
principles, Basel Committee guidance on third-party risks, the Egmont Group principles for FIU
exchange, ISO 20022 structured party data, and FATF/Egmont-aligned guidance on third-party payment
processing and nested relationships.

## Cross-jurisdiction conflicts encoded

Ten collisions, each with per-jurisdiction positions, the divergence, and an operational
resolution (`anjali conflicts list`):

| ID | Severity | The problem |
|---|---|---|
| `sar-group-disclosure` | CRITICAL | US § 5318(g)(2) has no intra-group carve-out; UK MLR and EU AMLD6 expect group disclosure |
| `tipping-off-scope` | HIGH | What may be told to the customer, and to whom, differs on all three sides |
| `ownership-50-percent-control` | CRITICAL | OFAC's 50% rule vs EU/UK "control" tests — same group, different blocking outcome |
| `travel-rule-thresholds` | HIGH | USD/EUR 1,000 FATF baseline vs the US 3,000 recordkeeping threshold; TFR covers CASP transfers |
| `retention-vs-gdpr` | HIGH | Five-year AML retention vs storage limitation and erasure |
| `dsar-vs-sar-confidentiality` | HIGH | GDPR Art. 15 access requests vs SAR confidentiality (Art. 23 derogations) |
| `filing-deadlines` | HIGH | 30 days (US), 7 days (UK DAML), 30 days (EU FIU) — one alert, three clocks |
| `pep-domestic-scope` | MEDIUM | Domestic PEPs are in scope in the EU/UK, treated as lower risk under US guidance |
| `secondary-sanctions-blocking` | CRITICAL | US secondary sanctions vs the EU Blocking Statute — a genuine legal trap |
| `automated-decisions` | HIGH | GDPR Art. 22 / AI Act obligations vs US model-risk expectations |

## Deliberate gaps

Honesty about coverage matters more than a longer list.

- **No US state-level law** (NYDFS Part 504, California privacy). Not modelled.
- **No MiCA / crypto-asset regime detail** beyond the TFR's CASP provisions.
- **No insurance, gaming or real-estate sector guidance.**
- **No case law.** Statutory and regulatory text only.
- **Not a licensed database.** Text is summarised for retrieval, with source URLs; verify against
  the official source before filing. `anjali kb verify "<citation>"` shows what the corpus holds
  and whether it is in force on the date you ask about.
- **Sanctions lists are synthetic fixtures** until you run `anjali sanctions import`.
