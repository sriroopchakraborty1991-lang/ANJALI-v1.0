from __future__ import annotations

from datetime import date

import pytest

from anjali.kb.resolve import resolve, verify_citation


def test_corpus_is_ingested(kb):
    stats = kb.stats()
    assert stats["documents"] >= 70
    assert stats["chunks"] >= 100
    assert stats["by_jurisdiction"]["US"] >= 20


def test_known_keys_resolve_to_verified_citations(kb):
    citations = resolve(kb, ["us-31cfr-1010-311", "fatf-r1-rba", "eu-amld6-2024-1640"])
    assert len(citations) == 3
    for citation in citations:
        assert citation.verified is True
        assert citation.source_url
        assert citation.citation
    # AMLD6 transposition is due in 2027, so a citation to it must be marked as not yet
    # in force rather than presented as current law.
    assert [c.future for c in citations] == [False, False, True]


def test_unknown_key_is_skipped_unless_strict(kb):
    assert resolve(kb, ["not-a-real-key"]) == []
    with pytest.raises(KeyError):
        resolve(kb, ["not-a-real-key"], strict=True)


def test_strict_resolution_raises_for_every_key_used_by_the_detectors(kb, demo_context):
    """A citation key that does not resolve is a silent loss of authority in the file."""
    from anjali.analysis.patterns import DETECTORS

    keys: set[str] = set()
    for detect in DETECTORS.values():
        for detection in detect(demo_context):
            keys |= set(detection.citation_keys)
    assert len(keys) >= 18
    assert resolve(kb, sorted(keys), strict=True)


def test_strict_resolution_raises_for_every_conflict(kb):
    from anjali.compliance.conflicts import all_conflicts

    keys = sorted({key for conflict in all_conflicts() for pos in conflict.positions for key in pos.doc_ids})
    resolve(kb, keys, strict=True)


def test_strict_resolution_raises_for_sar_and_screening_authorities(kb):
    resolve(
        kb,
        [
            "us-31cfr-1010-306",
            "us-31cfr-1020-320",
            "us-31cfr-1010-311",
            "us-fincen-sar-narrative",
            "us-sar-continuing",
        ],
        strict=True,
    )


def test_retrieval_ranks_the_on_point_provision_first(kb):
    hits = kb.search("structuring transactions to evade reporting requirements", top_k=5)
    assert hits
    assert "1010.314" in hits[0].chunk.citation


def test_as_of_dates_exclude_future_instruments(kb):
    hits = kb.search("beneficial ownership register requirement", top_k=6, as_of=date(2024, 1, 1))
    assert hits
    assert all(hit.chunk.effective_from <= date(2024, 1, 1) for hit in hits)


def test_verify_citation_reports_verdict(kb):
    report = verify_citation(kb, "31 CFR § 1010.311")
    assert report["found"] is True
    assert report["documents"][0]["doc_id"] == "us-31cfr-1010-311"


def test_verify_citation_flags_unknown_citation(kb):
    report = verify_citation(kb, "31 CFR § 9999.999")
    assert report["found"] is False


def test_get_document_returns_full_text(kb):
    doc = kb.get_document("us-31cfr-1010-311")
    assert doc is not None
    assert len(doc["text"]) > 200
    assert doc["jurisdiction"] == "US"


def test_list_documents_covers_every_jurisdiction(kb):
    jurisdictions = {doc["jurisdiction"] for doc in kb.list_documents()}
    assert {"US", "EU", "UK", "FATF"} <= jurisdictions


def test_dodd_frank_provisions_are_citable(kb):
    """The brief called for Dodd-Frank coverage; the implemented rules must resolve."""
    from anjali.kb.resolve import resolve

    citations = resolve(kb, ["us-dfa-312-correspondent-dd", "us-dfa-1502-aml-context"], strict=True)
    assert len(citations) == 2
    assert all(c.verified and not c.future for c in citations)
    assert any("1010.610" in c.citation for c in citations)
