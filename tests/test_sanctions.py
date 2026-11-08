from __future__ import annotations

import pytest

from anjali.analysis.sanctions import SanctionsScreener, seed_database
from anjali.core.models import MatchTier


@pytest.fixture(scope="module")
def screener(db):
    seed_database(db)
    return SanctionsScreener(db)


def test_seed_populates_lists(db, screener):
    stamp = screener.version_stamp()
    assert stamp["entries"] >= 20
    assert stamp["synthetic"] is True
    assert len(screener.lists()) >= 1


def test_exact_name_with_corroboration_is_exact(screener):
    result = screener.screen("Mohammed Al-Rashid", dob="1971-03-14", country="SY")
    assert result.matches
    top = result.matches[0]
    assert top.tier is MatchTier.EXACT
    assert top.score >= 0.99
    assert result.disposition == "EXACT"


def test_exact_name_with_conflicting_identifiers_is_not_exact(screener):
    """Same name, different DOB and country: reviewable, but not a confirmed hit."""
    result = screener.screen("Ravi Menon", dob="1990-11-04", country="US")
    assert result.matches
    top = result.matches[0]
    assert top.tier is not MatchTier.EXACT
    assert top.score < 0.95
    assert top.corroboration["country_match"] is False


def test_single_letter_transliteration_still_matches(screener):
    result = screener.screen("Mohamed Al Rashid", country="SY")
    assert result.matches
    assert result.matches[0].score >= 0.9
    assert result.matches[0].tier in (MatchTier.STRONG, MatchTier.EXACT)


def test_obviously_different_name_does_not_match(screener):
    result = screener.screen("Priya Sharma", country="US", dob="1992-02-18")
    assert result.disposition in {"NONE", "CLEAR"}
    assert all(match.tier not in (MatchTier.EXACT, MatchTier.STRONG) for match in result.matches)


def test_screening_is_deterministic(screener):
    first = screener.screen("Mohammed Al-Rashid", country="SY")
    second = screener.screen("Mohammed Al-Rashid", country="SY")
    assert [m.score for m in first.matches] == [m.score for m in second.matches]


def test_screening_records_which_lists_were_checked(screener):
    result = screener.screen("Mohammed Al-Rashid", country="SY")
    assert result.lists_checked
    assert result.threshold >= 0.8


def test_matches_expose_their_attributes_for_the_file(screener):
    result = screener.screen("Mohammed Al-Rashid", country="SY")
    top = result.matches[0]
    assert top.list_name
    assert top.list_id
    assert top.algorithm
    assert top.notes
