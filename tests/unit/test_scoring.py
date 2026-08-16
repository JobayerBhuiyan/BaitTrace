"""Scoring engine tests.

These check the properties the model claims: caps bind, categories saturate,
trust reduces but never clears, and the displayed breakdown adds up to the
score. The last one matters most for trust in the tool: a breakdown that does
not sum reads as a bug even when the maths behind it is right.
"""

from __future__ import annotations

import pytest

from baittrace.scoring import (
    BAND_BENIGN,
    BAND_HIGH,
    BAND_SUSPICIOUS,
    load_rulepack,
    score,
)
from baittrace.signal import Category, RuleSpec, Severity, SignalKind


def indicator(
    rule_id: str,
    category: Category = Category.IDENTITY,
    weight: float = 10.0,
    confidence: float = 1.0,
) -> object:
    spec = RuleSpec(
        id=rule_id,
        category=category,
        title=f"test rule {rule_id}",
        severity=Severity.MEDIUM,
        weight=weight,
        summary="",
        advice="",
    )
    return spec.fire(confidence=confidence, explanation="test")


def suppressor(rule_id: str, weight: float = 0.5) -> object:
    spec = RuleSpec(
        id=rule_id,
        category=Category.IDENTITY,
        title="trust",
        severity=Severity.INFO,
        weight=weight,
        summary="",
        advice="",
        kind=SignalKind.SUPPRESSOR,
    )
    return spec.fire(confidence=1.0, explanation="test")


class TestBasics:
    def test_no_signals_scores_zero(self) -> None:
        verdict = score([])
        assert verdict.score == 0
        assert verdict.band == BAND_BENIGN

    def test_score_is_bounded(self) -> None:
        signals = [indicator(f"X{i:03d}", weight=1000.0) for i in range(20)]
        verdict = score(signals)
        assert 0 <= verdict.score <= 100

    def test_confidence_scales_the_contribution(self) -> None:
        strong = score([indicator("X001", confidence=1.0)]).score
        weak = score([indicator("X001", confidence=0.2)]).score
        assert strong > weak


class TestCaps:
    def test_a_category_cannot_exceed_its_cap(self) -> None:
        pack = load_rulepack()
        cap = pack.config_for(Category.IDENTITY).cap
        at_cap = score([indicator("X001", weight=cap)])
        far_over = score([indicator("X001", weight=cap * 10)])
        assert at_cap.score == far_over.score

    def test_many_weak_signals_cannot_outrank_the_cap(self) -> None:
        pack = load_rulepack()
        cap = pack.config_for(Category.IDENTITY).cap
        many = score([indicator(f"X{i:03d}", weight=2.0) for i in range(50)])
        one = score([indicator("Y001", weight=cap)])
        assert many.score <= one.score

    def test_one_category_alone_cannot_reach_one_hundred(self) -> None:
        verdict = score([indicator("X001", weight=10_000.0)])
        pack = load_rulepack()
        ceiling = pack.config_for(Category.IDENTITY).ceiling
        assert verdict.score == pytest.approx(round(100 * ceiling), abs=1)

    def test_independent_categories_reinforce(self) -> None:
        one = score([indicator("X001", category=Category.IDENTITY, weight=25.0)])
        two = score(
            [
                indicator("X001", category=Category.IDENTITY, weight=25.0),
                indicator("Y001", category=Category.HEADERS, weight=10.0),
            ]
        )
        assert two.score > one.score


class TestTrust:
    def test_a_suppressor_reduces_the_score(self) -> None:
        loud = score([indicator("X001", weight=25.0)])
        quiet = score([indicator("X001", weight=25.0), suppressor("S001", 0.5)])
        assert quiet.score < loud.score

    def test_trust_can_never_clear_a_message(self) -> None:
        verdict = score([indicator("X001", weight=25.0), suppressor("S001", 1.0)])
        assert verdict.trust_factor <= load_rulepack().trust_max
        assert verdict.score > 0

    def test_suppressors_are_reported_separately(self) -> None:
        verdict = score([indicator("X001"), suppressor("S001")])
        assert [s.id for s in verdict.signals] == ["X001"]
        assert [s.id for s in verdict.suppressors] == ["S001"]


class TestAttribution:
    def test_contributions_sum_to_the_score(self) -> None:
        verdict = score(
            [
                indicator("X001", Category.IDENTITY, 25.0),
                indicator("X002", Category.IDENTITY, 15.0),
                indicator("X003", Category.IDENTITY, 8.0),
                indicator("Y001", Category.HEADERS, 8.0, 0.6),
            ]
        )
        assert sum(verdict.contributions) == verdict.score

    def test_the_strongest_finding_gets_the_largest_share(self) -> None:
        """Saturation must not invert the ranking a reader sees.

        Plain leave-one-out attribution gets this wrong: once identity is at
        its cap, removing any one identity finding barely moves the score, so a
        lone weak header rule collects the whole visible total.
        """
        verdict = score(
            [
                indicator("X001", Category.IDENTITY, 25.0),
                indicator("X002", Category.IDENTITY, 15.0),
                indicator("X003", Category.IDENTITY, 8.0),
                indicator("Y001", Category.HEADERS, 8.0, 0.6),
            ]
        )
        by_id = dict(zip([s.id for s in verdict.signals], verdict.contributions, strict=True))
        assert by_id["X001"] > by_id["X002"] > by_id["X003"] > by_id["Y001"]

    def test_contributions_are_index_aligned(self) -> None:
        verdict = score([indicator("X001"), indicator("X002")])
        assert len(verdict.contributions) == len(verdict.signals)


class TestBands:
    @pytest.mark.parametrize(
        ("score_value", "expected"),
        [(0, BAND_BENIGN), (24, BAND_BENIGN), (25, BAND_SUSPICIOUS), (50, BAND_HIGH)],
    )
    def test_band_boundaries(self, score_value: int, expected: str) -> None:
        assert load_rulepack().band_for(score_value) == expected


class TestRulepack:
    def test_the_identifier_is_recorded_in_the_verdict(self) -> None:
        assert score([]).rulepack == "core@2026.08"

    def test_an_unknown_rulepack_is_an_error(self) -> None:
        from baittrace.errors import ConfigError

        with pytest.raises(ConfigError):
            load_rulepack("nope@1999.01")

    def test_config_weights_override_the_rulepack(self) -> None:
        signals = [indicator("X001", weight=25.0)]
        assert score(signals, overrides={"X001": 1.0}).score < score(signals).score

    def test_scoring_is_deterministic(self) -> None:
        signals = [indicator("X001", weight=25.0), indicator("Y001", Category.HEADERS, 8.0)]
        first = score(signals)
        second = score(signals)
        assert first.score == second.score
        assert first.contributions == second.contributions
