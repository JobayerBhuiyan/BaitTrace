"""Corpus regression.

Two thresholds, and the benign one is the important half. Any heuristic can
find phishing if it flags everything; staying quiet on ordinary mail is what
decides whether the tool is still being used a month later.

As rules accumulate, the benign ceiling is the assertion that fails first. That
is the design working. When it fails, the new rule or its weight is wrong; the
fix is never to raise the threshold.
"""

from __future__ import annotations

import pytest

from baittrace.config import Config
from baittrace.pipeline import scan

from ..conftest import CORPUS

BENIGN_CEILING = 25
MALICIOUS_FLOOR = 50

BENIGN = sorted((CORPUS / "benign").glob("*.eml"))
MALICIOUS = sorted((CORPUS / "malicious").glob("*.eml"))


def config() -> Config:
    return Config(deterministic=True)


def test_the_corpus_is_not_empty() -> None:
    assert BENIGN, "no benign samples; run python corpus/generator.py"
    assert MALICIOUS, "no malicious samples; run python corpus/generator.py"


@pytest.mark.parametrize("path", BENIGN, ids=lambda p: p.name)
def test_benign_mail_stays_quiet(path) -> None:
    report = scan(path, config())
    assert report.verdict.score < BENIGN_CEILING, (
        f"{path.name} scored {report.verdict.score}, above the false-positive ceiling of "
        f"{BENIGN_CEILING}. Fired: {[s.id for s in report.verdict.signals]}"
    )


@pytest.mark.parametrize("path", MALICIOUS, ids=lambda p: p.name)
def test_malicious_mail_is_caught(path) -> None:
    report = scan(path, config())
    assert report.verdict.score >= MALICIOUS_FLOOR, (
        f"{path.name} scored only {report.verdict.score}. "
        f"Fired: {[s.id for s in report.verdict.signals]}"
    )


@pytest.mark.parametrize("path", MALICIOUS, ids=lambda p: p.name)
def test_every_malicious_sample_explains_itself(path) -> None:
    """A score with no evidence behind it is a number, not a verdict."""
    report = scan(path, config())
    assert report.verdict.signals
    for signal in report.verdict.signals:
        assert signal.explanation.strip()
        assert signal.advice.strip()


@pytest.mark.parametrize("path", BENIGN + MALICIOUS, ids=lambda p: p.name)
def test_no_sample_produces_an_analyzer_error(path) -> None:
    assert scan(path, config()).errors == ()


@pytest.mark.parametrize("path", BENIGN + MALICIOUS, ids=lambda p: p.name)
def test_scores_are_reproducible(path) -> None:
    first = scan(path, config())
    second = scan(path, config())
    assert first.verdict.score == second.verdict.score
    assert first.verdict.contributions == second.verdict.contributions


def test_the_committed_samples_match_the_generator() -> None:
    """A sample edited by hand instead of through generator.py drifts silently."""
    import sys

    sys.path.insert(0, str(CORPUS.parent))
    from corpus.generator import check_all

    stale = check_all(CORPUS)
    assert not stale, f"run python corpus/generator.py; stale: {[str(p) for p in stale]}"
