"""Property tests for the parser.

Example-based tests only cover the malformed input someone thought to write
down. Real phishing is malformed in ways nobody anticipated, so the parser is
also held to invariants that must hold for *any* byte string:

* it never raises anything outside the declared exception hierarchy
* it always terminates
* the report never contains raw terminal control characters

Hypothesis is looking for the input that breaks one of those, which is exactly
the input an attacker is looking for too.
"""

from __future__ import annotations

import contextlib

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from baittrace.config import Config
from baittrace.errors import BaitTraceError
from baittrace.limits import Limits
from baittrace.parse import parse_bytes
from baittrace.pipeline import scan_bytes
from baittrace.render.layout import Style
from baittrace.render.text import render
from baittrace.sanitize import sanitize

SMALL = Limits(max_bytes=200_000, max_parts=50, max_depth=8, budget_seconds=5.0)
FAST = settings(
    max_examples=150,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)

header_names = st.text(
    alphabet=st.characters(min_codepoint=33, max_codepoint=126, blacklist_characters=":"),
    min_size=1,
    max_size=20,
)
header_values = st.text(max_size=100)


@FAST
@given(st.binary(max_size=4000))
def test_parsing_arbitrary_bytes_never_raises_unexpectedly(data: bytes) -> None:
    with contextlib.suppress(BaitTraceError):
        parse_bytes(data, limits=SMALL)


@FAST
@given(st.lists(st.tuples(header_names, header_values), max_size=25), st.text(max_size=500))
def test_arbitrary_headers_stay_within_bounds(headers: list[tuple[str, str]], body: str) -> None:
    """Header count is bounded regardless of what the input tries.

    Not bounded by the *input's* header count: a value containing a line break
    splits into further headers, which is header injection and something the
    parser should surface rather than refuse to represent.
    """
    raw = "".join(f"{name}: {value}\r\n" for name, value in headers) + "\r\n" + body
    try:
        message = parse_bytes(raw.encode("utf-8", errors="replace"), limits=SMALL)
    except BaitTraceError:
        return
    assert len(message.headers) <= SMALL.max_headers


@FAST
@given(st.binary(max_size=4000))
def test_scanning_arbitrary_bytes_produces_a_bounded_score(data: bytes) -> None:
    try:
        report = scan_bytes(data, config=Config(deterministic=True, limits=SMALL))
    except BaitTraceError:
        return
    assert 0 <= report.verdict.score <= 100
    assert sum(report.verdict.contributions) == report.verdict.score


@FAST
@given(st.text(max_size=200))
def test_no_report_can_emit_terminal_control_characters(display_name: str) -> None:
    """The rendered report must be safe to print no matter what the message says."""
    raw = f'From: "{display_name}" <a@corp.example>\r\nSubject: x\r\n\r\nbody\r\n'
    try:
        report = scan_bytes(raw.encode("utf-8"), config=Config(deterministic=True, limits=SMALL))
    except BaitTraceError:
        return

    output = render(report, Style(color=False, unicode=True))
    assert "\x1b" not in output
    for char in output:
        assert char == "\n" or ord(char) >= 32 or char == "\t"


@FAST
@given(st.text(max_size=200))
def test_sanitize_is_idempotent(text: str) -> None:
    once = sanitize(text)
    assert sanitize(once) == once


@FAST
@given(st.binary(max_size=2000))
def test_scanning_is_deterministic(data: bytes) -> None:
    config = Config(deterministic=True, limits=SMALL)
    try:
        first = scan_bytes(data, config=config)
        second = scan_bytes(data, config=config)
    except BaitTraceError:
        return
    assert first.verdict.score == second.verdict.score
    assert [s.id for s in first.verdict.signals] == [s.id for s in second.verdict.signals]
