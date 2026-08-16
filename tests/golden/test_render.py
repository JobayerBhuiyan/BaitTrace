"""Golden-file renderer tests.

The report is the product, so a change to its wording or its layout should be
visible in a diff and deliberate. These tests make the output a reviewed
artefact rather than something that drifts one commit at a time.

Regenerate after an intentional change::

    BAITTRACE_UPDATE_GOLDEN=1 pytest tests/golden

Then read the diff. If it is not what you meant, the code is wrong.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from baittrace.config import Config
from baittrace.pipeline import scan
from baittrace.render.json import render as render_json
from baittrace.render.layout import Style
from baittrace.render.text import render as render_text

from ..conftest import CORPUS

GOLDEN = Path(__file__).resolve().parent / "expected"
UPDATE = bool(os.environ.get("BAITTRACE_UPDATE_GOLDEN"))

SAMPLES = sorted((CORPUS / "malicious").glob("*.eml")) + sorted((CORPUS / "benign").glob("*.eml"))


def compare(name: str, produced: str) -> None:
    GOLDEN.mkdir(parents=True, exist_ok=True)
    path = GOLDEN / name

    if UPDATE:
        path.write_text(produced, encoding="utf-8")
        pytest.skip(f"updated golden file {name}")

    if not path.is_file():
        pytest.fail(f"no golden file {name}. Run: BAITTRACE_UPDATE_GOLDEN=1 pytest tests/golden")

    expected = path.read_text(encoding="utf-8")
    assert produced == expected, (
        f"{name} changed. If the change was intended, regenerate with "
        f"BAITTRACE_UPDATE_GOLDEN=1 pytest tests/golden and review the diff."
    )


@pytest.mark.parametrize("path", SAMPLES, ids=lambda p: p.name)
def test_text_report_is_stable(path: Path) -> None:
    report = scan(path, Config(deterministic=True))
    produced = render_text(report, Style(color=False, unicode=True, width=72))
    compare(f"{path.stem}.txt", produced)


@pytest.mark.parametrize("path", SAMPLES, ids=lambda p: p.name)
def test_ascii_report_is_stable(path: Path) -> None:
    report = scan(path, Config(deterministic=True))
    produced = render_text(report, Style(color=False, unicode=False, width=72))
    compare(f"{path.stem}.ascii.txt", produced)


@pytest.mark.parametrize("path", SAMPLES, ids=lambda p: p.name)
def test_json_report_is_stable(path: Path) -> None:
    report = scan(path, Config(deterministic=True))
    produced = render_json(report, Style(color=False, unicode=True))
    compare(f"{path.stem}.json", produced)


@pytest.mark.parametrize("path", SAMPLES, ids=lambda p: p.name)
def test_no_line_exceeds_the_grid_width(path: Path) -> None:
    report = scan(path, Config(deterministic=True))
    output = render_text(report, Style(color=False, unicode=True, width=72))
    too_wide = [line for line in output.splitlines() if len(line) > 72]
    assert not too_wide, f"lines wider than 72 columns: {too_wide}"


@pytest.mark.parametrize("path", SAMPLES, ids=lambda p: p.name)
def test_ascii_mode_emits_no_non_ascii(path: Path) -> None:
    """--no-unicode has to work on a terminal that genuinely cannot show it."""
    report = scan(path, Config(deterministic=True))
    output = render_text(report, Style(color=False, unicode=False, width=72))
    output.encode("ascii", errors="strict")


@pytest.mark.parametrize("path", SAMPLES, ids=lambda p: p.name)
def test_reports_never_contain_a_clickable_url(path: Path) -> None:
    """Every link is defanged, so a report is safe to paste into a ticket."""
    report = scan(path, Config(deterministic=True))
    output = render_text(report, Style(color=False, unicode=True, width=72))
    assert "http://" not in output
    assert "https://" not in output


def test_redaction_removes_local_parts() -> None:
    path = CORPUS / "malicious" / "brand-lookalike.eml"
    report = scan(path, Config(deterministic=True, redact=True))
    output = render_text(report, Style(color=False, unicode=True, redact=True))
    assert "account@micros0ft-login.example" not in output
    assert "micros0ft-login.example" in output


def test_colour_output_is_opt_in() -> None:
    path = CORPUS / "malicious" / "brand-lookalike.eml"
    report = scan(path, Config(deterministic=True))
    assert "\x1b[" not in render_text(report, Style(color=False))
    assert "\x1b[" in render_text(report, Style(color=True))
