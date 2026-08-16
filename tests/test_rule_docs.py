"""Rule and documentation must stay in bijection.

This is the mechanism that stops the two most common decay modes in a detection
project: a rule shipped without an explanation, and a documentation page for a
rule that was quietly deleted. Both are silent failures, and both make a
detector untrustworthy in the same way. CI turns them into build failures.

If this test fails, the fix is to write the page, not to weaken the test.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from baittrace.analyzers.registry import all_rules

REPO_ROOT = Path(__file__).resolve().parent.parent
RULE_DOCS = REPO_ROOT / "docs" / "rules"

REQUIRED_SECTIONS = (
    "## What it detects",
    "## Why it matters",
    "## Example",
    "## Known false positives",
    "## References",
)


def documented_ids() -> set[str]:
    return {path.stem for path in RULE_DOCS.glob("*.md") if path.stem != "README"}


def implemented_ids() -> set[str]:
    return {spec.id for spec in all_rules(include_plugins=False)}


def test_every_implemented_rule_has_a_page() -> None:
    missing = sorted(implemented_ids() - documented_ids())
    assert not missing, (
        f"rules with no documentation page: {missing}. Create docs/rules/<ID>.md for each."
    )


def test_every_page_documents_a_real_rule() -> None:
    orphaned = sorted(documented_ids() - implemented_ids())
    assert not orphaned, (
        f"documentation pages for rules that no analyzer emits: {orphaned}. "
        f"Delete the page or restore the rule."
    )


@pytest.mark.parametrize("rule_id", sorted(implemented_ids()))
def test_each_page_has_the_required_sections(rule_id: str) -> None:
    text = (RULE_DOCS / f"{rule_id}.md").read_text(encoding="utf-8")
    missing = [section for section in REQUIRED_SECTIONS if section not in text]
    assert not missing, f"{rule_id}.md is missing sections: {missing}"


@pytest.mark.parametrize("rule_id", sorted(implemented_ids()))
def test_each_page_title_matches_the_rule_title(rule_id: str) -> None:
    spec = next(s for s in all_rules(include_plugins=False) if s.id == rule_id)
    first_line = (RULE_DOCS / f"{rule_id}.md").read_text(encoding="utf-8").splitlines()[0]
    assert first_line.startswith(f"# {rule_id}"), f"{rule_id}.md must start with '# {rule_id}'"
    assert spec.title.lower() in first_line.lower(), (
        f"{rule_id}.md title disagrees with the RuleSpec title {spec.title!r}"
    )


def test_rule_ids_follow_the_naming_scheme() -> None:
    pattern = re.compile(r"^[A-Z]{3}[0-9]{3}$")
    bad = [rule_id for rule_id in implemented_ids() if not pattern.match(rule_id)]
    assert not bad, f"rule IDs must be three letters then three digits: {bad}"


def test_every_rule_carries_advice_and_a_false_positive_note() -> None:
    """A finding with no recommended action is a fact, not triage."""
    for spec in all_rules(include_plugins=False):
        assert spec.summary.strip(), f"{spec.id} has no summary"
        assert spec.advice.strip(), f"{spec.id} has no advice"
        assert spec.false_positives.strip(), f"{spec.id} documents no false positives"


def test_the_rules_index_lists_every_rule() -> None:
    index = (RULE_DOCS / "README.md").read_text(encoding="utf-8")
    missing = [rule_id for rule_id in sorted(implemented_ids()) if rule_id not in index]
    assert not missing, f"docs/rules/README.md does not list: {missing}"
