"""Analyzer discovery.

Built-in analyzers register through the same ``importlib.metadata`` entry-point
group that third-party plugins use. That is deliberate: a plugin mechanism only
the plugins use is a mechanism nobody notices is broken. Because the built-ins
travel the same path, any regression in loading shows up in the first test run
rather than in a contributor's issue report.

Loading a plugin executes third-party code in this process. There is no
sandbox and pretending otherwise would be worse than saying so, which is why
``--no-plugins`` exists and why ``baittrace rules`` shows where each rule came
from.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from importlib.metadata import EntryPoint, entry_points

from ..signal import RuleSpec
from .base import Analyzer

ENTRY_POINT_GROUP = "baittrace.analyzers"

_BUILTIN_IDS = frozenset({"identity", "headers"})


def _builtins() -> list[Analyzer]:
    from .headers import HeaderAnalyzer
    from .identity import IdentityAnalyzer

    return [IdentityAnalyzer(), HeaderAnalyzer()]


def _load_entry_point(entry: EntryPoint) -> Analyzer | None:
    try:
        loaded = entry.load()
    except Exception:  # noqa: BLE001 - a broken plugin must not break the tool
        return None
    try:
        instance = loaded() if isinstance(loaded, type) else loaded
    except Exception:  # noqa: BLE001
        return None
    return instance if isinstance(instance, Analyzer) else None


def discover(*, include_plugins: bool = True) -> list[Analyzer]:
    """Return every available analyzer, built-ins first and always present.

    Built-ins are constructed directly rather than trusted to the entry-point
    table so that an editable checkout with stale metadata still works.
    """
    found: list[Analyzer] = _builtins()

    if not include_plugins or os.environ.get("BAITTRACE_NO_PLUGINS"):
        return found

    known = {analyzer.id for analyzer in found}
    for entry in entry_points(group=ENTRY_POINT_GROUP):
        if entry.name in _BUILTIN_IDS:
            continue
        analyzer = _load_entry_point(entry)
        if analyzer is not None and analyzer.id not in known:
            known.add(analyzer.id)
            found.append(analyzer)

    return found


def select(
    analyzers: Iterable[Analyzer],
    only: Iterable[str] = (),
    skip: Iterable[str] = (),
) -> list[Analyzer]:
    """Filter analyzers by category name."""
    only_set = {c.lower() for c in only}
    skip_set = {c.lower() for c in skip}
    result = []
    for analyzer in analyzers:
        name = str(analyzer.category)
        if only_set and name not in only_set:
            continue
        if name in skip_set:
            continue
        result.append(analyzer)
    return result


def all_rules(*, include_plugins: bool = True) -> tuple[RuleSpec, ...]:
    """Every rule every registered analyzer can emit.

    This is the source of truth for ``baittrace rules``, for ``baittrace
    explain``, and for the CI check that every rule has a documentation page.
    """
    specs: list[RuleSpec] = []
    for analyzer in discover(include_plugins=include_plugins):
        specs.extend(analyzer.RULES)
    return tuple(sorted(specs, key=lambda spec: spec.id))


def find_rule(rule_id: str, *, include_plugins: bool = True) -> RuleSpec | None:
    wanted = rule_id.strip().upper()
    for spec in all_rules(include_plugins=include_plugins):
        if spec.id.upper() == wanted:
            return spec
    return None
