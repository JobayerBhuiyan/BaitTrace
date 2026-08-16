"""Orchestration: bytes in, report out.

The failure model is the interesting part. A message that cannot be parsed is
fatal for that message and says so. An analyzer that raises is contained,
recorded, and reported alongside a degraded verdict, because losing one
evidence class is not a reason to lose the other six. The report always states
what did not run.
"""

from __future__ import annotations

import time
from collections.abc import Collection, Sequence
from pathlib import Path

from ._version import __version__
from .analyzers.base import Analyzer, Context
from .analyzers.registry import discover, select
from .config import Config
from .ingest import RawInput, read_input
from .limits import Budget
from .model import Message
from .parse import parse, parse_bytes
from .report import Report, ToolInfo
from .resolver import NullResolver, Resolver
from .scoring import Rulepack, load_rulepack, score
from .signal import AnalyzerError, Category, Signal


def _run_analyzers(
    message: Message,
    analyzers: Sequence[Analyzer],
    ctx: Context,
) -> tuple[list[Signal], list[AnalyzerError], list[str]]:
    signals: list[Signal] = []
    errors: list[AnalyzerError] = []
    completed: list[str] = []

    for analyzer in analyzers:
        if ctx.budget.expired:
            errors.append(
                AnalyzerError(
                    analyzer_id=analyzer.id,
                    message="skipped: time budget exhausted before this analyzer ran",
                )
            )
            continue

        if analyzer.requires_network and not ctx.online:
            # Not an error: the analyzer is correctly declining to guess.
            continue

        try:
            produced = analyzer.run(message, ctx)
        except Exception as exc:  # noqa: BLE001 - containment is the point
            errors.append(
                AnalyzerError(
                    analyzer_id=analyzer.id,
                    message=f"{type(exc).__name__}: {exc}",
                    detail="analysis continued without this evidence class",
                )
            )
            continue

        completed.append(analyzer.id)
        signals.extend(produced)

    return signals, errors, completed


def max_reachable_score(categories: Collection[Category], rulepack: Rulepack) -> int:
    """The highest score the given evidence classes could produce together.

    Every category contributes through its own ceiling, so a build that
    implements only some of them has a hard maximum below 100. Saying so is the
    difference between "we found nothing" and "we did not look".
    """
    survival = 1.0
    for category in categories:
        survival *= 1.0 - rulepack.config_for(category).ceiling
    return round(100.0 * (1.0 - survival))


def analyze(
    message: Message,
    config: Config | None = None,
    resolver: Resolver | None = None,
) -> Report:
    """Score an already-parsed message.

    Split out from :func:`scan` so tests and the hosted service can analyze a
    message they built in memory without going through the filesystem.
    """
    cfg = config or Config()
    started = time.monotonic()

    ctx = Context(
        config=cfg,
        resolver=resolver or NullResolver(),
        budget=Budget(cfg.limits.budget_seconds),
    )

    analyzers = select(
        discover(include_plugins=not cfg.no_plugins),
        only=cfg.only_categories,
        skip=cfg.skip_categories,
    )
    signals, errors, completed = _run_analyzers(message, analyzers, ctx)

    if cfg.disabled_rules:
        signals = [s for s in signals if s.id not in cfg.disabled_rules]

    rulepack = load_rulepack(cfg.rulepack)
    verdict = score(signals, rulepack, cfg.weight_overrides)

    duration_ms = 0 if cfg.deterministic else int((time.monotonic() - started) * 1000)
    covered = {analyzer.category for analyzer in analyzers if analyzer.id in completed}

    return Report(
        message=message,
        verdict=verdict,
        tool=ToolInfo(name="baittrace", version=__version__, rulepack=rulepack.identifier),
        errors=tuple(errors),
        analyzers_run=tuple(completed),
        duration_ms=duration_ms,
        online=ctx.online,
        scan_id=message.sha256[:16],
        max_reachable_score=max_reachable_score(covered, rulepack),
    )


def scan(
    target: str | Path,
    config: Config | None = None,
    resolver: Resolver | None = None,
) -> Report:
    """Read, parse and score one message.

    ``target`` is a path, or ``-`` to read from stdin.
    """
    cfg = config or Config()
    raw: RawInput = read_input(target, cfg.limits)
    message = parse(raw, cfg.limits)
    return analyze(message, cfg, resolver)


def scan_bytes(
    data: bytes,
    source: str = "<bytes>",
    config: Config | None = None,
    resolver: Resolver | None = None,
) -> Report:
    """Score a message already held in memory."""
    cfg = config or Config()
    message = parse_bytes(data, source=source, limits=cfg.limits)
    return analyze(message, cfg, resolver)


__all__ = ["Report", "analyze", "scan", "scan_bytes"]
