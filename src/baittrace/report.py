"""The render input.

A neutral container so the pipeline and the renderers never import each other.
Renderers read this and nothing else; they never re-parse the message and never
reach back into the analyzers.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import Message
from .signal import AnalyzerError, Verdict


@dataclass(frozen=True, slots=True)
class ToolInfo:
    name: str = "baittrace"
    version: str = "0.0.0"
    rulepack: str = "core@2026.08"


@dataclass(frozen=True, slots=True)
class Report:
    """Everything a renderer is allowed to know."""

    message: Message
    verdict: Verdict
    tool: ToolInfo = field(default_factory=ToolInfo)
    errors: tuple[AnalyzerError, ...] = ()
    analyzers_run: tuple[str, ...] = ()
    duration_ms: int = 0
    online: bool = False
    scan_id: str = ""

    # The highest score the analyzers that actually ran could possibly produce.
    # With two of seven evidence classes implemented this is well below 100, and
    # a reader who does not know that will misread every low score as a clean
    # bill of health. The report states it rather than letting 100 be assumed.
    max_reachable_score: int = 100

    @property
    def degraded(self) -> bool:
        """True when part of the analysis did not complete.

        A report that quietly omits a check is worse than one that admits it,
        so this drives an explicit warning rather than being swallowed.
        """
        return bool(self.errors) or self.message.limits.truncated
