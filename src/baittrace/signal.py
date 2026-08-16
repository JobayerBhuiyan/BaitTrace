"""The signal contract.

Explainability is the product, so it has to be structural rather than
cosmetic. Every analyzer emits the same object, and every point of every score
traces back to one of these with verbatim evidence attached.

A :class:`RuleSpec` is the static declaration of a rule: its ID, category, and
default weight. A :class:`Signal` is one firing of that rule against one
message, carrying the evidence and the instance-specific explanation. Keeping
them separate is what lets ``baittrace rules`` enumerate the catalogue without
a message in hand, and what lets CI assert that every rule has documentation.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    """How much attention a finding deserves, independent of its weight."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
}


class Category(StrEnum):
    """Evidence class. Each has its own cap and ceiling in the rulepack."""

    AUTH = "auth"
    IDENTITY = "identity"
    URLS = "urls"
    ATTACHMENTS = "attachments"
    CONTENT = "content"
    ROUTING = "routing"
    HEADERS = "headers"


class SignalKind(StrEnum):
    """Whether a signal argues for suspicion or against it.

    Suppressors matter more than they look. A tool that can only ever escalate
    is not a triage tool, and being able to say "this is fine, and here is the
    evidence" is what makes the verdict credible.
    """

    INDICATOR = "indicator"
    SUPPRESSOR = "suppressor"


@dataclass(frozen=True, slots=True)
class Evidence:
    """A verbatim excerpt and where it came from.

    ``excerpt`` is raw, attacker-controlled text. It is never safe to print
    directly; renderers pass it through :mod:`baittrace.sanitize` first.
    """

    locator: str
    excerpt: str
    note: str | None = None


@dataclass(frozen=True, slots=True)
class Signal:
    """One rule firing against one message."""

    id: str
    category: Category
    title: str
    severity: Severity
    weight: float
    confidence: float
    explanation: str
    advice: str
    evidence: tuple[Evidence, ...] = ()
    refs: tuple[str, ...] = ()
    kind: SignalKind = SignalKind.INDICATOR

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"{self.id}: confidence must be in [0, 1], got {self.confidence}")
        if self.weight < 0:
            raise ValueError(f"{self.id}: weight must be non-negative, got {self.weight}")
        if self.kind is SignalKind.SUPPRESSOR and self.weight > 1.0:
            raise ValueError(f"{self.id}: suppressor weight is a trust fraction and must be <= 1.0")

    @property
    def is_suppressor(self) -> bool:
        return self.kind is SignalKind.SUPPRESSOR

    @property
    def effective(self) -> float:
        """Points for an indicator, trust fraction for a suppressor."""
        return self.weight * self.confidence


@dataclass(frozen=True, slots=True)
class RuleSpec:
    """Static declaration of a rule.

    ``weight`` here is the default. The active rulepack may override it, which
    is why scoring reads weights from the rulepack rather than from the spec.
    """

    id: str
    category: Category
    title: str
    severity: Severity
    weight: float
    summary: str
    advice: str
    refs: tuple[str, ...] = ()
    kind: SignalKind = SignalKind.INDICATOR
    false_positives: str = ""

    def fire(
        self,
        *,
        confidence: float,
        explanation: str,
        evidence: Sequence[Evidence] = (),
        weight: float | None = None,
        advice: str | None = None,
    ) -> Signal:
        """Build a :class:`Signal` from this spec."""
        return Signal(
            id=self.id,
            category=self.category,
            title=self.title,
            severity=self.severity,
            weight=self.weight if weight is None else weight,
            confidence=confidence,
            explanation=explanation,
            advice=self.advice if advice is None else advice,
            evidence=tuple(evidence),
            refs=self.refs,
            kind=self.kind,
        )


@dataclass(frozen=True, slots=True)
class AnalyzerError:
    """An analyzer that raised or timed out.

    Carried through to the report so a degraded scan is visibly degraded.
    """

    analyzer_id: str
    message: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class CategoryScore:
    """Per-category scoring breakdown, kept for the report."""

    category: Category
    raw: float
    cap: float
    ceiling: float

    @property
    def strength(self) -> float:
        if self.cap <= 0:
            return 0.0
        return min(1.0, self.raw / self.cap)


@dataclass(frozen=True, slots=True)
class Verdict:
    """The scored result handed to renderers.

    ``contributions`` is index-aligned with ``signals`` rather than keyed by
    rule ID, so a rule that legitimately fires more than once on one message
    keeps a distinct attribution for each firing.
    """

    score: int
    band: str
    signals: tuple[Signal, ...]
    contributions: tuple[int, ...]
    categories: tuple[CategoryScore, ...]
    trust_factor: float
    rulepack: str
    suppressors: tuple[Signal, ...] = ()
    notes: tuple[str, ...] = field(default=())

    def __post_init__(self) -> None:
        if len(self.contributions) != len(self.signals):
            raise ValueError("contributions must be index-aligned with signals")

    @property
    def scored(self) -> tuple[tuple[Signal, int], ...]:
        """Signals paired with their attributed points, highest first."""
        pairs = tuple(zip(self.signals, self.contributions, strict=True))
        return tuple(sorted(pairs, key=lambda p: (-p[1], p[0].id)))
