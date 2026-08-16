"""Safety bounds for parsing attacker-controlled input.

Every byte this tool parses was crafted by someone trying to harm the reader,
so the parser is the primary attack surface. These bounds are applied before
the MIME parser is allowed to allocate anything proportional to the input.

Two kinds of bound:

* Hard bounds raise :class:`~baittrace.errors.LimitExceeded`. The message is
  unanalyzable and pretending otherwise would be dishonest.
* Soft bounds truncate and record a :class:`Truncation`. The scan continues and
  the report states what was skipped, because a triage tool that quietly omits
  a check is worse than one that admits uncertainty.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

DEFAULT_MAX_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_DEPTH = 20
DEFAULT_MAX_PARTS = 200
DEFAULT_MAX_HEADERS = 500
DEFAULT_MAX_HEADER_BYTES = 16 * 1024
DEFAULT_MAX_BODY_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_URLS = 500
DEFAULT_BUDGET_SECONDS = 5.0


@dataclass(frozen=True, slots=True)
class Limits:
    """Bounds applied to a single message."""

    max_bytes: int = DEFAULT_MAX_BYTES
    max_depth: int = DEFAULT_MAX_DEPTH
    max_parts: int = DEFAULT_MAX_PARTS
    max_headers: int = DEFAULT_MAX_HEADERS
    max_header_bytes: int = DEFAULT_MAX_HEADER_BYTES
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    max_urls: int = DEFAULT_MAX_URLS
    budget_seconds: float = DEFAULT_BUDGET_SECONDS


@dataclass(frozen=True, slots=True)
class Truncation:
    """A soft bound that was hit, recorded so the report can disclose it."""

    limit_name: str
    limit_value: int
    detail: str

    def describe(self) -> str:
        return f"{self.limit_name} ({self.limit_value}): {self.detail}"


@dataclass(slots=True)
class LimitsReport:
    """Accumulates what was skipped while parsing one message."""

    truncations: list[Truncation] = field(default_factory=list)

    def record(self, limit_name: str, limit_value: int, detail: str) -> None:
        self.truncations.append(Truncation(limit_name, limit_value, detail))

    @property
    def truncated(self) -> bool:
        return bool(self.truncations)

    def describe(self) -> list[str]:
        return [t.describe() for t in self.truncations]


class Budget:
    """A monotonic wall-clock budget for one message.

    Checked at loop boundaries rather than enforced pre-emptively; a hard kill
    needs process isolation, which belongs to the hosted service rather than
    the library.
    """

    __slots__ = ("_deadline", "_seconds", "_started")

    def __init__(self, seconds: float = DEFAULT_BUDGET_SECONDS) -> None:
        self._seconds = seconds
        self._started = time.monotonic()
        self._deadline = self._started + seconds

    @property
    def expired(self) -> bool:
        return time.monotonic() > self._deadline

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._started

    @property
    def remaining(self) -> float:
        return max(0.0, self._deadline - time.monotonic())
