"""Exception hierarchy.

The distinction that matters here is between "this message is malformed" and
"this tool broke". The CLI maps the first to a clean 422-style report and the
second to exit code 2, so automation can tell a detection from a failure.
"""

from __future__ import annotations


class BaitTraceError(Exception):
    """Base class for every error this package raises deliberately."""


class IngestError(BaitTraceError):
    """The input could not be read at all (missing file, unreadable stream)."""


class ParseError(BaitTraceError):
    """The bytes could not be interpreted as an email message."""


class LimitExceeded(ParseError):
    """Input exceeded a configured safety bound.

    Raised only when the excess makes the message unanalyzable. Bounds that can
    be applied by discarding part of the message are recorded as truncations in
    :class:`baittrace.limits.LimitsReport` instead, so the report stays honest
    about what was skipped rather than silently omitting it.
    """

    def __init__(self, limit_name: str, limit_value: int, observed: int | str) -> None:
        self.limit_name = limit_name
        self.limit_value = limit_value
        self.observed = observed
        super().__init__(f"{limit_name} exceeded: limit {limit_value}, observed {observed}")


class ConfigError(BaitTraceError):
    """Configuration or rulepack could not be loaded or validated."""


class UnknownRuleError(BaitTraceError):
    """A rule ID was referenced that no registered analyzer emits."""


class AnalyzerFailure(BaitTraceError):
    """One analyzer raised. Recorded and reported; never fatal to a scan."""

    def __init__(self, analyzer_id: str, cause: BaseException) -> None:
        self.analyzer_id = analyzer_id
        self.cause = cause
        super().__init__(f"analyzer {analyzer_id!r} failed: {cause.__class__.__name__}: {cause}")
