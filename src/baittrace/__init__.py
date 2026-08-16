"""BaitTrace: offline-first, explainable phishing triage.

The library API is a first-class surface, not an afterthought::

    from baittrace import scan

    report = scan("suspicious.eml")
    print(report.verdict.band, report.verdict.score)
    for signal in report.verdict.signals:
        print(signal.id, signal.title, report.verdict.contributions[signal.id])

Analysis is inert by default: no network, no HTML rendering, no attachment
execution, and no fetching of anything the message references.
"""

from __future__ import annotations

from .config import Config
from .errors import BaitTraceError, IngestError, LimitExceeded, ParseError
from .model import Message
from .pipeline import Report, scan, scan_bytes
from .signal import Category, Evidence, Severity, Signal, Verdict

__version__ = "0.1.0"

__all__ = [
    "BaitTraceError",
    "Category",
    "Config",
    "Evidence",
    "IngestError",
    "LimitExceeded",
    "Message",
    "ParseError",
    "Report",
    "Severity",
    "Signal",
    "Verdict",
    "__version__",
    "scan",
    "scan_bytes",
]
