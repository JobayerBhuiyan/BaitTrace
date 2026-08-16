"""Output formats.

Every renderer takes a :class:`~baittrace.report.Report` and returns a string.
None of them know how the report was produced, and none of them can reach back
into the message, which is what keeps the text and JSON outputs describing the
same analysis rather than drifting apart.
"""

from __future__ import annotations

from collections.abc import Callable

from ..report import Report
from . import json as json_renderer
from . import text as text_renderer
from .layout import Style

Renderer = Callable[[Report, Style], str]

FORMATS: dict[str, Renderer] = {
    "text": lambda report, style: text_renderer.render(report, style),
    "json": lambda report, style: json_renderer.render(report, style),
}


def get(name: str) -> Renderer:
    try:
        return FORMATS[name]
    except KeyError:
        raise KeyError(f"unknown format {name!r}; choose from {sorted(FORMATS)}") from None


__all__ = ["FORMATS", "Renderer", "Style", "get", "json_renderer", "text_renderer"]
