"""The terminal layout grid.

One fixed grid, applied everywhere, so the report reads as a table rather than
as a paragraph:

======  ==================================================================
1-11    label column, left aligned
12-13   gutter
14-72   value column, wrapping with a 13-space hanging indent
======  ==================================================================

Findings break the grid deliberately: their severity glyph sits in column 1 so
the eye can scan the left edge for the things that matter.

Colour is never load-bearing. Every severity is also a glyph and a word, so the
report survives a monochrome terminal, a screen reader, and a paste into a
ticket. ``NO_COLOR`` and a non-TTY stdout both disable it, per the informal
no-color.org convention.
"""

from __future__ import annotations

import os
import sys
import textwrap
from dataclasses import dataclass

WIDTH = 72
LABEL_WIDTH = 11
GUTTER = 2
VALUE_START = LABEL_WIDTH + GUTTER
VALUE_WIDTH = WIDTH - VALUE_START

RESET = "\x1b[0m"
_COLORS = {
    "critical": "\x1b[1;31m",
    "high": "\x1b[31m",
    "medium": "\x1b[33m",
    "low": "\x1b[36m",
    "info": "\x1b[2m",
    "good": "\x1b[32m",
    "dim": "\x1b[2m",
    "bold": "\x1b[1m",
}

_GLYPHS_UNICODE = {
    "high": "\u2717",
    "medium": "\u26a0",
    "low": "\u00b7",
    "info": "\u00b7",
    "good": "\u2713",
}
_GLYPHS_ASCII = {
    "high": "[x]",
    "medium": "[!]",
    "low": "[-]",
    "info": "[-]",
    "good": "[+]",
}

_RULE_UNICODE = "\u2500"
_RULE_ASCII = "-"
_BAR_FULL_UNICODE = "\u2588"
_BAR_EMPTY_UNICODE = "\u2591"
_BAR_FULL_ASCII = "#"
_BAR_EMPTY_ASCII = "."


def color_enabled(explicit: bool | None = None) -> bool:
    if explicit is not None:
        return explicit
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("BAITTRACE_FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


def unicode_enabled(explicit: bool | None = None) -> bool:
    if explicit is not None:
        return explicit
    encoding = (sys.stdout.encoding or "").lower()
    return "utf" in encoding


@dataclass(frozen=True, slots=True)
class Style:
    """Rendering switches resolved once, then passed down."""

    color: bool = False
    unicode: bool = True
    width: int = WIDTH
    redact: bool = False

    @property
    def value_width(self) -> int:
        return max(20, self.width - VALUE_START)

    def paint(self, text: str, style: str) -> str:
        if not self.color or style not in _COLORS:
            return text
        return f"{_COLORS[style]}{text}{RESET}"

    def glyph(self, severity: str) -> str:
        table = _GLYPHS_UNICODE if self.unicode else _GLYPHS_ASCII
        return table.get(severity, table["info"])

    def rule(self) -> str:
        return (_RULE_UNICODE if self.unicode else _RULE_ASCII) * self.width

    def bar(self, fraction: float, size: int) -> str:
        filled = max(0, min(size, round(fraction * size)))
        if self.unicode:
            return _BAR_FULL_UNICODE * filled + _BAR_EMPTY_UNICODE * (size - filled)
        return _BAR_FULL_ASCII * filled + _BAR_EMPTY_ASCII * (size - filled)


def wrap(text: str, width: int) -> list[str]:
    if not text:
        return [""]
    lines: list[str] = []
    for paragraph in text.split("\n"):
        wrapped = textwrap.wrap(paragraph, width=width) or [""]
        lines.extend(wrapped)
    return lines


def field(label: str, value: str, style: Style, *, label_style: str = "dim") -> list[str]:
    """A label/value row on the grid, wrapping into the value column."""
    padded = label[:LABEL_WIDTH].ljust(LABEL_WIDTH)
    head = style.paint(padded, label_style)
    indent = " " * VALUE_START

    wrapped = wrap(value, style.value_width)
    lines = [f"{head}{' ' * GUTTER}{wrapped[0]}"]
    lines.extend(f"{indent}{line}" for line in wrapped[1:])
    return lines


def section(title: str, style: Style) -> list[str]:
    """A section heading: blank line, then the title in the label column."""
    return ["", style.paint(title.upper(), "bold")]


def header(left: str, right: str, style: Style) -> list[str]:
    """Title bar with a right-aligned annotation, then a full-width rule."""
    space = max(1, style.width - len(left) - len(right))
    return [
        style.paint(left, "bold") + " " * space + style.paint(right, "dim"),
        style.rule(),
    ]


def field_split(label: str, left: str, right: str, style: Style) -> list[str]:
    """A grid row with a right-aligned trailing value, such as a score."""
    padded = label[:LABEL_WIDTH].ljust(LABEL_WIDTH)
    body_width = style.width - VALUE_START
    gap = max(1, body_width - len(left) - len(right))
    body = f"{left}{' ' * gap}{right}"
    return [f"{style.paint(padded, 'dim')}{' ' * GUTTER}{body}"]


def finding_head(severity: str, points: str, rule_id: str, title: str, style: Style) -> list[str]:
    """The scannable header for a finding, severity glyph in column 1.

    Wraps rather than truncating: a rule title cut off mid-word costs the
    reader more than the extra line saves.
    """
    plain_glyph = style.glyph(severity)
    prefix = f"{plain_glyph} {points:>5}  {rule_id}  "
    indent = " " * len(prefix)
    available = max(20, style.width - len(prefix))

    wrapped = wrap(title, available)
    painted_prefix = prefix.replace(plain_glyph, style.paint(plain_glyph, severity), 1)
    lines = [f"{painted_prefix}{style.paint(wrapped[0], 'bold')}"]
    lines.extend(f"{indent}{line}" for line in wrapped[1:])
    return lines


def finding_body(text: str, style: Style) -> list[str]:
    indent = " " * VALUE_START
    return [f"{indent}{line}" for line in wrap(text, style.value_width)]


def right(text: str, style: Style) -> str:
    return text.rjust(style.width)
