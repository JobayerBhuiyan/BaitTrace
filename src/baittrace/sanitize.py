"""Make attacker-controlled text safe to print.

Display names, subjects, filenames and link text all reach a terminal, a
browser or a ticket, and all of them were written by the attacker. A phishing
report that faithfully echoes its input is a delivery mechanism.

Three classes of problem are handled here:

* **Terminal control.** ANSI escape sequences can move the cursor, clear the
  screen, recolour output or, on some terminals, alter the window title. A
  filename containing ``\\x1b[2J`` should not be able to erase the analyst's
  scrollback.
* **Direction overrides.** ``invoice\\u202Egnp.exe`` renders as
  ``invoiceexe.png`` while remaining an executable. The override characters are
  replaced with visible tokens rather than removed, because their presence is
  itself the finding.
* **Invisible characters.** Zero-width spaces and joiners are used to break
  keyword matching and to hide text from a reader.
"""

from __future__ import annotations

import re
import unicodedata

# CSI, OSC and single-character escapes.
_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])")

_BIDI_TOKENS = {
    "\u202a": "<LRE>",
    "\u202b": "<RLE>",
    "\u202c": "<PDF>",
    "\u202d": "<LRO>",
    "\u202e": "<RLO>",
    "\u2066": "<LRI>",
    "\u2067": "<RLI>",
    "\u2068": "<FSI>",
    "\u2069": "<PDI>",
    "\u200e": "<LRM>",
    "\u200f": "<RLM>",
}

_INVISIBLE_TOKENS = {
    "\u200b": "<ZWSP>",
    "\u200c": "<ZWNJ>",
    "\u200d": "<ZWJ>",
    "\ufeff": "<BOM>",
    "\u00ad": "<SHY>",
    "\u2060": "<WJ>",
}

_REPLACEMENTS = {**_BIDI_TOKENS, **_INVISIBLE_TOKENS}

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

ELLIPSIS = "..."


def sanitize(text: str) -> str:
    """Strip terminal control and surface hidden characters.

    Line breaks become spaces. The report's structure -- which line is a
    finding, which is evidence -- must not be something the message can write.
    A display name containing a newline and a plausible-looking finding line
    would otherwise forge an entry in the report.
    """
    if not text:
        return ""

    out = _ANSI.sub("", text)

    chars: list[str] = []
    for char in out:
        token = _REPLACEMENTS.get(char)
        if token is not None:
            chars.append(token)
            continue
        if char in "\t\r\n\v\f":
            chars.append(" ")
            continue
        category = unicodedata.category(char)
        if category in {"Cc", "Cf", "Co", "Cs"}:
            chars.append(f"<U+{ord(char):04X}>")
            continue
        chars.append(char)

    return "".join(chars)


def to_ascii(text: str) -> str:
    """Escape non-ASCII as ``<U+XXXX>`` for terminals that cannot render it.

    Used by ``--no-unicode``. On a legacy terminal this is arguably the more
    useful rendering anyway: ``m<U+0456>crosoft.example`` states the homoglyph
    outright instead of hoping the reader spots it.
    """
    return "".join(char if ord(char) < 128 else f"<U+{ord(char):04X}>" for char in text)


def collapse(text: str) -> str:
    """Sanitize and squeeze runs of whitespace onto one line."""
    return re.sub(r"\s+", " ", sanitize(text)).strip()


def ellipsize(text: str, width: int) -> str:
    """Trim to ``width`` characters, keeping the result readable."""
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= len(ELLIPSIS):
        return text[:width]
    return text[: width - len(ELLIPSIS)] + ELLIPSIS


def redact(text: str) -> str:
    """Mask addresses and IPs for reports that leave the analyst's machine.

    Deliberately partial rather than total: ``a***@example.com`` still lets a
    reader follow the reasoning, which is the whole point of the report, while
    removing the identifier itself.
    """

    def _mask_email(match: re.Match[str]) -> str:
        local, _, domain = match.group(0).partition("@")
        head = local[0] if local else "?"
        return f"{head}{'*' * max(2, len(local) - 1)}@{domain}"

    def _mask_ip(match: re.Match[str]) -> str:
        parts = match.group(0).split(".")
        return f"{parts[0]}.{parts[1]}.x.x"

    return _IPV4.sub(_mask_ip, _EMAIL.sub(_mask_email, text))


def defang_schemes(text: str) -> str:
    """Replace live http(s) schemes anywhere in the string, including nested URLs."""
    out = re.sub(r"(?i)https://", "hxxps://", text)
    return re.sub(r"(?i)http://", "hxxp://", out)


def clean(
    text: str,
    *,
    width: int | None = None,
    redacted: bool = False,
    ascii_only: bool = False,
) -> str:
    """The one call renderers should use: collapse, redact, escape, trim.

    Nothing derived from a message should reach output by any other route.
    """
    out = defang_schemes(collapse(text))
    if redacted:
        out = redact(out)
    if ascii_only:
        out = to_ascii(out)
    if width is not None:
        out = ellipsize(out, width)
    return out
