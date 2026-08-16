"""The terminal report.

Reads a :class:`~baittrace.report.Report` and nothing else. Every string that
originated in the message passes through :mod:`baittrace.sanitize` on the way
out, and every URL is defanged, so the report can be pasted into a ticket
without becoming a delivery mechanism itself.
"""

from __future__ import annotations

from ..report import Report
from ..sanitize import clean
from ..scoring import BAND_BENIGN, BAND_CRITICAL, BAND_HIGH, BAND_SUSPICIOUS
from ..signal import Severity, Signal
from .layout import Style, field, field_split, finding_body, finding_head, header, section

_BAND_STYLE = {
    BAND_CRITICAL: "critical",
    BAND_HIGH: "high",
    BAND_SUSPICIOUS: "medium",
    BAND_BENIGN: "good",
}

_ACTION = {
    BAND_CRITICAL: (
        "Do not interact with this message. Do not click any link, open any "
        "attachment, or reply. Escalate for analyst review and consider blocking "
        "the sending domain."
    ),
    BAND_HIGH: (
        "Treat this as phishing until proven otherwise. Do not click links or open "
        "attachments. Verify with the supposed sender through a channel you already "
        "trust, not one this message provides."
    ),
    BAND_SUSPICIOUS: (
        "Something here does not line up. Verify through a known-good channel before "
        "acting on anything the message asks for."
    ),
    BAND_BENIGN: (
        "No strong indicators were found. Ordinary caution still applies: this tool "
        "reports what it can see, not what it cannot."
    ),
}

# Evidence excerpts are allowed to run over several wrapped lines. Cutting them
# to a single line hides the part of the header that matters often enough that
# the saved space is not worth it.
_EVIDENCE_WIDTH = 160

# Analyzer families the design commits to, so the report can say what it did
# not look at rather than implying complete coverage.
_PLANNED_COVERAGE = {
    "identity": "sender identity",
    "headers": "header hygiene",
    "urls": "links",
    "attachments": "attachments",
    "auth": "SPF, DKIM and DMARC",
    "content": "body wording",
    "routing": "delivery path",
}


def _severity_key(signal: Signal) -> str:
    return str(signal.severity)


def _show(st: Style, text: str, width: int | None = None) -> str:
    """Every string that came from the message leaves through here.

    Including analyzer explanations. They are written by this project, but they
    interpolate domains and display names taken verbatim from the message, so
    treating them as trusted would reopen the hole that sanitizing the raw
    fields closed.
    """
    return clean(text, width=width, redacted=st.redact, ascii_only=not st.unicode)


def render(report: Report, style: Style | None = None) -> str:
    st = style or Style()
    lines: list[str] = []
    verdict = report.verdict
    message = report.message

    lines.extend(header(f"{report.tool.name.upper()} {report.tool.version}", verdict.rulepack, st))

    band_text = st.paint(verdict.band, _BAND_STYLE.get(verdict.band, "info"))
    lines.extend(field_split("Risk", band_text, f"{verdict.score}/100", st))
    lines.extend(field("", st.bar(verdict.score / 100.0, st.value_width), st))
    lines.extend(field("Source", _show(st, message.source, st.value_width), st))

    mode = "online" if report.online else "offline"
    ran = ", ".join(report.analyzers_run) or "none"
    lines.extend(field("Analyzed", f"{mode} | {ran} | {report.duration_ms} ms", st))

    lines.extend(_message_section(report, st))
    lines.extend(_findings_section(report, st))
    lines.extend(_scoring_section(report, st))
    lines.extend(_coverage_section(report, st))
    lines.extend(_problems_section(report, st))

    lines.extend(section("Recommended action", st))
    lines.extend(finding_body(_ACTION.get(verdict.band, _ACTION[BAND_BENIGN]), st))
    lines.append("")

    return "\n".join(lines)


def _message_section(report: Report, st: Style) -> list[str]:
    message = report.message
    sender = message.identity.primary_from
    lines = section("Message", st)

    lines.extend(field("Subject", _show(st, message.subject, st.value_width) or "-", st))

    if sender is not None:
        display = _show(st, sender.display_name, st.value_width)
        address = _show(st, sender.addr_spec, st.value_width)
        lines.extend(field("Displayed", display or "(none)", st))
        lines.extend(field("Actual", address or "(none)", st))
        if sender.registrable_domain and sender.registrable_domain != sender.domain:
            lines.extend(
                field(
                    "Domain",
                    _show(st, f"{sender.domain} -> {sender.registrable_domain}", st.value_width),
                    st,
                )
            )
    else:
        lines.extend(field("From", "(no parsable sender)", st))

    if message.identity.reply_to:
        reply = message.identity.reply_to[0]
        lines.extend(field("Reply-To", _show(st, reply.addr_spec, st.value_width), st))

    lines.extend(field("Date", _show(st, message.dates.raw) or "(missing)", st))

    if message.urls:
        lines.extend(field("Links", f"{len(message.urls)} found", st))
        for url in message.urls[:3]:
            lines.extend(field("", _show(st, url.defanged, st.value_width), st))
        if len(message.urls) > 3:
            lines.extend(field("", f"... and {len(message.urls) - 3} more", st))

    if message.attachments:
        lines.extend(field("Attachments", f"{len(message.attachments)} found", st))
        for attachment in message.attachments:
            label = _show(st, attachment.filename or "(unnamed)", 40)
            lines.extend(field("", f"{label}  {attachment.declared_mime}", st))

    return lines


def _findings_section(report: Report, st: Style) -> list[str]:
    verdict = report.verdict
    scored = verdict.scored

    lines = section("Findings", st)
    if not scored:
        lines.extend(field("", "No indicators fired.", st))
    else:
        count = len(scored)
        lines.extend(field("", f"{count} indicator{'s' if count != 1 else ''}", st))
        lines.append("")

    for signal, points in scored:
        lines.extend(finding_head(_severity_key(signal), f"+{points}", signal.id, signal.title, st))
        lines.extend(finding_body(_show(st, signal.explanation), st))
        for item in signal.evidence:
            excerpt = _show(st, item.excerpt, _EVIDENCE_WIDTH)
            lines.extend(field("evidence", f"{item.locator}  {excerpt}", st))
            if item.note:
                lines.extend(field("", _show(st, item.note, _EVIDENCE_WIDTH), st))
        lines.append("")

    for signal in verdict.suppressors:
        lines.extend(finding_head("good", "trust", signal.id, signal.title, st))
        lines.extend(finding_body(_show(st, signal.explanation), st))
        lines.append("")

    return lines[:-1] if lines and lines[-1] == "" else lines


def _scoring_section(report: Report, st: Style) -> list[str]:
    verdict = report.verdict
    if not verdict.categories:
        return []

    lines = section("Scoring", st)
    for category in verdict.categories:
        bar = st.bar(category.strength, 16)
        detail = f"raw {category.raw:.1f}, cap {category.cap:.0f}"
        if category.raw > category.cap:
            detail += " (capped)"
        lines.extend(field(str(category.category), f"{bar}  {detail}", st))

    if verdict.trust_factor > 0:
        lines.extend(field("trust", f"score reduced by {verdict.trust_factor:.0%}", st))

    lines.extend(
        finding_body(
            "Points shown against each finding are attributed contributions that sum to "
            "the score, not literal addends; see docs/SCORING.md.",
            st,
        )
    )
    return lines


def _coverage_section(report: Report, st: Style) -> list[str]:
    missing = [
        description
        for key, description in _PLANNED_COVERAGE.items()
        if key not in report.analyzers_run
    ]
    if not missing:
        return []

    lines = section("Not analyzed", st)
    lines.extend(
        finding_body(
            "This release does not yet examine " + ", ".join(missing) + ". "
            f"The highest score reachable from the evidence classes that did run is "
            f"{report.max_reachable_score}/100, so a low score reflects what was "
            f"checked rather than a clean bill of health.",
            st,
        )
    )
    return lines


def _problems_section(report: Report, st: Style) -> list[str]:
    if not report.degraded:
        return []

    lines = section("Degraded", st)
    for error in report.errors:
        lines.extend(field("analyzer", f"{error.analyzer_id}: {_show(st, error.message)}", st))
    for truncation in report.message.limits.describe():
        lines.extend(field("truncated", _show(st, truncation, st.value_width), st))
    return lines


def severity_rank(signal: Signal) -> int:
    return Severity(signal.severity).rank
