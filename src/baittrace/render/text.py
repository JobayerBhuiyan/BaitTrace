"""The terminal report.

Reads a :class:`~baittrace.report.Report` and nothing else. Every string that
originated in the message passes through :mod:`baittrace.sanitize` on the way
out, and every URL is defanged, so the report can be pasted into a ticket
without becoming a delivery mechanism itself.

The sectioned layout (Authentication, Sender, Links, Attachments, Reasons for
score) is the instructor mock: a reader should see what is wrong before they
see the rule catalogue.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..model import AuthState
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
        "Do not interact with this email. Do not click any link, open any "
        "attachment, or reply. Escalate for analyst review."
    ),
    BAND_HIGH: (
        "Do not interact with this email. Escalate for analyst review. Verify with "
        "the supposed sender through a channel you already trust, not one this "
        "message provides."
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

_EVIDENCE_WIDTH = 160

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
    """Every string that came from the message leaves through here."""
    return clean(text, width=width, redacted=st.redact, ascii_only=not st.unicode)


def _ids(signals: Iterable[Signal]) -> set[str]:
    return {signal.id for signal in signals}


def render(report: Report, style: Style | None = None) -> str:
    st = style or Style()
    lines: list[str] = []
    verdict = report.verdict

    lines.extend(header(f"{report.tool.name.upper()} {report.tool.version}", verdict.rulepack, st))

    band_text = st.paint(verdict.band, _BAND_STYLE.get(verdict.band, "info"))
    lines.extend(field_split("Risk", band_text, f"{verdict.score}/100", st))
    lines.extend(field("", st.bar(verdict.score / 100.0, st.value_width), st))
    lines.extend(field("Source", _show(st, report.message.source, st.value_width), st))

    mode = "online" if report.online else "offline"
    ran = ", ".join(report.analyzers_run) or "none"
    lines.extend(field("Analyzed", f"{mode} | {ran} | {report.duration_ms} ms", st))

    lines.extend(_auth_section(report, st))
    lines.extend(_sender_section(report, st))
    lines.extend(_links_section(report, st))
    lines.extend(_attachments_section(report, st))
    lines.extend(_reasons_section(report, st))
    lines.extend(_coverage_section(report, st))
    lines.extend(_problems_section(report, st))

    lines.extend(section("Recommended action", st))
    lines.extend(finding_body(_ACTION.get(verdict.band, _ACTION[BAND_BENIGN]), st))
    lines.append("")

    return "\n".join(lines)


def _status_line(st: Style, severity: str, text: str) -> list[str]:
    return field(st.glyph(severity), text, st, label_style=severity)


def _auth_section(report: Report, st: Style) -> list[str]:
    auth = report.message.auth
    fired = _ids(report.verdict.signals)
    lines = section("Authentication", st)
    reported = " (reported)" if not report.online else " (verified)"

    def describe(state: AuthState, fail_id: str, pass_label: str, fail_label: str) -> list[str]:
        if fail_id in fired or state is AuthState.FAIL:
            return _status_line(st, "high", fail_label)
        if state is AuthState.PASS:
            return _status_line(st, "good", pass_label + reported)
        if state is AuthState.UNVERIFIABLE:
            return _status_line(st, "medium", f"{pass_label.split()[0]} unverifiable")
        if state is AuthState.UNTRUSTED:
            return _status_line(st, "medium", f"{pass_label.split()[0]} untrusted")
        return _status_line(st, "info", f"{pass_label.split()[0]} absent")

    lines.extend(describe(auth.spf, "AUTH001", "SPF passed", "SPF failed"))
    lines.extend(describe(auth.dkim, "AUTH002", "DKIM signature valid", "DKIM signature invalid"))

    if "AUTH003" in fired or auth.dmarc is AuthState.FAIL:
        policy = f" policy: {auth.dmarc_policy}" if auth.dmarc_policy else ""
        severity = "medium" if auth.dmarc_policy == "none" else "high"
        lines.extend(_status_line(st, severity, f"DMARC failed{policy}"))
    elif auth.dmarc_policy == "none":
        lines.extend(_status_line(st, "medium", "DMARC policy: none"))
    elif auth.dmarc is AuthState.PASS:
        lines.extend(_status_line(st, "good", "DMARC passed" + reported))
    else:
        lines.extend(_status_line(st, "info", "DMARC absent"))

    if "AUTH005" in fired:
        lines.extend(
            _status_line(
                st,
                "high",
                "SPF/DKIM pass is not aligned with From",
            )
        )
    if "AUTH004" in fired:
        lines.extend(_status_line(st, "low", "No authentication results on this message"))

    return lines


def _sender_section(report: Report, st: Style) -> list[str]:
    message = report.message
    sender = message.identity.primary_from
    fired = _ids(report.verdict.signals)
    lines = section("Sender", st)
    lines.extend(field("Subject", _show(st, message.subject, st.value_width) or "-", st))

    if sender is None:
        lines.extend(field("From", "(no parsable sender)", st))
        return lines

    display = _show(st, sender.display_name, st.value_width)
    address = _show(st, sender.addr_spec, st.value_width)
    lines.extend(field("Displayed", display or "(none)", st))
    lines.extend(field("Actual", address or "(none)", st))
    if "IDN003" in fired:
        lines.extend(finding_body("^ suspicious lookalike", st))
    if "IDN001" in fired:
        lines.extend(finding_body("display name contains a different address", st))
    if "IDN005" in fired:
        lines.extend(finding_body("punycode or mixed-script domain", st))

    if message.identity.reply_to:
        reply = message.identity.reply_to[0]
        lines.extend(field("Reply-To", _show(st, reply.addr_spec, st.value_width), st))

    lines.extend(field("Date", _show(st, message.dates.raw) or "(missing)", st))
    return lines


def _links_section(report: Report, st: Style) -> list[str]:
    message = report.message
    url_signals = [s for s in report.verdict.signals if s.id.startswith("URL")]
    lines = section("Links", st)
    count = len(message.urls)
    noun = "URLs" if count != 1 else "URL"
    lines.extend(field("", f"{count} {noun} discovered", st))

    ip_count = sum(1 for s in url_signals if s.id == "URL001")
    redirect_count = sum(1 for s in url_signals if s.id == "URL007")
    if redirect_count:
        lines.extend(
            _status_line(st, "medium", f"{redirect_count} redirect through unrelated domains")
        )
    if ip_count:
        lines.extend(_status_line(st, "medium", f"{ip_count} uses an IP address"))

    for url in message.urls[:5]:
        lines.extend(field("", _show(st, url.defanged, st.value_width), st))
    if len(message.urls) > 5:
        lines.extend(field("", f"... and {len(message.urls) - 5} more", st))

    for signal in url_signals:
        if signal.id in {"URL001", "URL007"}:
            continue
        lines.extend(_status_line(st, _severity_key(signal), signal.title))

    return lines


def _attachments_section(report: Report, st: Style) -> list[str]:
    message = report.message
    if not message.attachments and not any(s.id.startswith("ATT") for s in report.verdict.signals):
        return []

    lines = section("Attachments", st)
    if not message.attachments:
        lines.extend(field("", "none", st))
        return lines

    att_signals = [s for s in report.verdict.signals if s.id.startswith("ATT")]
    for attachment in message.attachments:
        label = _show(st, attachment.filename or "(unnamed)", 40)
        lines.extend(field("", f"{label}  {attachment.declared_mime}", st))
        if "html" in attachment.declared_mime or attachment.filename.lower().endswith(
            (".html", ".htm")
        ):
            lines.extend(_status_line(st, "medium", "HTML attachment"))
        if attachment.has_html_form:
            lines.extend(_status_line(st, "high", "Contains external form submission"))
        if attachment.has_script:
            lines.extend(_status_line(st, "high", "Contains a script element"))

    for signal in att_signals:
        if signal.id in {"ATT003"}:
            continue
        lines.extend(_status_line(st, _severity_key(signal), signal.title))
    return lines


def _reasons_section(report: Report, st: Style) -> list[str]:
    verdict = report.verdict
    scored = verdict.scored
    lines = section("Reasons for score", st)
    if not scored:
        lines.extend(field("", "No indicators fired.", st))
        return lines

    for signal, points in scored:
        lines.extend(finding_head(_severity_key(signal), f"+{points}", signal.id, signal.title, st))
        lines.extend(finding_body(_show(st, signal.explanation), st))
        for item in signal.evidence[:3]:
            excerpt = _show(st, item.excerpt, _EVIDENCE_WIDTH)
            lines.extend(field("evidence", f"{item.locator}  {excerpt}", st))
        lines.append("")

    for signal in verdict.suppressors:
        lines.extend(finding_head("good", "trust", signal.id, signal.title, st))
        lines.extend(finding_body(_show(st, signal.explanation), st))
        lines.append("")

    if verdict.categories:
        lines.extend(section("Scoring", st))
        for category in verdict.categories:
            bar = st.bar(category.strength, 16)
            detail = f"raw {category.raw:.1f}, cap {category.cap:.0f}"
            if category.raw > category.cap:
                detail += " (capped)"
            lines.extend(field(str(category.category), f"{bar}  {detail}", st))
        lines.extend(
            finding_body(
                "Points shown against each finding are attributed contributions that sum to "
                "the score, not literal addends; see docs/SCORING.md.",
                st,
            )
        )

    return lines[:-1] if lines and lines[-1] == "" else lines


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
            "checked rather than a clean bill of health.",
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
