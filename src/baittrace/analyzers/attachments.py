"""Attachment analysis.

Static only: declared vs sniffed type, filename tricks, and HTML attachments
that contain a form or a script. Nothing is executed, unpacked, or uploaded.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import ClassVar

from ..model import Attachment, Message
from ..parse import defang
from ..signal import Category, Evidence, RuleSpec, Severity, Signal
from .base import Analyzer, Context

_DOUBLE_EXT = re.compile(
    r"(?i)\.(?:pdf|docx?|xlsx?|pptx?|txt|jpg|jpeg|png|gif)"
    r"\.(?:exe|scr|bat|cmd|js|vbs|ps1|jar|msi|com|pif)$"
)
_RTL = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"}

_DANGEROUS_EXT = (
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".js",
    ".vbs",
    ".ps1",
    ".jar",
    ".msi",
    ".com",
    ".pif",
    ".lnk",
    ".iso",
    ".img",
    ".dll",
    ".hta",
    ".wsf",
)

_DANGEROUS_MIME = {
    "application/x-dosexec",
    "application/x-executable",
    "application/x-msdownload",
    "application/x-iso9660-image",
}

_EQUIV = {
    ("text/html", "text/html"),
    ("application/pdf", "application/pdf"),
    ("application/zip", "application/zip"),
    ("image/jpeg", "image/jpeg"),
    ("image/png", "image/png"),
    ("image/gif", "image/gif"),
}


ATT001 = RuleSpec(
    id="ATT001",
    category=Category.ATTACHMENTS,
    title="Declared MIME type does not match file contents",
    severity=Severity.HIGH,
    weight=16.0,
    summary="The Content-Type header disagrees with the file's magic bytes.",
    advice="Trust the sniffed type. The declared type is attacker-controlled.",
    refs=(),
    false_positives="Some mail clients declare application/octet-stream for everything.",
)

ATT002 = RuleSpec(
    id="ATT002",
    category=Category.ATTACHMENTS,
    title="Double extension disguises an executable",
    severity=Severity.HIGH,
    weight=20.0,
    summary="The filename ends in a document extension followed by an executable extension.",
    advice="The last extension is the real one. Do not open the file.",
    refs=("MITRE ATT&CK T1566.001",),
    false_positives="Almost never legitimate.",
)

ATT003 = RuleSpec(
    id="ATT003",
    category=Category.ATTACHMENTS,
    title="HTML attachment contains an external form or script",
    severity=Severity.HIGH,
    weight=18.0,
    summary="An attached HTML file includes a form posting off-box or a script element.",
    advice="This is a credential-harvest page delivered as an attachment. Do not open it.",
    refs=("MITRE ATT&CK T1566.001",),
    false_positives=(
        "Rare in legitimate mail. Some ticketing systems attach HTML receipts without forms."
    ),
)

ATT004 = RuleSpec(
    id="ATT004",
    category=Category.ATTACHMENTS,
    title="Attachment is an executable, script, shortcut or disk image",
    severity=Severity.HIGH,
    weight=20.0,
    summary="The attachment is a type that executes code when opened.",
    advice="Do not open it. Escalate for malware analysis if the context warrants it.",
    refs=("MITRE ATT&CK T1566.001",),
    false_positives="Software vendors distributing installers. Confirm the sender independently.",
)

ATT005 = RuleSpec(
    id="ATT005",
    category=Category.ATTACHMENTS,
    title="Filename contains a right-to-left override",
    severity=Severity.HIGH,
    weight=18.0,
    summary="The filename uses a Unicode direction override to hide its real extension.",
    advice="The override is itself the finding. Read the sanitised filename in this report.",
    refs=("Unicode UAX #9",),
    false_positives=(
        "Almost never legitimate. Direction overrides in filenames are a known malware trick."
    ),
)


def _looks_html(att: Attachment) -> bool:
    name = att.filename.lower()
    return (
        "html" in att.declared_mime
        or att.sniffed_mime == "text/html"
        or name.endswith((".html", ".htm"))
    )


class AttachmentAnalyzer(Analyzer):
    id: ClassVar[str] = "attachments"
    prefix: ClassVar[str] = "ATT"
    category: ClassVar[Category] = Category.ATTACHMENTS
    requires_network: ClassVar[bool] = False
    RULES: ClassVar[tuple[RuleSpec, ...]] = (ATT001, ATT002, ATT003, ATT004, ATT005)

    def run(self, msg: Message, ctx: Context) -> Sequence[Signal]:
        signals: list[Signal] = []
        for att in msg.attachments:
            signals.extend(self._one(att))
        return signals

    def _one(self, att: Attachment) -> list[Signal]:
        found: list[Signal] = []
        evidence = [
            Evidence(
                locator=f"attachment:{att.part_path}",
                excerpt=att.filename or att.filename_raw or "(unnamed)",
                note=f"declared {att.declared_mime}; sniffed {att.sniffed_mime or 'unknown'}",
            )
        ]

        if (
            att.sniffed_mime
            and att.declared_mime
            and att.declared_mime.split(";")[0].strip().lower() != att.sniffed_mime
            and att.declared_mime != "application/octet-stream"
            and (att.declared_mime, att.sniffed_mime) not in _EQUIV
        ):
            declared = att.declared_mime.split(";")[0].strip().lower()
            if declared != att.sniffed_mime and not (
                declared.startswith("text/") and att.sniffed_mime.startswith("text/")
            ):
                found.append(
                    ATT001.fire(
                        confidence=0.85,
                        explanation=(
                            f"The part is declared as {declared} but the contents sniff as "
                            f"{att.sniffed_mime}."
                        ),
                        evidence=evidence,
                    )
                )

        name = att.filename or att.filename_raw
        if _DOUBLE_EXT.search(name):
            found.append(
                ATT002.fire(
                    confidence=0.95,
                    explanation=(
                        f"The filename {name!r} uses a double extension so a document icon "
                        f"hides an executable."
                    ),
                    evidence=evidence,
                )
            )

        if _looks_html(att) and (att.has_html_form or att.has_script):
            extra = ""
            if att.form_action:
                extra = f" The form submits to {defang(att.form_action)}."
            found.append(
                ATT003.fire(
                    confidence=0.9,
                    explanation=(
                        "The HTML attachment "
                        + ("contains a <form>" if att.has_html_form else "contains a <script>")
                        + "."
                        + extra
                        + " This is how a credential-harvest page is delivered without a link."
                    ),
                    evidence=evidence,
                )
            )

        lowered = name.lower()
        if lowered.endswith(_DANGEROUS_EXT) or att.sniffed_mime in _DANGEROUS_MIME:
            found.append(
                ATT004.fire(
                    confidence=0.9,
                    explanation=(
                        f"{name or 'unnamed part'} is an executable, script, "
                        f"shortcut or disk image."
                    ),
                    evidence=evidence,
                )
            )

        if any(char in att.filename_raw or char in att.filename for char in _RTL):
            found.append(
                ATT005.fire(
                    confidence=0.95,
                    explanation=(
                        "The filename contains a Unicode direction override, which is used to "
                        "make invoice.exe render as invoiceexe.png (or similar) in a file list."
                    ),
                    evidence=evidence,
                )
            )

        return found
