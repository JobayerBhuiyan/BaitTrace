"""Bounded MIME parsing into the canonical :class:`~baittrace.model.Message`.

Every byte here was written by someone trying to harm the reader, so this
module treats its input as hostile throughout: bounds are checked at each loop
boundary, malformed sections degrade to a recorded truncation rather than an
exception, and no content is ever rendered, executed, or fetched.

The parser uses ``compat32`` rather than the modern email policy on purpose.
The modern policy decodes headers for you and discards the original, but the
difference between a header's raw and decoded forms is itself evidence: RFC
2047 encoded-word abuse is how a display name smuggles a homoglyph past a
human. Keeping both forms costs a little code and preserves the signal.
"""

from __future__ import annotations

import email.utils
import hashlib
import re
from email.errors import HeaderParseError
from email.header import decode_header
from email.message import Message as EmailMessage
from email.parser import Parser
from email.policy import compat32
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .assets import decode_punycode, registrable_domain
from .errors import ParseError
from .ingest import RawInput
from .limits import Limits, LimitsReport
from .model import (
    Address,
    Attachment,
    AuthResults,
    Bodies,
    Dates,
    Header,
    Headers,
    Hop,
    Identity,
    Message,
    Routing,
    Structure,
    Url,
)

_UNFOLD = re.compile(r"\s*\r?\n[ \t]+")
_URL_RE = re.compile(r"""(?i)\b((?:https?|ftp)://[^\s<>"'`\]\)\},]+)""")
_RECEIVED_FROM = re.compile(r"(?i)\bfrom\s+([^\s;()]+)")
_RECEIVED_BY = re.compile(r"(?i)\bby\s+([^\s;()]+)")
_RECEIVED_WITH = re.compile(r"(?i)\bwith\s+([^\s;()]+)")
_RECEIVED_IP = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?")

_AUTH_HEADERS = {
    "authentication-results": "authentication_results",
    "received-spf": "received_spf",
    "dkim-signature": "dkim_signatures",
}

_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"%PDF-", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
    (b"PK\x05\x06", "application/zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage"),
    (b"MZ", "application/x-dosexec"),
    (b"\x7fELF", "application/x-executable"),
    (b"Rar!\x1a\x07", "application/x-rar-compressed"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    (b"\x1f\x8b", "application/gzip"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"{\\rtf", "application/rtf"),
    (b"#!", "text/x-shellscript"),
)


# ---------------------------------------------------------------------------
# Header helpers
# ---------------------------------------------------------------------------


def recover_text(text: str) -> str:
    """Turn byte-preserved header text back into real characters.

    The message is parsed from a latin-1 decode, which is lossless but leaves
    every non-ASCII byte as a separate character. Re-encoding and decoding as
    UTF-8 recovers what the attacker actually wrote.

    This matters more than it sounds. A header carrying raw UTF-8 bytes is
    malformed per RFC 5322 and therefore exactly what a hand-rolled phishing
    kit emits. Without this step the right-to-left override in
    ``invoice<RLO>gnp.exe`` and the Cyrillic ``i`` in a homoglyph domain both
    dissolve into replacement characters, and the two rules written to catch
    them see nothing at all.

    Text that is not valid UTF-8 is left in its latin-1 reading, which is the
    best available guess and never worse than discarding the bytes.
    """
    if text.isascii():
        return text
    try:
        return text.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        pass
    if any("\ud800" <= char <= "\udfff" for char in text):
        return text.encode("utf-8", "surrogateescape").decode("utf-8", errors="replace")
    return text


def header_str(value: object) -> str:
    """Coerce a header value to ``str``.

    With the compat32 policy the stdlib returns an :class:`email.header.Header`
    instead of a string whenever the value contains non-ASCII bytes, which is
    exactly the case a phishing sample hits: a filename carrying a
    right-to-left override decodes to a Header object, and every downstream
    ``.lower()`` then raises. Anything hostile enough to be interesting is
    hostile enough to break naive typing, so nothing here trusts the declared
    return type.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return recover_text(value)
    try:
        return recover_text(str(value))
    except (UnicodeDecodeError, LookupError):  # pragma: no cover - defensive
        return repr(value)


def unfold(value: str) -> str:
    return _UNFOLD.sub(" ", value).strip()


def decode_rfc2047(value: str) -> str:
    """Decode encoded-words, never raising on malformed input.

    ``decode_header`` raises :class:`~email.errors.HeaderParseError` on
    base64 that does not decode, which is a routine occurrence in mail written
    by something other than a mail client. An undecodable header is data, not
    an error.
    """
    try:
        parts = decode_header(value)
    except (ValueError, UnicodeDecodeError, HeaderParseError):
        return value

    out: list[str] = []
    for text, charset in parts:
        if isinstance(text, bytes):
            try:
                out.append(text.decode(charset or "utf-8", errors="replace"))
            except (LookupError, UnicodeDecodeError):
                out.append(text.decode("utf-8", errors="replace"))
        else:
            out.append(recover_text(text))
    return "".join(out)


def _build_address(raw_display: str, addr_spec: str) -> Address:
    raw_display = recover_text(raw_display)
    addr_spec = recover_text(addr_spec).strip().strip("<>")
    local, _, domain = addr_spec.rpartition("@")
    domain = domain.strip().lower().rstrip(".")
    return Address(
        raw=f"{raw_display} <{addr_spec}>".strip() if raw_display else addr_spec,
        display_name=decode_rfc2047(raw_display).strip().strip('"'),
        raw_display_name=raw_display.strip().strip('"'),
        addr_spec=addr_spec,
        local_part=local,
        domain=domain,
        registrable_domain=registrable_domain(domain),
    )


def parse_addresses(values: tuple[str, ...]) -> tuple[Address, ...]:
    """Parse address-list headers, tolerating garbage."""
    out: list[Address] = []
    for value in values:
        try:
            pairs = email.utils.getaddresses([unfold(value)])
        except (ValueError, AttributeError):
            continue
        for display, addr in pairs:
            if not display and not addr:
                continue
            out.append(_build_address(display, addr))
    return tuple(out)


def _collect_headers(msg: EmailMessage, limits: Limits, report: LimitsReport) -> Headers:
    items: list[Header] = []
    for index, (name, raw_value) in enumerate(msg.items()):
        if index >= limits.max_headers:
            report.record(
                "max_headers",
                limits.max_headers,
                f"stopped after {limits.max_headers} headers; the rest were not analyzed",
            )
            break

        raw = header_str(raw_value)
        if len(raw) > limits.max_header_bytes:
            report.record(
                "max_header_bytes",
                limits.max_header_bytes,
                f"header {name!r} truncated from {len(raw)} characters",
            )
            raw = raw[: limits.max_header_bytes]

        unfolded = unfold(raw)
        items.append(
            Header(name=name, raw_value=unfolded, value=decode_rfc2047(unfolded), index=index)
        )
    return Headers(tuple(items))


def _parse_dates(headers: Headers) -> Dates:
    header = headers.first("date")
    if header is None:
        return Dates(missing=True)

    raw = header.value.strip()
    if not raw:
        return Dates(raw=raw, malformed=True, missing=False)

    try:
        parsed = email.utils.parsedate_to_datetime(raw)
    except (TypeError, ValueError, OverflowError):
        return Dates(raw=raw, malformed=True, missing=False)
    return Dates(raw=raw, parsed=parsed, malformed=False, missing=False)


def _parse_routing(headers: Headers) -> Routing:
    hops: list[Hop] = []
    received = headers.all("received")
    # Received headers are prepended, so the last one is the earliest hop.
    for index, header in enumerate(reversed(received)):
        raw = header.value
        timestamp = None
        _, _, date_part = raw.rpartition(";")
        if date_part:
            try:
                timestamp = email.utils.parsedate_to_datetime(date_part.strip())
            except (TypeError, ValueError, OverflowError):
                timestamp = None

        from_match = _RECEIVED_FROM.search(raw)
        by_match = _RECEIVED_BY.search(raw)
        with_match = _RECEIVED_WITH.search(raw)
        ip_match = _RECEIVED_IP.search(raw)

        hops.append(
            Hop(
                index=index,
                raw=raw,
                from_host=from_match.group(1).strip("[]") if from_match else "",
                by_host=by_match.group(1).strip("[]") if by_match else "",
                protocol=with_match.group(1) if with_match else "",
                claimed_ip=ip_match.group(1) if ip_match else "",
                timestamp=timestamp,
            )
        )

    originating = hops[0].claimed_ip if hops else ""
    # trust_boundary_index stays None: without a configured trusted relay, every
    # hop is attacker-supplied and any conclusion drawn from it is advisory.
    return Routing(hops=tuple(hops), originating_ip=originating, trust_boundary_index=None)


def _parse_auth(headers: Headers) -> AuthResults:
    buckets: dict[str, list[str]] = {v: [] for v in _AUTH_HEADERS.values()}
    arc: list[str] = []
    for header in headers:
        target = _AUTH_HEADERS.get(header.lname)
        if target:
            buckets[target].append(header.value)
        elif header.lname.startswith("arc-"):
            arc.append(f"{header.name}: {header.value}")

    return AuthResults(
        authentication_results=tuple(buckets["authentication_results"]),
        received_spf=tuple(buckets["received_spf"]),
        dkim_signatures=tuple(buckets["dkim_signatures"]),
        arc_headers=tuple(arc),
    )


# ---------------------------------------------------------------------------
# Body and part walking
# ---------------------------------------------------------------------------


class _LinkExtractor(HTMLParser):
    """Pulls link targets and anchor text out of HTML.

    A parser, never a renderer. Nothing is fetched, no script is evaluated, and
    no external resource is resolved: analyzing a phishing email must not tell
    the attacker that it was read.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str, str]] = []
        self._pending: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        mapping = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and "href" in mapping:
            self._pending = mapping["href"]
            self._text = []
        elif tag in {"img", "script", "iframe"} and mapping.get("src"):
            self.links.append((mapping["src"], "", f"html:{tag}[src]"))
        elif tag == "form" and mapping.get("action"):
            self.links.append((mapping["action"], "", "html:form[action]"))

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._pending is not None:
            self.links.append((self._pending, "".join(self._text).strip(), "html:a[href]"))
            self._pending = None
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._pending is not None:
            self._text.append(data)

    def error(self, message: str) -> None:  # pragma: no cover - py3.9 compat shim
        return


def defang(url: str) -> str:
    """Neuter a URL so it cannot be clicked out of a terminal or a ticket."""
    out = re.sub(r"(?i)^http", "hxxp", url)
    split = urlsplit(out if "://" in out else f"//{out}")
    host = split.netloc
    if host:
        out = out.replace(host, host.replace(".", "[.]"), 1)
    return out


def _make_url(raw: str, anchor: str, location: str) -> Url | None:
    raw = raw.strip()
    if not raw or raw.lower().startswith(("mailto:", "tel:", "#")):
        return None

    candidate = raw if "://" in raw else f"http://{raw}"
    try:
        split = urlsplit(candidate)
    except ValueError:
        return None

    host = (split.hostname or "").lower().rstrip(".")
    if not host:
        return None

    is_puny = "xn--" in host
    return Url(
        raw=raw,
        normalized=candidate,
        defanged=defang(raw),
        scheme=(split.scheme or "http").lower(),
        host=host,
        registrable_domain=registrable_domain(host),
        path=split.path or "",
        anchor_text=anchor,
        location=location,
        is_punycode=is_puny,
        unicode_host=decode_punycode(host) if is_puny else "",
    )


def extract_urls(bodies: Bodies, limits: Limits, report: LimitsReport) -> tuple[Url, ...]:
    found: list[Url] = []
    seen: set[tuple[str, str]] = set()

    def add(raw: str, anchor: str, location: str) -> bool:
        url = _make_url(raw, anchor, location)
        if url is None:
            return True
        key = (url.raw, url.location)
        if key in seen:
            return True
        if len(found) >= limits.max_urls:
            report.record(
                "max_urls",
                limits.max_urls,
                f"stopped after {limits.max_urls} links; the rest were not analyzed",
            )
            return False
        seen.add(key)
        found.append(url)
        return True

    for match in _URL_RE.finditer(bodies.text_plain):
        if not add(match.group(1), "", "body:text"):
            return tuple(found)

    if bodies.text_html:
        extractor = _LinkExtractor()
        try:
            extractor.feed(bodies.text_html)
            extractor.close()
        except (AssertionError, ValueError):
            report.record("html_parse", 0, "HTML could not be fully parsed; links may be missing")
        for href, anchor, location in extractor.links:
            if not add(href, anchor, location):
                return tuple(found)
        for match in _URL_RE.finditer(bodies.text_html):
            if not add(match.group(1), "", "body:html"):
                return tuple(found)

    return tuple(found)


def sniff(payload: bytes) -> str:
    for magic, mime in _MAGIC:
        if payload.startswith(magic):
            return mime
    head = payload[:512].lstrip().lower()
    if head.startswith((b"<!doctype html", b"<html")):
        return "text/html"
    return ""


def _decode_payload(part: EmailMessage, limits: Limits, report: LimitsReport) -> bytes:
    decoded: object = None
    try:
        decoded = part.get_payload(decode=True)
    except (AssertionError, ValueError, TypeError):
        decoded = None

    payload: bytes
    if isinstance(decoded, bytes):
        payload = decoded
    else:
        fallback = part.get_payload()
        payload = fallback.encode("utf-8", errors="replace") if isinstance(fallback, str) else b""

    if len(payload) > limits.max_body_bytes:
        report.record(
            "max_body_bytes",
            limits.max_body_bytes,
            f"part truncated from {len(payload)} bytes",
        )
        payload = payload[: limits.max_body_bytes]
    return payload


def _walk(
    msg: EmailMessage, limits: Limits, report: LimitsReport
) -> tuple[Bodies, tuple[Attachment, ...], Structure]:
    text_parts: list[str] = []
    html_parts: list[str] = []
    charsets: list[str] = []
    attachments: list[Attachment] = []
    content_types: list[str] = []
    anomalies: list[str] = []

    part_count = 0
    max_depth = 0
    stopped = False

    def visit(part: EmailMessage, depth: int, path: str) -> None:
        nonlocal part_count, max_depth, stopped
        if stopped:
            return
        max_depth = max(max_depth, depth)

        if depth > limits.max_depth:
            report.record(
                "max_depth",
                limits.max_depth,
                f"MIME nesting deeper than {limits.max_depth} at {path}; subtree skipped",
            )
            stopped = True
            return

        part_count += 1
        if part_count > limits.max_parts:
            report.record(
                "max_parts",
                limits.max_parts,
                f"stopped after {limits.max_parts} parts; the rest were not analyzed",
            )
            stopped = True
            return

        content_type = header_str(part.get_content_type()).lower()
        content_types.append(content_type)

        if part.is_multipart():
            children = part.get_payload()
            if not isinstance(children, list):
                anomalies.append(f"{path}: multipart part with a non-list payload")
                return
            if len(children) == 1 and content_type.startswith("multipart/"):
                anomalies.append(f"{path}: multipart container with a single part")
            for i, child in enumerate(children):
                if isinstance(child, EmailMessage):
                    visit(child, depth + 1, f"{path}.{i}")
            return

        filename_raw = header_str(part.get_filename())
        disposition = header_str(part.get("Content-Disposition")).lower()
        payload = _decode_payload(part, limits, report)

        is_attachment = bool(filename_raw) or disposition.startswith("attachment")
        if is_attachment:
            attachments.append(
                Attachment(
                    filename_raw=filename_raw,
                    filename=decode_rfc2047(filename_raw),
                    declared_mime=content_type,
                    sniffed_mime=sniff(payload),
                    size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                    part_path=path,
                    is_inline=disposition.startswith("inline"),
                )
            )
            return

        charset = header_str(part.get_content_charset()) or "utf-8"
        charsets.append(charset)
        try:
            text = payload.decode(charset, errors="replace")
        except (LookupError, UnicodeDecodeError):
            text = payload.decode("utf-8", errors="replace")

        if content_type == "text/plain":
            text_parts.append(text)
        elif content_type == "text/html":
            html_parts.append(text)
        elif content_type.startswith("text/"):
            text_parts.append(text)

    visit(msg, 1, "0")

    bodies = Bodies(
        text_plain="\n".join(text_parts).strip(),
        text_html="\n".join(html_parts).strip(),
        charsets=tuple(dict.fromkeys(charsets)),
    )
    structure = Structure(
        part_count=part_count,
        max_depth=max_depth,
        content_types=tuple(content_types),
        is_multipart=msg.is_multipart(),
        anomalies=tuple(anomalies),
    )
    return bodies, tuple(attachments), structure


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def parse(raw: RawInput, limits: Limits | None = None) -> Message:
    """Turn raw bytes into a canonical :class:`~baittrace.model.Message`."""
    bounds = limits or Limits()
    report = LimitsReport()

    # Parsed from a latin-1 decode rather than from bytes. BytesParser wraps any
    # header containing 8-bit bytes in an email.header.Header whose str() has
    # already replaced those bytes with U+FFFD, destroying the evidence before
    # this module ever sees it. latin-1 is a lossless byte-to-character mapping,
    # so nothing is lost here and recover_text() restores the real characters
    # afterwards. Binary payloads are unaffected: get_payload(decode=True) round
    # trips characters below U+0100 back to their original bytes.
    try:
        parsed = Parser(policy=compat32).parsestr(raw.data.decode("latin-1"))
    except (ValueError, TypeError, AssertionError) as exc:
        raise ParseError(f"could not parse message: {exc}") from exc

    if parsed is None:  # pragma: no cover - defensive
        raise ParseError("could not parse message: parser returned nothing")

    headers = _collect_headers(parsed, bounds, report)
    if not headers.items and not raw.data.strip():
        raise ParseError("message has no headers and no body")

    from_values = tuple(h.raw_value for h in headers.all("from"))
    sender_addresses = parse_addresses(tuple(h.raw_value for h in headers.all("sender")))
    return_path_addresses = parse_addresses(tuple(h.raw_value for h in headers.all("return-path")))

    identity = Identity(
        from_addresses=parse_addresses(from_values),
        reply_to=parse_addresses(tuple(h.raw_value for h in headers.all("reply-to"))),
        to=parse_addresses(tuple(h.raw_value for h in headers.all("to"))),
        cc=parse_addresses(tuple(h.raw_value for h in headers.all("cc"))),
        sender=sender_addresses[0] if sender_addresses else None,
        return_path=return_path_addresses[0] if return_path_addresses else None,
    )

    bodies, attachments, structure = _walk(parsed, bounds, report)
    urls = extract_urls(bodies, bounds, report)

    subject_header = headers.first("subject")
    return Message(
        identity=identity,
        subject=subject_header.value if subject_header else "",
        raw_subject=subject_header.raw_value if subject_header else "",
        dates=_parse_dates(headers),
        routing=_parse_routing(headers),
        auth=_parse_auth(headers),
        bodies=bodies,
        urls=urls,
        attachments=attachments,
        structure=structure,
        headers=headers,
        limits=report,
        size_bytes=raw.size,
        sha256=raw.sha256,
        source=raw.source,
    )


def parse_bytes(data: bytes, source: str = "<bytes>", limits: Limits | None = None) -> Message:
    """Convenience wrapper for callers that already hold the bytes."""
    raw = RawInput(data=data, source=source, sha256=hashlib.sha256(data).hexdigest())
    return parse(raw, limits)


__all__ = [
    "decode_rfc2047",
    "defang",
    "extract_urls",
    "header_str",
    "parse",
    "parse_bytes",
    "recover_text",
    "sniff",
    "unfold",
]
