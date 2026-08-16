"""The canonical message model.

This is the contract between parsing and everything downstream. Analyzers read
only from here, which is what keeps them pure and independently testable.

Three modelling decisions are load-bearing and easy to get wrong:

* Headers are an ordered sequence with duplicates preserved. A second ``From``
  header is a real spoofing technique that exploits disagreement between what
  the MTA validated and what the mail client displays. A dict destroys that
  evidence before an analyzer can see it.
* Every string keeps both its raw and decoded form. RFC 2047 encoded-word abuse
  is only visible when the two can be compared.
* Routing carries an explicit trust boundary. ``Received`` headers below your
  own infrastructure are attacker-supplied, so any claim derived from them is
  advisory until a trusted relay is configured.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime

from .limits import LimitsReport


@dataclass(frozen=True, slots=True)
class Header:
    """One header field, exactly as it appeared, plus its decoded form."""

    name: str
    raw_value: str
    value: str
    index: int

    @property
    def lname(self) -> str:
        return self.name.lower()

    @property
    def was_encoded(self) -> bool:
        """True when RFC 2047 decoding changed the value."""
        return self.raw_value.strip() != self.value.strip()


@dataclass(frozen=True, slots=True)
class Headers:
    """Ordered header list with duplicates preserved."""

    items: tuple[Header, ...] = ()

    def __iter__(self) -> Iterator[Header]:
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)

    def all(self, name: str) -> tuple[Header, ...]:
        lname = name.lower()
        return tuple(h for h in self.items if h.lname == lname)

    def first(self, name: str) -> Header | None:
        found = self.all(name)
        return found[0] if found else None

    def value(self, name: str) -> str:
        header = self.first(name)
        return header.value if header else ""

    def count(self, name: str) -> int:
        return len(self.all(name))

    def names(self) -> tuple[str, ...]:
        return tuple(h.name for h in self.items)


@dataclass(frozen=True, slots=True)
class Address:
    """A parsed mailbox.

    ``registrable_domain`` is the public-suffix-aware domain, which is the only
    correct basis for comparing two domains for "same organisation".
    """

    raw: str = ""
    display_name: str = ""
    raw_display_name: str = ""
    addr_spec: str = ""
    local_part: str = ""
    domain: str = ""
    registrable_domain: str = ""

    @property
    def is_empty(self) -> bool:
        return not self.addr_spec and not self.display_name


@dataclass(frozen=True, slots=True)
class Identity:
    """Who the message claims to be from."""

    from_addresses: tuple[Address, ...] = ()
    reply_to: tuple[Address, ...] = ()
    to: tuple[Address, ...] = ()
    cc: tuple[Address, ...] = ()
    sender: Address | None = None
    return_path: Address | None = None

    @property
    def primary_from(self) -> Address | None:
        return self.from_addresses[0] if self.from_addresses else None

    @property
    def from_domain(self) -> str:
        primary = self.primary_from
        return primary.registrable_domain if primary else ""


@dataclass(frozen=True, slots=True)
class Dates:
    """The ``Date`` header and whether it can be believed."""

    raw: str = ""
    parsed: datetime | None = None
    malformed: bool = False
    missing: bool = True


@dataclass(frozen=True, slots=True)
class Url:
    """A link found in the message.

    ``defanged`` is precomputed so no renderer can forget to use it.
    """

    raw: str
    normalized: str
    defanged: str
    scheme: str
    host: str
    registrable_domain: str
    path: str = ""
    anchor_text: str = ""
    location: str = "body"
    is_punycode: bool = False
    unicode_host: str = ""


@dataclass(frozen=True, slots=True)
class Attachment:
    """An attached part.

    ``filename_raw`` may contain bidi overrides or control characters; it is
    kept verbatim because that is itself evidence, and sanitized at render.
    """

    filename_raw: str
    filename: str
    declared_mime: str
    sniffed_mime: str
    size: int
    sha256: str
    part_path: str
    is_inline: bool = False


@dataclass(frozen=True, slots=True)
class Hop:
    """One ``Received`` header, parsed."""

    index: int
    raw: str
    from_host: str = ""
    by_host: str = ""
    protocol: str = ""
    claimed_ip: str = ""
    timestamp: datetime | None = None


@dataclass(frozen=True, slots=True)
class Routing:
    """The delivery path, and how much of it can be trusted."""

    hops: tuple[Hop, ...] = ()
    originating_ip: str = ""
    trust_boundary_index: int | None = None

    @property
    def trusted(self) -> bool:
        """False when no trusted relay is configured, making hops advisory."""
        return self.trust_boundary_index is not None


@dataclass(frozen=True, slots=True)
class AuthResults:
    """Authentication headers as written.

    Populated but not interpreted in M1. The AUTH analyzer arrives in M4 and
    distinguishes pass, fail, unverifiable, absent, and untrusted, because DKIM
    keys rotate and reporting an unresolvable selector as "invalid" would be a
    false accusation.
    """

    authentication_results: tuple[str, ...] = ()
    received_spf: tuple[str, ...] = ()
    dkim_signatures: tuple[str, ...] = ()
    arc_headers: tuple[str, ...] = ()

    @property
    def present(self) -> bool:
        return bool(
            self.authentication_results
            or self.received_spf
            or self.dkim_signatures
            or self.arc_headers
        )


@dataclass(frozen=True, slots=True)
class Bodies:
    """Decoded body text. HTML is a string and is never rendered."""

    text_plain: str = ""
    text_html: str = ""
    charsets: tuple[str, ...] = ()

    @property
    def has_html(self) -> bool:
        return bool(self.text_html.strip())

    @property
    def combined(self) -> str:
        return f"{self.text_plain}\n{self.text_html}".strip()


@dataclass(frozen=True, slots=True)
class Structure:
    """Shape of the MIME tree."""

    part_count: int = 1
    max_depth: int = 1
    content_types: tuple[str, ...] = ()
    is_multipart: bool = False
    anomalies: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Message:
    """One parsed email, normalized."""

    identity: Identity = field(default_factory=Identity)
    subject: str = ""
    raw_subject: str = ""
    dates: Dates = field(default_factory=Dates)
    routing: Routing = field(default_factory=Routing)
    auth: AuthResults = field(default_factory=AuthResults)
    bodies: Bodies = field(default_factory=Bodies)
    urls: tuple[Url, ...] = ()
    attachments: tuple[Attachment, ...] = ()
    structure: Structure = field(default_factory=Structure)
    headers: Headers = field(default_factory=Headers)
    limits: LimitsReport = field(default_factory=LimitsReport)
    size_bytes: int = 0
    sha256: str = ""
    source: str = "<stdin>"
