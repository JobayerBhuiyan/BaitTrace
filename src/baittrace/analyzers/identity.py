"""Sender identity: impersonation detection.

Impersonation is the core of phishing, so this is the analyzer that earns its
keep. It compares what the message claims to be against what it actually is,
using confusable skeletons rather than a hand-maintained list of tricks, so
``micros0ft``, ``rnicrosoft`` and ``mіcrosoft`` (Cyrillic i) are all caught by
the same code path.

One deliberate omission: recognising ``microsoft.com`` in ``From`` does **not**
reduce the score. Without DKIM verification the ``From`` header is a free-text
field that anyone can write, so treating it as evidence of legitimacy would
turn the easiest forgery into a discount. Trust is only granted through the
operator's explicit allowlist (IDN900) until the AUTH analyzer lands in M4 and
can verify a signature.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import ClassVar

from ..assets import (
    Brand,
    brands,
    decode_punycode,
    is_freemail,
    is_mixed_script,
    public_suffix_list,
    registrable_domain,
    skeleton,
)
from ..model import Address, Message
from ..signal import Category, Evidence, RuleSpec, Severity, Signal, SignalKind
from ..similarity import distance_threshold, levenshtein
from .base import Analyzer, Context
from .common import bulk_note, looks_like_bulk

_EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_WORD = re.compile(r"[A-Za-z0-9\u00a0-\uffff]+")
_SPLIT_LABEL = re.compile(r"[-_]+")

# Aliases shorter than this are skipped entirely. "ups" and "irs" would match
# an enormous number of innocent substrings, and every one of those matches
# would be a false positive.
MIN_ALIAS_LENGTH = 5


IDN001 = RuleSpec(
    id="IDN001",
    category=Category.IDENTITY,
    title="Display name contains a different email address",
    severity=Severity.HIGH,
    weight=18.0,
    summary=(
        "The display name shows one email address while the message is actually from another."
    ),
    advice="Treat the visible address as forged. Verify through a known-good channel.",
    refs=("RFC 5322 section 3.4", "MITRE ATT&CK T1566.002"),
    false_positives=(
        "Ticketing systems and mailing lists sometimes put the original sender's "
        "address in the display name when relaying."
    ),
)

IDN002 = RuleSpec(
    id="IDN002",
    category=Category.IDENTITY,
    title="Reply-To points at a different organisation",
    severity=Severity.MEDIUM,
    weight=10.0,
    summary="Replies would go to a different registrable domain than the sender.",
    advice="Check where a reply would actually go before responding.",
    refs=("RFC 5322 section 3.6.2",),
    false_positives=(
        "Extremely common in legitimate bulk mail: newsletters, ticketing systems "
        "and no-reply senders routinely redirect replies. Weighted low for this reason."
    ),
)

IDN003 = RuleSpec(
    id="IDN003",
    category=Category.IDENTITY,
    title="Sender domain resembles a known brand",
    severity=Severity.HIGH,
    weight=25.0,
    summary=(
        "The sending domain collapses to the confusable skeleton of a well-known "
        "brand but is not one of that brand's domains."
    ),
    advice="Treat as impersonation. Do not interact; escalate for analyst review.",
    refs=("Unicode UTS #39", "MITRE ATT&CK T1566.002"),
    false_positives=(
        "Resellers, franchises and regional partners legitimately put a brand name "
        "in their domain. Add those domains to the brand entry or the allowlist."
    ),
)

IDN004 = RuleSpec(
    id="IDN004",
    category=Category.IDENTITY,
    title="Display name claims a brand the domain does not belong to",
    severity=Severity.HIGH,
    weight=20.0,
    summary=(
        "The display name asserts a well-known brand while the message is sent "
        "from an unrelated or consumer mailbox."
    ),
    advice="Treat the branding as decoration. Verify through the brand's own app or site.",
    refs=("MITRE ATT&CK T1566.002",),
    false_positives=(
        "Small businesses and contractors sometimes send brand-related mail from "
        "consumer mailboxes."
    ),
)

IDN005 = RuleSpec(
    id="IDN005",
    category=Category.IDENTITY,
    title="Sender domain uses punycode or mixes scripts",
    severity=Severity.HIGH,
    weight=15.0,
    summary=(
        "The sending domain is internationalised or combines writing systems, the "
        "shape of a homograph attack."
    ),
    advice="Read the decoded form of the domain rather than the rendered one.",
    refs=("RFC 3492", "RFC 5890", "Unicode UTS #39"),
    false_positives=(
        "Non-English organisations use internationalised domains legitimately. "
        "Mixed script within one label is the stronger part of this signal."
    ),
)

IDN900 = RuleSpec(
    id="IDN900",
    category=Category.IDENTITY,
    title="Sender is on the operator's allowlist",
    severity=Severity.INFO,
    weight=0.6,
    summary="The sending domain or address was explicitly allowlisted in configuration.",
    advice="No action. This sender was vouched for by your own configuration.",
    refs=(),
    kind=SignalKind.SUPPRESSOR,
    false_positives=(
        "An allowlisted domain can still be spoofed while DKIM verification is "
        "unavailable, which is why the trust granted here is partial."
    ),
)


def _name_part(domain: str) -> str:
    """The domain with its public suffix removed."""
    suffix = public_suffix_list().public_suffix(domain)
    if suffix and domain.endswith(suffix) and domain != suffix:
        return domain[: -(len(suffix) + 1)]
    return domain


def _domain_tokens(domain: str) -> list[str]:
    """Candidate strings a lookalike could be hiding in.

    Every label and every hyphen-separated piece is considered, because
    ``micros0ft-login.example`` hides the brand in a fragment rather than in the
    registrable domain itself.
    """
    body = _name_part(domain)
    tokens: set[str] = set()
    for label in body.split("."):
        if not label:
            continue
        tokens.add(label)
        tokens.update(piece for piece in _SPLIT_LABEL.split(label) if piece)
    if body:
        tokens.add(body.replace(".", "").replace("-", ""))
    return sorted(t for t in tokens if len(t) >= MIN_ALIAS_LENGTH)


def match_brand(token: str) -> tuple[Brand, str, float] | None:
    """Match a token against the brand list, returning the confidence too.

    An exact skeleton match where the token is *not* literally the brand name
    means confusable characters were used, which is deliberate deception and
    scores high. A token that is literally the brand name on someone else's
    domain is suspicious but has innocent explanations, so it scores lower.
    """
    token_skeleton = skeleton(token)
    if len(token_skeleton) < MIN_ALIAS_LENGTH:
        return None

    for brand in brands():
        for alias in brand.aliases:
            if len(alias) < MIN_ALIAS_LENGTH:
                continue
            alias_skeleton = skeleton(alias)
            if token_skeleton == alias_skeleton:
                confidence = 0.75 if token.lower() == alias else 0.95
                return brand, alias, confidence

            threshold = distance_threshold(alias_skeleton)
            if threshold and levenshtein(token_skeleton, alias_skeleton) <= threshold:
                return brand, alias, 0.8
    return None


class IdentityAnalyzer(Analyzer):
    id: ClassVar[str] = "identity"
    prefix: ClassVar[str] = "IDN"
    category: ClassVar[Category] = Category.IDENTITY
    requires_network: ClassVar[bool] = False
    RULES: ClassVar[tuple[RuleSpec, ...]] = (IDN001, IDN002, IDN003, IDN004, IDN005, IDN900)

    def run(self, msg: Message, ctx: Context) -> Sequence[Signal]:
        sender = msg.identity.primary_from
        if sender is None or sender.is_empty:
            return ()

        signals: list[Signal] = []
        allowlisted = ctx.config.is_allowlisted(
            sender.registrable_domain or sender.domain, sender.addr_spec
        )

        if allowlisted:
            signals.append(self._allowlisted(sender))
            return signals

        signals.extend(self._display_name_address(sender))
        signals.extend(self._reply_to(msg, sender))
        signals.extend(self._lookalike_domain(sender))
        signals.extend(self._display_name_brand(sender))
        signals.extend(self._script_confusion(sender))
        return signals

    # -- IDN900 ------------------------------------------------------------

    def _allowlisted(self, sender: Address) -> Signal:
        return IDN900.fire(
            confidence=1.0,
            explanation=(
                f"{sender.addr_spec or sender.domain} matches an allowlist entry in your "
                f"configuration, so identity findings for this sender are suppressed."
            ),
            evidence=[Evidence(locator="header:From", excerpt=sender.raw)],
        )

    # -- IDN001 ------------------------------------------------------------

    def _display_name_address(self, sender: Address) -> list[Signal]:
        if not sender.display_name:
            return []

        match = _EMAIL_IN_TEXT.search(sender.display_name)
        if match is None:
            return []

        claimed = match.group(0)
        claimed_domain = registrable_domain(claimed.rpartition("@")[2])
        actual_domain = sender.registrable_domain or sender.domain
        if not claimed_domain or claimed_domain == actual_domain:
            return []

        return [
            IDN001.fire(
                confidence=0.95,
                explanation=(
                    f"The display name shows {claimed}, but the message is actually from "
                    f"{sender.addr_spec}. A mail client shows the display name, so the "
                    f"address a reader sees is not the address that sent this."
                ),
                evidence=[
                    Evidence(
                        locator="header:From",
                        excerpt=sender.raw,
                        note=f"claims {claimed_domain}, actually {actual_domain}",
                    )
                ],
            )
        ]

    # -- IDN002 ------------------------------------------------------------

    def _reply_to(self, msg: Message, sender: Address) -> list[Signal]:
        if not msg.identity.reply_to:
            return []

        sender_domain = sender.registrable_domain or sender.domain
        if not sender_domain:
            return []

        divergent = [
            addr
            for addr in msg.identity.reply_to
            if (addr.registrable_domain or addr.domain)
            and (addr.registrable_domain or addr.domain) != sender_domain
        ]
        if not divergent:
            return []

        target = divergent[0]
        target_domain = target.registrable_domain or target.domain
        bulk = looks_like_bulk(msg)
        return [
            IDN002.fire(
                confidence=0.8,
                weight=4.0 if bulk else IDN002.weight,
                explanation=(
                    f"A reply would be delivered to {target.addr_spec} at {target_domain}, "
                    f"not to {sender_domain}. Redirecting replies is how a conversation is "
                    f"moved somewhere the real sender cannot see it." + bulk_note(msg)
                ),
                evidence=[
                    Evidence(locator="header:From", excerpt=sender.raw),
                    Evidence(locator="header:Reply-To", excerpt=target.raw),
                ],
            )
        ]

    # -- IDN003 ------------------------------------------------------------

    def _lookalike_domain(self, sender: Address) -> list[Signal]:
        domain = sender.domain
        if not domain:
            return []

        registrable = sender.registrable_domain or domain
        for token in _domain_tokens(domain):
            matched = match_brand(token)
            if matched is None:
                continue

            brand, alias, confidence = matched
            if registrable in brand.domains or domain in brand.domains:
                return []

            note = (
                f"skeleton({token}) == skeleton({alias})"
                if skeleton(token) == skeleton(alias)
                else f"skeleton({token}) is {levenshtein(skeleton(token), skeleton(alias))} "
                f"edit(s) from skeleton({alias})"
            )
            return [
                IDN003.fire(
                    confidence=confidence,
                    explanation=(
                        f"The sending domain {domain} contains {token!r}, which reduces to the "
                        f"same confusable skeleton as {brand.name}. {registrable} is not one of "
                        f"{brand.name}'s known domains, so the resemblance is not legitimate."
                    ),
                    evidence=[
                        Evidence(locator="header:From", excerpt=sender.raw, note=note),
                    ],
                )
            ]
        return []

    # -- IDN004 ------------------------------------------------------------

    def _display_name_brand(self, sender: Address) -> list[Signal]:
        display = sender.display_name
        if not display:
            return []

        registrable = sender.registrable_domain or sender.domain
        candidates = [w for w in _WORD.findall(display) if len(w) >= MIN_ALIAS_LENGTH]
        candidates.append(display.replace(" ", ""))

        for token in candidates:
            matched = match_brand(token)
            if matched is None:
                continue

            brand, _alias, _confidence = matched
            if registrable in brand.domains or sender.domain in brand.domains:
                return []

            freemail = is_freemail(sender.domain) or is_freemail(registrable)
            return [
                IDN004.fire(
                    confidence=0.9 if freemail else 0.75,
                    explanation=(
                        f"The display name claims {brand.name}, but the message was sent from "
                        f"{registrable or sender.domain}, which is "
                        + (
                            "a consumer mailbox provider. A brand does not contact customers "
                            "from a personal mailbox."
                            if freemail
                            else f"not one of {brand.name}'s known domains."
                        )
                    ),
                    evidence=[
                        Evidence(
                            locator="header:From",
                            excerpt=sender.raw,
                            note=f"display name claims {brand.name}",
                        )
                    ],
                )
            ]
        return []

    # -- IDN005 ------------------------------------------------------------

    def _script_confusion(self, sender: Address) -> list[Signal]:
        domain = sender.domain
        if not domain:
            return []

        decoded = decode_punycode(domain)
        is_puny = "xn--" in domain.lower()
        mixed = is_mixed_script(decoded)
        if not is_puny and not mixed:
            return []

        if is_puny and mixed:
            reason = (
                f"{domain} is an internationalised domain that decodes to {decoded!r}, which "
                f"mixes writing systems within the name."
            )
            confidence = 0.95
        elif is_puny:
            reason = (
                f"{domain} is an internationalised domain. It renders as {decoded!r}, which is "
                f"what a reader sees rather than the ASCII form."
            )
            confidence = 0.7
        else:
            reason = (
                f"{domain} mixes writing systems within the name, which is how a homograph "
                f"attack makes one alphabet impersonate another."
            )
            confidence = 0.9

        return [
            IDN005.fire(
                confidence=confidence,
                explanation=reason,
                evidence=[
                    Evidence(
                        locator="header:From",
                        excerpt=sender.raw,
                        note=f"decodes to {decoded}" if is_puny else "mixed script",
                    )
                ],
            )
        ]
