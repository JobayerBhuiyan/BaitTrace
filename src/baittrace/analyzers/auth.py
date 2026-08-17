"""SPF, DKIM and DMARC.

Authentication is the strongest single evidence class, and the easiest to
report incorrectly. This analyzer never collapses a result to a boolean. A
rotated DKIM selector is ``unverifiable``, not ``fail``; an Authentication-
Results header the attacker wrote is ``untrusted`` until a trusted relay is
configured or ``--online`` verifies it independently.

Reported mode (default) parses Authentication-Results / Received-SPF /
DKIM-Signature with no network. Verified mode overlays DNS lookups through
``ctx.resolver``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import ClassVar

from ..assets import brand_domains, registrable_domain
from ..model import AuthState, Message
from ..signal import Category, Evidence, RuleSpec, Severity, Signal, SignalKind
from .base import Analyzer, Context

AUTH001 = RuleSpec(
    id="AUTH001",
    category=Category.AUTH,
    title="SPF failed",
    severity=Severity.HIGH,
    weight=18.0,
    summary="The sending IP is not authorised to send mail for the envelope domain.",
    advice="Treat the envelope sender as forged. Read it alongside DMARC alignment.",
    refs=("RFC 7208",),
    false_positives=(
        "Forwarders break SPF. A fail without a DMARC reject policy is weaker evidence "
        "than the same fail with one."
    ),
)

AUTH002 = RuleSpec(
    id="AUTH002",
    category=Category.AUTH,
    title="DKIM signature is invalid",
    severity=Severity.HIGH,
    weight=20.0,
    summary=(
        "A DKIM signature is present and does not verify, or Authentication-Results "
        "reports it as fail."
    ),
    advice="The body or signed headers were altered, or the signature was never valid.",
    refs=("RFC 6376",),
    false_positives=(
        "Mailing lists that rewrite Subject break DKIM. A rotated selector is unverifiable, "
        "not a failure, and does not fire this rule."
    ),
)

AUTH003 = RuleSpec(
    id="AUTH003",
    category=Category.AUTH,
    title="DMARC failed or publishes no enforcement",
    severity=Severity.HIGH,
    weight=18.0,
    summary=(
        "DMARC disposition is fail, or the domain publishes p=none so a fail is not enforced. "
        "Either way the From domain is not protected."
    ),
    advice="Do not trust the visible From domain. Brand impersonation usually presents this way.",
    refs=("RFC 7489",),
    false_positives=(
        "Many legitimate domains still publish p=none. The finding is stronger when alignment "
        "also fails."
    ),
)

AUTH004 = RuleSpec(
    id="AUTH004",
    category=Category.AUTH,
    title="Authentication results are absent",
    severity=Severity.LOW,
    weight=6.0,
    summary="The message carries no Authentication-Results, Received-SPF or DKIM-Signature.",
    advice="Weak on its own. Note it alongside identity findings.",
    refs=("RFC 8601",),
    false_positives=(
        "Internal mail that never passed an internet gateway often has no authentication "
        "headers. Weighted low for this reason."
    ),
)

AUTH005 = RuleSpec(
    id="AUTH005",
    category=Category.AUTH,
    title="SPF or DKIM passed for a domain that does not match From",
    severity=Severity.HIGH,
    weight=16.0,
    summary=(
        "An authentication check passed, but the passing identifier is not aligned with the "
        "From header the reader sees. This is how brand impersonation usually presents."
    ),
    advice="The pass authenticates a different organisation than the one being impersonated.",
    refs=("RFC 7489", "RFC 7208"),
    false_positives=(
        "Email service providers send on a customer's behalf from their own domain. "
        "Check whether the envelope domain is an expected provider."
    ),
)

AUTH900 = RuleSpec(
    id="AUTH900",
    category=Category.AUTH,
    title="DMARC-aligned DKIM passed",
    severity=Severity.INFO,
    weight=0.5,
    summary="A DKIM signature passed and aligns with the From domain.",
    advice="No action. This is evidence of authenticity, not of innocence of content.",
    refs=("RFC 6376", "RFC 7489"),
    kind=SignalKind.SUPPRESSOR,
    false_positives=(
        "A compromised mailbox at a real brand will also pass DKIM. Alignment is not a "
        "clean bill of health."
    ),
)


def aligned(left: str, right: str) -> bool:
    """Relaxed DMARC alignment: registrable domains match."""
    if not left or not right:
        return False
    a = registrable_domain(left) or left.lower()
    b = registrable_domain(right) or right.lower()
    return a == b


def _evaluate_spf(record: str, ip: str) -> AuthState:
    """Minimal SPF evaluator: ip4 mechanisms and all, plus include via pre-expansion.

    ``include:`` is handled by the caller, which appends fetched records. This
    function is pure so tests do not need DNS.
    """
    if not ip:
        return AuthState.UNVERIFIABLE
    try:
        from ipaddress import ip_address, ip_network

        addr = ip_address(ip)
    except ValueError:
        return AuthState.UNVERIFIABLE

    tokens = record.split()
    if not tokens or not tokens[0].lower().startswith("v=spf1"):
        return AuthState.ABSENT

    qualifier_map = {
        "+": AuthState.PASS,
        "-": AuthState.FAIL,
        "~": AuthState.FAIL,
        "?": AuthState.ABSENT,
    }
    for token in tokens[1:]:
        token = token.strip()
        if not token:
            continue
        qual = "+"
        if token[0] in "+-~?":
            qual, token = token[0], token[1:]
        outcome = qualifier_map[qual]
        lowered = token.lower()
        if lowered == "all":
            return outcome
        if lowered.startswith("ip4:"):
            try:
                if addr in ip_network(token[4:], strict=False):
                    return outcome
            except ValueError:
                continue
        if lowered.startswith("ip6:"):
            try:
                if addr in ip_network(token[4:], strict=False):
                    return outcome
            except ValueError:
                continue
    return AuthState.ABSENT


class AuthAnalyzer(Analyzer):
    id: ClassVar[str] = "auth"
    prefix: ClassVar[str] = "AUTH"
    category: ClassVar[Category] = Category.AUTH
    requires_network: ClassVar[bool] = False
    RULES: ClassVar[tuple[RuleSpec, ...]] = (
        AUTH001,
        AUTH002,
        AUTH003,
        AUTH004,
        AUTH005,
        AUTH900,
    )

    def run(self, msg: Message, ctx: Context) -> Sequence[Signal]:
        auth = msg.auth
        from_domain = ""
        sender = msg.identity.primary_from
        if sender is not None:
            from_domain = sender.registrable_domain or sender.domain
        if auth.from_domain:
            from_domain = registrable_domain(auth.from_domain) or auth.from_domain

        spf, dkim, dmarc = auth.spf, auth.dkim, auth.dmarc
        reported = True

        if ctx.online:
            verified = self._verify(msg, ctx)
            if verified is not None:
                spf, dkim, dmarc = verified
                reported = False

        signals: list[Signal] = []
        mode = "reported" if reported else "verified"
        note = (
            " These results were reported by the receiving gateway and have not been "
            "independently verified."
            if reported
            else " These results were verified over DNS."
        )

        if not auth.present and spf is AuthState.ABSENT and dkim is AuthState.ABSENT:
            signals.append(
                AUTH004.fire(
                    confidence=0.9,
                    explanation=(
                        "No Authentication-Results, Received-SPF or DKIM-Signature header is "
                        "present, so SPF, DKIM and DMARC cannot be evaluated from this message "
                        "alone."
                    ),
                    evidence=[],
                )
            )
            return signals

        envelope = auth.spf_domain or (
            (msg.identity.return_path.registrable_domain or msg.identity.return_path.domain)
            if msg.identity.return_path
            else ""
        )

        if spf is AuthState.FAIL:
            signals.append(
                AUTH001.fire(
                    confidence=0.9 if not reported else 0.75,
                    explanation=(
                        f"SPF {mode} result is fail for {envelope or 'the envelope domain'}." + note
                    ),
                    evidence=self._evidence(msg),
                )
            )

        if dkim is AuthState.FAIL:
            signals.append(
                AUTH002.fire(
                    confidence=0.9 if not reported else 0.8,
                    explanation=(
                        f"DKIM {mode} result is fail"
                        + (f" for d={auth.dkim_domain}" if auth.dkim_domain else "")
                        + ". The signature does not validate."
                        + note
                    ),
                    evidence=self._evidence(msg),
                )
            )

        spf_aligned = spf is AuthState.PASS and aligned(envelope, from_domain)
        dkim_aligned = (
            dkim is AuthState.PASS
            and bool(auth.dkim_domain or from_domain)
            and aligned(auth.dkim_domain or from_domain, from_domain)
        )
        aligned_pass = spf_aligned or dkim_aligned

        policy = auth.dmarc_policy
        dmarc_fail = dmarc is AuthState.FAIL
        policy_none = policy == "none"
        # p=none is the impersonation composite only when alignment also failed.
        if dmarc_fail or (policy_none and not aligned_pass):
            if dmarc_fail and policy_none:
                reason = f"DMARC {mode} result is fail and the published policy is p=none"
            elif dmarc_fail:
                reason = f"DMARC {mode} result is fail"
            else:
                reason = (
                    "The domain publishes a DMARC policy of p=none, which does not "
                    "enforce alignment"
                )
            signals.append(
                AUTH003.fire(
                    confidence=0.85 if dmarc_fail else 0.6,
                    explanation=reason + "." + note,
                    evidence=self._evidence(msg),
                )
            )
        if (
            (spf is AuthState.PASS or dkim is AuthState.PASS)
            and from_domain
            and not (spf_aligned or dkim_aligned)
        ):
            passing = envelope if spf is AuthState.PASS else auth.dkim_domain
            signals.append(
                AUTH005.fire(
                    confidence=0.9,
                    explanation=(
                        f"Authentication passed for {passing}, but the message claims "
                        f"to be from {from_domain}. The pass does not cover the identity a "
                        f"reader sees." + note
                    ),
                    evidence=self._evidence(msg),
                )
            )

        if dkim_aligned:
            registrable = registrable_domain(from_domain) or from_domain
            trusted = ctx.config.is_allowlisted(registrable) or registrable in brand_domains()
            if trusted:
                signals.append(
                    AUTH900.fire(
                        confidence=0.9,
                        explanation=(
                            f"DKIM passed and aligns with {from_domain}, which is a known or "
                            f"allowlisted sending domain."
                        ),
                        evidence=self._evidence(msg),
                    )
                )

        return signals

    def _evidence(self, msg: Message) -> list[Evidence]:
        items: list[Evidence] = []
        for raw in msg.auth.authentication_results[:2]:
            items.append(Evidence(locator="header:Authentication-Results", excerpt=raw))
        for raw in msg.auth.received_spf[:1]:
            items.append(Evidence(locator="header:Received-SPF", excerpt=raw))
        for raw in msg.auth.dkim_signatures[:1]:
            items.append(Evidence(locator="header:DKIM-Signature", excerpt=raw[:200]))
        return items

    def _verify(self, msg: Message, ctx: Context) -> tuple[AuthState, AuthState, AuthState] | None:
        """Overlay reported results with DNS-backed checks. None if DNS is unavailable."""
        spf, dkim, dmarc = msg.auth.spf, msg.auth.dkim, msg.auth.dmarc
        did_anything = False

        envelope = msg.auth.spf_domain
        if not envelope and msg.identity.return_path is not None:
            envelope = msg.identity.return_path.domain
        ip = msg.routing.originating_ip

        if envelope:
            answer = ctx.resolver.txt(envelope)
            if answer.ok and answer.value:
                records = [t for t in answer.value if t.lower().startswith("v=spf1")]
                includes = list(records)
                for record in records:
                    for token in record.split():
                        token = token.strip()
                        if token.lower().startswith("include:"):
                            nested = ctx.resolver.txt(token.split(":", 1)[1])
                            if nested.ok and nested.value:
                                includes.extend(
                                    t for t in nested.value if t.lower().startswith("v=spf1")
                                )
                if includes:
                    spf = _evaluate_spf(" ".join(includes), ip)
                    did_anything = True
            elif answer.ok and not answer.value:
                spf = AuthState.ABSENT
                did_anything = True
            elif not answer.ok:
                spf = AuthState.UNVERIFIABLE

        dkim = self._verify_dkim(msg, ctx, dkim)
        if dkim is not msg.auth.dkim:
            did_anything = True

        from_domain = ""
        if msg.identity.primary_from is not None:
            from_domain = msg.identity.primary_from.domain
        if from_domain:
            answer = ctx.resolver.txt(f"_dmarc.{from_domain}")
            if answer.ok and answer.value:
                did_anything = True
                blob = " ".join(answer.value)
                policy = ""
                for part in blob.split(";"):
                    part = part.strip()
                    if part.lower().startswith("p="):
                        policy = part.split("=", 1)[1].strip().lower()
                passing = (spf is AuthState.PASS and aligned(envelope, from_domain)) or (
                    dkim is AuthState.PASS and aligned(msg.auth.dkim_domain, from_domain)
                )
                if passing:
                    dmarc = AuthState.PASS
                elif policy in {"quarantine", "reject", "none"}:
                    dmarc = AuthState.FAIL
            elif not answer.ok:
                dmarc = AuthState.UNVERIFIABLE

        return (spf, dkim, dmarc) if did_anything else None

    def _verify_dkim(self, msg: Message, ctx: Context, current: AuthState) -> AuthState:
        if not ctx.raw_bytes:
            return current
        selector = msg.auth.dkim_selector
        domain = msg.auth.dkim_domain
        if selector and domain:
            answer = ctx.resolver.txt(f"{selector}._domainkey.{domain}")
            if not answer.ok:
                return AuthState.UNVERIFIABLE
            if answer.ok and not answer.value:
                return AuthState.UNVERIFIABLE

        try:
            import dkim
        except ImportError:
            return current

        def dnsfunc(name: bytes | str, timeout: int = 5) -> bytes:
            query = name.decode("ascii", errors="replace") if isinstance(name, bytes) else name
            query = query.rstrip(".")
            ans = ctx.resolver.txt(query)
            if not ans.ok or not ans.value:
                raise OSError("no dkim key")
            value = ans.value[0]
            return value.encode("utf-8") if isinstance(value, str) else value

        try:
            ok = bool(dkim.verify(ctx.raw_bytes, dnsfunc=dnsfunc))
        except Exception:  # noqa: BLE001 - hostile signatures, missing keys
            return AuthState.UNVERIFIABLE
        return AuthState.PASS if ok else AuthState.FAIL
