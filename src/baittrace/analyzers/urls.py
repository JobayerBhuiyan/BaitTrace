"""Link analysis.

Every URL here was extracted by the parser and is already defanged for display.
Nothing is fetched unless the operator passed ``--follow-redirects``. Following
a phishing link can confirm to the attacker that a live human received it,
which is why that path is off by default and called out in ``--help``.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from functools import lru_cache
from typing import ClassVar
from urllib.parse import urlsplit

from ..assets import is_mixed_script, registrable_domain
from ..model import Message, Url
from ..parse import defang
from ..signal import Category, Evidence, RuleSpec, Severity, Signal
from .base import Analyzer, Context
from .identity import MIN_ALIAS_LENGTH, match_brand

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_DOMAIN_IN_TEXT = re.compile(r"(?i)\b(?:https?://)?(?:www\.)?([a-z0-9][a-z0-9.-]+\.[a-z]{2,})\b")


URL001 = RuleSpec(
    id="URL001",
    category=Category.URLS,
    title="Link uses an IP address as the host",
    severity=Severity.HIGH,
    weight=15.0,
    summary="A URL's host is a raw IP address rather than a domain name.",
    advice="Do not visit the address. Legitimate brands do not send customers to raw IPs.",
    refs=("MITRE ATT&CK T1566.002",),
    false_positives="Internal monitoring systems sometimes link to literal IPs on a private LAN.",
)

URL002 = RuleSpec(
    id="URL002",
    category=Category.URLS,
    title="Link host uses punycode or mixed scripts",
    severity=Severity.HIGH,
    weight=14.0,
    summary="A URL host is internationalised or mixes writing systems, the shape of a homograph.",
    advice="Read the decoded form of the host rather than the rendered one.",
    refs=("RFC 3492", "Unicode UTS #39"),
    false_positives="Non-English organisations use internationalised domains legitimately.",
)

URL003 = RuleSpec(
    id="URL003",
    category=Category.URLS,
    title="Anchor text disagrees with the link target",
    severity=Severity.HIGH,
    weight=16.0,
    summary="Visible link text names one domain while the href points at another.",
    advice="Trust the href, not the painted text. Do not visit either without verifying.",
    refs=("MITRE ATT&CK T1566.002",),
    false_positives=(
        "URL shorteners and tracking wrappers often display a clean name over a redirector."
    ),
)

URL004 = RuleSpec(
    id="URL004",
    category=Category.URLS,
    title="Link uses a known URL shortener",
    severity=Severity.MEDIUM,
    weight=8.0,
    summary="The host is a URL shortener, which hides the real destination.",
    advice="Do not follow it. Expand it in a sandbox if an analyst must see the target.",
    refs=(),
    false_positives="Legitimate marketing mail uses shorteners. Weighted medium for this reason.",
)

URL005 = RuleSpec(
    id="URL005",
    category=Category.URLS,
    title="Link hides the real host behind userinfo",
    severity=Severity.HIGH,
    weight=18.0,
    summary="The URL uses the userinfo '@' trick so a brand name appears before the real host.",
    advice=(
        "The host after '@' is the one a browser will contact. Treat the brand prefix "
        "as decoration."
    ),
    refs=("RFC 3986 section 3.2.1",),
    false_positives=(
        "Almost never legitimate in mail. Credentials in URLs are a defect even when benign."
    ),
)

URL006 = RuleSpec(
    id="URL006",
    category=Category.URLS,
    title="Link puts a brand name on an unrelated domain",
    severity=Severity.HIGH,
    weight=14.0,
    summary="A brand alias appears in a URL label or path on a domain that is not the brand's.",
    advice="The brand in the path is decoration. The registrable domain is what matters.",
    refs=("MITRE ATT&CK T1566.002",),
    false_positives="Resellers and status pages sometimes put a brand in a path they do not own.",
)

URL007 = RuleSpec(
    id="URL007",
    category=Category.URLS,
    title="Redirect chain ends on an unrelated domain",
    severity=Severity.HIGH,
    weight=12.0,
    summary="Following the URL (explicitly requested) landed on a different registrable domain.",
    advice="The first hop is not the destination. Do not visit either.",
    refs=(),
    false_positives=(
        "Marketing wrappers redirect through tracking domains. Confirm before treating as malice."
    ),
)


@lru_cache(maxsize=1)
def shorteners() -> frozenset[str]:
    from importlib import resources

    text = (resources.files("baittrace.data") / "shorteners.txt").read_text(encoding="utf-8")
    return frozenset(
        line.strip().lower()
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    )


def _domain_from_text(text: str) -> str:
    match = _DOMAIN_IN_TEXT.search(text.strip())
    if match is None:
        return ""
    host = match.group(1).lower().rstrip(".")
    return registrable_domain(host) or host


def _defang_chain(chain: list[str]) -> list[str]:
    return [defang(hop) for hop in chain]


class UrlAnalyzer(Analyzer):
    id: ClassVar[str] = "urls"
    prefix: ClassVar[str] = "URL"
    category: ClassVar[Category] = Category.URLS
    requires_network: ClassVar[bool] = False
    RULES: ClassVar[tuple[RuleSpec, ...]] = (
        URL001,
        URL002,
        URL003,
        URL004,
        URL005,
        URL006,
        URL007,
    )

    def run(self, msg: Message, ctx: Context) -> Sequence[Signal]:
        signals: list[Signal] = []
        for url in msg.urls:
            signals.extend(self._one(url, ctx))
        return signals

    def _one(self, url: Url, ctx: Context) -> list[Signal]:
        found: list[Signal] = []
        evidence = [
            Evidence(
                locator=url.location,
                excerpt=url.defanged,
                note=url.host,
            )
        ]

        if url.is_ip or _IPV4.match(url.host):
            found.append(
                URL001.fire(
                    confidence=0.95,
                    explanation=(
                        f"The link host is the IP address {url.host}, not a domain name. "
                        f"Brands do not send customers to raw addresses."
                    ),
                    evidence=evidence,
                )
            )

        decoded = url.unicode_host or url.host
        if url.is_punycode or is_mixed_script(decoded):
            found.append(
                URL002.fire(
                    confidence=0.85,
                    explanation=(
                        f"The link host {url.host} "
                        + (
                            f"is punycode and decodes to {decoded!r}."
                            if url.is_punycode
                            else "mixes writing systems within the name."
                        )
                    ),
                    evidence=evidence,
                )
            )

        if url.anchor_text:
            painted = _domain_from_text(url.anchor_text)
            actual = url.registrable_domain or url.host
            if painted and actual and painted != actual and not url.anchor_text.startswith("#"):
                found.append(
                    URL003.fire(
                        confidence=0.9,
                        explanation=(
                            f"The visible text names {painted} but the href points at {actual}."
                        ),
                        evidence=evidence,
                    )
                )

        host = url.host.removeprefix("www.")
        if host in shorteners() or url.registrable_domain in shorteners():
            found.append(
                URL004.fire(
                    confidence=0.8,
                    explanation=(
                        f"{url.host} is a known URL shortener, which hides the real destination."
                    ),
                    evidence=evidence,
                )
            )

        if url.userinfo:
            found.append(
                URL005.fire(
                    confidence=0.95,
                    explanation=(
                        f"The URL puts {url.userinfo!r} before '@' so a reader sees that name, "
                        f"but the browser contacts {url.host}."
                    ),
                    evidence=evidence,
                )
            )

        if not url.is_ip:
            found.extend(self._brand_in_url(url, evidence))

        if ctx.config.follow_redirects:
            found.extend(self._redirects(url, ctx, evidence))

        return found

    def _brand_in_url(self, url: Url, evidence: list[Evidence]) -> list[Signal]:
        tokens: list[str] = []
        for label in url.host.split("."):
            tokens.extend(p for p in re.split(r"[-_]", label) if p)
        tokens.extend(p for p in url.path.split("/") if p)
        registrable = url.registrable_domain
        for token in tokens:
            if len(token) < MIN_ALIAS_LENGTH:
                continue
            matched = match_brand(token)
            if matched is None:
                continue
            brand, _alias, _conf = matched
            if registrable in brand.domains or url.host in brand.domains:
                return []
            return [
                URL006.fire(
                    confidence=0.8,
                    explanation=(
                        f"The URL contains {token!r}, which resembles {brand.name}, but "
                        f"{registrable or url.host} is not one of {brand.name}'s domains."
                    ),
                    evidence=evidence,
                )
            ]
        return []

    def _redirects(self, url: Url, ctx: Context, evidence: list[Evidence]) -> list[Signal]:
        answer = ctx.resolver.trace_redirects(url.normalized, max_hops=5)
        if not answer.ok or not answer.value:
            return []
        chain = answer.value
        if len(chain) < 2:
            return []
        start = url.registrable_domain or url.host
        try:
            terminal_host = (urlsplit(chain[-1]).hostname or "").lower()
        except ValueError:
            return []
        end = registrable_domain(terminal_host) or terminal_host
        if not start or not end or start == end:
            return []
        return [
            URL007.fire(
                confidence=0.85,
                explanation=(
                    f"The URL at {start} redirected through {len(chain) - 1} hop(s) and ended "
                    f"at {end}, a different organisation."
                ),
                evidence=[
                    *evidence,
                    Evidence(
                        locator="redirect-chain",
                        excerpt=" -> ".join(_defang_chain(chain)),
                    ),
                ],
            )
        ]
