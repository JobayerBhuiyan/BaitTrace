"""IDN rule tests.

Each rule gets a case that fires it and a case that must not. The negative
cases are the ones worth writing: a rule that never stays quiet is not a
detection, it is a warning banner.
"""

from __future__ import annotations

import pytest

from baittrace.analyzers.identity import match_brand
from baittrace.assets import skeleton
from baittrace.config import Config

from ..conftest import build_eml, fired, scan_eml


class TestIDN001DisplayNameAddress:
    def test_fires_when_display_name_shows_another_address(self) -> None:
        report = scan_eml(build_eml(headers={"From": '"service@paypal.com" <attacker@gmail.com>'}))
        assert "IDN001" in fired(report)

    def test_quiet_when_display_name_address_matches(self) -> None:
        report = scan_eml(build_eml(headers={"From": '"alice@corp.example" <alice@corp.example>'}))
        assert "IDN001" not in fired(report)

    def test_quiet_without_a_display_name(self) -> None:
        report = scan_eml(build_eml(headers={"From": "alice@corp.example"}))
        assert "IDN001" not in fired(report)


class TestIDN002ReplyTo:
    def test_fires_on_different_registrable_domain(self) -> None:
        report = scan_eml(build_eml(headers={"Reply-To": "elsewhere@other.example"}))
        assert "IDN002" in fired(report)

    def test_quiet_on_a_subdomain_of_the_sender(self) -> None:
        report = scan_eml(build_eml(headers={"Reply-To": "help@support.corp.example"}))
        assert "IDN002" not in fired(report)

    def test_weight_drops_for_bulk_mail(self) -> None:
        personal = scan_eml(build_eml(headers={"Reply-To": "elsewhere@other.example"}))
        bulk = scan_eml(
            build_eml(
                headers={"Reply-To": "elsewhere@other.example"},
                extra=[("List-Unsubscribe", "<https://other.example/u>")],
            )
        )
        personal_weight = next(s.weight for s in personal.verdict.signals if s.id == "IDN002")
        bulk_weight = next(s.weight for s in bulk.verdict.signals if s.id == "IDN002")
        assert bulk_weight < personal_weight
        assert bulk.verdict.score < personal.verdict.score


class TestIDN003LookalikeDomain:
    @pytest.mark.parametrize(
        "domain",
        [
            "micros0ft-login.example",
            "paypa1-billing.example",
            "app1e-support.example",
            "netfl1x-billing.example",
        ],
    )
    def test_fires_on_confusable_domains(self, domain: str) -> None:
        report = scan_eml(build_eml(headers={"From": f"noreply@{domain}"}))
        assert "IDN003" in fired(report), domain

    @pytest.mark.parametrize(
        "domain",
        ["corp.example", "shop.example", "university.example", "newsletter.example"],
    )
    def test_quiet_on_unrelated_domains(self, domain: str) -> None:
        report = scan_eml(build_eml(headers={"From": f"noreply@{domain}"}))
        assert "IDN003" not in fired(report), domain

    def test_quiet_when_the_domain_belongs_to_the_brand(self) -> None:
        report = scan_eml(build_eml(headers={"From": "noreply@microsoft.com"}))
        assert "IDN003" not in fired(report)

    def test_short_brand_aliases_are_ignored(self) -> None:
        # "ups" and "irs" are too short to match without flooding the report.
        report = scan_eml(build_eml(headers={"From": "noreply@groups.example"}))
        assert "IDN003" not in fired(report)

    def test_confusable_match_scores_above_a_literal_one(self) -> None:
        tricked = scan_eml(build_eml(headers={"From": "a@micros0ft-login.example"}))
        literal = scan_eml(build_eml(headers={"From": "a@microsoft-login.example"}))
        tricked_conf = next(s.confidence for s in tricked.verdict.signals if s.id == "IDN003")
        literal_conf = next(s.confidence for s in literal.verdict.signals if s.id == "IDN003")
        assert tricked_conf > literal_conf


class TestIDN004DisplayNameBrand:
    def test_fires_for_a_brand_claim_from_freemail(self) -> None:
        report = scan_eml(
            build_eml(headers={"From": '"Microsoft Account Team" <billing2026@gmail.com>'})
        )
        assert "IDN004" in fired(report)

    def test_quiet_when_the_domain_belongs_to_the_brand(self) -> None:
        report = scan_eml(
            build_eml(headers={"From": '"Microsoft Account Team" <noreply@microsoft.com>'})
        )
        assert "IDN004" not in fired(report)

    def test_freemail_raises_confidence(self) -> None:
        freemail = scan_eml(build_eml(headers={"From": '"PayPal Service" <x@gmail.com>'}))
        corporate = scan_eml(build_eml(headers={"From": '"PayPal Service" <x@vendor.example>'}))
        free_conf = next(s.confidence for s in freemail.verdict.signals if s.id == "IDN004")
        corp_conf = next(s.confidence for s in corporate.verdict.signals if s.id == "IDN004")
        assert free_conf > corp_conf


class TestIDN005ScriptConfusion:
    def test_fires_on_punycode(self) -> None:
        report = scan_eml(build_eml(headers={"From": "noreply@xn--pple-43d.example"}))
        assert "IDN005" in fired(report)

    def test_fires_on_mixed_script(self) -> None:
        report = scan_eml(build_eml(headers={"From": "noreply@m\u0456crosoft.example"}))
        assert "IDN005" in fired(report)

    def test_quiet_on_plain_ascii(self) -> None:
        report = scan_eml(build_eml(headers={"From": "noreply@corp.example"}))
        assert "IDN005" not in fired(report)

    def test_decoded_form_appears_in_the_evidence(self) -> None:
        report = scan_eml(build_eml(headers={"From": "noreply@xn--pple-43d.example"}))
        signal = next(s for s in report.verdict.signals if s.id == "IDN005")
        assert "\u0430pple" in signal.explanation or "\u0430pple" in signal.evidence[0].note


class TestIDN900Allowlist:
    def test_allowlisted_sender_suppresses_identity_findings(self) -> None:
        data = build_eml(headers={"From": '"Microsoft Support" <a@micros0ft-login.example>'})
        loud = scan_eml(data)
        quiet = scan_eml(
            data,
            Config(deterministic=True, allowlist_domains=("micros0ft-login.example",)),
        )
        assert "IDN003" in fired(loud)
        assert "IDN900" in fired(quiet)
        assert quiet.verdict.score < loud.verdict.score

    def test_trust_never_fully_clears_a_message(self) -> None:
        """An allowlisted domain is still spoofable until DKIM is verified."""
        report = scan_eml(
            build_eml(extra=[("Message-ID", "<dup@corp.example>")]),
            Config(deterministic=True, allowlist_domains=("corp.example",)),
        )
        assert report.verdict.trust_factor < 1.0


class TestBrandMatching:
    def test_skeletons_collapse_known_tricks(self) -> None:
        assert skeleton("micros0ft") == skeleton("microsoft")
        assert skeleton("rnicrosoft") == skeleton("microsoft")
        assert skeleton("paypa1") == skeleton("paypal")

    def test_unrelated_names_do_not_collapse(self) -> None:
        assert skeleton("netflix") != skeleton("microsoft")

    def test_match_brand_returns_the_brand_and_confidence(self) -> None:
        matched = match_brand("micros0ft")
        assert matched is not None
        brand, alias, confidence = matched
        assert brand.name == "Microsoft"
        assert alias == "microsoft"
        assert confidence > 0.9
