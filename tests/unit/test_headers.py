"""HDR rule tests."""

from __future__ import annotations

from baittrace.config import Config

from ..conftest import build_eml, fired, scan_eml


class TestHDR001Duplicates:
    def test_fires_on_a_duplicate_from(self) -> None:
        report = scan_eml(build_eml(extra=[("From", "Attacker <evil@other.example>")]))
        assert "HDR001" in fired(report)

    def test_duplicate_from_outweighs_a_duplicate_subject(self) -> None:
        from_dup = scan_eml(build_eml(extra=[("From", "Attacker <evil@other.example>")]))
        subject_dup = scan_eml(build_eml(extra=[("Subject", "Something else")]))
        from_weight = next(s.weight for s in from_dup.verdict.signals if s.id == "HDR001")
        subject_weight = next(s.weight for s in subject_dup.verdict.signals if s.id == "HDR001")
        assert from_weight > subject_weight

    def test_every_copy_is_kept_as_evidence(self) -> None:
        report = scan_eml(build_eml(extra=[("From", "Attacker <evil@other.example>")]))
        signal = next(s for s in report.verdict.signals if s.id == "HDR001")
        excerpts = [item.excerpt for item in signal.evidence]
        assert any("alice@corp.example" in e for e in excerpts)
        assert any("evil@other.example" in e for e in excerpts)

    def test_quiet_on_a_normal_message(self) -> None:
        assert "HDR001" not in fired(scan_eml(build_eml()))

    def test_quiet_on_headers_that_may_repeat(self) -> None:
        report = scan_eml(build_eml(extra=[("Received", "from a.example by b.example")]))
        assert "HDR001" not in fired(report)


class TestHDR002MissingMessageId:
    def test_fires_when_absent(self) -> None:
        assert "HDR002" in fired(scan_eml(build_eml(drop=["Message-ID"])))

    def test_quiet_when_present(self) -> None:
        assert "HDR002" not in fired(scan_eml(build_eml()))


class TestHDR003MessageIdDomain:
    def test_fires_on_a_different_organisation(self) -> None:
        report = scan_eml(build_eml(headers={"Message-ID": "<x@elsewhere.example>"}))
        assert "HDR003" in fired(report)

    def test_quiet_on_a_subdomain(self) -> None:
        report = scan_eml(build_eml(headers={"Message-ID": "<x@mail.corp.example>"}))
        assert "HDR003" not in fired(report)

    def test_weight_drops_for_bulk_mail(self) -> None:
        personal = scan_eml(build_eml(headers={"Message-ID": "<x@esp.example>"}))
        bulk = scan_eml(
            build_eml(
                headers={"Message-ID": "<x@esp.example>"},
                extra=[("Precedence", "bulk")],
            )
        )
        personal_weight = next(s.weight for s in personal.verdict.signals if s.id == "HDR003")
        bulk_weight = next(s.weight for s in bulk.verdict.signals if s.id == "HDR003")
        assert bulk_weight < personal_weight


class TestHDR004Date:
    def test_fires_on_a_malformed_date(self) -> None:
        assert "HDR004" in fired(scan_eml(build_eml(headers={"Date": "yesterday-ish"})))

    def test_fires_when_date_contradicts_delivery(self) -> None:
        report = scan_eml(
            build_eml(
                headers={"Date": "Mon, 03 Mar 2025 09:00:00 +0000"},
                extra=[
                    (
                        "Received",
                        "from a.example by b.example; Thu, 07 Aug 2026 08:05:00 +0000",
                    )
                ],
            )
        )
        assert "HDR004" in fired(report)

    def test_quiet_when_date_agrees_with_delivery(self) -> None:
        report = scan_eml(
            build_eml(
                extra=[
                    (
                        "Received",
                        "from a.example by b.example; Thu, 07 Aug 2026 08:05:00 +0000",
                    )
                ]
            )
        )
        assert "HDR004" not in fired(report)

    def test_quiet_when_the_date_is_simply_absent(self) -> None:
        assert "HDR004" not in fired(scan_eml(build_eml(drop=["Date"])))

    def test_verdict_does_not_depend_on_the_current_clock(self) -> None:
        """No rule may compare against 'now'; a report must stay reproducible."""
        data = build_eml(headers={"Date": "Mon, 01 Jan 1996 09:00:00 +0000"})
        assert "HDR004" not in fired(scan_eml(data))


class TestHDR005ReturnPath:
    def test_fires_on_an_envelope_mismatch(self) -> None:
        report = scan_eml(build_eml(headers={"Return-Path": "<bounce@other.example>"}))
        assert "HDR005" in fired(report)

    def test_quiet_when_the_envelope_matches(self) -> None:
        report = scan_eml(build_eml(headers={"Return-Path": "<alice@corp.example>"}))
        assert "HDR005" not in fired(report)


class TestDisablingRules:
    def test_a_disabled_rule_does_not_appear(self) -> None:
        data = build_eml(drop=["Message-ID"])
        assert "HDR002" in fired(scan_eml(data))
        assert "HDR002" not in fired(
            scan_eml(data, Config(deterministic=True, disabled_rules=frozenset({"HDR002"})))
        )
