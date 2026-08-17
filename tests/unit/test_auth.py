"""AUTH rule tests."""

from __future__ import annotations

from baittrace.config import Config
from baittrace.pipeline import analyze
from baittrace.resolver import Answer, NullResolver

from ..conftest import build_eml, fired, parse_eml, scan_eml


class FakeResolver:
    online = True

    def __init__(self, txt: dict[str, list[str]] | None = None) -> None:
        self._txt = txt or {}

    def txt(self, name: str) -> Answer[list[str]]:
        key = name.lower().rstrip(".")
        if key in self._txt:
            return Answer.found(self._txt[key])
        return Answer.found([])

    def a(self, name: str) -> Answer[list[str]]:
        return Answer.found(["203.0.113.9"])

    def ptr(self, ip: str) -> Answer[str]:
        return Answer.unavailable()

    def trace_redirects(self, url: str, max_hops: int = 5) -> Answer[list[str]]:
        return Answer.found([url])


def _auth_headers(**overrides: str) -> dict[str, str]:
    base = {
        "Authentication-Results": (
            "mx.example.com; spf=fail smtp.mailfrom=thief.example; "
            "dkim=fail header.d=thief.example; dmarc=fail policy.p=reject "
            "header.from=thief.example"
        )
    }
    base.update(overrides)
    return base


class TestAUTH001:
    def test_fires_on_spf_fail(self) -> None:
        report = scan_eml(build_eml(headers=_auth_headers()))
        assert "AUTH001" in fired(report)

    def test_quiet_when_spf_passes(self) -> None:
        report = scan_eml(
            build_eml(
                headers={
                    "Authentication-Results": (
                        "mx.example.com; spf=pass smtp.mailfrom=alice@corp.example; "
                        "dkim=pass header.d=corp.example; dmarc=pass header.from=corp.example"
                    )
                }
            )
        )
        assert "AUTH001" not in fired(report)


class TestAUTH002:
    def test_fires_on_dkim_fail(self) -> None:
        report = scan_eml(build_eml(headers=_auth_headers()))
        assert "AUTH002" in fired(report)

    def test_a_signature_without_a_result_is_not_a_failure(self) -> None:
        report = scan_eml(
            build_eml(
                headers={
                    "DKIM-Signature": "v=1; a=rsa-sha256; d=corp.example; s=selector; bh=abcd; b=efgh"
                }
            )
        )
        assert "AUTH002" not in fired(report)


class TestAUTH003:
    def test_fires_on_dmarc_fail(self) -> None:
        report = scan_eml(build_eml(headers=_auth_headers()))
        assert "AUTH003" in fired(report)

    def test_fires_on_p_none(self) -> None:
        report = scan_eml(
            build_eml(
                headers={
                    "Authentication-Results": (
                        "mx.example.com; spf=pass smtp.mailfrom=thief.example; "
                        "dmarc=fail policy.p=none header.from=corp.example"
                    )
                }
            )
        )
        assert "AUTH003" in fired(report)

    def test_quiet_when_dmarc_passes_even_if_policy_is_none(self) -> None:
        report = scan_eml(
            build_eml(
                headers={
                    "Authentication-Results": (
                        "mx.example.com; spf=pass smtp.mailfrom=alice@corp.example; "
                        "dkim=pass header.d=corp.example; "
                        "dmarc=pass policy.p=none header.from=corp.example"
                    )
                }
            )
        )
        assert "AUTH003" not in fired(report)


class TestAUTH004:
    def test_fires_when_nothing_is_present(self) -> None:
        report = scan_eml(build_eml())
        assert "AUTH004" in fired(report)

    def test_quiet_when_results_exist(self) -> None:
        report = scan_eml(build_eml(headers=_auth_headers()))
        assert "AUTH004" not in fired(report)


class TestAUTH005:
    def test_fires_when_spf_pass_is_not_aligned(self) -> None:
        report = scan_eml(
            build_eml(
                headers={
                    "From": "Microsoft Support <account@micros0ft-login.example>",
                    "Authentication-Results": (
                        "mx.example.com; spf=pass smtp.mailfrom=bounce@mail-secure.example; "
                        "dkim=fail header.d=micros0ft-login.example; "
                        "dmarc=fail policy.p=none header.from=micros0ft-login.example"
                    ),
                }
            )
        )
        assert "AUTH005" in fired(report)

    def test_quiet_when_dkim_is_aligned_even_if_spf_is_not(self) -> None:
        report = scan_eml(
            build_eml(
                headers={
                    "Authentication-Results": (
                        "mx.example.com; spf=pass smtp.mailfrom=bounces@provider.example; "
                        "dkim=pass header.d=corp.example; dmarc=pass header.from=corp.example"
                    )
                }
            )
        )
        assert "AUTH005" not in fired(report)


class TestAUTH900:
    def test_suppresses_when_aligned_dkim_passes_for_a_brand(self) -> None:
        report = scan_eml(
            build_eml(
                headers={
                    "From": "Microsoft <noreply@microsoft.com>",
                    "Authentication-Results": (
                        "mx.example.com; spf=pass smtp.mailfrom=noreply@microsoft.com; "
                        "dkim=pass header.d=microsoft.com; dmarc=pass header.from=microsoft.com"
                    ),
                }
            )
        )
        assert "AUTH900" in fired(report)


class TestVerifiedMode:
    def test_dns_spf_fail_overrides_reported_pass(self) -> None:
        message = parse_eml(
            build_eml(
                extra=[
                    (
                        "Received",
                        "from x (x [198.51.100.9]) by mx.example.com; Thu, 07 Aug 2026 08:05:00 +0000",
                    )
                ],
                headers={
                    "Return-Path": "<alice@corp.example>",
                    "Authentication-Results": "mx.example.com; spf=pass smtp.mailfrom=alice@corp.example",
                },
            )
        )
        resolver = FakeResolver(txt={"corp.example": ["v=spf1 ip4:203.0.113.0/24 -all"]})
        report = analyze(
            message,
            Config(online=True, deterministic=True),
            resolver=resolver,
        )
        assert "AUTH001" in fired(report)

    def test_unverifiable_is_not_a_fail(self) -> None:
        message = parse_eml(
            build_eml(
                headers={
                    "Authentication-Results": "mx.example.com; dkim=pass header.d=corp.example",
                    "DKIM-Signature": "v=1; a=rsa-sha256; d=corp.example; s=gone; bh=a; b=b",
                }
            )
        )

        class EmptyTxt(FakeResolver):
            def txt(self, name: str) -> Answer[list[str]]:
                return Answer.unavailable("timeout")

        report = analyze(message, Config(online=True, deterministic=True), resolver=EmptyTxt())
        assert "AUTH002" not in fired(report)


class TestOffline:
    def test_does_not_use_the_resolver_when_offline(self) -> None:
        report = scan_eml(build_eml(headers=_auth_headers()), Config(deterministic=True))
        assert report.online is False
        assert isinstance(report, object)
        _ = NullResolver  # imported for the module contract
        assert "AUTH001" in fired(report)
