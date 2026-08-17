"""URL rule tests."""

from __future__ import annotations

from baittrace.config import Config
from baittrace.pipeline import analyze
from baittrace.resolver import Answer

from ..conftest import build_eml, fired, parse_eml, scan_eml


class TestURL001:
    def test_fires_on_an_ip_literal(self) -> None:
        report = scan_eml(build_eml(body="Click http://198.51.100.23/login\n"))
        assert "URL001" in fired(report)

    def test_quiet_on_a_normal_host(self) -> None:
        report = scan_eml(build_eml(body="Click https://shop.example/orders/1\n"))
        assert "URL001" not in fired(report)


class TestURL002:
    def test_fires_on_punycode(self) -> None:
        report = scan_eml(build_eml(body="Click http://xn--pple-43d.example/login\n"))
        assert "URL002" in fired(report)

    def test_quiet_on_ascii_host(self) -> None:
        report = scan_eml(build_eml(body="Click https://shop.example/orders/1\n"))
        assert "URL002" not in fired(report)


class TestURL003:
    def test_fires_when_anchor_disagrees(self) -> None:
        html = '<a href="http://evil.example/pay">https://www.paypal.com/invoice</a>'
        report = scan_eml(build_eml(body=html, headers={"Content-Type": "text/html"}))
        assert "URL003" in fired(report)


class TestURL005:
    def test_fires_on_userinfo_trick(self) -> None:
        report = scan_eml(build_eml(body="Go to http://apple.com@evil.example/reset\n"))
        assert "URL005" in fired(report)


class TestURL006:
    def test_fires_when_a_brand_is_in_the_host(self) -> None:
        report = scan_eml(build_eml(body="http://microsoft-login.thief.example/secure\n"))
        assert "URL006" in fired(report)


class TestURL004:
    def test_fires_on_a_shortener(self) -> None:
        report = scan_eml(build_eml(body="http://bit.ly/abc123\n"))
        assert "URL004" in fired(report)


class TestURL007:
    def test_fires_when_the_chain_leaves_the_original_domain(self) -> None:
        message = parse_eml(build_eml(body="See http://go.mail-secure.example/r\n"))

        class Redirecting:
            online = True

            def txt(self, name: str) -> Answer[list[str]]:
                return Answer.unavailable()

            def a(self, name: str) -> Answer[list[str]]:
                return Answer.found(["203.0.113.9"])

            def ptr(self, ip: str) -> Answer[str]:
                return Answer.unavailable()

            def trace_redirects(self, url: str, max_hops: int = 5) -> Answer[list[str]]:
                return Answer.found([url, "http://collect.example/login"])

        report = analyze(
            message,
            Config(follow_redirects=True, deterministic=True),
            resolver=Redirecting(),
        )
        assert "URL007" in fired(report)
