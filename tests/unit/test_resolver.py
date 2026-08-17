"""SSRF guards and the offline/online seam."""

from __future__ import annotations

from baittrace.cli import EXIT_ERROR, main
from baittrace.config import Config
from baittrace.pipeline import _choose_resolver
from baittrace.resolver import LiveResolver, is_blocked_ip, online_dependencies_available


def test_metadata_and_loopback_are_blocked() -> None:
    resolver = LiveResolver()
    for url in (
        "http://127.0.0.1/latest",
        "http://169.254.169.254/latest/meta-data",
        "http://localhost/admin",
    ):
        answer = resolver.trace_redirects(url)
        assert not answer.ok, url
        assert answer.detail


def test_file_scheme_is_rejected() -> None:
    answer = LiveResolver().trace_redirects("file:///etc/passwd")
    assert not answer.ok


def test_is_blocked_ip() -> None:
    assert is_blocked_ip("169.254.169.254")
    assert is_blocked_ip("127.0.0.1")
    assert not is_blocked_ip("198.51.100.23")


def test_follow_redirects_does_not_require_the_online_extra() -> None:
    resolver = _choose_resolver(Config(follow_redirects=True), None)
    assert isinstance(resolver, LiveResolver)


def test_online_without_extras_fails_cleanly() -> None:
    if online_dependencies_available():
        return
    assert main(["scan", "corpus/benign/receipt.eml", "--online"]) == EXIT_ERROR
