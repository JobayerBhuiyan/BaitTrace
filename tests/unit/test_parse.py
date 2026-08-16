"""Parser tests."""

from __future__ import annotations

from baittrace.assets import registrable_domain
from baittrace.parse import decode_rfc2047, sniff

from ..conftest import build_eml, parse_eml


class TestHeaders:
    def test_duplicates_are_preserved_in_order(self) -> None:
        message = parse_eml(build_eml(extra=[("From", "Second <b@other.example>")]))
        froms = message.headers.all("from")
        assert len(froms) == 2
        assert froms[0].index < froms[1].index

    def test_lookup_is_case_insensitive(self) -> None:
        message = parse_eml(build_eml())
        assert message.headers.value("SUBJECT") == message.headers.value("subject")

    def test_folded_headers_are_unfolded(self) -> None:
        raw = (
            b"From: alice@corp.example\r\n"
            b"Subject: a very long subject\r\n that continues here\r\n"
            b"\r\nbody\r\n"
        )
        message = parse_eml(raw)
        assert message.subject == "a very long subject that continues here"

    def test_both_raw_and_decoded_forms_are_kept(self) -> None:
        raw = b"From: alice@corp.example\r\nSubject: =?utf-8?B?SGVsbG8=?=\r\n\r\nbody\r\n"
        message = parse_eml(raw)
        header = message.headers.first("subject")
        assert header is not None
        assert header.value == "Hello"
        assert header.raw_value == "=?utf-8?B?SGVsbG8=?="
        assert header.was_encoded

    def test_a_missing_header_yields_an_empty_string(self) -> None:
        assert parse_eml(build_eml(drop=["Subject"])).headers.value("subject") == ""


class TestAddresses:
    def test_display_name_and_address_are_split(self) -> None:
        message = parse_eml(build_eml())
        sender = message.identity.primary_from
        assert sender is not None
        assert sender.display_name == "Alice Nakamura"
        assert sender.addr_spec == "alice@corp.example"
        assert sender.domain == "corp.example"

    def test_registrable_domain_folds_subdomains(self) -> None:
        message = parse_eml(build_eml(headers={"From": "a@mail.eu.corp.example"}))
        sender = message.identity.primary_from
        assert sender is not None
        assert sender.registrable_domain == "corp.example"

    def test_encoded_display_names_are_decoded(self) -> None:
        raw = b"From: =?utf-8?B?TWljcm9zb2Z0?= <a@corp.example>\r\n\r\nbody\r\n"
        sender = parse_eml(raw).identity.primary_from
        assert sender is not None
        assert sender.display_name == "Microsoft"

    def test_a_garbled_from_does_not_raise(self) -> None:
        message = parse_eml(b"From: <<<>>@@\r\nSubject: x\r\n\r\nbody\r\n")
        assert message.subject == "x"


class TestBodiesAndUrls:
    def test_plain_and_html_parts_are_separated(self) -> None:
        raw = (
            b"From: a@corp.example\r\nMIME-Version: 1.0\r\n"
            b'Content-Type: multipart/alternative; boundary="b"\r\n\r\n'
            b"--b\r\nContent-Type: text/plain\r\n\r\nplain text\r\n"
            b"--b\r\nContent-Type: text/html\r\n\r\n<p>html text</p>\r\n"
            b"--b--\r\n"
        )
        message = parse_eml(raw)
        assert "plain text" in message.bodies.text_plain
        assert "html text" in message.bodies.text_html

    def test_urls_are_extracted_and_defanged(self) -> None:
        message = parse_eml(build_eml("Go to http://evil.example/login now\n"))
        assert len(message.urls) == 1
        assert message.urls[0].defanged == "hxxp://evil[.]example/login"

    def test_anchor_text_is_captured_for_html_links(self) -> None:
        raw = (
            b"From: a@corp.example\r\nContent-Type: text/html\r\n\r\n"
            b'<a href="http://evil.example">https://www.paypal.com</a>\r\n'
        )
        urls = parse_eml(raw).urls
        assert urls[0].host == "evil.example"
        assert "paypal.com" in urls[0].anchor_text

    def test_html_is_parsed_but_never_rendered(self) -> None:
        raw = (
            b"From: a@corp.example\r\nContent-Type: text/html\r\n\r\n"
            b'<img src="http://tracker.example/o.gif">\r\n'
        )
        message = parse_eml(raw)
        assert message.urls[0].host == "tracker.example"
        assert message.urls[0].location == "html:img[src]"

    def test_mailto_links_are_not_urls(self) -> None:
        assert parse_eml(build_eml("write to mailto:a@b.example\n")).urls == ()


class TestAttachments:
    def test_metadata_is_captured_without_decoding_content(self) -> None:
        raw = (
            b"From: a@corp.example\r\nMIME-Version: 1.0\r\n"
            b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
            b"--b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n"
            b'--b\r\nContent-Type: application/pdf; name="invoice.pdf"\r\n'
            b'Content-Disposition: attachment; filename="invoice.pdf"\r\n\r\n'
            b"%PDF-1.4 fake\r\n"
            b"--b--\r\n"
        )
        attachments = parse_eml(raw).attachments
        assert len(attachments) == 1
        assert attachments[0].filename == "invoice.pdf"
        assert attachments[0].sniffed_mime == "application/pdf"
        assert len(attachments[0].sha256) == 64

    def test_a_declared_type_that_contradicts_the_bytes_is_visible(self) -> None:
        raw = (
            b"From: a@corp.example\r\nMIME-Version: 1.0\r\n"
            b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
            b"--b\r\nContent-Type: image/png\r\n"
            b'Content-Disposition: attachment; filename="photo.png"\r\n\r\n'
            b"MZ\x90\x00 not a png\r\n"
            b"--b--\r\n"
        )
        attachment = parse_eml(raw).attachments[0]
        assert attachment.declared_mime == "image/png"
        assert attachment.sniffed_mime == "application/x-dosexec"

    def test_a_filename_with_a_direction_override_survives_parsing(self) -> None:
        raw = (
            b"From: a@corp.example\r\nMIME-Version: 1.0\r\n"
            b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
            b"--b\r\nContent-Type: text/plain\r\n"
            b'Content-Disposition: attachment; filename="invoice\xe2\x80\xaegnp.exe"\r\n\r\n'
            b"data\r\n--b--\r\n"
        )
        attachment = parse_eml(raw).attachments[0]
        assert "\u202e" in attachment.filename_raw


class TestDates:
    def test_a_valid_date_parses(self) -> None:
        dates = parse_eml(build_eml()).dates
        assert dates.parsed is not None
        assert not dates.malformed

    def test_a_malformed_date_is_flagged_rather_than_raising(self) -> None:
        dates = parse_eml(build_eml(headers={"Date": "not a date"})).dates
        assert dates.malformed
        assert dates.parsed is None

    def test_a_missing_date_is_distinct_from_a_malformed_one(self) -> None:
        dates = parse_eml(build_eml(drop=["Date"])).dates
        assert dates.missing and not dates.malformed


class TestRouting:
    def test_received_hops_are_ordered_earliest_first(self) -> None:
        raw = build_eml(
            extra=[
                ("Received", "from second.example by mx.example; Thu, 07 Aug 2026 08:06:00 +0000"),
                (
                    "Received",
                    "from first.example by relay.example; Thu, 07 Aug 2026 08:05:00 +0000",
                ),
            ]
        )
        hops = parse_eml(raw).routing.hops
        assert hops[0].from_host == "first.example"

    def test_the_trust_boundary_is_unset_without_configuration(self) -> None:
        """Every hop is attacker-supplied until a trusted relay is named."""
        assert parse_eml(build_eml()).routing.trusted is False


class TestHelpers:
    def test_decode_rfc2047_survives_garbage(self) -> None:
        """Malformed encoded-words must degrade, never raise."""
        assert isinstance(decode_rfc2047("=?utf-8?B?!!!not-base64!!!?="), str)
        assert isinstance(decode_rfc2047("=?nonsense-charset?Q?a?="), str)
        assert decode_rfc2047("plain text") == "plain text"

    def test_sniff_returns_empty_for_unknown_bytes(self) -> None:
        assert sniff(b"\x00\x01\x02 nothing familiar") == ""

    def test_registrable_domain_handles_multi_label_suffixes(self) -> None:
        assert registrable_domain("shop.example.co.uk") == "example.co.uk"

    def test_registrable_domain_of_a_bare_suffix_is_empty(self) -> None:
        assert registrable_domain("co.uk") == ""
