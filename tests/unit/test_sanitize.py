"""Terminal-safety tests.

Attacker-controlled text reaches a TTY on every single scan, so these are
security tests rather than formatting tests.
"""

from __future__ import annotations

import pytest

from baittrace.parse import defang
from baittrace.sanitize import clean, collapse, ellipsize, redact, sanitize


class TestControlCharacters:
    def test_ansi_colour_sequences_are_removed(self) -> None:
        assert sanitize("\x1b[31mred\x1b[0m") == "red"

    def test_screen_clearing_sequences_are_removed(self) -> None:
        assert "\x1b" not in sanitize("safe\x1b[2J\x1b[Hgone")

    def test_osc_title_sequences_are_removed(self) -> None:
        assert sanitize("\x1b]0;pwned\x07text") == "text"

    def test_bare_escapes_are_removed(self) -> None:
        assert "\x1b" not in sanitize("a\x1bcb")

    @pytest.mark.parametrize("char", ["\x00", "\x07", "\x08", "\x1a", "\x7f"])
    def test_control_characters_become_visible_tokens(self, char: str) -> None:
        out = sanitize(f"a{char}b")
        assert char not in out
        assert out.startswith("a") and out.endswith("b")

    def test_tabs_become_spaces(self) -> None:
        assert sanitize("a\tb") == "a b"

    def test_line_breaks_become_spaces(self) -> None:
        """A display name must not be able to forge a line in the report."""
        forged = "Alice\n\u2717  +99  FAK001  Totally legitimate"
        out = sanitize(forged)
        assert "\n" not in out


class TestBidi:
    def test_rtl_override_becomes_visible(self) -> None:
        """invoice<RLO>gnp.exe renders as invoiceexe.png in a naive terminal."""
        out = sanitize("invoice\u202egnp.exe")
        assert "<RLO>" in out
        assert "\u202e" not in out

    @pytest.mark.parametrize(
        "char", ["\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2069"]
    )
    def test_every_direction_control_is_surfaced(self, char: str) -> None:
        out = sanitize(f"a{char}b")
        assert char not in out
        assert "<" in out

    def test_zero_width_characters_are_surfaced(self) -> None:
        assert "<ZWSP>" in sanitize("pay\u200bpal")


class TestRedaction:
    def test_addresses_are_masked_but_domains_kept(self) -> None:
        out = redact("contact alice.nakamura@corp.example now")
        assert "alice.nakamura" not in out
        assert "corp.example" in out

    def test_ip_addresses_are_partially_masked(self) -> None:
        assert redact("from 198.51.100.23 today") == "from 198.51.x.x today"

    def test_redaction_is_opt_in(self) -> None:
        assert "alice@corp.example" in clean("alice@corp.example")
        assert "alice@corp.example" not in clean("alice@corp.example", redacted=True)


class TestTrimming:
    def test_whitespace_runs_collapse(self) -> None:
        assert collapse("a  \n  b\t\tc") == "a b c"

    def test_ellipsize_respects_the_width(self) -> None:
        assert len(ellipsize("x" * 100, 20)) == 20

    def test_short_text_is_untouched(self) -> None:
        assert ellipsize("short", 20) == "short"


class TestDefang:
    def test_scheme_and_host_are_neutered(self) -> None:
        assert defang("http://evil.example/path") == "hxxp://evil[.]example/path"

    def test_https_is_handled(self) -> None:
        assert defang("https://evil.example") == "hxxps://evil[.]example"

    def test_the_path_is_left_readable(self) -> None:
        assert "/login?id=1" in defang("http://evil.example/login?id=1")

    def test_ip_hosts_are_defanged(self) -> None:
        assert defang("http://198.51.100.23/x") == "hxxp://198[.]51[.]100[.]23/x"
