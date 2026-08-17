"""CLI contract tests.

Exit codes are the part of a CLI that other software depends on, so they are
tested as a contract: 0 clean, 1 detected, 2 the tool could not complete. A
tool that returns 1 for both "found phishing" and "file not found" cannot be
used in a pipeline.
"""

from __future__ import annotations

import json

import pytest

from baittrace.cli import EXIT_CLEAN, EXIT_DETECTED, EXIT_ERROR, main

from ..conftest import CORPUS

MALICIOUS = CORPUS / "malicious" / "brand-lookalike.eml"
BENIGN = CORPUS / "benign" / "receipt.eml"


class TestExitCodes:
    def test_benign_mail_exits_clean(self) -> None:
        assert main(["scan", str(BENIGN), "--no-color"]) == EXIT_CLEAN

    def test_phishing_exits_detected(self) -> None:
        assert main(["scan", str(MALICIOUS), "--no-color"]) == EXIT_DETECTED

    def test_a_missing_file_is_a_tool_error_not_a_detection(self) -> None:
        assert main(["scan", "does-not-exist.eml"]) == EXIT_ERROR

    def test_fail_on_threshold_is_respected(self) -> None:
        assert main(["scan", str(MALICIOUS), "--fail-on", "critical", "--no-color"]) == EXIT_CLEAN
        assert (
            main(["scan", str(MALICIOUS), "--fail-on", "suspicious", "--no-color"]) == EXIT_DETECTED
        )

    def test_fail_on_never_always_exits_clean(self) -> None:
        assert main(["scan", str(MALICIOUS), "--fail-on", "never", "--no-color"]) == EXIT_CLEAN


class TestFormats:
    def test_json_output_parses(self, capsys) -> None:
        main(["scan", str(MALICIOUS), "--format", "json", "--deterministic"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["schema_version"] == "1.0"
        assert payload["verdict"]["band"] in {"HIGH", "CRITICAL"}

    def test_text_output_names_the_rules(self, capsys) -> None:
        main(["scan", str(MALICIOUS), "--no-color"])
        out = capsys.readouterr().out
        assert "IDN003" in out
        assert "BAITTRACE" in out

    def test_no_unicode_output_is_ascii(self, capsys) -> None:
        main(["scan", str(MALICIOUS), "--no-color", "--no-unicode"])
        capsys.readouterr().out.encode("ascii", errors="strict")


class TestShorthand:
    def test_a_bare_path_is_treated_as_scan(self) -> None:
        assert main([str(BENIGN), "--no-color"]) == EXIT_CLEAN


class TestOtherCommands:
    def test_rules_lists_every_rule(self, capsys) -> None:
        assert main(["rules"]) == EXIT_CLEAN
        out = capsys.readouterr().out
        assert "IDN003" in out and "HDR001" in out
        assert "AUTH001" in out and "URL001" in out and "ATT003" in out

    def test_rules_can_filter_by_category(self, capsys) -> None:
        main(["rules", "--category", "headers"])
        out = capsys.readouterr().out
        assert "HDR001" in out and "IDN003" not in out

    def test_explain_describes_a_rule(self, capsys) -> None:
        assert main(["explain", "IDN003"]) == EXIT_CLEAN
        out = capsys.readouterr().out
        assert "Known false positives" in out
        assert "docs/rules/IDN003.md" in out

    def test_explain_is_case_insensitive(self) -> None:
        assert main(["explain", "idn003"]) == EXIT_CLEAN

    def test_explain_rejects_an_unknown_rule(self) -> None:
        assert main(["explain", "ZZZ999"]) == EXIT_ERROR

    def test_schema_emits_valid_json(self, capsys) -> None:
        assert main(["schema"]) == EXIT_CLEAN
        assert json.loads(capsys.readouterr().out)["title"] == "BaitTrace report"

    def test_version_lists_the_analyzers(self, capsys) -> None:
        assert main(["version"]) == EXIT_CLEAN
        out = capsys.readouterr().out
        assert "identity" in out and "headers" in out
        assert "auth" in out and "urls" in out and "attachments" in out

    def test_no_arguments_prints_help(self, capsys) -> None:
        assert main([]) == EXIT_ERROR
        assert "usage" in capsys.readouterr().out.lower()


class TestStdin:
    def test_a_message_can_be_piped_in(self, monkeypatch, capsys) -> None:
        import io
        import sys

        data = MALICIOUS.read_bytes()
        stream = io.TextIOWrapper(io.BytesIO(data), encoding="utf-8")
        monkeypatch.setattr(sys, "stdin", stream)

        assert main(["scan", "-", "--no-color"]) == EXIT_DETECTED
        assert "IDN003" in capsys.readouterr().out


class TestDeterminism:
    def test_two_runs_produce_identical_output(self, capsys) -> None:
        main(["scan", str(MALICIOUS), "--format", "json", "--deterministic"])
        first = capsys.readouterr().out
        main(["scan", str(MALICIOUS), "--format", "json", "--deterministic"])
        second = capsys.readouterr().out
        assert first == second

    def test_the_scan_id_is_derived_from_the_content(self, capsys) -> None:
        main(["scan", str(MALICIOUS), "--format", "json", "--deterministic"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["input"]["sha256"].startswith(payload["scan"]["id"])


@pytest.mark.parametrize("flag", ["--redact"])
def test_redaction_masks_addresses(flag: str, capsys) -> None:
    main(["scan", str(MALICIOUS), flag, "--no-color"])
    out = capsys.readouterr().out
    assert "account@micros0ft-login.example" not in out
