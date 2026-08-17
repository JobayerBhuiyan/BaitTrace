"""CLI contract tests.

Exit codes are the part of a CLI that other software depends on, so they are
tested as a contract: 0 clean, 1 detected, 2 the tool could not complete. A
tool that returns 1 for both "found phishing" and "file not found" cannot be
used in a pipeline.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from baittrace.cli import EXIT_CLEAN, EXIT_DETECTED, EXIT_ERROR, build_parser, main
from baittrace.config import load_config

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

    def test_explain_rejects_an_unknown_rule(self, capsys) -> None:
        assert main(["explain", "ZZZ999"]) == EXIT_ERROR
        assert "baittrace rules" in capsys.readouterr().err

    def test_explain_suggests_nearby_rule_ids(self, capsys) -> None:
        assert main(["explain", "IDN003x"]) == EXIT_ERROR
        err = capsys.readouterr().err
        assert "Did you mean" in err
        assert "IDN003" in err

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

    def test_help_includes_examples(self) -> None:
        text = build_parser().format_help()
        assert "examples:" in text
        assert "instructor-demo.eml" in text
        assert "baittrace explain IDN003" in text


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


class TestTerminalUx:
    def test_bare_invocation_on_a_tty_prints_getting_started(self, monkeypatch, capsys) -> None:
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        assert main([]) == EXIT_ERROR
        out = capsys.readouterr().out.lower()
        assert "usage" in out
        assert "instructor-demo.eml" in out
        assert "save a message as .eml" in out

    def test_tty_scan_appends_next_steps(self, monkeypatch, capsys) -> None:
        monkeypatch.setattr("baittrace.cli._stdout_is_tty", lambda: True)
        main(["scan", str(MALICIOUS), "--no-color"])
        out = capsys.readouterr().out
        assert "baittrace explain" in out
        assert "--online" in out
        assert "--format json" in out

    def test_json_on_a_tty_has_no_next_footer(self, monkeypatch, capsys) -> None:
        monkeypatch.setattr("baittrace.cli._stdout_is_tty", lambda: True)
        main(["scan", str(MALICIOUS), "--format", "json", "--deterministic"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["schema_version"] == "1.0"

    def test_missing_file_stderr_mentions_eml(self, capsys) -> None:
        assert main(["scan", "does-not-exist.eml"]) == EXIT_ERROR
        err = capsys.readouterr().err
        assert "no such file" in err
        assert ".eml" in err

    def test_init_writes_and_refuses_overwrite(self, tmp_path: Path, monkeypatch, capsys) -> None:
        monkeypatch.chdir(tmp_path)
        assert main(["init"]) == EXIT_CLEAN
        config_path = tmp_path / "baittrace.toml"
        assert config_path.is_file()
        text = config_path.read_text(encoding="utf-8")
        assert "IDN900" in text
        loaded = load_config(config_path)
        assert loaded.rulepack == "core@2026.08"

        assert main(["init"]) == EXIT_ERROR
        assert "--force" in capsys.readouterr().err
        assert main(["init", "--force"]) == EXIT_CLEAN

    def test_init_global_uses_xdg(self, tmp_path: Path, monkeypatch, capsys) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        assert main(["init", "--global"]) == EXIT_CLEAN
        written = tmp_path / "baittrace" / "config.toml"
        assert written.is_file()
        assert "wrote" in capsys.readouterr().out

    @pytest.mark.parametrize("shell", ["bash", "zsh", "fish"])
    def test_completion_mentions_scan_and_a_rule(self, shell: str, capsys) -> None:
        assert main(["completion", shell]) == EXIT_CLEAN
        out = capsys.readouterr().out
        assert "scan" in out
        assert "IDN003" in out
        assert "init" in out
