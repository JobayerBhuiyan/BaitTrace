"""Ingest: bounded reads and portable source paths."""

from __future__ import annotations

from pathlib import Path

import pytest

from baittrace.config import Config
from baittrace.errors import IngestError
from baittrace.ingest import display_source, read_path
from baittrace.pipeline import scan

from ..conftest import CORPUS


def test_corpus_paths_are_repo_relative() -> None:
    source = display_source(CORPUS / "malicious" / "brand-lookalike.eml")
    assert source == "corpus/malicious/brand-lookalike.eml"


def test_scan_records_the_portable_source() -> None:
    report = scan(CORPUS / "malicious" / "brand-lookalike.eml", Config(deterministic=True))
    assert report.message.source == "corpus/malicious/brand-lookalike.eml"


def test_read_path_hashes_the_bytes() -> None:
    raw = read_path(CORPUS / "benign" / "receipt.eml")
    assert len(raw.sha256) == 64
    assert raw.size == len(raw.data)


def test_display_source_falls_back_outside_the_repo(tmp_path: Path) -> None:
    lone = tmp_path / "outside.eml"
    lone.write_bytes(b"From: a@b.example\r\n\r\nbody\r\n")
    shown = display_source(lone)
    assert "corpus" not in shown
    assert shown.endswith("outside.eml") or shown == str(lone)


def test_missing_file_mentions_saving_as_eml(tmp_path: Path) -> None:
    with pytest.raises(IngestError, match="no such file"):
        read_path(tmp_path / "missing.eml")
    with pytest.raises(IngestError, match="Save the message as"):
        read_path(tmp_path / "missing.eml")


def test_msg_is_rejected_as_unsupported(tmp_path: Path) -> None:
    msg = tmp_path / "mail.msg"
    msg.write_bytes(b"not an eml")
    with pytest.raises(IngestError, match="not supported"):
        read_path(msg)


def test_directory_lists_eml_names(tmp_path: Path) -> None:
    (tmp_path / "sample.eml").write_bytes(b"From: a@b.example\r\n\r\n")
    with pytest.raises(IngestError, match=r"sample\.eml"):
        read_path(tmp_path)
