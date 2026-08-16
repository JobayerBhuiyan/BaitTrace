"""Shared fixtures.

``build_eml`` exists so a test can state the one header it cares about instead
of pasting a whole message. A test that says ``build_eml(reply_to=...)`` makes
its intent obvious; forty lines of RFC 5322 does not.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from baittrace.config import Config
from baittrace.model import Message
from baittrace.parse import parse_bytes
from baittrace.pipeline import analyze
from baittrace.report import Report

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "corpus"

DEFAULT_HEADERS: dict[str, str] = {
    "From": "Alice Nakamura <alice@corp.example>",
    "To": "bob@corp.example",
    "Subject": "Quarterly planning notes",
    "Date": "Thu, 07 Aug 2026 08:04:58 +0000",
    "Message-ID": "<abc123@corp.example>",
}


def build_eml(
    body: str = "Hello.\n",
    *,
    headers: dict[str, str] | None = None,
    extra: list[tuple[str, str]] | None = None,
    drop: list[str] | None = None,
) -> bytes:
    """Assemble a message from defaults plus overrides.

    ``extra`` takes a list of pairs rather than a dict so a test can create the
    duplicate headers that HDR001 exists to detect.
    """
    merged = dict(DEFAULT_HEADERS)
    merged.update(headers or {})
    for name in drop or []:
        merged.pop(name, None)

    lines = [f"{name}: {value}" for name, value in merged.items()]
    lines.extend(f"{name}: {value}" for name, value in extra or [])
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode("utf-8")


@pytest.fixture
def eml() -> object:
    return build_eml


@pytest.fixture
def config() -> Config:
    return Config(deterministic=True)


def parse_eml(data: bytes) -> Message:
    return parse_bytes(data, source="test.eml")


def scan_eml(data: bytes, config: Config | None = None) -> Report:
    return analyze(parse_eml(data), config or Config(deterministic=True))


def fired(report: Report) -> set[str]:
    return {signal.id for signal in report.verdict.signals} | {
        signal.id for signal in report.verdict.suppressors
    }
