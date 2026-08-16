"""Resource-exhaustion tests.

Every one of these is a message an attacker can send for free and that a naive
parser will die on. The bound either holds or the tool is a denial-of-service
vector aimed at the person trying to investigate an attack.

The tests assert two things together: that the parser survives, and that the
report says what was skipped. Surviving by silently dropping half the message
would be the worse outcome, because the analyst would never know.
"""

from __future__ import annotations

import time

import pytest

from baittrace.config import Config
from baittrace.errors import LimitExceeded
from baittrace.ingest import RawInput, read_path
from baittrace.limits import Limits
from baittrace.parse import parse, parse_bytes
from baittrace.pipeline import scan_bytes


def raw(data: bytes) -> RawInput:
    return RawInput(data=data, source="test", sha256="0" * 64)


class TestSizeBound:
    def test_oversized_input_is_refused_before_parsing(self, tmp_path) -> None:
        path = tmp_path / "big.eml"
        path.write_bytes(b"From: a@b.example\r\n\r\n" + b"x" * 5000)
        with pytest.raises(LimitExceeded) as caught:
            read_path(path, Limits(max_bytes=1000))
        assert caught.value.limit_name == "max_bytes"

    def test_the_bound_is_applied_while_reading(self, tmp_path) -> None:
        """Refusal must not require the whole file in memory first."""
        path = tmp_path / "big.eml"
        path.write_bytes(b"x" * 200_000)
        with pytest.raises(LimitExceeded):
            read_path(path, Limits(max_bytes=1024))


class TestNestingBound:
    def build_nested(self, depth: int) -> bytes:
        parts = [b"From: a@b.example\r\nMIME-Version: 1.0\r\n"]
        for level in range(depth):
            parts.append(
                f'Content-Type: multipart/mixed; boundary="b{level}"\r\n\r\n--b{level}\r\n'.encode()
            )
        parts.append(b"Content-Type: text/plain\r\n\r\ninner\r\n")
        for level in reversed(range(depth)):
            parts.append(f"--b{level}--\r\n".encode())
        return b"".join(parts)

    def test_deep_nesting_is_bounded_and_disclosed(self) -> None:
        message = parse(raw(self.build_nested(40)), Limits(max_depth=5))
        assert message.limits.truncated
        assert any("max_depth" in t for t in message.limits.describe())

    def test_ordinary_nesting_is_untouched(self) -> None:
        message = parse(raw(self.build_nested(2)), Limits(max_depth=20))
        assert not message.limits.truncated


class TestPartBound:
    def test_a_part_flood_is_bounded_and_disclosed(self) -> None:
        parts = [
            b"From: a@b.example\r\nMIME-Version: 1.0\r\n"
            b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
        ]
        for i in range(500):
            parts.append(f"--b\r\nContent-Type: text/plain\r\n\r\npart {i}\r\n".encode())
        parts.append(b"--b--\r\n")

        message = parse(raw(b"".join(parts)), Limits(max_parts=20))
        assert message.structure.part_count <= 21
        assert any("max_parts" in t for t in message.limits.describe())


class TestHeaderBounds:
    def test_a_header_flood_is_bounded(self) -> None:
        headers = b"".join(f"X-Pad-{i}: value\r\n".encode() for i in range(2000))
        message = parse(
            raw(b"From: a@b.example\r\n" + headers + b"\r\nbody\r\n"), Limits(max_headers=50)
        )
        assert len(message.headers) <= 50
        assert any("max_headers" in t for t in message.limits.describe())

    def test_an_enormous_single_header_is_truncated(self) -> None:
        data = b"From: a@b.example\r\nX-Huge: " + b"A" * 100_000 + b"\r\n\r\nbody\r\n"
        message = parse(raw(data), Limits(max_header_bytes=1024))
        assert any("max_header_bytes" in t for t in message.limits.describe())


class TestUrlBound:
    def test_a_link_flood_is_bounded(self) -> None:
        body = " ".join(f"http://host{i}.example/" for i in range(2000))
        message = parse_bytes(
            f"From: a@b.example\r\n\r\n{body}\r\n".encode(), limits=Limits(max_urls=25)
        )
        assert len(message.urls) <= 25
        assert any("max_urls" in t for t in message.limits.describe())


class TestDegradedReporting:
    def test_a_truncated_scan_is_marked_degraded(self) -> None:
        headers = b"".join(f"X-Pad-{i}: value\r\n".encode() for i in range(500))
        report = scan_bytes(
            b"From: a@b.example\r\n" + headers + b"\r\nbody\r\n",
            config=Config(deterministic=True, limits=Limits(max_headers=20)),
        )
        assert report.degraded


class TestBudget:
    def test_a_pathological_message_still_completes_quickly(self) -> None:
        parts = [
            b"From: a@b.example\r\nMIME-Version: 1.0\r\n"
            b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
        ]
        for i in range(200):
            parts.append(
                f"--b\r\nContent-Type: text/html\r\n\r\n<a href='http://h{i}.example'>x</a>\r\n".encode()
            )
        parts.append(b"--b--\r\n")
        data = b"".join(parts)

        started = time.monotonic()
        scan_bytes(data, config=Config(deterministic=True))
        assert time.monotonic() - started < 5.0
