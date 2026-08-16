#!/usr/bin/env python3
"""Refresh the vendored data assets.

The assets are committed rather than fetched at runtime. A library that
downloads a suffix list on first use is not offline-first, and a detection tool
whose behaviour depends on what the network returned that morning is not
reproducible. The cost is that the files go stale, which
``tests/test_data_assets.py`` fails on.

Usage::

    python tools/refresh_data.py

Then review the diff and commit. Run it from the repository root.
"""

from __future__ import annotations

import datetime as dt
import re
import sys
import urllib.request
from pathlib import Path

PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
CONFUSABLES_URL = "https://www.unicode.org/Public/security/latest/confusables.txt"

DATA_DIR = Path(__file__).resolve().parent.parent / "src" / "baittrace" / "data"

# Only mappings whose prototype is ASCII matter for domain lookalike detection.
# Everything else in UTS #39 is 700 KB of scripts we never compare against.
ASCII_TARGET = re.compile(r"^[a-zA-Z0-9.\-]{1,3}$")
HEX_FIELD = re.compile(r"^[0-9A-Fa-f]{4,6}( [0-9A-Fa-f]{4,6})*$")


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 - fixed https URLs
        raw: bytes = response.read()
    return raw.decode("utf-8")


def codepoints_to_str(field: str) -> str:
    return "".join(chr(int(cp, 16)) for cp in field.split())


def trim_confusables(source: str) -> tuple[str, int]:
    version = ""
    rows: list[tuple[str, str]] = []
    seen: set[str] = set()

    for line in source.splitlines():
        if not version and line.startswith("# Version:"):
            version = line.removeprefix("#").strip()
        stripped = line.split("#", 1)[0].strip()
        if not stripped:
            continue

        fields = [f.strip() for f in stripped.split(";")]
        if len(fields) < 2:
            continue
        src_field, tgt_field = fields[0], fields[1]
        if not HEX_FIELD.match(src_field) or not HEX_FIELD.match(tgt_field):
            continue

        try:
            src = codepoints_to_str(src_field)
            tgt = codepoints_to_str(tgt_field)
        except ValueError:
            continue

        if not ASCII_TARGET.match(tgt):
            continue
        if src == tgt or src in seen:
            continue

        seen.add(src)
        rows.append((src_field.strip(), tgt))

    rows.sort()
    header = [
        "# BaitTrace trimmed confusables map.",
        "# Derived from Unicode UTS #39 confusables.txt, filtered to mappings whose",
        "# prototype is ASCII, which is the subset relevant to domain lookalikes.",
        f"# Source: {CONFUSABLES_URL}",
        f"# Upstream: {version or 'unknown'}",
        f"# Retrieved: {dt.date.today().isoformat()}",
        f"# Mappings: {len(rows)}",
        "# Format: <source codepoints, space separated hex><TAB><ASCII prototype>",
        "",
    ]
    body = "\n".join(f"{src}\t{tgt}" for src, tgt in rows)
    return "\n".join(header) + body + "\n", len(rows)


def main() -> int:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    print(f"fetching {PSL_URL}")
    psl = fetch(PSL_URL)
    (DATA_DIR / "public_suffix_list.dat").write_text(psl, encoding="utf-8")
    version = next(
        (line for line in psl.splitlines() if line.startswith("// VERSION:")), "// VERSION: unknown"
    )
    print(f"  wrote public_suffix_list.dat ({len(psl):,} bytes, {version.strip()})")

    print(f"fetching {CONFUSABLES_URL}")
    trimmed, count = trim_confusables(fetch(CONFUSABLES_URL))
    (DATA_DIR / "confusables.txt").write_text(trimmed, encoding="utf-8")
    print(f"  wrote confusables.txt ({len(trimmed):,} bytes, {count:,} mappings)")

    print("\nReview the diff before committing.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
