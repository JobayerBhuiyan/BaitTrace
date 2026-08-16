#!/usr/bin/env python3
"""Block email samples from being committed outside the reviewed corpus.

.gitignore already excludes these patterns, but `git add -f` bypasses it and a
public repository cannot un-publish a mistake. This hook is the second layer.
"""

from __future__ import annotations

import sys
from pathlib import Path

SAMPLE_SUFFIXES = {".eml", ".msg", ".mbox", ".mbx", ".pst", ".ost"}
ALLOWED_ROOT = "corpus"


def offending(paths: list[str]) -> list[Path]:
    found = []
    for raw in paths:
        path = Path(raw)
        if path.suffix.lower() not in SAMPLE_SUFFIXES:
            continue
        if path.parts and path.parts[0] == ALLOWED_ROOT:
            continue
        found.append(path)
    return found


def main(argv: list[str]) -> int:
    bad = offending(argv[1:])
    if not bad:
        return 0

    print("Refusing to commit email samples outside corpus/:", file=sys.stderr)
    for path in bad:
        print(f"  {path}", file=sys.stderr)
    print(
        "\nEmail samples carry third-party personal data and often live malware.\n"
        "Only synthetic samples authored by corpus/generator.py belong in this\n"
        "repository. See corpus/README.md for the policy.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
