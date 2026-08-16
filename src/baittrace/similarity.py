"""Small string-distance helpers used by lookalike detection."""

from __future__ import annotations

from functools import lru_cache


@lru_cache(maxsize=8192)
def levenshtein(left: str, right: str) -> int:
    """Edit distance with the usual insert, delete and substitute operations."""
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    previous = list(range(len(right) + 1))
    for i, lchar in enumerate(left, start=1):
        current = [i]
        for j, rchar in enumerate(right, start=1):
            current.append(
                min(
                    previous[j] + 1,
                    current[j - 1] + 1,
                    previous[j - 1] + (lchar != rchar),
                )
            )
        previous = current
    return previous[-1]


def distance_threshold(reference: str) -> int:
    """How many edits still count as "looks like" for a string this long.

    Short names need an exact match. ``ups`` is three characters, so allowing
    even one edit would match half the dictionary; every such match would be a
    false positive, and false positives are what destroy trust in a detector.
    """
    length = len(reference)
    if length < 6:
        return 0
    if length < 10:
        return 1
    return 2
