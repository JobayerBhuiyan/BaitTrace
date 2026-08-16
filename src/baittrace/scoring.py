"""The scoring engine.

Scoring is where a detector either earns trust or loses it, so the model here
is deliberately boring and fully auditable. Three stages:

1. **Per category**, sum ``weight x confidence`` and normalise against that
   category's cap. The cap is what stops nine weak wording matches from
   outranking one forged sender.
2. **Across categories**, combine with a noisy-OR bounded by a per-category
   ceiling. Independent evidence reinforces with diminishing returns, and no
   single class can reach 100 alone.
3. **Apply trust** from suppressors, which can reduce but never clear a score.

Why not simple addition? Because addition has no notion of saturation: it
rewards volume over quality, and it lets a pile of low-grade heuristics outvote
a signature forgery. The cost of noisy-OR is that individual contributions are
no longer literal addends, which is why they are attributed by leave-one-out
and then normalised to sum to the total. ``docs/SCORING.md`` works an example
end to end.
"""

from __future__ import annotations

import math
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

from .errors import ConfigError
from .signal import Category, CategoryScore, Signal, Verdict

DEFAULT_RULEPACK = "core@2026.08"

BAND_BENIGN = "BENIGN"
BAND_SUSPICIOUS = "SUSPICIOUS"
BAND_HIGH = "HIGH"
BAND_CRITICAL = "CRITICAL"

BAND_ORDER = (BAND_BENIGN, BAND_SUSPICIOUS, BAND_HIGH, BAND_CRITICAL)


@dataclass(frozen=True, slots=True)
class CategoryConfig:
    cap: float
    ceiling: float


@dataclass(frozen=True, slots=True)
class Rulepack:
    """Every constant that can move a score."""

    name: str
    version: str
    combination: str
    categories: dict[Category, CategoryConfig]
    weights: dict[str, float]
    band_suspicious: int
    band_high: int
    band_critical: int
    trust_max: float

    @property
    def identifier(self) -> str:
        return f"{self.name}@{self.version}"

    def config_for(self, category: Category) -> CategoryConfig:
        return self.categories.get(category, CategoryConfig(cap=10.0, ceiling=0.2))

    def band_for(self, score: int) -> str:
        if score >= self.band_critical:
            return BAND_CRITICAL
        if score >= self.band_high:
            return BAND_HIGH
        if score >= self.band_suspicious:
            return BAND_SUSPICIOUS
        return BAND_BENIGN


def _rulepack_filename(spec: str) -> str:
    name, _, version = spec.partition("@")
    if not name or not version:
        raise ConfigError(f"rulepack must look like 'core@2026.08', got {spec!r}")
    return f"{name}-{version}.toml"


@lru_cache(maxsize=8)
def load_rulepack(spec: str = DEFAULT_RULEPACK) -> Rulepack:
    filename = _rulepack_filename(spec)
    try:
        text = (resources.files("baittrace.rulepacks") / filename).read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:
        raise ConfigError(f"unknown rulepack {spec!r} (looked for {filename})") from exc

    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"rulepack {spec!r} is not valid TOML: {exc}") from exc

    categories: dict[Category, CategoryConfig] = {}
    for key, values in data.get("categories", {}).items():
        try:
            category = Category(key)
        except ValueError as exc:
            raise ConfigError(f"rulepack {spec!r} defines unknown category {key!r}") from exc
        categories[category] = CategoryConfig(
            cap=float(values["cap"]), ceiling=float(values["ceiling"])
        )

    bands = data.get("bands", {})
    return Rulepack(
        name=str(data.get("name", "core")),
        version=str(data.get("version", "unknown")),
        combination=str(data.get("model", {}).get("combination", "noisy_or")),
        categories=categories,
        weights={str(k): float(v) for k, v in data.get("weights", {}).items()},
        band_suspicious=int(bands.get("suspicious", 25)),
        band_high=int(bands.get("high", 50)),
        band_critical=int(bands.get("critical", 75)),
        trust_max=float(data.get("trust", {}).get("max_factor", 0.9)),
    )


def effective_weight(
    signal: Signal, rulepack: Rulepack, overrides: Mapping[str, float] | None = None
) -> float:
    """User config beats the rulepack, which beats the analyzer's default."""
    if overrides and signal.id in overrides:
        return float(overrides[signal.id])
    if signal.id in rulepack.weights:
        return rulepack.weights[signal.id]
    return signal.weight


def _category_raw(
    signals: Sequence[Signal], rulepack: Rulepack, overrides: Mapping[str, float] | None
) -> dict[Category, float]:
    totals: dict[Category, float] = {}
    for signal in signals:
        points = effective_weight(signal, rulepack, overrides) * signal.confidence
        totals[signal.category] = totals.get(signal.category, 0.0) + points
    return totals


def _combine(raw: Mapping[Category, float], rulepack: Rulepack) -> float:
    """Return a 0..1 suspicion level from per-category raw totals."""
    if rulepack.combination == "additive":
        total = 0.0
        for category, value in raw.items():
            config = rulepack.config_for(category)
            total += min(value, config.cap)
        return min(1.0, total / 100.0)

    survival = 1.0
    for category, value in raw.items():
        config = rulepack.config_for(category)
        strength = min(1.0, value / config.cap) if config.cap > 0 else 0.0
        survival *= 1.0 - config.ceiling * strength
    return 1.0 - survival


def _allocate(total: int, shares: Sequence[float]) -> tuple[int, ...]:
    """Split ``total`` across ``shares`` so the parts sum exactly to the whole.

    Largest-remainder, so the displayed breakdown always adds up to the score
    shown at the top of the report. A breakdown that does not add up reads as a
    bug even when the underlying maths is right.
    """
    if not shares:
        return ()
    pool = sum(shares)
    if total <= 0 or pool <= 0:
        return tuple(0 for _ in shares)

    exact = [total * share / pool for share in shares]
    base = [math.floor(value) for value in exact]
    remainder = total - sum(base)
    order = sorted(range(len(shares)), key=lambda i: exact[i] - base[i], reverse=True)
    for index in order[:remainder]:
        base[index] += 1
    return tuple(base)


def _attribute(
    indicators: Sequence[Signal],
    raw: Mapping[Category, float],
    total_float: float,
    trust: float,
    pack: Rulepack,
    overrides: Mapping[str, float] | None,
) -> list[float]:
    """Split the score across findings in a way a human can follow.

    Attribution is done in two steps: leave-one-*category*-out to find how much
    each evidence class is worth, then split that within the class in
    proportion to each finding's weighted strength.

    The obvious approach, leaving out one signal at a time, gives badly
    misleading answers once a category is saturated. If identity is already at
    its cap, removing any single identity finding changes the score by almost
    nothing, so every one of them is attributed roughly zero while a lone weak
    header rule collects the entire visible score. The reader is then told that
    a Message-ID mismatch mattered more than a domain impersonating Microsoft,
    which is both wrong and exactly the kind of thing that makes people stop
    believing a tool.
    """
    if not indicators:
        return []

    per_category: dict[Category, float] = {}
    for category in raw:
        without = {k: v for k, v in raw.items() if k != category}
        reduced = 100.0 * _combine(without, pack) * (1.0 - trust)
        per_category[category] = max(0.0, total_float - reduced)

    shares: list[float] = []
    for signal in indicators:
        category_total = raw.get(signal.category, 0.0)
        strength = effective_weight(signal, pack, overrides) * signal.confidence
        within = strength / category_total if category_total > 0 else 0.0
        shares.append(per_category.get(signal.category, 0.0) * within)

    if sum(shares) <= 0:
        return [effective_weight(s, pack, overrides) * s.confidence for s in indicators]
    return shares


def score(
    signals: Sequence[Signal],
    rulepack: Rulepack | None = None,
    overrides: Mapping[str, float] | None = None,
) -> Verdict:
    """Turn a set of signals into a :class:`~baittrace.signal.Verdict`."""
    pack = rulepack or load_rulepack()

    indicators = [s for s in signals if not s.is_suppressor]
    suppressors = [s for s in signals if s.is_suppressor]

    raw = _category_raw(indicators, pack, overrides)
    combined = _combine(raw, pack)

    trust = min(pack.trust_max, sum(s.effective for s in suppressors))
    total_float = 100.0 * combined * (1.0 - trust)
    total = round(total_float)

    shares = _attribute(indicators, raw, total_float, trust, pack, overrides)
    contributions = _allocate(total, shares)

    categories = tuple(
        CategoryScore(
            category=category,
            raw=raw[category],
            cap=pack.config_for(category).cap,
            ceiling=pack.config_for(category).ceiling,
        )
        for category in sorted(raw, key=lambda c: -raw[c])
    )

    notes: list[str] = []
    if suppressors:
        notes.append(
            f"Trust factor {trust:.2f} applied from {len(suppressors)} suppressing signal(s)."
        )

    return Verdict(
        score=total,
        band=pack.band_for(total),
        signals=tuple(indicators),
        contributions=contributions,
        categories=categories,
        trust_factor=trust,
        rulepack=pack.identifier,
        suppressors=tuple(suppressors),
        notes=tuple(notes),
    )
