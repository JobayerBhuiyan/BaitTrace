# Scoring model

Scoring is where a detector either earns trust or loses it, so the model is
deliberately boring and fully auditable. This page is the specification.
`src/baittrace/scoring.py` is the implementation. If they disagree, the code
is wrong.

## What a score is

A number from 0 to 100, plus a band:

| Band | Score | Default exit code |
|------|-------|-------------------|
| BENIGN | 0–24 | 0 |
| SUSPICIOUS | 25–49 | 0 (1 with `--fail-on suspicious`) |
| HIGH | 50–74 | 1 |
| CRITICAL | 75–100 | 1 |

`--fail-on` changes the threshold. A tool error is always exit code 2, so
automation can tell a detection from a failure.

The score is **not** a probability that the message is phishing. It is a
saturated combination of independent evidence classes, each of which has been
capped so that volume cannot substitute for quality.

## Three stages

### 1. Per category

Each signal declares a `weight` (its maximum point contribution) and a
`confidence` in `[0, 1]`. Confidence has one specific meaning that must never
be blurred: it is the probability that **this check's evidence was detected
correctly**, not the probability that the message is phishing. A homoglyph
match at edit distance 1 on a 20-character domain is lower confidence than an
exact confusable-skeleton match.

For each category \(c\):

\[
p_c = \min\left(1, \frac{\sum_i w_i \cdot c_i}{\mathrm{cap}_c}\right)
\]

The cap is what stops nine weak content matches from outranking one forged
sender.

### 2. Across categories (noisy-OR)

Categories combine with a noisy-OR, each bounded by a ceiling \(\lambda_c\)
representing how much that evidence class alone may ever imply:

\[
\mathrm{combined} = 1 - \prod_c \left(1 - \lambda_c \cdot p_c\right)
\]

| Category | Cap | Ceiling \(\lambda_c\) |
|----------|-----|------------------------|
| Authentication | 30 | 0.55 |
| Identity | 25 | 0.50 |
| URLs | 25 | 0.50 |
| Attachments | 25 | 0.50 |
| Content | 15 | 0.25 |
| Routing | 10 | 0.20 |
| Header hygiene | 10 | 0.20 |

Three properties come out of this shape:

- One strong evidence class alone cannot exceed its ceiling, so a single
  failed DKIM on an old sample cannot reach CRITICAL by itself.
- Independent evidence classes reinforce each other with diminishing returns.
- No amount of weak content matching can outrank forged sender identity.

### 3. Trust factor

Negative signals (suppressors) — today, an operator allowlist (`IDN900`) —
accumulate into a trust factor \(T\) clamped to `[0, 0.9]`. The final score
is \(\mathrm{round}(100 \cdot \mathrm{combined} \cdot (1 - T))\).

Suppressors can never fully clear a message. An allowlisted domain can still
be spoofed while DKIM verification is unavailable.

## Displayed contributions

The report shows `+24 IDN003` next to each finding. Those numbers are
**attributed contributions**, not literal addends.

Attribution is leave-one-*category*-out, then split within the category in
proportion to each finding's weighted strength. Leaving out one signal at a
time gives badly misleading answers once a category is saturated: if identity
is already at its cap, removing any single identity finding changes the score
by almost nothing, so every one of them is attributed roughly zero while a
lone weak header rule collects the entire visible score. The reader is then
told that a Message-ID mismatch mattered more than a domain impersonating
Microsoft.

Largest-remainder allocation makes the displayed integers sum exactly to the
total. A breakdown that does not add up reads as a bug even when the
underlying maths is right.

The rulepack flag `combination = "additive"` exists for anyone who wants
strict addition. It is easier to explain and easier to game.

## Worked example: `brand-lookalike.eml`

The synthetic sample in `corpus/malicious/brand-lookalike.eml` fires five
indicators. Approximate raw strengths (weight × confidence):

| Finding | Category | Raw |
|---------|----------|-----|
| IDN003 lookalike domain | identity | ~23.8 |
| IDN004 display-name brand | identity | ~15.0 |
| IDN002 Reply-To divergence | identity | ~8.0 |
| HDR005 Return-Path mismatch | headers | ~8.0 |
| HDR003 Message-ID mismatch | headers | ~4.8 |

Identity raw ≈ 46.8 against a cap of 25, so \(p_{\mathrm{identity}} = 1.0\).
Headers raw ≈ 12.8 against a cap of 10, so \(p_{\mathrm{headers}} = 1.0\).

\[
\mathrm{combined} = 1 - (1 - 0.50 \cdot 1)(1 - 0.20 \cdot 1) = 1 - 0.40 = 0.60
\]

No suppressors, so the score is 60, band HIGH. The highest reachable score
from the two implemented classes is also 60, which the report states under
**NOT ANALYZED**.

The displayed `+24 / +15 / +8 / +8 / +5` sum to 60. Identity's leave-one-out
delta is most of the score because its ceiling is 0.50; headers contribute
the rest because their ceiling is 0.20. Within identity, IDN003 takes the
largest share because it has the largest weighted strength.

## Why not simple addition

Addition has no notion of saturation. It rewards volume over quality, and it
lets a pile of low-grade heuristics outvote a signature forgery. The cost of
noisy-OR is that individual contributions are no longer literal addends,
which is why they are attributed rather than summed, and why this page exists.

## Reproducibility

All weights, caps, ceilings, and band thresholds live in
`src/baittrace/rulepacks/core-2026.08.toml`. The pack identifier
(`core@2026.08`) is recorded in every report. Changing a weight is a rulepack
version bump, not a silent behaviour change, so a score from six months ago
can still be explained.

`--deterministic` zeroes timings so two runs produce byte-identical output.
Golden-file tests depend on that.

## Calibration

`tests/corpus/test_regression.py` asserts:

- every benign sample scores **under 25**
- every malicious sample scores **at or above 50**

As rules accumulate, the benign ceiling is the assertion that fails first.
That is the design working. When it fails, the new rule or its weight is
wrong; the fix is never to raise the threshold.
