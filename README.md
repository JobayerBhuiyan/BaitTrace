# BaitTrace

Offline-first, explainable phishing triage for a single email file.

A stranger should be able to clone this repository, run one command, and get a
verdict they can defend: not just *this looks like phishing*, but *which
evidence contributed how many points, and what to do about it*.

```bash
pip install -e ".[dev]"
baittrace scan corpus/malicious/brand-lookalike.eml
```

```
BAITTRACE 0.1.0                                             core@2026.08
────────────────────────────────────────────────────────────────────────
Risk         HIGH                                                 60/100
             ███████████████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░
Source       corpus/malicious/brand-lookalike.eml
Analyzed     offline | identity, headers | 0 ms

MESSAGE
Subject      Action required: your account will be suspended in 24 hours
Displayed    Microsoft Support
Actual       account@micros0ft-login.example
Reply-To     recovery@mail-secure.example
Date         Tue, 12 Aug 2026 09:14:02 +0000
Links        1 found
             hxxp://198[.]51[.]100[.]23/account/verify?id=8831

FINDINGS
             5 indicators

✗   +24  IDN003  Sender domain resembles a known brand
             The sending domain micros0ft-login.example contains
             'micros0ft', which reduces to the same confusable skeleton
             as Microsoft. micros0ft-login.example is not one of
             Microsoft's known domains, so the resemblance is not
             legitimate.

…  (full report in tests/golden/expected/brand-lookalike.txt)

NOT ANALYZED
             This release does not yet examine links, attachments, SPF,
             DKIM and DMARC, body wording, delivery path. The highest
             score reachable from the evidence classes that did run is
             60/100, so a low score reflects what was checked rather
             than a clean bill of health.

RECOMMENDED ACTION
             Treat this as phishing until proven otherwise.
```

## Why this exists

Plenty of security tools dump technical findings. BaitTrace is built around
the opposite problem: **explainability**. Every point of every score traces to
a documented rule ID, with verbatim evidence, a plain-English explanation, and
a recommended action.

It is deliberately not another vulnerability scanner, SIEM, or sandbox. Those
need infrastructure. This needs one file.

## Invariants

1. **Offline by default.** Nothing touches the network. There is no `--online`
   flag in this release; the resolver is a stub that returns *unavailable*.
2. **Analysis is inert.** HTML is never rendered. Attachments are never
   executed. Links are never fetched. Analyzing phishing must not phone home
   to the attacker.
3. **Every point traces to a rule ID.** No hidden heuristics. No unexplainable
   model.
4. **Analyzers are pure.** `Message → list[Signal]`. No I/O, no shared state,
   no knowledge of scoring or rendering.
5. **JSON output is a contract.** Versioned schema, stable field names. The
   same document a CLI prints is what a future hosted API will return.

## Scoring in five lines

Each finding has a weight and a confidence. Those are summed inside an
evidence class and clamped to that class's cap, so nine weak wording matches
cannot outrank one forged sender. Classes then combine with a noisy-OR bounded
by a ceiling, so no single class can reach 100 alone. The numbers next to
findings (`+24`, `+15`) are attributed contributions that sum to the score,
not literal addends. Full model and a worked example: [docs/SCORING.md](docs/SCORING.md).

This release implements two of seven evidence classes (identity and headers).
The highest reachable score is **60/100**. The report says so.

## Install

Python 3.11 or newer. No runtime third-party dependencies: the standard
library covers MIME, and the terminal grid is easier to keep exact when
nothing else is wrapping the text.

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
baittrace version
```

## Usage

```bash
baittrace scan suspicious.eml
baittrace scan suspicious.eml --format json
baittrace scan - --format json < suspicious.eml
baittrace explain IDN003
baittrace rules
baittrace schema
```

Exit codes, because the difference between "found something" and "the tool
broke" is what makes this safe in a pipeline:

| Code | Meaning |
|------|---------|
| 0 | Scan completed, below `--fail-on` (default: `high`) |
| 1 | Scan completed, at or above the threshold |
| 2 | The tool could not complete (unreadable input, bad config, bad usage) |

The library API is a first-class surface:

```python
from baittrace import scan

report = scan("suspicious.eml")
print(report.verdict.band, report.verdict.score)
for signal, points in report.verdict.scored:
    print(signal.id, points, signal.title)
```

## Rules in this release

| ID | What it detects |
|----|-----------------|
| [IDN001](docs/rules/IDN001.md) | Display name contains a different email address |
| [IDN002](docs/rules/IDN002.md) | Reply-To points at a different organisation |
| [IDN003](docs/rules/IDN003.md) | Sender domain resembles a known brand |
| [IDN004](docs/rules/IDN004.md) | Display name claims a brand the domain does not belong to |
| [IDN005](docs/rules/IDN005.md) | Sender domain uses punycode or mixes scripts |
| [IDN900](docs/rules/IDN900.md) | Sender is on the operator's allowlist (suppressor) |
| [HDR001](docs/rules/HDR001.md) | Duplicate single-occurrence header |
| [HDR002](docs/rules/HDR002.md) | Message-ID is missing |
| [HDR003](docs/rules/HDR003.md) | Message-ID domain does not match the sender |
| [HDR004](docs/rules/HDR004.md) | Date header is malformed or contradicts delivery |
| [HDR005](docs/rules/HDR005.md) | Return-Path does not match the sender |

CI asserts a bijection: every rule ID has a documentation page, and every
page documents a real rule.

## What is not here yet

M1 ships a working pipeline, not the whole design. Links, attachments, SPF /
DKIM / DMARC, body wording, and the delivery path are designed and stubbed,
not implemented. See [docs/ROADMAP.md](docs/ROADMAP.md).

The hosted demo (Railway) is M6 and waits until M3 exists to wrap.

## Documentation

- [System design](docs/DESIGN.md)
- [Scoring model](docs/SCORING.md)
- [Threat model of the tool itself](docs/THREAT_MODEL.md)
- [Roadmap](docs/ROADMAP.md)
- [Compatibility](COMPATIBILITY.md)
- [Corpus policy](corpus/README.md) — no real phishing email is ever committed
- [Contributing](CONTRIBUTING.md)

## Safety

This repository is public. Git history cannot be un-published.

- `.gitignore` blocks `.eml` / `.msg` / `.mbox` everywhere except `corpus/`
- A pre-commit hook refuses `git add -f` of samples outside `corpus/`
- Malicious samples are **synthetic**, authored by `corpus/generator.py`
- Every attacker-controlled string is sanitised before it reaches a terminal
- Every URL in a report is defanged (`hxxp://…[.]example`)

Analyse a real sample locally. Do not commit it. See [corpus/README.md](corpus/README.md).

## License

[Apache License 2.0](LICENSE)
