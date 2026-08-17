# BaitTrace

Offline-first, explainable phishing triage for a single email file.

A stranger should be able to clone this repository, run one command, and get a
verdict they can defend: not just *this looks like phishing*, but *which
evidence contributed how many points, and what to do about it*.

```bash
pip install -e ".[dev]"
baittrace scan corpus/malicious/instructor-demo.eml
```

```
BAITTRACE 0.1.0                                             core@2026.08
────────────────────────────────────────────────────────────────────────
Risk         CRITICAL                                             94/100

AUTHENTICATION
✓            SPF passed (reported)
✗            DKIM signature invalid
⚠            DMARC failed policy: none
✗            SPF/DKIM pass is not aligned with From

SENDER
Displayed    Microsoft Support
Actual       account@micros0ft-login.example
             ^ suspicious lookalike

LINKS
             3 URLs discovered
⚠            1 uses an IP address
             hxxp://198[.]51[.]100[.]23/account/verify?id=8831
             hxxp://go[.]mail-secure[.]example/redirect?u=hxxp://coll...
             hxxp://collect[.]example/harvest
✗            Anchor text disagrees with the link target

ATTACHMENTS
             invoice.html  text/html
⚠            HTML attachment
✗            Contains external form submission

REASONS FOR SCORE
✗   +12  IDN003  Sender domain resembles a known brand
✗   +12  URL001  Link uses an IP address as the host
✗   +12  ATT003  HTML attachment contains an external form or script
…

RECOMMENDED ACTION
             Do not interact with this email. Do not click any link,
             open any attachment, or reply. Escalate for analyst review.
```

(Full reports live in `tests/golden/expected/`.) Default scans stay offline.
`--online` independently verifies SPF/DKIM/DMARC over DNS; `--follow-redirects`
traces link chains. Both are off because following a phish link can beacon.

## Why this exists

Plenty of security tools dump technical findings. BaitTrace is built around
the opposite problem: **explainability**. Every point of every score traces to
a documented rule ID, with verbatim evidence, a plain-English explanation, and
a recommended action.

It is deliberately not another vulnerability scanner, SIEM, or sandbox. Those
need infrastructure. This needs one file.

## Invariants

1. **Offline by default.** Nothing touches the network unless you pass
   `--online` or `--follow-redirects`. The default resolver returns
   *unavailable*. `--online` needs `pip install 'baittrace[online]'`.
2. **Analysis is inert.** HTML is never rendered. Attachments are never
   executed. Links are never fetched unless you explicitly opt in.
   Analyzing phishing must not phone home to the attacker.
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

This release implements five of seven evidence classes (identity, headers,
authentication, links, attachments). Body wording and delivery path are not
in yet. The report states the highest reachable score so a low result is not
misread as a clean bill of health.

## Install

Python 3.11 or newer. No runtime third-party dependencies: the standard
library covers MIME, and the terminal grid is easier to keep exact when
nothing else is wrapping the text. Optional DNS verification is an extra.

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
baittrace version
```

```bash
pip install -e ".[online]"         # optional: --online SPF/DKIM/DMARC via DNS
```

## Usage

```bash
baittrace scan suspicious.eml
baittrace scan suspicious.eml --format json
baittrace scan - --format json < suspicious.eml
baittrace scan suspicious.eml --online
baittrace scan suspicious.eml --follow-redirects
baittrace explain AUTH005
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

Identity (`IDN001`–`IDN005`, `IDN900`), headers (`HDR001`–`HDR005`),
authentication (`AUTH001`–`AUTH005`, `AUTH900`), links (`URL001`–`URL007`) and
attachments (`ATT001`–`ATT005`). Catalogue: [docs/rules/README.md](docs/rules/README.md).

CI asserts a bijection: every rule ID has a documentation page, and every
page documents a real rule.

## What is not here yet

Body wording (`CNT`) and delivery-path (`RTE`) analyzers, replayable online
scans, and a hosted demo. See [docs/ROADMAP.md](docs/ROADMAP.md).

The hosted demo (Railway) is M6 and waits until there is a complete CLI to wrap.

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
