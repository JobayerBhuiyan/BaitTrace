# Contributing

Thank you. The most useful contributions to a detector are new rules, better
false-positive handling, and synthetic samples that isolate a technique. The
least useful is a rewrite.

Please read [corpus/README.md](corpus/README.md) before adding any email
sample. **No real phishing email is ever committed to this repository.**

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
pytest
```

`pre-commit` runs gitleaks, ruff, and a hook that refuses email samples
outside `corpus/`. The last one exists because `git add -f` bypasses
`.gitignore` and git history cannot be un-published.

## Add a rule in five steps

This is the path the architecture exists to serve. You should not need to
read the parser or the renderer.

1. **Declare it.** Add a `RuleSpec` next to its siblings in
   `src/baittrace/analyzers/identity.py` or `headers.py` (or a new analyzer
   module). Pick the next free ID in that prefix. IDs are append-only; do
   not reuse a retired number.
2. **Implement the check.** `run()` is a pure function of `Message` and
   `Context`. No I/O. Fire the spec with `spec.fire(confidence=..., explanation=..., evidence=...)`.
   The explanation interpolates evidence; the renderer will sanitize it.
3. **Document it.** Create `docs/rules/<ID>.md` with the five required
   sections (What it detects, Why it matters, Example, Known false positives,
   References). Start the page with `# <ID> <title>` matching the `RuleSpec`
   title. Add a row to `docs/rules/README.md`. CI asserts the bijection; if
   the test fails, write the page, do not weaken the test.
4. **Test it.** A crafted positive that fires, a crafted negative that does
   not. Use `tests/conftest.py:build_eml` so the test states the one header
   it cares about. If the rule can false-positive on bulk mail, add a case
   with `List-Unsubscribe` and assert the weight drop.
5. **Sample it, if it is load-bearing.** Add a synthetic sample to
   `SAMPLES` in `corpus/generator.py`, run `python corpus/generator.py`, and
   say in the pull request which rules it should (or must not) fire. Do not
   hand-edit a committed `.eml`.

Then:

```bash
pytest
ruff check src tests
ruff format src tests
mypy
```

If you changed renderer wording, regenerate goldens and read the diff:

```bash
BAITTRACE_UPDATE_GOLDEN=1 pytest tests/golden
```

## Adding an analyzer, not just a rule

Implement `baittrace.analyzers.base.Analyzer`, give it a three-letter prefix,
and register it in `[project.entry-points."baittrace.analyzers"]` in
`pyproject.toml`. Built-ins travel the same entry-point group as plugins, so
a loading regression shows up in the first test run.

If the analyzer needs the network, set `requires_network = True` and go
through `ctx.resolver`. Do not call `socket` yourself. The default resolver
returns `UNAVAILABLE`; write the analyzer against that. `--online` and
`--follow-redirects` inject a live resolver.

## Changing a score

Weights, caps, ceilings, and bands live in
`src/baittrace/rulepacks/core-2026.08.toml`. Changing one is a rulepack
version bump. See [docs/SCORING.md](docs/SCORING.md). If a new rule pushes a
benign sample over 25, the rule or its weight is wrong; do not raise the
threshold.

## Pull requests

- One concern per PR. A new rule and a parser refactor do not belong
  together.
- Tests for the behaviour you added.
- No real email samples, no victim PII, no live payloads.
- Actions stay pinned to SHAs if you touch `.github/workflows`.

Use the pull request template. A maintainer will review detection changes
against the benign corpus before merging.
