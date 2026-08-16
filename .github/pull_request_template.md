## Summary

<!-- What does this change, and why. -->

## Kind

- [ ] New rule or analyzer
- [ ] Scoring
- [ ] Parser / ingest
- [ ] Renderer / CLI
- [ ] Docs
- [ ] Tests / CI
- [ ] Other

## Detection changes

<!-- Delete this section if the PR does not change what fires. -->

- Rules added or changed:
- Synthetic sample (path under `corpus/`, authored via `generator.py`):
- Benign corpus still under 25? (`pytest tests/corpus`)
- False positives considered:

## Checklist

- [ ] `pytest` passes
- [ ] `ruff check` and `mypy --strict src/baittrace` pass
- [ ] Every new rule ID has `docs/rules/<ID>.md` with the five required sections
- [ ] No real email samples, no victim PII, no live payloads
- [ ] Goldens regenerated with `BAITTRACE_UPDATE_GOLDEN=1` only if the report wording was meant to change, and the diff was read
