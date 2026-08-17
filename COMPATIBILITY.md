# Compatibility

Three surfaces, versioned separately, because they change at different rates
and break different people.

## 1. CLI

The commands `scan`, `explain`, `rules`, `schema`, `version`, `init`, and
`completion` are stable. `init` and `completion` are additive (minor).
Exit codes are part of the contract:

| Code | Meaning |
|------|---------|
| 0 | Completed, below `--fail-on` |
| 1 | Completed, at or above `--fail-on` |
| 2 | Could not complete |

`--fail-on` values `benign`, `suspicious`, `high`, `critical`, `never` are
stable. Adding a flag is a minor version. Removing or reinterpreting one is a
major version. `baittrace file.eml` remaining shorthand for
`baittrace scan file.eml` is stable.

## 2. JSON schema

`schema_version` is currently `"1.0"`. Every JSON report carries it so a
consumer can branch.

- Adding a field is a **minor** schema version (`1.1`).
- Removing or retyping a field is a **major** schema version (`2.0`).
- `baittrace schema` prints the JSON Schema. CI validates every corpus
  report against it.
- Rule IDs are `PREFIX` + three digits, where `PREFIX` is three or four
  uppercase letters (`IDN003`, `AUTH005`). Widening the pattern to allow
  four-letter prefixes is compatible; shrinking it is not.

The same document is what a future `POST /v1/scan` will return. A consumer
written against the CLI is written against the API.

## 3. Rulepack

Scoring constants live in `src/baittrace/rulepacks/core-2026.08.toml`. The
identifier `core@2026.08` is recorded in every report.

- Changing a weight, cap, ceiling, or band threshold is a **rulepack version
  bump**, not a silent behaviour change.
- Rule IDs are append-only. A retired rule stops firing and keeps its number.
- A score from six months ago can be reproduced by pinning
  `--rulepack core@2026.08`.

## Library API

`baittrace.scan`, `baittrace.scan_bytes`, `Report`, `Verdict`, `Signal`,
`Config`, and the exception hierarchy are the supported import surface.
Everything under `baittrace.analyzers` and `baittrace.render` is public but
expected to grow. Private modules start with `_`.

## Deprecations

Deprecated flags and fields warn for one minor cycle before removal. There
are none yet.

## Python

3.11, 3.12, and 3.13. CI runs the suite on all three, on Ubuntu, macOS, and
Windows.
