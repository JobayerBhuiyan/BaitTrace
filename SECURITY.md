# Security policy

## This tool parses hostile input

BaitTrace's job is to read email that was written to harm someone. Treat any
crash, hang, or unexpected network activity while scanning a message as a
security bug, not a UX bug.

## Reporting a vulnerability

Please **do not** open a public issue for a vulnerability in the parser, the
sanitizer, the CLI's handling of attacker-controlled strings, or anything that
could be used to crash, hang, or beacon from this tool.

Use GitHub's private vulnerability reporting on this repository
(Security → Advisories → Report a vulnerability), or email the maintainer
listed on the GitHub profile.

Include:

- a synthetic `.eml` that reproduces the problem (reserved domains only —
  see `corpus/README.md`)
- the command you ran
- what you expected, and what happened
- Python version and OS

You should hear back within a week. Fixes ship as a patch release. Credit is
given unless you ask otherwise.

## What we consider in scope

- Parser resource exhaustion that bypasses the documented limits
- Terminal injection or report forgery via crafted headers, filenames, or
  body text
- Any network activity during a default (offline) scan
- Path traversal if a future `--extract` writes attacker-controlled names
- Supply-chain issues in this repository's own GitHub Actions or release
  process

## What we do not consider in scope

- "This phishing email scored too low" — that is a detection gap; open a
  regular issue describing the *technique* and a synthetic sample
- False positives on legitimate mail — same, with a benign synthetic sample
- Crashes on input that already exceeds a documented hard limit and is
  refused with `LimitExceeded`
- Plugin code you installed yourself (`--no-plugins` exists because plugins
  are a trust decision)

## Supply chain

- Zero runtime third-party dependencies
- GitHub Actions pinned to full commit SHAs
- Releases (when they exist) will use PyPI trusted publishing over OIDC —
  no long-lived token in the repository
