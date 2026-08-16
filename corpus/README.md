# Corpus policy

**No real phishing email is ever committed to this repository. Every malicious
sample here is synthetic and authored by [`generator.py`](generator.py).**

This is a hard rule, not a preference. Please read it before opening a pull
request that adds a sample.

## Why

**Real samples contain other people's data.** A captured phishing email carries
the recipient's name and address, usually a quoted business thread, and often
internal hostnames from the receiving organisation's own headers. Publishing it
publishes all of that, to everyone, permanently. Git history cannot be
un-published, and public repositories are scraped within minutes of a push.

**Real samples contain live malware.** Phishing attachments are weaponised
documents and executables. Committing one places a working payload in every
clone, every fork and every mirror. It will trip endpoint protection on
contributors' machines, and it breaks the acceptable use policy of GitHub, PyPI
and every CI provider this project touches.

**Real samples are not reproducible.** A regression test needs the same bytes
every run. A captured sample also cannot be varied to isolate one rule, so it
is a poor test even setting the other two problems aside.

## What is here

```
corpus/
  malicious/    synthetic samples that should score at or above 50
  benign/       ordinary mail that must stay below 25
  generator.py  the single source of truth for both
```

Every address uses a domain reserved for documentation by
[RFC 2606](https://www.rfc-editor.org/rfc/rfc2606) and
[RFC 6761](https://www.rfc-editor.org/rfc/rfc6761), or the `.example` TLD.
Nothing in this corpus can reach a real mailbox or resolve to a real host. IP
addresses come from the `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24`
documentation ranges.

Files are regenerated with:

```bash
python corpus/generator.py
```

CI runs `python corpus/generator.py --check` so the committed `.eml` files can
never drift from the generator.

## The benign set matters more

Any heuristic can find phishing if it flags everything. Staying quiet on
ordinary mail is the hard part, and it is the part that decides whether anyone
keeps using the tool after the first week.

`tests/corpus/test_regression.py` asserts that every benign sample scores under
25 and every malicious sample at or above 50. As rules accumulate, the benign
ceiling is the test that fails first, which is exactly what it is for. If a new
rule pushes a benign sample over the line, the rule is wrong or its weight is
wrong, and the fix is not to raise the threshold.

The benign set deliberately includes mail that *looks* structurally suspicious
and is not: `newsletter.eml` sends through a provider, so its Return-Path,
Reply-To and Message-ID domains all disagree with its `From` domain. Three
rules fire on it, and it still scores 16 because those rules are weighted down
when bulk-mail headers are present. That sample exists to keep that behaviour
honest.

## Adding a sample

1. Add it to `SAMPLES` in `generator.py`, never as a loose file.
2. Use only reserved domains and documentation IP ranges.
3. Write it yourself. Do not paste a message you received.
4. Run `python corpus/generator.py` and commit both the generator change and
   the generated file.
5. For a malicious sample, say in the pull request which rules it should fire.
   For a benign one, say which rules it is designed *not* to fire.

## If you have a real sample worth analysing

Analyse it locally. Nothing in this tool needs the sample to be committed:

```bash
baittrace scan /path/to/real-sample.eml
```

The repository's `.gitignore` and the `check-email-samples` pre-commit hook both
block `.eml`, `.msg` and `.mbox` files outside this directory, so an accidental
`git add` will not become an accidental `git push`.

If a real sample exposes a detection gap, open an issue describing the
*technique* and add a synthetic sample that reproduces it. The technique is the
useful part; the victim's data is not.
