# AUTH002 DKIM signature is invalid

## What it detects

A DKIM signature is present and Authentication-Results reports `dkim=fail`, or `--online` verification recomputes the signature and it does not match. A missing or unresolvable selector is unverifiable and does **not** fire this rule.

## Why it matters

DKIM binds the message body and selected headers to a domain's key. A fail means the body or signed headers were altered after signing, or the signature was never valid.

## Example

```
Authentication-Results: mx.example.com; dkim=fail header.d=micros0ft-login.example
```

## Known false positives

Mailing lists that rewrite Subject break DKIM. A rotated selector is unverifiable, not a failure.

## References

- RFC 6376
