# AUTH900 DMARC-aligned DKIM passed

This is a **suppressor**, not an indicator.

## What it detects

A DKIM signature passed and aligns with the From domain, and that domain is a known brand or on the operator allowlist.

## Why it matters

A tool that can only ever escalate is not a triage tool. A real Microsoft DKIM pass should reduce suspicion from identity heuristics, not ignore them entirely (a compromised mailbox still passes DKIM).

## Example

```
From: Microsoft <noreply@microsoft.com>
Authentication-Results: mx.example.com; dkim=pass header.d=microsoft.com; dmarc=pass
```

## Known false positives

A compromised mailbox at a real brand will also pass DKIM. Alignment is not a clean bill of health.

## References

- RFC 6376
- RFC 7489
