# AUTH003 DMARC failed or publishes no enforcement

## What it detects

DMARC disposition is fail, or the domain publishes `p=none` so a fail is not enforced. Either way the From domain is not protected against impersonation.

## Why it matters

DMARC is the check that actually catches brand impersonation: SPF or DKIM must pass **and** align with the From domain. `p=none` is a monitoring policy; it does not tell receivers to reject.

## Example

```
Authentication-Results: mx.example.com; dmarc=fail policy.p=none header.from=micros0ft-login.example
```

## Known false positives

Many legitimate domains still publish `p=none`. The finding is stronger when alignment also fails (see AUTH005).

## References

- RFC 7489
