# AUTH001 SPF failed

## What it detects

The reported or verified SPF result is fail (including softfail and permerror). The sending IP is not authorised to send mail for the envelope domain.

## Why it matters

SPF is how a domain publishes which hosts may send mail on its behalf. A fail means the envelope sender is forged, or the mail was forwarded through a host the domain did not list.

## Example

```
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=thief.example
```

## Known false positives

Forwarders break SPF. A fail without a DMARC reject policy is weaker evidence than the same fail with one.

## References

- RFC 7208
