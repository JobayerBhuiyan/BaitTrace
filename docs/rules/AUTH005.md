# AUTH005 SPF or DKIM passed for a domain that does not match From

## What it detects

An authentication check passed, but the passing identifier is not aligned with the From header a reader sees. SPF passed for the envelope domain; that domain is not the brand in From.

## Why it matters

This is how brand impersonation usually presents: `spf=pass` for `mail-secure.example` while From claims Microsoft. The pass authenticates a different organisation. The instructor mock's "SPF passed" plus lookalike sender is this rule.

## Example

```
From: Microsoft Support <account@micros0ft-login.example>
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=bounce@mail-secure.example
```

## Known false positives

Email service providers send on a customer's behalf from their own domain. If DKIM is aligned with From, this rule stays quiet even when SPF is not.

## References

- RFC 7489
- RFC 7208
