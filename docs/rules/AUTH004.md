# AUTH004 Authentication results are absent

## What it detects

The message carries no `Authentication-Results`, `Received-SPF` or `DKIM-Signature` header, so SPF, DKIM and DMARC cannot be evaluated from the message alone.

## Why it matters

Mail that crossed an internet gateway almost always has these headers. Their absence is a fingerprint of template assembly, or of an internal system that never passed a filter. Weighted low so it corroborates rather than drives a verdict.

## Example

A message whose headers include From, To, Subject and Date, and nothing else related to authentication.

## Known false positives

Internal mail that never passed an internet gateway often has no authentication headers.

## References

- RFC 8601
