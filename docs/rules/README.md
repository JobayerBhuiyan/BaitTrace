# Rule catalogue

Every rule BaitTrace can emit has a page here. CI asserts a bijection:
implemented IDs and these files are the same set. If a test fails, write the
page — do not weaken the test.

IDs are append-only. A retired rule keeps its number.

## Identity (`IDN`)

| ID | Title |
|----|-------|
| [IDN001](IDN001.md) | Display name contains a different email address |
| [IDN002](IDN002.md) | Reply-To points at a different organisation |
| [IDN003](IDN003.md) | Sender domain resembles a known brand |
| [IDN004](IDN004.md) | Display name claims a brand the domain does not belong to |
| [IDN005](IDN005.md) | Sender domain uses punycode or mixes scripts |
| [IDN900](IDN900.md) | Sender is on the operator's allowlist (suppressor) |

## Headers (`HDR`)

| ID | Title |
|----|-------|
| [HDR001](HDR001.md) | Duplicate single-occurrence header |
| [HDR002](HDR002.md) | Message-ID is missing |
| [HDR003](HDR003.md) | Message-ID domain does not match the sender |
| [HDR004](HDR004.md) | Date header is malformed or contradicts delivery |
| [HDR005](HDR005.md) | Return-Path does not match the sender |

## Later prefixes

`URL`, `ATT`, `AUTH`, `RTE`, and `CNT` are designed in [DESIGN.md](../DESIGN.md)
and are not implemented in M1. Their IDs are reserved; they will appear here
when the analyzers ship.

To inspect the live catalogue:

```bash
baittrace rules
baittrace explain IDN003
```
