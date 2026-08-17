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

## Authentication (`AUTH`)

| ID | Title |
|----|-------|
| [AUTH001](AUTH001.md) | SPF failed |
| [AUTH002](AUTH002.md) | DKIM signature is invalid |
| [AUTH003](AUTH003.md) | DMARC failed or publishes no enforcement |
| [AUTH004](AUTH004.md) | Authentication results are absent |
| [AUTH005](AUTH005.md) | SPF or DKIM passed for a domain that does not match From |
| [AUTH900](AUTH900.md) | DMARC-aligned DKIM passed (suppressor) |

## Links (`URL`)

| ID | Title |
|----|-------|
| [URL001](URL001.md) | Link uses an IP address as the host |
| [URL002](URL002.md) | Link host uses punycode or mixed scripts |
| [URL003](URL003.md) | Anchor text disagrees with the link target |
| [URL004](URL004.md) | Link uses a known URL shortener |
| [URL005](URL005.md) | Link hides the real host behind userinfo |
| [URL006](URL006.md) | Link puts a brand name on an unrelated domain |
| [URL007](URL007.md) | Redirect chain ends on an unrelated domain |

## Attachments (`ATT`)

| ID | Title |
|----|-------|
| [ATT001](ATT001.md) | Declared MIME type does not match file contents |
| [ATT002](ATT002.md) | Double extension disguises an executable |
| [ATT003](ATT003.md) | HTML attachment contains an external form or script |
| [ATT004](ATT004.md) | Attachment is an executable, script, shortcut or disk image |
| [ATT005](ATT005.md) | Filename contains a right-to-left override |

## Later prefixes

`RTE` and `CNT` are designed in [DESIGN.md](../DESIGN.md) and are not implemented yet.

To inspect the live catalogue:

```bash
baittrace rules
baittrace explain AUTH005
```
