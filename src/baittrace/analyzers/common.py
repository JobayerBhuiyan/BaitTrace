"""Helpers shared between analyzers.

Currently one thing, and it exists to hold down the false-positive rate.

Three of the weaker rules -- Reply-To divergence, Message-ID domain mismatch
and Return-Path mismatch -- describe structural facts that are suspicious in
one-to-one mail and completely routine in bulk mail. Every newsletter on earth
sends through a provider, redirects replies to a no-reply mailbox, and stamps
its own Message-ID. Scoring those at full weight means flagging the world's
legitimate marketing traffic, and a detector that cries wolf on newsletters
stops being read.

So the rules stay, and their weight drops when the message is visibly bulk. The
finding still appears in the report with its evidence; it just stops dominating
the score. An attacker can of course add a ``List-Unsubscribe`` header, which
is precisely why this reduces weight rather than granting trust.
"""

from __future__ import annotations

from ..model import Message

_BULK_HEADERS = (
    "list-unsubscribe",
    "list-id",
    "list-help",
    "list-subscribe",
    "feedback-id",
    "x-campaign-id",
    "x-mailer-lid",
)

_BULK_PRECEDENCE = {"bulk", "list", "junk"}


def bulk_mail_indicators(msg: Message) -> tuple[str, ...]:
    """Headers suggesting this is subscribed bulk mail rather than personal mail."""
    found = [header.name for header in msg.headers if header.lname in _BULK_HEADERS]

    precedence = msg.headers.value("precedence").strip().lower()
    if precedence in _BULK_PRECEDENCE:
        found.append("Precedence")

    auto = msg.headers.value("auto-submitted").strip().lower()
    if auto and auto != "no":
        found.append("Auto-Submitted")

    return tuple(dict.fromkeys(found))


def looks_like_bulk(msg: Message) -> bool:
    return bool(bulk_mail_indicators(msg))


def bulk_note(msg: Message) -> str:
    """A clause explaining the reduced weight, for the finding's explanation."""
    indicators = bulk_mail_indicators(msg)
    if not indicators:
        return ""
    return (
        f" This message carries bulk-mail headers ({', '.join(indicators)}), where this "
        f"pattern is routine, so the finding is weighted down rather than removed."
    )
