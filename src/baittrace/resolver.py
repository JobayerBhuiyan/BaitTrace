"""The network boundary.

Only a resolver may perform I/O during analysis, and it is injected. In M1 the
only implementation is :class:`NullResolver`, which answers ``UNAVAILABLE`` to
everything.

That is not a placeholder, it is the point. Because the default path returns no
data, every analyzer is written against missing data from the first line of
code, so the offline path is the normal path rather than a degraded special
case. When the live resolver arrives in M4 it is an addition, not a rewrite.

The three-valued :class:`Answer` matters for the same reason. An analyzer must
never confuse "the lookup failed" with "the record does not exist"; that
distinction is what stops a rotated DKIM selector from being reported as an
invalid signature.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Generic, Protocol, TypeVar

T = TypeVar("T")


class AnswerState(StrEnum):
    OK = "ok"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class Answer(Generic[T]):
    state: AnswerState
    value: T | None = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.state is AnswerState.OK

    @classmethod
    def found(cls, value: T) -> Answer[T]:
        return cls(AnswerState.OK, value)

    @classmethod
    def unavailable(cls, detail: str = "offline") -> Answer[T]:
        return cls(AnswerState.UNAVAILABLE, None, detail)

    @classmethod
    def error(cls, detail: str) -> Answer[T]:
        return cls(AnswerState.ERROR, None, detail)


class Resolver(Protocol):
    """Everything that touches the network goes through this."""

    @property
    def online(self) -> bool: ...

    def txt(self, name: str) -> Answer[list[str]]: ...

    def a(self, name: str) -> Answer[list[str]]: ...

    def ptr(self, ip: str) -> Answer[str]: ...


class NullResolver:
    """Answers nothing. The default, and the only implementation in M1."""

    __slots__ = ()

    @property
    def online(self) -> bool:
        return False

    def txt(self, name: str) -> Answer[list[str]]:
        return Answer.unavailable("offline: no DNS lookups performed")

    def a(self, name: str) -> Answer[list[str]]:
        return Answer.unavailable("offline: no DNS lookups performed")

    def ptr(self, ip: str) -> Answer[str]:
        return Answer.unavailable("offline: no DNS lookups performed")
