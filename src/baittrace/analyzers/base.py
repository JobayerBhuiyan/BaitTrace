"""The analyzer interface.

An analyzer is a pure function from a message to a list of signals. It performs
no I/O, holds no state between runs, and knows nothing about scoring or
rendering. That constraint is what makes each one independently testable and
what lets a contributor add detection without reading the rest of the codebase.

Anything that needs the outside world goes through ``ctx.resolver``, which
answers ``UNAVAILABLE`` unless the operator passed ``--online`` or
``--follow-redirects``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import ClassVar

from ..config import Config
from ..limits import Budget
from ..model import Message
from ..resolver import NullResolver, Resolver
from ..signal import Category, RuleSpec, Signal


@dataclass(slots=True)
class Context:
    """Everything an analyzer is allowed to depend on besides the message."""

    config: Config = field(default_factory=Config)
    resolver: Resolver = field(default_factory=NullResolver)
    budget: Budget = field(default_factory=Budget)
    raw_bytes: bytes = b""

    @property
    def online(self) -> bool:
        return self.config.online and self.resolver.online


class Analyzer(ABC):
    """Base class for all analyzers, built-in and third-party alike."""

    id: ClassVar[str] = ""
    prefix: ClassVar[str] = ""
    category: ClassVar[Category]
    requires_network: ClassVar[bool] = False
    RULES: ClassVar[tuple[RuleSpec, ...]] = ()

    @abstractmethod
    def run(self, msg: Message, ctx: Context) -> Sequence[Signal]:
        """Return every signal this analyzer finds in ``msg``."""

    @classmethod
    def rule(cls, rule_id: str) -> RuleSpec:
        for spec in cls.RULES:
            if spec.id == rule_id:
                return spec
        raise KeyError(f"{cls.__name__} does not define rule {rule_id!r}")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} id={self.id!r} rules={len(self.RULES)}>"
