"""Analyzers: the detection layer.

Each analyzer owns one evidence class, one rule-ID namespace, one test module
and one set of documentation pages. Adding detection means adding an analyzer
or a rule to one, never editing the pipeline.

Present in M1: :mod:`~baittrace.analyzers.identity` (IDN) and
:mod:`~baittrace.analyzers.headers` (HDR). The URL, attachment, content,
routing and authentication analyzers arrive in later milestones; see
``docs/ROADMAP.md``.
"""

from .base import Analyzer, Context
from .registry import all_rules, discover, find_rule, select

__all__ = ["Analyzer", "Context", "all_rules", "discover", "find_rule", "select"]
