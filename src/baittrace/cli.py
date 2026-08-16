"""Command line interface.

Exit codes are part of the contract, because the difference between "found
something" and "the tool broke" is what makes this safe to put in a pipeline:

====  ======================================================================
0     scan completed, below the ``--fail-on`` threshold
1     scan completed, at or above the threshold
2     the tool could not complete: unreadable input, bad config, bad usage
====  ======================================================================
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import NoReturn

from ._version import __version__
from .analyzers.registry import all_rules, find_rule
from .config import Config, load_config
from .errors import BaitTraceError
from .pipeline import scan as run_scan
from .render import get as get_renderer
from .render.json import schema_json
from .render.layout import Style, color_enabled, unicode_enabled
from .scoring import BAND_ORDER, DEFAULT_RULEPACK, load_rulepack

EXIT_CLEAN = 0
EXIT_DETECTED = 1
EXIT_ERROR = 2

_FAIL_ON = {
    "benign": 0,
    "suspicious": 1,
    "high": 2,
    "critical": 3,
    "never": 99,
}

SUBCOMMANDS = {"scan", "explain", "rules", "schema", "version"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="baittrace",
        description=(
            "Offline-first, explainable phishing triage. Analysis is inert: no "
            "network, no HTML rendering, and nothing the message references is "
            "ever fetched."
        ),
        epilog="Documentation: https://github.com/JobayerBhuiyan/baittrace",
    )
    parser.add_argument("--version", action="version", version=f"baittrace {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser(
        "scan",
        help="analyze one message and print a report",
        description="Analyze one .eml file, or '-' to read a message from stdin.",
    )
    scan_parser.add_argument("path", help="path to the message, or '-' for stdin")
    scan_parser.add_argument(
        "--format",
        default="text",
        choices=("text", "json"),
        help="output format (default: text)",
    )
    scan_parser.add_argument(
        "--fail-on",
        default="high",
        choices=tuple(_FAIL_ON),
        help="lowest band that exits non-zero (default: high)",
    )
    scan_parser.add_argument(
        "--redact",
        action="store_true",
        help="mask addresses and IPs so the report can be shared",
    )
    scan_parser.add_argument("--config", type=Path, help="path to a baittrace.toml")
    scan_parser.add_argument(
        "--rulepack", default=None, help=f"scoring pack to use (default: {DEFAULT_RULEPACK})"
    )
    scan_parser.add_argument("--only", action="append", default=[], help="run only this category")
    scan_parser.add_argument("--skip", action="append", default=[], help="skip this category")
    scan_parser.add_argument(
        "--no-plugins", action="store_true", help="ignore third-party analyzers"
    )
    scan_parser.add_argument(
        "--deterministic",
        action="store_true",
        help="zero volatile fields so two runs produce byte-identical output",
    )
    scan_parser.add_argument("--width", type=int, default=None, help="report width in columns")
    scan_parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    scan_parser.add_argument("--color", action="store_true", help="force ANSI colour")
    scan_parser.add_argument("--no-unicode", action="store_true", help="use ASCII glyphs and rules")

    explain_parser = subparsers.add_parser(
        "explain", help="describe one rule in detail", description="Explain a rule by ID."
    )
    explain_parser.add_argument("rule_id", help="a rule ID such as IDN003")

    rules_parser = subparsers.add_parser("rules", help="list every rule this build can emit")
    rules_parser.add_argument("--category", default=None, help="filter to one category")

    subparsers.add_parser("schema", help="print the JSON Schema for --format json")
    subparsers.add_parser("version", help="print version, rulepack and analyzer inventory")

    return parser


def _style_from(args: argparse.Namespace) -> Style:
    color: bool | None = None
    if getattr(args, "no_color", False):
        color = False
    elif getattr(args, "color", False):
        color = True

    unicode_pref: bool | None = False if getattr(args, "no_unicode", False) else None
    width = getattr(args, "width", None)

    return Style(
        color=color_enabled(color),
        unicode=unicode_enabled(unicode_pref),
        width=width if width and width >= 40 else 72,
        redact=bool(getattr(args, "redact", False)),
    )


def _config_from(args: argparse.Namespace) -> Config:
    config = load_config(getattr(args, "config", None))
    return config.with_overrides(
        redact=bool(getattr(args, "redact", False)) or config.redact,
        no_plugins=bool(getattr(args, "no_plugins", False)) or config.no_plugins,
        rulepack=getattr(args, "rulepack", None) or config.rulepack,
        only_categories=tuple(getattr(args, "only", []) or ()),
        skip_categories=tuple(getattr(args, "skip", []) or ()),
        deterministic=bool(getattr(args, "deterministic", False)),
    )


def cmd_scan(args: argparse.Namespace) -> int:
    config = _config_from(args)
    style = _style_from(args)

    report = run_scan(args.path, config)
    output = get_renderer(args.format)(report, style)
    print(output)

    threshold = _FAIL_ON[args.fail_on]
    band_rank = BAND_ORDER.index(report.verdict.band)
    return EXIT_DETECTED if band_rank >= threshold else EXIT_CLEAN


def cmd_explain(args: argparse.Namespace) -> int:
    spec = find_rule(args.rule_id)
    if spec is None:
        known = ", ".join(s.id for s in all_rules())
        print(f"unknown rule {args.rule_id!r}. Known rules: {known}", file=sys.stderr)
        return EXIT_ERROR

    style = Style(color=color_enabled(None), unicode=unicode_enabled(None))
    print(style.paint(f"{spec.id}  {spec.title}", "bold"))
    print(style.rule())
    print(f"Category    {spec.category}")
    print(f"Severity    {spec.severity}")
    print(f"Weight      {spec.weight:g} (default, before rulepack and config overrides)")
    print(f"Kind        {spec.kind}")
    print()
    print("What it detects")
    print(f"  {spec.summary}")
    print()
    print("Recommended action")
    print(f"  {spec.advice}")
    if spec.false_positives:
        print()
        print("Known false positives")
        print(f"  {spec.false_positives}")
    if spec.refs:
        print()
        print("References")
        for ref in spec.refs:
            print(f"  {ref}")
    print()
    print(f"Full page: docs/rules/{spec.id}.md")
    return EXIT_CLEAN


def cmd_rules(args: argparse.Namespace) -> int:
    wanted = (args.category or "").lower()
    specs = [s for s in all_rules() if not wanted or str(s.category) == wanted]
    if not specs:
        print(f"no rules in category {args.category!r}", file=sys.stderr)
        return EXIT_ERROR

    print(f"{'ID':<8}{'CATEGORY':<13}{'SEVERITY':<10}{'WEIGHT':>7}  TITLE")
    for spec in specs:
        print(
            f"{spec.id:<8}{spec.category!s:<13}{spec.severity!s:<10}"
            f"{spec.weight:>7.1f}  {spec.title}"
        )
    print(f"\n{len(specs)} rule(s). Use 'baittrace explain <ID>' for detail.")
    return EXIT_CLEAN


def cmd_schema(_: argparse.Namespace) -> int:
    print(schema_json())
    return EXIT_CLEAN


def cmd_version(_: argparse.Namespace) -> int:
    from .analyzers.registry import discover

    pack = load_rulepack()
    print(f"baittrace {__version__}")
    print(f"rulepack  {pack.identifier} ({pack.combination})")
    print("analyzers")
    for analyzer in discover():
        network = "network" if analyzer.requires_network else "offline"
        print(f"  {analyzer.id:<12} {len(analyzer.RULES):>2} rules  {network}")
    return EXIT_CLEAN


_COMMANDS = {
    "scan": cmd_scan,
    "explain": cmd_explain,
    "rules": cmd_rules,
    "schema": cmd_schema,
    "version": cmd_version,
}


def _normalize(argv: list[str]) -> list[str]:
    """Allow ``baittrace message.eml`` as shorthand for ``baittrace scan``."""
    if argv and argv[0] not in SUBCOMMANDS and not argv[0].startswith("-"):
        return ["scan", *argv]
    if argv and argv[0] == "-":
        return ["scan", *argv]
    return argv


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(_normalize(list(sys.argv[1:] if argv is None else argv)))

    if args.command is None:
        parser.print_help()
        return EXIT_ERROR

    handler = _COMMANDS[args.command]
    try:
        return handler(args)
    except BaitTraceError as exc:
        print(f"baittrace: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:  # pragma: no cover - piping into head
        return EXIT_CLEAN
    except KeyboardInterrupt:  # pragma: no cover
        print("baittrace: interrupted", file=sys.stderr)
        return EXIT_ERROR


def entrypoint() -> NoReturn:  # pragma: no cover - console script shim
    raise SystemExit(main())


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
