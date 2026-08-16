"""User configuration.

TOML only, parsed with :mod:`tomllib`. Deliberately not YAML: the config file
is one of the few pieces of attacker-adjacent input that is not an email, and
YAML's unsafe loaders are a well-worn foothold. Nothing here is ever pickled
for the same reason.

Discovery order, first match wins: an explicit ``--config`` path, then
``./baittrace.toml``, then ``$XDG_CONFIG_HOME/baittrace/config.toml``.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .errors import ConfigError
from .limits import Limits

CONFIG_FILENAME = "baittrace.toml"

_KNOWN_SECTIONS = {"scan", "organization", "allowlist", "rules", "limits"}


@dataclass(frozen=True, slots=True)
class Config:
    """Everything the pipeline needs that is not the message itself."""

    online: bool = False
    follow_redirects: bool = False
    redact: bool = False
    no_plugins: bool = False
    rulepack: str = "core@2026.08"
    limits: Limits = field(default_factory=Limits)

    # Zeroes volatile fields (timings) so two runs over the same input produce
    # byte-identical output. Used by golden tests and by anyone diffing reports.
    deterministic: bool = False

    own_domains: tuple[str, ...] = ()
    executives: tuple[str, ...] = ()
    trusted_relays: tuple[str, ...] = ()

    allowlist_domains: tuple[str, ...] = ()
    allowlist_addresses: tuple[str, ...] = ()

    disabled_rules: frozenset[str] = frozenset()
    only_categories: tuple[str, ...] = ()
    skip_categories: tuple[str, ...] = ()
    weight_overrides: dict[str, float] = field(default_factory=dict)

    source_path: Path | None = None

    def with_overrides(self, **kwargs: Any) -> Config:
        return replace(self, **kwargs)

    def is_allowlisted(self, domain: str, address: str = "") -> bool:
        domain = domain.lower()
        address = address.lower()
        return domain in {d.lower() for d in self.allowlist_domains} or address in {
            a.lower() for a in self.allowlist_addresses
        }


def _as_str_tuple(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where} must be a list of strings")
    return tuple(str(v) for v in value)


def discover_config_path(explicit: Path | None = None) -> Path | None:
    if explicit is not None:
        if not explicit.is_file():
            raise ConfigError(f"config file not found: {explicit}")
        return explicit

    local = Path.cwd() / CONFIG_FILENAME
    if local.is_file():
        return local

    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    candidate = base / "baittrace" / "config.toml"
    return candidate if candidate.is_file() else None


def load_config(explicit: Path | None = None) -> Config:
    """Load configuration, returning defaults when no file exists."""
    path = discover_config_path(explicit)
    if path is None:
        return Config()

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"could not read {path}: {exc}") from exc

    unknown = set(data) - _KNOWN_SECTIONS
    if unknown:
        # A warning rather than an error: a config written for a newer version
        # should still work, and silently ignoring a typo is the worse failure.
        print(f"baittrace: warning: unknown config sections in {path}: {sorted(unknown)}")

    scan = data.get("scan", {})
    org = data.get("organization", {})
    allow = data.get("allowlist", {})
    rules = data.get("rules", {})
    limit_data = data.get("limits", {})

    overrides_raw = rules.get("weights", {})
    if not isinstance(overrides_raw, dict):
        raise ConfigError("rules.weights must be a table of rule ID to number")
    weight_overrides = {str(k): float(v) for k, v in overrides_raw.items()}

    fallback = Limits()
    limits = Limits(
        max_bytes=int(limit_data.get("max_bytes", fallback.max_bytes)),
        max_depth=int(limit_data.get("max_depth", fallback.max_depth)),
        max_parts=int(limit_data.get("max_parts", fallback.max_parts)),
        max_headers=int(limit_data.get("max_headers", fallback.max_headers)),
        max_header_bytes=int(limit_data.get("max_header_bytes", fallback.max_header_bytes)),
        max_body_bytes=int(limit_data.get("max_body_bytes", fallback.max_body_bytes)),
        max_urls=int(limit_data.get("max_urls", fallback.max_urls)),
        budget_seconds=float(limit_data.get("budget_seconds", fallback.budget_seconds)),
    )

    return Config(
        online=bool(scan.get("online", False)),
        follow_redirects=bool(scan.get("follow_redirects", False)),
        redact=bool(scan.get("redact", False)),
        rulepack=str(scan.get("rulepack", "core@2026.08")),
        limits=limits,
        own_domains=_as_str_tuple(org.get("domains"), "organization.domains"),
        executives=_as_str_tuple(org.get("executives"), "organization.executives"),
        trusted_relays=_as_str_tuple(org.get("trusted_relays"), "organization.trusted_relays"),
        allowlist_domains=_as_str_tuple(allow.get("domains"), "allowlist.domains"),
        allowlist_addresses=_as_str_tuple(allow.get("addresses"), "allowlist.addresses"),
        disabled_rules=frozenset(_as_str_tuple(rules.get("disabled"), "rules.disabled")),
        weight_overrides=weight_overrides,
        source_path=path,
    )
