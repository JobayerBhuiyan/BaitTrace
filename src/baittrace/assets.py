"""Loaders for the vendored data assets.

Everything here reads from files committed to the repository. Nothing fetches
at runtime: a library that downloads a suffix list on first use is not
offline-first, and a detector whose behaviour depends on what the network
returned that morning is not reproducible. ``tools/refresh_data.py`` updates
the files, and the diff is reviewed like any other change.
"""

from __future__ import annotations

import re
import tomllib
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _read(name: str) -> str:
    return (resources.files("baittrace.data") / name).read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# Public suffix list
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PublicSuffixList:
    rules: frozenset[str]
    wildcards: frozenset[str]
    exceptions: frozenset[str]
    version: str

    def public_suffix(self, host: str) -> str:
        """Longest matching public suffix, per the publicsuffix.org algorithm."""
        labels = host.split(".")
        for i in range(len(labels)):
            suffix = ".".join(labels[i:])
            parent = ".".join(labels[i + 1 :])
            if suffix in self.exceptions:
                return parent
            if suffix in self.rules:
                return suffix
            if parent and parent in self.wildcards:
                return suffix
        return labels[-1]

    def registrable_domain(self, host: str) -> str:
        """The public suffix plus one label: the unit of "same organisation".

        Returns an empty string when the host is itself a public suffix, an IP
        literal, or otherwise has no registrable part. Comparing raw domains
        instead of registrable ones is the classic way to miss
        ``login.microsoft.com.evil.example``.
        """
        host = host.strip().strip(".").lower()
        if not host or _IPV4.match(host) or ":" in host:
            return ""
        if "." not in host:
            return ""

        suffix = self.public_suffix(host)
        if host == suffix:
            return ""

        suffix_labels = suffix.count(".") + 1
        labels = host.split(".")
        if len(labels) <= suffix_labels:
            return ""
        return ".".join(labels[-(suffix_labels + 1) :])


@lru_cache(maxsize=1)
def public_suffix_list() -> PublicSuffixList:
    rules: set[str] = set()
    wildcards: set[str] = set()
    exceptions: set[str] = set()
    version = "unknown"

    for line in _read("public_suffix_list.dat").splitlines():
        if line.startswith("// VERSION:"):
            version = line.removeprefix("// VERSION:").strip()
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if stripped.startswith("!"):
            exceptions.add(stripped[1:].lower())
        elif stripped.startswith("*."):
            wildcards.add(stripped[2:].lower())
        else:
            rules.add(stripped.lower())

    return PublicSuffixList(
        rules=frozenset(rules),
        wildcards=frozenset(wildcards),
        exceptions=frozenset(exceptions),
        version=version,
    )


def registrable_domain(host: str) -> str:
    return public_suffix_list().registrable_domain(host)


# --------------------------------------------------------------------------
# Confusable skeletons (UTS #39)
# --------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _confusables() -> tuple[dict[str, str], int]:
    mapping: dict[str, str] = {}
    for line in _read("confusables.txt").splitlines():
        if not line or line.startswith("#"):
            continue
        source_field, _, target = line.partition("\t")
        if not target:
            continue
        source = "".join(chr(int(cp, 16)) for cp in source_field.split())
        mapping[source] = target
    longest = max((len(k) for k in mapping), default=1)
    return mapping, longest


@lru_cache(maxsize=4096)
def skeleton(text: str) -> str:
    """Collapse visually confusable characters to a canonical form.

    ``micros0ft``, ``rnicrosoft`` and ``mіcrosoft`` (Cyrillic i) all reduce to
    the same skeleton as ``microsoft``, which is what makes lookalike detection
    work without a hand-maintained list of tricks.

    Case is folded on both sides because hostnames are case-insensitive and the
    UTS #39 prototypes are not consistently lowercase.
    """
    mapping, longest = _confusables()
    normalized = unicodedata.normalize("NFKC", text).casefold()

    out: list[str] = []
    i = 0
    while i < len(normalized):
        for size in range(min(longest, len(normalized) - i), 0, -1):
            chunk = normalized[i : i + size]
            replacement = mapping.get(chunk)
            if replacement is not None:
                out.append(replacement)
                i += size
                break
        else:
            out.append(normalized[i])
            i += 1
    return "".join(out).casefold()


def is_mixed_script(text: str) -> bool:
    """True when a string mixes scripts in a way legitimate domains rarely do.

    Deliberately coarse: it asks only whether Latin characters are combined
    with another script, which is the shape of a homograph attack. A purely
    Cyrillic or purely Greek domain is unusual but not itself deceptive.
    """
    scripts: set[str] = set()
    for char in text:
        if not char.isalpha():
            continue
        try:
            name = unicodedata.name(char)
        except ValueError:
            continue
        script = name.split(" ")[0]
        scripts.add(script)
        if len(scripts) > 1 and "LATIN" in scripts:
            return True
    return len(scripts) > 1


def decode_punycode(host: str) -> str:
    """Best-effort Unicode form of an IDNA hostname, for display only."""
    labels: list[str] = []
    for label in host.split("."):
        if label.lower().startswith("xn--"):
            try:
                labels.append(label[4:].encode("ascii").decode("punycode"))
                continue
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


# --------------------------------------------------------------------------
# Brands and freemail providers
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Brand:
    name: str
    aliases: tuple[str, ...]
    domains: tuple[str, ...]

    @property
    def skeletons(self) -> tuple[str, ...]:
        return tuple(skeleton(alias) for alias in self.aliases)


@lru_cache(maxsize=1)
def brands() -> tuple[Brand, ...]:
    data = tomllib.loads(_read("brands.toml"))
    entries = data.get("brand", [])
    result: list[Brand] = []
    for entry in entries:
        result.append(
            Brand(
                name=str(entry["name"]),
                aliases=tuple(str(a).lower() for a in entry.get("aliases", [])),
                domains=tuple(str(d).lower() for d in entry.get("domains", [])),
            )
        )
    return tuple(result)


@lru_cache(maxsize=1)
def brand_domains() -> frozenset[str]:
    return frozenset(domain for brand in brands() for domain in brand.domains)


@lru_cache(maxsize=1)
def freemail_domains() -> frozenset[str]:
    lines = _read("freemail.txt").splitlines()
    return frozenset(
        line.strip().lower() for line in lines if line.strip() and not line.startswith("#")
    )


def is_freemail(domain: str) -> bool:
    return domain.lower() in freemail_domains()


def data_dir() -> Path:
    """Filesystem path to the vendored assets, for tooling and tests."""
    return Path(str(resources.files("baittrace.data")))
