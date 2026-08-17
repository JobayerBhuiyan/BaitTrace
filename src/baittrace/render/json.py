"""The machine-readable report.

This is a published contract, not a debug dump. ``POST /v1/scan`` on the hosted
service and ``baittrace scan --format json`` return the same document, so a
consumer written against one works against the other.

Compatibility rules, restated in COMPATIBILITY.md: adding a field is a minor
version, removing or retyping one is a major version. ``schema_version`` is in
every document so a consumer can branch on it.
"""

from __future__ import annotations

import json
from typing import Any

from ..report import Report
from ..sanitize import clean
from .layout import Style

SCHEMA_VERSION = "1.0"


def to_dict(report: Report, style: Style | None = None) -> dict[str, Any]:
    st = style or Style()
    verdict = report.verdict
    message = report.message
    sender = message.identity.primary_from

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {
            "name": report.tool.name,
            "version": report.tool.version,
            "rulepack": verdict.rulepack,
        },
        "scan": {
            "id": report.scan_id,
            "duration_ms": report.duration_ms,
            "online": report.online,
            "analyzers": list(report.analyzers_run),
            "degraded": report.degraded,
            "max_reachable_score": report.max_reachable_score,
        },
        "input": {
            "source": clean(message.source, redacted=st.redact),
            "sha256": message.sha256,
            "size_bytes": message.size_bytes,
        },
        "verdict": {
            "score": verdict.score,
            "band": verdict.band,
            "trust_factor": round(verdict.trust_factor, 4),
        },
        "message": {
            "subject": clean(message.subject, redacted=st.redact),
            "from_display": clean(sender.display_name, redacted=st.redact) if sender else "",
            "from_address": clean(sender.addr_spec, redacted=st.redact) if sender else "",
            "from_domain": sender.registrable_domain if sender else "",
            "reply_to": [clean(a.addr_spec, redacted=st.redact) for a in message.identity.reply_to],
            "date": clean(message.dates.raw),
            "url_count": len(message.urls),
            "attachment_count": len(message.attachments),
            "urls": [
                {
                    "defanged": url.defanged,
                    "host": url.host,
                    "registrable_domain": url.registrable_domain,
                    "location": url.location,
                }
                for url in message.urls
            ],
            "attachments": [
                {
                    "filename": clean(a.filename),
                    "declared_mime": a.declared_mime,
                    "sniffed_mime": a.sniffed_mime,
                    "size_bytes": a.size,
                    "sha256": a.sha256,
                }
                for a in message.attachments
            ],
        },
        "categories": [
            {
                "name": str(category.category),
                "raw": round(category.raw, 4),
                "cap": category.cap,
                "ceiling": category.ceiling,
                "strength": round(category.strength, 4),
            }
            for category in verdict.categories
        ],
        "signals": [
            _signal_dict(signal, points, st)
            for signal, points in zip(verdict.signals, verdict.contributions, strict=True)
        ],
        "suppressors": [_signal_dict(signal, 0, st) for signal in verdict.suppressors],
        "errors": [
            {"analyzer": error.analyzer_id, "message": error.message, "detail": error.detail}
            for error in report.errors
        ],
        "truncations": list(message.limits.describe()),
        "notes": list(verdict.notes),
    }


def _signal_dict(signal: Any, points: int, st: Style) -> dict[str, Any]:
    return {
        "id": signal.id,
        "category": str(signal.category),
        "title": signal.title,
        "severity": str(signal.severity),
        "kind": str(signal.kind),
        "weight": signal.weight,
        "confidence": signal.confidence,
        "contribution": points,
        "explanation": clean(signal.explanation, redacted=st.redact),
        "advice": signal.advice,
        "evidence": [
            {
                "locator": item.locator,
                "excerpt": clean(item.excerpt, redacted=st.redact),
                "note": item.note or "",
            }
            for item in signal.evidence
        ],
        "refs": list(signal.refs),
    }


def render(report: Report, style: Style | None = None, *, indent: int = 2) -> str:
    return json.dumps(to_dict(report, style), indent=indent, sort_keys=False, ensure_ascii=False)


_SIGNAL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["id", "category", "title", "severity", "confidence", "contribution"],
    "properties": {
        "id": {"type": "string", "pattern": "^[A-Z]{3,4}[0-9]{3}$"},
        "category": {
            "type": "string",
            "enum": [
                "auth",
                "identity",
                "urls",
                "attachments",
                "content",
                "routing",
                "headers",
            ],
        },
        "title": {"type": "string"},
        "severity": {"type": "string", "enum": ["info", "low", "medium", "high"]},
        "kind": {"type": "string", "enum": ["indicator", "suppressor"]},
        "weight": {"type": "number", "minimum": 0},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "contribution": {"type": "integer", "minimum": 0},
        "explanation": {"type": "string"},
        "advice": {"type": "string"},
        "evidence": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["locator", "excerpt"],
                "properties": {
                    "locator": {"type": "string"},
                    "excerpt": {"type": "string"},
                    "note": {"type": "string"},
                },
            },
        },
        "refs": {"type": "array", "items": {"type": "string"}},
    },
}

SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://github.com/JobayerBhuiyan/baittrace/schema/report-1.0.json",
    "title": "BaitTrace report",
    "type": "object",
    "required": ["schema_version", "tool", "scan", "input", "verdict", "signals"],
    "properties": {
        "schema_version": {"type": "string", "const": SCHEMA_VERSION},
        "tool": {
            "type": "object",
            "required": ["name", "version", "rulepack"],
            "properties": {
                "name": {"type": "string"},
                "version": {"type": "string"},
                "rulepack": {"type": "string"},
            },
        },
        "scan": {
            "type": "object",
            "required": ["id", "duration_ms", "online", "analyzers", "degraded"],
            "properties": {
                "id": {"type": "string"},
                "duration_ms": {"type": "integer", "minimum": 0},
                "online": {"type": "boolean"},
                "analyzers": {"type": "array", "items": {"type": "string"}},
                "degraded": {"type": "boolean"},
                "max_reachable_score": {"type": "integer", "minimum": 0, "maximum": 100},
            },
        },
        "input": {
            "type": "object",
            "required": ["source", "sha256", "size_bytes"],
            "properties": {
                "source": {"type": "string"},
                "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "size_bytes": {"type": "integer", "minimum": 0},
            },
        },
        "verdict": {
            "type": "object",
            "required": ["score", "band", "trust_factor"],
            "properties": {
                "score": {"type": "integer", "minimum": 0, "maximum": 100},
                "band": {
                    "type": "string",
                    "enum": ["BENIGN", "SUSPICIOUS", "HIGH", "CRITICAL"],
                },
                "trust_factor": {"type": "number", "minimum": 0, "maximum": 1},
            },
        },
        "message": {"type": "object"},
        "categories": {"type": "array", "items": {"type": "object"}},
        "signals": {"type": "array", "items": _SIGNAL_SCHEMA},
        "suppressors": {"type": "array", "items": _SIGNAL_SCHEMA},
        "errors": {"type": "array", "items": {"type": "object"}},
        "truncations": {"type": "array", "items": {"type": "string"}},
        "notes": {"type": "array", "items": {"type": "string"}},
    },
}


def schema_json(indent: int = 2) -> str:
    return json.dumps(SCHEMA, indent=indent)
