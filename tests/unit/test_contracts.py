"""Contracts that outlive any individual rule.

The JSON document, the offline guarantee and the vendored data assets are all
things other software or other people depend on. Breaking one of them silently
is worse than a missed detection, because nobody finds out.
"""

from __future__ import annotations

import datetime as dt
import re
import socket

import jsonschema
import pytest

from baittrace import assets
from baittrace.analyzers.registry import all_rules, discover
from baittrace.config import Config
from baittrace.pipeline import scan
from baittrace.render.json import SCHEMA, to_dict
from baittrace.resolver import AnswerState, NullResolver

from ..conftest import CORPUS, build_eml, scan_eml

SAMPLES = sorted((CORPUS / "malicious").glob("*.eml")) + sorted((CORPUS / "benign").glob("*.eml"))


class TestJsonSchema:
    def test_the_schema_itself_is_valid(self) -> None:
        jsonschema.Draft202012Validator.check_schema(SCHEMA)

    @pytest.mark.parametrize("path", SAMPLES, ids=lambda p: p.name)
    def test_every_report_validates(self, path) -> None:
        document = to_dict(scan(path, Config(deterministic=True)))
        jsonschema.validate(document, SCHEMA)

    def test_an_empty_message_still_validates(self) -> None:
        document = to_dict(scan_eml(build_eml()))
        jsonschema.validate(document, SCHEMA)

    def test_contributions_appear_on_every_signal(self) -> None:
        document = to_dict(scan(SAMPLES[0], Config(deterministic=True)))
        for signal in document["signals"]:
            assert "contribution" in signal
            assert signal["explanation"]


class TestOfflineGuarantee:
    def test_the_default_resolver_answers_nothing(self) -> None:
        resolver = NullResolver()
        assert resolver.online is False
        assert resolver.txt("example.com").state is AnswerState.UNAVAILABLE
        assert resolver.a("example.com").value is None

    def test_no_analyzer_declares_a_network_requirement_yet(self) -> None:
        assert not any(analyzer.requires_network for analyzer in discover())

    def test_scanning_opens_no_sockets(self, monkeypatch) -> None:
        """The strongest form of the offline claim: make a socket fatal."""

        def forbidden(*args: object, **kwargs: object) -> None:
            raise AssertionError("analysis attempted a network connection")

        monkeypatch.setattr(socket, "socket", forbidden)
        monkeypatch.setattr(socket, "create_connection", forbidden)
        monkeypatch.setattr(socket, "getaddrinfo", forbidden)

        for path in SAMPLES:
            report = scan(path, Config(deterministic=True))
            assert report.online is False

    def test_reports_state_the_mode_they_ran_in(self) -> None:
        assert scan(SAMPLES[0], Config(deterministic=True)).online is False


class TestHonestCoverage:
    def test_the_report_states_its_maximum_reachable_score(self) -> None:
        report = scan(SAMPLES[0], Config(deterministic=True))
        assert 0 < report.max_reachable_score < 100

    def test_the_maximum_reflects_only_the_analyzers_that_ran(self) -> None:
        full = scan(SAMPLES[0], Config(deterministic=True))
        partial = scan(SAMPLES[0], Config(deterministic=True, only_categories=("headers",)))
        assert partial.max_reachable_score < full.max_reachable_score

    def test_no_score_can_exceed_the_stated_maximum(self) -> None:
        for path in SAMPLES:
            report = scan(path, Config(deterministic=True))
            assert report.verdict.score <= report.max_reachable_score


class TestDataAssets:
    def test_the_public_suffix_list_loads(self) -> None:
        psl = assets.public_suffix_list()
        assert len(psl.rules) > 5000
        assert "com" in psl.rules

    def test_the_suffix_list_records_its_version(self) -> None:
        assert re.match(r"^\d{4}-\d{2}-\d{2}", assets.public_suffix_list().version)

    def test_the_suffix_list_is_not_ancient(self) -> None:
        """Vendored assets go stale silently. This is the reminder to refresh."""
        version = assets.public_suffix_list().version
        stamped = dt.date.fromisoformat(version[:10])
        age = dt.date.today() - stamped
        assert age.days < 400, (
            f"public_suffix_list.dat is {age.days} days old. Run python tools/refresh_data.py."
        )

    def test_the_confusables_map_covers_the_common_tricks(self) -> None:
        assert assets.skeleton("micros0ft") == assets.skeleton("microsoft")
        assert assets.skeleton("\u0430pple") == assets.skeleton("apple")

    def test_brand_domains_are_lowercase_and_plausible(self) -> None:
        for brand in assets.brands():
            assert brand.aliases, f"{brand.name} has no aliases"
            assert brand.domains, f"{brand.name} has no legitimate domains"
            for domain in brand.domains:
                assert domain == domain.lower()
                assert "." in domain

    def test_freemail_list_loads(self) -> None:
        assert assets.is_freemail("gmail.com")
        assert not assets.is_freemail("corp.example")


class TestRuleCatalogue:
    def test_rule_ids_are_unique(self) -> None:
        ids = [spec.id for spec in all_rules()]
        assert len(ids) == len(set(ids))

    def test_each_rule_id_matches_its_analyzer_prefix(self) -> None:
        for analyzer in discover():
            for spec in analyzer.RULES:
                assert spec.id.startswith(analyzer.prefix), (
                    f"{spec.id} does not use the {analyzer.prefix} prefix of {analyzer.id}"
                )

    def test_each_rule_belongs_to_its_analyzer_category(self) -> None:
        for analyzer in discover():
            for spec in analyzer.RULES:
                assert spec.category == analyzer.category


class TestFailureContainment:
    def test_one_broken_analyzer_does_not_lose_the_others(self, monkeypatch) -> None:
        from baittrace.analyzers import headers as headers_module

        def explode(self, msg, ctx):  # type: ignore[no-untyped-def]
            raise RuntimeError("simulated analyzer bug")

        monkeypatch.setattr(headers_module.HeaderAnalyzer, "run", explode)

        report = scan(CORPUS / "malicious" / "brand-lookalike.eml", Config(deterministic=True))
        assert report.degraded
        assert any(e.analyzer_id == "headers" for e in report.errors)
        assert any(s.id.startswith("IDN") for s in report.verdict.signals)
