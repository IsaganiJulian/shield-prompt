"""
Unit tests for PatternIngester

Tests cover:
  - Initialization with default and custom config
  - ingest(): new patterns, updates, severity rejection, invalid regex fallback
  - ingest_mock_patterns(): built-in offline patterns
  - get_patterns(): filtering by type, severity, age, source
  - get_stats(): correct counts by type / severity / source
  - persist() / load(): JSON roundtrip via temp file
  - prune(): removes stale patterns, respects retention window
  - _normalize(): severity gate, regex fallback, description truncation
  - _validate_regex(): valid vs. invalid patterns
  - _merge(): severity escalation, reference union, date tracking
  - IngestionResult.success_rate
"""

import json
import pytest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.core.pattern_ingester import (
    MOCK_PATTERNS,
    IngestionResult,
    PatternIngester,
    _dict_to_pattern,
    _pattern_to_dict,
)
from src.core.threat_intel import ThreatPattern


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_pattern(
    pid="pat_001",
    threat_type="injection",
    severity="high",
    source="cve",
    regex=r"(?i)(inject)",
    days_old=0,
    refs=None,
) -> ThreatPattern:
    ts = datetime.now() - timedelta(days=days_old)
    return ThreatPattern(
        pattern_id=pid,
        description="Test pattern",
        pattern_regex=regex,
        threat_type=threat_type,
        severity=severity,
        first_seen=ts,
        last_updated=ts,
        source=source,
        references=refs or [],
    )


@pytest.fixture
def ingester():
    return PatternIngester()


@pytest.fixture
def ingester_medium(tmp_path):
    return PatternIngester({
        "store_path": str(tmp_path / "patterns.json"),
        "min_severity": "medium",
        "retention_days": 30,
    })


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

class TestPatternIngesterInit:
    def test_defaults(self, ingester):
        assert ingester.retention_days == 90
        assert ingester.min_severity == "low"
        assert ingester.pattern_count == 0

    def test_custom_config(self, tmp_path):
        cfg = {
            "store_path": str(tmp_path / "store.json"),
            "retention_days": 7,
            "min_severity": "high",
        }
        p = PatternIngester(cfg)
        assert p.retention_days == 7
        assert p.min_severity == "high"
        assert p.store_path == tmp_path / "store.json"


# ---------------------------------------------------------------------------
# ingest()
# ---------------------------------------------------------------------------

class TestIngest:
    def test_new_patterns_added(self, ingester):
        patterns = [_make_pattern("a"), _make_pattern("b")]
        result = ingester.ingest(patterns)

        assert result.total_received == 2
        assert result.new_patterns == 2
        assert result.updated_patterns == 0
        assert result.rejected_patterns == 0
        assert ingester.pattern_count == 2

    def test_duplicate_triggers_update(self, ingester):
        p = _make_pattern("dup_1")
        ingester.ingest([p])
        result = ingester.ingest([p])

        assert result.new_patterns == 0
        assert result.updated_patterns == 1
        assert ingester.pattern_count == 1

    def test_below_min_severity_rejected(self, ingester_medium):
        low = _make_pattern(pid="low_1", severity="low")
        result = ingester_medium.ingest([low])

        assert result.rejected_patterns == 1
        assert result.new_patterns == 0
        assert ingester_medium.pattern_count == 0

    def test_invalid_regex_uses_fallback(self, ingester):
        bad_regex = _make_pattern(regex="[unclosed")
        result = ingester.ingest([bad_regex])

        assert result.new_patterns == 1
        stored = ingester._patterns["pat_001"]
        assert stored.pattern_regex == r"(?i)(prompt|injection|bypass|override)"

    def test_empty_list_returns_zero_counts(self, ingester):
        result = ingester.ingest([])
        assert result.total_received == 0
        assert result.new_patterns == 0
        assert result.duration_ms >= 0

    def test_result_has_timestamp(self, ingester):
        result = ingester.ingest([_make_pattern()])
        assert isinstance(result.timestamp, datetime)

    def test_description_truncated_to_500(self, ingester):
        long_desc = "x" * 600
        p = _make_pattern()
        from dataclasses import replace as dc_replace
        p = dc_replace(p, description=long_desc)
        ingester.ingest([p])
        stored = ingester._patterns["pat_001"]
        assert len(stored.description) == 500


# ---------------------------------------------------------------------------
# IngestionResult.success_rate
# ---------------------------------------------------------------------------

class TestIngestionResult:
    def test_success_rate_all_accepted(self):
        r = IngestionResult(10, 8, 2, 0, [], 5.0)
        assert r.success_rate == 1.0

    def test_success_rate_partial(self):
        r = IngestionResult(10, 6, 2, 2, [], 5.0)
        assert r.success_rate == pytest.approx(0.8)

    def test_success_rate_zero_received(self):
        r = IngestionResult(0, 0, 0, 0, [], 0.0)
        assert r.success_rate == 1.0


# ---------------------------------------------------------------------------
# ingest_mock_patterns()
# ---------------------------------------------------------------------------

class TestIngestMockPatterns:
    def test_loads_all_mock_patterns(self, ingester):
        result = ingester.ingest_mock_patterns()
        assert result.new_patterns == len(MOCK_PATTERNS)
        assert ingester.pattern_count == len(MOCK_PATTERNS)

    def test_mock_patterns_are_valid(self, ingester):
        ingester.ingest_mock_patterns()
        for p in ingester.get_patterns():
            assert p.pattern_regex
            assert p.threat_type in ("injection", "bypass", "exfiltration", "override")
            assert p.severity in ("low", "medium", "high", "critical")


# ---------------------------------------------------------------------------
# get_patterns()
# ---------------------------------------------------------------------------

class TestGetPatterns:
    def _load_mixed(self, ingester):
        ingester.ingest([
            _make_pattern("inj_1", threat_type="injection", severity="high", source="cve"),
            _make_pattern("byp_1", threat_type="bypass", severity="medium", source="github"),
            _make_pattern("exf_1", threat_type="exfiltration", severity="critical", source="blog"),
            _make_pattern("old_1", threat_type="injection", severity="high", source="cve", days_old=60),
        ])

    def test_no_filter_returns_all(self, ingester):
        self._load_mixed(ingester)
        assert len(ingester.get_patterns()) == 4

    def test_filter_by_threat_type(self, ingester):
        self._load_mixed(ingester)
        result = ingester.get_patterns(threat_type="injection")
        assert all(p.threat_type == "injection" for p in result)
        assert len(result) == 2

    def test_filter_by_min_severity(self, ingester):
        self._load_mixed(ingester)
        result = ingester.get_patterns(min_severity="high")
        assert all(p.severity in ("high", "critical") for p in result)

    def test_filter_by_max_age_days(self, ingester):
        self._load_mixed(ingester)
        result = ingester.get_patterns(max_age_days=30)
        assert all(p.pattern_id != "old_1" for p in result)

    def test_filter_by_source(self, ingester):
        self._load_mixed(ingester)
        result = ingester.get_patterns(source="blog")
        assert all(p.source == "blog" for p in result)
        assert len(result) == 1

    def test_results_sorted_newest_first(self, ingester):
        self._load_mixed(ingester)
        result = ingester.get_patterns()
        dates = [p.last_updated for p in result]
        assert dates == sorted(dates, reverse=True)

    def test_combined_filters(self, ingester):
        self._load_mixed(ingester)
        result = ingester.get_patterns(
            threat_type="injection",
            min_severity="high",
            max_age_days=30,
        )
        assert len(result) == 1
        assert result[0].pattern_id == "inj_1"


# ---------------------------------------------------------------------------
# get_stats()
# ---------------------------------------------------------------------------

class TestGetStats:
    def test_empty_store(self, ingester):
        stats = ingester.get_stats()
        assert stats["total"] == 0
        assert stats["oldest_update"] is None
        assert stats["newest_update"] is None

    def test_counts_by_type(self, ingester):
        ingester.ingest([
            _make_pattern("a", threat_type="injection"),
            _make_pattern("b", threat_type="injection"),
            _make_pattern("c", threat_type="bypass"),
        ])
        stats = ingester.get_stats()
        assert stats["by_type"]["injection"] == 2
        assert stats["by_type"]["bypass"] == 1

    def test_counts_by_severity(self, ingester):
        ingester.ingest([
            _make_pattern("a", severity="high"),
            _make_pattern("b", severity="critical"),
            _make_pattern("c", severity="high"),
        ])
        stats = ingester.get_stats()
        assert stats["by_severity"]["high"] == 2
        assert stats["by_severity"]["critical"] == 1

    def test_counts_by_source(self, ingester):
        ingester.ingest([
            _make_pattern("a", source="cve"),
            _make_pattern("b", source="github"),
        ])
        stats = ingester.get_stats()
        assert stats["by_source"]["cve"] == 1
        assert stats["by_source"]["github"] == 1

    def test_total_matches_pattern_count(self, ingester):
        ingester.ingest([_make_pattern("a"), _make_pattern("b")])
        assert ingester.get_stats()["total"] == ingester.pattern_count


# ---------------------------------------------------------------------------
# persist() / load()
# ---------------------------------------------------------------------------

class TestPersistLoad:
    def test_roundtrip(self, tmp_path, ingester):
        ingester.ingest([_make_pattern("p1", severity="high")])
        store_file = tmp_path / "store.json"
        ingester.persist(str(store_file))

        fresh = PatternIngester()
        count = fresh.load(str(store_file))

        assert count == 1
        assert "p1" in fresh._patterns
        assert fresh._patterns["p1"].severity == "high"

    def test_persist_creates_parent_dirs(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c" / "store.json"
        p = PatternIngester({"store_path": str(deep)})
        p.ingest([_make_pattern()])
        p.persist()
        assert deep.exists()

    def test_load_missing_file_returns_zero(self, tmp_path, ingester):
        count = ingester.load(str(tmp_path / "nonexistent.json"))
        assert count == 0

    def test_load_merges_with_existing(self, tmp_path, ingester):
        p1 = _make_pattern("p1")
        p2 = _make_pattern("p2")
        ingester.ingest([p1])

        store_file = tmp_path / "store.json"
        other = PatternIngester()
        other.ingest([p2])
        other.persist(str(store_file))

        ingester.load(str(store_file))
        assert ingester.pattern_count == 2

    def test_load_handles_corrupt_entry(self, tmp_path, ingester):
        store_file = tmp_path / "store.json"
        with store_file.open("w") as fh:
            json.dump({
                "good_1": _pattern_to_dict(_make_pattern("good_1")),
                "bad_1": {"pattern_id": "bad_1"},  # missing required fields
            }, fh)

        count = ingester.load(str(store_file))
        assert count == 1  # only the valid entry loaded


# ---------------------------------------------------------------------------
# prune()
# ---------------------------------------------------------------------------

class TestPrune:
    def test_prunes_old_patterns(self, ingester):
        ingester.ingest([
            _make_pattern("fresh", days_old=5),
            _make_pattern("stale", days_old=100),
        ])
        removed = ingester.prune(retention_days=30)
        assert removed == 1
        assert "fresh" in ingester._patterns
        assert "stale" not in ingester._patterns

    def test_prunes_none_when_all_fresh(self, ingester):
        ingester.ingest([_make_pattern("new", days_old=1)])
        removed = ingester.prune(retention_days=30)
        assert removed == 0
        assert ingester.pattern_count == 1

    def test_prunes_all_when_all_stale(self, ingester):
        ingester.ingest([
            _make_pattern("a", days_old=200),
            _make_pattern("b", days_old=150),
        ])
        removed = ingester.prune(retention_days=30)
        assert removed == 2
        assert ingester.pattern_count == 0

    def test_uses_config_retention_when_no_arg(self, ingester_medium):
        ingester_medium.ingest([_make_pattern("old", days_old=31, severity="medium")])
        removed = ingester_medium.prune()
        assert removed == 1

    def test_prune_returns_count(self, ingester):
        ingester.ingest([_make_pattern("x", days_old=50)])
        removed = ingester.prune(retention_days=30)
        assert isinstance(removed, int)


# ---------------------------------------------------------------------------
# _normalize()
# ---------------------------------------------------------------------------

class TestNormalize:
    def test_accepts_valid_pattern(self, ingester):
        p = _make_pattern()
        result = ingester._normalize(p)
        assert result is not None
        assert result.pattern_id == p.pattern_id

    def test_rejects_below_min_severity(self, ingester_medium):
        low = _make_pattern(severity="low")
        assert ingester_medium._normalize(low) is None

    def test_accepts_min_severity_exactly(self, ingester_medium):
        medium = _make_pattern(severity="medium")
        result = ingester_medium._normalize(medium)
        assert result is not None

    def test_fallback_regex_on_invalid(self, ingester):
        bad = _make_pattern(regex="[bad")
        result = ingester._normalize(bad)
        assert result is not None
        assert result.pattern_regex == r"(?i)(prompt|injection|bypass|override)"

    def test_fallback_regex_on_empty(self, ingester):
        empty = _make_pattern(regex="")
        result = ingester._normalize(empty)
        assert result is not None
        assert result.pattern_regex == r"(?i)(prompt|injection|bypass|override)"

    def test_description_stripped(self, ingester):
        p = _make_pattern()
        from dataclasses import replace as dc_replace
        p = dc_replace(p, description="  spaces  ")
        result = ingester._normalize(p)
        assert result.description == "spaces"

    def test_description_truncated_at_500(self, ingester):
        from dataclasses import replace as dc_replace
        p = dc_replace(_make_pattern(), description="a" * 600)
        result = ingester._normalize(p)
        assert len(result.description) == 500


# ---------------------------------------------------------------------------
# _validate_regex()
# ---------------------------------------------------------------------------

class TestValidateRegex:
    def test_valid_regex(self, ingester):
        assert ingester._validate_regex(r"(?i)(prompt)") is True
        assert ingester._validate_regex(r".*") is True
        assert ingester._validate_regex(r"\b(inject)\b") is True

    def test_invalid_regex(self, ingester):
        assert ingester._validate_regex("[unclosed") is False
        assert ingester._validate_regex("(?P<invalid") is False

    def test_empty_string_is_valid(self, ingester):
        assert ingester._validate_regex("") is True


# ---------------------------------------------------------------------------
# _merge()
# ---------------------------------------------------------------------------

class TestMerge:
    def _make_pair(self, pid="p1"):
        older = _make_pattern(pid, days_old=5, severity="medium", refs=["https://ref-a.com"])
        newer = _make_pattern(pid, days_old=1, severity="high", refs=["https://ref-b.com"])
        return older, newer

    def test_keeps_earlier_first_seen(self, ingester):
        older, newer = self._make_pair()
        merged = ingester._merge(older, newer)
        assert merged.first_seen == older.first_seen

    def test_advances_last_updated(self, ingester):
        older, newer = self._make_pair()
        merged = ingester._merge(older, newer)
        assert merged.last_updated == newer.last_updated

    def test_escalates_severity(self, ingester):
        older, newer = self._make_pair()
        merged = ingester._merge(older, newer)
        assert merged.severity == "high"

    def test_keeps_existing_severity_when_not_escalated(self, ingester):
        high = _make_pattern("p1", severity="high")
        medium = _make_pattern("p1", severity="medium")
        merged = ingester._merge(high, medium)
        assert merged.severity == "high"

    def test_unions_references(self, ingester):
        older, newer = self._make_pair()
        merged = ingester._merge(older, newer)
        assert "https://ref-a.com" in merged.references
        assert "https://ref-b.com" in merged.references

    def test_deduplicates_references(self, ingester):
        a = _make_pattern("p1", refs=["https://same.com", "https://a.com"])
        b = _make_pattern("p1", refs=["https://same.com", "https://b.com"])
        merged = ingester._merge(a, b)
        ref_count = merged.references.count("https://same.com")
        assert ref_count == 1


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

class TestSerializationHelpers:
    def test_pattern_to_dict_roundtrip(self):
        p = _make_pattern("ser_1", severity="critical", refs=["https://example.com"])
        d = _pattern_to_dict(p)
        restored = _dict_to_pattern(d)
        assert restored.pattern_id == p.pattern_id
        assert restored.severity == p.severity
        assert restored.references == p.references

    def test_dates_serialized_as_iso_strings(self):
        p = _make_pattern()
        d = _pattern_to_dict(p)
        assert isinstance(d["first_seen"], str)
        assert isinstance(d["last_updated"], str)
        # Verify parseable
        datetime.fromisoformat(d["first_seen"])
        datetime.fromisoformat(d["last_updated"])
