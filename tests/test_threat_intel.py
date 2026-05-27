"""
Unit tests for ThreatIntelligence (orchestration layer).

Construction strategy: build a real ThreatIntelligence with
enable_vector_search=False (skips FAISS/OpenAI init), then replace the three
sub-components (client, ingester, vector_store) with MagicMock instances.
This avoids patching deferred imports and keeps tests fast and offline.
"""

from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from src.core.threat_intel import ThreatIntelligence, ThreatPattern


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_pattern(
    pid: str = "p1",
    threat_type: str = "injection",
    severity: str = "high",
) -> ThreatPattern:
    now = datetime.now()
    return ThreatPattern(
        pattern_id=pid,
        description="Ignore previous instructions",
        pattern_regex=r"(?i)(ignore.*instructions)",
        threat_type=threat_type,
        severity=severity,
        first_seen=now,
        last_updated=now,
        source="cve",
        references=[],
    )


def _make_ingestion_result(
    total: int = 3,
    new: int = 2,
    updated: int = 1,
    rejected: int = 0,
    duration_ms: float = 5.0,
) -> MagicMock:
    r = MagicMock()
    r.total_received = total
    r.new_patterns = new
    r.updated_patterns = updated
    r.rejected_patterns = rejected
    r.duration_ms = duration_ms
    return r


def _make_ti(**extra_config) -> ThreatIntelligence:
    """
    Construct ThreatIntelligence with FAISS/OpenAI disabled, then replace
    all three sub-components with mocks that have sensible defaults.
    """
    inst = ThreatIntelligence(config={"enable_vector_search": False, **extra_config})

    inst.client = MagicMock()
    inst.ingester = MagicMock()
    inst.vector_store = MagicMock()

    inst.ingester.pattern_count = 0
    inst.ingester._patterns = {}
    inst.ingester.get_patterns.return_value = []
    inst.ingester.ingest.return_value = _make_ingestion_result()
    inst.ingester.ingest_mock_patterns.return_value = _make_ingestion_result()
    inst.ingester.prune.return_value = 0
    inst.ingester.get_stats.return_value = {"total": 0, "by_type": {}}

    inst.vector_store.enabled = False
    inst.vector_store.pattern_count = 0
    inst.vector_store.add_patterns.return_value = 0
    inst.vector_store.search.return_value = []

    inst.client.fetch_all_patterns.return_value = []

    return inst


@pytest.fixture
def ti() -> ThreatIntelligence:
    return _make_ti()


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

class TestInit:
    def test_creates_three_sub_components(self, ti):
        assert ti.client is not None
        assert ti.ingester is not None
        assert ti.vector_store is not None

    def test_default_update_interval(self, ti):
        assert ti.update_interval == 3600

    def test_custom_update_interval(self):
        inst = ThreatIntelligence(config={
            "enable_vector_search": False,
            "threat_intel_update_interval": 600,
        })
        assert inst.update_interval == 600

    def test_last_update_none_on_init(self, ti):
        assert ti.last_update is None

    def test_bright_data_api_key_compat_field(self):
        inst = ThreatIntelligence(config={
            "enable_vector_search": False,
            "bright_data_api_key": "bdk-test",
        })
        assert inst.bright_data_api_key == "bdk-test"

    def test_use_mock_patterns_loads_real_patterns(self):
        # Construct with real sub-components; mock patterns are baked into PatternIngester
        inst = ThreatIntelligence(config={
            "enable_vector_search": False,
            "use_mock_patterns": True,
        })
        assert inst.ingester.pattern_count > 0


# ---------------------------------------------------------------------------
# patterns property
# ---------------------------------------------------------------------------

class TestPatternsProperty:
    def test_returns_dict_from_ingester(self, ti):
        p = _make_pattern()
        ti.ingester._patterns = {p.pattern_id: p}
        result = ti.patterns
        assert isinstance(result, dict)
        assert p.pattern_id in result

    def test_returns_empty_dict_when_no_patterns(self, ti):
        ti.ingester._patterns = {}
        assert ti.patterns == {}

    def test_returns_copy_not_reference(self, ti):
        ti.ingester._patterns = {"p1": _make_pattern("p1")}
        copy = ti.patterns
        copy["injected"] = _make_pattern("injected")
        assert "injected" not in ti.ingester._patterns


# ---------------------------------------------------------------------------
# fetch_latest_threats
# ---------------------------------------------------------------------------

class TestFetchLatestThreats:
    def test_calls_client_then_ingests(self, ti):
        patterns = [_make_pattern("p1"), _make_pattern("p2")]
        ti.client.fetch_all_patterns.return_value = patterns
        ti.ingester.ingest.return_value = _make_ingestion_result(
            total=2, new=2, updated=0
        )

        result = ti.fetch_latest_threats()

        ti.client.fetch_all_patterns.assert_called_once_with(ti.limit_per_source)
        ti.ingester.ingest.assert_called_once_with(patterns)
        assert result == patterns

    def test_syncs_to_vector_store_when_patterns_new(self, ti):
        patterns = [_make_pattern()]
        ti.client.fetch_all_patterns.return_value = patterns
        ti.ingester.ingest.return_value = _make_ingestion_result(new=1, updated=0)
        ti.ingester.get_patterns.return_value = patterns

        ti.fetch_latest_threats()

        ti.vector_store.add_patterns.assert_called()

    def test_no_vector_sync_when_nothing_new(self, ti):
        ti.client.fetch_all_patterns.return_value = []
        ti.fetch_latest_threats()
        ti.vector_store.add_patterns.assert_not_called()

    def test_returns_empty_when_client_returns_empty(self, ti):
        ti.client.fetch_all_patterns.return_value = []
        assert ti.fetch_latest_threats() == []

    def test_no_ingest_call_when_empty(self, ti):
        ti.client.fetch_all_patterns.return_value = []
        ti.fetch_latest_threats()
        ti.ingester.ingest.assert_not_called()


# ---------------------------------------------------------------------------
# add_pattern
# ---------------------------------------------------------------------------

class TestAddPattern:
    def test_ingests_and_indexes_single_pattern(self, ti):
        p = _make_pattern()
        ti.add_pattern(p)
        ti.ingester.ingest.assert_called_once_with([p])
        ti.vector_store.add_patterns.assert_called_once_with([p])

    def test_multiple_calls_each_ingested_separately(self, ti):
        for i in range(3):
            ti.add_pattern(_make_pattern(f"p{i}"))
        assert ti.ingester.ingest.call_count == 3
        assert ti.vector_store.add_patterns.call_count == 3


# ---------------------------------------------------------------------------
# load_mock_patterns
# ---------------------------------------------------------------------------

class TestLoadMockPatterns:
    def test_calls_ingest_mock_patterns(self, ti):
        ti.load_mock_patterns()
        ti.ingester.ingest_mock_patterns.assert_called_once()

    def test_syncs_when_new_patterns_ingested(self, ti):
        ti.ingester.ingest_mock_patterns.return_value = _make_ingestion_result(new=4)
        ti.ingester.get_patterns.return_value = [_make_pattern()]
        ti.load_mock_patterns()
        ti.vector_store.add_patterns.assert_called()

    def test_no_vector_sync_when_zero_new(self, ti):
        ti.ingester.ingest_mock_patterns.return_value = _make_ingestion_result(new=0)
        ti.load_mock_patterns()
        ti.vector_store.add_patterns.assert_not_called()

    def test_returns_ingestion_result(self, ti):
        mock_result = _make_ingestion_result()
        ti.ingester.ingest_mock_patterns.return_value = mock_result
        result = ti.load_mock_patterns()
        assert result is mock_result


# ---------------------------------------------------------------------------
# update_patterns
# ---------------------------------------------------------------------------

class TestUpdatePatterns:
    def test_runs_full_cycle_and_returns_updated(self, ti):
        ti.client.fetch_all_patterns.return_value = [_make_pattern()]
        result = ti.update_patterns(force=True)
        ti.client.fetch_all_patterns.assert_called_once()
        ti.ingester.ingest.assert_called_once()
        ti.ingester.prune.assert_called_once()
        assert result["status"] == "updated"

    def test_skips_when_interval_not_elapsed(self, ti):
        ti.last_update = datetime.now() - timedelta(seconds=100)
        ti.update_interval = 3600
        result = ti.update_patterns(force=False)
        assert result["status"] == "skipped"
        ti.client.fetch_all_patterns.assert_not_called()

    def test_force_bypasses_interval(self, ti):
        ti.last_update = datetime.now() - timedelta(seconds=10)
        ti.update_interval = 3600
        ti.client.fetch_all_patterns.return_value = []
        result = ti.update_patterns(force=True)
        assert result["status"] == "updated"
        ti.client.fetch_all_patterns.assert_called_once()

    def test_updates_last_update_timestamp(self, ti):
        ti.client.fetch_all_patterns.return_value = []
        before = datetime.now()
        ti.update_patterns(force=True)
        assert ti.last_update is not None
        assert ti.last_update >= before

    def test_returns_error_status_on_exception(self, ti):
        ti.client.fetch_all_patterns.side_effect = RuntimeError("network failure")
        result = ti.update_patterns(force=True)
        assert result["status"] == "error"
        assert "network failure" in result["error"]

    def test_error_does_not_update_last_update(self, ti):
        ti.client.fetch_all_patterns.side_effect = RuntimeError("fail")
        ti.update_patterns(force=True)
        assert ti.last_update is None

    def test_result_contains_all_expected_keys(self, ti):
        ti.client.fetch_all_patterns.return_value = []
        result = ti.update_patterns(force=True)
        for key in (
            "status", "patterns_fetched", "patterns_new", "patterns_updated",
            "patterns_pruned", "vectors_synced", "duration_ms",
            "last_update", "next_update",
        ):
            assert key in result, f"Missing key: {key}"

    def test_skipped_result_contains_timing_keys(self, ti):
        ti.last_update = datetime.now()
        result = ti.update_patterns(force=False)
        assert "last_update" in result
        assert "next_update" in result
        assert "reason" in result

    def test_runs_when_last_update_is_none(self, ti):
        ti.last_update = None
        ti.client.fetch_all_patterns.return_value = []
        result = ti.update_patterns(force=False)
        assert result["status"] == "updated"

    def test_duration_ms_in_result(self, ti):
        ti.client.fetch_all_patterns.return_value = []
        result = ti.update_patterns(force=True)
        assert isinstance(result["duration_ms"], float)
        assert result["duration_ms"] >= 0


# ---------------------------------------------------------------------------
# Pattern queries
# ---------------------------------------------------------------------------

class TestPatternQueries:
    def test_get_patterns_by_type_delegates(self, ti):
        patterns = [_make_pattern(threat_type="bypass")]
        ti.ingester.get_patterns.return_value = patterns
        result = ti.get_patterns_by_type("bypass")
        ti.ingester.get_patterns.assert_called_once_with(threat_type="bypass")
        assert result == patterns

    def test_get_high_severity_delegates_with_min_high(self, ti):
        patterns = [_make_pattern(severity="critical")]
        ti.ingester.get_patterns.return_value = patterns
        result = ti.get_high_severity_patterns()
        ti.ingester.get_patterns.assert_called_once_with(min_severity="high")
        assert result == patterns

    def test_search_similar_delegates_to_vector_store(self, ti):
        mock_results = [MagicMock()]
        ti.vector_store.search.return_value = mock_results
        result = ti.search_similar("ignore all instructions", top_k=3, threshold=0.8)
        ti.vector_store.search.assert_called_once_with(
            "ignore all instructions", top_k=3, threshold=0.8
        )
        assert result == mock_results

    def test_search_similar_uses_default_args(self, ti):
        ti.search_similar("query")
        ti.vector_store.search.assert_called_once_with("query", top_k=5, threshold=0.7)

    def test_search_similar_returns_empty_list_on_no_results(self, ti):
        ti.vector_store.search.return_value = []
        assert ti.search_similar("nothing") == []


# ---------------------------------------------------------------------------
# get_pattern_stats
# ---------------------------------------------------------------------------

class TestGetPatternStats:
    def test_includes_ingester_stats(self, ti):
        ti.ingester.get_stats.return_value = {
            "total": 10, "by_type": {"injection": 7}
        }
        stats = ti.get_pattern_stats()
        assert stats["total"] == 10
        assert stats["by_type"]["injection"] == 7

    def test_includes_vector_store_section(self, ti):
        ti.vector_store.pattern_count = 8
        ti.vector_store.enabled = True
        stats = ti.get_pattern_stats()
        assert stats["vector_store"]["indexed"] == 8
        assert stats["vector_store"]["enabled"] is True

    def test_last_update_isoformat_when_set(self, ti):
        ti.last_update = datetime(2026, 1, 1, 12, 0, 0)
        stats = ti.get_pattern_stats()
        assert "2026-01-01" in stats["last_update"]

    def test_last_update_none_when_never_run(self, ti):
        ti.last_update = None
        assert ti.get_pattern_stats()["last_update"] is None

    def test_update_interval_in_stats(self, ti):
        ti.update_interval = 1800
        assert ti.get_pattern_stats()["update_interval_sec"] == 1800


# ---------------------------------------------------------------------------
# export / import
# ---------------------------------------------------------------------------

class TestExportImport:
    def test_export_calls_ingester_persist(self, ti):
        ti.export_patterns("/tmp/patterns.json")
        ti.ingester.persist.assert_called_once_with("/tmp/patterns.json")

    def test_import_calls_ingester_load(self, ti):
        ti.ingester.pattern_count = 5
        ti.import_patterns("/tmp/patterns.json")
        ti.ingester.load.assert_called_once_with("/tmp/patterns.json")

    def test_import_syncs_vector_store_when_new_patterns(self, ti):
        ti.ingester.pattern_count = 2
        ti.ingester.get_patterns.return_value = [_make_pattern()]

        def _load_side_effect(path):
            ti.ingester.pattern_count = 5

        ti.ingester.load.side_effect = _load_side_effect
        ti.import_patterns("/tmp/patterns.json")
        ti.vector_store.add_patterns.assert_called()

    def test_import_no_vector_sync_when_count_unchanged(self, ti):
        ti.ingester.pattern_count = 5

        def _load_noop(path):
            pass  # count stays at 5

        ti.ingester.load.side_effect = _load_noop
        ti.import_patterns("/tmp/patterns.json")
        ti.vector_store.add_patterns.assert_not_called()
