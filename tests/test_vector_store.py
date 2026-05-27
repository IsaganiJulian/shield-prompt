"""
Unit tests for VectorStore.

Uses mocked OpenAI embeddings and real FAISS so tests run without API keys
or network access. All embedding calls are intercepted at the client level
(vs._openai_client = mock), leaving FAISS arithmetic fully exercised.
"""

import pickle
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from src.core.threat_intel import ThreatPattern
from src.core.vector_store import EMBEDDING_DIM, SearchResult, VectorStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_pattern(
    pid: str = "pat_001",
    desc: str = "Ignore previous instructions",
    threat_type: str = "injection",
    severity: str = "high",
) -> ThreatPattern:
    now = datetime.now()
    return ThreatPattern(
        pattern_id=pid,
        description=desc,
        pattern_regex=r"(?i)(ignore.*instructions)",
        threat_type=threat_type,
        severity=severity,
        first_seen=now,
        last_updated=now,
        source="cve",
        references=[],
    )


def _unit_vector(seed: int) -> np.ndarray:
    """Deterministic L2-normalised float32 vector of shape (EMBEDDING_DIM,)."""
    rng = np.random.default_rng(seed)
    v = rng.standard_normal(EMBEDDING_DIM).astype(np.float32)
    return v / np.linalg.norm(v)


def _mock_client(*embeddings: np.ndarray) -> MagicMock:
    """
    Build a mock OpenAI client whose embeddings.create() returns the
    supplied vectors in order, regardless of the input text.
    """
    mock = MagicMock()
    items = []
    for emb in embeddings:
        item = MagicMock()
        item.embedding = emb.tolist()
        items.append(item)
    mock.embeddings.create.return_value = MagicMock(data=items)
    return mock


def _store_with_client(*embeddings: np.ndarray) -> VectorStore:
    """Create an enabled VectorStore and inject a mock client."""
    with patch("src.core.vector_store.OpenAI") as MockOpenAI:
        MockOpenAI.return_value = MagicMock()
        vs = VectorStore(config={"openai_api_key": "test-key", "enable_vector_search": True})
    vs._openai_client = _mock_client(*embeddings)
    return vs


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

class TestInit:
    def test_enabled_by_default_when_key_present(self):
        with patch("src.core.vector_store.OpenAI"):
            vs = VectorStore(config={"openai_api_key": "key", "enable_vector_search": True})
        assert vs.enabled is True

    def test_disabled_via_config(self):
        vs = VectorStore(config={"enable_vector_search": False})
        assert vs.enabled is False

    def test_embedding_dimension_constant(self):
        vs = _store_with_client()
        assert vs.embedding_dimension == EMBEDDING_DIM

    def test_initial_pattern_count_zero(self):
        vs = _store_with_client()
        assert vs.pattern_count == 0

    def test_index_created_on_init(self):
        vs = _store_with_client()
        assert vs._index is not None
        assert vs._index.ntotal == 0


# ---------------------------------------------------------------------------
# add_patterns
# ---------------------------------------------------------------------------

class TestAddPatterns:
    def test_add_single_pattern(self):
        vs = _store_with_client(_unit_vector(1))
        added = vs.add_patterns([_make_pattern()])
        assert added == 1
        assert vs.pattern_count == 1
        assert vs._index.ntotal == 1

    def test_duplicate_pattern_skipped(self):
        vs = _store_with_client(_unit_vector(1))
        p = _make_pattern()
        vs.add_patterns([p])
        # Second call for same ID should be a no-op
        vs.add_patterns([p])
        assert vs.pattern_count == 1

    def test_add_multiple_patterns(self):
        patterns = [_make_pattern(f"p{i}") for i in range(5)]
        vs = _store_with_client(*[_unit_vector(i) for i in range(5)])
        added = vs.add_patterns(patterns)
        assert added == 5
        assert vs.pattern_count == 5

    def test_add_returns_zero_when_disabled(self):
        vs = VectorStore(config={"enable_vector_search": False})
        assert vs.add_patterns([_make_pattern()]) == 0

    def test_add_returns_zero_on_embedding_error(self):
        vs = _store_with_client()
        vs._openai_client.embeddings.create.side_effect = RuntimeError("API error")
        assert vs.add_patterns([_make_pattern()]) == 0
        assert vs.pattern_count == 0

    def test_id_map_matches_pattern_store(self):
        patterns = [_make_pattern(f"x{i}") for i in range(3)]
        vs = _store_with_client(*[_unit_vector(i) for i in range(3)])
        vs.add_patterns(patterns)
        assert len(vs._id_map) == vs.pattern_count == 3
        assert set(vs._id_map) == set(vs._patterns.keys())


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------

class TestSearch:
    def test_exact_match_returns_high_score(self):
        emb = _unit_vector(7)
        vs = _store_with_client(emb)
        vs.add_patterns([_make_pattern()])
        # Query with the same vector → cosine ≈ 1.0
        vs._openai_client = _mock_client(emb)
        results = vs.search("ignore previous instructions", threshold=0.5)
        assert len(results) == 1
        assert results[0].score >= 0.5
        assert isinstance(results[0], SearchResult)
        assert results[0].pattern_id == "pat_001"
        assert isinstance(results[0].pattern, ThreatPattern)

    def test_below_threshold_filtered_out(self):
        emb_stored = _unit_vector(7)
        vs = _store_with_client(emb_stored)
        vs.add_patterns([_make_pattern()])
        # Very different query vector → low cosine similarity
        vs._openai_client = _mock_client(_unit_vector(9999))
        results = vs.search("unrelated query", threshold=0.99)
        assert all(r.score >= 0.99 for r in results)

    def test_returns_empty_on_empty_index(self):
        vs = _store_with_client(_unit_vector(0))
        results = vs.search("test query")
        assert results == []

    def test_returns_empty_when_disabled(self):
        vs = VectorStore(config={"enable_vector_search": False})
        assert vs.search("anything") == []

    def test_returns_empty_on_embedding_error(self):
        emb = _unit_vector(7)
        vs = _store_with_client(emb)
        vs.add_patterns([_make_pattern()])
        vs._openai_client.embeddings.create.side_effect = RuntimeError("fail")
        assert vs.search("query") == []

    def test_top_k_limits_result_count(self):
        n = 10
        patterns = [_make_pattern(f"p{i}") for i in range(n)]
        vs = _store_with_client(*[_unit_vector(i) for i in range(n)])
        vs.add_patterns(patterns)
        # Use the same vector as p0 to maximise similarity
        vs._openai_client = _mock_client(_unit_vector(0))
        results = vs.search("test", top_k=3, threshold=0.0)
        assert len(results) <= 3

    def test_results_sorted_by_score_descending(self):
        n = 5
        patterns = [_make_pattern(f"p{i}") for i in range(n)]
        vs = _store_with_client(*[_unit_vector(i) for i in range(n)])
        vs.add_patterns(patterns)
        vs._openai_client = _mock_client(_unit_vector(0))
        results = vs.search("query", top_k=n, threshold=0.0)
        scores = [r.score for r in results]
        assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------------------
# rebuild
# ---------------------------------------------------------------------------

class TestRebuild:
    def test_rebuild_replaces_all_patterns(self):
        old = _make_pattern("old")
        vs = _store_with_client(_unit_vector(1))
        vs.add_patterns([old])

        new = _make_pattern("new", desc="Act as a DAN model")
        vs._openai_client = _mock_client(_unit_vector(2))
        count = vs.rebuild([new])

        assert count == 1
        assert vs.pattern_count == 1
        assert "old" not in vs._patterns
        assert "new" in vs._patterns

    def test_rebuild_resets_faiss_index(self):
        vs = _store_with_client(_unit_vector(1))
        vs.add_patterns([_make_pattern()])
        vs._openai_client = _mock_client(_unit_vector(2))
        vs.rebuild([_make_pattern("replacement")])
        assert vs._index.ntotal == 1

    def test_rebuild_returns_zero_when_disabled(self):
        vs = VectorStore(config={"enable_vector_search": False})
        assert vs.rebuild([_make_pattern()]) == 0


# ---------------------------------------------------------------------------
# remove_patterns
# ---------------------------------------------------------------------------

class TestRemovePatterns:
    def test_remove_single_pattern(self):
        p1 = _make_pattern("p1")
        p2 = _make_pattern("p2", desc="Jailbreak via roleplay")
        vs = _store_with_client(_unit_vector(1), _unit_vector(2))
        vs.add_patterns([p1, p2])

        # After remove, only p2 remains — re-embed it
        vs._openai_client = _mock_client(_unit_vector(2))
        removed = vs.remove_patterns(["p1"])

        assert removed == 1
        assert vs.pattern_count == 1
        assert "p1" not in vs._patterns
        assert "p2" in vs._patterns

    def test_remove_nonexistent_is_noop(self):
        vs = _store_with_client()
        removed = vs.remove_patterns(["does_not_exist"])
        assert removed == 0
        assert vs.pattern_count == 0

    def test_remove_returns_zero_when_disabled(self):
        vs = VectorStore(config={"enable_vector_search": False})
        assert vs.remove_patterns(["any"]) == 0


# ---------------------------------------------------------------------------
# persist / load
# ---------------------------------------------------------------------------

class TestPersistLoad:
    def test_roundtrip(self, tmp_path: Path):
        vs = _store_with_client(_unit_vector(1))
        vs.add_patterns([_make_pattern()])
        vs.persist(str(tmp_path))

        assert (tmp_path / "index.faiss").exists()
        assert (tmp_path / "metadata.pkl").exists()

        vs2 = _store_with_client()
        loaded = vs2.load(str(tmp_path))

        assert loaded == 1
        assert "pat_001" in vs2._patterns
        assert vs2._index.ntotal == 1

    def test_persist_creates_directory(self, tmp_path: Path):
        new_dir = tmp_path / "sub" / "deep"
        vs = _store_with_client(_unit_vector(1))
        vs.add_patterns([_make_pattern()])
        vs.persist(str(new_dir))
        assert new_dir.exists()

    def test_load_missing_files_returns_zero(self, tmp_path: Path):
        vs = _store_with_client()
        empty = tmp_path / "empty"
        empty.mkdir()
        assert vs.load(str(empty)) == 0

    def test_persist_noop_when_disabled(self, tmp_path: Path):
        vs = VectorStore(config={"enable_vector_search": False})
        vs.persist(str(tmp_path))
        assert not (tmp_path / "index.faiss").exists()

    def test_load_noop_when_disabled(self, tmp_path: Path):
        vs = VectorStore(config={"enable_vector_search": False})
        assert vs.load(str(tmp_path)) == 0

    def test_metadata_integrity_after_roundtrip(self, tmp_path: Path):
        p = _make_pattern(desc="Unique description for this test")
        vs = _store_with_client(_unit_vector(42))
        vs.add_patterns([p])
        vs.persist(str(tmp_path))

        vs2 = _store_with_client()
        vs2.load(str(tmp_path))
        loaded_pattern = vs2._patterns["pat_001"]
        assert loaded_pattern.description == p.description
        assert loaded_pattern.severity == p.severity


# ---------------------------------------------------------------------------
# is_healthy
# ---------------------------------------------------------------------------

class TestIsHealthy:
    def test_healthy_with_working_client(self):
        vs = _store_with_client(_unit_vector(0))
        assert vs.is_healthy() is True

    def test_unhealthy_without_api_key(self):
        vs = _store_with_client()
        vs.openai_api_key = None
        assert vs.is_healthy() is False

    def test_unhealthy_when_embedding_raises(self):
        vs = _store_with_client()
        vs.openai_api_key = "key"
        vs._openai_client.embeddings.create.side_effect = RuntimeError("no network")
        assert vs.is_healthy() is False

    def test_disabled_store_is_healthy(self):
        vs = VectorStore(config={"enable_vector_search": False})
        assert vs.is_healthy() is True


# ---------------------------------------------------------------------------
# _pattern_text
# ---------------------------------------------------------------------------

class TestPatternText:
    def test_includes_description_type_severity(self):
        p = _make_pattern(desc="DAN jailbreak", threat_type="override", severity="critical")
        text = VectorStore._pattern_text(p)
        assert "DAN jailbreak" in text
        assert "override" in text
        assert "critical" in text

    def test_includes_regex(self):
        p = _make_pattern()
        text = VectorStore._pattern_text(p)
        assert p.pattern_regex in text

    def test_parts_separated_by_pipe(self):
        p = _make_pattern()
        text = VectorStore._pattern_text(p)
        assert " | " in text
