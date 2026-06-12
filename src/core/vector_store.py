"""
Vector Store - FAISS-backed semantic similarity search for ThreatPatterns.

Pipeline position:
    PatternIngester -> VectorStore -> Shield Tier 2

Responsibilities:
    - Embed ThreatPattern descriptions with OpenAI text-embedding-3-small
    - Store and search vectors with FAISS IndexFlatIP (cosine similarity)
    - Persist index + metadata to disk for warm restarts
    - Expose search(query, top_k, threshold) -> List[SearchResult]

Feature flag: ENABLE_VECTOR_SEARCH env var (default: true).
Degrades gracefully to empty results when disabled or OpenAI key absent.
"""

import logging
import os
import pickle
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False
    faiss = None  # type: ignore

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    OpenAI = None  # type: ignore

from src.core.threat_intel import ThreatPattern

logger = logging.getLogger(__name__)

# Output dimension for text-embedding-3-small
EMBEDDING_DIM = 1536


@dataclass
class SearchResult:
    """Single similarity search result."""
    pattern: ThreatPattern
    score: float        # cosine similarity in [0, 1]
    pattern_id: str


class VectorStore:
    """
    FAISS-backed semantic similarity search over ThreatPatterns.

    Uses OpenAI text-embedding-3-small for dense vector embeddings and
    FAISS IndexFlatIP (inner product on L2-normalized vectors = cosine
    similarity) for nearest-neighbour search.

    Persists to two files under store_path/:
        index.faiss   — binary FAISS index
        metadata.pkl  — pattern dict and id-map

    Thread safety: single-threaded. Use external locking if shared.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Args:
            config keys:
                openai_api_key (str):        OpenAI key. Fallback: OPENAI_API_KEY env.
                embedding_model (str):       Default: text-embedding-3-small.
                store_path (str):            Persistence directory. Default: ./data/vector_store/
                enable_vector_search (bool): Feature flag. Fallback: ENABLE_VECTOR_SEARCH env.
                batch_size (int):            Embedding batch size. Default: 64.
        """
        self.config = config or {}

        env_flag = os.getenv("ENABLE_VECTOR_SEARCH", "true").lower()
        self.enabled: bool = self.config.get("enable_vector_search", env_flag != "false")

        self.openai_api_key: Optional[str] = (
            self.config.get("openai_api_key") or os.getenv("OPENAI_API_KEY")
        )
        self.embedding_model: str = self.config.get(
            "embedding_model",
            os.getenv("EMBEDDING_MODEL", "text-embedding-3-small"),
        )
        self.store_path = Path(self.config.get("store_path", "./data/vector_store"))
        self.batch_size: int = self.config.get("batch_size", 64)

        # Runtime state
        self._patterns: Dict[str, ThreatPattern] = {}  # pattern_id -> ThreatPattern
        self._id_map: List[str] = []                   # FAISS position  -> pattern_id
        self._index: Optional[Any] = None
        self._openai_client: Optional[Any] = None

        if self.enabled:
            self._init_faiss()
            self._init_openai()

        logger.info(
            "VectorStore initialized (enabled=%s, model=%s, store=%s)",
            self.enabled, self.embedding_model, self.store_path,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_patterns(self, patterns: List[ThreatPattern]) -> int:
        """
        Embed and index ThreatPatterns, skipping already-indexed IDs.

        Args:
            patterns: Patterns to embed and add.

        Returns:
            Number of patterns newly added (0 if disabled or all duplicates).
        """
        if not self.enabled or not patterns:
            return 0

        new_patterns = [p for p in patterns if p.pattern_id not in self._patterns]
        if not new_patterns:
            logger.debug("add_patterns: all %d patterns already indexed", len(patterns))
            return 0

        texts = [self._pattern_text(p) for p in new_patterns]
        try:
            vectors = self._embed_texts(texts)
        except Exception as exc:
            logger.error("Embedding failed for %d patterns: %s", len(new_patterns), exc)
            return 0

        faiss.normalize_L2(vectors)
        self._index.add(vectors)

        for p in new_patterns:
            self._patterns[p.pattern_id] = p
            self._id_map.append(p.pattern_id)

        logger.info(
            "Added %d patterns to vector store (total=%d)",
            len(new_patterns), len(self._id_map),
        )
        return len(new_patterns)

    def search(
        self,
        query: str,
        top_k: int = 5,
        threshold: float = 0.7,
    ) -> List[SearchResult]:
        """
        Semantic similarity search over indexed ThreatPatterns.

        Args:
            query:     Query text (e.g., suspicious user input or scraped content).
            top_k:     Maximum results to return.
            threshold: Minimum cosine similarity score (default 0.7).

        Returns:
            SearchResult list sorted by score descending. Empty if disabled or error.
        """
        if not self.enabled or self._index is None or self._index.ntotal == 0:
            return []

        try:
            t_start = time.monotonic()

            query_vec = self._embed_texts([query])
            faiss.normalize_L2(query_vec)

            k = min(top_k, self._index.ntotal)
            scores_arr, indices_arr = self._index.search(query_vec, k)

            results: List[SearchResult] = []
            for score, idx in zip(scores_arr[0], indices_arr[0]):
                if idx < 0 or idx >= len(self._id_map):
                    continue
                if float(score) < threshold:
                    continue
                pid = self._id_map[idx]
                pattern = self._patterns.get(pid)
                if pattern:
                    results.append(
                        SearchResult(pattern=pattern, score=float(score), pattern_id=pid)
                    )

            elapsed_ms = (time.monotonic() - t_start) * 1000
            logger.debug(
                "Vector search: %d results above threshold=%.2f (%.1f ms)",
                len(results), threshold, elapsed_ms,
            )
            return results

        except Exception as exc:
            logger.error("Vector search failed: %s", exc)
            return []

    def rebuild(self, patterns: List[ThreatPattern]) -> int:
        """
        Clear the index and re-add the supplied pattern list from scratch.

        Use after bulk pruning or large pattern rotations.

        Args:
            patterns: Full replacement pattern list.

        Returns:
            Number of patterns indexed.
        """
        if not self.enabled:
            return 0

        prev = len(self._patterns)
        self._patterns.clear()
        self._id_map.clear()
        self._index = self._create_index()
        logger.info("Rebuilding vector index (cleared %d patterns)", prev)
        return self.add_patterns(patterns)

    def remove_patterns(self, pattern_ids: List[str]) -> int:
        """
        Remove patterns by ID and rebuild the FAISS index from remaining data.

        FAISS IndexFlatIP has no native remove; rebuilding is the safe path
        for the small pattern counts expected here.

        Args:
            pattern_ids: IDs to remove.

        Returns:
            Number of patterns actually removed.
        """
        if not self.enabled:
            return 0

        to_remove = set(pattern_ids)
        before = len(self._patterns)
        remaining = [p for pid, p in self._patterns.items() if pid not in to_remove]
        removed = before - len(remaining)

        if removed:
            self._patterns.clear()
            self._id_map.clear()
            self._index = self._create_index()
            self.add_patterns(remaining)
            logger.info(
                "Removed %d patterns, rebuilt index (%d remaining)",
                removed, len(remaining),
            )

        return removed

    def persist(self, dirpath: Optional[str] = None) -> None:
        """
        Save FAISS index and metadata to disk.

        Writes:
            <dirpath>/index.faiss
            <dirpath>/metadata.pkl

        Args:
            dirpath: Override the default store_path directory.
        """
        if not self.enabled or self._index is None:
            return

        target = Path(dirpath) if dirpath else self.store_path
        target.mkdir(parents=True, exist_ok=True)

        faiss.write_index(self._index, str(target / "index.faiss"))
        with (target / "metadata.pkl").open("wb") as fh:
            pickle.dump({"patterns": self._patterns, "id_map": self._id_map}, fh)

        logger.info(
            "Persisted vector store: %d vectors -> %s", self._index.ntotal, target
        )

    def load(self, dirpath: Optional[str] = None) -> int:
        """
        Load FAISS index and metadata from disk.

        Args:
            dirpath: Override the default store_path directory.

        Returns:
            Number of patterns loaded, or 0 if files not found.
        """
        if not self.enabled:
            return 0

        target = Path(dirpath) if dirpath else self.store_path
        index_path = target / "index.faiss"
        meta_path = target / "metadata.pkl"

        if not index_path.exists() or not meta_path.exists():
            logger.warning("Vector store files not found at %s", target)
            return 0

        try:
            self._index = faiss.read_index(str(index_path))
            with meta_path.open("rb") as fh:
                meta = pickle.load(fh)
            self._patterns = meta["patterns"]
            self._id_map = meta["id_map"]
            count = len(self._patterns)
            logger.info("Loaded vector store: %d patterns from %s", count, target)
            return count
        except Exception as exc:
            logger.error("Failed to load vector store: %s", exc)
            return 0

    def is_healthy(self) -> bool:
        """
        Verify the embedding backend is reachable.

        Returns:
            True if a probe embedding succeeds (or store is disabled).
        """
        if not self.enabled:
            return True
        if not self.openai_api_key:
            logger.warning("VectorStore health check: no OpenAI API key configured")
            return False
        try:
            self._embed_texts(["health check"])
            return True
        except Exception as exc:
            logger.error("VectorStore health check failed: %s", exc)
            return False

    @property
    def pattern_count(self) -> int:
        """Number of patterns currently indexed."""
        return len(self._patterns)

    @property
    def embedding_dimension(self) -> int:
        """Dimension of the embedding vectors (1536 for text-embedding-3-small)."""
        return EMBEDDING_DIM

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _init_faiss(self) -> None:
        if not FAISS_AVAILABLE:
            raise RuntimeError(
                "faiss-cpu is not installed. Run: pip install faiss-cpu==1.7.4"
            )
        self._index = self._create_index()

    def _init_openai(self) -> None:
        if not OPENAI_AVAILABLE:
            logger.warning(
                "openai package not installed; vector search disabled. "
                "Run: pip install openai==1.3.9"
            )
            self.enabled = False
            return
        if self.openai_api_key:
            self._openai_client = OpenAI(api_key=self.openai_api_key)
        else:
            logger.warning(
                "OPENAI_API_KEY not set; embedding calls will fail at query time"
            )

    def _create_index(self) -> Any:
        """Return a fresh FAISS IndexFlatIP for cosine similarity searches."""
        return faiss.IndexFlatIP(EMBEDDING_DIM)

    def _embed_texts(self, texts: List[str]) -> np.ndarray:
        """
        Embed texts via OpenAI API, batching to respect token limits.

        Args:
            texts: Strings to embed.

        Returns:
            float32 numpy array of shape (len(texts), EMBEDDING_DIM).

        Raises:
            RuntimeError: If the OpenAI client is not initialized.
        """
        if not self._openai_client:
            raise RuntimeError(
                "OpenAI client not initialized — check OPENAI_API_KEY"
            )

        all_embeddings: List[List[float]] = []
        for i in range(0, len(texts), self.batch_size):
            batch = texts[i : i + self.batch_size]
            response = self._openai_client.embeddings.create(
                model=self.embedding_model,
                input=batch,
            )
            all_embeddings.extend([item.embedding for item in response.data])

        return np.array(all_embeddings, dtype=np.float32)

    @staticmethod
    def _pattern_text(pattern: ThreatPattern) -> str:
        """Build the text to embed for a pattern — description + key metadata."""
        parts = [
            pattern.description,
            pattern.threat_type,
            pattern.severity,
        ]
        if pattern.pattern_regex:
            parts.append(pattern.pattern_regex)
        return " | ".join(p for p in parts if p)
