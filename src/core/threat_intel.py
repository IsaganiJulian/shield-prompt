"""
Threat Intelligence Module - Orchestration Layer

Wires BrightDataClient, PatternIngester, and VectorStore into a single
unified interface. Responsibilities:
    - Schedule and execute pattern update cycles (hourly by default)
    - Manage full pattern lifecycle: fetch → ingest → prune → vector sync
    - Expose pattern queries and semantic search to Shield Tier 2
    - Provide export/import for offline or CI use

Import hierarchy (no circular deps):
    threat_intel  ->  bright_data_client
    threat_intel  ->  pattern_ingester  ->  threat_intel.ThreatPattern
    threat_intel  ->  vector_store      ->  threat_intel.ThreatPattern
"""

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Core data model (kept here — imported by all sub-modules)
# ---------------------------------------------------------------------------

@dataclass
class ThreatPattern:
    """Threat pattern with metadata."""
    pattern_id: str
    description: str
    pattern_regex: str
    threat_type: str   # "injection", "bypass", "exfiltration", "override"
    severity: str      # "low", "medium", "high", "critical"
    first_seen: datetime
    last_updated: datetime
    source: str        # "cve", "github", "blog", "custom"
    references: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Orchestration layer
# ---------------------------------------------------------------------------

class ThreatIntelligence:
    """
    Unified threat intelligence orchestrator.

    Owns and coordinates:
        client   — BrightDataClient  (live scraping)
        ingester — PatternIngester   (normalise, deduplicate, persist)
        vector   — VectorStore       (semantic similarity search)

    Public surface used by Shield Tier 2:
        update_patterns()       — run a full fetch/ingest/sync cycle
        get_patterns_by_type()  — filtered pattern query
        get_high_severity_patterns()
        search_similar()        — semantic ANN search via VectorStore
        get_pattern_stats()     — aggregate metrics

    Backwards-compatible surface (retained from v1):
        add_pattern()           — register a single custom pattern
        patterns                — property returning current pattern dict
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Args:
            config keys (all optional, fall back to environment variables):
                bright_data_api_key / bright_data_username / bright_data_password
                openai_api_key
                embedding_model             (default: text-embedding-3-small)
                pattern_store_path          (default: ./data/patterns/pattern_store.json)
                vector_store_path           (default: ./data/vector_store/)
                enable_vector_search        (default: True)
                threat_intel_update_interval (seconds, default: 3600)
                retention_days              (default: 90)
                min_severity                (default: "low")
                limit_per_source            (default: 50)
                use_mock_patterns           (default: False)
        """
        from src.core.bright_data_client import BrightDataClient
        from src.core.pattern_ingester import PatternIngester
        from src.core.vector_store import VectorStore

        self.config = config or {}

        # ---------- sub-components ----------
        self.client = BrightDataClient({
            "bright_data_api_key":   self.config.get("bright_data_api_key"),
            "bright_data_username":  self.config.get("bright_data_username"),
            "bright_data_password":  self.config.get("bright_data_password"),
            "rate_limit_per_min":    self.config.get("rate_limit_per_min", 100),
            "request_timeout_sec":   self.config.get("request_timeout_sec", 30),
            "max_retries":           self.config.get("max_retries", 3),
        })

        self.ingester = PatternIngester({
            "store_path":      self.config.get(
                "pattern_store_path", "./data/patterns/pattern_store.json"
            ),
            "retention_days":  self.config.get("retention_days", 90),
            "min_severity":    self.config.get("min_severity", "low"),
        })

        self.vector_store = VectorStore({
            "openai_api_key":       self.config.get("openai_api_key"),
            "embedding_model":      self.config.get(
                "embedding_model", "text-embedding-3-small"
            ),
            "store_path":           self.config.get(
                "vector_store_path", "./data/vector_store/"
            ),
            "enable_vector_search": self.config.get("enable_vector_search", True),
        })

        # ---------- scheduling state ----------
        self.update_interval: int = self.config.get(
            "threat_intel_update_interval", 3600
        )
        self.limit_per_source: int = self.config.get("limit_per_source", 50)
        self.last_update: Optional[datetime] = None

        # ---------- persistence paths ----------
        self.pattern_store_path: str = self.config.get(
            "pattern_store_path", "./data/patterns/pattern_store.json"
        )
        self.vector_store_path: str = self.config.get(
            "vector_store_path", "./data/vector_store/"
        )
        import os as _os
        self.snapshot_dir: str = self.config.get(
            "snapshot_dir", _os.getenv("SNAPSHOT_DIR", "./snapshots")
        )

        # ---------- v1 compat ----------
        # Kept for callers that reference self.bright_data_api_key directly
        self.bright_data_api_key = self.config.get("bright_data_api_key")

        # Auto-load any persisted intel from disk so harvested patterns survive
        # restarts (and the eventual loss of Bright Data access). Guarded by file
        # existence — a clean checkout with no warm cache is a no-op.
        auto_load = self.config.get(
            "auto_load_on_init",
            _os.getenv("AUTO_LOAD_ON_INIT", "true").lower() != "false",
        )
        if auto_load:
            self._auto_load()

        if self.config.get("use_mock_patterns", False):
            self.load_mock_patterns()

        logger.info("ThreatIntelligence initialized")

    # ------------------------------------------------------------------
    # Offline / liveness
    # ------------------------------------------------------------------

    def is_live(self) -> bool:
        """
        True when Bright Data scraping is currently available.

        When this returns False the system is in *frozen* mode: it serves the
        last harvested snapshot and cannot fetch new intel. Detection still works
        (Tier 1 dynamic signatures need no keys; Tier 2 vector search needs only
        the OpenAI embedding key against the already-embedded snapshot).
        """
        try:
            return bool(self.client.is_healthy())
        except Exception:
            return False

    def _auto_load(self) -> None:
        """Load persisted pattern store + vector index from disk if present."""
        try:
            store = Path(self.pattern_store_path)
            if store.exists():
                loaded = self.ingester.load(str(store))
                logger.info("Auto-loaded %d patterns from warm cache %s", loaded, store)
            vindex = Path(self.vector_store_path) / "index.faiss"
            if vindex.exists():
                count = self.vector_store.load(self.vector_store_path)
                logger.info("Auto-loaded %d vectors from warm cache %s", count, vindex)
        except Exception as exc:
            logger.warning("Auto-load skipped (%s)", exc)

    # ------------------------------------------------------------------
    # Pattern lifecycle
    # ------------------------------------------------------------------

    def fetch_latest_threats(self) -> List[ThreatPattern]:
        """
        Fetch new patterns from all Bright Data sources, ingest them,
        and sync to the vector store.

        Returns:
            All patterns retrieved in this fetch (new + updated).
        """
        logger.info("Fetching latest threats from Bright Data")
        patterns = self.client.fetch_all_patterns(self.limit_per_source)
        if not patterns:
            logger.info("No patterns returned from Bright Data sources")
            return []

        result = self.ingester.ingest(patterns)
        logger.info(
            "Ingested %d patterns: %d new, %d updated, %d rejected",
            result.total_received, result.new_patterns,
            result.updated_patterns, result.rejected_patterns,
        )

        if result.new_patterns > 0 or result.updated_patterns > 0:
            self._sync_all_to_vector_store()

        return patterns

    def add_pattern(self, pattern: ThreatPattern) -> None:
        """
        Register a single custom ThreatPattern and index it immediately.

        Args:
            pattern: ThreatPattern to add.
        """
        self.ingester.ingest([pattern])
        self.vector_store.add_patterns([pattern])
        logger.info("Pattern registered: %s", pattern.pattern_id)

    def load_mock_patterns(self) -> Any:
        """
        Ingest built-in mock patterns (offline / CI use) and sync to vector store.

        Returns:
            IngestionResult from the mock ingestion.
        """
        result = self.ingester.ingest_mock_patterns()
        if result.new_patterns > 0:
            self._sync_all_to_vector_store()
        logger.info("Mock patterns loaded: %d new", result.new_patterns)
        return result

    def update_patterns(self, force: bool = False) -> Dict[str, Any]:
        """
        Run a full fetch → ingest → prune → vector-sync cycle.

        Skips the cycle if the update interval has not elapsed, unless
        ``force=True`` is passed.

        Args:
            force: Skip the interval check and update immediately.

        Returns:
            Dict with status, counts, timing, and next-update timestamp.
        """
        now = datetime.now()

        if not force and self.last_update is not None:
            elapsed = (now - self.last_update).total_seconds()
            if elapsed < self.update_interval:
                remaining = self.update_interval - elapsed
                logger.debug(
                    "update_patterns skipped (next update in %.0fs)", remaining
                )
                return {
                    "status": "skipped",
                    "reason": f"Next update in {remaining:.0f}s",
                    "last_update": self.last_update.isoformat(),
                    "next_update": (
                        self.last_update + timedelta(seconds=self.update_interval)
                    ).isoformat(),
                }

        t_start = time.monotonic()

        try:
            patterns = self.client.fetch_all_patterns(self.limit_per_source)
            ingest_result = self.ingester.ingest(patterns)
            # Only prune when a live fetch actually returned data. Otherwise an
            # offline run (no Bright Data access) would age-out and delete the
            # frozen intel we are trying to preserve.
            pruned = self.ingester.prune() if patterns else 0
            vectors_synced = self._sync_all_to_vector_store()
            # Durably persist after every cycle so harvested intel survives a
            # restart — and the eventual loss of Bright Data access.
            self._persist_all()
        except Exception as exc:
            logger.error("update_patterns failed: %s", exc)
            return {
                "status": "error",
                "error": str(exc),
                "last_update": self.last_update.isoformat() if self.last_update else None,
            }

        self.last_update = now
        duration_ms = (time.monotonic() - t_start) * 1000

        return {
            "status": "updated",
            "patterns_fetched":  ingest_result.total_received,
            "patterns_new":      ingest_result.new_patterns,
            "patterns_updated":  ingest_result.updated_patterns,
            "patterns_pruned":   pruned,
            "vectors_synced":    vectors_synced,
            "patterns_total":    self.ingester.pattern_count,
            "duration_ms":       round(duration_ms, 1),
            "last_update":       now.isoformat(),
            "next_update":       (
                now + timedelta(seconds=self.update_interval)
            ).isoformat(),
        }

    def _persist_all(self) -> None:
        """Write the pattern store JSON and the FAISS vector index to disk."""
        try:
            self.ingester.persist(self.pattern_store_path)
            self.vector_store.persist(self.vector_store_path)
        except Exception as exc:
            logger.warning("Persist failed: %s", exc)

    # ------------------------------------------------------------------
    # Snapshots — portable, frozen intel bundles (survive access loss)
    # ------------------------------------------------------------------

    def export_snapshot(self, label: Optional[str] = None) -> str:
        """
        Freeze the current intel into a timestamped, portable bundle.

        Writes ``<snapshot_dir>/<label>/`` containing:
            patterns.json   — human-readable pattern store (the durable asset)
            index.faiss      — FAISS embedding index (warm Tier 2 without re-embedding)
            metadata.pkl     — vector id-map + pattern metadata
            manifest.json    — counts, timestamp, source breakdown
        Also refreshes the ``<snapshot_dir>/latest`` pointer.

        These bundles are meant to be committed to git so the harvested intel
        outlives Bright Data access.

        Returns:
            Path to the written snapshot directory.
        """
        label = label or datetime.now().strftime("%Y%m%d_%H%M%S")
        target = Path(self.snapshot_dir) / label
        target.mkdir(parents=True, exist_ok=True)

        self.ingester.persist(str(target / "patterns.json"))
        try:
            self.vector_store.persist(str(target))
        except Exception as exc:
            logger.warning("Snapshot vector persist skipped: %s", exc)

        stats = self.get_pattern_stats()
        manifest = {
            "label": label,
            "created_at": datetime.now().isoformat(),
            "pattern_count": self.ingester.pattern_count,
            "vector_count": self.vector_store.pattern_count,
            "by_type": stats.get("by_type", {}),
            "by_severity": stats.get("by_severity", {}),
            "by_source": stats.get("by_source", {}),
            "schema_version": 1,
        }
        with (target / "manifest.json").open("w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)

        # Refresh the "latest" pointer (plain text — portable across platforms).
        latest_ptr = Path(self.snapshot_dir) / "latest.txt"
        latest_ptr.parent.mkdir(parents=True, exist_ok=True)
        latest_ptr.write_text(label, encoding="utf-8")

        logger.info(
            "Snapshot exported: %s (%d patterns, %d vectors)",
            target, manifest["pattern_count"], manifest["vector_count"],
        )
        return str(target)

    def load_snapshot(self, label: Optional[str] = None) -> Dict[str, Any]:
        """
        Restore a frozen snapshot bundle into the live stores.

        Args:
            label: Snapshot directory name. When None, reads ``latest.txt``.

        Returns:
            The snapshot manifest dict (empty dict if not found).
        """
        snap_root = Path(self.snapshot_dir)
        if label is None:
            ptr = snap_root / "latest.txt"
            if not ptr.exists():
                logger.warning("No snapshot 'latest' pointer at %s", ptr)
                return {}
            label = ptr.read_text(encoding="utf-8").strip()

        target = snap_root / label
        patterns_file = target / "patterns.json"
        if not patterns_file.exists():
            logger.warning("Snapshot patterns file not found: %s", patterns_file)
            return {}

        before = self.ingester.pattern_count
        self.ingester.load(str(patterns_file))
        if (target / "index.faiss").exists():
            self.vector_store.load(str(target))
        else:
            # No frozen index — rebuild embeddings if the embedding backend is up.
            self._sync_all_to_vector_store()

        manifest_file = target / "manifest.json"
        manifest: Dict[str, Any] = {}
        if manifest_file.exists():
            with manifest_file.open(encoding="utf-8") as fh:
                manifest = json.load(fh)

        logger.info(
            "Snapshot '%s' loaded (%d -> %d patterns)",
            label, before, self.ingester.pattern_count,
        )
        return manifest

    def list_snapshots(self) -> List[Dict[str, Any]]:
        """Return manifests of all available snapshots, newest-first."""
        snap_root = Path(self.snapshot_dir)
        if not snap_root.exists():
            return []
        manifests: List[Dict[str, Any]] = []
        for child in snap_root.iterdir():
            man = child / "manifest.json"
            if child.is_dir() and man.exists():
                try:
                    with man.open(encoding="utf-8") as fh:
                        manifests.append(json.load(fh))
                except Exception:
                    continue
        manifests.sort(key=lambda m: m.get("created_at", ""), reverse=True)
        return manifests

    # ------------------------------------------------------------------
    # Dynamic Tier 1 signatures — harvested regexes usable with ZERO keys
    # ------------------------------------------------------------------

    def get_dynamic_signatures(
        self,
        min_severity: str = "high",
        max_signatures: int = 200,
    ) -> Dict[str, str]:
        """
        Export harvested pattern regexes as Tier 1 lexical signatures.

        This is the key to surviving access loss: even with no API keys at all,
        ShieldDetector's Tier 1 can run these regexes deterministically. Only
        patterns at/above ``min_severity`` are promoted, the over-broad scraper
        fallback regex is excluded, and each regex is compile-checked.

        Returns:
            {signature_name: regex} ready to inject into ShieldDetector.
        """
        import re as _re

        _GENERIC_FALLBACKS = {
            r"(?i)(prompt|injection|bypass|override|jailbreak)",
            r"(?i)(prompt|injection|bypass|override)",
        }
        signatures: Dict[str, str] = {}
        for p in self.ingester.get_patterns(min_severity=min_severity):
            regex = (p.pattern_regex or "").strip()
            if not regex or regex in _GENERIC_FALLBACKS:
                continue
            try:
                _re.compile(regex)
            except _re.error:
                continue
            name = f"harvested_{p.threat_type}_{p.pattern_id[:12]}"
            signatures[name] = regex
            if len(signatures) >= max_signatures:
                break
        logger.info("Exported %d dynamic Tier 1 signatures", len(signatures))
        return signatures

    # ------------------------------------------------------------------
    # Pattern queries
    # ------------------------------------------------------------------

    def get_patterns_by_type(self, threat_type: str) -> List[ThreatPattern]:
        """
        Retrieve patterns filtered by threat type.

        Args:
            threat_type: "injection", "bypass", "exfiltration", or "override"

        Returns:
            Matching ThreatPattern list, newest-first.
        """
        return self.ingester.get_patterns(threat_type=threat_type)

    def get_high_severity_patterns(self) -> List[ThreatPattern]:
        """
        Retrieve high and critical severity patterns.

        Returns:
            ThreatPattern list with severity >= "high", newest-first.
        """
        return self.ingester.get_patterns(min_severity="high")

    def search_similar(
        self,
        query: str,
        top_k: int = 5,
        threshold: float = 0.7,
    ) -> List[Any]:
        """
        Semantic similarity search over indexed ThreatPatterns.

        Args:
            query:     Text to search against (e.g., suspicious input fragment).
            top_k:     Maximum results to return.
            threshold: Minimum cosine similarity score (0–1, default 0.7).

        Returns:
            List of SearchResult objects sorted by score descending.
            Empty when VectorStore is disabled or no key is configured.
        """
        return self.vector_store.search(query, top_k=top_k, threshold=threshold)

    def get_pattern_stats(self) -> Dict[str, Any]:
        """
        Return aggregate statistics from the ingester and vector store.

        Returns:
            Dict with counts by type/severity/source, timing, and vector info.
        """
        stats = self.ingester.get_stats()
        stats["vector_store"] = {
            "indexed":  self.vector_store.pattern_count,
            "enabled":  self.vector_store.enabled,
        }
        stats["last_update"] = (
            self.last_update.isoformat() if self.last_update else None
        )
        stats["update_interval_sec"] = self.update_interval
        return stats

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def export_patterns(self, filepath: str) -> None:
        """
        Serialize the current pattern store to a JSON file.

        Args:
            filepath: Destination path (created if missing).
        """
        self.ingester.persist(filepath)
        logger.info("Patterns exported to %s", filepath)

    def import_patterns(self, filepath: str) -> None:
        """
        Load patterns from a JSON file and sync the new ones to VectorStore.

        Args:
            filepath: Source path to read patterns from.
        """
        before = self.ingester.pattern_count
        self.ingester.load(filepath)
        after = self.ingester.pattern_count
        if after > before:
            self._sync_all_to_vector_store()
        logger.info(
            "Patterns imported from %s (%d added)", filepath, after - before
        )

    # ------------------------------------------------------------------
    # Backwards-compatible property
    # ------------------------------------------------------------------

    @property
    def patterns(self) -> Dict[str, ThreatPattern]:
        """Read-only view of the ingester's current pattern store."""
        return dict(self.ingester._patterns)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _sync_all_to_vector_store(self) -> int:
        """
        Push all current ingester patterns to the vector store.

        Only patterns not already indexed are embedded (VectorStore deduplicates).

        Returns:
            Number of patterns newly added to the vector store.
        """
        all_patterns = self.ingester.get_patterns()
        if not all_patterns:
            return 0
        added = self.vector_store.add_patterns(all_patterns)
        logger.debug(
            "_sync_all_to_vector_store: %d newly indexed (store total=%d)",
            added, self.vector_store.pattern_count,
        )
        return added
