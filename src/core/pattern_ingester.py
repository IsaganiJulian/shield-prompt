"""
Pattern Ingester - Normalizes and persists ThreatPatterns.

Pipeline position:
    dataset / mock seed -> PatternIngester -> VectorStore -> Shield Tier 2

Responsibilities:
    - Validate and normalize incoming ThreatPatterns (compile regex, strip unsafe chars)
    - Merge duplicate patterns (update last_updated, escalate severity, union references)
    - Persist pattern store to / restore from JSON file cache
    - Prune patterns beyond retention window (default 90 days)
    - Provide filtered iteration for downstream consumers (VectorStore, Shield Tier 2)
"""

import json
import logging
import re
import time
from dataclasses import asdict, dataclass, field, replace as dc_replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.core.threat_intel import ThreatPattern

logger = logging.getLogger(__name__)

SEVERITY_RANK: Dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Built-in mock patterns for offline / test use
MOCK_PATTERNS: List[Dict[str, Any]] = [
    {
        "pattern_id": "mock_cve_001",
        "description": "Direct prompt injection via system prompt override",
        "pattern_regex": r"(?i)(ignore\s+(previous|prior|all)\s+instructions?)",
        "threat_type": "injection",
        "severity": "high",
        "source": "cve",
        "references": ["https://nvd.nist.gov/vuln/mock-001"],
    },
    {
        "pattern_id": "mock_github_001",
        "description": "Jailbreak via role-play persona adoption",
        "pattern_regex": r"(?i)(act\s+as|pretend\s+you\s+are|you\s+are\s+now)",
        "threat_type": "override",
        "severity": "medium",
        "source": "github",
        "references": ["https://github.com/mock/jailbreak-poc"],
    },
    {
        "pattern_id": "mock_blog_001",
        "description": "Data exfiltration via indirect prompt injection in scraped content",
        "pattern_regex": r"(?i)(exfiltrate|send\s+to\s+http|leak\s+system\s+prompt)",
        "threat_type": "exfiltration",
        "severity": "critical",
        "source": "blog",
        "references": ["https://security.example.com/indirect-injection"],
    },
    {
        "pattern_id": "mock_cve_002",
        "description": "Bypass via encoding obfuscation",
        "pattern_regex": r"(?i)(base64|url.?encod|unicode\s+escape)",
        "threat_type": "bypass",
        "severity": "high",
        "source": "cve",
        "references": ["https://nvd.nist.gov/vuln/mock-002"],
    },
]


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _pattern_to_dict(pattern: ThreatPattern) -> Dict[str, Any]:
    """Serialize ThreatPattern to JSON-safe dict."""
    d = asdict(pattern)
    d["first_seen"] = pattern.first_seen.isoformat()
    d["last_updated"] = pattern.last_updated.isoformat()
    return d


def _dict_to_pattern(d: Dict[str, Any]) -> ThreatPattern:
    """Deserialize ThreatPattern from dict."""
    return ThreatPattern(
        pattern_id=d["pattern_id"],
        description=d["description"],
        pattern_regex=d["pattern_regex"],
        threat_type=d["threat_type"],
        severity=d["severity"],
        first_seen=datetime.fromisoformat(d["first_seen"]),
        last_updated=datetime.fromisoformat(d["last_updated"]),
        source=d["source"],
        references=d.get("references", []),
    )


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class IngestionResult:
    """Metrics captured during a single ingestion run."""
    total_received: int
    new_patterns: int
    updated_patterns: int
    rejected_patterns: int
    errors: List[str]
    duration_ms: float
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def success_rate(self) -> float:
        """Fraction of received patterns that were accepted."""
        if self.total_received == 0:
            return 1.0
        return (self.new_patterns + self.updated_patterns) / self.total_received


# ---------------------------------------------------------------------------
# PatternIngester
# ---------------------------------------------------------------------------

class PatternIngester:
    """
    Normalizes, deduplicates, and persists ThreatPatterns from a dataset or seed.

    Thread safety: single-threaded. Use external locking if shared.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Args:
            config: Optional keys —
                store_path (str): JSON cache path.
                    Default: ./data/patterns/pattern_store.json
                retention_days (int): Prune patterns older than N days. Default: 90
                min_severity (str): Reject patterns below this level. Default: "low"
        """
        self.config = config or {}
        self.store_path = Path(
            self.config.get("store_path", "./data/patterns/pattern_store.json")
        )
        self.retention_days: int = self.config.get("retention_days", 90)
        self.min_severity: str = self.config.get("min_severity", "low")
        self._patterns: Dict[str, ThreatPattern] = {}
        logger.info("PatternIngester initialized (store=%s)", self.store_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest(self, patterns: List[ThreatPattern]) -> IngestionResult:
        """
        Normalize, validate, deduplicate, and store a batch of patterns.

        Args:
            patterns: Raw ThreatPattern list (e.g., from a dataset or mock seed)

        Returns:
            IngestionResult with counts and error details
        """
        t_start = time.monotonic()
        new_count = updated_count = rejected_count = 0
        errors: List[str] = []

        for raw in patterns:
            try:
                normalized = self._normalize(raw)
                if normalized is None:
                    rejected_count += 1
                    continue
                if normalized.pattern_id in self._patterns:
                    self._patterns[normalized.pattern_id] = self._merge(
                        self._patterns[normalized.pattern_id], normalized
                    )
                    updated_count += 1
                else:
                    self._patterns[normalized.pattern_id] = normalized
                    new_count += 1
            except Exception as exc:
                errors.append(f"{getattr(raw, 'pattern_id', '?')}: {exc}")
                rejected_count += 1
                logger.warning("Ingestion error for %s: %s", getattr(raw, "pattern_id", "?"), exc)

        duration_ms = (time.monotonic() - t_start) * 1000
        result = IngestionResult(
            total_received=len(patterns),
            new_patterns=new_count,
            updated_patterns=updated_count,
            rejected_patterns=rejected_count,
            errors=errors,
            duration_ms=duration_ms,
        )
        logger.info(
            "Ingested %d patterns: %d new, %d updated, %d rejected (%.1f ms)",
            len(patterns), new_count, updated_count, rejected_count, duration_ms,
        )
        return result

    def ingest_mock_patterns(self) -> IngestionResult:
        """Ingest built-in mock patterns for offline or CI use."""
        now = datetime.now()
        patterns = [
            ThreatPattern(
                pattern_id=m["pattern_id"],
                description=m["description"],
                pattern_regex=m["pattern_regex"],
                threat_type=m["threat_type"],
                severity=m["severity"],
                first_seen=now,
                last_updated=now,
                source=m["source"],
                references=m.get("references", []),
            )
            for m in MOCK_PATTERNS
        ]
        return self.ingest(patterns)

    def get_patterns(
        self,
        threat_type: Optional[str] = None,
        min_severity: Optional[str] = None,
        max_age_days: Optional[int] = None,
        source: Optional[str] = None,
    ) -> List[ThreatPattern]:
        """
        Return patterns filtered by optional criteria.

        Args:
            threat_type: "injection", "bypass", "exfiltration", "override"
            min_severity: Minimum severity level ("low", "medium", "high", "critical")
            max_age_days: Exclude patterns not updated within this many days
            source: Filter by source ("cve", "github", "blog")

        Returns:
            Filtered list of ThreatPattern objects, sorted newest-first
        """
        effective_min = min_severity if min_severity is not None else self.min_severity
        min_rank = SEVERITY_RANK.get(effective_min, 0)
        cutoff = (
            datetime.now() - timedelta(days=max_age_days)
            if max_age_days is not None
            else None
        )

        result = []
        for p in self._patterns.values():
            if threat_type and p.threat_type != threat_type:
                continue
            if SEVERITY_RANK.get(p.severity, 0) < min_rank:
                continue
            if cutoff and p.last_updated < cutoff:
                continue
            if source and p.source != source:
                continue
            result.append(p)

        result.sort(key=lambda p: p.last_updated, reverse=True)
        return result

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregate statistics about the current pattern store."""
        by_type: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        by_source: Dict[str, int] = {}
        dates: List[datetime] = []

        for p in self._patterns.values():
            by_type[p.threat_type] = by_type.get(p.threat_type, 0) + 1
            by_severity[p.severity] = by_severity.get(p.severity, 0) + 1
            by_source[p.source] = by_source.get(p.source, 0) + 1
            dates.append(p.last_updated)

        return {
            "total": len(self._patterns),
            "by_type": by_type,
            "by_severity": by_severity,
            "by_source": by_source,
            "oldest_update": min(dates).isoformat() if dates else None,
            "newest_update": max(dates).isoformat() if dates else None,
        }

    def persist(self, filepath: Optional[str] = None) -> None:
        """
        Serialize the in-memory pattern store to a JSON file.

        Args:
            filepath: Override the default store_path
        """
        target = Path(filepath) if filepath else self.store_path
        target.parent.mkdir(parents=True, exist_ok=True)
        data = {pid: _pattern_to_dict(p) for pid, p in self._patterns.items()}
        with target.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        logger.info("Persisted %d patterns to %s", len(data), target)

    def load(self, filepath: Optional[str] = None) -> int:
        """
        Load patterns from a JSON file, merging with the in-memory store.

        Args:
            filepath: Override the default store_path

        Returns:
            Number of patterns loaded (new or merged)
        """
        target = Path(filepath) if filepath else self.store_path
        if not target.exists():
            logger.warning("Pattern store file not found: %s", target)
            return 0

        with target.open("r", encoding="utf-8") as fh:
            raw_data = json.load(fh)

        loaded = 0
        for pid, d in raw_data.items():
            try:
                pattern = _dict_to_pattern(d)
                if pid not in self._patterns:
                    self._patterns[pid] = pattern
                else:
                    self._patterns[pid] = self._merge(self._patterns[pid], pattern)
                loaded += 1
            except Exception as exc:
                logger.warning("Failed to load pattern %s: %s", pid, exc)

        logger.info("Loaded %d patterns from %s", loaded, target)
        return loaded

    def prune(self, retention_days: Optional[int] = None) -> int:
        """
        Remove patterns whose last_updated is older than the retention window.

        Args:
            retention_days: Override the config retention_days

        Returns:
            Number of patterns removed
        """
        days = retention_days if retention_days is not None else self.retention_days
        cutoff = datetime.now() - timedelta(days=days)
        stale = [
            pid for pid, p in self._patterns.items()
            if p.last_updated < cutoff
        ]
        for pid in stale:
            del self._patterns[pid]
        if stale:
            logger.info(
                "Pruned %d stale patterns (cutoff=%s)", len(stale), cutoff.date()
            )
        return len(stale)

    @property
    def pattern_count(self) -> int:
        """Current number of patterns in the store."""
        return len(self._patterns)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _normalize(self, pattern: ThreatPattern) -> Optional[ThreatPattern]:
        """
        Validate and normalize a single pattern.

        Rejects patterns below min_severity.
        Falls back to a generic regex when the supplied one is invalid.
        Truncates description to 500 characters.

        Returns:
            Normalized ThreatPattern, or None if rejected.
        """
        if SEVERITY_RANK.get(pattern.severity, 0) < SEVERITY_RANK.get(self.min_severity, 0):
            logger.debug("Rejecting below-threshold pattern: %s", pattern.pattern_id)
            return None

        regex = pattern.pattern_regex.strip() if pattern.pattern_regex else ""
        if not regex or not self._validate_regex(regex):
            logger.warning(
                "Invalid regex in pattern %s — substituting fallback", pattern.pattern_id
            )
            regex = r"(?i)(prompt|injection|bypass|override)"

        return dc_replace(
            pattern,
            pattern_regex=regex,
            description=(pattern.description or "").strip()[:500],
        )

    def _validate_regex(self, regex_str: str) -> bool:
        """Return True if regex_str compiles without error."""
        try:
            re.compile(regex_str)
            return True
        except re.error:
            return False

    def _merge(
        self, existing: ThreatPattern, incoming: ThreatPattern
    ) -> ThreatPattern:
        """
        Merge incoming pattern into existing record:
          - Keep the earlier first_seen
          - Advance last_updated to the newer value
          - Escalate to the higher severity
          - Union and deduplicate references
        """
        merged_refs = list(dict.fromkeys(existing.references + incoming.references))
        higher_severity = (
            incoming.severity
            if SEVERITY_RANK.get(incoming.severity, 0)
               > SEVERITY_RANK.get(existing.severity, 0)
            else existing.severity
        )
        return dc_replace(
            existing,
            last_updated=max(existing.last_updated, incoming.last_updated),
            first_seen=min(existing.first_seen, incoming.first_seen),
            references=merged_refs,
            severity=higher_severity,
        )
