"""
Bright Data Client - Live Threat Intelligence Fetcher

Scrapes prompt-injection and LLM-security intelligence from public sources
using Bright Data's Web Unlocker API, then converts scraped content into
ThreatPattern objects for downstream vector indexing and Tier 2 detection.

Sources:
  - NVD / MITRE  — CVE entries for AI injection vulnerabilities
  - GitHub        — prompt-injection exploit repos and security advisories
  - Security blogs — OWASP, learnprompting.org, promptingguide.ai, arxiv

All scraping goes through the Bright Data Web Unlocker zone (mcp_unlocker)
so the client never touches target sites directly.
"""

import hashlib
import logging
import os
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.core.threat_intel import ThreatPattern

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Curated URL lists per source category
# ---------------------------------------------------------------------------

_CVE_URLS: List[str] = [
    "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview"
    "&query=prompt+injection&search_type=all&isCpeNameSearch=false",
    "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview"
    "&query=LLM+injection&search_type=all&isCpeNameSearch=false",
    "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=prompt+injection",
]

_GITHUB_URLS: List[str] = [
    "https://github.com/topics/prompt-injection",
    "https://github.com/topics/jailbreak",
    "https://github.com/advisories?query=type%3Areviewed+llm",
]

_BLOG_URLS: List[str] = [
    "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    "https://learnprompting.org/docs/prompt_hacking/injection",
    "https://learnprompting.org/docs/prompt_hacking/jailbreaking",
    "https://arxiv.org/search/?query=prompt+injection&searchtype=all",
]

# ---------------------------------------------------------------------------
# Keyword → regex library for pattern extraction
# ---------------------------------------------------------------------------

_KEYWORD_REGEX_MAP: Dict[str, str] = {
    "system prompt":        r"(?i)(system\s+prompt|system\s+instructions)",
    "role play":            r"(?i)(role\s*play|roleplay|act\s+as|pretend\s+(?:you|to\s+be))",
    "ignore":               r"(?i)(ignore|disregard|forget|override).*?(previous|prior|earlier|all)",
    "jailbreak":            r"(?i)(jailbreak|jail\s*break|breaking.*out|circumvent)",
    "dan":                  r"(?i)\bdan\b.*?(mode|now|prompt)",
    "inject":               r"(?i)(inject|injection|malicious\s+input)",
    "exfiltrate":           r"(?i)(exfiltrat|leak.*data|steal.*creden)",
    "bypass":               r"(?i)(bypass|evad[ei]|circumvent|work.*around)",
    "unrestricted":         r"(?i)(unrestricted|no\s+filter|without\s+restriction|limitless)",
    "override":             r"(?i)(overrid[ei]|replac[ei].*instruction|new\s+instruction)",
}


class BrightDataClient:
    """
    Fetch live threat patterns from security sources via Bright Data Web Unlocker.

    Usage:
        client = BrightDataClient(config)
        patterns = client.fetch_all_patterns(limit_per_source=30)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.api_key: Optional[str] = (
            self.config.get("bright_data_api_key")
            or os.getenv("BRIGHT_DATA_API_KEY")
        )
        self._zone: str = (
            self.config.get("bright_data_zone", "")
            or os.getenv("BRIGHT_DATA_ZONE", "mcp_unlocker")
        )
        self.rate_limit_per_min: int = self.config.get("rate_limit_per_min", 100)
        self.request_timeout_sec: int = self.config.get("request_timeout_sec", 30)
        self.max_retries: int = self.config.get("max_retries", 3)

        self._request_count: int = 0
        self._window_start: float = time.time()
        self._last_request_time: float = 0.0

        if not self.api_key:
            logger.warning(
                "BrightDataClient: BRIGHT_DATA_API_KEY not set — "
                "live scraping disabled; fetch methods will return empty lists."
            )

        logger.info("BrightDataClient initialized (zone=%s)", self._zone)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_healthy(self) -> bool:
        """Return True if credentials are configured."""
        if self.api_key:
            logger.info("BrightDataClient health check: OK")
            return True
        logger.warning("BrightDataClient health check: missing API key")
        return False

    def fetch_cve_patterns(self, limit: int = 50) -> List[ThreatPattern]:
        """Scrape NVD and MITRE for prompt-injection CVE patterns."""
        logger.info("Fetching CVE patterns (limit=%d)", limit)
        scraped = self._scrape_multiple(_CVE_URLS)
        patterns: List[ThreatPattern] = []
        for url, html in scraped.items():
            patterns.extend(self._parse_cve_html(url, html))
            if len(patterns) >= limit:
                break
        logger.info("Fetched %d CVE patterns", len(patterns))
        return patterns[:limit]

    def fetch_github_exploits(self, limit: int = 50) -> List[ThreatPattern]:
        """Scrape GitHub for prompt-injection repos and security advisories."""
        logger.info("Fetching GitHub exploit patterns (limit=%d)", limit)
        scraped = self._scrape_multiple(_GITHUB_URLS)
        patterns: List[ThreatPattern] = []
        for url, html in scraped.items():
            patterns.extend(self._parse_github_html(url, html))
            if len(patterns) >= limit:
                break
        logger.info("Fetched %d GitHub exploit patterns", len(patterns))
        return patterns[:limit]

    def fetch_security_blogs(self, limit: int = 50) -> List[ThreatPattern]:
        """Scrape security blogs for prompt-injection techniques."""
        logger.info("Fetching security blog patterns (limit=%d)", limit)
        scraped = self._scrape_multiple(_BLOG_URLS)
        patterns: List[ThreatPattern] = []
        for url, html in scraped.items():
            patterns.extend(self._parse_blog_html(url, html))
            if len(patterns) >= limit:
                break
        logger.info("Fetched %d security blog patterns", len(patterns))
        return patterns[:limit]

    def fetch_all_patterns(self, limit_per_source: int = 50) -> List[ThreatPattern]:
        """Fetch and deduplicate patterns from all three source categories."""
        logger.info("Fetching patterns from all sources")
        all_patterns: List[ThreatPattern] = []

        all_patterns.extend(self.fetch_cve_patterns(limit_per_source))
        all_patterns.extend(self.fetch_github_exploits(limit_per_source))
        all_patterns.extend(self.fetch_security_blogs(limit_per_source))

        unique: Dict[str, ThreatPattern] = {}
        for p in all_patterns:
            unique.setdefault(p.pattern_id, p)

        deduped = list(unique.values())
        logger.info(
            "Fetched %d total patterns → deduplicated to %d",
            len(all_patterns), len(deduped),
        )
        return deduped

    # ------------------------------------------------------------------
    # Web Unlocker scraping
    # ------------------------------------------------------------------

    def _scrape_with_unlocker(self, url: str) -> str:
        """
        Scrape a single URL via Bright Data Web Unlocker.

        Returns raw HTML on success, empty string on failure or missing key.
        """
        if not self.api_key:
            return ""

        from brightdata.sync_client import SyncBrightDataClient

        for attempt in range(self.max_retries):
            try:
                self._apply_rate_limit()
                with SyncBrightDataClient(
                    token=self.api_key,
                    timeout=self.request_timeout_sec,
                    ssl_verify=False,
                ) as client:
                    result = client.scrape_url(url, zone=self._zone)
                    if result.success and result.data:
                        logger.debug(
                            "Scraped %s (%d bytes)", url, len(result.data)
                        )
                        return result.data
                    logger.warning(
                        "Scrape returned empty for %s (success=%s, error=%s)",
                        url, result.success, getattr(result, "error", None),
                    )
                    return ""
            except Exception as exc:
                if attempt < self.max_retries - 1:
                    backoff = 2 ** attempt
                    logger.warning(
                        "Retry %d/%d for %s (backoff %ds): %s",
                        attempt + 1, self.max_retries, url, backoff, exc,
                    )
                    time.sleep(backoff)
                else:
                    logger.error(
                        "Failed to scrape %s after %d retries: %s",
                        url, self.max_retries, exc,
                    )
        return ""

    def _scrape_multiple(self, urls: List[str]) -> Dict[str, str]:
        """
        Scrape a list of URLs via Web Unlocker in a single SDK session.

        Returns {url: html} for all URLs that returned content.
        """
        if not self.api_key:
            logger.warning(
                "BrightDataClient: no API key — skipping live scrape of %d URLs",
                len(urls),
            )
            return {}

        from brightdata.sync_client import SyncBrightDataClient

        results: Dict[str, str] = {}
        with SyncBrightDataClient(
            token=self.api_key,
            timeout=self.request_timeout_sec,
            ssl_verify=False,
        ) as client:
            for url in urls:
                for attempt in range(self.max_retries):
                    try:
                        self._apply_rate_limit()
                        result = client.scrape_url(url, zone=self._zone)
                        if result.success and result.data:
                            results[url] = result.data
                            logger.debug(
                                "Scraped %s (%d bytes)", url, len(result.data)
                            )
                        else:
                            logger.debug(
                                "Empty response from %s (success=%s)",
                                url, result.success,
                            )
                        break
                    except Exception as exc:
                        if attempt < self.max_retries - 1:
                            backoff = 2 ** attempt
                            logger.warning(
                                "Retry %d/%d for %s: %s",
                                attempt + 1, self.max_retries, url, exc,
                            )
                            time.sleep(backoff)
                        else:
                            logger.error("Giving up on %s: %s", url, exc)
        return results

    # ------------------------------------------------------------------
    # HTML parsers
    # ------------------------------------------------------------------

    def _extract_text_blocks(self, html: str, min_length: int = 60) -> List[str]:
        """Extract meaningful text blocks from HTML using BeautifulSoup."""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")
            blocks: List[str] = []
            for tag in soup.find_all(["p", "li", "h2", "h3", "td", "div"]):
                text = tag.get_text(separator=" ", strip=True)
                if len(text) >= min_length:
                    blocks.append(text)
            return blocks
        except Exception as exc:
            logger.warning("HTML text extraction failed: %s", exc)
            return []

    def _blocks_to_patterns(
        self,
        blocks: List[str],
        source: str,
        source_url: str,
        threat_type_hint: str = "injection",
    ) -> List[ThreatPattern]:
        """Convert text blocks that contain security keywords into ThreatPatterns."""
        patterns: List[ThreatPattern] = []
        now = datetime.now()

        for block in blocks:
            block_lower = block.lower()
            # Only keep blocks that mention relevant attack terminology
            security_terms = [
                "inject", "jailbreak", "bypass", "ignore", "override",
                "prompt", "llm", "exfiltrat", "unrestricted", "dan",
                "malicious", "adversarial", "attack", "exploit",
            ]
            if not any(term in block_lower for term in security_terms):
                continue

            truncated = block[:200].strip()
            pattern_regex = self._extract_regex_from_text(block)
            threat_type = self._classify_threat(block)
            severity = self._infer_severity(block)

            pattern = ThreatPattern(
                pattern_id=self._generate_pattern_id(source, source_url, truncated),
                description=truncated,
                pattern_regex=pattern_regex,
                threat_type=threat_type,
                severity=severity,
                first_seen=now,
                last_updated=now,
                source=source,
                references=[source_url],
            )
            patterns.append(pattern)

        return patterns

    def _parse_cve_html(self, url: str, html: str) -> List[ThreatPattern]:
        """Parse NVD / MITRE HTML into ThreatPatterns."""
        blocks = self._extract_text_blocks(html)
        return self._blocks_to_patterns(blocks, "cve", url, "injection")

    def _parse_github_html(self, url: str, html: str) -> List[ThreatPattern]:
        """Parse GitHub topics/advisories HTML into ThreatPatterns."""
        blocks = self._extract_text_blocks(html)
        return self._blocks_to_patterns(blocks, "github", url, "bypass")

    def _parse_blog_html(self, url: str, html: str) -> List[ThreatPattern]:
        """Parse security blog HTML into ThreatPatterns."""
        blocks = self._extract_text_blocks(html)
        return self._blocks_to_patterns(blocks, "blog", url, "injection")

    # ------------------------------------------------------------------
    # Pattern helpers
    # ------------------------------------------------------------------

    def _generate_pattern_id(self, source: str, url: str, text: str) -> str:
        """Generate a stable, unique pattern ID."""
        combined = f"{source}:{url}:{text}"
        return f"{source}_{hashlib.sha256(combined.encode()).hexdigest()[:16]}"

    def _extract_regex_from_text(self, text: str) -> str:
        """Map text keywords to a representative regex pattern using word-boundary matching."""
        import re as _re
        text_lower = text.lower()
        for keyword, regex in _KEYWORD_REGEX_MAP.items():
            if _re.search(r"\b" + _re.escape(keyword) + r"\b", text_lower):
                return regex
        return r"(?i)(prompt|injection|bypass|override|jailbreak)"

    def _classify_threat(self, text: str) -> str:
        """Classify threat type from text."""
        text_lower = text.lower()
        if any(w in text_lower for w in ["bypass", "evasion", "evade", "circumvent"]):
            return "bypass"
        if any(w in text_lower for w in ["exfiltrat", "exfil", "leak", "steal"]):
            return "exfiltration"
        if any(w in text_lower for w in ["jailbreak", "override", "unrestricted"]):
            return "override"
        return "injection"

    def _infer_severity(self, text: str) -> str:
        """Infer severity from text signals."""
        text_lower = text.lower()
        if any(w in text_lower for w in ["critical", "severe", "dangerous", "catastrophic"]):
            return "critical"
        if any(w in text_lower for w in ["high", "serious", "significant"]):
            return "high"
        if any(w in text_lower for w in ["low", "minor", "unlikely"]):
            return "low"
        return "medium"

    def _map_severity(self, cvss_score: float) -> str:
        """Map CVSS score (0-10) to severity level."""
        if cvss_score >= 9.0:
            return "critical"
        if cvss_score >= 7.0:
            return "high"
        if cvss_score >= 4.0:
            return "medium"
        return "low"

    def _apply_rate_limit(self) -> None:
        """Enforce rate limit (default: 100 req/min)."""
        current = time.time()
        elapsed = current - self._window_start

        if elapsed > 60:
            self._request_count = 0
            self._window_start = current

        if self._request_count >= self.rate_limit_per_min:
            sleep_time = 60 - elapsed
            if sleep_time > 0:
                logger.debug(
                    "Rate limit reached (%d/%d), sleeping %.1fs",
                    self._request_count, self.rate_limit_per_min, sleep_time,
                )
                time.sleep(sleep_time)
                self._request_count = 0
                self._window_start = time.time()

        self._request_count += 1
        min_interval = 60.0 / self.rate_limit_per_min
        time_since_last = current - self._last_request_time
        if time_since_last < min_interval:
            time.sleep(min_interval - time_since_last)
        self._last_request_time = time.time()
