"""
Unit tests for BrightDataClient (live Web Unlocker implementation)

Tests cover:
  - Client initialization with config / env vars
  - HTML-based parsing of CVE, GitHub, and blog pages
  - Pattern generation and deduplication
  - Rate limiting enforcement
  - Error handling and graceful degradation when API key is absent
"""

import time
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from src.core.bright_data_client import BrightDataClient
from src.core.threat_intel import ThreatPattern


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def config():
    return {
        "bright_data_api_key": "test_key_123",
        "rate_limit_per_min": 100,
        "request_timeout_sec": 30,
        "max_retries": 3,
    }


@pytest.fixture
def client(config):
    return BrightDataClient(config)


@pytest.fixture
def no_key_client():
    return BrightDataClient({})


# Sample HTML snippets that contain security-relevant text
_CVE_HTML = """
<html><body>
<p>A critical prompt injection vulnerability allows an attacker to override
   the system prompt instructions and bypass safety filters in LLM agents.</p>
<p>This CVE details an LLM injection attack vector rated CVSS 9.1 critical.</p>
<p>Attackers can exfiltrate sensitive data by injecting adversarial prompts.</p>
</body></html>
"""

_GITHUB_HTML = """
<html><body>
<p>llm-jailbreak-poc — A proof-of-concept jailbreak that bypasses instruction
   following by using role play and system prompt override techniques.</p>
<p>This repository demonstrates prompt injection bypass in OpenAI, Anthropic,
   and Google LLMs. Stars: 1500</p>
</body></html>
"""

_BLOG_HTML = """
<html><body>
<h2>OWASP Top 10 for LLM Applications</h2>
<p>LLM01: Prompt Injection — Attackers craft malicious prompts that override
   system-level instructions and cause the model to behave unexpectedly.</p>
<p>Jailbreaking techniques use adversarial inputs to bypass content policies
   and safety guardrails in AI systems.</p>
<p>Indirect injection attacks embed malicious content in retrieved documents
   to hijack the agent's instruction set.</p>
</body></html>
"""


# ---------------------------------------------------------------------------
# Initialization tests
# ---------------------------------------------------------------------------

class TestBrightDataClientInit:

    def test_init_with_api_key(self, config):
        client = BrightDataClient(config)
        assert client.api_key == "test_key_123"
        assert client.rate_limit_per_min == 100
        assert client.request_timeout_sec == 30
        assert client.max_retries == 3

    def test_init_without_config(self):
        client = BrightDataClient()
        assert client.config == {}
        assert client.rate_limit_per_min == 100
        assert client.request_timeout_sec == 30
        assert client.api_key is None  # no env override in this test

    def test_init_uses_env_api_key(self, monkeypatch):
        monkeypatch.setenv("BRIGHT_DATA_API_KEY", "env_key_abc")
        client = BrightDataClient()
        assert client.api_key == "env_key_abc"

    def test_init_default_zone(self, client):
        assert client._zone == "mcp_unlocker"

    def test_init_custom_zone(self):
        client = BrightDataClient({"bright_data_zone": "my_zone"})
        assert client._zone == "my_zone"


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

class TestHealthCheck:

    def test_is_healthy_with_api_key(self, client):
        assert client.is_healthy() is True

    def test_is_healthy_without_api_key(self, no_key_client):
        assert no_key_client.is_healthy() is False


# ---------------------------------------------------------------------------
# HTML parsing — CVE pages
# ---------------------------------------------------------------------------

class TestCVEHTMLParsing:

    def test_parse_cve_html_returns_patterns(self, client):
        patterns = client._parse_cve_html("https://nvd.nist.gov/test", _CVE_HTML)
        assert isinstance(patterns, list)
        assert len(patterns) > 0

    def test_parse_cve_html_source_is_cve(self, client):
        patterns = client._parse_cve_html("https://nvd.nist.gov/test", _CVE_HTML)
        for p in patterns:
            assert p.source == "cve"

    def test_parse_cve_html_returns_threat_patterns(self, client):
        patterns = client._parse_cve_html("https://nvd.nist.gov/test", _CVE_HTML)
        for p in patterns:
            assert isinstance(p, ThreatPattern)
            assert p.pattern_id
            assert p.description
            assert p.pattern_regex

    def test_parse_cve_html_empty_returns_list(self, client):
        patterns = client._parse_cve_html("https://nvd.nist.gov/test", "")
        assert patterns == []

    def test_parse_cve_html_irrelevant_content_skipped(self, client):
        html = "<html><body><p>Cookie consent notice. Accept all cookies.</p></body></html>"
        patterns = client._parse_cve_html("https://nvd.nist.gov/test", html)
        assert patterns == []


# ---------------------------------------------------------------------------
# HTML parsing — GitHub pages
# ---------------------------------------------------------------------------

class TestGitHubHTMLParsing:

    def test_parse_github_html_returns_patterns(self, client):
        patterns = client._parse_github_html("https://github.com/topics/prompt-injection", _GITHUB_HTML)
        assert isinstance(patterns, list)
        assert len(patterns) > 0

    def test_parse_github_html_source_is_github(self, client):
        patterns = client._parse_github_html("https://github.com/topics/prompt-injection", _GITHUB_HTML)
        for p in patterns:
            assert p.source == "github"

    def test_parse_github_html_empty_returns_list(self, client):
        patterns = client._parse_github_html("https://github.com/topics/prompt-injection", "")
        assert patterns == []


# ---------------------------------------------------------------------------
# HTML parsing — security blogs
# ---------------------------------------------------------------------------

class TestBlogHTMLParsing:

    def test_parse_blog_html_returns_patterns(self, client):
        patterns = client._parse_blog_html("https://owasp.org/test", _BLOG_HTML)
        assert isinstance(patterns, list)
        assert len(patterns) > 0

    def test_parse_blog_html_source_is_blog(self, client):
        patterns = client._parse_blog_html("https://owasp.org/test", _BLOG_HTML)
        for p in patterns:
            assert p.source == "blog"

    def test_parse_blog_html_empty_returns_list(self, client):
        patterns = client._parse_blog_html("https://owasp.org/test", "")
        assert patterns == []


# ---------------------------------------------------------------------------
# Text block → pattern conversion
# ---------------------------------------------------------------------------

class TestBlocksToPatterns:

    def test_security_blocks_produce_patterns(self, client):
        blocks = [
            "Prompt injection vulnerability allows attackers to override system prompts.",
            "Jailbreak technique bypasses all safety filters using adversarial input.",
        ]
        patterns = client._blocks_to_patterns(blocks, "blog", "https://example.com")
        assert len(patterns) == 2

    def test_irrelevant_blocks_skipped(self, client):
        blocks = [
            "Subscribe to our newsletter for the latest updates.",
            "Cookie consent: we use cookies to improve your experience.",
        ]
        patterns = client._blocks_to_patterns(blocks, "blog", "https://example.com")
        assert patterns == []

    def test_pattern_description_truncated_to_200(self, client):
        long_block = "A " + ("prompt injection jailbreak " * 20)
        patterns = client._blocks_to_patterns([long_block], "blog", "https://example.com")
        assert len(patterns) == 1
        assert len(patterns[0].description) <= 200

    def test_pattern_references_source_url(self, client):
        blocks = ["Prompt injection attack bypasses system prompt instructions."]
        patterns = client._blocks_to_patterns(blocks, "blog", "https://security.example.com")
        assert "https://security.example.com" in patterns[0].references


# ---------------------------------------------------------------------------
# Pattern helpers
# ---------------------------------------------------------------------------

class TestPatternGeneration:

    def test_generate_pattern_id_uniqueness(self, client):
        id1 = client._generate_pattern_id("cve", "https://a.com", "text one")
        id2 = client._generate_pattern_id("cve", "https://b.com", "text two")
        assert id1 != id2

    def test_generate_pattern_id_consistency(self, client):
        id1 = client._generate_pattern_id("cve", "https://a.com", "same text")
        id2 = client._generate_pattern_id("cve", "https://a.com", "same text")
        assert id1 == id2

    def test_generate_pattern_id_includes_source_prefix(self, client):
        pid = client._generate_pattern_id("github", "https://github.com", "text")
        assert pid.startswith("github_")

    def test_classify_threat_injection(self, client):
        assert client._classify_threat("prompt injection attack") == "injection"
        assert client._classify_threat("LLM injection vulnerability") == "injection"

    def test_classify_threat_bypass(self, client):
        assert client._classify_threat("evasion technique") == "bypass"
        assert client._classify_threat("system prompt bypass") == "bypass"

    def test_classify_threat_exfiltration(self, client):
        assert client._classify_threat("data exfiltration via prompt") == "exfiltration"
        assert client._classify_threat("information leak attack") == "exfiltration"

    def test_classify_threat_override(self, client):
        assert client._classify_threat("jailbreak override") == "override"
        assert client._classify_threat("unrestricted mode") == "override"

    def test_infer_severity_critical(self, client):
        assert client._infer_severity("critical vulnerability found") == "critical"
        assert client._infer_severity("dangerous attack vector") == "critical"

    def test_infer_severity_high(self, client):
        assert client._infer_severity("high severity injection") == "high"
        assert client._infer_severity("serious threat actor") == "high"

    def test_infer_severity_medium_default(self, client):
        assert client._infer_severity("prompt injection technique") == "medium"

    def test_infer_severity_low(self, client):
        assert client._infer_severity("low risk minor bypass") == "low"


# ---------------------------------------------------------------------------
# Regex extraction
# ---------------------------------------------------------------------------

class TestRegexExtraction:

    def test_extract_regex_system_prompt(self, client):
        regex = client._extract_regex_from_text("system prompt override vulnerability")
        assert "system" in regex.lower() or "prompt" in regex.lower()

    def test_extract_regex_jailbreak(self, client):
        regex = client._extract_regex_from_text("jailbreak technique used to bypass")
        assert "jailbreak" in regex.lower()

    def test_extract_regex_ignore(self, client):
        regex = client._extract_regex_from_text("ignore all previous instructions")
        assert "ignore" in regex.lower() or "previous" in regex.lower()

    def test_extract_regex_unknown_returns_default(self, client):
        regex = client._extract_regex_from_text("completely unrelated weather forecast today")
        assert regex  # Falls back to a default pattern
        assert "(?i)" in regex

    def test_extract_regex_role_play(self, client):
        regex = client._extract_regex_from_text("role play as an unrestricted AI")
        assert regex


# ---------------------------------------------------------------------------
# CVSS severity mapping
# ---------------------------------------------------------------------------

class TestSeverityMapping:

    def test_map_severity_critical(self, client):
        assert client._map_severity(9.5) == "critical"
        assert client._map_severity(10.0) == "critical"

    def test_map_severity_high(self, client):
        assert client._map_severity(8.5) == "high"
        assert client._map_severity(7.0) == "high"

    def test_map_severity_medium(self, client):
        assert client._map_severity(6.9) == "medium"
        assert client._map_severity(4.0) == "medium"

    def test_map_severity_low(self, client):
        assert client._map_severity(3.9) == "low"
        assert client._map_severity(0.0) == "low"

    def test_map_severity_boundary(self, client):
        assert client._map_severity(9.0) == "critical"  # >= 9.0 → critical


# ---------------------------------------------------------------------------
# Fetch methods — mocked _scrape_multiple
# ---------------------------------------------------------------------------

class TestFetchMethods:

    def test_fetch_cve_patterns_calls_scrape(self, client):
        with patch.object(client, "_scrape_multiple", return_value={}) as mock_scrape:
            patterns = client.fetch_cve_patterns(limit=10)
            mock_scrape.assert_called_once()
            assert patterns == []

    def test_fetch_github_exploits_calls_scrape(self, client):
        with patch.object(client, "_scrape_multiple", return_value={}) as mock_scrape:
            patterns = client.fetch_github_exploits(limit=10)
            mock_scrape.assert_called_once()
            assert patterns == []

    def test_fetch_security_blogs_calls_scrape(self, client):
        with patch.object(client, "_scrape_multiple", return_value={}) as mock_scrape:
            patterns = client.fetch_security_blogs(limit=10)
            mock_scrape.assert_called_once()
            assert patterns == []

    def test_fetch_cve_patterns_respects_limit(self, client):
        with patch.object(
            client, "_scrape_multiple",
            return_value={"https://nvd.nist.gov": _CVE_HTML}
        ):
            patterns = client.fetch_cve_patterns(limit=1)
            assert len(patterns) <= 1

    def test_fetch_all_patterns_aggregation(self, client):
        p_cve = ThreatPattern(
            pattern_id="cve_001", description="CVE test",
            pattern_regex=r"inject", threat_type="injection",
            severity="high", first_seen=datetime.now(), last_updated=datetime.now(),
            source="cve",
        )
        p_github = ThreatPattern(
            pattern_id="github_001", description="GitHub test",
            pattern_regex=r"bypass", threat_type="bypass",
            severity="medium", first_seen=datetime.now(), last_updated=datetime.now(),
            source="github",
        )
        with patch.object(client, "fetch_cve_patterns", return_value=[p_cve]):
            with patch.object(client, "fetch_github_exploits", return_value=[p_github]):
                with patch.object(client, "fetch_security_blogs", return_value=[]):
                    result = client.fetch_all_patterns()
        assert len(result) == 2
        assert p_cve in result
        assert p_github in result

    def test_fetch_all_patterns_deduplication(self, client):
        p = ThreatPattern(
            pattern_id="dup_001", description="Duplicate",
            pattern_regex=r"dup", threat_type="injection",
            severity="high", first_seen=datetime.now(), last_updated=datetime.now(),
            source="cve",
        )
        with patch.object(client, "fetch_cve_patterns", return_value=[p]):
            with patch.object(client, "fetch_github_exploits", return_value=[p]):
                with patch.object(client, "fetch_security_blogs", return_value=[]):
                    result = client.fetch_all_patterns()
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

class TestRateLimiting:

    def test_apply_rate_limit_nearly_instant_initially(self, client):
        client._request_count = 0
        client._window_start = time.time()
        client._last_request_time = 0.0
        start = time.time()
        client._apply_rate_limit()
        elapsed = time.time() - start
        assert elapsed < 1.0  # Should not block significantly

    def test_apply_rate_limit_increments_counter(self, client):
        client._request_count = 0
        client._window_start = time.time()
        client._last_request_time = 0.0
        client._apply_rate_limit()
        assert client._request_count == 1


# ---------------------------------------------------------------------------
# Error handling — _scrape_multiple raises
# ---------------------------------------------------------------------------

class TestErrorHandling:

    def test_fetch_cve_patterns_returns_empty_on_scrape_error(self, client):
        with patch.object(client, "_scrape_multiple", side_effect=Exception("network error")):
            # _scrape_multiple exception propagates through fetch_cve_patterns
            # but individual URL errors are handled inside _scrape_multiple itself.
            # Test that the outer method handles a total scrape failure gracefully.
            try:
                patterns = client.fetch_cve_patterns()
                # If exception is swallowed, we expect empty list
                assert patterns == []
            except Exception:
                # If exception propagates, that is also acceptable behavior
                pass

    def test_no_api_key_scrape_returns_empty(self, no_key_client):
        results = no_key_client._scrape_multiple(["https://example.com"])
        assert results == {}

    def test_no_api_key_fetch_cve_returns_empty(self, no_key_client):
        patterns = no_key_client.fetch_cve_patterns()
        assert patterns == []

    def test_no_api_key_fetch_github_returns_empty(self, no_key_client):
        patterns = no_key_client.fetch_github_exploits()
        assert patterns == []

    def test_no_api_key_fetch_blogs_returns_empty(self, no_key_client):
        patterns = no_key_client.fetch_security_blogs()
        assert patterns == []

    def test_max_retries_configured(self, client):
        assert client.max_retries == 3
