"""
Shared pytest fixtures and test-suite hygiene.

Keeps the suite hermetic: tests must not read the developer's real warm cache
under ./data or make incidental API calls because of it. This autouse fixture
disables intel auto-load and points the snapshot dir at a throwaway location for
every test, unless a test sets these explicitly via its own config.
"""

import pytest


@pytest.fixture(autouse=True)
def _hermetic_intel_env(monkeypatch, tmp_path):
    # Default-off auto-load so ThreatIntelligence() with default paths never
    # ingests/embeds the real ./data warm cache during tests.
    monkeypatch.setenv("AUTO_LOAD_ON_INIT", "false")
    monkeypatch.setenv("SNAPSHOT_DIR", str(tmp_path / "snapshots"))
    yield
