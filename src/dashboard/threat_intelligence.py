"""
Threat Intelligence Dashboard Tab

Surfaces Phase 5 Bright Data integration to the Streamlit UI:
    - Feed status banner (last update, next update, pattern count)
    - KPI row: total patterns / high-critical count / vector index size / mode
    - Feed controls: live fetch + mock fallback
    - Pattern browser with type / severity / source filters
    - Semantic similarity search via VectorStore
    - Raw stats expander
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import streamlit as st

logger = logging.getLogger(__name__)

# Severity badge colours (background, text)
_SEVERITY_STYLES: Dict[str, tuple[str, str]] = {
    "critical": ("#EF4444", "#FFFFFF"),
    "high":     ("#F97316", "#FFFFFF"),
    "medium":   ("#EAB308", "#1C1917"),
    "low":      ("#22C55E", "#FFFFFF"),
}

# Threat-type badge colours
_TYPE_STYLES: Dict[str, tuple[str, str]] = {
    "injection":    ("#6366F1", "#FFFFFF"),
    "bypass":       ("#EC4899", "#FFFFFF"),
    "exfiltration": ("#0EA5E9", "#FFFFFF"),
    "override":     ("#8B5CF6", "#FFFFFF"),
}

# Source tag colours
_SOURCE_STYLES: Dict[str, tuple[str, str]] = {
    "cve":    ("#DC2626", "#FFFFFF"),
    "github": ("#1D4ED8", "#FFFFFF"),
    "blog":   ("#059669", "#FFFFFF"),
    "custom": ("#6B7280", "#FFFFFF"),
}


# ---------------------------------------------------------------------------
# Session-state helpers
# ---------------------------------------------------------------------------

def _get_threat_intel() -> Optional[Any]:
    """
    Return the shared ThreatIntelligence instance seeded by app.py at startup.

    The instance is created once via _build_threat_intel() (@st.cache_resource)
    and stored in st.session_state.threat_intel so both the detection router
    and this tab operate on the same pattern store.  Patterns fetched here are
    immediately visible to the Tier 2 vector gate.
    """
    return st.session_state.get("threat_intel")


def _init_page_state() -> None:
    """Initialise threat-intel session keys once per app session."""
    defaults = {
        "ti_last_result":     None,   # result dict from update_patterns()
        "ti_search_results":  [],     # list of SearchResult from search_similar()
        "ti_search_query":    "",
        "ti_mock_loaded":     False,
        "ti_fetch_error":     None,
        "ti_export_data":     None,   # JSON string ready for download button
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


# ---------------------------------------------------------------------------
# Badge rendering helpers
# ---------------------------------------------------------------------------

def _badge(label: str, bg: str, fg: str) -> str:
    return (
        f'<span style="background:{bg};color:{fg};padding:2px 8px;'
        f'border-radius:12px;font-size:11px;font-weight:700;">{label}</span>'
    )


def _severity_badge(severity: str) -> str:
    bg, fg = _SEVERITY_STYLES.get(severity, ("#6B7280", "#FFFFFF"))
    return _badge(severity.upper(), bg, fg)


def _type_badge(threat_type: str) -> str:
    bg, fg = _TYPE_STYLES.get(threat_type, ("#6B7280", "#FFFFFF"))
    return _badge(threat_type, bg, fg)


def _source_badge(source: str) -> str:
    bg, fg = _SOURCE_STYLES.get(source, ("#6B7280", "#FFFFFF"))
    return _badge(source.upper(), bg, fg)


# ---------------------------------------------------------------------------
# Sub-section renderers
# ---------------------------------------------------------------------------

def _render_feed_status(stats: Dict[str, Any]) -> None:
    """Top banner showing feed health and timing."""
    last_update = stats.get("last_update")
    update_interval = stats.get("update_interval_sec", 3600)
    total = stats.get("total", 0)
    vector_info = stats.get("vector_store", {})
    vector_enabled = vector_info.get("enabled", False)
    vector_indexed = vector_info.get("indexed", 0)
    mock_loaded = st.session_state.ti_mock_loaded

    # Status pill
    mode_label = "MOCK MODE" if mock_loaded else "LIVE MODE"
    mode_bg = "#6366F1" if mock_loaded else "#10B981"

    col_status, col_last, col_next, col_vec = st.columns(4)

    with col_status:
        st.markdown(
            f'<div style="text-align:center;">'
            f'<div style="font-size:11px;color:#94A3B8;margin-bottom:4px;">Feed Status</div>'
            f'<span style="background:{mode_bg};color:#fff;padding:4px 14px;'
            f'border-radius:20px;font-size:12px;font-weight:700;">{mode_label}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )

    with col_last:
        last_str = "Never"
        if last_update:
            try:
                dt = datetime.fromisoformat(last_update)
                last_str = dt.strftime("%H:%M:%S")
            except ValueError:
                last_str = last_update
        st.markdown(
            f'<div style="text-align:center;">'
            f'<div style="font-size:11px;color:#94A3B8;margin-bottom:4px;">Last Update</div>'
            f'<div style="font-size:16px;font-weight:700;color:#E2E8F0;">{last_str}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    with col_next:
        interval_min = update_interval // 60
        st.markdown(
            f'<div style="text-align:center;">'
            f'<div style="font-size:11px;color:#94A3B8;margin-bottom:4px;">Update Interval</div>'
            f'<div style="font-size:16px;font-weight:700;color:#E2E8F0;">{interval_min}m</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    with col_vec:
        vec_label = f"{vector_indexed} indexed" if vector_enabled else "disabled"
        vec_color = "#10B981" if vector_enabled else "#64748B"
        st.markdown(
            f'<div style="text-align:center;">'
            f'<div style="font-size:11px;color:#94A3B8;margin-bottom:4px;">Vector Store</div>'
            f'<div style="font-size:16px;font-weight:700;color:{vec_color};">{vec_label}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    st.divider()


def _render_kpi_row(stats: Dict[str, Any]) -> None:
    """Four KPI metrics cards."""
    total = stats.get("total", 0)
    by_severity = stats.get("by_severity", {})
    high_critical = by_severity.get("high", 0) + by_severity.get("critical", 0)
    vector_info = stats.get("vector_store", {})
    vector_indexed = vector_info.get("indexed", 0)
    by_type = stats.get("by_type", {})
    sources = stats.get("by_source", {})

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Patterns", total, help="Patterns currently in the ingester store")
    with col2:
        st.metric("High / Critical", high_critical,
                  delta=f"+{high_critical}" if high_critical else None,
                  delta_color="inverse",
                  help="Patterns rated high or critical severity")
    with col3:
        st.metric("Vector Indexed", vector_indexed, help="Patterns embedded in FAISS index")
    with col4:
        source_count = len(sources)
        st.metric("Active Sources", source_count, help="Distinct threat feed sources loaded")

    st.divider()


def _render_feed_controls(ti: Any) -> None:
    """Live fetch + mock load buttons with result feedback."""
    st.markdown('<div class="sp-section-label">FEED CONTROLS</div>', unsafe_allow_html=True)
    col_live, col_mock, col_export = st.columns(3)

    with col_live:
        if st.button("FETCH LATEST THREATS", use_container_width=True, type="primary"):
            with st.spinner("Querying Bright Data…"):
                try:
                    result = ti.update_patterns(force=True)
                    st.session_state.ti_last_result = result
                    st.session_state.ti_fetch_error = None
                    if result.get("status") == "updated":
                        st.toast(
                            f"Feed updated — {result['patterns_new']} new, "
                            f"{result['patterns_updated']} updated",
                            icon="✅",
                        )
                    elif result.get("status") == "skipped":
                        st.toast(result.get("reason", "Skipped"), icon="ℹ️")
                    else:
                        st.toast(f"Error: {result.get('error', 'unknown')}", icon="⚠️")
                except Exception as exc:
                    st.session_state.ti_fetch_error = str(exc)
                    st.toast(f"Fetch failed: {exc}", icon="❌")

    with col_mock:
        if st.button("LOAD MOCK PATTERNS", use_container_width=True):
            with st.spinner("Loading offline patterns…"):
                try:
                    ti.load_mock_patterns()
                    st.session_state.ti_mock_loaded = True
                    st.session_state.ti_fetch_error = None
                    st.toast("Mock patterns loaded", icon="🧪")
                except Exception as exc:
                    st.session_state.ti_fetch_error = str(exc)
                    st.toast(f"Failed to load mocks: {exc}", icon="❌")

    with col_export:
        if st.button("PREPARE EXPORT", use_container_width=True):
            try:
                from src.core.pattern_ingester import _pattern_to_dict
                patterns = ti.ingester.get_patterns()
                st.session_state.ti_export_data = json.dumps(
                    [_pattern_to_dict(p) for p in patterns],
                    indent=2,
                    default=str,
                )
                st.toast(f"Ready — {len(patterns)} patterns prepared", icon="📦")
            except Exception as exc:
                st.error(f"Export failed: {exc}")
        if st.session_state.ti_export_data:
            st.download_button(
                label="⬇ Download patterns.json",
                data=st.session_state.ti_export_data,
                file_name="shieldprompt_patterns.json",
                mime="application/json",
                use_container_width=True,
            )

    # Show last fetch result
    last = st.session_state.ti_last_result
    err = st.session_state.ti_fetch_error
    if err:
        st.error(f"Feed error: {err}")
    elif last and last.get("status") == "updated":
        st.success(
            f"Last fetch: **{last['patterns_new']} new** · "
            f"**{last['patterns_updated']} updated** · "
            f"**{last['patterns_pruned']} pruned** · "
            f"{last['duration_ms']:.0f}ms"
        )
    elif last and last.get("status") == "skipped":
        st.info(f"Feed check skipped — {last.get('reason', '')}")


def _render_pattern_browser(ti: Any) -> None:
    """Filterable grid of ThreatPattern cards."""
    st.markdown('<div class="sp-section-label">PATTERN BROWSER</div>', unsafe_allow_html=True)

    filter_col1, filter_col2, filter_col3, filter_col4 = st.columns(4)
    with filter_col1:
        type_filter = st.selectbox(
            "Threat Type",
            ["All", "injection", "bypass", "exfiltration", "override"],
            key="ti_type_filter",
        )
    with filter_col2:
        severity_filter = st.selectbox(
            "Min Severity",
            ["All", "low", "medium", "high", "critical"],
            key="ti_severity_filter",
        )
    with filter_col3:
        source_filter = st.selectbox(
            "Source",
            ["All", "cve", "github", "blog", "custom"],
            key="ti_source_filter",
        )
    with filter_col4:
        max_display = st.number_input(
            "Max Shown", min_value=5, max_value=200, value=20, step=5,
            key="ti_max_display",
        )

    # Fetch filtered patterns from ingester
    try:
        patterns = ti.ingester.get_patterns(
            threat_type=None if type_filter == "All" else type_filter,
            min_severity=None if severity_filter == "All" else severity_filter,
            source=None if source_filter == "All" else source_filter,
        )
    except Exception as exc:
        st.error(f"Pattern query failed: {exc}")
        return

    if not patterns:
        st.info("No patterns match the selected filters. Try loading mock patterns or fetching live data.")
        return

    st.caption(f"Showing {min(len(patterns), max_display)} of {len(patterns)} patterns")

    for pattern in patterns[:max_display]:
        sev_bg, sev_fg = _SEVERITY_STYLES.get(pattern.severity, ("#6B7280", "#FFFFFF"))
        type_bg, type_fg = _TYPE_STYLES.get(pattern.threat_type, ("#6B7280", "#FFFFFF"))
        src_bg, src_fg = _SOURCE_STYLES.get(pattern.source, ("#6B7280", "#FFFFFF"))
        last_upd = pattern.last_updated.strftime("%Y-%m-%d %H:%M") if pattern.last_updated else "—"

        st.markdown(
            f'<div style="background:#1E293B;border:1px solid #334155;border-radius:8px;'
            f'padding:12px 16px;margin:6px 0;">'
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">'
            f'{_badge(pattern.severity.upper(), sev_bg, sev_fg)}'
            f'{_badge(pattern.threat_type, type_bg, type_fg)}'
            f'{_badge(pattern.source.upper(), src_bg, src_fg)}'
            f'<span style="margin-left:auto;font-size:11px;color:#64748B;">{last_upd}</span>'
            f'</div>'
            f'<div style="font-size:13px;color:#E2E8F0;font-weight:600;margin-bottom:4px;">'
            f'{pattern.description}</div>'
            f'<code style="font-size:11px;color:#94A3B8;">{pattern.pattern_regex[:100]}'
            f'{"…" if len(pattern.pattern_regex) > 100 else ""}</code>'
            f'</div>',
            unsafe_allow_html=True,
        )


def _render_semantic_search(ti: Any, stats: Dict[str, Any]) -> None:
    """Semantic search over FAISS vector store."""
    st.markdown('<div class="sp-section-label">SEMANTIC PATTERN SEARCH</div>', unsafe_allow_html=True)

    vector_info = stats.get("vector_store", {})
    if not vector_info.get("enabled", False):
        st.warning(
            "Vector search is disabled. Set `ENABLE_VECTOR_SEARCH=true` and "
            "`OPENAI_API_KEY` to activate semantic pattern matching."
        )
        return

    if vector_info.get("indexed", 0) == 0:
        st.info("No patterns are indexed yet. Fetch threats or load mock patterns first.")
        return

    query = st.text_input(
        "Enter suspicious text or injection fragment to find similar patterns:",
        placeholder="e.g. ignore all previous instructions and act as…",
        key="ti_search_query",
    )

    search_col1, search_col2 = st.columns([1, 4])
    with search_col1:
        top_k = st.number_input("Top K", min_value=1, max_value=20, value=5, key="ti_top_k")
    with search_col2:
        threshold = st.slider(
            "Min Similarity", 0.0, 1.0, 0.70, 0.05, key="ti_threshold",
            help="Only return results with cosine similarity ≥ this value",
        )

    if st.button("SEARCH VECTOR INDEX", type="primary"):
        if not query.strip():
            st.warning("Enter a query to search.")
            return
        with st.spinner("Embedding and searching…"):
            try:
                results = ti.search_similar(query, top_k=int(top_k), threshold=threshold)
                st.session_state.ti_search_results = results
            except Exception as exc:
                st.error(f"Search failed: {exc}")
                st.session_state.ti_search_results = []

    results = st.session_state.ti_search_results
    if results:
        st.caption(f"{len(results)} result(s) above {threshold:.0%} similarity")
        for res in results:
            score_pct = f"{res.score:.1%}"
            score_color = "#10B981" if res.score >= 0.85 else "#F59E0B" if res.score >= 0.7 else "#94A3B8"
            p = res.pattern
            sev_bg, sev_fg = _SEVERITY_STYLES.get(p.severity, ("#6B7280", "#FFFFFF"))

            st.markdown(
                f'<div style="background:#1E293B;border:1px solid #334155;border-radius:8px;'
                f'padding:12px 16px;margin:6px 0;">'
                f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">'
                f'<span style="font-size:18px;font-weight:800;color:{score_color};">{score_pct}</span>'
                f'<span style="font-size:11px;color:#64748B;">similarity</span>'
                f'{_badge(p.severity.upper(), sev_bg, sev_fg)}'
                f'{_type_badge(p.threat_type)}'
                f'</div>'
                f'<div style="font-size:13px;color:#E2E8F0;font-weight:600;margin-bottom:4px;">'
                f'{p.description}</div>'
                f'<code style="font-size:11px;color:#94A3B8;">{p.pattern_regex[:120]}</code>'
                f'</div>',
                unsafe_allow_html=True,
            )
    elif st.session_state.ti_search_query:
        st.info("No patterns matched the similarity threshold for that query.")


def _render_raw_stats(stats: Dict[str, Any]) -> None:
    """Collapsible JSON dump of aggregate stats."""
    with st.expander("Raw Pattern Statistics (JSON)"):
        st.json(stats)


# ---------------------------------------------------------------------------
# Public entry point called from app.py
# ---------------------------------------------------------------------------

def render_threat_intel_page() -> None:
    """Full Threat Intelligence dashboard page."""
    from src.dashboard.components import render_header_section
    render_header_section()
    st.markdown('<div class="sp-section-label">THREAT INTELLIGENCE</div>', unsafe_allow_html=True)
    st.caption("Live threat pattern updates from CVEs, GitHub advisory feeds, and security research via Bright Data.")

    _init_page_state()

    ti = _get_threat_intel()
    if ti is None:
        err = st.session_state.get("threat_intel_error", "unknown error")
        st.error(f"ThreatIntelligence module failed to initialise: {err}")
        st.info(
            "Check that all dependencies are installed:\n"
            "```\npip install faiss-cpu openai aiohttp\n```\n"
            "and that required environment variables are set in `.env`."
        )
        return

    # Pull stats once per render (cheap — reads in-memory state)
    try:
        stats = ti.get_pattern_stats()
    except Exception as exc:
        stats = {}
        st.warning(f"Could not load pattern stats: {exc}")

    _render_feed_status(stats)
    _render_kpi_row(stats)
    _render_feed_controls(ti)

    st.divider()

    tab_browser, tab_search, tab_stats = st.tabs(
        ["Pattern Browser", "Semantic Search", "Raw Stats"]
    )

    with tab_browser:
        _render_pattern_browser(ti)

    with tab_search:
        _render_semantic_search(ti, stats)

    with tab_stats:
        _render_raw_stats(stats)
