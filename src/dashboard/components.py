"""
Streamlit UI components for ShieldPrompt dashboard.
- Metrics cards and KPI visualization
- Payload field visualizer
- Status indicators
"""

import random
import streamlit as st
from datetime import datetime
from src.dashboard.mock_data import MetricsSnapshot
from src.core.payload_parser import ParseResult, FieldClassification


def render_header_section():
    """Render dashboard header with branding and status."""
    st.markdown(
        """
        <div class="sp-header">
            <div class="sp-header-left">
                <div class="sp-shield-icon">⬡</div>
                <div class="sp-header-text">
                    <div class="sp-title">SHIELDPROMPT</div>
                    <div class="sp-subtitle">AI SECURITY CONSOLE · THREAT DETECTION SYSTEM</div>
                </div>
            </div>
            <div class="sp-header-right">
                <div class="sp-status-pill">
                    <span class="sp-pulse"></span>
                    <span class="sp-status-label">SYSTEM ACTIVE</span>
                </div>
                <div class="sp-version-tag">v1.0 · LIVE</div>
            </div>
        </div>
        <div class="sp-scan-line"></div>
        """,
        unsafe_allow_html=True,
    )


def render_metrics_row(metrics: MetricsSnapshot):
    """Render KPI metrics cards with real-time data."""
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Avg Latency",
            f"{metrics.avg_latency_ms:.1f} ms",
            delta="-0.3ms",
            delta_color="inverse",
            help="Time to complete multi-tier detection",
        )

    with col2:
        st.metric(
            "Total Scanned",
            f"{metrics.total_scanned_payloads:,}",
            delta=f"+{random.randint(1, 5)}",
            help="Cumulative payloads processed",
        )

    with col3:
        st.metric(
            "Threats Blocked",
            f"{metrics.threats_blocked:,}",
            delta=f"+{1 if random.random() > 0.8 else 0}",
            delta_color="off",
            help="Total threat detections and quarantines",
        )

    with col4:
        st.metric(
            "Compute Savings",
            f"${metrics.estimated_compute_savings_usd:.0f}",
            delta=f"+${random.randint(5, 25)}",
            delta_color="off",
            help="Savings vs. full semantic model on all inputs",
        )

    st.divider()


def render_payload_visualizer(parse_result: ParseResult):
    """Render dual-path payload parser visualization."""
    st.markdown('<div class="sp-section-label">PAYLOAD FIELD ANALYSIS</div>', unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            '<div class="sp-path-header sp-path-safe">STRUCTURAL FAST PATH'
            '<span class="sp-path-tag">BYPASS</span></div>',
            unsafe_allow_html=True,
        )
        if parse_result.structural_fields:
            for field in parse_result.structural_fields[:10]:
                st.markdown(
                    f'<div class="sp-field-card sp-field-safe">'
                    f'<code class="sp-field-path">{field.json_path}</code>'
                    f'<div class="sp-field-value">{field.value[:60]}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.info("No structural fields detected.")

    with col2:
        st.markdown(
            '<div class="sp-path-header sp-path-scan">ACTIVE SCANNING PATH'
            '<span class="sp-path-tag">SCANNED</span></div>',
            unsafe_allow_html=True,
        )
        if parse_result.scannable_fields:
            for field in parse_result.scannable_fields[:10]:
                st.markdown(
                    f'<div class="sp-field-card sp-field-scan">'
                    f'<code class="sp-field-path">{field.json_path}</code>'
                    f'<div class="sp-field-value">{field.value[:60]}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.info("No scannable fields detected.")

    st.markdown(
        f'<div class="sp-field-summary">'
        f'TOTAL: <strong>{parse_result.total_fields}</strong> &nbsp;|&nbsp; '
        f'STRUCTURAL: <strong>{len(parse_result.structural_fields)}</strong> &nbsp;|&nbsp; '
        f'SCANNABLE: <strong>{len(parse_result.scannable_fields)}</strong>'
        f'</div>',
        unsafe_allow_html=True,
    )


def render_dark_theme_css():
    """Inject ShieldPrompt cybersecurity theme CSS."""
    st.markdown(
        """
        <style>
        /* ── CORE PALETTE ─────────────────────────────────────────────── */
        :root {
            --sp-bg:          #03080F;
            --sp-surface:     #070F1C;
            --sp-card:        #0B1628;
            --sp-card-hover:  #0F1E38;
            --sp-border:      #0E2845;
            --sp-border-glow: #0D4080;
            --sp-cyan:        #00C8FF;
            --sp-cyan-dim:    #007BA8;
            --sp-green:       #00E676;
            --sp-green-dim:   #00864A;
            --sp-amber:       #FFB300;
            --sp-red:         #FF3D57;
            --sp-purple:      #7C4DFF;
            --sp-text:        #C8DFF5;
            --sp-text-muted:  #4A7A9B;
            --sp-text-dim:    #2A5070;
            --sp-font-mono:   'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
        }

        /* ── GLOBAL RESET ─────────────────────────────────────────────── */
        html, body, [class*="css"] {
            font-family: var(--sp-font-mono) !important;
            background-color: var(--sp-bg) !important;
            color: var(--sp-text) !important;
        }

        .stApp {
            background: var(--sp-bg) !important;
            background-image:
                linear-gradient(rgba(0,200,255,0.015) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0,200,255,0.015) 1px, transparent 1px);
            background-size: 40px 40px;
        }

        /* ── SCROLLBAR ────────────────────────────────────────────────── */
        ::-webkit-scrollbar { width: 5px; height: 5px; }
        ::-webkit-scrollbar-track { background: var(--sp-bg); }
        ::-webkit-scrollbar-thumb { background: var(--sp-border-glow); border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--sp-cyan-dim); }

        /* ── SIDEBAR ──────────────────────────────────────────────────── */
        section[data-testid="stSidebar"] {
            background: var(--sp-surface) !important;
            border-right: 1px solid var(--sp-border-glow) !important;
        }
        section[data-testid="stSidebar"]::before {
            content: '';
            display: block;
            height: 3px;
            background: linear-gradient(90deg, var(--sp-cyan), var(--sp-green), var(--sp-cyan));
            margin-bottom: 8px;
        }

        /* ── HEADER ───────────────────────────────────────────────────── */
        .sp-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 20px 24px;
            background: linear-gradient(135deg, #060E1C 0%, #091829 50%, #06121F 100%);
            border: 1px solid var(--sp-border-glow);
            border-radius: 8px;
            margin-bottom: 6px;
            box-shadow: 0 0 30px rgba(0,200,255,0.08), inset 0 1px 0 rgba(0,200,255,0.1);
        }
        .sp-header-left { display: flex; align-items: center; gap: 16px; }
        .sp-shield-icon {
            font-size: 42px;
            color: var(--sp-cyan);
            text-shadow: 0 0 20px rgba(0,200,255,0.8), 0 0 40px rgba(0,200,255,0.4);
            line-height: 1;
            filter: drop-shadow(0 0 8px rgba(0,200,255,0.6));
        }
        .sp-header-text {}
        .sp-title {
            font-size: 22px;
            font-weight: 800;
            letter-spacing: 6px;
            color: var(--sp-cyan);
            text-shadow: 0 0 15px rgba(0,200,255,0.6);
        }
        .sp-subtitle {
            font-size: 10px;
            letter-spacing: 3px;
            color: var(--sp-text-muted);
            margin-top: 3px;
        }
        .sp-header-right { display: flex; flex-direction: column; align-items: flex-end; gap: 6px; }
        .sp-status-pill {
            display: flex;
            align-items: center;
            gap: 8px;
            background: rgba(0,230,118,0.1);
            border: 1px solid rgba(0,230,118,0.3);
            padding: 5px 14px;
            border-radius: 20px;
        }
        .sp-pulse {
            width: 8px; height: 8px;
            background: var(--sp-green);
            border-radius: 50%;
            box-shadow: 0 0 8px var(--sp-green);
            animation: sp-blink 1.8s ease-in-out infinite;
        }
        @keyframes sp-blink {
            0%, 100% { opacity: 1; box-shadow: 0 0 8px var(--sp-green); }
            50% { opacity: 0.4; box-shadow: 0 0 3px var(--sp-green); }
        }
        .sp-status-label {
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 2px;
            color: var(--sp-green);
        }
        .sp-version-tag {
            font-size: 10px;
            letter-spacing: 2px;
            color: var(--sp-text-dim);
        }
        .sp-scan-line {
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--sp-cyan), var(--sp-green), var(--sp-cyan), transparent);
            margin: 4px 0 18px 0;
            opacity: 0.6;
            animation: sp-scan 3s ease-in-out infinite;
        }
        @keyframes sp-scan {
            0%, 100% { opacity: 0.3; }
            50% { opacity: 0.8; }
        }

        /* ── SECTION LABELS ───────────────────────────────────────────── */
        .sp-section-label {
            font-size: 10px;
            letter-spacing: 4px;
            color: var(--sp-cyan);
            font-weight: 700;
            margin-bottom: 12px;
            padding-left: 2px;
            border-left: 3px solid var(--sp-cyan);
            padding-left: 10px;
        }

        /* ── METRIC CARDS ─────────────────────────────────────────────── */
        [data-testid="stMetric"] {
            background: var(--sp-card) !important;
            border: 1px solid var(--sp-border-glow) !important;
            border-top: 2px solid var(--sp-cyan) !important;
            border-radius: 6px !important;
            padding: 16px !important;
            box-shadow: 0 4px 20px rgba(0,0,0,0.4), 0 0 15px rgba(0,200,255,0.05) !important;
        }
        [data-testid="stMetricLabel"] {
            font-size: 10px !important;
            letter-spacing: 2px !important;
            color: var(--sp-text-muted) !important;
            text-transform: uppercase !important;
        }
        [data-testid="stMetricValue"] {
            font-size: 26px !important;
            font-weight: 800 !important;
            color: var(--sp-cyan) !important;
            text-shadow: 0 0 10px rgba(0,200,255,0.4) !important;
        }
        [data-testid="stMetricDelta"] { font-size: 12px !important; }

        /* ── BUTTONS ──────────────────────────────────────────────────── */
        .stButton > button {
            background: transparent !important;
            border: 1px solid var(--sp-border-glow) !important;
            color: var(--sp-text) !important;
            font-family: var(--sp-font-mono) !important;
            letter-spacing: 1px !important;
            border-radius: 4px !important;
            transition: all 0.2s ease !important;
        }
        .stButton > button:hover {
            border-color: var(--sp-cyan) !important;
            color: var(--sp-cyan) !important;
            box-shadow: 0 0 12px rgba(0,200,255,0.2) !important;
        }
        .stButton > button[kind="primary"] {
            background: linear-gradient(135deg, #003A5C, #005080) !important;
            border-color: var(--sp-cyan) !important;
            color: var(--sp-cyan) !important;
            box-shadow: 0 0 15px rgba(0,200,255,0.15) !important;
        }
        .stButton > button[kind="primary"]:hover {
            background: linear-gradient(135deg, #004E7A, #006BA0) !important;
            box-shadow: 0 0 25px rgba(0,200,255,0.3) !important;
        }

        /* ── TEXT INPUTS & TEXT AREAS ─────────────────────────────────── */
        .stTextInput > div > div > input,
        .stTextArea > div > div > textarea,
        .stSelectbox > div > div {
            background: var(--sp-surface) !important;
            border: 1px solid var(--sp-border-glow) !important;
            color: var(--sp-text) !important;
            font-family: var(--sp-font-mono) !important;
            border-radius: 4px !important;
        }
        .stTextInput > div > div > input:focus,
        .stTextArea > div > div > textarea:focus {
            border-color: var(--sp-cyan) !important;
            box-shadow: 0 0 10px rgba(0,200,255,0.15) !important;
        }

        /* ── EXPANDERS ────────────────────────────────────────────────── */
        [data-testid="stExpander"] {
            background: var(--sp-card) !important;
            border: 1px solid var(--sp-border) !important;
            border-radius: 4px !important;
        }
        [data-testid="stExpander"]:hover {
            border-color: var(--sp-border-glow) !important;
        }
        [data-testid="stExpanderToggleIcon"] { color: var(--sp-cyan) !important; }

        /* ── TABS ─────────────────────────────────────────────────────── */
        [data-testid="stTabs"] [role="tab"] {
            font-family: var(--sp-font-mono) !important;
            letter-spacing: 1px !important;
            color: var(--sp-text-muted) !important;
            font-size: 11px !important;
        }
        [data-testid="stTabs"] [role="tab"][aria-selected="true"] {
            color: var(--sp-cyan) !important;
            border-bottom: 2px solid var(--sp-cyan) !important;
        }

        /* ── DIVIDER ──────────────────────────────────────────────────── */
        hr {
            border: none !important;
            border-top: 1px solid var(--sp-border-glow) !important;
            opacity: 0.5 !important;
        }

        /* ── ALERTS / INFO / SUCCESS ──────────────────────────────────── */
        [data-testid="stAlert"] {
            border-radius: 4px !important;
            font-family: var(--sp-font-mono) !important;
            font-size: 13px !important;
        }

        /* ── PAYLOAD FIELD CARDS ──────────────────────────────────────── */
        .sp-path-header {
            font-size: 10px;
            letter-spacing: 3px;
            font-weight: 700;
            padding: 8px 12px;
            border-radius: 4px 4px 0 0;
            margin-bottom: 2px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .sp-path-safe {
            background: rgba(0,230,118,0.08);
            color: var(--sp-green);
            border-left: 3px solid var(--sp-green);
        }
        .sp-path-scan {
            background: rgba(255,179,0,0.08);
            color: var(--sp-amber);
            border-left: 3px solid var(--sp-amber);
        }
        .sp-path-tag {
            font-size: 9px;
            padding: 2px 8px;
            border-radius: 10px;
            background: rgba(255,255,255,0.08);
            letter-spacing: 1px;
        }
        .sp-field-card {
            padding: 8px 12px;
            margin: 4px 0;
            border-radius: 3px;
        }
        .sp-field-safe {
            background: rgba(0,230,118,0.05);
            border-left: 3px solid var(--sp-green-dim);
        }
        .sp-field-scan {
            background: rgba(255,179,0,0.05);
            border-left: 3px solid #7A5500;
        }
        .sp-field-path {
            font-size: 12px;
            font-weight: 600;
            color: var(--sp-text);
            font-family: var(--sp-font-mono);
        }
        .sp-field-value {
            font-size: 11px;
            color: var(--sp-text-muted);
            margin-top: 2px;
            font-family: var(--sp-font-mono);
        }
        .sp-field-summary {
            font-size: 11px;
            letter-spacing: 1px;
            color: var(--sp-text-muted);
            border-top: 1px solid var(--sp-border);
            padding-top: 8px;
            margin-top: 8px;
        }

        /* ── SIDEBAR LABELS ───────────────────────────────────────────── */
        section[data-testid="stSidebar"] label,
        section[data-testid="stSidebar"] .stSelectbox label {
            font-size: 10px !important;
            letter-spacing: 2px !important;
            color: var(--sp-text-muted) !important;
            text-transform: uppercase !important;
        }
        section[data-testid="stSidebar"] h1 {
            font-size: 13px !important;
            letter-spacing: 4px !important;
            color: var(--sp-cyan) !important;
            text-transform: uppercase !important;
        }

        /* ── SELECT/SLIDER/CHECKBOX ───────────────────────────────────── */
        .stSlider [data-testid="stThumbValue"] { color: var(--sp-cyan) !important; }
        .stCheckbox label { font-size: 12px !important; letter-spacing: 1px !important; }
        </style>
        """,
        unsafe_allow_html=True,
    )
