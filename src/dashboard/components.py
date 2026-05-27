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
from core.payload_parser import ParseResult, FieldClassification


def render_header_section():
    """Render dashboard header with branding and status."""
    col1, col2 = st.columns([1, 0.3])

    with col1:
        st.markdown("## 🛡️ ShieldPrompt Security Console")

    with col2:
        st.markdown(
            '<div style="text-align: right; padding-top: 8px;">'
            '<span style="display: inline-block; background: #10B981; color: white; '
            'padding: 6px 12px; border-radius: 20px; font-size: 12px; font-weight: 600;">'
            '● System Active'
            '</span></div>',
            unsafe_allow_html=True
        )

    st.divider()


def render_metrics_row(metrics: MetricsSnapshot):
    """Render KPI metrics cards with real-time data."""
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Average Latency",
            f"{metrics.avg_latency_ms:.1f}ms",
            delta="-0.3ms",
            delta_color="inverse",
            help="Time to complete multi-tier detection"
        )

    with col2:
        st.metric(
            "Total Scanned",
            f"{metrics.total_scanned_payloads}",
            delta=f"+{random.randint(1, 5)}",
            help="Cumulative payloads processed"
        )

    with col3:
        st.metric(
            "Threats Blocked",
            f"{metrics.threats_blocked}",
            delta=f"+{1 if random.random() > 0.8 else 0}",
            delta_color="off",
            help="Total threat detections and quarantines"
        )

    with col4:
        st.metric(
            "Compute Savings",
            f"${metrics.estimated_compute_savings_usd:.0f}",
            delta=f"+${random.randint(5, 25)}",
            delta_color="off",
            help="Savings vs. full semantic model on all inputs"
        )

    st.divider()


def render_payload_visualizer(parse_result: ParseResult):
    """
    Render dual-path payload parser visualization.
    Color-codes structural (green) vs. scannable (orange/red) fields.
    """
    st.subheader("📦 Payload Field Analysis")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            "### 🟢 Structural Fast Path\n"
            "*Metadata & system fields — bypassed from active scanning*"
        )
        if parse_result.structural_fields:
            for field in parse_result.structural_fields[:10]:
                st.markdown(
                    f'<div style="background: #ECFDF5; border-left: 4px solid #10B981; '
                    f'padding: 8px 12px; margin: 6px 0; border-radius: 4px;">'
                    f'<code style="color: #065F46; font-weight: 600;">{field.json_path}</code><br/>'
                    f'<small style="color: #047857;">{field.value[:60]}</small>'
                    f'</div>',
                    unsafe_allow_html=True
                )
        else:
            st.info("No structural fields detected.")

    with col2:
        st.markdown(
            "### 🟠 Active Scanning Path\n"
            "*User content & prompts — full threat pipeline*"
        )
        if parse_result.scannable_fields:
            for field in parse_result.scannable_fields[:10]:
                st.markdown(
                    f'<div style="background: #FEF3C7; border-left: 4px solid #F59E0B; '
                    f'padding: 8px 12px; margin: 6px 0; border-radius: 4px;">'
                    f'<code style="color: #92400E; font-weight: 600;">{field.json_path}</code><br/>'
                    f'<small style="color: #B45309;">{field.value[:60]}</small>'
                    f'</div>',
                    unsafe_allow_html=True
                )
        else:
            st.info("No scannable fields detected.")

    # Summary footer
    st.caption(
        f"**Total Fields**: {parse_result.total_fields} | "
        f"**Structural**: {len(parse_result.structural_fields)} | "
        f"**Scannable**: {len(parse_result.scannable_fields)}"
    )


def render_dark_theme_css():
    """Inject custom CSS for dark theme styling."""
    st.markdown(
        """
        <style>
        :root {
            --shieldprompt-dark: #0F172A;
            --shieldprompt-surface: #1E293B;
            --shieldprompt-border: #334155;
            --shieldprompt-accent: #10B981;
        }

        body {
            background-color: var(--shieldprompt-dark);
            color: #E2E8F0;
        }

        .stMetric {
            background: linear-gradient(135deg, var(--shieldprompt-surface) 0%, #1E293B 100%);
            border: 1px solid var(--shieldprompt-border);
            border-radius: 8px;
            padding: 16px;
        }

        .stDivider {
            border-color: var(--shieldprompt-border) !important;
        }
        </style>
        """,
        unsafe_allow_html=True
    )
