"""
ShieldPrompt Dashboard Application

Streamlit UI with:
- Multi-mode navigation (Playground, Detection, Evaluation, Threat Intel)
- Live ingress playground with pipeline visualization
- Forensic audit trail & session log explorer
- Real-time metrics and payload analysis
"""

import json
import logging
import os
import time
import streamlit as st
import sys
from pathlib import Path
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Add project root to Python path for core imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

load_dotenv()  # Must run before any src.* import reads os.getenv()

from src.dashboard.components import (
    render_header_section,
    render_metrics_row,
    render_dark_theme_css,
)
from src.dashboard.playground import render_playground
from src.dashboard.forensics import (
    render_forensic_audit_trail,
    render_mock_traffic_control,
    initialize_forensic_state,
)
from src.dashboard.mock_data import generate_initial_metrics, update_metrics
from src.dashboard.threat_intelligence import render_threat_intel_page
from src.core.payload_parser import PayloadParser
from src.core.router import DualGateRouter
from src.core.shield import ThreatLevel
from tests.evaluate import EvaluationSuite


@st.cache_resource
def _build_threat_intel():
    """
    Build and cache the single shared ThreatIntelligence instance.

    Using @st.cache_resource means Streamlit returns the same object to every
    caller within the same server process — the detection router and the Threat
    Intel dashboard tab share one instance, so patterns fetched via the UI are
    immediately available to the Tier 2 vector gate.
    """
    try:
        from src.core.threat_intel import ThreatIntelligence
        use_mock = os.getenv("USE_MOCK_PATTERNS", "false").lower() == "true"
        ti = ThreatIntelligence(config={"use_mock_patterns": use_mock})
        logger.info("Shared ThreatIntelligence instance built (mock=%s)", use_mock)
        return ti
    except Exception as exc:
        logger.warning("ThreatIntelligence init failed: %s", exc)
        return None


@st.cache_resource
def _build_router(detection_threshold: float) -> DualGateRouter:
    """
    Build and cache a DualGateRouter for the given detection threshold.

    The shared ThreatIntelligence instance is injected so the router's Tier 2
    vector gate queries the same pattern store that the Threat Intel tab updates.
    @st.cache_resource keeps one instance per unique threshold value.
    """
    ti = _build_threat_intel()
    return DualGateRouter(
        threat_intel=ti,
        config={"detection_threshold": detection_threshold},
    )


def initialize_session_state():
    """Initialize Streamlit session state."""
    if "metrics" not in st.session_state:
        st.session_state.metrics = generate_initial_metrics()

    if "payload_parser" not in st.session_state:
        st.session_state.payload_parser = PayloadParser()

    if "detection_history" not in st.session_state:
        st.session_state.detection_history = []

    if "show_result" not in st.session_state:
        st.session_state.show_result = False

    # Seed the shared ThreatIntelligence instance so the Threat Intel tab's
    # _get_threat_intel() finds it already in session_state and never creates a
    # second, disconnected instance.
    if "threat_intel" not in st.session_state:
        st.session_state.threat_intel = _build_threat_intel()
        st.session_state.threat_intel_error = (
            None if st.session_state.threat_intel is not None
            else "ThreatIntelligence failed to initialize — check logs"
        )

    # Initialize forensic audit trail
    initialize_forensic_state()


def render_sidebar():
    """Render sidebar with mode selection and controls."""
    with st.sidebar:
        st.markdown(
            """
            <div style="padding:16px 0 8px 0; text-align:center;">
                <div style="font-size:36px;color:#00C8FF;
                            text-shadow:0 0 20px rgba(0,200,255,0.8);">⬡</div>
                <div style="font-size:11px;letter-spacing:4px;color:#00C8FF;
                            font-weight:800;margin-top:4px;">SHIELDPROMPT</div>
                <div style="font-size:9px;letter-spacing:2px;color:#4A7A9B;
                            margin-top:2px;">CONTROL PANEL</div>
            </div>
            <hr style="border-color:#0D4080;margin:8px 0 16px 0;"/>
            """,
            unsafe_allow_html=True,
        )

        mode_label = st.selectbox(
            "NAVIGATION",
            ["🛡️ Playground", "🎛️ Detection", "📊 Evaluation", "🔍 Threat Intel"],
        )

        st.divider()

        detection_threshold = st.slider(
            "DETECTION THRESHOLD",
            0.0, 1.0, 0.85,
            help="Confidence threshold for flagging threats",
        )

        auto_remediation = st.checkbox(
            "Auto-Remediation",
            value=True,
            help="Automatically attempt to remediate detected threats",
        )

        st.divider()

        if st.button("Refresh Metrics", use_container_width=True):
            st.session_state.metrics = update_metrics(st.session_state.metrics)
            st.toast("Metrics refreshed", icon="✅")

        st.divider()

        render_mock_traffic_control(sidebar=True)

        return mode_label, detection_threshold, auto_remediation


def main():
    """Main Streamlit application."""
    st.set_page_config(
        page_title="ShieldPrompt",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    render_dark_theme_css()
    initialize_session_state()

    mode_label, threshold, auto_remediate = render_sidebar()

    mode = {
        "🛡️ Playground": "Playground",
        "🎛️ Detection": "Detection",
        "📊 Evaluation": "Evaluation",
        "🔍 Threat Intel": "Threat Intel",
    }.get(mode_label, "Playground")

    # Rebuild the router whenever the threshold slider changes. Because _build_router
    # is a @st.cache_resource function, this is cheap: the cached instance is returned
    # immediately for the same threshold value, and a fresh router is built only when
    # the threshold differs. Session state carries the reference so playground.py
    # and the detection page both see the same up-to-date router.
    st.session_state.router = _build_router(threshold)

    if mode == "Playground":
        render_playground()
        render_forensic_audit_trail()
    elif mode == "Detection":
        render_detection_page()
        render_forensic_audit_trail()
    elif mode == "Evaluation":
        render_evaluation_page()
    elif mode == "Threat Intel":
        render_threat_intel_page()


def render_detection_page():
    """Detection mode with metrics dashboard."""
    render_header_section()
    render_metrics_row(st.session_state.metrics)

    st.markdown('<div class="sp-section-label">QUICK DETECTION TOOL</div>', unsafe_allow_html=True)
    user_input = st.text_area(
        "Input Payload",
        height=150,
        placeholder="Paste payload, JSON envelope, or encoded input here...",
    )

    if st.button("RUN ANALYSIS", type="primary", use_container_width=True):
        if not user_input.strip():
            st.warning("Please enter text to analyze")
            return

        with st.spinner("Scanning payload..."):
            routing_result = st.session_state.router.route(user_input)
            st.session_state.metrics = update_metrics(st.session_state.metrics)

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Decision", routing_result.decision.value.upper())
            with col2:
                st.metric("Confidence", f"{routing_result.confidence:.1%}")
            with col3:
                st.metric("Threats", len(routing_result.critical_threats))


def render_evaluation_page():
    """Evaluation mode with full EvaluationSuite integration."""
    render_header_section()
    st.markdown('<div class="sp-section-label">EVALUATION SUITE</div>', unsafe_allow_html=True)
    st.info(
        "Upload a labeled JSON dataset to benchmark ShieldPrompt detection accuracy. "
        "Each record needs `input` (string) and `label` (`malicious` | `benign`)."
    )

    default_dataset_path = project_root / "tests" / "eval_dataset.json"

    col_upload, col_default = st.columns([2, 1])
    with col_upload:
        dataset_file = st.file_uploader("Upload test dataset (JSON)", type="json")
    with col_default:
        st.markdown("<br/>", unsafe_allow_html=True)
        use_default = st.checkbox(
            "Use built-in dataset (35 cases)",
            value=True,
            disabled=bool(dataset_file),
        )

    if default_dataset_path.exists():
        with open(default_dataset_path, "rb") as _f:
            st.download_button(
                "⬇️ Download eval_dataset.json",
                _f.read(),
                file_name="eval_dataset.json",
                mime="application/json",
            )

    if st.button("▶️ Run Evaluation", type="primary", use_container_width=True):
        if dataset_file:
            try:
                dataset = json.loads(dataset_file.read().decode("utf-8"))
            except Exception as e:
                st.error(f"Failed to parse uploaded JSON: {e}")
                return
        elif use_default and default_dataset_path.exists():
            with open(default_dataset_path) as _f:
                dataset = json.load(_f)
        else:
            st.warning("No dataset available. Upload a JSON file or confirm tests/eval_dataset.json exists.")
            return

        if not dataset:
            st.error("Dataset is empty.")
            return

        # --- Single evaluation pass: aggregate metrics via EvaluationSuite ---
        with st.spinner(f"Evaluating {len(dataset)} samples…"):
            suite = EvaluationSuite()
            metrics = suite.evaluate_detection_accuracy(dataset)

            # Second pass to collect per-sample results for the table
            detector = suite.detector
            per_sample = []
            for case in dataset:
                label = case.get("label", "benign")
                actual = label == "malicious"
                result = detector.detect(case["input"])
                predicted = result.threat_level != ThreatLevel.CLEAN
                if actual and predicted:
                    outcome = "TP"
                elif not actual and not predicted:
                    outcome = "TN"
                elif not actual and predicted:
                    outcome = "FP"
                else:
                    outcome = "FN"
                per_sample.append({
                    "id": case.get("id", "—"),
                    "input": case["input"][:70] + ("…" if len(case["input"]) > 70 else ""),
                    "label": label,
                    "threat_level": result.threat_level.value,
                    "tier": result.tier,
                    "confidence": f"{result.confidence:.1%}",
                    "outcome": outcome,
                })

        n = len(dataset)
        st.success(f"✅ Evaluation complete — {n} samples processed")

        # --- Confusion Matrix ---
        st.subheader("🔢 Confusion Matrix")
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("✅ True Positives", metrics.true_positives, help="Correctly blocked injections")
        with c2:
            st.metric("✅ True Negatives", metrics.true_negatives, help="Correctly allowed benign inputs")
        with c3:
            st.metric("⚠️ False Positives", metrics.false_positives, help="Safe inputs incorrectly blocked")
        with c4:
            st.metric("🚨 False Negatives", metrics.false_negatives, help="Exploits missed")

        st.divider()

        # --- KPI Table ---
        st.subheader("📈 Security KPIs")
        k1, k2, k3, k4, k5, k6 = st.columns(6)
        with k1:
            st.metric("TPR / Recall", f"{metrics.tpr:.1%}")
        with k2:
            st.metric("FPR", f"{metrics.fpr:.1%}")
        with k3:
            st.metric("FNR", f"{metrics.fnr:.1%}")
        with k4:
            st.metric("Precision", f"{metrics.precision:.1%}")
        with k5:
            st.metric("F1 Score", f"{metrics.f1_score:.1%}")
        with k6:
            st.metric("⚡ Avg Latency", f"{metrics.avg_detection_latency_ms:.2f} ms")

        st.divider()

        # --- Per-sample results ---
        with st.expander(f"📋 Per-Sample Results ({n} total)", expanded=False):
            badge_colors = {
                "TP": "#10B981",
                "TN": "#6B7280",
                "FP": "#F59E0B",
                "FN": "#EF4444",
            }
            filter_opts = st.multiselect(
                "Show outcomes:",
                ["TP", "TN", "FP", "FN"],
                default=["TP", "TN", "FP", "FN"],
                key="eval_outcome_filter",
            )
            for sample in per_sample:
                if sample["outcome"] not in filter_opts:
                    continue
                color = badge_colors[sample["outcome"]]
                st.markdown(
                    f'<div style="background:{color}18; border-left:3px solid {color}; '
                    f'padding:6px 10px; margin:3px 0; border-radius:3px; font-size:12px;">'
                    f'<strong style="color:{color};">[{sample["outcome"]}]</strong> '
                    f'<code>#{sample["id"]}</code> · {sample["input"]}'
                    f'<span style="float:right; color:#9CA3AF;">'
                    f'label={sample["label"]} | tier={sample["tier"]} | '
                    f'{sample["threat_level"]} | {sample["confidence"]}'
                    f'</span></div>',
                    unsafe_allow_html=True,
                )




if __name__ == "__main__":
    main()
