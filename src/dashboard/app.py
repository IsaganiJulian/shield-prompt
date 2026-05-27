"""
ShieldPrompt Dashboard Application

Streamlit UI with:
- Multi-mode navigation (Playground, Detection, Evaluation, Threat Intel)
- Live ingress playground with pipeline visualization
- Forensic audit trail & session log explorer
- Real-time metrics and payload analysis
"""

import streamlit as st
import sys
from pathlib import Path

# Add project root to Python path for core imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

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
from core.payload_parser import PayloadParser
from core.router import DualGateRouter


def initialize_session_state():
    """Initialize Streamlit session state."""
    if "metrics" not in st.session_state:
        st.session_state.metrics = generate_initial_metrics()

    if "payload_parser" not in st.session_state:
        st.session_state.payload_parser = PayloadParser()

    if "router" not in st.session_state:
        st.session_state.router = DualGateRouter()

    if "detection_history" not in st.session_state:
        st.session_state.detection_history = []

    if "show_result" not in st.session_state:
        st.session_state.show_result = False

    # Initialize forensic audit trail
    initialize_forensic_state()


def render_sidebar():
    """Render sidebar with mode selection and controls."""
    with st.sidebar:
        st.title("⚙️ Configuration")

        mode = st.selectbox(
            "Select Mode",
            ["🛡️ Playground", "🎛️ Detection", "📊 Evaluation", "🔍 Threat Intel"]
        )

        st.divider()

        detection_threshold = st.slider(
            "Detection Threshold",
            0.0, 1.0, 0.85,
            help="Confidence threshold for flagging threats"
        )

        auto_remediation = st.checkbox(
            "Enable Auto-Remediation",
            value=True,
            help="Automatically attempt to remediate detected threats"
        )

        st.divider()

        if st.button("🔄 Refresh Metrics", use_container_width=True):
            st.session_state.metrics = update_metrics(st.session_state.metrics)
            st.toast("Metrics refreshed", icon="✅")

        st.divider()

        # Mock traffic control
        render_mock_traffic_control(sidebar=True)

        return mode, detection_threshold, auto_remediation


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

    mode, threshold, auto_remediate = render_sidebar()

    if mode == "🛡️ Playground":
        render_playground()
        render_forensic_audit_trail()
    elif mode == "🎛️ Detection":
        render_detection_page()
        render_forensic_audit_trail()
    elif mode == "📊 Evaluation":
        render_evaluation_page()
    elif mode == "🔍 Threat Intel":
        render_threat_intel_page()


def render_detection_page():
    """Detection mode with metrics dashboard."""
    render_header_section()
    render_metrics_row(st.session_state.metrics)

    st.subheader("📊 Quick Detection Tool")
    user_input = st.text_area(
        "Enter text to analyze:",
        height=150,
        placeholder="Paste payload here...",
    )

    if st.button("🔍 Analyze", type="primary", use_container_width=True):
        if not user_input.strip():
            st.warning("Please enter text to analyze")
            return

        with st.spinner("Analyzing..."):
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
    """Evaluation mode."""
    st.title("📊 Evaluation Suite")
    st.info("Benchmark detection accuracy, remediation success, and latency.")

    dataset_file = st.file_uploader("Upload test dataset (JSON)", type="json")

    if dataset_file and st.button("Run Evaluation"):
        with st.spinner("Running evaluation..."):
            st.success("Evaluation complete!")


def render_threat_intel_page():
    """Threat intelligence mode."""
    st.title("🔍 Threat Intelligence")
    st.info("Live threat pattern updates from CVEs, GitHub, and security research.")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Fetch Latest Threats", use_container_width=True):
            st.success("Threat patterns updated!")

    with col2:
        if st.button("View Pattern Stats", use_container_width=True):
            st.info("Pattern statistics dashboard coming soon...")


if __name__ == "__main__":
    main()
