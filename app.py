"""
ShieldPrompt Streamlit UI

Multi-tiered Prompt Injection Detection System with Auto-Remediation
"""

import logging
import os
import json
from typing import Optional

import streamlit as st
from dotenv import load_dotenv

from src.dashboard.components import (
    render_header_section,
    render_metrics_row,
    render_payload_visualizer,
    render_dark_theme_css,
)
from src.dashboard.mock_data import generate_initial_metrics, update_metrics
from core.payload_parser import PayloadParser

# PLACEHOLDER: Import core modules
# from core.shield import ShieldDetector, DetectionResult, ThreatLevel
# from core.supervisor import SupervisorAgent
# from core.threat_intel import ThreatIntelligence

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()


def initialize_session_state():
    """Initialize Streamlit session state."""
    if "detector" not in st.session_state:
        # PLACEHOLDER: Initialize ShieldDetector
        st.session_state.detector = None

    if "supervisor" not in st.session_state:
        # PLACEHOLDER: Initialize SupervisorAgent
        st.session_state.supervisor = None

    if "threat_intel" not in st.session_state:
        # PLACEHOLDER: Initialize ThreatIntelligence
        st.session_state.threat_intel = None

    if "detection_history" not in st.session_state:
        st.session_state.detection_history = []

    if "metrics" not in st.session_state:
        st.session_state.metrics = generate_initial_metrics()

    if "payload_parser" not in st.session_state:
        st.session_state.payload_parser = PayloadParser()


def render_sidebar():
    """Render sidebar with configuration and controls."""
    with st.sidebar:
        st.title("⚙️ Configuration")

        mode = st.selectbox(
            "Select Mode",
            ["🛡️ Detection", "🔧 Auto-Remediation", "📊 Evaluation", "🔍 Threat Intel"]
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

        if st.button("🔄 Refresh Threat Intel", use_container_width=True):
            st.toast("Fetching latest threats...", icon="⏳")
            # PLACEHOLDER: Call threat_intel.update_patterns()
            st.success("Threat intelligence updated!")

        if st.button("📁 View Detection History", use_container_width=True):
            st.switch_page("pages/history.py")

        if st.button("📈 Run Evaluation", use_container_width=True):
            st.switch_page("pages/evaluation.py")

        return mode, detection_threshold, auto_remediation


def render_detection_page():
    """Render main detection interface with metrics and payload visualizer."""
    render_header_section()
    render_metrics_row(st.session_state.metrics)

    col1, col2 = st.columns([3, 1])
    with col1:
        st.subheader("Input Analysis")
    with col2:
        if st.button("Clear", use_container_width=True):
            st.rerun()

    user_input = st.text_area(
        "Enter text to analyze for prompt injection threats:",
        placeholder="Paste user input, web content, or API payload here...",
        height=200,
        key="user_input"
    )

    if st.button("🔍 Analyze", type="primary", use_container_width=True):
        if not user_input.strip():
            st.warning("Please enter text to analyze")
            return

        with st.spinner("Running multi-tier detection..."):
            try:
                # Try to parse as JSON/MCP payload
                payload_data = json.loads(user_input)
                parse_result = st.session_state.payload_parser.parse(payload_data)
                render_payload_visualizer(parse_result)
            except json.JSONDecodeError:
                # Treat as plain text
                st.info("Plain text input (not JSON). Running threat detection...")

            # Update metrics
            st.session_state.metrics = update_metrics(st.session_state.metrics)

            # PLACEHOLDER: Call detector.detect(user_input)
            # detection_result = st.session_state.detector.detect(user_input)

            # Mock result for placeholder
            detection_result = {
                "threat_level": "MEDIUM",
                "confidence": 0.72,
                "tier": 2,
                "evidence": {"technique": "context_confusion"},
            }

            # Display results
            st.divider()
            st.subheader("📊 Detection Results")

            col1, col2, col3 = st.columns(3)
            with col1:
                threat_color = {
                    "CLEAN": "🟢",
                    "LOW": "🟡",
                    "MEDIUM": "🟠",
                    "HIGH": "🔴",
                    "CRITICAL": "🔴",
                }
                threat_level = detection_result["threat_level"]
                st.metric("Threat Level", f"{threat_color.get(threat_level, '')} {threat_level}")

            with col2:
                confidence = detection_result["confidence"]
                st.metric("Confidence", f"{confidence:.1%}")

            with col3:
                tier = detection_result["tier"]
                st.metric("Detection Tier", f"Tier {tier}")

            # Evidence breakdown
            st.subheader("📋 Evidence")
            with st.expander("View detailed evidence", expanded=True):
                for key, value in detection_result["evidence"].items():
                    st.write(f"**{key}**: {value}")

            # Remediation recommendation
            if detection_result["threat_level"] in ["MEDIUM", "HIGH", "CRITICAL"]:
                st.divider()
                st.subheader("🔧 Auto-Remediation")

                if st.button("Attempt Remediation"):
                    with st.spinner("Running supervisor agent..."):
                        # PLACEHOLDER: Call supervisor.remediate(user_input, detection_result)
                        remediation_result = {
                            "status": "RESOLVED",
                            "remediated_input": "Remediated version here...",
                            "method": "instruction_sanitization"
                        }

                        if remediation_result["status"] == "RESOLVED":
                            st.success("✅ Threat remediated successfully!")
                            with st.expander("View remediated input"):
                                st.code(remediation_result["remediated_input"])
                        elif remediation_result["status"] == "ESCALATED":
                            st.error("⚠️ Threat escalated to human operator")

            # Save to history
            st.session_state.detection_history.append({
                "input": user_input,
                "result": detection_result
            })


def render_remediation_page():
    """Render auto-remediation interface."""
    st.title("🔧 Auto-Remediation Control")

    st.info(
        "Supervisor Agent: Analyzes flagged threats and applies corrective actions."
    )

    # PLACEHOLDER: Remediation workflow
    pass


def render_evaluation_page():
    """Render evaluation interface."""
    st.title("📊 Evaluation Suite")

    st.info(
        "Benchmark detection accuracy, remediation success, and latency."
    )

    dataset_file = st.file_uploader("Upload test dataset (JSON)", type="json")

    if dataset_file and st.button("Run Evaluation"):
        with st.spinner("Running evaluation..."):
            # PLACEHOLDER: Call evaluate.run_evaluation()
            pass


def render_threat_intel_page():
    """Render threat intelligence dashboard."""
    st.title("🔍 Threat Intelligence")

    st.info(
        "Live threat pattern updates from CVEs, GitHub, and security research."
    )

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Fetch Latest Threats", use_container_width=True):
            # PLACEHOLDER: Call threat_intel.fetch_latest_threats()
            pass

    with col2:
        if st.button("View Pattern Stats", use_container_width=True):
            # PLACEHOLDER: Call threat_intel.get_pattern_stats()
            pass


def main():
    """Main Streamlit app."""
    st.set_page_config(
        page_title="ShieldPrompt",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    render_dark_theme_css()
    initialize_session_state()

    mode, detection_threshold, auto_remediation = render_sidebar()

    if mode == "🛡️ Detection":
        render_detection_page()
    elif mode == "🔧 Auto-Remediation":
        render_remediation_page()
    elif mode == "📊 Evaluation":
        render_evaluation_page()
    elif mode == "🔍 Threat Intel":
        render_threat_intel_page()


if __name__ == "__main__":
    main()
