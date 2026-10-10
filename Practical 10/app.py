"""
Practical 10: Master Threat Hunter & End-to-End Log Inference Dashboard
=======================================================================
A minimalist, premium Streamlit dashboard implementing a complete 4-stage
reusable inference pipeline for raw web server log intelligence.

Features:
- Live Threat Hunter (Multi-format Parsing -> Cleaning -> 31-D Feature Extraction -> Inference)
- Multi-Model Selector (Random Forest Champion, Decision Tree Tuned, Logistic Regression)
- Request-by-Request Inspection with Zero-Day Novel Anomaly Flagging
- SOC False Alarm Alert & Feedback Loop
- 1-Click Executive PDF Threat Audit Report Generation
- Comprehensive 31-D Features Explorer & Live Sandbox
- Project-Wide Datasets Archive (Practicals 1 through 10)
- Benchmark Comparison & Hyperparameter Insights
"""

import sys
import os
import io
import time
from pathlib import Path
from datetime import datetime
import pandas as pd
import numpy as np
import streamlit as st

# Setup Root & Module Search Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pipeline.log_parser import parse_logs_text
from pipeline.preprocessor import clean_and_normalize_logs
from pipeline.feature_extractor import extract_features_dataframe, FEATURE_COLUMNS
from pipeline.inference_engine import ThreatInferenceEngine, ATTACK_METADATA
from pipeline.pdf_generator import generate_threat_audit_pdf

# ---------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------
st.set_page_config(
    page_title="Threat Hunter | Log Intelligence & Inference Pipeline",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------------------------------------------------
# Minimalist, Premium Dark Aesthetic (Zinc/Slate Palette)
# ---------------------------------------------------------
st.markdown("""
<style>
    /* Global Base */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    code, pre, .mono {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Main Container Padding */
    .block-container {
        padding-top: 1.8rem;
        padding-bottom: 2.5rem;
        padding-left: 2.5rem;
        padding-right: 2.5rem;
        max-width: 1400px;
    }

    /* Minimalist Metric Cards */
    .metric-card {
        background-color: #121215;
        border: 1px solid #27272a;
        border-radius: 8px;
        padding: 16px 20px;
        transition: border-color 0.15s ease;
    }
    .metric-card:hover {
        border-color: #3f3f46;
    }
    .metric-label {
        font-size: 0.78rem;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #a1a1aa;
        margin-bottom: 4px;
    }
    .metric-value {
        font-size: 1.75rem;
        font-weight: 700;
        color: #fafafa;
        letter-spacing: -0.02em;
    }
    .metric-sub {
        font-size: 0.75rem;
        color: #71717a;
        margin-top: 4px;
    }

    /* Custom Badges */
    .badge-benign {
        background-color: rgba(16, 185, 129, 0.12);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.25);
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        display: inline-block;
    }
    .badge-attack {
        background-color: rgba(239, 68, 68, 0.12);
        color: #ef4444;
        border: 1px solid rgba(239, 68, 68, 0.25);
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        display: inline-block;
    }
    .badge-anomaly {
        background-color: rgba(245, 158, 11, 0.12);
        color: #f59e0b;
        border: 1px solid rgba(245, 158, 11, 0.25);
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        display: inline-block;
    }

    /* Subdued Section Headings */
    .section-title {
        font-size: 1.15rem;
        font-weight: 600;
        color: #fafafa;
        letter-spacing: -0.01em;
        margin-bottom: 0.25rem;
    }
    .section-desc {
        font-size: 0.85rem;
        color: #a1a1aa;
        margin-bottom: 1.25rem;
    }

    /* Alert Banner */
    .threat-banner {
        background-color: rgba(239, 68, 68, 0.08);
        border: 1px solid rgba(239, 68, 68, 0.28);
        border-radius: 6px;
        padding: 12px 16px;
        margin-bottom: 1.5rem;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .threat-banner-title {
        font-size: 0.9rem;
        font-weight: 600;
        color: #f87171;
    }
    .threat-banner-body {
        font-size: 0.82rem;
        color: #d4d4d8;
    }

    /* Clean Subtle Button Styling */
    div.stButton > button {
        border-radius: 6px;
        font-weight: 500;
        font-size: 0.85rem;
        border: 1px solid #3f3f46;
        background-color: #18181b;
        color: #fafafa;
        transition: all 0.15s ease;
    }
    div.stButton > button:hover {
        border-color: #71717a;
        background-color: #27272a;
        color: #ffffff;
    }
    div.stDownloadButton > button {
        border-radius: 6px;
        font-weight: 500;
        font-size: 0.85rem;
        border: 1px solid #10b981;
        background-color: rgba(16, 185, 129, 0.1);
        color: #10b981;
    }
    div.stDownloadButton > button:hover {
        background-color: rgba(16, 185, 129, 0.2);
        border-color: #34d399;
        color: #34d399;
    }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# State Management
# ---------------------------------------------------------
if "analyzed_data" not in st.session_state:
    st.session_state.analyzed_data = None
if "false_alarms" not in st.session_state:
    st.session_state.false_alarms = set()
if "raw_input_text" not in st.session_state:
    st.session_state.raw_input_text = ""
if "last_model_used" not in st.session_state:
    st.session_state.last_model_used = "Random Forest Ensemble (Champion)"

# ---------------------------------------------------------
# Sidebar: Navigation & Model Selection
# ---------------------------------------------------------
with st.sidebar:
    st.markdown("""
    <div style="padding-bottom: 12px; border-bottom: 1px solid #27272a; margin-bottom: 16px;">
        <div style="font-size: 1.1rem; font-weight: 700; color: #fafafa; letter-spacing: -0.02em;">
            🛡️ THREAT HUNTER
        </div>
        <div style="font-size: 0.75rem; color: #71717a; margin-top: 2px;">
            End-to-End Web Log Inference & Forensics
        </div>
    </div>
    """, unsafe_allow_html=True)

    nav_choice = st.radio(
        "Navigation",
        [
            "🛡️ Live Threat Hunter",
            "📊 Features Used",
            "🗄️ Datasets Archive",
            "⚡ Model Benchmarks"
        ],
        label_visibility="collapsed"
    )

    st.markdown("---")
    st.markdown("<div style='font-size: 0.78rem; font-weight: 600; color: #a1a1aa; text-transform: uppercase; margin-bottom: 8px;'>Active Classifier Model</div>", unsafe_allow_html=True)

    selected_model = st.selectbox(
        "Classifier Model",
        list(ThreatInferenceEngine.AVAILABLE_MODELS.keys()),
        index=0,
        label_visibility="collapsed"
    )

    # Model metadata badge
    if "Random Forest" in selected_model:
        st.caption("🏆 **Champion Ensemble** • 150 Trees • 98.36% Acc • 99.70% Recall")
    elif "Decision Tree" in selected_model:
        st.caption("⚡ **Fast Tuned Tree** • Depth=20 • 98.96% Acc • 99.64% Recall")
    else:
        st.caption("📐 **Linear Baseline** • L2 Regularized • 95.31% Acc • 97.69% Recall")

    st.markdown("---")
    st.markdown("<div style='font-size: 0.78rem; font-weight: 600; color: #a1a1aa; text-transform: uppercase; margin-bottom: 8px;'>System Status</div>", unsafe_allow_html=True)
    st.caption("• **Pipeline Status**: Online & Validated")
    st.caption("• **Feature Engine**: 31 Numerical Dimensions")
    st.caption("• **Engine Version**: Production v10.4.0")
    st.caption(f"• **False Alarm Overrides**: {len(st.session_state.false_alarms)} flagged")


# ==============================================================================
# TAB 1: LIVE THREAT HUNTER (MAIN PAGE)
# ==============================================================================
if nav_choice == "🛡️ Live Threat Hunter":
    st.markdown("""
    <div style="margin-bottom: 1.5rem;">
        <h1 style="font-size: 1.65rem; font-weight: 700; color: #fafafa; letter-spacing: -0.02em; margin-bottom: 4px;">
            Live Server Log Threat Hunter
        </h1>
        <div style="font-size: 0.88rem; color: #a1a1aa;">
            Feed raw server logs through the 4-stage forensic pipeline: Multi-Format Parsing → 13-Field Normalization → 31-D Feature Extraction → Model Inference.
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Load Sample Logs Button or File Upload
    col_input_left, col_input_right = st.columns([2, 1])

    with col_input_left:
        input_source = st.radio(
            "Input Method",
            ["Sample Realistic Logs (Instant)", "Upload Custom Log File", "Paste Raw Logs / Requests"],
            horizontal=True,
            label_visibility="collapsed"
        )

    with col_input_right:
        st.markdown("<div style='text-align: right;'>", unsafe_allow_html=True)
        if st.button("🔄 Reset Telemetry", use_container_width=False):
            st.session_state.analyzed_data = None
            st.session_state.false_alarms = set()
            st.session_state.raw_input_text = ""
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

    raw_text = ""

    if input_source == "Sample Realistic Logs (Instant)":
        sample_path = PROJECT_ROOT / "Practical 10" / "data" / "sample_eval_logs.log"
        if sample_path.exists():
            with open(sample_path, "r") as f:
                raw_text = f.read()
            st.caption("Loaded realistic sample stream containing benign traffic, SQLi, XSS, Path Traversal, Command Injection, Brute Force, and Zero-Day Anomalies.")
        else:
            st.warning("Sample logs file not found.")

    elif input_source == "Upload Custom Log File":
        uploaded_file = st.file_uploader(
            "Upload Web Access Log",
            type=["log", "txt", "csv", "json"],
            help="Supports Apache Combined, Nginx, JSON Lines, and Raw HTTP Request strings."
        )
        if uploaded_file is not None:
            raw_text = uploaded_file.getvalue().decode("utf-8", errors="ignore")
            st.success(f"Uploaded file: {uploaded_file.name} ({len(raw_text.splitlines())} lines)")

    else:
        raw_text = st.text_area(
            "Paste Raw Server Logs or HTTP Request Lines",
            value=st.session_state.raw_input_text or "192.168.1.50 - - [09/Oct/2026:06:20:00 +0000] \"GET /products?id=1%20UNION%20SELECT%20null,password%20FROM%20users-- HTTP/1.1\" 403 240 \"-\" \"curl/7.88\"\n192.168.1.50 - - [09/Oct/2026:06:20:05 +0000] \"GET /search?q=normal+search HTTP/1.1\" 200 4520 \"https://example.com/\" \"Mozilla/5.0\"",
            height=140,
            help="Paste standard Apache Combined, Nginx, JSON, or raw HTTP strings."
        )

    # Execution Trigger Button
    btn_col1, btn_col2 = st.columns([1, 3])
    with btn_col1:
        execute_pipeline = st.button("🚀 Run Forensic Inference Pipeline", type="primary", use_container_width=True)

    if execute_pipeline and raw_text.strip():
        with st.status("Executing 4-Stage Forensic Pipeline...", expanded=True) as status:
            t0 = time.time()
            st.write("🔹 **Stage 1**: Parsing multi-format server log telemetry...")
            df_parsed = parse_logs_text(raw_text)
            st.caption(f"Parsed {len(df_parsed)} raw log records into 13 standardized fields.")

            st.write("🔹 **Stage 2**: Cleaning, URL unquoting & path normalization...")
            df_clean = clean_and_normalize_logs(df_parsed)
            st.caption(f"Completed URL decoding and HTTP attribute normalization.")

            st.write("🔹 **Stage 3**: Extracting 31-D canonical & anomaly feature matrix...")
            df_feats = extract_features_dataframe(df_clean)
            st.caption(f"Computed lexical, semantic, temporal rate, and anomaly dimensions.")

            st.write(f"🔹 **Stage 4**: Model inference with `{selected_model}`...")
            engine = ThreatInferenceEngine(selected_model)
            df_preds = engine.predict(df_feats, df_clean=df_clean)

            elapsed = time.time() - t0
            status.update(label=f"Forensic Pipeline Complete in {elapsed:.2f}s!", state="complete", expanded=False)

        # Merge for unified state
        df_full = pd.concat([df_clean, df_preds], axis=1)
        st.session_state.analyzed_data = df_full
        st.session_state.last_model_used = selected_model
        st.session_state.features_data = df_feats

    # ---------------------------------------------------------
    # Results Display
    # ---------------------------------------------------------
    if st.session_state.analyzed_data is not None:
        df = st.session_state.analyzed_data.copy()

        # Update false alarms
        for fa_id in st.session_state.false_alarms:
            if fa_id in df["log_id"].values:
                df.loc[df["log_id"] == fa_id, "is_attack"] = False
                df.loc[df["log_id"] == fa_id, "display_name"] = "False Alarm (Analyst Override)"
                df.loc[df["log_id"] == fa_id, "severity"] = "Info"

        total_reqs = len(df)
        attacks_count = int(df["is_attack"].sum())
        benign_count = total_reqs - attacks_count
        novel_anomalies = int(df["is_novel_anomaly"].sum())
        attack_rate = (attacks_count / total_reqs * 100) if total_reqs > 0 else 0
        benign_rate = (benign_count / total_reqs * 100) if total_reqs > 0 else 0

        st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

        # KPI Metrics Row
        mcol1, mcol2, mcol3, mcol4, mcol5 = st.columns(5)
        with mcol1:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Total Requests</div>
                <div class="metric-value">{total_reqs:,}</div>
                <div class="metric-sub">Analyzed Telemetry</div>
            </div>
            """, unsafe_allow_html=True)
        with mcol2:
            st.markdown(f"""
            <div class="metric-card" style="border-left: 3px solid #ef4444;">
                <div class="metric-label">Attacks Blocked</div>
                <div class="metric-value" style="color: #ef4444;">{attacks_count:,}</div>
                <div class="metric-sub">{attack_rate:.1f}% Threat Ratio</div>
            </div>
            """, unsafe_allow_html=True)
        with mcol3:
            st.markdown(f"""
            <div class="metric-card" style="border-left: 3px solid #10b981;">
                <div class="metric-label">Legitimate Allowed</div>
                <div class="metric-value" style="color: #10b981;">{benign_count:,}</div>
                <div class="metric-sub">{benign_rate:.1f}% Normal Traffic</div>
            </div>
            """, unsafe_allow_html=True)
        with mcol4:
            st.markdown(f"""
            <div class="metric-card" style="border-left: 3px solid #f59e0b;">
                <div class="metric-label">Zero-Day Anomalies</div>
                <div class="metric-value" style="color: #f59e0b;">{novel_anomalies:,}</div>
                <div class="metric-sub">High Anomaly Score</div>
            </div>
            """, unsafe_allow_html=True)
        with mcol5:
            st.markdown(f"""
            <div class="metric-card" style="border-left: 3px solid #6366f1;">
                <div class="metric-label">False Alarms Flagged</div>
                <div class="metric-value" style="color: #818cf8;">{len(st.session_state.false_alarms):,}</div>
                <div class="metric-sub">Analyst Overrides</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)

        # Threat Alert Banner
        if attacks_count > 0:
            top_vector = df[df["is_attack"]]["display_name"].mode()[0] if not df[df["is_attack"]].empty else "Web Attack"
            st.markdown(f"""
            <div class="threat-banner">
                <div style="font-size: 1.4rem;">🚨</div>
                <div>
                    <div class="threat-banner-title">ACTIVE INCIDENT ALERT: {attacks_count} Malicious Requests Identified</div>
                    <div class="threat-banner-body">
                        Dominant attack vector: <strong>{top_vector}</strong>. Classifier <strong>{st.session_state.last_model_used}</strong> recommends immediate perimeter IP drop and WAF policy enforcement.
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        # Action Bar: PDF Report & CSV Export
        act_col1, act_col2, act_col3 = st.columns([1.5, 1.5, 3])
        with act_col1:
            # Generate Executive PDF
            summary_stats = {
                "total_requests": total_reqs,
                "attacks_count": attacks_count,
                "benign_count": benign_count,
                "attack_rate": attack_rate,
                "benign_rate": benign_rate,
                "novel_anomalies": novel_anomalies
            }
            try:
                pdf_bytes = generate_threat_audit_pdf(summary_stats, df, st.session_state.last_model_used)
                st.download_button(
                    label="📄 Download Executive PDF Report",
                    data=bytes(pdf_bytes),
                    file_name=f"threat_audit_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
            except Exception as e:
                st.error(f"Error compiling PDF: {e}")

        with act_col2:
            csv_buf = io.StringIO()
            df.to_csv(csv_buf, index=False)
            st.download_button(
                label="📥 Export Telemetry (CSV)",
                data=csv_buf.getvalue(),
                file_name=f"threat_telemetry_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )

        st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

        # ---------------------------------------------------------
        # Request-by-Request Telemetry Table
        # ---------------------------------------------------------
        st.markdown("<div class='section-title'>Request-by-Request Forensic Inspection</div>", unsafe_allow_html=True)
        st.markdown("<div class='section-desc'>Every incoming server request is independently classified with exact confidence, anomaly score, and recommended SOC action.</div>", unsafe_allow_html=True)

        # Filter controls
        fcol1, fcol2, fcol3 = st.columns([1.5, 2, 2.5])
        with fcol1:
            verdict_filter = st.selectbox(
                "Filter Verdict",
                ["All Requests", "Malicious Attacks Only", "Normal Traffic Only", "Novel Zero-Days Only"]
            )
        with fcol2:
            search_query = st.text_input("Search IP, Resource or Method", placeholder="e.g. 192.168, /products, UNION")

        # Apply filtering
        filtered_df = df.copy()
        if verdict_filter == "Malicious Attacks Only":
            filtered_df = filtered_df[filtered_df["is_attack"]]
        elif verdict_filter == "Normal Traffic Only":
            filtered_df = filtered_df[~filtered_df["is_attack"]]
        elif verdict_filter == "Novel Zero-Days Only":
            filtered_df = filtered_df[filtered_df["is_novel_anomaly"]]

        if search_query.strip():
            sq = search_query.strip().lower()
            filtered_df = filtered_df[
                filtered_df["ip_address"].str.lower().str.contains(sq) |
                filtered_df["resource"].str.lower().str.contains(sq) |
                filtered_df["method"].str.lower().str.contains(sq) |
                filtered_df["display_name"].str.lower().str.contains(sq)
            ]

        # Display table
        display_cols = [
            "log_id", "ip_address", "method", "resource",
            "display_name", "severity", "confidence_pct", "anomaly_score", "recommended_action"
        ]
        
        # Format columns for display
        df_show = filtered_df[display_cols].copy()
        df_show.columns = [
            "ID", "Client IP", "Method", "Resource / Payload",
            "Verdict", "Severity", "Confidence", "Anomaly Score", "SOC Action"
        ]
        df_show["Confidence"] = df_show["Confidence"].apply(lambda v: f"{v:.1f}%")
        df_show["Anomaly Score"] = df_show["Anomaly Score"].apply(lambda v: f"{v:.3f}")

        st.dataframe(
            df_show,
            use_container_width=True,
            hide_index=True,
            height=340
        )

        # ---------------------------------------------------------
        # Deep Request Inspection & False Alarm Feedback
        # ---------------------------------------------------------
        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
        st.markdown("<div class='section-title'>Deep Payload Inspection & False Alarm Override</div>", unsafe_allow_html=True)
        st.markdown("<div class='section-desc'>Select any request ID to inspect all 31 extracted features, decoded payload details, or flag as a False Alarm.</div>", unsafe_allow_html=True)

        inspect_col1, inspect_col2 = st.columns([1, 2])

        with inspect_col1:
            req_ids = df["log_id"].tolist()
            selected_req_id = st.selectbox("Select Request ID to Inspect", req_ids)

            # False alarm button
            is_already_fa = selected_req_id in st.session_state.false_alarms
            if is_already_fa:
                if st.button("↩️ Unmark False Alarm", key=f"unmark_{selected_req_id}"):
                    st.session_state.false_alarms.remove(selected_req_id)
                    st.rerun()
            else:
                if st.button("⚠️ Flag as False Alarm (Analyst Override)", key=f"mark_{selected_req_id}"):
                    st.session_state.false_alarms.add(selected_req_id)
                    st.rerun()

        with inspect_col2:
            req_row = df[df["log_id"] == selected_req_id].iloc[0]
            is_atk = req_row["is_attack"]
            status_badge = '<span class="badge-attack">MALICIOUS</span>' if is_atk else '<span class="badge-benign">SAFE / BENIGN</span>'
            if req_row["is_novel_anomaly"]:
                status_badge += ' <span class="badge-anomaly">ZERO-DAY NOVEL ANOMALY</span>'

            st.markdown(f"""
            <div style="background-color: #121215; border: 1px solid #27272a; border-radius: 8px; padding: 16px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <div style="font-size: 0.95rem; font-weight: 600; color: #fafafa;">Request #{selected_req_id} &bull; {req_row['method']} {req_row['normalized_path']}</div>
                    <div>{status_badge}</div>
                </div>
                <div style="font-size: 0.82rem; color: #a1a1aa; margin-bottom: 8px;">
                    <strong>Source IP:</strong> <code class="mono">{req_row['ip_address']}</code> &bull; 
                    <strong>Status Code:</strong> <code>{req_row['status_code']}</code> &bull; 
                    <strong>Verdict:</strong> <span style="color: {'#ef4444' if is_atk else '#10b981'}; font-weight: 600;">{req_row['display_name']}</span> &bull; 
                    <strong>Confidence:</strong> {req_row['confidence_pct']:.1f}% &bull; 
                    <strong>Anomaly Score:</strong> {req_row['anomaly_score']:.4f}
                </div>
                <div style="font-size: 0.82rem; color: #d4d4d8; background-color: #18181b; padding: 8px 12px; border-radius: 4px; border: 1px solid #27272a;">
                    <strong>Decoded Payload:</strong> <code class="mono">{req_row.get('decoded_payload', req_row['resource'])}</code>
                </div>
                <div style="margin-top: 8px; font-size: 0.8rem; color: #71717a;">
                    <strong>Recommended SOC Directive:</strong> {req_row['recommended_action']}
                </div>
            </div>
            """, unsafe_allow_html=True)

        # Show 31 extracted features for the selected request
        with st.expander(f"🔍 View Extracted 31-D Feature Vector for Request #{selected_req_id}"):
            if "features_data" in st.session_state and selected_req_id <= len(st.session_state.features_data):
                feat_row = st.session_state.features_data.iloc[selected_req_id - 1]
                f_df = pd.DataFrame([feat_row]).T.reset_index()
                f_df.columns = ["Feature Name", "Computed Value"]
                
                c_a, c_b = st.columns(2)
                half = len(f_df) // 2
                with c_a:
                    st.dataframe(f_df.iloc[:half], use_container_width=True, hide_index=True)
                with c_b:
                    st.dataframe(f_df.iloc[half:], use_container_width=True, hide_index=True)


# ==============================================================================
# TAB 2: FEATURES USED (31-D FEATURE CATALOG)
# ==============================================================================
elif nav_choice == "📊 Features Used":
    st.markdown("""
    <div style="margin-bottom: 1.5rem;">
        <h1 style="font-size: 1.65rem; font-weight: 700; color: #fafafa; letter-spacing: -0.02em; margin-bottom: 4px;">
            Feature Engineering Architecture (31 Dimensions)
        </h1>
        <div style="font-size: 0.88rem; color: #a1a1aa;">
            Complete breakdown of the 30 canonical cybersecurity features + 1 Isolation Forest anomaly score across 4 security dimensions.
        </div>
    </div>
    """, unsafe_allow_html=True)

    tab_lex, tab_sem, tab_temp, tab_net, tab_imp, tab_sandbox = st.tabs([
        "1. Lexical & Structural (9)",
        "2. Payload Semantics (7)",
        "3. Temporal & Velocity (7)",
        "4. Headers & Network (8)",
        "🏆 Feature Importances (Gini)",
        "🧪 Live Feature Sandbox"
    ])

    with tab_lex:
        st.markdown("### Dimension 1: Lexical & URL Structural Features")
        st.write("Measures syntactic anomalies in the uniform resource identifier without requiring server execution.")
        lex_data = [
            ("url_length", "Float / Integer", "Total string length of the raw requested URI.", "Buffer overflows, fuzzing payloads, polyglots."),
            ("url_entropy", "Float [0 - 8]", "Shannon entropy of characters across the entire URL string.", "Detects encoded shellcodes, encrypted C2 beacons, randomized params."),
            ("path_depth", "Integer", "Count of forward-slash delimiters `/` in the URI path.", "Directory traversal `../../` and nested file fuzzer detection."),
            ("query_param_count", "Integer", "Number of `&`-separated query parameter keys.", "Detects HTTP Parameter Pollution (HPP) and parameter fuzzing."),
            ("special_char_ratio", "Float [0 - 1]", "Ratio of non-alphanumeric ASCII characters.", "High in SQLi (`'--`), XSS (`<script>`), and command injection (`|;`)."),
            ("digit_ratio", "Float [0 - 1]", "Proportion of numeric digits [0-9] in the URL.", "Detects numeric blind SQLi boolean flags and IP-encoded targets."),
            ("uppercase_ratio", "Float [0 - 1]", "Proportion of uppercase letters in the URL.", "Detects WAF-bypass casing variations (`sElEcT`, `UnIoN`)."),
            ("double_slash_count", "Integer", "Occurrences of consecutive slashes `//`.", "Detects open redirect attacks and URL-normalization bypasses."),
            ("percent_encoding_count", "Integer", "Count of `%xx` hex escape characters.", "Detects double URL encoding and evasion techniques.")
        ]
        st.dataframe(pd.DataFrame(lex_data, columns=["Feature", "Type / Range", "Mathematical Definition", "Cybersecurity Threat Relevance"]), use_container_width=True, hide_index=True)

    with tab_sem:
        st.markdown("### Dimension 2: Payload Semantics & Signature Matchers")
        st.write("Evaluates syntactic payload patterns and domain-specific attack heuristics.")
        sem_data = [
            ("payload_length", "Float / Integer", "Byte length of extracted query/POST parameter body.", "Differentiates lightweight GET requests from heavy injection attempts."),
            ("payload_entropy", "Float [0 - 8]", "Shannon entropy computed solely on the decoded parameter payload.", "Flags base64/hex-encoded exploits and reverse shells."),
            ("has_sql_semantics", "Binary {0, 1}", "Regex match for `SELECT`, `UNION`, `OR 1=1`, `--`, `INFORMATION_SCHEMA`.", "Deterministic signature signal for SQL Injection."),
            ("has_script_semantics", "Binary {0, 1}", "Regex match for `<script>`, `onerror=`, `onload=`, `javascript:`.", "Deterministic signature signal for Cross-Site Scripting (XSS)."),
            ("has_traversal_semantics", "Binary {0, 1}", "Regex match for `../`, `..\\`, `/etc/passwd`, `win.ini`.", "Deterministic signal for Directory Path Traversal."),
            ("has_command_semantics", "Binary {0, 1}", "Regex match for `;`, `|`, `&&`, `cat `, `whoami`, `powershell`.", "Deterministic signal for OS Command Injection."),
            ("has_internal_ip_semantics", "Binary {0, 1}", "Match for RFC 1918 IPs (`10.x`, `192.168.x`, `169.254.x`).", "Detects Server-Side Request Forgery (SSRF) targeting cloud metadata.")
        ]
        st.dataframe(pd.DataFrame(sem_data, columns=["Feature", "Type / Range", "Mathematical Definition", "Cybersecurity Threat Relevance"]), use_container_width=True, hide_index=True)

    with tab_temp:
        st.markdown("### Dimension 3: Temporal, Session & Velocity Metrics")
        st.write("Dynamic sliding-window behavioral features tracking client velocity across 1-sec, 1-min, and 5-min windows.")
        temp_data = [
            ("inter_request_time", "Float (seconds)", "Time elapsed $\\Delta t$ since the client's previous request.", "Extremely small $\\Delta t < 0.05s$ indicates automated tools and bot floods."),
            ("requests_per_ip_1min", "Integer", "Total request volume from client IP within a 60-second window.", "DDoS HTTP flood and automated brute-force detection."),
            ("requests_per_ip_5min", "Integer", "Rolling 5-minute client request volume.", "Identifies persistent scanning and slow-rate reconnaissance."),
            ("request_velocity_1sec", "Float (req/sec)", "Instantaneous request arrival frequency.", "Spike detection during DDoS floods."),
            ("burst_ratio", "Float", "Ratio of short-term velocity to 5-minute rolling average.", "Flags sudden burst spikes typical of automated vulnerability scanners."),
            ("unique_resources_per_ip_5min", "Integer", "Count of distinct endpoints accessed by IP in 5 minutes.", "High count indicates directory brute-forcing (DirBuster/Gobuster)."),
            ("failed_login_count", "Integer", "Count of HTTP 401/403 status responses on authentication endpoints.", "Flags credential stuffing and dictionary attacks.")
        ]
        st.dataframe(pd.DataFrame(temp_data, columns=["Feature", "Type / Range", "Mathematical Definition", "Cybersecurity Threat Relevance"]), use_container_width=True, hide_index=True)

    with tab_net:
        st.markdown("### Dimension 4: Headers, Network & Telemetry")
        st.write("HTTP protocol metadata, user agent heuristics, and unsupervised anomaly baseline.")
        net_data = [
            ("status_code", "Integer [100 - 599]", "Standard HTTP response code returned by server.", "Error codes 400/403/404/500 correlate strongly with attack attempts."),
            ("is_error_status", "Binary {0, 1}", "Indicator whether HTTP response code $\\ge 400$.", "Provides direct binary signal of unsuccessful/rejected requests."),
            ("bytes_sent", "Integer", "Payload volume in bytes transmitted in server response.", "Outliers signify data exfiltration or internal error stacktraces."),
            ("user_agent_length", "Integer", "Character length of HTTP `User-Agent` header.", "Unusually short or absent User-Agents indicate scripted clients."),
            ("user_agent_entropy", "Float [0 - 8]", "Shannon entropy of User-Agent string.", "Detects randomized bot User-Agents."),
            ("is_known_scanner", "Binary {0, 1}", "Keyword match for `sqlmap`, `nikto`, `nuclei`, `nmap`, `nessus`.", "Flags offensive security scanner reconnaissance."),
            ("is_bot", "Binary {0, 1}", "Keyword match for generic `bot`, `crawler`, `spider`.", "Differentiates standard search indexing bots from human users."),
            ("anomaly_score", "Float [0 - 1]", "Unsupervised Isolation Forest anomaly score from Practical 5.", "Captures novel zero-day attack vectors without explicit labels.")
        ]
        st.dataframe(pd.DataFrame(net_data, columns=["Feature", "Type / Range", "Mathematical Definition", "Cybersecurity Threat Relevance"]), use_container_width=True, hide_index=True)

    with tab_imp:
        st.markdown("### Feature Importance Ranking (Gini Importance)")
        st.write("Trained Random Forest Ensemble Gini importance scores across all 31 features:")
        imp_path = PROJECT_ROOT / "Practical 9" / "outputs" / "data" / "random_forest_feature_importance.csv"
        if imp_path.exists():
            df_imp = pd.read_csv(imp_path)
            df_imp["importance_pct"] = (df_imp["importance"] * 100).round(2)
            st.dataframe(df_imp, use_container_width=True, hide_index=True, height=350)
            st.bar_chart(df_imp.set_index("feature")["importance_pct"])
        else:
            st.info("Feature importance data loaded from model definitions.")

    with tab_sandbox:
        st.markdown("### 🧪 Live Feature Extraction Sandbox")
        st.write("Type or paste any URL/payload to inspect its real-time 31-D feature vector.")
        sandbox_input = st.text_input(
            "Enter URL or Payload",
            value="/products.php?id=1' UNION SELECT null, username, password FROM users--"
        )
        if sandbox_input:
            dummy_row = pd.DataFrame([{
                "log_id": 1,
                "ip_address": "192.168.1.100",
                "timestamp": "09/Oct/2026:06:00:00 +0000",
                "method": "GET",
                "resource": sandbox_input,
                "protocol": "HTTP/1.1",
                "status_code": 200,
                "bytes_sent": 1024,
                "referer": "-",
                "user_agent": "Mozilla/5.0",
                "parse_format": "sandbox",
                "raw_log": sandbox_input
            }])
            df_sb_clean = clean_and_normalize_logs(dummy_row)
            df_sb_feat = extract_features_dataframe(df_sb_clean)
            st.markdown("**Computed 31 Numerical Features:**")
            st.dataframe(df_sb_feat.T.reset_index().rename(columns={"index": "Feature", 0: "Extracted Value"}), use_container_width=True, hide_index=True)


# ==============================================================================
# TAB 3: DATASETS ARCHIVE (PROJECT-WIDE CATALOG)
# ==============================================================================
elif nav_choice == "🗄️ Datasets Archive":
    st.markdown("""
    <div style="margin-bottom: 1.5rem;">
        <h1 style="font-size: 1.65rem; font-weight: 700; color: #fafafa; letter-spacing: -0.02em; margin-bottom: 4px;">
            Project Datasets Archive (Practicals 1 through 10)
        </h1>
        <div style="font-size: 0.88rem; color: #a1a1aa;">
            Complete lineage and catalog of all raw, preprocessed, feature-extracted, balanced, and external benchmark datasets across the curriculum.
        </div>
    </div>
    """, unsafe_allow_html=True)

    catalog_data = [
        {
            "Dataset": "1. Raw Server Access Logs",
            "Practical": "Practical 1 & 2",
            "Records": "291,489 lines",
            "Format": "Raw Text / Log",
            "Size": "92.16 MB",
            "Description": "Original Apache Combined Web Server access log telemetry with authentic HTTP requests.",
            "Path": "Practical 1/data/raw/server_access.log"
        },
        {
            "Dataset": "2. Structured Logs (13 Fields)",
            "Practical": "Practical 2",
            "Records": "291,489 rows",
            "Format": "Parquet & CSV",
            "Size": "34.57 MB",
            "Description": "Regex-parsed tabular data with 13 fields: ip, timestamp, method, resource, status, bytes, UA, etc.",
            "Path": "Practical 2/data/processed/structured_logs.parquet"
        },
        {
            "Dataset": "3. Cleaned & Preprocessed Telemetry",
            "Practical": "Practical 3",
            "Records": "291,489 rows",
            "Format": "Parquet & CSV",
            "Size": "65.50 MB",
            "Description": "URL-decoded, normalized paths, imputed missing headers, and validated status codes.",
            "Path": "Practical 3/data/processed/preprocessed_logs.parquet"
        },
        {
            "Dataset": "4. Labeled Multi-Class Attacks",
            "Practical": "Practical 4",
            "Records": "291,489 rows",
            "Format": "Parquet & CSV",
            "Size": "65.36 MB",
            "Description": "Ground-truth multi-class labeled dataset (Benign, SQLi, XSS, Path Traversal, Command Injection, etc.).",
            "Path": "Practical 4/data/processed/labeled_logs.parquet"
        },
        {
            "Dataset": "5. Master 31-D Feature Matrix",
            "Practical": "Practical 5",
            "Records": "291,489 rows",
            "Format": "Parquet & CSV",
            "Size": "70.93 MB",
            "Description": "Complete 30 canonical features + Isolation Forest unsupervised anomaly scores.",
            "Path": "Practical 5/data/processed/featured_logs.parquet"
        },
        {
            "Dataset": "6. SMOTE Balanced Training Partition",
            "Practical": "Practical 6",
            "Records": "66,000 rows",
            "Format": "Parquet & CSV",
            "Size": "11.93 MB",
            "Description": "Synthetic Minority Over-sampling (SMOTE) balanced training split mitigating class imbalance.",
            "Path": "Practical 6/data/processed/balanced_train_smote.parquet"
        },
        {
            "Dataset": "7. Golden Locked Test Partition",
            "Practical": "Practical 6",
            "Records": "14,000 rows",
            "Format": "Parquet & CSV",
            "Size": "15.56 MB",
            "Description": "Strictly held-out locked evaluation test set preserving authentic real-world class distributions.",
            "Path": "Practical 6/data/processed/test_dataset.parquet"
        },
        {
            "Dataset": "8. Wrangled & Filtered Telemetry",
            "Practical": "Practical 7 & 8",
            "Records": "260,000 rows",
            "Format": "Parquet & CSV",
            "Size": "23.41 MB",
            "Description": "Bot/internal-IP filtered, time-resampled aggregated hourly/daily matrices and pivot tables.",
            "Path": "Practical 7/data/processed/wrangled_filtered_dataset.parquet"
        },
        {
            "Dataset": "9. External Real-World Benchmark Suite",
            "Practical": "Practical 9",
            "Records": "15,515 rows",
            "Format": "CSV",
            "Size": "4.20 MB",
            "Description": "Unseen real-world HuggingFace & Kaggle web exploits (SQLi, XSS, Path Traversal) for blind generalizability testing.",
            "Path": "Practical 9/outputs/reports/real_world_benchmark_results.csv"
        }
    ]

    st.dataframe(pd.DataFrame(catalog_data)[["Dataset", "Practical", "Records", "Format", "Size", "Description"]], use_container_width=True, hide_index=True)

    st.markdown("---")
    st.markdown("<div class='section-title'>Interactive Dataset Inspector</div>", unsafe_allow_html=True)
    st.markdown("<div class='section-desc'>Select a dataset from the archive to inspect its disk metadata, shape, and sample records.</div>", unsafe_allow_html=True)

    ds_choice = st.selectbox(
        "Choose Dataset to Inspect",
        [d["Dataset"] for d in catalog_data]
    )

    chosen_meta = next(d for d in catalog_data if d["Dataset"] == ds_choice)
    target_path = PROJECT_ROOT / chosen_meta["Path"]

    d_col1, d_col2 = st.columns([1, 2])
    with d_col1:
        st.markdown(f"""
        <div style="background-color: #121215; border: 1px solid #27272a; border-radius: 8px; padding: 16px;">
            <div style="font-size: 0.95rem; font-weight: 600; color: #fafafa;">{chosen_meta['Dataset']}</div>
            <div style="font-size: 0.8rem; color: #a1a1aa; margin-top: 6px;">
                <strong>Stage:</strong> {chosen_meta['Practical']}<br>
                <strong>Records:</strong> {chosen_meta['Records']}<br>
                <strong>File Size:</strong> {chosen_meta['Size']}<br>
                <strong>Storage:</strong> {chosen_meta['Format']}<br>
                <strong>Disk Path:</strong> <code class="mono" style="font-size: 0.72rem;">{chosen_meta['Path']}</code>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with d_col2:
        if target_path.exists():
            st.success(f"File verified on local filesystem: {target_path.name}")
            try:
                if str(target_path).endswith(".parquet"):
                    df_preview = pd.read_parquet(target_path)
                    st.caption(f"Shape: {df_preview.shape[0]:,} rows × {df_preview.shape[1]} columns")
                    st.dataframe(df_preview.head(5), use_container_width=True)
                elif str(target_path).endswith(".csv"):
                    df_preview = pd.read_csv(target_path)
                    st.caption(f"Shape: {df_preview.shape[0]:,} rows × {df_preview.shape[1]} columns")
                    st.dataframe(df_preview.head(5), use_container_width=True)
                else:
                    with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = [f.readline() for _ in range(5)]
                    st.caption("First 5 lines of raw text:")
                    st.code("".join(lines), language="text")
            except Exception as e:
                st.info(f"Summary available. Direct read note: {e}")
        else:
            st.info(f"Dataset archived at: {chosen_meta['Path']}")


# ==============================================================================
# TAB 4: MODEL BENCHMARKS & COMPARISON
# ==============================================================================
elif nav_choice == "⚡ Model Benchmarks":
    st.markdown("""
    <div style="margin-bottom: 1.5rem;">
        <h1 style="font-size: 1.65rem; font-weight: 700; color: #fafafa; letter-spacing: -0.02em; margin-bottom: 4px;">
            Classifier Performance Benchmarks & Tuning Gains
        </h1>
        <div style="font-size: 0.88rem; color: #a1a1aa;">
            Comparative evaluation across Random Forest, Decision Tree, and Logistic Regression under Imbalanced vs Balanced training conditions.
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Top 3 Comparison Cards
    bcol1, bcol2, bcol3 = st.columns(3)

    with bcol1:
        st.markdown("""
        <div class="metric-card" style="border-top: 3px solid #10b981;">
            <div style="font-size: 0.85rem; font-weight: 700; color: #10b981;">🏆 RANDOM FOREST (CHAMPION)</div>
            <div style="font-size: 1.8rem; font-weight: 700; color: #fafafa; margin: 4px 0;">98.36%</div>
            <div style="font-size: 0.8rem; color: #a1a1aa;">
                &bull; <strong>Macro Recall:</strong> 99.70% (Near-Zero Missed Attacks)<br>
                &bull; <strong>Macro F1:</strong> 0.9690<br>
                &bull; <strong>Hyperparameters:</strong> 150 Estimators, Depth=25, Entropy<br>
                &bull; <strong>Inference Latency:</strong> 0.24 ms/batch<br>
                &bull; <strong>Disk Footprint:</strong> 52.39 MB
            </div>
        </div>
        """, unsafe_allow_html=True)

    with bcol2:
        st.markdown("""
        <div class="metric-card" style="border-top: 3px solid #3b82f6;">
            <div style="font-size: 0.85rem; font-weight: 700; color: #3b82f6;">⚡ DECISION TREE (TUNED FAST)</div>
            <div style="font-size: 1.8rem; font-weight: 700; color: #fafafa; margin: 4px 0;">98.96%</div>
            <div style="font-size: 0.8rem; color: #a1a1aa;">
                &bull; <strong>Macro Recall:</strong> 99.64%<br>
                &bull; <strong>Macro F1:</strong> 0.9804<br>
                &bull; <strong>Hyperparameters:</strong> Depth=20, Min Samples Split=5, Entropy<br>
                &bull; <strong>Inference Latency:</strong> 0.01 ms/batch (Ultra-Low)<br>
                &bull; <strong>Disk Footprint:</strong> 142 KB
            </div>
        </div>
        """, unsafe_allow_html=True)

    with bcol3:
        st.markdown("""
        <div class="metric-card" style="border-top: 3px solid #71717a;">
            <div style="font-size: 0.85rem; font-weight: 700; color: #a1a1aa;">📐 LOGISTIC REGRESSION (BASELINE)</div>
            <div style="font-size: 1.8rem; font-weight: 700; color: #fafafa; margin: 4px 0;">95.31%</div>
            <div style="font-size: 0.8rem; color: #a1a1aa;">
                &bull; <strong>Macro Recall:</strong> 97.69%<br>
                &bull; <strong>Macro F1:</strong> 0.9179<br>
                &bull; <strong>Hyperparameters:</strong> L2 Penalty, C=1.0, Saga Solver<br>
                &bull; <strong>Inference Latency:</strong> 0.00 ms/batch<br>
                &bull; <strong>Disk Footprint:</strong> 2.5 KB
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)

    # Detailed Benchmark Table
    st.markdown("<div class='section-title'>Rigorous Evaluation Matrix (Practical 9 Dual-Experiment Benchmark)</div>", unsafe_allow_html=True)
    bench_path = PROJECT_ROOT / "Practical 9" / "outputs" / "data" / "model_comparison.csv"
    if bench_path.exists():
        df_bench = pd.read_csv(bench_path)
        df_bench["accuracy"] = (df_bench["accuracy"] * 100).round(2).astype(str) + "%"
        df_bench["macro_recall"] = (df_bench["macro_recall"] * 100).round(2).astype(str) + "%"
        df_bench["macro_f1"] = df_bench["macro_f1"].round(4)
        df_bench["weighted_f1"] = df_bench["weighted_f1"].round(4)
        st.dataframe(df_bench[["model_name", "accuracy", "macro_recall", "macro_f1", "weighted_f1", "pred_time_seconds"]], use_container_width=True, hide_index=True)

    st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)

    # Real-World External Benchmark Section
    st.markdown("<div class='section-title'>Real-World Generalization Benchmark (15,515 Unseen Records)</div>", unsafe_allow_html=True)
    st.markdown("<div class='section-desc'>Evaluating the champion models against authentic external real-world attack corpora (HuggingFace Web Attacks & CSIC HTTP requests).</div>", unsafe_allow_html=True)

    rw_path = PROJECT_ROOT / "Practical 9" / "outputs" / "reports" / "real_world_benchmark_results.csv"
    if rw_path.exists():
        df_rw = pd.read_csv(rw_path)
        rcol1, rcol2 = st.columns([2, 1])
        with rcol1:
            st.dataframe(df_rw, use_container_width=True, hide_index=True)
        with rcol2:
            st.markdown("""
            <div style="background-color: #121215; border: 1px solid #27272a; border-radius: 8px; padding: 14px; font-size: 0.82rem; color: #a1a1aa;">
                <strong style="color: #fafafa;">Generalization Verdict:</strong><br>
                The model achieved <strong>86.42% overall accuracy</strong> and successfully blocked <strong>100.0% of external SQL Injection payloads</strong> on completely unseen external web traffic.
            </div>
            """, unsafe_allow_html=True)
