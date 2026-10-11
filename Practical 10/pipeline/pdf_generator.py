"""
pdf_generator.py
================
Executive Cybersecurity Threat Audit PDF Generator using fpdf2.
Compiles a publication-ready report of analyzed server logs.
"""

from datetime import datetime
from io import BytesIO
from typing import Dict, Any, List
import pandas as pd
from fpdf import FPDF


class ThreatAuditPDF(FPDF):
    """Custom styled PDF document for cybersecurity threat audit."""

    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(24, 24, 27)  # Zinc 900
        self.cell(0, 8, "EXECUTIVE LOG INTELLIGENCE & THREAT AUDIT REPORT", border=False, new_x="LMARGIN", new_y="NEXT", align="C")
        self.set_font("Helvetica", "I", 9)
        self.set_text_color(113, 113, 122)  # Zinc 500
        self.cell(0, 5, f"Automated SOC Analysis Generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", border=False, new_x="LMARGIN", new_y="NEXT", align="C")
        self.ln(4)
        self.set_draw_color(228, 228, 231)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(6)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(161, 161, 170)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}} - Confidential Cybersecurity Telemetry Audit", border=False, align="C")


def generate_threat_audit_pdf(
    summary_stats: Dict[str, Any],
    df_results: pd.DataFrame,
    model_name: str
) -> bytes:
    """Generates an executive PDF report and returns the bytes."""
    pdf = ThreatAuditPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Section 1: Executive Summary Box
    pdf.set_fill_color(244, 244, 245)
    pdf.rect(10, pdf.get_y(), 190, 36, "F")
    
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(39, 39, 42)
    pdf.cell(0, 7, "  1. INCIDENT & PIPELINE AUDIT OVERVIEW", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("Helvetica", "", 9.5)
    pdf.set_text_color(63, 63, 70)
    pdf.cell(95, 6, f"  * Total Server Requests Analyzed : {summary_stats.get('total_requests', 0):,}", align="L")
    pdf.cell(95, 6, f"  * Inference Classifier Used     : {model_name[:28]}", align="L", new_x="LMARGIN", new_y="NEXT")
    
    pdf.cell(95, 6, f"  * Malicious Attacks Blocked     : {summary_stats.get('attacks_count', 0):,} ({summary_stats.get('attack_rate', 0):.1f}%)", align="L")
    pdf.cell(95, 6, f"  * Legitimate Traffic Allowed    : {summary_stats.get('benign_count', 0):,} ({summary_stats.get('benign_rate', 0):.1f}%)", align="L", new_x="LMARGIN", new_y="NEXT")
    
    pdf.cell(95, 6, f"  * Zero-Day / Novel Anomalies    : {summary_stats.get('novel_anomalies', 0):,}", align="L")
    risk_level = "CRITICAL" if summary_stats.get("attacks_count", 0) > 10 else ("ELEVATED" if summary_stats.get("attacks_count", 0) > 0 else "NOMINAL")
    pdf.cell(95, 6, f"  * Threat Posture Assessment     : {risk_level}", align="L", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(8)

    # Section 2: Attack Classification Breakdown Table
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(39, 39, 42)
    pdf.cell(0, 7, "2. DETECTED ATTACK VECTOR DISTRIBUTION", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_fill_color(228, 228, 231)
    pdf.cell(65, 6, "Attack Category", border=1, fill=True)
    pdf.cell(30, 6, "Count", border=1, fill=True, align="C")
    pdf.cell(35, 6, "Proportion (%)", border=1, fill=True, align="C")
    pdf.cell(60, 6, "Recommended SOC Action", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 8.5)
    is_atk_mask = df_results["is_attack"].astype(bool) if "is_attack" in df_results.columns else pd.Series([False]*len(df_results))
    attack_counts = df_results[is_atk_mask]["display_name"].value_counts() if not df_results.empty else pd.Series()
    
    if attack_counts.empty:
        pdf.cell(190, 6, "No malicious cyberattacks detected in current log stream.", border=1, align="C", new_x="LMARGIN", new_y="NEXT")
    else:
        for atk_name, count in attack_counts.items():
            pct = count / summary_stats.get("total_requests", 1) * 100
            act = "Block IP & Deploy WAF Rule" if "SQL" in atk_name or "Command" in atk_name else "Inspect & Rate-Limit"
            pdf.cell(65, 6, str(atk_name)[:32], border=1)
            pdf.cell(30, 6, f"{count:,}", border=1, align="C")
            pdf.cell(35, 6, f"{pct:.2f}%", border=1, align="C")
            pdf.cell(60, 6, act, border=1, new_x="LMARGIN", new_y="NEXT")

    pdf.ln(6)

    # Section 3: Top Attacking Source IPs
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "3. TOP IDENTIFIED THREAT ACTOR IP ADDRESSES", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_fill_color(228, 228, 231)
    pdf.cell(50, 6, "Client IP Address", border=1, fill=True)
    pdf.cell(35, 6, "Attack Count", border=1, fill=True, align="C")
    pdf.cell(45, 6, "Primary Vector", border=1, fill=True)
    pdf.cell(60, 6, "Mitigation Directive", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 8.5)
    ip_col = "ip_address" if "ip_address" in df_results.columns else "client_ip"
    if ip_col in df_results.columns and not df_results[is_atk_mask].empty:
        top_ips = df_results[is_atk_mask][ip_col].value_counts().head(5)
        for ip, cnt in top_ips.items():
            matching_recs = df_results[(df_results[ip_col] == ip) & is_atk_mask]
            primary = matching_recs["display_name"].mode()[0] if not matching_recs.empty else "Attack"
            pdf.cell(50, 6, str(ip), border=1)
            pdf.cell(35, 6, f"{cnt:,}", border=1, align="C")
            pdf.cell(45, 6, str(primary)[:22], border=1)
            pdf.cell(60, 6, "Firewall Drop / Drop TCP SYN", border=1, new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.cell(190, 6, "Zero persistent host threat actors flagged.", border=1, align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(6)

    # Section 4: Sample Detailed Detections
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "4. SAMPLE CRITICAL THREAT DETECTIONS", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(228, 228, 231)
    pdf.cell(15, 6, "Method", border=1, fill=True, align="C")
    pdf.cell(90, 6, "Requested Resource / Payload Excerpt", border=1, fill=True)
    pdf.cell(45, 6, "Classification Result", border=1, fill=True)
    pdf.cell(20, 6, "Conf %", border=1, fill=True, align="C")
    pdf.cell(20, 6, "Anomaly", border=1, fill=True, align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 7.5)
    sample_df = df_results[is_atk_mask].head(10) if not df_results[is_atk_mask].empty else df_results.head(5)
    for _, r in sample_df.iterrows():
        res_text = str(r.get("resource", r.get("normalized_path", "/")))[:55]
        pdf.cell(15, 5.5, str(r.get("method", "GET")), border=1, align="C")
        pdf.cell(90, 5.5, res_text, border=1)
        pdf.cell(45, 5.5, str(r.get("display_name", r.get("predicted_label", "")))[:24], border=1)
        pdf.cell(20, 5.5, f"{r.get('confidence_pct', 95.0):.1f}%", border=1, align="C")
        pdf.cell(20, 5.5, f"{r.get('anomaly_score', 0.4):.3f}", border=1, align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(6)

    # Section 5: SOC Recommendations
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "5. RECOMMENDED INCIDENT RESPONSE ACTIONS", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 8.5)
    pdf.multi_cell(190, 5, 
        "1. Blacklist detected top attacking IP addresses at the edge reverse-proxy / Cloudflare WAF.\n"
        "2. Review web application parameter validation for SQL Injection and Command Injection endpoints.\n"
        "3. Audit high-anomaly requests flagged with Anomaly Score > 0.65 for zero-day exploitation attempts.\n"
        "4. Enforce strict rate-limiting policies for clients exhibiting burst request velocities > 20 req/sec."
    )

    return pdf.output()
