"""
run_practical8.py
=================
Practical 8: Data Visualization and Exploratory Data Analysis (EDA).
Course: Python for Data Science (BE05000231_PDS) - 5th Semester B.E./B.Tech

Objective:
----------
Use visual tools (Matplotlib, Seaborn, Plotly) to understand cybersecurity telemetry:
1. Plot Requests per hour (time-series trend).
2. Plot Top 10 attacking IPs (frequency analysis).
3. Plot Attack categories over time (temporal category dynamics).
4. Plot Status code distributions (server feedback).
5. Plot Heatmaps of IP vs request types (method utilization).
6. Export high-resolution static PNG figures and interactive Plotly HTML dashboards.
7. Compile comprehensive EDA findings into technical audit reports.
"""

import os
import sys
import time
import datetime
from pathlib import Path
from typing import Dict, Tuple, List, Any

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# -----------------------------------------------------------------------------
# DIRECTORY RESOLUTION & CONFIGURATION
# -----------------------------------------------------------------------------
PRACTICAL8_DIR = Path(__file__).resolve().parent
WORKSPACE_DIR = PRACTICAL8_DIR.parent
PRACTICAL7_PROCESSED = WORKSPACE_DIR / "Practical 7" / "data" / "processed"
PRACTICAL7_AGG = WORKSPACE_DIR / "Practical 7" / "outputs" / "aggregated"
PRACTICAL6_PROCESSED = WORKSPACE_DIR / "Practical 6" / "data" / "processed"

# Inputs
INPUT_PQ = PRACTICAL7_PROCESSED / "wrangled_filtered_dataset.parquet"
INPUT_CSV = PRACTICAL7_PROCESSED / "wrangled_filtered_dataset.csv"

# Fallback to Practical 6 if needed
if not INPUT_PQ.exists() and not INPUT_CSV.exists():
    INPUT_PQ = PRACTICAL6_PROCESSED / "balanced_training_dataset.parquet"
    INPUT_CSV = PRACTICAL6_PROCESSED / "balanced_training_dataset.csv"

# Output Directories
OUTPUTS_DIR = PRACTICAL8_DIR / "outputs"
PLOTS_DIR = OUTPUTS_DIR / "plots"
INTERACTIVE_DIR = OUTPUTS_DIR / "interactive"
REPORTS_DIR = OUTPUTS_DIR / "reports"

PLOTS_DIR.mkdir(parents=True, exist_ok=True)
INTERACTIVE_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# -----------------------------------------------------------------------------
# STEP 1: INGESTION & DATA INSPECTION
# -----------------------------------------------------------------------------
def load_and_inspect_data() -> pd.DataFrame:
    """Ingests wrangled cybersecurity dataset and ensures datetime parsing."""
    print("=" * 75)
    print("   PRACTICAL 8: DATA VISUALIZATION AND EDA PIPELINE")
    print("   Matplotlib, Seaborn & Plotly Open-Source Engines")
    print("=" * 75)

    if INPUT_PQ.exists():
        print(f"[Ingestion] Loading columnar Parquet: {INPUT_PQ.name}...")
        df = pd.read_parquet(INPUT_PQ)
    elif INPUT_CSV.exists():
        print(f"[Ingestion] Loading CSV fallback: {INPUT_CSV.name}...")
        df = pd.read_csv(INPUT_CSV)
    else:
        raise FileNotFoundError(f"Input telemetry not found at {INPUT_PQ}")

    print(f"  * Ingested: {len(df):,} records, {len(df.columns)} columns")
    df["datetime_utc"] = pd.to_datetime(df["datetime_utc"], errors="coerce")
    if "is_attack" not in df.columns:
        df["is_attack"] = (df["label"] != "benign").astype(np.int8)

    print(f"  * Valid Datetime Records : {df['datetime_utc'].notnull().sum():,} / {len(df):,}")
    print(f"  * Unique Client IPs      : {df['client_ip'].nunique():,}")
    print(f"  * Unique Attack Classes  : {df['label'].nunique()} classes")

    return df


# -----------------------------------------------------------------------------
# STEP 2: PLOT 1 — REQUESTS PER HOUR (TIME-SERIES)
# -----------------------------------------------------------------------------
def plot_requests_per_hour(df: pd.DataFrame) -> pd.DataFrame:
    """Plots hourly request volume and attack density (Matplotlib + Plotly)."""
    print("\n[Plot 1] Generating Requests per Hour Time-Series Visualizations...")

    df_ts = df.dropna(subset=["datetime_utc"]).sort_values("datetime_utc").set_index("datetime_utc")
    hourly = df_ts.resample("1h").agg(
        total_requests=("line_number", "count"),
        attacks=("is_attack", "sum"),
        benign=("is_attack", lambda s: int(np.sum(s == 0)))
    ).reset_index()

    # 1. Static Matplotlib / Seaborn
    fig, ax = plt.subplots(figsize=(12, 4.8), dpi=150)
    ax.plot(hourly["datetime_utc"], hourly["total_requests"], color="#2563EB", linewidth=2.0, label="Total Requests")
    ax.plot(hourly["datetime_utc"], hourly["attacks"], color="#EF4444", linewidth=2.2, label="Malicious Attacks")
    ax.fill_between(hourly["datetime_utc"], 0, hourly["attacks"], color="#EF4444", alpha=0.25)
    ax.set_title("Hourly Access Log Traffic Velocity & Attack Bursts", fontsize=12, fontweight="bold", pad=12)
    ax.set_ylabel("Requests / Hour", fontsize=10)
    ax.set_xlabel("Time (UTC)", fontsize=10)
    ax.legend(frameon=True, facecolor="#FFFFFF")
    ax.grid(True, linestyle="--", alpha=0.7)
    plt.tight_layout()
    p1_path = PLOTS_DIR / "01_requests_per_hour.png"
    plt.savefig(p1_path)
    plt.close()
    print(f"  * Saved Static PNG      : {p1_path.name}")

    # 2. Interactive Plotly HTML
    fig_plotly = go.Figure()
    fig_plotly.add_trace(go.Scatter(
        x=hourly["datetime_utc"], y=hourly["total_requests"],
        mode="lines", name="Total Requests", line=dict(color="#2563EB", width=2)
    ))
    fig_plotly.add_trace(go.Scatter(
        x=hourly["datetime_utc"], y=hourly["attacks"],
        mode="lines", name="Malicious Attacks", line=dict(color="#EF4444", width=2),
        fill="tozeroy", fillcolor="rgba(239, 68, 68, 0.2)"
    ))
    fig_plotly.update_layout(
        title="Interactive Hourly Telemetry Velocity & Threat Surges",
        xaxis_title="Time (UTC)",
        yaxis_title="Requests / Hour",
        template="plotly_white",
        hovermode="x unified"
    )
    p1_html = INTERACTIVE_DIR / "01_requests_per_hour.html"
    fig_plotly.write_html(str(p1_html))
    print(f"  * Saved Interactive HTML: {p1_html.name}")

    return hourly


# -----------------------------------------------------------------------------
# STEP 3: PLOT 2 — TOP 10 ATTACKING IPS (FREQUENCY ANALYSIS)
# -----------------------------------------------------------------------------
def plot_top10_attacking_ips(df: pd.DataFrame) -> pd.DataFrame:
    """Plots top 10 attacking IPs horizontal bar chart (Seaborn + Plotly)."""
    print("\n[Plot 2] Generating Top 10 Attacking IPs Visualizations...")

    ip_stats = df.groupby("client_ip").agg(
        total_requests=("line_number", "count"),
        attack_count=("is_attack", "sum")
    ).reset_index()
    ip_stats.sort_values(by="attack_count", ascending=False, inplace=True)
    top10 = ip_stats.head(10).iloc[::-1]

    # 1. Static Seaborn Horizontal Bar Chart
    fig, ax = plt.subplots(figsize=(10, 5), dpi=150)
    sns.barplot(data=top10, y="client_ip", x="attack_count", color="#DC2626", ax=ax, edgecolor="#7F1D1D")
    for p in ax.patches:
        w = p.get_width()
        ax.text(w + 15, p.get_y() + p.get_height()/2, f"{int(w):,} attacks",
                va="center", ha="left", fontsize=9, fontweight="bold", color="#1E293B")

    ax.set_title("Top 10 Persistent Malicious Client IP Addresses", fontsize=12, fontweight="bold", pad=12)
    ax.set_xlabel("Attack Event Volume", fontsize=10)
    ax.set_ylabel("Client IP Address", fontsize=10)
    ax.set_xlim(0, max(top10["attack_count"]) * 1.25)
    ax.grid(True, axis="x", linestyle="--", alpha=0.7)
    plt.tight_layout()
    p2_path = PLOTS_DIR / "02_top10_attacking_ips.png"
    plt.savefig(p2_path)
    plt.close()
    print(f"  * Saved Static PNG      : {p2_path.name}")

    # 2. Interactive Plotly Bar Chart
    fig_plotly = px.bar(
        top10.iloc[::-1], x="client_ip", y="attack_count",
        title="Top 10 Malicious Client IPs",
        labels={"client_ip": "Client IP", "attack_count": "Attacks"},
        color="attack_count", color_continuous_scale="Reds"
    )
    fig_plotly.update_layout(template="plotly_white")
    p2_html = INTERACTIVE_DIR / "02_top10_attacking_ips.html"
    fig_plotly.write_html(str(p2_html))
    print(f"  * Saved Interactive HTML: {p2_html.name}")

    return top10


# -----------------------------------------------------------------------------
# STEP 4: PLOT 3 — ATTACK CATEGORIES OVER TIME (TEMPORAL DYNAMICS)
# -----------------------------------------------------------------------------
def plot_attack_categories_over_time(df: pd.DataFrame) -> pd.DataFrame:
    """Plots temporal evolution of specific attack categories (Seaborn + Plotly)."""
    print("\n[Plot 3] Generating Attack Categories over Time Visualizations...")

    df_ts = df.dropna(subset=["datetime_utc"]).copy()
    attacks_only = df_ts[df_ts["label"] != "benign"]
    
    # Resample 2-hour bins per attack class
    temporal_cats = attacks_only.groupby([pd.Grouper(key="datetime_utc", freq="2h"), "label"])["line_number"].count().unstack(fill_value=0)

    # 1. Static Seaborn Multi-Line Plot
    fig, ax = plt.subplots(figsize=(12, 5.5), dpi=150)
    colors = plt.cm.tab10(np.linspace(0, 1, len(temporal_cats.columns)))
    for i, col in enumerate(temporal_cats.columns):
        ax.plot(temporal_cats.index, temporal_cats[col], label=col, linewidth=1.8, color=colors[i])

    ax.set_title("Temporal Dynamics of Web Threat Vectors over Time (2-Hour Intervals)", fontsize=12, fontweight="bold", pad=12)
    ax.set_ylabel("Attacks / Interval", fontsize=10)
    ax.set_xlabel("Time (UTC)", fontsize=10)
    ax.legend(bbox_to_anchor=(1.02, 1), loc="upper left", frameon=True, facecolor="#FFFFFF", fontsize=9)
    ax.grid(True, linestyle="--", alpha=0.7)
    plt.tight_layout()
    p3_path = PLOTS_DIR / "03_attack_categories_over_time.png"
    plt.savefig(p3_path)
    plt.close()
    print(f"  * Saved Static PNG      : {p3_path.name}")

    # 2. Interactive Plotly Line Plot
    fig_plotly = px.line(
        temporal_cats.reset_index().melt(id_vars="datetime_utc", var_name="Attack_Vector", value_name="Count"),
        x="datetime_utc", y="Count", color="Attack_Vector",
        title="Interactive Multi-Vector Attack Dynamics Over Time",
        labels={"datetime_utc": "Time (UTC)", "Count": "Incident Count"}
    )
    fig_plotly.update_layout(template="plotly_white")
    p3_html = INTERACTIVE_DIR / "03_attack_categories_over_time.html"
    fig_plotly.write_html(str(p3_html))
    print(f"  * Saved Interactive HTML: {p3_html.name}")

    return temporal_cats


# -----------------------------------------------------------------------------
# STEP 5: PLOT 4 — STATUS CODE DISTRIBUTIONS (HTTP FEEDBACK)
# -----------------------------------------------------------------------------
def plot_status_code_distribution(df: pd.DataFrame) -> pd.DataFrame:
    """Plots HTTP status code frequencies and class breakdown (Matplotlib/Seaborn)."""
    print("\n[Plot 4] Generating Status Code Distribution Visualizations...")

    status_counts = df["status_code"].value_counts().reset_index()
    status_counts.columns = ["status_code", "count"]
    status_counts["status_str"] = status_counts["status_code"].astype(str)

    # 1. Static Dual Plot (Bar Chart + Donut Chart)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.8), dpi=150)

    # Bar chart
    head_status = status_counts.head(8).copy()
    palette = ["#10B981" if s < 300 else "#F59E0B" if s < 400 else "#EF4444" for s in head_status["status_code"]]
    sns.barplot(data=head_status, x="status_str", y="count", hue="status_str", palette=palette, legend=False, ax=ax1, edgecolor="#1E293B")
    for p in ax1.patches:
        ax1.text(p.get_x() + p.get_width()/2, p.get_height() + 2000, f"{int(p.get_height()):,}",
                 ha="center", va="bottom", fontsize=8.5, fontweight="bold")
    ax1.set_title("HTTP Response Status Code Frequencies", fontsize=11, fontweight="bold")
    ax1.set_xlabel("Status Code")
    ax1.set_ylabel("Count")
    ax1.grid(True, axis="y", linestyle="--", alpha=0.7)

    # Donut Chart by Status Class (2xx, 3xx, 4xx, 5xx)
    df_copy = df.copy()
    df_copy["status_group"] = (df_copy["status_code"] // 100).astype(str) + "xx"
    group_counts = df_copy["status_group"].value_counts()
    group_colors = {"2xx": "#10B981", "3xx": "#3B82F6", "4xx": "#F59E0B", "5xx": "#EF4444"}
    c_list = [group_colors.get(g, "#94A3B8") for g in group_counts.index]

    wedges, texts, autotexts = ax2.pie(
        group_counts, labels=group_counts.index, autopct="%1.1f%%",
        colors=c_list, startangle=140, pctdistance=0.75,
        wedgeprops=dict(width=0.45, edgecolor="#FFFFFF", linewidth=2)
    )
    plt.setp(autotexts, size=9, weight="bold")
    ax2.set_title("HTTP Status Code Family Distribution", fontsize=11, fontweight="bold")

    plt.tight_layout()
    p4_path = PLOTS_DIR / "04_status_code_distribution.png"
    plt.savefig(p4_path)
    plt.close()
    print(f"  * Saved Static PNG      : {p4_path.name}")

    # 2. Interactive Plotly Pie Chart
    fig_plotly = px.pie(
        group_counts.reset_index(), names="status_group", values="count",
        title="Interactive HTTP Status Class Distribution",
        color="status_group", color_discrete_map=group_colors,
        hole=0.4
    )
    p4_html = INTERACTIVE_DIR / "04_status_code_distribution.html"
    fig_plotly.write_html(str(p4_html))
    print(f"  * Saved Interactive HTML: {p4_html.name}")

    return status_counts


# -----------------------------------------------------------------------------
# STEP 6: PLOT 5 — HEATMAP OF IP VS REQUEST TYPES (METHOD UTILIZATION)
# -----------------------------------------------------------------------------
def plot_ip_vs_request_type_heatmap(df: pd.DataFrame) -> pd.DataFrame:
    """Plots cross-tabulation heatmap for top 20 attacking IPs vs HTTP methods."""
    print("\n[Plot 5] Generating IP vs Request Type Crosstab Heatmap...")

    req_col = "request_method" if "request_method" in df.columns else "method"
    
    # Identify top 20 IPs by volume
    top_ips = df["client_ip"].value_counts().head(20).index
    df_top = df[df["client_ip"].isin(top_ips)]

    crosstab_ip_req = pd.crosstab(df_top["client_ip"], df_top[req_col])

    # 1. Static Seaborn Heatmap
    fig, ax = plt.subplots(figsize=(10, 7), dpi=150)
    sns.heatmap(crosstab_ip_req, annot=True, fmt="d", cmap="YlOrRd", ax=ax, cbar_kws={"label": "Request Count"}, linewidths=0.5)
    ax.set_title("Cross-Tabulation Matrix: Top 20 Client IPs vs HTTP Request Methods", fontsize=12, fontweight="bold", pad=12)
    ax.set_xlabel("HTTP Request Method", fontsize=10)
    ax.set_ylabel("Client IP Address", fontsize=10)
    plt.tight_layout()
    p5_path = PLOTS_DIR / "05_ip_vs_request_type_heatmap.png"
    plt.savefig(p5_path)
    plt.close()
    print(f"  * Saved Static PNG      : {p5_path.name}")

    # 2. Interactive Plotly Heatmap
    fig_plotly = px.imshow(
        crosstab_ip_req,
        labels=dict(x="Request Method", y="Client IP", color="Count"),
        x=crosstab_ip_req.columns,
        y=crosstab_ip_req.index,
        color_continuous_scale="Reds",
        title="Interactive Top 20 Client IPs vs HTTP Methods Heatmap"
    )
    fig_plotly.update_layout(template="plotly_white")
    p5_html = INTERACTIVE_DIR / "05_ip_vs_request_type_heatmap.html"
    fig_plotly.write_html(str(p5_html))
    print(f"  * Saved Interactive HTML: {p5_html.name}")

    return crosstab_ip_req


# -----------------------------------------------------------------------------
# STEP 7: ADDITIONAL EDA PLOTS (CLASS DISTRIBUTION & FEATURE CORRELATION)
# -----------------------------------------------------------------------------
def plot_additional_eda(df: pd.DataFrame) -> None:
    """Generates attack category distribution bar chart and feature correlation matrix."""
    print("\n[Additional EDA] Generating Attack Distribution & Feature Correlation Plots...")

    # Plot 6: Attack Class Distribution
    fig, ax = plt.subplots(figsize=(10, 5), dpi=150)
    counts = df["label"].value_counts()
    colors = ["#10B981" if c == "benign" else "#EF4444" for c in counts.index]
    sns.barplot(x=counts.values, y=counts.index, hue=counts.index, palette=colors, legend=False, ax=ax, edgecolor="#1E293B")
    for p in ax.patches:
        w = p.get_width()
        ax.text(w + 200, p.get_y() + p.get_height()/2, f"{int(w):,}",
                va="center", ha="left", fontsize=9, fontweight="bold")
    ax.set_title("Balanced Cybersecurity Dataset: 11-Class Representation", fontsize=12, fontweight="bold", pad=12)
    ax.set_xlabel("Record Count", fontsize=10)
    ax.set_xlim(0, max(counts.values) * 1.15)
    ax.grid(True, axis="x", linestyle="--", alpha=0.7)
    plt.tight_layout()
    p6_path = PLOTS_DIR / "06_attack_class_distribution.png"
    plt.savefig(p6_path)
    plt.close()
    print(f"  * Saved Static PNG      : {p6_path.name}")

    # Plot 7: Feature Correlation Matrix
    key_features = [
        "url_length", "url_entropy", "payload_length", "payload_entropy",
        "special_char_ratio", "inter_request_time", "requests_per_ip_1min",
        "user_agent_entropy", "failed_login_count", "anomaly_score"
    ]
    avail_cols = [c for c in key_features if c in df.columns]
    if len(avail_cols) >= 5:
        corr = df[avail_cols].corr()
        fig, ax = plt.subplots(figsize=(9, 7), dpi=150)
        sns.heatmap(corr, annot=True, fmt=".2f", cmap="coolwarm", vmin=-1, vmax=1, ax=ax, linewidths=0.5, cbar_kws={"label": "Pearson Correlation"})
        ax.set_title("Pearson Cross-Correlation Matrix of Canonical Security Features", fontsize=11, fontweight="bold", pad=12)
        plt.tight_layout()
        p7_path = PLOTS_DIR / "07_feature_correlation_heatmap.png"
        plt.savefig(p7_path)
        plt.close()
        print(f"  * Saved Static PNG      : {p7_path.name}")


# -----------------------------------------------------------------------------
# STEP 8: TECHNICAL AUDIT REPORTS
# -----------------------------------------------------------------------------
def generate_eda_reports(df: pd.DataFrame, hourly: pd.DataFrame, top10: pd.DataFrame) -> None:
    """Compiles the EDA findings and technical summary reports."""
    print("\n[Step 8] Compiling Practical 8 Technical EDA Audit Reports...")

    rep_file = REPORTS_DIR / "visualization_report.txt"
    with open(rep_file, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("   PRACTICAL 8: DATA VISUALIZATION AND EDA TECHNICAL REPORT\n")
        f.write("=" * 80 + "\n\n")
        f.write("Course         : Python for Data Science (BE05000231_PDS)\n")
        f.write(f"Execution Date : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        f.write("-" * 80 + "\n")
        f.write("1. DATASET VISUALIZATION AUDIT\n")
        f.write("-" * 80 + "\n")
        f.write(f"Total Telemetry Records Analyzed : {len(df):,}\n")
        f.write(f"Total Unique Client IPs          : {df['client_ip'].nunique():,}\n")
        f.write(f"Total Multi-Class Attack Vectors : {df['label'].nunique()}\n")
        f.write(f"Peak Hourly Traffic Arrival Rate : {int(hourly['total_requests'].max()):,} requests/hour\n")
        f.write(f"Peak Hourly Attack Volume        : {int(hourly['attacks'].max()):,} attacks/hour\n\n")

        f.write("-" * 80 + "\n")
        f.write("2. TOP 10 ATTACKING IPS (IDENTIFIED THREAT ACTORS)\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'Client IP Address':<22} | {'Attacks Executed':<18} | {'Total Hits':<12}\n")
        f.write("-" * 80 + "\n")
        for _, r in top10.iloc[::-1].iterrows():
            f.write(f"{r['client_ip']:<22} | {int(r['attack_count']):>18,} | {int(r['total_requests']):>12,}\n")
        f.write("-" * 80 + "\n\n")

        f.write("-" * 80 + "\n")
        f.write("3. GENERATED VISUALIZATION ARTIFACTS INVENTORY\n")
        f.write("-" * 80 + "\n")
        f.write("Static High-Resolution PNG Plots (outputs/plots/):\n")
        f.write("  * 01_requests_per_hour.png\n")
        f.write("  * 02_top10_attacking_ips.png\n")
        f.write("  * 03_attack_categories_over_time.png\n")
        f.write("  * 04_status_code_distribution.png\n")
        f.write("  * 05_ip_vs_request_type_heatmap.png\n")
        f.write("  * 06_attack_class_distribution.png\n")
        f.write("  * 07_feature_correlation_heatmap.png\n\n")

        f.write("Interactive Plotly Dashboards (outputs/interactive/):\n")
        f.write("  * 01_requests_per_hour.html\n")
        f.write("  * 02_top10_attacking_ips.html\n")
        f.write("  * 03_attack_categories_over_time.html\n")
        f.write("  * 04_status_code_distribution.html\n")
        f.write("  * 05_ip_vs_request_type_heatmap.html\n\n")

        f.write("=" * 80 + "\n")
        f.write("END OF PRACTICAL 8 VISUALIZATION REPORT\n")
        f.write("=" * 80 + "\n")

    print(f"  * Report Saved: {rep_file.name}")


# -----------------------------------------------------------------------------
# MAIN PIPELINE
# -----------------------------------------------------------------------------
def main():
    t_start = time.time()
    df = load_and_inspect_data()
    hourly = plot_requests_per_hour(df)
    top10 = plot_top10_attacking_ips(df)
    plot_attack_categories_over_time(df)
    plot_status_code_distribution(df)
    plot_ip_vs_request_type_heatmap(df)
    plot_additional_eda(df)
    generate_eda_reports(df, hourly, top10)

    total_time = round(time.time() - t_start, 2)
    print("\n" + "=" * 75)
    print(f"   PRACTICAL 8 COMPLETED IN {total_time} SECONDS!")
    print("   ALL VISUALIZATIONS & EDA REPORTS READY FOR PRACTICAL 9")
    print("=" * 75)


if __name__ == "__main__":
    main()
