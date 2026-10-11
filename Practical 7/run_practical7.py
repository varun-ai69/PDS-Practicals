"""
run_practical7.py
=================
Practical 7: Data Wrangling for Aggregated Analysis on Balanced Cybersecurity Dataset.
Course: Python for Data Science (BE05000231_PDS) - 5th Semester B.E./B.Tech

Objective:
----------
Aggregate and reshape balanced cybersecurity telemetry for deeper operational security insights:
1. Group by client IP to analyze attack frequency and identify top threat actors.
2. Perform time-series resampling (hourly and daily traffic patterns).
3. Construct pivot tables cross-tabulating request types (GET, POST, etc.) by attack labels.
4. Filter out automated bots/crawlers and RFC 1918 / loopback internal IP noise.
5. Export wrangled and filtered datasets in CSV and Snappy-compressed Parquet.
6. Generate 4 publication-quality diagnostic plots and a comprehensive technical audit report.
"""

import os
import sys
import time
import datetime
import ipaddress
from pathlib import Path
from typing import Dict, Tuple, List, Any

# Ensure live unbuffered logging
sys.stdout.reconfigure(line_buffering=True)

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# -----------------------------------------------------------------------------
# DIRECTORY RESOLUTION & CONFIGURATION
# -----------------------------------------------------------------------------
PRACTICAL7_DIR = Path(__file__).resolve().parent
WORKSPACE_DIR = PRACTICAL7_DIR.parent
PRACTICAL6_PROCESSED = WORKSPACE_DIR / "Practical 6" / "data" / "processed"

# Inputs from Practical 6
PRIMARY_INPUT_PQ = PRACTICAL6_PROCESSED / "balanced_training_dataset.parquet"
PRIMARY_INPUT_CSV = PRACTICAL6_PROCESSED / "balanced_training_dataset.csv"

# Practical 7 Directories
PROCESSED_DIR = PRACTICAL7_DIR / "data" / "processed"
OUTPUTS_DIR = PRACTICAL7_DIR / "outputs"
AGGREGATED_DIR = OUTPUTS_DIR / "aggregated"
FILTERED_AGG_DIR = AGGREGATED_DIR / "filtered"
PLOTS_DIR = OUTPUTS_DIR / "plots"
REPORTS_DIR = OUTPUTS_DIR / "reports"

PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
AGGREGATED_DIR.mkdir(parents=True, exist_ok=True)
FILTERED_AGG_DIR.mkdir(parents=True, exist_ok=True)
PLOTS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Bot signatures for User-Agent filtering
BOT_KEYWORDS = ["bot", "crawler", "spider", "slurp", "wget", "curl", "python-requests", "aiohttp", "headless", "nikto", "sqlmap", "nmap"]


# -----------------------------------------------------------------------------
# STEP 1: INGESTION & SCHEMA INTEGRITY AUDIT
# -----------------------------------------------------------------------------
def load_and_audit_dataset() -> pd.DataFrame:
    """Ingests the balanced training dataset from Practical 6 and verifies datetime parsing."""
    print("=" * 75)
    print("   PRACTICAL 7: DATA WRANGLING FOR AGGREGATED ANALYSIS")
    print("=" * 75)

    if PRIMARY_INPUT_PQ.exists():
        print(f"[Ingestion] Loading columnar Parquet: {PRIMARY_INPUT_PQ.name}...")
        df = pd.read_parquet(PRIMARY_INPUT_PQ)
    elif PRIMARY_INPUT_CSV.exists():
        print(f"[Ingestion] Loading CSV fallback: {PRIMARY_INPUT_CSV.name}...")
        df = pd.read_csv(PRIMARY_INPUT_CSV)
    else:
        raise FileNotFoundError(f"Practical 6 balanced dataset not found at {PRACTICAL6_PROCESSED}")

    print(f"  * Ingested: {len(df):,} records, {len(df.columns)} columns")
    
    # Ensure datetime conversion
    df["datetime_utc"] = pd.to_datetime(df["datetime_utc"], errors="coerce")
    if "is_attack" not in df.columns:
        df["is_attack"] = (df["label"] != "benign").astype(np.int8)

    print(f"  * Valid Datetime Records : {df['datetime_utc'].notnull().sum():,} / {len(df):,}")
    print(f"  * Unique Client IPs      : {df['client_ip'].nunique():,}")
    print(f"  * Classes Present        : {df['label'].nunique()} classes (balanced at {len(df)//df['label'].nunique():,} / class)")

    return df


# -----------------------------------------------------------------------------
# STEP 2: GROUP BY CLIENT IP — ATTACK FREQUENCY & THREAT ACTORS
# -----------------------------------------------------------------------------
def analyze_ip_attack_frequency(df: pd.DataFrame, out_dir: Path = AGGREGATED_DIR) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Computes per-IP request volumes, attack counts, attack ratios, and threat matrices."""
    print("\n[Step 2] Grouping by Client IP for Attack Frequency Analysis...")

    grouped = df.groupby("client_ip")
    ip_stats = grouped.agg(
        total_requests=("line_number", "count"),
        attack_count=("is_attack", "sum"),
        benign_count=("is_attack", lambda s: int(np.sum(s == 0))),
        mean_anomaly_score=("anomaly_score", "mean"),
        max_anomaly_score=("anomaly_score", "max"),
        first_seen=("datetime_utc", "min"),
        last_seen=("datetime_utc", "max")
    ).reset_index()

    ip_stats["attack_ratio"] = (ip_stats["attack_count"] / ip_stats["total_requests"]).round(4)
    ip_stats.sort_values(by=["attack_count", "total_requests"], ascending=False, inplace=True)

    # Top attacking IPs (minimum 1 attack)
    top_attackers = ip_stats[ip_stats["attack_count"] > 0].head(20).copy()

    # IP x Attack Label Crosstab Matrix
    ip_label_matrix = pd.crosstab(df["client_ip"], df["label"])

    # Export to CSV
    ip_stats_csv = out_dir / "ip_attack_frequency.csv"
    top_ips_csv = out_dir / "top_attack_ips.csv"
    matrix_csv = out_dir / "ip_attack_type_matrix.csv"

    ip_stats.to_csv(ip_stats_csv, index=False)
    top_attackers.to_csv(top_ips_csv, index=False)
    ip_label_matrix.to_csv(matrix_csv)

    print(f"  * Analyzed: {len(ip_stats):,} unique IPs")
    print(f"  * Top Threat IP: {top_attackers.iloc[0]['client_ip']} ({int(top_attackers.iloc[0]['attack_count']):,} attacks)")
    print(f"  * Saved IP Frequency CSV : {ip_stats_csv.name}")
    print(f"  * Saved Top Attackers CSV: {top_ips_csv.name}")
    print(f"  * Saved IP Crosstab CSV  : {matrix_csv.name}")

    return ip_stats, top_attackers, ip_label_matrix


# -----------------------------------------------------------------------------
# STEP 3: TIME-SERIES RESAMPLING (HOURLY & DAILY INTERVALS)
# -----------------------------------------------------------------------------
def resample_time_series(df: pd.DataFrame, out_dir: Path = AGGREGATED_DIR) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Resamples log telemetry into hourly and daily time-series bins."""
    print("\n[Step 3] Performing Time-Series Resampling (Hourly & Daily Intervals)...")

    df_ts = df.dropna(subset=["datetime_utc"]).sort_values("datetime_utc").set_index("datetime_utc")

    # 1. Hourly Resampling
    hourly_agg = df_ts.resample("1h").agg(
        total_requests=("line_number", "count"),
        attacks=("is_attack", "sum"),
        benign=("is_attack", lambda s: int(np.sum(s == 0))),
        mean_anomaly_score=("anomaly_score", "mean")
    ).reset_index()
    hourly_agg["attack_rate"] = (hourly_agg["attacks"] / hourly_agg["total_requests"].clip(lower=1)).round(4)

    # 2. Daily Resampling
    daily_agg = df_ts.resample("1D").agg(
        total_requests=("line_number", "count"),
        attacks=("is_attack", "sum"),
        benign=("is_attack", lambda s: int(np.sum(s == 0))),
        unique_ips=("client_ip", "nunique"),
        mean_anomaly_score=("anomaly_score", "mean")
    ).reset_index()
    daily_agg["attack_rate"] = (daily_agg["attacks"] / daily_agg["total_requests"].clip(lower=1)).round(4)

    # 3. Daily Attack Type Breakdown
    daily_labels = df_ts.groupby([pd.Grouper(freq="1D"), "label"])["line_number"].count().unstack(fill_value=0).reset_index()

    # Exports
    h_csv = out_dir / "hourly_traffic.csv"
    d_csv = out_dir / "daily_traffic.csv"
    d_label_csv = out_dir / "daily_attack_types.csv"

    hourly_agg.to_csv(h_csv, index=False)
    daily_agg.to_csv(d_csv, index=False)
    daily_labels.to_csv(d_label_csv, index=False)

    print(f"  * Hourly Bins Generated  : {len(hourly_agg):,} intervals ({h_csv.name})")
    print(f"  * Daily Bins Generated   : {len(daily_agg):,} intervals ({d_csv.name})")
    print(f"  * Daily Attack Matrix    : {len(daily_labels):,} intervals ({d_label_csv.name})")

    return hourly_agg, daily_agg, daily_labels


# -----------------------------------------------------------------------------
# STEP 4: PIVOT TABLES — REQUEST METHOD & STATUS CODE CROSS-TABULATION
# -----------------------------------------------------------------------------
def construct_pivot_tables(df: pd.DataFrame, out_dir: Path = AGGREGATED_DIR) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Generates pivot tables cross-tabulating request types and status codes by attack labels."""
    print("\n[Step 4] Generating Multi-Dimensional Pivot Tables...")

    # 1. Request Method x Attack Label Pivot
    req_col = "request_method" if "request_method" in df.columns else "method"
    pivot_req = pd.pivot_table(
        df,
        index=req_col,
        columns="label",
        values="line_number",
        aggfunc="count",
        fill_value=0
    )
    pivot_req["Total"] = pivot_req.sum(axis=1)

    # 2. Status Code x Attack Label Pivot
    pivot_status = pd.pivot_table(
        df,
        index="status_code",
        columns="label",
        values="line_number",
        aggfunc="count",
        fill_value=0
    )
    pivot_status["Total"] = pivot_status.sum(axis=1)

    # Exports
    p_req_csv = out_dir / "request_type_label_pivot.csv"
    p_status_csv = out_dir / "status_code_label_pivot.csv"

    pivot_req.to_csv(p_req_csv)
    pivot_status.to_csv(p_status_csv)

    print(f"  * Request Method Pivot Saved: {p_req_csv.name}")
    print(f"  * Status Code Pivot Saved   : {p_status_csv.name}")

    return pivot_req, pivot_status


# -----------------------------------------------------------------------------
# STEP 5: BOT & INTERNAL IP FILTERING PIPELINE
# -----------------------------------------------------------------------------
def is_internal_ipv4(ip_str: str) -> bool:
    """Checks if an IPv4 address belongs to RFC 1918 private, loopback, or link-local ranges."""
    try:
        ip_obj = ipaddress.ip_address(str(ip_str).strip())
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False


def is_bot_user_agent(ua_str: str) -> bool:
    """Detects automated bots, web crawlers, and scrapers in User-Agent header."""
    ua_lower = str(ua_str).lower()
    return any(k in ua_lower for k in BOT_KEYWORDS)


def execute_filtering_pipeline(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Applies User-Agent bot filtering and RFC 1918 internal IP filtering."""
    print("\n[Step 5] Filtering Automated Bots and RFC 1918 / Loopback Internal IPs...")

    total_records = len(df)

    # 1. Bot Mask
    bot_mask = df["user_agent"].apply(is_bot_user_agent)
    bot_count = int(bot_mask.sum())

    # 2. Internal IP Mask
    internal_mask = df["client_ip"].apply(is_internal_ipv4)
    internal_count = int(internal_mask.sum())

    # 3. Combined Filter (Remove bots AND internal IPs)
    exclude_mask = bot_mask | internal_mask
    filtered_df = df[~exclude_mask].copy().reset_index(drop=True)
    retained_records = len(filtered_df)
    filtered_out_records = total_records - retained_records

    filter_stats = {
        "total_records": total_records,
        "bot_records": bot_count,
        "bot_pct": round((bot_count / total_records) * 100, 2),
        "internal_ip_records": internal_count,
        "internal_ip_pct": round((internal_count / total_records) * 100, 2),
        "both_bot_and_internal": int((bot_mask & internal_mask).sum()),
        "total_filtered_out": filtered_out_records,
        "retained_records": retained_records,
        "retention_pct": round((retained_records / total_records) * 100, 2)
    }

    print(f"  * Automated Bot Records Filtered     : {filter_stats['bot_records']:,} ({filter_stats['bot_pct']}%)")
    print(f"  * RFC 1918 Internal IP Logs Filtered : {filter_stats['internal_ip_records']:,} ({filter_stats['internal_ip_pct']}%)")
    print(f"  * Total Discarded Operational Noise  : {filter_stats['total_filtered_out']:,}")
    print(f"  * Clean External Production Telemetry: {filter_stats['retained_records']:,} ({filter_stats['retention_pct']}%)")

    # Export clean filtered dataset
    out_csv = PROCESSED_DIR / "wrangled_filtered_dataset.csv"
    out_pq = PROCESSED_DIR / "wrangled_filtered_dataset.parquet"
    filtered_df.to_csv(out_csv, index=False)
    filtered_df.to_parquet(out_pq, index=False, compression="snappy")

    print(f"  * Exported wrangled_filtered_dataset.csv     : {out_csv.stat().st_size / (1024*1024):.2f} MB")
    print(f"  * Exported wrangled_filtered_dataset.parquet : {out_pq.stat().st_size / (1024*1024):.2f} MB")

    # Re-run key aggregations on filtered data
    print("  * Repeating aggregations on clean filtered telemetry...")
    analyze_ip_attack_frequency(filtered_df, out_dir=FILTERED_AGG_DIR)
    resample_time_series(filtered_df, out_dir=FILTERED_AGG_DIR)
    construct_pivot_tables(filtered_df, out_dir=FILTERED_AGG_DIR)

    return filtered_df, filter_stats


# -----------------------------------------------------------------------------
# STEP 6: PUBLICATION-QUALITY DIAGNOSTIC PLOTS
# -----------------------------------------------------------------------------
def generate_wrangling_plots(top_attackers: pd.DataFrame, hourly_df: pd.DataFrame, pivot_req: pd.DataFrame, filter_stats: Dict[str, Any]) -> None:
    """Generates 4 publication-quality plots illustrating wrangling insights."""
    print("\n[Step 6] Generating Publication-Quality Diagnostic Visualizations...")

    plt.rcParams.update({
        "font.family": "sans-serif",
        "axes.edgecolor": "#CBD5E1",
        "axes.linewidth": 1.2,
        "grid.color": "#E2E8F0",
        "grid.linestyle": "--",
        "grid.alpha": 0.7,
    })

    # Plot 1: Top 10 Attacking IPs Horizontal Bar Chart
    fig, ax = plt.subplots(figsize=(10, 5), dpi=150)
    top10 = top_attackers.head(10).iloc[::-1]  # Invert so top is on top
    bars = ax.barh(top10["client_ip"], top10["attack_count"], color="#DC2626", edgecolor="#7F1D1D", height=0.6)
    for bar in bars:
        w = bar.get_width()
        ax.text(w + 20, bar.get_y() + bar.get_height()/2, f"{int(w):,} attacks",
                va="center", ha="left", fontsize=9, fontweight="bold", color="#1E293B")

    ax.set_title("Top 10 High-Frequency Malicious Client IPs", fontsize=12, fontweight="bold", pad=12)
    ax.set_xlabel("Attack Event Volume", fontsize=10)
    ax.set_xlim(0, max(top10["attack_count"]) * 1.25)
    ax.grid(True, axis="x")
    plt.tight_layout()
    p1 = PLOTS_DIR / "ip_attack_frequency.png"
    plt.savefig(p1)
    plt.close()
    print(f"  * Generated: {p1.name}")

    # Plot 2: Hourly Traffic Time-Series with Attack Density
    fig, ax = plt.subplots(figsize=(12, 4.5), dpi=150)
    ax.plot(hourly_df["datetime_utc"], hourly_df["total_requests"], label="Total Traffic", color="#2563EB", linewidth=1.8)
    ax.plot(hourly_df["datetime_utc"], hourly_df["attacks"], label="Attack Traffic", color="#EF4444", linewidth=2.0)
    ax.fill_between(hourly_df["datetime_utc"], 0, hourly_df["attacks"], color="#EF4444", alpha=0.25)
    ax.set_title("Hourly Time-Series Resampling: Total Volume vs Malicious Surge", fontsize=12, fontweight="bold", pad=12)
    ax.set_ylabel("Requests / Hour", fontsize=10)
    ax.set_xlabel("Time (UTC)", fontsize=10)
    ax.legend(frameon=True, facecolor="#FFFFFF")
    ax.grid(True)
    plt.tight_layout()
    p2 = PLOTS_DIR / "hourly_traffic_timeseries.png"
    plt.savefig(p2)
    plt.close()
    print(f"  * Generated: {p2.name}")

    # Plot 3: Request Type by Attack Label Heatmap
    fig, ax = plt.subplots(figsize=(11, 4.5), dpi=150)
    sub_pivot = pivot_req.drop(columns=["Total"], errors="ignore")
    cax = ax.matshow(sub_pivot.values, cmap="YlOrRd")
    fig.colorbar(cax)

    ax.set_xticks(range(len(sub_pivot.columns)))
    ax.set_yticks(range(len(sub_pivot.index)))
    ax.set_xticklabels(sub_pivot.columns, rotation=35, ha="left", fontsize=8.5)
    ax.set_yticklabels(sub_pivot.index, fontsize=9.5)
    ax.set_title("Cross-Tabulation Matrix: Request Method vs Attack Vectors", fontsize=12, fontweight="bold", pad=20)
    plt.tight_layout()
    p3 = PLOTS_DIR / "request_type_by_label_pivot.png"
    plt.savefig(p3)
    plt.close()
    print(f"  * Generated: {p3.name}")

    # Plot 4: Waterfall Breakdown of Bot & Internal IP Filtering
    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=150)
    cats = ["Total Input", "Bots Discarded", "Internal IPs", "Clean Output"]
    vals = [
        filter_stats["total_records"],
        filter_stats["bot_records"],
        filter_stats["internal_ip_records"],
        filter_stats["retained_records"]
    ]
    colors = ["#3B82F6", "#EF4444", "#F59E0B", "#10B981"]
    bars = ax.bar(cats, vals, color=colors, edgecolor="#0F172A", width=0.55)
    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, h + 2500, f"{int(h):,}",
                ha="center", va="bottom", fontsize=9, fontweight="bold", color="#1E293B")

    ax.set_title("Operational Telemetry Filtering: Bots & Internal IP Exclusions", fontsize=12, fontweight="bold", pad=12)
    ax.set_ylabel("Record Volume", fontsize=10)
    ax.set_ylim(0, max(vals) * 1.15)
    ax.grid(True, axis="y")
    plt.tight_layout()
    p4 = PLOTS_DIR / "bot_and_internal_ip_filtering.png"
    plt.savefig(p4)
    plt.close()
    print(f"  * Generated: {p4.name}")


# -----------------------------------------------------------------------------
# STEP 7: COMPREHENSIVE TECHNICAL AUDIT REPORT
# -----------------------------------------------------------------------------
def generate_wrangling_reports(df: pd.DataFrame, top_attackers: pd.DataFrame, hourly_df: pd.DataFrame, filter_stats: Dict[str, Any]) -> None:
    """Compiles the final technical report for Practical 7."""
    print("\n[Step 7] Compiling Practical 7 Wrangling Audit Report...")

    rep_file = REPORTS_DIR / "wrangling_report.txt"
    with open(rep_file, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("   PRACTICAL 7: DATA WRANGLING FOR AGGREGATED ANALYSIS REPORT\n")
        f.write("=" * 80 + "\n\n")
        f.write("Course         : Python for Data Science (BE05000231_PDS)\n")
        f.write(f"Execution Date : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        f.write("-" * 80 + "\n")
        f.write("1. INGESTION & DATASET INTEGRITY AUDIT\n")
        f.write("-" * 80 + "\n")
        f.write("Input Ingestion Path       : Practical 6/data/processed/balanced_training_dataset.parquet\n")
        f.write(f"Total Balanced Records     : {filter_stats['total_records']:,}\n")
        f.write(f"Input Class Balancing      : Perfectly equalized across all {df['label'].nunique()} classes ({len(df)//df['label'].nunique():,} / class)\n\n")

        f.write("-" * 80 + "\n")
        f.write("2. CLIENT IP ATTACK FREQUENCY AUDIT (TOP THREAT ACTORS)\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'Client IP Address':<20} | {'Total Hits':<12} | {'Attacks':<10} | {'Attack Rate':<12} | {'Mean Anomaly':<12}\n")
        f.write("-" * 80 + "\n")
        for _, r in top_attackers.head(10).iterrows():
            f.write(f"{r['client_ip']:<20} | {int(r['total_requests']):>10,} | {int(r['attack_count']):>8,} | {r['attack_ratio']*100:>10.2f}% | {r['mean_anomaly_score']:>12.4f}\n")
        f.write("-" * 80 + "\n\n")

        f.write("-" * 80 + "\n")
        f.write("3. TIME-SERIES RESAMPLING AUDIT\n")
        f.write("-" * 80 + "\n")
        f.write(f"Hourly Bins Resampled      : {len(hourly_df):,} intervals (outputs/aggregated/hourly_traffic.csv)\n")
        f.write(f"Peak Hourly Traffic Volume : {int(hourly_df['total_requests'].max()):,} requests/hour\n")
        f.write(f"Peak Hourly Attack Volume  : {int(hourly_df['attacks'].max()):,} attacks/hour\n\n")

        f.write("-" * 80 + "\n")
        f.write("4. BOT & RFC 1918 INTERNAL IP FILTERING AUDIT\n")
        f.write("-" * 80 + "\n")
        f.write(f"Total Records Before Filter: {filter_stats['total_records']:,}\n")
        f.write(f"Automated Bots Excluded    : {filter_stats['bot_records']:,} ({filter_stats['bot_pct']}%)\n")
        f.write(f"Internal RFC 1918 Excluded : {filter_stats['internal_ip_records']:,} ({filter_stats['internal_ip_pct']}%)\n")
        f.write(f"Clean Operational Telemetry: {filter_stats['retained_records']:,} ({filter_stats['retention_pct']}%)\n")
        f.write("Clean Filtered Export Path : Practical 7/data/processed/wrangled_filtered_dataset.csv\n\n")

        f.write("=" * 80 + "\n")
        f.write("END OF PRACTICAL 7 WRANGLING REPORT\n")
        f.write("=" * 80 + "\n")

    print(f"  * Report Saved: {rep_file.name}")


# -----------------------------------------------------------------------------
# MAIN PIPELINE
# -----------------------------------------------------------------------------
def main():
    t_start = time.time()
    df = load_and_audit_dataset()
    ip_stats, top_attackers, ip_label_matrix = analyze_ip_attack_frequency(df)
    hourly_df, daily_df, daily_labels = resample_time_series(df)
    pivot_req, pivot_status = construct_pivot_tables(df)
    filtered_df, filter_stats = execute_filtering_pipeline(df)
    generate_wrangling_plots(top_attackers, hourly_df, pivot_req, filter_stats)
    generate_wrangling_reports(df, top_attackers, hourly_df, filter_stats)

    total_time = round(time.time() - t_start, 2)
    print("\n" + "=" * 75)
    print(f"   PRACTICAL 7 COMPLETED IN {total_time} SECONDS!")
    print("   WRANGLED TELEMETRY READY FOR PRACTICAL 8 EDA")
    print("=" * 75)


if __name__ == "__main__":
    main()
