"""
run_practical4.py
=================
Practical 4: Basic Attack Classification Using Calibrated Heuristic Engine.
Course: Python for Data Science (BE05000231_PDS) - 5th Semester B.E./B.Tech

Objective:
----------
Assign high-precision, ground-truth multi-class attack labels and human-readable
diagnostic attributions to preprocessed server access logs using a calibrated
heuristic classification engine.
1. Ingest clean tabular logs from Practical 3 (preprocessed_logs.csv).
2. Calculate temporal inter-request deltas per client IP.
3. Classify each record across 10 discrete attack classes + benign.
4. Assign severity ratings (CRITICAL, HIGH, MEDIUM, LOW, INFO) and label reasons.
5. Export labeled datasets to CSV and Snappy-compressed Parquet.
6. Benchmark on external real-world dataset (Elastic official production logs).
7. Generate publication-quality diagnostic plots and audit reports.
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

# -----------------------------------------------------------------------------
# DIRECTORY RESOLUTION & MODULE IMPORT
# -----------------------------------------------------------------------------
PRACTICAL4_DIR = Path(__file__).resolve().parent
WORKSPACE_DIR = PRACTICAL4_DIR.parent
PRACTICAL3_PROCESSED = WORKSPACE_DIR / "Practical 3" / "data" / "processed"

# Import Master Heuristic Engine
sys.path.insert(0, str(WORKSPACE_DIR))
from src.pipeline.heuristic_engine import HeuristicLabeler

# Input Files from Practical 3
PRIMARY_INPUT_CSV = PRACTICAL3_PROCESSED / "preprocessed_logs.csv"
EXTERNAL_INPUT_CSV = PRACTICAL3_PROCESSED / "elastic_preprocessed_logs.csv"

# Fallback to local data/raw if running standalone
if not PRIMARY_INPUT_CSV.exists():
    PRIMARY_INPUT_CSV = PRACTICAL4_DIR / "data" / "raw" / "preprocessed_logs.csv"
if not EXTERNAL_INPUT_CSV.exists():
    EXTERNAL_INPUT_CSV = PRACTICAL4_DIR / "data" / "raw" / "elastic_preprocessed_logs.csv"

# Outputs for Practical 4
PROCESSED_DIR = PRACTICAL4_DIR / "data" / "processed"
OUTPUTS_DIR = PRACTICAL4_DIR / "outputs"
PLOTS_DIR = OUTPUTS_DIR / "plots"
REPORTS_DIR = OUTPUTS_DIR / "reports"

PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
PLOTS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# -----------------------------------------------------------------------------
# SEVERITY MAPPING FOR ENTERPRISE SIEM / SOC INTEGRATION
# -----------------------------------------------------------------------------
SEVERITY_MAP = {
    "command_injection": "CRITICAL",
    "web_shell": "CRITICAL",
    "sqli": "HIGH",
    "xss": "HIGH",
    "ssrf": "HIGH",
    "ddos_http_flood": "HIGH",
    "path_traversal": "MEDIUM",
    "brute_force": "MEDIUM",
    "dir_fuzzing": "LOW",
    "mal_scanner": "LOW",
    "benign": "INFO"
}


# -----------------------------------------------------------------------------
# BATCH HEURISTIC CLASSIFICATION PIPELINE
# -----------------------------------------------------------------------------
def classify_dataset(df: pd.DataFrame, dataset_name: str = "Primary") -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Runs high-throughput, calibrated multi-class labeling on a preprocessed log DataFrame."""
    metrics = {
        "dataset_name": dataset_name,
        "total_rows": len(df),
    }
    
    t_start = time.time()
    print(f"[{dataset_name}] Computing inter-request temporal velocity per client IP...")
    
    # Ensure datetime format for velocity delta calculation
    df["_parsed_dt"] = pd.to_datetime(df["datetime_utc"], errors="coerce")
    inter_req_time = df.groupby("client_ip")["_parsed_dt"].diff().dt.total_seconds()
    df.drop(columns=["_parsed_dt"], inplace=True, errors="ignore")
    
    labeler = HeuristicLabeler()
    
    print(f"[{dataset_name}] Applying multi-class heuristic engine across {len(df):,} records...")
    labels: List[str] = []
    reasons: List[str] = []
    
    # Fast iteration over required attributes using zip
    resources = df["resource_requested"].tolist()
    methods = df["request_method"].astype(str).tolist()
    statuses = df["status_code"].astype(int).tolist()
    user_agents = df["user_agent"].astype(str).tolist()
    irts = inter_req_time.tolist()
    
    for res, meth, stat, ua, irt in zip(resources, methods, statuses, user_agents, irts):
        irt_val = irt if (irt is not None and not np.isnan(irt)) else None
        lbl, rsn = labeler.classify_single_request(
            resource=res,
            method=meth,
            status_code=stat,
            user_agent=ua,
            inter_request_time=irt_val
        )
        labels.append(lbl)
        reasons.append(rsn)
        
    df["label"] = pd.Series(labels, dtype="category")
    df["label_reason"] = reasons
    df["is_attack"] = (df["label"] != "benign").astype(np.int8)
    df["severity"] = pd.Series([SEVERITY_MAP.get(l, "INFO") for l in labels], dtype="category")
    
    elapsed = round(time.time() - t_start, 2)
    rps = round(len(df) / max(0.001, elapsed), 1)
    
    class_counts = df["label"].value_counts().to_dict()
    benign_cnt = int(class_counts.get("benign", 0))
    attack_cnt = len(df) - benign_cnt
    
    metrics["runtime_seconds"] = elapsed
    metrics["throughput_rps"] = rps
    metrics["class_counts"] = class_counts
    metrics["benign_count"] = benign_cnt
    metrics["attack_count"] = attack_cnt
    metrics["benign_pct"] = round((benign_cnt / len(df)) * 100, 2)
    metrics["attack_pct"] = round((attack_cnt / len(df)) * 100, 2)
    metrics["severity_counts"] = df["severity"].value_counts().to_dict()
    metrics["memory_mb"] = round(df.memory_usage(deep=True).sum() / (1024 * 1024), 2)
    
    return df, metrics


# -----------------------------------------------------------------------------
# PLOT GENERATION (PUBLICATION QUALITY)
# -----------------------------------------------------------------------------
def generate_classification_plots(df: pd.DataFrame, metrics: Dict[str, Any]) -> None:
    """Generates 4 high-resolution plots illustrating attack classification outcomes."""
    print("[Plots] Generating high-resolution diagnostic plots...")

    plt.rcParams.update({
        "font.family": "sans-serif",
        "axes.edgecolor": "#CBD5E1",
        "axes.linewidth": 1.2,
        "grid.color": "#E2E8F0",
        "grid.linestyle": "--",
        "grid.alpha": 0.7,
    })

    # Plot 1: Attack Class Distribution Bar Chart
    fig, ax = plt.subplots(figsize=(11, 5), dpi=150)
    c_counts = df["label"].value_counts()
    colors = [
        "#10B981" if c == "benign" else (
            "#EF4444" if SEVERITY_MAP.get(c) == "CRITICAL" else (
                "#F97316" if SEVERITY_MAP.get(c) == "HIGH" else (
                    "#FBBF24" if SEVERITY_MAP.get(c) == "MEDIUM" else "#3B82F6"
                )
            )
        )
        for c in c_counts.index
    ]
    
    bars = ax.barh(c_counts.index.astype(str), c_counts.values, color=colors, edgecolor="#0F172A")
    ax.set_title("Ground-Truth Multi-Class Classification Distribution", fontsize=13, fontweight="bold", pad=12)
    ax.set_xlabel("Record Count", fontsize=10)
    ax.invert_yaxis()
    ax.grid(True, axis="x")
    for b in bars:
        w = b.get_width()
        pct = (w / len(df)) * 100
        ax.text(w + 2000, b.get_y() + b.get_height()/2., f"{w:,} ({pct:.1f}%)", ha="left", va="center", fontsize=8, fontweight="bold")
    ax.set_xlim(0, max(c_counts.values) * 1.18)
    plt.tight_layout()
    p1 = PLOTS_DIR / "attack_class_distribution.png"
    plt.savefig(p1)
    plt.close()
    print(f"  * Generated: {p1.name}")

    # Plot 2: Benign vs Attack Ratio Donut Chart
    fig, ax = plt.subplots(figsize=(7, 5), dpi=150)
    ratios = [metrics["benign_count"], metrics["attack_count"]]
    labels = [f"Benign\n({metrics['benign_pct']}%)", f"Attacks\n({metrics['attack_pct']}%)"]
    colors = ["#10B981", "#EF4444"]
    
    wedges, texts, autotexts = ax.pie(
        ratios, labels=labels, autopct="%1.1f%%", colors=colors, startangle=140,
        textprops=dict(color="#0F172A", fontweight="bold", fontsize=10),
        wedgeprops=dict(width=0.42, edgecolor="#FFFFFF", linewidth=2)
    )
    ax.set_title("Macro Dataset Balance: Benign vs Malicious Web Traffic", fontsize=12, fontweight="bold")
    plt.tight_layout()
    p2 = PLOTS_DIR / "benign_vs_attack_ratio.png"
    plt.savefig(p2)
    plt.close()
    print(f"  * Generated: {p2.name}")

    # Plot 3: SIEM Severity Distribution
    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=150)
    sev_counts = df["severity"].value_counts()
    sev_colors = {"CRITICAL": "#991B1B", "HIGH": "#EF4444", "MEDIUM": "#F59E0B", "LOW": "#3B82F6", "INFO": "#10B981"}
    
    ax.bar(
        sev_counts.index.astype(str),
        sev_counts.values,
        color=[sev_colors.get(s, "#94A3B8") for s in sev_counts.index],
        width=0.55,
        edgecolor="#0F172A"
    )
    ax.set_title("Threat Severity Distribution (SOC Incident Response Priority)", fontsize=13, fontweight="bold", pad=12)
    ax.set_ylabel("Request Count", fontsize=10)
    ax.set_xlabel("Severity Level", fontsize=10)
    ax.grid(True, axis="y")
    plt.tight_layout()
    p3 = PLOTS_DIR / "attack_severity_distribution.png"
    plt.savefig(p3)
    plt.close()
    print(f"  * Generated: {p3.name}")

    # Plot 4: Hourly Attack Volume Timeline
    fig, ax = plt.subplots(figsize=(11, 4.5), dpi=150)
    df["dt_hour"] = pd.to_datetime(df["datetime_utc"]).dt.floor("h")
    hourly_attack = df[df["is_attack"] == 1]["dt_hour"].value_counts().sort_index()
    hourly_benign = df[df["is_attack"] == 0]["dt_hour"].value_counts().sort_index()
    
    ax.plot(hourly_benign.index, hourly_benign.values, label="Benign Traffic", color="#10B981", linewidth=1.8)
    ax.plot(hourly_attack.index, hourly_attack.values, label="Attack Traffic", color="#EF4444", linewidth=2.0)
    ax.set_title("Timeline Traffic Dynamics: Benign vs Attack Volume (Hourly UTC)", fontsize=13, fontweight="bold", pad=12)
    ax.set_ylabel("Requests / Hour", fontsize=10)
    ax.set_xlabel("Timeline (UTC)", fontsize=10)
    ax.legend(frameon=True, facecolor="#FFFFFF")
    ax.grid(True)
    plt.tight_layout()
    p4 = PLOTS_DIR / "attack_timeline_hourly.png"
    plt.savefig(p4)
    plt.close()
    print(f"  * Generated: {p4.name}")


# -----------------------------------------------------------------------------
# AUDIT REPORT GENERATOR
# -----------------------------------------------------------------------------
def generate_audit_report(primary_metrics: Dict[str, Any], ext_metrics: Dict[str, Any]) -> Path:
    """Generates a comprehensive scientific report of the classification pipeline."""
    report_file = REPORTS_DIR / "practical4_classification_report.txt"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("   PRACTICAL 4: HEURISTIC ATTACK CLASSIFICATION AUDIT REPORT\n")
        f.write("=" * 80 + "\n\n")
        f.write("Course         : Python for Data Science (BE05000231_PDS)\n")
        f.write(f"Execution Date : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        f.write("-" * 80 + "\n")
        f.write("1. PRIMARY ENTERPRISE DATASET CLASSIFICATION AUDIT (server_access.log)\n")
        f.write("-" * 80 + "\n")
        f.write(f"Source Input File        : preprocessed_logs.csv\n")
        f.write(f"Total Rows Classified    : {primary_metrics['total_rows']:,}\n")
        f.write(f"Classification Runtime   : {primary_metrics['runtime_seconds']} seconds ({primary_metrics['throughput_rps']:,.1f} rows/sec)\n")
        f.write(f"Macro Ratio              : {primary_metrics['benign_pct']}% Benign : {primary_metrics['attack_pct']}% Attack\n")
        f.write(f"Benign Requests          : {primary_metrics['benign_count']:,}\n")
        f.write(f"Malicious Requests       : {primary_metrics['attack_count']:,}\n")
        f.write(f"In-Memory Data Size      : {primary_metrics['memory_mb']} MB\n\n")

        f.write("Class-by-Class Breakdown (10 Attack Vectors + Benign):\n")
        for cls, count in primary_metrics["class_counts"].items():
            pct = (count / primary_metrics["total_rows"]) * 100
            sev = SEVERITY_MAP.get(cls, "INFO")
            f.write(f"  * {cls:<20}: {count:>8,} records ({pct:>5.2f}%) [{sev}]\n")

        f.write("\nSeverity Triage Summary:\n")
        for sev, count in primary_metrics["severity_counts"].items():
            pct = (count / primary_metrics["total_rows"]) * 100
            f.write(f"  * {sev:<10}: {count:>8,} records ({pct:>5.2f}%)\n")

        f.write("\n" + "-" * 80 + "\n")
        f.write("2. EXTERNAL PRODUCTION BENCHMARK AUDIT (Elastic Official Apache Logs)\n")
        f.write("-" * 80 + "\n")
        f.write(f"Source External File     : elastic_preprocessed_logs.csv\n")
        f.write(f"Total Lines Evaluated    : {ext_metrics['total_rows']:,}\n")
        f.write(f"Classification Runtime   : {ext_metrics['runtime_seconds']} seconds ({ext_metrics['throughput_rps']:,.1f} rows/sec)\n")
        f.write(f"Benign Requests Verified : {ext_metrics['benign_count']:,} ({ext_metrics['benign_pct']}%)\n")
        f.write(f"Attacks Identified       : {ext_metrics['attack_count']:,} ({ext_metrics['attack_pct']}%)\n")
        f.write(f"Attack Vectors Detected  : {ext_metrics['class_counts']}\n\n")

        f.write("=" * 80 + "\n")
        f.write("END OF PRACTICAL 4 CLASSIFICATION REPORT\n")
        f.write("=" * 80 + "\n")

    return report_file


# -----------------------------------------------------------------------------
# MAIN EXECUTION ROUTINE
# -----------------------------------------------------------------------------
def main():
    print("=" * 75)
    print("   PRACTICAL 4: HEURISTIC ATTACK CLASSIFICATION PIPELINE")
    print("=" * 75)

    if not PRIMARY_INPUT_CSV.exists():
        print(f"[Error] Primary input CSV not found at: {PRIMARY_INPUT_CSV}")
        print("Please run Practical 3 first to generate preprocessed_logs.csv.")
        sys.exit(1)

    # Step 1: Load Primary Preprocessed Dataset
    print(f"\n[Step 1] Ingesting Practical 3 Preprocessed Dataset: {PRIMARY_INPUT_CSV.name}...")
    df_primary = pd.read_csv(PRIMARY_INPUT_CSV)
    print(f"  * Ingested: {len(df_primary):,} rows, {len(df_primary.columns)} columns ({PRIMARY_INPUT_CSV.stat().st_size / (1024*1024):.2f} MB)")

    # Step 2: Classify Primary Dataset
    print("\n[Step 2] Executing Heuristic Classification on Primary Dataset...")
    df_primary_labeled, primary_metrics = classify_dataset(df_primary, dataset_name="Primary")

    # Step 3: Export Labeled Primary Dataset
    print("\n[Step 3] Exporting Labeled Datasets (CSV & Parquet)...")
    out_csv = PROCESSED_DIR / "labeled_logs.csv"
    out_pq = PROCESSED_DIR / "labeled_logs.parquet"

    df_primary_labeled.to_csv(out_csv, index=False)
    df_primary_labeled.to_parquet(out_pq, index=False, compression="snappy")
    print(f"  * Saved Labeled CSV     : {out_csv.name} ({out_csv.stat().st_size / (1024*1024):.2f} MB)")
    print(f"  * Saved Labeled Parquet : {out_pq.name} ({out_pq.stat().st_size / (1024*1024):.2f} MB)")

    # Step 4: Benchmark on External Dataset
    ext_metrics = {}
    if EXTERNAL_INPUT_CSV.exists():
        print(f"\n[Step 4] Benchmarking Heuristic Classifier on External Dataset: {EXTERNAL_INPUT_CSV.name}...")
        df_ext = pd.read_csv(EXTERNAL_INPUT_CSV)
        print(f"  * Ingested External: {len(df_ext):,} rows ({EXTERNAL_INPUT_CSV.stat().st_size / (1024*1024):.2f} MB)")
        df_ext_labeled, ext_metrics = classify_dataset(df_ext, dataset_name="External_Elastic")

        out_ext_csv = PROCESSED_DIR / "elastic_labeled_logs.csv"
        df_ext_labeled.to_csv(out_ext_csv, index=False)
        print(f"  * Saved External Labeled CSV: {out_ext_csv.name} ({out_ext_csv.stat().st_size / (1024*1024):.2f} MB)")
    else:
        print(f"\n[Step 4] External dataset not found at {EXTERNAL_INPUT_CSV}. Skipping benchmark.")

    # Step 5: Visualizations
    print("\n[Step 5] Generating Publication-Quality Diagnostic Plots...")
    generate_classification_plots(df_primary_labeled, primary_metrics)

    # Step 6: Audit Report
    print("\n[Step 6] Compiling Audit & Verification Report...")
    report_path = generate_audit_report(primary_metrics, ext_metrics)
    print(f"  * Report Saved  : {report_path}")

    print("\n" + "=" * 75)
    print("   PRACTICAL 4 COMPLETE: LABELED GROUND-TRUTH DATASET READY FOR PRACTICAL 5")
    print("=" * 75)


if __name__ == "__main__":
    main()
