#!/usr/bin/env python3
"""
Practical 2: Convert Unstructured Log Data into a Structured Dataset
====================================================================
GTU Course: Python for Data Science (BE05000231_PDS)

Objectives:
1. Parse unstructured access log lines into structured tabular records.
2. Utilize compiled Regular Expressions with named capture groups to extract:
   - IP address (client_ip)
   - Date/time (timestamp)
   - Request type (request_method: GET, POST, HEAD, etc.)
   - Status code (status_code)
   - Resource requested (resource_requested)
   - Bytes sent (bytes_sent)
   - Referrer (referrer)
   - User-agent (user_agent)
   - Protocol & Isolated Query Payload
3. Handle irregular and malformed log lines gracefully with zero pipeline crashes.
4. Construct an optimized Pandas DataFrame with appropriate data types.
5. Save the structured dataset to CSV and high-efficiency Parquet formats.
6. Test and benchmark on authentic external real-world server traffic (Elastic Apache Access Log).
7. Generate visual distribution and schema completeness plots.
"""

import sys
import re
import time
from pathlib import Path
from typing import List, Dict, Any, Tuple
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# Path Discovery
PRACTICAL_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PRACTICAL_DIR.parent
DATA_RAW_DIR = PRACTICAL_DIR / "data" / "raw"
DATA_PROCESSED_DIR = PRACTICAL_DIR / "data" / "processed"
OUTPUTS_DIR = PRACTICAL_DIR / "outputs"
REPORTS_DIR = OUTPUTS_DIR / "reports"
PLOTS_DIR = OUTPUTS_DIR / "plots"

# Ensure all target directories exist
DATA_PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
PLOTS_DIR.mkdir(parents=True, exist_ok=True)

# -----------------------------------------------------------------------------
# 1. COMPILED REGEX PATTERN FOR APACHE / NGINX COMBINED LOG FORMAT
# -----------------------------------------------------------------------------
# Captures:
# Group 1: client_ip
# Group 2: ident (remote logname)
# Group 3: auth_user
# Group 4: timestamp
# Group 5: request_method (GET, POST, etc.)
# Group 6: resource_requested (URI with parameters)
# Group 7: http_protocol (HTTP/1.1, HTTP/2, etc.)
# Group 8: status_code
# Group 9: bytes_sent
# Group 10: referrer
# Group 11: user_agent
CLF_REGEX = re.compile(
    r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+(.+?)(?:\s+(HTTP/[\d\.]+|-))?"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?',
    re.IGNORECASE
)


def parse_log_line(line_num: int, line_text: str) -> Dict[str, Any]:
    """Parses a single unstructured access log line into structured dictionary fields.
    Gracefully handles unencoded spaces, missing headers, and malformed lines.
    """
    m = CLF_REGEX.match(line_text)
    if m:
        raw_res = m.group(6) or "-"
        payload = ""
        if "?" in raw_res:
            payload = raw_res.split("?", 1)[1]

        raw_bytes = m.group(9)
        bytes_val = int(raw_bytes) if raw_bytes and raw_bytes.isdigit() else 0

        return {
            "line_number": line_num,
            "client_ip": m.group(1),
            "ident": m.group(2) if m.group(2) != "-" else "",
            "auth_user": m.group(3) if m.group(3) != "-" else "",
            "timestamp": m.group(4),
            "request_method": m.group(5).upper(),
            "resource_requested": raw_res,
            "http_protocol": m.group(7) if m.group(7) else "HTTP/1.1",
            "status_code": int(m.group(8)),
            "bytes_sent": bytes_val,
            "referrer": m.group(10) if m.group(10) and m.group(10) != "-" else "",
            "user_agent": m.group(11) if m.group(11) and m.group(11) != "-" else "",
            "payload": payload,
            "parse_success": 1
        }
    else:
        # Fallback heuristic parser for irregular lines
        parts = line_text.split()
        ip = parts[0] if parts else "-"
        status = 200
        bytes_val = 0
        method = "GET"
        res = "-"

        for p in parts:
            if p.isdigit() and len(p) == 3 and p in ["200", "301", "302", "401", "403", "404", "500", "503"]:
                status = int(p)
                break

        return {
            "line_number": line_num,
            "client_ip": ip,
            "ident": "",
            "auth_user": "",
            "timestamp": "",
            "request_method": method,
            "resource_requested": res,
            "http_protocol": "HTTP/1.1",
            "status_code": status,
            "bytes_sent": bytes_val,
            "referrer": "",
            "user_agent": "",
            "payload": "",
            "parse_success": 0
        }


def parse_access_log_file(file_path: Path, max_lines: int = None) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Streams and parses log file into an optimized Pandas DataFrame with performance metrics."""
    t0 = time.time()
    records = []
    malformed_count = 0
    total_lines = 0

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for idx, line in enumerate(f):
            total_lines += 1
            s = line.strip()
            if not s:
                continue
            record = parse_log_line(idx + 1, s)
            if record["parse_success"] == 0:
                malformed_count += 1
            records.append(record)
            if max_lines and len(records) >= max_lines:
                break

    # Construct initial raw DataFrame
    df = pd.DataFrame(records)

    # -------------------------------------------------------------------------
    # Optimize Data Types to Reduce RAM Footprint
    # -------------------------------------------------------------------------
    initial_memory_mb = df.memory_usage(deep=True).sum() / (1024 * 1024)

    df["line_number"] = df["line_number"].astype(np.int32)
    df["status_code"] = df["status_code"].astype(np.int16)
    df["bytes_sent"] = df["bytes_sent"].astype(np.int32)
    df["request_method"] = df["request_method"].astype("category")
    df["http_protocol"] = df["http_protocol"].astype("category")
    df["parse_success"] = df["parse_success"].astype(np.int8)

    optimized_memory_mb = df.memory_usage(deep=True).sum() / (1024 * 1024)
    parse_time = time.time() - t0

    metrics = {
        "file_name": file_path.name,
        "file_size_mb": round(file_path.stat().st_size / (1024 * 1024), 2),
        "total_lines_read": total_lines,
        "parsed_records": len(df),
        "malformed_lines": malformed_count,
        "success_rate_percent": round(((total_lines - malformed_count) / total_lines) * 100, 4) if total_lines > 0 else 0.0,
        "parse_time_sec": round(parse_time, 2),
        "lines_per_second": round(total_lines / parse_time, 1) if parse_time > 0 else 0,
        "initial_memory_mb": round(initial_memory_mb, 2),
        "optimized_memory_mb": round(optimized_memory_mb, 2),
        "memory_savings_percent": round(((initial_memory_mb - optimized_memory_mb) / initial_memory_mb) * 100, 2) if initial_memory_mb > 0 else 0.0
    }

    return df, metrics


def run_practical2_pipeline():
    print("=" * 75)
    print("   PRACTICAL 2: CONVERT UNSTRUCTURED LOG DATA INTO STRUCTURED DATASET")
    print("=" * 75)

    primary_log = DATA_RAW_DIR / "server_access.log"
    if not primary_log.exists():
        fallback = PROJECT_ROOT / "data" / "raw" / "server_access.log"
        if fallback.exists():
            import shutil
            shutil.copy2(fallback, primary_log)
        else:
            raise FileNotFoundError(f"Primary log not found at {primary_log}")

    # -------------------------------------------------------------------------
    # Step 1: Parse Primary Master Access Log (300,000 Records)
    # -------------------------------------------------------------------------
    print(f"\n[Step 1] Parsing Primary Enterprise Access Log ({primary_log.name})...")
    df_primary, metrics_primary = parse_access_log_file(primary_log)

    print(f"  * Total Lines Read    : {metrics_primary['total_lines_read']:,}")
    print(f"  * Structured Records  : {metrics_primary['parsed_records']:,}")
    print(f"  * Parsing Success Rate: {metrics_primary['success_rate_percent']:.4f}% ({metrics_primary['malformed_lines']:,} malformed)")
    print(f"  * Parsing Throughput  : {metrics_primary['lines_per_second']:,} lines/sec ({metrics_primary['parse_time_sec']}s)")
    print(f"  * Memory Optimization : {metrics_primary['initial_memory_mb']} MB -> {metrics_primary['optimized_memory_mb']} MB ({metrics_primary['memory_savings_percent']}% reduction)")

    # -------------------------------------------------------------------------
    # Step 2: Export Structured Datasets (CSV & Parquet)
    # -------------------------------------------------------------------------
    csv_out = DATA_PROCESSED_DIR / "structured_logs.csv"
    parquet_out = DATA_PROCESSED_DIR / "structured_logs.parquet"

    print(f"\n[Step 2] Exporting Structured Tabular Datasets...")
    df_primary.to_csv(csv_out, index=False)
    csv_size_mb = csv_out.stat().st_size / (1024 * 1024)
    print(f"  * Exported CSV        : {csv_out.name} ({csv_size_mb:.2f} MB)")

    try:
        df_primary.to_parquet(parquet_out, index=False, compression="snappy")
        pq_size_mb = parquet_out.stat().st_size / (1024 * 1024)
        print(f"  * Exported Parquet    : {parquet_out.name} ({pq_size_mb:.2f} MB) [{round((1 - pq_size_mb/csv_size_mb)*100, 1)}% compression reduction]")
    except Exception as e:
        print(f"  * Parquet Export Note : pyarrow/fastparquet not available ({e})")

    # -------------------------------------------------------------------------
    # Step 3: Parse External Real-World Log (Elastic 10,000 Production Lines)
    # -------------------------------------------------------------------------
    external_log = DATA_RAW_DIR / "elastic_apache_access.log"
    metrics_external = None
    df_external = None
    if external_log.exists():
        print(f"\n[Step 3] Benchmarking on External Real-World Dataset ({external_log.name})...")
        df_external, metrics_external = parse_access_log_file(external_log)
        print(f"  * External Records    : {metrics_external['parsed_records']:,} lines from Elastic production server")
        print(f"  * Parsing Success Rate: {metrics_external['success_rate_percent']:.4f}%")
        print(f"  * Top Client IPs      : {', '.join(df_external['client_ip'].value_counts().head(3).index.tolist())}")
        print(f"  * Methods Breakdown   : {dict(df_external['request_method'].value_counts())}")

        # Save external structured logs
        ext_csv_out = DATA_PROCESSED_DIR / "elastic_structured_logs.csv"
        df_external.to_csv(ext_csv_out, index=False)
        print(f"  * Saved External CSV  : {ext_csv_out.name} ({ext_csv_out.stat().st_size / (1024*1024):.2f} MB)")

    # -------------------------------------------------------------------------
    # Step 4: Generate Visual Distribution Artifacts
    # -------------------------------------------------------------------------
    print(f"\n[Step 4] Generating Publication-Quality Plots...")
    plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")

    # Plot 1: Column Schema Completeness Matrix
    fig, ax = plt.subplots(figsize=(10, 4.5), dpi=300)
    col_completeness = (df_primary.notnull() & (df_primary != "")).mean() * 100
    cols = col_completeness.index.tolist()
    pcts = col_completeness.values.tolist()
    bars = ax.barh(cols, pcts, color="#1687FF", edgecolor="#060912", height=0.6)
    for bar in bars:
        w = bar.get_width()
        ax.text(w - 6 if w > 10 else w + 1, bar.get_y() + bar.get_height() / 2, f"{w:.1f}%", va="center", ha="right" if w > 10 else "left", color="white" if w > 10 else "black", fontsize=9, fontweight="bold")
    ax.set_title("Practical 02: Structured DataFrame Column Completeness (%)", fontsize=12, fontweight="bold", pad=12)
    ax.set_xlabel("Completeness Percentage (%)", fontsize=10)
    ax.set_xlim(0, 105)
    plt.tight_layout()
    plot1_path = PLOTS_DIR / "column_completeness_matrix.png"
    plt.savefig(plot1_path)
    plt.close()

    # Plot 2: HTTP Method Frequency Distribution
    fig, ax = plt.subplots(figsize=(8, 4), dpi=300)
    methods = df_primary["request_method"].value_counts().head(5)
    bars = ax.bar(methods.index.astype(str), methods.values, color=["#22D3EE", "#1687FF", "#21D98B", "#FFB547"], edgecolor="#101827", width=0.55)
    for bar in bars:
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2.0, yval + (0.01 * max(methods.values)), f"{yval:,}", ha="center", va="bottom", fontsize=9, fontweight="bold")
    ax.set_title("Practical 02: Structured HTTP Request Method Distribution", fontsize=12, fontweight="bold", pad=12)
    ax.set_xlabel("HTTP Method", fontsize=10)
    ax.set_ylabel("Request Count", fontsize=10)
    plt.tight_layout()
    plot2_path = PLOTS_DIR / "http_method_distribution.png"
    plt.savefig(plot2_path)
    plt.close()

    # Plot 3: HTTP Status Code Breakdown
    fig, ax = plt.subplots(figsize=(9, 4), dpi=300)
    status_counts = df_primary["status_code"].value_counts().head(8)
    status_labels = status_counts.index.astype(str).tolist()
    colors = ["#21D98B" if s.startswith("2") else ("#FFB547" if s.startswith("3") else "#FF5577") for s in status_labels]
    bars = ax.bar(status_labels, status_counts.values, color=colors, edgecolor="#101827", width=0.55)
    for bar in bars:
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2.0, yval + (0.01 * max(status_counts.values)), f"{yval:,}", ha="center", va="bottom", fontsize=9, fontweight="bold")
    ax.set_title("Practical 02: HTTP Status Code Distribution (2xx, 3xx, 4xx, 5xx)", fontsize=12, fontweight="bold", pad=12)
    ax.set_xlabel("HTTP Status Code", fontsize=10)
    ax.set_ylabel("Occurrence Count", fontsize=10)
    plt.tight_layout()
    plot3_path = PLOTS_DIR / "status_code_distribution.png"
    plt.savefig(plot3_path)
    plt.close()

    # Plot 4: Memory Optimization Reduction
    fig, ax = plt.subplots(figsize=(6, 4), dpi=300)
    mem_labels = ["Raw String Objects", "Downcasted Categories"]
    mem_vals = [metrics_primary["initial_memory_mb"], metrics_primary["optimized_memory_mb"]]
    bars = ax.bar(mem_labels, mem_vals, color=["#FF5577", "#21D98B"], edgecolor="#101827", width=0.5)
    for bar in bars:
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2.0, yval + 2, f"{yval:.1f} MB", ha="center", va="bottom", fontsize=10, fontweight="bold")
    ax.set_title("Practical 02: In-Memory RAM Consumption Before vs After Dtype Optimization", fontsize=10, fontweight="bold", pad=12)
    ax.set_ylabel("RAM Utilization (MB)", fontsize=10)
    plt.tight_layout()
    plot4_path = PLOTS_DIR / "dataset_memory_reduction.png"
    plt.savefig(plot4_path)
    plt.close()

    print(f"  * Generated Plot 1   : {plot1_path.name}")
    print(f"  * Generated Plot 2   : {plot2_path.name}")
    print(f"  * Generated Plot 3   : {plot3_path.name}")
    print(f"  * Generated Plot 4   : {plot4_path.name}")

    # -------------------------------------------------------------------------
    # Step 5: Write Detailed Practical 2 Report
    # -------------------------------------------------------------------------
    report_path = REPORTS_DIR / "practical2_structuring_report.txt"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("   PRACTICAL 2: UNSTRUCTURED LOG CONVERSION INTO STRUCTURED DATASET REPORT\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Course         : Python for Data Science (BE05000231_PDS)\n")
        f.write(f"Execution Date : {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("-" * 80 + "\n")
        f.write("1. PRIMARY ENTERPRISE DATASET STRUCTURING AUDIT\n")
        f.write("-" * 80 + "\n")
        f.write(f"Source File Name       : {metrics_primary['file_name']}\n")
        f.write(f"Source File Size       : {metrics_primary['file_size_mb']} MB\n")
        f.write(f"Total Physical Lines   : {metrics_primary['total_lines_read']:,}\n")
        f.write(f"Parsed DataFrame Rows  : {metrics_primary['parsed_records']:,}\n")
        f.write(f"Parsing Success Rate   : {metrics_primary['success_rate_percent']}%\n")
        f.write(f"Malformed Lines        : {metrics_primary['malformed_lines']:,}\n")
        f.write(f"Parsing Runtime        : {metrics_primary['parse_time_sec']} seconds ({metrics_primary['lines_per_second']:,} lines/sec)\n")
        f.write(f"Initial Memory Usage   : {metrics_primary['initial_memory_mb']} MB\n")
        f.write(f"Optimized Memory Usage : {metrics_primary['optimized_memory_mb']} MB ({metrics_primary['memory_savings_percent']}% reduction)\n\n")

        f.write("-" * 80 + "\n")
        f.write("2. CANONICAL 13-COLUMN SCHEMA DEFINITION & DATA TYPES\n")
        f.write("-" * 80 + "\n")
        for col, dtype in df_primary.dtypes.items():
            comp = (df_primary[col].notnull() & (df_primary[col] != "")).mean() * 100
            f.write(f"  * {col:<22} : {str(dtype):<15} (Completeness: {comp:.1f}%)\n")
        f.write("\n")

        if metrics_external:
            f.write("-" * 80 + "\n")
            f.write("3. EXTERNAL REAL-WORLD BENCHMARK AUDIT (Elastic Production Server)\n")
            f.write("-" * 80 + "\n")
            f.write(f"Source File Name       : {metrics_external['file_name']}\n")
            f.write(f"Source File Size       : {metrics_external['file_size_mb']} MB\n")
            f.write(f"Total Lines Processed  : {metrics_external['total_lines_read']:,}\n")
            f.write(f"Parsing Success Rate   : {metrics_external['success_rate_percent']}%\n")
            f.write(f"Unique Client IPs      : {df_external['client_ip'].nunique():,}\n")
            f.write(f"Top Client IP          : {df_external['client_ip'].value_counts().index[0]} ({df_external['client_ip'].value_counts().iloc[0]:,} requests)\n")
            f.write(f"HTTP Status Breakdown  : {dict(df_external['status_code'].value_counts())}\n\n")

        f.write("=" * 80 + "\n")
        f.write("END OF PRACTICAL 2 STRUCTURING REPORT\n")
        f.write("=" * 80 + "\n")

    print(f"\n[Step 5] Practical 2 Pipeline Complete!")
    print(f"  * Audit Report Saved : {report_path.resolve()}")
    print("=" * 75)
    return True


if __name__ == "__main__":
    run_practical2_pipeline()
