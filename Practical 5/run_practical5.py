"""
run_practical5.py
=================
Practical 5: Feature Extraction & Unsupervised Anomaly Detection.
Course: Python for Data Science (BE05000231_PDS) - 5th Semester B.E./B.Tech

Objective:
----------
Extract mathematically grounded, non-leaky statistical, lexical, temporal,
and behavioral features from preprocessed logs, and execute unsupervised
anomaly detection using Isolation Forest to identify outliers and malicious patterns.
1. Ingest labeled ground-truth logs from Practical 4 (labeled_logs.csv).
2. Extract 30 canonical features across 4 orthogonal dimensions:
   - 9 Lexical & Path Features (URL entropy, depth, character ratios)
   - 7 Payload Complexity & Semantics (Shannon entropy, SQL/Script footprints)
   - 7 Temporal & Session Dynamics (Rolling 1-min & 5-min rates, failed logins)
   - 7 Network & Client Header Features (User-Agent entropy, bot flags)
3. Train scikit-learn Isolation Forest to derive anomaly scores and outlier flags.
4. Persist trained Isolation Forest and StandardScaler models to disk for downstream inference.
5. Export featured datasets to CSV and Snappy-compressed Parquet.
6. Generate publication-quality diagnostic plots and audit reports.
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

import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.metrics import roc_auc_score, precision_recall_fscore_support

# -----------------------------------------------------------------------------
# DIRECTORY RESOLUTION & MODULE IMPORT
# -----------------------------------------------------------------------------
PRACTICAL5_DIR = Path(__file__).resolve().parent
WORKSPACE_DIR = PRACTICAL5_DIR.parent
PRACTICAL4_PROCESSED = WORKSPACE_DIR / "Practical 4" / "data" / "processed"

# Import Canonical Feature Definitions
sys.path.insert(0, str(WORKSPACE_DIR))
from src.features.feature_definitions import (
    CANONICAL_FEATURE_NAMES,
    calculate_shannon_entropy,
    extract_lexical_features,
    extract_payload_semantics,
    extract_header_features
)

# Input Files from Practical 4
PRIMARY_INPUT_CSV = PRACTICAL4_PROCESSED / "labeled_logs.csv"

# Fallback to local data/raw if running standalone
if not PRIMARY_INPUT_CSV.exists():
    PRIMARY_INPUT_CSV = PRACTICAL5_DIR / "data" / "raw" / "labeled_logs.csv"

# Outputs for Practical 5
PROCESSED_DIR = PRACTICAL5_DIR / "data" / "processed"
OUTPUTS_DIR = PRACTICAL5_DIR / "outputs"
PLOTS_DIR = OUTPUTS_DIR / "plots"
REPORTS_DIR = OUTPUTS_DIR / "reports"
MODELS_DIR = OUTPUTS_DIR / "models"
SRC_MODELS_DIR = WORKSPACE_DIR / "src" / "models"

PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
PLOTS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)
SRC_MODELS_DIR.mkdir(parents=True, exist_ok=True)


# -----------------------------------------------------------------------------
# HIGH-EFFICIENCY BATCH FEATURE EXTRACTION PIPELINE
# -----------------------------------------------------------------------------
def extract_all_features(df: pd.DataFrame, dataset_name: str = "Primary") -> pd.DataFrame:
    """Extracts all 30 canonical features from a labeled log DataFrame using cached lookups."""
    t_start = time.time()
    print(f"[{dataset_name}] Starting 30-feature extraction across {len(df):,} records...")

    # 1. Lexical Features (Cached for speed)
    print(f"[{dataset_name}] Extracting 9 Lexical & Path features...")
    lex_cache: Dict[str, Dict[str, float]] = {}
    lex_records = []
    for u in df["resource_requested"]:
        if u not in lex_cache:
            lex_cache[u] = extract_lexical_features(u)
        lex_records.append(lex_cache[u])
    df_lex = pd.DataFrame(lex_records, index=df.index)

    # 2. Payload Complexity & Semantics (Cached)
    print(f"[{dataset_name}] Extracting 7 Payload Complexity & Semantics features...")
    payload_cache: Dict[str, Dict[str, Any]] = {}
    payload_records = []
    for p in df["payload"].fillna(""):
        p_str = str(p)
        if p_str not in payload_cache:
            payload_cache[p_str] = extract_payload_semantics(p_str)
        payload_records.append(payload_cache[p_str])
    df_payload = pd.DataFrame(payload_records, index=df.index)

    # 3. Header & Network Telemetry Features (Cached on UA)
    print(f"[{dataset_name}] Extracting 7 Header & Network Telemetry features...")
    header_records = []
    statuses = df["status_code"].fillna(200).astype(int).tolist()
    bytes_list = df["bytes_sent"].fillna(0).astype(int).tolist()
    uas = df["user_agent"].fillna("unknown").astype(str).tolist()

    for s, b, ua in zip(statuses, bytes_list, uas):
        header_records.append(extract_header_features(s, b, ua))
    df_header = pd.DataFrame(header_records, index=df.index)

    # 4. Temporal & Session Dynamics (Vectorized Rolling Window Execution)
    print(f"[{dataset_name}] Computing 7 Temporal & Session Dynamics features...")
    df["_dt"] = pd.to_datetime(df["datetime_utc"], errors="coerce")
    df_sorted = df.sort_values(["client_ip", "_dt"]).copy()

    # Inter-request time
    df_sorted["inter_request_time"] = df_sorted.groupby("client_ip")["_dt"].diff().dt.total_seconds().fillna(60.0).clip(lower=0.0)

    # Failed auth indicator
    df_sorted["is_failed_auth"] = df_sorted["status_code"].isin([401, 403]).astype(np.int8)

    # Fast Datetime Rolling per Client IP
    df_indexed = df_sorted.set_index("_dt")
    grouped_ip = df_indexed.groupby("client_ip")

    df_sorted["requests_per_ip_1min"] = grouped_ip["line_number"].rolling("1min").count().values.astype(np.int32)
    df_sorted["requests_per_ip_5min"] = grouped_ip["line_number"].rolling("5min").count().values.astype(np.int32)
    df_sorted["failed_login_count"] = grouped_ip["is_failed_auth"].rolling("5min").sum().values.astype(np.int32)

    # Request velocity in 1 second
    df_sorted["request_velocity_1sec"] = (df_sorted["inter_request_time"] <= 1.0).astype(np.int8)

    # Burst ratio: 1-min count divided by average 5-min arrival velocity per min
    avg_rate_5m = (df_sorted["requests_per_ip_5min"] / 5.0).clip(lower=1.0)
    df_sorted["burst_ratio"] = (df_sorted["requests_per_ip_1min"] / avg_rate_5m).round(3)

    # Unique resources in 5-min window (factorized to numeric IDs for C-level speed)
    df_sorted["path_id"] = pd.factorize(df_sorted["clean_path"])[0].astype(np.float64)
    df_indexed = df_sorted.set_index("_dt")
    grouped_ip = df_indexed.groupby("client_ip")
    df_sorted["unique_resources_per_ip_5min"] = grouped_ip["path_id"].rolling("5min").apply(lambda s: len(np.unique(s)), raw=True).values.astype(np.int32)
    df_sorted.drop(columns=["path_id"], inplace=True, errors="ignore")

    # Re-align back to original dataframe index
    df_temporal = df_sorted.loc[df.index, [
        "inter_request_time",
        "requests_per_ip_1min",
        "requests_per_ip_5min",
        "request_velocity_1sec",
        "burst_ratio",
        "unique_resources_per_ip_5min",
        "failed_login_count"
    ]]

    # Combine all feature partitions
    features_df = pd.concat([df_lex, df_payload, df_temporal, df_header], axis=1)

    # Enforce strictly standardized canonical ordering
    features_df = features_df[CANONICAL_FEATURE_NAMES]

    # Clean intermediate columns
    df.drop(columns=["_dt"], inplace=True, errors="ignore")

    # Merge features with original table and deduplicate columns (e.g. status_code, bytes_sent)
    result_df = pd.concat([df, features_df], axis=1)
    result_df = result_df.loc[:, ~result_df.columns.duplicated()]

    elapsed = round(time.time() - t_start, 2)
    rps = round(len(df) / max(0.001, elapsed), 1)
    print(f"[{dataset_name}] Successfully extracted all 30 features in {elapsed}s ({rps:,} rows/sec)!")

    return result_df


# -----------------------------------------------------------------------------
# UNSUPERVISED ANOMALY DETECTION (ISOLATION FOREST)
# -----------------------------------------------------------------------------
def run_anomaly_detection(df: pd.DataFrame, dataset_name: str = "Primary") -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Fits an unsupervised Isolation Forest on the 30 canonical features and persists models."""
    t_start = time.time()
    print(f"[{dataset_name}] Training unsupervised Isolation Forest anomaly detector...")

    X = df[CANONICAL_FEATURE_NAMES].fillna(0).values

    # Standardize features for robust distance/depth partitioning
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # 100 Isolation Trees, 256 sub-sample depth, 10% expected anomaly contamination
    iso = IsolationForest(
        n_estimators=100,
        max_samples=256,
        contamination=0.10,
        random_state=42,
        n_jobs=-1
    )
    iso.fit(X_scaled)

    # Score samples returns negative anomaly score: higher score = more anomalous
    raw_scores = iso.score_samples(X_scaled)
    anomaly_scores = -raw_scores  # Invert so higher score represents higher anomaly probability
    
    # Predict: -1 for outlier, 1 for inlier
    raw_preds = iso.predict(X_scaled)
    is_anomaly = (raw_preds == -1).astype(np.int8)

    df["anomaly_score"] = np.round(anomaly_scores, 4)
    df["is_anomaly"] = is_anomaly

    # Persist physical models to disk for downstream inference (Practical 10 & Streamlit)
    joblib.dump(iso, MODELS_DIR / "isolation_forest.joblib")
    joblib.dump(scaler, MODELS_DIR / "scaler.joblib")
    joblib.dump(iso, SRC_MODELS_DIR / "isolation_forest.joblib")
    joblib.dump(scaler, SRC_MODELS_DIR / "scaler.joblib")
    print(f"[{dataset_name}] Persisted isolation_forest.joblib and scaler.joblib to {MODELS_DIR} and {SRC_MODELS_DIR}!")

    # Calculate alignment with ground truth
    metrics: Dict[str, Any] = {
        "dataset_name": dataset_name,
        "total_rows": len(df),
        "total_features": len(CANONICAL_FEATURE_NAMES),
        "outlier_count": int(is_anomaly.sum()),
        "outlier_pct": round((is_anomaly.sum() / len(df)) * 100, 2),
        "mean_anomaly_score": round(float(np.mean(anomaly_scores)), 4),
        "max_anomaly_score": round(float(np.max(anomaly_scores)), 4),
        "min_anomaly_score": round(float(np.min(anomaly_scores)), 4),
        "runtime_seconds": round(time.time() - t_start, 2)
    }

    if "is_attack" in df.columns:
        y_true = df["is_attack"].values
        try:
            auc = roc_auc_score(y_true, anomaly_scores)
            prec, rec, f1, _ = precision_recall_fscore_support(y_true, is_anomaly, average="binary", zero_division=0)
            metrics["roc_auc"] = round(float(auc), 4)
            metrics["precision"] = round(float(prec), 4)
            metrics["recall"] = round(float(rec), 4)
            metrics["f1_score"] = round(float(f1), 4)
        except Exception:
            metrics["roc_auc"] = 0.0

    print(f"[{dataset_name}] Anomaly Detection Complete in {metrics['runtime_seconds']}s! Outliers: {metrics['outlier_count']:,} ({metrics['outlier_pct']}%)")
    return df, metrics


# -----------------------------------------------------------------------------
# PLOT GENERATION (PUBLICATION QUALITY)
# -----------------------------------------------------------------------------
def generate_feature_plots(df: pd.DataFrame, metrics: Dict[str, Any]) -> None:
    """Generates 4 high-resolution plots illustrating feature engineering and anomaly detection."""
    print("[Plots] Generating high-resolution diagnostic plots...")

    plt.rcParams.update({
        "font.family": "sans-serif",
        "axes.edgecolor": "#CBD5E1",
        "axes.linewidth": 1.2,
        "grid.color": "#E2E8F0",
        "grid.linestyle": "--",
        "grid.alpha": 0.7,
    })

    # Plot 1: Feature Correlation Heatmap (Top 10 Key Features)
    key_features = [
        "url_length", "url_entropy", "payload_length", "payload_entropy",
        "special_char_ratio", "inter_request_time", "requests_per_ip_1min",
        "user_agent_entropy", "failed_login_count", "bytes_sent"
    ]
    corr_matrix = df[key_features].corr()

    fig, ax = plt.subplots(figsize=(10, 8), dpi=150)
    cax = ax.matshow(corr_matrix, cmap="coolwarm", vmin=-1, vmax=1)
    fig.colorbar(cax)

    ax.set_xticks(range(len(key_features)))
    ax.set_yticks(range(len(key_features)))
    ax.set_xticklabels(key_features, rotation=45, ha="left", fontsize=9)
    ax.set_yticklabels(key_features, fontsize=9)
    ax.set_title("Canonical Feature Cross-Correlation Matrix", fontsize=13, fontweight="bold", pad=20)
    plt.tight_layout()
    p1 = PLOTS_DIR / "feature_correlation_matrix.png"
    plt.savefig(p1)
    plt.close()
    print(f"  * Generated: {p1.name}")

    # Plot 2: Shannon Entropy by Attack Class
    fig, ax = plt.subplots(figsize=(11, 5), dpi=150)
    top_classes = df["label"].value_counts().head(8).index
    entropy_data = [df[df["label"] == c]["url_entropy"].values for c in top_classes]

    ax.boxplot(entropy_data, tick_labels=top_classes, patch_artist=True,
               boxprops=dict(facecolor="#1687FF", color="#060912"),
               medianprops=dict(color="#FF5577", linewidth=2))
    ax.set_title("Character-Level Shannon Entropy Distribution Across Classes", fontsize=13, fontweight="bold", pad=12)
    ax.set_ylabel("Shannon Entropy (Bits / Char)", fontsize=10)
    ax.set_xlabel("Class", fontsize=10)
    ax.tick_params(axis="x", rotation=30)
    ax.grid(True, axis="y")
    plt.tight_layout()
    p2 = PLOTS_DIR / "shannon_entropy_by_class.png"
    plt.savefig(p2)
    plt.close()
    print(f"  * Generated: {p2.name}")

    # Plot 3: Anomaly Score Distribution (Benign vs Attack)
    fig, ax = plt.subplots(figsize=(10, 4.5), dpi=150)
    benign_scores = df[df["is_attack"] == 0]["anomaly_score"]
    attack_scores = df[df["is_attack"] == 1]["anomaly_score"]

    ax.hist(benign_scores, bins=60, alpha=0.6, label="Benign Traffic", color="#10B981", density=True)
    ax.hist(attack_scores, bins=60, alpha=0.6, label="Malicious Attacks", color="#EF4444", density=True)
    ax.set_title("Isolation Forest Anomaly Score Distribution (Density)", fontsize=13, fontweight="bold", pad=12)
    ax.set_xlabel("Anomaly Score (Higher = Outlier)", fontsize=10)
    ax.set_ylabel("Probability Density", fontsize=10)
    ax.legend(frameon=True, facecolor="#FFFFFF")
    ax.grid(True)
    plt.tight_layout()
    p3 = PLOTS_DIR / "anomaly_score_distribution.png"
    plt.savefig(p3)
    plt.close()
    print(f"  * Generated: {p3.name}")

    # Plot 4: 2D PCA Anomaly Outlier Scatter Projection
    fig, ax = plt.subplots(figsize=(9, 6), dpi=150)
    sample_df = df.sample(min(5000, len(df)), random_state=42)
    X_sample = sample_df[CANONICAL_FEATURE_NAMES].fillna(0).values
    pca = PCA(n_components=2, random_state=42)
    X_pca = pca.fit_transform(StandardScaler().fit_transform(X_sample))

    normal_mask = sample_df["is_anomaly"] == 0
    outlier_mask = sample_df["is_anomaly"] == 1

    ax.scatter(X_pca[normal_mask, 0], X_pca[normal_mask, 1], c="#10B981", alpha=0.4, s=15, label="Normal Inliers")
    ax.scatter(X_pca[outlier_mask, 0], X_pca[outlier_mask, 1], c="#EF4444", alpha=0.8, s=25, label="Isolation Forest Outliers")
    ax.set_title(f"2D PCA Projection of Inliers vs Outliers (Var Explained: {pca.explained_variance_ratio_.sum()*100:.1f}%)", fontsize=12, fontweight="bold", pad=12)
    ax.set_xlabel("Principal Component 1", fontsize=10)
    ax.set_ylabel("Principal Component 2", fontsize=10)
    ax.legend(frameon=True, facecolor="#FFFFFF")
    ax.grid(True)
    plt.tight_layout()
    p4 = PLOTS_DIR / "pca_anomaly_cluster_projection.png"
    plt.savefig(p4)
    plt.close()
    print(f"  * Generated: {p4.name}")


# -----------------------------------------------------------------------------
# AUDIT REPORT GENERATOR
# -----------------------------------------------------------------------------
def generate_audit_report(primary_metrics: Dict[str, Any]) -> Path:
    """Generates a comprehensive scientific report of the feature extraction pipeline."""
    report_file = REPORTS_DIR / "practical5_feature_report.txt"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("   PRACTICAL 5: FEATURE EXTRACTION & ANOMALY DETECTION REPORT\n")
        f.write("=" * 80 + "\n\n")
        f.write("Course         : Python for Data Science (BE05000231_PDS)\n")
        f.write(f"Execution Date : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        f.write("-" * 80 + "\n")
        f.write("1. PRIMARY ENTERPRISE DATASET FEATURE EXTRACTION AUDIT\n")
        f.write("-" * 80 + "\n")
        f.write(f"Source Input File        : labeled_logs.csv\n")
        f.write(f"Total Rows Processed     : {primary_metrics['total_rows']:,}\n")
        f.write(f"Canonical Features       : {primary_metrics['total_features']} (Across 4 Orthogonal Dimensions)\n")
        f.write(f"Isolation Forest Runtime : {primary_metrics['runtime_seconds']} seconds\n")
        f.write(f"Flagged Outlier Records  : {primary_metrics['outlier_count']:,} ({primary_metrics['outlier_pct']}% Contamination)\n")
        f.write(f"Mean Anomaly Score       : {primary_metrics['mean_anomaly_score']}\n")
        f.write(f"ROC-AUC (vs Attacks)     : {primary_metrics.get('roc_auc', 'N/A')}\n")
        f.write(f"Precision / Recall / F1  : {primary_metrics.get('precision', 'N/A')} / {primary_metrics.get('recall', 'N/A')} / {primary_metrics.get('f1_score', 'N/A')}\n\n")

        f.write("Canonical 30-Feature Inventory:\n")
        for i, fname in enumerate(CANONICAL_FEATURE_NAMES, 1):
            f.write(f"  {i:>2}. {fname}\n")

        f.write("\n" + "=" * 80 + "\n")
        f.write("END OF PRACTICAL 5 FEATURE REPORT\n")
        f.write("=" * 80 + "\n")

    return report_file


# -----------------------------------------------------------------------------
# MAIN EXECUTION ROUTINE
# -----------------------------------------------------------------------------
def main():
    print("=" * 75)
    print("   PRACTICAL 5: FEATURE EXTRACTION & ANOMALY DETECTION PIPELINE")
    print("=" * 75)

    if not PRIMARY_INPUT_CSV.exists():
        print(f"[Error] Primary input CSV not found at: {PRIMARY_INPUT_CSV}")
        print("Please run Practical 4 first to generate labeled_logs.csv.")
        sys.exit(1)

    # Step 1: Ingest Practical 4 Dataset
    print(f"\n[Step 1] Ingesting Practical 4 Ground-Truth Dataset: {PRIMARY_INPUT_CSV.name}...")
    df_primary = pd.read_csv(PRIMARY_INPUT_CSV)
    print(f"  * Ingested: {len(df_primary):,} rows, {len(df_primary.columns)} columns ({PRIMARY_INPUT_CSV.stat().st_size / (1024*1024):.2f} MB)")

    # Step 2: Extract 30 Features
    print("\n[Step 2] Executing 30-Feature Extraction Pipeline on Primary Dataset...")
    df_primary_featured = extract_all_features(df_primary, dataset_name="Primary")

    # Step 3: Run Unsupervised Anomaly Detection
    print("\n[Step 3] Running Isolation Forest Outlier Detection on Primary Dataset...")
    df_primary_featured, primary_metrics = run_anomaly_detection(df_primary_featured, dataset_name="Primary")

    # Step 4: Export Featured Datasets (CSV & Parquet)
    print("\n[Step 4] Exporting Feature-Engineered Datasets (CSV & Parquet)...")
    out_csv = PROCESSED_DIR / "featured_logs.csv"
    out_pq = PROCESSED_DIR / "featured_logs.parquet"

    df_primary_featured.to_csv(out_csv, index=False)
    df_primary_featured.to_parquet(out_pq, index=False, compression="snappy")
    print(f"  * Saved Featured CSV     : {out_csv.name} ({out_csv.stat().st_size / (1024*1024):.2f} MB)")
    print(f"  * Saved Featured Parquet : {out_pq.name} ({out_pq.stat().st_size / (1024*1024):.2f} MB)")

    # Step 5: Visualizations
    print("\n[Step 5] Generating Publication-Quality Diagnostic Plots...")
    generate_feature_plots(df_primary_featured, primary_metrics)

    # Step 6: Audit Report
    print("\n[Step 6] Compiling Feature Engineering Audit Report...")
    report_path = generate_audit_report(primary_metrics)
    print(f"  * Report Saved  : {report_path}")

    print("\n" + "=" * 75)
    print("   PRACTICAL 5 COMPLETE: FEATURED DATASET READY FOR PRACTICAL 6")
    print("=" * 75)


if __name__ == "__main__":
    main()
