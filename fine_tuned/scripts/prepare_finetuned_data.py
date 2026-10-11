"""
prepare_finetuned_data.py
=========================
Curates an enriched, diverse benign training dataset using Hard Negative Mining.
Extracts natural browser User-Agents, short URL paths, and diverse legitimate HTTP sessions
from the 179k master pool to eliminate false alarms without corrupting attack detection.
"""

import sys
from pathlib import Path
import pandas as pd
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "Practical 10"))

from pipeline.inference_engine import FEATURE_COLUMNS
from pipeline.log_parser import parse_logs_text
from pipeline.preprocessor import clean_and_normalize_logs
from pipeline.feature_extractor import extract_features_dataframe

DATA_DIR = PROJECT_ROOT / "fine_tuned" / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)


def build_finetuned_dataset():
    print("[Step 1] Loading base balanced training dataset (275,000 records)...")
    base_train_path = PROJECT_ROOT / "Practical 6" / "data" / "processed" / "balanced_training_dataset.parquet"
    df_base = pd.read_parquet(base_train_path)

    print("[Step 2] Ingesting master featured telemetry (500,000 records)...")
    feat_all_path = PROJECT_ROOT / "Practical 5" / "data" / "processed" / "featured_logs.parquet"
    df_feat_all = pd.read_parquet(feat_all_path)

    # Prevent data leakage: exclude test dataset records
    test_path = PROJECT_ROOT / "Practical 6" / "data" / "processed" / "test_dataset.parquet"
    df_test = pd.read_parquet(test_path)
    test_indices = set(df_test.index)

    df_train_pool = df_feat_all[~df_feat_all.index.isin(test_indices)]
    df_benign_pool = df_train_pool[df_train_pool["label"] == "benign"]
    print(f"  Available training benign pool: {len(df_benign_pool):,} records")

    # Hard Negative Mining: Sample diverse benign records across different path depths
    # Depth 1: Root & single-segment paths (/, /contact, /about, /faq, /dashboard)
    b_depth1 = df_benign_pool[df_benign_pool["path_depth"] <= 1]
    # Depth 2: Multi-segment paths (/products/view, /api/v1/metrics)
    b_depth2 = df_benign_pool[df_benign_pool["path_depth"] == 2]
    # Depth 3+: Deep application paths
    b_depth3_plus = df_benign_pool[df_benign_pool["path_depth"] >= 3]

    print(f"  Available Depth <= 1: {len(b_depth1):,}, Depth 2: {len(b_depth2):,}, Depth >= 3: {len(b_depth3_plus):,}")

    sample_d1 = b_depth1.sample(min(len(b_depth1), 6000), random_state=42)
    sample_d2 = b_depth2.sample(min(len(b_depth2), 10000), random_state=42)
    sample_d3 = b_depth3_plus.sample(min(len(b_depth3_plus), 12000), random_state=42)

    # Ingest synthetic clean modern browser patterns for diverse short URLs
    synthetic_clean_logs = [
        '192.168.1.10 - - [10/Oct/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 4520 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"',
        '192.168.1.10 - - [10/Oct/2026:12:00:15 +0000] "GET /about-us HTTP/1.1" 200 5120 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"',
        '192.168.1.10 - - [10/Oct/2026:12:00:30 +0000] "GET /contact HTTP/1.1" 200 3940 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"',
        '192.168.1.10 - - [10/Oct/2026:12:00:45 +0000] "POST /contact/submit HTTP/1.1" 200 450 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"',
        '192.168.1.10 - - [10/Oct/2026:12:01:00 +0000] "GET /faq HTTP/1.1" 200 5800 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"',
        '192.168.1.10 - - [10/Oct/2026:12:01:15 +0000] "GET /privacy-policy HTTP/1.1" 200 6210 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"',
        '192.168.1.10 - - [10/Oct/2026:12:01:30 +0000] "GET /dashboard HTTP/1.1" 200 8920 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"',
        '192.168.1.10 - - [10/Oct/2026:12:01:45 +0000] "GET /healthz HTTP/1.1" 200 24 "https://example.com/" "kube-probe/1.28"',
        '192.168.1.20 - - [10/Oct/2026:12:02:00 +0000] "GET /search?q=wireless+headphones HTTP/1.1" 200 6820 "https://example.com/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1"',
        '192.168.1.20 - - [10/Oct/2026:12:02:15 +0000] "POST /cart/add HTTP/1.1" 200 120 "https://example.com/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1"',
        '192.168.1.20 - - [10/Oct/2026:12:02:30 +0000] "GET /cart/checkout HTTP/1.1" 200 9400 "https://example.com/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1"'
    ]
    df_syn_raw = parse_logs_text("\n".join(synthetic_clean_logs))
    df_syn_clean = clean_and_normalize_logs(df_syn_raw)
    df_syn_feats = extract_features_dataframe(df_syn_clean)
    df_syn_feats["label"] = "benign"
    df_syn_repeated = pd.concat([df_syn_feats] * 120, ignore_index=True)

    # Curate final benign class (28,000 diverse records)
    curated_benign = pd.concat([
        sample_d1[FEATURE_COLUMNS + ["label"]],
        sample_d2[FEATURE_COLUMNS + ["label"]],
        sample_d3[FEATURE_COLUMNS + ["label"]],
        df_syn_repeated[FEATURE_COLUMNS + ["label"]]
    ], ignore_index=True)

    print(f"  Curated diverse benign partition size: {len(curated_benign):,} records")

    # Keep all 10 attack classes intact from base training dataset (25,000 each = 250,000)
    df_attacks = df_base[df_base["label"] != "benign"][FEATURE_COLUMNS + ["label"]]

    df_finetuned_train = pd.concat([df_attacks, curated_benign], ignore_index=True)
    df_finetuned_train = df_finetuned_train.sample(frac=1.0, random_state=42).reset_index(drop=True)

    out_path = DATA_DIR / "finetuned_training_dataset.parquet"
    df_finetuned_train.to_parquet(out_path, index=False)
    print(f"[OK] Enriched dataset generated successfully: {out_path}")
    print(f"[OK] Total records: {len(df_finetuned_train):,} across 11 classes")
    print(df_finetuned_train["label"].value_counts())


if __name__ == "__main__":
    build_finetuned_dataset()
