"""
preprocessor.py
===============
Data Cleaning & Normalization Engine for Stage 2 of the Reusable Pipeline.
Performs:
- Missing value imputation
- URL decoding & path normalization
- Query parameter & payload extraction
- Protocol and status code validation
"""

import urllib.parse
from typing import Dict, Any, List
import pandas as pd
import numpy as np


def clean_and_normalize_logs(df_raw: pd.DataFrame) -> pd.DataFrame:
    """Preprocesses and normalizes parsed log telemetry."""
    if df_raw.empty:
        return df_raw

    df = df_raw.copy()

    # 1. Fill missing core attributes
    df["ip_address"] = df["ip_address"].fillna("127.0.0.1").astype(str)
    df["method"] = df["method"].fillna("GET").astype(str).str.upper()
    df["resource"] = df["resource"].fillna("/").astype(str)
    df["status_code"] = pd.to_numeric(df["status_code"], errors="coerce").fillna(200).astype(int)
    df["bytes_sent"] = pd.to_numeric(df["bytes_sent"], errors="coerce").fillna(0).astype(int)
    df["user_agent"] = df["user_agent"].fillna("Mozilla/5.0").astype(str)
    df["referer"] = df["referer"].fillna("-").astype(str)

    # 2. Extract path, query, and decoded payload
    base_paths = []
    queries = []
    decoded_payloads = []

    for res in df["resource"]:
        try:
            parsed = urllib.parse.urlparse(res)
            bp = parsed.path if parsed.path else "/"
            q = parsed.query if parsed.query else ""
            # Attempt URL unquoting safely
            dec = urllib.parse.unquote(res)
        except Exception:
            bp = "/"
            q = ""
            dec = res
        base_paths.append(bp)
        queries.append(q)
        decoded_payloads.append(dec)

    df["normalized_path"] = base_paths
    df["query_string"] = queries
    df["decoded_payload"] = decoded_payloads

    # 3. HTTP status flags
    df["is_error_status"] = (df["status_code"] >= 400).astype(int)
    df["is_server_error"] = (df["status_code"] >= 500).astype(int)

    return df
