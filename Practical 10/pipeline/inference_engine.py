"""
inference_engine.py
===================
Authentic Machine Learning Threat Inference Engine for Practical 10.
Executes physical trained champion models (Random Forest Tuned, Decision Tree Tuned, Logistic Regression)
with 100% independent ML predictions.
ZERO hardcoded if-else overrides, ZERO regex fallback rules.
"""

import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd
import numpy as np
import joblib

PRACTICAL10_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = PRACTICAL10_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.features.feature_definitions import CANONICAL_FEATURE_NAMES

FEATURE_COLUMNS = CANONICAL_FEATURE_NAMES + ["anomaly_score"]

MODELS_DIR = PROJECT_ROOT / "Practical 9" / "outputs" / "models" / "balanced"
SRC_MODELS_DIR = PROJECT_ROOT / "src" / "models"


# Human-Readable Cybersecurity SOC Metadata
ATTACK_METADATA = {
    "benign": {
        "display_name": "Normal / Legitimate Traffic",
        "severity": "Low",
        "badge_color": "#10B981",
        "action": "Allow Request (Normal Operation)"
    },
    "sqli": {
        "display_name": "SQL Injection (SQLi)",
        "severity": "Critical",
        "badge_color": "#EF4444",
        "action": "Drop Request & IP Blacklist (WAF Rule 942100)"
    },
    "xss": {
        "display_name": "Cross-Site Scripting (XSS)",
        "severity": "High",
        "badge_color": "#F97316",
        "action": "Sanitize Input & Apply Content-Security-Policy"
    },
    "command_injection": {
        "display_name": "OS Command Injection",
        "severity": "Critical",
        "badge_color": "#DC2626",
        "action": "Immediate Process Isolation & Firewall Block"
    },
    "path_traversal": {
        "display_name": "Directory Path Traversal",
        "severity": "High",
        "badge_color": "#E11D48",
        "action": "Restrict Filesystem Boundary & Reject HTTP 403"
    },
    "brute_force": {
        "display_name": "Credential Brute Force",
        "severity": "Medium",
        "badge_color": "#8B5CF6",
        "action": "Enforce Multi-Factor Auth & Exponential Rate Limit"
    },
    "ddos_http_flood": {
        "display_name": "DDoS HTTP Flood",
        "severity": "High",
        "badge_color": "#B91C1C",
        "action": "Trigger Edge Volumetric Mitigation & Rate-Limiting"
    },
    "dir_fuzzing": {
        "display_name": "Directory Fuzzing / Discovery",
        "severity": "Medium",
        "badge_color": "#D97706",
        "action": "Return HTTP 404 Honeytoken & Throttle Subnet"
    },
    "mal_scanner": {
        "display_name": "Malicious Vulnerability Scanner",
        "severity": "Medium",
        "badge_color": "#D97706",
        "action": "Drop Connection & Block Scanner User-Agent"
    },
    "ssrf": {
        "display_name": "Server-Side Request Forgery (SSRF)",
        "severity": "Critical",
        "badge_color": "#991B1B",
        "action": "Quarantine Request & Block Cloud Metadata Endpoints"
    },
    "web_shell": {
        "display_name": "Web Shell Execution / Upload",
        "severity": "Critical",
        "badge_color": "#7F1D1D",
        "action": "Quarantine File Upload & Terminate Compromised Session"
    }
}


ANOMALY_THRESHOLD = 0.52


class ThreatInferenceEngine:
    """Manages model loading and 100% independent machine learning prediction."""

    AVAILABLE_MODELS = {
        "Random Forest Ensemble (Champion)": "random_forest_tuned.joblib",
        "Decision Tree (Tuned Fast)": "decision_tree_tuned.joblib",
        "Random Forest Ensemble (Base)": "random_forest.joblib",
        "Decision Tree (Base)": "decision_tree.joblib",
        "Logistic Regression (Linear Baseline)": "logistic_regression.joblib"
    }

    def __init__(self, model_key: str = "Random Forest Ensemble (Champion)", model_path: Path = None):
        self.current_model_key = model_key
        self.model = self._load_model(model_key, model_path=model_path)
        self.scaler = self._load_scaler()

    def _load_scaler(self) -> Any:
        scaler_candidates = [
            MODELS_DIR / "scaler.joblib",
            SRC_MODELS_DIR / "scaler.joblib",
            PRACTICAL10_DIR.parent / "Practical 9" / "outputs" / "models" / "balanced" / "scaler.joblib"
        ]
        for p in scaler_candidates:
            if p.exists():
                return joblib.load(p)
        return None

    def _load_model(self, model_key: str, model_path: Path = None) -> Any:
        if model_path is not None and Path(model_path).exists():
            return joblib.load(model_path)

        fname = self.AVAILABLE_MODELS.get(model_key, "random_forest_tuned.joblib")
        if (MODELS_DIR / fname).exists():
            return joblib.load(MODELS_DIR / fname)
        elif (SRC_MODELS_DIR / fname).exists():
            return joblib.load(SRC_MODELS_DIR / fname)
        elif (SRC_MODELS_DIR / "random_forest_champion.joblib").exists():
            return joblib.load(SRC_MODELS_DIR / "random_forest_champion.joblib")
        else:
            raise FileNotFoundError(f"Trained model not found at {MODELS_DIR / fname}")

    def switch_model(self, model_key: str) -> None:
        if model_key != self.current_model_key:
            self.model = self._load_model(model_key)
            self.current_model_key = model_key

    def predict(self, df_features: pd.DataFrame, df_clean: Any = None) -> pd.DataFrame:
        """
        Executes 100% independent machine learning multi-class prediction without heuristic overrides.
        """
        if df_features.empty:
            return pd.DataFrame()

        # Enforce canonical feature order
        feat_cols = [c for c in FEATURE_COLUMNS if c in df_features.columns]
        X = df_features[feat_cols].fillna(0).to_numpy(dtype=np.float32)

        # Scale features if model is linear (Logistic Regression requires standard scaling)
        is_linear = "logistic" in self.current_model_key.lower() or "linear" in self.current_model_key.lower()
        if is_linear and self.scaler is not None:
            X_input = self.scaler.transform(X)
        else:
            X_input = X

        # 1. Authoritative Class Predictions directly from ML Model
        raw_preds = self.model.predict(X_input)

        # 2. Probability & Confidence Calculation
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(X_input)
            confidences = np.max(probs, axis=1) * 100.0
        else:
            confidences = np.ones(len(raw_preds)) * 95.0

        anomaly_scores = df_features["anomaly_score"].values if "anomaly_score" in df_features else np.zeros(len(raw_preds))

        results = []
        for i in range(len(raw_preds)):
            pred_lbl = str(raw_preds[i])
            conf = float(confidences[i])
            anom = float(anomaly_scores[i])

            meta = ATTACK_METADATA.get(pred_lbl, {
                "display_name": pred_lbl.upper(),
                "severity": "Medium" if pred_lbl != "benign" else "Low",
                "badge_color": "#EF4444" if pred_lbl != "benign" else "#10B981",
                "action": "Inspect Manually" if pred_lbl != "benign" else "Allow Request"
            })

            # Check if flagged as an unsupervised anomaly by Isolation Forest (>= 0.52)
            is_anomaly = bool(anom >= ANOMALY_THRESHOLD)
            is_atk = bool(pred_lbl != "benign")

            results.append({
                "predicted_label": pred_lbl,
                "display_name": meta["display_name"],
                "severity": meta["severity"],
                "badge_color": meta["badge_color"],
                "confidence_pct": round(conf, 2),
                "anomaly_score": round(anom, 4),
                "is_anomaly": is_anomaly,
                "recommended_action": meta["action"],
                "is_attack": is_atk
            })

        return pd.DataFrame(results)
