"""
inference_engine.py
===================
Model Inference, Confidence Scoring & Zero-Day Anomaly Detection Engine (Stage 4).
Supports:
1. Random Forest Ensemble (Champion)
2. Decision Tree (Tuned)
3. Logistic Regression (Baseline)
"""

import sys
from pathlib import Path
from typing import Dict, Any, List, Tuple
import pandas as pd
import numpy as np
import joblib

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MODELS_DIR = PROJECT_ROOT / "Practical 9" / "outputs" / "models"
RETRAIN_MODELS_DIR = PROJECT_ROOT / "model_retraining" / "outputs" / "models"


# Human-Readable Security Metadata
ATTACK_METADATA = {
    "benign": {
        "display_name": "Normal / Legitimate Traffic",
        "severity": "Info",
        "badge_color": "#10B981",
        "action": "Allow Request (No Intervention Required)"
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
        "action": "Sanitize Input & Content-Security-Policy Alert"
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
        "action": "Enforce CAPTCHA & Exponential Backoff Delay"
    },
    "ddos_http_flood": {
        "display_name": "DDoS HTTP Flood",
        "severity": "High",
        "badge_color": "#B91C1C",
        "action": "Trigger Cloudflare / Edge Rate-Limiting"
    },
    "dir_fuzzing": {
        "display_name": "Directory Fuzzing / Enumeration",
        "severity": "Medium",
        "badge_color": "#D97706",
        "action": "Return HTTP 404 Honeytoken / Rate-Limit Subnet"
    },
    "mal_scanner": {
        "display_name": "Malicious Vulnerability Scanner",
        "severity": "Medium",
        "badge_color": "#D97706",
        "action": "Drop Connection & Log Offensive Signature"
    },
    "ssrf": {
        "display_name": "Server-Side Request Forgery (SSRF)",
        "severity": "Critical",
        "badge_color": "#991B1B",
        "action": "Block Metadata Endpoints (169.254.169.254)"
    },
    "web_shell": {
        "display_name": "Web Shell Execution / Upload",
        "severity": "Critical",
        "badge_color": "#7F1D1D",
        "action": "Quarantine File Upload & Terminate Session"
    }
}


class ThreatInferenceEngine:
    """Manages model loading and real-time threat inference."""

    AVAILABLE_MODELS = {
        "Random Forest Ensemble (Champion)": "random_forest_retrained_170k.joblib",
        "Random Forest Ensemble (Academic Base)": "random_forest_balanced.joblib",
        "Decision Tree (Tuned Fast)": "decision_tree_retrained_170k.joblib",
        "Decision Tree (Academic Base)": "decision_tree_tuned.joblib",
        "Logistic Regression (Linear Baseline)": "logistic_regression_retrained_170k.joblib",
        "Logistic Regression (Academic Base)": "logistic_regression_balanced.joblib"
    }

    def __init__(self, model_key: str = "Random Forest Ensemble (Champion)", model_path: Path = None):
        self.current_model_key = model_key
        self.model = self._load_model(model_key, model_path=model_path)

    def _load_model(self, model_key: str, model_path: Path = None) -> Any:
        if model_path is not None and Path(model_path).exists():
            return joblib.load(model_path)
            
        fname = self.AVAILABLE_MODELS.get(model_key, "random_forest_retrained_170k.joblib")
        # Check retrained models first for 170k models
        if (RETRAIN_MODELS_DIR / fname).exists():
            return joblib.load(RETRAIN_MODELS_DIR / fname)
        elif (MODELS_DIR / fname).exists():
            return joblib.load(MODELS_DIR / fname)
        elif (MODELS_DIR / "random_forest_balanced.joblib").exists():
            return joblib.load(MODELS_DIR / "random_forest_balanced.joblib")
        else:
            raise FileNotFoundError(f"Trained model not found at {MODELS_DIR / fname}")

    def switch_model(self, model_key: str) -> None:
        if model_key != self.current_model_key:
            self.model = self._load_model(model_key)
            self.current_model_key = model_key

    def predict(self, df_features: pd.DataFrame, df_clean: Any = None) -> pd.DataFrame:
        """Executes multi-class prediction, confidence calculation, and anomaly detection."""
        if df_features.empty:
            return pd.DataFrame()

        X = df_features.fillna(0).to_numpy(dtype=np.float32)

        # Class predictions
        raw_preds = self.model.predict(X)

        # Probabilities
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(X)
            confidences = np.max(probs, axis=1) * 100
        else:
            confidences = np.ones(len(raw_preds)) * 95.0

        anomaly_scores = df_features["anomaly_score"].values if "anomaly_score" in df_features else np.zeros(len(raw_preds))

        results = []
        for i in range(len(raw_preds)):
            pred_lbl = raw_preds[i]
            conf = confidences[i]
            anom = anomaly_scores[i]
            f_row = df_features.iloc[i]

            # Domain-Specific Signature Escalation
            if f_row.get("has_sql_semantics", 0) == 1.0:
                pred_lbl = "sqli"
                conf = max(conf, 96.0)
            elif f_row.get("has_script_semantics", 0) == 1.0:
                pred_lbl = "xss"
                conf = max(conf, 96.0)
            elif f_row.get("has_traversal_semantics", 0) == 1.0:
                pred_lbl = "path_traversal"
                conf = max(conf, 96.0)
            elif f_row.get("has_command_semantics", 0) == 1.0:
                pred_lbl = "command_injection"
                conf = max(conf, 96.0)
            elif f_row.get("has_internal_ip_semantics", 0) == 1.0:
                pred_lbl = "ssrf"
                conf = max(conf, 95.0)
            elif f_row.get("is_known_scanner", 0) == 1.0:
                pred_lbl = "mal_scanner"
                conf = max(conf, 92.0)
            elif f_row.get("failed_login_count", 0) >= 3.0:
                pred_lbl = "brute_force"
                conf = max(conf, 92.0)

            # Endpoint-specific detection if cleaned telemetry is available
            if df_clean is not None and hasattr(df_clean, "iloc") and i < len(df_clean):
                r_res = str(df_clean.iloc[i].get("resource", "")).lower()
                r_ua = str(df_clean.iloc[i].get("user_agent", "")).lower()
                if any(fz in r_res for fz in [".env", ".git", "wp-config", "backup.sql", "phpmyadmin", "web.config", ".svn", ".ds_store", "server-status", "actuator", "swagger", "dump.rdb", "database.yml", "backup.", "console/"]):
                    pred_lbl = "dir_fuzzing"
                    conf = max(conf, 92.0)
                elif any(ws in r_res for ws in ["shell.php", "cmd.php", "c99.php", "r57.php", "b374k.php", "wso.php", "eval=", "passthru("]):
                    pred_lbl = "web_shell"
                    conf = max(conf, 92.0)
                elif f_row.get("requests_per_ip_1min", 0) > 8.0 and any(fl in r_ua for fl in ["slowloris", "flood", "loic"]):
                    pred_lbl = "ddos_http_flood"
                    conf = max(conf, 90.0)

            meta = ATTACK_METADATA.get(pred_lbl, {
                "display_name": str(pred_lbl),
                "severity": "Unknown",
                "badge_color": "#6B7280",
                "action": "Inspect Manually"
            })

            # Zero-Day / Novel Anomaly rule
            is_novel = bool(anom > 0.60 and (pred_lbl != "benign" or conf < 80.0))
            
            # If model classified as benign but anomaly score is exceptionally high (>0.60), flag as Novel Zero-Day threat
            if is_novel and pred_lbl == "benign":
                disp_name = "Zero-Day Novel Threat (High Anomaly)"
                sev = "High"
                act = "Quarantine Request & Inspect Novel Pattern"
                is_atk = True
            else:
                disp_name = meta["display_name"]
                sev = meta["severity"]
                act = meta["action"]
                is_atk = (pred_lbl != "benign")

            results.append({
                "predicted_label": pred_lbl,
                "display_name": disp_name,
                "severity": sev,
                "confidence_pct": round(float(conf), 2),
                "anomaly_score": round(float(anom), 4),
                "is_novel_anomaly": is_novel,
                "recommended_action": act,
                "is_attack": is_atk
            })

        return pd.DataFrame(results)
