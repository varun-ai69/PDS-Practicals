"""
main.py
=======
High-Performance FastAPI Backend for Practical 10 SOC Threat Platform.
Orchestrates the 5-stage authentic ML pipeline, SQLite persistence, and PDF reporting.
"""

import os
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

import pandas as pd
import numpy as np
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

PRACTICAL10_DIR = Path(__file__).resolve().parent.parent
WORKSPACE_DIR = PRACTICAL10_DIR.parent
sys.path.insert(0, str(WORKSPACE_DIR))
sys.path.insert(0, str(PRACTICAL10_DIR))

from pipeline.log_parser import parse_log_line
from pipeline.preprocessor import clean_and_normalize_logs
from pipeline.feature_extractor import extract_features_dataframe
from pipeline.inference_engine import ThreatInferenceEngine, ATTACK_METADATA
from pipeline.pdf_generator import generate_threat_audit_pdf
from backend.database import init_db, save_run, get_all_runs, get_run_by_id, delete_run

app = FastAPI(
    title="SOC Threat Telemetry Platform API",
    description="Machine Learning Cybersecurity Log Classification Platform (BE05000231_PDS Practical 10)",
    version="2.0.0"
)

# Enable CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database
init_db()

# Initialize ML inference engine
inference_engine = ThreatInferenceEngine()


SAMPLE_LOGS = {
    "mixed_attack_stream": (
        "192.168.1.10 - - [10/Oct/2026:13:55:36 +0000] \"GET /products/apparel/4469 HTTP/1.1\" 200 11300 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\"\n"
        "194.26.29.167 - - [10/Oct/2026:13:55:38 +0000] \"POST /login.php?user=admin%27%20OR%201=1-- HTTP/1.1\" 500 412 \"-\" \"sqlmap/1.5\"\n"
        "45.146.164.27 - - [10/Oct/2026:13:55:40 +0000] \"GET /comment.php?id=%3Cscript%3Ealert(document.cookie)%3C/script%3E HTTP/1.1\" 200 1024 \"-\" \"Mozilla/5.0\"\n"
        "185.220.100.241 - - [10/Oct/2026:13:55:42 +0000] \"GET /download.php?file=../../../../etc/passwd HTTP/1.1\" 403 240 \"-\" \"curl/7.81.0\"\n"
        "198.51.100.45 - - [10/Oct/2026:13:55:44 +0000] \"GET /proxy.php?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1\" 500 190 \"-\" \"Mozilla/5.0\"\n"
        "45.146.164.138 - - [10/Oct/2026:13:55:46 +0000] \"GET /tools/ping.php?host=127.0.0.1%3Bcat%20/etc/shadow HTTP/1.1\" 500 230 \"-\" \"Mozilla/5.0\"\n"
        "192.168.1.15 - - [10/Oct/2026:13:55:48 +0000] \"GET /cart/checkout HTTP/1.1\" 200 4520 \"-\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)\"\n"
        "192.220.66.221 - - [10/Oct/2026:13:55:50 +0000] \"POST /uploads/shell.php?cmd=whoami HTTP/1.1\" 500 620 \"-\" \"Mozilla/5.0\"\n"
        "194.26.29.112 - - [10/Oct/2026:13:55:52 +0000] \"POST /api/v1/auth/login HTTP/1.1\" 401 128 \"-\" \"Hydra/9.2\"\n"
        "171.25.193.20 - - [10/Oct/2026:13:55:54 +0000] \"GET /api/v1/feed HTTP/1.1\" 503 340 \"-\" \"LOIC/1.0\""
    ),
    "clean_benign": (
        "192.168.1.100 - - [10/Oct/2026:12:01:00 +0000] \"GET /home HTTP/1.1\" 200 8420 \"-\" \"Mozilla/5.0\"\n"
        "192.168.1.100 - - [10/Oct/2026:12:01:02 +0000] \"GET /static/css/main.css HTTP/1.1\" 200 1420 \"-\" \"Mozilla/5.0\"\n"
        "192.168.1.100 - - [10/Oct/2026:12:01:03 +0000] \"GET /static/js/bundle.js HTTP/1.1\" 200 32400 \"-\" \"Mozilla/5.0\"\n"
        "192.168.1.102 - - [10/Oct/2026:12:01:10 +0000] \"GET /products/category/hardware HTTP/1.1\" 200 12500 \"-\" \"Mozilla/5.0\"\n"
        "192.168.1.102 - - [10/Oct/2026:12:01:15 +0000] \"GET /products/view/1049 HTTP/1.1\" 200 9400 \"-\" \"Mozilla/5.0\"\n"
        "192.168.1.105 - - [10/Oct/2026:12:01:22 +0000] \"GET /about-us HTTP/1.1\" 200 5310 \"-\" \"Mozilla/5.0\"\n"
        "192.168.1.108 - - [10/Oct/2026:12:01:30 +0000] \"GET /contact HTTP/1.1\" 200 4200 \"-\" \"Mozilla/5.0\""
    ),
    "sqli_wave": (
        "45.146.164.27 - - [10/Oct/2026:14:00:01 +0000] \"GET /items.php?id=1%27%20UNION%20SELECT%20null,schema_name%20FROM%20information_schema.schemata-- HTTP/1.1\" 500 480 \"-\" \"sqlmap/1.5\"\n"
        "45.146.164.27 - - [10/Oct/2026:14:00:03 +0000] \"GET /items.php?id=1%27%20AND%201=1-- HTTP/1.1\" 200 4120 \"-\" \"sqlmap/1.5\"\n"
        "45.146.164.27 - - [10/Oct/2026:14:00:05 +0000] \"GET /items.php?id=1%27%20AND%201=2-- HTTP/1.1\" 500 210 \"-\" \"sqlmap/1.5\"\n"
        "45.146.164.27 - - [10/Oct/2026:14:00:07 +0000] \"GET /users.php?name=admin%27-- HTTP/1.1\" 200 3200 \"-\" \"Mozilla/5.0\"\n"
        "45.146.164.27 - - [10/Oct/2026:14:00:09 +0000] \"POST /login.php?user=%27%20OR%20%271%27=%271 HTTP/1.1\" 500 512 \"-\" \"sqlmap/1.5\""
    ),
    "path_traversal_wave": (
        "185.220.100.241 - - [10/Oct/2026:14:05:01 +0000] \"GET /download.php?file=../../../../etc/passwd HTTP/1.1\" 403 240 \"-\" \"curl/7.81.0\"\n"
        "185.220.100.241 - - [10/Oct/2026:14:05:03 +0000] \"GET /view?doc=..%2f..%2f..%2fwindows%2fwin.ini HTTP/1.1\" 404 180 \"-\" \"Mozilla/5.0\"\n"
        "185.220.100.241 - - [10/Oct/2026:14:05:05 +0000] \"GET /static/../../../../boot.ini HTTP/1.1\" 403 210 \"-\" \"curl/7.81.0\"\n"
        "185.220.100.241 - - [10/Oct/2026:14:05:07 +0000] \"GET /images/..%252f..%252f..%252fetc%252fshadow HTTP/1.1\" 403 190 \"-\" \"curl/7.81.0\""
    )
}


@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "current_model": inference_engine.current_model_key,
        "available_models": list(inference_engine.AVAILABLE_MODELS.keys())
    }


@app.get("/api/models")
def get_models():
    return {
        "current_model": inference_engine.current_model_key,
        "models": [
            {
                "key": k,
                "filename": v,
                "is_champion": "Champion" in k,
                "type": "Ensemble" if "Forest" in k else ("Tree" if "Tree" in k else "Linear")
            }
            for k, v in inference_engine.AVAILABLE_MODELS.items()
        ]
    }


@app.get("/api/sample-logs")
def get_sample_logs():
    return SAMPLE_LOGS


@app.post("/api/analyze-log")
async def analyze_log(
    request: Request
):
    """
    Executes the complete 5-stage ML pipeline on incoming log telemetry:
    Stage 1: Validation & Ingestion
    Stage 2: Common Log Format Structured Parsing
    Stage 3: Normalization & Preprocessing
    Stage 4: 30 Canonical Features + Real Isolation Forest Anomaly Scoring
    Stage 5: 100% Model-Driven Classification & DB Persistence
    """
    t_start = time.time()
    content_type = request.headers.get("content-type", "")
    log_content = ""
    filename = "live_stream_entry.log"
    model_key = "Random Forest Ensemble (Champion)"

    if "application/json" in content_type:
        try:
            body = await request.json()
            log_content = body.get("log_content") or body.get("raw_text") or ""
            model_key = body.get("model_key") or body.get("model_name") or model_key
            filename = body.get("filename") or body.get("run_name") or filename
        except Exception:
            pass
    else:
        form = await request.form()
        if "file" in form and hasattr(form["file"], "read"):
            upload_file = form["file"]
            filename = getattr(upload_file, "filename", "uploaded_logs.log")
            content_bytes = await upload_file.read()
            log_content = content_bytes.decode("utf-8", errors="replace")
        elif "raw_text" in form:
            log_content = str(form["raw_text"])
        if "model_key" in form:
            model_key = str(form["model_key"])

    MODEL_KEY_ALIASES = {
        "random_forest_tuned": "Random Forest Ensemble (Champion)",
        "random_forest": "Random Forest Ensemble (Base)",
        "decision_tree_tuned": "Decision Tree (Tuned Fast)",
        "decision_tree": "Decision Tree (Base)",
        "logistic_regression": "Logistic Regression (Linear Baseline)",
    }
    if model_key in MODEL_KEY_ALIASES:
        model_key = MODEL_KEY_ALIASES[model_key]

    if not log_content or not log_content.strip():
        raise HTTPException(status_code=400, detail="No log content provided. Upload a file or paste raw log lines.")

    lines = [l.strip() for l in log_content.splitlines() if l.strip()]
    if not lines:
        raise HTTPException(status_code=400, detail="Provided log file contains zero valid lines.")

    MAX_LINES = 5000
    if len(lines) > MAX_LINES:
        lines = lines[:MAX_LINES]

    if model_key and model_key in inference_engine.AVAILABLE_MODELS:
        inference_engine.switch_model(model_key)

    # Stage 1 & 2: Structured Parsing
    parsed_records = []
    for idx, line in enumerate(lines, start=1):
        parsed = parse_log_line(line, idx)
        if parsed:
            parsed_records.append(parsed)

    if not parsed_records:
        raise HTTPException(status_code=422, detail="Failed to parse log lines into structured format.")

    df_raw = pd.DataFrame(parsed_records)

    # Stage 3: Normalization & Preprocessing
    df_clean = clean_and_normalize_logs(df_raw)

    # Stage 4: 30 Canonical Features + Isolation Forest Anomaly Score
    df_features = extract_features_dataframe(df_clean)

    # Stage 5: Pure Machine Learning Classification
    df_preds = inference_engine.predict(df_features, df_clean)

    exec_time_ms = round((time.time() - t_start) * 1000, 2)

    # Compile merged records
    classified_list = []
    for i in range(len(df_preds)):
        c_row = df_clean.iloc[i]
        p_row = df_preds.iloc[i]
        classified_list.append({
            "line_number": int(c_row.get("log_id", i + 1)),
            "client_ip": str(c_row.get("ip_address", "127.0.0.1")),
            "timestamp": str(c_row.get("timestamp", "")),
            "method": str(c_row.get("method", "GET")),
            "resource": str(c_row.get("resource", "/")),
            "status_code": int(c_row.get("status_code", 200)),
            "bytes_sent": int(c_row.get("bytes_sent", 0)),
            "user_agent": str(c_row.get("user_agent", "-")),
            "anomaly_score": float(p_row.get("anomaly_score", 0.0)),
            "predicted_label": str(p_row.get("predicted_label", "benign")),
            "display_name": str(p_row.get("display_name", "Normal Traffic")),
            "confidence_pct": float(p_row.get("confidence_pct", 95.0)),
            "severity": str(p_row.get("severity", "Low")),
            "recommended_action": str(p_row.get("recommended_action", "Allow")),
            "is_attack": bool(p_row.get("is_attack", False)),
            "is_anomaly": bool(p_row.get("is_anomaly", False))
        })

    total_reqs = len(classified_list)
    attacks = [r for r in classified_list if r["is_attack"]]
    benign = [r for r in classified_list if not r["is_attack"]]
    attack_count = len(attacks)
    benign_count = len(benign)
    attack_rate = round((attack_count / max(1, total_reqs)) * 100, 2)

    # Attack Breakdown
    attack_breakdown: Dict[str, int] = {}
    for r in attacks:
        lbl = r["predicted_label"]
        attack_breakdown[lbl] = attack_breakdown.get(lbl, 0) + 1

    # Top Attack Type
    top_attack = max(attack_breakdown, key=attack_breakdown.get) if attack_breakdown else "None"

    # Top Attacking IPs
    ip_attack_counts: Dict[str, int] = {}
    ip_primary_vector: Dict[str, str] = {}
    for r in attacks:
        ip = r["client_ip"]
        ip_attack_counts[ip] = ip_attack_counts.get(ip, 0) + 1
        if ip not in ip_primary_vector:
            ip_primary_vector[ip] = r["display_name"]

    top_ips = [
        {
            "ip": ip,
            "attack_count": count,
            "primary_vector": ip_primary_vector.get(ip, "Attack"),
            "percentage": round((count / max(1, attack_count)) * 100, 1)
        }
        for ip, count in sorted(ip_attack_counts.items(), key=lambda x: -x[1])[:8]
    ]

    # Anomaly Scores
    scores = [r["anomaly_score"] for r in classified_list]
    mean_anom = round(float(np.mean(scores)), 4) if scores else 0.0
    max_anom = round(float(np.max(scores)), 4) if scores else 0.0
    anomalies_flagged = sum(1 for s in scores if s > 0.50)

    # Threat Risk Level
    if any(r["severity"] == "Critical" for r in attacks) or attack_rate > 35.0:
        risk_level = "Critical"
    elif attack_count > 5 or attack_rate > 15.0:
        risk_level = "High"
    elif attack_count > 0:
        risk_level = "Elevated"
    else:
        risk_level = "Nominal"

    run_id = f"RUN-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"

    run_summary = {
        "run_id": run_id,
        "filename": filename,
        "timestamp": datetime.utcnow().isoformat(),
        "total_requests": total_reqs,
        "benign_count": benign_count,
        "attack_count": attack_count,
        "attack_rate_pct": attack_rate,
        "mean_anomaly_score": mean_anom,
        "max_anomaly_score": max_anom,
        "anomalies_flagged": anomalies_flagged,
        "execution_time_ms": exec_time_ms,
        "model_used": inference_engine.current_model_key,
        "risk_level": risk_level,
        "top_attack_type": top_attack,
        "attack_breakdown": attack_breakdown,
        "top_ips": top_ips
    }

    # Persist in SQLite Database
    save_run(run_summary, classified_list)

    return {
        "summary": run_summary,
        "requests": classified_list
    }


@app.get("/api/history")
def get_history(limit: int = 50):
    return get_all_runs(limit=limit)


@app.get("/api/runs/{run_id}")
def get_run(run_id: str):
    run_data = get_run_by_id(run_id)
    if not run_data:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found in database.")
    return run_data


@app.delete("/api/runs/{run_id}")
def remove_run(run_id: str):
    success = delete_run(run_id)
    return {"success": success, "run_id": run_id}


@app.get("/api/export-pdf/{run_id}")
def export_pdf(run_id: str):
    run_data = get_run_by_id(run_id)
    if not run_data:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found.")

    summary = {
        "total_requests": run_data["total_requests"],
        "attacks_count": run_data["attack_count"],
        "attack_rate": run_data["attack_rate_pct"],
        "benign_count": run_data["benign_count"],
        "benign_rate": round(100.0 - run_data["attack_rate_pct"], 2),
        "novel_anomalies": sum(1 for r in run_data.get("requests", []) if r.get("anomaly_score", 0) >= 0.52)
    }

    df_results = pd.DataFrame(run_data.get("requests", []))
    if not df_results.empty:
        df_results["ip_address"] = df_results["client_ip"]

    model_name = run_data.get("model_used", "Random Forest Ensemble (Champion)")

    pdf_bytes = bytes(generate_threat_audit_pdf(summary, df_results, model_name))

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=threat_audit_{run_id}.pdf"
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
