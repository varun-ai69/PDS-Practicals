"""
database.py
===========
SQLite Telemetry Database for Practical 10 SOC Dashboard.
Persists analysis audit runs and individual classified request records.
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional

DB_DIR = Path(__file__).resolve().parent.parent / "data"
DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DB_DIR / "telemetry.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initializes the database schema if not already present."""
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # 1. Runs Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT UNIQUE NOT NULL,
                filename TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                total_requests INTEGER NOT NULL,
                benign_count INTEGER NOT NULL,
                attack_count INTEGER NOT NULL,
                attack_rate_pct REAL NOT NULL,
                mean_anomaly_score REAL NOT NULL,
                max_anomaly_score REAL NOT NULL,
                execution_time_ms REAL NOT NULL,
                model_used TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                top_attack_type TEXT NOT NULL,
                attack_breakdown_json TEXT NOT NULL
            );
        """)

        # 2. Classified Requests Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS classified_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                line_number INTEGER NOT NULL,
                client_ip TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                method TEXT NOT NULL,
                resource TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                bytes_sent INTEGER NOT NULL,
                user_agent TEXT NOT NULL,
                anomaly_score REAL NOT NULL,
                predicted_label TEXT NOT NULL,
                display_name TEXT NOT NULL,
                confidence_pct REAL NOT NULL,
                severity TEXT NOT NULL,
                recommended_action TEXT NOT NULL,
                is_attack INTEGER NOT NULL,
                FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
            );
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_requests_run_id ON classified_requests(run_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_requests_ip ON classified_requests(client_ip);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_requests_label ON classified_requests(predicted_label);")
        conn.commit()


def save_run(run_summary: Dict[str, Any], requests_list: List[Dict[str, Any]]) -> str:
    """Saves an analysis run and all its classified records into the database."""
    init_db()
    run_id = run_summary["run_id"]

    with get_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO runs (
                run_id, filename, timestamp, total_requests, benign_count, attack_count,
                attack_rate_pct, mean_anomaly_score, max_anomaly_score, execution_time_ms,
                model_used, risk_level, top_attack_type, attack_breakdown_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            run_id,
            run_summary.get("filename", "uploaded_logs.log"),
            run_summary.get("timestamp", datetime.utcnow().isoformat()),
            int(run_summary.get("total_requests", len(requests_list))),
            int(run_summary.get("benign_count", 0)),
            int(run_summary.get("attack_count", 0)),
            float(run_summary.get("attack_rate_pct", 0.0)),
            float(run_summary.get("mean_anomaly_score", 0.0)),
            float(run_summary.get("max_anomaly_score", 0.0)),
            float(run_summary.get("execution_time_ms", 0.0)),
            str(run_summary.get("model_used", "Random Forest Ensemble (Champion)")),
            str(run_summary.get("risk_level", "Low")),
            str(run_summary.get("top_attack_type", "None")),
            json.dumps(run_summary.get("attack_breakdown", {}))
        ))

        # Batch insert classified requests
        req_rows = []
        for r in requests_list:
            req_rows.append((
                run_id,
                int(r.get("line_number", 1)),
                str(r.get("client_ip", "127.0.0.1")),
                str(r.get("timestamp", "")),
                str(r.get("method", "GET")),
                str(r.get("resource", "/")),
                int(r.get("status_code", 200)),
                int(r.get("bytes_sent", 0)),
                str(r.get("user_agent", "-")),
                float(r.get("anomaly_score", 0.0)),
                str(r.get("predicted_label", "benign")),
                str(r.get("display_name", "Normal Traffic")),
                float(r.get("confidence_pct", 0.0)),
                str(r.get("severity", "Low")),
                str(r.get("recommended_action", "Allow")),
                1 if r.get("is_attack") else 0
            ))

        cursor.executemany("""
            INSERT INTO classified_requests (
                run_id, line_number, client_ip, timestamp, method, resource,
                status_code, bytes_sent, user_agent, anomaly_score, predicted_label,
                display_name, confidence_pct, severity, recommended_action, is_attack
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, req_rows)

        conn.commit()

    return run_id


def get_all_runs(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves metadata of the most recent analysis runs."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()

    results = []
    for r in rows:
        d = dict(r)
        try:
            d["attack_breakdown"] = json.loads(d["attack_breakdown_json"])
        except Exception:
            d["attack_breakdown"] = {}
        results.append(d)
    return results


def get_run_by_id(run_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves full details and classified requests for a specific run."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,))
        run_row = cursor.fetchone()
        if not run_row:
            return None

        run_dict = dict(run_row)
        try:
            run_dict["attack_breakdown"] = json.loads(run_dict["attack_breakdown_json"])
        except Exception:
            run_dict["attack_breakdown"] = {}

        cursor.execute("""
            SELECT line_number, client_ip, timestamp, method, resource, status_code,
                   bytes_sent, user_agent, anomaly_score, predicted_label, display_name,
                   confidence_pct, severity, recommended_action, is_attack
            FROM classified_requests
            WHERE run_id = ?
            ORDER BY line_number ASC
        """, (run_id,))
        req_rows = [dict(row) for row in cursor.fetchall()]
        run_dict["requests"] = req_rows

    return run_dict


def delete_run(run_id: str) -> bool:
    """Deletes a run and all associated records."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM classified_requests WHERE run_id = ?", (run_id,))
        cursor.execute("DELETE FROM runs WHERE run_id = ?", (run_id,))
        conn.commit()
    return True
