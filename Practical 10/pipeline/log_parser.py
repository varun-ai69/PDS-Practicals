"""
log_parser.py
=============
Robust Multi-Format Web Log Parser for Stage 1 of the Reusable Pipeline.
Supports:
- Apache Combined / Common Log Format
- Nginx Access Logs
- JSON Log Lines
- Raw HTTP Request Lines
"""

import re
import json
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List, Optional
import pandas as pd


# Regex Patterns for Log Formats
APACHE_COMBINED_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<resource>\S+)(?:\s+(?P<protocol>[^"]+))?"\s+(?P<status_code>\d+)\s+(?P<bytes_sent>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

RAW_HTTP_PATTERN = re.compile(
    r'^(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(?P<resource>\S+)(?:\s+(?P<protocol>\S+))?',
    re.IGNORECASE
)


def parse_log_line(line: str, line_num: int = 1) -> Dict[str, Any]:
    """Parses a single log line into a standardized 13-field dictionary."""
    text = line.strip()
    if not text:
        return {}

    # 1. Try Apache / Nginx Combined Regex
    m = APACHE_COMBINED_PATTERN.match(text)
    if m:
        d = m.groupdict()
        status = int(d["status_code"]) if d["status_code"] and d["status_code"].isdigit() else 200
        bytes_val = int(d["bytes_sent"]) if d["bytes_sent"] and d["bytes_sent"].isdigit() else 0
        return {
            "log_id": line_num,
            "ip_address": d["ip"] or "127.0.0.1",
            "timestamp": d["timestamp"] or datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000"),
            "method": (d["method"] or "GET").upper(),
            "resource": d["resource"] or "/",
            "protocol": d["protocol"] or "HTTP/1.1",
            "status_code": status,
            "bytes_sent": bytes_val,
            "referer": d["referer"] or "-",
            "user_agent": d["user_agent"] or "Mozilla/5.0",
            "parse_format": "apache_combined",
            "raw_log": text
        }

    # 2. Try JSON Line
    if text.startswith("{") and text.endswith("}"):
        try:
            j = json.loads(text)
            return {
                "log_id": line_num,
                "ip_address": j.get("ip") or j.get("client_ip") or "127.0.0.1",
                "timestamp": j.get("timestamp") or j.get("time") or datetime.utcnow().isoformat(),
                "method": str(j.get("method") or "GET").upper(),
                "resource": j.get("resource") or j.get("uri") or j.get("url") or "/",
                "protocol": j.get("protocol") or "HTTP/1.1",
                "status_code": int(j.get("status") or j.get("status_code") or 200),
                "bytes_sent": int(j.get("bytes") or j.get("bytes_sent") or 0),
                "referer": j.get("referer") or "-",
                "user_agent": j.get("user_agent") or "Mozilla/5.0",
                "parse_format": "json",
                "raw_log": text
            }
        except Exception:
            pass

    # 3. Try Raw HTTP Request Line (e.g. GET /index.php?id=1 HTTP/1.1)
    m_http = RAW_HTTP_PATTERN.match(text)
    if m_http:
        d_http = m_http.groupdict()
        return {
            "log_id": line_num,
            "ip_address": "192.168.1.100",
            "timestamp": datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000"),
            "method": d_http["method"].upper(),
            "resource": d_http["resource"],
            "protocol": d_http["protocol"] or "HTTP/1.1",
            "status_code": 200,
            "bytes_sent": 1250,
            "referer": "-",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "parse_format": "raw_http",
            "raw_log": text
        }

    # 4. Fallback Generic Path / Payload
    return {
        "log_id": line_num,
        "ip_address": "10.0.0.1",
        "timestamp": datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000"),
        "method": "GET",
        "resource": text if text.startswith("/") else f"/{text}",
        "protocol": "HTTP/1.1",
        "status_code": 200,
        "bytes_sent": 850,
        "referer": "-",
        "user_agent": "Mozilla/5.0",
        "parse_format": "raw_fallback",
        "raw_log": text
    }


def parse_logs_text(raw_text: str) -> pd.DataFrame:
    """Parses a multi-line raw log string into a structured pandas DataFrame."""
    lines = raw_text.strip().split("\n")
    records = []
    for idx, line in enumerate(lines, 1):
        if line.strip():
            rec = parse_log_line(line, idx)
            if rec:
                records.append(rec)
    return pd.DataFrame(records)
