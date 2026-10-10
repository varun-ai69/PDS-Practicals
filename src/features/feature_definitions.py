"""
feature_definitions.py
======================
Canonical Feature Definitions for PDS Web Threat Intelligence Platform.

Defines 28 mathematically grounded, non-leaky features across 4 dimensions:
1. Lexical / Structural URL & Path (9 features)
2. Payload Complexity & Semantic Entropy (7 features)
3. Temporal & Session Dynamics (6 features)
4. Network & Client Header Telemetry (6 features)
"""

import math
import collections
import urllib.parse
import re
from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd


# 30 Canonical Feature Names in Standardized Order (Including GTU Syllabus Specifics)
CANONICAL_FEATURE_NAMES = [
    # 1. Lexical & Path Features (9)
    "url_length",
    "url_entropy",
    "path_depth",
    "query_param_count",
    "special_char_ratio",
    "digit_ratio",
    "uppercase_ratio",
    "double_slash_count",
    "percent_encoding_count",

    # 2. Payload Complexity & Semantics (7)
    "payload_length",
    "payload_entropy",
    "has_sql_semantics",
    "has_script_semantics",
    "has_traversal_semantics",
    "has_command_semantics",
    "has_internal_ip_semantics",

    # 3. Temporal & Session Dynamics (7)
    "inter_request_time",
    "requests_per_ip_1min",
    "requests_per_ip_5min",
    "request_velocity_1sec",
    "burst_ratio",
    "unique_resources_per_ip_5min",
    "failed_login_count",

    # 4. Network & Header Telemetry (7)
    "status_code",
    "is_error_status",
    "bytes_sent",
    "user_agent_length",
    "user_agent_entropy",
    "is_known_scanner",
    "is_bot"
]


def calculate_shannon_entropy(text: str) -> float:
    """Calculates character-level Shannon Entropy in bits.
    Higher entropy (> 4.0 bits) indicates randomized, encoded, or obfuscated payloads.
    """
    if not isinstance(text, str) or not text:
        return 0.0
    length = len(text)
    counts = collections.Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_lexical_features(url_string: str) -> Dict[str, float]:
    """Extracts 9 structural and lexical features from a URL / request path."""
    if not isinstance(url_string, str) or not url_string:
        return {
            "url_length": 0,
            "url_entropy": 0.0,
            "path_depth": 0,
            "query_param_count": 0,
            "special_char_ratio": 0.0,
            "digit_ratio": 0.0,
            "uppercase_ratio": 0.0,
            "double_slash_count": 0,
            "percent_encoding_count": 0
        }

    length = len(url_string)
    entropy = calculate_shannon_entropy(url_string)
    path_depth = url_string.count("/")
    
    # Query parameters count
    query_count = 0
    if "?" in url_string:
        query_part = url_string.split("?", 1)[1]
        query_count = query_part.count("&") + 1

    # Character distributions
    digits = sum(c.isdigit() for c in url_string)
    uppers = sum(c.isupper() for c in url_string)
    # Special non-alphanumeric chars
    specials = sum(not c.isalnum() for c in url_string)

    double_slashes = url_string.count("//")
    percent_encodings = len(re.findall(r"%[0-9a-fA-F]{2}", url_string))

    return {
        "url_length": length,
        "url_entropy": entropy,
        "path_depth": path_depth,
        "query_param_count": query_count,
        "special_char_ratio": round(specials / length, 4) if length else 0.0,
        "digit_ratio": round(digits / length, 4) if length else 0.0,
        "uppercase_ratio": round(uppers / length, 4) if length else 0.0,
        "double_slash_count": double_slashes,
        "percent_encoding_count": percent_encodings
    }


# High-efficiency pre-compiled patterns for semantic density extraction
_SQL_PATTERN = re.compile(
    r"\b(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table|"
    r"waitfor\s+delay|information_schema|order\s+by|\bor\b\s+\d+=\d+|\band\b\s+\d+=\d+)\b",
    re.IGNORECASE
)
_SCRIPT_PATTERN = re.compile(
    r"(<script|</script>|javascript:|onerror\s*=|onload\s*=|document\.cookie|alert\s*\()",
    re.IGNORECASE
)
_TRAVERSAL_PATTERN = re.compile(
    r"(\.\./|\.\.\\|/etc/passwd|win\.ini|boot\.ini|%2e%2e%2f)",
    re.IGNORECASE
)
_COMMAND_PATTERN = re.compile(
    r"([;\|\&`\$\(]\s*(?:cat|whoami|id|uname|curl|wget|sh|bash|nc|chmod)\b|/(?:bin|usr/bin)/(?:sh|bash))",
    re.IGNORECASE
)
_INTERNAL_IP_PATTERN = re.compile(
    r"(169\.254\.169\.254|localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
    re.IGNORECASE
)


def extract_payload_semantics(payload_str: str) -> Dict[str, Any]:
    """Extracts 7 payload complexity and semantic footprint features."""
    if not isinstance(payload_str, str) or not payload_str or payload_str in ("-", "null", "none"):
        return {
            "payload_length": 0,
            "payload_entropy": 0.0,
            "has_sql_semantics": 0,
            "has_script_semantics": 0,
            "has_traversal_semantics": 0,
            "has_command_semantics": 0,
            "has_internal_ip_semantics": 0
        }

    length = len(payload_str)
    entropy = calculate_shannon_entropy(payload_str)
    
    # Safely decode percent encodings to catch evasion payloads (%20, %3B, etc.)
    try:
        dec_str = urllib.parse.unquote(payload_str)
    except Exception:
        dec_str = payload_str
    
    match_str = payload_str + " " + dec_str
    
    return {
        "payload_length": length,
        "payload_entropy": entropy,
        "has_sql_semantics": 1 if _SQL_PATTERN.search(match_str) else 0,
        "has_script_semantics": 1 if _SCRIPT_PATTERN.search(match_str) else 0,
        "has_traversal_semantics": 1 if _TRAVERSAL_PATTERN.search(match_str) else 0,
        "has_command_semantics": 1 if _COMMAND_PATTERN.search(match_str) else 0,
        "has_internal_ip_semantics": 1 if _INTERNAL_IP_PATTERN.search(match_str) else 0
    }


_SCANNER_UA_PATTERN = re.compile(
    r"(sqlmap|nikto|masscan|acunetix|nessus|openvas|gobuster|dirbuster|nmap|zgrab|wpscan|hydra)",
    re.IGNORECASE
)
_BOT_UA_PATTERN = re.compile(
    r"(bot|crawler|spider|slurp|facebook|google|bing|yandex|duckduckgo)",
    re.IGNORECASE
)


def extract_header_features(status_code: int, bytes_sent: int, user_agent: str) -> Dict[str, Any]:
    """Extracts 7 network and header telemetry features."""
    ua = str(user_agent) if user_agent else ""
    ua_len = len(ua)
    ua_entropy = calculate_shannon_entropy(ua)
    
    status = int(status_code) if status_code else 200
    is_error = 1 if status >= 400 else 0
    bytes_val = int(bytes_sent) if bytes_sent else 0
    
    is_scanner = 1 if _SCANNER_UA_PATTERN.search(ua) else 0
    is_bot = 1 if _BOT_UA_PATTERN.search(ua) else 0

    return {
        "status_code": status,
        "is_error_status": is_error,
        "bytes_sent": bytes_val,
        "user_agent_length": ua_len,
        "user_agent_entropy": ua_entropy,
        "is_known_scanner": is_scanner,
        "is_bot": is_bot
    }
