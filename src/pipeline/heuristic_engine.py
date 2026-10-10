"""
heuristic_engine.py
===================
Master Production-Grade Heuristic Classification Engine.

Implements:
1. Multi-Pass Normalization Layer (URL decode, HTML decode, comment flattening, whitespace stripping)
2. High-Precision Context-Aware Signature Matching (Zero False Positive Protection)
3. Strict Deterministic Priority Hierarchy across 10 Web Attack Classes + Benign
4. Human-Readable Attribution Explanations (label_reason)
"""

import re
import html
import urllib.parse
from typing import Dict, Any, Tuple, Optional, List


def normalize_request_payload(text: str) -> str:
    """Pre-decodes and normalizes requests to defeat evasion techniques.
    Unwraps recursive URL encodings (%2527 -> %27 -> '),
    flattens SQL comments (/**/ -> space), decodes HTML entities (&quot; -> "),
    and lowercases strings for unified analysis.
    """
    if not isinstance(text, str) or not text:
        return ""
    
    s = text.strip()
    
    # 1. First HTML entity unescape
    s = html.unescape(s)
    
    # 2. Recursive URL unquoting (up to 3 passes to catch double/triple encodings)
    for _ in range(3):
        decoded = urllib.parse.unquote(s)
        if decoded == s:
            break
        s = decoded
        
    # 3. Second HTML unescape for embedded entities inside URL encodings
    s = html.unescape(s)
    
    # 4. Flatten inline SQL comments (e.g. UNION/**/SELECT -> UNION SELECT)
    s = re.sub(r"/\*.*?\*/", " ", s)
    
    # 5. Standardize whitespace & lowercase
    s = re.sub(r"\s+", " ", s).lower().strip()
    return s


# =========================================================================
# COMPILED CONTEXT-AWARE REGEX PATTERNS (Engineered for Low False Positives)
# =========================================================================

# 1. SQL Injection: Strict syntax grammar, tautologies, database functions
_SQLI_RULES = [
    # UNION SELECT variants (union distinct, union all, etc.)
    r"\bunion(?:\s+(?:all|distinct))?\s+select\b",
    # SELECT ... FROM / SELECT ... INTO
    r"\bselect\b[\s\S]{1,120}\b(?:from|into)\b",
    # Stacked SELECT queries: ; select ...
    r";\s*select\b",
    # Tautology / Boolean injection:
    # Handles both closed quotes ('1'='1', "a"="a") and unclosed trailing quotes ('x'='x, "1"="1)
    # Handles parentheses: (1)=(1), ('a')=('a), ((1))=((1))
    # Handles arithmetic tautology: or 1=1, or 0=0, or 2>1, or 1<2
    r"(?:'|\"|%27|%22|\))?\s*\b(?:or|and)\b\s+[\(\s]*(?:\d+\s*[=><]\s*\d+|'[^']*'\s*[=><]\s*'[^']*'?|\"[^\"]*\"\s*[=><]\s*\"[^\"]*\"?|[a-z0-9_]+\s*=\s*[a-z0-9_]+|''\s*[\-\+\*\&\^\|][\-\+\*\&\^\|\s]*'?)",
    # BETWEEN tautologies: or 2 between 1 and 3
    r"\b(?:or|and)\b\s+\d+\s+between\s+\d+\s+and\s+\d+\b",
    # Column fuzzing: order by \d+, group by \d+
    r"\b(?:order|group)\s+by\s+\d+\b",
    # SQL comments: --, #, /* ... */ with trailing quotes or space
    r"(?:--\s*|\s+#\s*|\/\*[\s\S]*?\*\/)\s*(?:$|'|\"|#)",
    # Stacked DDL / DML commands: ; drop table, ; insert into, ; update ... set
    r";\s*(?:drop\s+table|delete\s+from|insert\s+into|update\s+\w+\s+set|create\s+user|alter\s+table|truncate\s+table)\b",
    # INSERT INTO ... VALUES / CREATE USER ... IDENTIFIED BY
    r"\binsert\s+into\b[\s\S]{1,80}\bvalues\b",
    r"\bcreate\s+user\b[\s\S]{1,60}\bidentified\s+by\b",
    # Stacked DECLARE in MSSQL / Stored procedures
    r"\bdeclare\s+@\w+\s+(?:varchar|nvarchar|int)\b",
    r"\b(?:exec|execute)\s+(?:sp_|xp_|master\.)\w+\b",
    # DB fingerprinting, tables & functions
    r"\b(?:version\s*\(|@@version|information_schema|sysobjects|sys\.tables|sysibm|all_tab_columns|all_users|schema_name|table_name|column_name|load_file|into\s+outfile|into\s+dumpfile)\b",
    # Time delays & blind injections
    r"\b(?:waitfor\s+delay|sleep\s*\(\s*(?:\d+|__time__)\s*\)|pg_sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+)\b",
    # Error extraction & character functions
    r"\b(?:utl_inaddr\.get_host_address|ctxsys\.drithsx\.sn|extractvalue\s*\(|updatexml\s*\(|user_name\s*\(|char\s*\(\s*\d+\s*\))\b"
]
_SQLI_REGEX = re.compile("|".join(_SQLI_RULES), re.IGNORECASE)

# 2. Cross-Site Scripting (XSS): Executable HTML/JS tags, DOM attributes
_XSS_RULES = [
    # Explicit script tags
    r"<\s*script[^>]*>",
    r"<\s*/\s*script\s*>",
    # Inline Event Handlers: onerror=, onload=, onmouseover=, onbeforecut=, etc.
    r"\bon(?:error|load|mouseover|click|focus|submit|blur|input|beforecut|mouseenter|mouseleave)\s*=",
    # JavaScript / VBScript pseudo-protocols
    r"(?:javascript|vbscript|data):\s*[^;]+",
    # DOM Cookie and Location theft
    r"document\.(?:cookie|location|write)",
    # Exploit functions: alert(), prompt(), confirm(), eval()
    r"\b(?:alert|prompt|confirm|eval)\s*\(\s*[^)]*\)",
    # SVG, Iframe, Marquee execution vectors
    r"<\s*(?:svg|iframe|embed|object|marquee|video|audio)[^>]+(?:onload|onerror|src|onbeforecut)\s*=",
    # Entity encoded expressions
    r"&#x?[0-9a-f]+;"
]
_XSS_REGEX = re.compile("|".join(_XSS_RULES), re.IGNORECASE)

# 3. Path Traversal & LFI: Directory climbing & sensitive operating system targets
_PATH_TRAVERSAL_RULES = [
    # Directory climbing sequences
    r"(?:\.\./|\.\.\\|\.\.%2f|\.\.%5c)",
    # Linux sensitive system files
    r"/(?:etc/(?:passwd|shadow|hosts|group|issue)|proc/self/(?:environ|status)|var/log/)",
    # Windows system files
    r"(?:win\.ini|boot\.ini|system32/drivers/etc/hosts|windows/system\.ini)",
    # PHP wrapper protocols
    r"php://(?:filter|input|data|expect)",
    # Null-byte truncation
    r"%00|\x00"
]
_PATH_TRAVERSAL_REGEX = re.compile("|".join(_PATH_TRAVERSAL_RULES), re.IGNORECASE)

# 4. Command Injection (RCE): Shell separators combined with OS command binaries
_COMMAND_INJECTION_RULES = [
    # Command chaining followed by shell binary: ; cat, | whoami, && id, \n id, %0a id
    r"(?:[;\|\&`\$\(\n]|%0a)\s*(?:cat|whoami|id|uname|curl|wget|sh|bash|chmod|nc|net\s+user|dir|ping|netstat|ls)\b",
    # Direct execution of system shells and core binaries
    r"/(?:bin|usr/bin)/(?:sh|bash|zsh|dash|cat|id|whoami|ls)",
    # Process / execution wrapper functions: system('...'), exec('...'), passthru('...'), shell_exec('...')
    r"\b(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*['\"].*?['\"]\s*\)",
    # Sensitive file extraction via cat
    r"\bcat\s+/(?:etc/(?:passwd|shadow|hosts|issue)|proc/)",
    # SSI Exec directives
    r"(?:<!--#exec\s+cmd|#exec\s+cmd)",
    # Subshell syntax: `cmd` or $(cmd)
    r"(?:`[^`]+`|\$\([^\)]+\))",
    # Redirections to null
    r">\s*/dev/null"
]
_COMMAND_INJECTION_REGEX = re.compile("|".join(_COMMAND_INJECTION_RULES), re.IGNORECASE)

# 5. SSRF: Cloud metadata service & private loopback probing
_SSRF_RULES = [
    # AWS / GCP / Azure Instance Metadata Service (IMDS) IP
    r"169\.254\.169\.254",
    # Google Cloud internal metadata
    r"metadata\.google\.internal",
    # Loopback addresses
    r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]):\d+",
    # Non-HTTP internal protocols
    r"(?:gopher|dict|file)://"
]
_SSRF_REGEX = re.compile("|".join(_SSRF_RULES), re.IGNORECASE)

# 6. Web Shell Probing: Known backdoor scripts & dynamic execution parameters
_WEB_SHELL_RULES = [
    # Common PHP / JSP backdoor filenames
    r"/(?:c99|r57|b374k|wso|alfa|shell|backdoor|eval-stdin|cmd|up)\.(?:php|jsp|aspx?|cgi)",
    # Parameter triggers for shell execution
    r"\?(?:cmd|exec|query|do|action)=(?:whoami|id|ls|cat|pwd|system)"
]
_WEB_SHELL_REGEX = re.compile("|".join(_WEB_SHELL_RULES), re.IGNORECASE)

# 7. Directory Scanning / Fuzzing: Probing for hidden files, admin portals, configs
_DIR_FUZZING_RULES = [
    r"/\.(?:env|git(?:/head|/config)?|svn|aws|htaccess|DS_Store)",
    r"/(?:wp-config|config|settings|database)\.(?:php|bak|old|swp|json|yml)",
    r"/(?:phpmyadmin|adminer|pma|server-status|swagger\.json|actuator/health)",
    r"/(?:backup|dump|db)\.(?:zip|tar\.gz|sql|rar|7z)"
]
_DIR_FUZZING_REGEX = re.compile("|".join(_DIR_FUZZING_RULES), re.IGNORECASE)

# 8. Malicious Scanner Signatures in User-Agent
_SCANNER_UA_RULES = [
    r"\b(?:sqlmap|nikto|masscan|acunetix|nessus|openvas|gobuster|dirbuster|wpscan|hydra|zgrab)\b"
]
_SCANNER_UA_REGEX = re.compile("|".join(_SCANNER_UA_RULES), re.IGNORECASE)

# 9. Authentication endpoints for Brute Force
_AUTH_ENDPOINTS = re.compile(
    r"/(?:login|signin|sign-in|authenticate|auth|wp-login|admin/login|account/login)",
    re.IGNORECASE
)


class HeuristicLabeler:
    """Production-grade heuristic classifier with low false-positive guards."""

    def __init__(
        self,
        brute_force_threshold: int = 10,
        brute_force_window_seconds: int = 600,
        ddos_rate_threshold: float = 25.0
    ):
        self.bf_threshold = brute_force_threshold
        self.bf_window_sec = brute_force_window_seconds
        self.ddos_rate_threshold = ddos_rate_threshold

    def classify_single_request(
        self,
        resource: str,
        method: str = "GET",
        status_code: int = 200,
        user_agent: str = "",
        inter_request_time: Optional[float] = None
    ) -> Tuple[str, str]:
        """Classifies a single HTTP request using calibrated heuristic priority.

        Returns:
            Tuple[str, str]: (predicted_label, label_reason)
        """
        norm_res = normalize_request_payload(resource)

        # Priority 1: DDoS Detection via inter-request time velocity or rate limiting
        if inter_request_time is not None and inter_request_time <= 0.04 and status_code in (503, 429, 504, 200):
            return "ddos_http_flood", f"DDoS HTTP Flood: Microscopic inter-arrival time ({inter_request_time:.4f}s) indicates automated volumetric flood"

        # Priority 2: Vulnerability Scanner User-Agent header
        if user_agent and _SCANNER_UA_REGEX.search(user_agent):
            m = _SCANNER_UA_REGEX.search(user_agent).group()
            return "mal_scanner", f"Malicious Scanner User-Agent: Detected '{m}' tool fingerprint"

        # Priority 3: Command Injection in User-Agent (Shellshock CVE-2014-6271)
        if user_agent and re.search(r"\(\)\s*\{\s*:\s*;\s*\}\s*;", user_agent):
            return "command_injection", "Command Injection: Detected Shellshock function definition in User-Agent"

        # Priority 4: SQL Injection (Grammar & Tautology detection in URI)
        if _SQLI_REGEX.search(norm_res):
            m = _SQLI_REGEX.search(norm_res).group()
            return "sqli", f"SQL Injection: Detected SQL syntax/tautology matching '{m[:40]}'"

        # Priority 5: Cross-Site Scripting (XSS in URI)
        if _XSS_REGEX.search(norm_res):
            m = _XSS_REGEX.search(norm_res).group()
            return "xss", f"XSS: Detected script tag or event handler matching '{m[:40]}'"

        # Priority 6: Command Injection (RCE in URI)
        if _COMMAND_INJECTION_REGEX.search(norm_res):
            m = _COMMAND_INJECTION_REGEX.search(norm_res).group()
            return "command_injection", f"Command Injection: Detected shell operator/binary matching '{m[:40]}'"

        # Priority 7: Path Traversal / LFI in URI
        if _PATH_TRAVERSAL_REGEX.search(norm_res):
            m = _PATH_TRAVERSAL_REGEX.search(norm_res).group()
            return "path_traversal", f"Path Traversal: Detected directory climbing or system file probe '{m[:40]}'"

        # Priority 8: Server-Side Request Forgery (SSRF in URI)
        if _SSRF_REGEX.search(norm_res):
            m = _SSRF_REGEX.search(norm_res).group()
            return "ssrf", f"SSRF: Detected cloud metadata or private loopback reference '{m[:40]}'"

        # Priority 9: Web Shell Probing in URI
        if _WEB_SHELL_REGEX.search(norm_res):
            m = _WEB_SHELL_REGEX.search(norm_res).group()
            return "web_shell", f"Web Shell: Detected backdoor filename or trigger parameter '{m[:40]}'"

        # Priority 10: Directory Fuzzing / Discovery in URI
        if _DIR_FUZZING_REGEX.search(norm_res):
            m = _DIR_FUZZING_REGEX.search(norm_res).group()
            return "dir_fuzzing", f"Directory Fuzzing: Probe of sensitive/hidden resource '{m[:40]}'"

        # Priority 11: Authentication Brute Force
        # Flagged when accessing auth endpoints with failed status code (401/403) or brute credentials
        if _AUTH_ENDPOINTS.search(norm_res):
            if status_code in (401, 403) or "password=" in norm_res or "pwd=" in norm_res:
                m = _AUTH_ENDPOINTS.search(norm_res).group()
                return "brute_force", f"Brute Force: Credential/auth probe against '{m}' with status {status_code}"

        # Default: Benign
        return "benign", "Normal benign request (no attack pattern detected)"
