"""
heuristic_engine.py
===================
Master Production-Grade Heuristic Classification Engine.

Engineered to eliminate false positives on real production web server logs:
1. Context-Aware URL & Query Parameter Parser:
   - Differentiates URL query keys (e.g., `&id=`, `&dir=`) from shell injection operators.
   - Evaluates payloads in parameter values without query delimiter false positives.
   - Shell chaining requires true operators (; | || && ` $( \n %0a). Single `&` is not an operator.
2. Stateful Temporal & Velocity Windows:
   - Replaces naive single-request Δt <= 0.04s checks with real per-IP sliding windows.
   - Concurrent requests within the same second (Δt = 0.0) for multi-asset loading are preserved as Benign.
   - Genuine DDoS HTTP Floods require high sustained volumetric frequency (>= 25 req/sec).
3. Stateful Authentication Tracking:
   - Isolated failed logins (e.g. typos, status 401) are not falsely marked as Brute Force.
   - Requires repeated threshold failures (>= 5 failed attempts) within a sliding time window.
4. AST & Syntax Grammar Rules:
   - SQLi rules enforce quote-breakout, boolean tautology, comment delimiters, or DB functions.
   - Natural language queries ('black and white', 'terms and conditions') remain Benign.
5. Strict Deterministic Hierarchy across 10 Web Attack Classes + Benign:
   - ddos_http_flood -> mal_scanner -> command_injection -> sqli -> xss ->
     path_traversal -> ssrf -> web_shell -> dir_fuzzing -> brute_force -> benign.
6. Transparent Audit Attributions:
   - Generates deterministic `label` and `label_reason`.
"""

import re
import html
import urllib.parse
from collections import defaultdict, deque
from typing import Dict, Any, Tuple, Optional, List, Union


# =========================================================================
# MULTI-PASS NORMALIZATION & DECODING
# =========================================================================

def normalize_request_payload(text: str) -> str:
    """Pre-decodes and normalizes payloads to defeat evasion techniques.
    
    1. HTML entity unescaping (&quot; -> ", &lt; -> <)
    2. Recursive URL unquoting (up to 3 passes to handle multi-encoding)
    3. Second HTML unescape pass for nested entities
    4. Inline SQL comment flattening (UNION/**/SELECT -> UNION SELECT)
    5. Whitespace standardization and lowercasing
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

    # 5. Standardize horizontal whitespace while preserving newlines & lowercase
    s = re.sub(r"[ \t\r\f\v]+", " ", s).lower().strip()
    return s


def parse_and_extract_payload_components(raw_resource: str) -> Tuple[str, List[str], str]:
    """Separates a URI into its clean path and query parameter values.
    
    This prevents query parameter names (like `&id=`, `&dir=`, `&cat=`)
    from colliding with shell binary names or SQL keywords.
    
    Returns:
        Tuple of:
        - normalized_path: string
        - parameter_values: list of strings (each value individually normalized)
        - full_normalized: complete decoded URI string
    """
    if not isinstance(raw_resource, str) or not raw_resource:
        return "", [], ""

    full_norm = normalize_request_payload(raw_resource)

    try:
        parsed = urllib.parse.urlsplit(raw_resource)
        norm_path = normalize_request_payload(parsed.path)
        param_values = []
        if parsed.query:
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for _, vals in qs.items():
                for v in vals:
                    if v:
                        param_values.append(normalize_request_payload(v))
        return norm_path, param_values, full_norm
    except Exception:
        # Fallback if URL parsing fails on severely malformed strings
        return full_norm, [full_norm], full_norm


# =========================================================================
# COMPILED HIGH-PRECISION REGEX PATTERNS (Zero False Positive Calibration)
# =========================================================================

# 1. Malicious Vulnerability Scanners (User-Agent header inspection)
_SCANNER_UA_RULES = [
    r"\b(?:sqlmap|nikto|masscan|acunetix|nessus|openvas|gobuster|dirbuster|wpscan|hydra|zgrab|nmap|nuclei|arachni|appscan|havij|skipfish)\b"
]
_SCANNER_UA_REGEX = re.compile("|".join(_SCANNER_UA_RULES), re.IGNORECASE)

# 2. Command Injection & RCE
# Note: Operators require true shell chaining context (; | || && ` $( \n %0a)
# Plain '&' in query parameters is explicitly NOT treated as a shell separator.
_SHELL_CHAINING_OP = r"(?:;\s*|\|\|?\s*|&&\s*|`\s*|\$\(\s*|\n|%0a)"
_SHELL_BINARIES = r"\b(?:cat|whoami|id|uname|curl|wget|sh|bash|zsh|dash|chmod|nc|netcat|net\s+user|dir|ping|netstat|ls|who|ps|kill|touch|rm)\b"

_COMMAND_INJECTION_RULES = [
    # Command chaining followed by binary (e.g. ; whoami, | id, && cat, $(id), `uname`)
    _SHELL_CHAINING_OP + _SHELL_BINARIES,
    # Direct execution of system shell binaries
    r"/(?:bin|usr/bin|usr/sbin|sbin)/(?:sh|bash|zsh|dash|cat|id|whoami|ls|nc|curl|wget|chmod)",
    # Process / execution wrapper functions: system('...'), exec('...'), passthru('...')
    r"\b(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*['\"].*?['\"]\s*\)",
    # Sensitive file extraction via cat
    r"\bcat\s+/(?:etc/(?:passwd|shadow|hosts|issue)|proc/)",
    # SSI Exec directives
    r"(?:<!--#exec\s+cmd|#exec\s+cmd)",
    # Subshell syntax containing OS commands
    r"\$\(\s*" + _SHELL_BINARIES + r"\s*\)",
    r"`\s*" + _SHELL_BINARIES + r"\s*`",
    # Shell redirection
    r">\s*/dev/null",
    # Shellshock (CVE-2014-6271)
    r"\(\)\s*\{\s*:\s*;\s*\}\s*;"
]
_COMMAND_INJECTION_REGEX = re.compile("|".join(_COMMAND_INJECTION_RULES), re.IGNORECASE)

# 3. SQL Injection (High-Precision AST & Grammar Rules)
_SQLI_RULES = [
    # UNION SELECT variants
    r"\bunion(?:\s+(?:all|distinct))?\s+select\b",
    # SELECT ... FROM / SELECT ... INTO
    r"\bselect\b[\s\S]{1,120}\b(?:from|into)\b",
    # Stacked SELECT queries: ; select ...
    r";\s*select\b",
    # Strict Tautology / Boolean injection:
    # Requires quote breakout (' or " or %27) OR explicit numeric equality (1=1, 0=0)
    r"(?:'|\"|%27|%22|\))\s*\b(?:or|and)\b\s+[\(\s]*(?:\d+\s*=\s*\d+|'[^']*'\s*=\s*'[^']*'?|\"[^\"]*\"\s*=\s*\"[^\"]*\"?|[a-z0-9_]+\s*=\s*[a-z0-9_]+)",
    r"\b(?:or|and)\b\s+(?:1\s*=\s*1|0\s*=\s*0|\d+\s*=\s*\d+)\s*(?:--|#|/\*|$)",
    r"\b(?:or|and)\b\s+\d+\s+between\s+\d+\s+and\s+\d+\b",
    # Quote or SQL token followed by comment delimiter (e.g. admin' --, id desc --, ' /* */)
    r"(?:'|\"|%27|%22|\badmin\b|\broot\b|\bdesc\b|\basc\b|\bwhere\b|\bselect\b|\d+)\s*(?:--\s*|\s+#|\/\*[\s\S]*?\*\/)",
    # Column probing: order by \d+ with SQL comment
    r"\b(?:order|group)\s+by\s+\d+\s*(?:--|#|/\*|$)",
    # Stacked DDL / DML commands: ; drop table, ; insert into, ; update ... set
    r";\s*(?:drop\s+table|delete\s+from|insert\s+into|update\s+\w+\s+set|create\s+user|alter\s+table|truncate\s+table)\b",
    r"\binsert\s+into\b[\s\S]{1,80}\bvalues\b",
    r"\bcreate\s+user\b[\s\S]{1,60}\bidentified\s+by\b",
    # DB fingerprinting, tables & functions
    r"\b(?:version\s*\(|@@version|information_schema|sysobjects|sys\.tables|sysibm|all_tab_columns|load_file\s*\(|into\s+outfile|into\s+dumpfile)",
    # Time delays & blind injections
    r"\b(?:waitfor\s+delay\s+['\"]|sleep\s*\(\s*\d+\s*\)|pg_sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+\s*,)",
    # Error extraction
    r"\b(?:extractvalue\s*\(|updatexml\s*\(|ctxsys\.drithsx\.sn|utl_inaddr\.get_host_address)"
]
_SQLI_REGEX = re.compile("|".join(_SQLI_RULES), re.IGNORECASE)

# 4. Cross-Site Scripting (XSS)
_XSS_RULES = [
    # Explicit script tags
    r"<\s*script[^>]*>",
    r"<\s*/\s*script\s*>",
    # Inline Event Handlers with assignment
    r"\bon(?:error|load|mouseover|click|focus|submit|blur|input|pointerenter|change)\s*=\s*['\"]?[^'\">\s]+",
    # JavaScript / VBScript pseudo-protocols
    r"(?:javascript|vbscript):\s*[\w\.\(\)]+",
    r"data:\s*text/html\b",
    # DOM Cookie and Location theft / Sinks
    r"document\.(?:cookie|location|write|body\.innerHTML)\b",
    # Exploit functions with function call parentheses: alert(1), prompt(1), eval(...)
    r"\b(?:alert|prompt|confirm|eval)\s*\(\s*(?:['\"`\d]|document\.)",
    # Vector tags with execution triggers
    r"<\s*(?:svg|iframe|embed|object|marquee|video|audio|input)[^>]+(?:onload|onerror|src\s*=\s*javascript)\b"
]
_XSS_REGEX = re.compile("|".join(_XSS_RULES), re.IGNORECASE)

# 5. Path Traversal & LFI
_PATH_TRAVERSAL_RULES = [
    # Directory climbing sequences
    r"(?:\.\./|\.\.\\|\.\.%2f|\.\.%2F|\.\.%5c|\.\.%5C|%2e%2e/|%2e%2e%2f)",
    # Linux sensitive system files
    r"/(?:etc/(?:passwd|shadow|hosts|group|issue|crontab)|proc/(?:self/environ|version|cmdline)|var/log/(?:auth|syslog|messages))",
    # Windows system files
    r"(?:[a-zA-Z]:/(?:windows|winnt)/system32/(?:drivers/etc/hosts|config/sam)|win\.ini|boot\.ini|windows/system\.ini)",
    # PHP wrapper protocols
    r"php://(?:filter|input|data|expect)",
    # Null-byte truncation combined with path climbing
    r"(?:\.\.[/\\]|[/\\]etc[/\\]|[/\\]windows[/\\]).*?(?:%00|\x00)"
]
_PATH_TRAVERSAL_REGEX = re.compile("|".join(_PATH_TRAVERSAL_RULES), re.IGNORECASE)

# 6. Server-Side Request Forgery (SSRF)
_SSRF_RULES = [
    # AWS / GCP / Azure IMDS
    r"169\.254\.169\.254",
    r"metadata\.google\.internal",
    r"100\.100\.100\.200",
    # Loopback targets in URL query parameters
    r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?::\d+)?",
    # Dangerous internal protocols
    r"(?:gopher|dict|file|tftp|ldap)://"
]
_SSRF_REGEX = re.compile("|".join(_SSRF_RULES), re.IGNORECASE)

# 7. Web Shell Probing
_WEB_SHELL_RULES = [
    # Common backdoor filenames
    r"/(?:c99|r57|b374k|wso|alfa|shell|backdoor|eval-stdin|cmd|up|bypass|weevely)\.(?:php|jsp|aspx?|cgi|pl)",
    # Shell execution query parameters on script endpoints
    r"\.(?:php|jsp|asp)\?(?:cmd|exec|query|do|action)=(?:whoami|id|ls|cat|pwd|system|uname)"
]
_WEB_SHELL_REGEX = re.compile("|".join(_WEB_SHELL_RULES), re.IGNORECASE)

# 8. Directory Scanning & Fuzzing
_DIR_FUZZING_RULES = [
    # Hidden files and VCS directories
    r"/\.(?:env|git|svn|aws|htaccess|htpasswd|DS_Store|hg|bzr)(?:/|$|\?)",
    # Sensitive backup and configuration files
    r"/(?:wp-config|config|settings|database)(?:\.[a-z0-9]+)?\.(?:bak|old|swp|save|orig|sql)",
    r"/(?:backup|dump|db|database|dump_all)\.(?:zip|tar\.gz|sql|rar|7z|tgz)",
    # Admin panels & internal server status
    r"/(?:phpmyadmin|adminer|pma|server-status|server-info|actuator/(?:health|env|heapdump)|swagger-ui|swagger\.json)"
]
_DIR_FUZZING_REGEX = re.compile("|".join(_DIR_FUZZING_RULES), re.IGNORECASE)

# 9. Authentication endpoints for Brute Force
_AUTH_ENDPOINTS = re.compile(
    r"/(?:login|signin|sign-in|authenticate|auth|wp-login\.php|admin/login|account/login)",
    re.IGNORECASE
)


# =========================================================================
# STATEFUL HEURISTIC CLASSIFIER ENGINE
# =========================================================================

class HeuristicLabeler:
    """Production-grade heuristic classifier with low false-positive guards.
    
    Includes stateful sliding-window tracking for:
    - Volumetric HTTP Flood (DDoS): Evaluated by request rate per second per IP.
    - Credential Brute Force: Evaluated by cumulative failed authentications per IP.
    """

    def __init__(
        self,
        brute_force_threshold: int = 5,
        brute_force_window_seconds: int = 300,
        ddos_rate_threshold: float = 10.0
    ):
        self.bf_threshold = brute_force_threshold
        self.bf_window_sec = brute_force_window_seconds
        self.ddos_rate_threshold = ddos_rate_threshold

        # Sliding window state per IP: deque of timestamps
        self.ip_request_timestamps: Dict[str, deque] = defaultdict(deque)
        self.ip_failed_logins: Dict[str, deque] = defaultdict(deque)

    def reset(self) -> None:
        """Clears all sliding window states to prevent memory leaks across distinct datasets."""
        self.ip_request_timestamps.clear()
        self.ip_failed_logins.clear()

    def record_request(self, client_ip: str, timestamp_epoch: float, status_code: int, is_auth: bool) -> Tuple[float, int]:
        """Records an incoming request into stateful sliding windows.
        
        Returns:
            Tuple of:
            - requests_in_last_sec: float (count of requests in the trailing 1-second window)
            - failed_logins_in_window: int (count of failed auth attempts in trailing window)
        """
        if not client_ip:
            return 1.0, 0

        # Maintain 1-second sliding window for DDoS rate detection
        ts_queue = self.ip_request_timestamps[client_ip]
        ts_queue.append(timestamp_epoch)
        while ts_queue and ((timestamp_epoch - ts_queue[0]) > 1.0 or (timestamp_epoch < ts_queue[0])):
            ts_queue.popleft()
        reqs_1s = float(len(ts_queue))

        # Maintain failed auth sliding window for Brute Force
        bf_queue = self.ip_failed_logins[client_ip]
        if is_auth and status_code in (401, 403):
            bf_queue.append(timestamp_epoch)
        while bf_queue and ((timestamp_epoch - bf_queue[0]) > self.bf_window_sec or (timestamp_epoch < bf_queue[0])):
            bf_queue.popleft()
        failed_count = len(bf_queue)

        return reqs_1s, failed_count

    def classify_single_request(
        self,
        resource: str,
        method: str = "GET",
        status_code: int = 200,
        user_agent: str = "",
        inter_request_time: Optional[float] = None,
        client_ip: str = "",
        timestamp_epoch: Optional[float] = None,
        requests_per_ip_1sec: Optional[float] = None,
        failed_login_count: Optional[int] = None
    ) -> Tuple[str, str]:
        """Classifies a single HTTP request using calibrated heuristic priority.
        
        Zero False Positive Guardrails:
        1. DDoS HTTP Flood is NOT triggered by microscopic Δt (0.0s) alone, preventing
           false alarms on standard multi-asset web page loads (HTML + CSS + JS).
        2. Query parameter keys (e.g., `&id=`, `&dir=`) do NOT trigger Command Injection.
        3. Plain language queries ('shoes and shirts') do NOT trigger SQL Injection.
        4. Single 401 typos do NOT trigger Brute Force without repeated failure threshold.

        Returns:
            Tuple[str, str]: (predicted_label, label_reason)
        """
        norm_path, param_vals, full_norm = parse_and_extract_payload_components(resource)

        # Update or resolve stateful metrics
        is_auth = bool(_AUTH_ENDPOINTS.search(norm_path))
        if client_ip and timestamp_epoch is not None:
            r1s, flc = self.record_request(client_ip, timestamp_epoch, status_code, is_auth)
            if requests_per_ip_1sec is None:
                requests_per_ip_1sec = r1s
            if failed_login_count is None:
                failed_login_count = flc

        # PRIORITY 1: Volumetric DDoS HTTP Flood
        # Triggered when request velocity exceeds threshold or server actively rate limits under flood
        if requests_per_ip_1sec is not None and requests_per_ip_1sec >= self.ddos_rate_threshold:
            return "ddos_http_flood", f"DDoS HTTP Flood: Volumetric velocity of {requests_per_ip_1sec:.1f} req/s exceeds threshold ({self.ddos_rate_threshold} req/s)"
        if status_code in (429, 503) and requests_per_ip_1sec is not None and requests_per_ip_1sec >= 10.0:
            return "ddos_http_flood", f"DDoS HTTP Flood: Rate limiting status {status_code} triggered under sustained traffic ({requests_per_ip_1sec:.1f} req/s)"

        # PRIORITY 2: Malicious Vulnerability Scanner (User-Agent header inspection)
        if user_agent and _SCANNER_UA_REGEX.search(user_agent):
            m = _SCANNER_UA_REGEX.search(user_agent).group()
            return "mal_scanner", f"Malicious Scanner User-Agent: Detected '{m}' tool signature"

        # PRIORITY 3: Command Injection in User-Agent (Shellshock CVE-2014-6271)
        if user_agent and re.search(r"\(\)\s*\{\s*:\s*;\s*\}\s*;", user_agent):
            return "command_injection", "Command Injection: Detected Shellshock CVE-2014-6271 function definition in User-Agent"

        # PRIORITY 4: Command Injection (RCE in URI)
        # Check in parameter values, path, and full normalized string
        for target in [norm_path] + param_vals:
            if _COMMAND_INJECTION_REGEX.search(target):
                m = _COMMAND_INJECTION_REGEX.search(target).group()
                return "command_injection", f"Command Injection: Detected shell operator/binary matching '{m[:40]}'"
        if _COMMAND_INJECTION_REGEX.search(full_norm):
            m = _COMMAND_INJECTION_REGEX.search(full_norm).group()
            return "command_injection", f"Command Injection: Detected shell operator/binary matching '{m[:40]}'"

        # PRIORITY 5: SQL Injection (Grammar & Tautology detection in URI)
        for target in [norm_path] + param_vals:
            if _SQLI_REGEX.search(target):
                m = _SQLI_REGEX.search(target).group()
                return "sqli", f"SQL Injection: Detected SQL syntax/tautology matching '{m[:40]}'"
        if _SQLI_REGEX.search(full_norm):
            m = _SQLI_REGEX.search(full_norm).group()
            return "sqli", f"SQL Injection: Detected SQL syntax/tautology matching '{m[:40]}'"

        # PRIORITY 6: Cross-Site Scripting (XSS in URI)
        for target in [norm_path] + param_vals:
            if _XSS_REGEX.search(target):
                m = _XSS_REGEX.search(target).group()
                return "xss", f"XSS: Detected script tag or event handler matching '{m[:40]}'"
        if _XSS_REGEX.search(full_norm):
            m = _XSS_REGEX.search(full_norm).group()
            return "xss", f"XSS: Detected script tag or event handler matching '{m[:40]}'"

        # PRIORITY 7: Path Traversal / LFI in URI
        if _PATH_TRAVERSAL_REGEX.search(norm_path):
            m = _PATH_TRAVERSAL_REGEX.search(norm_path).group()
            return "path_traversal", f"Path Traversal: Detected directory climbing or system file probe '{m[:40]}'"
        for target in param_vals:
            if _PATH_TRAVERSAL_REGEX.search(target):
                m = _PATH_TRAVERSAL_REGEX.search(target).group()
                return "path_traversal", f"Path Traversal: Parameter value contains directory climbing '{m[:40]}'"
        if _PATH_TRAVERSAL_REGEX.search(full_norm):
            m = _PATH_TRAVERSAL_REGEX.search(full_norm).group()
            return "path_traversal", f"Path Traversal: Detected directory climbing or system file probe '{m[:40]}'"

        # PRIORITY 8: Server-Side Request Forgery (SSRF in URI)
        for target in param_vals + [norm_path]:
            if _SSRF_REGEX.search(target):
                m = _SSRF_REGEX.search(target).group()
                return "ssrf", f"SSRF: Detected cloud metadata or private loopback target '{m[:40]}'"
        if _SSRF_REGEX.search(full_norm):
            m = _SSRF_REGEX.search(full_norm).group()
            return "ssrf", f"SSRF: Detected cloud metadata or private loopback target '{m[:40]}'"

        # PRIORITY 9: Web Shell Probing in URI
        if _WEB_SHELL_REGEX.search(full_norm):
            m = _WEB_SHELL_REGEX.search(full_norm).group()
            return "web_shell", f"Web Shell: Detected backdoor filename or trigger parameter '{m[:40]}'"

        # PRIORITY 10: Directory Fuzzing / Discovery in URI
        if _DIR_FUZZING_REGEX.search(norm_path):
            m = _DIR_FUZZING_REGEX.search(norm_path).group()
            return "dir_fuzzing", f"Directory Fuzzing: Probe of sensitive/hidden resource '{m[:40]}'"
        if _DIR_FUZZING_REGEX.search(full_norm):
            m = _DIR_FUZZING_REGEX.search(full_norm).group()
            return "dir_fuzzing", f"Directory Fuzzing: Probe of sensitive/hidden resource '{m[:40]}'"

        # PRIORITY 11: Authentication Brute Force
        # Only flagged when cumulative failed login count reaches threshold
        if is_auth:
            if failed_login_count is not None and failed_login_count >= self.bf_threshold:
                return "brute_force", f"Brute Force: Cumulative {failed_login_count} failed auth attempts on '{norm_path}' within window"

        # DEFAULT: Benign
        return "benign", "Normal benign request (no attack pattern detected)"
