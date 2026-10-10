"""
build_external_test_log.py
===========================
Generates a realistic, authentic web server access log (real_world_unseen_access.log)
by sampling from real-world external corpora that the model was never trained on:
- Elastic Apache Production Access Logs (genuine legitimate user traffic)
- HuggingFace SQL Injection dataset
- HuggingFace XSS dataset
- HuggingFace Command Injection dataset
- Real vulnerability scanner traces (Nikto, sqlmap, DirBuster)
- Zero-Day novel anomalies (SSRF, high-entropy shellcodes)
"""

import urllib.parse
from datetime import datetime, timedelta
import random
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# 1. Load genuine benign requests from elastic_apache_access.log
elastic_log_path = PROJECT_ROOT / "datasets" / "external_real_world" / "elastic_apache_access.log"
benign_lines = []
if elastic_log_path.exists():
    with open(elastic_log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            l = line.strip()
            # Only keep successful/normal requests with standard status
            if ' 200 ' in l or ' 304 ' in l:
                benign_lines.append(l)
            if len(benign_lines) >= 500:
                break

random.seed(42)
selected_benign = random.sample(benign_lines, min(120, len(benign_lines)))

# 2. Load real SQL injections
sql_path = PROJECT_ROOT / "datasets" / "hf_sql_injection" / "sql_injection_dataset.csv"
sql_payloads = []
if sql_path.exists():
    df_sql = pd.read_csv(sql_path)
    # Filter malicious queries (Label == 1)
    mal_sql = df_sql[df_sql["Label"] == 1]["Query"].dropna().tolist()
    sql_payloads = random.sample(mal_sql, min(20, len(mal_sql)))

# 3. Load real XSS payloads
xss_path = PROJECT_ROOT / "datasets" / "hf_xss" / "xss_dataset.csv"
xss_payloads = []
if xss_path.exists():
    df_xss = pd.read_csv(xss_path)
    mal_xss = df_xss[df_xss["Label"] == 1]["Sentence"].dropna().tolist()
    xss_payloads = random.sample(mal_xss, min(20, len(mal_xss)))

# 4. Load real Command Injections
cmd_path = PROJECT_ROOT / "datasets" / "hf_command_injection" / "command_injection.csv"
cmd_payloads = []
if cmd_path.exists():
    df_cmd = pd.read_csv(cmd_path)
    mal_cmd = df_cmd[df_cmd["Label"] == 1]["sentence"].dropna().tolist()
    cmd_payloads = random.sample(mal_cmd, min(15, len(mal_cmd)))

# 5. Define Path Traversals, Scanners & Zero-Day Anomalies
traversal_payloads = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2fwindows%2fsystem32%2fdrivers%2fetc%2fhosts",
    "/view.php?file=../../../../boot.ini",
    "/include.php?page=..%2f..%2f..%2fvar%2flog%2fapache2%2faccess.log%00",
    "/download?path=../../../../etc/shadow",
    "/get_doc?file=....//....//....//etc/passwd",
    "/export?template=../../../../../../proc/self/environ",
    "/doc.pdf?rel=..\\..\\..\\..\\windows\\win.ini"
]

scanner_requests = [
    ('94.102.49.190', 'GET /.env HTTP/1.1', 404, 180, 'Nikto/2.1.6'),
    ('94.102.49.190', 'GET /.git/HEAD HTTP/1.1', 404, 180, 'Nikto/2.1.6'),
    ('94.102.49.190', 'GET /wp-config.php.bak HTTP/1.1', 404, 180, 'Nikto/2.1.6'),
    ('94.102.49.190', 'GET /phpmyadmin/index.php HTTP/1.1', 404, 180, 'Nikto/2.1.6'),
    ('94.102.49.190', 'GET /admin/backup.sql HTTP/1.1', 404, 180, 'Nikto/2.1.6'),
    ('103.251.167.20', 'GET /api/v1/user?id=1%27%20AND%201=1-- HTTP/1.1', 403, 240, 'sqlmap/1.7.2#stable'),
    ('103.251.167.20', 'GET /search?id=1%20UNION%20SELECT%20NULL,VERSION()-- HTTP/1.1', 403, 240, 'sqlmap/1.7.2#stable'),
    ('198.51.100.88', 'HEAD /web.config HTTP/1.1', 404, 0, 'DirBuster-1.0-RC1'),
    ('198.51.100.88', 'HEAD /server-status HTTP/1.1', 403, 0, 'DirBuster-1.0-RC1'),
    ('198.51.100.88', 'GET /swagger-ui.html HTTP/1.1', 404, 150, 'DirBuster-1.0-RC1')
]

zero_day_anomalies = [
    ('194.135.25.10', 'POST /proxy?target=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role HTTP/1.1', 403, 280, 'Mozilla/5.0'),
    ('194.135.25.10', 'GET /fetch?url=http://127.0.0.1:8080/internal/system/actuator/env HTTP/1.1', 403, 280, 'Mozilla/5.0'),
    ('212.102.57.12', 'POST /eval?code=%5C%78%33%31%5C%78%63%30%5C%78%35%30%5C%78%36%38%5C%78%32%66%5C%78%32%66%5C%78%37%33%5C%78%36%38 HTTP/1.1', 500, 110, 'curl/8.1.2'),
    ('212.102.57.12', 'GET /debug?payload=%25%32%35%25%33%32%25%36%35%25%32%35%25%33%32%25%36%36%25%32%35%25%33%32%25%36%35etc/passwd HTTP/1.1', 400, 140, 'curl/8.1.2'),
    ('212.102.57.12', 'POST /api/v2/deserialize?blob=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sBFlzaAwQMAAHhwAAAA HTTP/1.1', 500, 320, 'curl/8.1.2')
]

# Assemble attack log lines
attack_lines = []
base_time = datetime(2026, 10, 9, 14, 0, 0)

# SQLi Lines
for i, query in enumerate(sql_payloads):
    encoded_q = urllib.parse.quote(str(query))
    ts = (base_time + timedelta(seconds=i * 12)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    ip = f"198.51.100.{random.randint(10, 80)}"
    line = f'{ip} - - [{ts}] "GET /products/search?q={encoded_q} HTTP/1.1" 403 285 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
    attack_lines.append(line)

# XSS Lines
for i, payload in enumerate(xss_payloads):
    encoded_p = urllib.parse.quote(str(payload))
    ts = (base_time + timedelta(seconds=i * 15 + 3)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    ip = f"203.0.113.{random.randint(20, 90)}"
    line = f'{ip} - - [{ts}] "GET /comment?body={encoded_p} HTTP/1.1" 400 310 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64)"'
    attack_lines.append(line)

# Command Injection Lines
for i, cmd in enumerate(cmd_payloads):
    encoded_c = urllib.parse.quote(str(cmd))
    ts = (base_time + timedelta(seconds=i * 20 + 6)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    ip = f"185.220.101.{random.randint(1, 40)}"
    line = f'{ip} - - [{ts}] "POST /tools/ping.php?host=127.0.0.1;{encoded_c} HTTP/1.1" 500 420 "-" "Python-urllib/3.10"'
    attack_lines.append(line)

# Traversal Lines
for i, trv in enumerate(traversal_payloads):
    ts = (base_time + timedelta(seconds=i * 25 + 9)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    ip = f"192.0.2.{random.randint(50, 99)}"
    line = f'{ip} - - [{ts}] "GET /download?file={trv} HTTP/1.1" 403 210 "-" "curl/7.88.1"'
    attack_lines.append(line)

# Scanner Lines
for ip, req, status, bytes_val, ua in scanner_requests:
    ts = (base_time + timedelta(seconds=random.randint(100, 600))).strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = f'{ip} - - [{ts}] "{req}" {status} {bytes_val} "-" "{ua}"'
    attack_lines.append(line)

# Zero-Day Anomalies
for ip, req, status, bytes_val, ua in zero_day_anomalies:
    ts = (base_time + timedelta(seconds=random.randint(200, 800))).strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = f'{ip} - - [{ts}] "{req}" {status} {bytes_val} "-" "{ua}"'
    attack_lines.append(line)

# Combine and shuffle realistically
all_lines = selected_benign + attack_lines
random.seed(999)
random.shuffle(all_lines)

out_text = "\n".join(all_lines) + "\n"

# Save to root workspace & Practical 10 data
dest_root = PROJECT_ROOT / "real_world_unseen_access.log"
dest_p10 = PROJECT_ROOT / "Practical 10" / "data" / "real_world_unseen_access.log"

with open(dest_root, "w", encoding="utf-8") as f:
    f.write(out_text)

with open(dest_p10, "w", encoding="utf-8") as f:
    f.write(out_text)

print(f"[OK] Created real_world_unseen_access.log successfully!")
print(f"Total Lines: {len(all_lines)}")
print(f"Benign Lines: {len(selected_benign)} ({len(selected_benign)/len(all_lines)*100:.1f}%)")
print(f"Attack Lines: {len(attack_lines)} ({len(attack_lines)/len(all_lines)*100:.1f}%)")
print(f"Saved to: {dest_root}")
print(f"Saved to: {dest_p10}")
