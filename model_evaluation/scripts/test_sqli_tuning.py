#!/usr/bin/env python3
import sys
import re
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.pipeline.heuristic_engine import normalize_request_payload

# Highly refined, robust SQLi rules
test_rules = [
    # 1. UNION SELECT variants
    r"\bunion(?:\s+(?:all|distinct))?\s+select\b",
    
    # 2. SELECT ... FROM / SELECT ... INTO
    r"\bselect\b[\s\S]{1,120}\b(?:from|into)\b",
    
    # 3. Stacked SELECT queries: ; select ...
    r";\s*select\b",
    
    # 4. Tautology / Boolean injection:
    # Handles both closed quotes ('1'='1', "a"="a") and unclosed trailing quotes ('x'='x, "1"="1)
    # Handles parentheses: (1)=(1), ('a')=('a), ((1))=((1))
    # Handles arithmetic tautology: or 1=1, or 0=0, or 2>1, or 1<2
    r"(?:'|\"|%27|%22|\))?\s*\b(?:or|and)\b\s+[\(\s]*(?:\d+\s*[=><]\s*\d+|'[^']*'\s*[=><]\s*'[^']*'?|\"[^\"]*\"\s*[=><]\s*\"[^\"]*\"?|[a-z0-9_]+\s*=\s*[a-z0-9_]+|''\s*[\-\+\*\&\^\|][\-\+\*\&\^\|\s]*'?)",
    
    # 5. BETWEEN tautologies: or 2 between 1 and 3
    r"\b(?:or|and)\b\s+\d+\s+between\s+\d+\s+and\s+\d+\b",
    
    # 6. Column fuzzing: order by \d+, group by \d+
    r"\b(?:order|group)\s+by\s+\d+\b",
    
    # 7. SQL comments: --, #, /* ... */ with trailing quotes or space
    r"(?:--\s*|\s+#\s*|\/\*[\s\S]*?\*\/)\s*(?:$|'|\"|#)",
    
    # 8. Stacked DDL / DML commands
    r";\s*(?:drop\s+table|delete\s+from|insert\s+into|update\s+\w+\s+set|create\s+user|alter\s+table|exec\s+|execute\s+|truncate\s+)\b",
    
    # 9. INSERT INTO ... VALUES / CREATE USER ... IDENTIFIED BY
    r"\binsert\s+into\b[\s\S]{1,80}\bvalues\b",
    r"\bcreate\s+user\b[\s\S]{1,60}\bidentified\s+by\b",
    r"\btruncate\s+table\b",
    
    # 10. Stacked DECLARE in MSSQL / Stored procedures
    r"\bdeclare\s+@\w+\s+(?:varchar|nvarchar|int)\b",
    r"\b(?:exec|execute)\s+(?:sp_|xp_)\w+\b",
    
    # 11. DB fingerprinting, tables & functions
    r"\b(?:version\s*\(|@@version|information_schema|sysobjects|sys\.tables|sysibm|all_tab_columns|all_users|schema_name|table_name|column_name|load_file|into\s+outfile|into\s+dumpfile)\b",
    
    # 12. Time delays & blind injections
    r"\b(?:waitfor\s+delay|sleep\s*\(\s*(?:\d+|__time__)\s*\)|pg_sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+)\b",
    
    # 13. Error extraction & Hex decoding functions
    r"\b(?:utl_inaddr\.get_host_address|ctxsys\.drithsx\.sn|extractvalue\s*\(|updatexml\s*\(|user_name\s*\(|char\s*\(\s*\d+\s*\))\b"
]

test_regex = re.compile("|".join(test_rules), re.IGNORECASE)

print("=" * 70)
print("EVALUATING REFINED SQLI RULES ACROSS ALL BENCHMARKS")
print("=" * 70)

# 1. Shengqin Web Attacks
wa_file = PROJECT_ROOT / "datasets" / "hf_web_attacks" / "web_attacks_all.csv"
if wa_file.exists():
    df_wa = pd.read_csv(wa_file)
    sqli_samples = df_wa[df_wa["text_label"] == "SQLi"]["Payload"].dropna().tolist()
    norm_samples = df_wa[df_wa["text_label"] == "normal"]["Payload"].dropna().tolist()

    detected = sum(1 for p in sqli_samples if test_regex.search(normalize_request_payload(p)))
    fp = sum(1 for p in norm_samples if test_regex.search(normalize_request_payload(p)))

    print(f"Shengqin SQLi Detection Recall : {detected:,} / {len(sqli_samples):,} ({detected/len(sqli_samples)*100:.2f}%)")
    print(f"Shengqin Normal Traffic FPR    : {fp} / {len(norm_samples):,} ({fp/len(norm_samples)*100:.4f}%)")

# 2. AmirAli SQLi Dataset
sqli_file = PROJECT_ROOT / "datasets" / "hf_sql_injection" / "sql_injection_dataset.csv"
if sqli_file.exists():
    df_sqli = pd.read_csv(sqli_file)
    atk = df_sqli[df_sqli["Label"] == 1]["Query"].dropna().tolist()
    det_ali = sum(1 for q in atk if test_regex.search(normalize_request_payload(q)))
    print(f"AmirAli SQLi Detection Recall  : {det_ali:,} / {len(atk):,} ({det_ali/len(atk)*100:.2f}%)")

# 3. CSIC 2010 Normal Traffic (36,000 requests)
csic_file = PROJECT_ROOT / "datasets" / "csic_2010_http" / "normalTrafficTraining.txt"
if csic_file.exists():
    from calibrate_heuristics import parse_csic_clean
    n_reqs = parse_csic_clean(csic_file)
    csic_fps = []
    for m, pq, h, b in n_reqs:
        target = pq + (" " + b if b else "")
        if test_regex.search(normalize_request_payload(target)):
            csic_fps.append(target)
    print(f"CSIC 2010 Normal Traffic FP    : {len(csic_fps)} / {len(n_reqs)} ({len(csic_fps)/len(n_reqs)*100:.4f}%)")
    if csic_fps:
        print("Sample CSIC False Positives:")
        for s in csic_fps[:5]:
            print(" ", repr(s[:80]))

print("=" * 70)
