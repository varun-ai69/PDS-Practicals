#!/usr/bin/env python3
import sys
import re
from pathlib import Path
import pandas as pd
from collections import Counter

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
from src.pipeline.heuristic_engine import normalize_request_payload
from test_sqli_tuning import test_regex

wa_file = PROJECT_ROOT / "datasets" / "hf_web_attacks" / "web_attacks_all.csv"
df_wa = pd.read_csv(wa_file)
sqli_samples = df_wa[df_wa["text_label"] == "SQLi"]["Payload"].dropna().tolist()

missed = [p for p in sqli_samples if not test_regex.search(normalize_request_payload(p))]
print(f"Remaining Missed in Shengqin: {len(missed)} / {len(sqli_samples)}")
print("Sample remaining missed in Shengqin:")
for p in missed[:25]:
    print(" ", repr(p[:100]))

sqli_file = PROJECT_ROOT / "datasets" / "hf_sql_injection" / "sql_injection_dataset.csv"
df_sqli = pd.read_csv(sqli_file)
atk = df_sqli[df_sqli["Label"] == 1]["Query"].dropna().tolist()
missed_ali = [q for q in atk if not test_regex.search(normalize_request_payload(q))]
print(f"\nRemaining Missed in AmirAli: {len(missed_ali)} / {len(atk)}")
print("Sample remaining missed in AmirAli:")
for q in missed_ali[:25]:
    print(" ", repr(q[:100]))
