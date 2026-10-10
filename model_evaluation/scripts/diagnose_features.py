import sys
from pathlib import Path
root = Path(__file__).resolve().parent
sys.path.insert(0, str(root / "Practical 10"))
import pandas as pd
from pipeline.log_parser import parse_log_line
from pipeline.preprocessor import clean_and_normalize_logs
from pipeline.feature_extractor import extract_features_dataframe
from pipeline.inference_engine import ThreatInferenceEngine

rf = ThreatInferenceEngine("Random Forest Ensemble (Champion)")
dt = ThreatInferenceEngine("Decision Tree (Tuned Fast)")

test_lines = [
    '192.168.1.45 - - [09/Oct/2026:06:12:01 +0000] "GET / HTTP/1.1" 200 4520 "-" "Mozilla/5.0"',
    '192.168.1.45 - - [09/Oct/2026:06:12:03 +0000] "GET /assets/css/main.css HTTP/1.1" 200 12840 "-" "Mozilla/5.0"',
    '192.168.1.45 - - [09/Oct/2026:06:12:08 +0000] "GET /about-us HTTP/1.1" 200 5120 "-" "Mozilla/5.0"',
    '198.51.100.14 - - [09/Oct/2026:06:13:01 +0000] "GET /products?id=1%20UNION%20SELECT%20null,password%20FROM%20users-- HTTP/1.1" 403 280 "-" "curl/7.88"',
    '203.0.113.82 - - [09/Oct/2026:06:13:18 +0000] "GET /comments?msg=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1" 400 310 "-" "Mozilla/5.0"'
]

for l in test_lines:
    df_clean = clean_and_normalize_logs(pd.DataFrame([parse_log_line(l, 1)]))
    feats = extract_features_dataframe(df_clean)
    pred_rf = rf.predict(feats).iloc[0]
    pred_dt = dt.predict(feats).iloc[0]
    res = df_clean['resource'].values[0]
    print(f"Path: {res[:35]:35s} | RF: {pred_rf['display_name']} ({pred_rf['confidence_pct']}%) | DT: {pred_dt['display_name']} ({pred_dt['confidence_pct']}%)")
