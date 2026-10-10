import sys
from pathlib import Path
root = Path(__file__).resolve().parent
sys.path.insert(0, str(root / "Practical 10"))
import pandas as pd
import numpy as np

from pipeline.log_parser import parse_logs_text
from pipeline.preprocessor import clean_and_normalize_logs
from pipeline.feature_extractor import extract_features_dataframe
from pipeline.inference_engine import ThreatInferenceEngine

with open("Practical 10/data/sample_eval_logs.log", "r") as f:
    text = f.read()

df_clean = clean_and_normalize_logs(parse_logs_text(text))
df_feats = extract_features_dataframe(df_clean)
eng = ThreatInferenceEngine("Random Forest Ensemble (Champion)")
preds = eng.predict(df_feats)
df_res = pd.concat([df_clean, preds], axis=1)

print("Predictions on sample_eval_logs.log:")
for _, r in df_res.iterrows():
    print(f"{r['log_id']:2d} | {r['method']:4s} | {r['resource'][:40]:40s} | {r['display_name']:32s} | {r['confidence_pct']:5.1f}% | Anom: {r['anomaly_score']:.3f}")
