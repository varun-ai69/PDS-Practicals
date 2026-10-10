"""
train_logistic_regression.py
=============================
Trains an updated, diversified Logistic Regression Pipeline
(StandardScaler + LogisticRegression(solver='lbfgs', max_iter=250, class_weight='balanced'))
on the 170,000 augmented dataset (165k base + 5,000 diverse real-world benign logs).
"""

import sys
import time
from pathlib import Path
import pandas as pd
import numpy as np
import joblib

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
RETRAIN_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "Practical 10"))
sys.path.insert(0, str(PROJECT_ROOT / "model_evaluation" / "scripts"))

from pipeline.log_parser import parse_logs_text
from pipeline.preprocessor import clean_and_normalize_logs
from pipeline.feature_extractor import extract_features_dataframe, FEATURE_COLUMNS
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

print("=" * 70)
print("  RE-TRAINING DIVERSIFIED LOGISTIC REGRESSION (BRANCH: test)")
print("=" * 70)

# 1. Ingest 5,000 diverse benign logs
elastic_path = RETRAIN_DIR / "data" / "elastic_apache_access.log"
if not elastic_path.exists():
    elastic_path = PROJECT_ROOT / "datasets" / "external_real_world" / "elastic_apache_access.log"
print(f"\n[Step 1] Ingesting diverse benign telemetry from {elastic_path.name}...")
lines = []
with open(elastic_path, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        l = line.strip()
        if " 200 " in l or " 304 " in l:
            lines.append(l)
        if len(lines) >= 5000:
            break

df_parsed = parse_logs_text("\n".join(lines))
df_clean = clean_and_normalize_logs(df_parsed)
df_elastic_feats = extract_features_dataframe(df_clean)
df_elastic_feats["label"] = "benign"
print(f"  -> Extracted features for {len(df_elastic_feats):,} diverse benign samples.")

# 2. Ingest base balanced training set
train_pq = PROJECT_ROOT / "Practical 6" / "data" / "processed" / "balanced_training_dataset.parquet"
print(f"\n[Step 2] Loading base balanced training dataset ({train_pq.name})...")
df_base_train = pd.read_parquet(train_pq)

# 3. Concatenate
df_aug_train = pd.concat([df_base_train, df_elastic_feats], ignore_index=True)
print(f"  -> Total Augmented Training Set: {len(df_aug_train):,} samples across 11 classes.")

X_train = df_aug_train[FEATURE_COLUMNS].fillna(0).to_numpy(dtype=np.float32)
y_train = df_aug_train["label"].to_numpy()

# 4. Train Scaled Logistic Regression Pipeline
print("\n[Step 3] Training StandardScaler + LogisticRegression(solver='lbfgs', max_iter=250)...")
lr_pipeline = Pipeline([
    ("scaler", StandardScaler()),
    ("clf", LogisticRegression(
        solver="lbfgs",
        max_iter=250,
        class_weight="balanced",
        random_state=42
    ))
])

t0 = time.time()
lr_pipeline.fit(X_train, y_train)
t_fit = time.time() - t0
print(f"  -> Logistic Regression trained successfully in {t_fit:.2f} seconds!")

# 5. Save model into model_retraining/outputs/models/
models_dir = RETRAIN_DIR / "outputs" / "models"
models_dir.mkdir(parents=True, exist_ok=True)
model_path = models_dir / "logistic_regression_retrained_170k.joblib"
joblib.dump(lr_pipeline, model_path)
print(f"\n[Step 4] Serialized retrained model to:")
print(f"  - {model_path} ({model_path.stat().st_size / 1e3:.2f} KB)")

# 6. Evaluate on comprehensive 225-request evaluation log
print("\n[Step 5] Evaluating updated Logistic Regression on 225 multi-attack requests...")
from pipeline.inference_engine import ThreatInferenceEngine

# Use the newly trained pipeline directly for audit
with open(PROJECT_ROOT / "model_evaluation" / "test_logs" / "comprehensive_multi_attack_eval.log", "r", encoding="utf-8") as f:
    eval_text = f.read()

eval_df_clean = clean_and_normalize_logs(parse_logs_text(eval_text))
eval_df_feats = extract_features_dataframe(eval_df_clean)
X_eval = eval_df_feats[FEATURE_COLUMNS].fillna(0).to_numpy(dtype=np.float32)
raw_preds = lr_pipeline.predict(X_eval)
preds = pd.DataFrame({"is_attack": raw_preds != "benign", "pred_label": raw_preds})

from test_all_attack_classes import test_records
true_classes = [rec[1] for rec in test_records]

atk_correct = ((pd.Series(true_classes) != "benign") & (preds["is_attack"])).sum()
atk_total = (pd.Series(true_classes) != "benign").sum()
ben_correct = ((pd.Series(true_classes) == "benign") & (~preds["is_attack"])).sum()
ben_total = (pd.Series(true_classes) == "benign").sum()

print("\n" + "=" * 60)
print("     UPDATED LOGISTIC REGRESSION AUDIT (225 REQUESTS)")
print("=" * 60)
print(f"Attacks Blocked (Recall) : {atk_correct} / {atk_total} ({atk_correct/atk_total*100:.2f}%)")
print(f"Benign Allowed           : {ben_correct} / {ben_total} ({ben_correct/ben_total*100:.2f}%)")
print(f"False Alarms             : {ben_total - ben_correct} / {ben_total} ({(ben_total - ben_correct)/ben_total*100:.2f}%)")
print(f"Overall Accuracy         : {(atk_correct + ben_correct)/len(true_classes)*100:.2f}%")
print("=" * 60)
print("[OK] Re-training complete!")
