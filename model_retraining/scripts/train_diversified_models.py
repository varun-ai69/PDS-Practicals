"""
train_diversified_models.py
===========================
Augments the Practical 6 balanced training dataset with 5,000 diverse real-world
benign server access logs from Elastic Apache production data (static assets,
short paths, favicons, modern user agents).

Re-trains:
1. Random Forest Ensemble (Champion)
2. Decision Tree (Tuned Fast)
And updates Practical 9/outputs/models/
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

from pipeline.log_parser import parse_logs_text
from pipeline.preprocessor import clean_and_normalize_logs
from pipeline.feature_extractor import extract_features_dataframe, FEATURE_COLUMNS
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier

print("=" * 70)
print("  TRAINING DIVERSIFIED WEB TELEMETRY MODELS (BRANCH: test)")
print("=" * 70)

# 1. Extract features for 5,000 diverse benign logs
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
print(f"  -> Extracted 31-D features for {len(df_elastic_feats):,} diverse benign samples.")

# 2. Ingest existing balanced training dataset
train_pq = PROJECT_ROOT / "Practical 6" / "data" / "processed" / "balanced_training_dataset.parquet"
print(f"\n[Step 2] Loading base balanced training dataset ({train_pq.name})...")
df_base_train = pd.read_parquet(train_pq)
print(f"  -> Base Training Set: {len(df_base_train):,} records across {df_base_train['label'].nunique()} classes.")

# 3. Augment and concatenate
df_aug_train = pd.concat([df_base_train, df_elastic_feats], ignore_index=True)
print(f"  -> Augmented Training Set: {len(df_aug_train):,} records ({df_aug_train['label'].value_counts()['benign']:,} benign).")

X_train = df_aug_train[FEATURE_COLUMNS].fillna(0).to_numpy(dtype=np.float32)
y_train = df_aug_train["label"].to_numpy()

# 4. Train Diversified Random Forest
print("\n[Step 3] Training Diversified Random Forest Ensemble (150 trees, max_depth=25)...")
t0 = time.time()
rf_div = RandomForestClassifier(
    n_estimators=150,
    max_depth=25,
    criterion="entropy",
    random_state=42,
    n_jobs=-1
)
rf_div.fit(X_train, y_train)
t_rf = time.time() - t0
print(f"  -> Random Forest trained successfully in {t_rf:.2f} seconds.")

# 5. Train Diversified Decision Tree
print("\n[Step 4] Training Diversified Decision Tree (max_depth=20, min_samples_split=5)...")
t0 = time.time()
dt_div = DecisionTreeClassifier(
    max_depth=20,
    min_samples_split=5,
    criterion="entropy",
    random_state=42
)
dt_div.fit(X_train, y_train)
t_dt = time.time() - t0
print(f"  -> Decision Tree trained successfully in {t_dt:.2f} seconds.")

# 6. Save models into model_retraining/outputs/models/
models_dir = RETRAIN_DIR / "outputs" / "models"
models_dir.mkdir(parents=True, exist_ok=True)

rf_path = models_dir / "random_forest_retrained_170k.joblib"
dt_path = models_dir / "decision_tree_retrained_170k.joblib"

joblib.dump(rf_div, rf_path)
joblib.dump(dt_div, dt_path)
print(f"\n[Step 5] Serialized retrained models to:")
print(f"  - {rf_path} ({rf_path.stat().st_size / 1e6:.2f} MB)")
print(f"  - {dt_path} ({dt_path.stat().st_size / 1e3:.2f} KB)")
print("\n[OK] Diversified model training complete!")
