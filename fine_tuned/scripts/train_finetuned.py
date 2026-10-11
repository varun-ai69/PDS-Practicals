"""
train_finetuned.py
==================
Trains the Fine-Tuned Sentinel Random Forest using the curated diverse benign training dataset.
Produces: fine_tuned/models/random_forest_finetuned.joblib
"""

import sys
import time
from pathlib import Path
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "Practical 10"))

from pipeline.inference_engine import FEATURE_COLUMNS

MODELS_DIR = PROJECT_ROOT / "fine_tuned" / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)
DATA_PATH = PROJECT_ROOT / "fine_tuned" / "data" / "finetuned_training_dataset.parquet"


def train_finetuned_model():
    print(f"[Step 1] Loading enriched training dataset from {DATA_PATH}...")
    t0 = time.time()
    df_train = pd.read_parquet(DATA_PATH)
    print(f"  Ingested {len(df_train):,} rows with {len(FEATURE_COLUMNS)} feature vectors in {time.time() - t0:.2f}s")

    X_train = df_train[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
    y_train = df_train["label"].to_numpy()

    print("[Step 2] Initializing Fine-Tuned Sentinel Random Forest (150 trees, entropy, max_depth=22)...")
    rf_model = RandomForestClassifier(
        n_estimators=150,
        max_depth=22,
        criterion="entropy",
        min_samples_split=4,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )

    print("[Step 3] Fitting model on 279,320 records...")
    t_train = time.time()
    rf_model.fit(X_train, y_train)
    duration = time.time() - t_train
    print(f"[OK] Training completed in {duration:.2f} seconds.")

    out_model_path = MODELS_DIR / "random_forest_finetuned.joblib"
    joblib.dump(rf_model, out_model_path, compress=3)
    print(f"[OK] Fine-tuned model saved to: {out_model_path}")
    print(f"  File size: {out_model_path.stat().st_size / (1024*1024):.2f} MB")


if __name__ == "__main__":
    train_finetuned_model()
