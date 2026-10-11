# Practical 9: Supervised Attack Classification

**Course:** Python for Data Science (`BE05000231_PDS`)  
**Semester:** 5th Semester B.E. / B.Tech  
**Topic:** Supervised Machine Learning Classifiers (Logistic Regression vs Decision Tree vs Random Forest)  
**Pipeline Ingestion:**  
- **Locked Test Set:** [`Practical 6/data/processed/test_dataset.parquet`](../Practical%206/data/processed/test_dataset.parquet) (100,000 records $\times$ 31 features, locked 20% holdout).  
- **Balanced Training Set:** [`Practical 6/data/processed/balanced_training_dataset.parquet`](../Practical%206/data/processed/balanced_training_dataset.parquet) (275,000 records: exactly 25,000 per class across 11 classes).  
- **Unbalanced Training Set:** 80% natural split from [`Practical 5/data/processed/featured_logs.parquet`](../Practical%205/data/processed/featured_logs.parquet) (400,000 records: 143,254 benign vs. 256,746 attacks).  
**Downstream Pipeline:** Supplies champion weights ([`outputs/models/balanced/random_forest_tuned.joblib`](outputs/models/balanced/random_forest_tuned.joblib)) to **Practical 10 (Interactive Real-Time Threat Hunting & Model Deployment Platform)**.

---

## 1. Clean Model Directory Structure

All model weights and scalers are strictly organized into two dedicated folders:

```text
Practical 9/outputs/models/
├── balanced/                                   # Trained on 275,000 balanced records (25k/class)
│   ├── logistic_regression.joblib              # Linear multinomial baseline (2.5 KB)
│   ├── decision_tree.joblib                    # Default CART: max_depth=15, gini (165 KB)
│   ├── decision_tree_tuned.joblib              # ⚡ BEST ULTRA-FAST: max_depth=20, entropy (271 KB)
│   ├── random_forest.joblib                    # Default Ensemble: 100 trees, depth=15 (92.4 MB)
│   ├── random_forest_tuned.joblib              # 🏆 OVERALL CHAMPION: 150 trees, depth=25, entropy (92.4 MB)
│   └── scaler.joblib                           # StandardScaler for balanced feature normalization (1.3 KB)
└── unbalanced/                                 # Trained on 400,000 natural skewed records
    ├── logistic_regression.joblib              # Linear model on natural skewed data (2.5 KB)
    ├── decision_tree.joblib                    # Single tree on natural skewed data (138 KB)
    ├── random_forest.joblib                    # Ensemble on natural skewed data (34.3 MB)
    └── scaler.joblib                           # StandardScaler for unbalanced feature normalization (1.3 KB)
```

> [!NOTE]
> All redundant root copies and duplicate folders have been deleted. Only `balanced/` and `unbalanced/` are maintained. Champion models are also mirrored to [`src/models/`](../src/models/) for repository-wide production access.

---

## 2. Complete Performance Scorecard (Empirical 100,000 Test Records)

Every single score below was evaluated dynamically on the locked 100,000-sample test partition with zero data leakage:

| Model File Location | Training Paradigm | Classifier Architecture | Accuracy | Macro Recall | Macro F1 | Fit Time | Predict Time | Role & Status |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| `balanced/random_forest_tuned.joblib` | **Balanced (275k)** | **Random Forest (d=25, n=150, entropy)** | **98.72%** | **99.62%** | **0.9881** | 11.68s | 0.53s | 🏆 **OVERALL CHAMPION MODEL** |
| `balanced/decision_tree_tuned.joblib` | **Balanced (275k)** | **Decision Tree (d=20, entropy)** | **99.01%** | **99.58%** | **0.9908** | 2.57s | 0.01s | ⚡ **BEST ULTRA-FAST MODEL** |
| `balanced/decision_tree.joblib` | Balanced (275k) | Decision Tree (d=15, gini) | 97.32% | 99.14% | 0.9737 | 3.00s | 0.01s | Default Tree Baseline |
| `balanced/random_forest.joblib` | Balanced (275k) | Random Forest (d=15, n=100, gini) | 97.07% | 99.20% | 0.9720 | 8.32s | 0.32s | Default Ensemble Baseline |
| `balanced/logistic_regression.joblib` | Balanced (275k) | Logistic Regression (Linear + L2) | 94.95% | 98.02% | 0.9503 | 15.87s | 0.01s | Linear Multinomial Baseline |
| `unbalanced/random_forest.joblib` | Unbalanced (400k) | Random Forest (d=15, n=100, gini) | 98.76% | 98.72% | 0.9871 | 13.67s | 0.35s | Comparison Benchmark |
| `unbalanced/decision_tree.joblib` | Unbalanced (400k) | Decision Tree (d=15, gini) | 97.97% | 97.35% | 0.9775 | 4.47s | 0.01s | Comparison Benchmark |
| `unbalanced/logistic_regression.joblib` | Unbalanced (400k) | Logistic Regression (Linear + L2) | 96.28% | 96.60% | 0.9610 | 34.49s | 0.01s | Comparison Benchmark |

---

## 3. Best Model Analysis: Which One Should You Use?

### 🏆 Overall Best Model: `outputs/models/balanced/random_forest_tuned.joblib`
- **Architecture:** Bagged ensemble of 150 decorrelated decision trees, `max_depth=25`, `criterion="entropy"`, random feature subspace $m = \lfloor\sqrt{31}\rfloor = 5$.
- **Why it is the Best:**
  - **Highest Attack Recall (99.62%):** Catches **99.62%** of all attacks across all 11 classes, leaving an escape rate of only **0.38%**.
  - **Robustness against Non-Linear Exploits:** By averaging votes across 150 trees, it prevents single-feature vulnerabilities from spoofing the model.
  - **Selected for Practical 10 Production:** Ingested directly into the real-time inference engine.

### ⚡ Best Ultra-Fast Model: `outputs/models/balanced/decision_tree_tuned.joblib`
- **Architecture:** Single CART decision tree, `max_depth=20`, `criterion="entropy"`.
- **What is the Tuning?**
  1. **Depth Expansion ($d=15 \to d=20$):** Standard trees capped at depth 15 suffer from underfitting when separating lookalike injection syntax (e.g., distinguishing SQLi from XSS or Command Injection). Increasing depth to 20 allows fine-grained hierarchical token splits.
  2. **Information Gain Criterion (`gini` $\to$ `entropy`):** Entropy measures $-\sum p_k \log_2 p_k$, penalizing impure leaf nodes more severely than Gini impurity, forcing sharper class separation.
- **Why it is Outstanding:**
  - **Highest Raw Accuracy (99.01%)** and **Macro F1 (0.9908)**.
  - **Sub-Millisecond Latency:** Predicts 100,000 records in just **0.01 seconds** (10,000,000 req/sec vectorized throughput).
  - **Ultra-Compact:** Only **271 KB** disk footprint.

---

## 4. Balanced vs. Unbalanced: Why Balancing Was Essential

Training on the **unbalanced** dataset caused the models to optimize heavily for the majority benign class, missing dangerous rare cyberattacks. Training on the **balanced** dataset resolved this:

| Attack Category | Test Samples | Unbalanced Recall | Balanced Recall | Improvement ($\Delta$) | Real-World Security Impact |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Command Injection** | 3,693 | 94.29% | **99.97%** | **+5.69%** | Missed attacks dropped from 211 down to **1** |
| **SQL Injection (SQLi)** | 5,331 | 97.47% | **100.00%** | **+2.53%** | Missed attacks dropped from 135 down to **0** |
| **DDoS HTTP Flood** | 6,436 | 96.04% | **99.29%** | **+3.25%** | Volumetric surges caught with near-zero escape |
| **Directory Fuzzing** | 7,000 | 99.91% | **100.00%** | **+0.09%** | Scanner reconnaissance completely neutralized |
| **Web Shell** | 7,000 | 99.99% | **100.00%** | **+0.01%** | RCE payloads isolated |
| **Brute Force** | 6,952 | 100.00% | **100.00%** | 0.00% | 100% credential spray detection |
| **Malicious Scanner** | 7,000 | 100.00% | **100.00%** | 0.00% | 100% scanner signature detection |
| **Path Traversal** | 7,088 | 100.00% | **100.00%** | 0.00% | 100% traversal detection |
| **SSRF** | 7,000 | 100.00% | **100.00%** | 0.00% | 100% metadata query detection |
| **XSS** | 6,687 | 99.96% | **99.96%** | 0.00% | 99.96% script injection detection |
| **Benign Traffic** | 35,813 | 98.25% | **91.97%** | -6.28% | Controlled SOC trade-off (prioritizing 0 missed attacks) |
| **Macro Average Recall** | **100,000** | **98.72%** | **99.20%** | **+0.48%** | **Tuned RF reaches 99.62% Macro Recall** |

---

## 5. Visual Diagnostics Manifest

All plots are updated dynamically based on real model evaluations:

| Plot Artifact | Description |
| :--- | :--- |
| [`01_model_comparison_metrics.png`](outputs/plots/01_model_comparison_metrics.png) | Triple-bar chart contrasting Accuracy, Macro F1, and Macro Recall across all models. |
| [`02_confusion_matrix_rf_balanced.png`](outputs/plots/02_confusion_matrix_rf_balanced.png) | Normalized $11 \times 11$ confusion matrix for the Random Forest classifier trained on balanced data. |
| [`03_confusion_matrix_rf_imbalanced.png`](outputs/plots/03_confusion_matrix_rf_imbalanced.png) | Normalized confusion matrix for the baseline Random Forest trained on imbalanced telemetry. |
| [`04_feature_importance_rf.png`](outputs/plots/04_feature_importance_rf.png) | Ranked horizontal bar chart displaying Gini importance percentages for top 15 features. |
| [`05_imbalanced_vs_balanced_recall.png`](outputs/plots/05_imbalanced_vs_balanced_recall.png) | Per-class recall gains on minority attacks under balanced training. |
| [`06_hyperparameter_tuning_analysis.png`](outputs/plots/06_hyperparameter_tuning_analysis.png) | Empirical optimization chart showing tuning gains across tree depths and criteria. |
| [`07_real_world_external_benchmark.png`](outputs/plots/07_real_world_external_benchmark.png) | Blind validation benchmark on 15,515 external real-world samples (HuggingFace + CSIC 2010). |
| [`logistic_regression_confusion_matrix.png`](outputs/plots/logistic_regression_confusion_matrix.png) | Normalized confusion matrix for the linear Logistic Regression baseline. |

---

## 6. How to Run

### Step 1: Run Full Training Pipeline
```powershell
python "Practical 9/run_practical9.py"
```

### Step 2: Run External Generalization Benchmark
```powershell
python "Practical 9/test_real_world_benchmark.py"
```

### Step 3: Interactive Exploration
```powershell
jupyter notebook "Practical 9/notebooks/Practical_09_Attack_Classification.ipynb"
```

---

## 7. Pipeline Continuity to Practical 10

The champion model [`outputs/models/balanced/random_forest_tuned.joblib`](outputs/models/balanced/random_forest_tuned.joblib) and scaler [`outputs/models/balanced/scaler.joblib`](outputs/models/balanced/scaler.joblib) feed directly into **Practical 10: Real-Time Streamlit Threat Hunting Platform**, enabling 100% independent real-time classification on live HTTP access logs.
