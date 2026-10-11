# Practical 6: Dataset Balancing & Stratified Partitioning for Machine Learning

**Course:** Python for Data Science (`BE05000231_PDS`)  
**Semester:** 5th Semester B.E. / B.Tech  
**Topic:** Mitigation of Multi-Class Imbalance, Zero-Leakage Stratified Partitioning, and $k$-NN SMOTE Manifold Interpolation  
**Pipeline Ingestion:** Practical 5 Feature-Engineered Dataset ([featured_logs.parquet](../Practical%205/data/processed/featured_logs.parquet) — 500,000 records $\times$ 55 columns)  
**Pipeline Hand-off:** Prepares Balanced Training Matrix ($X_{\text{train}}, y_{\text{train}}$) and Pure Test Set ($X_{\text{test}}, y_{\text{test}}$) for Supervised Classification in Practicals 7, 8, and 9  

---

## 1. Aim and Objectives

### Aim
To handle multi-class class imbalance across cybersecurity telemetry by systematically evaluating Random Undersampling (RUS), Random Oversampling (ROS), and SMOTE strictly on an isolated training split, while locking the test partition 100% untouched to ensure legitimate, leak-free real-world model evaluation.

### Objectives
1. **Pipeline Continuity:** Ingest the 30-feature numerical matrix with continuous anomaly scores from Practical 5 (`featured_logs.parquet` — 500,000 records).
2. **Zero-Leakage Split Protocol:** Execute a stratified 80% / 20% train-test split **before** applying any resampling algorithm, locking the 100,000 test records completely untouched.
3. **Resampling Methodology Comparison:** Implement and compare three core balancing techniques on the 400,000 training records:
   - **Random Under-Sampling (RUS):** Downsampling all classes to the minority baseline ($14,772$ samples per class, $162,492$ records total).
   - **Random Over-Sampling (ROS):** Exact minority duplication with replacement up to $25,000$ samples per class ($413,904$ records total).
   - **SMOTE (Synthetic Minority Over-sampling Technique):** $k$-NN ($k=5$) feature interpolation synthesizing mathematically novel instances.
4. **Equalized 275,000-Record Training Synthesis:** Establish a perfectly equalized training dataset containing exactly $25,000$ samples per class across all 11 classes ($1:1:1:1:1:1:1:1:1:1:1$).
5. **Dual-Format Serialization:** Export balanced training matrices and locked test partitions to CSV and Snappy-compressed Apache Parquet.
6. **Diagnostic Visualizations:** Generate publication-quality plots illustrating raw imbalance, stratified split alignment, technique comparisons, and 2D PCA projections of SMOTE manifolds.

---

## 2. Theoretical Architecture: The Class Imbalance Challenge

### 2.1 The Accuracy Paradox in Cyber Telemetry
In raw access telemetry, benign traffic naturally constitutes the majority ($35.8\%$ in our master log, and $>99\%$ in enterprise networks), while specific attack vectors (`command_injection`, `sqli`) represent minority fractions.

If a machine learning classifier is trained on raw imbalanced distributions:
- A trivial dummy classifier predicting majority classes achieves high nominal accuracy.
- However, its **Recall on stealthy zero-day attacks is unacceptably low**, allowing critical exploits to execute undetected.
- Therefore, evaluation must prioritize **Macro F1-Score, Balanced Accuracy, Precision, and Recall**, rather than raw nominal accuracy.

---

### 2.2 The Golden Rule of Resampling: Pre-Split Isolation
A frequent critical error in naive data science workflows is applying resampling algorithms **before** splitting data:

$$\text{INCORRECT (FATAL LEAKAGE): } \quad \text{Raw Data} \xrightarrow{\text{SMOTE}} \text{Resampled Data} \xrightarrow{\text{Split}} \text{Train} + \text{Test}$$

When SMOTE is executed prior to splitting:
1. Synthetic samples are generated using neighbors that end up in the test set.
2. The model trains on synthetic data directly correlated with evaluation records.
3. Evaluation produces artificially inflated metrics ($>99.9\%$) that collapse completely in production.

#### Our Enterprise Zero-Leakage Architecture:
$$\text{ENTERPRISE PROTOCOL: } \quad \text{Raw Data (500k)} \xrightarrow{\text{Stratified 80/20 Split}} \begin{cases} \text{Train (80\% = 400,000)} \xrightarrow{\text{SMOTE}} \text{Balanced Train (275,000)} \\ \text{Test (20\% = 100,000)} \xrightarrow{\text{LOCKED}} \text{Untouched Real Distribution} \end{cases}$$

The 100,000 test records remain 100% pure, containing the natural distribution of benign and attack traffic for honest, production-grade validation in Practicals 7, 8, and 9.

---

### 2.3 Mathematical Formulation of Resampling Techniques

#### 1. Random Under-Sampling (RUS)
Downsamples majority classes by random selection without replacement until equal to the minority class count $N_{\text{min}}$:

$$S_{\text{RUS}} = \{x_i \sim P(X | y = c) : |S_c| = N_{\text{min}}, \forall c \in C\}$$

- **Advantage:** Fast computational execution ($1.54$s).
- **Limitation:** Discards over $237,508$ records, severely impoverishing decision boundaries.

#### 2. Random Over-Sampling (ROS)
Duplicates minority class instances with replacement until reaching target size $N_{\text{target}}$:

$$S_{\text{ROS}} = S_{\text{orig}} \cup \{x_i \text{ sampled with replacement from } S_c : |S_c| = N_{\text{target}}\}$$

- **Advantage:** Preserves majority class diversity.
- **Limitation:** Replicates identical feature vectors, shrinking decision boundaries and inducing decision tree overfitting.

#### 3. SMOTE ($k$-Nearest Neighbors Manifold Interpolation)
For each minority instance $x_i$, SMOTE computes its $k$-nearest neighbors in Euclidean feature space ($k=5$). It randomly selects a neighbor $x_{zi}$ and synthesizes a novel point along the line segment:

$$x_{\text{new}} = x_i + \lambda \cdot (x_{zi} - x_i), \quad \lambda \sim \text{Uniform}(0, 1)$$

- **Advantage:** Generates mathematically novel feature vectors, expanding the convex hull of minority attack classes without duplicating records.

---

## 3. Directory Structure

```
Practical 6/
├── data/
│   └── processed/
│       ├── balanced_training_dataset.csv         # Final equalized training dataset (275,000 rows, 25k / class) (161.60 MB)
│       ├── balanced_training_dataset.parquet     # Snappy-compressed Parquet training dataset (26.66 MB)
│       ├── balanced_train_smote.csv              # Full SMOTE training dataset (413,904 rows) (63.84 MB)
│       ├── balanced_train_smote.parquet          # Snappy Parquet SMOTE dataset (9.63 MB)
│       ├── balanced_train_random_oversampled.csv # Random oversampled dataset (63.15 MB)
│       ├── balanced_train_undersampled.csv       # Random undersampled dataset (162,492 rows) (24.96 MB)
│       ├── test_dataset.csv                      # Strictly locked untouched test partition (100,000 rows) (53.00 MB)
│       └── test_dataset.parquet                  # Snappy Parquet test partition (8.49 MB)
├── notebooks/
│   └── Practical_06_Dataset_Balancing.ipynb     # Interactive Jupyter notebook with formulas & plots
├── outputs/
│   ├── plots/
│   │   ├── original_class_imbalance.png          # Horizontal bar chart of raw training class imbalance
│   │   ├── train_test_split_distribution.png     # Stratified 80/20 train vs test alignment (log scale)
│   │   ├── balancing_methods_comparison.png      # Side-by-side comparison across Original, RUS, ROS, SMOTE
│   │   └── smote_knn_feature_space_pca.png       # 2D PCA projection of SMOTE synthetic points vs real points
│   └── reports/
│       ├── balancing_comparison.csv              # Class-by-class comparison table across all 4 methods
│       └── balancing_report.txt                  # Comprehensive technical audit report
├── run_practical6.py                             # Production execution script
└── README.md                                     # Enterprise technical documentation
```

---

## 4. Empirical Verification & Results

### 4.1 Resampling Methodologies Comparison Benchmark

| Metric | Original Train (80%) | Random Under-Sampling (RUS) | Random Over-Sampling (ROS) | Final SMOTE Balanced (1:1) |
|---|---|---|---|---|
| **Total Record Volume** | 400,000 records | 162,492 records | 413,904 records | **275,000 records** |
| **Execution Runtime** | — | **1.54 seconds** | **1.25 seconds** | **3.21 seconds** |
| **Information Retention** | 100% | 40.6% (237k discarded) | 100% (Duplicated) | **100% + Synthetic Manifolds** |
| **Overfitting Vulnerability**| High (Majority Bias) | Low | High (Memorization) | **Minimal (Interpolated)** |
| **Class Distribution** | Imbalanced ($35.8\%$ Benign) | Balanced ($14,772$ / class) | Imbalanced ($143k$ Benign) | **Perfect Equalization ($25,000$ / class)** |

---

### 4.2 Class-by-Class Distribution Breakdown

| Attack Class | Original Train (80%) | RUS Count | ROS Count | Final SMOTE Balanced | Test Split (20% Locked) |
|---|---|---|---|---|---|
| `benign` | 143,254 | 14,772 | 143,254 | **25,000** | 35,813 |
| `path_traversal` | 28,351 | 14,772 | 28,351 | **25,000** | 7,088 |
| `dir_fuzzing` | 28,000 | 14,772 | 28,000 | **25,000** | 7,000 |
| `mal_scanner` | 28,000 | 14,772 | 28,000 | **25,000** | 7,000 |
| `ssrf` | 28,000 | 14,772 | 28,000 | **25,000** | 7,000 |
| `web_shell` | 28,000 | 14,772 | 28,000 | **25,000** | 7,000 |
| `brute_force` | 27,809 | 14,772 | 27,809 | **25,000** | 6,952 |
| `xss` | 26,749 | 14,772 | 26,749 | **25,000** | 6,687 |
| `ddos_http_flood` | 25,741 | 14,772 | 25,741 | **25,000** | 6,436 |
| `sqli` | 21,324 | 14,772 | 25,000 | **25,000** | 5,331 |
| `command_injection`| 14,772 | 14,772 | 25,000 | **25,000** | 3,693 |
| **Total Records** | **400,000** | **162,492** | **413,904** | **275,000** | **100,000** |

---

## 5. Publication-Quality Diagnostic Visualizations

The pipeline generates 4 high-resolution diagnostic plots stored in [outputs/plots/](outputs/plots):

1. **[original_class_imbalance.png](outputs/plots/original_class_imbalance.png)**: Horizontal bar chart illustrating the raw training class distribution, highlighting benign volume alongside all 10 attack classes.
2. **[train_test_split_distribution.png](outputs/plots/train_test_split_distribution.png)**: Grouped bar chart validating that the stratified 80/20 train/test split preserved exact class proportions across all 11 classes on a logarithmic scale.
3. **[balancing_methods_comparison.png](outputs/plots/balancing_methods_comparison.png)**: Side-by-side grouped bar chart comparing class volumes across Original, RUS, ROS, and Final SMOTE.
4. **[smote_knn_feature_space_pca.png](outputs/plots/smote_knn_feature_space_pca.png)**: 2D PCA projection of `command_injection` demonstrating original training points (blue) alongside newly synthesized SMOTE instances (orange) along Euclidean manifolds.

---

## 6. How to Run the Pipeline

### Step 1: Execute Production Script
Run the automated pipeline from the project root:
```bash
python "Practical 6/run_practical6.py"
```

### Step 2: Interactive Notebook Exploration
Launch the interactive Jupyter notebook to step through each mathematical formulation and plot:
```bash
jupyter notebook "Practical 6/notebooks/Practical_06_Dataset_Balancing.ipynb"
```

---

## 7. Pipeline Continuity to Practical 7
The generated datasets are pre-configured for direct consumption in **Practical 7: Decision Tree & Supervised Classification**:
- **Training Input:** [balanced_training_dataset.parquet](data/processed/balanced_training_dataset.parquet) (275,000 records, exactly 25,000 per class across all 11 classes).
- **Evaluation Input:** [test_dataset.parquet](data/processed/test_dataset.parquet) (100,000 untouched test records).
- Ready for multi-class classification training with leak-free test validation.
