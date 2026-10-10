# Practical 6: Dataset Balancing & Stratified Partitioning for Machine Learning

**Course:** Python for Data Science (`BE05000231_PDS`)  
**Semester:** 5th Semester B.E. / B.Tech  
**Topic:** Mitigation of Extreme Class Imbalance, Zero-Leakage Stratified Partitioning, and $k$-NN SMOTE Manifold Interpolation  
**Pipeline Ingestion:** Practical 5 Feature-Engineered Dataset ([`featured_logs.parquet`](file:///c:/Users/Asus%20f15/PDS-Practicals/Practical%205/data/processed/featured_logs.parquet) — 300,010 records $\times$ 55 columns)  
**External Benchmark Dataset:** Elastic Production Telemetry ([`elastic_featured_logs.csv`](file:///c:/Users/Asus%20f15/PDS-Practicals/Practical%205/data/processed/elastic_featured_logs.csv) — 10,000 records)  
**Pipeline Hand-off:** Prepares Balanced Training Matrix ($X_{\text{train}}, y_{\text{train}}$) and Pure Test Set ($X_{\text{test}}, y_{\text{test}}$) for Practical 7 (Supervised Classification Models)  

---

## 1. Aim and Objectives

### Aim
To handle multi-class class imbalance across cyber telemetry by systematically evaluating Random Undersampling (RUS), Random Oversampling (ROS), and SMOTE strictly on an isolated training split, while locking the test partition 100% untouched to ensure legitimate, leak-free real-world model evaluation.

### Objectives
1. **Pipeline Continuity:** Ingest the 30-feature numerical matrix with continuous anomaly scores from Practical 5 (`featured_logs.parquet`).
2. **Zero-Leakage Split Protocol:** Execute a stratified 80% / 20% train-test split **before** applying any resampling algorithm, locking the 60,002 test records completely untouched.
3. **Resampling Methodology Comparison:** Implement and compare three core balancing techniques:
   - **Random Under-Sampling (RUS):** Majority class downsampling to the minority class baseline ($3,939$ samples per class).
   - **Random Over-Sampling (ROS):** Exact minority duplication with replacement up to $15,000$ samples per class.
   - **SMOTE (Synthetic Minority Over-sampling Technique):** $k$-NN ($k=5$) feature interpolation synthesizing mathematically novel instances.
4. **Equalized 165,000-Record Training Synthesis:** Establish a perfectly equalized training dataset containing exactly $15,000$ samples per class across all 11 classes ($1:1:1:1:1:1:1:1:1:1:1$).
5. **Dual-Format Serialization:** Export balanced training matrices and locked test partitions to CSV and Snappy-compressed Apache Parquet.
6. **Diagnostic Visualizations:** Generate publication-quality plots illustrating raw imbalance, stratified split alignment, technique comparisons, and 2D PCA projections of SMOTE manifolds.

---

## 2. Theoretical Architecture: The Class Imbalance Challenge

### 2.1 The Accuracy Paradox in Cyber Telemetry
In raw access telemetry, benign traffic naturally constitutes the vast majority ($68.7\%$ in our master dataset, and $>99\%$ in production networks), while specific attack vectors (`command_injection`, `sqli`) represent narrow minority fractions.

If a machine learning classifier is trained on raw imbalanced distributions:
- A trivial dummy classifier predicting "Benign" on every request achieves **$68.7\%$ raw accuracy**.
- However, its **Recall on cyberattacks is $0.0\%$**, allowing critical exploits to execute completely undetected.
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
$$\text{ENTERPRISE PROTOCOL: } \quad \text{Raw Data} \xrightarrow{\text{Stratified 80/20 Split}} \begin{cases} \text{Train (80\% = 240,008)} \xrightarrow{\text{SMOTE}} \text{Balanced Train (165,000)} \\ \text{Test (20\% = 60,002)} \xrightarrow{\text{LOCKED}} \text{Untouched Real Distribution} \end{cases}$$

The 60,002 test records remain 100% pure, containing the natural distribution of benign and attack traffic for honest, production-grade validation in Practical 7, 8, and 9.

---

### 2.3 Mathematical Formulation of Resampling Techniques

#### 1. Random Under-Sampling (RUS)
Downsamples majority classes by random selection without replacement until equal to the minority class count $N_{\text{min}}$:

$$S_{\text{RUS}} = \{x_i \sim P(X | y = c) : |S_c| = N_{\text{min}}, \forall c \in C\}$$

- **Advantage:** Fast computational execution ($0.73$s).
- **Limitation:** Discards over $196,679$ legitimate records, severely impoverishing the decision boundary.

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
│       ├── balanced_training_dataset.csv         # Final equalized training dataset (165,000 rows, 15k / class) (29.67 MB)
│       ├── balanced_training_dataset.parquet     # Snappy-compressed Parquet training dataset (9.52 MB)
│       ├── balanced_train_smote.csv              # Full SMOTE training dataset (314,960 rows) (53.04 MB)
│       ├── balanced_train_random_oversampled.csv # Random oversampled dataset (49.11 MB)
│       ├── balanced_train_undersampled.csv       # Random undersampled dataset (43,329 rows) (6.76 MB)
│       ├── test_dataset.csv                      # Strictly locked untouched test partition (60,002 rows) (48.19 MB)
│       ├── test_dataset.parquet                  # Snappy Parquet test partition (14.84 MB)
│       ├── elastic_train_dataset.csv             # Elastic benchmark train partition (8,000 rows)
│       └── elastic_test_dataset.csv              # Elastic benchmark test partition (2,000 rows)
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
| **Total Record Volume** | 240,008 records | 43,329 records | 314,960 records | **165,000 records** |
| **Execution Runtime** | — | **0.73 seconds** | **0.63 seconds** | **2.54 seconds** |
| **Information Retention** | 100% | 18.0% (196k discarded) | 100% (Duplicated) | **100% + Synthetic Manifolds** |
| **Overfitting Vulnerability**| High (Majority Bias) | Low | High (Memorization) | **Minimal (Interpolated)** |
| **Class Distribution** | Imbalanced ($68.7\%$ Benign) | Balanced ($3,939$ / class) | Imbalanced ($165k$ Benign) | **Perfect Equalization ($15,000$ / class)** |

---

### 4.2 Class-by-Class Distribution Breakdown

| Attack Class | Original Train (80%) | RUS Count | ROS Count | Final SMOTE Balanced | Test Split (20% Locked) |
|---|---|---|---|---|---|
| `benign` | 164,960 | 3,939 | 164,960 | **15,000** | 41,240 |
| `path_traversal` | 8,446 | 3,939 | 15,000 | **15,000** | 2,112 |
| `web_shell` | 8,385 | 3,939 | 15,000 | **15,000** | 2,096 |
| `brute_force` | 8,373 | 3,939 | 15,000 | **15,000** | 2,093 |
| `ssrf` | 8,343 | 3,939 | 15,000 | **15,000** | 2,086 |
| `ddos_http_flood` | 8,221 | 3,939 | 15,000 | **15,000** | 2,055 |
| `xss` | 7,738 | 3,939 | 15,000 | **15,000** | 1,934 |
| `dir_fuzzing` | 7,597 | 3,939 | 15,000 | **15,000** | 1,900 |
| `mal_scanner` | 7,312 | 3,939 | 15,000 | **15,000** | 1,828 |
| `sqli` | 6,694 | 3,939 | 15,000 | **15,000** | 1,673 |
| `command_injection`| 3,939 | 3,939 | 15,000 | **15,000** | 985 |
| **Total Records** | **240,008** | **43,329** | **314,960** | **165,000** | **60,002** |

---

## 5. Publication-Quality Diagnostic Visualizations

The pipeline generates 4 high-resolution diagnostic plots stored in [`outputs/plots/`](file:///c:/Users/Asus%20f15/PDS-Practicals/Practical%206/outputs/plots):

1. **`original_class_imbalance.png`**: Horizontal bar chart illustrating the raw training class distribution, highlighting benign dominance ($68.7\%$) against minority vectors.
2. **`train_test_split_distribution.png`**: Grouped bar chart validating that the stratified 80/20 train/test split preserved exact class proportions across all 11 classes on a logarithmic scale.
3. **`balancing_methods_comparison.png`**: Side-by-side grouped bar chart comparing class volumes across Original, RUS, ROS, and Final SMOTE.
4. **`smote_knn_feature_space_pca.png`**: 2D PCA projection of `command_injection` demonstrating original training points (blue) alongside newly synthesized SMOTE instances (orange) along Euclidean manifolds.

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
The generated datasets are pre-configured for direct consumption in **Practical 7: Supervised Classification & Model Training**:
- **Training Input:** [`balanced_training_dataset.parquet`](file:///c:/Users/Asus%20f15/PDS-Practicals/Practical%206/data/processed/balanced_training_dataset.parquet) (165,000 records, 15,000 per class across all 11 classes).
- **Evaluation Input:** [`test_dataset.parquet`](file:///c:/Users/Asus%20f15/PDS-Practicals/Practical%206/data/processed/test_dataset.parquet) (60,002 untouched test records).
- Ready for multi-class classification training (Decision Trees, Random Forest, XGBoost, Logistic Regression) with leak-free test validation.
