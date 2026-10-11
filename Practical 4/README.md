# Practical 4: Basic Attack Classification Using Calibrated Heuristic Engine

**Course:** Python for Data Science (`BE05000231_PDS`)  
**Semester:** 5th Semester B.E. / B.Tech  
**Topic:** Ground-Truth Attack Categorization, Multi-Pass Normalization, SIEM Severity Triage, and Stateful Heuristic Attribution  
**Pipeline Ingestion:** Practical 3 Preprocessed Telemetry ([preprocessed_logs.csv](../Practical%203/data/processed/preprocessed_logs.csv) — 500,000 records)  
**Scientific Calibration Documentation:** See [HEURISTIC.md](HEURISTIC.md)  

---

## 1. Aim and Objectives

### Aim
To assign high-precision, ground-truth multi-class attack labels and human-readable diagnostic attributions to preprocessed web access logs using a calibrated, stateful heuristic classification engine across 10 discrete attack vectors plus benign traffic.

### Objectives
1. **Pipeline Continuity:** Ingest the clean tabular dataset output from Practical 3 (`preprocessed_logs.csv` — 500,000 records).
2. **Stateful Multi-Class Ground-Truth Labeling:** Map requests to 10 canonical attack classes (`ddos_http_flood`, `brute_force`, `sqli`, `xss`, `command_injection`, `path_traversal`, `dir_fuzzing`, `ssrf`, `web_shell`, `mal_scanner`) and `benign` using sliding-window rate evaluation and context-aware URL parsing.
3. **Zero False-Positive Protection:** Employ syntax grammar rules and per-IP sliding windows that prevent false alarms on legitimate e-commerce browsing, multi-asset concurrent requests, and search queries.
4. **SIEM Threat Triage:** Assign operational security severity ratings (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) and generate human-readable `label_reason` attributions for SOC incident response.
5. **Dual-Format Serialization:** Export the labeled dataset to CSV and high-efficiency Snappy-compressed Parquet for downstream feature extraction.

---

## 2. Theoretical Architecture: Heuristic Labeling vs ML Decoupling

### 2.1 The Non-Circular Heuristic Guarantee
In amateur machine learning workflows, heuristic regex patterns are frequently copied into feature vectors (e.g., `feature_sqli = 1 if SQLI_REGEX.search()`). This creates **circular data leakage**, where models achieve 100% artificial accuracy during evaluation but fail completely on novel zero-day exploits.

Our architecture enforces strict separation of concerns:
- **Practical 4 (This Practical):** Applies signature heuristics and stateful sliding windows strictly to generate the target ground-truth label vector ($y = \text{label}$).
- **Practical 5 (Feature Extraction):** Derives 30 purely statistical, structural, and behavioral metrics ($X = \text{features}$) such as Shannon entropy, query parameter depth, and token lengths. **No heuristic regex is ever included in the feature set!**

### 2.2 Canonical Attack Classes & Priority Hierarchy

| Priority | Attack Class | Target Vector | Severity Rating |
|---|---|---|---|
| `1` | `ddos_http_flood` | Volumetric velocity $\ge 10.0$ req/s sustained over sliding 1-second window per client IP | HIGH |
| `2` | `mal_scanner` | Automated vulnerability audit tool signatures in User-Agent (`sqlmap`, `nikto`, `gobuster`) | LOW |
| `3` | `command_injection` | Shellshock / OS command binaries and execution operators (`; cat`, `| whoami`, `system()`) | CRITICAL |
| `4` | `sqli` | Database syntax grammar, union queries, and tautologies (`'1'='1`, `2>1`, stacked DDL) | HIGH |
| `5` | `xss` | Executable HTML/JS tags, DOM event handlers (`onerror=`, `onload=`, `alert()`) | HIGH |
| `6` | `path_traversal` | Directory climbing (`../`), sensitive OS file targets (`/etc/passwd`, `win.ini`) | MEDIUM |
| `7` | `ssrf` | Cloud metadata service (`169.254.169.254`), private loopbacks (`127.0.0.1`) | HIGH |
| `8` | `web_shell` | Backdoor filenames (`c99.php`, `wso.php`), execution parameters (`?cmd=whoami`) | CRITICAL |
| `9` | `dir_fuzzing` | Hidden config/environment leaks (`.env`, `.git`), admin portals (`phpmyadmin`) | LOW |
| `10` | `brute_force` | Cumulative $\ge 5$ failed authentications (401/403) against `/login`, `/auth` within 300s window | MEDIUM |
| `11` | `benign` | Normal, legitimate browsing traffic | INFO |

---

## 3. Directory Structure

```
Practical 4/
├── data/
│   └── processed/
│       ├── labeled_logs.csv                       # Primary labeled ground-truth dataset (228.51 MB / 217.92 MiB)
│       └── labeled_logs.parquet                   # Compressed Snappy Parquet format (30.18 MB / 28.78 MiB)
├── notebooks/
│   └── Practical_04_Attack_Classification.ipynb  # Interactive runnable Jupyter Notebook
├── outputs/
│   ├── plots/
│   │   ├── attack_class_distribution.png          # Multi-class frequency distribution
│   │   ├── benign_vs_attack_ratio.png             # Macro dataset balance donut chart
│   │   ├── attack_severity_distribution.png       # SIEM incident response severity breakdown
│   │   └── attack_timeline_hourly.png             # Hourly traffic dynamics timeline
│   └── reports/
│       └── practical4_classification_report.txt   # Mathematical audit report
├── run_practical4.py                              # Standalone execution pipeline
├── HEURISTIC.md                                   # Scientific architecture & calibration report
└── README.md                                      # Comprehensive GTU Documentation & Report
```

---

## 4. How to Run

### Option A: Standalone CLI Pipeline
Execute the ground-truth classification pipeline from the workspace root:
```bash
python "Practical 4/run_practical4.py"
```

### Option B: Interactive Jupyter Notebook
Open and run all cells interactively in VS Code or Jupyter Lab:
```bash
jupyter notebook "Practical 4/notebooks/Practical_04_Attack_Classification.ipynb"
```

---

## 5. Execution Results & Empirical Observations

### 5.1 Primary Enterprise Dataset Classification (`server_access.log`)
- **Input File**: Ingested directly from `Practical 3/data/processed/preprocessed_logs.csv`
- **Total Records Evaluated**: **500,000 records**
- **Classification Throughput**: **14,961.1 records/second** (Full dataset labeled in **33.42 seconds**)
- **In-Memory Data Footprint**: **275.04 MB**
- **Macro Distribution**: **35.81% Benign** (179,067 records) : **64.19% Attacks** (320,933 records)

### 5.2 Class-by-Class Ground-Truth Breakdown (10 Attack Vectors + Benign)

| Attack Class | Severity | Record Count | Percentage | Detection Status |
|---|---|---|---|---|
| **benign** | `INFO` | **179,067** | **35.81%** | Active (Zero False Alarms) |
| **path_traversal** | `MEDIUM` | **35,439** | **7.09%** | Active |
| **dir_fuzzing** | `LOW` | **35,000** | **7.00%** | Active |
| **mal_scanner** | `LOW` | **35,000** | **7.00%** | Active |
| **ssrf** | `HIGH` | **35,000** | **7.00%** | Active |
| **web_shell** | `CRITICAL` | **35,000** | **7.00%** | Active |
| **brute_force** | `MEDIUM` | **34,761** | **6.95%** | Active (Stateful $\ge 5$ Failures) |
| **xss** | `HIGH` | **33,436** | **6.69%** | Active |
| **ddos_http_flood** | `HIGH` | **32,177** | **6.44%** | Active (Stateful $\ge 10.0$ req/s) |
| **sqli** | `HIGH` | **26,655** | **5.33%** | Active |
| **command_injection** | `CRITICAL` | **18,465** | **3.69%** | Active |
| **Total** | — | **500,000** | **100.00%** | **All 11 Classes Active** |

### 5.3 Severity Triage Summary (SOC Incident Response Priority)

| Severity Level | Record Count | Percentage | Target Incident Response Action |
|---|---|---|---|
| **INFO** | 179,067 | 35.81% | Baseline operational traffic logging |
| **HIGH** | 127,268 | 25.45% | Automated IP blocking & firewall rule application |
| **MEDIUM** | 70,200 | 14.04% | Rate limiting & authentication challenge (CAPTCHA) |
| **LOW** | 70,000 | 14.00% | Scanner intelligence & reconnaissance tracking |
| **CRITICAL** | 53,465 | 10.69% | Immediate SOC pager alert & server containment |

### 5.4 Exported Datasets
- `labeled_logs.csv`: **228.51 MB** (217.92 MiB)
- `labeled_logs.parquet`: **30.18 MB** (28.78 MiB) (**86.8% compression reduction via Snappy column encoding**)

---

## 6. Generated Visual Artifacts

1. **[attack_class_distribution.png](outputs/plots/attack_class_distribution.png)**:
   - Horizontal bar chart illustrating the distribution across the 10 discrete attack vectors and benign traffic, color-coded by SIEM severity level.
2. **[benign_vs_attack_ratio.png](outputs/plots/benign_vs_attack_ratio.png)**:
   - Donut chart depicting the macro ratio of the dataset (35.8% Benign : 64.2% Malicious).
3. **[attack_severity_distribution.png](outputs/plots/attack_severity_distribution.png)**:
   - Priority triage bar chart categorizing requests into `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and `INFO`.
4. **[attack_timeline_hourly.png](outputs/plots/attack_timeline_hourly.png)**:
   - Time-series plot comparing benign vs attack volumes per hour across the 48-hour UTC timeline.

---

## 7. Pipeline Linkage

```
[Practical 1] Raw Telemetry Exploration
      │
      ▼
[Practical 2] Log Structuring & Regex Parsing (structured_logs.csv)
      │
      ▼
[Practical 3] Data Cleaning & Normalization (preprocessed_logs.csv)
      │
      ▼
[Practical 4] Ground Truth Attack Classification (labeled_logs.csv & labeled_logs.parquet)
      │
      ▼
[Practical 5] Feature Extraction (30 Canonical Features) & Isolation Forest Anomaly Detection
```

- **Upstream Input**: Ingests preprocessed telemetry from [Practical 3/run_practical3.py](../Practical%203/run_practical3.py).
- **Downstream Output**: Supplies 500,000 ground-truth labeled records in [labeled_logs.csv](data/processed/labeled_logs.csv) and [labeled_logs.parquet](data/processed/labeled_logs.parquet) for 30-feature extraction and Isolation Forest anomaly detection in [Practical 5](../Practical%205/run_practical5.py).
