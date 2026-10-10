# Practical 4: Basic Attack Classification Using Calibrated Heuristic Engine

**Course:** Python for Data Science (`BE05000231_PDS`)  
**Semester:** 5th Semester B.E. / B.Tech  
**Topic:** Ground-Truth Attack Categorization, Multi-Pass Normalization, SIEM Severity Triage, and Heuristic Attribution  
**Pipeline Ingestion:** Practical 3 Preprocessed Telemetry (`preprocessed_logs.csv` — 300,010 records)  
**External Benchmark Dataset:** Elastic Official Production Apache Access Log (`elastic_preprocessed_logs.csv` — 10,000 records)  
**Scientific Calibration Documentation:** See [`HEURISTIC.md`](file:///c:/Users/Asus%20f15/PDS-Practicals/Practical%204/HEURISTIC.md)  

---

## 1. Aim and Objectives

### Aim
To assign high-precision, ground-truth multi-class attack labels and human-readable diagnostic attributions to preprocessed web access logs using a calibrated heuristic classification engine across 10 discrete attack vectors plus benign traffic.

### Objectives
1. **Pipeline Continuity:** Ingest the clean tabular dataset output from Practical 3 (`preprocessed_logs.csv`).
2. **Multi-Class Ground-Truth Labeling:** Map requests to 10 canonical attack classes (`ddos_http_flood`, `brute_force`, `sqli`, `xss`, `command_injection`, `path_traversal`, `dir_fuzzing`, `ssrf`, `web_shell`, `mal_scanner`) and `benign`.
3. **Zero False-Positive Protection:** Employ context-aware syntax grammar rules that prevent false positives on legitimate customer names and searches.
4. **SIEM Threat Triage:** Assign operational security severity ratings (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) and generate human-readable `label_reason` attributions.
5. **Dual-Format Serialization:** Export the labeled dataset to CSV and high-efficiency Snappy-compressed Parquet.
6. **External Production Benchmark:** Validate heuristic precision against Elastic's official production web server logs.

---

## 2. Theoretical Architecture: Heuristic Labeling vs ML Decoupling

### 2.1 The Non-Circular Heuristic Guarantee
In amateur machine learning workflows, heuristic regex patterns are frequently copied into feature vectors (e.g., `feature_sqli = 1 if SQLI_REGEX.search()`). This creates **circular data leakage**, where models achieve 100% artificial accuracy during evaluation but fail completely on novel zero-day exploits.

Our architecture enforces strict separation of concerns:
- **Practical 4 (This Practical):** Applies signature heuristics strictly to generate the target label vector ($y = \text{label}$).
- **Practical 5 (Feature Extraction):** Derives 28 purely statistical, structural, and behavioral metrics ($X = \text{features}$) such as Shannon entropy, query parameter depth, and token lengths. **No heuristic regex is ever included in the feature set!**

### 2.2 Canonical Attack Classes & Priority Hierarchy

| Priority | Attack Class | Target Vector | Severity Rating |
|---|---|---|---|
| `1` | `ddos_http_flood` | Microscopic inter-arrival time ($\Delta t \le 0.04$s) paired with server saturation | HIGH |
| `2` | `mal_scanner` | Automated vulnerability audit tool signatures in User-Agent (`sqlmap`, `nikto`) | LOW |
| `3` | `command_injection` | Shellshock / OS command binaries and execution operators (`; cat`, `| whoami`) | CRITICAL |
| `4` | `sqli` | Database syntax grammar, union queries, and tautologies (`'1'='1`, `2>1`) | HIGH |
| `5` | `xss` | Executable HTML/JS tags, DOM event handlers (`onerror=`, `onload=`) | HIGH |
| `6` | `path_traversal` | Directory climbing (`../`), sensitive OS file targets (`/etc/passwd`, `win.ini`) | MEDIUM |
| `7` | `ssrf` | Cloud metadata service (`169.254.169.254`), private loopbacks (`127.0.0.1`) | HIGH |
| `8` | `web_shell` | Backdoor filenames (`c99.php`, `wso.php`), execution parameters (`?cmd=whoami`) | CRITICAL |
| `9` | `dir_fuzzing` | Hidden config/environment leaks (`.env`, `.git`), admin portals (`phpmyadmin`) | LOW |
| `10` | `brute_force` | Credential spraying against `/login`, `/auth` with 401/403 or password parameters | MEDIUM |
| `11` | `benign` | Normal, legitimate browsing traffic | INFO |

---

## 3. Directory Structure

```
Practical 4/
├── data/
│   └── processed/
│       ├── labeled_logs.csv                       # Primary labeled ground-truth dataset (210.79 MB)
│       ├── labeled_logs.parquet                   # Compressed Snappy Parquet format (62.33 MB)
│       └── elastic_labeled_logs.csv               # External Elastic labeled dataset (4.04 MB)
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
- **Total Records Evaluated**: **300,010 records**
- **Classification Throughput**: **10,316.7 records/second** (Full dataset labeled in **29.08 seconds**)
- **Macro Distribution**: **68.73% Benign** (206,200 records) : **31.27% Attacks** (93,810 records)
- **Class-by-Class Breakdown**:
  - `benign`: 206,200 records (68.73%)
  - `path_traversal`: 10,558 records (3.52%)
  - `web_shell`: 10,481 records (3.49%)
  - `brute_force`: 10,466 records (3.49%)
  - `ssrf`: 10,429 records (3.48%)
  - `ddos_http_flood`: 10,276 records (3.43%)
  - `xss`: 9,672 records (3.22%)
  - `dir_fuzzing`: 9,497 records (3.17%)
  - `mal_scanner`: 9,140 records (3.05%)
  - `sqli`: 8,367 records (2.79%)
  - `command_injection`: 4,924 records (1.64%)
- **Severity Triage Summary**:
  - `INFO`: 206,200 records (68.73%)
  - `HIGH`: 38,744 records (12.91%)
  - `MEDIUM`: 21,024 records (7.01%)
  - `LOW`: 18,637 records (6.21%)
  - `CRITICAL`: 15,405 records (5.13%)
- **Exported Datasets**:
  - `labeled_logs.csv`: **210.79 MB**
  - `labeled_logs.parquet`: **62.33 MB** (**70.4% compression reduction**)

### 5.2 External Production Benchmark (`elastic_apache_access.log`)
- **Input File**: `Practical 3/data/processed/elastic_preprocessed_logs.csv`
- **Total Lines Evaluated**: **10,000 real production lines**
- **Classification Throughput**: **43,478.3 records/second** (Finished in **0.23 seconds**)
- **Verified Exploits Detected**:
  - Detected 4 real file-wrapper SSRF exploit probes targeting Elastic (`/misc/nmh//%22file://$file/%22` and `/scripts//%22file://$file/%22`)
- **Zero False-Positive Protection**: 0 normal user requests falsely flagged as SQLi or Command Injection.
- **Exported Dataset**: `elastic_labeled_logs.csv` (**4.04 MB**)

---

## 6. Generated Visual Artifacts

1. **`attack_class_distribution.png`**:
   - Horizontal bar chart illustrating the balance across the 10 discrete attack vectors and benign traffic, color-coded by SIEM severity level.
2. **`benign_vs_attack_ratio.png`**:
   - Donut chart depicting the macro ratio of the dataset (68.7% Benign : 31.3% Malicious), fulfilling the 65:35 target balance.
3. **`attack_severity_distribution.png`**:
   - Priority triage bar chart categorizing requests into `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and `INFO`.
4. **`attack_timeline_hourly.png`**:
   - Time-series plot comparing benign vs attack volumes per hour across the ISO-8601 UTC timeline.

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
[Practical 5] Feature Extraction (28 Canonical Features) & Isolation Forest Anomaly Detection
```
