# Practical 10: End-to-End Reusable Web Log Inference Pipeline & Master Threat Hunter GUI

**Course:** Python for Data Science (`BE05000231_PDS`)  
**Semester:** 5th Semester B.E. / B.Tech  
**Academic Term:** 2023–24 GTU-GSET  
**Topic:** Production Inference Pipeline, Real-Time Web Telemetry Forensics, Multi-Model Threat Hunter Dashboard & Executive Audit Reporting  

---

## 1. AIM & OBJECTIVES

### Aim
To design, implement, and deploy an end-to-end, reusable, multi-stage machine learning inference pipeline and an interactive executive web dashboard (Streamlit) for automated parsing, feature extraction, threat classification, zero-day anomaly detection, and publication-ready PDF audit reporting on raw server access logs.

### Objectives
1. **Pipeline Modularity & Continuity:** Ingest raw server access logs and process them seamlessly through the exact sequential transformations engineered across Practicals 1 to 9 (Parsing $\to$ Cleaning $\to$ 31-D Feature Extraction $\to$ Classifier Inference).
2. **Multi-Format Log Parser:** Support arbitrary web server log formats without schema friction, including Apache Combined Log Format, Apache Common, Nginx access logs, JSON Lines telemetry, and raw HTTP request lines.
3. **High-Dimensional Feature Engineering:** Compute all 30 canonical cybersecurity features plus an unsupervised Isolation Forest anomaly score spanning lexical, semantic, velocity, and network dimensions.
4. **Multi-Model Support:** Enable dynamic switching between the top 3 production classifiers trained in Practical 9:
   - **Random Forest Ensemble (Champion):** 98.36% Accuracy, 99.70% Macro Recall, 150 Estimators, Entropy criterion.
   - **Decision Tree (Tuned Fast):** 98.96% Accuracy, 99.64% Macro Recall, Depth=20, sub-millisecond latency.
   - **Logistic Regression (Linear Baseline):** 95.31% Accuracy, 97.69% Macro Recall, L2 regularized.
5. **Request-by-Request Forensic Analysis:** Provide granular classification for every incoming request, identifying legitimate traffic, specific attack categories (SQLi, XSS, Path Traversal, Command Injection, Brute Force, Scanners), and novel zero-day threats via anomaly scores.
6. **False Alarm Management & SOC Feedback:** Implement an analyst feedback loop permitting security operators to flag false alarms with immediate alert feedback and state updates.
7. **Automated Executive PDF Audit Reporting:** Generate 1-click downloadable publication-ready PDF incident reports summarizing attack distributions, top threat actor IPs, sample detections, and actionable mitigation directives.
8. **Minimalist, Premium SOC Aesthetics:** Present a clean, dark-themed user interface utilizing zinc and slate palettes, avoiding harsh or garish neon AI color schemes.

---

## 2. FORENSIC PIPELINE ARCHITECTURE

The Practical 10 inference engine operates as a strictly decoupled 4-stage pipeline:

```
                  ┌─────────────────────────────────────────────────────────┐
                  │            RAW INCOMING SERVER TELEMETRY                │
                  │  (Apache Combined / Nginx / JSON Lines / Raw HTTP Lines) │
                  └───────────────────────────┬─────────────────────────────┘
                                              │
                                              ▼
                  ┌─────────────────────────────────────────────────────────┐
                  │      STAGE 1: MULTI-FORMAT REGEX & JSON PARSER          │
                  │  (pipeline/log_parser.py)                               │
                  │  • Apache Combined regex tokenization                   │
                  │  • JSON-line key-value mapping                          │
                  │  • Raw HTTP request verb/URI decomposition              │
                  │  • Standardized 13-field forensic schema mapping        │
                  └───────────────────────────┬─────────────────────────────┘
                                              │
                                              ▼
                  ┌─────────────────────────────────────────────────────────┐
                  │       STAGE 2: DATA CLEANING & NORMALIZATION            │
                  │  (pipeline/preprocessor.py)                             │
                  │  • URL decoding (%20 -> space, %27 -> ', %3C -> <)     │
                  │  • URI path normalization and query string isolation    │
                  │  • Status code & byte volume numerical coercion         │
                  │  • Missing User-Agent and Referer header imputation     │
                  └───────────────────────────┬─────────────────────────────┘
                                              │
                                              ▼
                  ┌─────────────────────────────────────────────────────────┐
                  │      STAGE 3: 31-D HIGH-DIMENSIONAL FEATURE EXTRACTION  │
                  │  (pipeline/feature_extractor.py)                        │
                  │  • Lexical & Structural: Length, entropy, depth (9 feats│
                  │  • Payload Semantics: SQL, script, traversal, cmd (7)   │
                  │  • Temporal & Velocity: Sliding-window rates, burst (7) │
                  │  • Headers & Anomaly: UA entropy, bot, Isolation Forest │
                  └───────────────────────────┬─────────────────────────────┘
                                              │
                                              ▼
                  ┌─────────────────────────────────────────────────────────┐
                  │     STAGE 4: MULTI-MODEL INFERENCE & ZERO-DAY FILTER    │
                  │  (pipeline/inference_engine.py)                         │
                  │  • Serialized model loading (Practical 9 model artifacts│
                  │  • Multi-class threat classification & probability conf │
                  │  • Isolation Forest zero-day anomaly gating             │
                  │  • Automated SOC mitigation directive mapping           │
                  └───────────────────────────┬─────────────────────────────┘
                                              │
                                              ▼
                  ┌─────────────────────────────────────────────────────────┐
                  │        STAGE 5: PRESENTATION, ALERTS & REPORTING        │
                  │  • Interactive Streamlit Threat Hunter GUI (app.py)     │
                  │  • False Alarm Override & Active Incident Alert Banner  │
                  │  • 1-Click Executive PDF Threat Audit Generator (FPDF2) │
                  └─────────────────────────────────────────────────────────┘
```

---

## 3. STREAMLIT APPLICATION STRUCTURE

The dashboard (`Practical 10/app.py`) is structured into four primary navigation views accessible via the sidebar:

### View 1: 🛡️ Live Threat Hunter (Core Operational Console)
- **Model Selector:** Dynamically swap between Random Forest Ensemble, Tuned Decision Tree, and Logistic Regression.
- **Flexible Ingestion:**
  1. *Sample Realistic Logs (Instant):* 1-click loading of realistic multi-attack evaluation stream (`Practical 10/data/sample_eval_logs.log`).
  2. *Upload Custom Log File:* Accepts `.log`, `.txt`, `.csv`, `.json` access logs.
  3. *Raw Text / Stream Input:* Direct interactive pasting of individual or batched raw log strings.
- **Forensic Pipeline Execution:** Visual step progress indicator tracking Stages 1 through 4 with timing benchmarks.
- **Executive KPI Metric Cards:** Instant display of Total Telemetry Requests, Attacks Blocked (Count & Rate), Legitimate Allowed (Count & Rate), Zero-Day Anomalies Flagged, and Analyst False Alarm Overrides.
- **Active Threat Incident Banner:** Real-time visual alert highlighting dominant threat vectors and edge mitigation recommendations.
- **Request-by-Request Forensics Table:** Filterable and searchable table listing Request ID, Source IP, Method, Resource/Payload, Predicted Verdict, Severity, Confidence Percentage, Anomaly Score, and SOC Action.
- **Deep Payload Inspector & False Alarm Feedback:** Inspect all 31 extracted features for any request, view decoded payload vs raw URL, and toggle false alarm overrides to update telemetry statistics dynamically.
- **1-Click Executive PDF Export:** Generates an executive audit PDF report containing incident summaries, attack breakdowns, top threat actor IPs, and incident response recommendations.

### View 2: 📊 Features Used (31-D Feature Architecture)
- Comprehensive technical documentation of the 30 canonical cybersecurity features + Isolation Forest anomaly score across the 4 security dimensions:
  1. *Lexical & Structural (9 features):* `url_length`, `url_entropy`, `path_depth`, `query_param_count`, `special_char_ratio`, `digit_ratio`, `uppercase_ratio`, `double_slash_count`, `percent_encoding_count`.
  2. *Payload Semantics (7 features):* `payload_length`, `payload_entropy`, `has_sql_semantics`, `has_script_semantics`, `has_traversal_semantics`, `has_command_semantics`, `has_internal_ip_semantics`.
  3. *Temporal & Velocity (7 features):* `inter_request_time`, `requests_per_ip_1min`, `requests_per_ip_5min`, `request_velocity_1sec`, `burst_ratio`, `unique_resources_per_ip_5min`, `failed_login_count`.
  4. *Headers, Network & Anomaly (8 features):* `status_code`, `is_error_status`, `bytes_sent`, `user_agent_length`, `user_agent_entropy`, `is_known_scanner`, `is_bot`, `anomaly_score`.
- **Gini Feature Importance Ranking:** Visual bar chart and table displaying feature importance scores computed from the champion Random Forest model.
- **Live Feature Sandbox:** Interactive input allowing security analysts to enter arbitrary URLs or attack payloads and inspect real-time 31-D extraction values.

### View 3: 🗄️ Datasets Archive (Project-Wide Catalog)
- Complete chronological catalog documenting every dataset created across the curriculum from Practical 1 to Practical 10:
  1. *Raw Server Access Logs (P1 & P2):* 291,489 lines, 92.16 MB raw Apache text.
  2. *Structured Logs (P2):* 291,489 rows, 34.57 MB Parquet, 13 fields.
  3. *Cleaned & Preprocessed Telemetry (P3):* 291,489 rows, 65.50 MB Parquet, URL-decoded.
  4. *Labeled Multi-Class Attacks (P4):* 291,489 rows, 65.36 MB Parquet, ground-truth labels.
  5. *Master 31-D Feature Matrix (P5):* 291,489 rows, 70.93 MB Parquet, 31 dimensions.
  6. *SMOTE Balanced Training Partition (P6):* 66,000 rows, 11.93 MB Parquet, balanced minority classes.
  7. *Golden Locked Test Partition (P6):* 14,000 rows, 15.56 MB Parquet, untouched evaluation set.
  8. *Wrangled & Filtered Telemetry (P7 & P8):* 260,000 rows, 23.41 MB Parquet, aggregated temporal matrices.
  9. *External Real-World Benchmark Suite (P9):* 15,515 rows, 4.20 MB CSV, HuggingFace & CSIC corpora.
- **Interactive Dataset Previewer:** Inspect row counts, schemas, disk paths, and sample record heads directly within the dashboard.

### View 4: ⚡ Model Benchmarks & Tuning Insights
- Side-by-side performance cards for Random Forest (Champion), Decision Tree (Tuned Fast), and Logistic Regression (Baseline).
- Evaluation metrics under both imbalanced and SMOTE-balanced training conditions.
- Real-world external benchmark results validating zero-day generalizability against 15,515 external unseen attack payloads.

---

## 4. HOW TO RUN THE APPLICATION

### Prerequisites
Ensure the virtual environment is active and all required libraries are installed:
```powershell
pip install streamlit fpdf2 pandas numpy scikit-learn joblib
```

### Launching the Dashboard
From the project root directory (`PDS-Practicals`), run:
```powershell
streamlit run "Practical 10/app.py"
```

The application will launch locally at `http://localhost:8501`.

---

## 5. DIRECTORY STRUCTURE & FILE MANIFEST

```
Practical 10/
├── app.py                          # Master Streamlit Threat Hunter Web Dashboard
├── generate_notebook.py             # Automated notebook generator script
├── README.md                       # Comprehensive technical documentation
├── pipeline/
│   ├── __init__.py                 # Pipeline module initializer
│   ├── log_parser.py               # Stage 1: Multi-format log regex and JSON parser
│   ├── preprocessor.py             # Stage 2: URL decoding, path cleaning & normalization
│   ├── feature_extractor.py        # Stage 3: 31-D canonical & anomaly feature extractor
│   ├── inference_engine.py         # Stage 4: Model loading, inference & zero-day detection
│   └── pdf_generator.py            # Stage 5: Executive Threat Audit PDF report generator
├── data/
│   └── sample_eval_logs.log        # Realistic multi-vector evaluation log stream
├── notebooks/
│   └── Practical_10_Reusable_Log_Pipeline.ipynb  # End-to-end reproducible Jupyter Notebook
└── outputs/
    └── executive_threat_audit_report.pdf         # Sample generated PDF audit report
```

---

## 6. PIPELINE MODULE SPECIFICATIONS

| Module | Purpose | Key Functions / Classes | Inputs | Outputs |
| :--- | :--- | :--- | :--- | :--- |
| `log_parser.py` | Multi-Format Ingestion | `parse_log_line()`, `parse_logs_text()` | Raw text string | Standardized 13-field DataFrame |
| `preprocessor.py` | Normalization & Cleaning | `clean_and_normalize_logs()` | Parsed DataFrame | Decoded & normalized DataFrame |
| `feature_extractor.py` | High-D Feature Matrix | `extract_features_dataframe()` | Cleaned DataFrame | 31-column numerical feature matrix |
| `inference_engine.py` | Prediction & Forensics | `ThreatInferenceEngine`, `.predict()` | Feature DataFrame | Class labels, confidences, anomaly flags |
| `pdf_generator.py` | Executive Reporting | `generate_threat_audit_pdf()` | Telemetry & predictions | Publication-ready PDF byte stream |

---

## 7. SUMMARY OF PRODUCTION CLASSIFIERS

| Classifier | Model File | Accuracy | Macro Recall | Macro F1 | Latency | Deployment Role |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **Random Forest Ensemble** | `random_forest_balanced.joblib` | **98.36%** | **99.70%** | **0.9690** | 0.24 ms | **Champion Model:** Highest recall, ensemble robustness. |
| **Decision Tree (Tuned)** | `decision_tree_tuned.joblib` | **98.96%** | **99.64%** | **0.9804** | 0.01 ms | **Fast Edge Model:** Ultra-low latency edge filtering. |
| **Logistic Regression** | `logistic_regression.joblib` | **95.31%** | **97.69%** | **0.9179** | 0.00 ms | **Baseline Model:** Linear calibration reference. |
