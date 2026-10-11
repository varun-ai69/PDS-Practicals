# Practical 8: Data Visualization and Exploratory Data Analysis (EDA)

**Course:** Python for Data Science (`BE05000231_PDS`)  
**Semester:** 5th Semester B.E. / B.Tech  
**Topic:** Visual Security Analytics, Temporal Traffic Profiling, Heatmaps, and Interactive Dashboards using Matplotlib, Seaborn, and Plotly  
**Pipeline Ingestion:** Practical 7 Clean Wrangled Telemetry ([`wrangled_filtered_dataset.parquet`](../Practical%207/data/processed/wrangled_filtered_dataset.parquet) — 253,663 records $\times$ 55 columns)  
**Pipeline Hand-off:** Prepares Exploratory Ground Truth and Feature Baselines for Practical 9 (Supervised Machine Learning Model Training & Evaluation)  

---

## 1. Aim and Objectives

### Aim
To use visual tools and Python open-source visualization engines (Matplotlib, Seaborn, Plotly) to understand cybersecurity telemetry by constructing requests per hour time-series curves, top attacking IP rankings, temporal attack category distributions, HTTP status code breakdowns, and IP vs request method crosstab heatmaps.

### Objectives
1. **Pipeline Continuity:** Ingest the clean wrangled dataset from Practical 7 (`wrangled_filtered_dataset.parquet`).
2. **Requests per Hour:** Plot time-series traffic velocity and malicious attack surges using dual-engine visualization (Matplotlib line chart + Plotly interactive chart).
3. **Top 10 Attacking IPs:** Visualize persistent threat actor rankings using Seaborn horizontal bar charts and frequency annotations.
4. **Attack Categories Over Time:** Map the multi-vector temporal progression of the 10 discrete attack vectors over time.
5. **Status Code Distributions:** Evaluate HTTP server feedback (2xx, 3xx, 4xx, 5xx) using frequency bar charts and donut charts.
6. **Heatmap of IP vs Request Types:** Construct cross-tabulation heatmaps of top client IPs against HTTP request methods (`GET`, `POST`, `HEAD`, `PUT`).
7. **Interactive Dashboarding:** Export standalone Plotly HTML figures with hover metadata, zoom, and range sliders.
8. **Technical Reporting:** Compile comprehensive exploratory insights into structured audit reports.

---

## 2. Theoretical Architecture & Visual Security Intelligence

### 2.1 Visual Analytics in Security Operations (SOC)
Raw web access logs generated at thousands of events per second are impossible for human analysts to audit manually. Exploratory visual analytics transforms high-dimensional telemetry into actionable threat intelligence:

1. **Temporal Velocity Profiling (Requests per Hour):**
   - Normal traffic follows circadian human schedules (higher during working hours, lower at night).
   - Automated volumetric attacks (DDoS HTTP floods, automated fuzzing) exhibit sudden vertical spikes that deviate from human baselines.
2. **Pareto Threat Concentration (Top 10 Attacking IPs):**
   - Cyber attacks frequently obey the 80/20 Pareto principle: a tiny fraction of coordinated client IPs account for the vast majority of malicious attempts.
3. **Multi-Vector Temporal Dynamics (Attacks Over Time):**
   - Modern advanced persistent threats (APTs) execute multi-stage kill chains: broad directory fuzzing and scanning $\to$ targeted injection (SQLi / XSS) $\to$ brute-force credential stuffing $\to$ remote webshell deployment.
4. **Server Protocol Telemetry (Status Code Distributions):**
   - Normal traffic is dominated by `200 OK` ($>85\%$).
   - Vulnerability audits generate massive clusters of `404 Not Found` (directory enumeration) and `403 Forbidden` (unauthorized access). Exploited server-side syntax bugs manifest as `500 Internal Server Error`.
5. **Protocol Method Utilization (IP vs Request Type Heatmaps):**
   - Benign browsing predominantly uses `GET`.
   - Threat actors skew toward `POST` for credential spraying and webshell commands, or illegal verbs for protocol probing.

---

## 3. Directory Structure

```
Practical 8/
├── data/
│   └── processed/
├── notebooks/
│   └── Practical_08_Visualization_and_EDA.ipynb  # Interactive Jupyter notebook with inline plots & Plotly
├── outputs/
│   ├── plots/
│   │   ├── 01_requests_per_hour.png              # Time-series trend of total traffic vs attacks
│   │   ├── 02_top10_attacking_ips.png            # Horizontal bar chart of top malicious IPs
│   │   ├── 03_attack_categories_over_time.png    # Multi-line dynamics of all attack classes over time
│   │   ├── 04_status_code_distribution.png       # Bar chart & donut chart of HTTP status codes
│   │   ├── 05_ip_vs_request_type_heatmap.png     # Seaborn heatmap of top 20 IPs vs HTTP methods
│   │   ├── 06_attack_class_distribution.png      # Balanced representation of 11 attack classes
│   │   └── 07_feature_correlation_heatmap.png    # Pearson cross-correlation of canonical features
│   ├── interactive/
│   │   ├── 01_requests_per_hour.html             # Interactive Plotly time-series with range slider
│   │   ├── 02_top10_attacking_ips.html           # Interactive Plotly bar chart
│   │   ├── 03_attack_categories_over_time.html   # Interactive Plotly multi-vector line chart
│   │   ├── 04_status_code_distribution.html      # Interactive Plotly status donut chart
│   │   └── 05_ip_vs_request_type_heatmap.html    # Interactive Plotly 2D heatmap
│   └── reports/
│       └── visualization_report.txt              # Factual technical summary report
├── run_practical8.py                             # Production execution script
└── README.md                                     # Enterprise technical documentation
```

---

## 4. Empirical Verification & Results

### 4.1 Ingestion & Execution Metrics

| Metric | Result | Operational Significance |
|---|---|---|
| **Input Ingestion** | `wrangled_filtered_dataset.parquet` | Clean external operational telemetry from Practical 7 |
| **Total Records Analyzed** | **253,663 records** | Post-bot and internal IP filtered telemetry dataset |
| **Unique Client IPs** | **5,340 unique IPs** | Identified public telemetry actors |
| **Attack Classes Evaluated**| **11 discrete classes** | Multi-class attack coverage |
| **Peak Hourly Traffic Arrival Rate** | **9,407 requests/hour** | System maximum burst velocity |
| **Peak Hourly Attack Volume** | **8,944 attacks/hour** | Maximum concurrent malicious surge velocity |
| **Execution Runtime** | **4.85 seconds** | High-speed vectorized visualization generation |

---

### 4.2 Top 10 Malicious Threat Actors Identified

| Rank | Client IP Address | Attack Volume | Total Requests | Dominant Threat Profile |
|---|---|---|---|---|
| 1 | `45.146.164.27` | **4,182** | 4,250 | High-frequency multi-vector automated exploits |
| 2 | `45.146.164.144` | **4,162** | 4,225 | Coordinated external subnet scanning |
| 3 | `45.146.164.21` | **4,150** | 4,224 | Web shell and path traversal fuzzing |
| 4 | `45.146.164.138` | **4,122** | 4,173 | Command injection & SQL injection probe |
| 5 | `45.146.164.139` | **4,120** | 4,198 | High-density injection & scanning burst |
| 6 | `45.146.164.163` | **4,117** | 4,184 | Automated credential stuffing & fuzzing |
| 7 | `194.26.29.167` | **2,568** | 2,568 | 100% malicious exploit scanner probe |
| 8 | `194.26.29.87` | **2,525** | 2,525 | 100% malicious exploit scanner probe |
| 9 | `194.26.29.113` | **2,521** | 2,521 | 100% malicious exploit scanner probe |
| 10 | `194.26.29.17` | **2,518** | 2,518 | 100% malicious exploit scanner probe |

---

## 5. Visual Artifacts Inventory

### 5.1 Static Publication-Quality PNG Plots (`outputs/plots/`)
1. **[`01_requests_per_hour.png`](outputs/plots/01_requests_per_hour.png)**: Multi-line time-series chart showing total hourly request arrival velocity against malicious attack surges with area fill.
2. **[`02_top10_attacking_ips.png`](outputs/plots/02_top10_attacking_ips.png)**: Horizontal bar chart ranking top threat actor IPs by volume with text callouts.
3. **[`03_attack_categories_over_time.png`](outputs/plots/03_attack_categories_over_time.png)**: Multi-line temporal plot showing how different attack vectors peak across time intervals.
4. **[`04_status_code_distribution.png`](outputs/plots/04_status_code_distribution.png)**: Dual-panel figure featuring HTTP status code frequencies (bar chart) and HTTP class distribution (donut chart).
5. **[`05_ip_vs_request_type_heatmap.png`](outputs/plots/05_ip_vs_request_type_heatmap.png)**: High-density color-graded crosstab heatmap cross-referencing top 20 client IPs with HTTP request methods.
6. **[`06_attack_class_distribution.png`](outputs/plots/06_attack_class_distribution.png)**: Balanced representation bar chart across all 11 classes.
7. **[`07_feature_correlation_heatmap.png`](outputs/plots/07_feature_correlation_heatmap.png)**: Pearson cross-correlation matrix across canonical security features.

### 5.2 Standalone Interactive Plotly Dashboards (`outputs/interactive/`)
- **[`01_requests_per_hour.html`](outputs/interactive/01_requests_per_hour.html)**: Interactive time-series explorer with pan, zoom, hover tooltips, and range slider.
- **[`02_top10_attacking_ips.html`](outputs/interactive/02_top10_attacking_ips.html)**: Interactive horizontal bar chart with exact count tooltips.
- **[`03_attack_categories_over_time.html`](outputs/interactive/03_attack_categories_over_time.html)**: Interactive multi-line chart with legend toggling per attack class.
- **[`04_status_code_distribution.html`](outputs/interactive/04_status_code_distribution.html)**: Interactive donut chart with percentage breakdown.
- **[`05_ip_vs_request_type_heatmap.html`](outputs/interactive/05_ip_vs_request_type_heatmap.html)**: Interactive 2D heatmap with cell inspection coordinates.

---

## 6. How to Run the Pipeline

### Step 1: Execute Production Script
Run the automated pipeline from the project root:
```bash
python "Practical 8/run_practical8.py"
```

### Step 2: Interactive Notebook Exploration
Launch the interactive Jupyter notebook to step through each visualization and interact with Plotly charts:
```bash
jupyter notebook "Practical 8/notebooks/Practical_08_Visualization_and_EDA.ipynb"
```

---

## 7. Pipeline Continuity to Practical 9
The exploratory visual distributions and wrangled telemetry feed directly into **Practical 9: Machine Learning Model Evaluation & Hyperparameter Tuning** (multi-class classifiers: Random Forest, Decision Tree, Logistic Regression, XGBoost evaluated across balanced train and untouched test partitions).
