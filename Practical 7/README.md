# Practical 7: Data Wrangling for Aggregated Analysis on Balanced Dataset

**Course:** Python for Data Science (`BE05000231_PDS`)  
**Semester:** 5th Semester B.E. / B.Tech  
**Topic:** Threat Actor Grouping, Temporal Time-Series Resampling, Multi-Dimensional Pivot Tables, and Bot / Internal IP Filtering  
**Pipeline Ingestion:** Practical 6 Balanced Training Dataset ([balanced_training_dataset.parquet](../Practical%206/data/processed/balanced_training_dataset.parquet) — 275,000 records $\times$ 55 columns)  
**Pipeline Hand-off:** Clean Wrangled Telemetry ([wrangled_filtered_dataset.parquet](data/processed/wrangled_filtered_dataset.parquet)) feeds into Practical 8 (Data Visualization & EDA)  

---

## 1. Aim and Objectives

### Aim
To aggregate, reshape, and clean balanced cybersecurity telemetry for deeper operational security insights by grouping attack frequencies per client IP, resampling hourly and daily traffic patterns, constructing multi-dimensional pivot tables, and filtering out automated bot noise and internal RFC 1918 traffic.

### Objectives
1. **Pipeline Continuity:** Ingest the 275,000-record balanced training dataset with full schema preserved from Practical 6 (`balanced_training_dataset.parquet`).
2. **Client IP Threat Profiling:** Group requests by `client_ip` to evaluate attack frequency, attack ratios, and mean Isolation Forest anomaly scores, identifying top persistent threat actors.
3. **Temporal Time-Series Resampling:** Resample datetime telemetry into hourly (`1h`) and daily (`1D`) intervals to monitor volumetric arrival velocity and attack surges across the 48-hour timeline.
4. **Multi-Dimensional Pivot Tables:** Cross-tabulate HTTP request methods (GET, POST, HEAD, etc.) and server status codes (200, 401, 403, 404, 500) against multi-class attack categories.
5. **Operational Noise Filtering:** Filter out automated crawlers (`user_agent` inspection) and RFC 1918 private/loopback IPv4 ranges (`ipaddress.ip_address`), isolating clean external production telemetry.
6. **Dual-Format Serialization:** Export wrangled and filtered datasets to CSV and Snappy-compressed Apache Parquet.
7. **Diagnostic Visualizations:** Generate publication-quality plots illustrating top attacking IPs, hourly trends, pivot heatmaps, and filtering waterfall distributions.

---

## 2. Theoretical Architecture & Engineering Methodology

### 2.1 Threat Actor Profiling by Client IP
Raw web logs record discrete request events. To identify distributed intrusion campaigns, requests must be aggregated by `client_ip`:
- **Total Request Volume ($N_{\text{total}}$):** Baseline traffic footprint of the IP.
- **Attack Event Count ($N_{\text{attack}}$):** Number of requests matching malicious attack vectors.
- **Attack Ratio ($\rho$):** 
  $$\rho = \frac{N_{\text{attack}}}{N_{\text{total}}}$$
  Differentiates benign users ($\rho = 0$), occasional probing ($\rho < 0.2$), and dedicated attacker IPs ($\rho > 0.8$).
- **Mean Anomaly Score:** Continuous Isolation Forest score tracking anomalous behavioral deviations.

---

### 2.2 Temporal Time-Series Resampling
Security attacks occur in bursts. Using Pandas datetime indexing, discrete log records are resampled into continuous time bins:
- **Hourly Resampling ($\Delta t = 1\text{h}$):** Captures high-frequency DDoS surges, brute-force campaigns, and nighttime scanning activity across 48 discrete hourly intervals.
- **Daily Resampling ($\Delta t = 1\text{D}$):** Tracks day-over-day operational threat baselines and multi-day scanning patterns.

---

### 2.3 Multi-Dimensional Pivot Tables
Web threats exploit specific protocol vectors:
- **Request Method $\times$ Attack Label:** SQL injection and XSS frequently leverage `GET` query strings, whereas Credential Stuffing and WebShell uploads exploit `POST` bodies.
- **Status Code $\times$ Attack Label:** Directory fuzzing causes massive spikes in `404 Not Found`, while brute-force attacks concentrate on `401 Unauthorized` and `403 Forbidden`.

---

### 2.4 Operational Noise Filtering
Real-world SOC environments must filter non-malicious operational noise to focus on external threats:
1. **Automated Bot & Crawler Filtering:** Search engine spiders (`Googlebot`, `bingbot`) and automated tools are identified via User-Agent inspection.
2. **RFC 1918 Internal IP Filtering:** Enterprise networks generate internal diagnostic traffic (health checks, monitoring probes). Using Python's `ipaddress` module, private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopbacks (`127.0.0.1`), and link-local addresses (`169.254.0.0/16`) are separated from public internet threats.

---

## 3. Directory Structure

```
Practical 7/
├── data/
│   └── processed/
│       ├── wrangled_filtered_dataset.csv         # Clean external telemetry after bot & internal IP exclusion (151.73 MB)
│       └── wrangled_filtered_dataset.parquet     # Snappy-compressed Parquet (24.23 MB)
├── notebooks/
│   └── Practical_07_Data_Wrangling.ipynb         # Interactive Jupyter notebook walkthrough
├── outputs/
│   ├── aggregated/
│   │   ├── ip_attack_frequency.csv               # Per-IP request volumes, attacks, and attack ratios
│   │   ├── top_attack_ips.csv                    # Top 20 malicious threat actor IPs
│   │   ├── ip_attack_type_matrix.csv             # Full IP x attack class crosstab matrix
│   │   ├── hourly_traffic.csv                    # Hourly resampled traffic & attack rates
│   │   ├── daily_traffic.csv                     # Daily resampled traffic volume
│   │   ├── daily_attack_types.csv                # Daily breakdown across all 11 attack classes
│   │   ├── request_type_label_pivot.csv          # HTTP method x attack label pivot table
│   │   ├── status_code_label_pivot.csv           # Status code x attack label pivot table
│   │   └── filtered/                             # Secondary aggregations on clean filtered telemetry
│   ├── plots/
│   │   ├── ip_attack_frequency.png               # Horizontal bar chart of Top 10 threat IPs
│   │   ├── hourly_traffic_timeseries.png         # Hourly time-series trend of total traffic vs attacks
│   │   ├── request_type_by_label_pivot.png       # Heatmap of HTTP request methods vs attack categories
│   │   └── bot_and_internal_ip_filtering.png     # Waterfall breakdown of noise filtering
│   └── reports/
│       └── wrangling_report.txt                  # Comprehensive technical audit report
├── run_practical7.py                             # Production execution script
└── README.md                                     # Enterprise technical documentation
```

---

## 4. Empirical Verification & Results

### 4.1 Ingestion & Processing Audit

| Metric | Result | Operational Significance |
|---|---|---|
| **Input Ingestion** | `balanced_training_dataset.parquet` | Full 55-column schema from Practical 6 |
| **Total Records Ingested**| **275,000 records** | Perfectly equalized across all 11 classes (25k / class) |
| **Unique Client IPs** | **7,635 unique IPs** | Rich international threat actor distribution |
| **Datetime Range** | UTC Valid Timestamps | Continuous 48-hour enterprise server timeline |
| **Processing Runtime** | **13.04 seconds** | High-throughput vectorized execution |

---

### 4.2 Top 10 Persistent Malicious Threat Actors

| Client IP Address | Total Requests | Attack Count | Attack Ratio | Mean Anomaly Score |
|---|---|---|---|---|
| `45.146.164.27` | 4,250 | **4,182** | **98.40%** | 0.5240 |
| `45.146.164.144`| 4,225 | **4,162** | **98.51%** | 0.5236 |
| `45.146.164.21` | 4,224 | **4,150** | **98.25%** | 0.5242 |
| `45.146.164.138`| 4,173 | **4,122** | **98.78%** | 0.5233 |
| `45.146.164.139`| 4,198 | **4,120** | **98.14%** | 0.5240 |
| `45.146.164.163`| 4,184 | **4,117** | **98.40%** | 0.5233 |
| `194.26.29.167` | 2,568 | **2,568** | **100.00%** | 0.4989 |
| `194.26.29.87`  | 2,525 | **2,525** | **100.00%** | 0.4994 |
| `194.26.29.113` | 2,521 | **2,521** | **100.00%** | 0.4998 |
| `194.26.29.17`  | 2,518 | **2,518** | **100.00%** | 0.5006 |

---

### 4.3 Bot & Internal RFC 1918 Noise Filtering Summary

| Partition | Record Volume | Percentage | Operational Action |
|---|---|---|---|
| **Total Ingested Records** | 275,000 | 100.00% | Full balanced training matrix |
| **Automated Crawlers & Bots** | 15,151 | 5.51% | Excluded via User-Agent signature matching |
| **RFC 1918 / Loopback IPs** | 6,403 | 2.33% | Excluded via standard `ipaddress.is_private` check |
| **Total Discarded Noise** | **21,337** | **7.76%** | Non-malicious background noise filtered |
| **Clean External Telemetry** | **253,663** | **92.24%** | Exported to `wrangled_filtered_dataset.csv` |

---

## 5. Publication-Quality Diagnostic Visualizations

The pipeline generates 4 high-resolution diagnostic plots stored in [outputs/plots/](outputs/plots):

1. **[ip_attack_frequency.png](outputs/plots/ip_attack_frequency.png)**: Horizontal bar chart of the Top 10 high-frequency malicious IPs, demonstrating persistent threat actor concentrations.
2. **[hourly_traffic_timeseries.png](outputs/plots/hourly_traffic_timeseries.png)**: Multi-line time-series chart showing total hourly traffic volume against malicious attack surges with area fill.
3. **[request_type_by_label_pivot.png](outputs/plots/request_type_by_label_pivot.png)**: Color-graded heatmap cross-tabulating HTTP methods (`GET`, `POST`, `HEAD`) against the 11 attack classes.
4. **[bot_and_internal_ip_filtering.png](outputs/plots/bot_and_internal_ip_filtering.png)**: Waterfall bar chart quantifying the exclusion of automated bot crawlers and RFC 1918 internal IPs.

---

## 6. How to Run the Pipeline

### Step 1: Execute Production Script
Run the automated pipeline from the project root:
```bash
python "Practical 7/run_practical7.py"
```

### Step 2: Interactive Notebook Exploration
Launch the interactive Jupyter notebook to step through each aggregation and plot:
```bash
jupyter notebook "Practical 7/notebooks/Practical_07_Data_Wrangling.ipynb"
```

---

## 7. Pipeline Continuity to Practical 8
The clean wrangled telemetry ([wrangled_filtered_dataset.parquet](data/processed/wrangled_filtered_dataset.parquet) — 253,663 records) and aggregated tables directly feed into **Practical 8: Data Visualization and Exploratory Data Analysis (EDA)** using Matplotlib, Seaborn, and Plotly.
