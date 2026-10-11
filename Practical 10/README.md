# Practical 10: Interactive Threat Intelligence & Autonomous Model Deployment Platform

**Course:** Python for Data Science (`BE05000231_PDS`)  
**Semester:** 5th Semester B.E. / B.Tech  
**Academic Term:** 2023–24 GTU-GSET  
**Topic:** Next.js SOC Dashboard, FastAPI Telemetry Backend, Isolation Forest Anomaly Engine, Multi-Class ML Inference, SQLite Audit Persistence & Executive PDF Export  

---

## 1. Aim & Objectives

### Aim
To engineer, integrate, and deploy a production-grade, end-to-end cyber threat intelligence platform consisting of a high-performance **FastAPI** machine learning service and an executive **Next.js** Security Operations Center (SOC) dashboard. The platform ingests raw HTTP web access logs, executes a 5-stage ML pipeline, performs unsupervised Isolation Forest anomaly scoring, classifies threats using physical scikit-learn champion models with **100% autonomous machine learning inference**, persists all telemetry runs and threat actor profiles to an **SQLite database**, and generates publication-ready executive PDF audit reports with a single click.

### Objectives
1. **Pipeline Continuity (Practicals 1 to 9):** Ingest raw server access logs and execute the authentic pipeline transformations:
   $$\text{Ingestion (P1)} \to \text{CLF Lexer (P2)} \to \text{Sanitization (P3)} \to \text{30 Features + Isolation Forest (P5)} \to \text{Champion ML Inference (P9)}$$
2. **Autonomous ML Decision Logic:** Eliminate mock formulas, heuristic keyword overrides, and hardcoded post-prediction escalations. Classification decisions are 100% computed from the 30-feature vector and physical scikit-learn models. Ground truth labels originate from Practical 4 weak supervision heuristics (as mandated by the GTU syllabus), and feature extraction computes numeric lexical properties.
3. **Executive Next.js Frontend:** Modern, responsive, minimalist SOC dashboard built with Next.js 16, TypeScript, and Tailwind CSS. Strictly **ZERO emojis** throughout the user interface, utilizing clean Lucide SVG icons.
4. **Persistent SQLite Telemetry Store:** Save every ingested log stream and every classified request into a local relational database (`data/telemetry.db`) with relational schema mapping (`runs` and `classified_requests` tables, including persistent `top_ips` profiling).
5. **Interactive Model Switching & Real Benchmarks:** Support on-the-fly switching between the models trained in Practical 9:
   - **Random Forest Ensemble (Champion):** 98.72% Accuracy, 99.62% Macro Recall, 150 bagged trees, entropy criterion.
   - **Decision Tree (Tuned Fast):** 99.01% Accuracy, 99.58% Macro Recall, depth=20, sub-millisecond line-rate latency.
6. **Executive PDF Audit Export:** One-click automated report generation compiling incident summaries, attack rate percentages, top malicious source IPs, anomaly distributions, and WAF mitigation directives using `fpdf2`.

---

## 2. Platform Architecture

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        NEXT.JS 16 SOC FRONTEND                         │
│                    (http://localhost:3000 - Web UI)                    │
│  • Dark Slate SOC Aesthetic            • Zero Emojis (Lucide Icons)    │
│  • Drag & Drop Telemetry Buffer        • Interactive Attack Meters     │
│  • Top Malicious IPs Drilldown         • Granular Telemetry Table      │
│  • SQLite Audit History Modal          • 1-Click Executive PDF Export  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Reverse Proxy (/api/*)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        FASTAPI ML BACKEND                              │
│                   (http://127.0.0.1:8000 - REST API)                   │
├────────────────────────────────────────────────────────────────────────┤
│ STAGE 1: INGESTION & BUFFER (Practical 1)                              │
│   Reads raw access logs; validates UTF-8 payload byte streams.        │
├────────────────────────────────────────────────────────────────────────┤
│ STAGE 2: COMBINED LOG FORMAT LEXER (Practical 2)                       │
│   Extracts IP, RFC-1123 timestamp, HTTP verb, URI, status, bytes.      │
├────────────────────────────────────────────────────────────────────────┤
│ STAGE 3: NORMALIZATION & DATA CLEANING (Practical 3)                   │
│   URL decodes query parameters; isolates path & query strings.         │
├────────────────────────────────────────────────────────────────────────┤
│ STAGE 4: 30-VECTOR FEATURE EXTRACTION & ISOLATION FOREST (Practical 5) │
│   Computes Shannon entropy, token ratios, lexical markers.             │
│   Evaluates isolation_forest.joblib: anomaly_score = -score_samples(X) │
├────────────────────────────────────────────────────────────────────────┤
│ STAGE 5: CHAMPION MULTI-CLASS ML CLASSIFIER (Practical 9)              │
│   Evaluates random_forest_tuned.joblib / decision_tree_tuned.joblib.   │
│   Strictly 100% pure machine learning prediction matrices.             │
└───────────────────┬────────────────────────────────┬───────────────────┘
                    │                                │
                    ▼                                ▼
       ┌────────────────────────┐      ┌───────────────────────────┐
       │   SQLITE DATABASE      │      │    EXECUTIVE PDF ENGINE   │
       │  (data/telemetry.db)   │      │  (fpdf2 Executive Audit)  │
       │  • runs table          │      │ • Attack distribution     │
       │  • classified_requests │      │ • Top threat actor IPs    │
       └────────────────────────┘      │ • WAF mitigation orders   │
                                       └───────────────────────────┘
```

---

## 3. Machine Learning Models & Real Empirical Benchmarks

All models were trained on 275,000 balanced instances (Practical 6-9) and evaluated on the locked 100,000 test partition:

| Model Architecture | Partition | 100k Test Acc | Macro Recall | Macro F1 | Unseen Attack Recall (225 reqs) | Production Role |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Random Forest (Tuned)** | Balanced (275k) | **98.72%** | **99.62%** | **0.9881** | **95.86% (139 / 145)** | **Production Champion** |
| **Decision Tree (Tuned)** | Balanced (275k) | **99.01%** | **99.58%** | **0.9908** | **58.62% (85 / 145)** | **High-Throughput Line-Rate** |
| **Random Forest (Base)** | Balanced (275k) | 98.72% | 99.62% | 0.9881 | 95.86% (139 / 145) | Default Ensemble Baseline |
| **Decision Tree (Base)** | Balanced (275k) | 97.32% | 99.14% | 0.9737 | 89.66% (130 / 145) | Default Tree Baseline |
| **Logistic Regression (Linear)** | Balanced (275k) | 94.95% | 98.02% | 0.9503 | 74.48% (108 / 145) | Linear Scaled Baseline |

### Anomaly Engine Specifications (Practical 5)
- **Model:** Physical `isolation_forest.joblib` + `scaler.joblib`.
- **Hyperparameters:** $n=100$ isolation trees, contamination rate $= 0.015$ (1.5%), sub-sample ratio $= 0.8$.
- **Scoring Function:** Normalized inverted path length: $\text{Score} = -\text{score\_samples}(X)$.
- **Escalation Policy:** Transactions scoring $> 0.52$ trigger automated WAF quarantine and alert escalation.

---

## 4. SQLite Database Schema

All inference telemetry is stored locally in `Practical 10/data/telemetry.db`:

### `runs` Table
| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | INTEGER PRIMARY KEY | Autoincrementing unique primary key |
| `run_id` | TEXT UNIQUE | Unique audit run identifier (`RUN-YYYYMMDDHHMMSS-XXXXXX`) |
| `filename` | TEXT | Log source filename or buffer tag |
| `timestamp` | TEXT | UTC execution timestamp (ISO-8601) |
| `total_requests` | INTEGER | Total HTTP requests analyzed |
| `benign_count` | INTEGER | Total legitimate requests |
| `attack_count` | INTEGER | Total malicious requests identified |
| `attack_rate_pct` | REAL | Attack ratio percentage ($0.0 - 100.0\%$) |
| `mean_anomaly_score` | REAL | Mean Isolation Forest score |
| `max_anomaly_score` | REAL | Peak anomaly score detected |
| `execution_time_ms` | REAL | Total pipeline processing latency in ms |
| `model_used` | TEXT | Classifier model identifier |
| `risk_level` | TEXT | Overall SOC risk badge (`Nominal`, `Elevated`, `High`, `Critical`) |
| `top_attack_type` | TEXT | Dominant exploit category |
| `attack_breakdown_json` | TEXT | Serialized JSON dictionary of class counts |
| `top_ips_json` | TEXT | Serialized JSON array of top threat actor source IPs |

### `classified_requests` Table
| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | INTEGER PRIMARY KEY | Autoincrementing record ID |
| `run_id` | TEXT | Foreign key reference to `runs.run_id` |
| `line_number` | INTEGER | Sequential line index within source log |
| `client_ip` | TEXT | Source IPv4 address |
| `timestamp` | TEXT | Original Apache Common log timestamp |
| `method` | TEXT | HTTP request verb (`GET`, `POST`, `PUT`, `DELETE`) |
| `resource` | TEXT | Target request URI path and query string |
| `status_code` | INTEGER | HTTP response status code |
| `bytes_sent` | INTEGER | Response size in bytes |
| `user_agent` | TEXT | Client User-Agent header string |
| `anomaly_score` | REAL | Isolation Forest anomaly score ($0.0 - 1.0$) |
| `predicted_label` | TEXT | Canonical attack label (`sqli`, `xss`, `benign`, etc.) |
| `display_name` | TEXT | Human-readable attack category name |
| `confidence_pct` | REAL | ML classification confidence percentage ($0.0 - 100.0\%$) |
| `severity` | TEXT | Threat severity level (`Low`, `Medium`, `High`, `Critical`) |
| `recommended_action` | TEXT | Prescribed SOC mitigation action |
| `is_attack` | INTEGER | Binary classification indicator ($0 = \text{Benign}, 1 = \text{Attack}$) |

---

## 5. API Reference (FastAPI Backend)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Returns backend operational status, active model, and loaded weights. |
| `GET` | `/api/models` | Returns list of available trained models and champion indicators. |
| `GET` | `/api/sample-logs` | Returns built-in demonstration telemetry streams. |
| `POST` | `/api/analyze-log` | Ingests log stream (JSON or multipart file), runs pipeline stages 1-5, persists to DB, and returns full results. |
| `GET` | `/api/history` | Returns paginated list of historical audit runs from SQLite. |
| `GET` | `/api/runs/{run_id}` | Retrieves full summary and classified request array for a past run. |
| `DELETE` | `/api/runs/{run_id}` | Removes a run and all associated records from SQLite. |
| `GET` | `/api/export-pdf/{run_id}` | Generates and streams executive incident audit PDF report. |

---

## 6. Execution Guide

### Option 1: Unified Platform Launcher
To start both the FastAPI ML Backend and Next.js Frontend simultaneously:
```bash
python run_practical10.py
```
This automatically launches:
- **Frontend Dashboard:** [http://localhost:3000](http://localhost:3000)
- **Backend API:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive Swagger Docs:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### Option 2: Running Components Individually
**FastAPI Backend:**
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

**Next.js Frontend:**
```bash
cd frontend
npm install
npm run dev
```

---

## 7. Directory Structure

```text
Practical 10/
├── backend/
│   ├── main.py                     # FastAPI REST server & pipeline orchestrator
│   └── database.py                 # SQLite persistence layer (telemetry.db)
├── data/
│   └── telemetry.db                # SQLite database storing runs & classifications
├── frontend/
│   ├── package.json                # Next.js dependencies (Next 16, React 19, Lucide)
│   ├── next.config.ts              # API proxy rewrite to localhost:8000
│   └── src/
│       ├── app/
│       │   ├── globals.css         # Dark minimalist SOC styling
│       │   ├── layout.tsx          # Root layout & page metadata
│       │   └── page.tsx            # Main interactive dashboard container
│       ├── components/
│       │   ├── Navbar.tsx          # Brand, model selector, health status pill
│       │   ├── PipelineFlow.tsx    # 5-stage architectural pipeline breadcrumbs
│       │   ├── LogIngestionCard.tsx# Drag & drop upload, presets, raw text buffer
│       │   ├── KpiSummaryCards.tsx # Total volume, attack rate, anomaly score, PDF export
│       │   ├── ThreatAnalyticsGrid.tsx # Attack distribution & top threat actor IPs
│       │   ├── RequestTable.tsx    # Multi-class table, search filter, feature details
│       │   ├── HistoricalRunsModal.tsx # Past SQLite audit run drawer
│       │   └── ModelBenchmarkModal.tsx # Empirical training benchmarks & scorecard
│       ├── services/
│       │   └── api.ts              # Resilient typed API client
│       └── types/
│           └── telemetry.ts        # TypeScript interface definitions
├── pipeline/
│   ├── log_parser.py               # Practical 2 Combined Log Format lexer
│   ├── preprocessor.py             # Practical 3 Sanitization & normalization
│   ├── feature_extractor.py        # Practical 5 30 features + Isolation Forest joblib
│   ├── inference_engine.py         # Practical 9 Champion scikit-learn models (with standard scaling)
│   └── pdf_generator.py            # fpdf2 publication-ready incident PDF export
├── run_practical10.py              # Single-command unified platform launcher
└── README.md                       # Comprehensive platform documentation
```
