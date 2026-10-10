# Practical 1: To Load and Explore the Unstructured Access Log Data

**Course:** Python for Data Science (`BE05000231_PDS`)  
**Semester:** 5th Semester B.E. / B.Tech  
**Topic:** Access Log Telemetry Ingestion, Generator Streaming, Schema Anatomy, and Reservoir Sampling  
**Target Dataset:** Enterprise Apache/Nginx Combined Access Log (`server_access.log` — 300,000 records, 87.89 MB)

---

## 1. Aim and Objectives

### Aim
To learn how to import, inspect, memory-audit, and explore raw, unstructured web server access logs formatted according to the industry-standard Apache/Nginx Combined Log Format using Python standard libraries, generator streaming, and scientific data visualization.

### Objectives
1. **Memory-Efficient Streaming Ingestion**: Implement an $O(1)$ space complexity generator using Python `yield` to stream large raw access logs without memory exhaustion.
2. **Memory Profiling Audit**: Measure and contrast Peak RAM utilization versus eager full-file memory allocation using `tracemalloc`.
3. **Schema Anatomy & Token Identification**: Deconstruct the 9 constituent tokens of the standard Combined Log Format (`%h`, `%l`, `%u`, `%t`, `%r`, `%>s`, `%b`, `Referer`, `User-Agent`).
4. **Reproducible Random Sampling**: Extract 10 diverse sample lines across 300,000 log records using reservoir sampling (seed = 42) for manual pattern inspection.
5. **Useful Field Identification**: Map raw fields to downstream cybersecurity analytics (attack detection, session velocity, bot classification).
6. **Exploratory Visualizations**: Plot character line length distributions, HTTP method distributions, and HTTP response status code breakdowns.
7. **Real-World Cross-Verification**: Verify streaming ingestion across external, independent server captures (CSIC 2010 HTTP dataset).

---

## 2. Theoretical Background

### 2.1 Unstructured Web Server Access Logs
In production web infrastructure (Apache HTTP Server, Nginx, LiteSpeed, Caddy), incoming client interactions are logged line-by-line as unstructured text strings. The web server writes one continuous line per HTTP transaction following the **NCSA Combined Log Format**:

$$\text{Log Line} = \text{\%h \%l \%u \%t \"\%r\" \%>s \%b \"\%\{Referer\}i\" \"\%\{User-Agent\}i\"}$$

```text
192.168.1.105 - - [08/Oct/2026:08:15:32 +0000] "GET /products/item?id=45 HTTP/1.1" 200 4520 "https://google.com/" "Mozilla/5.0..."
└───┬───────┘ │ │ └─────────────┬─────────────┘ └─────────────────┬───────────────┘  │    │   └──────────┬──────────┘ └───────┬──────┘
    │         │ │               │                                 │                  │    │              │                    │
 Client IP  Ident User      Timestamp                       Request Line           Status Bytes       Referer             User-Agent
```

### 2.2 Token-by-Token Specification

| Token | Directive | Semantic Meaning | Diagnostic Role in Security |
|---|---|---|---|
| `%h` | Remote Host | Client IPv4 / IPv6 address | IP velocity, session rate, bot clustering, brute force IP tracking |
| `%l` | Remote Logname | RFC 1413 identd lookup (typically `-`) | Historical user identity check |
| `%u` | Authenticated User | HTTP Basic Auth username (typically `-`) | Credential spraying, account enumeration |
| `%t` | Request Time | `[day/month/year:hour:minute:second zone]` | Arrival velocity delta ($\Delta t$), diurnal trends, Layer-7 DDoS bursts |
| `"%r"` | Request Line | Method, URI path with query string, and protocol | Injection payloads (SQLi, XSS, Path Traversal, SSRF, WebShell) |
| `%>s` | Status Code | 3-digit HTTP response code | Anomaly signal: `401/403` (auth failure), `404` (fuzzing), `503/429` (DDoS) |
| `%b` | Bytes Sent | Response body size excluding headers | Information exfiltration, buffer leaks, error page size anomalies |
| `Referer` | HTTP Referer | Originating page URL | CSRF investigation, traffic origin analysis |
| `User-Agent` | User-Agent | Client browser, OS, crawler, or audit tool | Malicious scanners (`sqlmap`, `nikto`, `masscan`), search engine bots |

### 2.3 Memory Complexity: Generator Streaming ($O(1)$) vs Eager Loading ($O(N)$)
When processing access logs in Python:
- **Eager Loading (`file.readlines()` / `pd.read_csv()`)**: Allocates every physical line into an in-memory list or DataFrame simultaneously. For an 88 MB file with 300,000 lines, memory consumption exceeds **250+ MB** of Python object overhead. On a 10 GB production log, this causes an `OutOfMemoryError` crash.
- **Generator Streaming (`yield`)**: Keeps only a **single line in memory at any given instant**. Space complexity is strictly $O(1)$, keeping RAM usage $< 8\text{ MB}$ regardless of file size.

---

## 3. Directory Structure

```
Practical 1/
├── data/
│   └── raw/
│       └── server_access.log                      # Master 300,000-line server access log (87.89 MB)
├── notebooks/
│   └── Practical_01_Access_Log_Exploration.ipynb  # Interactive runnable Jupyter Notebook
├── outputs/
│   ├── plots/
│   │   ├── line_length_distribution.png           # Character line length histogram & KDE
│   │   ├── top_methods_preliminary.png            # HTTP request method frequency breakdown
│   │   └── top_status_preliminary.png             # HTTP status code frequency breakdown
│   └── reports/
│       └── practical1_exploration_report.txt      # Full mathematical & architectural audit report
├── run_practical1.py                              # Standalone CLI execution pipeline
└── README.md                                      # Comprehensive GTU Documentation & Report
```

---

## 4. How to Run

### Option A: Standalone Python Script
Execute the end-to-end exploration script from the terminal:
```bash
python "Practical 1/run_practical1.py"
```

### Option B: Interactive Jupyter Notebook
Open and run all cells interactively:
```bash
jupyter notebook "Practical 1/notebooks/Practical_01_Access_Log_Exploration.ipynb"
```

---

## 5. Execution Results & Empirical Observations

### 5.1 Ingestion & Memory Profiling Metrics
- **Dataset**: `server_access.log` (Apache/Nginx Combined Log Format)
- **Physical File Size**: **87.89 MB** (92,161,229 bytes)
- **Total Physical Lines**: **300,010 lines**
- **Peak RAM Footprint (Generator Streaming)**: **7.34 MB** ($O(1)$ memory verified)
- **Ingestion Throughput**: **~28,255 lines/second**
- **Memory Reduction**: **> 96% savings** compared to eager in-memory loading.

### 5.2 Reproducible Random Sample Inspection (Seed = 42)
Below are 10 sample lines extracted across different offsets of the 300,000-line dataset via Reservoir Sampling:

| Line # | Client IP | HTTP Method | Status Code | Resource URI (with Payload) |
|---|---|---|---|---|
| `#128343` | `191.220.166.232` | `GET` | `200` | `/search?q=%3Cstyle%3E%40keyframes%20x...` *(XSS Probe)* |
| `#22772` | `189.220.208.176` | `POST` | `200` | `/cmd.aspx?action=dir` *(Web Shell Probe)* |
| `#29552` | `24.28.147.187` | `GET` | `200` | `/store/item?modo=registro&login=piatt...` *(Benign)* |
| `#233428` | `192.87.177.29` | `GET` | `404` | `/store/item?modo=entrar&login=dev...` *(Benign)* |
| `#55457` | `73.95.41.66` | `POST` | `200` | `/store/item?modo=entrar&login=gabbai...` *(Benign)* |
| `#267804` | `73.130.15.101` | `GET` | `302` | `/store/item?RotomMow Rotom` *(Benign Bingbot)* |
| `#50443` | `199.220.30.39` | `GET` | `403` | `/products/item?id=1%22%20%20%20%29...` *(SQLi Tautology)* |
| `#227047` | `104.28.149.7` | `GET` | `301` | `/store/item?modo=entrar&login=marlee...` *(Benign)* |
| `#298818` | `24.254.98.201` | `GET` | `200` | `/store/item?Jessie,Lin,6155,Air Defense...` *(Benign)* |
| `#152717` | `98.241.206.124` | `GET` | `302` | `/store/item?modo=registro&login=marykay...` *(Benign)* |

### 5.3 External Real-World Log Cross-Verification
- **External Dataset**: CSIC 2010 HTTP Dataset (`normalTrafficTraining.txt` — Spanish National Research Council).
- **Physical Lines Streamed**: **420,000 lines**.
- **Ingestion Result**: **100% Success** with zero encoding or memory errors.

---

## 6. Generated Visual Artifacts

1. **`outputs/plots/line_length_distribution.png`**:
   - Histogram displaying character length distribution per log line. Shows the bimodal distribution: short standard browsing requests (~120–250 chars) versus heavily encoded, high-entropy injection payloads (> 500 chars).
2. **`outputs/plots/top_methods_preliminary.png`**:
   - Frequency breakdown of preliminary HTTP request methods (`GET`, `POST`, `HEAD`).
3. **`outputs/plots/top_status_preliminary.png`**:
   - HTTP response status code breakdown categorized by class: `2xx` Success (green), `3xx` Redirection (amber), and `4xx`/`5xx` Errors (red).


