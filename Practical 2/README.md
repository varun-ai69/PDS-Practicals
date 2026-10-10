# Practical 2: Convert Unstructured Log Data into a Structured Dataset

**Course:** Python for Data Science (`BE05000231_PDS`)  
**Semester:** 5th Semester B.E. / B.Tech  
**Topic:** Regular Expression Log Parsing, Schema Harmonization, Data Type Optimization, and Tabular Export  
**Primary Dataset:** Enterprise Master Access Log (`server_access.log` — 300,000 lines, 87.89 MB)  
**External Benchmark Dataset:** Elastic Official Production Apache Access Log (`elastic_apache_access.log` — 10,000 lines, 2.26 MB)

---

## 1. Aim and Objectives

### Aim
To parse unstructured web server access log lines into a structured tabular dataset (Pandas DataFrame), enforce canonical data types, extract isolated query payloads, and export the standardized records into CSV and Parquet formats.

### Objectives
1. **Compiled Regular Expressions**: Formulate a robust regex pattern utilizing named/numbered capture groups to extract the 9 core NCSA Combined Log tokens.
2. **Graceful Malformed Line Handling**: Guarantee 100% resilient parsing with zero script termination on unencoded or non-standard characters.
3. **Canonical 13-Column Schema**: Structure every record into standard fields (`client_ip`, `ident`, `auth_user`, `timestamp`, `request_method`, `resource_requested`, `http_protocol`, `status_code`, `bytes_sent`, `referrer`, `user_agent`, `payload`, `line_number`).
4. **Memory Downcasting Optimization**: Convert generic Python string object columns into optimized numerical (`int16`, `int32`) and `category` types to reduce RAM utilization.
5. **Dual-Format Tabular Serialization**: Export the final structured dataset to standard CSV and high-efficiency Snappy-compressed Apache Parquet.
6. **External Production Benchmark**: Validate the parser against an external, independent production web log from Elastic (10,000 real-world lines).

---

## 2. Theoretical Architecture & Regular Expression Formulation

### 2.1 The Parsing Challenge
In raw access logs, fields are delimited by a mixture of spaces and quotes. For example, a single space inside a user-agent string or unencoded URI must not be mistaken for a field boundary.

We formulate the compiled pattern:
```regex
^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+(.+?)(?:\s+(HTTP/[\d\.]+|-))?"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?
```

### 2.2 Capture Group Token Mapping

| Group | Field Name | Target Entity | Example Extracted Value |
|---|---|---|---|
| `1` | `client_ip` | Remote Host / Client IP | `192.168.1.105` |
| `2` | `ident` | Remote Logname (RFC 1413) | `-` |
| `3` | `auth_user` | HTTP Basic Auth User | `-` |
| `4` | `timestamp` | Date / Time String | `08/Oct/2026:08:15:30 +0000` |
| `5` | `request_method` | HTTP Verb | `GET`, `POST`, `HEAD`, `OPTIONS` |
| `6` | `resource_requested` | Target URI Path & Parameters | `/store/item?id=45&category=tech` |
| `7` | `http_protocol` | Application Protocol | `HTTP/1.1`, `HTTP/2.0` |
| `8` | `status_code` | HTTP Response Status Code | `200`, `301`, `401`, `404`, `503` |
| `9` | `bytes_sent` | Response Body Size in Bytes | `4520` |
| `10` | `referrer` | HTTP Referer URL | `https://www.google.com/` |
| `11` | `user_agent` | Client User-Agent Header | `Mozilla/5.0 (Windows NT 10.0; Win64; x64)...` |
| Derived | `payload` | Isolated Query Parameter String | `id=45&category=tech` |
| Derived | `line_number` | Physical Line Offset | `1`, `2`, `...`, `300000` |

---

## 3. Directory Structure

```
Practical 2/
├── data/
│   ├── raw/
│   │   ├── server_access.log                      # Master 300,000-line server access log (87.89 MB)
│   │   └── elastic_apache_access.log              # External 10,000-line Elastic production log (2.26 MB)
│   └── processed/
│       ├── structured_logs.csv                    # Primary structured dataset (116.34 MB)
│       ├── structured_logs.parquet                # Snappy compressed Parquet format (32.97 MB)
│       └── elastic_structured_logs.csv            # Structured external Elastic dataset (2.28 MB)
├── notebooks/
│   └── Practical_02_Log_Structuring.ipynb         # Interactive runnable Jupyter Notebook
├── outputs/
│   ├── plots/
│   │   ├── column_completeness_matrix.png         # Field nullity and completeness percentages
│   │   ├── http_method_distribution.png           # GET, POST, HEAD, OPTIONS frequency breakdown
│   │   ├── status_code_distribution.png           # Status codes grouped by 2xx, 3xx, 4xx, 5xx
│   │   └── dataset_memory_reduction.png           # RAM utilization before vs after dtype downcasting
│   └── reports/
│       └── practical2_structuring_report.txt      # Full mathematical & architectural audit report
├── run_practical2.py                              # Standalone execution pipeline
└── README.md                                      # Documentation & Practical Guide
```

---

## 4. How to Run

### Option A: Standalone Python Script
Execute the structured parsing pipeline from the workspace root:
```bash
python "Practical 2/run_practical2.py"
```

### Option B: Interactive Jupyter Notebook
Open and run all cells interactively in VS Code or Jupyter Lab:
```bash
jupyter notebook "Practical 2/notebooks/Practical_02_Log_Structuring.ipynb"
```

---

## 5. Execution Results & Empirical Observations

### 5.1 Primary Enterprise Dataset Structuring (`server_access.log`)
- **Source Physical Lines**: **300,010 lines**
- **Structured Records Generated**: **300,010 rows** (100% accounted)
- **Parsing Success Rate**: **99.9933%** (20 non-standard lines safely handled via fallback parser)
- **Parsing Throughput**: **79,147.2 lines/second** (Full dataset parsed in **3.79 seconds**)
- **Initial In-Memory RAM**: **139.68 MB** (generic Python string objects)
- **Optimized In-Memory RAM**: **126.46 MB** (**9.47% RAM reduction** via categorical and integer downcasting)
- **Exported Formats**:
  - `structured_logs.csv`: **116.34 MB**
  - `structured_logs.parquet`: **32.97 MB** (**71.7% disk compression savings**)

### 5.2 External Real-World Benchmark (`elastic_apache_access.log`)
To verify external validity, we streamed and structured Elastic's official production web server log:
- **External Dataset Source**: Elastic Real-World Apache Logs (10,000 production lines)
- **Parsing Success Rate**: **100.0000%** (10,000 / 10,000 parsed cleanly)
- **Unique Client IPs Identified**: **1,008 unique hosts**
- **Top Requesting IP**: `66.249.73.135` (Googlebot — 482 requests)
- **HTTP Methods Breakdown**:
  - `GET`: 9,952 requests (99.52%)
  - `HEAD`: 42 requests (0.42%)
  - `POST`: 5 requests (0.05%)
  - `OPTIONS`: 1 request (0.01%)
- **Exported External Dataset**: `elastic_structured_logs.csv` (**2.28 MB**)

---

## 6. Generated Visual Artifacts

1. **`column_completeness_matrix.png`**:
   - Horizontal bar chart confirming near-100% field completeness across all core telemetry columns (`client_ip`, `status_code`, `request_method`, `resource_requested`, `timestamp`).
2. **`http_method_distribution.png`**:
   - Visual breakdown of HTTP request methods showing dominant `GET` web browsing accompanied by `POST` form submissions and API operations.
3. **`status_code_distribution.png`**:
   - Categorized status distribution highlighting `200 OK` (success), `301/302` (redirects), `401/403/404` (client-side anomalies and probes), and `503` (volumetric flood saturation).
4. **`dataset_memory_reduction.png`**:
   - Bar comparison demonstrating the reduction in RAM footprint when converting generic object columns into memory-mapped categories and downcasted integers.
