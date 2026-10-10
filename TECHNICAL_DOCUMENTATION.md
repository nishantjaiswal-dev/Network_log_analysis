# AI Log Analysis for Forensics — Technical Architecture & Specifications

This document provides a comprehensive technical breakdown of the **AI Log Analysis for Forensics (DFIR)** platform. It details the internal data pipelines, machine learning algorithms, heuristic scoring logic, cryptographic evidence guarantees, and the complete technology stack used across the backend and frontend.

---

## 1. System Philosophy & Forensic Principles

Digital Forensics and Incident Response (DFIR) mandates strict operational constraints that distinguish it from standard log aggregation (SIEM) tools:

1. **Zero Cloud Dependency & Absolute Data Confidentiality**:
   Host security event logs often contain highly confidential organizational metadata (usernames, internal IP schemes, active directory domain controllers, process arguments, and potentially sensitive command-line parameters). The entire system executes strictly on the local machine with zero external network transmission.

2. **Non-Repudiation & Cryptographic Evidence Integrity (RFC 3161 Principle)**:
   Evidence must remain defensible in formal legal or incident audit scenarios. Raw log evidence is immutable. Every ingested event is cryptographically sealed using SHA-256 hashing and ordered into an append-only Merkle-linked hash chain. Any in-place alteration of records or database tampering is immediately detectable.

3. **Strict Separation of Synthetic Demo Data vs. Real Observed Evidence**:
   A common failure mode in security tooling is the pollution of real forensic baselines with test or synthetic data. Every event carries an immutable `data_origin` tag (`OBSERVED` vs. `SYNTHETIC_DEMO`) enforced from the collector through database storage and API filtering.

4. **Transparent, Explainable AI (XAI)**:
   Security analysts cannot act on black-box risk scores. The system draws a hard line between:
   * **Statistical Anomaly Signal**: Unsupervised Isolation Forest outlier detection relative to an observed baseline.
   * **Heuristic Risk Rules**: Named, auditable detection rules mapped to the MITRE ATT&CK framework.
   * **Score Composition**: The 0–100 risk score explicitly itemizes the points contributed by the ML model versus specific heuristic triggers.

---

## 2. End-to-End Architectural Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             NATIVE OS LOG SOURCES                           │
│  Windows Event Log (Security/System/Sysmon) | macOS Unified Log | Linux Log │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      STAGE 1: NATIVE OS LOG COLLECTORS                      │
│  • Windows: pywin32 (win32evtlog / win32evtlogutil)                         │
│  • macOS: /usr/bin/log show (NDJSON streaming)                              │
│  • Linux: journalctl (systemd journal) / /var/log/auth fallback             │
│  • Demo Mode: Deterministic multi-stage attack storyline generator          │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Raw Record Payloads
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                   STAGE 2: NORMALIZATION & CANONICAL SCHEMA                 │
│  • Transform disparate OS schemas into uniform NormalizedEvent dataclass   │
│  • Preserve verbatim raw_data string (never mutated or stripped)            │
│  • Extract canonical timestamp (ISO 8601 UTC) and Event IDs                 │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│               STAGE 3: CRYPTOGRAPHIC CHAIN OF CUSTODY SEALING               │
│  • Compute Payload SHA-256: H(raw_data : event_uid : timestamp)             │
│  • Compute Parent Pointer: Link to previous_hash in sequential order        │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     STAGE 4: FEATURE EXTRACTION MATRIX                      │
│  • Extract 18 fixed numerical & categorical features                        │
│  • Compute batch-relative frequency/rarity scores: R(x) = 1.0 - count(x) / N│
│  • Calculate Shannon Entropy of command lines: H(s) = -Σ p_i log2(p_i)      │
│  • Detect LOLBins (certutil, powershell) & anomalous parent-child processes │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Feature Matrix (N x 18)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                STAGE 5: UNSUPERVISED ML ANOMALY DETECTION                   │
│  • Scikit-Learn Isolation Forest (200 estimators, random_state=42)          │
│  • Measure average path length across random partitioning trees             │
│  • Min-max normalization: Anomaly Score scaled to [0.00, 1.00]              │
│  • Local Z-Score feature attribution heuristic                              │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Anomaly Score [0, 1]
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│               STAGE 6: EXPLAINABLE FORENSIC RISK SCORING                    │
│  • ML Anomaly contribution: Anomaly Score × 40 points                       │
│  • Rule Heuristics: Up to 60+ points from 18+ MITRE ATT&CK mapped rules    │
│  • Risk Score clamped to [0, 100]                                           │
│  • Stratification: LOW (0-30), MEDIUM (31-60), HIGH (61-80), CRITICAL (81+) │
│  • Generate itemized audit trail: reasons = [ML anomaly, Rule A, Rule B]    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│               STAGE 7: PERSISTENCE (SQLite + SQLALCHEMY ORM)                │
│  • Write-Ahead Logging (WAL) mode for concurrency and atomic writes         │
│  • Indexed by timestamp, risk_score, risk_level, data_origin, batch_id      │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     STAGE 8: FASTAPI REST API SERVICE                       │
│  • /events, /events/suspicious, /timeline, /stats, /forensics/verify        │
│  • Strict CORS allowlist and localhost-only binding                         │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                STAGE 9: REACT 19 INVESTIGATOR DASHBOARD                     │
│  • Incident Trace Timeline with interactive drag-to-select time scrubbing   │
│  • Multi-column sortable table with keyboard triage (↑/↓, j/k)              │
│  • MITRE ATT&CK tactic tagging & one-click entity pivoting (User/IP/Process)│
│  • Real-time Chain-of-Custody Integrity Modal & RFC 3161 proof certification│
│  • Executive Case Dossier report generator with print CSS & JSON export     │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Technology Stack & Technical Dependencies

### 2.1 Backend Core & Libraries

| Library | Version | Technical Purpose & Justification |
| :--- | :--- | :--- |
| **Python** | `3.12+` | Runtime environment leveraging modern type hinting, dataclasses, and standard library concurrency. |
| **FastAPI** | `0.115.0` | High-performance asynchronous REST web framework based on Starlette and Pydantic. Provides auto-generated OpenAPI documentation (`/docs`) and request validation. |
| **Uvicorn** | `0.30.6` | Lightweight ASGI web server for running the FastAPI application. |
| **Pydantic** | `2.9.2` | Data validation, type enforcement, and serialization for request parameters and API payloads. |
| **SQLAlchemy** | `2.0.35` | Object-Relational Mapping (ORM) and SQL expression engine managing database models, transactions, and scoped queries. |
| **SQLite3** | Standard Lib | Serverless, zero-configuration relational database engine operating in WAL mode. Enables portability without database daemon setup. |
| **scikit-learn** | `1.5.2` | Machine learning toolkit providing `IsolationForest` for unsupervised anomaly detection. |
| **NumPy** | `2.1.1` | Optimized numerical arrays and vector calculations for feature matrices and score scaling. |
| **Pandas** | `2.2.3` | Data structures (`DataFrame`, `Series`) used to compute column statistics, rarity frequencies, and Z-score distributions. |
| **pywin32** | Latest | Win32 API bindings for Windows systems (`win32evtlog`, `win32evtlogutil`, `win32con`). Reads raw event records directly from Windows Event Log channels. |
| **pytest** | `8.3.3` | Test automation framework powering the 83-test verification suite. |
| **HTTPX** | `0.27.2` | Asynchronous HTTP test client for testing FastAPI endpoints. |

### 2.2 Frontend Core & Libraries

| Technology | Version | Technical Purpose & Justification |
| :--- | :--- | :--- |
| **React** | `^19.2.8` | Component library using modern hooks (`useState`, `useEffect`, `useMemo`, `useRef`, `useCallback`) for deterministic state management. |
| **React-DOM** | `^19.2.8` | DOM renderer for React components. |
| **Vite** | `^8.2.2` | Ultra-fast build tool and dev server with Hot Module Replacement (HMR) and production bundling via Rollup/esbuild. |
| **Oxlint** | `^1.75.0` | High-performance Rust-based JavaScript/JSX linter enforcing correctness, react-compiler compatibility, and code purity. |
| **Vanilla CSS** | CSS3 | Custom Design Tokens architecture (`tokens.css`) without bloated external UI frameworks. Uses CSS Custom Properties for themes, transitions, and print stylesheets. |
| **Google Fonts** | Hosted | `IBM Plex Sans` (readability), `IBM Plex Sans Condensed` (dense data displays), and `IBM Plex Mono` (timestamps, hashes, and raw records). |

---

## 3. Component Deep Dive

### 3.1 Native OS Log Collection Layer

The collection layer abstracts operating system differences into raw Python dictionaries while preserving raw event payloads.

#### Windows Log Collector (`app/collector/windows_collector.py`)
* **API Mechanism**: Uses `win32evtlog.OpenEventLog` and `win32evtlog.ReadEventLog` with `EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ`.
* **Channels Evaluated**:
  * `Security`: Authentication events (4624, 4625), account lockouts (4740), user account modifications (4720, 4732), and log clearing (1102). Requires elevated Administrator permissions.
  * `System`: Service creation (7045), system time changes, kernel warnings.
  * `Application`: Application crashes and software events.
  * `Sysmon` (`Microsoft-Windows-Sysmon/Operational`): Detailed process creation with full command lines (Event ID 1), network connections (Event ID 3), and registry modifications (Event ID 13).
* **Graceful Degradation**: If the backend runs without administrative elevation, it catches `pywintypes.error` (Error 5: Access is denied) when opening the `Security` log, appends a descriptive warning in the response, and continues reading `System` and `Application` logs.

#### macOS Unified Log Collector (`app/collector/macos_collector.py`)
* **API Mechanism**: Invokes `/usr/bin/log show --style ndjson --predicate ... --last <time_window>` via `subprocess.run`.
* **Stream Handling**: Streams NDJSON (Newline Delimited JSON) outputs, filtering system noise and parsing Apple unified log fields (`machTimestamp`, `subsystem`, `category`, `processImagePath`, `eventMessage`).

#### Linux Collector (`app/collector/linux_collector.py`)
* **Primary Mechanism**: Queries `journalctl -o json --since <time_window>` for structured systemd journal events.
* **Fallback Mechanism**: Reads text logs from `/var/log/auth.log`, `/var/log/secure`, or `/var/log/syslog` using regex patterns for SSH authentication, sudo invocations, and account provisioning.

#### Synthetic Attack Generator (`app/demo/synthetic_data.py`)
* Generates a realistic, correlated attack storyline consisting of:
  1. *Benign Baseline*: Normal employee workstation activity (Outlook, Chrome, Word, Teams).
  2. *Reconnaissance & Password Guessing*: Repeated failed logons (4625) followed by account lockout (4740).
  3. *Execution*: Encoded PowerShell execution with hidden window flags (`powershell.exe -enc -w hidden ...`).
  4. *Living-off-the-Land (LOLBin)*: Binary execution via `certutil.exe -urlcache -split -f`.
  5. *Privilege Escalation*: Backdoor user account creation (4720) added to the Administrators group (4732).
  6. *Persistence*: Modification of `CurrentVersion\Run` registry keys (Sysmon 13).
  7. *Defense Evasion*: Security event log clearing (Event ID 1102).

---

### 3.2 Data Normalization & Canonical Schema

The `NormalizedEvent` class (`app/schemas.py`) serves as the single source of truth across all pipeline stages:

```python
@dataclass
class NormalizedEvent:
    # Identity & Scope
    event_uid: str = field(default_factory=lambda: str(uuid.uuid4()))
    data_origin: str = "OBSERVED"           # "OBSERVED" or "SYNTHETIC_DEMO"
    operating_system: Optional[str] = None  # "Windows", "macOS", "Linux"

    # Core Forensic Fields
    timestamp: str = field(...)            # ISO 8601 UTC
    event_id: Optional[int] = None
    log_source: str = "Unknown"             # "Security", "System", "Sysmon", etc.
    provider: Optional[str] = None
    level: Optional[str] = None             # "Information", "Warning", "Error", "Critical"
    computer: Optional[str] = None
    user: Optional[str] = None
    process_id: Optional[int] = None
    message: Optional[str] = None

    # Extended Contextual Attributes
    parent_process: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None

    # Normalization & Categorization
    event_type: str = "Unknown"             # Human-readable label (e.g. "Logon Failure")
    severity: Optional[str] = None          # Derived unified severity

    # Cryptographic Chain of Custody
    raw_data: str = ""                      # Verbatim original record (Immutable)
    evidence_hash: str = ""                 # SHA-256 digest of record identity
    previous_hash: Optional[str] = None     # SHA-256 link to preceding block

    # Features (Populated downstream)
    features: dict = field(default_factory=dict)
```

---

### 3.3 Cryptographic Chain of Custody & Tamper Verification

To ensure legal defensibility and proof of non-repudiation, records are cryptographically sealed upon ingestion:

#### 1. Payload Hash Calculation
For every row $i$, the evidence hash is computed over the unmutated raw record combined with its unique identifier and timestamp:
$$\text{evidence\_hash}_i = \text{SHA-256}\left(\text{raw\_data}_i \parallel \text{event\_uid}_i \parallel \text{timestamp}_i\right)$$

#### 2. Merkle Chain Link
Each record stores the cryptographic hash of the record immediately preceding it in ingestion order:
$$\text{previous\_hash}_i = \begin{cases} 
0^{64} & \text{if } i = 0 \text{ (Genesis Record)} \\ 
\text{evidence\_hash}_{i-1} & \text{if } i > 0 
\end{cases}$$

#### 3. Continuous Audit Verification Algorithm (`app/pipeline.py`)
When `/forensics/verify` is called, the verification engine audits up to 5,000 records in sequence:
* **Check 1: Content Invariance**: Re-computes $\text{SHA-256}(\text{raw\_data} \parallel \text{event\_uid} \parallel \text{timestamp})$ and verifies equality with stored `evidence_hash`. Any in-place SQL update to raw data or timestamp triggers a hash mismatch alert.
* **Check 2: Chain Continuity**: Verifies that $\text{previous\_hash}_i = \text{evidence\_hash}_{i-1}$. Any deleted record, spliced row, or out-of-order insertion breaks the hash chain linkage.

---

### 3.4 Feature Extraction & Engineering

The feature extraction engine (`app/features/feature_extraction.py`) converts a batch of normalized events into a fixed 18-column numeric feature matrix:

#### Feature Matrix Columns

| Feature Column | Type | Description |
| :--- | :--- | :--- |
| `hour_of_day` | Float | Hour of event timestamp normalized to $[0, 23]$. |
| `is_off_hours` | Binary (0/1) | 1 if event occurred outside standard business hours (8:00 AM – 6:00 PM) or on weekends. |
| `event_type_rarity` | Float $[0, 1]$ | Statistical rarity of the event label relative to the batch. |
| `process_rarity` | Float $[0, 1]$ | Statistical rarity of the executing process binary name. |
| `source_ip_rarity` | Float $[0, 1]$ | Statistical rarity of the originating network address. |
| `dest_port_rarity` | Float $[0, 1]$ | Statistical rarity of the destination port. |
| `user_activity_rarity`| Float $[0, 1]$ | Statistical rarity of the user context within the batch. |
| `is_failed_logon` | Binary (0/1) | 1 if event indicates an authentication failure (Event ID 4625, SSH auth fail). |
| `is_lockout` | Binary (0/1) | 1 if event indicates account lockout (Event ID 4740). |
| `is_powershell_suspicious`| Binary (0/1) | 1 if process is PowerShell and flags include `-enc`, `-encodedcommand`, `-w hidden`, `-nop`, or `-executionpolicy bypass`. |
| `is_lolbin` | Binary (0/1) | 1 if binary matches Living-off-the-Land binaries (`certutil`, `mshta`, `vssadmin`, `rundll32`, `wmic`, `bitsadmin`). |
| `is_suspicious_parent_child` | Binary (0/1) | 1 if interactive shells (`cmd.exe`, `powershell.exe`, `bash`) were spawned by web servers or Office applications (`WINWORD`, `EXCEL`, `w3wp.exe`, `httpd`). |
| `command_line_entropy`| Float | Shannon entropy of the command line string. High entropy ($> 4.6$) indicates base64 encoding or binary obfuscation. |
| `has_command_line` | Binary (0/1) | 1 if command line text is present. |
| `has_network_fields` | Binary (0/1) | 1 if IP and port network attributes are present. |
| `is_uncommon_dest_port`| Binary (0/1) | 1 if destination port is outside standard business traffic (80, 443, 53, 389, 445, 135, 88, 3389, 22). |
| `severity_numeric` | Integer $[0, 3]$ | Numeric mapping: Informational = 0, Warning = 1, Error = 2, Critical = 3. |
| `message_length` | Float | Natural log of message character length: $\ln(\text{len} + 1)$. |

#### Mathematical Formulations

* **Self-Referential Frequency Rarity**:
  $$R(v) = 1.0 - \frac{\text{Count}(v)}{N}$$
  Where $N$ is total events in the batch and $\text{Count}(v)$ is occurrences of attribute $v$. Values approaching $1.0$ indicate high uniqueness.

* **Shannon Entropy of Command Strings**:
  $$H(S) = -\sum_{i=1}^{k} P(c_i) \log_2 P(c_i)$$
  Where $P(c_i)$ represents the empirical probability of character $c_i$ appearing within command line string $S$.

* **Temporal Correlation Heuristics (Cross-Event)**:
  * *Burst Detection*: Flagged if $\ge 3$ failed logon attempts target the same user or source within the batch.
  * *Privilege Escalation Window*: Flagged if a newly created account (Event ID 4720) is added to the Administrators group (Event ID 4732) within a 15-minute sliding window ($\le 900$ seconds).

---

### 3.5 Machine Learning Anomaly Detection (Isolation Forest)

The anomaly detector (`app/ml/anomaly_detector.py`) identifies multi-dimensional outliers without requiring pre-labeled training data.

#### Isolation Forest Algorithm Mechanics
1. **Tree Ensembles**: Constructs $T = 200$ isolation trees (`n_estimators = 200`).
2. **Recursive Partitioning**: At each node of a tree, an attribute feature $q$ is chosen at random, and a split value $p$ is selected uniformly between the minimum and maximum values of $q$ in the subset.
3. **Path Length Principle**: Anomalous points possess attribute values substantially different from normal points. Consequently, they require fewer random splits to isolate into leaf nodes, resulting in a noticeably shorter tree path length $h(x)$.
4. **Scoring Function**:
   $$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$
   Where $E(h(x))$ is the average path length across all isolation trees, and $c(n)$ is the average path length of unsuccessful searches in a Binary Search Tree (BST) over $n$ samples:
   $$c(n) = 2 \ln(n - 1) + 0.5772156649\text{ (Euler's Constant)} - \frac{2(n - 1)}{n}$$

#### Score Normalization & Safeguards
* **Inversion**: Scikit-learn outputs `score_samples` where higher values indicate normality. The engine negates the raw output so that higher values correspond to greater anomaly severity:
  $$\text{raw} = - \text{score\_samples}(X)$$
* **Min-Max Scaling**: Normalizes raw scores to an intuitive forensic scale:
  $$\text{anomaly\_score} = \frac{\text{raw} - \min(\text{raw})}{\max(\text{raw}) - \min(\text{raw})}$$
* **Sample Size Protection**: Isolation Forest requires an adequate statistical baseline. If $n < 10$ events (`MIN_EVENTS_FOR_ML`), the ML model is bypassed, and all anomaly scores default to $0.0$, preventing artificial confidence on insufficient data.

---

### 3.6 Explainable Forensic Risk Scoring Engine

The scoring engine (`app/scoring/risk_scoring.py`) combines the statistical anomaly signal with deterministic detection rules.

#### Hybrid Scoring Formula
$$\text{Risk Score} = \min\left(100.0, \; \text{Anomaly Score} \times 40 + \sum_{j \in \text{Triggered Rules}} w_j\right)$$

* The unsupervised ML anomaly score can contribute up to **40 points**.
* Contextual detection rules contribute up to **60+ points**.
* If an event triggers no rules and displays no statistical anomaly, its score remains low (0–10). If an event is both statistically rare and triggers high-severity rules (e.g. privilege group modification with encoded PowerShell), its score reaches Critical severity (80–100).

#### Complete Rule Matrix & MITRE ATT&CK Mapping

| MITRE ATT&CK ID | Detection Rule Description | Weight ($w_j$) |
| :--- | :--- | :---: |
| **T1059** | Suspicious process tree: shell spawned by non-standard parent (Office / Web) | **+35** |
| **T1070.001** | Security audit log clearing attempt (Event ID 1102) | **+35** |
| **T1059.001** | Suspicious PowerShell execution (encoded / hidden-window flags) | **+30** |
| **T1218 / T1105** | Suspicious Living-off-the-Land Binary (LOLBin) execution | **+30** |
| **T1098** | User added to an administrator security group (SID `S-1-5-32-544`) | **+30** |
| **T1059.004** | Suspicious shell command (download-and-execute or reverse shell) | **+30** |
| **T1547.001** | Registry Run-key modification (`CurrentVersion\Run`) | **+25** |
| **T1078 / T1098** | Account created and granted admin rights within 15 minutes | **+25** |
| **T1548.003** | Linux `sudo` command denied (user not in sudoers) | **+25** |
| **T1027** | High command-line entropy ($H > 4.6$, base64 / obfuscated payload) | **+20** |
| **T1043** | Outbound connection to an uncommon destination port | **+20** |
| **T1136** | New user account created | **+20** |
| **T1110** | Repeated failed logons for same account/source (burst detected) | **+15** |
| **T1110.001** | Account lockout following repeated failed logons | **+15** |
| **T1078** | Failed logon event | **+10** |
| **T1110** | SSH login attempt for non-existent user | **+10** |
| — | Rare / unusual process for this environment (Rarity $> 0.85$) | **+12** |
| — | Rare event type relative to observed baseline (Rarity $> 0.90$) | **+6** |
| **T1078** | Activity occurred outside typical working hours (`is_off_hours = 1`) | **+5** |
| — | Elevated event log severity level (Error / Critical) | **+5** |

#### Severity Classification
$$\text{Risk Level} = \begin{cases} 
\text{LOW} & \text{if } \text{Risk Score} \le 30.0 \\ 
\text{MEDIUM} & \text{if } 30.0 < \text{Risk Score} \le 60.0 \\ 
\text{HIGH} & \text{if } 60.0 < \text{Risk Score} \le 80.0 \\ 
\text{CRITICAL} & \text{if } \text{Risk Score} > 80.0 
\end{cases}$$

---

### 3.7 Database Schema & Persistence

The relational database layer (`app/database.py`, `app/models.py`) utilizes SQLite with SQLAlchemy 2.0 ORM.

#### SQLite Concurrency Configuration
```python
@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")      # Write-Ahead Logging
    cursor.execute("PRAGMA synchronous=NORMAL")     # Optimal balance of durability & speed
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()
```

#### Database Schema: `events` Table

```sql
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_uid VARCHAR NOT NULL UNIQUE,
    data_origin VARCHAR NOT NULL,          -- 'OBSERVED' or 'SYNTHETIC_DEMO'
    operating_system VARCHAR,              -- 'Windows', 'macOS', 'Linux'
    timestamp VARCHAR NOT NULL,            -- ISO 8601 UTC
    event_id INTEGER,
    log_source VARCHAR NOT NULL,
    provider VARCHAR,
    level VARCHAR,
    computer VARCHAR,
    user VARCHAR,
    process_id INTEGER,
    message TEXT,
    parent_process VARCHAR,
    process_name VARCHAR,
    command_line TEXT,
    source_ip VARCHAR,
    destination_ip VARCHAR,
    source_port INTEGER,
    destination_port INTEGER,
    event_type VARCHAR NOT NULL,
    severity VARCHAR,
    raw_data TEXT NOT NULL,                -- Verbatim raw log
    features_json TEXT,                    -- JSON serialized feature dictionary
    anomaly_score FLOAT,                   -- 0.00 to 1.00
    risk_score FLOAT,                      -- 0.0 to 100.0
    risk_level VARCHAR,                    -- LOW, MEDIUM, HIGH, CRITICAL
    analysis_reasons TEXT,                 -- JSON array of trigger strings
    analyzed BOOLEAN NOT NULL DEFAULT 0,
    analyzed_at VARCHAR,
    batch_id VARCHAR,                      -- Unique ingest batch identifier
    evidence_hash VARCHAR,                 -- SHA-256 digest
    previous_hash VARCHAR                  -- Merkle chain pointer
);

-- Optimized Performance Indexes
CREATE INDEX ix_events_timestamp ON events (timestamp);
CREATE INDEX ix_events_risk_level ON events (risk_level);
CREATE INDEX ix_events_risk_score ON events (risk_score);
CREATE INDEX ix_events_data_origin ON events (data_origin);
CREATE INDEX ix_events_operating_system ON events (operating_system);
CREATE INDEX ix_events_batch_id ON events (batch_id);
```

---

### 3.8 REST API Specifications

The FastAPI service exposes an asynchronous REST API documented via Swagger UI at `/docs`.

| Endpoint | Method | Parameters | Description |
| :--- | :---: | :--- | :--- |
| `/health` | `GET` | None | Returns backend status, host OS identification, and live collection capability. |
| `/collect` | `POST` | `channels`, `max_events_per_channel`, `include_sysmon`, `last` | Triggers live collection of real host logs for current OS. Non-fatal permission errors returned in `warnings`. |
| `/collect/safe-incident` | `POST` | None | Staged test incident: creates temporary local account, tests failed logons, writes audit text, immediately cleans up, collects and analyzes logs. |
| `/demo/load` | `POST` | `num_normal_events` | Ingests synthetic multi-stage attack scenario tagged `SYNTHETIC_DEMO`. |
| `/analysis/run` | `POST` | `batch_id`, `rerun_all`, `os`, `data_origin` | Executes feature extraction, Isolation Forest model, and risk scoring over unanalyzed events within the requested scope. |
| `/events` | `GET` | `limit`, `offset`, `risk_level`, `os`, `data_origin` | Paginated listing of all normalized log events. |
| `/events/suspicious` | `GET` | `min_risk_level`, `limit`, `os`, `data_origin` | Ranked list of suspicious events ($Score \ge Threshold$), ordered by risk severity then recency. |
| `/events/{id}` | `GET` | `id` (Row ID) | Returns detailed event metadata including unmutated `raw_data`, feature breakdown, and cryptographic hashes. |
| `/timeline` | `GET` | `limit`, `batch_id`, `os`, `data_origin` | Chronological event stream with severity markers for timeline rendering. |
| `/stats` | `GET` | `os`, `data_origin` | Aggregated metrics: total, analyzed, pending, suspicious count, risk distribution, and OS breakdowns. |
| `/forensics/verify` | `GET` | `limit` (default 5,000) | Cryptographic Chain-of-Custody verification. Validates SHA-256 payload integrity and hash-chain continuity. |

---

### 3.9 Frontend Architecture & Component Design

The investigator dashboard is built with **React 19** and **Vite**, structured around a specialized dark forensic console palette.

#### Design System Tokens (`frontend/src/styles/tokens.css`)
* **Case-Room Navy Surfaces**: `--bg-app: #0d141d`, `--bg-panel: #141d29`, `--bg-panel-raised: #1b2635`.
* **UV Evidence Light Accent**: `--accent: #57c7d4`, `--accent-soft: rgba(87, 199, 212, 0.12)`.
* **Functional Heat Scale**:
  * Low Risk: `#4fb58a` (Emerald Green)
  * Medium Risk: `#e0a43a` (Amber Yellow)
  * High Risk: `#e8743b` (Orange)
  * Critical Risk: `#e5484d` (Crimson Red)
* **Typography**: Proportional `IBM Plex Sans` for UI labels, `IBM Plex Sans Condensed` for high-density headers, and `IBM Plex Mono` for machine data (timestamps, hashes, command lines).

#### Key Frontend Components

1. **`Header.jsx`**:
   * Displays live machine detection (`Windows`, `macOS`, `Linux`) and collector readiness.
   * Action triggers for live collection, safe incident simulation, demo loading, and analysis.
   * Direct triggers for **Audit Integrity** modal and **Export Dossier** reporting.

2. **`OverviewCards.jsx`**:
   * Real-time metrics counters (Total Events, Awaiting Analysis, Suspicious Events, High Risk, Critical).
   * Visual risk distribution bar showing relative proportions of analyzed severity levels.

3. **`Timeline.jsx`**:
   * **Seismograph Amplitude Encoding**: Bar heights reflect risk score magnitude (10–100%), and horizontal placement reflects real elapsed time.
   * **Drag-to-Select Time Scrubbing**: Users click and drag across the track to isolate an attack spike. The active time slice is visually highlighted with a cyan boundary, dims events outside the window, and filters the table below.

4. **`SuspiciousTable.jsx`**:
   * Multi-column interactive sorting by Risk Score, Timestamp, Event Type, and Anomaly Score.
   * Rapid triage keyboard navigation: <kbd>↑</kbd> / <kbd>↓</kbd> or <kbd>j</kbd> / <kbd>k</kbd> steps through rows and opens the detail panel.
   * MITRE ATT&CK tactic badges displayed inline.
   * Clearable search filter with active query indicators.

5. **`EventDetailPanel.jsx`**:
   * Circular risk score gauge alongside the ML anomaly score.
   * **Score Composition Bar**: Visual segment breakdown illustrating how much of the score derived from the ML Isolation Forest versus heuristic detection rules.
   * **One-Click Entity Pivoting**: Interactive crosshair buttons beside `User`, `Host`, `Process`, and `IPs` instantly populate the search filter to display all correlated activity.
   * Collapsible sections for extracted ML features, SHA-256 evidence hashes, and formatted raw records.

6. **`IntegrityModal.jsx`**:
   * Direct integration with `/forensics/verify`.
   * Displays verified status, unbroken chain guarantees, and discrepancy reporting.
   * **Copy Forensic Certificate**: Generates a court-admissible RFC 3161 proof stamp formatted for legal attachments.

7. **`ReportModal.jsx`**:
   * Compiles an executive-grade Forensic Case Dossier.
   * Automatic IOC (Indicators of Compromise) extraction: accounts, binaries, and network endpoints observed during the incident.
   * **Download JSON**: Exports structured incident data for SIEM/SOAR ingestion.
   * **Print / PDF**: Dedicated `@media print` styling formatting the report for print or PDF archiving.

---

## 4. Verification & Test Suite

The system includes test coverage verifying functionality from OS log collection to ML scoring:

* **Test Framework**: `pytest` with `pytest-asyncio` and `httpx`.
* **Test Modules**:
  * `tests/test_normalizer.py`: Tests schema mapping across Windows Event IDs (4624, 4625, 4720, 4732, 7045, Sysmon) and Linux syslog inputs.
  * `tests/test_feature_extraction.py`: Verifies calculation of frequency rarity, Shannon entropy, LOLBins, and temporal burst detection.
  * `tests/test_ml_scoring.py`: Tests Isolation Forest fitting, min-max score normalization, and minimum sample size fallbacks.
  * `tests/test_risk_scoring.py`: Validates risk point arithmetic, MITRE ATT&CK rule execution, and classification thresholds.
  * `tests/test_pipeline.py`: End-to-end ingest, database persistence, and cryptographic chain-of-custody verification.
  * `tests/test_api.py`: Validates FastAPI routes, query parameter filtering, and error handling.
  * `tests/test_linux_collector.py`: Validates Linux journalctl parsing and auth.log regex matching.
  * `tests/test_safe_incident.py`: Validates execution and cleanup of safe incident scripts.

---

## 5. Project Directory Reference

```
AI_DataLog_Forensics/
├── README.md                      # Quickstart and usage guide
├── TECHNICAL_DOCUMENTATION.md     # Complete technical specifications (this document)
├── start-backend.ps1              # Windows elevated backend launcher
├── start-backend.sh               # Unix sudo backend launcher
├── start-frontend.ps1             # Frontend dev launcher
│
├── backend/
│   ├── requirements.txt           # Production Python dependencies
│   ├── requirements-dev.txt       # Testing dependencies (pytest, httpx)
│   ├── run_demo.py                # Standalone CLI demo runner
│   │
│   ├── app/
│   │   ├── main.py                # FastAPI app initialization, CORS, and REST routes
│   │   ├── database.py            # SQLite engine, connection pragmas, and session maker
│   │   ├── models.py              # SQLAlchemy ORM Event table definition
│   │   ├── schemas.py             # Canonical NormalizedEvent dataclass & Enums
│   │   ├── pipeline.py            # Orchestrator: ingest, crypto hashing, analysis, audit
│   │   ├── filtering.py           # Multi-dimensional OS, data origin, and batch filters
│   │   │
│   │   ├── collector/             # Native log collectors
│   │   │   ├── windows_collector.py  # pywin32 Windows Event Log reader
│   │   │   ├── macos_collector.py    # Apple Unified Log runner (/usr/bin/log)
│   │   │   └── linux_collector.py    # systemd journalctl & /var/log reader
│   │   │
│   │   ├── normalizer/            # Log schema normalizer
│   │   │   └── normalize.py          # Transforms raw records to NormalizedEvent
│   │   │
│   │   ├── features/              # Feature engineering
│   │   │   └── feature_extraction.py # 18-feature extraction matrix & entropy logic
│   │   │
│   │   ├── ml/                    # Machine Learning anomaly detection
│   │   │   └── anomaly_detector.py   # Scikit-learn Isolation Forest wrapper
│   │   │
│   │   ├── scoring/               # Forensic risk scoring
│   │   │   └── risk_scoring.py       # Rule engine, MITRE mapping, and hybrid scoring
│   │   │
│   │   ├── demo/                  # Synthetic attack data generator
│   │   │   └── synthetic_data.py     # Deterministic multi-stage incident scenarios
│   │   │
│   │   └── safe_incident/         # Harmless real incident simulator
│   │       ├── runner.py             # Safe incident dispatcher
│   │       ├── windows.py            # Ephemeral local user & admin group simulator
│   │       ├── macos.py              # macOS test incident script
│   │       └── linux.py              # Linux test incident script
│   │
│   └── tests/                     # Test automation suite (83 test cases)
│
└── frontend/
    ├── package.json               # Node.js dependencies (React 19, Vite, Oxlint)
    ├── vite.config.js             # Dev-server proxy configuration (/api -> :8000)
    ├── index.html                 # Single-page application root HTML
    │
    └── src/
        ├── App.jsx                # Application shell, state coordinator, modal wiring
        ├── App.css                # Layout grids, responsive shells
        ├── api.js                 # Fetch wrapper for FastAPI endpoints
        ├── format.js              # Datetime, axis, and numeric formatting helpers
        ├── dataSources.js         # Evidence scope definitions and host OS mapping
        │
        ├── styles/
        │   └── tokens.css         # Design system tokens (colors, typography, spacing)
        │
        └── components/
            ├── Header.jsx         # Navigation, host status, collection controls
            ├── Header.css
            ├── OverviewCards.jsx  # Summary metrics & segmented risk distribution
            ├── OverviewCards.css
            ├── Timeline.jsx       # Incident trace with drag-to-select range scrubbing
            ├── Timeline.css
            ├── SuspiciousTable.jsx# Sortable event table with keyboard triage & MITRE tags
            ├── SuspiciousTable.css
            ├── EventDetailPanel.jsx # Deep inspection, pivoting, and score breakdown
            ├── EventDetailPanel.css
            ├── IntegrityModal.jsx # Cryptographic chain-of-custody verification modal
            ├── IntegrityModal.css
            ├── ReportModal.jsx    # Forensic case dossier generator (PDF / JSON)
            ├── ReportModal.css
            ├── DataSourceSelector.jsx # Evidence scope tab switcher
            ├── DataSourceSelector.css
            ├── WorkflowSteps.jsx  # Investigation phase progression indicator
            ├── WorkflowSteps.css
            ├── RiskBadge.jsx      # Severity pills and evidence origin tags
            ├── RiskBadge.css
            ├── Notices.jsx        # Notification alert banners
            ├── Notices.css
            ├── EmptyState.jsx     # Zero-data guidance screens
            ├── EmptyState.css
            └── Icon.jsx           # Inline SVG icon library
