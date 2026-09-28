# ShieldNet Daemon: Engineering Execution Report (Tasks 1 to 4)
**Autonomous Offline Network Threat Detection & Verifiable Cryptographic Action Ledger**  
*System Architecture, Milestone Implementation Details, and Operational Guide*

---

## 1. Executive Summary

ShieldNet is a low-latency, 100% offline, air-gapped autonomous network threat detection engine and cryptographic action ledger designed for zero-trust environments. Operating entirely without cloud dependencies, external CDNs, or runtime internet access, ShieldNet continuously captures network traffic, extracts canonical 84-dimensional flow representations, projects latent future system states via an autoregressive $K=5$ neural world model, gates detections through an ensemble confidence gate, attributes threat drivers using a continuous SHAP KernelExplainer, and commits tamper-evident alerts to a SHA-256 hash-chained SQLite ledger.

Across **Tasks 1 through 4**, the ShieldNet daemon underwent comprehensive hardening, algorithmic refinement, privacy-preserving threat intelligence extensions, and operational interface polish:

| Task | Scope & Objective | Primary Deliverables | Status |
| :--- | :--- | :--- | :---: |
| **Task 1** | **$K$-Step Forward Alerting Logic** | Confidence gate scans all $K=5$ predicted steps; triggers on earliest threshold crossing; assigns forward class, MITRE tactic, and severity. | **VERIFIED** |
| **Task 2** | **Production Terminal Ergonomics & Minimal Telemetry** | Gated continuous 84-dim vectors behind `--verbose`/`--debug`; added rotating log file and periodic single-line telemetry status display. | **VERIFIED** |
| **Task 3** | **Zero-IP Verifiable Ledger & Tier 2 Corroboration** | Zero-IP privacy invariant; verifiable signature export/import; continuous 84-dim SHAP cosine similarity cross-node corroboration ($+15\%$ max boost); benign traffic immunity. | **VERIFIED** |
| **Task 4** | **Row-Capped Ledger & $K=5$ Trajectory Dashboard** | Row-capping with rolling checkpoint anchor hashing; post-pruning cryptographic verification; decoupled dashboard with visible $K=5$ forward trajectory radar and trigger horizon badges. | **VERIFIED** |

**Repository Test Status:** **77 / 77 automated tests passing (100% pass rate)**.

---

## 2. Comprehensive Breakdown of Completed Tasks

### Task 1: $K$-Step Forward Threat Alerting Logic

#### The Problem
The neural world model generates both an immediate single-step prediction ($t+1$) and an autoregressive latent rollout across $K=5$ future timesteps ($t+1, t+2, t+3, t+4, t+5$). Previously:
1. The confidence gate only scanned a subset of rollout timesteps or relied solely on immediate step-1 metrics.
2. Detections failed to record *which* forward step triggered the alert.
3. If an attack emerged at $t+3$ or $t+5$ while $t+1$ remained benign, the alert could be suppressed or misclassified with step-1 baseline labels.

#### Architectural Implementation
- **Full Horizon Scan:** Updated `ConfidenceGate.evaluate_window()` in `engine/confidence_gate.py` to evaluate immediate step $t+1$, and if nominal, sequentially scan steps $t+2$ through $t+K$ ($K=5$).
- **Earliest Crossing Selection:** The earliest step $k \in [1, 5]$ that crosses `threat_threshold` (default $0.80$) is selected as the alert trigger:
  - `triggering_step`: Integer index ($1$ to $5$).
  - `triggering_step_ahead`: Formatted identifier (`t+1`, `t+2`, `t+3`, `t+4`, `t+5`).
- **Dynamic Attribute Override:** When triggered by a forward step $k > 1$, the alert's effective threat probability, predicted attack class, and MITRE ATT&CK tactic/stage are inherited from step $k$, not suppressed by step $1$.
- **Severity Mapping:**
  - `CRITICAL`: Threat probability $\ge 0.95$ and MITRE stage $\ge 4$.
  - `HIGH`: Threat probability $\ge 0.85$ or MITRE stage $\ge 4$.
  - `MEDIUM`: Threat probability $\ge 0.50$ or MITRE stage $\ge 2$.
  - `LOW`: Other flagged conditions.
  - `CLEAN`: Unflagged benign traffic.
- **Benign Invariant Guard:** Forward steps predicted explicitly as `BENIGN` or at MITRE Stage 0 (Normal Operations) while current traffic is benign are bypassed to prevent false-positive forward triggers.

---

### Task 2: Production Terminal Ergonomics & Minimal Telemetry Display

#### The Problem
During foreground execution (`shieldnet daemon run`), the terminal output was flooded with raw continuous 84-dimensional feature arrays, temporal sequence matrices $(3, 84)$, and verbose Npcap diagnostic messages. Operators in production or SOC environments could not monitor high-level system telemetry without console scrolling and terminal buffer exhaustion.

#### Architectural Implementation
- **Verbosity Flags in CLI & Windows Service:** Added `--verbose` (`-v`) and `--debug` flags to `shieldnet daemon run` in `cli.py` and `windows_service.py run`.
- **Dual Logging Topology:**
  - *Default Mode (Standard Run):* Console log level is set to `logging.WARNING`. Initialization info and packet diagnostics are routed exclusively to the rotating log file (`data/shieldnet_daemon.log`, max 5 MB, 3 backups).
  - *Verbose Mode (`--verbose` / `--debug`):* Console log level is set to `logging.DEBUG`. Emits full feature matrices, SHAP attribution vectors, and per-flow calculations.
- **Periodic Minimal Telemetry Heartbeat:** In blocking foreground mode (`daemon.start(block=True)`), the main thread prints a single, concise status line every 3 seconds:
  ```text
  [17:20:15] [STATUS] State: RUNNING (LIVE_SNIFFING) | Pkts: 4520 | Flows: 14 | Alerts: 3 | Threat Confidence: 0.12 (Nominal)
  ```
  If threat confidence crosses threshold:
  ```text
  [17:21:04] [STATUS] State: RUNNING (LIVE_SNIFFING) | Pkts: 5120 | Flows: 18 | Alerts: 4 | Threat Confidence: 0.96 (FLAGGED (DDoS))
  ```
- **Telemetry Query API:** Added `daemon.get_telemetry_summary()` exposing structured metrics (`state`, `packets`, `flows`, `alerts`, `threat_prob`, `threat_level`, `last_alert`).

---

### Task 3: Verifiable Action Ledger (Zero-IP Privacy) & Tier 2 Cross-Node Threat Corroboration

#### The Problem
In distributed enterprise deployments, nodes must share emerging threat intelligence signatures without leaking sensitive network topology, hostnames, or user identity. Furthermore, local nodes receiving peer signatures must not bypass local model inference or generate false alerts on benign traffic.

#### Architectural Implementation
- **Zero-IP Threat Signature Schema (`engine/corroboration.py`):**
  - Designed `PeerThreatSignature` encapsulating: `signature_id`, `origin_node_id`, `timestamp`, `prediction`, `threat_probability`, `mitre_stage`, `mitre_tactic`, 84-dim continuous `shap_vector`, `top_drivers`, `prev_hash`, and `record_hash`.
  - **Strict Privacy Invariant:** Keys containing network identifiers (`src_ip`, `dst_ip`, `ip`, `mac`, `hostname`, `username`, `user`, `host`) are strictly forbidden. If any forbidden key is detected during signature export or deserialization, a `ValueError: Privacy violation` is raised immediately.
- **Mathematical Corroboration via SHAP Cosine Similarity:**
  - Local node detection computes continuous 84-dimensional SHAP vector $\mathbf{s}_{\text{local}}$.
  - Computes cosine similarity against imported peer signatures $\mathbf{s}_{\text{peer}}$:
    $$\text{CosineSim}(\mathbf{s}_{\text{local}}, \mathbf{s}_{\text{peer}}) = \frac{\mathbf{s}_{\text{local}} \cdot \mathbf{s}_{\text{peer}}}{\|\mathbf{s}_{\text{local}}\|_2 \|\mathbf{s}_{\text{peer}}\|_2}$$
  - Guarded against zero-magnitude division and dimension mismatch.
- **Local Inference Immunity Invariant:**
  - Local inference is **never skipped**.
  - If local traffic is benign ($P(\text{threat}) < 0.40$ or class is `BENIGN`), peer signatures have **zero effect**; no false positives can be induced by external signatures.
  - If local traffic exhibits an elevated threat profile matching a peer signature ($\text{CosineSim} \ge \tau = 0.75$), an additive confidence boost is applied:
    $$P_{\text{final}} = \min\left(0.9999, P_{\text{local}} + \min(\Delta p_{\max}, (\text{CosineSim} - \tau) \cdot 0.30)\right)$$
    where $\Delta p_{\max} = 0.15$.
- **CLI Management Subcommands:**
  - `python cli.py peer export --record-id <ID> [--out <FILE>]`: Exports zero-IP signed threat signature.
  - `python cli.py peer verify --file <FILE>`: Cryptographically audits peer signature payloads offline.
- **Driver Resilience Discovery:** In `shared/feature_extractor.py`, optimized `parse_scapy_packet` to inspect packet layers using string names (`pkt.haslayer("IP")`), completely eliminating unnecessary Npcap DLL/UAC helper prompts during test execution and non-admin runs.

---

### Task 4: Proper SQLite Persistence (Row-Capping & Rolling Checkpoint) & Decoupled Dashboard

#### The Problem
1. **Unbounded Storage Growth:** The SQLite Action Ledger lacked row ceilings, risking disk exhaustion in high-throughput environments.
2. **Broken Cryptographic Chains:** Naive deletion of older blocks invalidates SHA-256 hash chains, because block 1 points to the Genesis digest (`0*64`).
3. **Hidden Rollout Trajectory:** The monitoring dashboard had no visualization for the autoregressive $K=5$ forecast trajectory.

#### Architectural Implementation
1. **Row-Capping with Rolling Checkpoint Anchoring (`engine/ledger.py`):**
   - Configurable `max_records` (default `10,000` rows) stored in a `ledger_metadata` table.
   - When table row count exceeds `max_records`, `prune_records(keep_count)`:
     1. Identifies the oldest record to be retained.
     2. Persists its `prev_hash` as the rolling `checkpoint_anchor_hash` in `ledger_metadata`.
     3. Deletes records older than the retained window.
     4. Runs `PRAGMA wal_checkpoint(PASSIVE)` to reclaim space without write-lock contention.
   - **Verification Continuity:** `verify_integrity()` dynamically starts validation from `checkpoint_anchor_hash` if pruned, verifying all subsequent blocks and cryptographic payloads. Tamper detection remains 100% effective.
2. **Daemon Status & Forecast Exposure (`daemon/service.py`):**
   - Daemon formats the full $K=5$ step forecast trajectory (`step`, `step_ahead`, `threat_probability`, `predicted_class`, `mitre_stage`, `mitre_tactic`, `is_trigger`).
   - Persists `k_step_forecast` into `latest_forecast`, `last_alert`, and `shap_summary_json` committed to the ledger.
3. **Decoupled Dashboard REST APIs (`dashboard/app.py`):**
   - `GET /api/status`: Includes `latest_forecast`.
   - `GET /api/ledger`: Includes `triggering_step`, `triggering_step_ahead`, and `k_step_forecast`.
   - `GET /api/ledger/record/<id>`: Returns full record detail, top 12 SHAP drivers, $K=5$ forecast timeline, and Tier 2 Corroboration metadata.
   - `GET /api/stats`: Returns `ledger_capacity` (`max_records`, `total_records`, `pruned_records`, `retention_policy`).
4. **Cybersecurity Dashboard Visualizer (`dashboard/templates/index.html`):**
   - **Autoregressive $K=5$ Threat Trajectory Radar:** Interactive cards for timesteps $t+1$ through $t+5$ displaying threat probabilities, progress bars, attack classifications, and pulsing `TRIGGER` highlights.
   - **Trigger Horizon Badges:** Action Ledger table displays `IMMEDIATE t+1` vs `LOOKAHEAD t+X` badges for rapid horizon triage.
   - **Cryptographic Proof Box:** Displays Genesis/Rolling Checkpoint Anchor, retained record count, retention policy ceiling, and pruned block count.
   - **Detailed Inspection Modal:** Renders the full 5-step forecast trajectory alongside continuous 84-dimensional SHAP drivers and Tier 2 peer corroboration proofs.

---

## 3. Application Execution Instructions

### Prerequisites

1. **Python Environment:** Python 3.10, 3.11, 3.12, or 3.13 (64-bit).
2. **Packet Capture Driver (Windows Live Mode only):**
   - [Npcap](https://npcap.com/) installed with default options.
   - For live packet capture from physical network interfaces, PowerShell or Command Prompt should be run as **Administrator**.
   - For simulated/demo mode (`--mock`), administrator privileges are **not required**.

---

### Step 1: Activate Virtual Environment

Always activate the project virtual environment before running CLI commands:

**Windows PowerShell:**
```powershell
cd d:\sih-backend\shieldnet_daemon
.\.venv\Scripts\Activate.ps1
```

**Windows Command Prompt (cmd.exe):**
```cmd
cd /d d:\sih-backend\shieldnet_daemon
.\.venv\Scripts\activate.bat
```

> **Important Windows PowerShell Note:**  
> On Windows PowerShell, `.py` files cannot be executed directly by typing `cli.py` or `./cli.py`. You must always prefix the command with `python`, for example:  
> `python cli.py daemon run --mock`

---

### Step 2: System Health & Security Posture Audit (`doctor`)

Run the automated doctor diagnostic to verify Python environment, kernel driver access, model asset integrity, and ledger health:

```powershell
python cli.py doctor
```

*Expected Output:*
```text
============================================================
       SHIELDNET SYSTEM & SECURITY POSTURE AUDIT            
============================================================
 [1/5] Host Environment
   Platform:           Windows 11 (AMD64)
   Python Version:     3.13.5
   Process Admin:      [YES/NO]

 [2/5] Kernel Sniffer & Npcap Driver Security
   Driver Status:      [PASS] Npcap installed & AdminOnly=1 enforced

 [3/5] Cryptographic Neural Asset & Checkpoint Integrity
   Model Weights:      [PASS] All ONNX & scaler parameters cryptographically verified

 [4/5] Action Ledger Cryptographic Hash-Chain
   Hash-Chain Status:  [PASS] Verified blocks intact against genesis

 [5/5] Attack Surface & Isolation Posture
   IPC Simulation:     DISABLED BY DEFAULT (Production Safe)
   Dashboard Binding:  Strictly 127.0.0.1 (Loopback-only, DNS Rebinding Protected)
   Data Directory:     data
============================================================
```

---

### Step 3: Running the Background Detection Daemon

The daemon captures traffic, processes rolling flow windows, runs ONNX inference + confidence gating, and writes alerts to the ledger.

#### Option A: Demo / Simulation Mode (Recommended for testing without Admin rights)
Does not require physical NIC binding or administrator privileges:

```powershell
python cli.py daemon run --mock
```

#### Option B: Live Sniffing Mode (Production / SOC monitoring)
Captures real-time packets from your active physical network adapter (requires Administrator privileges):

```powershell
# 1. Identify network adapter name in PowerShell
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status

# 2. Run daemon bound to your active adapter (e.g., Wi-Fi or Ethernet)
python cli.py daemon run --interface "Wi-Fi"
```

#### Option C: Verbose Debug Mode
To inspect real-time 84-dimensional feature vectors, sequence matrices, and SHAP attribution arrays:

```powershell
python cli.py daemon run --mock --verbose
```

#### Checking Daemon Status & Stopping
In a separate terminal window:

```powershell
# Check live heartbeat telemetry
python cli.py daemon status

# Gracefully stop background daemon
python cli.py daemon stop
```

---

### Step 4: Launching the Decoupled Monitoring Dashboard

The monitoring dashboard runs completely decoupled from the daemon. It reads the Action Ledger in non-blocking WAL mode and monitors the daemon's status file.

```powershell
python cli.py dashboard --port 8080
```

1. Open your web browser and navigate to:  
   **`http://127.0.0.1:8080`**
2. The dashboard interface displays:
   - **System KPI Cards:** Daemon state, uptime, RAM, NIC flow counters, alert rates, and chain validity.
   - **$K=5$ Forward Threat Trajectory Radar:** Continuous lookahead cards for $t+1$ through $t+5$ with dynamic threat probabilities and trigger badges.
   - **Attack & MITRE Breakdown:** Real-time distribution of attack classifications and tactic stages.
   - **Cryptographic Proof Box:** Genesis / rolling anchor hash, retained blocks, retention limit, and pruned count.
   - **Action Ledger Table:** Real-time alert feed with `Trigger Horizon` indicators (`IMMEDIATE t+1` vs `LOOKAHEAD t+X`).
   - **Deep Event Inspection Modal:** Click **Inspect** on any alert to view the full 5-step forecast timeline, Tier 2 corroboration proof, and continuous 84-dimensional SHAP driver rankings.
   - **Interactive Audit Button:** Click **Audit Chain** to execute an on-demand cryptographic verification of the SHA-256 hash-chain.

---

### Step 5: Generating Synthetic Attack Traffic (`simulate`)

While the daemon is running, you can inject synthetic multi-stage attack scenarios to observe confidence gating, SHAP explanations, and dashboard alerting:

```powershell
# Simulate a DDoS SYN Flood attack scenario
python cli.py simulate --scenario ddos --count 200 --delay 0.01

# Simulate a PortScan reconnaissance attack
python cli.py simulate --scenario portscan --count 150 --delay 0.02

# Simulate Botnet C2 traffic
python cli.py simulate --scenario botnet --count 100 --delay 0.05

# Simulate benign baseline browsing traffic
python cli.py simulate --scenario benign --count 300 --delay 0.01
```

---

### Step 6: Verifying Cryptographic Action Ledger Integrity (`audit`)

Perform an offline cryptographic audit of all blocks in the ledger:

```powershell
python cli.py audit
```

*Expected Output:*
```text
============================================================
      SHIELDNET CRYPTOGRAPHIC ACTION LEDGER AUDIT
============================================================
 Database:             data/ledger.db
 Total Blocks:         276
 Verified Blocks:      276
 Genesis Anchor:       0000000000000000000000000000000000000000000000000000000000000000
 Latest Tip Hash:      db561f89b85558f4d003965f70d683587661f85dfecfd6f9ec964cfb20b0c675
 Chain Status:         [VERIFIED INTACT]
============================================================
```

---

### Step 7: Tier 2 Cross-Node Threat Signature Sharing (`peer`)

Export zero-IP threat signatures from your ledger to share with peer ShieldNet nodes, or verify incoming signatures:

```powershell
# Export signature for ledger record #1 (Zero-IP guaranteed)
python cli.py peer export --record-id 1 --out data/threat_sig_1.json

# Cryptographically verify the exported signature offline
python cli.py peer verify --file data/threat_sig_1.json
```

---

### Step 8: Running Automated Test Suites

Run the full automated test suite covering all modules:

```powershell
# Run the entire test suite (77 tests)
python -m pytest -q

# Run specific module test suites
python -m pytest tests/test_confidence_gate.py -v
python -m pytest tests/test_corroboration.py -v
python -m pytest tests/test_action_ledger.py -v
python -m pytest tests/test_dashboard.py -v
```

---

## 4. Verification Matrix

| Subsystem / Test Suite | Test Count | Result | Key Verified Capabilities |
| :--- | :---: | :---: | :--- |
| `tests/test_confidence_gate.py` | 8 | **PASSED** | Early forward alerting, $K=5$ threshold scanning, benign invariance, dynamic severity assignment. |
| `tests/test_corroboration.py` | 7 | **PASSED** | Zero-IP privacy invariant, cosine similarity math, local inference immunity on benign traffic, peer confidence boosting, tamper detection. |
| `tests/test_action_ledger.py` | 9 | **PASSED** | Row-capping, rolling checkpoint anchoring, post-pruning cryptographic verification, WAL concurrency, tamper detection. |
| `tests/test_dashboard.py` | 9 | **PASSED** | Decoupled HTTP server, $K=5$ forecast endpoints, ledger capacity stats, SPA template delivery, read-only WAL concurrency. |
| `tests/test_daemon_service.py` | 9 | **PASSED** | Headless pipeline, status heartbeat generation, verbose gating, graceful queue draining, simulated attack detection. |
| `tests/test_feature_extractor.py` | 5 | **PASSED** | 84-dimensional feature extraction, BPF parsing resilience, zero-division safety. |
| `tests/test_shap_explainer.py` | 5 | **PASSED** | Gated SHAP explainability, top feature attribution drivers, background baseline caching. |
| `tests/test_packaging.py` | 5 | **PASSED** | CLI argument parsing, peer export/verify subcommands, doctor audit execution. |
| `tests/test_security_integrity.py` | 8 | **PASSED** | SHA-256 model asset verification, tampered weight detection, manifest verification. |
| `tests/test_dashboard_security.py` | 6 | **PASSED** | DNS rebinding defense, Host header validation, CORS loopback restriction, security headers. |
| `tests/test_buffer_dos_resilience.py` | 2 | **PASSED** | Inactive flow eviction timeout, queue overflow resilience under high packet load. |
| `tests/test_ipc_bridge.py` | 4 | **PASSED** | Loopback simulation bridge, provenance tagging, production mode isolation. |
| **Total Automated Tests** | **77** | **ALL PASSED** | **100% Pass Rate across the complete ShieldNet codebase.** |

---

## 5. Architectural Summary & Security Guarantees

1. **Air-Gap Compliance:** Zero internet connection, zero cloud telemetry, zero remote DNS dependencies.
2. **Mathematical Trust Chain:** Every threat logged to `data/ledger.db` is sealed with SHA-256 hash-chaining. Row-capping maintains complete integrity proofs through rolling checkpoint hashes stored in `ledger_metadata`.
3. **Zero-IP Privacy Guarantee:** Threat intelligence shared across enterprise boundaries contains continuous 84-dimensional mathematical attribution vectors with zero IP addresses, MAC addresses, hostnames, or credentials.
4. **Local Inference Primacy:** External peer signatures can never force false alerts or override local inference on benign traffic.
5. **Decoupled Architecture:** The monitoring dashboard and CLI tools read runtime status and SQLite storage concurrently via read-only WAL mode without interfering with daemon detection loops.
