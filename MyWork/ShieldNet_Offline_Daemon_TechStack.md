# ShieldNet — Offline Background Product: Tech Stack & Build Flow
**Addendum to: ShieldNet_NextPhase_Report.md**
**Topic: Running the detection engine as a continuous, headless, offline background process**

---

## 0. Context

This addendum covers how ShieldNet's core detection logic (already correct — GRU+Attention, K=5 rollout, SHAP, confidence-gated ensemble) gets turned into an actual **product**: a background daemon that scans ports/traffic continuously on a live system, fully offline, with no terminal window or always-open dashboard required.

Key design principle carried through every layer: **the detection core never depends on a UI being open, and never requires network access.** Any future connectivity (e.g. the blockchain node-sync work from the previous addendum) is a bolt-on that reads finished records after the fact — it never sits inside the live detection path.

---

## 1. Pipeline Overview (Seven Stages)

```
Packet capture
      ↓
Feature extraction
      ↓
Model inference
      ↓
Confidence gate
      ↓
SHAP explain (only if flagged)
      ↓
Action ledger
      ↓
Local dashboard (reads on demand, separate process)
```

Nothing above requires network access. The dashboard is intentionally decoupled — it's a separate process that only reads from storage when a human opens it; the daemon's detect → infer → log loop runs regardless of whether anyone is looking at it.

---

## 2. Tech Stack by Layer

### 2.1 Packet capture
- **Driver:** Npcap (Windows) / libpcap (Linux) — OS-level capture layer.
- **Wrapper:** Scapy or PyShark in Python (fine for hackathon timeline).
- **Known optimization path (mention, don't necessarily build):** pure-Python parsing gets CPU-heavy on a busy interface. `dpkt` is a lower-level, faster parser — a legitimate answer if asked "how would this scale on a busier network?"

### 2.2 Feature extraction
- Must reproduce, in real time, the **same two feature sets used in training**: flow-level (IAT stats, TCP flags, bytes/packet counts) and packet-level (TTL variance, window size, fragment flags).
- Implementation: rolling time-window buffer per active flow key (e.g. a `deque` per flow), aggregates computed when the window closes. NumPy/Pandas for the math.
- **Critical practice:** keep this feature-computation logic in **one shared module**, imported by both the training pipeline and the live daemon — never reimplemented twice. A live/train feature mismatch silently breaks model accuracy and is hard to debug later.

### 2.3 Model inference
- Trained in PyTorch, but **exported to ONNX and run via ONNX Runtime (CPU)** for the live daemon.
- Reason: ONNX Runtime is lighter and faster for repeated small-batch inference on modest hardware than keeping the full PyTorch runtime loaded — this is what makes "runs continuously on a laptop-class machine" a credible claim rather than an aspiration.
- K=5 forward rollout happens here, producing the infiltration-probability time series and predicted MITRE ATT&CK stage.

### 2.4 Confidence gate
- Plain Python logic: compare World Model confidence against threshold, blend with Logistic Regression baseline score per the existing gated-ensemble design.
- Cheap, no special library needed.

### 2.5 SHAP explain
- **Important engineering constraint, not just a library choice:** SHAP's `DeepExplainer` (needed for a GRU) is too slow to run on every single time window if real-time behavior matters.
- **Fix is architectural:** only invoke SHAP when the confidence gate actually flags something. Most windows are benign and skip explanation entirely; only rare flagged windows pay the SHAP cost.
- **Worth stating explicitly in the architecture doc** — "why not explain every prediction?" is a fair judge question, and this cost-vs-value tradeoff is the honest, defensible answer (not a shortcut being hidden).

### 2.6 Action ledger
- **SQLite**, not a server-based DB. Single file, zero setup, embedded — fits the "offline, no dependencies" story exactly.
- One table: `{prediction, mitre_stage, shap_summary, timestamp, prev_hash, record_hash}`.
- Hash computed with Python's built-in `hashlib.sha256` over the previous record's serialized bytes.
- **No blockchain library needed for Tier 1** — it is genuinely just a hash-chain, and it's correct and honest to call it exactly that (see prior addendum re: not overclaiming "blockchain").

### 2.7 Background daemon mechanics
This is what turns "a script" into "a product":
- **Linux:** a `systemd` unit file (`shieldnet.service`) — starts on boot, restarts on crash.
- **Windows:** a Windows Service, via `pywin32` or the `NSSM` wrapper around the Python script — runs without a terminal window open, survives logoff, appears in Task Manager/Services like any normal background application.

### 2.8 Dashboard
- Streamlit or Flask, but **decoupled from the daemon** — a separate process that reads the SQLite ledger only when opened.
- Deliberate design choice: the daemon's job (detect, infer, log) never depends on whether a dashboard is open. This is the correct story for "runs in the background."

### 2.9 Packaging for demo portability
- `PyInstaller` to bundle the daemon into a single executable — judges can double-click it rather than needing a live Python environment set up during the demo.

---

## 3. Build Flow Summary

Sniffer feeds packets continuously → windowed feature extraction (flow + packet level, matching training features exactly via the shared module) → ONNX inference (GRU+Attention, K=5 rollout) → confidence gate (ensemble with Logistic Regression) → **only if flagged:** SHAP explanation generated → result + explanation written to the SQLite hash-chain → dashboard reads the chain whenever a human opens it.

The only place connectivity would ever enter this system is the export/sync module described in the blockchain node-sync addendum — and it sits *after* the ledger, reading already-finished records. It never touches the live detection path.

---

## 4. Task Items Generated From This Discussion

| # | Task | Notes |
|---|---|---|
| 1 | Set up shared feature-extraction module used by both training pipeline and live daemon | Prevents live/train feature mismatch — highest-leverage correctness item |
| 2 | Export trained GRU+Attention model to ONNX; benchmark inference latency via ONNX Runtime vs. raw PyTorch | Supports the "lightweight → low latency" claim with real numbers |
| 3 | Implement rolling time-window buffer for live flow/packet feature aggregation | Core of the feature extraction stage |
| 4 | Gate SHAP invocation strictly behind the confidence-threshold flag — never run on every window | Real-time feasibility constraint; document the reasoning in the architecture doc |
| 5 | Build the SQLite Action Ledger table + hash-chaining logic | Same schema as prior addendum: `{prediction, mitre_stage, shap_summary, timestamp, prev_hash, record_hash}` |
| 6 | Write and test a `systemd` unit file (Linux) and/or Windows Service wrapper (`pywin32`/NSSM) | Turns the script into a real background daemon |
| 7 | Decouple dashboard into a separate process reading the ledger on demand | Confirms "runs without UI open" claim |
| 8 | Package the daemon with PyInstaller for a double-click demo executable | Demo portability |
| 9 | Prepare a rehearsed answer for "why not explain every prediction with SHAP?" | Cost-vs-value tradeoff, not a shortcut — see Section 2.5 |
