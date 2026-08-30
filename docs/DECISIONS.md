# ShieldNet Architectural Decisions & Open Forensic Findings

---

## 1. Context Horizon Selection ($L=3$)
- **Decision:** Select context horizon $L=3$ (30-second host-level sliding window) as the canonical temporal architecture.
- **Empirical Rationale:** Context length sweeps across $L \in \{3, 5, 7, 10\}$ demonstrated that as $L$ increases beyond 3, Balanced Accuracy monotonically degrades ($71.48\% \to 69.42\% \to 58.53\% \to 51.21\%$) and shuffle significance collapses ($+3.16\sigma \to +0.09\sigma$). Short-horizon dynamics capture multi-stage network attack transitions with minimal background historical noise.

---

## 2. Open Finding: Exact Canonical Replicate Metric Gap
- **Finding:** The fresh exact-replicate of the $L=3$ model achieved **71.48% Balanced Accuracy** (Macro-F1 0.5232, $+1.88\sigma$ shuffle drop), compared to the locked baseline checkpoint `world_model_v1.pt` at **79.15% Balanced Accuracy** (Macro-F1 0.2926, $+3.28\sigma$ shuffle drop).
- **Status:** Open finding. Exact-replicate did not reproduce the locked baseline despite matched hyperparameters; root cause not fully identified; does not affect the Phase 2 context-length decision ($L=3$ remains the clear winner across both training pipelines).
- **Policy:** The verified checkpoint `models/checkpoints/world_model_v1.pt` is retained as the authoritative canonical model.

---

## 3. Two-Config Architectural Decision
- **Decision:** Maintain **Config A** (`fused_matched_v1.parquet`, $N = 2,194,284$ flows, 84 features: 77 flow + 7 packet) for World Model training and **Config B** (`flow_only_full.parquet`, $N = 2,830,743$ flows) as the pure flow-only baseline.
- **Integrity Rule:** Zero imputation used. Unmatched flows are excluded from Config A to eliminate feature-presence leakage artifacts.

---

## 4. Production Champion Model & Shuffle-Significance Reconciliation
- **Decision:** The **ShieldNet Dual-Engine Ensemble (World Model GRU+Attention + Balanced Logistic Regression, Soft Averaging $w=0.6$)** is confirmed as the official primary production champion system, achieving:
  - **Balanced Accuracy:** **83.12%** (+3.97% over standalone World Model)
  - **Multi-Class Macro-F1:** **0.4203** (+0.1277 over standalone World Model)
  - **Overall Accuracy:** **93.69%**
  - **Threat ROC-AUC:** **0.9800**
  - **Threat PR-AUC:** **0.5571**
  - **Inference Latency:** **0.0155 ms / sample** (~64,400 samples/sec)
- **Shuffle-Significance Reconciliation:**
  - `world_model_v1.pt`'s shuffle-significance was originally established at **$+3.28\sigma$** using a 5-seed protocol. A comprehensive 20-seed re-estimate revised this to **$+2.53\sigma$** (mean drop $-11.05\% \pm 4.38\%$), which is a more statistically robust figure due to reduced seed-count variance.
  - This recalibration does **not** change any prior phase's decisions (context-length sweep, loss-tuning, etc.) because candidate models were rejected primarily on Balanced Accuracy margins far larger than any sigma difference could offset.
  - Going forward, **$+2.53\sigma$** is the official 20-seed reference figure for standalone `world_model_v1.pt`, and **$+3.92\sigma$** (mean drop $-14.27\% \pm 3.64\%$, paired $t$-test $p = 4.33 \times 10^{-5}$) is the official 20-seed figure for the champion Dual-Engine Ensemble.
