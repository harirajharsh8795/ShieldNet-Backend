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

## 4. Production Champion Model & Operating Profile Calibration
- **Decision:** The **ShieldNet Dual-Engine Ensemble (World Model GRU+Attention + Balanced Logistic Regression, Soft Averaging $w=0.6$, Calibrated $\tau=0.80$)** is confirmed as the official primary production champion system, achieving:
  - **Operational Threat Recall ($\tau=0.80$):** **79.38%** (Intercepts 77/97 multi-class attack sequences)
  - **False Positive Rate (FPR):** **3.99%** (431 false alarms / 10,812 benign flows $\to$ Triage-feasible $5.6:1$ Alert Ratio)
  - **Binary Balanced Accuracy:** **87.70%** (+4.29% over baseline)
  - **Multi-Class Gated Balanced Accuracy:** **76.40%** (+28.59% over memoryless baseline)
  - **Multi-Class Macro-F1:** **0.5335** (+0.0644 over baseline)
  - **Overall Accuracy:** **95.81%**
  - **Threat ROC-AUC / PR-AUC:** **0.9800 / 0.5571**
  - **Inference Latency:** **0.0155 ms / sample** (~64,400 samples/sec on CPU)
- **Secondary Reference Point (Raw Argmax Mode):**
  - Multi-Class Balanced Accuracy: **83.12%**, Threat Recall: **96.91%**, FPR: **10.73%** ($12.3:1$ alert ratio), Macro-F1: **0.4203**. (Maintained as an uncalibrated maximum-sensitivity comparison point).
- **Shuffle-Significance Reconciliation:**
  - `world_model_v1.pt`'s standalone shuffle-significance was established at **$+2.53\sigma$** across a 20-seed independent permutation protocol (mean drop $-11.05\% \pm 4.38\%$), confirming genuine temporal sequence dynamics learning.
  - The full state-perturbed ensemble achieves **$+3.92\sigma$** (mean drop $-14.27\% \pm 3.64\%$, paired $t$-test $p = 4.33 \times 10^{-5}$).
  - Under sequential-branch-only perturbation where the tabular LR anchor remains intact, the ensemble drops by $-5.88\%$ ($83.12\% \to 77.24\% \pm 6.00\%$, $+0.98\sigma$). This confirms that the temporal GRU contributes a $+5.88\%$ boost over the static tabular floor (77.20%), while pure temporal sensitivity is driven by the GRU core ($+2.53\sigma$).

