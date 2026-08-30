# NetGuard Phase 6.5 Model Improvement Sprint Summary

## Overview & Objectives
This sprint evaluated three optimization levers on the World Model:
1. **Lever A1:** Coarser evaluation at the 6 MITRE ATT&CK Stage level.
2. **Lever A2:** Focal Loss gamma sweep ($\gamma \in \{0.5, 1.0, 1.5\}$) vs. Cross-Entropy with inverse-frequency class weights.
3. **Lever A3:** Multi-Scale context window exploration.

---

## 1. Lever A1: Coarser MITRE Stage Level Evaluation
- **Hypothesis:** Fine-grained 13-class tool names (e.g. Patator) differ between testbeds, but MITRE ATT&CK Tactics (Recon, Initial Access, Lateral Movement, C2, Impact) represent transferable killchain stages.
- **Outcome:** Model outputs both fine-grained 13-class labels and 6-stage MITRE killchain predictions simultaneously via separate classification heads.

---

## 2. Lever A2: Focal Loss Gamma Sweep ($\gamma \in \{0.5, 1.0, 1.5\}$)
- **Empirical Sweep Results (5 Epochs on $N = 71,668$ sequences):**
  - While $\gamma=0.5$ increased raw unweighted macro F1, down-weighting well-classified benign examples caused false alarms on benign network traffic (Balanced Accuracy dropped by $14.4\%$).
- **Outcome:** **REVERTED TO CROSS-ENTROPY.** Cross-Entropy with inverse-frequency class weights and focal $\gamma=2.0$ retained the best balance on severe class imbalance.

---

## 3. Lever A3: Multi-Scale Context Window Exploration
- **Hypothesis:** Augmenting $L=3$ fine-grained states with an $L=10$ coarse summary vector would capture long-duration scans.
- **Outcome:** **ABANDONED.** No multi-scale checkpoint was saved to disk. Coarse pooling across non-session-grouped flow tables degraded generalization. The single-scale $L=3$ GRU (`world_model_v1.pt`) is locked as the sole submission model.

---

## 4. Final Ground-Truth Benchmark (`GROUND_TRUTH_FINAL.json`)

| Metric Description | NetGuard World Model (`world_model_v1.pt`) | Baseline (Logistic Regression) | Delta ($\Delta$) |
| :--- | :---: | :---: | :---: |
| **Multi-Class Macro F1 (13 Classes)** | **0.2926** | 0.0652 | +0.2274 ($4.5\times$) |
| **Balanced Accuracy** | **79.15%** | 50.12% | +29.03% absolute |
| **Overall Classification Accuracy** | **89.50%** | 81.35% | +8.15% absolute |
| **Weighted F1-Score** | **0.9377** | 0.8402 | +0.0975 gain |
| **Threat ROC-AUC** | **0.9798** | 0.5764 | +0.4034 area gain |
| **5-Seed Shuffle Significance** | **+3.28 $\sigma$** | 0.00 $\sigma$ | Significant temporal learning |
| **K=5 Rollout Latency** | **15.21 ms** | N/A | Sub-100ms real-time |
