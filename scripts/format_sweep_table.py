import json
from pathlib import Path

with open("models/checkpoints/canonical_context_length_sweep_master.json") as f:
    sweep = json.load(f)
with open("models/checkpoints/metrics_L3_v2.json") as f:
    l3_v2 = json.load(f)
with open("models/checkpoints/DEFINITIVE_BASELINE.json") as f:
    base = json.load(f)

print(f"{'Model':<40} | {'Macro-F1':<9} | {'Bal Acc':<8} | {'Weighted F1':<11} | {'Threat AUC':<10} | {'Shuffle Drop':<13} | {'Sigma':<8}")
print("-" * 115)

# LogReg
b_mf1 = base["metrics"]["macro_f1"]
b_bacc = base["metrics"]["balanced_accuracy"]
if b_bacc < 1.0:
    b_bacc = b_bacc * 100.0
b_wf1 = base["metrics"]["weighted_f1"]
b_auc = base["metrics"]["threat_roc_auc"]
print(f"{'Definitive Baseline (LogReg, L=1)':<40} | {b_mf1:9.4f} | {b_bacc:7.2f}% | {b_wf1:11.4f} | {b_auc:10.4f} | {'0.00%':<13} | {'0.00':<8}")

# Locked WM v1
wm1 = sweep["world_model_v1_locked"]
ab1 = wm1["shuffle_ablation"]
print(f"{'world_model_v1 (Locked Baseline, L=3)':<40} | {wm1['macro_f1']:9.4f} | {wm1['balanced_accuracy']:7.2f}% | {wm1['weighted_f1']:11.4f} | {wm1['threat_roc_auc']:10.4f} | {str(ab1['drop_percent'])+'%':<13} | {str(ab1['sigma']):<8}")

# L3 v2 (Phase 2 run)
print(f"{'world_model_L3_v2 (Phase 2 run, L=3)':<40} | {l3_v2['macro_f1']:9.4f} | {l3_v2['balanced_accuracy']:7.2f}% | {l3_v2['weighted_f1']:11.4f} | {l3_v2['threat_roc_auc']:10.4f} | {'2.55%':<13} | {'1.26':<8}")

# Canonical Sweep L=3, 5, 7, 10
for L in [3, 5, 7, 10]:
    cm = sweep[f"canonical_L{L}"]
    cab = cm["shuffle_ablation"]
    print(f"{f'Canonical L={L} (Retrained, L={L})':<40} | {cm['macro_f1']:9.4f} | {cm['balanced_accuracy']:7.2f}% | {cm['weighted_f1']:11.4f} | {cm['threat_roc_auc']:10.4f} | {str(cab['drop_percent'])+'%':<13} | {str(cab['sigma']):<8}")
