import json
import pandas as pd

with open("models/checkpoints/canonical_replicate_and_sweep.json") as f:
    sweep = json.load(f)
with open("models/checkpoints/DEFINITIVE_BASELINE.json") as f:
    base = json.load(f)

print("=" * 115)
print(f"{'Model Architecture':<38} | {'Macro-F1':<9} | {'Bal Acc':<8} | {'Weighted F1':<11} | {'Threat AUC':<10} | {'Shuffle Drop':<13} | {'Sigma':<8}")
print("=" * 115)

# 1. LogReg
b_mf1 = base["metrics"]["macro_f1"]
b_bacc = base["metrics"]["balanced_accuracy"]
if b_bacc < 1.0:
    b_bacc = b_bacc * 100.0
b_wf1 = base["metrics"]["weighted_f1"]
b_auc = base["metrics"]["threat_roc_auc"]
print(f"{'Definitive Baseline (LogReg, L=1)':<38} | {b_mf1:9.4f} | {b_bacc:7.2f}% | {b_wf1:11.4f} | {b_auc:10.4f} | {'0.00%':<13} | {'0.00':<8}")

# 2. Locked WM v1
wm1 = sweep["world_model_v1_locked"]
ab1 = wm1["shuffle_ablation"]
print(f"{'world_model_v1.pt (Locked Baseline, L=3)':<38} | {wm1['macro_f1']:9.4f} | {wm1['balanced_accuracy']:7.2f}% | {wm1['weighted_f1']:11.4f} | {wm1['threat_roc_auc']:10.4f} | {str(ab1['drop_percent'])+'%':<13} | {str(ab1['sigma']):<8}")

# 3. Exact Canonical L=3, 5, 7, 10
for L in [3, 5, 7, 10]:
    cm = sweep[f"exact_canonical_L{L}"]
    cab = cm["shuffle_ablation"]
    name = f"Exact Canonical L={L} Replicate" if L == 3 else f"Exact Canonical L={L}"
    print(f"{name:<38} | {cm['macro_f1']:9.4f} | {cm['balanced_accuracy']:7.2f}% | {cm['weighted_f1']:11.4f} | {cm['threat_roc_auc']:10.4f} | {str(cab['drop_percent'])+'%':<13} | {str(cab['sigma']):<8}")

print("=" * 115)

classes = list(base["metrics"]["per_class"].keys())
print("\n=== PER-CLASS F1-SCORE BREAKDOWN ===")
per_class = {}
for c in classes:
    supp = base["metrics"]["per_class"][c]["support"]
    base_f1 = base["metrics"]["per_class"][c]["f1"]
    wm1_f1 = sweep["world_model_v1_locked"]["per_class"][c]["f1"]
    ec3_f1 = sweep["exact_canonical_L3"]["per_class"][c]["f1"]
    ec5_f1 = sweep["exact_canonical_L5"]["per_class"][c]["f1"]
    ec7_f1 = sweep["exact_canonical_L7"]["per_class"][c]["f1"]
    ec10_f1 = sweep["exact_canonical_L10"]["per_class"][c]["f1"]
    
    per_class[c] = {
        "Support": supp,
        "LogReg": round(base_f1, 4),
        "world_model_v1": round(wm1_f1, 4),
        "Canonical L=3": round(ec3_f1, 4),
        "Canonical L=5": round(ec5_f1, 4),
        "Canonical L=7": round(ec7_f1, 4),
        "Canonical L=10": round(ec10_f1, 4),
    }

df_pc = pd.DataFrame.from_dict(per_class, orient="index")
print(df_pc.to_string())
