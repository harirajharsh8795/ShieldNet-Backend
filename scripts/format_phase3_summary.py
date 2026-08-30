import json
import pandas as pd

with open("models/checkpoints/phase3_loss_tuning_summary.json") as f:
    sweep = json.load(f)
with open("models/checkpoints/DEFINITIVE_BASELINE.json") as f:
    base = json.load(f)

print("=" * 125)
print(f"{'Loss Variant':<35} | {'Macro-F1':<9} | {'Bal Acc':<8} | {'Weighted F1':<11} | {'Threat AUC':<10} | {'Shuffle Drop':<13} | {'Sigma':<8}")
print("=" * 125)

# Baseline
b_mf1 = base["metrics"]["macro_f1"]
b_bacc = base["metrics"]["balanced_accuracy"]
if b_bacc < 1.0:
    b_bacc = b_bacc * 100.0
b_wf1 = base["metrics"]["weighted_f1"]
b_auc = base["metrics"]["threat_roc_auc"]
print(f"{'Definitive Baseline (LogReg)':<35} | {b_mf1:9.4f} | {b_bacc:7.2f}% | {b_wf1:11.4f} | {b_auc:10.4f} | {'0.00%':<13} | {'0.00':<8}")

# Control WM v1
wm1 = sweep["world_model_v1_control"]
ab1 = wm1["shuffle_ablation"]
print(f"{'world_model_v1 (Control, gamma=0.0)':<35} | {wm1['macro_f1']:9.4f} | {wm1['balanced_accuracy']:7.2f}% | {wm1['weighted_f1']:11.4f} | {wm1['threat_roc_auc']:10.4f} | {str(ab1['drop_percent'])+'%':<13} | {str(ab1['sigma']):<8}")

# Variants
variants = [
    ("inv_freq_smoothed", "Smoothed Inv-Freq (gamma=0.0)"),
    ("focal_g05", "Focal Loss (gamma=0.5)"),
    ("focal_g10", "Focal Loss (gamma=1.0)"),
    ("focal_g15", "Focal Loss (gamma=1.5)"),
    ("focal_g20", "Focal Loss (gamma=2.0)"),
]

for key, display in variants:
    vm = sweep[key]
    vab = vm["shuffle_ablation"]
    print(f"{display:<35} | {vm['macro_f1']:9.4f} | {vm['balanced_accuracy']:7.2f}% | {vm['weighted_f1']:11.4f} | {vm['threat_roc_auc']:10.4f} | {str(vab['drop_percent'])+'%':<13} | {str(vab['sigma']):<8}")

print("=" * 125)

# Focus classes: Bot, PortScan, SSH-Patator, FTP-Patator
focus_classes = ["Bot", "PortScan", "SSH-Patator", "FTP-Patator"]
print("\n=== PER-CLASS F1-SCORE FOCUS TABLE (Bot, PortScan, SSH, FTP) ===")
focus_data = {}
for c in focus_classes:
    supp = base["metrics"]["per_class"][c]["support"]
    base_f1 = base["metrics"]["per_class"][c]["f1"]
    wm1_f1 = sweep["world_model_v1_control"]["per_class"][c]["f1"]
    
    row = {
        "Support": supp,
        "LogReg": round(base_f1, 4),
        "Control v1": round(wm1_f1, 4),
    }
    for key, display in variants:
        row[display] = round(sweep[key]["per_class"][c]["f1"], 4)
    focus_data[c] = row

df_f = pd.DataFrame.from_dict(focus_data, orient="index")
print(df_f.to_string())

# Full per-class F1 table
print("\n=== FULL 13-CLASS F1-SCORE BREAKDOWN ===")
all_classes = list(base["metrics"]["per_class"].keys())
full_data = {}
for c in all_classes:
    supp = base["metrics"]["per_class"][c]["support"]
    base_f1 = base["metrics"]["per_class"][c]["f1"]
    wm1_f1 = sweep["world_model_v1_control"]["per_class"][c]["f1"]
    row = {
        "Support": supp,
        "LogReg": round(base_f1, 4),
        "Control v1": round(wm1_f1, 4),
    }
    for key, display in variants:
        row[key] = round(sweep[key]["per_class"][c]["f1"], 4)
    full_data[c] = row
df_all = pd.DataFrame.from_dict(full_data, orient="index")
print(df_all.to_string())
