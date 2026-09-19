"""
Mathematical Audit Script for Macro-F1, Precision/Recall, and DoS-Volumetric Merge.
Directly verifies the ground-truth test set numbers on data/processed/sequences_test.parquet.
"""

import sys
from pathlib import Path
import json
import numpy as np
import torch
import joblib
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score, balanced_accuracy_score

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.world_model.model import WorldModel
from src.world_model.dataset import extract_temporal_sequences_from_parquet

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
CKPT_DIR = PROJECT_ROOT / "models" / "checkpoints"

# 1. Load manifest & classes
with open(CKPT_DIR / "feature_columns.json") as f:
    manifest = json.load(f)
classes = manifest["classes"]
num_classes = len(classes)
benign_idx = classes.index("BENIGN")

le = LabelEncoder()
le.fit(classes)

# 2. Load test set
test_parquet = str(PROJECT_ROOT / "data" / "processed" / "sequences_test.parquet")
print(f"Loading test sequences from {test_parquet}...", flush=True)
X_test, y_st_test, y_test, y_mit_test = extract_temporal_sequences_from_parquet(test_parquet, le, context_length=3)
X_last = X_test[:, -1, :]
N = len(y_test)
print(f"Total Test Sequences N = {N}", flush=True)

# 3. Load models
wm = WorldModel(input_size=84, hidden_size=128, num_layers=2, num_classes=num_classes, num_mitre_stages=6, use_attention=True).to(DEVICE)
ckpt = torch.load(CKPT_DIR / "world_model_v1.pt", map_location=DEVICE, weights_only=False)
wm.load_state_dict(ckpt["model_state_dict"])
wm.eval()

lr_model = joblib.load(CKPT_DIR / "ensemble_logreg.joblib")

# 4. Predict
X_test_tensor = torch.from_numpy(X_test).float().to(DEVICE)
with torch.no_grad():
    wm_out = wm(X_test_tensor)
    wm_probs = torch.softmax(wm_out["class_logits"], dim=-1).cpu().numpy()

raw_lr = lr_model.predict_proba(X_last)
lr_probs = np.zeros((len(X_last), num_classes), dtype=np.float32)
lr_probs[:, getattr(lr_model, "classes_", range(raw_lr.shape[1]))] = raw_lr

# Dual-engine blend
ens_probs = 0.60 * wm_probs + 0.40 * lr_probs

# Load optimal weights if available
cal_file = CKPT_DIR / "optimal_threshold_calibration.json"
if cal_file.exists():
    with open(cal_file) as f:
        cal_data = json.load(f)
    weights_dict = cal_data.get("optimal_class_weights", {})
    weights_vec = np.array([weights_dict.get(c, 1.0) for c in classes], dtype=np.float32)
    cal_probs = ens_probs * weights_vec
    cal_probs = cal_probs / cal_probs.sum(axis=1, keepdims=True)
    preds = np.argmax(cal_probs, axis=1)
else:
    preds = np.argmax(ens_probs, axis=1)

# Raw argmax predictions for baseline
raw_preds = np.argmax(ens_probs, axis=1)

print("\n" + "=" * 90, flush=True)
print("13-CLASS TEST SET EVALUATION AUDIT", flush=True)
print("=" * 90, flush=True)

# Compute per-class metrics
cm = confusion_matrix(y_test, preds, labels=range(num_classes))
report = classification_report(y_test, preds, target_names=classes, output_dict=True, zero_division=0)

f1_list = []
print(f"{'Class':<26} | {'Support':>7} | {'Precision':>9} | {'Recall':>8} | {'F1-Score':>8}", flush=True)
print("-" * 70, flush=True)
for c in classes:
    m = report[c]
    p, r, f, s = m['precision'], m['recall'], m['f1-score'], int(m['support'])
    f1_list.append(f)
    print(f"{c:<26} | {s:>7} | {p:>9.4f} | {r:>8.4f} | {f:>8.4f}", flush=True)

unweighted_macro_f1 = float(np.mean(f1_list))
weighted_f1 = f1_score(y_test, preds, average="weighted", zero_division=0)
bal_acc = balanced_accuracy_score(y_test, preds)
overall_acc = np.mean(preds == y_test)

raw_macro_f1 = f1_score(y_test, raw_preds, average="macro", zero_division=0)
raw_bal_acc = balanced_accuracy_score(y_test, raw_preds)

print("-" * 70, flush=True)
print(f"Exact Arithmetic Mean of 13 Classes: {unweighted_macro_f1:.4f}", flush=True)
print(f"Raw Argmax Macro-F1 (uncalibrated):  {raw_macro_f1:.4f}", flush=True)
print(f"Weighted F1-Score:                   {weighted_f1:.4f}", flush=True)
print(f"Balanced Accuracy:                   {bal_acc*100:.2f}% (Raw: {raw_bal_acc*100:.2f}%)", flush=True)
print(f"Overall Accuracy:                    {overall_acc*100:.2f}%", flush=True)

print("\n" + "=" * 90, flush=True)
print("ACTIONABLE REFINEMENT A: DOS VARIANT MERGE (DoS-Volumetric)", flush=True)
print("=" * 90, flush=True)

# Merge DoS variants into DoS-Volumetric:
# Classes to merge: DoS GoldenEye, DoS Hulk, DoS Slowhttptest, DoS slowloris
dos_variant_names = ["DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest", "DoS slowloris"]
dos_variant_indices = [classes.index(name) for name in dos_variant_names if name in classes]
print(f"Merging classes: {dos_variant_names} (indices: {dos_variant_indices})", flush=True)

# Create 10-class mapping
# New class list:
# 0: BENIGN
# 1: Bot
# 2: DDoS
# 3: DoS-Volumetric (merged GoldenEye, Hulk, Slowhttptest, slowloris)
# 4: FTP-Patator
# 5: PortScan
# 6: Rare-Attack
# 7: SSH-Patator
# 8: Web Attack - Brute Force
# 9: Web Attack - XSS

merged_classes = [
    "BENIGN", "Bot", "DDoS", "DoS-Volumetric", "FTP-Patator", 
    "PortScan", "Rare-Attack", "SSH-Patator", "Web Attack - Brute Force", "Web Attack - XSS"
]

def map_to_merged(idx):
    c_name = classes[idx]
    if c_name in dos_variant_names:
        return merged_classes.index("DoS-Volumetric")
    return merged_classes.index(c_name)

y_merged = np.array([map_to_merged(idx) for idx in y_test])
preds_merged = np.array([map_to_merged(idx) for idx in preds])

merged_report = classification_report(y_merged, preds_merged, target_names=merged_classes, output_dict=True, zero_division=0)
merged_f1_list = []

print(f"{'Merged Class':<26} | {'Support':>7} | {'Precision':>9} | {'Recall':>8} | {'F1-Score':>8}", flush=True)
print("-" * 70, flush=True)
for c in merged_classes:
    m = merged_report[c]
    p, r, f, s = m['precision'], m['recall'], m['f1-score'], int(m['support'])
    merged_f1_list.append(f)
    print(f"{c:<26} | {s:>7} | {p:>9.4f} | {r:>8.4f} | {f:>8.4f}", flush=True)

merged_macro_f1 = float(np.mean(merged_f1_list))
merged_bal_acc = balanced_accuracy_score(y_merged, preds_merged)
print("-" * 70, flush=True)
print(f"Merged 10-Class Macro-F1:            {merged_macro_f1:.4f} (Stabilized from {unweighted_macro_f1:.4f})", flush=True)
print(f"Merged 10-Class Balanced Accuracy:   {merged_bal_acc*100:.2f}%", flush=True)

print("\n" + "=" * 90, flush=True)
print("ACTIONABLE REFINEMENT C: SAMPLE SIZE SPLIT (N >= 10 vs N < 10)", flush=True)
print("=" * 90, flush=True)

high_support_f1 = [f for c, f in zip(classes, f1_list) if report[c]['support'] >= 10]
rare_support_f1 = [f for c, f in zip(classes, f1_list) if report[c]['support'] < 10]

print(f"Macro-F1 for Adequately Sampled Classes (N >= 10): {np.mean(high_support_f1):.4f}")
print(f"Macro-F1 for Ultra-Rare Boundary Classes (N < 10):   {np.mean(rare_support_f1):.4f}")
print("=" * 90, flush=True)
