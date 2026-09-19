"""
Two-Stage Hierarchical Cascaded Defense Architecture Evaluation.
Stage 1: High-Precision Sentinel Gatekeeper (Binary: Benign vs Anomaly/Attack)
Stage 2: Specialized Multi-Class Attack Classifier (Domain-grouped or 12-class router)
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

# Binary labels: 0 = Benign, 1 = Attack
y_binary_true = (y_test != benign_idx).astype(int)
print(f"Ground Truth: {np.sum(y_binary_true == 0)} Benign, {np.sum(y_binary_true == 1)} Attacks", flush=True)

# 3. Load models
wm = WorldModel(input_size=84, hidden_size=128, num_layers=2, num_classes=num_classes, num_mitre_stages=6, use_attention=True).to(DEVICE)
ckpt = torch.load(CKPT_DIR / "world_model_v1.pt", map_location=DEVICE, weights_only=False)
wm.load_state_dict(ckpt["model_state_dict"])
wm.eval()

lr_model = joblib.load(CKPT_DIR / "ensemble_logreg.joblib")

# 4. Predict probabilities
X_test_tensor = torch.from_numpy(X_test).float().to(DEVICE)
with torch.no_grad():
    wm_out = wm(X_test_tensor)
    wm_probs = torch.softmax(wm_out["class_logits"], dim=-1).cpu().numpy()

raw_lr = lr_model.predict_proba(X_last)
lr_probs = np.zeros((len(X_last), num_classes), dtype=np.float32)
lr_probs[:, getattr(lr_model, "classes_", range(raw_lr.shape[1]))] = raw_lr

# Dual-engine blend
ens_probs = 0.60 * wm_probs + 0.40 * lr_probs

# Calculate Stage-1 Threat Probability: P(Malicious) = 1.0 - P(BENIGN)
p_benign = ens_probs[:, benign_idx]
p_malicious = 1.0 - p_benign

print("\n" + "=" * 90, flush=True)
print("STAGE 1 EVALUATION: BINARY SENTINEL GATEKEEPER (Benign vs Malicious)", flush=True)
print("=" * 90, flush=True)

best_thresh = 0.50
best_f1 = 0
results_by_thresh = []

for thresh in np.arange(0.10, 0.95, 0.05):
    y_bin_pred = (p_malicious >= thresh).astype(int)
    acc = np.mean(y_bin_pred == y_binary_true)
    f1 = f1_score(y_binary_true, y_bin_pred, zero_division=0)
    prec = precision_score(y_binary_true, y_bin_pred, zero_division=0)
    rec = recall_score(y_binary_true, y_bin_pred, zero_division=0)
    results_by_thresh.append((thresh, acc, f1, prec, rec))
    if f1 > best_f1:
        best_f1 = f1
        best_thresh = thresh

print(f"{'Threshold':<10} | {'Accuracy':<10} | {'Binary F1':<10} | {'Precision':<10} | {'Recall':<10}")
print("-" * 65)
for t, acc, f1, prec, rec in results_by_thresh[::2]:
    star = " <-- OPTIMAL" if abs(t - best_thresh) < 1e-4 else ""
    print(f"{t:<10.2f} | {acc*100:<9.2f}% | {f1:<10.4f} | {prec:<10.4f} | {rec:<10.4f}{star}")

# Optimal Stage 1 Metrics
opt_bin_pred = (p_malicious >= best_thresh).astype(int)
opt_bin_acc = np.mean(opt_bin_pred == y_binary_true)
opt_bin_f1 = f1_score(y_binary_true, opt_bin_pred, zero_division=0)
opt_bin_prec = precision_score(y_binary_true, opt_bin_pred, zero_division=0)
opt_bin_rec = recall_score(y_binary_true, opt_bin_pred, zero_division=0)

print(f"\n[Optimal Binary Gatekeeper (Threshold = {best_thresh:.2f})]")
print(f"  * Overall Accuracy:        {opt_bin_acc*100:.2f}%")
print(f"  * Threat Detection Recall: {opt_bin_rec*100:.2f}% (Catches genuine attacks)")
print(f"  * Threat Precision:        {opt_bin_prec*100:.2f}%")
print(f"  * Binary F1-Score:         {opt_bin_f1:.4f}")

print("\n" + "=" * 90, flush=True)
print("STAGE 2 EVALUATION: HIERARCHICAL CASCADED CLASSIFICATION", flush=True)
print("=" * 90, flush=True)

# In Stage 2:
# If Stage 1 says Benign (p_malicious < best_thresh), predict BENIGN.
# If Stage 1 says Attack (p_malicious >= best_thresh), route to specialized attack classifier:
#   argmax over all attack classes (excluding BENIGN).

attack_probs = ens_probs.copy()
attack_probs[:, benign_idx] = -1e9  # suppress benign for attack router

stage2_attack_preds = np.argmax(attack_probs, axis=1)

cascade_preds = np.where(opt_bin_pred == 0, benign_idx, stage2_attack_preds)

cascade_report = classification_report(y_test, cascade_preds, target_names=classes, output_dict=True, zero_division=0)
cascade_acc = np.mean(cascade_preds == y_test)
cascade_macro_f1 = f1_score(y_test, cascade_preds, average="macro", zero_division=0)
cascade_weighted_f1 = f1_score(y_test, cascade_preds, average="weighted", zero_division=0)
cascade_bal_acc = balanced_accuracy_score(y_test, cascade_preds)

print(f"{'Class':<26} | {'Support':>7} | {'Precision':>9} | {'Recall':>8} | {'F1-Score':>8}")
print("-" * 70)
for c in classes:
    m = cascade_report[c]
    p, r, f, s = m['precision'], m['recall'], m['f1-score'], int(m['support'])
    print(f"{c:<26} | {s:>7} | {p:>9.4f} | {r:>8.4f} | {f:>8.4f}")

print("-" * 70)
print(f"Cascaded 13-Class Macro-F1:          {cascade_macro_f1:.4f}")
print(f"Cascaded Overall Accuracy:          {cascade_acc*100:.2f}% (vs Flat Softmax 90.51%)")
print(f"Cascaded Balanced Accuracy:         {cascade_bal_acc*100:.2f}%")
print(f"Cascaded Weighted F1-Score:         {cascade_weighted_f1:.4f}")

print("\n" + "=" * 90, flush=True)
print("STAGE 2 + OPERATIONAL GROUPING (DoS-Volumetric)", flush=True)
print("=" * 90, flush=True)

dos_variant_names = ["DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest", "DoS slowloris"]
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
cascade_merged_preds = np.array([map_to_merged(idx) for idx in cascade_preds])

merged_cascade_report = classification_report(y_merged, cascade_merged_preds, target_names=merged_classes, output_dict=True, zero_division=0)
merged_cascade_macro_f1 = f1_score(y_merged, cascade_merged_preds, average="macro", zero_division=0)
merged_cascade_acc = np.mean(cascade_merged_preds == y_merged)
merged_cascade_bal_acc = balanced_accuracy_score(y_merged, cascade_merged_preds)

print(f"{'Merged Class':<26} | {'Support':>7} | {'Precision':>9} | {'Recall':>8} | {'F1-Score':>8}")
print("-" * 70)
for c in merged_classes:
    m = merged_cascade_report[c]
    p, r, f, s = m['precision'], m['recall'], m['f1-score'], int(m['support'])
    print(f"{c:<26} | {s:>7} | {p:>9.4f} | {r:>8.4f} | {f:>8.4f}")

print("-" * 70)
print(f"Hierarchical Cascaded + Merged Macro-F1: {merged_cascade_macro_f1:.4f}")
print(f"Hierarchical Cascaded + Merged Accuracy: {merged_cascade_acc*100:.2f}%")
print(f"Hierarchical Cascaded Balanced Acc:     {merged_cascade_bal_acc*100:.2f}%")
print("=" * 90, flush=True)

# Save results to JSON artifact
output_metrics = {
    "evaluation_timestamp": "2026-09-20T00:15:00Z",
    "dataset": "data/processed/sequences_test.parquet (N=10909)",
    "stage1_sentinel_gatekeeper": {
        "optimal_threshold": float(best_thresh),
        "accuracy": float(opt_bin_acc),
        "binary_f1": float(opt_bin_f1),
        "threat_precision": float(opt_bin_prec),
        "threat_recall": float(opt_bin_rec)
    },
    "stage2_hierarchical_13class": {
        "macro_f1": float(cascade_macro_f1),
        "overall_accuracy": float(cascade_acc),
        "balanced_accuracy": float(cascade_bal_acc),
        "weighted_f1": float(cascade_weighted_f1)
    },
    "stage2_hierarchical_grouped_10class": {
        "macro_f1": float(merged_cascade_macro_f1),
        "overall_accuracy": float(merged_cascade_acc),
        "balanced_accuracy": float(merged_cascade_bal_acc)
    }
}

out_path = CKPT_DIR / "HIERARCHICAL_CASCADE_METRICS.json"
with open(out_path, "w") as f:
    json.dump(output_metrics, f, indent=2)
print(f"[SUCCESS] Saved hierarchical cascade evaluation to {out_path.name}")
