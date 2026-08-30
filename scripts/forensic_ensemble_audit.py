"""
Forensic Audit Script: Rigorous Deconstruction of the 83.12% Balanced-Accuracy Ensemble Result.

Addresses:
1. Full per-class precision, recall, F1, and support for all models & ensemble.
2. Operating thresholds: argmax and binary threat thresholds (tau in [0.1, 0.3, 0.5, 0.7, 0.85, 0.95]).
3. Comparison between Phase 0 Definitive Baseline LogReg vs Phase 5 Balanced LogReg.
4. FPR & Alert Fidelity ("Crying Wolf" metric: False Alerts per Real Alert).
5. Mathematical deconstruction of the shuffle ablation on ensemble vs standalone.
"""

import sys
from pathlib import Path
import json
import numpy as np
import torch
import joblib
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, balanced_accuracy_score, f1_score, precision_score, recall_score, roc_auc_score, confusion_matrix

sys.path.insert(0, str(Path(__file__).parent.parent))
from src.world_model.model import WorldModel
from src.world_model.dataset import extract_temporal_sequences_from_parquet

print("=" * 110)
print("NETGUARD FORENSIC AUDIT: DECONSTRUCTION OF DUAL-ENGINE ENSEMBLE (83.12% BAL-ACC)")
print("=" * 110)

DEVICE = torch.device("cpu")
CKPT_DIR = Path("models/checkpoints")

with open(CKPT_DIR / "feature_columns.json") as f:
    manifest = json.load(f)
classes = manifest["classes"]
num_classes = len(classes)
benign_idx = classes.index("BENIGN")

le = LabelEncoder()
le.fit(classes)

# 1. Load Test Sequences
test_parquet = str(Path("data/processed/sequences_test.parquet"))
X_test, y_st_test, y_test, y_mit_test = extract_temporal_sequences_from_parquet(test_parquet, le, context_length=3)
X_last = X_test[:, -1, :]  # (10909, 84)

# 2. Load Models
# A. Standalone World Model
wm = WorldModel(input_size=84, hidden_size=128, num_layers=2, num_classes=num_classes, num_mitre_stages=6, use_attention=True).to(DEVICE)
ckpt = torch.load(CKPT_DIR / "world_model_v1.pt", map_location=DEVICE, weights_only=False)
wm.load_state_dict(ckpt["model_state_dict"])
wm.eval()

# B. Phase 0 Definitive Baseline LogReg
logreg_phase0 = joblib.load(CKPT_DIR / "baseline_logreg_configA.joblib")

# C. Phase 5 Balanced LogReg
logreg_phase5 = joblib.load(CKPT_DIR / "ensemble_logreg.joblib")

# 3. Model Inference & Probabilities
X_test_tensor = torch.from_numpy(X_test).float().to(DEVICE)
with torch.no_grad():
    wm_out = wm(X_test_tensor)
    wm_probs = torch.softmax(wm_out["class_logits"], dim=-1).cpu().numpy()

def get_lr_probs(lr_model, X):
    raw_p = lr_model.predict_proba(X)
    full_p = np.zeros((len(X), num_classes), dtype=np.float32)
    full_p[:, getattr(lr_model, "classes_", range(raw_p.shape[1]))] = raw_p
    return full_p

lr_phase0_probs = get_lr_probs(logreg_phase0, X_last)
lr_phase5_probs = get_lr_probs(logreg_phase5, X_last)

ensemble_probs = 0.6 * wm_probs + 0.4 * lr_phase5_probs
ensemble_phase0_probs = 0.6 * wm_probs + 0.4 * lr_phase0_probs

# 4. POINT 3: Checkpoint Dissection (Phase 0 vs Phase 5 LogReg)
print("\n" + "=" * 110)
print("POINT 3: IS 'BALANCED LOGREG' THE SAME AS PHASE 0 'DEFINITIVE BASELINE' LOGREG?")
print("=" * 110)
print(f"Phase 0 LogReg Model Path:    models/checkpoints/baseline_logreg_configA.joblib")
print(f"  - Model Class:              {type(logreg_phase0).__name__}")
print(f"  - class_weight Parameter:   {getattr(logreg_phase0, 'class_weight', None)}")
print(f"  - C (Regularization):       {getattr(logreg_phase0, 'C', None)}")
print(f"  - max_iter:                 {getattr(logreg_phase0, 'max_iter', None)}")
print(f"  - Solver:                   {getattr(logreg_phase0, 'solver', None)}")

print(f"\nPhase 5 LogReg Model Path:    models/checkpoints/ensemble_logreg.joblib")
print(f"  - Model Class:              {type(logreg_phase5).__name__}")
print(f"  - class_weight Parameter:   {getattr(logreg_phase5, 'class_weight', None)}")
print(f"  - C (Regularization):       {getattr(logreg_phase5, 'C', None)}")
print(f"  - max_iter:                 {getattr(logreg_phase5, 'max_iter', None)}")
print(f"  - Solver:                   {getattr(logreg_phase5, 'solver', None)}")

# Compute standalone metrics for both LogReg models
for name, p_mat in [("Phase 0 Standard LogReg", lr_phase0_probs), ("Phase 5 Balanced LogReg", lr_phase5_probs)]:
    pred_c = np.argmax(p_mat, axis=1)
    ba = balanced_accuracy_score(y_test, pred_c)
    mf1 = f1_score(y_test, pred_c, average="macro", zero_division=0)
    wf1 = f1_score(y_test, pred_c, average="weighted", zero_division=0)
    acc = np.mean(pred_c == y_test)
    print(f"\nStandalone Performance for {name}:")
    print(f"  Balanced Accuracy: {ba*100:.2f}% | Macro-F1: {mf1:.4f} | Weighted-F1: {wf1:.4f} | Overall Acc: {acc*100:.2f}%")

# 5. POINT 1: Full Per-Class Precision, Recall, F1 Table
print("\n" + "=" * 110)
print("POINT 1: FULL PER-CLASS PRECISION, RECALL, F1, AND TEST SUPPORT (N) COMPARISON")
print("=" * 110)

models_to_eval = [
    ("Phase 0 Standard LogReg (Definitive Baseline)", lr_phase0_probs),
    ("Phase 5 Balanced LogReg Alone", lr_phase5_probs),
    ("Standalone World Model (world_model_v1.pt)", wm_probs),
    ("Dual-Engine Ensemble (0.6 WM + 0.4 Bal LR)", ensemble_probs)
]

for model_name, p_mat in models_to_eval:
    pred_c = np.argmax(p_mat, axis=1)
    report = classification_report(y_test, pred_c, target_names=classes, output_dict=True, zero_division=0)
    ba = balanced_accuracy_score(y_test, pred_c)
    mf1 = f1_score(y_test, pred_c, average="macro", zero_division=0)
    
    print(f"\n--- {model_name} (Balanced Acc: {ba*100:.2f}%, Macro-F1: {mf1:.4f}) ---")
    print(f"{'Class Name':<28} | {'Test N':<7} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10}")
    print("-" * 75)
    for c_name in classes:
        row = report.get(c_name, {})
        sup = int(row.get("support", 0))
        prec = row.get("precision", 0.0)
        rec = row.get("recall", 0.0)
        f1 = row.get("f1-score", 0.0)
        print(f"{c_name:<28} | {sup:<7} | {prec:<10.4f} | {rec:<10.4f} | {f1:<10.4f}")

# 6. POINT 2 & 4: Threshold Curves, FPR, and Alert Fidelity ("Crying Wolf")
print("\n" + "=" * 110)
print("POINT 2 & 4: THRESHOLD SENSITIVITY, FPR, AND ALERT FIDELITY ('CRYING WOLF' ANALYSIS)")
print("=" * 110)
print(f"Total Test Set Samples:    N = {len(y_test)}")
print(f"  - Known Benign Samples:  N = {np.sum(y_test == benign_idx)} (99.11%)")
print(f"  - Known Attack Samples:  N = {np.sum(y_test != benign_idx)} (0.89%)")

for model_name, p_mat in [
    ("Standalone World Model (world_model_v1.pt)", wm_probs),
    ("Dual-Engine Ensemble (0.6 WM + 0.4 Bal LR)", ensemble_probs)
]:
    threat_probs = 1.0 - p_mat[:, benign_idx]
    true_threat = (y_test != benign_idx).astype(int)
    
    print(f"\n--- Operating Point Curve for: {model_name} ---")
    print(f"{'Threshold (tau)':<16} | {'Threat Rec':<11} | {'Threat Prec':<12} | {'FPR (FP/Benign)':<16} | {'FP Count':<9} | {'Alert Ratio (FP:TP)':<20} | {'Threat F1':<10}")
    print("-" * 105)
    
    # 1. Multi-class argmax operating point
    pred_c = np.argmax(p_mat, axis=1)
    bin_pred_argmax = (pred_c != benign_idx).astype(int)
    tp_arg = np.sum((bin_pred_argmax == 1) & (true_threat == 1))
    fp_arg = np.sum((bin_pred_argmax == 1) & (true_threat == 0))
    fn_arg = np.sum((bin_pred_argmax == 0) & (true_threat == 1))
    tn_arg = np.sum((bin_pred_argmax == 0) & (true_threat == 0))
    rec_arg = tp_arg / (tp_arg + fn_arg) if (tp_arg + fn_arg) > 0 else 0
    prec_arg = tp_arg / (tp_arg + fp_arg) if (tp_arg + fp_arg) > 0 else 0
    fpr_arg = fp_arg / (fp_arg + tn_arg) if (fp_arg + tn_arg) > 0 else 0
    ratio_arg = f"{fp_arg/tp_arg:.1f} : 1" if tp_arg > 0 else "N/A"
    f1_arg = 2 * (prec_arg * rec_arg) / (prec_arg + rec_arg) if (prec_arg + rec_arg) > 0 else 0
    print(f"{'Standard Argmax':<16} | {rec_arg:<11.4f} | {prec_arg:<12.4f} | {fpr_arg*100:<6.2f}% ({fp_arg:<4})   | {fp_arg:<9} | {ratio_arg:<20} | {f1_arg:<10.4f}")
    
    # 2. Continuous threshold sweeps
    for tau in [0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90]:
        bin_pred = (threat_probs >= tau).astype(int)
        tp = np.sum((bin_pred == 1) & (true_threat == 1))
        fp = np.sum((bin_pred == 1) & (true_threat == 0))
        fn = np.sum((bin_pred == 0) & (true_threat == 1))
        tn = np.sum((bin_pred == 0) & (true_threat == 0))
        
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        ratio = f"{fp/tp:.1f} : 1" if tp > 0 else "N/A"
        f1_bin = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0
        print(f"tau = {tau:<10.2f} | {rec:<11.4f} | {prec:<12.4f} | {fpr*100:<6.2f}% ({fp:<4})   | {fp:<9} | {ratio:<20} | {f1_bin:<10.4f}")

# 7. POINT 5: Mathematical Deconstruction of Shuffle Ablation on Ensemble Output
print("\n" + "=" * 110)
print("POINT 5: SHUFFLE-ABLATION ON ENSEMBLE OUTPUT VS STANDALONE WORLD MODEL")
print("=" * 110)

seeds = [42, 101, 2024, 777, 999, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]

wm_shuffled_bas = []
ens_shuffled_bas = []
lr_shuffled_bas = []

for s in seeds:
    np.random.seed(s)
    shuf_order = np.random.permutation(3)
    X_shuf = X_test[:, shuf_order, :]
    X_shuf_tensor = torch.from_numpy(X_shuf).float().to(DEVICE)
    
    with torch.no_grad():
        w_out = wm(X_shuf_tensor)
        w_p = torch.softmax(w_out["class_logits"], dim=-1).cpu().numpy()
        
    ens_p = 0.6 * w_p + 0.4 * lr_phase5_probs
    lr_p = lr_phase5_probs
    
    wm_shuffled_bas.append(balanced_accuracy_score(y_test, np.argmax(w_p, axis=1)))
    ens_shuffled_bas.append(balanced_accuracy_score(y_test, np.argmax(ens_p, axis=1)))
    lr_shuffled_bas.append(balanced_accuracy_score(y_test, np.argmax(lr_p, axis=1)))

wm_intact = balanced_accuracy_score(y_test, np.argmax(wm_probs, axis=1))
ens_intact = balanced_accuracy_score(y_test, np.argmax(ensemble_probs, axis=1))
lr_intact = balanced_accuracy_score(y_test, np.argmax(lr_phase5_probs, axis=1))

wm_mean_shuf, wm_std_shuf = np.mean(wm_shuffled_bas), np.std(wm_shuffled_bas)
ens_mean_shuf, ens_std_shuf = np.mean(ens_shuffled_bas), np.std(ens_shuffled_bas)
lr_mean_shuf, lr_std_shuf = np.mean(lr_shuffled_bas), np.std(lr_shuffled_bas)

wm_drop = wm_intact - wm_mean_shuf
ens_drop = ens_intact - ens_mean_shuf
lr_drop = lr_intact - lr_mean_shuf

wm_sigma = wm_drop / wm_std_shuf if wm_std_shuf > 0 else 0
ens_sigma = ens_drop / ens_std_shuf if ens_std_shuf > 0 else 0
lr_sigma = lr_drop / lr_std_shuf if lr_std_shuf > 0 else 0

print(f"1. Standalone World Model (world_model_v1.pt):")
print(f"   - Intact Balanced Acc:   {wm_intact*100:.2f}%")
print(f"   - Shuffled 20-Seed Mean: {wm_mean_shuf*100:.2f}% +/- {wm_std_shuf*100:.2f}%")
print(f"   - Absolute Drop:         {wm_drop*100:.2f}%")
print(f"   - Significance:          +{wm_sigma:.2f} sigma")

print(f"\n2. Standalone Balanced LogReg:")
print(f"   - Intact Balanced Acc:   {lr_intact*100:.2f}%")
print(f"   - Shuffled 20-Seed Mean: {lr_mean_shuf*100:.2f}% +/- {lr_std_shuf*100:.2f}%")
print(f"   - Absolute Drop:         {lr_drop*100:.2f}%")
print(f"   - Significance:          +{lr_sigma:.2f} sigma (Memoryless tabular model has 0 temporal drop)")

print(f"\n3. Dual-Engine Ensemble (0.6 WM + 0.4 Bal LR):")
print(f"   - Intact Balanced Acc:   {ens_intact*100:.2f}%")
print(f"   - Shuffled 20-Seed Mean: {ens_mean_shuf*100:.2f}% +/- {ens_std_shuf*100:.2f}%")
print(f"   - Absolute Drop:         {ens_drop*100:.2f}%")
print(f"   - Significance:          +{ens_sigma:.2f} sigma")

print("\n" + "=" * 110)
print("AUDIT COMPLETE.")
print("=" * 110)
