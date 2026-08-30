"""
ShieldNet Step 1: Locked World Model Re-Verification Script.
1. Computes SHA-256 of models/checkpoints/world_model_v1.pt
2. Checks file modification timestamps and sizes for data/processed/sequences_test.parquet
3. Evaluates world_model_v1.pt on sequences_test.parquet (N=10,909)
4. Computes exact Macro-F1, Balanced Accuracy, Weighted F1, Accuracy, Threat ROC-AUC, Threat PR-AUC, State MSE, and Shuffle Ablation
"""

import sys
import os
import hashlib
import json
import time
from pathlib import Path
import numpy as np
import pandas as pd
import torch
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    classification_report, f1_score, accuracy_score, balanced_accuracy_score,
    roc_auc_score, precision_recall_curve, auc, mean_squared_error, confusion_matrix
)

sys.path.insert(0, str(Path(__file__).parent.parent))
from src.world_model.model import WorldModel
from src.world_model.dataset import extract_temporal_sequences_from_parquet

def compute_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def main():
    print("=" * 90)
    print("STEP 1: SHIELDNET LOCKED WORLD MODEL RE-VERIFICATION")
    print("=" * 90)
    
    ckpt_path = Path("models/checkpoints/world_model_v1.pt")
    test_parquet = Path("data/processed/sequences_test.parquet")
    manifest_path = Path("models/checkpoints/feature_columns.json")
    
    # 1. Checkpoint Verification
    assert ckpt_path.exists(), f"Checkpoint {ckpt_path} missing!"
    ckpt_sha = compute_sha256(ckpt_path)
    ckpt_stat = ckpt_path.stat()
    ckpt_mtime = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(ckpt_stat.st_mtime))
    print(f"Checkpoint File:     {ckpt_path}")
    print(f"  SHA-256:           {ckpt_sha}")
    print(f"  Size:              {ckpt_stat.st_size:,} bytes")
    print(f"  Modified (UTC):    {ckpt_mtime}")
    
    # 2. Test Dataset Verification
    assert test_parquet.exists(), f"Test set {test_parquet} missing!"
    test_sha = compute_sha256(test_parquet)
    test_stat = test_parquet.stat()
    test_mtime = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(test_stat.st_mtime))
    print(f"\nTest Dataset File:   {test_parquet}")
    print(f"  SHA-256:           {test_sha}")
    print(f"  Size:              {test_stat.st_size:,} bytes")
    print(f"  Modified (UTC):    {test_mtime}")
    
    # 3. Load Manifest & Classes
    with open(manifest_path) as f:
        manifest = json.load(f)
    classes = manifest["classes"]
    le = LabelEncoder()
    le.fit(classes)
    
    # 4. Extract Test Sequences (L=3)
    print("\nExtracting test sequence transitions (L=3)...", flush=True)
    X_test, y_state, y_class, y_mitre = extract_temporal_sequences_from_parquet(
        str(test_parquet), label_encoder=le, context_length=3
    )
    print(f"Total Held-Out Test Transitions (N): {len(X_test):,}")
    print(f"Input Sequence Tensor Shape:          {X_test.shape}")
    
    # 5. Load Model Checkpoint
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = WorldModel(
        input_size=84,
        hidden_size=128,
        num_layers=2,
        num_classes=len(classes),
        num_mitre_stages=6,
        use_attention=True
    ).to(device)
    
    ckpt_dict = torch.load(ckpt_path, map_location=device, weights_only=False)
    model.load_state_dict(ckpt_dict["model_state_dict"])
    model.eval()
    print(f"Model initialized on device:          {device}")
    
    # 6. Run In-Distribution Inference
    batch_size = 512
    pred_classes = []
    pred_probs = []
    pred_states = []
    pred_mitre = []
    
    with torch.no_grad():
        for i in range(0, len(X_test), batch_size):
            bx = torch.from_numpy(X_test[i : i + batch_size]).to(device)
            out = model(bx)
            logits = out["class_logits"]
            probs = torch.softmax(logits, dim=-1).cpu().numpy()
            cls_idx = torch.argmax(logits, dim=-1).cpu().numpy()
            m_idx = torch.argmax(out["mitre_logits"], dim=-1).cpu().numpy()
            next_st = out["predicted_next_state"].cpu().numpy()
            
            pred_classes.extend(cls_idx)
            pred_probs.extend(probs)
            pred_states.extend(next_st)
            pred_mitre.extend(m_idx)
            
    y_pred = np.array(pred_classes)
    probs_arr = np.array(pred_probs)
    pred_st = np.array(pred_states)
    
    # 7. Compute Standard In-Distribution Metrics
    acc = accuracy_score(y_class, y_pred)
    bal_acc = balanced_accuracy_score(y_class, y_pred)
    macro_f1 = f1_score(y_class, y_pred, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_class, y_pred, average="weighted", zero_division=0)
    state_mse = mean_squared_error(y_state, pred_st)
    
    # Binary threat detection metrics (0: BENIGN, 1: Attack)
    y_bin_true = (y_class != 0).astype(int)
    p_attack = 1.0 - probs_arr[:, 0]
    roc_auc = roc_auc_score(y_bin_true, p_attack)
    prec_c, rec_c, _ = precision_recall_curve(y_bin_true, p_attack)
    pr_auc = auc(rec_c, prec_c)
    
    # False positive rate at default (0.50) and optimal (0.99)
    benign_mask = (y_class == 0)
    fpr_50 = float((p_attack[benign_mask] >= 0.50).sum() / benign_mask.sum())
    fpr_99 = float((p_attack[benign_mask] >= 0.99).sum() / benign_mask.sum())
    
    # Calibrated decision threshold (threat calibration)
    # Calibrated threshold: if p_attack > 0.05, pick highest attack class
    calibrated_preds = y_pred.copy()
    for idx, p in enumerate(probs_arr):
        if p_attack[idx] > 0.05:
            attack_logits = p[1:]
            calibrated_preds[idx] = np.argmax(attack_logits) + 1
        else:
            calibrated_preds[idx] = 0
    cal_macro_f1 = f1_score(y_class, calibrated_preds, average="macro", zero_division=0)
    cal_bal_acc = balanced_accuracy_score(y_class, calibrated_preds)
    
    # 8. 5-Seed Shuffle Permutation Ablation
    shuf_f1s, shuf_mses = [], []
    for shuf_seed in [42, 101, 2024, 777, 999]:
        np.random.seed(shuf_seed)
        X_shuf = X_test.copy()
        for k in range(len(X_shuf)):
            perm = np.random.permutation(3)
            X_shuf[k] = X_shuf[k, perm, :]
        with torch.no_grad():
            bx_s = torch.from_numpy(X_shuf).to(device)
            out_s = model(bx_s)
            ps_s = torch.argmax(out_s["class_logits"], dim=-1).cpu().numpy()
            pst_s = out_s["predicted_next_state"].cpu().numpy()
        shuf_f1s.append(f1_score(y_class, ps_s, average="macro", zero_division=0))
        shuf_mses.append(mean_squared_error(y_state, pst_s))
        
    shuf_f1_mean = float(np.mean(shuf_f1s))
    shuf_f1_std = float(np.std(shuf_f1s))
    shuf_mse_mean = float(np.mean(shuf_mses))
    shuf_mse_std = float(np.std(shuf_mses))
    mse_sigma = float((shuf_mse_mean - state_mse) / max(shuf_mse_std, 1e-9))
    
    print("\n" + "=" * 90)
    print("STEP 1: REPRODUCED & LOCKED BASELINE METRICS (N = 10,909)")
    print("=" * 90)
    print(f"Raw Multi-Class Macro F1:          {macro_f1:.4f}")
    print(f"Threat-Calibrated Macro F1:        {cal_macro_f1:.4f}")
    print(f"Classification Accuracy:           {acc*100:.2f}%")
    print(f"Balanced Accuracy (Raw):           {bal_acc*100:.2f}%")
    print(f"Balanced Accuracy (Calibrated):    {cal_bal_acc*100:.2f}%")
    print(f"Weighted F1-Score:                 {weighted_f1:.4f}")
    print(f"Threat Detection ROC-AUC:          {roc_auc:.4f}")
    print(f"Threat Detection PR-AUC:           {pr_auc:.4f}")
    print(f"False Positive Rate (tau=0.50):    {fpr_50*100:.2f}%")
    print(f"False Positive Rate (tau=0.99):    {fpr_99*100:.2f}%")
    print(f"Next-State Dynamics MSE:           {state_mse:.4f}")
    print(f"Shuffled Next-State MSE:           {shuf_mse_mean:.4f} +/- {shuf_mse_std:.4f} (Degradation: {mse_sigma:+.2f} sigma)")
    print("=" * 90)
    
    # Print per-class summary
    print(f"\nPer-Class Breakdown (13 Classes, N = {len(X_test):,}):")
    print(f"{'Class Name':26s} | {'Support N':10s} | {'Precision':10s} | {'Recall':10s} | {'F1-Score':10s}")
    print("-" * 75)
    cr = classification_report(y_class, y_pred, target_names=classes, output_dict=True, zero_division=0)
    for cname in classes:
        if cname in cr:
            row = cr[cname]
            print(f"{cname:26s} | {int(row['support']):10,d} | {row['precision']:10.4f} | {row['recall']:10.4f} | {row['f1-score']:10.4f}")
    print("-" * 75)
    
    # Save locked json
    locked_json = {
        "step": "Step 1 Verification",
        "timestamp_utc": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        "checkpoint_sha256": ckpt_sha,
        "test_parquet_sha256": test_sha,
        "test_support_n": len(X_test),
        "raw_macro_f1": round(macro_f1, 4),
        "calibrated_macro_f1": round(cal_macro_f1, 4),
        "accuracy": round(acc, 4),
        "balanced_accuracy_raw": round(bal_acc, 4),
        "balanced_accuracy_calibrated": round(cal_bal_acc, 4),
        "weighted_f1": round(weighted_f1, 4),
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "fpr_at_50": round(fpr_50, 4),
        "fpr_at_99": round(fpr_99, 4),
        "state_mse": round(state_mse, 4),
        "shuffled_mse": round(shuf_mse_mean, 4),
        "mse_sigma": round(mse_sigma, 2),
    }
    with open("models/checkpoints/step1_locked_baseline_verification.json", "w") as f:
        json.dump(locked_json, f, indent=2)
    print("\nSaved locked verification summary to: models/checkpoints/step1_locked_baseline_verification.json")

if __name__ == "__main__":
    main()
