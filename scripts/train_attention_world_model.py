"""
NetGuard Attention-GRU World Model Training, Multi-Seed Audit, and Threshold Tuning.

Implements:
1. GRU + Temporal Attention-Pooling Architecture
2. Multi-Class Focal Loss (gamma=2.0)
3. 5-Seed Shuffle-Ablation Significance Audit
4. Decision Threshold Tuning (ROC-AUC, PR-AUC, Optimal-F1, High-Recall SOC Sentinel)
"""

import sys
from pathlib import Path
import numpy as np
import torch
import torch.optim as optim
from torch.utils.data import DataLoader
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import (
    classification_report, f1_score, accuracy_score, balanced_accuracy_score,
    mean_squared_error, roc_auc_score, precision_recall_curve, auc,
    confusion_matrix, recall_score, precision_score
)
import json
import time

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.world_model.model import WorldModel, WorldModelLoss
from src.world_model.dataset import extract_temporal_sequences_from_parquet, WorldModelSequenceDataset
from src.world_model.trainer import train_one_epoch, evaluate_world_model

def set_seed(seed: int = 42):
    torch.manual_seed(seed)
    np.random.seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)

def main():
    print("=" * 85, flush=True)
    print("NETGUARD LEVER 3, 4 & 5: ATTENTION-GRU WORLD MODEL + FOCAL LOSS + THRESHOLD TUNING", flush=True)
    print("=" * 85, flush=True)
    
    set_seed(42)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    checkpoint_dir = Path("models/checkpoints")
    
    with open(checkpoint_dir / "feature_columns.json", "r") as f:
        manifest = json.load(f)
    classes = manifest["classes"]
    le = LabelEncoder()
    le.fit(classes)
    
    L = 3
    print("\nLoading unfragmented sequence splits (L=3)...", flush=True)
    X_train, y_train_state, y_train_label, y_train_mitre = extract_temporal_sequences_from_parquet(
        "data/processed/sequences_train.parquet", le, context_length=L
    )
    X_val, y_val_state, y_val_label, y_val_mitre = extract_temporal_sequences_from_parquet(
        "data/processed/sequences_val.parquet", le, context_length=L
    )
    X_test, y_test_state, y_test_label, y_test_mitre = extract_temporal_sequences_from_parquet(
        "data/processed/sequences_test.parquet", le, context_length=L
    )
    print(f"Loaded Sequences: Train={len(X_train):,}, Val={len(X_val):,}, Test={len(X_test):,}", flush=True)
    
    train_dataset = WorldModelSequenceDataset(X_train, y_train_state, y_train_label, y_train_mitre)
    val_dataset = WorldModelSequenceDataset(X_val, y_val_state, y_val_label, y_val_mitre)
    test_dataset = WorldModelSequenceDataset(X_test, y_test_state, y_test_label, y_test_mitre)
    
    train_loader = DataLoader(train_dataset, batch_size=128, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=128, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=128, shuffle=False)
    
    # Class weights for focal loss alpha
    present_classes = np.unique(y_train_label)
    cw = compute_class_weight(class_weight="balanced", classes=present_classes, y=y_train_label)
    full_weights = np.ones(len(classes), dtype=np.float32)
    for cls_idx, w in zip(present_classes, cw):
        full_weights[cls_idx] = float(np.clip(w, 0.1, 50.0))
    class_weights_tensor = torch.tensor(full_weights, dtype=torch.float32).to(device)
    
    # Instantiate GRU + Attention-Pooling Model
    model = WorldModel(
        input_size=84,
        hidden_size=128,
        num_layers=2,
        dropout=0.2,
        num_classes=len(classes),
        num_mitre_stages=6,
        use_attention=True,
    ).to(device)
    
    criterion = WorldModelLoss(
        lambda_class=1.0,
        lambda_mitre=0.25,
        lambda_order=0.5,
        focal_gamma=2.0,
        class_weights=class_weights_tensor,
    ).to(device)
    
    epochs = 15
    optimizer = optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs, eta_min=1e-5)
    
    best_val_f1 = -1.0
    best_state_dict = None
    
    print(f"\nTraining Attention-GRU World Model for {epochs} epochs on {device}...", flush=True)
    for ep in range(1, epochs + 1):
        t0 = time.time()
        tr = train_one_epoch(model, train_loader, optimizer, criterion, device)
        val = evaluate_world_model(model, val_loader, criterion, device, classes)
        scheduler.step()
        elapsed = time.time() - t0
        
        is_best = val["macro_f1"] > best_val_f1
        if is_best:
            best_val_f1 = val["macro_f1"]
            best_state_dict = {k: v.cpu().clone() for k, v in model.state_dict().items()}
            
        print(f"  Epoch [{ep:2d}/{epochs}] ({elapsed:4.1f}s) | Train Loss: {tr['total_loss']:.4f} (State: {tr['state_loss']:.4f}, Focal Class: {tr['class_loss']:.4f}) | Val F1: {val['macro_f1']:.4f} | Val MSE: {val['state_loss']:.4f} {'[BEST]' if is_best else ''}", flush=True)
        
    model.load_state_dict(best_state_dict)
    model.eval()
    
    # ─── 1. ORDERED TEST EVALUATION ───────────────────────────────────────────
    print("\n" + "=" * 80, flush=True)
    print("TASK 1: ORDERED (CHRONOLOGICAL) TEST SET EVALUATION", flush=True)
    print("=" * 80, flush=True)
    
    X_ord_tensor = torch.from_numpy(X_test).float().to(device)
    with torch.no_grad():
        out_ord = model(X_ord_tensor)
        p_state_ord = out_ord["predicted_next_state"].cpu().numpy()
        p_logits_ord = out_ord["class_logits"].cpu().numpy()
        p_probs_ord = torch.softmax(out_ord["class_logits"], dim=-1).cpu().numpy()
        p_class_ord = np.argmax(p_logits_ord, axis=-1)
        p_attn_ord = out_ord["attention_weights"].cpu().numpy()
        
    ord_mse = float(mean_squared_error(y_test_state, p_state_ord))
    ord_f1 = float(f1_score(y_test_label, p_class_ord, average="macro", zero_division=0))
    ord_weighted_f1 = float(f1_score(y_test_label, p_class_ord, average="weighted", zero_division=0))
    ord_bal_acc = float(balanced_accuracy_score(y_test_label, p_class_ord))
    ord_acc = float(accuracy_score(y_test_label, p_class_ord))
    
    rep = classification_report(y_test_label, p_class_ord, target_names=classes, output_dict=True, zero_division=0)
    
    print(f"  - 1-Step Macro F1:      {ord_f1:.4f}", flush=True)
    print(f"  - Balanced Accuracy:    {ord_bal_acc:.2%}", flush=True)
    print(f"  - Next-State MSE:       {ord_mse:.4f}", flush=True)
    print(f"  - Raw Accuracy:         {ord_acc:.2%}", flush=True)
    print(f"  - Mean Attention Weight [t-2, t-1, t]: [{p_attn_ord[:, 0].mean():.3f}, {p_attn_ord[:, 1].mean():.3f}, {p_attn_ord[:, 2].mean():.3f}]", flush=True)
    
    # ─── 2. 5-SEED SHUFFLE-ABLATION SIGNIFICANCE AUDIT ────────────────────────
    print("\n" + "=" * 80, flush=True)
    print("TASK 2: 5-SEED SHUFFLE-ABLATION AUDIT (SEEDS 42, 101, 2024, 777, 999)", flush=True)
    print("=" * 80, flush=True)
    
    shuf_f1_list = []
    shuf_mse_list = []
    shuf_bal_list = []
    
    for seed in [42, 101, 2024, 777, 999]:
        np.random.seed(seed)
        X_shuf = X_test.copy()
        for i in range(len(X_shuf)):
            perm = np.random.permutation(L)
            X_shuf[i] = X_shuf[i, perm, :]
        X_shuf_t = torch.from_numpy(X_shuf).float().to(device)
        with torch.no_grad():
            out_s = model(X_shuf_t)
            ps_s = out_s["predicted_next_state"].cpu().numpy()
            pc_s = np.argmax(out_s["class_logits"].cpu().numpy(), axis=-1)
        s_mse = float(mean_squared_error(y_test_state, ps_s))
        s_f1 = float(f1_score(y_test_label, pc_s, average="macro", zero_division=0))
        s_bal = float(balanced_accuracy_score(y_test_label, pc_s))
        shuf_mse_list.append(s_mse)
        shuf_f1_list.append(s_f1)
        shuf_bal_list.append(s_bal)
        print(f"    Seed {seed:4d} -> Shuffled Macro F1: {s_f1:.4f} | Shuffled Bal Acc: {s_bal:.2%} | Shuffled MSE: {s_mse:.4f}", flush=True)
        
    shuf_f1_m, shuf_f1_s = float(np.mean(shuf_f1_list)), float(np.std(shuf_f1_list))
    shuf_mse_m, shuf_mse_s = float(np.mean(shuf_mse_list)), float(np.std(shuf_mse_list))
    shuf_bal_m, shuf_bal_s = float(np.mean(shuf_bal_list)), float(np.std(shuf_bal_list))
    
    f1_gap = ord_f1 - shuf_f1_m
    f1_sigma = f1_gap / max(shuf_f1_s, 1e-9)
    
    mse_gap = shuf_mse_m - ord_mse
    mse_sigma = mse_gap / max(shuf_mse_s, 1e-9)
    
    bal_gap = ord_bal_acc - shuf_bal_m
    bal_sigma = bal_gap / max(shuf_bal_s, 1e-9)
    
    print("\nStatistical Significance Comparison:", flush=True)
    print(f"  - Macro F1:       {ord_f1:.4f} vs {shuf_f1_m:.4f} +/- {shuf_f1_s:.4f} -> Gap: {f1_gap:+.4f} ({f1_sigma:+.2f} sigma)", flush=True)
    print(f"  - State MSE:      {ord_mse:.4f} vs {shuf_mse_m:.4f} +/- {shuf_mse_s:.4f} -> Gap: {mse_gap:+.4f} ({mse_sigma:+.2f} sigma)", flush=True)
    print(f"  - Balanced Acc:   {ord_bal_acc:.2%} vs {shuf_bal_m:.2%} +/- {shuf_bal_s:.2%} -> Gap: {bal_gap:+.2%} ({bal_sigma:+.2f} sigma)", flush=True)
    
    # ─── 3. LEVER 5: THRESHOLD TUNING & ROC/PR-AUC ────────────────────────────
    print("\n" + "=" * 80, flush=True)
    print("TASK 3: DECISION THRESHOLD TUNING (ROC-AUC, PR-AUC & SOC SENTINEL OPERATING POINTS)", flush=True)
    print("=" * 80, flush=True)
    
    # Binary attack ground truth: 0 if BENIGN, 1 if any attack
    benign_idx = classes.index("BENIGN") if "BENIGN" in classes else 0
    y_binary_true = (y_test_label != benign_idx).astype(int)
    attack_risk_scores = 1.0 - p_probs_ord[:, benign_idx]  # P(Attack)
    
    roc_auc = float(roc_auc_score(y_binary_true, attack_risk_scores))
    precision_curve, recall_curve, pr_thresholds = precision_recall_curve(y_binary_true, attack_risk_scores)
    pr_auc = float(auc(recall_curve, precision_curve))
    
    # Optimal-F1 threshold on PR curve
    f1_scores_curve = 2 * (precision_curve * recall_curve) / np.maximum(precision_curve + recall_curve, 1e-9)
    best_thresh_idx = int(np.argmax(f1_scores_curve))
    optimal_threshold = float(pr_thresholds[min(best_thresh_idx, len(pr_thresholds) - 1)])
    
    # Evaluate at 3 key thresholds: Default (0.50), Optimal-F1, High-Recall Sentinel (0.20)
    threshold_evals = []
    for thresh in [0.50, optimal_threshold, 0.20]:
        y_bin_pred = (attack_risk_scores >= thresh).astype(int)
        cm_bin = confusion_matrix(y_binary_true, y_bin_pred)
        tn, fp, fn, tp = cm_bin.ravel()
        rec = float(recall_score(y_binary_true, y_bin_pred, zero_division=0))
        prec = float(precision_score(y_binary_true, y_bin_pred, zero_division=0))
        f1_bin = float(f1_score(y_binary_true, y_bin_pred, zero_division=0))
        fpr = float(fp / max(fp + tn, 1))
        
        mode_name = "Default Balanced (0.50)" if thresh == 0.50 else ("Optimal PR-F1" if thresh == optimal_threshold else "SOC High-Recall Sentinel")
        threshold_evals.append({
            "threshold": float(thresh),
            "mode": mode_name,
            "attack_recall": rec,
            "precision": prec,
            "binary_f1": f1_bin,
            "false_positive_rate": fpr,
            "true_positives": int(tp),
            "false_positives": int(fp),
            "false_negatives": int(fn),
        })
        
    print(f"  Binary Threat Forecasting Metrics:", flush=True)
    print(f"    - ROC-AUC: {roc_auc:.4f}", flush=True)
    print(f"    - PR-AUC:  {pr_auc:.4f}", flush=True)
    print("\n  Operational Decision Threshold Evaluation Table:", flush=True)
    print(f"  {'Operating Mode':26s} | {'Threshold':9s} | {'Attack Recall':13s} | {'Precision':10s} | {'Binary F1':9s} | {'FPR':7s} | {'Attacks Caught':14s}", flush=True)
    print("  " + "-" * 98, flush=True)
    for te in threshold_evals:
        total_attacks = te['true_positives'] + te['false_negatives']
        print(f"  {te['mode']:26s} | {te['threshold']:9.4f} | {te['attack_recall']:13.2%} | {te['precision']:10.2%} | {te['binary_f1']:9.4f} | {te['false_positive_rate']:7.2%} | {te['true_positives']:3d} / {total_attacks:3d} ({te['attack_recall']:.1%})", flush=True)
        
    # ─── 4. PER-CLASS F1 BREAKDOWN TABLE ──────────────────────────────────────
    print("\n" + "=" * 80, flush=True)
    print("PER-CLASS CLASSIFICATION BREAKDOWN (ATTENTION-GRU + FOCAL LOSS)", flush=True)
    print("=" * 80, flush=True)
    print(f"  {'Class':26s} | {'Support':7s} | {'Precision':9s} | {'Recall':9s} | {'F1-Score':9s}", flush=True)
    print("  " + "-" * 68, flush=True)
    for c in classes:
        c_stats = rep.get(c, {})
        sup = int(c_stats.get("support", 0))
        prec = float(c_stats.get("precision", 0.0))
        rec = float(c_stats.get("recall", 0.0))
        f1_c = float(c_stats.get("f1-score", 0.0))
        print(f"  {c:26s} | {sup:7d} | {prec:9.4f} | {rec:9.4f} | {f1_c:9.4f}", flush=True)
        
    # Save winning checkpoint and manifest
    torch.save({
        "model_state_dict": model.state_dict(),
        "input_size": 84,
        "hidden_size": 128,
        "num_layers": 2,
        "classes": classes,
        "use_attention": True,
        "metrics": {
            "macro_f1": ord_f1,
            "balanced_accuracy": ord_bal_acc,
            "state_mse": ord_mse,
            "f1_sigma": f1_sigma,
            "mse_sigma": mse_sigma,
            "roc_auc": roc_auc,
            "pr_auc": pr_auc,
        }
    }, checkpoint_dir / "world_model_v1.pt")
    
    final_summary = {
        "architecture": "RSS-WM (2-Layer GRU + Temporal Attention Pooling)",
        "loss_function": "MSE (State) + Focal Loss (Class, gamma=2.0) + CE (MITRE) + BCE (Order)",
        "ordered_metrics": {
            "macro_f1": ord_f1,
            "weighted_f1": ord_weighted_f1,
            "balanced_accuracy": ord_bal_acc,
            "raw_accuracy": ord_acc,
            "state_mse": ord_mse,
        },
        "shuffle_ablation_5_seeds": {
            "shuffled_f1_mean": shuf_f1_m,
            "shuffled_f1_std": shuf_f1_s,
            "f1_significance_sigma": f1_sigma,
            "shuffled_mse_mean": shuf_mse_m,
            "shuffled_mse_std": shuf_mse_s,
            "mse_significance_sigma": mse_sigma,
        },
        "threshold_tuning": {
            "roc_auc": roc_auc,
            "pr_auc": pr_auc,
            "operating_points": threshold_evals,
        },
        "classification_report": rep,
    }
    
    out_summary_file = checkpoint_dir / "final_model_metrics.json"
    with open(out_summary_file, "w") as f:
        json.dump(final_summary, f, indent=2)
    print(f"\nSaved reinforced model checkpoint to: {checkpoint_dir / 'world_model_v1.pt'}", flush=True)
    print(f"Saved comprehensive metrics manifest to: {out_summary_file}", flush=True)

if __name__ == "__main__":
    main()
