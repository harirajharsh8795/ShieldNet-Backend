"""
NetGuard Canonical Context Length Sweep & Direct Head-to-Head Audit.

Uses the EXACT canonical training pipeline of world_model_v1.pt:
- WorldModelLoss with lambda_class=1.0, lambda_mitre=0.25, lambda_order=0.5
- train_one_epoch with fast vectorized negative-permutation contrastive order training
- Balanced class weights computed via sklearn compute_class_weight
- Epochs: 10, AdamW lr=1e-3, weight_decay=1e-4, seed=42
- Sweeps context length L in {3, 5, 7, 10}
- Direct side-by-side comparison against locked baseline world_model_v1.pt on sequences_test.parquet
"""

import sys, os, time, json
from pathlib import Path
import numpy as np
import pandas as pd
import torch
import torch.optim as optim
from torch.utils.data import DataLoader
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import (
    classification_report, f1_score, accuracy_score, balanced_accuracy_score,
    roc_auc_score, confusion_matrix
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.world_model.model import WorldModel, WorldModelLoss
from src.world_model.dataset import extract_temporal_sequences_from_parquet, WorldModelSequenceDataset
from src.world_model.trainer import train_one_epoch

def set_seed(seed: int = 42):
    torch.manual_seed(seed)
    np.random.seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)

def eval_model_checkpoint(model: WorldModel, X_te: np.ndarray, y_st_te: np.ndarray, y_cls_te: np.ndarray, classes: list, device: torch.device):
    model.eval()
    with torch.no_grad():
        out = model(torch.from_numpy(X_te).float().to(device))
        cls_logits = out["class_logits"].cpu().numpy()
        state_preds = out["predicted_next_state"].cpu().numpy()
        
    y_pred_cls = np.argmax(cls_logits, axis=-1)
    
    macro_f1 = float(f1_score(y_cls_te, y_pred_cls, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_cls_te, y_pred_cls, average="weighted", zero_division=0))
    bal_acc = float(balanced_accuracy_score(y_cls_te, y_pred_cls)) * 100.0
    acc = float(accuracy_score(y_cls_te, y_pred_cls)) * 100.0
    
    threat_true = (y_cls_te > 0).astype(int)
    threat_probs = 1.0 - torch.softmax(torch.from_numpy(cls_logits), dim=-1)[:, 0].numpy()
    threat_roc_auc = float(roc_auc_score(threat_true, threat_probs))
    next_state_mse = float(np.mean((state_preds - y_st_te) ** 2))
    
    cm = confusion_matrix(y_cls_te, y_pred_cls, labels=range(13))
    report = classification_report(y_cls_te, y_pred_cls, target_names=classes, output_dict=True, zero_division=0)
    
    return {
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "balanced_accuracy": round(bal_acc, 2),
        "accuracy": round(acc, 2),
        "threat_roc_auc": round(threat_roc_auc, 4),
        "next_state_mse": round(next_state_mse, 6),
        "confusion_matrix": cm.tolist(),
        "per_class": {
            c: {
                "precision": round(report[c]["precision"], 4),
                "recall": round(report[c]["recall"], 4),
                "f1": round(report[c]["f1-score"], 4),
                "support": int(report[c]["support"])
            }
            for c in classes
        }
    }

def run_shuffle_ablation_for_model(model: WorldModel, X_te: np.ndarray, y_cls_te: np.ndarray, L: int, n_seeds: int = 5):
    device = next(model.parameters()).device
    model.eval()
    
    with torch.no_grad():
        out = model(torch.from_numpy(X_te).float().to(device))
        preds_intact = np.argmax(out["class_logits"].cpu().numpy(), axis=-1)
    intact_bal_acc = balanced_accuracy_score(y_cls_te, preds_intact) * 100.0
    intact_macro_f1 = f1_score(y_cls_te, preds_intact, average="macro", zero_division=0)
    
    shuffled_baccs = []
    shuffled_mf1s = []
    
    for seed in range(42, 42 + n_seeds):
        np.random.seed(seed)
        X_shuf = np.zeros_like(X_te)
        for i in range(len(X_te)):
            perm = np.random.permutation(L)
            X_shuf[i] = X_te[i, perm, :]
        with torch.no_grad():
            out_s = model(torch.from_numpy(X_shuf).float().to(device))
            preds_s = np.argmax(out_s["class_logits"].cpu().numpy(), axis=-1)
        shuffled_baccs.append(balanced_accuracy_score(y_cls_te, preds_s) * 100.0)
        shuffled_mf1s.append(f1_score(y_cls_te, preds_s, average="macro", zero_division=0))
        
    mean_bacc = float(np.mean(shuffled_baccs))
    std_bacc = float(np.std(shuffled_baccs))
    drop = intact_bal_acc - mean_bacc
    sigma = drop / (std_bacc + 1e-6)
    
    return {
        "intact_balanced_accuracy": round(intact_bal_acc, 2),
        "intact_macro_f1": round(intact_macro_f1, 4),
        "shuffled_baccs": [round(x, 2) for x in shuffled_baccs],
        "shuffled_mf1s": [round(x, 4) for x in shuffled_mf1s],
        "shuffled_mean_bacc": round(mean_bacc, 2),
        "shuffled_std_bacc": round(std_bacc, 2),
        "drop_percent": round(drop, 2),
        "sigma": round(sigma, 2)
    }

def train_canonical_model_for_L(L: int, classes: list, le: LabelEncoder, epochs: int = 10, batch_size: int = 256):
    set_seed(42)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    train_path = str(PROJECT_ROOT / "data" / "processed" / "sequences_train.parquet")
    val_path = str(PROJECT_ROOT / "data" / "processed" / "sequences_val.parquet")
    test_path = str(PROJECT_ROOT / "data" / "processed" / "sequences_test.parquet")
    
    X_tr, y_st_tr, y_cls_tr, y_mit_tr = extract_temporal_sequences_from_parquet(train_path, le, context_length=L)
    X_va, y_st_va, y_cls_va, y_mit_va = extract_temporal_sequences_from_parquet(val_path, le, context_length=L)
    X_te, y_st_te, y_cls_te, y_mit_te = extract_temporal_sequences_from_parquet(test_path, le, context_length=L)
    
    # Canonical balanced class weights
    present_classes = np.unique(y_cls_tr)
    cw = compute_class_weight(class_weight="balanced", classes=present_classes, y=y_cls_tr)
    full_weights = np.ones(len(classes), dtype=np.float32)
    for cls_idx, w in zip(present_classes, cw):
        full_weights[cls_idx] = float(np.clip(w, 0.1, 50.0))
    class_weights_tensor = torch.tensor(full_weights, dtype=torch.float32).to(device)
    
    train_ds = WorldModelSequenceDataset(X_tr, y_st_tr, y_cls_tr, y_mit_tr)
    val_ds = WorldModelSequenceDataset(X_va, y_st_va, y_cls_va, y_mit_va)
    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False)
    
    model = WorldModel(
        input_size=84,
        hidden_size=128,
        num_layers=2,
        dropout=0.2,
        num_classes=len(classes),
        num_mitre_stages=6,
        use_attention=True
    ).to(device)
    
    criterion = WorldModelLoss(
        lambda_class=1.0,
        lambda_mitre=0.25,
        lambda_order=0.5,
        focal_gamma=0.0,
        class_weights=class_weights_tensor
    ).to(device)
    
    optimizer = optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    
    best_val_loss = float("inf")
    best_weights = None
    start_t = time.time()
    
    for epoch in range(1, epochs + 1):
        tr_metrics = train_one_epoch(model, train_loader, optimizer, criterion, device)
        
        # Validation
        model.eval()
        va_loss = 0.0
        n_val = 0
        with torch.no_grad():
            for b_X, b_st, b_cls, b_mit in val_loader:
                b_X, b_st, b_cls, b_mit = b_X.to(device), b_st.to(device), b_cls.to(device), b_mit.to(device)
                t_ord = torch.ones(len(b_X), device=device)
                out_v = model(b_X)
                lv = criterion(out_v, b_st, b_cls, b_mit, t_ord)
                va_loss += lv["total_loss"].item() * len(b_X)
                n_val += len(b_X)
        va_loss /= max(n_val, 1)
        
        if va_loss < best_val_loss:
            best_val_loss = va_loss
            best_weights = {k: v.cpu().clone() for k, v in model.state_dict().items()}
            
    train_time = time.time() - start_t
    
    # Save canonical checkpoint
    ckpt_path = PROJECT_ROOT / "models" / "checkpoints" / f"canonical_world_model_L{L}.pt"
    torch.save({
        "context_length": L,
        "input_size": 84,
        "hidden_size": 128,
        "num_layers": 2,
        "num_classes": len(classes),
        "num_mitre_stages": 6,
        "model_state_dict": best_weights,
        "training_time_seconds": train_time,
        "timestamp_utc": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }, ckpt_path)
    
    model.load_state_dict(best_weights)
    eval_metrics = eval_model_checkpoint(model, X_te, y_st_te, y_cls_te, classes, device)
    ablation = run_shuffle_ablation_for_model(model, X_te, y_cls_te, L=L, n_seeds=5)
    
    eval_metrics["context_length"] = L
    eval_metrics["checkpoint_path"] = f"models/checkpoints/canonical_world_model_L{L}.pt"
    eval_metrics["training_time_seconds"] = round(train_time, 2)
    eval_metrics["shuffle_ablation"] = ablation
    
    metric_path = PROJECT_ROOT / "models" / "checkpoints" / f"canonical_metrics_L{L}.json"
    with open(metric_path, "w") as f:
        json.dump(eval_metrics, f, indent=2)
        
    print(f"--> Canonical L={L}: Macro-F1={eval_metrics['macro_f1']:.4f} | BalAcc={eval_metrics['balanced_accuracy']:.2f}% | Threat ROC-AUC={eval_metrics['threat_roc_auc']:.4f} | Drop={ablation['drop_percent']:.2f}% (+{ablation['sigma']:.2f} sigma)")
    
    return eval_metrics, X_te, y_st_te, y_cls_te, model

def main():
    print("=" * 85)
    print("NETGUARD CANONICAL CONTEXT LENGTH SWEEP & BENCHMARK RECONCILIATION")
    print(f"Timestamp (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    print("=" * 85)
    
    with open(PROJECT_ROOT / "models" / "checkpoints" / "feature_columns.json") as f:
        manifest = json.load(f)
    classes = manifest["classes"]
    le = LabelEncoder()
    le.fit(classes)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    # 1. Evaluate Locked Baseline world_model_v1.pt on L=3
    print("\n[1/5] Evaluating Locked Baseline world_model_v1.pt...")
    test_path = str(PROJECT_ROOT / "data" / "processed" / "sequences_test.parquet")
    X_te3, y_st_te3, y_cls_te3, _ = extract_temporal_sequences_from_parquet(test_path, le, context_length=3)
    
    locked_ckpt = torch.load(PROJECT_ROOT / "models" / "checkpoints" / "world_model_v1.pt", map_location=device, weights_only=False)
    locked_model = WorldModel(input_size=84, hidden_size=128, num_layers=2, num_classes=13, num_mitre_stages=6).to(device)
    locked_model.load_state_dict(locked_ckpt["model_state_dict"])
    
    locked_metrics = eval_model_checkpoint(locked_model, X_te3, y_st_te3, y_cls_te3, classes, device)
    locked_ablation = run_shuffle_ablation_for_model(locked_model, X_te3, y_cls_te3, L=3, n_seeds=5)
    locked_metrics["shuffle_ablation"] = locked_ablation
    
    # 2. Run Canonical Sweep for L in {3, 5, 7, 10}
    sweep_results = {"world_model_v1_locked": locked_metrics}
    
    for L in [3, 5, 7, 10]:
        print(f"\n[Running Canonical Sweep for L={L}]...")
        m, _, _, _, _ = train_canonical_model_for_L(L=L, classes=classes, le=le, epochs=10)
        sweep_results[f"canonical_L{L}"] = m
        
    master_summary_path = PROJECT_ROOT / "models" / "checkpoints" / "canonical_context_length_sweep_master.json"
    with open(master_summary_path, "w") as f:
        json.dump(sweep_results, f, indent=2)
    print(f"\nMaster sweep summary saved to: {master_summary_path}")
    print("=" * 85)

if __name__ == "__main__":
    main()
