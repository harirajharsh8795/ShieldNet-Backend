"""
NetGuard Exact Canonical Replication & Context Length Sweep (L in {3, 5, 7, 10}).

Uses the identical training pipeline as build_final_world_model.py:
- WorldModelLoss with lambda_class=1.0, lambda_mitre=0.25, lambda_order=0.5
- Balanced class weights computed via sklearn compute_class_weight (clipped to 50.0)
- AdamW (lr=1e-3, weight_decay=1e-4) + CosineAnnealingLR (T_max=10, eta_min=1e-5)
- Selection by best validation macro_f1
- 5-seed shuffle ablation using canonical seeds [42, 101, 2024, 777, 999] with RandomState(seed)
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
from src.world_model.trainer import train_one_epoch, evaluate_world_model

def set_seed(seed: int = 42):
    torch.manual_seed(seed)
    np.random.seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)

def evaluate_test_set_and_ablation(model: WorldModel, X_te: np.ndarray, y_st_te: np.ndarray, y_cls_te: np.ndarray, classes: list, L: int, device: torch.device):
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
    
    report = classification_report(y_cls_te, y_pred_cls, target_names=classes, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_cls_te, y_pred_cls, labels=range(13))
    
    # 5-Seed Shuffle Ablation using canonical RandomState seeds
    seeds = [42, 101, 2024, 777, 999]
    shuffled_accs = []
    shuffled_f1s = []
    
    for seed in seeds:
        rng = np.random.RandomState(seed)
        X_shuffled = X_te.copy()
        for sample_idx in range(len(X_shuffled)):
            perm = rng.permutation(L)
            X_shuffled[sample_idx] = X_shuffled[sample_idx][perm]
            
        with torch.no_grad():
            out_shuf = model(torch.from_numpy(X_shuffled).float().to(device))
            preds_shuf = np.argmax(out_shuf["class_logits"].cpu().numpy(), axis=-1)
            
        s_bacc = float(balanced_accuracy_score(y_cls_te, preds_shuf)) * 100.0
        s_mf1 = float(f1_score(y_cls_te, preds_shuf, average="macro", zero_division=0))
        shuffled_accs.append(s_bacc)
        shuffled_f1s.append(s_mf1)
        
    mean_shuffled_bacc = float(np.mean(shuffled_accs))
    std_shuffled_bacc = float(np.std(shuffled_accs))
    delta_bacc = bal_acc - mean_shuffled_bacc
    sigma_bacc = delta_bacc / (std_shuffled_bacc + 1e-9)
    
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
        },
        "shuffle_ablation": {
            "seeds": seeds,
            "intact_balanced_accuracy": round(bal_acc, 2),
            "shuffled_balanced_accuracies": [round(x, 2) for x in shuffled_accs],
            "shuffled_macro_f1s": [round(x, 4) for x in shuffled_f1s],
            "mean_shuffled_bacc": round(mean_shuffled_bacc, 2),
            "std_shuffled_bacc": round(std_shuffled_bacc, 2),
            "drop_percent": round(delta_bacc, 2),
            "sigma": round(sigma_bacc, 2)
        }
    }

def train_canonical_L(L: int, classes: list, le: LabelEncoder, epochs: int = 10, batch_size: int = 256):
    set_seed(42)
    device = torch.device("cpu")
    
    train_path = str(PROJECT_ROOT / "data" / "processed" / "sequences_train.parquet")
    val_path = str(PROJECT_ROOT / "data" / "processed" / "sequences_val.parquet")
    test_path = str(PROJECT_ROOT / "data" / "processed" / "sequences_test.parquet")
    
    print(f"\n[Extracting Sequences for L={L}]...")
    X_tr, y_st_tr, y_cls_tr, y_mit_tr = extract_temporal_sequences_from_parquet(train_path, le, context_length=L)
    X_va, y_st_va, y_cls_va, y_mit_va = extract_temporal_sequences_from_parquet(val_path, le, context_length=L)
    X_te, y_st_te, y_cls_te, y_mit_te = extract_temporal_sequences_from_parquet(test_path, le, context_length=L)
    
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
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs, eta_min=1e-5)
    
    best_val_f1 = -1.0
    best_state_dict = None
    start_t = time.time()
    
    for ep in range(1, epochs + 1):
        tr = train_one_epoch(model, train_loader, optimizer, criterion, device)
        val = evaluate_world_model(model, val_loader, criterion, device, classes)
        scheduler.step()
        
        is_best = val["macro_f1"] > best_val_f1
        if is_best:
            best_val_f1 = val["macro_f1"]
            best_state_dict = {k: v.cpu().clone() for k, v in model.state_dict().items()}
        print(f"  Epoch {ep:2d}/{epochs:2d} | Train Loss: {tr['total_loss']:.4f} | Val F1: {val['macro_f1']:.4f} | Val BalAcc: {val['balanced_accuracy']*100:.2f}% {'[*BEST*]' if is_best else ''}")
        
    train_time = time.time() - start_t
    
    # Save checkpoint
    ckpt_path = PROJECT_ROOT / "models" / "checkpoints" / f"exact_canonical_L{L}.pt"
    torch.save({
        "context_length": L,
        "input_size": 84,
        "hidden_size": 128,
        "num_layers": 2,
        "num_classes": len(classes),
        "num_mitre_stages": 6,
        "model_state_dict": best_state_dict,
        "training_time_seconds": train_time,
        "timestamp_utc": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    }, ckpt_path)
    
    model.load_state_dict(best_state_dict)
    eval_res = evaluate_test_set_and_ablation(model, X_te, y_st_te, y_cls_te, classes, L=L, device=device)
    eval_res["context_length"] = L
    eval_res["checkpoint_path"] = f"models/checkpoints/exact_canonical_L{L}.pt"
    eval_res["training_time_seconds"] = round(train_time, 2)
    
    print(f"--> Finished L={L}: Macro-F1: {eval_res['macro_f1']:.4f} | BalAcc: {eval_res['balanced_accuracy']:.2f}% | Threat ROC-AUC: {eval_res['threat_roc_auc']:.4f} | Drop: {eval_res['shuffle_ablation']['drop_percent']:.2f}% (+{eval_res['shuffle_ablation']['sigma']:.2f} sigma)")
    return eval_res

def main():
    print("=" * 85)
    print("NETGUARD EXACT CANONICAL REPLICATION & CONTEXT LENGTH SWEEP")
    print(f"Timestamp (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    print("=" * 85)
    
    with open(PROJECT_ROOT / "models" / "checkpoints" / "feature_columns.json") as f:
        manifest = json.load(f)
    classes = manifest["classes"]
    le = LabelEncoder()
    le.fit(classes)
    
    device = torch.device("cpu")
    
    # 1. Evaluate Locked Baseline world_model_v1.pt
    print("\n[Evaluating Locked Baseline world_model_v1.pt with canonical 5 seeds]...")
    test_path = str(PROJECT_ROOT / "data" / "processed" / "sequences_test.parquet")
    X_te3, y_st_te3, y_cls_te3, _ = extract_temporal_sequences_from_parquet(test_path, le, context_length=3)
    
    locked_ckpt = torch.load(PROJECT_ROOT / "models" / "checkpoints" / "world_model_v1.pt", map_location=device, weights_only=False)
    locked_model = WorldModel(input_size=84, hidden_size=128, num_layers=2, num_classes=13, num_mitre_stages=6).to(device)
    locked_model.load_state_dict(locked_ckpt["model_state_dict"])
    locked_eval = evaluate_test_set_and_ablation(locked_model, X_te3, y_st_te3, y_cls_te3, classes, L=3, device=device)
    
    results = {
        "world_model_v1_locked": locked_eval
    }
    
    # 2. Train exact canonical models for L in {3, 5, 7, 10}
    for L in [3, 5, 7, 10]:
        res_L = train_canonical_L(L=L, classes=classes, le=le, epochs=10)
        results[f"exact_canonical_L{L}"] = res_L
        
    master_path = PROJECT_ROOT / "models" / "checkpoints" / "canonical_replicate_and_sweep.json"
    with open(master_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nMaster summary saved to: {master_path}")

if __name__ == "__main__":
    main()
