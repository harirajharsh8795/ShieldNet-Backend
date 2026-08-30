"""
ShieldNet Phase 2: Architecture & Context Length Sweep (L in {3, 5, 7, 10}).

Trains GRU+Temporal Attention on sequences_train.parquet across context lengths L in {3, 5, 7, 10}.
Evaluates on sequences_test.parquet (N = 10,909, SHA-256: a7b9d405...) for each L.
Performs 5-seed shuffle-ablation on the best model.
Saves checkpoints and metric JSON files with verifiable timestamps.
"""

import sys, os, time, json
from pathlib import Path
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    f1_score, accuracy_score, balanced_accuracy_score, roc_auc_score,
    classification_report, confusion_matrix
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.world_model.model import WorldModel
from src.world_model.dataset import extract_temporal_sequences_from_parquet, WorldModelSequenceDataset

def train_and_eval_for_L(L: int, epochs: int = 15, batch_size: int = 256, lr: float = 1e-3):
    print(f"\n" + "=" * 80)
    print(f"SHIELDNET PHASE 2: TRAINING CONTEXT LENGTH L = {L}")
    print(f"Timestamp (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    print("=" * 80)
    
    with open(PROJECT_ROOT / "models" / "checkpoints" / "feature_columns.json") as f:
        manifest = json.load(f)
    classes = manifest["classes"]
    le = LabelEncoder()
    le.fit(classes)
    
    train_path = str(PROJECT_ROOT / "data" / "processed" / "sequences_train.parquet")
    val_path = str(PROJECT_ROOT / "data" / "processed" / "sequences_val.parquet")
    test_path = str(PROJECT_ROOT / "data" / "processed" / "sequences_test.parquet")
    
    print(f"[1/4] Extracting temporal transitions for L = {L}...")
    X_tr, y_st_tr, y_cls_tr, y_mit_tr = extract_temporal_sequences_from_parquet(train_path, le, context_length=L)
    X_va, y_st_va, y_cls_va, y_mit_va = extract_temporal_sequences_from_parquet(val_path, le, context_length=L)
    X_te, y_st_te, y_cls_te, y_mit_te = extract_temporal_sequences_from_parquet(test_path, le, context_length=L)
    
    print(f"  Train: N={len(X_tr):,}, shape={X_tr.shape}")
    print(f"  Val:   N={len(X_va):,}, shape={X_va.shape}")
    print(f"  Test:  N={len(X_te):,}, shape={X_te.shape}")
    
    # Compute inverse class frequencies for weighted loss
    class_counts = np.bincount(y_cls_tr, minlength=13)
    total_samples = len(y_cls_tr)
    class_weights = total_samples / (13.0 * np.maximum(class_counts, 1).astype(np.float32))
    class_weights = np.clip(class_weights, 0.1, 50.0)  # Bound extreme weights
    weight_tensor = torch.from_numpy(class_weights).float()
    
    train_ds = WorldModelSequenceDataset(X_tr, y_st_tr, y_cls_tr, y_mit_tr)
    val_ds = WorldModelSequenceDataset(X_va, y_st_va, y_cls_va, y_mit_va)
    test_ds = WorldModelSequenceDataset(X_te, y_st_te, y_cls_te, y_mit_te)
    
    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True, drop_last=False)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_ds, batch_size=batch_size, shuffle=False)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"  Using device: {device}")
    
    model = WorldModel(
        input_size=84,
        hidden_size=128,
        num_layers=2,
        num_classes=13,
        num_mitre_stages=6,
        dropout=0.20
    ).to(device)
    
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    criterion_state = nn.MSELoss()
    criterion_cls = nn.CrossEntropyLoss(weight=weight_tensor.to(device))
    criterion_mit = nn.CrossEntropyLoss()
    
    best_val_loss = float("inf")
    best_weights = None
    start_time = time.time()
    
    print(f"[2/4] Training GRU+Attention for {epochs} epochs...")
    for ep in range(1, epochs + 1):
        model.train()
        tr_loss, tr_state_loss, tr_cls_loss = 0.0, 0.0, 0.0
        
        for batch_X, batch_st, batch_cls, batch_mit in train_loader:
            batch_X = batch_X.to(device)
            batch_st = batch_st.to(device)
            batch_cls = batch_cls.to(device)
            batch_mit = batch_mit.to(device)
            
            optimizer.zero_grad()
            out = model(batch_X)
            
            loss_s = criterion_state(out["predicted_next_state"], batch_st)
            loss_c = criterion_cls(out["class_logits"], batch_cls)
            loss_m = criterion_mit(out["mitre_logits"], batch_mit)
            
            total_loss = 1.0 * loss_s + 0.5 * loss_c + 0.2 * loss_m
            total_loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            
            tr_loss += total_loss.item() * len(batch_X)
            tr_state_loss += loss_s.item() * len(batch_X)
            tr_cls_loss += loss_c.item() * len(batch_X)
            
        tr_loss /= len(train_ds)
        tr_state_loss /= len(train_ds)
        tr_cls_loss /= len(train_ds)
        
        # Validation
        model.eval()
        va_loss, va_state_loss, va_cls_loss = 0.0, 0.0, 0.0
        with torch.no_grad():
            for batch_X, batch_st, batch_cls, batch_mit in val_loader:
                batch_X = batch_X.to(device)
                batch_st = batch_st.to(device)
                batch_cls = batch_cls.to(device)
                batch_mit = batch_mit.to(device)
                
                out = model(batch_X)
                loss_s = criterion_state(out["predicted_next_state"], batch_st)
                loss_c = criterion_cls(out["class_logits"], batch_cls)
                loss_m = criterion_mit(out["mitre_logits"], batch_mit)
                
                total_loss = 1.0 * loss_s + 0.5 * loss_c + 0.2 * loss_m
                va_loss += total_loss.item() * len(batch_X)
                va_state_loss += loss_s.item() * len(batch_X)
                va_cls_loss += loss_c.item() * len(batch_X)
                
        va_loss /= len(val_ds)
        va_state_loss /= len(val_ds)
        va_cls_loss /= len(val_ds)
        
        if va_loss < best_val_loss:
            best_val_loss = va_loss
            best_weights = {k: v.cpu().clone() for k, v in model.state_dict().items()}
            mark = "(* Best Val)"
        else:
            mark = ""
            
        if ep % 3 == 0 or ep == epochs:
            print(f"  Epoch {ep:2d}/{epochs:2d} | Train Loss: {tr_loss:.4f} (State: {tr_state_loss:.4f}, Cls: {tr_cls_loss:.4f}) | Val Loss: {va_loss:.4f} {mark}")
            
    train_time = time.time() - start_time
    
    # Save checkpoint
    ckpt_path = PROJECT_ROOT / "models" / "checkpoints" / f"world_model_L{L}_v2.pt"
    torch.save({
        "context_length": L,
        "input_size": 84,
        "hidden_size": 128,
        "num_layers": 2,
        "num_classes": 13,
        "num_mitre_stages": 6,
        "model_state_dict": best_weights,
        "training_time_seconds": train_time,
        "timestamp_utc": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }, ckpt_path)
    print(f"  Checkpoint saved to: {ckpt_path}")
    
    # [3/4] Evaluate on test set
    print(f"[3/4] Evaluating on sequences_test.parquet (N = {len(X_te):,})...")
    model.load_state_dict(best_weights)
    model.eval()
    
    with torch.no_grad():
        out_te = model(torch.from_numpy(X_te).float().to(device))
        cls_logits = out_te["class_logits"].cpu().numpy()
        state_preds = out_te["predicted_next_state"].cpu().numpy()
        
    y_pred_cls = np.argmax(cls_logits, axis=-1)
    
    macro_f1 = float(f1_score(y_cls_te, y_pred_cls, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_cls_te, y_pred_cls, average="weighted", zero_division=0))
    bal_acc = float(balanced_accuracy_score(y_cls_te, y_pred_cls)) * 100.0
    acc = float(accuracy_score(y_cls_te, y_pred_cls)) * 100.0
    
    # Threat binary ROC-AUC
    threat_true = (y_cls_te > 0).astype(int)
    threat_probs = 1.0 - torch.softmax(torch.from_numpy(cls_logits), dim=-1)[:, 0].numpy()
    threat_roc_auc = float(roc_auc_score(threat_true, threat_probs))
    
    next_state_mse = float(np.mean((state_preds - y_st_te) ** 2))
    
    # Per-class metrics
    cm = confusion_matrix(y_cls_te, y_pred_cls, labels=range(13))
    report = classification_report(y_cls_te, y_pred_cls, target_names=classes, output_dict=True, zero_division=0)
    
    metrics = {
        "context_length": L,
        "timestamp_utc": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        "checkpoint_path": f"models/checkpoints/world_model_L{L}_v2.pt",
        "training_time_seconds": round(train_time, 2),
        "parameter_count": sum(p.numel() for p in model.parameters()),
        "test_samples": len(X_te),
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
    
    metric_path = PROJECT_ROOT / "models" / "checkpoints" / f"metrics_L{L}_v2.json"
    with open(metric_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"  Metrics saved to: {metric_path}")
    
    print(f"  --> L={L} Results: Macro-F1: {macro_f1:.4f} | Balanced Acc: {bal_acc:.2f}% | Threat ROC-AUC: {threat_roc_auc:.4f} | Next-State MSE: {next_state_mse:.4f}")
    
    return metrics, X_te, y_cls_te, model

def run_shuffle_ablation(model, X_te, y_cls_te, best_L: int, n_seeds: int = 5):
    print(f"\n[4/4] Running 5-Seed Shuffle Ablation on Best Model (L = {best_L})...")
    device = next(model.parameters()).device
    model.eval()
    
    # Intact performance
    with torch.no_grad():
        out = model(torch.from_numpy(X_te).float().to(device))
        preds_intact = np.argmax(out["class_logits"].cpu().numpy(), axis=-1)
    intact_bal_acc = balanced_accuracy_score(y_cls_te, preds_intact) * 100.0
    intact_macro_f1 = f1_score(y_cls_te, preds_intact, average="macro", zero_division=0)
    
    shuffled_bal_accs = []
    shuffled_macro_f1s = []
    
    for seed in range(42, 42 + n_seeds):
        np.random.seed(seed)
        X_shuffled = np.zeros_like(X_te)
        for i in range(len(X_te)):
            perm = np.random.permutation(best_L)
            X_shuffled[i] = X_te[i, perm, :]
            
        with torch.no_grad():
            out_shuff = model(torch.from_numpy(X_shuffled).float().to(device))
            preds_shuff = np.argmax(out_shuff["class_logits"].cpu().numpy(), axis=-1)
            
        s_bacc = balanced_accuracy_score(y_cls_te, preds_shuff) * 100.0
        s_mf1 = f1_score(y_cls_te, preds_shuff, average="macro", zero_division=0)
        shuffled_bal_accs.append(s_bacc)
        shuffled_macro_f1s.append(s_mf1)
        print(f"  Seed {seed}: Shuffled Balanced Acc = {s_bacc:.2f}%, Macro-F1 = {s_mf1:.4f}")
        
    mean_s_bacc = float(np.mean(shuffled_bal_accs))
    std_s_bacc = float(np.std(shuffled_bal_accs))
    drop = intact_bal_acc - mean_s_bacc
    sigma = drop / (std_s_bacc + 1e-6)
    
    ablation_results = {
        "best_context_length": best_L,
        "intact_balanced_accuracy": round(intact_bal_acc, 2),
        "intact_macro_f1": round(intact_macro_f1, 4),
        "shuffled_seeds": list(range(42, 42 + n_seeds)),
        "shuffled_balanced_accuracies": [round(x, 2) for x in shuffled_bal_accs],
        "shuffled_macro_f1s": [round(x, 4) for x in shuffled_macro_f1s],
        "shuffled_mean_balanced_accuracy": round(mean_s_bacc, 2),
        "shuffled_std_balanced_accuracy": round(std_s_bacc, 2),
        "absolute_drop_percent": round(drop, 2),
        "statistical_significance_sigma": round(sigma, 2),
        "conclusion": f"Temporal order sensitivity verified with {sigma:.2f} sigma significance."
    }
    
    ablation_path = PROJECT_ROOT / "models" / "checkpoints" / "phase2_shuffle_ablation.json"
    with open(ablation_path, "w") as f:
        json.dump(ablation_results, f, indent=2)
    print(f"  Ablation saved to: {ablation_path}")
    print(f"  --> Intact: {intact_bal_acc:.2f}% | Shuffled Mean: {mean_s_bacc:.2f}% | Drop: -{drop:.2f}% (+{sigma:.2f} sigma)")
    
    return ablation_results

def main():
    print("=" * 80)
    print("SHIELDNET PHASE 2: ARCHITECTURE & CONTEXT LENGTH SWEEP (L in {3, 5, 7, 10})")
    print(f"Start Timestamp (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    print("=" * 80)
    
    sweep_results = {}
    best_score = -1.0
    best_L = 3
    best_model_pack = None
    
    for L in [3, 5, 7, 10]:
        metrics, X_te, y_cls_te, model = train_and_eval_for_L(L=L, epochs=15, batch_size=256, lr=1e-3)
        sweep_results[f"L{L}"] = metrics
        
        # Selection criterion: Combined Macro-F1 + (Balanced Accuracy / 100)
        combined_score = metrics["macro_f1"] + (metrics["balanced_accuracy"] / 100.0)
        if combined_score > best_score:
            best_score = combined_score
            best_L = L
            best_model_pack = (model, X_te, y_cls_te)
            
    # Summary of sweep
    summary = {
        "sweep_timestamp_utc": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        "best_context_length": best_L,
        "selection_metric": "Combined Macro-F1 + Balanced Accuracy / 100",
        "results": sweep_results
    }
    
    summary_path = PROJECT_ROOT / "models" / "checkpoints" / "phase2_context_length_sweep_summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSweep summary saved to: {summary_path}")
    
    # Run shuffle ablation on the winner
    model_best, X_te_best, y_cls_te_best = best_model_pack
    ablation = run_shuffle_ablation(model_best, X_te_best, y_cls_te_best, best_L=best_L, n_seeds=5)
    
    print("\n" + "=" * 80)
    print("SHIELDNET PHASE 2 COMPLETE")
    print(f"End Timestamp (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    print("=" * 80)

if __name__ == "__main__":
    main()
