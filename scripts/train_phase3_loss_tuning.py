"""
NetGuard Phase 3: Loss Function Tuning on Canonical Locked Baseline Pipeline.

Directly based on scripts/build_final_world_model.py:
- Evaluates:
  1. Control: world_model_v1.pt (Locked Baseline)
  2. Inverse-Frequency Weighted Cross-Entropy (Raw Inverse-Freq w_c = N_total / (13 * N_c))
  3. Multi-Class Focal Loss (gamma = 0.5)
  4. Multi-Class Focal Loss (gamma = 1.0)
  5. Multi-Class Focal Loss (gamma = 1.5)
  6. Multi-Class Focal Loss (gamma = 2.0)
- Canonical 5-seed shuffle ablation [42, 101, 2024, 777, 999]
- Saves individual checkpoints and master metrics JSON
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

def evaluate_test_and_shuffle(model: WorldModel, X_te: np.ndarray, y_st_te: np.ndarray, y_cls_te: np.ndarray, classes: list, device: torch.device):
    model.eval()
    with torch.no_grad():
        out = model(torch.from_numpy(X_te).float().to(device))
        cls_logits = out["class_logits"].cpu().numpy()
        state_preds = out["predicted_next_state"].cpu().numpy()
        
    preds = np.argmax(cls_logits, axis=-1)
    macro_f1 = float(f1_score(y_cls_te, preds, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_cls_te, preds, average="weighted", zero_division=0))
    bal_acc = float(balanced_accuracy_score(y_cls_te, preds)) * 100.0
    acc = float(accuracy_score(y_cls_te, preds)) * 100.0
    
    threat_true = (y_cls_te > 0).astype(int)
    threat_probs = 1.0 - torch.softmax(torch.from_numpy(cls_logits), dim=-1)[:, 0].numpy()
    threat_roc_auc = float(roc_auc_score(threat_true, threat_probs))
    next_state_mse = float(np.mean((state_preds - y_st_te) ** 2))
    
    report = classification_report(y_cls_te, preds, target_names=classes, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_cls_te, preds, labels=range(13))
    
    # 5-Seed Shuffle Ablation using canonical RandomState seeds
    seeds = [42, 101, 2024, 777, 999]
    shuffled_accs = []
    shuffled_f1s = []
    
    for seed in seeds:
        rng = np.random.RandomState(seed)
        X_shuf = X_te.copy()
        for sample_idx in range(len(X_shuf)):
            perm = rng.permutation(3)
            X_shuf[sample_idx] = X_shuf[sample_idx][perm]
            
        with torch.no_grad():
            out_shuf = model(torch.from_numpy(X_shuf).float().to(device))
            preds_shuf = np.argmax(out_shuf["class_logits"].cpu().numpy(), axis=-1)
            
        s_bacc = float(balanced_accuracy_score(y_cls_te, preds_shuf)) * 100.0
        s_mf1 = float(f1_score(y_cls_te, preds_shuf, average="macro", zero_division=0))
        shuffled_accs.append(s_bacc)
        shuffled_f1s.append(s_mf1)
        
    mean_shuf_bacc = float(np.mean(shuffled_accs))
    std_shuf_bacc = float(np.std(shuffled_accs))
    drop_bacc = bal_acc - mean_shuf_bacc
    sigma_bacc = drop_bacc / (std_shuf_bacc + 1e-9)
    
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
            "mean_shuffled_bacc": round(mean_shuf_bacc, 2),
            "std_shuffled_bacc": round(std_shuf_bacc, 2),
            "drop_percent": round(drop_bacc, 2),
            "sigma": round(sigma_bacc, 2)
        }
    }

def train_loss_variant(name: str,
                       focal_gamma: float,
                       weight_type: str,
                       X_tr, y_st_tr, y_cls_tr, y_mit_tr,
                       X_va, y_st_va, y_cls_va, y_mit_va,
                       X_te, y_st_te, y_cls_te, y_mit_te,
                       classes: list,
                       epochs: int = 10,
                       batch_size: int = 256):
    set_seed(42)
    device = torch.device("cpu")
    
    # Compute weights
    present_classes = np.unique(y_cls_tr)
    if weight_type == "balanced":
        cw = compute_class_weight(class_weight="balanced", classes=present_classes, y=y_cls_tr)
        full_weights = np.ones(len(classes), dtype=np.float32)
        for cls_idx, w in zip(present_classes, cw):
            full_weights[cls_idx] = float(np.clip(w, 0.1, 50.0))
    elif weight_type == "inv_freq_smoothed":
        counts = np.bincount(y_cls_tr, minlength=len(classes))
        full_weights = np.zeros(len(classes), dtype=np.float32)
        for i in range(len(classes)):
            if counts[i] > 0:
                full_weights[i] = float(np.clip(np.sqrt(len(y_cls_tr) / (counts[i] + 1.0)), 0.1, 50.0))
            else:
                full_weights[i] = 1.0
    else:
        full_weights = np.ones(len(classes), dtype=np.float32)
        
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
        focal_gamma=focal_gamma,
        class_weights=class_weights_tensor
    ).to(device)
    
    optimizer = optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs, eta_min=1e-5)
    
    best_val_f1 = -1.0
    best_state_dict = None
    start_t = time.time()
    
    print(f"\n[Training Variant: {name} (gamma={focal_gamma}, weights={weight_type})]...")
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
    
    ckpt_path = PROJECT_ROOT / "models" / "checkpoints" / f"loss_tuning_{name}.pt"
    torch.save({
        "variant_name": name,
        "focal_gamma": focal_gamma,
        "weight_type": weight_type,
        "context_length": 3,
        "model_state_dict": best_state_dict,
        "training_time_seconds": train_time,
        "timestamp_utc": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    }, ckpt_path)
    
    model.load_state_dict(best_state_dict)
    eval_res = evaluate_test_and_shuffle(model, X_te, y_st_te, y_cls_te, classes, device)
    eval_res["variant_name"] = name
    eval_res["focal_gamma"] = focal_gamma
    eval_res["weight_type"] = weight_type
    eval_res["checkpoint_path"] = f"models/checkpoints/loss_tuning_{name}.pt"
    eval_res["training_time_seconds"] = round(train_time, 2)
    
    print(f"--> Result for {name}: Macro-F1: {eval_res['macro_f1']:.4f} | BalAcc: {eval_res['balanced_accuracy']:.2f}% | Threat ROC-AUC: {eval_res['threat_roc_auc']:.4f} | Drop: {eval_res['shuffle_ablation']['drop_percent']:.2f}% (+{eval_res['shuffle_ablation']['sigma']:.2f} sigma)")
    return eval_res

def main():
    print("=" * 85)
    print("NETGUARD PHASE 3: LOSS FUNCTION TUNING (CLASS-WEIGHTED & FOCAL LOSS SWEEP)")
    print(f"Timestamp (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    print("=" * 85)
    
    with open(PROJECT_ROOT / "models" / "checkpoints" / "feature_columns.json") as f:
        manifest = json.load(f)
    classes = manifest["classes"]
    le = LabelEncoder()
    le.fit(classes)
    
    device = torch.device("cpu")
    
    # Load test data
    test_path = str(PROJECT_ROOT / "data" / "processed" / "sequences_test.parquet")
    train_path = str(PROJECT_ROOT / "data" / "processed" / "sequences_train.parquet")
    val_path = str(PROJECT_ROOT / "data" / "processed" / "sequences_val.parquet")
    
    X_tr, y_st_tr, y_cls_tr, y_mit_tr = extract_temporal_sequences_from_parquet(train_path, le, context_length=3)
    X_va, y_st_va, y_cls_va, y_mit_va = extract_temporal_sequences_from_parquet(val_path, le, context_length=3)
    X_te, y_st_te, y_cls_te, y_mit_te = extract_temporal_sequences_from_parquet(test_path, le, context_length=3)
    
    # 1. Evaluate Control: world_model_v1.pt
    print("\n[Evaluating Control: world_model_v1.pt]...")
    locked_ckpt = torch.load(PROJECT_ROOT / "models" / "checkpoints" / "world_model_v1.pt", map_location=device, weights_only=False)
    locked_model = WorldModel(input_size=84, hidden_size=128, num_layers=2, num_classes=13, num_mitre_stages=6).to(device)
    locked_model.load_state_dict(locked_ckpt["model_state_dict"])
    control_eval = evaluate_test_and_shuffle(locked_model, X_te, y_st_te, y_cls_te, classes, device)
    control_eval["variant_name"] = "world_model_v1_control"
    
    results = {
        "world_model_v1_control": control_eval
    }
    
    # 2. Variants
    variants = [
        ("inv_freq_smoothed", 0.0, "inv_freq_smoothed"),
        ("focal_g05", 0.5, "balanced"),
        ("focal_g10", 1.0, "balanced"),
        ("focal_g15", 1.5, "balanced"),
        ("focal_g20", 2.0, "balanced"),
    ]
    
    for v_name, gamma, w_type in variants:
        res = train_loss_variant(
            name=v_name,
            focal_gamma=gamma,
            weight_type=w_type,
            X_tr=X_tr, y_st_tr=y_st_tr, y_cls_tr=y_cls_tr, y_mit_tr=y_mit_tr,
            X_va=X_va, y_st_va=y_st_va, y_cls_va=y_cls_va, y_mit_va=y_mit_va,
            X_te=X_te, y_st_te=y_st_te, y_cls_te=y_cls_te, y_mit_te=y_mit_te,
            classes=classes, epochs=10, batch_size=256
        )
        results[v_name] = res
        
    master_path = PROJECT_ROOT / "models" / "checkpoints" / "phase3_loss_tuning_summary.json"
    with open(master_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nPhase 3 summary saved to: {master_path}")

if __name__ == "__main__":
    main()
