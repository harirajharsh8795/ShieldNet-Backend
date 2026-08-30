"""
NetGuard World Model Disentanglement Ablation (Live Terminal Streaming).

Evaluates the 3 experimental conditions:
Condition A: Original (lambda_class=0.5, no order-head)
Condition B: Reweighted only (lambda_class=1.0, no order-head)
Condition C: Reweighted + order-head (lambda_class=1.0, lambda_order=0.5)

Isolates the contribution of loss reweighting vs explicit order discrimination.
"""

import sys
from pathlib import Path
import numpy as np
import torch
import torch.optim as optim
from torch.utils.data import DataLoader
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import classification_report, f1_score, accuracy_score, balanced_accuracy_score, mean_squared_error
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

def evaluate_condition(cond_name: str,
                       lambda_class: float,
                       lambda_order: float,
                       classes: list,
                       le: LabelEncoder,
                       device: torch.device,
                       epochs: int = 15) -> dict:
    """Train and evaluate a specific ablation condition with live terminal output."""
    print("\n" + "=" * 80, flush=True)
    print(f"EVALUATING: {cond_name}", flush=True)
    print(f"Parameters: lambda_class={lambda_class}, lambda_order={lambda_order}", flush=True)
    print("=" * 80, flush=True)
    
    set_seed(42)
    L = 3
    
    print("Loading sequence splits...", flush=True)
    X_train, y_train_state, y_train_label, y_train_mitre = extract_temporal_sequences_from_parquet(
        "data/processed/sequences_train.parquet", le, context_length=L
    )
    X_val, y_val_state, y_val_label, y_val_mitre = extract_temporal_sequences_from_parquet(
        "data/processed/sequences_val.parquet", le, context_length=L
    )
    X_test, y_test_state, y_test_label, y_test_mitre = extract_temporal_sequences_from_parquet(
        "data/processed/sequences_test.parquet", le, context_length=L
    )
    print(f"Sequences Ready: Train={len(X_train):,}, Val={len(X_val):,}, Test={len(X_test):,}", flush=True)
    
    train_dataset = WorldModelSequenceDataset(X_train, y_train_state, y_train_label, y_train_mitre)
    val_dataset = WorldModelSequenceDataset(X_val, y_val_state, y_val_label, y_val_mitre)
    test_dataset = WorldModelSequenceDataset(X_test, y_test_state, y_test_label, y_test_mitre)
    
    train_loader = DataLoader(train_dataset, batch_size=128, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=128, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=128, shuffle=False)
    
    present_classes = np.unique(y_train_label)
    cw = compute_class_weight(class_weight="balanced", classes=present_classes, y=y_train_label)
    full_weights = np.ones(len(classes), dtype=np.float32)
    for cls_idx, w in zip(present_classes, cw):
        full_weights[cls_idx] = float(np.clip(w, 0.1, 50.0))
    class_weights_tensor = torch.tensor(full_weights, dtype=torch.float32).to(device)
    
    model = WorldModel(
        input_size=84,
        hidden_size=128,
        num_layers=2,
        dropout=0.2,
        num_classes=len(classes),
        num_mitre_stages=6,
    ).to(device)
    
    criterion = WorldModelLoss(
        lambda_class=lambda_class, lambda_mitre=0.25, lambda_order=lambda_order, class_weights=class_weights_tensor
    ).to(device)
    
    optimizer = optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs, eta_min=1e-5)
    
    best_val_f1 = -1.0
    best_state_dict = None
    
    print(f"Training for {epochs} epochs on {device}...", flush=True)
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
            
        print(f"  Epoch [{ep:2d}/{epochs}] ({elapsed:4.1f}s) | Train Loss: {tr['total_loss']:.4f} (State: {tr['state_loss']:.4f}, Class: {tr['class_loss']:.4f}) | Val F1: {val['macro_f1']:.4f} | Val MSE: {val['state_loss']:.4f} {'[BEST]' if is_best else ''}", flush=True)
            
    model.load_state_dict(best_state_dict)
    model.eval()
    
    # 1. Ordered test performance
    print("Evaluating Ordered (Chronological) Test Performance...", flush=True)
    X_ord_tensor = torch.from_numpy(X_test).float().to(device)
    with torch.no_grad():
        out_ord = model(X_ord_tensor)
        p_state_ord = out_ord["predicted_next_state"].cpu().numpy()
        p_class_ord = np.argmax(out_ord["class_logits"].cpu().numpy(), axis=-1)
        
    ord_mse = mean_squared_error(y_test_state, p_state_ord)
    ord_f1 = f1_score(y_test_label, p_class_ord, average="macro", zero_division=0)
    ord_bal_acc = balanced_accuracy_score(y_test_label, p_class_ord)
    ord_acc = accuracy_score(y_test_label, p_class_ord)
    
    # 2. 5-Seed Shuffled test performance
    print("Running 5-Seed Shuffle Ablation...", flush=True)
    shuf_f1_list = []
    shuf_mse_list = []
    
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
        s_mse = mean_squared_error(y_test_state, ps_s)
        s_f1 = f1_score(y_test_label, pc_s, average="macro", zero_division=0)
        shuf_mse_list.append(s_mse)
        shuf_f1_list.append(s_f1)
        print(f"    Seed {seed:4d} -> Shuffled F1: {s_f1:.4f}, Shuffled MSE: {s_mse:.4f}", flush=True)
        
    shuf_f1_m, shuf_f1_s = np.mean(shuf_f1_list), np.std(shuf_f1_list)
    shuf_mse_m, shuf_mse_s = np.mean(shuf_mse_list), np.std(shuf_mse_list)
    
    f1_gap = ord_f1 - shuf_f1_m
    f1_sigma = f1_gap / max(shuf_f1_s, 1e-9)
    
    mse_gap = shuf_mse_m - ord_mse
    mse_sigma = mse_gap / max(shuf_mse_s, 1e-9)
    
    print(f"\nCondition Summary for '{cond_name}':", flush=True)
    print(f"  - Ordered Macro F1:  {ord_f1:.4f}", flush=True)
    print(f"  - Shuffled Macro F1: {shuf_f1_m:.4f} +/- {shuf_f1_s:.4f}", flush=True)
    print(f"  - F1 Significance:   {f1_gap:+.4f} ({f1_sigma:+.2f} sigma)", flush=True)
    print(f"  - Ordered State MSE: {ord_mse:.4f}", flush=True)
    print(f"  - MSE Significance:  {mse_gap:+.4f} ({mse_sigma:+.2f} sigma)", flush=True)
    
    return {
        "condition": cond_name,
        "lambda_class": lambda_class,
        "lambda_order": lambda_order,
        "ordered_f1": float(ord_f1),
        "shuffled_f1_mean": float(shuf_f1_m),
        "shuffled_f1_std": float(shuf_f1_s),
        "f1_gap": float(f1_gap),
        "f1_sigma": float(f1_sigma),
        "ordered_mse": float(ord_mse),
        "shuffled_mse_mean": float(shuf_mse_m),
        "shuffled_mse_std": float(shuf_mse_s),
        "mse_gap": float(mse_gap),
        "mse_sigma": float(mse_sigma),
        "balanced_accuracy": float(ord_bal_acc),
        "accuracy": float(ord_acc),
    }

def main():
    print("=" * 80, flush=True)
    print("NETGUARD PHASE 3: DISENTANGLEMENT ABLATION (REWEIGHTING vs ORDER-HEAD)", flush=True)
    print("=" * 80, flush=True)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    checkpoint_dir = Path("models/checkpoints")
    
    with open(checkpoint_dir / "feature_columns.json", "r") as f:
        manifest = json.load(f)
    classes = manifest["classes"]
    le = LabelEncoder()
    le.fit(classes)
    
    # 1. Condition A: Original (lambda_class=0.5, lambda_order=0.0)
    res_A = evaluate_condition("Condition A: Original (lambda_class=0.5, no order-head)", 0.5, 0.0, classes, le, device)
    
    # 2. Condition B: Reweighted only (lambda_class=1.0, lambda_order=0.0)
    res_B = evaluate_condition("Condition B: Reweighted Only (lambda_class=1.0, no order-head)", 1.0, 0.0, classes, le, device)
    
    # 3. Condition C: Reweighted + Order Head (lambda_class=1.0, lambda_order=0.5)
    res_C = evaluate_condition("Condition C: Reweighted + Order-Head (lambda_class=1.0, lambda_order=0.5)", 1.0, 0.5, classes, le, device)
    
    print("\n" + "=" * 95, flush=True)
    print("DISENTANGLEMENT ABLATION SUMMARY TABLE", flush=True)
    print("=" * 95, flush=True)
    print(f"  Condition                                    | Macro F1 | Shuffled F1       | F1 Gap (Sigma) | State MSE | MSE Gap (Sigma)", flush=True)
    print(f"  ----------------------------------------------------------------------------------------------------------------------", flush=True)
    for r in [res_A, res_B, res_C]:
        print(f"  {r['condition']:44s} | {r['ordered_f1']:8.4f} | {r['shuffled_f1_mean']:.4f} +/- {r['shuffled_f1_std']:.4f} | {r['f1_gap']:+6.4f} ({r['f1_sigma']:+5.2f} sigma) | {r['ordered_mse']:9.4f} | {r['mse_gap']:+7.4f} ({r['mse_sigma']:+5.2f} sigma)", flush=True)
        
    out_path = checkpoint_dir / "disentanglement_ablation_summary.json"
    with open(out_path, "w") as f:
        json.dump([res_A, res_B, res_C], f, indent=2)
    print(f"\nSaved summary manifest to: {out_path}", flush=True)

if __name__ == "__main__":
    main()
