"""
ShieldNet World Model Training & Evaluation Pipeline (Phase 3).

Trains the Recurrent State-Space World Model on sequences_train.parquet,
validates on sequences_val.parquet, and evaluates 1-step forecasting on sequences_test.parquet.
Saves model checkpoint to models/checkpoints/world_model_v1.pt.
"""

import sys
from pathlib import Path
import numpy as np
import pandas as pd
import torch
import torch.optim as optim
from torch.utils.data import DataLoader
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_class_weight
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
    print("=" * 80)
    print("SHIELDNET PHASE 3: WORLD MODEL TRAINING (TEMPORAL DYNAMICS & NEXT-STATE FORECASTING)")
    print("=" * 80)
    
    set_seed(42)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Execution Device: {device}")
    
    checkpoint_dir = Path("models/checkpoints")
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Setup Classes and LabelEncoder
    with open(checkpoint_dir / "feature_columns.json", "r") as f:
        manifest = json.load(f)
    classes = manifest["classes"]
    le = LabelEncoder()
    le.fit(classes)
    
    print(f"Target classes ({len(classes)}): {classes}")
    
    # 2. Extract Temporal Transition Sequences
    print("\n[1/4] Extracting Temporal Transition Sequences (Context L=3, Horizon=1)...")
    X_train, y_train_state, y_train_label, y_train_mitre = extract_temporal_sequences_from_parquet(
        "data/processed/sequences_train.parquet", le, context_length=3
    )
    X_val, y_val_state, y_val_label, y_val_mitre = extract_temporal_sequences_from_parquet(
        "data/processed/sequences_val.parquet", le, context_length=3
    )
    X_test, y_test_state, y_test_label, y_test_mitre = extract_temporal_sequences_from_parquet(
        "data/processed/sequences_test.parquet", le, context_length=3
    )
    
    print(f"  Train Sequences: {X_train.shape[0]:,} samples | Shape: {X_train.shape}")
    print(f"  Val Sequences:   {X_val.shape[0]:,} samples | Shape: {X_val.shape}")
    print(f"  Test Sequences:  {X_test.shape[0]:,} samples | Shape: {X_test.shape}")
    
    train_dataset = WorldModelSequenceDataset(X_train, y_train_state, y_train_label, y_train_mitre)
    val_dataset = WorldModelSequenceDataset(X_val, y_val_state, y_val_label, y_val_mitre)
    test_dataset = WorldModelSequenceDataset(X_test, y_test_state, y_test_label, y_test_mitre)
    
    train_loader = DataLoader(train_dataset, batch_size=128, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=128, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=128, shuffle=False)
    
    # 3. Compute Class Weights for Balanced Learning
    present_classes = np.unique(y_train_label)
    cw = compute_class_weight(class_weight="balanced", classes=present_classes, y=y_train_label)
    full_weights = np.ones(len(classes), dtype=np.float32)
    for cls_idx, w in zip(present_classes, cw):
        full_weights[cls_idx] = float(np.clip(w, 0.1, 50.0))  # Smooth extreme outliers
    class_weights_tensor = torch.tensor(full_weights, dtype=torch.float32).to(device)
    
    # 4. Instantiate World Model & Loss
    print("\n[2/4] Initializing Recurrent State-Space World Model (RSS-WM)...")
    model = WorldModel(
        input_size=84,
        hidden_size=128,
        num_layers=2,
        dropout=0.2,
        num_classes=len(classes),
        num_mitre_stages=6,
    ).to(device)
    
    n_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"  Trainable Parameters: {n_params:,}")
    
    criterion = WorldModelLoss(
        lambda_class=0.5, lambda_mitre=0.25, class_weights=class_weights_tensor
    ).to(device)
    
    optimizer = optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    epochs = 20
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs, eta_min=1e-5)
    
    # 5. Training Loop
    print(f"\n[3/4] Training World Model for {epochs} Epochs...")
    history = {"train_loss": [], "val_loss": [], "val_state_loss": [], "val_macro_f1": []}
    best_val_loss = float("inf")
    best_model_path = checkpoint_dir / "world_model_v1.pt"
    
    for epoch in range(1, epochs + 1):
        t0 = time.time()
        train_metrics = train_one_epoch(model, train_loader, optimizer, criterion, device)
        val_metrics = evaluate_world_model(model, val_loader, criterion, device, classes)
        scheduler.step()
        
        elapsed = time.time() - t0
        
        history["train_loss"].append(train_metrics["total_loss"])
        history["val_loss"].append(val_metrics["total_loss"])
        history["val_state_loss"].append(val_metrics["state_loss"])
        history["val_macro_f1"].append(val_metrics["macro_f1"])
        
        print(f"  Epoch {epoch:2d}/{epochs:2d} | "
              f"Train Loss: {train_metrics['total_loss']:.4f} (State MSE: {train_metrics['state_loss']:.4f}) | "
              f"Val Loss: {val_metrics['total_loss']:.4f} (State MSE: {val_metrics['state_loss']:.4f}, Macro F1: {val_metrics['macro_f1']:.4f}) | "
              f"{elapsed:.1f}s")
        
        if val_metrics["total_loss"] < best_val_loss:
            best_val_loss = val_metrics["total_loss"]
            torch.save({
                "epoch": epoch,
                "model_state_dict": model.state_dict(),
                "optimizer_state_dict": optimizer.state_dict(),
                "val_loss": best_val_loss,
                "classes": classes,
                "input_size": 84,
                "hidden_size": 128,
            }, best_model_path)
            
    print(f"\nBest Model Checkpoint saved to: {best_model_path}")
    
    # Load best checkpoint for final test evaluation
    best_checkpoint = torch.load(best_model_path, map_location=device, weights_only=False)
    model.load_state_dict(best_checkpoint["model_state_dict"])
    
    # 6. Test Set Evaluation
    print("\n[4/4] Evaluating Best World Model on Test Set (1-Step Ahead Forecasting S_{t-L:t} -> y_{t+1})...")
    test_metrics = evaluate_world_model(model, test_loader, criterion, device, classes)
    
    print("\n" + "=" * 80)
    print("WORLD MODEL 1-STEP-AHEAD TEST PERFORMANCE (PER CLASS)")
    print("=" * 80)
    
    rep = test_metrics["classification_report"]
    table_rows = []
    for cls_name in classes:
        cls_rep = rep.get(cls_name, {})
        table_rows.append({
            "Class": cls_name,
            "Support": int(cls_rep.get("support", 0)),
            "Precision": round(cls_rep.get("precision", 0.0), 4),
            "Recall": round(cls_rep.get("recall", 0.0), 4),
            "F1-Score": round(cls_rep.get("f1-score", 0.0), 4),
        })
    df_results = pd.DataFrame(table_rows)
    print(df_results.to_string(index=False))
    
    print(f"\nSummary Test Metrics:")
    print(f"  - Next-State Prediction MSE: {test_metrics['state_loss']:.4f}")
    print(f"  - 1-Step Macro F1:           {test_metrics['macro_f1']:.4f}")
    print(f"  - 1-Step Weighted F1:        {test_metrics['weighted_f1']:.4f}")
    print(f"  - Accuracy:                  {test_metrics['accuracy']:.4f}")
    
    # Save training logs and evaluation metrics
    output_metrics = {
        "history": history,
        "test_metrics": test_metrics,
        "per_class_table": table_rows,
        "classes": classes,
    }
    metrics_file = checkpoint_dir / "world_model_metrics.json"
    with open(metrics_file, "w") as f:
        json.dump(output_metrics, f, indent=2)
    print(f"Saved metrics to: {metrics_file}")

if __name__ == "__main__":
    main()
