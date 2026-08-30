"""
NetGuard World Model Trainer (Fast Vectorized Temporal Conditioning).

Handles training, validation, checkpointing, and evaluation with
auxiliary temporal order sensitivity.
"""

import sys
from pathlib import Path
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score, confusion_matrix, balanced_accuracy_score
import json
import time
from typing import Tuple, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.world_model.model import WorldModel, WorldModelLoss
from src.world_model.dataset import WorldModelSequenceDataset

def train_one_epoch(model: WorldModel,
                    loader: DataLoader,
                    optimizer: optim.Optimizer,
                    criterion: WorldModelLoss,
                    device: torch.device,
                    grad_clip: float = 1.0) -> Dict[str, float]:
    """Train model for one epoch with fast conditional temporal order auxiliary task."""
    model.train()
    total_loss = 0.0
    state_loss = 0.0
    class_loss = 0.0
    mitre_loss = 0.0
    order_loss = 0.0
    n_batches = 0
    
    for batch_X, batch_y_state, batch_y_label, batch_y_mitre in loader:
        batch_size, seq_len, feat_dim = batch_X.shape
        batch_X = batch_X.to(device)
        batch_y_state = batch_y_state.to(device)
        batch_y_label = batch_y_label.to(device)
        batch_y_mitre = batch_y_mitre.to(device)
        
        # 1. Forward on ordered sequences (order target = 1)
        target_order_pos = torch.ones(batch_size, device=device)
        outputs_pos = model(batch_X)
        losses_pos = criterion(outputs_pos, batch_y_state, batch_y_label, batch_y_mitre, target_order_pos)
        
        if criterion.lambda_order > 0:
            # 2. Fast vectorized permutation of timesteps directly on tensor
            perm = torch.rand(batch_size, seq_len, device=device).argsort(dim=1)
            batch_X_shuf = torch.gather(batch_X, 1, perm.unsqueeze(-1).expand(-1, -1, feat_dim))
            target_order_neg = torch.zeros(batch_size, device=device)
            
            outputs_neg = model(batch_X_shuf)
            loss_order_neg = criterion.bce_order(outputs_neg["order_logits"], target_order_neg)
            
            batch_total_loss = losses_pos["total_loss"] + (criterion.lambda_order * loss_order_neg)
            order_loss_val = (losses_pos["order_loss"].item() + loss_order_neg.item()) / 2.0
        else:
            batch_total_loss = losses_pos["total_loss"]
            order_loss_val = 0.0
        
        optimizer.zero_grad()
        batch_total_loss.backward()
        
        if grad_clip > 0:
            nn.utils.clip_grad_norm_(model.parameters(), grad_clip)
            
        optimizer.step()
        
        total_loss += batch_total_loss.item()
        state_loss += losses_pos["state_loss"].item()
        class_loss += losses_pos["class_loss"].item()
        mitre_loss += losses_pos["mitre_loss"].item()
        order_loss += order_loss_val
        n_batches += 1
        
    return {
        "total_loss": total_loss / max(n_batches, 1),
        "state_loss": state_loss / max(n_batches, 1),
        "class_loss": class_loss / max(n_batches, 1),
        "mitre_loss": mitre_loss / max(n_batches, 1),
        "order_loss": order_loss / max(n_batches, 1),
    }


def evaluate_world_model(model: WorldModel,
                         loader: DataLoader,
                         criterion: WorldModelLoss,
                         device: torch.device,
                         class_names: List[str]) -> Dict:
    """Evaluate World Model next-step forecasting performance."""
    model.eval()
    total_loss = 0.0
    state_loss = 0.0
    class_loss = 0.0
    mitre_loss = 0.0
    n_batches = 0
    
    all_preds = []
    all_targets = []
    
    with torch.no_grad():
        for batch_X, batch_y_state, batch_y_label, batch_y_mitre in loader:
            batch_X = batch_X.to(device)
            batch_y_state = batch_y_state.to(device)
            batch_y_label = batch_y_label.to(device)
            batch_y_mitre = batch_y_mitre.to(device)
            
            outputs = model(batch_X)
            target_order = torch.ones(len(batch_X), device=device)
            losses = criterion(outputs, batch_y_state, batch_y_label, batch_y_mitre, target_order)
            
            total_loss += losses["total_loss"].item()
            state_loss += losses["state_loss"].item()
            class_loss += losses["class_loss"].item()
            mitre_loss += losses["mitre_loss"].item()
            n_batches += 1
            
            preds = torch.argmax(outputs["class_logits"], dim=-1).cpu().numpy()
            all_preds.extend(preds)
            all_targets.extend(batch_y_label.cpu().numpy())
            
    y_true = np.array(all_targets)
    y_pred = np.array(all_preds)
    
    report = classification_report(
        y_true, y_pred, target_names=class_names, output_dict=True, zero_division=0
    )
    cm = confusion_matrix(y_true, y_pred, labels=np.arange(len(class_names)))
    bal_acc = balanced_accuracy_score(y_true, y_pred)
    
    return {
        "total_loss": total_loss / max(n_batches, 1),
        "state_loss": state_loss / max(n_batches, 1),
        "class_loss": class_loss / max(n_batches, 1),
        "mitre_loss": mitre_loss / max(n_batches, 1),
        "classification_report": report,
        "confusion_matrix": cm.tolist(),
        "macro_f1": float(report.get("macro avg", {}).get("f1-score", 0.0)),
        "weighted_f1": float(report.get("weighted avg", {}).get("f1-score", 0.0)),
        "balanced_accuracy": float(bal_acc),
        "accuracy": float(report.get("accuracy", 0.0)),
    }
