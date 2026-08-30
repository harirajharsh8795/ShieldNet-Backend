"""
Evaluation harness for NetGuard.

Computes F1, precision, recall, false-positive-rate for both the 
World Model and the Logistic Regression baseline, ensuring fair comparison
using identical metrics (Constraint C5).

Also supports cross-dataset generalisation testing (train on CIC, eval on CTU).
"""

import numpy as np
import pandas as pd
import json
import torch
from pathlib import Path
from typing import Dict, Optional, Tuple, List
from sklearn.metrics import (
    f1_score, precision_score, recall_score, 
    confusion_matrix, classification_report
)
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from src.world_model.model import WorldModel


def evaluate_world_model(model: WorldModel,
                         X_test: np.ndarray,
                         y_test_states: np.ndarray,
                         y_test_labels: np.ndarray,
                         label_names: Optional[List[str]] = None,
                         device: str = 'cpu') -> Dict:
    """Evaluate World Model on test set.
    
    Uses the same metrics as the baseline for fair comparison (Constraint C5):
    - F1 (weighted)
    - Precision (weighted)
    - Recall (weighted)
    - False Positive Rate
    
    Also computes state-prediction MSE to measure dynamics-learning quality.
    
    Args:
        model: Trained WorldModel.
        X_test: Test input sequences (N, seq_len, features).
        y_test_states: Test target next states (N, features).
        y_test_labels: Test target labels (N,).
        label_names: Human-readable label names.
        device: Torch device.
    
    Returns:
        Dict of metrics.
    """
    model.eval()
    model.to(device)
    
    all_preds = []
    all_probs = []
    all_state_errors = []
    
    batch_size = 64
    
    with torch.no_grad():
        for i in range(0, len(X_test), batch_size):
            batch_X = torch.FloatTensor(X_test[i:i+batch_size]).to(device)
            batch_y_state = torch.FloatTensor(y_test_states[i:i+batch_size]).to(device)
            
            outputs = model(batch_X)
            
            # Classification predictions
            class_preds = outputs['class_logits'].argmax(dim=-1).cpu().numpy()
            all_preds.extend(class_preds)
            
            # Infiltration probabilities
            probs = outputs['infiltration_prob'].squeeze().cpu().numpy()
            if probs.ndim == 0:
                probs = [probs.item()]
            all_probs.extend(probs)
            
            # State prediction error
            state_error = torch.mean((outputs['predicted_next_state'] - batch_y_state) ** 2, dim=-1)
            all_state_errors.extend(state_error.cpu().numpy())
    
    y_pred = np.array(all_preds)
    y_true = y_test_labels
    
    # ─── Core Metrics (matching baseline evaluation) ─────────────
    metrics = {
        'f1_weighted': float(f1_score(y_true, y_pred, average='weighted', zero_division=0)),
        'f1_macro': float(f1_score(y_true, y_pred, average='macro', zero_division=0)),
        'precision_weighted': float(precision_score(y_true, y_pred, average='weighted', zero_division=0)),
        'recall_weighted': float(recall_score(y_true, y_pred, average='weighted', zero_division=0)),
    }
    
    # False positive rate (binary: benign=0 vs attack>0)
    y_true_binary = (y_true > 0).astype(int)
    y_pred_binary = (y_pred > 0).astype(int)
    
    tn = np.sum((y_true_binary == 0) & (y_pred_binary == 0))
    fp = np.sum((y_true_binary == 0) & (y_pred_binary == 1))
    fpr = float(fp / max(tn + fp, 1))
    metrics['false_positive_rate'] = fpr
    
    # State prediction MSE (dynamics learning quality)
    metrics['state_prediction_mse'] = float(np.mean(all_state_errors))
    
    # Classification report
    if label_names:
        report = classification_report(
            y_true, y_pred, target_names=label_names[:max(y_true.max(), y_pred.max())+1],
            output_dict=True, zero_division=0
        )
    else:
        report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    metrics['classification_report'] = report
    
    return metrics


def compare_models(baseline_metrics: Dict, world_model_metrics: Dict) -> pd.DataFrame:
    """Create comparison table between baseline and World Model.
    
    Args:
        baseline_metrics: Metrics dict from baseline evaluation.
        world_model_metrics: Metrics dict from World Model evaluation.
    
    Returns:
        DataFrame comparison table.
    """
    comparison_metrics = [
        'f1_weighted', 'f1_macro', 'precision_weighted', 
        'recall_weighted', 'false_positive_rate'
    ]
    
    rows = []
    for metric in comparison_metrics:
        baseline_val = baseline_metrics.get(metric, 'N/A')
        wm_val = world_model_metrics.get(metric, 'N/A')
        
        if isinstance(baseline_val, (int, float)) and isinstance(wm_val, (int, float)):
            delta = wm_val - baseline_val
            # For FPR, lower is better; for others, higher is better
            if metric == 'false_positive_rate':
                improvement = 'Better' if delta < 0 else 'Worse'
            else:
                improvement = 'Better' if delta > 0 else 'Worse'
        else:
            delta = 'N/A'
            improvement = 'N/A'
        
        rows.append({
            'Metric': metric.replace('_', ' ').title(),
            'Baseline (LR)': f"{baseline_val:.4f}" if isinstance(baseline_val, float) else str(baseline_val),
            'World Model': f"{wm_val:.4f}" if isinstance(wm_val, float) else str(wm_val),
            'Delta': f"{delta:+.4f}" if isinstance(delta, float) else str(delta),
            'Result': improvement,
        })
    
    return pd.DataFrame(rows)


def save_evaluation_results(metrics: Dict, comparison_df: Optional[pd.DataFrame],
                            output_dir: str = 'models') -> None:
    """Save evaluation results to disk for reproducibility.
    
    Args:
        metrics: World model metrics dict.
        comparison_df: Optional comparison DataFrame.
        output_dir: Output directory.
    """
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    
    # Save metrics as JSON (make serializable)
    serializable = {}
    for k, v in metrics.items():
        if isinstance(v, (float, int, str, bool)):
            serializable[k] = v
        elif isinstance(v, np.floating):
            serializable[k] = float(v)
        elif isinstance(v, dict):
            serializable[k] = {
                str(kk): {str(kkk): float(vvv) if isinstance(vvv, (float, np.floating)) else vvv 
                          for kkk, vvv in vv.items()} if isinstance(vv, dict) else vv
                for kk, vv in v.items()
            }
    
    with open(out_path / 'world_model_metrics.json', 'w') as f:
        json.dump(serializable, f, indent=2)
    
    if comparison_df is not None:
        comparison_df.to_csv(out_path / 'comparison_table.csv', index=False)
    
    print(f"  Evaluation results saved to {out_path}")
