"""
Baseline model: Logistic Regression classifier.
Built for Phase 2 to establish the flat, non-sequential benchmark on both
Config A (Fused Flow+Packet) and Config B (Flow-Only Baseline).

Ensures strict zero-leakage scaling and detailed per-class evaluation.
"""

import numpy as np
import pandas as pd
import joblib
import json
from pathlib import Path
from sklearn.linear_model import SGDClassifier, LogisticRegression
from sklearn.metrics import (
    f1_score, precision_score, recall_score, confusion_matrix,
    classification_report
)
from sklearn.preprocessing import LabelEncoder, StandardScaler
from typing import Dict, List, Tuple, Optional


def train_logistic_baseline(X_train: np.ndarray,
                            y_train: np.ndarray,
                            classes: np.ndarray,
                            random_seed: int = 42) -> SGDClassifier:
    """Train multiclass logistic regression using SGDClassifier with balanced weights and early stopping.
    
    Args:
        X_train: Scaled feature matrix of shape (N, D).
        y_train: Encoded integer labels of shape (N,).
        classes: All unique class integers.
        random_seed: Seed for reproducibility.
        
    Returns:
        Trained SGDClassifier model (log-loss / logistic regression).
    """
    model = SGDClassifier(
        loss="log_loss",
        penalty="l2",
        alpha=1e-5,
        max_iter=50,
        tol=1e-3,
        early_stopping=True,
        n_iter_no_change=3,
        validation_fraction=0.1,
        class_weight="balanced",
        random_state=random_seed,
        n_jobs=-1,
        learning_rate="optimal"
    )
    
    print(f"  Fitting Logistic Regression (SGD log_loss, balanced, early_stopping) on {X_train.shape[0]:,} samples x {X_train.shape[1]} features...")
    model.fit(X_train, y_train)
    print(f"  Model converged in {model.n_iter_} iterations.")
    return model


def evaluate_baseline_model(model: SGDClassifier,
                            X_test: np.ndarray,
                            y_test: np.ndarray,
                            class_names: List[str]) -> Dict:
    """Evaluate baseline model on test split and compute detailed per-class metrics.
    
    Args:
        model: Trained classifier.
        X_test: Scaled test feature matrix.
        y_test: True integer labels.
        class_names: Human-readable class label strings.
        
    Returns:
        Dict containing per-class metrics, macro/weighted averages, and confusion matrix.
    """
    y_pred = model.predict(X_test)
    
    # Per-class classification report
    report_dict = classification_report(
        y_test,
        y_pred,
        target_names=class_names,
        output_dict=True,
        zero_division=0
    )
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred, labels=np.arange(len(class_names)))
    
    # Binary False Positive Rate (Benign=0 vs Attack>0)
    benign_idx = class_names.index("BENIGN") if "BENIGN" in class_names else 0
    y_test_binary = (y_test != benign_idx).astype(int)
    y_pred_binary = (y_pred != benign_idx).astype(int)
    
    tn = np.sum((y_test_binary == 0) & (y_pred_binary == 0))
    fp = np.sum((y_test_binary == 0) & (y_pred_binary == 1))
    fpr = float(fp / max(tn + fp, 1))
    
    metrics = {
        "macro_avg": report_dict.get("macro avg", {}),
        "weighted_avg": report_dict.get("weighted avg", {}),
        "false_positive_rate": fpr,
        "classification_report": report_dict,
        "confusion_matrix": cm.tolist(),
        "classes": class_names,
        "accuracy": float(report_dict.get("accuracy", 0.0))
    }
    
    return metrics
