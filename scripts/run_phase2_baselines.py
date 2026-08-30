"""
NetGuard Phase 2 Baseline Training & Evaluation Script.

Trains Logistic Regression on:
1. Config A (Fused Flow + Packet, 84 numeric features) using scaler.joblib
2. Config B (Flow-Only Baseline, 77 numeric features) using separate scaler

Evaluates on test splits, reporting detailed per-class precision, recall, F1,
confusion matrices, and Config A vs Config B comparison.
"""

import sys
from pathlib import Path
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import joblib
import json
from typing import Tuple, List, Dict, Optional
from sklearn.preprocessing import StandardScaler, LabelEncoder

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.baseline.baseline_model import train_logistic_baseline, evaluate_baseline_model
from src.features.schema import get_numeric_feature_names

def load_and_scale_split(split_path: str,
                         feature_cols: list,
                         scaler: StandardScaler,
                         label_encoder: LabelEncoder) -> Tuple[np.ndarray, np.ndarray]:
    """Load split, extract numeric features, apply scaler, and encode labels in a memory-safe way."""
    pf = pq.ParquetFile(split_path)
    X_parts = []
    y_parts = []
    
    for batch in pf.iter_batches(batch_size=200_000, columns=feature_cols + ["Label"]):
        df_batch = batch.to_pandas()
        
        # Features
        X_mat = df_batch[feature_cols].values.astype(np.float64)
        X_mat = np.nan_to_num(X_mat, nan=0.0, posinf=0.0, neginf=0.0)
        X_scaled = scaler.transform(X_mat).astype(np.float32)
        X_parts.append(X_scaled)
        
        # Labels
        y_enc = label_encoder.transform(df_batch["Label"].astype(str))
        y_parts.append(y_enc)
        
    X_all = np.vstack(X_parts)
    y_all = np.concatenate(y_parts)
    return X_all, y_all


def main():
    print("=" * 80)
    print("NETGUARD PHASE 2: BASELINE MODELING & EVALUATION (CONFIG A vs CONFIG B)")
    print("=" * 80)
    
    checkpoint_dir = Path("models/checkpoints")
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    
    # ─── 1. Setup Classes and Label Encoder ───────────────────────────────────
    with open(checkpoint_dir / "feature_columns.json", "r") as f:
        manifest = json.load(f)
    classes = manifest["classes"]
    le = LabelEncoder()
    le.fit(classes)
    
    print(f"Target classes ({len(classes)}): {classes}")
    
    # ─── 2. WORKSTREAM 1A: Config A Baseline (Fused Flow + Packet) ────────────
    print("\n" + "-" * 80)
    print("TRAINING & EVALUATING BASELINE ON CONFIG A (FUSED FLOW + PACKET, 84 FEATURES)")
    print("-" * 80)
    
    features_a = manifest["numeric_features"]
    scaler_a = joblib.load(checkpoint_dir / "scaler.joblib")
    
    print("Loading scaled Config A train split...")
    X_train_a, y_train_a = load_and_scale_split("data/processed/train_v1.parquet", features_a, scaler_a, le)
    print(f"  Config A Train: {X_train_a.shape[0]:,} samples x {X_train_a.shape[1]} features")
    
    model_a = train_logistic_baseline(X_train_a, y_train_a, np.arange(len(classes)), random_seed=42)
    joblib.dump(model_a, checkpoint_dir / "baseline_logreg_configA.joblib")
    print(f"  Saved model to: {checkpoint_dir / 'baseline_logreg_configA.joblib'}")
    
    del X_train_a, y_train_a  # Free memory
    
    print("Loading scaled Config A test split...")
    X_test_a, y_test_a = load_and_scale_split("data/processed/test_v1.parquet", features_a, scaler_a, le)
    print(f"  Config A Test: {X_test_a.shape[0]:,} samples")
    
    metrics_a = evaluate_baseline_model(model_a, X_test_a, y_test_a, list(le.classes_))
    del X_test_a, y_test_a
    
    # ─── 3. WORKSTREAM 1B: Config B Baseline (Flow-Only Baseline) ─────────────
    print("\n" + "-" * 80)
    print("TRAINING & EVALUATING BASELINE ON CONFIG B (FLOW-ONLY BASELINE, 77 FEATURES)")
    print("-" * 80)
    
    features_b = get_numeric_feature_names(include_packet_level=False)
    
    # Fit scaler for Config B on train_flow_only.parquet
    print("Fitting separate StandardScaler on Config B train split...")
    pf_train_b = pq.ParquetFile("data/processed/train_flow_only.parquet")
    sample_b = pf_train_b.read_row_group(0, columns=features_b).to_pandas()
    valid_features_b = [f for f in features_b if f in sample_b.columns]
    
    scaler_b = StandardScaler()
    for batch in pf_train_b.iter_batches(batch_size=200_000, columns=valid_features_b):
        df_batch = batch.to_pandas()
        X_mat = df_batch.values.astype(np.float64)
        X_mat = np.nan_to_num(X_mat, nan=0.0, posinf=0.0, neginf=0.0)
        scaler_b.partial_fit(X_mat)
        
    joblib.dump(scaler_b, checkpoint_dir / "scaler_configB.joblib")
    print(f"  Saved Config B scaler to: {checkpoint_dir / 'scaler_configB.joblib'}")
    
    print("Loading scaled Config B train split...")
    X_train_b, y_train_b = load_and_scale_split("data/processed/train_flow_only.parquet", valid_features_b, scaler_b, le)
    print(f"  Config B Train: {X_train_b.shape[0]:,} samples x {X_train_b.shape[1]} features")
    
    model_b = train_logistic_baseline(X_train_b, y_train_b, np.arange(len(classes)), random_seed=42)
    joblib.dump(model_b, checkpoint_dir / "baseline_logreg_configB.joblib")
    print(f"  Saved model to: {checkpoint_dir / 'baseline_logreg_configB.joblib'}")
    
    del X_train_b, y_train_b
    
    print("Loading scaled Config B test split...")
    X_test_b, y_test_b = load_and_scale_split("data/processed/test_flow_only.parquet", valid_features_b, scaler_b, le)
    print(f"  Config B Test: {X_test_b.shape[0]:,} samples")
    
    metrics_b = evaluate_baseline_model(model_b, X_test_b, y_test_b, list(le.classes_))
    del X_test_b, y_test_b
    
    # ─── 4. Comparison Table & Metrics Export ─────────────────────────────────
    print("\n" + "=" * 80)
    print("PER-CLASS EVALUATION & ABLATION COMPARISON: CONFIG A vs CONFIG B")
    print("=" * 80)
    
    comparison_rows = []
    for cls_name in classes:
        rep_a = metrics_a["classification_report"].get(cls_name, {})
        rep_b = metrics_b["classification_report"].get(cls_name, {})
        
        comparison_rows.append({
            "Class": cls_name,
            "Support (A)": int(rep_a.get("support", 0)),
            "Prec A": round(rep_a.get("precision", 0.0), 4),
            "Rec A": round(rep_a.get("recall", 0.0), 4),
            "F1 A": round(rep_a.get("f1-score", 0.0), 4),
            "Support (B)": int(rep_b.get("support", 0)),
            "Prec B": round(rep_b.get("precision", 0.0), 4),
            "Rec B": round(rep_b.get("recall", 0.0), 4),
            "F1 B": round(rep_b.get("f1-score", 0.0), 4),
            "F1 Delta (A - B)": round(rep_a.get("f1-score", 0.0) - rep_b.get("f1-score", 0.0), 4)
        })
        
    df_comp = pd.DataFrame(comparison_rows)
    print(df_comp.to_string(index=False))
    
    print("\nSummary Aggregate Metrics:")
    print(f"  Config A Macro F1:    {metrics_a['macro_avg']['f1-score']:.4f} | Weighted F1: {metrics_a['weighted_avg']['f1-score']:.4f} | FPR: {metrics_a['false_positive_rate']:.4f}")
    print(f"  Config B Macro F1:    {metrics_b['macro_avg']['f1-score']:.4f} | Weighted F1: {metrics_b['weighted_avg']['f1-score']:.4f} | FPR: {metrics_b['false_positive_rate']:.4f}")
    print(f"  Macro F1 Gain (A - B): {metrics_a['macro_avg']['f1-score'] - metrics_b['macro_avg']['f1-score']:+.4f}")
    
    # Save comparison metrics
    summary_data = {
        "config_a": metrics_a,
        "config_b": metrics_b,
        "comparison_table": comparison_rows,
        "macro_f1_delta": float(metrics_a['macro_avg']['f1-score'] - metrics_b['macro_avg']['f1-score']),
        "weighted_f1_delta": float(metrics_a['weighted_avg']['f1-score'] - metrics_b['weighted_avg']['f1-score'])
    }
    
    metrics_path = checkpoint_dir / "baseline_comparison_metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(summary_data, f, indent=2)
    print(f"\nSaved baseline comparison metrics to: {metrics_path}")

if __name__ == "__main__":
    main()
