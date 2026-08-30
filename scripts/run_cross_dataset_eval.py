"""
Cross-Dataset Generalisation Evaluation Script.

Evaluates a model trained on CIC-IDS-2018 against CTU-13 (or vice versa)
to satisfy the PS requirement: "must generalise to unseen attack patterns, not memorise signatures."

Usage:
    python scripts/run_cross_dataset_eval.py --train-dataset cic-ids-2018 --test-dataset ctu-13
"""

import sys
import json
import argparse
import numpy as np
import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.config import load_config
from src.features.schema import get_model_feature_names
from src.features.packet_level import derive_packet_features_from_flow
from src.features.sequencer import create_time_windows, create_sequences
from src.features.preprocessing import transform_features, load_processed_data
from src.ingestion.loader import load_dataset
from src.world_model.trainer import load_world_model
from src.evaluation.evaluate import evaluate_world_model


def run_cross_dataset_evaluation(train_ds='cic-ids-2018', test_ds='ctu-13'):
    print("=" * 70)
    print(f"  NetGuard — Cross-Dataset Generalisation Test")
    print(f"  Train Source: {train_ds}  -->  Test Target: {test_ds}")
    print("=" * 70)

    config = load_config()
    processed = load_processed_data("data/processed/v1")
    scaler = processed['scaler']
    label_encoder = processed['label_encoder']
    feature_cols = processed['feature_cols']

    # Load test dataset
    print(f"\nLoading test target dataset ({test_ds})...")
    try:
        test_raw_df = load_dataset(test_ds, config)
    except Exception as e:
        print(f"Error loading {test_ds}: {e}")
        print("Ensure raw data for the target dataset exists in data/raw/")
        return False

    test_raw_df = derive_packet_features_from_flow(test_raw_df)
    test_scaled_df = transform_features(test_raw_df, scaler, feature_cols)

    # Sequence creation
    print("Creating time-windowed sequences for target dataset...")
    seq_config = config.get('sequencer', {})
    windows = create_time_windows(
        test_scaled_df,
        window_size_seconds=seq_config.get('window_size_seconds', 10),
        min_flows_per_window=seq_config.get('min_flows_per_window', 5)
    )

    X_test, y_test_states, y_test_labels = create_sequences(
        windows, sequence_length=seq_config.get('sequence_length', 20)
    )

    print(f"Generated {len(X_test):,} sequences from target dataset.")

    # Load trained model
    model_path = "models/checkpoints/world_model_best.pt"
    if not Path(model_path).exists():
        print(f"Model checkpoint not found at {model_path}. Train the model first.")
        return False

    model = load_world_model(model_path)
    metrics = evaluate_world_model(
        model, X_test, y_test_states, y_test_labels,
        label_names=list(label_encoder.classes_)
    )

    print(f"\n{'─'*50}")
    print("Cross-Dataset Generalisation Results:")
    print(f"{'─'*50}")
    print(f"  F1 Score (Weighted):    {metrics['f1_weighted']:.4f}")
    print(f"  Precision (Weighted): {metrics['precision_weighted']:.4f}")
    print(f"  Recall (Weighted):    {metrics['recall_weighted']:.4f}")
    print(f"  False Positive Rate:  {metrics['false_positive_rate']:.4f}")
    print(f"  Next-State MSE:       {metrics['state_prediction_mse']:.6f}")

    # Save output
    out_file = Path("docs/cross_dataset_eval.json")
    with open(out_file, 'w') as f:
        json.dump(metrics, f, indent=2)

    print(f"\n✓ Cross-dataset evaluation results saved to {out_file}")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--train-dataset", default="cic-ids-2018")
    parser.add_argument("--test-dataset", default="ctu-13")
    args = parser.parse_args()

    run_cross_dataset_evaluation(args.train_dataset, args.test_dataset)
