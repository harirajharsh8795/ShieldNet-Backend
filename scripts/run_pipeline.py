"""
ShieldNet Master Pipeline — End-to-End Execution.

Runs the complete pipeline from data loading through training to evaluation:
1. Load & preprocess data
2. Create time-windowed sequences
3. Train baseline (Logistic Regression)
4. Train World Model (LSTM)
5. Evaluate both models
6. Generate comparison report

Usage:
    python scripts/run_pipeline.py [--config configs/default.yaml] [--skip-training]
"""

import sys
import os
import json
import time
import argparse
import numpy as np
import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.config import load_config
from src.features.schema import get_model_feature_names, generate_data_dictionary
from src.features.packet_level import derive_packet_features_from_flow
from src.features.sequencer import create_time_windows, create_sequences, get_window_feature_names
from src.features.preprocessing import (
    stratified_split, fit_scaler, transform_features, 
    encode_labels, save_processed_data
)
from src.ingestion.loader import load_cic_ids_2018, load_ctu_13


def run_pipeline(config_path=None, skip_training=False):
    """Run the complete ShieldNet pipeline."""
    
    print("=" * 70)
    print("  ShieldNet — Master Pipeline")
    print("=" * 70)
    
    # ─── Load Config ──────────────────────────────────────────────
    config = load_config(config_path)
    seed = config.get('seed', 42)
    np.random.seed(seed)
    
    print(f"\n  Config: {config_path or 'default'}")
    print(f"  Seed: {seed}")
    
    # ─── Phase 1: Data Loading ────────────────────────────────────
    print(f"\n{'─'*70}")
    print("  PHASE 1: Data Loading & Feature Engineering")
    print(f"{'─'*70}")
    
    # Load CIC-IDS-2018
    cic_dir = config['data']['cic_ids_2018_dir']
    print(f"\n  Loading CIC-IDS-2018 from {cic_dir}...")
    try:
        cic_df = load_cic_ids_2018(cic_dir)
        print(f"  CIC-IDS-2018: {len(cic_df):,} rows loaded")
    except FileNotFoundError:
        print(f"  WARNING: CIC-IDS-2018 not found at {cic_dir}")
        print(f"  Run 'python scripts/generate_synthetic_data.py' first")
        return
    
    # Load CTU-13
    ctu_dir = config['data']['ctu_13_dir']
    print(f"\n  Loading CTU-13 from {ctu_dir}...")
    try:
        ctu_df = load_ctu_13(ctu_dir)
        print(f"  CTU-13: {len(ctu_df):,} rows loaded")
    except FileNotFoundError:
        print(f"  WARNING: CTU-13 not found at {ctu_dir}")
        ctu_df = None
    
    # ─── Derive Packet-Level Features ─────────────────────────────
    print(f"\n  Deriving packet-level features...")
    cic_df = derive_packet_features_from_flow(cic_df)
    if ctu_df is not None:
        ctu_df = derive_packet_features_from_flow(ctu_df)
    
    # Verify both feature levels
    model_features = get_model_feature_names()
    present = [f for f in model_features if f in cic_df.columns]
    print(f"  Model features present: {len(present)}/{len(model_features)}")
    
    # ─── Generate Data Dictionary ─────────────────────────────────
    dict_path = PROJECT_ROOT / "docs" / "DATA_DICTIONARY.md"
    generate_data_dictionary(str(dict_path))
    print(f"  Data dictionary: {dict_path}")
    
    # ─── Split Data ───────────────────────────────────────────────
    print(f"\n  Splitting CIC-IDS-2018...")
    split_config = config.get('split', {})
    train_df, val_df, test_df = stratified_split(
        cic_df,
        train_ratio=split_config.get('train_ratio', 0.7),
        val_ratio=split_config.get('val_ratio', 0.15),
        test_ratio=split_config.get('test_ratio', 0.15),
        random_seed=seed,
    )
    
    # ─── Encode Labels ────────────────────────────────────────────
    train_df, label_encoder = encode_labels(train_df)
    val_df, _ = encode_labels(val_df, encoder=label_encoder)
    test_df, _ = encode_labels(test_df, encoder=label_encoder)
    
    # ─── Scale Features (fit on train only!) ──────────────────────
    feature_cols = [f for f in model_features if f in train_df.columns]
    scaler = fit_scaler(train_df, feature_cols)
    train_df = transform_features(train_df, scaler, feature_cols)
    val_df = transform_features(val_df, scaler, feature_cols)
    test_df = transform_features(test_df, scaler, feature_cols)
    
    # ─── Save Processed Data ─────────────────────────────────────
    version = config['data'].get('version', 'v1')
    processed_dir = str(PROJECT_ROOT / "data" / "processed" / version)
    save_processed_data(
        processed_dir, train_df, val_df, test_df,
        scaler, label_encoder, feature_cols,
    )
    
    # ─── Phase 2: Baseline Model ─────────────────────────────────
    print(f"\n{'─'*70}")
    print("  PHASE 2: Baseline Model (Logistic Regression)")
    print(f"{'─'*70}")
    
    from src.baseline.baseline_model import train_baseline, evaluate_baseline, save_baseline
    
    baseline_config = config.get('baseline', {})
    baseline_model = train_baseline(train_df, feature_cols, config=baseline_config)
    
    baseline_metrics = evaluate_baseline(
        baseline_model, test_df, feature_cols,
        label_names=list(label_encoder.classes_)
    )
    
    save_baseline(baseline_model, baseline_metrics, str(PROJECT_ROOT / "models" / "checkpoints"))
    
    # ─── Phase 3: World Model ────────────────────────────────────
    print(f"\n{'─'*70}")
    print("  PHASE 3: World Model (LSTM Sequence Model)")
    print(f"{'─'*70}")
    
    # Create time-windowed sequences
    seq_config = config.get('sequencer', {})
    window_size = seq_config.get('window_size_seconds', 10)
    seq_length = seq_config.get('sequence_length', 20)
    min_flows = seq_config.get('min_flows_per_window', 5)
    
    print(f"\n  Creating time windows (window={window_size}s, seq_len={seq_length})...")
    
    train_windows = create_time_windows(train_df, window_size, min_flows)
    val_windows = create_time_windows(val_df, window_size, min_flows)
    test_windows = create_time_windows(test_df, window_size, min_flows)
    
    print(f"  Windows — Train: {len(train_windows)} | Val: {len(val_windows)} | Test: {len(test_windows)}")
    
    window_feature_names = get_window_feature_names(train_windows)
    
    # Create sequences
    print(f"  Creating sequences...")
    X_train, y_train_states, y_train_labels = create_sequences(train_windows, seq_length)
    X_val, y_val_states, y_val_labels = create_sequences(val_windows, seq_length)
    X_test, y_test_states, y_test_labels = create_sequences(test_windows, seq_length)
    
    print(f"  Sequences — Train: {X_train.shape} | Val: {X_val.shape} | Test: {X_test.shape}")
    
    # Save sequence data for prove_world_model.py
    np.savez(
        str(PROJECT_ROOT / "data" / "processed" / version / "sequences.npz"),
        X_train=X_train, y_train_states=y_train_states, y_train_labels=y_train_labels,
        X_val=X_val, y_val_states=y_val_states, y_val_labels=y_val_labels,
        X_test=X_test, y_test_states=y_test_states, y_test_labels=y_test_labels,
    )
    
    # Save window feature names
    with open(str(PROJECT_ROOT / "data" / "processed" / version / "window_feature_names.json"), 'w') as f:
        json.dump(window_feature_names, f, indent=2)
    
    if skip_training:
        print("\n  --skip-training flag set, skipping World Model training")
        return
    
    # Train World Model
    import torch
    from src.world_model.trainer import train_world_model
    
    print(f"\n  Training World Model...")
    checkpoint_dir = str(PROJECT_ROOT / "models" / "checkpoints")
    
    model, history = train_world_model(
        X_train, y_train_states, y_train_labels,
        X_val, y_val_states, y_val_labels,
        config, checkpoint_dir
    )
    
    # ─── Phase 4-5: Evaluation ────────────────────────────────────
    print(f"\n{'─'*70}")
    print("  PHASE 4-5: Evaluation & Comparison")
    print(f"{'─'*70}")
    
    from src.evaluation.evaluate import evaluate_world_model, compare_models, save_evaluation_results
    
    wm_metrics = evaluate_world_model(
        model, X_test, y_test_states, y_test_labels,
        label_names=list(label_encoder.classes_),
    )
    
    # Comparison
    comparison = compare_models(baseline_metrics, wm_metrics)
    
    print(f"\n  Model Comparison:")
    print(comparison.to_string(index=False))
    
    save_evaluation_results(wm_metrics, comparison, str(PROJECT_ROOT / "models"))
    
    # ─── Save Demo Sample ─────────────────────────────────────────
    # Save a small sample for the dashboard demo
    sample_size = min(1000, len(test_df))
    demo_sample = test_df.head(sample_size)
    demo_path = PROJECT_ROOT / "data" / "processed" / version / "sample_demo.csv"
    demo_sample.to_csv(demo_path, index=False)
    print(f"\n  Demo sample saved: {demo_path} ({sample_size} rows)")
    
    print(f"\n{'='*70}")
    print("  Pipeline complete!")
    print(f"{'='*70}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='ShieldNet Master Pipeline')
    parser.add_argument('--config', default=None, help='Path to config YAML')
    parser.add_argument('--skip-training', action='store_true', help='Skip model training')
    args = parser.parse_args()
    
    run_pipeline(args.config, args.skip_training)
