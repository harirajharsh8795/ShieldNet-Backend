"""
ShieldNet Phase 1 Master Pipeline Execution Script (Memory-Optimized).

Performs:
1. Window-size density diagnostics on Config A.
2. Label standardization and Rare-Attack meta-class merging.
3. Stratified 70/15/15 train/val/test splits for Config A and aligned Config B.
4. StandardScaler fitting on Train split ONLY (saved to models/checkpoints/scaler.joblib).
5. Auto-generation of docs/DATA_DICTIONARY.md.
"""

import sys
from pathlib import Path
import pandas as pd
import numpy as np
import pyarrow.parquet as pq
import pyarrow as pa
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import json

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.features.schema import (
    get_config_a_feature_names, get_numeric_feature_names, generate_data_dictionary
)
from src.features.preprocessing import (
    clean_label_string, standardize_and_merge_rare_classes, RARE_ATTACK_CLASSES
)
from src.features.sequencer import analyze_window_density

def main():
    print("=" * 80)
    print("SHIELDNET PHASE 1: DUAL-LEVEL FEATURE ENGINEERING & PARSING")
    print("=" * 80)
    
    config_a_path = "data/processed/fused_matched_v1.parquet"
    config_b_path = "data/processed/flow_only_full.parquet"
    output_dir = Path("data/processed")
    output_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_dir = Path("models/checkpoints")
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    
    # ─── 1. Window Density Diagnostics (Task 1) ───────────────────────────────
    print("\n[1/5] Running Time-Window Density Diagnostics (10-second windows)...")
    meta_cols = ["Timestamp", "Source IP", "session_group"]
    df_meta_a = pd.read_parquet(config_a_path, columns=meta_cols)
    print(f"  Loaded {len(df_meta_a):,} flow timestamps for density profiling.")
    
    host_stats = analyze_window_density(df_meta_a, window_size_seconds=10, group_by="host")
    session_stats = analyze_window_density(df_meta_a, window_size_seconds=10, group_by="session")
    
    print("\n  A. Host-Level Windowing (Group by Session + Source IP):")
    for k, v in host_stats.items():
        if isinstance(v, float):
            print(f"    - {k}: {v:.2f}")
        else:
            print(f"    - {k}: {v:,}")
            
    print("\n  B. Session-Level Windowing (Group by Session):")
    for k, v in session_stats.items():
        if isinstance(v, float):
            print(f"    - {k}: {v:.2f}")
        else:
            print(f"    - {k}: {v:,}")
            
    del df_meta_a  # Free memory
    
    # ─── 2. Sparse-Class Handling & Stratified Split Indexing (Task 2 & 3) ─────
    print("\n[2/5] Standardizing Labels and Merging Rare Attack Classes...")
    df_labels_a = pd.read_parquet(config_a_path, columns=["Label"])
    df_labels_a = standardize_and_merge_rare_classes(df_labels_a, label_col="Label")
    
    print("\n  Config A Final Post-Merge Class Distribution (2,194,284 flows):")
    dist_a = df_labels_a["Label"].value_counts().reset_index()
    dist_a.columns = ["Label", "Count"]
    dist_a["Percentage"] = (dist_a["Count"] / len(df_labels_a)) * 100
    print(dist_a.to_string(index=False))
    
    # Rare-Attack composition
    rare_mask = df_labels_a["Label"] == "Rare-Attack"
    print(f"\n  Rare-Attack Meta-Class Composition (Total: {rare_mask.sum()} flows):")
    print(df_labels_a[rare_mask]["Label_Original"].value_counts().to_string())
    
    print("\n  Computing Stratified 70/15/15 Split Indices for Config A...")
    n_total_a = len(df_labels_a)
    all_indices_a = np.arange(n_total_a)
    labels_a = df_labels_a["Label"].values
    
    # Stratified split: 70% Train, 30% (Val + Test)
    train_idx_a, val_test_idx_a = train_test_split(
        all_indices_a,
        test_size=0.30,
        random_state=42,
        stratify=labels_a
    )
    
    # Split remainder 50/50 -> 15% Val, 15% Test
    val_idx_a, test_idx_a = train_test_split(
        val_test_idx_a,
        test_size=0.50,
        random_state=42,
        stratify=labels_a[val_test_idx_a]
    )
    
    train_set_a = set(train_idx_a)
    val_set_a = set(val_idx_a)
    test_set_a = set(test_idx_a)
    
    print(f"  Config A Split Sizes:")
    print(f"    - Train (70%): {len(train_idx_a):,} rows")
    print(f"    - Val   (15%): {len(val_idx_a):,} rows")
    print(f"    - Test  (15%): {len(test_idx_a):,} rows")
    
    # Verify stratification balance
    train_labels = df_labels_a.iloc[train_idx_a]["Label"].value_counts()
    val_labels = df_labels_a.iloc[val_idx_a]["Label"].value_counts()
    test_labels = df_labels_a.iloc[test_idx_a]["Label"].value_counts()
    
    split_dist = pd.DataFrame({
        "Train Count": train_labels,
        "Train (%)": (train_labels / len(train_idx_a)) * 100,
        "Val Count": val_labels,
        "Val (%)": (val_labels / len(val_idx_a)) * 100,
        "Test Count": test_labels,
        "Test (%)": (test_labels / len(test_idx_a)) * 100,
    }).round(3)
    print("\n  Class Distribution per Split:")
    print(split_dist.to_string())
    
    del df_labels_a  # Free memory
    
    # ─── 3. Stream & Write Config A Split Parquets ────────────────────────────
    print("\n[3/5] Streaming and Writing Config A Parquet Splits...")
    train_a_path = output_dir / "train_v1.parquet"
    val_a_path = output_dir / "val_v1.parquet"
    test_a_path = output_dir / "test_v1.parquet"
    
    pf_a = pq.ParquetFile(config_a_path)
    writer_train_a = None
    writer_val_a = None
    writer_test_a = None
    
    current_global_idx = 0
    
    for batch in pf_a.iter_batches(batch_size=200_000):
        df_batch = batch.to_pandas()
        batch_len = len(df_batch)
        batch_indices = np.arange(current_global_idx, current_global_idx + batch_len)
        current_global_idx += batch_len
        
        # Standardize labels and add Label_Original
        df_batch = standardize_and_merge_rare_classes(df_batch, label_col="Label")
        
        # Masks for this batch
        in_train = np.isin(batch_indices, train_idx_a)
        in_val = np.isin(batch_indices, val_idx_a)
        in_test = np.isin(batch_indices, test_idx_a)
        
        # Write train
        if np.any(in_train):
            sub_df = df_batch[in_train]
            tbl = pa.Table.from_pandas(sub_df, preserve_index=False)
            if writer_train_a is None:
                writer_train_a = pq.ParquetWriter(train_a_path, tbl.schema, compression="snappy")
            writer_train_a.write_table(tbl)
            
        # Write val
        if np.any(in_val):
            sub_df = df_batch[in_val]
            tbl = pa.Table.from_pandas(sub_df, preserve_index=False)
            if writer_val_a is None:
                writer_val_a = pq.ParquetWriter(val_a_path, tbl.schema, compression="snappy")
            writer_val_a.write_table(tbl)
            
        # Write test
        if np.any(in_test):
            sub_df = df_batch[in_test]
            tbl = pa.Table.from_pandas(sub_df, preserve_index=False)
            if writer_test_a is None:
                writer_test_a = pq.ParquetWriter(test_a_path, tbl.schema, compression="snappy")
            writer_test_a.write_table(tbl)
            
    if writer_train_a: writer_train_a.close()
    if writer_val_a: writer_val_a.close()
    if writer_test_a: writer_test_a.close()
    print(f"  Config A splits saved successfully:\n    - {train_a_path}\n    - {val_a_path}\n    - {test_a_path}")
    
    # ─── 4. Stream & Write Config B Splits (Aligned) ──────────────────────────
    print("\n  Aligning and Splitting Config B (Flow-Only Baseline)...")
    df_labels_b = pd.read_parquet(config_b_path, columns=["Label"])
    df_labels_b = standardize_and_merge_rare_classes(df_labels_b, label_col="Label")
    
    all_indices_b = np.arange(len(df_labels_b))
    labels_b = df_labels_b["Label"].values
    
    train_idx_b, val_test_idx_b = train_test_split(
        all_indices_b,
        test_size=0.30,
        random_state=42,
        stratify=labels_b
    )
    val_idx_b, test_idx_b = train_test_split(
        val_test_idx_b,
        test_size=0.50,
        random_state=42,
        stratify=labels_b[val_test_idx_b]
    )
    
    train_b_path = output_dir / "train_flow_only.parquet"
    val_b_path = output_dir / "val_flow_only.parquet"
    test_b_path = output_dir / "test_flow_only.parquet"
    
    pf_b = pq.ParquetFile(config_b_path)
    writer_train_b = None
    writer_val_b = None
    writer_test_b = None
    current_global_idx = 0
    
    for batch in pf_b.iter_batches(batch_size=200_000):
        df_batch = batch.to_pandas()
        batch_len = len(df_batch)
        batch_indices = np.arange(current_global_idx, current_global_idx + batch_len)
        current_global_idx += batch_len
        
        df_batch = standardize_and_merge_rare_classes(df_batch, label_col="Label")
        
        in_train = np.isin(batch_indices, train_idx_b)
        in_val = np.isin(batch_indices, val_idx_b)
        in_test = np.isin(batch_indices, test_idx_b)
        
        if np.any(in_train):
            tbl = pa.Table.from_pandas(df_batch[in_train], preserve_index=False)
            if writer_train_b is None:
                writer_train_b = pq.ParquetWriter(train_b_path, tbl.schema, compression="snappy")
            writer_train_b.write_table(tbl)
            
        if np.any(in_val):
            tbl = pa.Table.from_pandas(df_batch[in_val], preserve_index=False)
            if writer_val_b is None:
                writer_val_b = pq.ParquetWriter(val_b_path, tbl.schema, compression="snappy")
            writer_val_b.write_table(tbl)
            
        if np.any(in_test):
            tbl = pa.Table.from_pandas(df_batch[in_test], preserve_index=False)
            if writer_test_b is None:
                writer_test_b = pq.ParquetWriter(test_b_path, tbl.schema, compression="snappy")
            writer_test_b.write_table(tbl)
            
    if writer_train_b: writer_train_b.close()
    if writer_val_b: writer_val_b.close()
    if writer_test_b: writer_test_b.close()
    print(f"  Config B splits saved successfully:\n    - {train_b_path}\n    - {val_b_path}\n    - {test_b_path}")
    
    del df_labels_b
    
    # ─── 5. Fit StandardScaler Incrementally on Train Split (Task 4) ──────────
    print("\n[4/5] Fitting StandardScaler incrementally on Config A Train Split...")
    numeric_features = get_numeric_feature_names(include_packet_level=True)
    
    # Check sample batch to confirm available columns
    pf_train = pq.ParquetFile(train_a_path)
    sample_batch = pf_train.read_row_group(0, columns=numeric_features).to_pandas()
    valid_numeric_features = [f for f in numeric_features if f in sample_batch.columns]
    print(f"  Fitting StandardScaler on {len(valid_numeric_features)} numeric features...")
    
    scaler = StandardScaler()
    
    for batch in pf_train.iter_batches(batch_size=200_000, columns=valid_numeric_features):
        df_num = batch.to_pandas()
        X_batch = df_num.values.astype(np.float64)
        X_batch = np.nan_to_num(X_batch, nan=0.0, posinf=0.0, neginf=0.0)
        scaler.partial_fit(X_batch)
        
    scaler_path = checkpoint_dir / "scaler.joblib"
    joblib.dump(scaler, scaler_path)
    print(f"  Fitted StandardScaler artifact saved to: {scaler_path}")
    
    # Save feature columns metadata manifest
    manifest_path = checkpoint_dir / "feature_columns.json"
    with open(manifest_path, "w") as f:
        json.dump({
            "numeric_features": valid_numeric_features,
            "flow_features_count": len([f for f in valid_numeric_features if f not in ["ttl_mean", "ttl_variance", "tcp_window_mean", "tcp_window_min", "tcp_window_max", "ip_fragment_flag_present", "retransmission_count"]]),
            "packet_features_count": len(["ttl_mean", "ttl_variance", "tcp_window_mean", "tcp_window_min", "tcp_window_max", "ip_fragment_flag_present", "retransmission_count"]),
            "classes": sorted(list(train_labels.index))
        }, f, indent=2)
    print(f"  Feature manifest saved to: {manifest_path}")
    
    # ─── 6. Generate Data Dictionary (Task 5) ─────────────────────────────────
    print("\n[5/5] Auto-generating docs/DATA_DICTIONARY.md...")
    dict_path = generate_data_dictionary("docs/DATA_DICTIONARY.md")
    print(f"  Data Dictionary updated at: {dict_path}")
    
    print("\n" + "=" * 80)
    print("PHASE 1 EXECUTION COMPLETE & VERIFIED!")
    print("=" * 80)

if __name__ == "__main__":
    main()
