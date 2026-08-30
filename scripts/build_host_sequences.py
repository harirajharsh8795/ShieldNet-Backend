"""
ShieldNet Host-Level Temporal Sequence Builder (Corrected Window-First Order, Memory-Optimized).

Methodology:
1. Group the FULL Config A (2,194,284 flows) into whole host-level 10-second windows FIRST.
   - Validates that total windows = 139,908 and sequence-eligible (>= 2 flows) = 65,190.
2. Applies scaler to the 139,908 aggregated window feature vectors S_t.
3. Performs WINDOW-LEVEL stratified split (70/15/15) by window's dominant attack label.
   - Includes deliberate stratification override for ultra-rare classes (e.g. Rare-Attack: 4 train, 1 val, 1 test).
4. Saves intact, non-fragmented window sequences to:
   - data/processed/sequences_train.parquet
   - data/processed/sequences_val.parquet
   - data/processed/sequences_test.parquet
5. Re-generates sequence_metadata.json.
"""

import sys
from pathlib import Path
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import joblib
import json
from typing import Tuple, Dict, List, Optional
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.features.sequencer import parse_timestamps, MITRE_STAGE_MAP
from src.features.preprocessing import standardize_and_merge_rare_classes

def build_host_windows_from_full_config_a(config_a_path: str,
                                          numeric_features: List[str],
                                          scaler: StandardScaler,
                                          window_size_seconds: int = 10) -> pd.DataFrame:
    """Group the full Config A dataset into whole, unfragmented host-level 10s windows."""
    print(f"Loading full Config A from {config_a_path} (2,194,284 flows)...")
    
    cols_to_load = ["Timestamp", "session_group", "Source IP", "Label"] + numeric_features
    df = pd.read_parquet(config_a_path, columns=cols_to_load)
    n_flows = len(df)
    print(f"  Loaded {n_flows:,} flows.")
    
    # Standardize labels and add Label_Original
    df = standardize_and_merge_rare_classes(df, label_col="Label")
    df["_parsed_time"] = parse_timestamps(df["Timestamp"])
    df["_host_key"] = df["session_group"].astype(str) + "___" + df["Source IP"].astype(str)
    
    # 1. Compute t0 per host
    print("  Computing per-host temporal window bins (10s windows)...")
    host_t0 = df.groupby("_host_key")["_parsed_time"].transform("min")
    df["_bin_idx"] = ((df["_parsed_time"] - host_t0).dt.total_seconds() // window_size_seconds).astype(np.int64)
    df["_win_id"] = df["_host_key"] + "___w" + df["_bin_idx"].astype(str)
    
    total_unique_windows = df["_win_id"].nunique()
    print(f"  Total unique host windows formed: {total_unique_windows:,}")
    
    # 2. Vectorized aggregation of metadata, labels, and MITRE stages
    print("  Vectorized aggregation of window metadata and security labels...")
    df["_is_benign"] = (df["Label"] == "BENIGN").astype(int)
    df["_mitre_stage"] = df["Label"].map(lambda l: MITRE_STAGE_MAP.get(str(l), 0))
    
    meta_grouped = df.groupby("_win_id", sort=False).agg(
        flow_count=("_parsed_time", "count"),
        window_start_time=("_parsed_time", "min"),
        window_end_time=("_parsed_time", "max"),
        session_group=("session_group", "first"),
        source_ip=("Source IP", "first"),
        window_idx=("_bin_idx", "first"),
        label=("Label", "first"),
        label_original=("Label_Original", "first"),
        benign_count=("_is_benign", "sum"),
        mitre_stage=("_mitre_stage", "max"),
    )
    
    # 3. Aggregate unscaled numeric feature means across windows (memory-safe)
    print("  Computing window state means for 139,908 windows...")
    unscaled_means = df.groupby("_win_id", sort=False)[numeric_features].mean()
    
    # Replace inf/nan in the 139,908 rows and scale to produce S_t
    win_ids = list(meta_grouped.index)
    X_unscaled_win = unscaled_means.loc[win_ids].values.astype(np.float64)
    X_unscaled_win = np.nan_to_num(X_unscaled_win, nan=0.0, posinf=0.0, neginf=0.0)
    
    print("  Applying StandardScaler to 139,908 window state vectors...")
    X_scaled_win = scaler.transform(X_unscaled_win).astype(np.float32)
    
    meta_grouped["attack_ratio"] = 1.0 - (meta_grouped["benign_count"] / meta_grouped["flow_count"])
    meta_grouped["host_window_id"] = [w.replace("___", "_") for w in meta_grouped.index]
    meta_grouped["is_sequence_eligible"] = meta_grouped["flow_count"] >= 2
    meta_grouped["state_vector"] = X_scaled_win.tolist()
    
    meta_grouped = meta_grouped.drop(columns=["benign_count"])
    full_windows_df = meta_grouped.reset_index(drop=True)
    
    return full_windows_df


def stratified_split_windows(windows_df: pd.DataFrame,
                             train_ratio: float = 0.70,
                             val_ratio: float = 0.15,
                             test_ratio: float = 0.15,
                             random_seed: int = 42) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Perform window-level stratified train/val/test split by dominant window label.
    
    Handles rare classes with explicit override (ensuring >= 1 sample in val and test).
    """
    assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-6
    
    windows_df = windows_df.copy()
    labels = windows_df["label"].values
    
    counts = windows_df["label"].value_counts()
    print("\nWindow counts per class across ALL 139,908 windows:")
    print(counts.to_string())
    
    # Separate standard classes from Rare-Attack (which has few windows)
    standard_mask = ~windows_df["label"].isin(["Rare-Attack"])
    
    standard_indices = windows_df.index[standard_mask].values
    standard_labels = windows_df.loc[standard_indices, "label"].values
    
    # 1. Stratify standard classes (70% train, 15% val, 15% test)
    val_test_ratio = val_ratio + test_ratio
    train_std_idx, val_test_std_idx = train_test_split(
        standard_indices,
        test_size=val_test_ratio,
        random_state=random_seed,
        stratify=standard_labels
    )
    
    test_fraction_of_val_test = test_ratio / val_test_ratio
    val_std_idx, test_std_idx = train_test_split(
        val_test_std_idx,
        test_size=test_fraction_of_val_test,
        random_state=random_seed,
        stratify=windows_df.loc[val_test_std_idx, "label"].values
    )
    
    # 2. Handle Rare-Attack windows with deliberate allocation
    rare_indices = windows_df.index[~standard_mask].values
    np.random.seed(random_seed)
    shuffled_rare = np.random.permutation(rare_indices)
    
    # Allocate at least 1 to val, 1 to test, remainder to train
    n_rare = len(shuffled_rare)
    n_val_rare = max(1, int(round(n_rare * val_ratio)))
    n_test_rare = max(1, int(round(n_rare * test_ratio)))
    n_train_rare = n_rare - n_val_rare - n_test_rare
    
    train_rare_idx = shuffled_rare[:n_train_rare]
    val_rare_idx = shuffled_rare[n_train_rare : n_train_rare + n_val_rare]
    test_rare_idx = shuffled_rare[n_train_rare + n_val_rare :]
    
    print(f"\nDeliberate Rare-Attack window allocation (total {n_rare} windows):")
    print(f"  - Train: {len(train_rare_idx)} | Val: {len(val_rare_idx)} | Test: {len(test_rare_idx)}")
    
    # Combine standard and rare indices
    train_all_idx = np.concatenate([train_std_idx, train_rare_idx])
    val_all_idx = np.concatenate([val_std_idx, val_rare_idx])
    test_all_idx = np.concatenate([test_std_idx, test_rare_idx])
    
    train_df = windows_df.loc[train_all_idx].copy()
    val_df = windows_df.loc[val_all_idx].copy()
    test_df = windows_df.loc[test_all_idx].copy()
    
    train_df["split"] = "train"
    val_df["split"] = "val"
    test_df["split"] = "test"
    
    return train_df, val_df, test_df


def main():
    print("=" * 80)
    print("SHIELDNET WORKSTREAM 2 (CORRECTED): WHOLE-WINDOW HOST SEQUENCE BUILDER")
    print("=" * 80)
    
    config_a_path = "data/processed/fused_matched_v1.parquet"
    output_dir = Path("data/processed")
    checkpoint_dir = Path("models/checkpoints")
    
    with open(checkpoint_dir / "feature_columns.json", "r") as f:
        manifest = json.load(f)
    numeric_features = manifest["numeric_features"]
    scaler = joblib.load(checkpoint_dir / "scaler.joblib")
    
    # ─── Step 1: Build Full Windows from Config A ──────────────────────────────
    full_windows_df = build_host_windows_from_full_config_a(
        config_a_path, numeric_features, scaler, window_size_seconds=10
    )
    
    total_windows = len(full_windows_df)
    n_eligible_total = int((full_windows_df["is_sequence_eligible"] == True).sum())
    n_single_total = int((full_windows_df["is_sequence_eligible"] == False).sum())
    
    print("\n" + "-" * 80)
    print("GLOBAL WINDOW SANITY CHECK (FULL CONFIG A):")
    print("-" * 80)
    print(f"  - Total Host Windows:           {total_windows:,} (Expected: 139,908)")
    print(f"  - Sequence-Eligible (>= 2):     {n_eligible_total:,} (Expected: 65,190)")
    print(f"  - Single-Flow Windows (== 1):   {n_single_total:,} (Expected: 74,718)")
    
    check_passed = (total_windows == 139_908) and (n_eligible_total == 65_190) and (n_single_total == 74_718)
    print(f"  -> SANITY CHECK: {'PASSED [OK]' if check_passed else 'FAILED [MISMATCH]'}")
    
    # ─── Step 2: Window-Level Stratified Train/Val/Test Split ──────────────────
    print("\n" + "-" * 80)
    print("WINDOW-LEVEL STRATIFIED SPLIT (70% Train / 15% Val / 15% Test):")
    print("-" * 80)
    
    train_windows, val_windows, test_windows = stratified_split_windows(
        full_windows_df, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, random_seed=42
    )
    
    sum_split_windows = len(train_windows) + len(val_windows) + len(test_windows)
    print(f"\nSplit Windows Count Reconciliation:")
    print(f"  - Train: {len(train_windows):,} ({len(train_windows)/total_windows*100:.2f}%)")
    print(f"  - Val:   {len(val_windows):,} ({len(val_windows)/total_windows*100:.2f}%)")
    print(f"  - Test:  {len(test_windows):,} ({len(test_windows)/total_windows*100:.2f}%)")
    print(f"  - Sum:   {sum_split_windows:,} (Expected: 139,908)")
    reconciliation_passed = (sum_split_windows == 139_908)
    print(f"  -> SPLIT RECONCILIATION: {'PASSED [OK]' if reconciliation_passed else 'FAILED [MISMATCH]'}")
    
    # ─── Step 3: Save Non-Fragmented Sequence Parquet Files ────────────────────
    print("\nSaving corrected sequence parquet datasets...")
    train_out = output_dir / "sequences_train.parquet"
    val_out = output_dir / "sequences_val.parquet"
    test_out = output_dir / "sequences_test.parquet"
    
    train_windows.to_parquet(train_out, index=False)
    val_windows.to_parquet(val_out, index=False)
    test_windows.to_parquet(test_out, index=False)
    print(f"  Saved:\n    - {train_out}\n    - {val_out}\n    - {test_out}")
    
    # ─── Step 4: Rare-Class Sequence Representation Audit ─────────────────────
    print("\n" + "=" * 80)
    print("CORRECTED RARE-CLASS SEQUENCE-ELIGIBLE REPRESENTATION AUDIT")
    print("=" * 80)
    
    splits_meta = []
    for s_name, s_df in [("train", train_windows), ("val", val_windows), ("test", test_windows)]:
        s_eligible = s_df[s_df["is_sequence_eligible"] == True]
        s_single = s_df[s_df["is_sequence_eligible"] == False]
        
        stat = {
            "split": s_name,
            "total_windows": len(s_df),
            "sequence_eligible_windows": len(s_eligible),
            "sequence_eligible_pct": float(len(s_eligible) / len(s_df) * 100),
            "single_flow_windows": len(s_single),
            "single_flow_pct": float(len(s_single) / len(s_df) * 100),
            "class_distribution_eligible": s_eligible["label"].value_counts().to_dict(),
            "class_distribution_single": s_single["label"].value_counts().to_dict(),
        }
        splits_meta.append(stat)
        
        print(f"\nSplit: {s_name.upper()} (Total Windows: {len(s_df):,})")
        print(f"  - Sequence-Eligible (>=2 flows): {len(s_eligible):,} ({len(s_eligible)/len(s_df)*100:.2f}%)")
        print(f"  - Single-Flow (==1 flow):        {len(s_single):,} ({len(s_single)/len(s_df)*100:.2f}%)")
        print("  Sequence-Eligible Class Breakdown:")
        for lbl, cnt in stat["class_distribution_eligible"].items():
            print(f"    - {lbl:26s}: {cnt:,} windows")
            
    # Save sequence metadata json
    meta_path = checkpoint_dir / "sequence_metadata.json"
    with open(meta_path, "w") as f:
        json.dump({
            "total_windows": total_windows,
            "reconciliation_passed": reconciliation_passed,
            "sanity_check_passed": check_passed,
            "splits": splits_meta
        }, f, indent=2)
    print(f"\nSaved sequence metadata manifest to: {meta_path}")

if __name__ == "__main__":
    main()
