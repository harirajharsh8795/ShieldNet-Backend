"""
Feature preprocessing and stratified dataset splitting pipeline for ShieldNet.

Handles:
1. Clean label normalization and Rare-Attack meta-class merging.
2. Stratified train/val/test splitting (70/15/15, random_seed=42).
3. Cross-config alignment between Config A (fused) and Config B (flow-only).
4. StandardScaler fitting on training split ONLY (preventing data leakage).
5. Saving splits and scaler artifacts.
"""

import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from typing import Tuple, Dict, List, Optional
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import json
import re

# Rare attack classes to merge for stratified splitting (< 200 samples threshold)
RARE_ATTACK_CLASSES = {
    "Heartbleed",
    "Web Attack - SQL Injection",
    "Infiltration"
}

def clean_label_string(label: str) -> str:
    """Normalize label string encoding and punctuation."""
    if not isinstance(label, str):
        return "BENIGN"
    lbl = label.strip()
    # Normalize unicode replacement characters or mangled hyphens
    lbl = re.sub(r"[\ufffd\x96\x97\u2013\u2014]+", "-", lbl)
    lbl = re.sub(r"\s+", " ", lbl)
    
    # Specific standardizations
    if "brute force" in lbl.lower() and "web" in lbl.lower():
        return "Web Attack - Brute Force"
    if "xss" in lbl.lower():
        return "Web Attack - XSS"
    if "sql" in lbl.lower():
        return "Web Attack - SQL Injection"
    if "infiltration" in lbl.lower() or "infilteration" in lbl.lower():
        return "Infiltration"
    if "heartbleed" in lbl.lower():
        return "Heartbleed"
    if "benign" in lbl.lower():
        return "BENIGN"
    return lbl


def standardize_and_merge_rare_classes(df: pd.DataFrame, 
                                       label_col: str = "Label") -> pd.DataFrame:
    """Standardize label names and merge ultra-rare attack classes into 'Rare-Attack'.
    
    Creates:
      - 'Label_Original': Standardized fine-grained attack label
      - 'Label': Post-merge label with Rare-Attack category for training
    """
    df = df.copy()
    raw_labels = df[label_col].astype(str)
    standardized = raw_labels.apply(clean_label_string)
    
    df["Label_Original"] = standardized
    
    # Merge rare classes into 'Rare-Attack'
    df["Label"] = df["Label_Original"].apply(
        lambda x: "Rare-Attack" if x in RARE_ATTACK_CLASSES else x
    )
    
    return df


def stratified_split_dataset(df: pd.DataFrame,
                             train_ratio: float = 0.70,
                             val_ratio: float = 0.15,
                             test_ratio: float = 0.15,
                             random_seed: int = 42,
                             label_col: str = "Label") -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Perform 70/15/15 stratified train/val/test split by merged attack label.
    
    Args:
        df: Full dataset DataFrame with standardized 'Label' column.
        train_ratio: Fraction for training (default 0.70).
        val_ratio: Fraction for validation (default 0.15).
        test_ratio: Fraction for test (default 0.15).
        random_seed: Reproducibility seed (Constraint C6).
        label_col: Column to stratify on.
        
    Returns:
        Tuple of (train_df, val_df, test_df).
    """
    assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-6, "Split ratios must sum to 1.0"
    
    val_test_ratio = val_ratio + test_ratio
    
    # First split: Train vs (Val + Test)
    train_df, val_test_df = train_test_split(
        df,
        test_size=val_test_ratio,
        random_state=random_seed,
        stratify=df[label_col]
    )
    
    # Second split: Val vs Test
    test_frac_of_val_test = test_ratio / val_test_ratio
    val_df, test_df = train_test_split(
        val_test_df,
        test_size=test_frac_of_val_test,
        random_state=random_seed,
        stratify=val_test_df[label_col]
    )
    
    return train_df, val_df, test_df


def fit_standard_scaler(train_df: pd.DataFrame, 
                        feature_cols: List[str]) -> StandardScaler:
    """Fit StandardScaler on training split numeric features ONLY."""
    scaler = StandardScaler()
    
    # Extract values and clean inf/nan
    X_train = train_df[feature_cols].values.astype(np.float64)
    X_train = np.nan_to_num(X_train, nan=0.0, posinf=0.0, neginf=0.0)
    
    scaler.fit(X_train)
    return scaler


def transform_numeric_features(df: pd.DataFrame,
                               scaler: StandardScaler,
                               feature_cols: List[str]) -> pd.DataFrame:
    """Apply fitted StandardScaler to numeric feature columns."""
    df_transformed = df.copy()
    X = df_transformed[feature_cols].values.astype(np.float64)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    
    df_transformed[feature_cols] = scaler.transform(X)
    return df_transformed
