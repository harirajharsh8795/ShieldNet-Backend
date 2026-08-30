"""
Time-Windowed Sequencer for NetGuard World Model.

Groups network flows into configurable time windows (default: 10 seconds),
producing ordered temporal state vectors S_t that the World Model consumes to learn
state transition dynamics P(S_{t+1} | S_t, a_t).

Features:
- Configurable grouping: 'host' (Session + Source IP) or 'session' (Macro-level)
- Statistical feature aggregation (mean, std, min, max) per window
- MITRE ATT&CK stage mapping
- Sequence generation with cross-entity boundary isolation
- Memory-optimized window density diagnostics
"""

import numpy as np
import pandas as pd
from typing import Tuple, List, Dict, Optional, Union
from pathlib import Path

# MITRE ATT&CK Stage Mapping for CIC-IDS2017 attack classes
MITRE_STAGE_MAP = {
    "BENIGN": 0,
    # Reconnaissance / Discovery
    "PortScan": 1,
    # Initial Access / Credential Access
    "FTP-Patator": 2,
    "SSH-Patator": 2,
    "Web Attack - Brute Force": 2,
    "Web Attack - XSS": 2,
    "Web Attack - SQL Injection": 2,
    # Lateral Movement / Privilege Escalation / Execution
    "Infiltration": 3,
    # Command & Control (C2)
    "Bot": 4,
    # Exfiltration / Impact / Disruption
    "DDoS": 5,
    "DoS Hulk": 5,
    "DoS GoldenEye": 5,
    "DoS slowloris": 5,
    "DoS Slowhttptest": 5,
    "Heartbleed": 5,
    "Rare-Attack": 3,  # Blend of Infiltration / Heartbleed / SQLi
}

MITRE_STAGE_NAMES = {
    0: "Benign / Normal",
    1: "Reconnaissance",
    2: "Initial Access",
    3: "Lateral Movement",
    4: "Command & Control",
    5: "Exfiltration / Impact",
}


def parse_timestamps(timestamp_series: pd.Series) -> pd.Series:
    """Robustly parse timestamps into datetime64[ns] in a memory-safe manner."""
    if pd.api.types.is_datetime64_any_dtype(timestamp_series):
        return timestamp_series
    
    # Fast parsing
    ts = pd.to_datetime(timestamp_series, format="%d/%m/%Y %H:%M:%S", errors="coerce")
    null_mask = ts.isna()
    if null_mask.any():
        ts[null_mask] = pd.to_datetime(timestamp_series[null_mask], format="%d/%m/%Y %H:%M", errors="coerce")
    null_mask = ts.isna()
    if null_mask.any():
        ts[null_mask] = pd.to_datetime(timestamp_series[null_mask], errors="coerce")
    
    if ts.isna().any():
        valid_min = ts.min() if not ts.isna().all() else pd.Timestamp("2017-07-03 00:00:00")
        ts = ts.fillna(valid_min)
        
    return ts


def analyze_window_density(df: pd.DataFrame,
                           window_size_seconds: int = 10,
                           group_by: str = "host") -> Dict[str, Union[int, float]]:
    """Compute comprehensive window density and sparsity diagnostics using minimal memory.
    
    Uses only timestamp and grouping columns without copying feature matrices.
    """
    ts_col = "Timestamp" if "Timestamp" in df.columns else ("timestamp" if "timestamp" in df.columns else None)
    if ts_col is None:
        raise ValueError("No timestamp column found in DataFrame")
        
    ts = parse_timestamps(df[ts_col])
    
    # Determine grouping keys
    if group_by == "host":
        grp_series = []
        if "session_group" in df.columns:
            grp_series.append(df["session_group"].astype(str))
        ip_col = "Source IP" if "Source IP" in df.columns else ("src_ip" if "src_ip" in df.columns else None)
        if ip_col:
            grp_series.append(df[ip_col].astype(str))
            
        if len(grp_series) == 2:
            keys = grp_series[0] + "_" + grp_series[1]
        elif len(grp_series) == 1:
            keys = grp_series[0]
        else:
            keys = pd.Series(["global"] * len(df), index=df.index)
    elif group_by == "session":
        if "session_group" in df.columns:
            keys = df["session_group"].astype(str)
        else:
            keys = pd.Series(["global"] * len(df), index=df.index)
    else:
        keys = pd.Series(["global"] * len(df), index=df.index)
        
    # Build lightweight summary DataFrame
    mini_df = pd.DataFrame({"ts": ts, "key": keys})
    
    window_flow_counts = []
    
    for _, group in mini_df.groupby("key", sort=False):
        if len(group) == 0:
            continue
        g_ts = group["ts"].sort_values()
        t0 = g_ts.iloc[0]
        bin_indices = ((g_ts - t0).dt.total_seconds() // window_size_seconds).astype(np.int64)
        counts = bin_indices.value_counts().values
        window_flow_counts.extend(counts)
        
    if not window_flow_counts:
        return {"total_windows": 0, "avg_flows_per_window": 0.0, "sparsity_ratio_1flow_pct": 0.0}
        
    flow_counts = np.array(window_flow_counts, dtype=np.int64)
    total_windows = len(flow_counts)
    single_flow_windows = int(np.sum(flow_counts == 1))
    multi_flow_windows = int(np.sum(flow_counts > 1))
    
    stats = {
        "total_windows": total_windows,
        "total_flows_processed": int(np.sum(flow_counts)),
        "mean_flows_per_window": float(np.mean(flow_counts)),
        "median_flows_per_window": float(np.median(flow_counts)),
        "std_flows_per_window": float(np.std(flow_counts)),
        "min_flows_per_window": int(np.min(flow_counts)),
        "max_flows_per_window": int(np.max(flow_counts)),
        "p25_flows_per_window": float(np.percentile(flow_counts, 25)),
        "p75_flows_per_window": float(np.percentile(flow_counts, 75)),
        "p95_flows_per_window": float(np.percentile(flow_counts, 95)),
        "single_flow_windows": single_flow_windows,
        "multi_flow_windows": multi_flow_windows,
        "sparsity_ratio_1flow_pct": float((single_flow_windows / total_windows) * 100),
        "multi_flow_ratio_pct": float((multi_flow_windows / total_windows) * 100),
    }
    return stats


def create_time_windows(df: pd.DataFrame,
                        feature_cols: Optional[List[str]] = None,
                        window_size_seconds: int = 10,
                        group_by: str = "host",
                        min_flows_per_window: int = 1) -> pd.DataFrame:
    """Group flow records into fixed-duration time windows and compute aggregated state vectors S_t.
    
    Memory-optimized implementation.
    """
    ts_col = "Timestamp" if "Timestamp" in df.columns else ("timestamp" if "timestamp" in df.columns else None)
    if ts_col is None:
        raise ValueError("No timestamp column found in DataFrame")
        
    parsed_time = parse_timestamps(df[ts_col])
    
    if feature_cols is None:
        exclude_meta = {
            "Flow ID", "Source IP", "Destination IP", "Timestamp", "Label", "Label_Original",
            "proto_int", "src_port_int", "dst_port_int", "src_ip_str", "dst_ip_str",
            "session_group", "five_tuple_key", "is_packet_matched", "_parsed_time",
            "label", "timestamp", "src_ip", "dst_ip"
        }
        feature_cols = [c for c in df.select_dtypes(include=[np.number]).columns if c not in exclude_meta]
    
    # Determine grouping key
    if group_by == "host":
        grp_parts = []
        if "session_group" in df.columns:
            grp_parts.append(df["session_group"].astype(str))
        ip_col = "Source IP" if "Source IP" in df.columns else ("src_ip" if "src_ip" in df.columns else None)
        if ip_col:
            grp_parts.append(df[ip_col].astype(str))
            
        if len(grp_parts) == 2:
            group_keys = grp_parts[0] + "_" + grp_parts[1]
        elif len(grp_parts) == 1:
            group_keys = grp_parts[0]
        else:
            group_keys = pd.Series(["global"] * len(df), index=df.index)
    elif group_by == "session":
        group_keys = df["session_group"].astype(str) if "session_group" in df.columns else pd.Series(["global"] * len(df), index=df.index)
    else:
        group_keys = pd.Series(["global"] * len(df), index=df.index)
        
    window_records = []
    
    # Work on index subsets to avoid allocating large temporary copies
    unique_groups = group_keys.unique()
    
    for g_val in unique_groups:
        g_mask = (group_keys == g_val)
        sub_indices = df.index[g_mask]
        if len(sub_indices) == 0:
            continue
            
        g_times = parsed_time.loc[sub_indices]
        sort_order = g_times.argsort()
        sorted_indices = sub_indices[sort_order]
        sorted_times = g_times.iloc[sort_order]
        
        t0 = sorted_times.iloc[0]
        bin_indices = ((sorted_times - t0).dt.total_seconds() // window_size_seconds).astype(np.int64)
        
        unique_bins = bin_indices.unique()
        for b_idx in unique_bins:
            b_mask = (bin_indices == b_idx)
            win_indices = sorted_indices[b_mask]
            n_flows = len(win_indices)
            if n_flows < min_flows_per_window:
                continue
                
            rec = {
                "window_idx": int(b_idx),
                "flow_count": n_flows,
                "group_key": str(g_val),
                "window_start_time": sorted_times.loc[win_indices].min(),
                "window_end_time": sorted_times.loc[win_indices].max(),
            }
            
            # Numeric feature aggregations
            win_subset = df.loc[win_indices, feature_cols]
            for feat in feature_cols:
                vals = win_subset[feat].values.astype(np.float64)
                vals = np.nan_to_num(vals, nan=0.0, posinf=0.0, neginf=0.0)
                rec[f"{feat}_mean"] = float(np.mean(vals))
                rec[f"{feat}_std"] = float(np.std(vals)) if n_flows > 1 else 0.0
                rec[f"{feat}_max"] = float(np.max(vals))
                rec[f"{feat}_min"] = float(np.min(vals))
                
            # Labels
            label_col = "Label" if "Label" in df.columns else ("label" if "label" in df.columns else None)
            if label_col:
                lbls = df.loc[win_indices, label_col]
                lbl_counts = lbls.value_counts()
                rec["label"] = lbl_counts.index[0]
                benign_cnt = lbl_counts.get("BENIGN", 0)
                rec["attack_ratio"] = float(1.0 - (benign_cnt / n_flows))
                rec["mitre_stage"] = _get_dominant_mitre_stage(lbls)
                
            window_records.append(rec)
            
    return pd.DataFrame(window_records)


def create_sequences(windowed_df: pd.DataFrame,
                     sequence_length: int = 20,
                     stride: int = 1,
                     group_column: Optional[str] = "group_key") -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Generate sequential state-transitions S_{t-L:t} -> S_{t+1} for World Model training.
    
    Ensures sequences do NOT cross boundaries between distinct host entities or sessions.
    """
    exclude_meta = {
        "window_idx", "flow_count", "window_start_time", "window_end_time",
        "session_group", "source_ip", "group_id", "group_key", "label", "attack_ratio", "mitre_stage"
    }
    state_feature_cols = [c for c in windowed_df.columns if c not in exclude_meta]
    
    X_list = []
    y_next_list = []
    y_labels_list = []
    
    if group_column and group_column in windowed_df.columns:
        grouped = windowed_df.groupby(group_column, sort=False)
    else:
        grouped = [(None, windowed_df)]
        
    for _, entity_df in grouped:
        if len(entity_df) <= sequence_length:
            continue
            
        entity_df = entity_df.sort_values("window_idx").reset_index(drop=True)
        feat_mat = entity_df[state_feature_cols].values.astype(np.float32)
        feat_mat = np.nan_to_num(feat_mat, nan=0.0, posinf=0.0, neginf=0.0)
        
        mitre_labels = entity_df["mitre_stage"].values if "mitre_stage" in entity_df.columns else np.zeros(len(entity_df))
        
        n_windows = len(feat_mat)
        for i in range(0, n_windows - sequence_length, stride):
            X_seq = feat_mat[i : i + sequence_length]
            y_next = feat_mat[i + sequence_length]
            y_lbl = mitre_labels[i + sequence_length]
            
            X_list.append(X_seq)
            y_next_list.append(y_next)
            y_labels_list.append(y_lbl)
            
    if not X_list:
        n_features = len(state_feature_cols)
        return (
            np.empty((0, sequence_length, n_features), dtype=np.float32),
            np.empty((0, n_features), dtype=np.float32),
            np.empty((0,), dtype=np.int64)
        )
        
    return (
        np.array(X_list, dtype=np.float32),
        np.array(y_next_list, dtype=np.float32),
        np.array(y_labels_list, dtype=np.int64)
    )


def _get_dominant_mitre_stage(labels: pd.Series) -> int:
    """Return dominant MITRE stage with highest attack severity."""
    stages = [MITRE_STAGE_MAP.get(str(lbl), 0) for lbl in labels]
    non_benign = [s for s in stages if s > 0]
    if non_benign:
        return max(non_benign)
    return 0
