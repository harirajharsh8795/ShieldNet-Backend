"""
Data ingestion module for ShieldNet.
Handles loading from CSV files (CIC-IDS-2018, CTU-13) and normalizing to the shared schema.
Also supports PCAP ingestion via Scapy when raw packet data is available.
"""

import os
import sys
import pandas as pd
import numpy as np
from pathlib import Path
from typing import List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from src.features.schema import (
    get_feature_names, get_model_feature_names, validate_dataframe,
    FLOW_LEVEL, PACKET_LEVEL, META_LEVEL
)


# ─── Column Name Mappings ────────────────────────────────────────────────────
# CIC-IDS-2018 CSV columns → our canonical schema names
# (CIC-IDS-2018 uses space-padded headers and inconsistent casing)

CIC_COLUMN_MAP = {
    'Timestamp':                'timestamp',
    'Src IP':                   'src_ip',
    'Dst IP':                   'dst_ip',
    'Src Port':                 'src_port',
    'Dst Port':                 'dst_port',
    'Protocol':                 'protocol',
    'Flow Duration':            'flow_duration',
    'Tot Fwd Pkts':             'total_fwd_packets',
    'Total Fwd Packets':        'total_fwd_packets',
    'Tot Bwd Pkts':             'total_bwd_packets',
    'Total Backward Packets':   'total_bwd_packets',
    'TotLen Fwd Pkts':          'total_fwd_bytes',
    'Total Length of Fwd Packets': 'total_fwd_bytes',
    'TotLen Bwd Pkts':          'total_bwd_bytes',
    'Total Length of Bwd Packets': 'total_bwd_bytes',
    'Fwd Pkt Len Mean':         'fwd_packet_length_mean',
    'Fwd Packet Length Mean':    'fwd_packet_length_mean',
    'Fwd Pkt Len Std':          'fwd_packet_length_std',
    'Fwd Packet Length Std':     'fwd_packet_length_std',
    'Bwd Pkt Len Mean':         'bwd_packet_length_mean',
    'Bwd Packet Length Mean':    'bwd_packet_length_mean',
    'Bwd Pkt Len Std':          'bwd_packet_length_std',
    'Bwd Packet Length Std':     'bwd_packet_length_std',
    'Flow Byts/s':              'flow_bytes_per_sec',
    'Flow Bytes/s':             'flow_bytes_per_sec',
    'Flow Pkts/s':              'flow_packets_per_sec',
    'Flow Packets/s':           'flow_packets_per_sec',
    'Flow IAT Mean':            'flow_iat_mean',
    'Flow IAT Std':             'flow_iat_std',
    'Fwd IAT Mean':             'fwd_iat_mean',
    'Fwd IAT Std':              'fwd_iat_std',
    'Bwd IAT Mean':             'bwd_iat_mean',
    'Bwd IAT Std':              'bwd_iat_std',
    'Fwd PSH Flags':            'fwd_psh_flags',
    'Bwd PSH Flags':            'bwd_psh_flags',
    'Fwd URG Flags':            'fwd_urg_flags',
    'Bwd URG Flags':            'bwd_urg_flags',
    'FIN Flag Cnt':             'fin_flag_count',
    'FIN Flag Count':           'fin_flag_count',
    'SYN Flag Cnt':             'syn_flag_count',
    'SYN Flag Count':           'syn_flag_count',
    'RST Flag Cnt':             'rst_flag_count',
    'RST Flag Count':           'rst_flag_count',
    'PSH Flag Cnt':             'psh_flag_count',
    'PSH Flag Count':           'psh_flag_count',
    'ACK Flag Cnt':             'ack_flag_count',
    'ACK Flag Count':           'ack_flag_count',
    'URG Flag Cnt':             'urg_flag_count',
    'URG Flag Count':           'urg_flag_count',
    'ECE Flag Cnt':             'ece_flag_count',
    'ECE Flag Count':           'ece_flag_count',
    'Down/Up Ratio':            'down_up_ratio',
    'Fwd Header Len':           'fwd_header_length',
    'Fwd Header Length':        'fwd_header_length',
    'Bwd Header Len':           'bwd_header_length',
    'Bwd Header Length':        'bwd_header_length',
    'Fwd Pkts/s':               'fwd_packets_per_sec',
    'Fwd Packets/s':            'fwd_packets_per_sec',
    'Bwd Pkts/s':               'bwd_packets_per_sec',
    'Bwd Packets/s':            'bwd_packets_per_sec',
    'Pkt Len Mean':             'packet_length_mean',
    'Packet Length Mean':       'packet_length_mean',
    'Pkt Len Std':              'packet_length_std',
    'Packet Length Std':        'packet_length_std',
    'Pkt Len Var':              'packet_length_variance',
    'Packet Length Variance':   'packet_length_variance',
    'Avg Pkt Size':             'avg_packet_size',
    'Average Packet Size':      'avg_packet_size',
    'Fwd Seg Size Avg':         'fwd_segment_size_avg',
    'Avg Fwd Segment Size':     'fwd_segment_size_avg',
    'Bwd Seg Size Avg':         'bwd_segment_size_avg',
    'Avg Bwd Segment Size':     'bwd_segment_size_avg',
    'Init Fwd Win Byts':        'init_win_bytes_forward',
    'Init_Win_bytes_forward':   'init_win_bytes_forward',
    'Init Bwd Win Byts':        'init_win_bytes_backward',
    'Init_Win_bytes_backward':  'init_win_bytes_backward',
    'Active Mean':              'active_mean',
    'Active Std':               'active_std',
    'Idle Mean':                'idle_mean',
    'Idle Std':                 'idle_std',
    'Subflow Fwd Pkts':         'subflow_fwd_packets',
    'Subflow Fwd Packets':      'subflow_fwd_packets',
    'Subflow Bwd Pkts':         'subflow_bwd_packets',
    'Subflow Bwd Packets':      'subflow_bwd_packets',
    'Subflow Fwd Byts':         'subflow_fwd_bytes',
    'Subflow Fwd Bytes':        'subflow_fwd_bytes',
    'Subflow Bwd Byts':         'subflow_bwd_bytes',
    'Subflow Bwd Bytes':        'subflow_bwd_bytes',
    'Label':                    'label',
}


def normalize_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize column names to canonical schema, handling various CIC naming conventions."""
    # Strip whitespace from column names (CIC-IDS-2018 has leading/trailing spaces)
    df.columns = df.columns.str.strip()
    
    # Apply mapping
    rename_map = {}
    for col in df.columns:
        if col in CIC_COLUMN_MAP:
            rename_map[col] = CIC_COLUMN_MAP[col]
        else:
            # Convert to snake_case as fallback
            normalized = col.lower().replace(' ', '_').replace('/', '_per_')
            rename_map[col] = normalized
    
    df = df.rename(columns=rename_map)
    return df


def load_cic_ids_2018(data_dir: str, max_rows_per_file: Optional[int] = None) -> pd.DataFrame:
    """Load CIC-IDS-2018 CSV files and normalize to schema.
    
    Args:
        data_dir: Path to CIC-IDS-2018 data directory.
        max_rows_per_file: Optional row limit per file (for development/testing).
    
    Returns:
        Normalized DataFrame.
    """
    data_path = Path(data_dir)
    csv_files = sorted(data_path.glob("*.csv"))
    
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")
    
    dfs = []
    for csv_file in csv_files:
        print(f"  Loading {csv_file.name}...", end=" ")
        df = pd.read_csv(csv_file, low_memory=False, nrows=max_rows_per_file)
        df = normalize_column_names(df)
        dfs.append(df)
        print(f"{len(df):,} rows")
    
    combined = pd.concat(dfs, ignore_index=True)
    combined = _clean_numeric_columns(combined)
    combined['dataset_source'] = 'cic-ids-2018'
    
    return combined


def load_ctu_13(data_dir: str, max_rows_per_file: Optional[int] = None, 
                scenarios: Optional[List[int]] = None) -> pd.DataFrame:
    """Load CTU-13 CSV files and normalize to schema.
    
    Args:
        data_dir: Path to CTU-13 data directory.
        max_rows_per_file: Optional row limit per file.
        scenarios: Optional list of scenario numbers to load (1-13). Loads all if None.
    
    Returns:
        Normalized DataFrame.
    """
    data_path = Path(data_dir)
    csv_files = sorted(data_path.glob("*.csv"))
    
    if scenarios:
        csv_files = [f for f in csv_files 
                     if any(f"scenario_{s}" in f.stem for s in scenarios)]
    
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")
    
    dfs = []
    for csv_file in csv_files:
        print(f"  Loading {csv_file.name}...", end=" ")
        df = pd.read_csv(csv_file, low_memory=False, nrows=max_rows_per_file)
        df = normalize_column_names(df)
        dfs.append(df)
        print(f"{len(df):,} rows")
    
    combined = pd.concat(dfs, ignore_index=True)
    combined = _clean_numeric_columns(combined)
    combined['dataset_source'] = 'ctu-13'
    
    # Normalize CTU labels to match CIC format for cross-dataset compatibility
    if 'label' in combined.columns:
        combined['label'] = combined['label'].replace({
            'Normal': 'Benign',
            'Background': 'Benign',
        })
    
    return combined


def _clean_numeric_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Clean numeric columns: handle infinities, NaNs, and type issues."""
    model_features = get_model_feature_names()
    
    for col in model_features:
        if col in df.columns:
            # Convert to numeric, coercing errors
            df[col] = pd.to_numeric(df[col], errors='coerce')
            # Replace infinities with NaN, then fill with 0
            df[col] = df[col].replace([np.inf, -np.inf], np.nan)
            df[col] = df[col].fillna(0)
    
    return df


def load_csv_upload(filepath: str) -> pd.DataFrame:
    """Load a user-uploaded CSV file and attempt to normalize to schema.
    
    Used by the dashboard for ad-hoc file uploads.
    """
    df = pd.read_csv(filepath, low_memory=False)
    df = normalize_column_names(df)
    df = _clean_numeric_columns(df)
    
    # Validate
    validation = validate_dataframe(df)
    model_features = get_model_feature_names()
    present = [f for f in model_features if f in df.columns]
    
    print(f"  Loaded {len(df):,} rows, {len(present)}/{len(model_features)} model features present")
    
    if validation['flow_present'] == 0 and validation['packet_present'] == 0:
        raise ValueError(
            "Uploaded CSV has no recognizable flow-level or packet-level features. "
            "Please provide a CICFlowMeter-style CSV or a file matching the ShieldNet schema."
        )
    
    return df


def load_dataset(dataset_name: str, config: dict) -> pd.DataFrame:
    """Unified dataset loader dispatching to the appropriate loader.
    
    Args:
        dataset_name: 'cic-ids-2018' or 'ctu-13'
        config: Configuration dictionary.
    
    Returns:
        Normalized DataFrame.
    """
    if dataset_name == 'cic-ids-2018':
        return load_cic_ids_2018(config['data']['cic_ids_2018_dir'])
    elif dataset_name == 'ctu-13':
        return load_ctu_13(config['data']['ctu_13_dir'])
    else:
        raise ValueError(f"Unknown dataset: {dataset_name}. Use 'cic-ids-2018' or 'ctu-13'.")
