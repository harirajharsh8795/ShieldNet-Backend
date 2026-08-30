"""
NetGuard World Model Dataset and Sequence Preparation Utilities.

Extracts ordered historical context sequences and next-state targets (S_{t-L:t} -> S_{t+1}, y_{t+1}, m_{t+1})
from sequence parquets without cross-host boundary contamination.
"""

import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import LabelEncoder
from typing import Tuple, Dict, List, Optional

class WorldModelSequenceDataset(Dataset):
    """PyTorch Dataset for World Model training."""
    
    def __init__(self,
                 X: np.ndarray,
                 y_state: np.ndarray,
                 y_label: np.ndarray,
                 y_mitre: np.ndarray):
        self.X = torch.from_numpy(X).float()
        self.y_state = torch.from_numpy(y_state).float()
        self.y_label = torch.from_numpy(y_label).long()
        self.y_mitre = torch.from_numpy(y_mitre).long()
        
    def __len__(self) -> int:
        return len(self.X)
        
    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        return self.X[idx], self.y_state[idx], self.y_label[idx], self.y_mitre[idx]


def extract_temporal_sequences_from_parquet(parquet_path: str,
                                            label_encoder: LabelEncoder,
                                            context_length: int = 3,
                                            stride: int = 1) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Extract ordered (S_{t-L:t} -> S_{t+1}) transition tensors from a sequence parquet file.
    
    Args:
        parquet_path: Path to sequences_train/val/test.parquet
        label_encoder: Fitted LabelEncoder for 13 target classes
        context_length: Number of historical time-window states L (default 3)
        stride: Step size between sliding sequence windows
        
    Returns:
        Tuple of:
          - X: (N, L, 84) historical input sequences
          - y_state: (N, 84) ground truth next state S_{t+1}
          - y_label: (N,) ground truth next attack label
          - y_mitre: (N,) ground truth next MITRE stage
    """
    df = pd.read_parquet(parquet_path)
    df["_host_key"] = df["session_group"].astype(str) + "___" + df["source_ip"].astype(str)
    
    # Pre-encode labels
    df["_label_enc"] = label_encoder.transform(df["label"].astype(str))
    
    X_list = []
    y_state_list = []
    y_label_list = []
    y_mitre_list = []
    
    # Group by host entity
    for _, host_df in df.groupby("_host_key", sort=False):
        if len(host_df) < 2:
            continue
            
        host_df = host_df.sort_values("window_idx").reset_index(drop=True)
        states = np.stack(host_df["state_vector"].values).astype(np.float32)  # (M, 84)
        labels = host_df["_label_enc"].values.astype(np.int64)                 # (M,)
        mitres = host_df["mitre_stage"].values.astype(np.int64)               # (M,)
        
        M = len(states)
        
        # Extract sliding context windows
        for t in range(1, M, stride):
            # Target is timestep t
            target_s = states[t]
            target_l = labels[t]
            target_m = mitres[t]
            
            # Context is up to context_length steps ending at t-1
            start_idx = max(0, t - context_length)
            history = states[start_idx:t]
            
            # If history is shorter than context_length, pad with the earliest available state
            if len(history) < context_length:
                pad_len = context_length - len(history)
                pad_tensor = np.tile(history[0:1], (pad_len, 1))
                history = np.vstack([pad_tensor, history])
                
            X_list.append(history)
            y_state_list.append(target_s)
            y_label_list.append(target_l)
            y_mitre_list.append(target_m)
            
    if not X_list:
        return (
            np.empty((0, context_length, 84), dtype=np.float32),
            np.empty((0, 84), dtype=np.float32),
            np.empty((0,), dtype=np.int64),
            np.empty((0,), dtype=np.int64),
        )
        
    X_arr = np.array(X_list, dtype=np.float32)
    y_state_arr = np.array(y_state_list, dtype=np.float32)
    y_label_arr = np.array(y_label_list, dtype=np.int64)
    y_mitre_arr = np.array(y_mitre_list, dtype=np.int64)
    
    return X_arr, y_state_arr, y_label_arr, y_mitre_arr
