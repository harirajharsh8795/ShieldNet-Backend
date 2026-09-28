"""
ShieldNet Canonical 84-Feature Unified Schema.

Defines the exact 84-dimensional continuous numeric feature schema used by both
the training pipeline and the live background detection daemon.
- 77 Flow-level features (IAT statistics, TCP flags, byte/packet aggregations)
- 7 Packet-level verified features (TTL variance, TCP window sizes, fragments, retransmissions)
"""

from typing import List, Dict, Tuple, Optional, Any
import numpy as np

# ─── Canonical Feature Column Names (Strict 84 Order) ───────────────────────
CANONICAL_FLOW_FEATURES: List[str] = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

CANONICAL_PACKET_FEATURES: List[str] = [
    "ttl_mean",
    "ttl_variance",
    "tcp_window_mean",
    "tcp_window_min",
    "tcp_window_max",
    "ip_fragment_flag_present",
    "retransmission_count",
]

CANONICAL_84_FEATURES: List[str] = CANONICAL_FLOW_FEATURES + CANONICAL_PACKET_FEATURES

NUM_FLOW_FEATURES = len(CANONICAL_FLOW_FEATURES)       # 77
NUM_PACKET_FEATURES = len(CANONICAL_PACKET_FEATURES)   # 7
NUM_CANONICAL_FEATURES = len(CANONICAL_84_FEATURES)    # 84
CONTEXT_LENGTH = 3                                      # L = 3 temporal context windows

FEATURE_TO_IDX: Dict[str, int] = {feat: idx for idx, feat in enumerate(CANONICAL_84_FEATURES)}
IDX_TO_FEATURE: Dict[int, str] = {idx: feat for idx, feat in enumerate(CANONICAL_84_FEATURES)}

# ─── Target Classification Schema (13 Classes) ──────────────────────────────
ATTACK_CLASSES: List[str] = [
    "BENIGN",
    "Bot",
    "DDoS",
    "DoS GoldenEye",
    "DoS Hulk",
    "DoS Slowhttptest",
    "DoS slowloris",
    "FTP-Patator",
    "PortScan",
    "Rare-Attack",
    "SSH-Patator",
    "Web Attack - Brute Force",
    "Web Attack - XSS",
]

# ─── MITRE ATT&CK Kill-Chain Stages (6 Stages) ──────────────────────────────
MITRE_STAGES: Dict[int, str] = {
    0: "Normal Operations",
    1: "TA0043: Reconnaissance",
    2: "TA0001/TA0002: Initial Access & Execution",
    3: "TA0008: Lateral Movement",
    4: "TA0011: Command and Control",
    5: "TA0040: Impact",
}

# ─── Cross-Dataset Mapping (CTU-13 / NetFlow -> Canonical 84) ────────────────
CTU13_TO_CANONICAL: Dict[str, str] = {
    "Dur": "Flow Duration",
    "TotPkts": "Total Fwd Packets",
    "TotBytes": "Total Length of Fwd Packets",
    "SrcBytes": "Total Length of Fwd Packets",
    "DstBytes": "Total Length of Bwd Packets",
    "SrcPkts": "Total Fwd Packets",
    "DstPkts": "Total Backward Packets",
    "Rate": "Flow Packets/s",
    "sTos": "min_seg_size_forward",
}

# ─── Cross-Dataset Mapping (UNSW-NB15 -> Canonical 84) ───────────────────────
UNSW_TO_CANONICAL: Dict[str, str] = {
    "dur": "Flow Duration",
    "spkts": "Total Fwd Packets",
    "dpkts": "Total Backward Packets",
    "sbytes": "Total Length of Fwd Packets",
    "dbytes": "Total Length of Bwd Packets",
    "smean": "Fwd Packet Length Mean",
    "dmean": "Bwd Packet Length Mean",
    "rate": "Flow Packets/s",
    "sload": "Flow Bytes/s",
    "sinpkt": "Fwd IAT Mean",
    "dinpkt": "Bwd IAT Mean",
    "sjit": "Fwd IAT Std",
    "djit": "Bwd IAT Std",
    "swin": "Init_Win_bytes_forward",
    "dwin": "Init_Win_bytes_backward",
    "synack": "SYN Flag Count",
    "ackdat": "ACK Flag Count",
    "tcprtt": "Active Mean",
    "sttl": "ttl_mean",
}


def validate_feature_vector(vec: np.ndarray) -> bool:
    """Validates that a feature vector or batch matches the canonical 84-dimensional schema."""
    if vec.ndim == 1:
        return vec.shape[0] == NUM_CANONICAL_FEATURES
    elif vec.ndim == 2:
        return vec.shape[1] == NUM_CANONICAL_FEATURES
    elif vec.ndim == 3:
        return vec.shape[2] == NUM_CANONICAL_FEATURES
    return False
