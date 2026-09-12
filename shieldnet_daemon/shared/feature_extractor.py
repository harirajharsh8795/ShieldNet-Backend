"""
ShieldNet Real-Time Shared Feature Extraction Engine.

Computes the exact 84-dimensional continuous feature representation:
- 77 Flow-level features (duration, IAT distributions, TCP flag counts, packet/byte metrics)
- 7 Packet-level verified features (TTL statistics, TCP window sizes, fragments, retransmissions)

Used symmetrically by:
1. The background live sniffer daemon (processing rolling packet windows)
2. The training and offline evaluation pipelines (processing PCAP / CSVs)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any, Union
import numpy as np
import pandas as pd

from .schema import (
    CANONICAL_84_FEATURES,
    CANONICAL_FLOW_FEATURES,
    CANONICAL_PACKET_FEATURES,
    NUM_CANONICAL_FEATURES,
    NUM_FLOW_FEATURES,
    NUM_PACKET_FEATURES,
    FEATURE_TO_IDX,
    CTU13_TO_CANONICAL,
    UNSW_TO_CANONICAL,
)


@dataclass
class PacketMetadata:
    """Lightweight representation of a captured packet for feature aggregation."""
    timestamp: float              # Packet arrival timestamp in seconds (epoch or monotonic)
    src_ip: str                   # Source IPv4 address
    dst_ip: str                   # Destination IPv4 address
    src_port: int                 # Source TCP/UDP port (0 for ICMP/other)
    dst_port: int                 # Destination TCP/UDP port (0 for ICMP/other)
    protocol: int                 # IP protocol (6 = TCP, 17 = UDP, 1 = ICMP)
    total_length: int             # Total IP packet length in bytes
    payload_length: int           # Transport layer payload length in bytes
    header_length: int            # Total IP + Transport header length in bytes
    direction: int = 0            # 0 = Forward (Initiator -> Responder), 1 = Backward (Responder -> Initiator)
    # TCP-specific fields
    tcp_flags: int = 0            # Raw 8-bit TCP flags
    tcp_window: int = 0           # TCP window size advertisement
    seq_num: int = 0              # 32-bit TCP sequence number
    ack_num: int = 0              # 32-bit TCP acknowledgment number
    # IP-specific fields
    ttl: int = 64                 # IP Time-to-Live
    ip_flags: int = 0             # Raw IP flags (MF, DF)
    frag_offset: int = 0          # IP fragment offset


def parse_scapy_packet(pkt: Any, flow_direction_hint: int = 0) -> Optional[PacketMetadata]:
    """Parses a Scapy packet into a standardized PacketMetadata object."""
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
    except ImportError:
        # If scapy is not installed, parse via layer inspection if compatible
        return None

    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    proto = int(ip.proto)
    src_ip = str(ip.src)
    dst_ip = str(ip.dst)
    ttl = int(ip.ttl)
    ip_flags = int(ip.flags)
    frag_offset = int(ip.frag)
    total_len = int(len(pkt))

    src_port = 0
    dst_port = 0
    payload_len = 0
    header_len = int(ip.ihl * 4)
    tcp_flags = 0
    tcp_win = 0
    seq = 0
    ack = 0

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        tcp_win = int(tcp.window)
        tcp_flags = int(tcp.flags)
        seq = int(tcp.seq)
        ack = int(tcp.ack)
        tcp_hdr_len = int(tcp.dataofs * 4) if hasattr(tcp, "dataofs") and tcp.dataofs else 20
        header_len += tcp_hdr_len
        payload_len = max(0, total_len - header_len)
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        src_port = int(udp.sport)
        dst_port = int(udp.dport)
        header_len += 8
        payload_len = max(0, total_len - header_len)
    elif pkt.haslayer(ICMP):
        header_len += 8
        payload_len = max(0, total_len - header_len)

    pkt_time = float(getattr(pkt, "time", 0.0))

    return PacketMetadata(
        timestamp=pkt_time,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto,
        total_length=total_len,
        payload_length=payload_len,
        header_length=header_len,
        direction=flow_direction_hint,
        tcp_flags=tcp_flags,
        tcp_window=tcp_win,
        seq_num=seq,
        ack_num=ack,
        ttl=ttl,
        ip_flags=ip_flags,
        frag_offset=frag_offset,
    )


def compute_flow_features(packets: List[PacketMetadata]) -> np.ndarray:
    """
    Computes the canonical 84-dimensional feature vector from a list of packets
    belonging to a single flow window.
    
    Args:
        packets: List of PacketMetadata objects sorted chronologically.
        
    Returns:
        np.ndarray of shape (84,) containing all 77 flow and 7 packet features.
    """
    vector = np.zeros(NUM_CANONICAL_FEATURES, dtype=np.float32)

    if not packets:
        return vector

    # Sort packets chronologically
    packets = sorted(packets, key=lambda p: p.timestamp)
    n_pkts = len(packets)

    fwd_pkts = [p for p in packets if p.direction == 0]
    bwd_pkts = [p for p in packets if p.direction == 1]

    n_fwd = len(fwd_pkts)
    n_bwd = len(bwd_pkts)

    # Timestamps & Flow Duration (in microseconds)
    t_start = packets[0].timestamp
    t_end = packets[-1].timestamp
    duration_sec = max(0.0, t_end - t_start)
    duration_us = duration_sec * 1e6
    eps = 1e-6

    # Packet & Payload lengths
    all_lengths = np.array([p.total_length for p in packets], dtype=np.float64)
    all_payloads = np.array([p.payload_length for p in packets], dtype=np.float64)
    
    fwd_lengths = np.array([p.total_length for p in fwd_pkts], dtype=np.float64) if n_fwd > 0 else np.array([0.0])
    bwd_lengths = np.array([p.total_length for p in bwd_pkts], dtype=np.float64) if n_bwd > 0 else np.array([0.0])
    
    fwd_payloads = np.array([p.payload_length for p in fwd_pkts], dtype=np.float64) if n_fwd > 0 else np.array([0.0])
    bwd_payloads = np.array([p.payload_length for p in bwd_pkts], dtype=np.float64) if n_bwd > 0 else np.array([0.0])

    tot_fwd_bytes = float(np.sum(fwd_payloads))
    tot_bwd_bytes = float(np.sum(bwd_payloads))

    # Inter-Arrival Times (IAT) in microseconds
    def calc_iats(pkt_list: List[PacketMetadata]) -> np.ndarray:
        if len(pkt_list) < 2:
            return np.array([0.0], dtype=np.float64)
        ts = np.array([p.timestamp for p in pkt_list], dtype=np.float64)
        return (np.diff(ts) * 1e6).clip(min=0.0)

    flow_iats = calc_iats(packets)
    fwd_iats = calc_iats(fwd_pkts)
    bwd_iats = calc_iats(bwd_pkts)

    # TCP Flags decomposition: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20, ECE=0x40, CWR=0x80
    fin_count = sum(1 for p in packets if (p.tcp_flags & 0x01))
    syn_count = sum(1 for p in packets if (p.tcp_flags & 0x02))
    rst_count = sum(1 for p in packets if (p.tcp_flags & 0x04))
    psh_count = sum(1 for p in packets if (p.tcp_flags & 0x08))
    ack_count = sum(1 for p in packets if (p.tcp_flags & 0x10))
    urg_count = sum(1 for p in packets if (p.tcp_flags & 0x20))
    ece_count = sum(1 for p in packets if (p.tcp_flags & 0x40))
    cwe_count = sum(1 for p in packets if (p.tcp_flags & 0x80))

    fwd_psh = sum(1 for p in fwd_pkts if (p.tcp_flags & 0x08))
    bwd_psh = sum(1 for p in bwd_pkts if (p.tcp_flags & 0x08))
    fwd_urg = sum(1 for p in fwd_pkts if (p.tcp_flags & 0x20))
    bwd_urg = sum(1 for p in bwd_pkts if (p.tcp_flags & 0x20))

    # Header lengths
    fwd_header_len = float(sum(p.header_length for p in fwd_pkts))
    bwd_header_len = float(sum(p.header_length for p in bwd_pkts))

    # TCP Window bytes
    fwd_init_win = float(fwd_pkts[0].tcp_window) if (n_fwd > 0 and fwd_pkts[0].tcp_window > 0) else 0.0
    bwd_init_win = float(bwd_pkts[0].tcp_window) if (n_bwd > 0 and bwd_pkts[0].tcp_window > 0) else 0.0

    act_data_pkt_fwd = sum(1 for p in fwd_pkts if p.payload_length > 0)
    min_seg_size_fwd = min((p.header_length for p in fwd_pkts), default=20.0)

    # Active / Idle Periods (idle threshold = 5.0 seconds = 5,000,000 us)
    active_times = []
    idle_times = []
    curr_active = 0.0
    for iat in flow_iats:
        if iat > 5000000.0:
            if curr_active > 0:
                active_times.append(curr_active)
                curr_active = 0.0
            idle_times.append(iat)
        else:
            curr_active += iat
    if curr_active > 0:
        active_times.append(curr_active)

    act_arr = np.array(active_times) if active_times else np.array([0.0])
    idle_arr = np.array(idle_times) if idle_times else np.array([0.0])

    # ── Populate 77 Flow Features ──────────────────────────────────────────
    vector[FEATURE_TO_IDX["Flow Duration"]] = float(duration_us)
    vector[FEATURE_TO_IDX["Total Fwd Packets"]] = float(n_fwd)
    vector[FEATURE_TO_IDX["Total Backward Packets"]] = float(n_bwd)
    vector[FEATURE_TO_IDX["Total Length of Fwd Packets"]] = tot_fwd_bytes
    vector[FEATURE_TO_IDX["Total Length of Bwd Packets"]] = tot_bwd_bytes
    
    vector[FEATURE_TO_IDX["Fwd Packet Length Max"]] = float(np.max(fwd_payloads))
    vector[FEATURE_TO_IDX["Fwd Packet Length Min"]] = float(np.min(fwd_payloads)) if n_fwd > 0 else 0.0
    vector[FEATURE_TO_IDX["Fwd Packet Length Mean"]] = float(np.mean(fwd_payloads))
    vector[FEATURE_TO_IDX["Fwd Packet Length Std"]] = float(np.std(fwd_payloads)) if n_fwd > 1 else 0.0

    vector[FEATURE_TO_IDX["Bwd Packet Length Max"]] = float(np.max(bwd_payloads))
    vector[FEATURE_TO_IDX["Bwd Packet Length Min"]] = float(np.min(bwd_payloads)) if n_bwd > 0 else 0.0
    vector[FEATURE_TO_IDX["Bwd Packet Length Mean"]] = float(np.mean(bwd_payloads))
    vector[FEATURE_TO_IDX["Bwd Packet Length Std"]] = float(np.std(bwd_payloads)) if n_bwd > 1 else 0.0

    vector[FEATURE_TO_IDX["Flow Bytes/s"]] = float((tot_fwd_bytes + tot_bwd_bytes) / (duration_sec + eps))
    vector[FEATURE_TO_IDX["Flow Packets/s"]] = float(n_pkts / (duration_sec + eps))

    vector[FEATURE_TO_IDX["Flow IAT Mean"]] = float(np.mean(flow_iats))
    vector[FEATURE_TO_IDX["Flow IAT Std"]] = float(np.std(flow_iats)) if len(flow_iats) > 1 else 0.0
    vector[FEATURE_TO_IDX["Flow IAT Max"]] = float(np.max(flow_iats))
    vector[FEATURE_TO_IDX["Flow IAT Min"]] = float(np.min(flow_iats))

    vector[FEATURE_TO_IDX["Fwd IAT Total"]] = float(np.sum(fwd_iats))
    vector[FEATURE_TO_IDX["Fwd IAT Mean"]] = float(np.mean(fwd_iats))
    vector[FEATURE_TO_IDX["Fwd IAT Std"]] = float(np.std(fwd_iats)) if len(fwd_iats) > 1 else 0.0
    vector[FEATURE_TO_IDX["Fwd IAT Max"]] = float(np.max(fwd_iats))
    vector[FEATURE_TO_IDX["Fwd IAT Min"]] = float(np.min(fwd_iats))

    vector[FEATURE_TO_IDX["Bwd IAT Total"]] = float(np.sum(bwd_iats))
    vector[FEATURE_TO_IDX["Bwd IAT Mean"]] = float(np.mean(bwd_iats))
    vector[FEATURE_TO_IDX["Bwd IAT Std"]] = float(np.std(bwd_iats)) if len(bwd_iats) > 1 else 0.0
    vector[FEATURE_TO_IDX["Bwd IAT Max"]] = float(np.max(bwd_iats))
    vector[FEATURE_TO_IDX["Bwd IAT Min"]] = float(np.min(bwd_iats))

    vector[FEATURE_TO_IDX["Fwd PSH Flags"]] = float(fwd_psh)
    vector[FEATURE_TO_IDX["Bwd PSH Flags"]] = float(bwd_psh)
    vector[FEATURE_TO_IDX["Fwd URG Flags"]] = float(fwd_urg)
    vector[FEATURE_TO_IDX["Bwd URG Flags"]] = float(bwd_urg)

    vector[FEATURE_TO_IDX["Fwd Header Length"]] = fwd_header_len
    vector[FEATURE_TO_IDX["Bwd Header Length"]] = bwd_header_len
    vector[FEATURE_TO_IDX["Fwd Packets/s"]] = float(n_fwd / (duration_sec + eps))
    vector[FEATURE_TO_IDX["Bwd Packets/s"]] = float(n_bwd / (duration_sec + eps))

    vector[FEATURE_TO_IDX["Min Packet Length"]] = float(np.min(all_lengths))
    vector[FEATURE_TO_IDX["Max Packet Length"]] = float(np.max(all_lengths))
    vector[FEATURE_TO_IDX["Packet Length Mean"]] = float(np.mean(all_lengths))
    vector[FEATURE_TO_IDX["Packet Length Std"]] = float(np.std(all_lengths)) if n_pkts > 1 else 0.0
    vector[FEATURE_TO_IDX["Packet Length Variance"]] = float(np.var(all_lengths)) if n_pkts > 1 else 0.0

    vector[FEATURE_TO_IDX["FIN Flag Count"]] = float(fin_count)
    vector[FEATURE_TO_IDX["SYN Flag Count"]] = float(syn_count)
    vector[FEATURE_TO_IDX["RST Flag Count"]] = float(rst_count)
    vector[FEATURE_TO_IDX["PSH Flag Count"]] = float(psh_count)
    vector[FEATURE_TO_IDX["ACK Flag Count"]] = float(ack_count)
    vector[FEATURE_TO_IDX["URG Flag Count"]] = float(urg_count)
    vector[FEATURE_TO_IDX["CWE Flag Count"]] = float(cwe_count)
    vector[FEATURE_TO_IDX["ECE Flag Count"]] = float(ece_count)

    vector[FEATURE_TO_IDX["Down/Up Ratio"]] = float(n_bwd / max(1, n_fwd))
    vector[FEATURE_TO_IDX["Average Packet Size"]] = float(np.mean(all_lengths))
    vector[FEATURE_TO_IDX["Avg Fwd Segment Size"]] = float(tot_fwd_bytes / max(1, n_fwd))
    vector[FEATURE_TO_IDX["Avg Bwd Segment Size"]] = float(tot_bwd_bytes / max(1, n_bwd))
    vector[FEATURE_TO_IDX["Fwd Header Length.1"]] = fwd_header_len

    # Bulk features (defaults to 0.0 for standard small windows)
    vector[FEATURE_TO_IDX["Fwd Avg Bytes/Bulk"]] = 0.0
    vector[FEATURE_TO_IDX["Fwd Avg Packets/Bulk"]] = 0.0
    vector[FEATURE_TO_IDX["Fwd Avg Bulk Rate"]] = 0.0
    vector[FEATURE_TO_IDX["Bwd Avg Bytes/Bulk"]] = 0.0
    vector[FEATURE_TO_IDX["Bwd Avg Packets/Bulk"]] = 0.0
    vector[FEATURE_TO_IDX["Bwd Avg Bulk Rate"]] = 0.0

    # Subflow stats (subflow = 1 flow in rolling window)
    vector[FEATURE_TO_IDX["Subflow Fwd Packets"]] = float(n_fwd)
    vector[FEATURE_TO_IDX["Subflow Fwd Bytes"]] = tot_fwd_bytes
    vector[FEATURE_TO_IDX["Subflow Bwd Packets"]] = float(n_bwd)
    vector[FEATURE_TO_IDX["Subflow Bwd Bytes"]] = tot_bwd_bytes

    vector[FEATURE_TO_IDX["Init_Win_bytes_forward"]] = fwd_init_win
    vector[FEATURE_TO_IDX["Init_Win_bytes_backward"]] = bwd_init_win
    vector[FEATURE_TO_IDX["act_data_pkt_fwd"]] = float(act_data_pkt_fwd)
    vector[FEATURE_TO_IDX["min_seg_size_forward"]] = float(min_seg_size_fwd)

    vector[FEATURE_TO_IDX["Active Mean"]] = float(np.mean(act_arr))
    vector[FEATURE_TO_IDX["Active Std"]] = float(np.std(act_arr)) if len(active_times) > 1 else 0.0
    vector[FEATURE_TO_IDX["Active Max"]] = float(np.max(act_arr))
    vector[FEATURE_TO_IDX["Active Min"]] = float(np.min(act_arr))

    vector[FEATURE_TO_IDX["Idle Mean"]] = float(np.mean(idle_arr))
    vector[FEATURE_TO_IDX["Idle Std"]] = float(np.std(idle_arr)) if len(idle_times) > 1 else 0.0
    vector[FEATURE_TO_IDX["Idle Max"]] = float(np.max(idle_arr))
    vector[FEATURE_TO_IDX["Idle Min"]] = float(np.min(idle_arr))

    # ── Populate 7 Packet-Level Verified Features ───────────────────────────
    ttls = np.array([p.ttl for p in packets], dtype=np.float64)
    tcp_windows = np.array([p.tcp_window for p in packets if p.tcp_window > 0], dtype=np.float64)
    fragments = sum(1 for p in packets if (p.ip_flags & 0x01) or (p.frag_offset > 0))

    # Retransmission detection: duplicate sequence numbers with payload > 0
    seen_seqs = set()
    retrans_count = 0
    for p in packets:
        if p.protocol == 6 and p.payload_length > 0:
            key = (p.direction, p.seq_num)
            if key in seen_seqs:
                retrans_count += 1
            else:
                seen_seqs.add(key)

    vector[FEATURE_TO_IDX["ttl_mean"]] = float(np.mean(ttls)) if len(ttls) > 0 else 64.0
    vector[FEATURE_TO_IDX["ttl_variance"]] = float(np.var(ttls)) if len(ttls) > 1 else 0.0
    vector[FEATURE_TO_IDX["tcp_window_mean"]] = float(np.mean(tcp_windows)) if len(tcp_windows) > 0 else 0.0
    vector[FEATURE_TO_IDX["tcp_window_min"]] = float(np.min(tcp_windows)) if len(tcp_windows) > 0 else 0.0
    vector[FEATURE_TO_IDX["tcp_window_max"]] = float(np.max(tcp_windows)) if len(tcp_windows) > 0 else 0.0
    vector[FEATURE_TO_IDX["ip_fragment_flag_present"]] = 1.0 if fragments > 0 else 0.0
    vector[FEATURE_TO_IDX["retransmission_count"]] = float(retrans_count)

    return vector


def adapt_dataframe_to_canonical(df: pd.DataFrame) -> np.ndarray:
    """
    Transforms any incoming DataFrame (CIC-IDS-2017/2018, CTU-13, UNSW-NB15, or raw CSV)
    into a canonical (N, 84) matrix in the exact schema order.
    
    Missing features are filled with safe default values (0.0).
    """
    N = len(df)
    matrix = np.zeros((N, NUM_CANONICAL_FEATURES), dtype=np.float32)
    cols = set(df.columns)

    # Detect dataset type
    is_ctu = {"Dur", "TotPkts"}.issubset(cols) or "TotBytes" in cols
    is_unsw = {"dur", "spkts"}.issubset(cols) or "sbytes" in cols

    mapping: Dict[str, str] = {}
    if is_ctu:
        mapping = CTU13_TO_CANONICAL
    elif is_unsw:
        mapping = UNSW_TO_CANONICAL

    mapped_cols = {}
    for src_col, target_col in mapping.items():
        if src_col in df.columns:
            mapped_cols[target_col] = pd.to_numeric(df[src_col], errors="coerce").fillna(0.0).values

    for i, target_feat in enumerate(CANONICAL_84_FEATURES):
        if target_feat in df.columns:
            matrix[:, i] = pd.to_numeric(df[target_feat], errors="coerce").fillna(0.0).values
        elif target_feat in mapped_cols:
            matrix[:, i] = mapped_cols[target_feat]
        elif target_feat == "ttl_mean" and "sttl" in df.columns:
            matrix[:, i] = pd.to_numeric(df["sttl"], errors="coerce").fillna(64.0).values
        else:
            # Neutral default
            matrix[:, i] = 0.0

    return matrix
