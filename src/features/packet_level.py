"""
Packet-level feature extraction for ShieldNet.

Extracts features that require packet-level inspection:
- TTL variance and statistics
- TCP window size analysis
- IP fragmentation detection
- Payload size distribution and entropy
- Port-scan pattern detection
- Retransmission analysis
- TCP flag ratios

When raw PCAP data is available, these are computed directly from packets.
When only flow-CSV is available, proxy features are derived from available metadata.
Proxy features are flagged in the schema and DECISIONS.md.
"""

import numpy as np
import pandas as pd
from typing import Optional
from collections import Counter


def extract_packet_features_from_pcap(pcap_path: str) -> pd.DataFrame:
    """Extract packet-level features from a PCAP file using Scapy.
    
    This is the gold-standard extraction path when raw packet data is available.
    
    Args:
        pcap_path: Path to .pcap or .pcapng file.
    
    Returns:
        DataFrame with packet-level features aggregated per flow (5-tuple).
    """
    try:
        from scapy.all import rdpcap, IP, TCP, UDP
    except ImportError:
        raise ImportError("Scapy is required for PCAP parsing. Install with: pip install scapy")
    
    packets = rdpcap(pcap_path)
    
    # Group packets by flow (5-tuple)
    flows = {}
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        
        ip = pkt[IP]
        proto = ip.proto
        
        src_port = dst_port = 0
        tcp_win = 0
        tcp_flags = 0
        
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            tcp_win = tcp.window
            tcp_flags = int(tcp.flags)
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport
        
        flow_key = (ip.src, ip.dst, src_port, dst_port, proto)
        
        if flow_key not in flows:
            flows[flow_key] = {
                'ttls': [], 'tcp_windows': [], 'payload_sizes': [],
                'flags': [], 'ports_accessed': [], 'is_fragment': [],
                'is_retransmission': [], 'seq_numbers': set(),
            }
        
        flow = flows[flow_key]
        flow['ttls'].append(ip.ttl)
        flow['tcp_windows'].append(tcp_win)
        flow['payload_sizes'].append(len(pkt) - len(ip))
        flow['flags'].append(tcp_flags)
        flow['ports_accessed'].append(dst_port)
        flow['is_fragment'].append(1 if (ip.flags & 0x1) or ip.frag > 0 else 0)
        
        # Simple retransmission detection (same seq number seen twice)
        if pkt.haslayer(TCP):
            seq = pkt[TCP].seq
            if seq in flow['seq_numbers']:
                flow['is_retransmission'].append(1)
            else:
                flow['is_retransmission'].append(0)
            flow['seq_numbers'].add(seq)
    
    # Compute per-flow features
    records = []
    for (src_ip, dst_ip, src_port, dst_port, proto), flow in flows.items():
        ttls = np.array(flow['ttls'])
        windows = np.array(flow['tcp_windows'])
        payloads = np.array(flow['payload_sizes'])
        flags = np.array(flow['flags'])
        fragments = np.array(flow['is_fragment'])
        retrans = np.array(flow['is_retransmission'])
        
        total_packets = len(ttls)
        
        record = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': proto,
            'ttl_variance': float(np.var(ttls)) if len(ttls) > 1 else 0.0,
            'ttl_mean': float(np.mean(ttls)),
            'tcp_window_size_mean': float(np.mean(windows)) if len(windows) > 0 else 0.0,
            'tcp_window_size_std': float(np.std(windows)) if len(windows) > 1 else 0.0,
            'ip_fragment_flag_ratio': float(np.mean(fragments)),
            'payload_size_mean': float(np.mean(payloads)) if len(payloads) > 0 else 0.0,
            'payload_size_std': float(np.std(payloads)) if len(payloads) > 1 else 0.0,
            'payload_size_entropy': _compute_entropy(payloads),
            'port_scan_sequential_score': _compute_sequential_scan_score(flow['ports_accessed']),
            'port_scan_random_score': _compute_random_scan_score(flow['ports_accessed']),
            'retransmission_count': int(np.sum(retrans)),
            'retransmission_ratio': float(np.mean(retrans)) if total_packets > 0 else 0.0,
            'syn_ratio': float(np.sum((flags & 0x02) > 0)) / max(total_packets, 1),
            'rst_ratio': float(np.sum((flags & 0x04) > 0)) / max(total_packets, 1),
            'fin_ratio': float(np.sum((flags & 0x01) > 0)) / max(total_packets, 1),
        }
        records.append(record)
    
    return pd.DataFrame(records)


def derive_packet_features_from_flow(df: pd.DataFrame) -> pd.DataFrame:
    """Derive packet-level proxy features from flow-level CSV data.
    
    When raw PCAP is not available, we derive approximate packet-level
    features from available flow metadata. These are PROXY features
    and are clearly marked as such.
    
    Args:
        df: DataFrame with flow-level features (already normalized to schema).
    
    Returns:
        DataFrame with packet-level features added.
    """
    result = df.copy()
    
    # TTL features — derive from init_win_bytes as OS fingerprint proxy
    if 'ttl_variance' not in result.columns:
        if 'init_win_bytes_forward' in result.columns:
            # Different window sizes suggest different OS/TTL defaults
            result['ttl_variance'] = result['init_win_bytes_forward'].apply(
                lambda x: np.random.exponential(2) if x in [65535, 29200] else np.random.exponential(8)
            )
            result['ttl_mean'] = result['init_win_bytes_forward'].apply(
                lambda x: 64 if x in [29200, 65535] else 128  # Linux vs Windows default
            )
        else:
            result['ttl_variance'] = 2.0
            result['ttl_mean'] = 64.0
    
    # TCP window features
    if 'tcp_window_size_mean' not in result.columns:
        if 'init_win_bytes_forward' in result.columns:
            result['tcp_window_size_mean'] = result['init_win_bytes_forward'].astype(float)
            result['tcp_window_size_std'] = abs(
                result.get('init_win_bytes_forward', 0).astype(float) - 
                result.get('init_win_bytes_backward', 0).astype(float)
            ) / 2
        else:
            result['tcp_window_size_mean'] = 16384.0
            result['tcp_window_size_std'] = 0.0
    
    # IP fragmentation — derive from packet size vs typical MTU
    if 'ip_fragment_flag_ratio' not in result.columns:
        if 'avg_packet_size' in result.columns:
            result['ip_fragment_flag_ratio'] = (result['avg_packet_size'] > 1500).astype(float) * 0.1
        else:
            result['ip_fragment_flag_ratio'] = 0.0
    
    # Payload size features
    if 'payload_size_mean' not in result.columns:
        if 'avg_packet_size' in result.columns:
            result['payload_size_mean'] = (result['avg_packet_size'] - 40).clip(0)  # subtract headers
            result['payload_size_std'] = result.get('packet_length_std', 0).astype(float)
        else:
            result['payload_size_mean'] = 0.0
            result['payload_size_std'] = 0.0
    
    if 'payload_size_entropy' not in result.columns:
        if 'packet_length_variance' in result.columns:
            # Higher variance ≈ higher entropy in payload sizes
            result['payload_size_entropy'] = np.log1p(result['packet_length_variance']) / np.log(256) * 4
            result['payload_size_entropy'] = result['payload_size_entropy'].clip(0, 8)
        else:
            result['payload_size_entropy'] = 4.0
    
    # Port scan scores — derive from destination port patterns
    if 'port_scan_sequential_score' not in result.columns:
        result['port_scan_sequential_score'] = 0.0
        result['port_scan_random_score'] = 0.0
    
    # Retransmission features
    if 'retransmission_count' not in result.columns:
        if 'rst_flag_count' in result.columns:
            # RST flags correlate with connection issues/retransmissions
            result['retransmission_count'] = (result['rst_flag_count'] * 2).astype(float)
            total_pkts = (result.get('total_fwd_packets', 1).astype(float) + 
                         result.get('total_bwd_packets', 0).astype(float)).clip(1)
            result['retransmission_ratio'] = result['retransmission_count'] / total_pkts
        else:
            result['retransmission_count'] = 0.0
            result['retransmission_ratio'] = 0.0
    
    # TCP flag ratios
    if 'syn_ratio' not in result.columns:
        total_flags = (
            result.get('syn_flag_count', 0).astype(float) +
            result.get('fin_flag_count', 0).astype(float) +
            result.get('rst_flag_count', 0).astype(float) +
            result.get('ack_flag_count', 0).astype(float) +
            result.get('psh_flag_count', 0).astype(float)
        ).clip(1)
        
        result['syn_ratio'] = result.get('syn_flag_count', 0).astype(float) / total_flags
        result['rst_ratio'] = result.get('rst_flag_count', 0).astype(float) / total_flags
        result['fin_ratio'] = result.get('fin_flag_count', 0).astype(float) / total_flags
    
    return result


def _compute_entropy(values):
    """Compute Shannon entropy of a discrete distribution."""
    if len(values) == 0:
        return 0.0
    # Bin continuous values
    hist, _ = np.histogram(values, bins=min(50, len(values)))
    probs = hist / hist.sum()
    probs = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs)))


def _compute_sequential_scan_score(ports):
    """Detect sequential port scanning pattern.
    
    Returns a score [0, 1] where 1 indicates strong sequential pattern.
    """
    if len(ports) < 3:
        return 0.0
    
    unique_ports = list(dict.fromkeys(ports))  # preserve order, remove dupes
    if len(unique_ports) < 3:
        return 0.0
    
    # Check for sequential differences
    diffs = np.diff(unique_ports)
    sequential_count = np.sum(np.abs(diffs) == 1)
    return float(sequential_count / max(len(diffs), 1))


def _compute_random_scan_score(ports):
    """Detect random port scanning pattern.
    
    Returns a score [0, 1] where 1 indicates many unique ports accessed (random scan).
    """
    if len(ports) < 3:
        return 0.0
    
    unique_ratio = len(set(ports)) / len(ports)
    # High unique ratio with many ports suggests random scanning
    if len(set(ports)) > 10 and unique_ratio > 0.8:
        return min(unique_ratio, 1.0)
    return unique_ratio * 0.3
