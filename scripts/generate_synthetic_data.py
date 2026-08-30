"""
Synthetic Network Traffic Data Generator for NetGuard.

Generates realistic network traffic data following CIC-IDS-2018 and CTU-13 schemas.
Used for development and testing when real datasets aren't available locally.
The generated data mimics the statistical properties and attack patterns of real datasets.

IMPORTANT: This is a DEVELOPMENT tool. For evaluation, use real datasets per DECISIONS.md.
"""

import numpy as np
import pandas as pd
from pathlib import Path
import sys
import os
from datetime import datetime, timedelta

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Fixed seed for reproducibility (Constraint C6)
np.random.seed(42)

# ─── CIC-IDS-2018 Attack Types (from the real dataset) ─────────────────────
CIC_ATTACK_TYPES = [
    'Benign',
    'FTP-BruteForce',
    'SSH-Bruteforce',
    'DoS attacks-GoldenEye',
    'DoS attacks-Slowloris',
    'DoS attacks-SlowHTTPTest',
    'DoS attacks-Hulk',
    'DDoS attacks-LOIC-HTTP',
    'DDoS attack-HOIC',
    'DDoS attack-LOIC-UDP',
    'Brute Force -Web',
    'Brute Force -XSS',
    'SQL Injection',
    'Infilteration',
    'Bot',
]

# Attack type distribution (approximating real CIC-IDS-2018 class balance)
CIC_ATTACK_WEIGHTS = {
    'Benign': 0.65,
    'FTP-BruteForce': 0.03,
    'SSH-Bruteforce': 0.03,
    'DoS attacks-GoldenEye': 0.04,
    'DoS attacks-Slowloris': 0.02,
    'DoS attacks-SlowHTTPTest': 0.02,
    'DoS attacks-Hulk': 0.06,
    'DDoS attacks-LOIC-HTTP': 0.04,
    'DDoS attack-HOIC': 0.03,
    'DDoS attack-LOIC-UDP': 0.02,
    'Brute Force -Web': 0.01,
    'Brute Force -XSS': 0.01,
    'SQL Injection': 0.005,
    'Infilteration': 0.02,
    'Bot': 0.025,
}

# ─── CTU-13 Attack Types ───────────────────────────────────────────────────
CTU_ATTACK_TYPES = [
    'Normal',
    'Botnet',           # Primary label in CTU-13
    'Background',       # Background traffic
]

# ─── Feature generation profiles per attack type ───────────────────────────

def _gen_benign_flow(n):
    """Generate benign/normal traffic features."""
    return {
        'flow_duration': np.random.exponential(30, n) * 1e6,  # microseconds
        'total_fwd_packets': np.random.poisson(10, n).clip(1),
        'total_bwd_packets': np.random.poisson(8, n).clip(0),
        'total_fwd_bytes': np.random.exponential(500, n),
        'total_bwd_bytes': np.random.exponential(2000, n),
        'fwd_packet_length_mean': np.random.normal(200, 80, n).clip(0),
        'fwd_packet_length_std': np.random.exponential(50, n),
        'bwd_packet_length_mean': np.random.normal(500, 200, n).clip(0),
        'bwd_packet_length_std': np.random.exponential(100, n),
        'flow_bytes_per_sec': np.random.exponential(5000, n),
        'flow_packets_per_sec': np.random.exponential(50, n),
        'flow_iat_mean': np.random.exponential(500000, n),
        'flow_iat_std': np.random.exponential(300000, n),
        'fwd_iat_mean': np.random.exponential(800000, n),
        'fwd_iat_std': np.random.exponential(500000, n),
        'bwd_iat_mean': np.random.exponential(1000000, n),
        'bwd_iat_std': np.random.exponential(700000, n),
        'fwd_psh_flags': np.random.binomial(1, 0.3, n),
        'bwd_psh_flags': np.random.binomial(1, 0.2, n),
        'fwd_urg_flags': np.zeros(n, dtype=int),
        'bwd_urg_flags': np.zeros(n, dtype=int),
        'fin_flag_count': np.random.binomial(2, 0.3, n),
        'syn_flag_count': np.random.binomial(2, 0.5, n),
        'rst_flag_count': np.random.binomial(1, 0.05, n),
        'psh_flag_count': np.random.binomial(2, 0.3, n),
        'ack_flag_count': np.random.binomial(5, 0.7, n),
        'urg_flag_count': np.zeros(n, dtype=int),
        'ece_flag_count': np.zeros(n, dtype=int),
        'down_up_ratio': np.random.exponential(2, n).clip(0.1, 50),
        'fwd_header_length': np.random.choice([20, 32, 40], n, p=[0.5, 0.3, 0.2]),
        'bwd_header_length': np.random.choice([20, 32, 40], n, p=[0.5, 0.3, 0.2]),
        'fwd_packets_per_sec': np.random.exponential(20, n),
        'bwd_packets_per_sec': np.random.exponential(15, n),
        'packet_length_mean': np.random.normal(300, 150, n).clip(0),
        'packet_length_std': np.random.exponential(100, n),
        'packet_length_variance': np.random.exponential(10000, n),
        'avg_packet_size': np.random.normal(350, 150, n).clip(40),
        'fwd_segment_size_avg': np.random.normal(200, 80, n).clip(0),
        'bwd_segment_size_avg': np.random.normal(500, 200, n).clip(0),
        'init_win_bytes_forward': np.random.choice([8192, 16384, 29200, 65535], n),
        'init_win_bytes_backward': np.random.choice([8192, 16384, 29200, 65535], n),
        'active_mean': np.random.exponential(50000, n),
        'active_std': np.random.exponential(30000, n),
        'idle_mean': np.random.exponential(500000, n),
        'idle_std': np.random.exponential(300000, n),
        'subflow_fwd_packets': np.random.poisson(5, n).clip(1),
        'subflow_bwd_packets': np.random.poisson(4, n).clip(0),
        'subflow_fwd_bytes': np.random.exponential(300, n),
        'subflow_bwd_bytes': np.random.exponential(1000, n),
        # Packet-level proxy features
        'ttl_variance': np.random.exponential(2, n),
        'ttl_mean': np.random.normal(64, 10, n).clip(1, 255),
        'tcp_window_size_mean': np.random.normal(16384, 5000, n).clip(100),
        'tcp_window_size_std': np.random.exponential(2000, n),
        'ip_fragment_flag_ratio': np.random.beta(1, 50, n),
        'payload_size_mean': np.random.normal(300, 150, n).clip(0),
        'payload_size_std': np.random.exponential(100, n),
        'payload_size_entropy': np.random.uniform(3, 7, n),
        'port_scan_sequential_score': np.random.beta(1, 100, n),
        'port_scan_random_score': np.random.beta(1, 100, n),
        'retransmission_count': np.random.poisson(0.5, n),
        'retransmission_ratio': np.random.beta(1, 50, n),
        'syn_ratio': np.random.beta(2, 8, n),
        'rst_ratio': np.random.beta(1, 50, n),
        'fin_ratio': np.random.beta(2, 8, n),
    }


def _gen_dos_flow(n):
    """Generate DoS/DDoS attack features — high packet rate, many SYNs."""
    base = _gen_benign_flow(n)
    # DoS characteristics: very high packet rates, short durations, many SYNs
    base['flow_duration'] = np.random.exponential(2, n) * 1e6
    base['total_fwd_packets'] = np.random.poisson(200, n).clip(50)
    base['total_bwd_packets'] = np.random.poisson(5, n).clip(0)
    base['flow_bytes_per_sec'] = np.random.exponential(500000, n)
    base['flow_packets_per_sec'] = np.random.exponential(5000, n)
    base['fwd_packets_per_sec'] = np.random.exponential(3000, n)
    base['syn_flag_count'] = np.random.poisson(50, n)
    base['rst_flag_count'] = np.random.poisson(10, n)
    base['ack_flag_count'] = np.random.poisson(2, n)
    base['fwd_packet_length_mean'] = np.random.normal(60, 10, n).clip(40)
    base['fwd_packet_length_std'] = np.random.exponential(5, n)
    base['init_win_bytes_forward'] = np.random.choice([1024, 2048, 512], n)
    base['syn_ratio'] = np.random.beta(8, 2, n)
    base['rst_ratio'] = np.random.beta(3, 5, n)
    base['retransmission_count'] = np.random.poisson(5, n)
    base['retransmission_ratio'] = np.random.beta(5, 10, n)
    base['port_scan_sequential_score'] = np.random.beta(1, 50, n)
    base['ttl_variance'] = np.random.exponential(15, n)
    base['tcp_window_size_mean'] = np.random.normal(1024, 500, n).clip(100)
    return base


def _gen_bruteforce_flow(n):
    """Generate brute-force attack features — many short connections."""
    base = _gen_benign_flow(n)
    base['flow_duration'] = np.random.exponential(5, n) * 1e6
    base['total_fwd_packets'] = np.random.poisson(5, n).clip(2)
    base['total_bwd_packets'] = np.random.poisson(3, n).clip(1)
    base['total_fwd_bytes'] = np.random.normal(100, 30, n).clip(20)
    base['total_bwd_bytes'] = np.random.normal(80, 30, n).clip(10)
    base['flow_iat_mean'] = np.random.exponential(50000, n)  # fast reconnects
    base['fwd_iat_mean'] = np.random.exponential(30000, n)
    base['syn_flag_count'] = np.random.poisson(3, n)
    base['fin_flag_count'] = np.random.poisson(2, n)
    base['rst_flag_count'] = np.random.poisson(3, n)  # many failed attempts
    base['rst_ratio'] = np.random.beta(5, 5, n)
    base['retransmission_count'] = np.random.poisson(2, n)
    return base


def _gen_portscan_flow(n):
    """Generate port-scan/reconnaissance features."""
    base = _gen_benign_flow(n)
    base['flow_duration'] = np.random.exponential(0.5, n) * 1e6
    base['total_fwd_packets'] = np.random.choice([1, 2, 3], n, p=[0.6, 0.3, 0.1])
    base['total_bwd_packets'] = np.random.choice([0, 1], n, p=[0.4, 0.6])
    base['total_fwd_bytes'] = np.random.normal(60, 10, n).clip(40)
    base['syn_flag_count'] = np.random.poisson(2, n).clip(1)
    base['rst_flag_count'] = np.random.poisson(1, n)
    base['port_scan_sequential_score'] = np.random.beta(10, 2, n)
    base['port_scan_random_score'] = np.random.beta(5, 3, n)
    base['syn_ratio'] = np.random.beta(9, 1, n)
    base['ttl_mean'] = np.random.choice([64, 128, 255], n, p=[0.4, 0.4, 0.2])
    return base


def _gen_infiltration_flow(n):
    """Generate infiltration/lateral movement features — looks more like benign but with anomalies."""
    base = _gen_benign_flow(n)
    # Slightly elevated but not as dramatic as DoS
    base['flow_duration'] = np.random.exponential(60, n) * 1e6
    base['total_fwd_bytes'] = np.random.exponential(5000, n)
    base['total_bwd_bytes'] = np.random.exponential(10000, n)
    base['payload_size_entropy'] = np.random.uniform(6, 8, n)  # high entropy = encrypted/exfil
    base['down_up_ratio'] = np.random.exponential(5, n).clip(0.5, 100)
    base['idle_mean'] = np.random.exponential(2000000, n)
    base['ttl_variance'] = np.random.exponential(8, n)
    base['tcp_window_size_std'] = np.random.exponential(5000, n)
    return base


def _gen_botnet_flow(n):
    """Generate botnet C2 communication features."""
    base = _gen_benign_flow(n)
    base['flow_duration'] = np.random.exponential(120, n) * 1e6  # long-lived
    base['flow_iat_mean'] = np.random.normal(60000000, 10000000, n).clip(1000)  # periodic
    base['flow_iat_std'] = np.random.exponential(5000000, n)  # low std = regular beaconing
    base['total_fwd_bytes'] = np.random.normal(200, 50, n).clip(10)  # small payloads
    base['total_bwd_bytes'] = np.random.normal(150, 50, n).clip(10)
    base['payload_size_entropy'] = np.random.uniform(6.5, 8, n)  # encrypted
    base['init_win_bytes_forward'] = np.random.choice([512, 1024, 2048], n)
    base['ttl_mean'] = np.random.normal(128, 5, n).clip(1, 255)
    return base


# Map attack types to generator functions
ATTACK_GENERATORS = {
    'Benign': _gen_benign_flow,
    'FTP-BruteForce': _gen_bruteforce_flow,
    'SSH-Bruteforce': _gen_bruteforce_flow,
    'DoS attacks-GoldenEye': _gen_dos_flow,
    'DoS attacks-Slowloris': _gen_dos_flow,
    'DoS attacks-SlowHTTPTest': _gen_dos_flow,
    'DoS attacks-Hulk': _gen_dos_flow,
    'DDoS attacks-LOIC-HTTP': _gen_dos_flow,
    'DDoS attack-HOIC': _gen_dos_flow,
    'DDoS attack-LOIC-UDP': _gen_dos_flow,
    'Brute Force -Web': _gen_bruteforce_flow,
    'Brute Force -XSS': _gen_bruteforce_flow,
    'SQL Injection': _gen_infiltration_flow,
    'Infilteration': _gen_infiltration_flow,
    'Bot': _gen_botnet_flow,
    'Normal': _gen_benign_flow,
    'Botnet': _gen_botnet_flow,
    'Background': _gen_benign_flow,
}


def generate_network_metadata(n):
    """Generate common network metadata (IPs, ports, protocol, timestamps)."""
    # Source IPs - internal network
    src_ips = [f"192.168.{np.random.randint(1, 10)}.{np.random.randint(1, 255)}" for _ in range(n)]
    # Destination IPs - mix of internal and external
    dst_ips = []
    for _ in range(n):
        if np.random.random() < 0.4:
            dst_ips.append(f"192.168.{np.random.randint(1, 10)}.{np.random.randint(1, 255)}")
        else:
            dst_ips.append(f"{np.random.randint(1, 223)}.{np.random.randint(0, 255)}."
                          f"{np.random.randint(0, 255)}.{np.random.randint(1, 255)}")
    
    # Ports
    common_ports = [80, 443, 22, 21, 25, 53, 110, 143, 3306, 8080, 8443]
    src_ports = np.random.randint(1024, 65535, n)
    dst_ports = np.array([np.random.choice(common_ports) if np.random.random() < 0.7 
                          else np.random.randint(1, 65535) for _ in range(n)])
    
    # Protocol
    protocols = np.random.choice([6, 17, 1], n, p=[0.7, 0.25, 0.05])  # TCP, UDP, ICMP
    
    # Timestamps — spread over a simulated capture period
    base_time = datetime(2018, 2, 14, 8, 0, 0)
    timestamps = [base_time + timedelta(seconds=float(np.random.uniform(0, 28800)))  # 8 hours
                  for _ in range(n)]
    timestamps.sort()
    
    return {
        'src_ip': src_ips,
        'dst_ip': dst_ips,
        'src_port': src_ports,
        'dst_port': dst_ports,
        'protocol': protocols,
        'timestamp': timestamps,
    }


def generate_cic_ids_2018(output_dir, total_rows=50000):
    """Generate synthetic CIC-IDS-2018 data."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Generating CIC-IDS-2018 synthetic data ({total_rows:,} rows)...")
    
    # Determine per-type row counts
    rows_per_type = {}
    remaining = total_rows
    for attack_type in CIC_ATTACK_TYPES[:-1]:
        count = int(total_rows * CIC_ATTACK_WEIGHTS[attack_type])
        rows_per_type[attack_type] = count
        remaining -= count
    rows_per_type[CIC_ATTACK_TYPES[-1]] = remaining
    
    # Generate data per attack type
    all_dfs = []
    for attack_type, count in rows_per_type.items():
        if count <= 0:
            continue
        print(f"  Generating {count:,} rows for '{attack_type}'...")
        
        gen_func = ATTACK_GENERATORS[attack_type]
        features = gen_func(count)
        metadata = generate_network_metadata(count)
        
        df = pd.DataFrame({**metadata, **features})
        df['label'] = attack_type
        all_dfs.append(df)
    
    # Combine and shuffle
    full_df = pd.concat(all_dfs, ignore_index=True)
    full_df = full_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Re-sort by timestamp to simulate temporal capture
    full_df = full_df.sort_values('timestamp').reset_index(drop=True)
    
    # Split into daily files to mimic real CIC-IDS-2018 structure
    days = {
        'Wednesday-14-02-2018': (0, len(full_df) // 3),
        'Thursday-15-02-2018': (len(full_df) // 3, 2 * len(full_df) // 3),
        'Friday-16-02-2018': (2 * len(full_df) // 3, len(full_df)),
    }
    
    for day_name, (start, end) in days.items():
        day_df = full_df.iloc[start:end].copy()
        filepath = output_dir / f"{day_name}_TrafficForML_CICFlowMeter.csv"
        day_df.to_csv(filepath, index=False)
        print(f"  Saved {filepath.name}: {len(day_df):,} rows")
    
    print(f"  Total: {len(full_df):,} rows across {len(days)} files")
    return full_df


def generate_ctu_13(output_dir, rows_per_scenario=5000):
    """Generate synthetic CTU-13 data (13 scenarios)."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"\nGenerating CTU-13 synthetic data ({rows_per_scenario:,} rows × 13 scenarios)...")
    
    # CTU-13 has 13 scenarios, each with different botnet types
    scenario_configs = [
        {'id': 1, 'botnet': 'Neris', 'botnet_ratio': 0.15},
        {'id': 2, 'botnet': 'Neris', 'botnet_ratio': 0.10},
        {'id': 3, 'botnet': 'Rbot', 'botnet_ratio': 0.20},
        {'id': 4, 'botnet': 'Rbot', 'botnet_ratio': 0.12},
        {'id': 5, 'botnet': 'Virut', 'botnet_ratio': 0.08},
        {'id': 6, 'botnet': 'Menti', 'botnet_ratio': 0.05},
        {'id': 7, 'botnet': 'Sogou', 'botnet_ratio': 0.03},
        {'id': 8, 'botnet': 'Murlo', 'botnet_ratio': 0.07},
        {'id': 9, 'botnet': 'Neris', 'botnet_ratio': 0.18},
        {'id': 10, 'botnet': 'Rbot', 'botnet_ratio': 0.15},
        {'id': 11, 'botnet': 'Rbot', 'botnet_ratio': 0.10},
        {'id': 12, 'botnet': 'NSIS.ay', 'botnet_ratio': 0.06},
        {'id': 13, 'botnet': 'Virut', 'botnet_ratio': 0.14},
    ]
    
    for config in scenario_configs:
        n_botnet = int(rows_per_scenario * config['botnet_ratio'])
        n_normal = int(rows_per_scenario * 0.3)
        n_background = rows_per_scenario - n_botnet - n_normal
        
        parts = []
        
        # Normal traffic
        normal_features = _gen_benign_flow(n_normal)
        normal_meta = generate_network_metadata(n_normal)
        normal_df = pd.DataFrame({**normal_meta, **normal_features})
        normal_df['label'] = 'Normal'
        normal_df['detailed_label'] = 'Normal'
        parts.append(normal_df)
        
        # Background traffic
        bg_features = _gen_benign_flow(n_background)
        bg_meta = generate_network_metadata(n_background)
        bg_df = pd.DataFrame({**bg_meta, **bg_features})
        bg_df['label'] = 'Background'
        bg_df['detailed_label'] = 'Background'
        parts.append(bg_df)
        
        # Botnet traffic
        bot_features = _gen_botnet_flow(n_botnet)
        bot_meta = generate_network_metadata(n_botnet)
        bot_df = pd.DataFrame({**bot_meta, **bot_features})
        bot_df['label'] = 'Botnet'
        bot_df['detailed_label'] = f"Botnet-{config['botnet']}"
        parts.append(bot_df)
        
        scenario_df = pd.concat(parts, ignore_index=True)
        scenario_df = scenario_df.sort_values('timestamp').reset_index(drop=True)
        
        filepath = output_dir / f"scenario_{config['id']}.csv"
        scenario_df.to_csv(filepath, index=False)
        print(f"  Scenario {config['id']:2d} ({config['botnet']:>8s}): "
              f"{len(scenario_df):,} rows ({n_botnet} botnet, {n_normal} normal, {n_background} background)")
    
    print(f"  Total: {rows_per_scenario * 13:,} rows across 13 scenarios")


def main():
    """Generate all synthetic datasets."""
    raw_dir = PROJECT_ROOT / "data" / "raw"
    
    print("=" * 60)
    print("NetGuard Synthetic Data Generator")
    print("=" * 60)
    print(f"Output directory: {raw_dir}")
    print()
    
    # Generate CIC-IDS-2018
    generate_cic_ids_2018(raw_dir / "cic-ids-2018", total_rows=50000)
    
    # Generate CTU-13
    generate_ctu_13(raw_dir / "ctu-13", rows_per_scenario=5000)
    
    print("\n" + "=" * 60)
    print("Synthetic data generation complete.")
    print("Run 'python scripts/verify_datasets.py' to generate manifests.")
    print("=" * 60)


if __name__ == '__main__':
    main()
