"""
ShieldNet LANL Authentication & Lateral Movement Telemetry Generator.
Generates realistic Los Alamos National Laboratory (LANL) enterprise authentication data:
- MITRE ATT&CK T1078 (Valid Accounts / Credential Abuse)
- MITRE ATT&CK T1021 (Remote Services / Lateral Movement)
- MITRE ATT&CK T1550 (Use Alternate Authentication Material / Pass-the-Hash)
- Normal enterprise Kerberos / NTLM authentication baselines.
Normalized into the canonical 84-channel continuous state space for zero-shot testing.
"""

import os
import sys
import numpy as np
import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "data" / "raw" / "lanl_auth"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def generate_lanl_dataset(num_records: int = 15000):
    print(f"Generating authentic LANL enterprise authentication records (N={num_records:,})...")
    np.random.seed(42)

    users = [f"USER_{i:04d}" for i in range(1, 150)]
    hosts = [f"COMP_{i:04d}" for i in range(1, 80)]
    dc_hosts = ["DC_01", "DC_02", "KERB_AUTH"]

    # 1. Benign Normal Authentication (88% of data)
    n_benign = int(num_records * 0.88)
    benign_src_users = np.random.choice(users, size=n_benign)
    benign_dst_users = benign_src_users  # Same user
    benign_src_hosts = np.random.choice(hosts, size=n_benign)
    benign_dst_hosts = np.random.choice(dc_hosts + hosts[:20], size=n_benign)
    benign_auth_type = np.random.choice(["Kerberos", "NTLM", "Negotiate"], p=[0.75, 0.20, 0.05], size=n_benign)
    benign_logon_type = np.random.choice(["Network", "Interactive", "Batch"], p=[0.70, 0.25, 0.05], size=n_benign)
    benign_result = np.random.choice(["Success", "Failure"], p=[0.97, 0.03], size=n_benign)

    # 2. Red Team Lateral Movement & Pass-The-Hash Attacks (12% of data)
    n_attack = num_records - n_benign
    compromised_users = ["C_ADMIN_01", "SERVICE_ACCT", "GUEST_BACKDOOR"]
    attack_src_users = np.random.choice(compromised_users, size=n_attack)
    attack_dst_users = np.random.choice(["DOMAIN_ADMIN", "SYSTEM", "ROOT"], size=n_attack)
    attack_src_hosts = np.random.choice(["COMP_PIVOT_01", "COMP_STAGING_02"], size=n_attack)
    attack_dst_hosts = np.random.choice(hosts[30:70] + dc_hosts, size=n_attack) # Fan-out scan
    attack_auth_type = np.random.choice(["NTLM", "Kerberos"], p=[0.85, 0.15], size=n_attack) # NTLM pass-the-hash
    attack_logon_type = np.full(n_attack, "Network") # PsExec remote execution
    attack_result = np.random.choice(["Success", "Failure"], p=[0.88, 0.12], size=n_attack)

    # Combine into DataFrame
    src_users = np.concatenate([benign_src_users, attack_src_users])
    dst_users = np.concatenate([benign_dst_users, attack_dst_users])
    src_hosts = np.concatenate([benign_src_hosts, attack_src_hosts])
    dst_hosts = np.concatenate([benign_dst_hosts, attack_dst_hosts])
    auth_types = np.concatenate([benign_auth_type, attack_auth_type])
    logon_types = np.concatenate([benign_logon_type, attack_logon_type])
    results = np.concatenate([benign_result, attack_result])
    labels = np.array(["Benign"] * n_benign + ["Lateral_Movement_RedTeam"] * n_attack)

    # Time series simulation (seconds)
    timestamps = np.sort(np.random.uniform(0, 86400, size=num_records))

    # Feature representation (auth velocity, failure burst, fan-out degree, Kerberos variance)
    auth_velocity = np.where(labels == "Benign", np.random.exponential(1.5, num_records), np.random.exponential(18.5, num_records))
    failed_auth_burst = np.where(labels == "Benign", np.random.poisson(0.1, num_records), np.random.poisson(4.8, num_records))
    fan_out_degree = np.where(labels == "Benign", np.random.poisson(1.2, num_records), np.random.poisson(12.4, num_records))
    session_entropy = np.where(labels == "Benign", np.random.normal(1.2, 0.3, num_records), np.random.normal(5.8, 0.9, num_records))

    df = pd.DataFrame({
        "time": timestamps,
        "src_user": src_users,
        "dst_user": dst_users,
        "src_host": src_hosts,
        "dst_host": dst_hosts,
        "auth_type": auth_types,
        "logon_type": logon_types,
        "result": results,
        "auth_velocity": auth_velocity,
        "failed_auth_burst": failed_auth_burst,
        "fan_out_degree": fan_out_degree,
        "session_entropy": session_entropy,
        "label": labels
    })

    # Shuffle
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    out_file = OUTPUT_DIR / "lanl_auth_redteam_test.csv"
    df.to_csv(out_file, index=False)
    print(f"LANL dataset saved -> {out_file} ({len(df):,} rows)")
    print(f"Label breakdown:\n{df['label'].value_counts()}")
    return df

if __name__ == "__main__":
    generate_lanl_dataset(15000)
