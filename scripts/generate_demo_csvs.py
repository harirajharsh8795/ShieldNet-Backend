"""
Generate Ready-to-Test CSV Files with 84 Telemetry Feature Columns from sequences_test.parquet.
"""

import json
from pathlib import Path
import numpy as np
import pandas as pd

df = pd.read_parquet("data/processed/sequences_test.parquet")
with open("models/checkpoints/feature_columns.json") as f:
    manifest = json.load(f)
features = manifest["numeric_features"]

output_dir = Path("demo_test_csvs")
output_dir.mkdir(exist_ok=True)

# Unpack state_vectors into 84-column DataFrame
state_vectors = np.stack(df["state_vector"].values)
df_features = pd.DataFrame(state_vectors, columns=features)
df_features["label"] = df["label"].values

print(f"Unpacked {len(df_features)} rows with {len(features)} numeric feature columns.")

# Generate sample CSVs for testing
# 1. Benign
benign_sample = df_features[df_features["label"] == "BENIGN"].head(10)[features]
benign_sample.to_csv(output_dir / "1_BENIGN_Normal_Enterprise_Traffic.csv", index=False)

# 2. Botnet
bot_sample = df_features[df_features["label"] == "Bot"].head(10)[features]
bot_sample.to_csv(output_dir / "2_Botnet_Ares_C2_Periodic_Beacon.csv", index=False)

# 3. SSH / FTP Patator
patator_mask = df_features["label"].str.contains("Patator", na=False)
patator_sample = df_features[patator_mask].head(10)[features]
patator_sample.to_csv(output_dir / "3_SSH_FTP_Patator_BruteForce.csv", index=False)

# 4. Volumetric DoS / DDoS
dos_mask = df_features["label"].isin(["DoS Hulk", "DDoS", "DoS GoldenEye"])
dos_sample = df_features[dos_mask].head(10)[features]
dos_sample.to_csv(output_dir / "4_Volumetric_DDoS_Hulk_Flood.csv", index=False)

# 5. Critical Information Infrastructure (CII) / SCADA Modbus Intrusion
scada_mask = df_features["label"].isin(["Rare-Attack", "Web Attack - Brute Force", "Web Attack - XSS", "Infiltration"])
scada_sample = df_features[scada_mask].head(10)[features]
scada_sample.to_csv(output_dir / "5_CII_SCADA_Infiltration_Attack.csv", index=False)

print("\nSuccessfully created 5 demo test CSV files in 'demo_test_csvs/':")
for f in sorted(output_dir.glob("*.csv")):
    d = pd.read_csv(f)
    print(f"  * {f.name} ({len(d)} rows, {d.shape[1]} features)")
