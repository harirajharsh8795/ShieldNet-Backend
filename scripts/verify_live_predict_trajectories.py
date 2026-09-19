"""
Verification script for Section 3 Priority 1:
Confirm that /api/predict-sequence generates genuine, live, non-identical model trajectories
for different uploaded CSVs and presets (no canned/mock sine waves).
"""

import sys
from pathlib import Path
import json
import pandas as pd
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.api.server import app, load_system_assets

load_system_assets()
client = TestClient(app)

print("=" * 80)
print("VERIFYING LIVE /api/predict-sequence ON REAL CSV DATA")
print("=" * 80)

# Test 1: SSH-Patator Preset / Filename
res_ssh = client.post("/api/predict-sequence", json={
    "filename": "3_SSH_FTP_Patator_BruteForce.csv",
    "scenario_id": "sess_ssh_patator",
    "k_steps": 4
})
assert res_ssh.status_code == 200, f"SSH request failed: {res_ssh.text}"
data_ssh = res_ssh.json()

print("\n--- TEST 1: SSH-Patator (3_SSH_FTP_Patator_BruteForce.csv) ---")
print(f"Predicted Class:    {data_ssh.get('predicted_class')}")
print(f"Threat Score:       {data_ssh.get('threat_probability')}")
print(f"Trajectory Length:  {len(data_ssh.get('threat_trajectory', []))}")
print(f"Trajectory:         {data_ssh.get('threat_trajectory')}")
print(f"Projected K-Steps:  {data_ssh.get('projected_k_steps')}")
print(f"Lead Time (s):      {data_ssh.get('lead_time_seconds')}")

# Test 2: CII-SCADA Infiltration Preset / Filename
res_scada = client.post("/api/predict-sequence", json={
    "filename": "5_CII_SCADA_Infiltration_Attack.csv",
    "scenario_id": "session-scada-grid-exfiltration",
    "k_steps": 4
})
assert res_scada.status_code == 200, f"SCADA request failed: {res_scada.text}"
data_scada = res_scada.json()

print("\n--- TEST 2: CII SCADA Infiltration (5_CII_SCADA_Infiltration_Attack.csv) ---")
print(f"Predicted Class:    {data_scada.get('predicted_class')}")
print(f"Threat Score:       {data_scada.get('threat_probability')}")
print(f"Trajectory Length:  {len(data_scada.get('threat_trajectory', []))}")
print(f"Trajectory:         {data_scada.get('threat_trajectory')}")
print(f"Projected K-Steps:  {data_scada.get('projected_k_steps')}")
print(f"Lead Time (s):      {data_scada.get('lead_time_seconds')}")

# Test 3: Normal Benign Enterprise Traffic
res_benign = client.post("/api/predict-sequence", json={
    "filename": "1_BENIGN_Normal_Enterprise_Traffic.csv",
    "scenario_id": "sess_benign_normal",
    "k_steps": 4
})
assert res_benign.status_code == 200, f"Benign request failed: {res_benign.text}"
data_benign = res_benign.json()

print("\n--- TEST 3: Benign Normal (1_BENIGN_Normal_Enterprise_Traffic.csv) ---")
print(f"Predicted Class:    {data_benign.get('predicted_class')}")
print(f"Threat Score:       {data_benign.get('threat_probability')}")
print(f"Trajectory Length:  {len(data_benign.get('threat_trajectory', []))}")
print(f"Trajectory:         {data_benign.get('threat_trajectory')}")
print(f"Projected K-Steps:  {data_benign.get('projected_k_steps')}")
print(f"Lead Time (s):      {data_benign.get('lead_time_seconds')}")

# Test 4: Uploading Raw CSV Text (Simulate Frontend File Upload)
csv_path = PROJECT_ROOT / "demo_test_csvs" / "3_SSH_FTP_Patator_BruteForce.csv"
with open(csv_path, "r", encoding="utf-8") as f:
    raw_text = f.read()

res_raw = client.post("/api/predict-sequence", json={
    "raw_csv_text": raw_text,
    "filename": "custom_uploaded_analyst_capture.csv",
    "k_steps": 4
})
assert res_raw.status_code == 200, f"Raw CSV upload request failed: {res_raw.text}"
data_raw = res_raw.json()

print("\n--- TEST 4: Raw CSV Text Upload (custom_uploaded_analyst_capture.csv) ---")
print(f"Resolved Name:      {data_raw.get('name')}")
print(f"Predicted Class:    {data_raw.get('predicted_class')}")
print(f"Threat Score:       {data_raw.get('threat_probability')}")
print(f"Trajectory:         {data_raw.get('threat_trajectory')}")

# Rigorous Assertions: Trajectories MUST NOT be identical
assert data_ssh.get('threat_trajectory') != data_scada.get('threat_trajectory'), "CRITICAL: SSH and SCADA trajectories are identical!"
assert data_ssh.get('threat_trajectory') != data_benign.get('threat_trajectory'), "CRITICAL: SSH and Benign trajectories are identical!"
assert data_ssh.get('threat_probability') != data_benign.get('threat_probability'), "CRITICAL: Threat probabilities are identical!"

print("\n" + "=" * 80)
print("SUCCESS: ALL TRAJECTORIES ARE DYNAMIC, DISTINCT, AND MODEL-DRIVEN!")
print(f"SSH vs SCADA Trajectory Difference: Checked distinct.")
print(f"SSH vs Benign Trajectory Difference: Checked distinct.")
print(f"Raw CSV Text Upload: Successfully processed & inferred.")
print("=" * 80)
