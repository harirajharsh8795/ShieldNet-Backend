"""
Two Final Checks Script:
1. Custom upload with genuinely modified rows (proving trajectory is distinct from all presets).
2. Deep investigation of CII-SCADA trajectory saturation vs K-step dynamic rollout.
"""

import sys
from pathlib import Path
import json
import io
import numpy as np
import pandas as pd
import torch
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.api.server import app, load_system_assets, world_model, secondary_model, schema_adapter, scaler_guard, classes_list, DEVICE

load_system_assets()
client = TestClient(app)

print("=" * 85, flush=True)
print("CHECK 1: GENUINELY MODIFIED CUSTOM UPLOAD TEST", flush=True)
print("=" * 85, flush=True)

# Load BENIGN CSV
benign_csv_path = PROJECT_ROOT / "demo_test_csvs" / "1_BENIGN_Normal_Enterprise_Traffic.csv"
df_benign = pd.read_csv(benign_csv_path)

# Preset Benign inference
res_benign_preset = client.post("/api/predict-sequence", json={
    "filename": "1_BENIGN_Normal_Enterprise_Traffic.csv",
    "scenario_id": "sess_benign_normal",
    "k_steps": 4
})
traj_benign = res_benign_preset.json()["threat_trajectory"]
print(f"Original BENIGN Preset Trajectory (10 steps):", flush=True)
print(f"  {traj_benign}", flush=True)
print(f"  Final Threat Score: {res_benign_preset.json()['threat_probability']}", flush=True)

# Create genuinely modified dataframe: alter rows 2, 4, 6, 8, 9 with distinct perturbations
df_custom = df_benign.copy()
# Inject high SYN / PSH bursts and abnormal TTL / Window sizes into rows 3 to 8
df_custom.loc[2:6, "SYN Flag Count"] = 14.5
df_custom.loc[2:6, "Flow Duration"] = 8.2
df_custom.loc[3:7, "tcp_window_max"] = -4.5
df_custom.loc[4:8, "Packet Length Mean"] = 12.8
df_custom.loc[5:9, "retransmission_count"] = 9.0

custom_csv_text = df_custom.to_csv(index=False)

res_custom = client.post("/api/predict-sequence", json={
    "raw_csv_text": custom_csv_text,
    "filename": "genuinely_modified_user_traffic.csv",
    "k_steps": 4
})
assert res_custom.status_code == 200
data_custom = res_custom.json()
traj_custom = data_custom["threat_trajectory"]

print(f"\nGenuinely Modified Custom Upload Trajectory (10 steps):", flush=True)
print(f"  {traj_custom}", flush=True)
print(f"  Final Threat Score: {data_custom['threat_probability']}", flush=True)
print(f"  Predicted Class:    {data_custom['predicted_class']}", flush=True)
print(f"  Projected K-Steps:  {data_custom['projected_k_steps']}", flush=True)

# Preset SSH and SCADA trajectories for comparison
res_ssh = client.post("/api/predict-sequence", json={"filename": "3_SSH_FTP_Patator_BruteForce.csv", "k_steps": 4}).json()
res_scada = client.post("/api/predict-sequence", json={"filename": "5_CII_SCADA_Infiltration_Attack.csv", "k_steps": 4}).json()

traj_ssh = res_ssh["threat_trajectory"]
traj_scada = res_scada["threat_trajectory"]

print(f"\nComparing Trajectories:")
print(f"  Custom vs Benign diff: {np.max(np.abs(np.array(traj_custom) - np.array(traj_benign))):.4f}")
print(f"  Custom vs SSH diff:    {np.max(np.abs(np.array(traj_custom) - np.array(traj_ssh))):.4f}")
print(f"  Custom vs SCADA diff:  {np.max(np.abs(np.array(traj_custom) - np.array(traj_scada))):.4f}")

assert traj_custom != traj_benign, "ERROR: Custom trajectory equals Benign!"
assert traj_custom != traj_ssh, "ERROR: Custom trajectory equals SSH!"
assert traj_custom != traj_scada, "ERROR: Custom trajectory equals SCADA!"
print(">>> CHECK 1 PASSED: Custom upload trajectory is GENUINELY DIFFERENT from all presets! <<<\n", flush=True)


print("=" * 85, flush=True)
print("CHECK 2: INVESTIGATION OF CII-SCADA TRAJECTORY & SATURATION DYNAMICS", flush=True)
print("=" * 85, flush=True)

scada_csv_path = PROJECT_ROOT / "demo_test_csvs" / "5_CII_SCADA_Infiltration_Attack.csv"
df_scada = pd.read_csv(scada_csv_path)

print(f"SCADA Telemetry Dimensions: {df_scada.shape}", flush=True)
raw_scada_mat = schema_adapter.adapt_dataframe(df_scada)
guarded_scada = scaler_guard.guard_batch(raw_scada_mat)

print(f"Raw Matrix Extrema:  min = {raw_scada_mat.min():.2f}, max = {raw_scada_mat.max():.2f}, mean = {raw_scada_mat.mean():.2f}")
print(f"Guarded Matrix Extrema: min = {guarded_scada.min():.2f}, max = {guarded_scada.max():.2f}, mean = {guarded_scada.mean():.2f}")

# Step-by-step model inspection for SCADA
print("\nStep-by-Step Step Model Logits & Probabilities for SCADA:")
for t in range(1, len(guarded_scada) + 1):
    w = guarded_scada[max(0, t - 3):t]
    if len(w) < 3:
        pad = np.tile(w[0:1], (3 - len(w), 1))
        w = np.vstack([pad, w])
    import src.api.server as srv
    inp_t = torch.from_numpy(w).unsqueeze(0).float().to(srv.DEVICE)
    with torch.no_grad():
        out_t = srv.world_model(inp_t)
        wm_logits = out_t["class_logits"].squeeze(0).cpu().numpy()
        wm_probs = torch.softmax(out_t["class_logits"], dim=-1).squeeze(0).cpu().numpy()
    sec_raw = srv.secondary_model.predict_proba(w[-1:])[0]
    sec_p = np.zeros(len(srv.classes_list), dtype=np.float32)
    sec_p[getattr(srv.secondary_model, "classes_", range(len(sec_raw)))] = sec_raw
    blend = 0.6 * wm_probs + 0.4 * sec_p
    p_benign = float(blend[0])
    p_threat = float(1.0 - p_benign)
    
    pred_c_idx = int(np.argmax(wm_logits))
    pred_name = srv.classes_list[pred_c_idx] if pred_c_idx < len(srv.classes_list) else f"Class_{pred_c_idx}"
    print(f"  Step t={t:02d}: P(Benign)={p_benign:.6f} | P(Threat)={p_threat:.6f} | WM Benign Logit={wm_logits[0]:.2f}, Max Attack Logit={wm_logits[1:].max():.2f} ({pred_name})", flush=True)

# K-step rollout analysis
print(f"\nK-Step Forward Rollout for SCADA:")
for step_info in res_scada["k_step_rollout"]:
    print(f"  Rollout {step_info['step_label']}: Threat Prob = {step_info['threat_probability']:.4f}, Confidence = {step_info['confidence']:.2f}, MITRE Stage = {step_info['predicted_stage_name']}", flush=True)
    if step_info["threat_probability"] >= 0.50:
        assert step_info["predicted_stage_name"] != "Benign", f"Inconsistency: High threat {step_info['threat_probability']} mapped to Benign!"

print(">>> MITRE STAGE CONSISTENCY CHECK PASSED: High threat rollout steps strictly map to attack stages! <<<", flush=True)
print("=" * 85, flush=True)
