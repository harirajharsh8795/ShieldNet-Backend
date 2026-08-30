"""
ShieldNet Phase 4: Concrete Counterfactual Scenarios & Safety Shield Demonstration.

Uses genuine empirical test sequences for:
1. SSH-Patator (Brute Force)
2. Web Attack - Brute Force (Web Exploitation)
3. Bot (Botnet C2)
4. BENIGN (Mission-Critical Legitimate Server)
"""

import sys
from pathlib import Path
import numpy as np
import pandas as pd
import torch
import json

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.world_model.model import WorldModel
from src.mitigation.actions import MitigationAction
from src.mitigation.counterfactual_engine import CounterfactualTrajectoryEngine
from src.mitigation.safety_shield import SafetyShieldPolicy

def get_real_host_sequence(df: pd.DataFrame, label: str, min_len: int = 3) -> tuple:
    """Extract genuine sequence for a specific label from parquet."""
    df_match = df[df["label"] == label]
    if df_match.empty:
        raise ValueError(f"No samples for {label}")
    
    # Find host key
    df["_host_key"] = df["session_group"].astype(str) + "___" + df["source_ip"].astype(str)
    host_keys = df[df["label"] == label]["_host_key"].unique()
    
    for hk in host_keys:
        hdf = df[df["_host_key"] == hk].sort_values("window_idx").reset_index(drop=True)
        if len(hdf) >= 2:
            states = np.array(hdf["state_vector"].tolist(), dtype=np.float32)
            # Take up to 3 timesteps
            if len(states) < 3:
                pad = np.tile(states[0:1], (3 - len(states), 1))
                states = np.vstack([pad, states])
            else:
                states = states[:3]
            src_ip = hdf["source_ip"].iloc[0]
            return states, src_ip
            
    # Fallback to single padded
    first_state = np.array(df_match["state_vector"].iloc[0], dtype=np.float32)
    return np.tile(first_state[np.newaxis, :], (3, 1)), df_match["source_ip"].iloc[0]


def main():
    print("=" * 80)
    print("SHIELDNET PHASE 4: EMPIRICAL COUNTERFACTUAL SCENARIOS & SAFETY SHIELD")
    print("=" * 80)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    checkpoint_dir = Path("models/checkpoints")
    
    with open(checkpoint_dir / "feature_columns.json", "r") as f:
        manifest = json.load(f)
    classes = manifest["classes"]
    
    model = WorldModel(
        input_size=84,
        hidden_size=128,
        num_layers=2,
        dropout=0.2,
        num_classes=len(classes),
        num_mitre_stages=6,
    ).to(device)
    
    model_path = checkpoint_dir / "world_model_v1.pt"
    checkpoint = torch.load(model_path, map_location=device)
    state_dict = checkpoint["model_state_dict"] if isinstance(checkpoint, dict) and "model_state_dict" in checkpoint else checkpoint
    model.load_state_dict(state_dict)
    model.eval()
    print(f"Loaded World Model from: {model_path}")
    
    engine = CounterfactualTrajectoryEngine(model, classes, device=str(device))
    shield = SafetyShieldPolicy(engine, critical_attack_threshold=0.90, active_intervention_threshold=0.35)
    
    test_df = pd.read_parquet("data/processed/sequences_test.parquet")
    print(f"Loaded test sequences: {len(test_df):,} windows across {test_df['source_ip'].nunique():,} hosts\n")
    
    scenarios = []
    
    # ─── SCENARIO 1: Web Attack - Brute Force Mitigation ──────────────────────
    print("=" * 75)
    print("SCENARIO 1: Web Attack - Brute Force -> Rate Limiting / Session Reset")
    print("=" * 75)
    seq1, ip1 = get_real_host_sequence(test_df, "Web Attack - Brute Force")
    res1 = shield.evaluate_and_recommend(
        context_sequence=seq1,
        historic_benign_ratio=0.20,  # External attacker IP
        is_critical_asset=False,
        host_identifier=f"{ip1} (External Ingress)",
        k_steps=3
    )
    print(f"  Host:                 {res1['host_identifier']}")
    print(f"  Baseline Attack Risk: {res1['baseline_attack_risk']:.1%}")
    print(f"  Recommended Action:   {res1['recommended_action']}")
    print(f"  Mitigated Risk:       {res1['mitigated_attack_risk']:.1%}")
    print(f"  Risk Reduction:       {res1['risk_reduction']:.1%}")
    print(f"  Rationale:            {res1['decision_rationale']}")
    scenarios.append({"scenario_id": "SCENARIO_1_WEB_ATTACK_MITIGATION", **res1})
    
    # ─── SCENARIO 2: SSH-Patator Credential Brute-Force ───────────────────────
    print("\n" + "=" * 75)
    print("SCENARIO 2: SSH-Patator Brute Force -> Edge IP Drop / Connection Reset")
    print("=" * 75)
    seq2, ip2 = get_real_host_sequence(test_df, "SSH-Patator")
    res2 = shield.evaluate_and_recommend(
        context_sequence=seq2,
        historic_benign_ratio=0.15,
        is_critical_asset=False,
        host_identifier=f"{ip2} (SSH Attacker)",
        k_steps=3
    )
    print(f"  Host:                 {res2['host_identifier']}")
    print(f"  Baseline Attack Risk: {res2['baseline_attack_risk']:.1%}")
    print(f"  Recommended Action:   {res2['recommended_action']}")
    print(f"  Mitigated Risk:       {res2['mitigated_attack_risk']:.1%}")
    print(f"  Risk Reduction:       {res2['risk_reduction']:.1%}")
    print(f"  Rationale:            {res2['decision_rationale']}")
    scenarios.append({"scenario_id": "SCENARIO_2_SSH_PATATOR_BLOCK", **res2})
    
    # ─── SCENARIO 3: Botnet C2 Persistent Activity ────────────────────────────
    print("\n" + "=" * 75)
    print("SCENARIO 3: Botnet C2 Exfiltration -> Zero-Trust Quarantine")
    print("=" * 75)
    seq3, ip3 = get_real_host_sequence(test_df, "Bot")
    res3 = shield.evaluate_and_recommend(
        context_sequence=seq3,
        historic_benign_ratio=0.10,
        is_critical_asset=False,
        host_identifier=f"{ip3} (Compromised Endpoint)",
        k_steps=3
    )
    print(f"  Host:                 {res3['host_identifier']}")
    print(f"  Baseline Attack Risk: {res3['baseline_attack_risk']:.1%}")
    print(f"  Recommended Action:   {res3['recommended_action']}")
    print(f"  Mitigated Risk:       {res3['mitigated_attack_risk']:.1%}")
    print(f"  Risk Reduction:       {res3['risk_reduction']:.1%}")
    print(f"  Rationale:            {res3['decision_rationale']}")
    scenarios.append({"scenario_id": "SCENARIO_3_BOTNET_QUARANTINE", **res3})
    
    # ─── SCENARIO 4: Mission-Critical Production Server (Safety Shield Test) ──
    print("\n" + "=" * 75)
    print("SCENARIO 4: Critical Production Server -> Safety Shield Protection")
    print("=" * 75)
    seq4, ip4 = get_real_host_sequence(test_df, "BENIGN")
    res4 = shield.evaluate_and_recommend(
        context_sequence=seq4,
        historic_benign_ratio=0.999,  # Legitimate internal server
        is_critical_asset=True,        # Mission critical database
        host_identifier=f"{ip4} (Core Production DB)",
        k_steps=3
    )
    print(f"  Host:                 {res4['host_identifier']}")
    print(f"  Baseline Attack Risk: {res4['baseline_attack_risk']:.1%}")
    print(f"  Recommended Action:   {res4['recommended_action']}")
    print(f"  Mitigated Risk:       {res4['mitigated_attack_risk']:.1%}")
    print(f"  Guardrail Actions:    {[g['action'] for g in res4['guardrail_enforcements']]}")
    print(f"  Rationale:            {res4['decision_rationale']}")
    scenarios.append({"scenario_id": "SCENARIO_4_SAFETY_GUARDRAIL_PROTECTION", **res4})
    
    # Save scenarios json
    def convert_numpy(obj):
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, (np.float32, np.float64)):
            return float(obj)
        elif isinstance(obj, (np.int32, np.int64)):
            return int(obj)
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
        
    out_file = checkpoint_dir / "counterfactual_scenarios.json"
    with open(out_file, "w") as f:
        json.dump(scenarios, f, indent=2, default=convert_numpy)
    print(f"\nSaved all 4 counterfactual scenarios to: {out_file}")

if __name__ == "__main__":
    main()
