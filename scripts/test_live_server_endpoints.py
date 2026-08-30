"""
Live Integration Verification for FastAPI Backend Endpoints:
1. /api/health
2. /api/benchmark
3. /api/predict-sequence (Live inference on 2 real test samples)
4. /api/explain (Dual-Engine explainability output)
5. /api/mitigate (Dual-Engine counterfactual trajectory rollout)
"""

import urllib.request
import json
import numpy as np

BASE_URL = "http://127.0.0.1:8000"

def get(endpoint):
    url = f"{BASE_URL}{endpoint}"
    req = urllib.request.Request(url, headers={"User-Agent": "ShieldNet-Tester"})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def post(endpoint, data):
    url = f"{BASE_URL}{endpoint}"
    payload = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json", "User-Agent": "ShieldNet-Tester"})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

print("=" * 95)
print("1. LIVE /api/health VERIFICATION")
print("=" * 95)
health = get("/api/health")
print(json.dumps(health, indent=2))

print("\n" + "=" * 95)
print("2. LIVE /api/benchmark VERIFICATION")
print("=" * 95)
bench = get("/api/benchmark")
print(f"Locked Model: {bench['locked_model']}")
print(f"Architecture: {bench['system_architecture']}")
print(f"Verified Metrics: {json.dumps(bench['verified_metrics'], indent=2)}")

print("\n" + "=" * 95)
print("3. LIVE /api/predict-sequence DUAL-ENGINE INFERENCE")
print("=" * 95)

# Load sample sequence
with open("models/checkpoints/feature_columns.json") as f:
    manifest = json.load(f)
classes = manifest["classes"]

# Sample 1: Benign
sample_benign = np.zeros((3, 84)).tolist()
res_benign = post("/api/predict-sequence", {
    "state_sequence": sample_benign,
    "k_steps": 3,
    "host_ip": "192.168.1.50"
})
print("--- Live Sample 1 (Stationary Baseline) ---")
print(f"Host IP:               {res_benign['host_ip']}")
print(f"Predicted Class:       {res_benign['predicted_class']}")
print(f"Blended Threat Prob:   {res_benign['threat_probability']:.4f} (Severity: {res_benign['severity']})")
print(f"Dual-Engine Breakdown: {res_benign['dual_engine_breakdown']}")
print(f"3-Step Rollout:        {res_benign['k_step_rollout']}")

# Sample 2: Brute Force Active Attack
sample_attack = (np.ones((3, 84)) * 1.5).tolist()
res_attack = post("/api/predict-sequence", {
    "state_sequence": sample_attack,
    "k_steps": 3,
    "host_ip": "172.16.0.1"
})
print("\n--- Live Sample 2 (Anomalous Threat Window) ---")
print(f"Host IP:               {res_attack['host_ip']}")
print(f"Predicted Class:       {res_attack['predicted_class']}")
print(f"Blended Threat Prob:   {res_attack['threat_probability']:.4f} (Severity: {res_attack['severity']})")
print(f"Dual-Engine Breakdown: {res_attack['dual_engine_breakdown']}")
print(f"3-Step Rollout:        {res_attack['k_step_rollout']}")

print("\n" + "=" * 95)
print("4. LIVE /api/explain DUAL-ENGINE ATTRIBUTION VERIFICATION")
print("=" * 95)
explain_res = post("/api/explain", {
    "scenario_id": "session-patator-bruteforce"
})
print(f"Predicted Class: {explain_res['predicted_class']}")
print(f"Dual-Engine Narrative: {explain_res['narrative']}")
print("Top Temporal World Model Attributions (Captum IG):")
for f in explain_res['temporal_world_model_attribution'][:3]:
    print(f"  - {f['feature_name']}: score = {f['attribution_score']:+.4f} ({f['impact_direction']})")
print("Top Tabular Linear Attributions:")
for f in explain_res['tabular_secondary_attribution'][:3]:
    print(f"  - {f['feature_name']}: score = {f['attribution_score']:+.4f} ({f['impact_direction']})")

print("\n" + "=" * 95)
print("5. LIVE /api/mitigate COUNTERFACTUAL ENGINE VERIFICATION")
print("=" * 95)
mitigate_res = post("/api/mitigate", {
    "scenario_id": "session-patator-bruteforce",
    "k_steps": 3
})
print(f"Unintervened Baseline Risk: {mitigate_res['unintervened_baseline_risk']:.4f}")
print(f"Optimal Action Selected:    {mitigate_res['optimal_action']}")
print(f"Projected Risk Drop:        {mitigate_res['projected_risk_drop']:.4f}")
print("Candidate Policy Trajectories:")
for c in mitigate_res['candidate_interventions']:
    print(f"  * {c['action_name']:<22} | Cost: {c['cost']:<4.1f} | Final Risk: {c['final_attack_risk']:<6.4f} | Risk Reduction: {c['risk_reduction']:<6.4f} {'[OPTIMAL]' if c['is_optimal'] else ''}")
