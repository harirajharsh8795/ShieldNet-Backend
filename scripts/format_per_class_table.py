import json
import pandas as pd

with open("models/checkpoints/canonical_context_length_sweep_master.json") as f:
    sweep = json.load(f)
with open("models/checkpoints/metrics_L3_v2.json") as f:
    l3_v2 = json.load(f)
with open("models/checkpoints/DEFINITIVE_BASELINE.json") as f:
    base = json.load(f)

classes = list(base["metrics"]["per_class"].keys())

print("=== PER-CLASS F1-SCORE COMPARISON TABLE ===")
per_class_data = {}
for c in classes:
    support = base["metrics"]["per_class"][c]["support"]
    base_f1 = base["metrics"]["per_class"][c]["f1"]
    wm1_f1 = sweep["world_model_v1_locked"]["per_class"][c]["f1"]
    l3v2_f1 = l3_v2["per_class"][c]["f1"]
    cL3_f1 = sweep["canonical_L3"]["per_class"][c]["f1"]
    cL5_f1 = sweep["canonical_L5"]["per_class"][c]["f1"]
    cL7_f1 = sweep["canonical_L7"]["per_class"][c]["f1"]
    cL10_f1 = sweep["canonical_L10"]["per_class"][c]["f1"]
    
    per_class_data[c] = {
        "Support": support,
        "LogReg (L=1)": round(base_f1, 4),
        "world_model_v1 (L=3)": round(wm1_f1, 4),
        "world_model_L3_v2 (L=3)": round(l3v2_f1, 4),
        "Canonical L=3": round(cL3_f1, 4),
        "Canonical L=5": round(cL5_f1, 4),
        "Canonical L=7": round(cL7_f1, 4),
        "Canonical L=10": round(cL10_f1, 4),
    }

df = pd.DataFrame.from_dict(per_class_data, orient="index")
print(df.to_string())
