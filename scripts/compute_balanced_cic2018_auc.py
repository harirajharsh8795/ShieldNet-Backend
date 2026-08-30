import json, os, sys
from pathlib import Path
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import roc_auc_score, precision_recall_curve, auc, balanced_accuracy_score, f1_score

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.world_model.model import WorldModel
from scripts.run_phase4_cross_dataset import FEATURE_MAP_2017_TO_2018

device = torch.device("cpu")
ckpt = torch.load("models/checkpoints/world_model_v1.pt", map_location=device, weights_only=False)
model = WorldModel(input_size=84, hidden_size=128, num_layers=2, num_classes=13, num_mitre_stages=6).to(device)
model.load_state_dict(ckpt["model_state_dict"])
model.eval()

with open("models/checkpoints/feature_columns.json") as f:
    manifest = json.load(f)
flow_cols = manifest["numeric_features"][:77]

# Load balanced slice from 02-14-2018.csv
df = pd.read_csv("dataset/data 1/02-14-2018.csv")
lbl_col = [c for c in df.columns if "label" in c.lower()][0]

df_benign = df[df[lbl_col].str.strip().str.lower() == "benign"].sample(n=10000, random_state=42)
df_attack = df[df[lbl_col].str.strip().str.lower() != "benign"].sample(n=10000, random_state=42)
df_balanced = pd.concat([df_benign, df_attack]).sample(frac=1.0, random_state=42).reset_index(drop=True)

print(f"Loaded Balanced 2018 Dataset: Total={len(df_balanced)} (Benign={len(df_benign)}, Attack={len(df_attack)})")

flow_mat = np.zeros((len(df_balanced), 77), dtype=np.float32)
for idx, f_name in enumerate(flow_cols):
    candidates = FEATURE_MAP_2017_TO_2018.get(f_name, [f_name])
    for c in candidates:
        if c in df_balanced.columns:
            vals = pd.to_numeric(df_balanced[c], errors="coerce").fillna(0.0).values
            flow_mat[:, idx] = np.nan_to_num(vals, nan=0.0, posinf=0.0, neginf=0.0)
            break

st_norm = (flow_mat - np.mean(flow_mat, axis=0)) / (np.std(flow_mat, axis=0) + 1e-6)
st_84 = np.zeros((len(df_balanced), 84), dtype=np.float32)
st_84[:, :77] = st_norm

X_seq = np.array([st_84[i:i+3] for i in range(len(st_84) - 2)], dtype=np.float32)
y_bin = (df_balanced[lbl_col].str.strip().str.lower() != "benign").astype(int).values[2:]

with torch.no_grad():
    probs = 1.0 - torch.softmax(model(torch.from_numpy(X_seq).to(device))["class_logits"], dim=-1)[:, 0].numpy()

roc = roc_auc_score(y_bin, probs)
p_curve, r_curve, _ = precision_recall_curve(y_bin, probs)
pr_auc = auc(r_curve, p_curve)
preds_50 = (probs >= 0.5).astype(int)
bal_50 = balanced_accuracy_score(y_bin, preds_50) * 100.0
f1_50 = f1_score(y_bin, preds_50, average="macro")

print("=" * 70)
print(f"CSE-CIC-IDS2018 BALANCED TEST RESULTS (N = {len(X_seq):,}):")
print(f"  Threat ROC-AUC:    {roc:.4f}")
print(f"  Threat PR-AUC:     {pr_auc:.4f}")
print(f"  Balanced Accuracy: {bal_50:.2f}%")
print(f"  Macro-F1:          {f1_50:.4f}")
print("=" * 70)
