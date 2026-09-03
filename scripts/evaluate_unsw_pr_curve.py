import sys
from pathlib import Path
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import precision_recall_curve, roc_auc_score, balanced_accuracy_score, f1_score, accuracy_score

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.world_model.model import WorldModel
from scripts.resolve_section_1_master import DomainFeatureReconstructor, UNSW_MAP

DEVICE = torch.device("cpu")
CKPT_DIR = PROJECT_ROOT / "models" / "checkpoints"

ckpt = torch.load(CKPT_DIR / "world_model_section1_resolved.pt", map_location=DEVICE, weights_only=False)
model = WorldModel(input_size=84, hidden_size=128, num_layers=2, num_classes=13, num_mitre_stages=6, use_attention=True).to(DEVICE)
model.load_state_dict(ckpt["model_state_dict"])
model.eval()

reconstructor = DomainFeatureReconstructor().to(DEVICE)
reconstructor.load_state_dict(ckpt["reconstructor_state_dict"])
reconstructor.eval()

scaler = ckpt["scaler"]

f_unsw = PROJECT_ROOT / "dataset" / "UNSW" / "UNSW_NB15_testing-set.csv"
df_unsw = pd.read_csv(f_unsw, nrows=20000)

y_unsw_true = df_unsw["label"].values[2:]
mat_unsw_15 = np.zeros((len(df_unsw), 15), dtype=np.float32)
for idx, (target_pos, col_name) in enumerate(UNSW_MAP.items()):
    if col_name in df_unsw.columns:
        v = pd.to_numeric(df_unsw[col_name], errors='coerce').fillna(0.0).values
        if col_name == "dur":
            v = v * 1e6
        h_mean = scaler.mean_[target_pos]
        h_std = scaler.scale_[target_pos] + 1e-6
        norm_v = (v - h_mean) / h_std
        mat_unsw_15[:, idx] = np.clip(np.nan_to_num(norm_v, nan=0.0), -5.0, 5.0)

with torch.no_grad():
    mat_unsw_84 = reconstructor(torch.from_numpy(mat_unsw_15).float().to(DEVICE)).cpu().numpy()

X_unsw_seq = np.array([mat_unsw_84[i:i+3] for i in range(len(mat_unsw_84) - 2)], dtype=np.float32)

with torch.no_grad():
    out_u = model(torch.from_numpy(X_unsw_seq).float().to(DEVICE))
    p_u = torch.softmax(out_u["class_logits"], dim=-1).cpu().numpy()
    threat_p_u = 1.0 - p_u[:, 0]  # 0 is BENIGN

roc_auc = roc_auc_score(y_unsw_true, threat_p_u)
print(f"ROC-AUC on UNSW-NB15: {roc_auc*100:.2f}%")
print(f"Threat Probability Stats: Min={np.min(threat_p_u):.4f}, Mean={np.mean(threat_p_u):.4f}, Median={np.median(threat_p_u):.4f}, Max={np.max(threat_p_u):.4f}")

# Threshold Sweep
print("\nThreshold Sweep on UNSW-NB15:")
print(f"{'Threshold':<10} | {'Recall':<10} | {'Precision':<10} | {'Balanced Acc':<14} | {'F1-Score':<10} | {'Accuracy':<10}")
print("-" * 75)
for tau in [0.01, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30]:
    p_bin = (threat_p_u >= tau).astype(int)
    rec = np.sum((p_bin == 1) & (y_unsw_true == 1)) / np.sum(y_unsw_true == 1)
    prec = np.sum((p_bin == 1) & (y_unsw_true == 1)) / max(1, np.sum(p_bin == 1))
    ba = balanced_accuracy_score(y_unsw_true, p_bin)
    f1 = f1_score(y_unsw_true, p_bin, zero_division=0)
    acc = accuracy_score(y_unsw_true, p_bin)
    print(f"{tau:<10.2f} | {rec*100:<9.2f}% | {prec*100:<9.2f}% | {ba*100:<13.2f}% | {f1*100:<9.2f}% | {acc*100:<9.2f}%")
