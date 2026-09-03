"""
Evaluate Phase 2 Model with Calibrated Decision Boundaries.
"""

import sys
from pathlib import Path
import json
import numpy as np
import torch
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    classification_report, balanced_accuracy_score, f1_score,
    accuracy_score, roc_auc_score
)
from scipy.optimize import minimize

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.world_model.model import WorldModel
from src.world_model.dataset import extract_temporal_sequences_from_parquet

DEVICE = torch.device("cpu")
CKPT_DIR = PROJECT_ROOT / "models" / "checkpoints"

with open(CKPT_DIR / "feature_columns.json") as f:
    manifest = json.load(f)
classes = manifest["classes"]
num_classes = len(classes)
benign_idx = classes.index("BENIGN")

le = LabelEncoder()
le.fit(classes)

test_parquet = str(PROJECT_ROOT / "data" / "processed" / "sequences_test.parquet")
X_test, y_st_test, y_test, y_mit_test = extract_temporal_sequences_from_parquet(test_parquet, le, context_length=3)

# Load Phase 2 Checkpoint
model = WorldModel(input_size=84, hidden_size=128, num_layers=2, num_classes=num_classes, num_mitre_stages=6, use_attention=True).to(DEVICE)
ckpt = torch.load(CKPT_DIR / "world_model_phase2_focal.pt", map_location=DEVICE, weights_only=False)
model.load_state_dict(ckpt["model_state_dict"])
model.eval()

with torch.no_grad():
    out = model(torch.from_numpy(X_test).float().to(DEVICE))
    probs = torch.softmax(out["class_logits"], dim=-1).cpu().numpy()

# 50% split calibration
np.random.seed(42)
indices = np.arange(len(y_test))
np.random.shuffle(indices)
split = len(indices) // 2
cal_idx = indices[:split]
eval_idx = indices[split:]

cal_probs = probs[cal_idx]
cal_y = y_test[cal_idx]
eval_probs = probs[eval_idx]
eval_y = y_test[eval_idx]

def loss_func(weights):
    w = np.clip(weights, 0.05, 5.0)
    adjusted_p = cal_probs * w
    preds = np.argmax(adjusted_p, axis=1)
    return -balanced_accuracy_score(cal_y, preds)

init_weights = np.ones(num_classes)
res = minimize(loss_func, init_weights, method="Nelder-Mead", options={"maxiter": 300, "disp": False})
opt_weights = np.clip(res.x, 0.05, 5.0)

eval_adjusted = eval_probs * opt_weights
eval_preds = np.argmax(eval_adjusted, axis=1)

cal_ba = balanced_accuracy_score(eval_y, eval_preds)
cal_f1 = f1_score(eval_y, eval_preds, average="macro", zero_division=0)
cal_wf1 = f1_score(eval_y, eval_preds, average="weighted", zero_division=0)
cal_acc = np.mean(eval_preds == eval_y)

print("=" * 80)
print("PHASE 2 MODEL + CALIBRATED THRESHOLDS EVALUATION")
print("=" * 80)
print(f"Held-Out Evaluation Split (N={len(eval_idx)}):")
print(f"  Balanced Accuracy: {cal_ba*100:.2f}%")
print(f"  Macro F1:          {cal_f1:.4f}")
print(f"  Weighted F1:       {cal_wf1:.4f}")
print(f"  Overall Accuracy:  {cal_acc*100:.2f}%")
print("=" * 80)
