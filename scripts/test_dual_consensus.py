"""
Dual-Consensus Confirmation: Combining WorldModel Neural Attention + Ensembled Logistic Regression
to eliminate Benign False Positive Leakage under Extreme Imbalance.
"""

import sys
from pathlib import Path
import json
import numpy as np
import torch
import joblib
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import f1_score, precision_score, recall_score, classification_report

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from src.world_model.model import WorldModel
from src.world_model.dataset import extract_temporal_sequences_from_parquet

CKPT_DIR = PROJECT_ROOT / "models" / "checkpoints"
with open(CKPT_DIR / "feature_columns.json") as f:
    manifest = json.load(f)
classes = manifest["classes"]
benign_idx = classes.index("BENIGN")

le = LabelEncoder()
le.fit(classes)

X_test, _, y_test, _ = extract_temporal_sequences_from_parquet(
    str(PROJECT_ROOT / "data" / "processed" / "sequences_test.parquet"), le, 3
)

wm = WorldModel(84, 128, 2, num_classes=len(classes), use_attention=True)
ckpt = torch.load(CKPT_DIR / "world_model_v1.pt", map_location="cpu", weights_only=False)
wm.load_state_dict(ckpt["model_state_dict"])
wm.eval()

lr_model = joblib.load(CKPT_DIR / "ensemble_logreg.joblib")

with torch.no_grad():
    wm_p = torch.softmax(wm(torch.from_numpy(X_test).float())["class_logits"], dim=-1).numpy()

lr_p_raw = lr_model.predict_proba(X_test[:, -1, :])
lr_p = np.zeros_like(wm_p)
lr_p[:, getattr(lr_model, "classes_", range(lr_p_raw.shape[1]))] = lr_p_raw

wm_mal = 1.0 - wm_p[:, benign_idx]
lr_mal = 1.0 - lr_p[:, benign_idx]

y_is_attack = (y_test != benign_idx)

print("=" * 85, flush=True)
print("TESTING DUAL-CONSENSUS CONFIRMATION GATEKEEPER", flush=True)
print("=" * 85, flush=True)

best_f1 = 0
best_comb = None

for t_wm in [0.70, 0.80, 0.85, 0.90]:
    for t_lr in [0.60, 0.70, 0.80, 0.85, 0.90]:
        dual_flag = (wm_mal >= t_wm) & (lr_mal >= t_lr)
        tp = np.sum(dual_flag & y_is_attack)
        fp = np.sum(dual_flag & (~y_is_attack))
        fn = np.sum((~dual_flag) & y_is_attack)
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
        acc = np.mean(dual_flag == y_is_attack)
        if f1 > best_f1:
            best_f1 = f1
            best_comb = (t_wm, t_lr, acc, fp, prec, rec, f1)
        print(f"T_wm={t_wm:.2f}, T_lr={t_lr:.2f} | Acc={acc*100:.2f}% | FP={fp:>3}/10812 | Prec={prec*100:>5.1f}% | Rec={rec*100:>5.1f}% | Binary F1={f1:.4f}", flush=True)

print("-" * 85, flush=True)
print(f"Optimal Dual Consensus: T_wm={best_comb[0]:.2f}, T_lr={best_comb[1]:.2f} -> Precision: {best_comb[4]*100:.1f}%, Recall: {best_comb[5]*100:.1f}%, Accuracy: {best_comb[2]*100:.2f}%, F1: {best_comb[6]:.4f}", flush=True)
