"""
Test Tau-Normalization on WorldModel weights.
Kang et al., ICLR 2020: Tau-normalization scales classifier weights:
W_norm = W / (norm(W)^tau) to mitigate majority class weight norm dominance.
"""

import sys
from pathlib import Path
import json
import numpy as np
import torch
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, f1_score

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from src.world_model.model import WorldModel
from src.world_model.dataset import extract_temporal_sequences_from_parquet

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

DEVICE = torch.device("cpu")
wm = WorldModel(input_size=84, hidden_size=128, num_layers=2, num_classes=num_classes, num_mitre_stages=6, use_attention=True)
ckpt = torch.load(CKPT_DIR / "world_model_v1.pt", map_location=DEVICE, weights_only=False)
wm.load_state_dict(ckpt["model_state_dict"])
wm.eval()

# Check classifier weight norms:
W = wm.class_head[4].weight.data.clone()  # [13, 128]
b = wm.class_head[4].bias.data.clone()
norms = torch.norm(W, dim=1)
print("[Classifier Weight Norms per Class]:", flush=True)
for c, n in zip(classes, norms):
    print(f"  {c:<26}: norm = {n.item():.4f}", flush=True)

# Forward pass to get features before final projection
with torch.no_grad():
    X_tensor = torch.from_numpy(X_test).float()
    feat, _ = wm.rnn(X_tensor)
    if wm.use_attention:
        pooled, _ = wm.attn_pool(feat)
    else:
        pooled = feat[:, -1, :]

    # Pass through first MLP layers of class_head
    h = wm.class_head[0](pooled)
    h = wm.class_head[1](h)
    h = wm.class_head[2](h)
    h = wm.class_head[3](h)

    print("\n[Tau-Normalization Results]:", flush=True)
    for tau in [0.0, 0.2, 0.4, 0.6, 0.8, 1.0, 1.2]:
        W_tau = W / (norms.unsqueeze(1) ** tau)
        logits_tau = torch.matmul(h, W_tau.t()) + b
        preds_tau = torch.argmax(logits_tau, dim=1).numpy()
        macro_f1 = f1_score(y_test, preds_tau, average="macro", zero_division=0)
        acc = np.mean(preds_tau == y_test)
        print(f"  Tau = {tau:.1f} | Overall Acc: {acc*100:.2f}% | Macro-F1: {macro_f1:.4f}", flush=True)
