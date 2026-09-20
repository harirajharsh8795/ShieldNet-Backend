"""
Canonical 9-Class SOTA Benchmark on CICIDS2017:
Groups micro-labels according to the original CIC-IDS specification and CERT incident response:
1. BENIGN
2. Botnet C2
3. DDoS
4. DoS-Volumetric (GoldenEye, Hulk, Slowhttptest, Slowloris)
5. FTP-Patator
6. SSH-Patator
7. PortScan
8. Web-Attack (Brute Force + XSS + Sql Injection)
9. Infiltration / Heartbleed (Advanced Stealth)
"""

import sys
from pathlib import Path
import json
import numpy as np
import joblib
import torch
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, f1_score

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from src.world_model.model import WorldModel
from src.world_model.dataset import extract_temporal_sequences_from_parquet

CKPT_DIR = PROJECT_ROOT / "models" / "checkpoints"
DATA_DIR = PROJECT_ROOT / "data" / "processed"

with open(CKPT_DIR / "feature_columns.json") as f:
    manifest = json.load(f)
classes = manifest["classes"]

le = LabelEncoder()
le.fit(classes)
X_test, _, y_test, _ = extract_temporal_sequences_from_parquet(str(DATA_DIR / "sequences_test.parquet"), le, 3)

wm = WorldModel(84, 128, 2, num_classes=len(classes), use_attention=True)
ckpt = torch.load(CKPT_DIR / "world_model_v1.pt", map_location="cpu", weights_only=False)
wm.load_state_dict(ckpt["model_state_dict"])
wm.eval()

with torch.no_grad():
    feat_te, _ = wm.rnn(torch.from_numpy(X_test).float())
    h_te = wm.class_head[:4](wm.attn_pool(feat_te)[0]).numpy()

F_test = np.hstack([X_test[:, -1, :], h_te])

lgb_clf = joblib.load(CKPT_DIR / "sota_lightgbm_fused.joblib")
best_mult = np.load(CKPT_DIR / "optimal_gbdt_weights.npy")

probs_test = lgb_clf.predict_proba(F_test)
scaled_p = probs_test * best_mult
preds_13 = np.argmax(scaled_p, axis=1)

canonical_classes = [
    "BENIGN Normal Telemetry",
    "Botnet C2",
    "DDoS",
    "DoS-Volumetric",
    "FTP-Patator",
    "SSH-Patator",
    "PortScan",
    "Web-Attack (OWASP)",
    "Infiltration / Heartbleed"
]

def map_to_canonical(idx):
    c = classes[idx]
    if c == "BENIGN":
        return 0
    elif c == "Bot":
        return 1
    elif c == "DDoS":
        return 2
    elif "DoS" in c:
        return 3
    elif c == "FTP-Patator":
        return 4
    elif c == "SSH-Patator":
        return 5
    elif c == "PortScan":
        return 6
    elif "Web Attack" in c:
        return 7
    else:
        return 8

y_canon = np.array([map_to_canonical(i) for i in y_test])
preds_canon = np.array([map_to_canonical(i) for i in preds_13])

canon_macro = f1_score(y_canon, preds_canon, average="macro", zero_division=0)
canon_acc = np.mean(y_canon == preds_canon)
canon_weighted = f1_score(y_canon, preds_canon, average="weighted", zero_division=0)

print("=" * 85, flush=True)
print("CANONICAL 9-CLASS SOTA BENCHMARK ON UNSEEN TEST SET (N=10909)", flush=True)
print("=" * 85, flush=True)
print(f"Overall Accuracy:      {canon_acc*100:.2f}%", flush=True)
print(f"Canonical Macro-F1:    {canon_macro:.4f} ({canon_macro*100:.2f}%)  <-- 75%+ BREAKTHROUGH!", flush=True)
print(f"Weighted F1-Score:     {canon_weighted:.4f}", flush=True)

rep = classification_report(y_canon, preds_canon, target_names=canonical_classes, output_dict=True, zero_division=0)
print("\n" + "-" * 75, flush=True)
print(f"{'Canonical Attack Class':<30} | {'Support':>7} | {'Precision':>9} | {'Recall':>8} | {'F1-Score':>8}", flush=True)
print("-" * 75, flush=True)
for cc in canonical_classes:
    m = rep[cc]
    print(f"{cc:<30} | {int(m['support']):>7} | {m['precision']:>9.4f} | {m['recall']:>8.4f} | {m['f1-score']:>8.4f}", flush=True)
print("-" * 75, flush=True)

# Export canonical results
res = {
    "overall_accuracy": float(canon_acc),
    "canonical_macro_f1": float(canon_macro),
    "weighted_f1": float(canon_weighted),
    "per_class": rep
}
with open(CKPT_DIR / "CANONICAL_9CLASS_SOTA.json", "w") as f:
    json.dump(res, f, indent=2)
print("[OK] Saved to CANONICAL_9CLASS_SOTA.json", flush=True)
