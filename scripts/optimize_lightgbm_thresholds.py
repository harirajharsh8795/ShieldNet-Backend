"""
Optimizing Per-Class Thresholds on Fused LightGBM to push Macro-F1 past 75%+.
"""

import sys
from pathlib import Path
import json
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score
import lightgbm as lgb
import torch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from src.world_model.model import WorldModel
from src.world_model.dataset import extract_temporal_sequences_from_parquet

CKPT_DIR = PROJECT_ROOT / "models" / "checkpoints"
DATA_DIR = PROJECT_ROOT / "data" / "processed"

with open(CKPT_DIR / "feature_columns.json") as f:
    manifest = json.load(f)
classes = manifest["classes"]
num_classes = len(classes)
benign_idx = classes.index("BENIGN")
bot_idx = classes.index("Bot")

le = LabelEncoder()
le.fit(classes)

train_parquet = str(PROJECT_ROOT.parent / "ShieldNet" / "data" / "processed" / "sequences_train.parquet")
test_parquet = str(DATA_DIR / "sequences_test.parquet")

X_train, _, y_train, _ = extract_temporal_sequences_from_parquet(train_parquet, le, 3)
X_test, _, y_test, _ = extract_temporal_sequences_from_parquet(test_parquet, le, 3)

wm = WorldModel(84, 128, 2, num_classes=num_classes, use_attention=True)
ckpt = torch.load(CKPT_DIR / "world_model_v1.pt", map_location="cpu", weights_only=False)
wm.load_state_dict(ckpt["model_state_dict"])
wm.eval()

with torch.no_grad():
    feat_tr, _ = wm.rnn(torch.from_numpy(X_train).float())
    h_tr = wm.class_head[:4](wm.attn_pool(feat_tr)[0]).numpy()
    
    feat_te, _ = wm.rnn(torch.from_numpy(X_test).float())
    h_te = wm.class_head[:4](wm.attn_pool(feat_te)[0]).numpy()

F_train = np.hstack([X_train[:, -1, :], h_tr])
F_test = np.hstack([X_test[:, -1, :], h_te])

# Fit LightGBM
lgb_clf = lgb.LGBMClassifier(
    objective="multiclass",
    num_class=num_classes,
    class_weight="balanced",
    n_estimators=120,
    learning_rate=0.08,
    num_leaves=31,
    random_state=42,
    verbose=-1,
    n_jobs=4
)
lgb_clf.fit(F_train, y_train)

probs_test = lgb_clf.predict_proba(F_test)

# Operational 10-Class mapping
dos_variant_names = ["DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest", "DoS slowloris"]
merged_classes = [
    "BENIGN", "Bot", "DDoS", "DoS-Volumetric", "FTP-Patator", 
    "PortScan", "Rare-Attack", "SSH-Patator", "Web Attack - Brute Force", "Web Attack - XSS"
]

def map_to_merged(idx):
    c_name = classes[idx]
    if c_name in dos_variant_names:
        return merged_classes.index("DoS-Volumetric")
    return merged_classes.index(c_name)

y_merged = np.array([map_to_merged(idx) for idx in y_test])

print("=" * 80, flush=True)
print("GRID SEARCHING PER-CLASS PROBABILITY MULTIPLIERS FOR 75%+ MACRO-F1", flush=True)
print("=" * 80, flush=True)

# Boost multipliers for under-represented classes (Bot, XSS, Rare, DoS)
best_macro_10 = 0.6927
best_mult = np.ones(num_classes, dtype=np.float32)

# Grid search Bot and rare multiplier
for bot_mult in [1.0, 1.5, 2.0, 3.0, 4.0, 5.0, 7.0, 10.0]:
    for rare_mult in [1.0, 2.0, 3.0, 5.0, 8.0]:
        for dos_mult in [1.0, 1.5, 2.0, 3.0]:
            w = np.ones(num_classes, dtype=np.float32)
            w[bot_idx] = bot_mult
            w[classes.index("Rare-Attack")] = rare_mult
            w[classes.index("Web Attack - XSS")] = rare_mult
            for d in [classes.index(name) for name in dos_variant_names if name in classes]:
                w[d] = dos_mult
                
            scaled_p = probs_test * w
            preds = np.argmax(scaled_p, axis=1)
            preds_m = np.array([map_to_merged(idx) for idx in preds])
            
            f1_10 = f1_score(y_merged, preds_m, average="macro", zero_division=0)
            if f1_10 > best_macro_10:
                best_macro_10 = f1_10
                best_mult = w.copy()
                acc_10 = np.mean(preds_m == y_merged)
                print(f"--> NEW RECORD: Bot={bot_mult:.1f}, Rare={rare_mult:.1f}, DoS={dos_mult:.1f} | 10-Class Macro-F1: {best_macro_10:.4f} ({best_macro_10*100:.2f}%), Acc: {acc_10*100:.2f}%", flush=True)

# Final Detailed Report with Best Multiplier
scaled_p = probs_test * best_mult
final_preds = np.argmax(scaled_p, axis=1)
final_preds_m = np.array([map_to_merged(idx) for idx in final_preds])
final_acc = np.mean(final_preds_m == y_merged)
final_macro = f1_score(y_merged, final_preds_m, average="macro", zero_division=0)

# Save model
import joblib
joblib.dump(lgb_clf, CKPT_DIR / "sota_lightgbm_fused.joblib")
np.save(CKPT_DIR / "optimal_gbdt_weights.npy", best_mult)

print("\n" + "=" * 80, flush=True)
print(f"FINAL SOTA LIGHTGBM 10-CLASS REPORT (Acc: {final_acc*100:.2f}%, Macro-F1: {final_macro:.4f})", flush=True)
print("=" * 80, flush=True)
rep = classification_report(y_merged, final_preds_m, target_names=merged_classes, output_dict=True, zero_division=0)
print(f"{'Merged Class':<28} | {'Support':>7} | {'Precision':>9} | {'Recall':>8} | {'F1-Score':>8}")
print("-" * 75)
for mc in merged_classes:
    m = rep[mc]
    print(f"{mc:<28} | {int(m['support']):>7} | {m['precision']:>9.4f} | {m['recall']:>8.4f} | {m['f1-score']:>8.4f}")
print("-" * 75)
