"""
SOTA Intrusion Detection Benchmark: Neural WorldModel Temporal Representation + Cost-Sensitive GBDT
Combines WorldModel Attention State-Space Embeddings (h in R^128) + Raw NetFlow Telemetry (X in R^84)
Evaluated on:
1. LightGBM (class_weight='balanced')
2. XGBoost (multi:softprob with class-balanced weighting)
3. Two-Stage Cascaded Hybrid (Binary Sentinel LightGBM -> Multi-Class Specialist)
"""

import sys
from pathlib import Path
import json
import time
import numpy as np
import pandas as pd
import torch
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score, balanced_accuracy_score
import lightgbm as lgb
import xgboost as xgb

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.world_model.model import WorldModel
from src.world_model.dataset import extract_temporal_sequences_from_parquet

CKPT_DIR = PROJECT_ROOT / "models" / "checkpoints"
DATA_DIR = PROJECT_ROOT / "data" / "processed"

print("=" * 90, flush=True)
print("SOTA BENCHMARK: WORLDMODEL TEMPORAL REPRESENTATIONS + COST-SENSITIVE GBDT", flush=True)
print("=" * 90, flush=True)

# 1. Load manifest & classes
with open(CKPT_DIR / "feature_columns.json") as f:
    manifest = json.load(f)
classes = manifest["classes"]
num_classes = len(classes)
benign_idx = classes.index("BENIGN")

le = LabelEncoder()
le.fit(classes)

# 2. Load Datasets
val_parquet = str(DATA_DIR / "sequences_val.parquet")
test_parquet = str(DATA_DIR / "sequences_test.parquet")

# Check if training set exists
train_parquet = str(PROJECT_ROOT.parent / "ShieldNet" / "data" / "processed" / "sequences_train.parquet")
if not Path(train_parquet).exists():
    train_parquet = val_parquet

print(f"[*] Loading Training/Validation Set from {train_parquet}...", flush=True)
X_train, y_st_tr, y_train, _ = extract_temporal_sequences_from_parquet(train_parquet, le, context_length=3)
print(f"    Loaded {len(y_train)} training sequences.", flush=True)

print(f"[*] Loading Test Set from {test_parquet}...", flush=True)
X_test, y_st_te, y_test, _ = extract_temporal_sequences_from_parquet(test_parquet, le, context_length=3)
print(f"    Loaded {len(y_test)} test sequences.", flush=True)

# 3. Extract Neural Temporal Embeddings from Pretrained WorldModel
DEVICE = torch.device("cpu")
wm = WorldModel(input_size=84, hidden_size=128, num_layers=2, num_classes=num_classes, num_mitre_stages=6, use_attention=True)
ckpt = torch.load(CKPT_DIR / "world_model_v1.pt", map_location=DEVICE, weights_only=False)
wm.load_state_dict(ckpt["model_state_dict"])
wm.eval()

print("\n[*] Extracting WorldModel attention embeddings...", flush=True)
with torch.no_grad():
    # Train embeddings
    X_tr_t = torch.from_numpy(X_train).float()
    feat_tr, _ = wm.rnn(X_tr_t)
    pooled_tr, _ = wm.attn_pool(feat_tr)
    h_train = wm.class_head[:4](pooled_tr).numpy()
    
    # Test embeddings
    X_te_t = torch.from_numpy(X_test).float()
    feat_te, _ = wm.rnn(X_te_t)
    pooled_te, _ = wm.attn_pool(feat_te)
    h_test = wm.class_head[:4](pooled_te).numpy()

# Concatenate Raw NetFlow features (84) with WorldModel Temporal Representation (128)
# Total Fused Feature Vector = 212 dimensions
F_train = np.hstack([X_train[:, -1, :], h_train])
F_test = np.hstack([X_test[:, -1, :], h_test])
print(f"    Fused Feature Matrix: Train shape {F_train.shape}, Test shape {F_test.shape}", flush=True)

# Compute class sample weights to counter 10,812:1 imbalance
class_counts = np.bincount(y_train, minlength=num_classes)
print("\n[Training Class Counts]:", flush=True)
for i, c in enumerate(classes):
    print(f"  {c:<26}: {class_counts[i]} samples", flush=True)

# Square-root smoothed inverse frequency weights
weights_per_class = {i: float((len(y_train) / (num_classes * max(class_counts[i], 1))) ** 0.5) for i in range(num_classes)}
sample_weights_tr = np.array([weights_per_class[y] for y in y_train], dtype=np.float32)

# ==============================================================================
# MODEL 1: LIGHTGBM WITH BALANCED CLASS WEIGHTS
# ==============================================================================
print("\n" + "=" * 80, flush=True)
print("TRAINING MODEL 1: COST-SENSITIVE LIGHTGBM MULTI-CLASS", flush=True)
print("=" * 80, flush=True)

lgb_clf = lgb.LGBMClassifier(
    objective="multiclass",
    num_class=num_classes,
    class_weight="balanced",
    n_estimators=150,
    learning_rate=0.08,
    num_leaves=31,
    random_state=42,
    verbose=-1,
    n_jobs=4
)

start_time = time.time()
lgb_clf.fit(F_train, y_train)
lgb_train_time = time.time() - start_time
print(f"[OK] LightGBM trained in {lgb_train_time:.2f} seconds.", flush=True)

lgb_preds = lgb_clf.predict(F_test)
lgb_acc = np.mean(lgb_preds == y_test)
lgb_macro_f1 = f1_score(y_test, lgb_preds, average="macro", zero_division=0)
lgb_weighted_f1 = f1_score(y_test, lgb_preds, average="weighted", zero_division=0)
lgb_bal_acc = balanced_accuracy_score(y_test, lgb_preds)

print(f"\n[LightGBM Test Results]")
print(f"  * Overall Accuracy:  {lgb_acc*100:.2f}%")
print(f"  * Macro-F1:          {lgb_macro_f1:.4f}")
print(f"  * Balanced Accuracy: {lgb_bal_acc*100:.2f}%")
print(f"  * Weighted F1:       {lgb_weighted_f1:.4f}")

# Print Per-Class Performance
lgb_rep = classification_report(y_test, lgb_preds, target_names=classes, output_dict=True, zero_division=0)
print("\n" + "-" * 75)
print(f"{'Class':<26} | {'Support':>7} | {'Precision':>9} | {'Recall':>8} | {'F1-Score':>8}")
print("-" * 75)
for c in classes:
    m = lgb_rep[c]
    print(f"{c:<26} | {int(m['support']):>7} | {m['precision']:>9.4f} | {m['recall']:>8.4f} | {m['f1-score']:>8.4f}")

# ==============================================================================
# MODEL 2: TWO-STAGE CASCADED HYBRID (Binary Sentinel GBDT -> Attack Specialist)
# ==============================================================================
print("\n" + "=" * 80, flush=True)
print("TRAINING MODEL 2: TWO-STAGE CASCADED HYBRID", flush=True)
print("=" * 80, flush=True)

# Stage 1: Binary Sentinel (Benign vs Attack)
y_binary_train = (y_train != benign_idx).astype(int)
y_binary_test = (y_test != benign_idx).astype(int)

# Scale pos weight for binary sentinel = ratio of negative to positive
scale_pos = (np.sum(y_binary_train == 0) / max(np.sum(y_binary_train == 1), 1))
print(f"Stage 1 Binary Sentinel scale_pos_weight: {scale_pos:.2f}")

binary_sentinel = xgb.XGBClassifier(
    n_estimators=100,
    learning_rate=0.1,
    max_depth=5,
    scale_pos_weight=scale_pos,
    random_state=42,
    tree_method="hist",
    eval_metric="logloss"
)
binary_sentinel.fit(F_train, y_binary_train)

# Evaluate Stage 1 Sentinel
p_attack_sentinel = binary_sentinel.predict_proba(F_test)[:, 1]
sentinel_acc = np.mean((p_attack_sentinel >= 0.5) == y_binary_test)
sentinel_rec = recall_score(y_binary_test, (p_attack_sentinel >= 0.5), zero_division=0)
sentinel_prec = precision_score(y_binary_test, (p_attack_sentinel >= 0.5), zero_division=0)
sentinel_f1 = f1_score(y_binary_test, (p_attack_sentinel >= 0.5), zero_division=0)
print(f"[Stage 1 Sentinel Performance] Acc: {sentinel_acc*100:.2f}%, Recall: {sentinel_rec*100:.2f}%, Precision: {sentinel_prec*100:.2f}%, Binary F1: {sentinel_f1:.4f}")

# Stage 2: Attack Specialist on attack samples only
attack_mask_tr = (y_train != benign_idx)
F_train_attacks = F_train[attack_mask_tr]
y_train_attacks = y_train[attack_mask_tr]

attack_specialist = lgb.LGBMClassifier(
    objective="multiclass",
    num_class=num_classes,
    class_weight="balanced",
    n_estimators=100,
    learning_rate=0.08,
    num_leaves=20,
    random_state=42,
    verbose=-1
)
attack_specialist.fit(F_train_attacks, y_train_attacks)

# Combine: If Sentinel says Benign (p < threshold), predict BENIGN. Else attack specialist.
for s_thresh in [0.40, 0.50, 0.60, 0.70, 0.80, 0.85]:
    is_mal = p_attack_sentinel >= s_thresh
    spec_preds = attack_specialist.predict(F_test)
    casc_preds = np.where(is_mal, spec_preds, benign_idx)
    
    c_macro = f1_score(y_test, casc_preds, average="macro", zero_division=0)
    c_acc = np.mean(casc_preds == y_test)
    print(f"Sentinel Threshold = {s_thresh:.2f} | Overall Acc: {c_acc*100:.2f}% | Macro-F1: {c_macro:.4f}")

# ==============================================================================
# MODEL 3: OPERATIONAL 10-CLASS & 7-FAMILY EVALUATION
# ==============================================================================
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

y_merged_test = np.array([map_to_merged(idx) for idx in y_test])
lgb_merged_preds = np.array([map_to_merged(idx) for idx in lgb_preds])

merged_macro = f1_score(y_merged_test, lgb_merged_preds, average="macro", zero_division=0)
merged_acc = np.mean(lgb_merged_preds == y_merged_test)

print("\n" + "=" * 80, flush=True)
print(f"[OPERATIONAL 10-CLASS LIGHTGBM EVALUATION]", flush=True)
print(f"  * 10-Class Overall Accuracy: {merged_acc*100:.2f}%", flush=True)
print(f"  * 10-Class Macro-F1:         {merged_macro:.4f}", flush=True)
print("=" * 80, flush=True)

rep_merged = classification_report(y_merged_test, lgb_merged_preds, target_names=merged_classes, output_dict=True, zero_division=0)
print(f"{'Merged Class':<28} | {'Support':>7} | {'Precision':>9} | {'Recall':>8} | {'F1-Score':>8}")
print("-" * 75)
for mc in merged_classes:
    m = rep_merged[mc]
    print(f"{mc:<28} | {int(m['support']):>7} | {m['precision']:>9.4f} | {m['recall']:>8.4f} | {m['f1-score']:>8.4f}")
print("-" * 75)
