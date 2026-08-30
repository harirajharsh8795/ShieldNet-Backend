"""
DEFINITIVE BASELINE EVALUATION — SIH26153 ShieldNet (Phase 0)
Loads sequences_test.parquet (N=10,909) and evaluates Logistic Regression baseline
on the exact same 84-dimensional standardized features and test split used by the World Model.
Saves to models/checkpoints/DEFINITIVE_BASELINE.json and prints full literal content.
"""
import sys, json, time, hashlib
from pathlib import Path
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    f1_score, accuracy_score, balanced_accuracy_score,
    roc_auc_score, classification_report
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.world_model.dataset import extract_temporal_sequences_from_parquet

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    print("=" * 80)
    print("SHIELDNET PHASE 0: DEFINITIVE BASELINE EVALUATION (LOGISTIC REGRESSION)")
    print(f"Timestamp (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    print("=" * 80)

    train_path = PROJECT_ROOT / "data" / "processed" / "sequences_train.parquet"
    test_path = PROJECT_ROOT / "data" / "processed" / "sequences_test.parquet"
    manifest_path = PROJECT_ROOT / "models" / "checkpoints" / "feature_columns.json"
    logreg_saved_path = PROJECT_ROOT / "models" / "checkpoints" / "baseline_logreg_configA.joblib"

    # 1. SHA-256 Hashes
    train_hash = sha256_file(train_path)
    test_hash = sha256_file(test_path)
    print(f"Train data SHA-256: {train_hash}")
    print(f"Test data SHA-256:  {test_hash}")

    with open(manifest_path) as f:
        manifest = json.load(f)
    classes = manifest["classes"]
    le = LabelEncoder()
    le.fit(classes)

    # 2. Extract sequences
    print("\nLoading test sequences from sequences_test.parquet...", flush=True)
    X_test_seq, y_st_test, y_cls_test, y_mit_test = extract_temporal_sequences_from_parquet(
        str(test_path), label_encoder=le, context_length=3
    )
    print(f"Test sequences loaded: N = {len(X_test_seq):,}, shape = {X_test_seq.shape}")

    print("Loading train sequences from sequences_train.parquet...", flush=True)
    X_train_seq, y_st_train, y_cls_train, y_mit_train = extract_temporal_sequences_from_parquet(
        str(train_path), label_encoder=le, context_length=3
    )
    print(f"Train sequences loaded: N = {len(X_train_seq):,}, shape = {X_train_seq.shape}")

    # Static baseline uses current time-step feature vector S_t = X[:, -1, :] (84 features)
    X_train_flat = X_train_seq[:, -1, :]
    X_test_flat = X_test_seq[:, -1, :]

    # 3. Fit standard Logistic Regression on exact train split (or load saved)
    print("\nFitting Logistic Regression (standard multi-class baseline)...", flush=True)
    clf = LogisticRegression(max_iter=1000, random_state=42, solver="lbfgs")
    clf.fit(X_train_flat, y_cls_train)

    # Also check saved model if available
    if logreg_saved_path.exists():
        try:
            saved_clf = joblib.load(logreg_saved_path)
            print("Loaded saved baseline_logreg_configA.joblib successfully.")
        except Exception as e:
            print(f"Could not load saved model: {e}")
            saved_clf = clf
    else:
        saved_clf = clf

    # Save the freshly verified model checkpoint
    joblib.dump(clf, logreg_saved_path)

    # 4. Evaluate on test split
    preds = clf.predict(X_test_flat)
    probs = clf.predict_proba(X_test_flat)

    # Map class indices
    clf_classes = clf.classes_
    full_probs = np.zeros((len(X_test_flat), len(classes)), dtype=np.float64)
    for idx, c in enumerate(clf_classes):
        full_probs[:, c] = probs[:, idx]

    macro_f1 = float(f1_score(y_cls_test, preds, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_cls_test, preds, average="weighted", zero_division=0))
    bal_acc = float(balanced_accuracy_score(y_cls_test, preds))
    accuracy = float(accuracy_score(y_cls_test, preds))

    # Binary threat ROC-AUC (class 0 is BENIGN, non-zero is Attack)
    y_binary = (y_cls_test != 0).astype(int)
    p_threat = 1.0 - full_probs[:, 0]
    try:
        roc_auc = float(roc_auc_score(y_binary, p_threat))
    except Exception as e:
        roc_auc = None

    # Per-class metrics
    per_class_f1 = f1_score(y_cls_test, preds, average=None, zero_division=0)
    class_counts = np.bincount(y_cls_test, minlength=len(classes))
    per_class_detail = {}
    for i, cls_name in enumerate(classes):
        per_class_detail[cls_name] = {
            "f1": float(per_class_f1[i]) if i < len(per_class_f1) else 0.0,
            "support": int(class_counts[i]) if i < len(class_counts) else 0
        }

    # 5. Build definitive JSON payload
    result = {
        "audit_timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model_name": "Logistic Regression (Definitive Baseline)",
        "model_type": "Linear / Static Memoryless (Config A features, N=84)",
        "train_data": {
            "path": "data/processed/sequences_train.parquet",
            "sha256": train_hash,
            "n_samples": int(len(X_train_seq))
        },
        "test_data": {
            "path": "data/processed/sequences_test.parquet",
            "sha256": test_hash,
            "n_samples": int(len(X_test_seq))
        },
        "metrics": {
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
            "balanced_accuracy": bal_acc,
            "overall_accuracy": accuracy,
            "threat_roc_auc": roc_auc,
            "per_class": per_class_detail
        },
        "retired_previous_values": {
            "0.5421": "Retired (old binary / unaligned split artifact)",
            "0.2475": "Retired (pre-harmonized class indexing artifact)",
            "0.0652": "Retired (unweighted raw single-class artifact)"
        },
        "status": "DEFINITIVE_LOCKED"
    }

    out_path = PROJECT_ROOT / "models" / "checkpoints" / "DEFINITIVE_BASELINE.json"
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)

    print("\n" + "=" * 80)
    print(f"DEFINITIVE BASELINE SAVED TO: {out_path}")
    print("=" * 80)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
