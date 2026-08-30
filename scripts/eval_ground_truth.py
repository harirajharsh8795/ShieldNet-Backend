"""
GROUND TRUTH EVALUATION — Single source of truth for ALL project metrics.
Loads the ONE real model checkpoint, runs REAL inference, computes REAL metrics.
No hardcoded numbers. Every value computed from actual model output.
"""
import sys, json, time, hashlib
from pathlib import Path
import numpy as np
import pandas as pd
import torch
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    f1_score, accuracy_score, balanced_accuracy_score,
    roc_auc_score, classification_report
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.world_model.model import WorldModel
from src.world_model.dataset import extract_temporal_sequences_from_parquet

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    device = torch.device("cpu")
    ckpt_path = PROJECT_ROOT / "models" / "checkpoints" / "world_model_v1.pt"
    test_path = PROJECT_ROOT / "data" / "processed" / "sequences_test.parquet"

    # --- SHA-256 verification ---
    ckpt_hash = sha256_file(ckpt_path)
    test_hash = sha256_file(test_path)
    print(f"Checkpoint SHA-256: {ckpt_hash}")
    print(f"Test data SHA-256:  {test_hash}")
    print(f"Checkpoint size:    {ckpt_path.stat().st_size} bytes")
    print(f"Test data size:     {test_path.stat().st_size} bytes")

    # --- Load model ---
    ckpt = torch.load(ckpt_path, map_location=device, weights_only=False)
    model = WorldModel(
        input_size=84, hidden_size=128, num_layers=2,
        num_classes=13, num_mitre_stages=6
    ).to(device)
    model.load_state_dict(ckpt["model_state_dict"])
    model.eval()
    param_count = sum(p.numel() for p in model.parameters())
    print(f"Model parameters:   {param_count:,}")

    # --- Load test data ---
    with open(PROJECT_ROOT / "models" / "checkpoints" / "feature_columns.json") as f:
        manifest = json.load(f)
    classes = manifest["classes"]
    le = LabelEncoder()
    le.fit(classes)

    X_test, y_st_test, y_cls_test, y_mit_test = extract_temporal_sequences_from_parquet(
        str(test_path), label_encoder=le, context_length=3
    )
    print(f"Test samples:       {len(X_test):,}")
    print(f"Class distribution: {dict(zip(*np.unique(y_cls_test, return_counts=True)))}")

    # --- Run inference ---
    X_t = torch.from_numpy(X_test).float().to(device)
    with torch.no_grad():
        out = model(X_t)
        logits = out["class_logits"].cpu().numpy()
        preds = np.argmax(logits, axis=-1)

    # --- Compute ALL metrics from real inference ---
    macro_f1 = float(f1_score(y_cls_test, preds, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_cls_test, preds, average="weighted", zero_division=0))
    bal_acc = float(balanced_accuracy_score(y_cls_test, preds))
    accuracy = float(accuracy_score(y_cls_test, preds))

    # Per-class F1
    per_class_f1 = f1_score(y_cls_test, preds, average=None, zero_division=0)
    class_counts = np.bincount(y_cls_test, minlength=len(classes))
    per_class_detail = {}
    for i, cls_name in enumerate(classes):
        per_class_detail[cls_name] = {
            "f1": float(per_class_f1[i]) if i < len(per_class_f1) else 0.0,
            "support": int(class_counts[i]) if i < len(class_counts) else 0
        }

    # ROC-AUC (binary: threat vs benign, where class 0 = BENIGN)
    probs = torch.softmax(torch.from_numpy(logits), dim=-1).numpy()
    y_binary = (y_cls_test != 0).astype(int)
    p_threat = 1.0 - probs[:, 0]
    try:
        roc_auc = float(roc_auc_score(y_binary, p_threat))
    except Exception:
        roc_auc = None

    print(f"\n=== PRIMARY METRICS (from real inference) ===")
    print(f"Macro-F1:           {macro_f1:.6f}")
    print(f"Weighted-F1:        {weighted_f1:.6f}")
    print(f"Balanced Accuracy:  {bal_acc*100:.4f}%")
    print(f"Overall Accuracy:   {accuracy*100:.4f}%")
    print(f"Threat ROC-AUC:     {roc_auc}")

    # --- 5-seed shuffle ablation (REAL permutation, REAL re-inference) ---
    print(f"\n=== 5-SEED SHUFFLE ABLATION ===")
    seeds = [42, 101, 2024, 777, 999]
    original_bal_acc = bal_acc
    shuffled_accs = []

    for seed in seeds:
        rng = np.random.RandomState(seed)
        X_shuffled = X_test.copy()
        for sample_idx in range(len(X_shuffled)):
            perm = rng.permutation(X_shuffled.shape[1])
            X_shuffled[sample_idx] = X_shuffled[sample_idx][perm]

        X_shuf_t = torch.from_numpy(X_shuffled).float().to(device)
        with torch.no_grad():
            out_shuf = model(X_shuf_t)
            preds_shuf = torch.argmax(out_shuf["class_logits"], dim=-1).cpu().numpy()

        shuf_bal_acc = float(balanced_accuracy_score(y_cls_test, preds_shuf))
        shuffled_accs.append(shuf_bal_acc)
        print(f"  Seed {seed}: Shuffled Bal-Acc = {shuf_bal_acc*100:.4f}%")

    mean_shuffled = float(np.mean(shuffled_accs))
    std_shuffled = float(np.std(shuffled_accs))
    delta = original_bal_acc - mean_shuffled
    sigma = delta / std_shuffled if std_shuffled > 1e-9 else float("inf")

    print(f"\n  Original Bal-Acc:  {original_bal_acc*100:.4f}%")
    print(f"  Mean Shuffled:     {mean_shuffled*100:.4f}%")
    print(f"  Std Shuffled:      {std_shuffled*100:.6f}%")
    print(f"  Delta:             {delta*100:.4f}%")
    print(f"  Sigma (significance): {sigma:.4f}")

    # --- K-step rollout latency ---
    sample = X_t[:1]
    # warmup
    for _ in range(10):
        with torch.no_grad():
            _ = model(sample)
    times = []
    for _ in range(200):
        t0 = time.perf_counter()
        curr = sample.clone()
        for step in range(5):
            with torch.no_grad():
                o = model(curr)
                ns = o["predicted_next_state"].unsqueeze(1)
                curr = torch.cat([curr[:, 1:, :], ns], dim=1)
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1000.0)
    latency_ms = float(np.mean(times))
    print(f"\n  K=5 Rollout Latency: {latency_ms:.4f} ms (mean of 200 runs)")

    # --- Save to GROUND_TRUTH_FINAL.json ---
    result = {
        "audit_timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "audit_note": "ALL metrics computed from real inference. ZERO hardcoded numbers.",
        "checkpoint": {
            "path": "models/checkpoints/world_model_v1.pt",
            "sha256": ckpt_hash,
            "size_bytes": int(ckpt_path.stat().st_size),
            "parameters": param_count,
            "architecture": "2-layer GRU (H=128) + Temporal Softmax Attention + 4 multi-task heads"
        },
        "test_data": {
            "path": "data/processed/sequences_test.parquet",
            "sha256": test_hash,
            "n_samples": int(len(X_test)),
            "source": "CICIDS2017 held-out test partition"
        },
        "in_distribution_metrics": {
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
            "balanced_accuracy": bal_acc,
            "overall_accuracy": accuracy,
            "threat_roc_auc": roc_auc,
            "per_class": per_class_detail
        },
        "shuffle_ablation": {
            "seeds": seeds,
            "original_balanced_accuracy": original_bal_acc,
            "shuffled_balanced_accuracies": shuffled_accs,
            "mean_shuffled": mean_shuffled,
            "std_shuffled": std_shuffled,
            "delta": delta,
            "sigma_significance": sigma
        },
        "k_step_rollout": {
            "k": 5,
            "latency_ms_mean_200runs": latency_ms
        }
    }

    out_path = PROJECT_ROOT / "models" / "checkpoints" / "GROUND_TRUTH_FINAL.json"
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n{'='*80}")
    print(f"GROUND TRUTH SAVED TO: {out_path}")
    print(f"{'='*80}")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
