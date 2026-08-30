"""
GROUND TRUTH CROSS-DATASET EVALUATION
Loads the ONE real checkpoint (world_model_v1.pt), runs REAL inference on
UNSW-NB15 and CIC-IDS-2018. Zero hardcoded numbers.
"""
import sys, json, time, hashlib
from pathlib import Path
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import roc_auc_score, f1_score, balanced_accuracy_score

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.world_model.model import WorldModel

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    device = torch.device("cpu")
    ckpt_path = PROJECT_ROOT / "models" / "checkpoints" / "world_model_v1.pt"

    # --- Verify checkpoint ---
    ckpt_hash = sha256_file(ckpt_path)
    print(f"Checkpoint SHA-256: {ckpt_hash}")

    # --- Load model ---
    ckpt = torch.load(ckpt_path, map_location=device, weights_only=False)
    model = WorldModel(
        input_size=84, hidden_size=128, num_layers=2,
        num_classes=13, num_mitre_stages=6
    ).to(device)
    model.load_state_dict(ckpt["model_state_dict"])
    model.eval()

    # --- Load feature column manifest ---
    with open(PROJECT_ROOT / "models" / "checkpoints" / "feature_columns.json") as f:
        manifest = json.load(f)
    flow_cols = manifest["numeric_features"][:77]

    # =====================================================================
    # UNSW-NB15
    # =====================================================================
    print("\n=== UNSW-NB15 CROSS-DATASET EVALUATION ===")
    unsw_path = PROJECT_ROOT / "dataset" / "UNSW" / "UNSW_NB15_testing-set.csv"
    unsw_hash = sha256_file(unsw_path)
    print(f"UNSW data SHA-256: {unsw_hash}")
    print(f"UNSW data size:    {unsw_path.stat().st_size} bytes")

    df_unsw = pd.read_csv(unsw_path)
    print(f"UNSW rows loaded:  {len(df_unsw)}")

    # Build 84-dim state vectors from flow columns
    st_unsw = np.zeros((len(df_unsw), 84), dtype=np.float32)
    matched_cols = 0
    for idx, col in enumerate(flow_cols):
        if col in df_unsw.columns:
            vals = pd.to_numeric(df_unsw[col], errors="coerce").fillna(0.0).values
            vals = np.nan_to_num(vals, nan=0.0, posinf=0.0, neginf=0.0)
            st_unsw[:, idx] = (vals - np.mean(vals)) / (np.std(vals) + 1e-6)
            matched_cols += 1
    print(f"Feature columns matched: {matched_cols}/{len(flow_cols)}")

    # Build L=3 sequences
    n_seq = min(20000, len(st_unsw) - 2)
    unsw_X = np.array([st_unsw[i:i+3] for i in range(n_seq)], dtype=np.float32)
    unsw_y = df_unsw["label"].values[2:2+n_seq]
    print(f"UNSW sequences:    {len(unsw_X)}")
    print(f"UNSW label dist:   benign={np.sum(unsw_y==0)}, attack={np.sum(unsw_y==1)}")

    # Run inference
    with torch.no_grad():
        out_unsw = model(torch.from_numpy(unsw_X).to(device))
        probs_unsw = torch.softmax(out_unsw["class_logits"], dim=-1).cpu().numpy()
        p_threat_unsw = 1.0 - probs_unsw[:, 0]
        preds_unsw = (p_threat_unsw >= 0.5).astype(int)

    unsw_roc = float(roc_auc_score(unsw_y, p_threat_unsw))
    unsw_f1 = float(f1_score(unsw_y, preds_unsw, average="macro", zero_division=0))
    unsw_bal_acc = float(balanced_accuracy_score(unsw_y, preds_unsw))
    print(f"UNSW ROC-AUC:      {unsw_roc:.6f}")
    print(f"UNSW Macro-F1:     {unsw_f1:.6f}")
    print(f"UNSW Bal-Acc:      {unsw_bal_acc*100:.4f}%")

    # =====================================================================
    # CIC-IDS-2018
    # =====================================================================
    print("\n=== CIC-IDS-2018 CROSS-DATASET EVALUATION ===")
    cic_path = PROJECT_ROOT / "dataset" / "data 1" / "02-14-2018.csv"
    cic_hash = sha256_file(cic_path)
    print(f"CIC data SHA-256:  {cic_hash}")
    print(f"CIC data size:     {cic_path.stat().st_size} bytes")

    df_cic = pd.read_csv(cic_path, nrows=20000)
    print(f"CIC rows loaded:   {len(df_cic)}")

    # Find label column
    lbl_col = [c for c in df_cic.columns if "label" in c.lower()][0]
    print(f"CIC label column:  {lbl_col}")
    y_cic_raw = df_cic[lbl_col].str.strip().str.lower()
    y_cic_bin = (y_cic_raw != "benign").astype(int).values[2:]
    print(f"CIC label dist:    benign={np.sum(y_cic_bin==0)}, attack={np.sum(y_cic_bin==1)}")

    # Feature mapping 2017->2018
    try:
        from scripts.train_eval_expanded_world_model import FEATURE_MAP_2017_TO_2018
        use_map = True
    except ImportError:
        use_map = False
        print("WARNING: FEATURE_MAP_2017_TO_2018 not available, using direct column matching")

    flow_mat = np.zeros((len(df_cic), 77), dtype=np.float32)
    cic_matched = 0
    for f_i, f_name in enumerate(flow_cols):
        candidates = [f_name]
        if use_map:
            candidates = FEATURE_MAP_2017_TO_2018.get(f_name, [f_name])
        for c in candidates:
            if c in df_cic.columns:
                vals = pd.to_numeric(df_cic[c], errors="coerce").fillna(0.0).values
                flow_mat[:, f_i] = np.nan_to_num(vals, nan=0.0, posinf=0.0, neginf=0.0)
                cic_matched += 1
                break
    print(f"CIC features matched: {cic_matched}/{len(flow_cols)}")

    st_cic = np.zeros((len(df_cic), 84), dtype=np.float32)
    st_cic[:, :77] = (flow_mat - np.mean(flow_mat, axis=0)) / (np.std(flow_mat, axis=0) + 1e-6)
    cic_X = np.array([st_cic[i:i+3] for i in range(len(st_cic) - 2)], dtype=np.float32)
    print(f"CIC sequences:     {len(cic_X)}")

    with torch.no_grad():
        out_cic = model(torch.from_numpy(cic_X).to(device))
        probs_cic = torch.softmax(out_cic["class_logits"], dim=-1).cpu().numpy()
        p_threat_cic = 1.0 - probs_cic[:, 0]
        preds_cic = (p_threat_cic >= 0.5).astype(int)

    cic_roc = float(roc_auc_score(y_cic_bin, p_threat_cic))
    cic_f1 = float(f1_score(y_cic_bin, preds_cic, average="macro", zero_division=0))
    cic_bal_acc = float(balanced_accuracy_score(y_cic_bin, preds_cic))
    print(f"CIC ROC-AUC:       {cic_roc:.6f}")
    print(f"CIC Macro-F1:      {cic_f1:.6f}")
    print(f"CIC Bal-Acc:       {cic_bal_acc*100:.4f}%")

    # --- Save ---
    result = {
        "audit_timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "audit_note": "ALL metrics from real inference on world_model_v1.pt. ZERO hardcoded numbers.",
        "checkpoint_sha256": ckpt_hash,
        "unsw_nb15": {
            "data_file": "dataset/UNSW/UNSW_NB15_testing-set.csv",
            "data_sha256": unsw_hash,
            "n_sequences": int(len(unsw_X)),
            "feature_columns_matched": matched_cols,
            "roc_auc": unsw_roc,
            "macro_f1": unsw_f1,
            "balanced_accuracy": unsw_bal_acc
        },
        "cic_ids_2018": {
            "data_file": "dataset/data 1/02-14-2018.csv",
            "data_sha256": cic_hash,
            "n_sequences": int(len(cic_X)),
            "feature_columns_matched": cic_matched,
            "roc_auc": cic_roc,
            "macro_f1": cic_f1,
            "balanced_accuracy": cic_bal_acc
        }
    }

    out_path = PROJECT_ROOT / "models" / "checkpoints" / "GROUND_TRUTH_CROSS_DATASET.json"
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n{'='*80}")
    print(f"SAVED TO: {out_path}")
    print(f"{'='*80}")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
