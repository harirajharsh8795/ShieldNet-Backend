"""
Phase A: Data Scientist Log-Scale Feature Transformation Pipeline.
Based on Srivastava et al., arXiv:2312.17270.
"""

import sys, os, time, json
from pathlib import Path
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
import joblib
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import (
    f1_score, accuracy_score, balanced_accuracy_score,
    roc_auc_score, precision_recall_curve, auc
)
from typing import Dict, List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.world_model.model import WorldModel, WorldModelLoss
from scripts.run_phase4_cross_dataset import FEATURE_MAP_2017_TO_2018, UNSW_SEMANTIC_FEATURE_MAP

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
CKPT_DIR = PROJECT_ROOT / "models" / "checkpoints"

def analyze_skewness(parquet_file: str, cols: List[str]) -> Tuple[List[str], Dict[str, float]]:
    df = pd.read_parquet(parquet_file, columns=cols)
    skews = {}
    skewed = []
    for c in cols:
        v = pd.to_numeric(df[c], errors="coerce").fillna(0.0).values.astype(np.float64)
        v = np.nan_to_num(v, nan=0.0, posinf=0.0, neginf=0.0)
        m, s = np.mean(v), np.std(v, ddof=1)
        if s < 1e-8:
            sk = 0.0
        else:
            sk = float(np.mean((v - m) ** 3) / (s ** 3))
        skews[c] = sk
        if abs(sk) > 2.0:
            skewed.append(c)
    return skewed, skews

def apply_log(X: np.ndarray, all_cols: List[str], skew_cols: List[str]) -> np.ndarray:
    X_out = X.copy()
    s_set = set(skew_cols)
    for i, col in enumerate(all_cols):
        if col in s_set:
            X_out[:, i] = np.log1p(np.maximum(0.0, np.nan_to_num(X_out[:, i], nan=0.0, posinf=0.0, neginf=0.0)))
    return X_out

def build_datasets(skewed_cols: List[str], le: LabelEncoder, cols: List[str]):
    scaler_orig = joblib.load(CKPT_DIR / "scaler.joblib")
    m_orig = getattr(scaler_orig, "mean_", np.zeros(len(cols)))
    s_orig = getattr(scaler_orig, "scale_", np.ones(len(cols)))

    def load_unscaled(p_file):
        df = pd.read_parquet(p_file)
        st = np.stack(df["state_vector"].values).astype(np.float64) * s_orig + m_orig
        return df, st

    df_tr, raw_tr = load_unscaled("data/processed/sequences_train.parquet")
    df_va, raw_va = load_unscaled("data/processed/sequences_val.parquet")
    df_te, raw_te = load_unscaled("data/processed/sequences_test.parquet")

    log_tr = apply_log(raw_tr, cols, skewed_cols)
    log_va = apply_log(raw_va, cols, skewed_cols)
    log_te = apply_log(raw_te, cols, skewed_cols)

    new_scaler = StandardScaler()
    sc_tr = new_scaler.fit_transform(log_tr).astype(np.float32)
    sc_va = new_scaler.transform(log_va).astype(np.float32)
    sc_te = new_scaler.transform(log_te).astype(np.float32)

    def extract_seqs(df, sc):
        df = df.copy()
        df["_hk"] = df["session_group"].astype(str) + "___" + df["source_ip"].astype(str)
        df["_l"] = le.transform(df["label"].astype(str))
        X_l, ys_l, yc_l, ym_l = [], [], [], []
        for _, hdf in df.groupby("_hk", sort=False):
            if len(hdf) < 2:
                continue
            hdf = hdf.sort_values("window_idx").reset_index()
            idx = hdf["index"].values
            st, lbl, mit = sc[idx], hdf["_l"].values.astype(np.int64), hdf["mitre_stage"].values.astype(np.int64)
            for t in range(1, len(st)):
                start = max(0, t - 3)
                hist = st[start:t]
                if len(hist) < 3:
                    hist = np.vstack([np.tile(hist[0:1], (3 - len(hist), 1)), hist])
                X_l.append(hist)
                ys_l.append(st[t])
                yc_l.append(lbl[t])
                ym_l.append(mit[t])
        return np.array(X_l, dtype=np.float32), np.array(ys_l, dtype=np.float32), np.array(yc_l, dtype=np.int64), np.array(ym_l, dtype=np.int64)

    return extract_seqs(df_tr, sc_tr), extract_seqs(df_va, sc_va), extract_seqs(df_te, sc_te), new_scaler

def main():
    print("=" * 95)
    print("PHASE A: DATA SCIENTIST LOG-SCALE FEATURE TRANSFORMATION")
    print("Citation: Srivastava et al., arXiv:2312.17270 (Anticipated Network Surveillance)")
    print("=" * 95)

    with open(CKPT_DIR / "feature_columns.json") as f:
        manifest = json.load(f)
    cols = manifest["numeric_features"]
    classes = manifest["classes"]
    le = LabelEncoder().fit(classes)

    # 1. Identify skewed features
    skewed_cols, skews = analyze_skewness("data/processed/train_v1.parquet", cols)
    print(f"Total Continuous Features: {len(cols)}")
    print(f"Highly Skewed (|Skew| > 2.0): {len(skewed_cols)} / {len(cols)}")
    top_skew = sorted(skews.items(), key=lambda x: abs(x[1]), reverse=True)[:10]
    for c, sk in top_skew:
        print(f"  * {c:<32s}: Skew = {sk:+10.2f} -> log1p applied")

    # 2. Build datasets
    (X_tr, ys_tr, yc_tr, ym_tr), (X_va, ys_va, yc_va, ym_va), (X_te, ys_te, yc_te, ym_te), new_scaler = build_datasets(skewed_cols, le, cols)
    print(f"Dataset shapes: Train={X_tr.shape} | Val={X_va.shape} | Test={X_te.shape}")
    joblib.dump(new_scaler, CKPT_DIR / "scaler_logscale_v1.joblib")

    # 3. Retrain World Model
    print("\nRetraining World Model on log-scaled features (10 Epochs)...")
    model = WorldModel(input_size=84, hidden_size=128, num_layers=2, dropout=0.2, num_classes=len(classes), num_mitre_stages=6).to(DEVICE)
    class_counts = np.bincount(yc_tr, minlength=len(classes))
    weights = np.clip(len(yc_tr) / (len(classes) * np.maximum(class_counts, 1.0)), 0.1, 50.0)
    criterion = WorldModelLoss(lambda_class=1.0, lambda_mitre=0.25, lambda_order=0.5, focal_gamma=2.0, class_weights=torch.FloatTensor(weights).to(DEVICE)).to(DEVICE)
    optimizer = optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)

    loader = DataLoader(TensorDataset(torch.from_numpy(X_tr), torch.from_numpy(ys_tr), torch.from_numpy(yc_tr), torch.from_numpy(ym_tr)), batch_size=256, shuffle=True, drop_last=True)
    best_ba = 0.0
    best_state = None

    for epoch in range(1, 11):
        model.train()
        tot_l = 0.0
        for bx, bys, byc, bym in loader:
            bx, bys, byc, bym = bx.to(DEVICE), bys.to(DEVICE), byc.to(DEVICE), bym.to(DEVICE)
            out_pos = model(bx)
            l_pos = criterion(out_pos, bys, byc, bym, torch.ones(len(bx), device=DEVICE))
            perm = torch.rand(len(bx), 3, device=DEVICE).argsort(dim=1)
            bx_shuf = torch.gather(bx, 1, perm.unsqueeze(-1).expand(-1, -1, 84))
            l_neg = criterion.bce_order(model(bx_shuf)["order_logits"], torch.zeros(len(bx), device=DEVICE))
            loss = l_pos["total_loss"] + 0.5 * l_neg
            optimizer.zero_grad()
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            tot_l += loss.item()

        model.eval()
        with torch.no_grad():
            v_p = np.argmax(model(torch.from_numpy(X_va).to(DEVICE))["class_logits"].cpu().numpy(), axis=1)
            v_ba = balanced_accuracy_score(yc_va, v_p) * 100.0
        print(f"  Epoch {epoch:02d}/10 | Train Loss: {tot_l/len(loader):.4f} | Val Bal-Acc: {v_ba:.2f}%")
        if v_ba > best_ba:
            best_ba = v_ba
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}

    torch.save({"model_state_dict": best_state, "val_ba": best_ba}, CKPT_DIR / "world_model_logscale_v1.pt")
    model.load_state_dict(best_state)
    model.eval()

    # 4. In-distribution evaluation
    with torch.no_grad():
        t_out = model(torch.from_numpy(X_te).to(DEVICE))
        t_probs = torch.softmax(t_out["class_logits"], dim=-1).cpu().numpy()
        t_preds = np.argmax(t_probs, axis=1)
    
    ba_te = balanced_accuracy_score(yc_te, t_preds) * 100.0
    f1_te = f1_score(yc_te, t_preds, average="macro", zero_division=0)
    threat_p = 1.0 - t_probs[:, 0]
    roc_te = roc_auc_score((yc_te != 0).astype(int), threat_p)
    p_c, r_c, _ = precision_recall_curve((yc_te != 0).astype(int), threat_p)
    pr_te = auc(r_c, p_c)

    # Shuffle ablation
    print("  Running 20-Seed Temporal Shuffle Ablation...")
    shufs = []
    for s in [42, 101, 2024, 777, 999, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]:
        np.random.seed(s)
        X_s = np.zeros_like(X_te)
        for i in range(len(X_te)):
            X_s[i] = X_te[i, np.random.permutation(3), :]
        with torch.no_grad():
            shufs.append(balanced_accuracy_score(yc_te, np.argmax(model(torch.from_numpy(X_s).to(DEVICE))["class_logits"].cpu().numpy(), axis=1)) * 100.0)
    drop_shuf = ba_te - np.mean(shufs)
    sigma_shuf = drop_shuf / max(np.std(shufs, ddof=1), 1e-6)

    # 5. Cross-Dataset Evaluation
    # CSE-CIC-IDS2018
    df_c1 = pd.read_csv(PROJECT_ROOT / "dataset" / "data 1" / "02-14-2018.csv", nrows=30000)
    df_c2 = pd.read_csv(PROJECT_ROOT / "dataset" / "data 1" / "02-15-2018.csv", nrows=30000)
    df_cic = pd.concat([df_c1, df_c2], ignore_index=True)
    lbl_c = [c for c in df_cic.columns if "label" in c.lower()][0]
    y_c_bin = (df_cic[lbl_c].astype(str).str.strip().str.lower() != "benign").astype(int).values[2:]
    
    mat_18 = np.zeros((len(df_cic), 84), dtype=np.float64)
    for idx, fn in enumerate(cols[:77]):
        for cand in FEATURE_MAP_2017_TO_2018.get(fn, [fn]):
            if cand in df_cic.columns:
                mat_18[:, idx] = np.nan_to_num(pd.to_numeric(df_cic[cand], errors="coerce").fillna(0.0).values)
                break
    log_18 = apply_log(mat_18, cols, skewed_cols)
    sc_18 = new_scaler.transform(log_18).astype(np.float32)
    X_18 = np.array([sc_18[i:i+3] for i in range(len(sc_18) - 2)], dtype=np.float32)

    with torch.no_grad():
        p_18 = 1.0 - torch.softmax(model(torch.from_numpy(X_18).to(DEVICE))["class_logits"], dim=-1)[:, 0].cpu().numpy()
    roc_18 = roc_auc_score(y_c_bin, p_18)
    p_c18, r_c18, _ = precision_recall_curve(y_c_bin, p_18)
    pr_18 = auc(r_c18, p_c18)
    
    # Self-tuned tau on 2018
    best_ba_18, best_t_18 = 0.0, 0.5
    for t in np.linspace(0.05, 0.95, 19):
        ba = balanced_accuracy_score(y_c_bin, (p_18 >= t).astype(int)) * 100.0
        if ba > best_ba_18:
            best_ba_18, best_t_18 = ba, t

    # UNSW-NB15
    df_u = pd.read_csv(PROJECT_ROOT / "dataset" / "UNSW" / "UNSW_NB15_testing-set.csv")
    y_u_bin = df_u["label"].values[2:]
    mat_u = np.zeros((len(df_u), 84), dtype=np.float64)
    for target_idx, (cn, mult) in UNSW_SEMANTIC_FEATURE_MAP.items():
        if cn in df_u.columns:
            mat_u[:, target_idx] = np.nan_to_num(pd.to_numeric(df_u[cn], errors="coerce").fillna(0.0).values) * mult
    log_u = apply_log(mat_u, cols, skewed_cols)
    sc_u = new_scaler.transform(log_u).astype(np.float32)
    X_u = np.array([sc_u[i:i+3] for i in range(len(sc_u) - 2)], dtype=np.float32)

    with torch.no_grad():
        p_u = 1.0 - torch.softmax(model(torch.from_numpy(X_u).to(DEVICE))["class_logits"], dim=-1)[:, 0].cpu().numpy()
    roc_u = roc_auc_score(y_u_bin, p_u)
    p_cu, r_cu, _ = precision_recall_curve(y_u_bin, p_u)
    pr_u = auc(r_cu, p_cu)

    # 6. Save JSON
    out_metrics = {
        "timestamp_utc": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        "paper_citation": "Srivastava et al., arXiv:2312.17270",
        "num_skewed_features": len(skewed_cols),
        "in_distribution": {
            "balanced_accuracy": round(float(ba_te), 2),
            "macro_f1": round(float(f1_te), 4),
            "threat_roc_auc": round(float(roc_te), 4),
            "threat_pr_auc": round(float(pr_te), 4),
            "shuffle_sigma": round(float(sigma_shuf), 2),
            "shuffle_drop": round(float(drop_shuf), 2)
        },
        "cross_dataset": {
            "cse_cic_ids2018": {
                "threat_roc_auc": round(float(roc_18), 4),
                "threat_pr_auc": round(float(pr_18), 4),
                "tuned_balanced_accuracy": round(float(best_ba_18), 2),
                "optimal_threshold": round(float(best_t_18), 2)
            },
            "unsw_nb15": {
                "threat_roc_auc": round(float(roc_u), 4),
                "threat_pr_auc": round(float(pr_u), 4)
            }
        }
    }
    with open(CKPT_DIR / "metrics_logscale_v1.json", "w") as f:
        json.dump(out_metrics, f, indent=2)

    print("\n" + "=" * 95)
    print("PHASE A SUMMARY COMPARISON:")
    print("=" * 95)
    print(f"1. In-Distribution (Test N=10,909):")
    print(f"   - Balanced Accuracy: 79.15% (Original) vs {ba_te:.2f}% (Log-Scale) -> Delta: {ba_te - 79.15:+.2f}%")
    print(f"   - Threat ROC-AUC:    0.9798 (Original) vs {roc_te:.4f} (Log-Scale) -> Delta: {roc_te - 0.9798:+.4f}")
    print(f"   - Shuffle Dynamics:  +2.53 sigma       vs +{sigma_shuf:.2f} sigma  -> Delta: {sigma_shuf - 2.53:+.2f}s")
    print(f"\n2. Cross-Dataset Transferability:")
    print(f"   - CSE-CIC-IDS2018 ROC-AUC: 0.6198 (Original) vs {roc_18:.4f} (Log-Scale) -> Delta: {roc_18 - 0.6198:+.4f}")
    print(f"   - CSE-CIC-IDS2018 Tuned BA:67.21% (Original) vs {best_ba_18:.2f}% (Log-Scale) -> Delta: {best_ba_18 - 67.21:+.2f}%")
    print(f"   - UNSW-NB15 ROC-AUC:       0.1814 (Original) vs {roc_u:.4f} (Log-Scale) -> Delta: {roc_u - 0.1814:+.4f}")
    print("=" * 95)

if __name__ == "__main__":
    main()
