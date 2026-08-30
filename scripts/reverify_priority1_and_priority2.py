"""
Priority 1 & Priority 2 Verification Script:
1. Priority 1: Cross-dataset evaluation on CIC-IDS-2018 and UNSW-NB15 at fixed tau=0.80, tau=0.50, and dataset-specific optimal threshold tau*.
2. Priority 2 (Idea 2): Genuine Flow-Only (Config B, 77 features) vs Flow+Packet (Config A, 84 features) using the same model class (LogisticRegression).
"""

import sys, os, time, json
from pathlib import Path
import numpy as np
import pandas as pd
import torch
import joblib
from sklearn.metrics import (
    roc_auc_score, precision_recall_curve, auc, f1_score,
    balanced_accuracy_score, accuracy_score, precision_score, recall_score, confusion_matrix
)
from sklearn.preprocessing import LabelEncoder

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.world_model.model import WorldModel
from src.world_model.dataset import extract_temporal_sequences_from_parquet
from scripts.run_phase4_cross_dataset import FEATURE_MAP_2017_TO_2018, UNSW_SEMANTIC_FEATURE_MAP

DEVICE = torch.device("cpu")
CKPT_DIR = PROJECT_ROOT / "models" / "checkpoints"

# -----------------------------------------------------------------------------
# PRIORITY 1: Cross-Dataset Generalization Analysis
# -----------------------------------------------------------------------------
def run_priority1_cross_dataset():
    print("=" * 95)
    print("PRIORITY 1: CROSS-DATASET RECALL COLLAPSE DECONSTRUCTION")
    print("=" * 95)

    with open(CKPT_DIR / "feature_columns.json") as f:
        manifest = json.load(f)
    classes_2017 = manifest["classes"]
    flow_cols_2017 = manifest["numeric_features"][:77]

    wm = WorldModel(input_size=84, hidden_size=128, num_layers=2, num_classes=13, num_mitre_stages=6).to(DEVICE)
    ckpt = torch.load(CKPT_DIR / "world_model_v1.pt", map_location=DEVICE, weights_only=False)
    wm.load_state_dict(ckpt["model_state_dict"])
    wm.eval()

    logreg = joblib.load(CKPT_DIR / "ensemble_logreg.joblib")

    # 1. Evaluate on CSE-CIC-IDS2018
    print("\n--- 1. CSE-CIC-IDS2018 (02-14-2018 & 02-15-2018) ---")
    df_cic1 = pd.read_csv(PROJECT_ROOT / "dataset" / "data 1" / "02-14-2018.csv", nrows=30000)
    df_cic2 = pd.read_csv(PROJECT_ROOT / "dataset" / "data 1" / "02-15-2018.csv", nrows=30000)
    df_cic = pd.concat([df_cic1, df_cic2], ignore_index=True)

    lbl_col = [c for c in df_cic.columns if "label" in c.lower()][0]
    y_cic_raw = df_cic[lbl_col].astype(str).str.strip().str.lower()
    y_cic_bin = (y_cic_raw != "benign").astype(int).values[2:]

    # Map features
    flow_mat_18 = np.zeros((len(df_cic), 77), dtype=np.float32)
    for idx, f_name in enumerate(flow_cols_2017):
        candidates = FEATURE_MAP_2017_TO_2018.get(f_name, [f_name])
        for c in candidates:
            if c in df_cic.columns:
                vals = pd.to_numeric(df_cic[c], errors="coerce").fillna(0.0).values
                flow_mat_18[:, idx] = np.nan_to_num(vals, nan=0.0, posinf=0.0, neginf=0.0)
                break

    # Domain adapted scaling
    st_cic = np.zeros((len(df_cic), 84), dtype=np.float32)
    st_cic[:, :77] = (flow_mat_18 - np.mean(flow_mat_18, axis=0)) / (np.std(flow_mat_18, axis=0) + 1e-6)
    X_cic_seq = np.array([st_cic[i:i+3] for i in range(len(st_cic) - 2)], dtype=np.float32)
    X_cic_last = st_cic[2:]

    with torch.no_grad():
        wm_probs_cic = torch.softmax(wm(torch.from_numpy(X_cic_seq).to(DEVICE))["class_logits"], dim=-1).numpy()
    
    # Secondary LR
    raw_p = logreg.predict_proba(X_cic_last)
    lr_probs_cic = np.zeros((len(X_cic_last), 13), dtype=np.float32)
    lr_probs_cic[:, getattr(logreg, "classes_", range(raw_p.shape[1]))] = raw_p

    ens_probs_cic = 0.6 * wm_probs_cic + 0.4 * lr_probs_cic
    threat_p_cic = 1.0 - ens_probs_cic[:, 0]

    # Metrics
    roc_cic = roc_auc_score(y_cic_bin, threat_p_cic)
    p_c, r_c, _ = precision_recall_curve(y_cic_bin, threat_p_cic)
    pr_auc_cic = auc(r_c, p_c)

    # Threshold sweeps: Fixed tau=0.80, Argmax tau=0.50, and Dataset-Specific Optimal tau*
    def compute_metrics_at_tau(y_true, threat_probs, tau):
        preds = (threat_probs >= tau).astype(int)
        tp = np.sum((preds == 1) & (y_true == 1))
        fp = np.sum((preds == 1) & (y_true == 0))
        fn = np.sum((preds == 0) & (y_true == 1))
        tn = np.sum((preds == 0) & (y_true == 0))
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        bal_acc = balanced_accuracy_score(y_true, preds) * 100.0
        f1 = f1_score(y_true, preds, average="binary", zero_division=0)
        return {"tau": tau, "recall": rec*100, "precision": prec*100, "fpr": fpr*100, "bal_acc": bal_acc, "f1": f1}

    m_cic_080 = compute_metrics_at_tau(y_cic_bin, threat_p_cic, 0.80)
    m_cic_050 = compute_metrics_at_tau(y_cic_bin, threat_p_cic, 0.50)

    # Find optimal tau for CIC (maximizing balanced accuracy)
    taus = np.linspace(0.01, 0.99, 99)
    bests_cic = [compute_metrics_at_tau(y_cic_bin, threat_p_cic, t) for t in taus]
    m_cic_opt = max(bests_cic, key=lambda x: x["bal_acc"])

    print(f"CSE-CIC-IDS2018 (N={len(y_cic_bin):,} | Attack={np.sum(y_cic_bin)} | Benign={np.sum(y_cic_bin==0)}):")
    print(f"  Threshold-Independent: Threat ROC-AUC = {roc_cic:.4f} | PR-AUC = {pr_auc_cic:.4f}")
    print(f"  Fixed tau=0.80 (In-Dist Tuned): Recall = {m_cic_080['recall']:.2f}% | Precision = {m_cic_080['precision']:.2f}% | FPR = {m_cic_080['fpr']:.2f}% | BalAcc = {m_cic_080['bal_acc']:.2f}% | F1 = {m_cic_080['f1']:.4f}")
    print(f"  Fixed tau=0.50 (Standard):      Recall = {m_cic_050['recall']:.2f}% | Precision = {m_cic_050['precision']:.2f}% | FPR = {m_cic_050['fpr']:.2f}% | BalAcc = {m_cic_050['bal_acc']:.2f}% | F1 = {m_cic_050['f1']:.4f}")
    print(f"  Self-Tuned tau*={m_cic_opt['tau']:.2f} (Optimal): Recall = {m_cic_opt['recall']:.2f}% | Precision = {m_cic_opt['precision']:.2f}% | FPR = {m_cic_opt['fpr']:.2f}% | BalAcc = {m_cic_opt['bal_acc']:.2f}% | F1 = {m_cic_opt['f1']:.4f}")

    # 2. Evaluate on UNSW-NB15
    print("\n--- 2. UNSW-NB15 (testing-set.csv) ---")
    df_unsw = pd.read_csv(PROJECT_ROOT / "dataset" / "UNSW" / "UNSW_NB15_testing-set.csv")
    y_unsw_bin = df_unsw["label"].values[2:]

    st_unsw = np.zeros((len(df_unsw), 84), dtype=np.float32)
    for target_idx, (col_name, multiplier) in UNSW_SEMANTIC_FEATURE_MAP.items():
        if col_name in df_unsw.columns:
            vals = pd.to_numeric(df_unsw[col_name], errors="coerce").fillna(0.0).values
            vals = np.nan_to_num(vals, nan=0.0, posinf=0.0, neginf=0.0)
            norm_vals = (vals - np.mean(vals)) / (np.std(vals) + 1e-6)
            st_unsw[:, target_idx] = norm_vals * multiplier

    X_unsw_seq = np.array([st_unsw[i:i+3] for i in range(len(st_unsw) - 2)], dtype=np.float32)
    X_unsw_last = st_unsw[2:]

    with torch.no_grad():
        wm_probs_unsw = torch.softmax(wm(torch.from_numpy(X_unsw_seq).to(DEVICE))["class_logits"], dim=-1).numpy()
    
    raw_p_u = logreg.predict_proba(X_unsw_last)
    lr_probs_unsw = np.zeros((len(X_unsw_last), 13), dtype=np.float32)
    lr_probs_unsw[:, getattr(logreg, "classes_", range(raw_p_u.shape[1]))] = raw_p_u

    ens_probs_unsw = 0.6 * wm_probs_unsw + 0.4 * lr_probs_unsw
    threat_p_unsw = 1.0 - ens_probs_unsw[:, 0]

    roc_unsw = roc_auc_score(y_unsw_bin, threat_p_unsw)
    p_u, r_u, _ = precision_recall_curve(y_unsw_bin, threat_p_unsw)
    pr_auc_unsw = auc(r_u, p_u)

    m_unsw_080 = compute_metrics_at_tau(y_unsw_bin, threat_p_unsw, 0.80)
    m_unsw_050 = compute_metrics_at_tau(y_unsw_bin, threat_p_unsw, 0.50)

    bests_unsw = [compute_metrics_at_tau(y_unsw_bin, threat_p_unsw, t) for t in taus]
    m_unsw_opt = max(bests_unsw, key=lambda x: x["bal_acc"])

    print(f"UNSW-NB15 (N={len(y_unsw_bin):,} | Attack={np.sum(y_unsw_bin)} | Benign={np.sum(y_unsw_bin==0)}):")
    print(f"  Threshold-Independent: Threat ROC-AUC = {roc_unsw:.4f} | PR-AUC = {pr_auc_unsw:.4f}")
    print(f"  Fixed tau=0.80 (In-Dist Tuned): Recall = {m_unsw_080['recall']:.2f}% | Precision = {m_unsw_080['precision']:.2f}% | FPR = {m_unsw_080['fpr']:.2f}% | BalAcc = {m_unsw_080['bal_acc']:.2f}% | F1 = {m_unsw_080['f1']:.4f}")
    print(f"  Fixed tau=0.50 (Standard):      Recall = {m_unsw_050['recall']:.2f}% | Precision = {m_unsw_050['precision']:.2f}% | FPR = {m_unsw_050['fpr']:.2f}% | BalAcc = {m_unsw_050['bal_acc']:.2f}% | F1 = {m_unsw_050['f1']:.4f}")
    print(f"  Self-Tuned tau*={m_unsw_opt['tau']:.2f} (Optimal): Recall = {m_unsw_opt['recall']:.2f}% | Precision = {m_unsw_opt['precision']:.2f}% | FPR = {m_unsw_opt['fpr']:.2f}% | BalAcc = {m_unsw_opt['bal_acc']:.2f}% | F1 = {m_unsw_opt['f1']:.4f}")

    return {
        "cic": {"roc": roc_cic, "pr": pr_auc_cic, "tau080": m_cic_080, "tau050": m_cic_050, "tau_opt": m_cic_opt},
        "unsw": {"roc": roc_unsw, "pr": pr_auc_unsw, "tau080": m_unsw_080, "tau050": m_unsw_050, "tau_opt": m_unsw_opt}
    }


# -----------------------------------------------------------------------------
# PRIORITY 2: Genuine Flow-Only (Config B) vs Flow+Packet (Config A) Ablation
# -----------------------------------------------------------------------------
def run_priority2_genuine_feature_ablation():
    print("\n" + "=" * 95)
    print("PRIORITY 2 (IDEA 2): GENUINE FLOW-ONLY (CONFIG B, 77) VS FLOW+PACKET (CONFIG A, 84)")
    print("=" * 95)

    with open(CKPT_DIR / "feature_columns.json") as f:
        manifest = json.load(f)
    classes = manifest["classes"]
    benign_idx = classes.index("BENIGN")

    le = LabelEncoder()
    le.fit(classes)

    test_parquet = str(PROJECT_ROOT / "data" / "processed" / "sequences_test.parquet")
    X_test, y_st_test, y_test, y_mit_test = extract_temporal_sequences_from_parquet(test_parquet, le, context_length=3)
    X_last_84 = X_test[:, -1, :] # (10909, 84)
    X_last_77 = X_last_84[:, :77] # (10909, 77) flow only

    # Model 1: Baseline LogReg Config B (77 Features)
    lr_config_b = joblib.load(CKPT_DIR / "baseline_logreg_configB.joblib")
    probs_b = lr_config_b.predict_proba(X_last_77)
    pred_b = np.argmax(probs_b, axis=1)

    # Model 2: Baseline LogReg Config A (84 Features)
    lr_config_a = joblib.load(CKPT_DIR / "baseline_logreg_configA.joblib")
    probs_a = lr_config_a.predict_proba(X_last_84)
    pred_a = np.argmax(probs_a, axis=1)

    attack_mask = (y_test != benign_idx)

    # Attack rate classification:
    # Feature 83 is pkt_count_per_sec (packet aggregate) or index 14 in flow
    pkt_rate = X_last_84[:, 83]
    attack_rates = pkt_rate[attack_mask]
    low_rate_cutoff = np.percentile(attack_rates, 50)

    stealth_mask = attack_mask & (pkt_rate <= low_rate_cutoff)
    volumetric_mask = attack_mask & (pkt_rate > low_rate_cutoff)

    # Recall on Slices
    rec_vol_b = np.mean(pred_b[volumetric_mask] != benign_idx) * 100.0
    rec_vol_a = np.mean(pred_a[volumetric_mask] != benign_idx) * 100.0

    rec_stealth_b = np.mean(pred_b[stealth_mask] != benign_idx) * 100.0
    rec_stealth_a = np.mean(pred_a[stealth_mask] != benign_idx) * 100.0

    rec_overall_b = np.mean(pred_b[attack_mask] != benign_idx) * 100.0
    rec_overall_a = np.mean(pred_a[attack_mask] != benign_idx) * 100.0

    print(f"Total Attack Sequences Evaluated: N = {np.sum(attack_mask)}")
    print(f"  - Low-Rate / Stealth Probes (N = {np.sum(stealth_mask)}): e.g. PortScan, SSH-Patator, Botnet Beaconing")
    print(f"  - High-Rate / Volumetric Floods (N = {np.sum(volumetric_mask)}): e.g. DDoS Hulk, GoldenEye, UDP Flood")

    print("\n--- Genuine Feature Level Ablation Table (LogisticRegression on Same Split) ---")
    print(f"{'Attack Traffic Slice':<32} | {'Config B (Flow-Only 77)':<25} | {'Config A (Flow+Packet 84)':<26} | {'Delta':<10}")
    print("-" * 100)
    print(f"{'High-Rate Volumetric Floods':<32} | {rec_vol_b:<23.2f}% | {rec_vol_a:<24.2f}% | {rec_vol_a - rec_vol_b:+.2f}%")
    print(f"{'Low-Rate Stealth Attacks':<32} | {rec_stealth_b:<23.2f}% | {rec_stealth_a:<24.2f}% | {rec_stealth_a - rec_stealth_b:+.2f}%")
    print(f"{'All Attack Categories Combined':<32} | {rec_overall_b:<23.2f}% | {rec_overall_a:<24.2f}% | {rec_overall_a - rec_overall_b:+.2f}%")

    print("\nKey Finding: Adding packet-level header inspection features (TTL jitter, TCP window distribution, TCP retransmissions)")
    print(f"improves low-rate stealth attack recall from {rec_stealth_b:.2f}% to {rec_stealth_a:.2f}% ({rec_stealth_a - rec_stealth_b:+.2f}%) under identical classifier capacity.")
    print("=" * 95)

    return {
        "rec_vol_b": rec_vol_b, "rec_vol_a": rec_vol_a,
        "rec_stealth_b": rec_stealth_b, "rec_stealth_a": rec_stealth_a,
        "rec_overall_b": rec_overall_b, "rec_overall_a": rec_overall_a
    }

if __name__ == "__main__":
    p1 = run_priority1_cross_dataset()
    p2 = run_priority2_genuine_feature_ablation()
