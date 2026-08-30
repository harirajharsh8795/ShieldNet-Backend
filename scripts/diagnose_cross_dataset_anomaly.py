"""
Diagnostic script for Phase 4 Cross-Dataset ROC-AUC Anomaly.

Inspects:
1. Label encoding exact definitions for 2018 and UNSW
2. Probability channel feeding roc_auc_score
3. 10-sample inspection (5 benign, 5 attack) on CSE-CIC-IDS2018 with full logits & probs
4. 10-sample inspection (5 benign, 5 attack) on UNSW-NB15 with full logits & probs
5. Evaluates if the correlation between ground-truth threat and P(attack) is inverted by domain shift.
"""

import sys, os, json
from pathlib import Path
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import roc_auc_score, precision_recall_curve

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.world_model.model import WorldModel
from scripts.run_phase4_cross_dataset import FEATURE_MAP_2017_TO_2018, UNSW_SEMANTIC_FEATURE_MAP

def main():
    device = torch.device("cpu")
    ckpt_path = PROJECT_ROOT / "models" / "checkpoints" / "world_model_v1.pt"
    ckpt = torch.load(ckpt_path, map_location=device, weights_only=False)
    model = WorldModel(input_size=84, hidden_size=128, num_layers=2, num_classes=13, num_mitre_stages=6).to(device)
    model.load_state_dict(ckpt["model_state_dict"])
    model.eval()
    
    with open(PROJECT_ROOT / "models" / "checkpoints" / "feature_columns.json") as f:
        manifest = json.load(f)
    classes = manifest["classes"]
    flow_cols_2017 = manifest["numeric_features"][:77]
    
    print("=" * 90)
    print("1. LABEL ENCODING & PROBABILITY CHANNEL VERIFICATION")
    print("=" * 90)
    print(f"Index 0 Class Name in Manifest: '{classes[0]}' (Must be BENIGN -> 0)")
    print(f"Attack Classes (Indices 1..12): {classes[1:]}")
    print("Formula used: P(Attack) = 1.0 - softmax(logits)[:, 0] = sum(softmax(logits)[:, 1:])")
    
    # ─── 2. CSE-CIC-IDS2018 INSPECTION ─────────────────────────────────────────
    print("\n" + "=" * 90)
    print("2. CSE-CIC-IDS2018: 10-SAMPLE MANUAL INSPECTION (5 Benign, 5 Attack)")
    print("=" * 90)
    df_cic = pd.read_csv(PROJECT_ROOT / "dataset" / "data 1" / "02-14-2018.csv")
    lbl_col = [c for c in df_cic.columns if "label" in c.lower()][0]
    
    # Pick 5 benign and 5 attack rows
    benign_rows = df_cic[df_cic[lbl_col].str.strip().str.lower() == "benign"].head(10)
    attack_rows = df_cic[df_cic[lbl_col].str.strip().str.lower() != "benign"].head(10)
    
    inspect_df = pd.concat([benign_rows.iloc[2:7], attack_rows.iloc[2:7]], ignore_index=True)
    
    # Map features for these rows (using domain-adapted standardization)
    flow_mat_18 = np.zeros((len(df_cic), 77), dtype=np.float32)
    for idx, f_name in enumerate(flow_cols_2017):
        candidates = FEATURE_MAP_2017_TO_2018.get(f_name, [f_name])
        for c in candidates:
            if c in df_cic.columns:
                vals = pd.to_numeric(df_cic[c], errors="coerce").fillna(0.0).values
                flow_mat_18[:, idx] = np.nan_to_num(vals, nan=0.0, posinf=0.0, neginf=0.0)
                break
                
    st_cic_norm = (flow_mat_18 - np.mean(flow_mat_18, axis=0)) / (np.std(flow_mat_18, axis=0) + 1e-6)
    st_cic_84 = np.zeros((len(df_cic), 84), dtype=np.float32)
    st_cic_84[:, :77] = st_cic_norm
    
    # Indices in inspect_df
    inspect_indices = list(benign_rows.index[2:7]) + list(attack_rows.index[2:7])
    
    for rank, row_idx in enumerate(inspect_indices):
        raw_lbl = df_cic.loc[row_idx, lbl_col]
        true_binary = 0 if str(raw_lbl).strip().lower() == "benign" else 1
        
        # Build 3-step sequence ending at row_idx
        if row_idx >= 2:
            seq = st_cic_84[row_idx-2:row_idx+1][np.newaxis, ...]
        else:
            seq = np.repeat(st_cic_84[row_idx:row_idx+1], 3, axis=0)[np.newaxis, ...]
            
        with torch.no_grad():
            out = model(torch.from_numpy(seq).to(device))
            logits = out["class_logits"][0].numpy()
            probs = torch.softmax(out["class_logits"], dim=-1)[0].numpy()
            
        p_benign = probs[0]
        p_attack = 1.0 - p_benign
        pred_cls = classes[np.argmax(probs)]
        
        type_str = "BENIGN" if true_binary == 0 else "ATTACK"
        print(f"Sample {rank+1:2d} | True: {type_str:<6} ('{raw_lbl}') | P(Benign): {p_benign:6.4f} | P(Attack): {p_attack:6.4f} | Top Class: {pred_cls}")
        
    # ─── 3. UNSW-NB15 INSPECTION ───────────────────────────────────────────────
    print("\n" + "=" * 90)
    print("3. UNSW-NB15: 10-SAMPLE MANUAL INSPECTION (5 Benign, 5 Attack)")
    print("=" * 90)
    df_unsw = pd.read_csv(PROJECT_ROOT / "dataset" / "UNSW" / "UNSW_NB15_testing-set.csv")
    
    benign_unsw = df_unsw[df_unsw["label"] == 0].head(10)
    attack_unsw = df_unsw[df_unsw["label"] == 1].head(10)
    
    inspect_unsw_indices = list(benign_unsw.index[2:7]) + list(attack_unsw.index[2:7])
    
    # Extract semantic features for full dataset
    st_unsw_sem = np.zeros((len(df_unsw), 84), dtype=np.float32)
    for target_idx, (col_name, multiplier) in UNSW_SEMANTIC_FEATURE_MAP.items():
        if col_name in df_unsw.columns:
            vals = pd.to_numeric(df_unsw[col_name], errors="coerce").fillna(0.0).values
            vals = np.nan_to_num(vals, nan=0.0, posinf=0.0, neginf=0.0)
            st_unsw_sem[:, target_idx] = (vals - np.mean(vals)) / (np.std(vals) + 1e-6) * multiplier
            
    for rank, row_idx in enumerate(inspect_unsw_indices):
        raw_lbl = df_unsw.loc[row_idx, "attack_cat"] if "attack_cat" in df_unsw.columns else "Attack"
        true_binary = int(df_unsw.loc[row_idx, "label"])
        
        seq = st_unsw_sem[row_idx-2:row_idx+1][np.newaxis, ...]
        with torch.no_grad():
            out = model(torch.from_numpy(seq).to(device))
            probs = torch.softmax(out["class_logits"], dim=-1)[0].numpy()
            
        p_benign = probs[0]
        p_attack = 1.0 - p_benign
        pred_cls = classes[np.argmax(probs)]
        type_str = "BENIGN" if true_binary == 0 else "ATTACK"
        print(f"Sample {rank+1:2d} | True: {type_str:<6} ('{raw_lbl}') | P(Benign): {p_benign:6.4f} | P(Attack): {p_attack:6.4f} | Top Class: {pred_cls}")
        
    # ─── 4. FULL STATISTICAL DISTRIBUTION ANALYSIS ─────────────────────────────
    print("\n" + "=" * 90)
    print("4. FULL STATISTICAL THREAT PROBABILITY COMPARISON")
    print("=" * 90)
    
    # Compute full dataset P(attack) distributions
    X_cic_adapted = np.array([st_cic_84[i:i+3] for i in range(min(5000, len(st_cic_84) - 2))], dtype=np.float32)
    y_cic_sub = (df_cic[lbl_col].str.strip().str.lower() != "benign").astype(int).values[2:2+len(X_cic_adapted)]
    
    with torch.no_grad():
        p_cic_attack = (1.0 - torch.softmax(model(torch.from_numpy(X_cic_adapted).to(device))["class_logits"], dim=-1)[:, 0]).numpy()
        
    mean_p_attack_on_benign_cic = np.mean(p_cic_attack[y_cic_sub == 0])
    mean_p_attack_on_attack_cic = np.mean(p_cic_attack[y_cic_sub == 1])
    
    print("CSE-CIC-IDS2018 (First 5,000 Flows):")
    print(f"  Mean P(Attack) given True BENIGN: {mean_p_attack_on_benign_cic:.4f}")
    print(f"  Mean P(Attack) given True ATTACK: {mean_p_attack_on_attack_cic:.4f}")
    print(f"  Distribution Separation Delta:    {mean_p_attack_on_attack_cic - mean_p_attack_on_benign_cic:+.4f}")
    
    X_unsw_sub = np.array([st_unsw_sem[i:i+3] for i in range(min(5000, len(st_unsw_sem) - 2))], dtype=np.float32)
    y_unsw_sub = df_unsw["label"].values[2:2+len(X_unsw_sub)]
    with torch.no_grad():
        p_unsw_attack = (1.0 - torch.softmax(model(torch.from_numpy(X_unsw_sub).to(device))["class_logits"], dim=-1)[:, 0]).numpy()
        
    mean_p_attack_on_benign_unsw = np.mean(p_unsw_attack[y_unsw_sub == 0])
    mean_p_attack_on_attack_unsw = np.mean(p_unsw_attack[y_unsw_sub == 1])
    print("\nUNSW-NB15 (First 5,000 Flows):")
    print(f"  Mean P(Attack) given True BENIGN: {mean_p_attack_on_benign_unsw:.4f}")
    print(f"  Mean P(Attack) given True ATTACK: {mean_p_attack_on_attack_unsw:.4f}")
    print(f"  Distribution Separation Delta:    {mean_p_attack_on_attack_unsw - mean_p_attack_on_benign_unsw:+.4f}")
    print("=" * 90)

if __name__ == "__main__":
    main()
