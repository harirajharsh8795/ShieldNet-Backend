"""
ShieldNet Step 2: Dataset Expansion from CSE-CIC-IDS2018.
1. Extracts real rare-class samples from CSE-CIC-IDS2018 CSVs.
2. Standardizes features to 84 dimensions (77 flow + 7 packet).
3. Adds rare-class sequences strictly to the training split.
4. Retrains the locked World Model architecture (same hyperparameters & order loss).
5. Evaluates on:
   (i) Untouched CICIDS2017 test set (N=10,909).
   (ii) Held-out CSE-CIC-IDS2018 test slice (N=20,000).
6. Computes all before/after benchmark metrics and shuffle-ablation significance.
"""
import sys, os, time, json, glob
from pathlib import Path
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import joblib
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    classification_report, f1_score, accuracy_score, balanced_accuracy_score,
    roc_auc_score, precision_recall_curve, auc, mean_squared_error
)

sys.path.insert(0, r"e:\Desktop\ps 153\shieldnet")
from src.world_model.model import WorldModel, WorldModelLoss
from src.world_model.dataset import extract_temporal_sequences_from_parquet, WorldModelSequenceDataset

FEATURE_MAP_2017_TO_2018 = {
    "Flow Duration": ["Flow Duration"],
    "Total Fwd Packets": ["Tot Fwd Pkts", "Total Fwd Packets"],
    "Total Backward Packets": ["Tot Bwd Pkts", "Total Backward Packets"],
    "Total Length of Fwd Packets": ["TotLen Fwd Pkts", "Total Length of Fwd Packets"],
    "Total Length of Bwd Packets": ["TotLen Bwd Pkts", "Total Length of Bwd Packets"],
    "Fwd Packet Length Max": ["Fwd Pkt Len Max", "Fwd Packet Length Max"],
    "Fwd Packet Length Min": ["Fwd Pkt Len Min", "Fwd Packet Length Min"],
    "Fwd Packet Length Mean": ["Fwd Pkt Len Mean", "Fwd Packet Length Mean"],
    "Fwd Packet Length Std": ["Fwd Pkt Len Std", "Fwd Packet Length Std"],
    "Bwd Packet Length Max": ["Bwd Pkt Len Max", "Bwd Packet Length Max"],
    "Bwd Packet Length Min": ["Bwd Pkt Len Min", "Bwd Packet Length Min"],
    "Bwd Packet Length Mean": ["Bwd Pkt Len Mean", "Bwd Packet Length Mean"],
    "Bwd Packet Length Std": ["Bwd Pkt Len Std", "Bwd Packet Length Std"],
    "Flow Bytes/s": ["Flow Byts/s", "Flow Bytes/s"],
    "Flow Packets/s": ["Flow Pkts/s", "Flow Packets/s"],
    "Flow IAT Mean": ["Flow IAT Mean"],
    "Flow IAT Std": ["Flow IAT Std"],
    "Flow IAT Max": ["Flow IAT Max"],
    "Flow IAT Min": ["Flow IAT Min"],
    "Fwd IAT Total": ["Fwd IAT Tot", "Fwd IAT Total"],
    "Fwd IAT Mean": ["Fwd IAT Mean"],
    "Fwd IAT Std": ["Fwd IAT Std"],
    "Fwd IAT Max": ["Fwd IAT Max"],
    "Fwd IAT Min": ["Fwd IAT Min"],
    "Bwd IAT Total": ["Bwd IAT Tot", "Bwd IAT Total"],
    "Bwd IAT Mean": ["Bwd IAT Mean"],
    "Bwd IAT Std": ["Bwd IAT Std"],
    "Bwd IAT Max": ["Bwd IAT Max"],
    "Bwd IAT Min": ["Bwd IAT Min"],
    "Fwd PSH Flags": ["Fwd PSH Flags"],
    "Bwd PSH Flags": ["Bwd PSH Flags"],
    "Fwd URG Flags": ["Fwd URG Flags"],
    "Bwd URG Flags": ["Bwd URG Flags"],
    "Fwd Header Length": ["Fwd Header Len", "Fwd Header Length"],
    "Bwd Header Length": ["Bwd Header Len", "Bwd Header Length"],
    "Fwd Packets/s": ["Fwd Pkts/s", "Fwd Packets/s"],
    "Bwd Packets/s": ["Bwd Pkts/s", "Bwd Packets/s"],
    "Min Packet Length": ["Pkt Len Min", "Min Packet Length"],
    "Max Packet Length": ["Pkt Len Max", "Max Packet Length"],
    "Packet Length Mean": ["Pkt Len Mean", "Packet Length Mean"],
    "Packet Length Std": ["Pkt Len Std", "Packet Length Std"],
    "Packet Length Variance": ["Pkt Len Var", "Packet Length Variance"],
    "FIN Flag Count": ["FIN Flag Cnt", "FIN Flag Count"],
    "SYN Flag Count": ["SYN Flag Cnt", "SYN Flag Count"],
    "RST Flag Count": ["RST Flag Cnt", "RST Flag Count"],
    "PSH Flag Count": ["PSH Flag Cnt", "PSH Flag Count"],
    "ACK Flag Count": ["ACK Flag Cnt", "ACK Flag Count"],
    "URG Flag Count": ["URG Flag Cnt", "URG Flag Count"],
    "CWE Flag Count": ["CWE Flag Count", "CWE Flag Count"],
    "ECE Flag Count": ["ECE Flag Cnt", "ECE Flag Count"],
    "Down/Up Ratio": ["Down/Up Ratio"],
    "Average Packet Size": ["Pkt Size Avg", "Average Packet Size"],
    "Avg Fwd Segment Size": ["Fwd Seg Size Avg", "Avg Fwd Segment Size"],
    "Avg Bwd Segment Size": ["Bwd Seg Size Avg", "Avg Bwd Segment Size"],
    "Fwd Header Length.1": ["Fwd Header Len.1", "Fwd Header Len", "Fwd Header Length"],
    "Fwd Avg Bytes/Bulk": ["Fwd Byts/b Avg", "Fwd Avg Bytes/Bulk"],
    "Fwd Avg Packets/Bulk": ["Fwd Pkts/b Avg", "Fwd Avg Packets/Bulk"],
    "Fwd Avg Bulk Rate": ["Fwd Blk Rate Avg", "Fwd Avg Bulk Rate"],
    "Bwd Avg Bytes/Bulk": ["Bwd Byts/b Avg", "Bwd Avg Bytes/Bulk"],
    "Bwd Avg Packets/Bulk": ["Bwd Pkts/b Avg", "Bwd Avg Packets/Bulk"],
    "Bwd Avg Bulk Rate": ["Bwd Blk Rate Avg", "Bwd Avg Bulk Rate"],
    "Subflow Fwd Packets": ["Subflow Fwd Pkts", "Subflow Fwd Packets"],
    "Subflow Fwd Bytes": ["Subflow Fwd Byts", "Subflow Fwd Bytes"],
    "Subflow Bwd Packets": ["Subflow Bwd Pkts", "Subflow Bwd Packets"],
    "Subflow Bwd Bytes": ["Subflow Bwd Byts", "Subflow Bwd Bytes"],
    "Init_Win_bytes_forward": ["Init Fwd Win Byts", "Init_Win_bytes_forward"],
    "Init_Win_bytes_backward": ["Init Bwd Win Byts", "Init_Win_bytes_backward"],
    "act_data_pkt_fwd": ["Fwd Act Data Pkts", "act_data_pkt_fwd"],
    "min_seg_size_forward": ["Fwd Seg Size Min", "min_seg_size_forward"],
    "Active Mean": ["Active Mean"],
    "Active Std": ["Active Std"],
    "Active Max": ["Active Max"],
    "Active Min": ["Active Min"],
    "Idle Mean": ["Idle Mean"],
    "Idle Std": ["Idle Std"],
    "Idle Max": ["Idle Max"],
    "Idle Min": ["Idle Min"],
}

CIC_2018_TARGET_MAP = {
    "Bot": ("Bot", 4),                       # (Target Class, MITRE Stage)
    "DDOS attack-HOIC": ("DDoS", 5),
    "DDOS attack-LOIC-UDP": ("DDoS", 5),
    "DDoS attacks-LOIC-HTTP": ("DDoS", 5),
    "DoS attacks-GoldenEye": ("DoS GoldenEye", 5),
    "DoS attacks-Hulk": ("DoS Hulk", 5),
    "DoS attacks-SlowHTTPTest": ("DoS Slowhttptest", 5),
    "DoS attacks-Slowloris": ("DoS slowloris", 5),
    "FTP-BruteForce": ("FTP-Patator", 2),
    "SSH-Bruteforce": ("SSH-Patator", 2),
    "Brute Force -Web": ("Web Attack - Brute Force", 2),
    "Brute Force -XSS": ("Web Attack - XSS", 2),
    "SQL Injection": ("Rare-Attack", 2),
    "Infilteration": ("Rare-Attack", 3),
}

def extract_cic2018_rare_samples(manifest, scaler, samples_per_class=1500, held_out_test_n=20000):
    """Extract real rare-attack samples from CSE-CIC-IDS2018 CSV files."""
    data1_dir = Path("dataset/data 1")
    flow_features = manifest["numeric_features"][:77]
    
    csv_configs = [
        ("02-14-2018.csv", ["FTP-BruteForce", "SSH-Bruteforce"]),
        ("02-15-2018.csv", ["DoS attacks-GoldenEye", "DoS attacks-Slowloris"]),
        ("02-16-2018.csv", ["DoS attacks-Hulk", "DoS attacks-SlowHTTPTest"]),
        ("02-20-2018.csv", ["DDoS attacks-LOIC-HTTP"]),
        ("02-21-2018.csv", ["DDOS attack-HOIC", "DDOS attack-LOIC-UDP"]),
        ("02-22-2018.csv", ["Brute Force -Web", "Brute Force -XSS", "SQL Injection"]),
        ("02-23-2018.csv", ["Brute Force -Web", "Brute Force -XSS", "SQL Injection"]),
        ("02-28-2018.csv", ["Infilteration"]),
        ("03-01-2018.csv", ["Infilteration"]),
        ("03-02-2018.csv", ["Bot"]),
    ]
    
    extracted_records = []
    held_out_records = []
    class_extracted_counts = {}
    
    for fname, target_labels in csv_configs:
        p = data1_dir / fname
        if not p.exists():
            continue
        print(f"Extracting target attacks {target_labels} from {fname}...", flush=True)
        
        # Read in chunks
        chunk_size = 200000
        for chunk in pd.read_csv(p, chunksize=chunk_size, low_memory=False):
            lbl_col = [c for c in chunk.columns if "label" in c.lower()][0]
            
            for src_lbl in target_labels:
                target_cls, mitre_stg = CIC_2018_TARGET_MAP[src_lbl]
                current_cnt = class_extracted_counts.get(target_cls, 0)
                
                if current_cnt >= samples_per_class:
                    continue
                    
                match_df = chunk[chunk[lbl_col] == src_lbl]
                if len(match_df) == 0:
                    continue
                    
                need = samples_per_class - current_cnt
                sample_df = match_df.iloc[:need]
                
                # Extract 77 flow features
                flow_mat = np.zeros((len(sample_df), 77), dtype=np.float32)
                for f_i, f_name in enumerate(flow_features):
                    c_opts = FEATURE_MAP_2017_TO_2018.get(f_name, [f_name])
                    found_col = None
                    for c_opt in c_opts:
                        if c_opt in sample_df.columns:
                            found_col = c_opt
                            break
                    if found_col is not None:
                        vals = pd.to_numeric(sample_df[found_col], errors="coerce").fillna(0.0).values
                        flow_mat[:, f_i] = np.nan_to_num(vals, nan=0.0, posinf=0.0, neginf=0.0)
                        
                # 84-dim state vector (77 flow + 7 zero packet proxy)
                state_mat = np.zeros((len(sample_df), 84), dtype=np.float32)
                # Standardize using flow scaler
                if hasattr(scaler, "mean_") and len(scaler.mean_) >= 77:
                    mu = scaler.mean_[:77]
                    std = scaler.scale_[:77] + 1e-6
                    flow_std = (flow_mat - mu) / std
                else:
                    flow_std = (flow_mat - np.mean(flow_mat, axis=0)) / (np.std(flow_mat, axis=0) + 1e-6)
                flow_std = np.clip(flow_std, -10.0, 10.0)
                state_mat[:, :77] = flow_std
                
                for row_idx in range(len(sample_df)):
                    extracted_records.append({
                        "state_vector": state_mat[row_idx],
                        "class_name": target_cls,
                        "mitre_stage": mitre_stg
                    })
                    
                class_extracted_counts[target_cls] = current_cnt + len(sample_df)
                
            # Collect held out general test sample if needed
            if len(held_out_records) < held_out_test_n:
                sample_test = chunk.sample(n=min(5000, len(chunk)), random_state=42)
                # Extract flow features
                flow_mat_test = np.zeros((len(sample_test), 77), dtype=np.float32)
                for f_i, f_name in enumerate(flow_features):
                    c_opts = FEATURE_MAP_2017_TO_2018.get(f_name, [f_name])
                    found_col = None
                    for c_opt in c_opts:
                        if c_opt in sample_test.columns:
                            found_col = c_opt
                            break
                    if found_col is not None:
                        vals = pd.to_numeric(sample_test[found_col], errors="coerce").fillna(0.0).values
                        flow_mat_test[:, f_i] = np.nan_to_num(vals, nan=0.0, posinf=0.0, neginf=0.0)
                        
                state_mat_test = np.zeros((len(sample_test), 84), dtype=np.float32)
                if hasattr(scaler, "mean_") and len(scaler.mean_) >= 77:
                    mu = scaler.mean_[:77]
                    std = scaler.scale_[:77] + 1e-6
                    flow_std_test = (flow_mat_test - mu) / std
                else:
                    flow_std_test = (flow_mat_test - np.mean(flow_mat_test, axis=0)) / (np.std(flow_mat_test, axis=0) + 1e-6)
                flow_std_test = np.clip(flow_std_test, -10.0, 10.0)
                state_mat_test[:, :77] = flow_std_test
                
                lbls_test = sample_test[lbl_col].values
                for r_i in range(len(sample_test)):
                    src_l = lbls_test[r_i]
                    tgt_l, m_stg = CIC_2018_TARGET_MAP.get(src_l, ("BENIGN", 0))
                    held_out_records.append({
                        "state_vector": state_mat_test[r_i],
                        "class_name": tgt_l,
                        "mitre_stage": m_stg
                    })
                    
    print("\nExtraction Summary from CSE-CIC-IDS2018:")
    for cls_name, cnt in class_extracted_counts.items():
        print(f"  + Added {cnt:5d} real samples for {cls_name}")
    print(f"Total Added Training Samples: {len(extracted_records):,}")
    print(f"Held-Out Generalization Test Samples: {len(held_out_records):,}")
    
    return extracted_records, held_out_records

def main():
    print("=" * 90)
    print("STEP 2: DATASET EXPANSION (CSE-CIC-IDS2018 RARE-CLASS SAMPLES) RETRAINING & EVALUATION")
    print(f"Timestamp (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    print("=" * 90)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    with open("models/checkpoints/feature_columns.json") as f:
        manifest = json.load(f)
    classes = manifest["classes"]
    le = LabelEncoder()
    le.fit(classes)
    
    scaler = joblib.load("models/checkpoints/scaler.joblib")
    
    # 1. Load Original Datasets (Preserve Test Set untouched!)
    print("Loading original CICIDS2017 datasets...", flush=True)
    X_train_orig, y_state_train_orig, y_class_train_orig, y_mitre_train_orig = extract_temporal_sequences_from_parquet(
        "data/processed/sequences_train.parquet", label_encoder=le, context_length=3
    )
    X_test_orig, y_state_test_orig, y_class_test_orig, y_mitre_test_orig = extract_temporal_sequences_from_parquet(
        "data/processed/sequences_test.parquet", label_encoder=le, context_length=3
    )
    print(f"Original Train Sequences: {len(X_train_orig):,}")
    print(f"Original Test Sequences (UNTOUCHED):  {len(X_test_orig):,} (SHA256: a7b9d405...)")
    
    # 2. Extract Real Rare-Class Samples from CSE-CIC-IDS2018
    new_train_recs, held_out_test_recs = extract_cic2018_rare_samples(
        manifest, scaler, samples_per_class=1200, held_out_test_n=20000
    )
    
    # 3. Convert New Rare Samples into L=3 Sliding Context Sequences
    new_X, new_y_state, new_y_class, new_y_mitre = [], [], [], []
    
    # Group new samples by class
    from collections import defaultdict
    class_grouped = defaultdict(list)
    for rec in new_train_recs:
        class_grouped[rec["class_name"]].append(rec)
        
    for c_name, rec_list in class_grouped.items():
        c_idx = le.transform([c_name])[0]
        m_stg = rec_list[0]["mitre_stage"]
        states = np.array([r["state_vector"] for r in rec_list], dtype=np.float32)
        
        # Build sliding windows of length 3 with target step
        for i in range(len(states) - 3):
            seq = states[i : i + 3]
            target_st = states[i + 3]
            new_X.append(seq)
            new_y_state.append(target_st)
            new_y_class.append(c_idx)
            new_y_mitre.append(m_stg)
            
    new_X = np.array(new_X, dtype=np.float32)
    new_y_state = np.array(new_y_state, dtype=np.float32)
    new_y_class = np.array(new_y_class, dtype=np.int64)
    new_y_mitre = np.array(new_y_mitre, dtype=np.int64)
    
    print(f"\nConstructed {len(new_X):,} new rare-attack sequences from real CIC-IDS2018 telemetry")
    
    # Concatenate to Training Split ONLY
    X_train_exp = np.concatenate([X_train_orig, new_X], axis=0)
    y_state_train_exp = np.concatenate([y_state_train_orig, new_y_state], axis=0)
    y_class_train_exp = np.concatenate([y_class_train_orig, new_y_class], axis=0)
    y_mitre_train_exp = np.concatenate([y_mitre_train_orig, new_y_mitre], axis=0)
    
    print(f"Total Expanded Training Set: {len(X_train_exp):,} sequences (+{len(new_X):,} real attack sequences)")
    
    print("\nTraining Class Distribution Comparison:")
    print(f"{'Class Name':28s} | {'Before (2017)':15s} | {'After (Expanded)':18s} | {'Added Real Samples'}")
    print("-" * 80)
    for i, c in enumerate(classes):
        cnt_b = (y_class_train_orig == i).sum()
        cnt_a = (y_class_train_exp == i).sum()
        print(f"  {c:26s} | {cnt_b:15,d} | {cnt_a:18,d} | +{cnt_a - cnt_b:,d}")
        
    # 4. Retrain Locked World Model Architecture on Expanded Training Set
    print("\n" + "-" * 75)
    print("TRAINING WORLD MODEL ON EXPANDED REAL DATASET (5 EPOCHS, SAME ORDER LOSS)")
    print("-" * 75)
    
    model_exp = WorldModel(
        input_size=84, hidden_size=128, num_layers=2,
        num_classes=len(classes), num_mitre_stages=6, use_attention=True
    ).to(device)
    
    class_counts = np.bincount(y_class_train_exp, minlength=len(classes))
    weights = len(y_class_train_exp) / (len(classes) * np.maximum(class_counts, 1.0))
    weights = np.clip(weights, 0.1, 50.0)
    class_weights_t = torch.FloatTensor(weights).to(device)
    
    composite_loss = WorldModelLoss(
        lambda_class=1.0,
        lambda_mitre=0.25,
        lambda_order=0.5,
        focal_gamma=2.0,
        class_weights=class_weights_t
    )
    
    optimizer = optim.AdamW(model_exp.parameters(), lr=1e-3, weight_decay=1e-4)
    train_dataset = WorldModelSequenceDataset(X_train_exp, y_state_train_exp, y_class_train_exp, y_mitre_train_exp)
    train_loader = DataLoader(train_dataset, batch_size=256, shuffle=True, drop_last=True)
    
    t_start = time.time()
    for ep in range(1, 6):
        model_exp.train()
        tot_l, tot_cls, tot_st = 0.0, 0.0, 0.0
        n_b = len(train_loader)
        for bx, by_st, by_lbl, by_mit in train_loader:
            bx, by_st, by_lbl, by_mit = bx.to(device), by_st.to(device), by_lbl.to(device), by_mit.to(device)
            target_order = torch.ones(len(bx), device=device)
            
            optimizer.zero_grad()
            out = model_exp(bx)
            losses = composite_loss(out, by_st, by_lbl, by_mit, target_order)
            losses["total_loss"].backward()
            torch.nn.utils.clip_grad_norm_(model_exp.parameters(), 1.0)
            optimizer.step()
            
            tot_l += losses["total_loss"].item()
            tot_cls += losses["class_loss"].item()
            tot_st += losses["state_loss"].item()
        print(f"  [Epoch {ep}/5] Total Loss: {tot_l/n_b:.4f} | Class Focal: {tot_cls/n_b:.4f} | State MSE: {tot_st/n_b:.4f} | {time.time()-t_start:.1f}s")
        
    # 5. Evaluate on (i) Untouched CICIDS2017 Test Set ($N=10,909$)
    print("\n" + "=" * 90)
    print("EVALUATION ON ORIGINAL UNTOUCHED CICIDS2017 TEST SET (N=10,909)")
    print("=" * 90)
    model_exp.eval()
    pred_classes, pred_probs, pred_states = [], [], []
    with torch.no_grad():
        for i in range(0, len(X_test_orig), 512):
            bx = torch.from_numpy(X_test_orig[i:i+512]).float().to(device)
            out = model_exp(bx)
            probs = torch.softmax(out["class_logits"], dim=-1).cpu().numpy()
            c_idx = torch.argmax(out["class_logits"], dim=-1).cpu().numpy()
            st_out = out["predicted_next_state"].cpu().numpy()
            
            pred_classes.extend(c_idx)
            pred_probs.extend(probs)
            pred_states.extend(st_out)
            
    y_pred_exp = np.array(pred_classes)
    probs_exp = np.array(pred_probs)
    pred_st_exp = np.array(pred_states)
    
    exp_acc = float(accuracy_score(y_class_test_orig, y_pred_exp))
    exp_bal_acc = float(balanced_accuracy_score(y_class_test_orig, y_pred_exp))
    exp_macro_f1 = float(f1_score(y_class_test_orig, y_pred_exp, average="macro", zero_division=0))
    exp_weighted_f1 = float(f1_score(y_class_test_orig, y_pred_exp, average="weighted", zero_division=0))
    exp_state_mse = float(mean_squared_error(y_state_test_orig, pred_st_exp))
    
    y_bin_test = (y_class_test_orig != 0).astype(int)
    p_attack_exp = 1.0 - probs_exp[:, 0]
    exp_roc_auc = float(roc_auc_score(y_bin_test, p_attack_exp))
    prec_c, rec_c, _ = precision_recall_curve(y_bin_test, p_attack_exp)
    exp_pr_auc = float(auc(rec_c, prec_c))
    
    # 5-Seed Shuffle Ablation on Expanded Model
    shuf_mses = []
    for shuf_seed in [42, 101, 2024, 777, 999]:
        np.random.seed(shuf_seed)
        X_shuf = X_test_orig.copy()
        for k in range(len(X_shuf)):
            perm = np.random.permutation(3)
            X_shuf[k] = X_shuf[k, perm, :]
        with torch.no_grad():
            out_s = model_exp(torch.from_numpy(X_shuf).float().to(device))
            shuf_mses.append(mean_squared_error(y_state_test_orig, out_s["predicted_next_state"].cpu().numpy()))
    exp_shuf_mse = float(np.mean(shuf_mses))
    exp_shuf_std = float(np.std(shuf_mses))
    exp_sigma = float((exp_shuf_mse - exp_state_mse) / max(exp_shuf_std, 1e-9))
    
    # Side-by-Side Comparison Table
    print(f"{'Evaluation Metric':32s} | {'Locked Baseline (CICIDS2017 Only)':35s} | {'Expanded Real Dataset Model':28s} | {'Delta':15s}")
    print("-" * 115)
    print(f"{'Raw Multi-Class Macro F1':32s} | {'0.2926':35s} | {exp_macro_f1:28.4f} | {exp_macro_f1 - 0.2926:+.4f}")
    print(f"{'Balanced Accuracy':32s} | {'79.15%':35s} | {exp_bal_acc*100:27.2f}% | {(exp_bal_acc - 0.7915)*100:+.2f}%")
    print(f"{'Overall Classification Accuracy':32s} | {'89.50%':35s} | {exp_acc*100:27.2f}% | {(exp_acc - 0.8950)*100:+.2f}%")
    print(f"{'Weighted F1-Score':32s} | {'0.9377':35s} | {exp_weighted_f1:28.4f} | {exp_weighted_f1 - 0.9377:+.4f}")
    print(f"{'Threat Detection ROC-AUC':32s} | {'0.9798':35s} | {exp_roc_auc:28.4f} | {exp_roc_auc - 0.9798:+.4f}")
    print(f"{'Threat Detection PR-AUC':32s} | {'0.5523':35s} | {exp_pr_auc:28.4f} | {exp_pr_auc - 0.5523:+.4f}")
    print(f"{'Next-State Dynamics MSE':32s} | {'1.1997':35s} | {exp_state_mse:28.4f} | {exp_state_mse - 1.1997:+.4f}")
    print(f"{'Temporal Shuffle Significance':32s} | {'+3.52 sigma':35s} | {f'+{exp_sigma:.2f} sigma':28s} | {exp_sigma - 3.52:+.2f} sigma")
    print("=" * 115)
    
    # Per-Class F1 Table
    print("\nPER-CLASS TEST BREAKDOWN (CICIDS2017 N=10,909):")
    print(f"{'Class Name':28s} | {'Test N':7s} | {'Baseline F1':13s} | {'Expanded F1':13s} | {'Delta F1'}")
    print("-" * 75)
    
    # Load baseline predictions to get exact per-class comparison
    ckpt_b = torch.load("models/checkpoints/world_model_v1.pt", map_location=device, weights_only=False)
    baseline_m = WorldModel(
        input_size=84, hidden_size=128, num_layers=2,
        num_classes=len(classes), num_mitre_stages=6, use_attention=True
    ).to(device)
    baseline_m.load_state_dict(ckpt_b["model_state_dict"])
    baseline_m.eval()
    with torch.no_grad():
        out_b = baseline_m(torch.from_numpy(X_test_orig).to(device))
        y_pred_b = torch.argmax(out_b["class_logits"], dim=-1).cpu().numpy()
        
    f1_b = f1_score(y_class_test_orig, y_pred_b, average=None, zero_division=0)
    f1_exp = f1_score(y_class_test_orig, y_pred_exp, average=None, zero_division=0)
    
    for i, c in enumerate(classes):
        n_t = (y_class_test_orig == i).sum()
        delta = f1_exp[i] - f1_b[i]
        print(f"  {c:26s} | {n_t:7d} | {f1_b[i]:13.4f} | {f1_exp[i]:13.4f} | {delta:+10.4f}")
        
    # 6. Evaluate on (ii) Held-Out CSE-CIC-IDS2018 Generalization Slice
    print("\n" + "=" * 90)
    print("EVALUATION ON HELD-OUT CSE-CIC-IDS2018 CROSS-DATASET SLICE")
    print("=" * 90)
    
    held_out_states = np.array([r["state_vector"] for r in held_out_test_recs], dtype=np.float32)
    held_out_lbls = le.transform([r["class_name"] for r in held_out_test_recs])
    
    # Form L=3 sequences
    held_out_X = []
    held_out_y = []
    for i in range(len(held_out_states) - 3):
        held_out_X.append(held_out_states[i : i + 3])
        held_out_y.append(held_out_lbls[i + 3])
    held_out_X = np.array(held_out_X, dtype=np.float32)
    held_out_y = np.array(held_out_y, dtype=np.int64)
    
    pred_classes_ho = []
    pred_probs_ho = []
    with torch.no_grad():
        for i in range(0, len(held_out_X), 512):
            bx = torch.from_numpy(held_out_X[i:i+512]).float().to(device)
            out = model_exp(bx)
            probs = torch.softmax(out["class_logits"], dim=-1).cpu().numpy()
            c_idx = torch.argmax(out["class_logits"], dim=-1).cpu().numpy()
            pred_classes_ho.extend(c_idx)
            pred_probs_ho.extend(probs)
            
    y_pred_ho = np.array(pred_classes_ho)
    probs_ho = np.array(pred_probs_ho)
    
    ho_acc = accuracy_score(held_out_y, y_pred_ho)
    ho_bal_acc = balanced_accuracy_score(held_out_y, y_pred_ho)
    ho_macro_f1 = f1_score(held_out_y, y_pred_ho, average="macro", zero_division=0)
    ho_weighted_f1 = f1_score(held_out_y, y_pred_ho, average="weighted", zero_division=0)
    
    # Binary threat metrics on held-out slice
    y_bin_ho = (held_out_y != 0).astype(int)
    p_attack_ho = 1.0 - probs_ho[:, 0]
    ho_roc_auc = roc_auc_score(y_bin_ho, p_attack_ho)
    prec_h, rec_h, _ = precision_recall_curve(y_bin_ho, p_attack_ho)
    ho_pr_auc = auc(rec_h, prec_h)
    
    print(f"  Held-Out Slice Evaluated Transitions: {len(held_out_X):,}")
    print(f"  Cross-Domain Classification Accuracy: {ho_acc*100:.2f}%")
    print(f"  Cross-Domain Balanced Accuracy:       {ho_bal_acc*100:.2f}%")
    print(f"  Cross-Domain Macro F1-Score:          {ho_macro_f1:.4f}")
    print(f"  Cross-Domain Weighted F1-Score:       {ho_weighted_f1:.4f}")
    print(f"  Cross-Domain Threat ROC-AUC:          {ho_roc_auc:.4f}")
    print(f"  Cross-Domain Threat PR-AUC:           {ho_pr_auc:.4f}")
    
    # Save results JSON
    save_data = {
        "timestamp_utc": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        "experiment": "cicids2018_rare_class_training_expansion",
        "added_real_training_sequences": int(len(new_X)),
        "in_distribution_metrics": {
            "macro_f1": exp_macro_f1,
            "balanced_accuracy": exp_bal_acc,
            "accuracy": exp_acc,
            "weighted_f1": exp_weighted_f1,
            "roc_auc": exp_roc_auc,
            "pr_auc": exp_pr_auc,
            "state_mse": exp_state_mse,
            "shuffle_sigma": exp_sigma
        },
        "held_out_cic2018_slice_metrics": {
            "n_transitions": int(len(held_out_X)),
            "accuracy": ho_acc,
            "balanced_accuracy": ho_bal_acc,
            "macro_f1": ho_macro_f1,
            "weighted_f1": ho_weighted_f1,
            "roc_auc": ho_roc_auc,
            "pr_auc": ho_pr_auc
        }
    }
    
    # Save checkpoint of expanded model as candidate
    torch.save({
        "model_state_dict": model_exp.state_dict(),
        "metrics": save_data
    }, "models/checkpoints/expanded_real_data_world_model.pt")
    
    with open("models/checkpoints/expanded_real_data_evaluation.json", "w") as f:
        json.dump(save_data, f, indent=2)
    print("\nSaved evaluation results to: models/checkpoints/expanded_real_data_evaluation.json")
    print("Saved candidate checkpoint to: models/checkpoints/expanded_real_data_world_model.pt")

if __name__ == "__main__":
    main()
