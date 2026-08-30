"""
NetGuard Coarser Cross-Dataset Evaluation (MITRE-Stage Killchain Level).

Collapses fine-grained attack tool names to 6 standardized MITRE ATT&CK Stages:
- Stage 0: Benign / Normal
- Stage 1: Reconnaissance (PortScan, IP Scan, Fuzzers, Analysis)
- Stage 2: Initial Access (FTP/SSH/Web BruteForce, Exploits)
- Stage 3: Lateral Movement (Infiltration, Generic, Worms)
- Stage 4: Command & Control (Botnet, Backdoor, Shellcode)
- Stage 5: Impact / Exfiltration (DoS Hulk/GoldenEye/Slowloris, DDoS, LOIC/HOIC)

Evaluates:
1. CIC-IDS2017 (In-Distribution Test Set, N=10,909)
2. UNSW-NB15 (Out-of-Distribution, N=82,329)
3. CIC-IDS-2018 (Flow-Only AWS Enterprise, N=149,997)
"""

import sys
from pathlib import Path
import json
import torch
import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report, f1_score, precision_score, recall_score,
    balanced_accuracy_score, accuracy_score, confusion_matrix
)
from sklearn.preprocessing import LabelEncoder

sys.path.insert(0, str(Path(__file__).parent.parent))
from src.world_model.model import WorldModel
from src.world_model.dataset import extract_temporal_sequences_from_parquet

MITRE_STAGE_NAMES = {
    0: "Stage 0: Benign",
    1: "Stage 1: Reconnaissance",
    2: "Stage 2: Initial Access",
    3: "Stage 3: Lateral Movement",
    4: "Stage 4: Command & Control",
    5: "Stage 5: Impact / Exfiltration",
}

# 13-class to MITRE stage mapping
CLASS_TO_MITRE = {
    "BENIGN": 0,
    "PortScan": 1,
    "FTP-Patator": 2,
    "SSH-Patator": 2,
    "Web Attack - Brute Force": 2,
    "Web Attack - XSS": 2,
    "Infiltration": 3,
    "Rare-Attack": 3,
    "Bot": 4,
    "DDoS": 5,
    "DoS GoldenEye": 5,
    "DoS Hulk": 5,
    "DoS Slowhttptest": 5,
    "DoS slowloris": 5,
    "Heartbleed": 5,
}

UNSW_TO_MITRE = {
    "Normal": 0,
    "Reconnaissance": 1,
    "Fuzzers": 1,
    "Analysis": 1,
    "Exploits": 2,
    "Generic": 3,
    "Worms": 3,
    "Backdoor": 4,
    "Shellcode": 4,
    "DoS": 5,
}

CIC2018_TO_MITRE = {
    "Benign": 0,
    "FTP-BruteForce": 2,
    "SSH-Bruteforce": 2,
    "DoS attacks-GoldenEye": 5,
    "DoS attacks-Slowloris": 5,
    "DoS attacks-SlowHTTPTest": 5,
    "DoS attacks-Hulk": 5,
    "DDOS attack-HOIC": 5,
    "DDOS attack-LOIC-UDP": 5,
    "DDoS attacks-LOIC-HTTP": 5,
    "Bot": 4,
    "Infilteration": 3,
}

def evaluate_dataset_at_stage_level(name: str, y_true_stage: np.ndarray, y_pred_stage: np.ndarray):
    stages = [0, 1, 2, 3, 4, 5]
    stage_labels = [MITRE_STAGE_NAMES[s] for s in stages]
    
    acc = accuracy_score(y_true_stage, y_pred_stage)
    bal_acc = balanced_accuracy_score(y_true_stage, y_pred_stage)
    macro_f1 = f1_score(y_true_stage, y_pred_stage, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_true_stage, y_pred_stage, average="weighted", zero_division=0)
    
    rep = classification_report(
        y_true_stage, y_pred_stage,
        labels=stages,
        target_names=stage_labels,
        output_dict=True,
        zero_division=0
    )
    
    print("\n" + "=" * 90, flush=True)
    print(f"MITRE STAGE-LEVEL EVALUATION: {name.upper()}", flush=True)
    print("=" * 90, flush=True)
    print(f"Total Sequence Transitions: {len(y_true_stage):,}")
    print(f"  - Stage-Level Accuracy:          {acc*100:.2f}%")
    print(f"  - Stage-Level Balanced Accuracy: {bal_acc*100:.2f}%")
    print(f"  - Stage-Level Macro F1:          {macro_f1:.4f}")
    print(f"  - Stage-Level Weighted F1:       {weighted_f1:.4f}")
    
    print("\nPer-Stage Detailed Breakdown (with exact test-N):")
    print(f"{'MITRE ATT&CK Stage':32s} | {'Test Support N':15s} | {'Precision':10s} | {'Recall':10s} | {'F1-Score':10s}")
    print("-" * 85)
    
    stage_breakdown = []
    for s in stages:
        s_name = MITRE_STAGE_NAMES[s]
        s_dict = rep.get(s_name, {})
        supp = int(s_dict.get("support", 0))
        prec = float(s_dict.get("precision", 0.0))
        rec = float(s_dict.get("recall", 0.0))
        f1 = float(s_dict.get("f1-score", 0.0))
        
        print(f"{s_name:32s} | {supp:15,d} | {prec:10.4f} | {rec:10.4f} | {f1:10.4f}")
        stage_breakdown.append({
            "stage_id": s,
            "stage_name": s_name,
            "support_n": supp,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
        })
        
    return {
        "dataset": name,
        "total_transitions": len(y_true_stage),
        "accuracy": acc,
        "balanced_accuracy": bal_acc,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "stage_breakdown": stage_breakdown,
    }

def main():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    checkpoint_dir = Path("models/checkpoints")
    
    with open(checkpoint_dir / "feature_columns.json") as f:
        manifest = json.load(f)
    classes = manifest["classes"]
    le = LabelEncoder()
    le.fit(classes)
    
    # 1. Load Model Checkpoint
    ckpt_path = checkpoint_dir / "world_model_v1.pt"
    ckpt = torch.load(ckpt_path, map_location=device, weights_only=False)
    
    model = WorldModel(
        input_size=84,
        hidden_size=128,
        num_layers=2,
        num_classes=len(classes),
        num_mitre_stages=6,
        use_attention=True
    ).to(device)
    model.load_state_dict(ckpt["model_state_dict"])
    model.eval()
    
    all_results = {}
    
    # ─── 1. CIC-IDS2017 In-Distribution Evaluation ────────────────────────────
    X_test, y_test_state, y_test_label, y_test_mitre = extract_temporal_sequences_from_parquet(
        "data/processed/sequences_test.parquet", le, context_length=3
    )
    with torch.no_grad():
        out17 = model(torch.from_numpy(X_test).to(device))
        pred_class_17 = torch.argmax(out17["class_logits"], dim=-1).cpu().numpy()
        pred_class_str = le.inverse_transform(pred_class_17)
        pred_stage_17 = np.array([CLASS_TO_MITRE.get(c, 0) for c in pred_class_str])
        true_stage_17 = y_test_mitre
        
    res_17 = evaluate_dataset_at_stage_level("CIC-IDS2017 (In-Distribution)", true_stage_17, pred_stage_17)
    all_results["cicids2017"] = res_17
    
    # ─── 2. UNSW-NB15 Out-of-Distribution Evaluation ──────────────────────────
    unsw_csv = Path("e:/Desktop/dataset/UNSW/UNSW_NB15_testing-set.csv")
    df_unsw = pd.read_csv(unsw_csv)
    n_samples = len(df_unsw)
    state_matrix = np.zeros((n_samples, 84), dtype=np.float32)
    
    col_map = {
        0: "dur", 1: "spkts", 2: "dpkts", 3: "sbytes", 4: "dbytes", 5: "rate",
        6: "sload", 7: "dload", 8: "sloss", 9: "dloss", 10: "sintpkt", 11: "dintpkt",
        12: "sjit", 13: "djit", 14: "swin", 15: "dwin", 16: "stcpb", 17: "dtcpb",
        18: "tcprtt", 19: "synack", 20: "ackdat", 21: "smeansz", 22: "dmeansz",
        23: "trans_depth", 24: "res_bdy_len", 25: "sttl", 26: "dttl", 27: "swin", 28: "dwin"
    }
    for s_idx, u_col in col_map.items():
        if u_col in df_unsw.columns:
            vals = df_unsw[u_col].values.astype(np.float32)
            vals = np.nan_to_num(vals, nan=0.0, posinf=0.0, neginf=0.0)
            std_v = np.std(vals)
            if std_v > 1e-6:
                vals = (vals - np.mean(vals)) / std_v
            state_matrix[:, s_idx] = vals
            
    unsw_true_stages = np.array([UNSW_TO_MITRE.get(str(c), 0) for c in df_unsw["attack_cat"]], dtype=np.int64)
    
    X_unsw_list, y_unsw_stage_list = [], []
    for i in range(len(state_matrix) - 3):
        X_unsw_list.append(state_matrix[i : i + 3])
        y_unsw_stage_list.append(unsw_true_stages[i + 3])
        
    X_unsw = np.array(X_unsw_list, dtype=np.float32)
    y_unsw_stage = np.array(y_unsw_stage_list, dtype=np.int64)
    
    pred_unsw_stages = []
    with torch.no_grad():
        for b_idx in range(0, len(X_unsw), 512):
            b_X = torch.from_numpy(X_unsw[b_idx : b_idx + 512]).to(device)
            out_u = model(b_X)
            # Map predicted class to MITRE stage
            p_cls = torch.argmax(out_u["class_logits"], dim=-1).cpu().numpy()
            p_cls_names = [classes[c] for c in p_cls]
            p_stages = [CLASS_TO_MITRE.get(cn, 0) for cn in p_cls_names]
            pred_unsw_stages.extend(p_stages)
            
    pred_unsw_stage = np.array(pred_unsw_stages, dtype=np.int64)
    res_unsw = evaluate_dataset_at_stage_level("UNSW-NB15 (Out-of-Distribution Stage Level)", y_unsw_stage, pred_unsw_stage)
    all_results["unsw_nb15"] = res_unsw
    
    # ─── 3. CIC-IDS-2018 Flow-Only Evaluation ─────────────────────────────────
    data1_dir = Path("e:/Desktop/dataset/data 1")
    target_files = [
        ("02-14-2018.csv", 25000),
        ("02-15-2018.csv", 25000),
        ("02-16-2018.csv", 25000),
        ("02-21-2018.csv", 25000),
        ("03-01-2018.csv", 25000),
        ("03-02-2018.csv", 25000),
    ]
    flow_dfs = []
    for fname, n_sample in target_files:
        fpath = data1_dir / fname
        if not fpath.exists():
            continue
        chunks = []
        for chunk in pd.read_csv(fpath, chunksize=100000, low_memory=False):
            chunk.columns = [c.strip() for c in chunk.columns]
            if "Label" in chunk.columns:
                atk = chunk[chunk["Label"] != "Benign"]
                ben = chunk[chunk["Label"] == "Benign"]
                n_atk = min(len(atk), n_sample // 2)
                n_ben = min(len(ben), n_sample - n_atk)
                chunks.append(pd.concat([atk.head(n_atk), ben.head(n_ben)]))
                if sum(len(c) for c in chunks) >= n_sample:
                    break
        if chunks:
            flow_dfs.append(pd.concat(chunks).head(n_sample))
            
    df_2018 = pd.concat(flow_dfs, ignore_index=True)
    
    # Feature mapping
    feat_names = manifest["numeric_features"]
    state_mat_18 = np.zeros((len(df_2018), 84), dtype=np.float32)
    alias_map = {
        "Flow Duration": "Flow Duration", "Total Fwd Packets": "Tot Fwd Pkts", "Total Backward Packets": "Tot Bwd Pkts",
        "Total Length of Fwd Packets": "TotLen Fwd Pkts", "Total Length of Bwd Packets": "TotLen Bwd Pkts",
        "Fwd Packet Length Max": "Fwd Pkt Len Max", "Fwd Packet Length Min": "Fwd Pkt Len Min",
        "Fwd Packet Length Mean": "Fwd Pkt Len Mean", "Fwd Packet Length Std": "Fwd Pkt Len Std",
        "Bwd Packet Length Max": "Bwd Pkt Len Max", "Bwd Packet Length Min": "Bwd Pkt Len Min",
        "Bwd Packet Length Mean": "Bwd Pkt Len Mean", "Bwd Packet Length Std": "Bwd Pkt Len Std",
        "Flow Bytes/s": "Flow Byts/s", "Flow Packets/s": "Flow Pkts/s",
        "Flow IAT Mean": "Flow IAT Mean", "Flow IAT Std": "Flow IAT Std", "Flow IAT Max": "Flow IAT Max", "Flow IAT Min": "Flow IAT Min",
        "Fwd IAT Total": "Fwd IAT Tot", "Fwd IAT Mean": "Fwd IAT Mean", "Fwd IAT Std": "Fwd IAT Std", "Fwd IAT Max": "Fwd IAT Max", "Fwd IAT Min": "Fwd IAT Min",
        "Bwd IAT Total": "Bwd IAT Tot", "Bwd IAT Mean": "Bwd IAT Mean", "Bwd IAT Std": "Bwd IAT Std", "Bwd IAT Max": "Bwd IAT Max", "Bwd IAT Min": "Bwd IAT Min",
        "Fwd PSH Flags": "Fwd PSH Flags", "Bwd PSH Flags": "Bwd PSH Flags", "Fwd URG Flags": "Fwd URG Flags", "Bwd URG Flags": "Bwd URG Flags",
        "Fwd Header Length": "Fwd Header Len", "Bwd Header Length": "Bwd Header Len", "Fwd Packets/s": "Fwd Pkts/s", "Bwd Packets/s": "Bwd Pkts/s",
        "Min Packet Length": "Pkt Len Min", "Max Packet Length": "Pkt Len Max", "Packet Length Mean": "Pkt Len Mean", "Packet Length Std": "Pkt Len Std",
        "Packet Length Variance": "Pkt Len Var", "FIN Flag Count": "FIN Flag Cnt", "SYN Flag Count": "SYN Flag Cnt", "RST Flag Count": "RST Flag Cnt",
        "PSH Flag Count": "PSH Flag Cnt", "ACK Flag Count": "ACK Flag Cnt", "URG Flag Count": "URG Flag Cnt", "CWE Flag Count": "CWE Flag Count",
        "ECE Flag Count": "ECE Flag Cnt", "Down/Up Ratio": "Down/Up Ratio", "Average Packet Size": "Pkt Size Avg",
        "Avg Fwd Segment Size": "Fwd Seg Size Avg", "Avg Bwd Segment Size": "Bwd Seg Size Avg",
        "Init_Win_bytes_forward": "Init Fwd Win Byts", "Init_Win_bytes_backward": "Init Bwd Win Byts",
        "act_data_pkt_fwd": "Fwd Act Data Pkts", "min_seg_size_forward": "Fwd Seg Size Min",
        "Active Mean": "Active Mean", "Active Std": "Active Std", "Active Max": "Active Max", "Active Min": "Active Min",
        "Idle Mean": "Idle Mean", "Idle Std": "Idle Std", "Idle Max": "Idle Max", "Idle Min": "Idle Min",
    }
    for idx, f_name in enumerate(feat_names):
        col = alias_map.get(f_name, f_name)
        if col in df_2018.columns:
            vals = pd.to_numeric(df_2018[col], errors="coerce").fillna(0.0).values.astype(np.float32)
            vals = np.nan_to_num(vals, nan=0.0, posinf=0.0, neginf=0.0)
            std_v = np.std(vals)
            if std_v > 1e-6:
                vals = (vals - np.mean(vals)) / std_v
            state_mat_18[:, idx] = vals
            
    true_stages_18 = np.array([CIC2018_TO_MITRE.get(str(l), 0) for l in df_2018["Label"]], dtype=np.int64)
    
    X_18_list, y_18_stage_list = [], []
    for i in range(len(state_mat_18) - 3):
        X_18_list.append(state_mat_18[i : i + 3])
        y_18_stage_list.append(true_stages_18[i + 3])
        
    X_18 = np.array(X_18_list, dtype=np.float32)
    y_18_stage = np.array(y_18_stage_list, dtype=np.int64)
    
    pred_18_stages = []
    with torch.no_grad():
        for b_idx in range(0, len(X_18), 512):
            b_X = torch.from_numpy(X_18[b_idx : b_idx + 512]).to(device)
            out_18 = model(b_X)
            p_cls = torch.argmax(out_18["class_logits"], dim=-1).cpu().numpy()
            p_cls_names = [classes[c] for c in p_cls]
            p_stages = [CLASS_TO_MITRE.get(cn, 0) for cn in p_cls_names]
            pred_18_stages.extend(p_stages)
            
    pred_18_stage = np.array(pred_18_stages, dtype=np.int64)
    res_18 = evaluate_dataset_at_stage_level("CIC-IDS-2018 (Flow-Only Stage Level)", y_18_stage, pred_18_stage)
    all_results["cicids2018"] = res_18
    
    # Save results
    out_file = checkpoint_dir / "mitre_stage_cross_dataset_results.json"
    with open(out_file, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nSaved MITRE Stage-Level Cross-Dataset Results to: {out_file}", flush=True)

if __name__ == "__main__":
    main()
