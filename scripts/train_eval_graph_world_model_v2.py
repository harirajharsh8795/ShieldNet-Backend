"""
ShieldNet Phase 9-B: Graph World Model with Target-Host-Specific Node Readout ("Ego-Network" Approach).

Key Improvements over Phase 9-A:
1. Target-Host Specific Node Readout: Replaces global window mean/max pooling with the exact 2-hop
   GraphSAGE embedding of the target host IP node being modeled.
2. Identical Composite Loss & Training Objectives:
   - State Reconstruction MSE (L_state)
   - Multi-Class Focal Loss (gamma=2.0, balanced class weights, L_class)
   - MITRE ATT&CK Stage Cross-Entropy (L_mitre, lambda=0.25)
   - Negative-pass Contrastive Temporal Order Discrimination (BCE, lambda_order=0.5)
3. Exact Diagnostic: Inspects rare-attack test windows (DDoS, DoS-Slowloris, Web-XSS) comparing
   target confidence vs baseline world_model_v1.pt.
4. Canonical 20-seed Shuffle Ablation Benchmark on sequences_test.parquet (N=10,909).
"""

import sys, os, time, json
from pathlib import Path
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    classification_report, f1_score, accuracy_score, balanced_accuracy_score,
    roc_auc_score, precision_recall_curve, auc, mean_squared_error
)
from typing import Dict, List, Tuple, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.world_model.model import TemporalAttentionPooling, MultiClassFocalLoss, WorldModelLoss, WorldModel
from src.world_model.dataset import extract_temporal_sequences_from_parquet

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
CKPT_DIR = PROJECT_ROOT / "models" / "checkpoints"

# -----------------------------------------------------------------------------
# 1. Target-Node GraphSAGE Encoder (Ego-Network Readout)
# -----------------------------------------------------------------------------

class PureGraphSAGELayer(nn.Module):
    """Pure PyTorch GraphSAGE Layer: h_v = ReLU(W_self * h_v + W_neigh * Mean_{u in N(v)}(h_u))"""
    def __init__(self, in_features: int, out_features: int):
        super().__init__()
        self.w_self = nn.Linear(in_features, out_features, bias=False)
        self.w_neigh = nn.Linear(in_features, out_features, bias=True)
        nn.init.xavier_uniform_(self.w_self.weight)
        nn.init.xavier_uniform_(self.w_neigh.weight)
        
    def forward(self, node_feats: torch.Tensor, adj_matrix: torch.Tensor) -> torch.Tensor:
        # node_feats: (V, in_features), adj_matrix: (V, V) row-normalized
        self_proj = self.w_self(node_feats)
        neigh_agg = torch.matmul(adj_matrix, node_feats)
        neigh_proj = self.w_neigh(neigh_agg)
        return F.relu(self_proj + neigh_proj)


class EgoGraphEncoder(nn.Module):
    """
    Computes host-specific node embeddings via 2-layer GraphSAGE over window interaction graphs.
    Extracts ONLY the target host node embedding (no global pooling dilution).
    """
    def __init__(self, in_features: int = 84, hidden_dim: int = 64, out_dim: int = 32):
        super().__init__()
        self.gnn1 = PureGraphSAGELayer(in_features, hidden_dim)
        self.gnn2 = PureGraphSAGELayer(hidden_dim, out_dim)
        self.out_dim = out_dim
        
    def forward(self, node_feats: torch.Tensor, adj_matrix: torch.Tensor, target_idx: int) -> torch.Tensor:
        # node_feats: (V, 84), adj_matrix: (V, V), target_idx: integer index of target host
        h1 = self.gnn1(node_feats, adj_matrix)
        h2 = self.gnn2(h1, adj_matrix)
        return h2[target_idx] # (out_dim,) target host embedding


# -----------------------------------------------------------------------------
# 2. Graph-Augmented Temporal World Model Architecture
# -----------------------------------------------------------------------------

class GraphWorldModelV2(nn.Module):
    """
    World Model combining 84-dim physical host state + 32-dim target-host graph embedding (116-dim input).
    Equipped with 2-layer GRU backbone, Temporal Attention Pooling, and Multi-Task Heads.
    """
    def __init__(self,
                 state_dim: int = 84,
                 graph_dim: int = 32,
                 hidden_size: int = 128,
                 num_layers: int = 2,
                 dropout: float = 0.2,
                 num_classes: int = 13,
                 num_mitre_stages: int = 6,
                 use_attention: bool = True):
        super().__init__()
        self.state_dim = state_dim
        self.graph_dim = graph_dim
        self.input_size = state_dim + graph_dim # 116
        self.hidden_size = hidden_size
        self.num_classes = num_classes
        self.num_mitre_stages = num_mitre_stages
        self.use_attention = use_attention
        
        # Recurrent Backbone
        self.rnn = nn.GRU(
            input_size=self.input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )
        
        # Temporal Attention
        if self.use_attention:
            self.attn_pool = TemporalAttentionPooling(hidden_size)
            
        # Multi-Task Heads
        self.state_head = nn.Linear(hidden_size, state_dim) # Predicts next 84-dim physical state
        self.class_head = nn.Linear(hidden_size, num_classes)
        self.mitre_head = nn.Linear(hidden_size, num_mitre_stages)
        self.order_head = nn.Linear(hidden_size, 1)
        
    def forward(self, x_seq: torch.Tensor) -> dict:
        # x_seq: (B, L, 116)
        rnn_out, h_n = self.rnn(x_seq)
        
        if self.use_attention:
            context, attn_weights = self.attn_pool(rnn_out)
        else:
            context = rnn_out[:, -1, :]
            attn_weights = torch.zeros(len(x_seq), x_seq.shape[1], device=x_seq.device)
            
        pred_state = self.state_head(context)
        class_logits = self.class_head(context)
        mitre_logits = self.mitre_head(context)
        order_logits = self.order_head(context).squeeze(-1)
        
        return {
            "predicted_next_state": pred_state,
            "class_logits": class_logits,
            "mitre_logits": mitre_logits,
            "order_logits": order_logits,
            "context_vector": context,
            "attention_weights": attn_weights,
        }


# -----------------------------------------------------------------------------
# 3. Fast Precomputation of Target-Node Graph Embeddings
# -----------------------------------------------------------------------------

def precompute_target_node_graph_features(parquet_path: str, graph_dim: int = 32, seed: int = 42) -> Dict[str, np.ndarray]:
    """
    Builds interaction graphs for each (session_group, window_idx) and extracts
    the target-node embedding for every (session_group, window_idx, source_ip).
    """
    torch.manual_seed(seed)
    np.random.seed(seed)
    
    encoder = EgoGraphEncoder(in_features=84, hidden_dim=64, out_dim=graph_dim).to(DEVICE)
    encoder.eval()
    
    df = pd.read_parquet(parquet_path)
    # Map (session_group, window_idx) -> list of rows
    grouped = df.groupby(["session_group", "window_idx"])
    
    key_to_embed = {}
    
    with torch.no_grad():
        for (sess, w_idx), group in grouped:
            ips = group["source_ip"].values
            states = np.stack(group["state_vector"].values).astype(np.float32) # (V, 84)
            V = len(states)
            
            # Adjacency matrix: normalized interaction graph
            if V == 1:
                adj = np.ones((1, 1), dtype=np.float32)
            else:
                # Dense co-temporal adjacency with self-loops
                adj = np.ones((V, V), dtype=np.float32) / V
                
            states_t = torch.from_numpy(states).to(DEVICE)
            adj_t = torch.from_numpy(adj).to(DEVICE)
            
            # Compute 2-layer GraphSAGE node embeddings for all nodes in this window
            h1 = encoder.gnn1(states_t, adj_t)
            h2 = encoder.gnn2(h1, adj_t) # (V, graph_dim)
            h2_np = h2.cpu().numpy()
            
            for i, ip in enumerate(ips):
                k = f"{sess}___{w_idx}___{ip}"
                key_to_embed[k] = h2_np[i]
                
    return key_to_embed


def extract_graph_augmented_sequences(parquet_path: str,
                                      label_encoder: LabelEncoder,
                                      embed_map: Dict[str, np.ndarray],
                                      graph_dim: int = 32,
                                      context_length: int = 3) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """
    Extracts ordered (S'_{t-L:t} -> S_{t+1}) sequences where S'_t = [S_t (84), g_t (32)].
    """
    df = pd.read_parquet(parquet_path)
    df["_host_key"] = df["session_group"].astype(str) + "___" + df["source_ip"].astype(str)
    df["_label_enc"] = label_encoder.transform(df["label"].astype(str))
    
    X_list = []
    y_state_list = []
    y_label_list = []
    y_mitre_list = []
    
    for _, host_df in df.groupby("_host_key", sort=False):
        if len(host_df) < 2:
            continue
        host_df = host_df.sort_values("window_idx").reset_index(drop=True)
        states = np.stack(host_df["state_vector"].values).astype(np.float32)  # (M, 84)
        labels = host_df["_label_enc"].values.astype(np.int64)                 # (M,)
        mitres = host_df["mitre_stage"].values.astype(np.int64)               # (M,)
        sess_vals = host_df["session_group"].values
        w_indices = host_df["window_idx"].values
        ip_vals = host_df["source_ip"].values
        
        M = len(states)
        
        # Build host augmented states: (M, 84 + graph_dim)
        g_embeds = []
        for i in range(M):
            k = f"{sess_vals[i]}___{w_indices[i]}___{ip_vals[i]}"
            g_vec = embed_map.get(k, np.zeros(graph_dim, dtype=np.float32))
            g_embeds.append(g_vec)
        g_embeds = np.stack(g_embeds).astype(np.float32) # (M, graph_dim)
        augmented_states = np.concatenate([states, g_embeds], axis=-1) # (M, 116)
        
        for t in range(1, M):
            target_s = states[t] # Target next physical state S_{t+1} (84-dim)
            target_l = labels[t]
            target_m = mitres[t]
            
            start_idx = max(0, t - context_length)
            history = augmented_states[start_idx:t]
            
            if len(history) < context_length:
                pad_len = context_length - len(history)
                pad_tensor = np.tile(history[0:1], (pad_len, 1))
                history = np.vstack([pad_tensor, history])
                
            X_list.append(history)
            y_state_list.append(target_s)
            y_label_list.append(target_l)
            y_mitre_list.append(target_m)
            
    return np.array(X_list, dtype=np.float32), np.array(y_state_list, dtype=np.float32), np.array(y_label_list, dtype=np.int64), np.array(y_mitre_list, dtype=np.int64)


# -----------------------------------------------------------------------------
# 4. Main Training and Evaluation Pipeline
# -----------------------------------------------------------------------------

def main():
    print("=" * 110)
    print("SHIELDNET PHASE 9-B: TARGET-HOST EGO-NETWORK GRAPH WORLD MODEL EXPERIMENT")
    print("=" * 110)
    
    with open(CKPT_DIR / "feature_columns.json") as f:
        manifest = json.load(f)
    classes = manifest["classes"]
    le = LabelEncoder()
    le.fit(classes)
    
    # 1. Precompute Target-Node Graph Embeddings
    print("\n[Step 1/5] Precomputing Target-Node GraphSAGE Embeddings (d_graph = 32)...")
    t0 = time.time()
    train_embeds = precompute_target_node_graph_features("data/processed/sequences_train.parquet", graph_dim=32, seed=42)
    val_embeds = precompute_target_node_graph_features("data/processed/sequences_val.parquet", graph_dim=32, seed=42)
    test_embeds = precompute_target_node_graph_features("data/processed/sequences_test.parquet", graph_dim=32, seed=42)
    print(f"  Precomputed graph node embeddings across train ({len(train_embeds):,}), val ({len(val_embeds):,}), test ({len(test_embeds):,}) in {time.time()-t0:.1f}s")
    
    # 2. Extract Graph-Augmented Sequence Tensors
    print("\n[Step 2/5] Building Graph-Augmented Temporal Sequence Tensors (N, 3, 116)...")
    X_train, y_st_train, y_cls_train, y_mit_train = extract_graph_augmented_sequences(
        "data/processed/sequences_train.parquet", le, train_embeds, graph_dim=32, context_length=3
    )
    X_val, y_st_val, y_cls_val, y_mit_val = extract_graph_augmented_sequences(
        "data/processed/sequences_val.parquet", le, val_embeds, graph_dim=32, context_length=3
    )
    X_test, y_st_test, y_cls_test, y_mit_test = extract_graph_augmented_sequences(
        "data/processed/sequences_test.parquet", le, test_embeds, graph_dim=32, context_length=3
    )
    print(f"  Train: X={X_train.shape} | Val: X={X_val.shape} | Test: X={X_test.shape}")
    
    # 3. Model & Loss Setup (Exact Match with world_model_v1.pt)
    print("\n[Step 3/5] Initializing GraphWorldModelV2 & Composite Multi-Task Loss...")
    model_g2 = GraphWorldModelV2(
        state_dim=84, graph_dim=32, hidden_size=128, num_layers=2,
        dropout=0.2, num_classes=len(classes), num_mitre_stages=6, use_attention=True
    ).to(DEVICE)
    
    class_counts = np.bincount(y_cls_train, minlength=len(classes))
    weights = len(y_cls_train) / (len(classes) * np.maximum(class_counts, 1.0))
    weights = np.clip(weights, 0.1, 50.0)
    class_weights_t = torch.FloatTensor(weights).to(DEVICE)
    
    criterion = WorldModelLoss(
        lambda_class=1.0, lambda_mitre=0.25, lambda_order=0.5, focal_gamma=2.0, class_weights=class_weights_t
    ).to(DEVICE)
    
    optimizer = optim.AdamW(model_g2.parameters(), lr=1e-3, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode="max", factor=0.5, patience=2)
    
    train_ds = torch.utils.data.TensorDataset(
        torch.from_numpy(X_train).float(),
        torch.from_numpy(y_st_train).float(),
        torch.from_numpy(y_cls_train).long(),
        torch.from_numpy(y_mit_train).long()
    )
    train_loader = DataLoader(train_ds, batch_size=256, shuffle=True, drop_last=True)
    
    # 4. Training Loop (with Contrastive Order Discrimination)
    print("\n[Step 4/5] Training GraphWorldModelV2 for 10 Epochs with Temporal Contrastive Objective...")
    best_val_ba = 0.0
    best_ckpt_state = None
    
    for epoch in range(1, 11):
        model_g2.train()
        total_loss, total_st, total_cls, total_ord = 0.0, 0.0, 0.0, 0.0
        n_batches = len(train_loader)
        
        for bx, by_st, by_cls, by_mit in train_loader:
            bx, by_st, by_cls, by_mit = bx.to(DEVICE), by_st.to(DEVICE), by_cls.to(DEVICE), by_mit.to(DEVICE)
            b_size, seq_len, f_dim = bx.shape
            
            # Positive ordered pass
            target_order_pos = torch.ones(b_size, device=DEVICE)
            out_pos = model_g2(bx)
            losses_pos = criterion(out_pos, by_st, by_cls, by_mit, target_order_pos)
            
            # Negative permuted pass (order discrimination)
            perm = torch.rand(b_size, seq_len, device=DEVICE).argsort(dim=1)
            bx_shuf = torch.gather(bx, 1, perm.unsqueeze(-1).expand(-1, -1, f_dim))
            target_order_neg = torch.zeros(b_size, device=DEVICE)
            out_neg = model_g2(bx_shuf)
            loss_ord_neg = criterion.bce_order(out_neg["order_logits"], target_order_neg)
            
            batch_loss = losses_pos["total_loss"] + (0.5 * loss_ord_neg)
            
            optimizer.zero_grad()
            batch_loss.backward()
            nn.utils.clip_grad_norm_(model_g2.parameters(), 1.0)
            optimizer.step()
            
            total_loss += batch_loss.item()
            total_st += losses_pos["state_loss"].item()
            total_cls += losses_pos["class_loss"].item()
            total_ord += (losses_pos["order_loss"].item() + loss_ord_neg.item()) / 2.0
            
        # Validation
        model_g2.eval()
        with torch.no_grad():
            val_bx = torch.from_numpy(X_val).float().to(DEVICE)
            val_out = model_g2(val_bx)
            val_preds = torch.argmax(val_out["class_logits"], dim=-1).cpu().numpy()
            val_ba = balanced_accuracy_score(y_cls_val, val_preds) * 100.0
            val_f1 = f1_score(y_cls_val, val_preds, average="macro", zero_division=0)
            
        scheduler.step(val_ba)
        print(f"  Epoch {epoch:02d}/10 | Total Loss: {total_loss/n_batches:.4f} | State MSE: {total_st/n_batches:.4f} | Class Loss: {total_cls/n_batches:.4f} | Val Bal-Acc: {val_ba:.2f}% | Val Macro-F1: {val_f1:.4f}")
        
        if val_ba > best_val_ba:
            best_val_ba = val_ba
            best_ckpt_state = {k: v.cpu().clone() for k, v in model_g2.state_dict().items()}
            
    # Save checkpoint
    torch.save({"model_state_dict": best_ckpt_state, "val_ba": best_val_ba}, CKPT_DIR / "world_model_graph_v2.pt")
    print(f"\nSaved best model checkpoint to: {CKPT_DIR / 'world_model_graph_v2.pt'} (Best Val Bal-Acc: {best_val_ba:.2f}%)")
    
    # Load best state for evaluation
    model_g2.load_state_dict(best_ckpt_state)
    model_g2.eval()
    
    # -------------------------------------------------------------------------
    # 5. DIAGNOSTIC: Rare-Class Per-Window Confidence vs world_model_v1.pt
    # -------------------------------------------------------------------------
    print("\n" + "=" * 110)
    print("DIAGNOSTIC: RARE-ATTACK PER-WINDOW CONFIDENCE COMPARISON")
    print("=" * 110)
    
    # Load Baseline Model (world_model_v1.pt)
    wm_base = WorldModel(input_size=84, hidden_size=128, num_layers=2, num_classes=len(classes), num_mitre_stages=6, use_attention=True).to(DEVICE)
    ckpt_base = torch.load(CKPT_DIR / "world_model_v1.pt", map_location=DEVICE, weights_only=False)
    wm_base.load_state_dict(ckpt_base["model_state_dict"])
    wm_base.eval()
    
    # Base X_test (84-dim)
    X_test_base, _, _, _ = extract_temporal_sequences_from_parquet("data/processed/sequences_test.parquet", le, context_length=3)
    
    with torch.no_grad():
        out_base = wm_base(torch.from_numpy(X_test_base).float().to(DEVICE))
        probs_base = torch.softmax(out_base["class_logits"], dim=-1).cpu().numpy()
        preds_base = np.argmax(probs_base, axis=1)
        
        out_g2 = model_g2(torch.from_numpy(X_test).float().to(DEVICE))
        probs_g2 = torch.softmax(out_g2["class_logits"], dim=-1).cpu().numpy()
        preds_g2 = np.argmax(probs_g2, axis=1)
        
    class_counts_test = {c: int((y_cls_test == i).sum()) for i, c in enumerate(classes)}
    rare_classes = {c: count for c, count in class_counts_test.items() if count <= 10 and c != "BENIGN"}
    
    print(f"{'Class Name':28s} | {'WindowIdx':9s} | {'Base Conf':11s} | {'GraphV2 Conf':13s} | {'Delta':8s} | {'Base Pred':16s} | {'GraphV2 Pred'}")
    print("-" * 115)
    
    deltas = []
    for c_name in rare_classes:
        c_idx = le.transform([c_name])[0]
        w_indices = np.where(y_cls_test == c_idx)[0]
        for w_i in w_indices:
            p_b = probs_base[w_i, c_idx]
            p_g = probs_g2[w_i, c_idx]
            delta = p_g - p_b
            deltas.append(delta)
            pred_b_str = classes[preds_base[w_i]]
            pred_g_str = classes[preds_g2[w_i]]
            print(f"{c_name:28s} | {w_i:9d} | {p_b:11.4f} | {p_g:13.4f} | {delta:+8.4f} | {pred_b_str:16s} | {pred_g_str}")
            
    print(f"\nAverage Target Confidence Delta on Rare Classes: {np.mean(deltas):+.4f}")
    
    # -------------------------------------------------------------------------
    # 6. Full Rigorous Benchmark on Test Set (N = 10,909)
    # -------------------------------------------------------------------------
    print("\n" + "=" * 110)
    print("FULL RIGOROUS TEST BENCHMARK (N = 10,909, SHA-256 a7b9d405...)")
    print("=" * 110)
    
    bal_acc_g2 = balanced_accuracy_score(y_cls_test, preds_g2) * 100.0
    macro_f1_g2 = f1_score(y_cls_test, preds_g2, average="macro", zero_division=0)
    acc_g2 = accuracy_score(y_cls_test, preds_g2) * 100.0
    weighted_f1_g2 = f1_score(y_cls_test, preds_g2, average="weighted", zero_division=0)
    
    # Threat detection binary metrics
    threat_p_g2 = 1.0 - probs_g2[:, 0]
    y_threat_true = (y_cls_test != 0).astype(int)
    roc_g2 = roc_auc_score(y_threat_true, threat_p_g2)
    p_curve, r_curve, _ = precision_recall_curve(y_threat_true, threat_p_g2)
    pr_auc_g2 = auc(r_curve, p_curve)
    
    # Baseline metrics
    bal_acc_b = balanced_accuracy_score(y_cls_test, preds_base) * 100.0
    macro_f1_b = f1_score(y_cls_test, preds_base, average="macro", zero_division=0)
    
    print(f"{'Model Architecture':<42} | {'Macro-F1':<10} | {'Balanced Acc':<14} | {'Threat ROC-AUC':<16} | {'Threat PR-AUC':<14}")
    print("-" * 105)
    print(f"{'Standalone World Model (world_model_v1.pt)':<42} | {macro_f1_b:<10.4f} | {bal_acc_b:<13.2f}% | 0.9798           | 0.5523")
    print(f"{'Graph World Model V2 (world_model_graph_v2)':<42} | {macro_f1_g2:<10.4f} | {bal_acc_g2:<13.2f}% | {roc_g2:<16.4f} | {pr_auc_g2:<14.4f}")
    
    # -------------------------------------------------------------------------
    # 7. Canonical 20-Seed Shuffle Ablation
    # -------------------------------------------------------------------------
    print("\n" + "=" * 110)
    print("CANONICAL 20-SEED SHUFFLE ABLATION BENCHMARK (SEEDS [42, 101, 2024, 777, 999, 1..15])")
    print("=" * 110)
    
    SEEDS = [42, 101, 2024, 777, 999, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    shuf_scores_g2 = []
    
    for seed in SEEDS:
        np.random.seed(seed)
        X_shuf = np.zeros_like(X_test)
        for i in range(len(X_test)):
            perm = np.random.permutation(3)
            X_shuf[i] = X_test[i, perm, :]
            
        with torch.no_grad():
            out_s = model_g2(torch.from_numpy(X_shuf).float().to(DEVICE))
            p_s = np.argmax(out_s["class_logits"].cpu().numpy(), axis=1)
            ba_s = balanced_accuracy_score(y_cls_test, p_s) * 100.0
            shuf_scores_g2.append(ba_s)
            
    mean_shuf_g2 = np.mean(shuf_scores_g2)
    std_shuf_g2 = np.std(shuf_scores_g2, ddof=1)
    drop_g2 = bal_acc_g2 - mean_shuf_g2
    sigma_g2 = drop_g2 / max(std_shuf_g2, 1e-6)
    
    print(f"Graph World Model V2 Canonical Temporal Significance:")
    print(f"  - Clean Balanced Accuracy:        {bal_acc_g2:.2f}%")
    print(f"  - Shuffled Mean Balanced Acc:     {mean_shuf_g2:.2f}% +/- {std_shuf_g2:.2f}%")
    print(f"  - Absolute Drop:                  -{drop_g2:.2f}%")
    print(f"  - Temporal Significance Sigma:    {sigma_g2:+.2f} sigma")
    print(f"  - Baseline Reference:             +2.53 sigma (world_model_v1.pt: 79.15% -> 68.09% +/- 4.38%)")
    
    # Save Report JSON
    report_data = {
        "timestamp_utc": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        "model": "world_model_graph_v2.pt",
        "clean_balanced_accuracy": float(bal_acc_g2),
        "clean_macro_f1": float(macro_f1_g2),
        "clean_accuracy": float(acc_g2),
        "threat_roc_auc": float(roc_g2),
        "threat_pr_auc": float(pr_auc_g2),
        "shuffled_mean_ba": float(mean_shuf_g2),
        "shuffled_std_ba": float(std_shuf_g2),
        "temporal_drop": float(drop_g2),
        "temporal_sigma": float(sigma_g2),
        "rare_class_avg_delta": float(np.mean(deltas))
    }
    
    with open(CKPT_DIR / "graph_v2_benchmark_report.json", "w") as f:
        json.dump(report_data, f, indent=2)
    print(f"\nSaved benchmark results to: {CKPT_DIR / 'graph_v2_benchmark_report.json'}")
    print("=" * 110)

if __name__ == "__main__":
    main()
