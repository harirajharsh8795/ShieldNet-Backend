"""
ShieldNet World Model Architecture (RSS-WM with Temporal Attention Pooling & Multi-Class Focal Loss).

Combines:
1. 2-layer Recurrent State-Space Backbone (GRU)
2. Temporal Attention-Pooling layer over context window timesteps
3. Multi-task heads: Continuous State Dynamics (MSE), Class Forecasting (Focal Loss),
   MITRE Killchain Stage (CE), and Temporal Order Discrimination (BCE).
4. Autoregressive K-step rollout engine.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Dict, List, Tuple, Optional, Any


class TemporalAttentionPooling(nn.Module):
    """Computes learned self-attention weights over recurrent context timesteps."""
    
    def __init__(self, hidden_dim: int):
        super().__init__()
        self.attn_dense = nn.Linear(hidden_dim, hidden_dim)
        self.attn_v = nn.Linear(hidden_dim, 1, bias=False)
        
    def forward(self, rnn_outputs: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Args:
            rnn_outputs: Tensor of shape (batch_size, seq_len, hidden_dim)
            
        Returns:
            context_vector: (batch_size, hidden_dim)
            attention_weights: (batch_size, seq_len)
        """
        # score = v^T * tanh(W * H)
        u = torch.tanh(self.attn_dense(rnn_outputs))             # (B, L, H)
        scores = self.attn_v(u).squeeze(-1)                      # (B, L)
        attn_weights = F.softmax(scores, dim=-1)                 # (B, L)
        context_vector = torch.bmm(attn_weights.unsqueeze(1), rnn_outputs).squeeze(1) # (B, H)
        return context_vector, attn_weights


class MultiClassFocalLoss(nn.Module):
    """Multi-Class Focal Loss for handling severe class imbalance in transition dynamics."""
    
    def __init__(self, gamma: float = 2.0, alpha: Optional[torch.Tensor] = None, reduction: str = "mean"):
        super().__init__()
        self.gamma = gamma
        self.alpha = alpha  # Class weights tensor (num_classes,)
        self.reduction = reduction
        
    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        """
        Args:
            logits: (batch_size, num_classes)
            targets: (batch_size,) integer class indices
        """
        ce_loss = F.cross_entropy(logits, targets, reduction="none", weight=self.alpha)
        pt = torch.exp(-ce_loss)  # Probability of true class
        focal_loss = ((1.0 - pt) ** self.gamma) * ce_loss
        
        if self.reduction == "mean":
            return focal_loss.mean()
        elif self.reduction == "sum":
            return focal_loss.sum()
        return focal_loss


class WorldModel(nn.Module):
    """ShieldNet Recurrent State-Space World Model with Attention Pooling."""
    
    def __init__(self,
                 input_size: int = 84,
                 hidden_size: int = 128,
                 num_layers: int = 2,
                 dropout: float = 0.2,
                 num_classes: int = 13,
                 num_mitre_stages: int = 6,
                 use_attention: bool = True):
        super().__init__()
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.num_classes = num_classes
        self.num_mitre_stages = num_mitre_stages
        self.use_attention = use_attention
        
        # 1. Recurrent State-Space Backbone
        self.rnn = nn.GRU(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )
        
        # 2. Temporal Attention Layer
        if self.use_attention:
            self.attn_pool = TemporalAttentionPooling(hidden_size)
            
        # 3. Continuous State Dynamics Head: S_{t+1} (MSE)
        self.state_predictor = nn.Sequential(
            nn.Linear(hidden_size, hidden_size),
            nn.LayerNorm(hidden_size),
            nn.GELU(),
            nn.Linear(hidden_size, input_size),
        )
        
        # 4. Attack Class Forecasting Head: y_{t+1}
        self.class_head = nn.Sequential(
            nn.Linear(hidden_size, hidden_size),
            nn.LayerNorm(hidden_size),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size, num_classes),
        )
        
        # 5. MITRE Killchain Stage Head: m_{t+1}
        self.mitre_head = nn.Sequential(
            nn.Linear(hidden_size, 64),
            nn.GELU(),
            nn.Linear(64, num_mitre_stages),
        )
        
        # 6. Auxiliary Temporal Order Discrimination Head: p_order in [0, 1]
        self.order_head = nn.Sequential(
            nn.Linear(hidden_size, 64),
            nn.GELU(),
            nn.Linear(64, 1),
        )

    def forward(self,
                x: torch.Tensor,
                hidden: Optional[torch.Tensor] = None,
                return_hidden: bool = False) -> Dict[str, torch.Tensor]:
        """Forward pass through World Model.
        
        Args:
            x: Input tensor of shape (batch_size, seq_len, input_size).
            hidden: Optional initial hidden state.
            return_hidden: If True, returns hidden representation.
            
        Returns:
            Dict containing predicted next state, class logits, MITRE logits,
            order logits, attention weights, and infiltration probability.
        """
        rnn_out, h_n = self.rnn(x, hidden)  # rnn_out: (B, L, H), h_n: (num_layers, B, H)
        
        if self.use_attention:
            context, attn_weights = self.attn_pool(rnn_out)  # context: (B, H), attn_weights: (B, L)
        else:
            context = rnn_out[:, -1, :]
            attn_weights = torch.zeros(x.shape[0], x.shape[1], device=x.device)
            
        # Multi-task heads
        pred_state = self.state_predictor(context)
        class_logits = self.class_head(context)
        mitre_logits = self.mitre_head(context)
        order_logits = self.order_head(context).squeeze(-1)
        
        # Infiltration probability: 1.0 - P(BENIGN class)
        class_probs = F.softmax(class_logits, dim=-1)
        infiltration_prob = 1.0 - class_probs[:, 0]
        
        out = {
            "predicted_next_state": pred_state,
            "class_logits": class_logits,
            "mitre_logits": mitre_logits,
            "order_logits": order_logits,
            "attention_weights": attn_weights,
            "infiltration_prob": infiltration_prob,
        }
        
        if return_hidden:
            out["hidden_state"] = context
            out["rnn_hidden"] = h_n
            
        return out

    def rollout(self, initial_sequence: torch.Tensor, k_steps: int = 3) -> Dict[str, torch.Tensor]:
        """Autoregressive multi-step forward simulation."""
        current_seq = initial_sequence.clone()
        seq_len = current_seq.shape[1]
        
        predicted_states = []
        class_logits_list = []
        mitre_logits_list = []
        attention_weights_list = []
        
        for _ in range(k_steps):
            out = self.forward(current_seq)
            pred_state = out["predicted_next_state"]  # (B, 84)
            predicted_states.append(pred_state)
            class_logits_list.append(out["class_logits"])
            mitre_logits_list.append(out["mitre_logits"])
            attention_weights_list.append(out["attention_weights"])
            
            # Autoregressive update: drop oldest state, append predicted state
            next_input = pred_state.unsqueeze(1)      # (B, 1, 84)
            current_seq = torch.cat([current_seq[:, 1:, :], next_input], dim=1)
            
        return {
            "predicted_states": torch.stack(predicted_states, dim=1),
            "class_logits": torch.stack(class_logits_list, dim=1),
            "mitre_logits": torch.stack(mitre_logits_list, dim=1),
            "attention_weights": torch.stack(attention_weights_list, dim=1),
        }

    def rollout_with_uncertainty(self, initial_sequence: torch.Tensor, k_steps: int = 5, num_mc_samples: int = 8) -> Dict[str, Any]:
        """
        Section 3 Fix: Bayesian Monte-Carlo Dropout Uncertainty-Weighted Rollout.
        Calculates epistemic & aleatoric variance (σ²_{t+k}) for future steps k=1..5.
        Prevents blind trust in decaying autoregressive predictions when confidence drops.
        """
        self.train() # Enable dropout for Monte-Carlo sampling
        mc_rollouts = []
        for _ in range(num_mc_samples):
            with torch.no_grad():
                res = self.rollout(initial_sequence, k_steps=k_steps)
                mc_rollouts.append(torch.softmax(res["class_logits"], dim=-1))
        self.eval()
        
        # mc_tensor: (num_mc, B, K, num_classes)
        mc_tensor = torch.stack(mc_rollouts, dim=0)
        mean_probs = torch.mean(mc_tensor, dim=0) # (B, K, num_classes)
        std_probs = torch.std(mc_tensor, dim=0)   # (B, K, num_classes) - Uncertainty envelope
        
        # Infiltration probability and uncertainty bounds: P(Attack) = 1.0 - P(BENIGN)
        mean_threat = 1.0 - mean_probs[..., 0]
        threat_uncertainty = std_probs[..., 0]
        
        upper_bound = torch.clamp(mean_threat + 1.96 * threat_uncertainty, 0.0, 1.0)
        lower_bound = torch.clamp(mean_threat - 1.96 * threat_uncertainty, 0.0, 1.0)
        
        # Flag warning if k=5 variance exceeds safe tolerance threshold
        k5_uncertainty = threat_uncertainty[:, -1]
        uncertainty_warning = (k5_uncertainty > 0.25)
        
        return {
            "mean_threat_trajectory": mean_threat,
            "threat_uncertainty_std": threat_uncertainty,
            "confidence_upper_95": upper_bound,
            "confidence_lower_95": lower_bound,
            "uncertainty_warning": uncertainty_warning,
            "k_steps": k_steps
        }


class HierarchicalTemporalWindowModel(nn.Module):
    """
    Section 3 Fix: Multi-Scale Hierarchical Temporal Operator.
    Fuses three complementary temporal observation scales:
    1. Micro-Window (1s bin): Resolves ultra-fast 50ms volumetric bursts & SYN pulses.
    2. Meso-Window (10s bin): Tracks session-level protocol progression & TCP handshakes.
    3. Macro-Window (60s bin): Detects stealth ultra-slow port scans & Clause 16 APT dwell times.
    """
    def __init__(self, base_world_model: WorldModel):
        super().__init__()
        self.world_model = base_world_model
        # Scale-weighting fusion gate
        self.scale_gate = nn.Sequential(
            nn.Linear(84 * 3, 64),
            nn.ReLU(),
            nn.Linear(64, 3),
            nn.Softmax(dim=-1)
        )
        
    def forward(self, x_micro: torch.Tensor, x_meso: torch.Tensor, x_macro: torch.Tensor) -> Dict[str, Any]:
        """
        Args:
            x_micro: 1-second dynamic resolution (B, L=3, 84)
            x_meso:  10-second session resolution (B, L=3, 84)
            x_macro: 60-second stealth persistence resolution (B, L=3, 84)
        """
        # Run base World Model across all three scales
        out_micro = self.world_model(x_micro)
        out_meso = self.world_model(x_meso)
        out_macro = self.world_model(x_macro)
        
        # Calculate dynamic attention weights for each temporal scale
        last_states = torch.cat([x_micro[:, -1, :], x_meso[:, -1, :], x_macro[:, -1, :]], dim=-1)
        weights = self.scale_gate(last_states) # (B, 3)
        
        w_micro = weights[:, 0].unsqueeze(-1)
        w_meso = weights[:, 1].unsqueeze(-1)
        w_macro = weights[:, 2].unsqueeze(-1)
        
        fused_logits = (
            w_micro * out_micro["class_logits"] +
            w_meso * out_meso["class_logits"] +
            w_macro * out_macro["class_logits"]
        )
        
        fused_probs = F.softmax(fused_logits, dim=-1)
        fused_threat = 1.0 - fused_probs[:, 0]
        
        return {
            "fused_class_logits": fused_logits,
            "fused_threat_prob": fused_threat,
            "scale_weights": {
                "micro_1s_weight": weights[:, 0],
                "meso_10s_weight": weights[:, 1],
                "macro_60s_weight": weights[:, 2]
            },
            "micro_out": out_micro,
            "meso_out": out_meso,
            "macro_out": out_macro
        }


class WorldModelLoss(nn.Module):
    """Composite Multi-Task Loss with Focal Loss and Temporal Order BCE."""
    
    def __init__(self,
                 lambda_class: float = 1.0,
                 lambda_mitre: float = 0.25,
                 lambda_order: float = 0.5,
                 focal_gamma: float = 2.0,
                 class_weights: Optional[torch.Tensor] = None):
        super().__init__()
        self.lambda_class = lambda_class
        self.lambda_mitre = lambda_mitre
        self.lambda_order = lambda_order
        
        self.mse_state = nn.MSELoss()
        self.focal_class = MultiClassFocalLoss(gamma=focal_gamma, alpha=class_weights)
        self.ce_mitre = nn.CrossEntropyLoss()
        self.bce_order = nn.BCEWithLogitsLoss()
        
    def forward(self,
                outputs: Dict[str, torch.Tensor],
                target_state: torch.Tensor,
                target_label: torch.Tensor,
                target_mitre: torch.Tensor,
                target_order: Optional[torch.Tensor] = None) -> Dict[str, torch.Tensor]:
        loss_state = self.mse_state(outputs["predicted_next_state"], target_state)
        loss_class = self.focal_class(outputs["class_logits"], target_label)
        loss_mitre = self.ce_mitre(outputs["mitre_logits"], target_mitre)
        
        if target_order is None:
            target_order = torch.ones(len(target_state), device=target_state.device)
            
        loss_order = self.bce_order(outputs["order_logits"], target_order)
        
        total_loss = (
            loss_state +
            (self.lambda_class * loss_class) +
            (self.lambda_mitre * loss_mitre) +
            (self.lambda_order * loss_order)
        )
        
        return {
            "total_loss": total_loss,
            "state_loss": loss_state,
            "class_loss": loss_class,
            "mitre_loss": loss_mitre,
            "order_loss": loss_order,
        }
