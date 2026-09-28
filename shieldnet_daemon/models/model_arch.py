"""
ShieldNet PyTorch World Model Architecture (GRU + Temporal Attention Pooling).

Self-contained reference architecture used to load world_model_v1.pt and export to ONNX.
"""

from typing import Dict, Tuple, Optional
import torch
import torch.nn as nn
import torch.nn.functional as F


class TemporalAttentionPooling(nn.Module):
    """Computes learned self-attention weights over recurrent context timesteps."""
    def __init__(self, hidden_dim: int):
        super().__init__()
        self.attn_dense = nn.Linear(hidden_dim, hidden_dim)
        self.attn_v = nn.Linear(hidden_dim, 1, bias=False)
        
    def forward(self, rnn_outputs: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Args:
            rnn_outputs: (batch_size, seq_len, hidden_dim)
        Returns:
            context_vector: (batch_size, hidden_dim)
            attention_weights: (batch_size, seq_len)
        """
        u = torch.tanh(self.attn_dense(rnn_outputs))
        scores = self.attn_v(u).squeeze(-1)
        attn_weights = F.softmax(scores, dim=-1)
        context_vector = torch.bmm(attn_weights.unsqueeze(1), rnn_outputs).squeeze(1)
        return context_vector, attn_weights


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
        
        # 1. Recurrent Backbone
        self.rnn = nn.GRU(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )
        
        # 2. Attention Layer
        if self.use_attention:
            self.attn_pool = TemporalAttentionPooling(hidden_size)
            
        # 3. Next State Predictor
        self.state_predictor = nn.Sequential(
            nn.Linear(hidden_size, hidden_size),
            nn.LayerNorm(hidden_size),
            nn.GELU(),
            nn.Linear(hidden_size, input_size),
        )
        
        # 4. Attack Class Forecasting Head
        self.class_head = nn.Sequential(
            nn.Linear(hidden_size, hidden_size),
            nn.LayerNorm(hidden_size),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size, num_classes),
        )
        
        # 5. MITRE Killchain Stage Head
        self.mitre_head = nn.Sequential(
            nn.Linear(hidden_size, 64),
            nn.GELU(),
            nn.Linear(64, num_mitre_stages),
        )
        
        # 6. Auxiliary Temporal Order Head
        self.order_head = nn.Sequential(
            nn.Linear(hidden_size, 64),
            nn.GELU(),
            nn.Linear(64, 1),
        )

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Forward pass formatted for clean ONNX export.
        
        Args:
            x: (batch_size, seq_len, 84)
            
        Returns:
            predicted_next_state: (batch_size, 84)
            class_logits: (batch_size, 13)
            mitre_logits: (batch_size, 6)
            infiltration_prob: (batch_size,)
            attention_weights: (batch_size, seq_len)
        """
        rnn_out, _ = self.rnn(x)
        if self.use_attention:
            context, attn_weights = self.attn_pool(rnn_out)
        else:
            context = rnn_out[:, -1, :]
            attn_weights = torch.zeros((x.shape[0], x.shape[1]), device=x.device)
            
        pred_state = self.state_predictor(context)
        class_logits = self.class_head(context)
        mitre_logits = self.mitre_head(context)
        
        class_probs = F.softmax(class_logits, dim=-1)
        infiltration_prob = 1.0 - class_probs[:, 0]
        
        return pred_state, class_logits, mitre_logits, infiltration_prob, attn_weights
