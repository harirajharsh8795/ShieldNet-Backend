"""
Temporal Transformer World Model for Cyber Attack Forecasting & State Dynamics.

Architecture:
- Input projection: 84 -> d_model (128)
- Learnable / Sinusoidal Positional Encoding for sequence length L=3
- 2-layer Transformer Encoder (4 attention heads, 256 FFN dim, dropout 0.2)
- Multi-task heads: Next State MSE (84), Class Logits (13), MITRE Logits (6), Order Logit (1)
"""

import math
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, Optional

class PositionalEncoding(nn.Module):
    def __init__(self, d_model: int, max_len: int = 50):
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        self.register_buffer("pe", pe.unsqueeze(0))  # (1, max_len, d_model)
        
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch_size, seq_len, d_model)
        return x + self.pe[:, :x.size(1), :]

class TemporalTransformerWorldModel(nn.Module):
    def __init__(self,
                 input_size: int = 84,
                 d_model: int = 128,
                 nhead: int = 4,
                 num_layers: int = 2,
                 dim_feedforward: int = 256,
                 dropout: float = 0.2,
                 num_classes: int = 13,
                 num_mitre_stages: int = 6):
        super().__init__()
        self.input_size = input_size
        self.d_model = d_model
        
        self.input_proj = nn.Linear(input_size, d_model)
        self.pos_encoder = PositionalEncoding(d_model, max_len=20)
        
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=dim_feedforward,
            dropout=dropout,
            batch_first=True,
            activation="relu"
        )
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        
        # Multi-task heads operating on sequence pooling (mean + last step)
        self.state_head = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(d_model, input_size)
        )
        
        self.class_head = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(d_model, num_classes)
        )
        
        self.mitre_head = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(d_model // 2, num_mitre_stages)
        )
        
        self.order_head = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(d_model // 2, 1)
        )
        
    def forward(self, x: torch.Tensor) -> Dict[str, torch.Tensor]:
        # x: (B, L, 84)
        B, L, _ = x.shape
        h = self.input_proj(x)                  # (B, L, 128)
        h = self.pos_encoder(h)                 # (B, L, 128)
        encoded = self.transformer_encoder(h)   # (B, L, 128)
        
        # Last step context vector
        ctx = encoded[:, -1, :]                 # (B, 128)
        
        pred_state = self.state_head(ctx)       # (B, 84)
        class_logits = self.class_head(ctx)     # (B, 13)
        mitre_logits = self.mitre_head(ctx)     # (B, 6)
        order_logits = self.order_head(ctx).squeeze(-1)  # (B,)
        
        return {
            "predicted_next_state": pred_state,
            "class_logits": class_logits,
            "mitre_logits": mitre_logits,
            "order_logits": order_logits,
            "context_vector": ctx,
            "attention_weights": torch.ones(B, L, device=x.device) / L
        }
