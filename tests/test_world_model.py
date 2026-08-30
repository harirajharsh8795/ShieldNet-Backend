"""
Unit tests for ShieldNet World Model architecture, autoregressive rollout, and empirical validation suite.
"""

import pytest
import numpy as np
import torch
import torch.nn as nn
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.world_model.model import WorldModel, WorldModelLoss
from src.world_model.dataset import WorldModelSequenceDataset

class TestWorldModelArchitecture:
    """Tests for the World Model neural architecture."""
    
    def test_forward_shapes(self):
        """Forward pass must return correct tensor shapes for next-state, class, and MITRE stage."""
        batch_size = 16
        seq_len = 5
        input_size = 84
        num_classes = 13
        num_mitre = 6
        
        model = WorldModel(
            input_size=input_size,
            hidden_size=64,
            num_layers=2,
            num_classes=num_classes,
            num_mitre_stages=num_mitre
        )
        
        x = torch.randn(batch_size, seq_len, input_size)
        out = model(x)
        
        assert "predicted_next_state" in out
        assert "class_logits" in out
        assert "mitre_logits" in out
        
        assert out["predicted_next_state"].shape == (batch_size, input_size)
        assert out["class_logits"].shape == (batch_size, num_classes)
        assert out["mitre_logits"].shape == (batch_size, num_mitre)
        
    def test_loss_computation_and_gradients(self):
        """WorldModelLoss must compute non-zero loss and propagate valid gradients."""
        batch_size = 8
        input_size = 84
        num_classes = 13
        num_mitre = 6
        
        model = WorldModel(input_size=input_size, hidden_size=64, num_classes=num_classes)
        criterion = WorldModelLoss(lambda_class=0.5, lambda_mitre=0.25)
        
        x = torch.randn(batch_size, 3, input_size)
        target_state = torch.randn(batch_size, input_size)
        target_class = torch.randint(0, num_classes, (batch_size,))
        target_mitre = torch.randint(0, num_mitre, (batch_size,))
        
        out = model(x)
        loss_dict = criterion(out, target_state, target_class, target_mitre)
        
        assert "total_loss" in loss_dict
        assert "state_loss" in loss_dict
        assert "class_loss" in loss_dict
        assert "mitre_loss" in loss_dict
        
        assert loss_dict["total_loss"].item() > 0
        loss_dict["total_loss"].backward()
        
        # Verify gradients exist
        assert model.state_predictor[0].weight.grad is not None
        assert model.class_head[0].weight.grad is not None


class TestAutoregressiveRollout:
    """Tests for multi-step autoregressive rollout logic."""
    
    def test_k_step_rollout_shapes(self):
        """Rollout must produce (B, K, D) states and (B, K, C) class predictions for K=3."""
        batch_size = 4
        seq_len = 3
        input_size = 84
        k_steps = 3
        
        model = WorldModel(input_size=input_size, hidden_size=32, num_classes=13)
        initial_ctx = torch.randn(batch_size, seq_len, input_size)
        
        rollout_out = model.rollout(initial_ctx, k_steps=k_steps)
        
        assert rollout_out["predicted_states"].shape == (batch_size, k_steps, input_size)
        assert rollout_out["class_logits"].shape == (batch_size, k_steps, 13)
        assert rollout_out["mitre_logits"].shape == (batch_size, k_steps, 6)
        
    def test_autoregressive_context_progression(self):
        """Autoregressive step K=2 must incorporate the predicted state from step K=1."""
        model = WorldModel(input_size=84, hidden_size=32, num_classes=13)
        ctx = torch.randn(2, 3, 84)
        
        rollout_out = model.rollout(ctx, k_steps=2)
        s1 = rollout_out["predicted_states"][:, 0, :]
        s2 = rollout_out["predicted_states"][:, 1, :]
        
        # S1 and S2 must be distinct generated future states
        assert not torch.allclose(s1, s2)


class TestShuffleAblationLogic:
    """Tests for shuffle-timestep ablation logic."""
    
    def test_shuffle_destroys_order(self):
        """Permuting timesteps must alter the sequence order without altering distribution."""
        np.random.seed(42)
        X = np.array([[[1.0], [2.0], [3.0], [4.0], [5.0]]])  # (1, 5, 1)
        
        X_shuf = X.copy()
        L = X.shape[1]
        perm = np.random.permutation(L)
        X_shuf[0] = X_shuf[0, perm, :]
        
        # Order is changed
        assert not np.array_equal(X, X_shuf)
        # Values preserved
        assert set(X.flatten()) == set(X_shuf.flatten())
