"""
Unit Tests for Phase 4: Mitigation Action Space, Counterfactual Trajectory Engine, and Safety Shield.
"""

import pytest
import numpy as np
import torch
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.world_model.model import WorldModel
from src.mitigation.actions import (
    MitigationAction, ACTION_COST_MAP, apply_action_to_state_vector
)
from src.mitigation.counterfactual_engine import CounterfactualTrajectoryEngine
from src.mitigation.safety_shield import SafetyShieldPolicy


@pytest.fixture
def mock_world_model():
    """Create a mock or initialized WorldModel for testing."""
    classes = [
        "BENIGN", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest",
        "DoS slowloris", "FTP-Patator", "PortScan", "Rare-Attack", "SSH-Patator",
        "Web Attack - Brute Force", "Web Attack - XSS"
    ]
    model = WorldModel(
        input_size=84,
        hidden_size=64,
        num_layers=1,
        dropout=0.0,
        num_classes=len(classes),
        num_mitre_stages=6,
    )
    model.eval()
    return model, classes


class TestMitigationActions:
    """Test state-space intervention operators."""
    
    def test_no_action_leaves_state_identical(self):
        state = np.random.randn(84).astype(np.float32)
        intervened = apply_action_to_state_vector(state, MitigationAction.NO_ACTION)
        np.testing.assert_array_equal(state, intervened)
        
    def test_rate_limit_dampens_positive_spikes(self):
        state = np.array([2.0, -1.0, 4.0, 0.0] + [0.0] * 80, dtype=np.float32)
        intervened = apply_action_to_state_vector(state, MitigationAction.RATE_LIMIT)
        assert intervened[0] < 2.0
        assert intervened[2] < 4.0
        assert intervened[1] == -1.0  # Negative unperturbed
        
    def test_block_ip_clamps_traffic(self):
        state = np.array([3.0, 1.5, -0.5] + [0.0] * 81, dtype=np.float32)
        intervened = apply_action_to_state_vector(state, MitigationAction.BLOCK_IP)
        assert np.all(intervened <= -1.5)
        
    def test_isolate_host_sets_zero_trust_baseline(self):
        state = np.random.randn(84).astype(np.float32)
        intervened = apply_action_to_state_vector(state, MitigationAction.ISOLATE_HOST)
        np.testing.assert_array_equal(intervened, np.full(84, -2.0, dtype=np.float32))


class TestCounterfactualEngine:
    """Test parallel forward trajectory rollouts."""
    
    def test_evaluate_all_counterfactuals_structure(self, mock_world_model):
        model, classes = mock_world_model
        engine = CounterfactualTrajectoryEngine(model, classes, device="cpu")
        
        ctx = np.random.randn(3, 84).astype(np.float32)
        results = engine.evaluate_all_counterfactuals(ctx, k_steps=3)
        
        assert results["horizon_steps"] == 3
        assert "baseline_risk" in results
        assert "actions" in results
        assert len(results["actions"]) == 5  # NO_ACTION, RATE_LIMIT, RESET_CONNECTIONS, BLOCK_IP, ISOLATE_HOST
        
        for act in MitigationAction:
            assert act.value in results["actions"]
            act_res = results["actions"][act.value]
            assert len(act_res["predicted_states"]) == 3
            assert len(act_res["attack_probabilities"]) == 3
            assert "state_divergence" in act_res
            assert "risk_reduction" in act_res
            
    def test_trajectory_divergence_non_negative(self, mock_world_model):
        model, classes = mock_world_model
        engine = CounterfactualTrajectoryEngine(model, classes, device="cpu")
        
        ctx = np.random.randn(3, 84).astype(np.float32)
        results = engine.evaluate_all_counterfactuals(ctx, k_steps=2)
        
        # NO_ACTION has zero divergence w.r.t itself
        assert results["actions"]["NO_ACTION"]["state_divergence"] == 0.0
        
        # Alternative actions should produce measurable divergence
        for act_name, act_res in results["actions"].items():
            assert act_res["state_divergence"] >= 0.0


class TestSafetyShieldPolicy:
    """Test operational safety guardrails and utility-driven policy."""
    
    def test_guardrail_g01_prevents_blocking_benign_host(self, mock_world_model):
        model, classes = mock_world_model
        engine = CounterfactualTrajectoryEngine(model, classes, device="cpu")
        shield = SafetyShieldPolicy(engine, critical_attack_threshold=0.90, active_intervention_threshold=0.35)
        
        # Moderate risk sequence
        ctx = np.random.randn(3, 84).astype(np.float32)
        
        # High benign history (98%)
        res = shield.evaluate_and_recommend(
            context_sequence=ctx,
            historic_benign_ratio=0.98,
            is_critical_asset=False,
            host_identifier="192.168.1.100",
            k_steps=3
        )
        
        # If baseline risk is < 0.90, BLOCK_IP and ISOLATE_HOST must be rejected by Guardrail G-01
        if res["baseline_attack_risk"] < 0.90:
            assert res["recommended_action"] not in ["BLOCK_IP", "ISOLATE_HOST"]
            guardrail_rejections = [g["action"] for g in res["guardrail_enforcements"]]
            assert "BLOCK_IP" in guardrail_rejections or res["baseline_attack_risk"] < 0.35
            
    def test_guardrail_g01_protects_critical_infrastructure_asset(self, mock_world_model):
        model, classes = mock_world_model
        engine = CounterfactualTrajectoryEngine(model, classes, device="cpu")
        shield = SafetyShieldPolicy(engine, critical_attack_threshold=0.90, active_intervention_threshold=0.35)
        
        ctx = np.random.randn(3, 84).astype(np.float32)
        
        res = shield.evaluate_and_recommend(
            context_sequence=ctx,
            historic_benign_ratio=0.50,
            is_critical_asset=True,  # Mission-critical server
            host_identifier="Core-DB-01",
            k_steps=3
        )
        
        if res["baseline_attack_risk"] < 0.90:
            assert res["recommended_action"] not in ["BLOCK_IP", "ISOLATE_HOST"]
            
    def test_low_risk_defaults_to_no_action(self, mock_world_model):
        model, classes = mock_world_model
        engine = CounterfactualTrajectoryEngine(model, classes, device="cpu")
        # Set high active threshold so risk is below threshold
        shield = SafetyShieldPolicy(engine, critical_attack_threshold=0.95, active_intervention_threshold=0.99)
        
        ctx = np.random.randn(3, 84).astype(np.float32)
        res = shield.evaluate_and_recommend(
            context_sequence=ctx,
            historic_benign_ratio=0.95,
            is_critical_asset=False,
            k_steps=3
        )
        
        assert res["recommended_action"] == "NO_ACTION"
        assert res["operational_cost"] == 0.0
