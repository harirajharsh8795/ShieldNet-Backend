"""
ShieldNet Module 3 Verification Test Suite.

Validates:
1. Baseline Logistic Regression parameter loading & linear projection.
2. Confidence Gate high-certainty branch (C_wm >= tau -> World Model dominant).
3. Confidence Gate low-certainty branch (C_wm < tau -> Ensemble fallback blending).
4. Benign traffic bypass gate (is_flagged == False -> skips SHAP).
5. Attack traffic trigger gate (is_flagged == True -> triggers SHAP + Ledger).
6. End-to-end integration between ONNXInferenceEngine and ConfidenceGate.
"""

from pathlib import Path
import numpy as np
import pytest

from shared.schema import (
    NUM_CANONICAL_FEATURES,
    CONTEXT_LENGTH,
    ATTACK_CLASSES,
)
from engine.inference import ONNXInferenceEngine
from engine.confidence_gate import ConfidenceGate


@pytest.fixture(scope="module")
def confidence_gate():
    """Initializes and returns the ConfidenceGate instance."""
    return ConfidenceGate(confidence_tau=0.80, wm_blend_weight=0.60, threat_threshold=0.50)


@pytest.fixture(scope="module")
def onnx_engine():
    """Initializes and returns the ONNXInferenceEngine instance."""
    return ONNXInferenceEngine()


def test_confidence_gate_initialization(confidence_gate):
    """Verify that calibrated baseline weights are loaded cleanly."""
    assert confidence_gate.is_loaded, "LogReg baseline weights must be loaded"
    assert confidence_gate.lr_coef.shape == (len(ATTACK_CLASSES), NUM_CANONICAL_FEATURES)
    assert confidence_gate.lr_intercept.shape == (len(ATTACK_CLASSES),)
    assert confidence_gate.confidence_tau == 0.80
    assert confidence_gate.wm_blend_weight == 0.60


def test_logistic_regression_prediction(confidence_gate):
    """Verify linear dot product and softmax calculation of baseline."""
    # Single sample
    state = np.zeros(NUM_CANONICAL_FEATURES, dtype=np.float32)
    p_lr = confidence_gate.predict_logreg_proba(state)

    assert p_lr.shape == (13,)
    assert abs(np.sum(p_lr) - 1.0) < 1e-5
    assert np.all(p_lr >= 0.0)

    # Batch test
    batch_states = np.random.randn(5, NUM_CANONICAL_FEATURES).astype(np.float32)
    batch_p_lr = confidence_gate.predict_logreg_proba(batch_states)
    assert batch_p_lr.shape == (5, 13)
    for p in batch_p_lr:
        assert abs(np.sum(p) - 1.0) < 1e-5


def test_high_confidence_branch(confidence_gate):
    """Test World Model dominant branch when C_wm >= tau (0.80)."""
    # Simulated high-confidence DDoS detection from World Model
    wm_probs = np.zeros(13, dtype=np.float32)
    wm_probs[2] = 0.95  # DDoS class
    wm_probs[0] = 0.05  # BENIGN

    wm_step_out = {
        "class_probs": wm_probs,
        "mitre_stage": 5,  # Impact
        "predicted_next_state": np.zeros(84, dtype=np.float32),
    }
    current_state = np.zeros(84, dtype=np.float32)

    eval_res = confidence_gate.evaluate_window(wm_step_out, current_state)

    assert eval_res["gating_action"] == "world_model_dominant"
    assert eval_res["is_flagged"] is True
    assert eval_res["predicted_class"] == "DDoS"
    assert eval_res["threat_probability"] > 0.80
    assert eval_res["severity"] == "HIGH"


def test_low_confidence_fallback_branch(confidence_gate):
    """Test ensemble fallback blending when C_wm < tau (0.80)."""
    # Simulated uncertain World Model prediction
    wm_probs = np.zeros(13, dtype=np.float32)
    wm_probs[8] = 0.45   # PortScan
    wm_probs[0] = 0.40   # BENIGN
    wm_probs[1] = 0.15   # Bot
    # Max prob is 0.45 < 0.80 (uncertain)

    wm_step_out = {
        "class_probs": wm_probs,
        "mitre_stage": 1,  # Reconnaissance
        "predicted_next_state": np.zeros(84, dtype=np.float32),
    }
    current_state = np.zeros(84, dtype=np.float32)

    eval_res = confidence_gate.evaluate_window(wm_step_out, current_state)

    assert eval_res["gating_action"] == "ensemble_fallback"
    assert eval_res["wm_confidence"] == 0.45
    # Verify that blended distribution is a valid probability distribution
    assert abs(np.sum(eval_res["blended_probs"]) - 1.0) < 1e-4


def test_clean_benign_window_bypass(confidence_gate):
    """Verify that clean benign traffic is NOT flagged, skipping SHAP explainability."""
    wm_probs = np.zeros(13, dtype=np.float32)
    wm_probs[0] = 0.98   # BENIGN
    wm_probs[2] = 0.02

    wm_step_out = {
        "class_probs": wm_probs,
        "mitre_stage": 0,  # Normal Operations
        "predicted_next_state": np.zeros(84, dtype=np.float32),
    }
    current_state = np.zeros(84, dtype=np.float32)

    eval_res = confidence_gate.evaluate_window(wm_step_out, current_state)

    # Must NOT be flagged
    assert eval_res["is_flagged"] is False
    assert eval_res["predicted_class"] == "BENIGN"
    assert eval_res["threat_probability"] < 0.20
    assert eval_res["severity"] == "CLEAN"


def test_end_to_end_onnx_and_confidence_gate(onnx_engine, confidence_gate):
    """Verify full integration between ONNX Runtime inference and Confidence Gate."""
    seq = np.random.randn(1, CONTEXT_LENGTH, NUM_CANONICAL_FEATURES).astype(np.float32)
    
    # 1. ONNX step inference & K=5 rollout
    wm_step = onnx_engine.predict_step(seq)
    rollout_res = onnx_engine.rollout(seq, k_steps=5)

    # 2. Evaluate window via Confidence Gate
    current_state = seq[0, -1, :]
    gate_out = confidence_gate.evaluate_window(
        wm_step,
        current_state,
        k_step_rollout=rollout_res["k_step_rollout"]
    )

    # Validate output schema
    assert "is_flagged" in gate_out
    assert isinstance(gate_out["is_flagged"], bool)
    assert "threat_probability" in gate_out
    assert 0.0 <= gate_out["threat_probability"] <= 1.0
    assert "predicted_class" in gate_out
    assert gate_out["predicted_class"] in ATTACK_CLASSES
    assert "severity" in gate_out
    assert gate_out["severity"] in ["CLEAN", "LOW", "MEDIUM", "HIGH"]
    assert "gating_action" in gate_out
    assert len(gate_out["k_step_rollout"]) == 5


if __name__ == "__main__":
    pytest.main(["-v", __file__])
