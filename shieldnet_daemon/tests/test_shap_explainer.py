"""
ShieldNet Module 4 Verification Test Suite.

Validates:
1. Strict architectural gating: Benign windows (is_flagged=False) completely bypass SHAP (0ms latency).
2. Flagged windows (is_flagged=True) trigger SHAP explanation, producing 84-dim attribution vectors.
3. Structured SHAPOutput: top features, impact direction, and JSON summary for Action Ledger.
4. Privacy & Structural constraint (Section 5.1): output contains only feature attributions,
   never raw packets or payload bytes.
5. Operational metrics: verification of bypass rate on streaming telemetry.
"""

from pathlib import Path
import json
import time
import numpy as np
import pytest

from shared.schema import (
    NUM_CANONICAL_FEATURES,
    CONTEXT_LENGTH,
    CANONICAL_84_FEATURES,
)
from engine.inference import ONNXInferenceEngine
from engine.confidence_gate import ConfidenceGate
from engine.explainer import GatedSHAPExplainer, SHAPOutput


@pytest.fixture(scope="module")
def onnx_engine():
    """Initializes the ONNX Runtime inference engine."""
    return ONNXInferenceEngine()


@pytest.fixture(scope="module")
def confidence_gate():
    """Initializes the Confidence Gate."""
    return ConfidenceGate()


@pytest.fixture(scope="module")
def shap_explainer(onnx_engine):
    """Initializes the GatedSHAPExplainer with fast sample count for tests."""
    return GatedSHAPExplainer(inference_engine=onnx_engine, nsamples=30, top_k=5)


def test_benign_window_bypasses_shap(shap_explainer):
    """Verify that clean benign windows bypass SHAP with near-zero latency."""
    seq = np.zeros((1, CONTEXT_LENGTH, NUM_CANONICAL_FEATURES), dtype=np.float32)

    # Benign gate result
    benign_gate_result = {
        "is_flagged": False,
        "threat_probability": 0.02,
        "predicted_class": "BENIGN",
        "mitre_stage": 0,
        "severity": "CLEAN"
    }

    t0 = time.perf_counter()
    output = shap_explainer.explain_window(benign_gate_result, seq)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    # Must return None and execute in less than 0.5 ms
    assert output is None, "Benign window must NOT trigger SHAP explanation"
    assert elapsed_ms < 0.5, f"Bypassed window took {elapsed_ms:.2f} ms (expected < 0.5 ms)"


def test_flagged_window_triggers_shap(shap_explainer):
    """Verify that flagged windows trigger SHAP and produce valid 84-dim attributions."""
    # Synthetic suspicious sequence (e.g. port scan / DDoS burst)
    seq = np.random.randn(1, CONTEXT_LENGTH, NUM_CANONICAL_FEATURES).astype(np.float32)
    # Exaggerate SYN flags and short IATs
    seq[:, :, 43] = 50.0  # SYN flag count
    seq[:, :, 15] = 0.001 # Flow IAT mean

    flagged_gate_result = {
        "is_flagged": True,
        "threat_probability": 0.89,
        "predicted_class": "PortScan",
        "mitre_stage": 1,
        "mitre_tactic": "TA0043: Reconnaissance",
        "wm_confidence": 0.91,
        "severity": "HIGH"
    }

    t0 = time.perf_counter()
    output = shap_explainer.explain_window(flagged_gate_result, seq)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    assert isinstance(output, SHAPOutput), "Flagged window must return a SHAPOutput instance"
    assert output.is_explained is True
    assert output.target_class == "PortScan"
    assert output.mitre_stage == 1
    assert output.threat_probability == 0.89

    # Check 84-dimensional attribution vector
    assert output.shap_vector.shape == (84,)
    assert len(output.feature_attributions) == 84
    assert not np.isnan(output.shap_vector).any(), "SHAP vector must not contain NaNs"

    # Check Top-5 features
    assert len(output.top_features) == 5
    for f in output.top_features:
        assert "rank" in f
        assert "feature_name" in f
        assert "attribution_score" in f
        assert "impact_direction" in f
        assert f["feature_name"] in CANONICAL_84_FEATURES

    # Check JSON summary format for SQLite Action Ledger
    assert isinstance(output.shap_summary, str)
    summary_dict = json.loads(output.shap_summary)
    assert summary_dict["target_class"] == "PortScan"
    assert summary_dict["mitre_stage"] == 1
    assert len(summary_dict["top_drivers"]) >= 1


def test_structural_privacy_constraint(shap_explainer):
    """Verify Section 5.1 constraint: SHAP output contains NO raw packets or payload bytes."""
    seq = np.random.randn(1, CONTEXT_LENGTH, NUM_CANONICAL_FEATURES).astype(np.float32)
    flagged_gate = {
        "is_flagged": True,
        "threat_probability": 0.75,
        "predicted_class": "Bot",
        "mitre_stage": 4,
        "mitre_tactic": "TA0011: Command and Control",
        "wm_confidence": 0.82,
        "severity": "HIGH"
    }

    output = shap_explainer.explain_window(flagged_gate, seq)
    out_dict = output.to_dict()

    # Verify absence of packet structures, sockets, or payload bytes
    forbidden_keys = {"packets", "raw_packet", "payload", "socket", "pcap", "bytes"}
    for k in out_dict.keys():
        assert k not in forbidden_keys, f"Found forbidden raw traffic key: {k}"

    # Verify JSON serializability of entire output
    serialized = json.dumps(out_dict)
    assert len(serialized) > 0


def test_streaming_gate_bypass_metrics(shap_explainer):
    """Simulate streaming telemetry and verify operational bypass metrics."""
    shap_explainer.total_windows_seen = 0
    shap_explainer.total_windows_explained = 0
    shap_explainer.total_windows_bypassed = 0

    seq = np.zeros((1, CONTEXT_LENGTH, NUM_CANONICAL_FEATURES), dtype=np.float32)

    # Stream 8 benign windows and 2 attack windows
    stream_results = [
        {"is_flagged": False, "predicted_class": "BENIGN", "threat_probability": 0.01},
        {"is_flagged": False, "predicted_class": "BENIGN", "threat_probability": 0.02},
        {"is_flagged": True,  "predicted_class": "DDoS",   "threat_probability": 0.95, "mitre_stage": 5},
        {"is_flagged": False, "predicted_class": "BENIGN", "threat_probability": 0.01},
        {"is_flagged": False, "predicted_class": "BENIGN", "threat_probability": 0.03},
        {"is_flagged": False, "predicted_class": "BENIGN", "threat_probability": 0.01},
        {"is_flagged": True,  "predicted_class": "PortScan","threat_probability": 0.82, "mitre_stage": 1},
        {"is_flagged": False, "predicted_class": "BENIGN", "threat_probability": 0.04},
        {"is_flagged": False, "predicted_class": "BENIGN", "threat_probability": 0.02},
        {"is_flagged": False, "predicted_class": "BENIGN", "threat_probability": 0.01},
    ]

    for gate_res in stream_results:
        shap_explainer.explain_window(gate_res, seq)

    metrics = shap_explainer.get_operational_metrics()
    assert metrics["total_windows_seen"] == 10
    assert metrics["total_windows_explained"] == 2
    assert metrics["total_windows_bypassed"] == 8
    assert metrics["bypass_rate_pct"] == 80.0


if __name__ == "__main__":
    pytest.main(["-v", __file__])
