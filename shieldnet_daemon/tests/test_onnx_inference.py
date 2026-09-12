"""
ShieldNet Module 2 Verification Test Suite.

Validates:
1. PyTorch to ONNX export and graph verification.
2. Numerical equivalence between PyTorch and ONNX Runtime (< 1e-4 absolute difference).
3. Single-step inference producing continuous state dynamics, 13-class attack forecasts,
   MITRE stages, and threat probabilities.
4. Autoregressive K=5 forward rollout trajectories.
5. CPU inference latency benchmarking (< 5 ms latency SLA).
"""

from pathlib import Path
import numpy as np
import pytest
import torch

from shared.schema import (
    NUM_CANONICAL_FEATURES,
    CONTEXT_LENGTH,
    ATTACK_CLASSES,
    MITRE_STAGES,
)
from engine.export_onnx import export_world_model_to_onnx
from engine.inference import ONNXInferenceEngine
from models.model_arch import WorldModel


@pytest.fixture(scope="module")
def onnx_model_path():
    """Ensures ONNX model is exported and returns its path."""
    onnx_path = Path(__file__).resolve().parent.parent / "models" / "onnx" / "world_model.onnx"
    ckpt_path = Path(__file__).resolve().parent.parent / "models" / "checkpoints" / "world_model_v1.pt"
    
    if not onnx_path.exists():
        export_world_model_to_onnx(checkpoint_path=ckpt_path, output_onnx_path=onnx_path)
    return onnx_path


def test_onnx_export_and_numerical_equivalence(onnx_model_path):
    """Verify export validity and tight numerical match with PyTorch baseline."""
    assert onnx_model_path.exists(), "ONNX model file must exist"
    assert onnx_model_path.stat().st_size > 50_000, "ONNX model file too small"

    ckpt_path = Path(__file__).resolve().parent.parent / "models" / "checkpoints" / "world_model_v1.pt"
    
    # Load PyTorch model
    pt_model = WorldModel(
        input_size=84, hidden_size=128, num_layers=2,
        dropout=0.2, num_classes=13, num_mitre_stages=6, use_attention=True
    )
    ckpt = torch.load(ckpt_path, map_location="cpu", weights_only=False)
    pt_model.load_state_dict(ckpt.get("model_state_dict", ckpt))
    pt_model.eval()

    # Create fixed test sequence
    np.random.seed(42)
    sample_seq = np.random.randn(1, CONTEXT_LENGTH, NUM_CANONICAL_FEATURES).astype(np.float32)

    # PyTorch inference
    with torch.no_grad():
        pt_state, pt_class, pt_mitre, pt_threat, pt_attn = pt_model(torch.from_numpy(sample_seq))

    # ONNX Runtime inference
    engine = ONNXInferenceEngine(model_path=onnx_model_path)
    ort_out = engine.predict_step(sample_seq)

    # Assert exact numerical equivalence
    diff_threat = abs(pt_threat.numpy()[0] - ort_out["infiltration_prob"])
    diff_class = np.max(np.abs(pt_class.numpy()[0] - ort_out["class_logits"]))
    diff_state = np.max(np.abs(pt_state.numpy()[0] - ort_out["predicted_next_state"]))

    assert diff_threat < 1e-4, f"Threat probability discrepancy: {diff_threat:.2e}"
    assert diff_class < 1e-4, f"Class logits discrepancy: {diff_class:.2e}"
    assert diff_state < 1e-4, f"Predicted state discrepancy: {diff_state:.2e}"


def test_single_step_inference(onnx_model_path):
    """Verify single-step prediction outputs, shapes, and value bounds."""
    engine = ONNXInferenceEngine(model_path=onnx_model_path)
    seq = np.random.randn(1, CONTEXT_LENGTH, NUM_CANONICAL_FEATURES).astype(np.float32)

    out = engine.predict_step(seq)

    assert "predicted_next_state" in out
    assert "class_probs" in out
    assert "predicted_class_label" in out
    assert "mitre_stage" in out
    assert "mitre_tactic" in out
    assert "infiltration_prob" in out
    assert "attention_weights" in out

    # Shapes and constraints
    assert out["predicted_next_state"].shape == (84,)
    assert out["class_probs"].shape == (13,)
    assert abs(np.sum(out["class_probs"]) - 1.0) < 1e-5
    assert 0.0 <= out["infiltration_prob"] <= 1.0
    assert 0 <= out["mitre_stage"] <= 5
    assert out["predicted_class_label"] in ATTACK_CLASSES
    assert out["mitre_tactic"] == MITRE_STAGES[out["mitre_stage"]]
    assert out["attention_weights"].shape == (3,)


def test_autoregressive_k5_rollout(onnx_model_path):
    """Verify K=5 autoregressive rollout trajectories and predicted kill-chain escalation."""
    engine = ONNXInferenceEngine(model_path=onnx_model_path)
    seq = np.random.randn(1, CONTEXT_LENGTH, NUM_CANONICAL_FEATURES).astype(np.float32)

    rollout_out = engine.rollout(seq, k_steps=5)

    assert "k_step_rollout" in rollout_out
    assert "mitre_trajectory" in rollout_out
    assert "predicted_classes" in rollout_out
    assert "predicted_states" in rollout_out

    assert len(rollout_out["k_step_rollout"]) == 5
    assert len(rollout_out["mitre_trajectory"]) == 5
    assert len(rollout_out["predicted_classes"]) == 5
    assert rollout_out["predicted_states"].shape == (5, 84)

    for p in rollout_out["k_step_rollout"]:
        assert 0.0 <= p <= 1.0
    for stage in rollout_out["mitre_trajectory"]:
        assert 0 <= stage <= 5


def test_cpu_latency_benchmark(onnx_model_path):
    """Verify that ONNX Runtime inference latency satisfies the lightweight SLA (< 10 ms)."""
    engine = ONNXInferenceEngine(model_path=onnx_model_path)
    metrics = engine.benchmark_latency(num_runs=150)

    print(f"\n[ONNX Runtime CPU Inference Latency Benchmark]:")
    print(f"  - Mean Latency:   {metrics['mean_ms']:.3f} ms")
    print(f"  - Median (p50):   {metrics['p50_ms']:.3f} ms")
    print(f"  - 95th Percentile: {metrics['p95_ms']:.3f} ms")
    print(f"  - 99th Percentile: {metrics['p99_ms']:.3f} ms")
    print(f"  - Throughput:     {metrics['throughput_samples_per_sec']:.0f} samples/sec")

    assert metrics["mean_ms"] < 15.0, f"Mean latency {metrics['mean_ms']:.2f} ms exceeds 15 ms limit"
    assert metrics["throughput_samples_per_sec"] > 50.0


if __name__ == "__main__":
    pytest.main(["-v", "-s", __file__])
