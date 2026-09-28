"""
ShieldNet Lightweight ONNX Runtime Inference & K=5 Rollout Engine.

Runs high-speed, continuous, headless network threat inference on CPU:
1. Loads optimized world_model.onnx via ONNX Runtime CPUExecutionProvider.
2. Single-step inference producing continuous state dynamics, 13-class attack forecasts,
   MITRE ATT&CK stages (0-5), and attention weights.
3. Autoregressive K=5 forward rollout producing threat probability trajectories
   and kill-chain escalation path.
4. Latency benchmarking against target SLA (< 5 ms on laptop-class hardware).
"""

from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Union
import time
import numpy as np
import onnxruntime as ort

from shared.schema import (
    ATTACK_CLASSES,
    MITRE_STAGES,
    CONTEXT_LENGTH,
    NUM_CANONICAL_FEATURES,
)
from shared.scaler_guard import FrozenReferenceScalerGuard


class ONNXInferenceEngine:
    """
    Production-grade ONNX Runtime inference wrapper for the ShieldNet World Model.
    Designed for continuous headless background execution on modest CPU hardware.
    """
    def __init__(
        self,
        model_path: Optional[Union[str, Path]] = None,
        scaler_guard: Optional[FrozenReferenceScalerGuard] = None,
        num_threads: int = 2
    ):
        if model_path is None:
            default_path = Path(__file__).resolve().parent.parent / "models" / "onnx" / "world_model.onnx"
            model_path = default_path
        self.model_path = Path(model_path)
        
        if not self.model_path.exists():
            raise FileNotFoundError(
                f"ONNX model not found at {self.model_path}. "
                f"Run 'python engine/export_onnx.py' first to generate it."
            )

        # Configure ONNX Runtime Session for fast, lightweight CPU execution
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = num_threads
        opts.inter_op_num_threads = 1
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        opts.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL

        self.session = ort.InferenceSession(
            str(self.model_path),
            sess_options=opts,
            providers=["CPUExecutionProvider"]
        )

        # Inspect input & output tensors
        self.input_name = self.session.get_inputs()[0].name
        self.output_names = [o.name for o in self.session.get_outputs()]

        # Associated reference scaler guard
        self.scaler_guard = scaler_guard or FrozenReferenceScalerGuard()

    def predict_step(self, sequence: np.ndarray) -> Dict[str, Any]:
        """
        Executes single-step inference on a temporal sequence tensor.
        
        Args:
            sequence: Array of shape (L=3, 84) or (B, L=3, 84).
            
        Returns:
            Dict containing:
            - 'predicted_next_state': (B, 84)
            - 'class_logits': (B, 13)
            - 'class_probs': (B, 13)
            - 'predicted_class_idx': int or list
            - 'predicted_class_label': str or list
            - 'mitre_logits': (B, 6)
            - 'mitre_probs': (B, 6)
            - 'mitre_stage': int or list
            - 'mitre_tactic': str or list
            - 'infiltration_prob': float or np.ndarray
            - 'attention_weights': (B, L)
        """
        seq = np.asarray(sequence, dtype=np.float32)
        if seq.ndim == 2:
            # Add batch dimension: (1, L, 84)
            seq = np.expand_dims(seq, axis=0)

        assert seq.shape[2] == NUM_CANONICAL_FEATURES, (
            f"Expected {NUM_CANONICAL_FEATURES} features, got {seq.shape[2]}"
        )

        # Run ONNX Runtime forward pass
        ort_inputs = {self.input_name: seq}
        outputs = self.session.run(None, ort_inputs)
        
        pred_state = outputs[0]        # (B, 84)
        class_logits = outputs[1]      # (B, 13)
        mitre_logits = outputs[2]      # (B, 6)
        threat_prob = outputs[3]       # (B,)
        attn_weights = outputs[4]      # (B, L)

        # Softmax for probabilities
        exp_class = np.exp(class_logits - np.max(class_logits, axis=-1, keepdims=True))
        class_probs = exp_class / np.sum(exp_class, axis=-1, keepdims=True)

        exp_mitre = np.exp(mitre_logits - np.max(mitre_logits, axis=-1, keepdims=True))
        mitre_probs = exp_mitre / np.sum(exp_mitre, axis=-1, keepdims=True)

        pred_class_idx = np.argmax(class_probs, axis=-1)
        pred_mitre_idx = np.argmax(mitre_probs, axis=-1)

        is_single = (seq.shape[0] == 1)
        
        return {
            "predicted_next_state": pred_state if not is_single else pred_state[0],
            "class_logits": class_logits if not is_single else class_logits[0],
            "class_probs": class_probs if not is_single else class_probs[0],
            "predicted_class_idx": int(pred_class_idx[0]) if is_single else pred_class_idx.tolist(),
            "predicted_class_label": ATTACK_CLASSES[pred_class_idx[0]] if is_single else [ATTACK_CLASSES[i] for i in pred_class_idx],
            "mitre_logits": mitre_logits if not is_single else mitre_logits[0],
            "mitre_probs": mitre_probs if not is_single else mitre_probs[0],
            "mitre_stage": int(pred_mitre_idx[0]) if is_single else pred_mitre_idx.tolist(),
            "mitre_tactic": MITRE_STAGES[pred_mitre_idx[0]] if is_single else [MITRE_STAGES[i] for i in pred_mitre_idx],
            "infiltration_prob": float(threat_prob[0]) if is_single else threat_prob,
            "attention_weights": attn_weights if not is_single else attn_weights[0],
        }

    def rollout(self, initial_sequence: np.ndarray, k_steps: int = 5) -> Dict[str, Any]:
        """
        Autoregressive multi-step forward simulation (K=5).
        
        At each step k in 1..K:
        1. Predicts step k dynamics, class, MITRE stage, and infiltration probability.
        2. Drops the oldest historical timestep and appends predicted state S_{t+k}.
        3. Repeats autoregressively.
        
        Args:
            initial_sequence: Array of shape (L=3, 84) or (1, L=3, 84).
            k_steps: Horizon length (default K=5).
            
        Returns:
            Dict containing:
            - 'k_step_rollout': List of K threat probabilities [P(threat)_{t+1} ... P(threat)_{t+K}]
            - 'mitre_trajectory': List of K MITRE stage indices
            - 'predicted_classes': List of K predicted attack class names
            - 'predicted_states': Array of shape (K, 84)
        """
        curr_seq = np.asarray(initial_sequence, dtype=np.float32)
        if curr_seq.ndim == 2:
            curr_seq = np.expand_dims(curr_seq, axis=0)  # (1, L, 84)
            
        rollout_probs = []
        rollout_mitre = []
        rollout_classes = []
        predicted_states = []

        for _ in range(k_steps):
            step_out = self.predict_step(curr_seq)
            
            p_threat = float(step_out["infiltration_prob"])
            rollout_probs.append(round(p_threat, 4))
            rollout_mitre.append(int(step_out["mitre_stage"]))
            rollout_classes.append(step_out["predicted_class_label"])
            
            pred_s = step_out["predicted_next_state"]  # (84,)
            predicted_states.append(pred_s)

            # Autoregressive update: drop oldest timestep (axis 1, index 0), append pred_s
            next_step_input = np.expand_dims(np.expand_dims(pred_s, axis=0), axis=1) # (1, 1, 84)
            curr_seq = np.concatenate([curr_seq[:, 1:, :], next_step_input], axis=1)

        return {
            "k_step_rollout": rollout_probs,
            "mitre_trajectory": rollout_mitre,
            "predicted_classes": rollout_classes,
            "predicted_states": np.array(predicted_states, dtype=np.float32),
            "k_steps": k_steps,
        }

    def benchmark_latency(self, num_runs: int = 300) -> Dict[str, float]:
        """
        Benchmarks inference latency over repeated runs on CPU to prove
        lightweight, low-latency execution.
        """
        dummy_input = np.random.randn(1, CONTEXT_LENGTH, NUM_CANONICAL_FEATURES).astype(np.float32)

        # Warmup (10 runs)
        for _ in range(10):
            self.predict_step(dummy_input)

        latencies_ms = []
        for _ in range(num_runs):
            t0 = time.perf_counter()
            self.predict_step(dummy_input)
            t1 = time.perf_counter()
            latencies_ms.append((t1 - t0) * 1000.0)

        latencies_ms = np.array(latencies_ms)
        return {
            "mean_ms": float(np.mean(latencies_ms)),
            "p50_ms": float(np.percentile(latencies_ms, 50)),
            "p95_ms": float(np.percentile(latencies_ms, 95)),
            "p99_ms": float(np.percentile(latencies_ms, 99)),
            "throughput_samples_per_sec": float(1000.0 / np.mean(latencies_ms)),
        }
