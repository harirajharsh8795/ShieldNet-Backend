"""
ShieldNet PyTorch to ONNX Exporter.

Loads the trained GRU+Attention World Model (world_model_v1.pt),
exports it into an optimized ONNX graph with dynamic batch and sequence axes,
and verifies numerical equivalence against ONNX Runtime.
"""

from pathlib import Path
from typing import Optional
import sys
import os

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")
os.environ["PYTHONIOENCODING"] = "utf-8"
import numpy as np
import torch
import onnx

# Add parent directory to sys.path
SCRIPT_DIR = Path(__file__).resolve().parent
DAEMON_ROOT = SCRIPT_DIR.parent
if str(DAEMON_ROOT) not in sys.path:
    sys.path.insert(0, str(DAEMON_ROOT))

from models.model_arch import WorldModel


def export_world_model_to_onnx(
    checkpoint_path: Optional[Path] = None,
    output_onnx_path: Optional[Path] = None,
    opset_version: int = 18,
    verbose: bool = False
) -> Path:
    """
    Exports world_model_v1.pt to ONNX format.
    
    Args:
        checkpoint_path: Path to PyTorch .pt checkpoint.
        output_onnx_path: Destination path for .onnx model.
        opset_version: ONNX operator set version (default 17).
        verbose: Verbose ONNX export logging.
        
    Returns:
        Path to the verified ONNX model file.
    """
    if checkpoint_path is None:
        checkpoint_path = DAEMON_ROOT / "models" / "checkpoints" / "world_model_v1.pt"
    checkpoint_path = Path(checkpoint_path)
    
    if output_onnx_path is None:
        output_onnx_path = DAEMON_ROOT / "models" / "onnx" / "world_model.onnx"
    output_onnx_path = Path(output_onnx_path)
    output_onnx_path.parent.mkdir(parents=True, exist_ok=True)

    if not checkpoint_path.exists():
        raise FileNotFoundError(f"Checkpoint not found at: {checkpoint_path}")

    # 1. Instantiate Model Architecture
    model = WorldModel(
        input_size=84,
        hidden_size=128,
        num_layers=2,
        dropout=0.2,
        num_classes=13,
        num_mitre_stages=6,
        use_attention=True
    )

    # 2. Load Weights
    ckpt = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
    state_dict = ckpt.get("model_state_dict", ckpt)
    model.load_state_dict(state_dict)
    model.eval()

    # 3. Create Representative Dummy Input (Batch=1, Seq_Len=3, Feats=84)
    dummy_input = torch.randn(1, 3, 84, dtype=torch.float32)

    # 4. Export to ONNX
    print(f"Exporting WorldModel to ONNX: {output_onnx_path} ...", flush=True)
    torch.onnx.export(
        model,
        dummy_input,
        str(output_onnx_path),
        export_params=True,
        opset_version=opset_version,
        do_constant_folding=True,
        input_names=["input_sequence"],
        output_names=[
            "predicted_next_state",
            "class_logits",
            "mitre_logits",
            "infiltration_prob",
            "attention_weights"
        ],
        dynamic_axes={
            "input_sequence": {0: "batch_size", 1: "seq_len"},
            "predicted_next_state": {0: "batch_size"},
            "class_logits": {0: "batch_size"},
            "mitre_logits": {0: "batch_size"},
            "infiltration_prob": {0: "batch_size"},
            "attention_weights": {0: "batch_size", 1: "seq_len"},
        }
    )

    # 5. Verify ONNX Graph
    onnx_model = onnx.load(str(output_onnx_path))
    onnx.checker.check_model(onnx_model)
    print(f"ONNX graph verified successfully! (File size: {output_onnx_path.stat().st_size / 1024:.1f} KB)", flush=True)

    # 6. Verify Numerical Equivalence with ONNX Runtime
    import onnxruntime as ort
    session = ort.InferenceSession(str(output_onnx_path), providers=["CPUExecutionProvider"])
    
    with torch.no_grad():
        pt_state, pt_class, pt_mitre, pt_threat, pt_attn = model(dummy_input)

    ort_inputs = {"input_sequence": dummy_input.numpy()}
    ort_outputs = session.run(None, ort_inputs)
    ort_state, ort_class, ort_mitre, ort_threat, ort_attn = ort_outputs

    max_diff_threat = np.max(np.abs(pt_threat.numpy() - ort_threat))
    max_diff_class = np.max(np.abs(pt_class.numpy() - ort_class))
    max_diff_state = np.max(np.abs(pt_state.numpy() - ort_state))

    print(f"Max Absolute Differences (PyTorch vs ONNX Runtime):", flush=True)
    print(f"  - Infiltration Probability: {max_diff_threat:.2e}", flush=True)
    print(f"  - Class Logits:             {max_diff_class:.2e}", flush=True)
    print(f"  - Predicted State:          {max_diff_state:.2e}", flush=True)

    assert max_diff_threat < 1e-4, f"Discrepancy in threat prob: {max_diff_threat}"
    assert max_diff_class < 1e-4, f"Discrepancy in class logits: {max_diff_class}"
    assert max_diff_state < 1e-4, f"Discrepancy in predicted state: {max_diff_state}"

    return output_onnx_path


if __name__ == "__main__":
    export_world_model_to_onnx()
