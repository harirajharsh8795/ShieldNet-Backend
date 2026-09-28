"""
Tests for ShieldNet Cryptographic Asset Integrity & Anti-Poisoning Subsystem.
"""

from pathlib import Path
import json
import pytest
import shutil
import tempfile

from shared.integrity import IntegrityVerifier, SecurityIntegrityViolation, compute_sha256
from daemon.service import ShieldNetDaemon, DaemonConfig


def test_manifest_verification_on_valid_assets():
    """Verifies that the legitimate model directory passes manifest verification."""
    models_dir = Path(__file__).resolve().parent.parent / "models"
    is_valid, errors = IntegrityVerifier.verify_all(models_dir)
    assert is_valid is True
    assert len(errors) == 0


def test_integrity_detects_tampered_model(tmp_path):
    """Verifies that modifying any model weight causes an immediate SecurityIntegrityViolation."""
    fake_models_dir = tmp_path / "models"
    fake_onnx_dir = fake_models_dir / "onnx"
    fake_ckpt_dir = fake_models_dir / "checkpoints"
    fake_onnx_dir.mkdir(parents=True)
    fake_ckpt_dir.mkdir(parents=True)

    model_file = fake_onnx_dir / "world_model.onnx"
    scaler_file = fake_ckpt_dir / "scaler_reference.npz"
    logreg_file = fake_ckpt_dir / "logreg_params.npz"

    model_file.write_bytes(b"LEGITIMATE_MODEL_DATA_V1")
    scaler_file.write_bytes(b"LEGITIMATE_SCALER_DATA_V1")
    logreg_file.write_bytes(b"LEGITIMATE_LOGREG_DATA_V1")

    # Generate initial valid manifest
    IntegrityVerifier.generate_manifest(fake_models_dir)

    # Confirm it verifies cleanly
    assert IntegrityVerifier.verify_all(fake_models_dir)[0] is True

    # Tamper with the ONNX model (adversary injection / poisoning)
    model_file.write_bytes(b"TAMPERED_POISONED_MODEL_DATA_EVIL")

    with pytest.raises(SecurityIntegrityViolation) as exc_info:
        IntegrityVerifier.verify_all(fake_models_dir)

    assert "Integrity check failed" in str(exc_info.value) or "poisoning detected" in str(exc_info.value)


def test_integrity_detects_missing_model_file(tmp_path):
    """Verifies that deleting or missing a model file triggers a SecurityIntegrityViolation."""
    fake_models_dir = tmp_path / "models"
    fake_onnx_dir = fake_models_dir / "onnx"
    fake_ckpt_dir = fake_models_dir / "checkpoints"
    fake_onnx_dir.mkdir(parents=True)
    fake_ckpt_dir.mkdir(parents=True)

    model_file = fake_onnx_dir / "world_model.onnx"
    scaler_file = fake_ckpt_dir / "scaler_reference.npz"
    logreg_file = fake_ckpt_dir / "logreg_params.npz"

    model_file.write_bytes(b"DATA_A")
    scaler_file.write_bytes(b"DATA_B")
    logreg_file.write_bytes(b"DATA_C")

    IntegrityVerifier.generate_manifest(fake_models_dir)

    # Delete one file
    scaler_file.unlink()

    with pytest.raises(SecurityIntegrityViolation) as exc_info:
        IntegrityVerifier.verify_all(fake_models_dir)

    assert "missing" in str(exc_info.value).lower()


def test_production_posture_blocks_ipc_bridge():
    """Verifies that attempting to enable IPC in live sniffer mode triggers a SecurityIntegrityViolation."""
    config = DaemonConfig(
        mock_mode=False,
        enable_ipc=True,
        enforce_production_security=True,
        verify_integrity=False,  # bypass for rapid unit test
    )

    daemon = ShieldNetDaemon(config=config)
    with pytest.raises(SecurityIntegrityViolation) as exc_info:
        daemon.start()

    assert "Security Policy Violation" in str(exc_info.value)
    assert "restricted to mock/demo mode" in str(exc_info.value)
