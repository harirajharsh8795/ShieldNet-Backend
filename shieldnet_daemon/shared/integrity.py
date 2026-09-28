"""
ShieldNet Cryptographic Asset Integrity & Anti-Poisoning Subsystem.

Verifies SHA-256 cryptographic signatures of all critical neural network models,
frozen scalers, and logistic regression parameters at startup before any inference
or packet capture begins.

Mitigates:
- Model Poisoning / Substitution attacks by malicious local processes.
- Supply-chain tampering or partial file corruption.
- Unauthorized weight modifications.
"""

from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import hashlib
import json
import logging

logger = logging.getLogger("ShieldNetIntegrity")


class SecurityIntegrityViolation(RuntimeError):
    """Raised when a critical model, scaler, or parameter file fails integrity verification."""
    pass


def compute_sha256(file_path: Path) -> str:
    """Computes hexadecimal SHA-256 checksum of a file in 64KB chunks."""
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


class IntegrityVerifier:
    """
    Manages and verifies cryptographic integrity manifests for ShieldNet assets.
    """

    DEFAULT_MANIFEST_NAME = "manifest.json"

    @classmethod
    def generate_manifest(cls, models_dir: Path, output_path: Optional[Path] = None) -> Dict[str, str]:
        """
        Scans models directory and generates a SHA-256 integrity manifest.
        """
        models_dir = Path(models_dir)
        manifest_path = output_path or (models_dir / cls.DEFAULT_MANIFEST_NAME)

        critical_relative_files = [
            Path("onnx") / "world_model.onnx",
            Path("checkpoints") / "scaler_reference.npz",
            Path("checkpoints") / "logreg_params.npz",
        ]

        manifest: Dict[str, str] = {}
        for rel_file in critical_relative_files:
            abs_file = models_dir / rel_file
            if abs_file.exists():
                sha = compute_sha256(abs_file)
                # Store normalized posix relative path
                manifest[rel_file.as_posix()] = sha
                logger.info("[Integrity] Calculated SHA-256 for %s: %s", rel_file.as_posix(), sha[:16] + "...")
            else:
                logger.warning("[Integrity] Missing expected critical file during manifest generation: %s", abs_file)

        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        logger.info("[Integrity] Saved manifest to %s (%d files)", manifest_path, len(manifest))
        return manifest

    @classmethod
    def verify_all(cls, models_dir: Path, manifest_path: Optional[Path] = None) -> Tuple[bool, List[str]]:
        """
        Verifies all critical files listed in the manifest.
        
        Returns:
            (is_valid, list_of_errors)
        
        Raises:
            SecurityIntegrityViolation: If any file is missing, modified, or hash mismatches.
        """
        models_dir = Path(models_dir)
        manifest_file = manifest_path or (models_dir / cls.DEFAULT_MANIFEST_NAME)

        if not manifest_file.exists():
            err = f"Integrity manifest not found at {manifest_file}. Manifest required in production."
            logger.error("[Security] %s", err)
            raise SecurityIntegrityViolation(err)

        try:
            with open(manifest_file, "r", encoding="utf-8") as f:
                manifest: Dict[str, str] = json.load(f)
        except Exception as exc:
            err = f"Failed to parse integrity manifest {manifest_file}: {exc}"
            logger.error("[Security] %s", err)
            raise SecurityIntegrityViolation(err)

        if not manifest:
            err = f"Integrity manifest at {manifest_file} is empty."
            logger.error("[Security] %s", err)
            raise SecurityIntegrityViolation(err)

        errors: List[str] = []

        for rel_path_str, expected_hash in manifest.items():
            abs_file = models_dir / Path(rel_path_str)
            if not abs_file.exists():
                err_msg = f"Critical file missing: '{rel_path_str}' (Expected SHA-256: {expected_hash[:16]}...)"
                errors.append(err_msg)
                logger.critical("[Security Violation] %s", err_msg)
                continue

            actual_hash = compute_sha256(abs_file)
            if actual_hash.lower() != expected_hash.lower():
                err_msg = (
                    f"Integrity check failed for '{rel_path_str}'! "
                    f"Expected {expected_hash[:16]}..., got {actual_hash[:16]}... Possible model poisoning detected!"
                )
                errors.append(err_msg)
                logger.critical("[Security Violation] %s", err_msg)
            else:
                logger.debug("[Integrity] Verified %s OK (%s...)", rel_path_str, actual_hash[:12])

        if errors:
            raise SecurityIntegrityViolation(
                f"Security integrity checks failed ({len(errors)} violations):\n" + "\n".join(errors)
            )

        logger.info("[Integrity] All %d critical model assets cryptographically verified OK.", len(manifest))
        return True, []
