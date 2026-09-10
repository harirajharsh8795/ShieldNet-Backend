"""
ShieldNet Evidence & Artifact Hasher.

Computes SHA-256 cryptographic hashes for:
1. Raw Evidence (PCAP, CSV, JSON network telemetry)
2. Deployed Model Weights & Preprocessors (Model Supply Chain Integrity)
3. World Model Predictions & MITRE Stage Classifications
4. Explainability (XAI) Attributions (Captum Integrated Gradients)
5. Proposed Mitigation Actions
"""

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Union


def hash_bytes_sha256(data: bytes) -> str:
    """Computes SHA-256 digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def hash_file_sha256(file_path: Union[str, Path], chunk_size: int = 65536) -> str:
    """Computes SHA-256 digest of a local file in memory-efficient chunks."""
    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(f"File not found for hashing: {file_path}")

    sha = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(chunk_size):
            sha.update(chunk)
    return sha.hexdigest()


def hash_canonical_json(obj: Any) -> str:
    """
    Serializes a Python dict/object to deterministic sorted JSON
    and returns its SHA-256 digest.
    """
    canonical_str = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def hash_model_weights(model_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Generates cryptographic proof of model supply chain integrity
    by hashing checkpoint weights and file size.
    """
    p = Path(model_path)
    if not p.exists():
        return {
            "model_name": p.name if hasattr(p, "name") else "unknown",
            "model_path": str(model_path),
            "exists": False,
            "sha256": "UNKNOWN_MODEL_FILE",
            "size_bytes": 0
        }
    digest = hash_file_sha256(p)
    return {
        "model_name": p.name,
        "model_path": str(p),
        "exists": True,
        "sha256": digest,
        "size_bytes": p.stat().st_size
    }


def hash_prediction(
    incident_id: str,
    threat_type: str,
    confidence: float,
    mitre_stage: int,
    probabilities: Dict[str, float]
) -> str:
    """Computes SHA-256 hash of a World Model prediction payload."""
    payload = {
        "incident_id": incident_id,
        "threat_type": threat_type,
        "confidence": round(float(confidence), 6),
        "mitre_stage": int(mitre_stage),
        "probabilities": {k: round(float(v), 6) for k, v in sorted(probabilities.items())}
    }
    return hash_canonical_json(payload)


def hash_xai_explanation(
    incident_id: str,
    top_features: list,
    mitre_technique: str
) -> str:
    """Computes SHA-256 hash of an XAI attribution explanation."""
    payload = {
        "incident_id": incident_id,
        "top_features": top_features,
        "mitre_technique": mitre_technique
    }
    return hash_canonical_json(payload)
