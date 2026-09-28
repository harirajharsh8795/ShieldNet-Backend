"""
ShieldNet Tier 2 Cross-Node Threat Intel Corroboration Engine.

Implements Sections 3, 5, and 6 of ShieldNet Tech Stack:
- Strictly network-only, zero-system, zero-IP verifiable threat signatures.
- Local detection runs continuous and uninterrupted: local inference is NEVER skipped or overridden.
- Incoming peer signatures act solely as an enrichment signal for local corroboration.
- Mathematical similarity check: Computes cosine similarity between local 84-dimensional
  SHAP attribution vectors and incoming peer threat fingerprints.
- If local traffic exhibits a matching feature pattern, confidence is boosted;
  if local traffic does not match, peer signatures have ZERO effect (malicious/false
  peer flags cannot manufacture an attack out of thin air).
- Fully air-gap compliant: signature payloads are compact, deterministic JSON blobs
  containing only statistical attribution vectors and SHA-256 hash proofs.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
import hashlib
import json
import time
import numpy as np

from shared.schema import (
    CANONICAL_84_FEATURES,
    NUM_CANONICAL_FEATURES,
    ATTACK_CLASSES,
    MITRE_STAGES,
)


# Forbidden keys that must NEVER appear in an exported or imported threat signature
FORBIDDEN_SYSTEM_KEYS = {
    "ip", "src_ip", "dst_ip", "source_ip", "destination_ip", "s_ip", "d_ip",
    "mac", "src_mac", "dst_mac", "hostname", "host", "computer_name",
    "username", "user", "process_id", "pid", "device_id", "guid"
}


@dataclass
class PeerThreatSignature:
    """
    A verifiable, portable, zero-system-data threat signature payload
    suitable for cross-node threat intelligence sharing.
    """
    signature_id: str                      # Deterministic SHA-256 digest of canonical fields
    origin_node_id: str                    # Anonymized / pseudonymous node ID
    timestamp: float
    iso_time: str
    prediction: str                        # Attack class label from ATTACK_CLASSES
    threat_probability: float              # Confidence at origin node [0.0, 1.0]
    mitre_stage: int                       # MITRE ATT&CK stage index [0..5]
    mitre_tactic: str                      # MITRE tactic name
    shap_vector: np.ndarray                # Continuous (84,) float32 SHAP attribution vector
    top_drivers: List[Dict[str, Any]]      # Ranked top feature drivers (names & weights, zero IP)
    prev_hash: str                         # Genesis or previous block SHA-256 hash
    record_hash: str                       # Cryptographic Action Ledger record hash

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the signature to a dictionary, strictly omitting all system/IP data."""
        return {
            "signature_id": self.signature_id,
            "origin_node_id": self.origin_node_id,
            "timestamp": round(self.timestamp, 6),
            "iso_time": self.iso_time,
            "prediction": self.prediction,
            "threat_probability": round(float(self.threat_probability), 4),
            "mitre_stage": int(self.mitre_stage),
            "mitre_tactic": self.mitre_tactic,
            "shap_vector": self.shap_vector.astype(np.float32).tolist(),
            "top_drivers": self.top_drivers,
            "prev_hash": self.prev_hash,
            "record_hash": self.record_hash,
        }

    @classmethod
    def compute_signature_id(
        cls,
        origin_node_id: str,
        timestamp: float,
        prediction: str,
        threat_probability: float,
        mitre_stage: int,
        shap_vector: np.ndarray,
        record_hash: str,
    ) -> str:
        """Computes deterministic SHA-256 hash of signature canonical payload."""
        # Quantize float array for cross-platform deterministic serialization
        vec_bytes = np.round(shap_vector, decimals=5).astype(np.float32).tobytes()
        vec_digest = hashlib.sha256(vec_bytes).hexdigest()
        
        raw_payload = (
            f"{origin_node_id}|"
            f"{timestamp:.6f}|"
            f"{prediction}|"
            f"{threat_probability:.4f}|"
            f"{mitre_stage}|"
            f"{vec_digest}|"
            f"{record_hash}"
        )
        return hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()

    def verify_integrity(self) -> Tuple[bool, str]:
        """Validates cryptographic integrity and structural schema constraints."""
        if len(self.shap_vector) != NUM_CANONICAL_FEATURES:
            return False, f"Invalid SHAP vector dimension: expected {NUM_CANONICAL_FEATURES}, got {len(self.shap_vector)}"

        expected_id = self.compute_signature_id(
            origin_node_id=self.origin_node_id,
            timestamp=self.timestamp,
            prediction=self.prediction,
            threat_probability=self.threat_probability,
            mitre_stage=self.mitre_stage,
            shap_vector=self.shap_vector,
            record_hash=self.record_hash,
        )
        if self.signature_id != expected_id:
            return False, f"Signature digest mismatch: expected {expected_id}, got {self.signature_id}"

        return True, "VERIFIED"


@dataclass
class CorroborationResult:
    """Outcome of evaluating local detection against cross-node threat intelligence."""
    is_corroborated: bool
    boosted_probability: float
    original_probability: float
    max_similarity: float
    corroborating_signature_id: Optional[str] = None
    corroborating_node_id: Optional[str] = None
    corroborating_class: Optional[str] = None
    notes: str = "Local inference dominant"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_corroborated": self.is_corroborated,
            "boosted_probability": round(self.boosted_probability, 4),
            "original_probability": round(self.original_probability, 4),
            "max_similarity": round(self.max_similarity, 4),
            "corroborating_signature_id": self.corroborating_signature_id,
            "corroborating_node_id": self.corroborating_node_id,
            "corroborating_class": self.corroborating_class,
            "notes": self.notes,
        }


class CrossNodeCorroborator:
    """
    Tier 2 Cross-Node Threat Intelligence Corroborator.
    
    Cross-references locally evaluated SHAP feature fingerprints against incoming
    peer threat signatures using cosine similarity.
    """

    def __init__(
        self,
        node_id: str = "shieldnet-node-local",
        similarity_threshold: float = 0.75,
        max_boost: float = 0.15,
        signature_ttl_seconds: float = 86400.0,
    ):
        self.node_id = node_id
        self.similarity_threshold = similarity_threshold
        self.max_boost = max_boost
        self.signature_ttl = signature_ttl_seconds
        self.peer_signatures: Dict[str, PeerThreatSignature] = {}

    @staticmethod
    def compute_cosine_similarity(vec_a: np.ndarray, vec_b: np.ndarray) -> float:
        """
        Computes cosine similarity between two continuous vectors:
            sim(A, B) = (A . B) / (||A|| * ||B||)
        Returns 0.0 if either vector has zero magnitude.
        """
        a = np.asarray(vec_a, dtype=np.float32).ravel()
        b = np.asarray(vec_b, dtype=np.float32).ravel()
        if len(a) != len(b):
            raise ValueError(f"Vector dimensions do not match: {len(a)} vs {len(b)}")

        dot_prod = float(np.dot(a, b))
        norm_a = float(np.linalg.norm(a))
        norm_b = float(np.linalg.norm(b))

        if norm_a < 1e-12 or norm_b < 1e-12:
            return 0.0

        similarity = dot_prod / (norm_a * norm_b)
        return float(np.clip(similarity, -1.0, 1.0))

    def import_signature_payload(self, payload: Union[str, Dict[str, Any]]) -> Tuple[bool, str, Optional[PeerThreatSignature]]:
        """
        Parses, validates, and stores an incoming peer threat signature.
        
        Strict Privacy Check:
        Rejects payload immediately if ANY forbidden system/IP field is detected.
        """
        if isinstance(payload, str):
            try:
                data = json.loads(payload)
            except Exception as exc:
                return False, f"Malformed JSON payload: {exc}", None
        elif isinstance(payload, dict):
            data = payload
        else:
            return False, f"Unsupported payload type: {type(payload)}", None

        # 1. Enforce Zero System/IP Data Invariant
        found_forbidden = [k for k in data.keys() if k.lower() in FORBIDDEN_SYSTEM_KEYS]
        if found_forbidden:
            return False, f"Privacy violation: signature contains forbidden identity/system fields: {found_forbidden}", None

        # Check nested structures for forbidden keys
        top_drivers = data.get("top_drivers", [])
        if isinstance(top_drivers, list):
            for item in top_drivers:
                if isinstance(item, dict):
                    f_nested = [k for k in item.keys() if k.lower() in FORBIDDEN_SYSTEM_KEYS]
                    if f_nested:
                        return False, f"Privacy violation: nested top_drivers contains forbidden fields: {f_nested}", None

        # 2. Extract and validate required fields
        required_fields = [
            "signature_id", "origin_node_id", "timestamp", "prediction",
            "threat_probability", "mitre_stage", "shap_vector", "record_hash"
        ]
        for req in required_fields:
            if req not in data:
                return False, f"Missing required field in signature: '{req}'", None

        # 3. Construct PeerThreatSignature
        try:
            shap_vec = np.asarray(data["shap_vector"], dtype=np.float32)
            sig = PeerThreatSignature(
                signature_id=data["signature_id"],
                origin_node_id=data["origin_node_id"],
                timestamp=float(data["timestamp"]),
                iso_time=data.get("iso_time", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(data["timestamp"]))),
                prediction=data["prediction"],
                threat_probability=float(data["threat_probability"]),
                mitre_stage=int(data["mitre_stage"]),
                mitre_tactic=data.get("mitre_tactic", MITRE_STAGES.get(int(data["mitre_stage"]), "Normal Operations")),
                shap_vector=shap_vec,
                top_drivers=top_drivers,
                prev_hash=data.get("prev_hash", "0" * 64),
                record_hash=data["record_hash"],
            )
        except Exception as exc:
            return False, f"Signature data type construction error: {exc}", None

        # 4. Verify Cryptographic Integrity
        is_valid, msg = sig.verify_integrity()
        if not is_valid:
            return False, f"Integrity check failed: {msg}", None

        # 5. Store in peer signature pool
        self.peer_signatures[sig.signature_id] = sig
        self._prune_expired_signatures()
        return True, "SUCCESS", sig

    def export_signature(
        self,
        prediction: str,
        threat_probability: float,
        mitre_stage: int,
        mitre_tactic: str,
        shap_vector: np.ndarray,
        top_drivers: List[Dict[str, Any]],
        record_hash: str,
        prev_hash: str = "0" * 64,
        timestamp: Optional[float] = None,
    ) -> PeerThreatSignature:
        """
        Creates a new verifiable, zero-IP threat signature from local detection results.
        """
        ts = timestamp if timestamp is not None else time.time()
        iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
        vec = np.asarray(shap_vector, dtype=np.float32)

        sig_id = PeerThreatSignature.compute_signature_id(
            origin_node_id=self.node_id,
            timestamp=ts,
            prediction=prediction,
            threat_probability=threat_probability,
            mitre_stage=mitre_stage,
            shap_vector=vec,
            record_hash=record_hash,
        )

        return PeerThreatSignature(
            signature_id=sig_id,
            origin_node_id=self.node_id,
            timestamp=ts,
            iso_time=iso,
            prediction=prediction,
            threat_probability=threat_probability,
            mitre_stage=mitre_stage,
            mitre_tactic=mitre_tactic,
            shap_vector=vec,
            top_drivers=top_drivers,
            prev_hash=prev_hash,
            record_hash=record_hash,
        )

    def corroborate_local_threat(
        self,
        local_shap: np.ndarray,
        local_threat_prob: float,
        local_pred_class: str,
    ) -> CorroborationResult:
        """
        Cross-references local detection against active peer signatures.
        
        Strict Invariants:
        1. Local detection is NEVER skipped or overridden.
        2. If local traffic has nominal threat probability (< 0.40) or predicts BENIGN,
           external peer signatures CANNOT manufacture an alert (returns non-corroborated).
        3. Only when local traffic exhibits a non-benign pattern AND high cosine similarity
           with a peer signature is a confidence boost applied.
        """
        # If local detection saw benign / unflagged traffic, peer signatures must never trigger an alert
        if local_threat_prob < 0.40 or local_pred_class == "BENIGN":
            return CorroborationResult(
                is_corroborated=False,
                boosted_probability=local_threat_prob,
                original_probability=local_threat_prob,
                max_similarity=0.0,
                notes="Local traffic is benign; external signatures bypassed."
            )

        if not self.peer_signatures:
            return CorroborationResult(
                is_corroborated=False,
                boosted_probability=local_threat_prob,
                original_probability=local_threat_prob,
                max_similarity=0.0,
                notes="No active peer threat signatures loaded."
            )

        best_sig: Optional[PeerThreatSignature] = None
        best_sim: float = -1.0

        for sig in self.peer_signatures.values():
            # Originating from self is skipped
            if sig.origin_node_id == self.node_id:
                continue

            # Compute cosine similarity across 84-dimensional continuous SHAP space
            sim = self.compute_cosine_similarity(local_shap, sig.shap_vector)
            if sim > best_sim:
                best_sim = sim
                best_sig = sig

        if best_sig is not None and best_sim >= self.similarity_threshold:
            # Corroborated! Calculate scaled boost based on similarity and peer confidence
            # boost = max_boost * similarity * peer_probability
            boost = self.max_boost * best_sim * best_sig.threat_probability
            boosted_prob = min(1.0, local_threat_prob + boost)

            return CorroborationResult(
                is_corroborated=True,
                boosted_probability=float(boosted_prob),
                original_probability=float(local_threat_prob),
                max_similarity=float(best_sim),
                corroborating_signature_id=best_sig.signature_id,
                corroborating_node_id=best_sig.origin_node_id,
                corroborating_class=best_sig.prediction,
                notes=f"Corroborated by peer {best_sig.origin_node_id} (Cosine Similarity: {best_sim:.3f})"
            )

        return CorroborationResult(
            is_corroborated=False,
            boosted_probability=local_threat_prob,
            original_probability=local_threat_prob,
            max_similarity=max(0.0, best_sim),
            notes=f"Below similarity threshold ({best_sim:.3f} < {self.similarity_threshold:.2f})"
        )

    def _prune_expired_signatures(self):
        """Removes peer signatures exceeding TTL to bound in-memory cache size."""
        now = time.time()
        expired = [sid for sid, s in self.peer_signatures.items() if (now - s.timestamp) > self.signature_ttl]
        for sid in expired:
            del self.peer_signatures[sid]
