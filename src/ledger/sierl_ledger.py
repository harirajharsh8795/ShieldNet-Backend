"""
ShieldNet Immutable Evidence & Response Ledger (SIERL).

Core Cryptographic Ledger implementing:
- SHA-256 Hash Chained Block Structure
- Genesis Block Initialization
- Multi-Artifact Provenance (Evidence, Model Weights, Predictions, XAI Attributions)
- Human-in-the-Loop Admin Approval State Tracking
- Tamper-Detection & Verification Engine
- Thread-Safe Local JSON Persistence (Offline-First)
"""

import json
import os
import time
import datetime
import hashlib
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from src.ledger.evidence_hasher import (
    hash_canonical_json,
    hash_model_weights,
    hash_bytes_sha256
)
from src.ledger.orchestrator import get_firewall_orchestrator



class SIERLBlock:
    """Represents a single tamper-evident block in the SIERL chain."""

    def __init__(
        self,
        block_index: int,
        timestamp: str,
        incident_id: str,
        threat_type: str,
        severity: str,
        confidence: float,
        evidence_name: str,
        evidence_hash: str,
        model_hash: str,
        prediction_hash: str,
        xai_hash: str,
        approval_state: str = "PENDING",
        approver_role: Optional[str] = None,
        approval_timestamp: Optional[str] = None,
        proposed_action: Optional[str] = None,
        target_ip: Optional[str] = None,
        orchestration_record: Optional[Dict[str, Any]] = None,
        prev_hash: str = "",
        block_hash: str = ""
    ):
        self.block_index = block_index
        self.timestamp = timestamp
        self.incident_id = incident_id
        self.threat_type = threat_type
        self.severity = severity
        self.confidence = round(float(confidence), 4)
        self.evidence_name = evidence_name
        self.evidence_hash = evidence_hash
        self.model_hash = model_hash
        self.prediction_hash = prediction_hash
        self.xai_hash = xai_hash
        self.approval_state = approval_state
        self.approver_role = approver_role
        self.approval_timestamp = approval_timestamp
        self.proposed_action = proposed_action or "Rate Limit & Monitored Quarantine"
        self.target_ip = target_ip or "192.168.1.100"
        self.orchestration_record = orchestration_record
        self.prev_hash = prev_hash
        self.block_hash = block_hash or self.calculate_hash()

    def calculate_hash(self) -> str:
        """Computes SHA-256 digest over the block's canonical payload."""
        payload = {
            "block_index": self.block_index,
            "timestamp": self.timestamp,
            "incident_id": self.incident_id,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence_name": self.evidence_name,
            "evidence_hash": self.evidence_hash,
            "model_hash": self.model_hash,
            "prediction_hash": self.prediction_hash,
            "xai_hash": self.xai_hash,
            "approval_state": self.approval_state,
            "approver_role": self.approver_role,
            "approval_timestamp": self.approval_timestamp,
            "proposed_action": self.proposed_action,
            "target_ip": self.target_ip,
            "prev_hash": self.prev_hash,
        }
        return hash_canonical_json(payload)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes block to JSON-friendly dictionary."""
        return {
            "block_index": self.block_index,
            "timestamp": self.timestamp,
            "incident_id": self.incident_id,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence_name": self.evidence_name,
            "evidence_hash": self.evidence_hash,
            "model_hash": self.model_hash,
            "prediction_hash": self.prediction_hash,
            "xai_hash": self.xai_hash,
            "approval_state": self.approval_state,
            "approver_role": self.approver_role,
            "approval_timestamp": self.approval_timestamp,
            "proposed_action": self.proposed_action,
            "target_ip": self.target_ip,
            "orchestration_record": self.orchestration_record,
            "prev_hash": self.prev_hash,
            "block_hash": self.block_hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SIERLBlock":
        return cls(
            block_index=data["block_index"],
            timestamp=data["timestamp"],
            incident_id=data["incident_id"],
            threat_type=data["threat_type"],
            severity=data["severity"],
            confidence=data["confidence"],
            evidence_name=data.get("evidence_name", "network_capture.pcap"),
            evidence_hash=data["evidence_hash"],
            model_hash=data["model_hash"],
            prediction_hash=data["prediction_hash"],
            xai_hash=data["xai_hash"],
            approval_state=data.get("approval_state", "PENDING"),
            approver_role=data.get("approver_role"),
            approval_timestamp=data.get("approval_timestamp"),
            proposed_action=data.get("proposed_action"),
            target_ip=data.get("target_ip"),
            orchestration_record=data.get("orchestration_record"),
            prev_hash=data["prev_hash"],
            block_hash=data["block_hash"],
        )


class SIERLLedger:
    """
    Cryptographic Blockchain Ledger maintaining immutable chain of threat records,
    evidence digests, model versions, and human SOAR approvals.
    """

    def __init__(self, persistence_path: Optional[Path] = None):
        self.lock = threading.RLock()
        if persistence_path is None:
            base_dir = Path(__file__).parent.parent.parent / "models" / "checkpoints"
            base_dir.mkdir(parents=True, exist_ok=True)
            self.persistence_path = base_dir / "sierl_ledger.json"
        else:
            self.persistence_path = Path(persistence_path)

        self.chain: List[SIERLBlock] = []
        self._load_or_create_genesis()

    def _load_or_create_genesis(self):
        """Loads existing chain from disk or creates Genesis Block #0."""
        with self.lock:
            if self.persistence_path.exists():
                try:
                    with open(self.persistence_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    self.chain = [SIERLBlock.from_dict(b) for b in data.get("chain", [])]
                    if len(self.chain) > 0:
                        return
                except Exception as e:
                    print(f"[SIERL Warning] Failed loading ledger from {self.persistence_path}: {e}")

            # Initialize Genesis Block
            genesis = SIERLBlock(
                block_index=0,
                timestamp="2026-09-08T00:00:00Z",
                incident_id="GENESIS-BLOCK-000",
                threat_type="ROOT_CONSENSUS",
                severity="SYSTEM",
                confidence=1.0,
                evidence_name="genesis_manifest.json",
                evidence_hash="0000000000000000000000000000000000000000000000000000000000000000",
                model_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                prediction_hash="0000000000000000000000000000000000000000000000000000000000000000",
                xai_hash="0000000000000000000000000000000000000000000000000000000000000000",
                approval_state="GENESIS_AUTHORIZED",
                approver_role="System_Root",
                approval_timestamp="2026-09-08T00:00:00Z",
                proposed_action="Initialize Immutable Defense Ledger",
                target_ip="127.0.0.1",
                orchestration_record={"status": "INITIALIZED", "system": "SIERL v2.0"},
                prev_hash="0" * 64
            )
            self.chain = [genesis]
            self._save_to_disk()

    def _save_to_disk(self):
        """Saves current ledger state to JSON file."""
        try:
            payload = {
                "ledger_name": "ShieldNet Immutable Evidence & Response Ledger (SIERL)",
                "spec": "SIH26153 NTRO PS-153 Notary Layer",
                "total_blocks": len(self.chain),
                "last_updated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "chain": [b.to_dict() for b in self.chain]
            }
            with open(self.persistence_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except Exception as e:
            print(f"[SIERL Error] Could not persist ledger: {e}")

    def add_incident_block(
        self,
        incident_id: str,
        threat_type: str,
        severity: str,
        confidence: float,
        evidence_name: str,
        evidence_hash: str,
        model_hash: str,
        prediction_hash: str,
        xai_hash: str,
        proposed_action: Optional[str] = None,
        target_ip: Optional[str] = None,
        auto_approved: bool = False
    ) -> SIERLBlock:
        """Appends an immutable threat incident record with multi-artifact hashes."""
        with self.lock:
            prev_block = self.chain[-1]
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            
            approval_state = "APPROVED" if auto_approved else "PENDING"
            approver_role = "Autonomous_Safety_Policy" if auto_approved else None
            approval_timestamp = now_iso if auto_approved else None
            
            orchestration_record = None
            if auto_approved:
                orchestrator = get_firewall_orchestrator()
                orchestration_record = orchestrator.execute_action(
                    incident_id=incident_id,
                    action_type=proposed_action or "Rate Limit",
                    target_ip=target_ip or "192.168.1.100",
                    approver_role="Autonomous_Safety_Policy",
                    transaction_hash=""
                )

            new_block = SIERLBlock(
                block_index=len(self.chain),
                timestamp=now_iso,
                incident_id=incident_id,
                threat_type=threat_type,
                severity=severity,
                confidence=confidence,
                evidence_name=evidence_name,
                evidence_hash=evidence_hash,
                model_hash=model_hash,
                prediction_hash=prediction_hash,
                xai_hash=xai_hash,
                approval_state=approval_state,
                approver_role=approver_role,
                approval_timestamp=approval_timestamp,
                proposed_action=proposed_action,
                target_ip=target_ip,
                orchestration_record=orchestration_record,
                prev_hash=prev_block.block_hash
            )

            # Update orchestration transaction hash if executed
            if orchestration_record:
                orchestration_record["ledger_tx_hash"] = new_block.block_hash

            self.chain.append(new_block)
            self._save_to_disk()
            return new_block

    def approve_mitigation(
        self,
        incident_id: str,
        approver_role: str = "Admin",
        decision: str = "APPROVED"
    ) -> Optional[Dict[str, Any]]:
        """
        Processes human-in-the-loop security administrator decision.
        Updates state and triggers the simulated SOAR firewall executioner.
        """
        with self.lock:
            target_block = None
            for b in self.chain:
                if b.incident_id == incident_id:
                    target_block = b
                    break

            if not target_block:
                return None

            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            target_block.approval_state = decision
            target_block.approver_role = approver_role
            target_block.approval_timestamp = now_iso

            orchestration_record = None
            if decision == "APPROVED":
                orchestrator = get_firewall_orchestrator()
                orchestration_record = orchestrator.execute_action(
                    incident_id=incident_id,
                    action_type=target_block.proposed_action,
                    target_ip=target_block.target_ip,
                    approver_role=approver_role,
                    transaction_hash=target_block.block_hash
                )
                target_block.orchestration_record = orchestration_record

            # Re-seal block hash with updated approval record
            target_block.block_hash = target_block.calculate_hash()
            self._save_to_disk()

            return {
                "incident_id": incident_id,
                "block_index": target_block.block_index,
                "approval_state": decision,
                "approver_role": approver_role,
                "approval_timestamp": now_iso,
                "block_hash": target_block.block_hash,
                "orchestration_record": orchestration_record
            }

    def verify_chain(self) -> Tuple[bool, str, Optional[int]]:
        """
        Cryptographically verifies the entire ledger chain.
        Returns (is_valid, status_message, tampered_block_index).
        """
        with self.lock:
            for i in range(1, len(self.chain)):
                curr_block = self.chain[i]
                prev_block = self.chain[i - 1]

                # Check 1: Prev hash continuity
                if curr_block.prev_hash != prev_block.block_hash:
                    return (
                        False,
                        f"Hash Continuity Broken at Block #{curr_block.block_index}. Expected prev_hash {prev_block.block_hash[:16]}..., got {curr_block.prev_hash[:16]}...",
                        curr_block.block_index
                    )

                # Check 2: Block integrity
                expected_hash = curr_block.calculate_hash()
                if curr_block.block_hash != expected_hash:
                    return (
                        False,
                        f"Block #{curr_block.block_index} Content Tampered. Expected hash {expected_hash[:16]}..., found {curr_block.block_hash[:16]}...",
                        curr_block.block_index
                    )

            return (True, "Chain integrity 100% verified. All blocks valid & tamper-free.", None)

    def verify_evidence(self, evidence_hash: str) -> Dict[str, Any]:
        """
        Searches the immutable chain for a matching evidence hash.
        Supports forensic proof of evidence authenticity.
        """
        with self.lock:
            matches = []
            for b in self.chain:
                if b.evidence_hash.lower() == evidence_hash.lower():
                    matches.append(b.to_dict())

            is_valid_chain, chain_msg, _ = self.verify_chain()

            if matches:
                return {
                    "verified": True,
                    "evidence_hash": evidence_hash,
                    "status": "AUTHENTIC_RECORD_FOUND",
                    "chain_valid": is_valid_chain,
                    "message": "Evidence hash matches an immutable record registered on SIERL ledger.",
                    "matching_blocks": matches
                }
            else:
                return {
                    "verified": False,
                    "evidence_hash": evidence_hash,
                    "status": "UNREGISTERED_OR_TAMPERED",
                    "chain_valid": is_valid_chain,
                    "message": "No immutable commitment found for this evidence hash on the ledger.",
                    "matching_blocks": []
                }

    def log_analyst_override(
        self,
        incident_id: str,
        original_threat: str,
        corrected_threat: str,
        reason: str,
        analyst_user: str = "SecOps_Analyst_Tier2"
    ) -> Dict[str, Any]:
        """
        Appends an immutable Analyst False-Positive Override block to the chain.
        Captures the human correction, rationale, and flags the sample for retraining.
        """
        with self.lock:
            orig_block = None
            for b in self.chain:
                if b.incident_id == incident_id:
                    orig_block = b
                    break
                    
            prev_block = self.chain[-1]
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            
            override_evidence = f"OVERRIDE:{incident_id}:{original_threat}->{corrected_threat}:{reason}:{analyst_user}"
            override_hash = hash_bytes_sha256(override_evidence.encode("utf-8"))
            
            new_block = SIERLBlock(
                block_index=len(self.chain),
                timestamp=now_iso,
                incident_id=f"OVR-{incident_id}",
                threat_type=f"OVERRIDE: {original_threat} -> {corrected_threat}",
                severity="INFORMATIONAL",
                confidence=1.0,
                evidence_name=f"analyst_correction_{incident_id}.json",
                evidence_hash=override_hash,
                model_hash=orig_block.model_hash if orig_block else "0"*64,
                prediction_hash=orig_block.prediction_hash if orig_block else "0"*64,
                xai_hash=orig_block.xai_hash if orig_block else "0"*64,
                approval_state="OVERRIDDEN_FALSE_POSITIVE",
                approver_role=analyst_user,
                approval_timestamp=now_iso,
                proposed_action="Unblock IP & Commit Retraining Sample",
                target_ip=orig_block.target_ip if orig_block else "N/A",
                orchestration_record={
                    "status": "OVERRIDE_RECORDED",
                    "retraining_feedback_queued": True,
                    "original_threat": original_threat,
                    "corrected_threat": corrected_threat,
                    "reason": reason,
                    "analyst": analyst_user
                },
                prev_hash=prev_block.block_hash
            )
            
            self.chain.append(new_block)
            self._save_to_disk()
            
            return {
                "status": "OVERRIDE_COMMITTED_TO_SIERL",
                "incident_id": incident_id,
                "block_index": new_block.block_index,
                "block_hash": new_block.block_hash,
                "corrected_threat": corrected_threat,
                "reason": reason,
                "analyst": analyst_user,
                "timestamp": now_iso
            }

    def get_all_blocks(self) -> List[Dict[str, Any]]:
        with self.lock:
            return [b.to_dict() for b in self.chain]

    def get_block_by_incident_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            for b in self.chain:
                if b.incident_id == incident_id:
                    return b.to_dict()
            return None



# Global Singleton
_SIERL_LEDGER_INSTANCE = None

def get_sierl_ledger() -> SIERLLedger:
    global _SIERL_LEDGER_INSTANCE
    if _SIERL_LEDGER_INSTANCE is None:
        _SIERL_LEDGER_INSTANCE = SIERLLedger()
    return _SIERL_LEDGER_INSTANCE
