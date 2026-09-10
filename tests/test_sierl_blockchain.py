"""
Unit tests for ShieldNet Immutable Evidence & Response Ledger (SIERL).

Tests:
1. Genesis block initialization & structure
2. Adding incident blocks with multi-artifact hashes
3. Cryptographic hash chain continuity verification
4. Anti-Tampering Engine: modifying a committed block is detected immediately
5. Forensic Evidence verification (matching hash vs unknown hash)
6. Human-in-the-Loop SOAR Approval and Simulated Firewall Orchestration
"""

import os
import tempfile
import uuid
from pathlib import Path
import pytest

from src.ledger.sierl_ledger import SIERLLedger, SIERLBlock
from src.ledger.evidence_hasher import (
    hash_bytes_sha256,
    hash_file_sha256,
    hash_prediction,
    hash_xai_explanation
)
from src.ledger.orchestrator import FirewallOrchestrator


@pytest.fixture
def temp_ledger():
    """Creates a temporary SIERL ledger in an isolated temp file."""
    temp_path = Path(tempfile.gettempdir()) / f"test_sierl_{uuid.uuid4().hex[:8]}.json"
    ledger = SIERLLedger(persistence_path=temp_path)
    yield ledger

    if temp_path.exists():
        try:
            temp_path.unlink()
        except Exception:
            pass


def test_genesis_block_initialization(temp_ledger):
    """Verifies Genesis block is created correctly as Block #0."""
    assert len(temp_ledger.chain) == 1
    genesis = temp_ledger.chain[0]
    assert genesis.block_index == 0
    assert genesis.incident_id == "GENESIS-BLOCK-000"
    assert genesis.prev_hash == "0" * 64
    assert len(genesis.block_hash) == 64

    is_valid, msg, tampered_idx = temp_ledger.verify_chain()
    assert is_valid is True
    assert tampered_idx is None


def test_add_incident_blocks(temp_ledger):
    """Verifies blocks are appended with valid cryptographic links."""
    b1 = temp_ledger.add_incident_block(
        incident_id="inc-test-001",
        threat_type="SSH-Patator Brute Force",
        severity="CRITICAL",
        confidence=0.985,
        evidence_name="capture_bruteforce.pcap",
        evidence_hash=hash_bytes_sha256(b"pcap_payload_sample_001"),
        model_hash=hash_bytes_sha256(b"dummy_world_model_weights"),
        prediction_hash=hash_prediction("inc-test-001", "SSH-Patator", 0.985, 2, {"BENIGN": 0.015, "SSH-Patator": 0.985}),
        xai_hash=hash_xai_explanation("inc-test-001", ["Flow Packets/s", "Fwd IAT Mean"], "TA0001"),
        proposed_action="Isolate Host Port 22",
        target_ip="192.168.10.50"
    )

    assert b1.block_index == 1
    assert b1.prev_hash == temp_ledger.chain[0].block_hash
    assert len(temp_ledger.chain) == 2

    # Add second block
    b2 = temp_ledger.add_incident_block(
        incident_id="inc-test-002",
        threat_type="DoS Hulk Flood",
        severity="CRITICAL",
        confidence=0.992,
        evidence_name="capture_hulk.pcap",
        evidence_hash=hash_bytes_sha256(b"pcap_payload_sample_002"),
        model_hash=hash_bytes_sha256(b"dummy_world_model_weights"),
        prediction_hash=hash_prediction("inc-test-002", "DoS Hulk", 0.992, 5, {"BENIGN": 0.008, "DoS Hulk": 0.992}),
        xai_hash=hash_xai_explanation("inc-test-002", ["Bwd Packet Length Std"], "TA0040"),
        proposed_action="Rate Limit HTTP Ingress",
        target_ip="192.168.10.80"
    )

    assert b2.block_index == 2
    assert b2.prev_hash == b1.block_hash
    assert len(temp_ledger.chain) == 3

    # Chain must be valid
    is_valid, msg, _ = temp_ledger.verify_chain()
    assert is_valid is True


def test_anti_tampering_detection(temp_ledger):
    """
    CRITICAL SECURITY PROPERTY:
    Verifies that if an attacker alters even one byte in a previous block,
    the ledger immediately detects tampering and flags the exact corrupted block.
    """
    temp_ledger.add_incident_block(
        incident_id="inc-honest-001",
        threat_type="PortScan",
        severity="ELEVATED",
        confidence=0.88,
        evidence_name="honest.pcap",
        evidence_hash="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        model_hash="1111111111111111111111111111111111111111111111111111111111111111",
        prediction_hash="2222222222222222222222222222222222222222222222222222222222222222",
        xai_hash="3333333333333333333333333333333333333333333333333333333333333333"
    )

    temp_ledger.add_incident_block(
        incident_id="inc-honest-002",
        threat_type="Bot",
        severity="HIGH",
        confidence=0.91,
        evidence_name="honest2.pcap",
        evidence_hash="4444444444444444444444444444444444444444444444444444444444444444",
        model_hash="1111111111111111111111111111111111111111111111111111111111111111",
        prediction_hash="5555555555555555555555555555555555555555555555555555555555555555",
        xai_hash="6666666666666666666666666666666666666666666666666666666666666666"
    )

    # Sanity check: chain is currently valid
    assert temp_ledger.verify_chain()[0] is True

    # Malicious attacker secretly alters threat_type in Block 1
    temp_ledger.chain[1].threat_type = "BENIGN (Tampered)"

    # Ledger must catch tampering
    is_valid, err_msg, tampered_idx = temp_ledger.verify_chain()
    assert is_valid is False
    assert tampered_idx == 1
    assert "Tampered" in err_msg or "Content Tampered" in err_msg


def test_evidence_verification(temp_ledger):
    """Tests forensic verification of raw evidence digests."""
    raw_pcap = b"GENUINE_FORENSIC_CAPTURE_OCTETS_XYZ_123"
    pcap_hash = hash_bytes_sha256(raw_pcap)

    temp_ledger.add_incident_block(
        incident_id="inc-evidence-test",
        threat_type="Infiltration",
        severity="CRITICAL",
        confidence=0.97,
        evidence_name="forensic_capture.pcap",
        evidence_hash=pcap_hash,
        model_hash="aaaa"*16,
        prediction_hash="bbbb"*16,
        xai_hash="cccc"*16
    )

    # 1. Matching evidence lookup
    res_match = temp_ledger.verify_evidence(pcap_hash)
    assert res_match["verified"] is True
    assert res_match["status"] == "AUTHENTIC_RECORD_FOUND"
    assert len(res_match["matching_blocks"]) == 1

    # 2. Fake / modified evidence lookup
    fake_hash = hash_bytes_sha256(b"MODIFIED_PCAP_BYTES_TAMPERED")
    res_fake = temp_ledger.verify_evidence(fake_hash)
    assert res_fake["verified"] is False
    assert res_fake["status"] == "UNREGISTERED_OR_TAMPERED"


def test_human_approval_and_orchestration(temp_ledger):
    """
    Tests Human-in-the-Loop SOAR Approval and ensures
    Notary (Ledger) triggers the Executioner (Firewall Orchestrator).
    """
    inc_id = "inc-approval-flow"
    temp_ledger.add_incident_block(
        incident_id=inc_id,
        threat_type="Bot",
        severity="HIGH",
        confidence=0.94,
        evidence_name="bot_c2.csv",
        evidence_hash="dddd"*16,
        model_hash="eeee"*16,
        prediction_hash="ffff"*16,
        xai_hash="1212"*16,
        proposed_action="Isolate Host & Drop Ingress",
        target_ip="10.0.100.42"
    )

    # Initially pending
    block_before = temp_ledger.chain[-1]
    assert block_before.approval_state == "PENDING"
    assert block_before.orchestration_record is None

    # Admin approves
    approval_res = temp_ledger.approve_mitigation(
        incident_id=inc_id,
        approver_role="CISO (Admin)",
        decision="APPROVED"
    )

    assert approval_res is not None
    assert approval_res["approval_state"] == "APPROVED"
    assert "orchestration_record" in approval_res
    assert approval_res["orchestration_record"]["status"] == "ENFORCED"
    assert "iptables" in approval_res["orchestration_record"]["generated_rules"]
    assert "10.0.100.42" in approval_res["orchestration_record"]["generated_rules"]["iptables"]

    # Chain remains cryptographically sound after approval
    is_valid, _, _ = temp_ledger.verify_chain()
    assert is_valid is True


def test_analyst_override_logging(temp_ledger):
    """
    Tests Human Analyst False-Positive Override.
    Verifies that analyst corrections are committed as immutable feedback blocks on the chain.
    """
    inc_id = "inc-false-pos-404"
    temp_ledger.add_incident_block(
        incident_id=inc_id,
        threat_type="SSH-Patator",
        severity="HIGH",
        confidence=0.82,
        evidence_name="ssh_test.pcap",
        evidence_hash="11223344"*8,
        model_hash="55667788"*8,
        prediction_hash="99aabbcc"*8,
        xai_hash="ddeeff00"*8,
        proposed_action="Block Port 22",
        target_ip="192.168.1.105"
    )

    # Analyst overrides as benign authorized admin maintenance
    override_res = temp_ledger.log_analyst_override(
        incident_id=inc_id,
        original_threat="SSH-Patator",
        corrected_threat="BENIGN (Sysadmin Ansible Run)",
        reason="Scheduled automated maintenance window per Change Request CR-9021",
        analyst_user="Senior_Analyst_DevOps"
    )

    assert override_res["status"] == "OVERRIDE_COMMITTED_TO_SIERL"
    assert override_res["incident_id"] == inc_id
    assert override_res["corrected_threat"] == "BENIGN (Sysadmin Ansible Run)"
    assert len(temp_ledger.chain) == 3  # Genesis + Incident + Override

    override_block = temp_ledger.chain[-1]
    assert override_block.approval_state == "OVERRIDDEN_FALSE_POSITIVE"
    assert override_block.orchestration_record["retraining_feedback_queued"] is True

    # Entire chain must remain 100% valid
    is_valid, msg, tampered_idx = temp_ledger.verify_chain()
    assert is_valid is True
    assert tampered_idx is None

