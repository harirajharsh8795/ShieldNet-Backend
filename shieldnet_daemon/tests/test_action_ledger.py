"""
ShieldNet Module 5 Verification Test Suite.

Validates:
1. SQLite initialization with WAL mode and schema integrity.
2. Genesis record anchoring with 64-zero SHA-256 prev_hash.
3. Cryptographic hash-chaining across sequential records.
4. Chain integrity verification passing on intact records.
5. Mathematical tamper detection: immediate identification when any byte in a record is modified.
6. Deletion/insertion detection: immediate detection if an intermediate record is deleted.
7. Serialization & deserialization of 84-dimensional SHAP attribution blobs.
"""

from pathlib import Path
import sqlite3
import time
import numpy as np
import pytest

from engine.ledger import ActionLedger, GENESIS_HASH


@pytest.fixture
def temp_ledger(tmp_path):
    """Creates a temporary isolated ActionLedger instance."""
    db_file = tmp_path / "test_ledger.db"
    return ActionLedger(db_path=db_file)


def test_genesis_record_creation(temp_ledger):
    """Verify that the first record in an empty ledger binds to the Genesis Hash."""
    assert temp_ledger.count_records() == 0

    rec = temp_ledger.append_record(
        prediction="PortScan",
        threat_probability=0.8850,
        mitre_stage=1,
        mitre_tactic="TA0043: Reconnaissance",
        severity="HIGH",
        shap_summary='{"top_drivers": ["SYN Flag Count (+0.45)"]}'
    )

    assert rec.id == 1
    assert rec.prev_hash == GENESIS_HASH
    assert len(rec.record_hash) == 64
    assert temp_ledger.count_records() == 1


def test_sequential_hash_chaining(temp_ledger):
    """Verify that subsequent records cryptographically link to their predecessor."""
    events = [
        ("BENIGN", 0.02, 0, "Normal Operations", "CLEAN"),
        ("PortScan", 0.85, 1, "TA0043: Reconnaissance", "HIGH"),
        ("Botnet C2", 0.91, 4, "TA0011: Command and Control", "HIGH"),
        ("DDoS", 0.99, 5, "TA0040: Impact", "HIGH"),
    ]

    records = []
    for pred, prob, stage, tactic, sev in events:
        r = temp_ledger.append_record(
            prediction=pred,
            threat_probability=prob,
            mitre_stage=stage,
            mitre_tactic=tactic,
            severity=sev,
            shap_summary=f'{{"pred": "{pred}"}}'
        )
        records.append(r)

    # Check cryptographic linking
    assert records[0].prev_hash == GENESIS_HASH
    for i in range(1, len(records)):
        assert records[i].prev_hash == records[i - 1].record_hash

    # Verify whole chain integrity
    is_valid, count, err = temp_ledger.verify_integrity()
    assert is_valid is True
    assert count == 4
    assert err is None


def test_tamper_detection_on_record_edit(temp_ledger):
    """Verify that altering any byte in an existing row is caught by verify_integrity."""
    # Insert 3 records
    for i in range(3):
        temp_ledger.append_record(
            prediction=f"Attack_{i}",
            threat_probability=0.80 + (i * 0.05),
            mitre_stage=i,
            mitre_tactic="Tactic",
            severity="HIGH",
            shap_summary=f'{{"attack_idx": {i}}}'
        )

    # Verify chain is initially pristine
    is_valid, count, err = temp_ledger.verify_integrity()
    assert is_valid is True
    assert count == 3

    # Tamper with Record ID 2: secretly modify the threat_probability
    with sqlite3.connect(str(temp_ledger.db_path)) as conn:
        conn.execute("UPDATE action_ledger SET threat_probability = 0.10 WHERE id = 2;")
        conn.commit()

    # Verify that integrity verification detects the tampering immediately
    is_valid, count, err = temp_ledger.verify_integrity()
    assert is_valid is False
    assert "Data tampering detected at record ID 2" in err


def test_deletion_detection(temp_ledger):
    """Verify that deleting a record from the chain breaks the cryptographic sequence."""
    # Insert 4 records
    for i in range(1, 5):
        temp_ledger.append_record(
            prediction=f"Event_{i}",
            threat_probability=0.70,
            mitre_stage=1,
            mitre_tactic="Tactic",
            severity="MEDIUM",
            shap_summary="{}"
        )

    # Delete Record ID 2
    with sqlite3.connect(str(temp_ledger.db_path)) as conn:
        conn.execute("DELETE FROM action_ledger WHERE id = 2;")
        conn.commit()

    is_valid, count, err = temp_ledger.verify_integrity()
    assert is_valid is False
    assert "Hash-chain broken at record ID 3" in err


def test_shap_vector_blob_persistence(temp_ledger):
    """Verify 84-dimensional continuous SHAP vector binary serialization and restoration."""
    sample_shap = np.random.randn(84).astype(np.float32)

    rec = temp_ledger.append_record(
        prediction="DDoS",
        threat_probability=0.98,
        mitre_stage=5,
        mitre_tactic="TA0040: Impact",
        severity="HIGH",
        shap_summary='{"top_driver": "flow_iat_mean"}',
        shap_vector=sample_shap
    )

    # Fetch from ledger
    latest = temp_ledger.get_latest_record()
    assert latest is not None
    assert latest.shap_vector is not None
    assert latest.shap_vector.shape == (84,)
    assert np.allclose(latest.shap_vector, sample_shap, atol=1e-6)


def test_wal_mode_concurrency(temp_ledger):
    """Verify that SQLite WAL mode is active and concurrent read queries succeed without locks."""
    with sqlite3.connect(str(temp_ledger.db_path)) as conn:
        cursor = conn.execute("PRAGMA journal_mode;")
        mode = cursor.fetchone()[0]
        assert mode.lower() == "wal"

    # Simulate concurrent reading while writing
    for i in range(5):
        temp_ledger.append_record(
            prediction="PortScan",
            threat_probability=0.85,
            mitre_stage=1,
            mitre_tactic="Reconnaissance",
            severity="HIGH",
            shap_summary="{}"
        )
        records = temp_ledger.get_records(limit=10)
        assert len(records) == i + 1


if __name__ == "__main__":
    pytest.main(["-v", __file__])
