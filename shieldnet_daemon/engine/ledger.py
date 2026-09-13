"""
ShieldNet Tamper-Evident SQLite Action Ledger with Cryptographic Hash-Chaining.

Implements Section 2.6 of ShieldNet Tech Stack:
- Single-file embedded SQLite database (zero dependencies, fully offline, air-gap safe).
- High-concurrency WAL (Write-Ahead Logging) mode allowing the background daemon to write
  without blocking decoupled dashboard readers.
- Cryptographic SHA-256 hash-chaining: every record cryptographically links to the previous
  record's SHA-256 digest, providing mathematical tamper-evidence for compliance & auditing.
- Complete chain verification utility verifying every link and detecting unauthorized edits.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
import hashlib
import json
import sqlite3
import time
import numpy as np


GENESIS_HASH = "0" * 64  # 64 hexadecimal zeros representing the genesis block anchor


@dataclass
class LedgerRecord:
    """Represents a single tamper-evident record in the Action Ledger."""
    id: int
    timestamp: float
    iso_time: str
    prediction: str
    threat_probability: float
    mitre_stage: int
    mitre_tactic: str
    severity: str
    shap_summary: str
    shap_vector: Optional[np.ndarray]
    prev_hash: str
    record_hash: str
    source: str = "live_sniffer"

    def to_dict(self) -> Dict[str, Any]:
        """Serializes record to dictionary for API/Dashboard consumption."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "iso_time": self.iso_time,
            "prediction": self.prediction,
            "threat_probability": self.threat_probability,
            "mitre_stage": self.mitre_stage,
            "mitre_tactic": self.mitre_tactic,
            "severity": self.severity,
            "shap_summary": self.shap_summary,
            "shap_vector": self.shap_vector.tolist() if self.shap_vector is not None else None,
            "prev_hash": self.prev_hash,
            "record_hash": self.record_hash,
            "source": self.source,
        }


class ActionLedger:
    """
    Manages the offline SQLite action ledger with tamper-evident cryptographic hash-chaining.
    """
    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        if db_path is None:
            default_dir = Path(__file__).resolve().parent.parent / "data"
            default_dir.mkdir(parents=True, exist_ok=True)
            db_path = default_dir / "ledger.db"
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._init_database()

    def _get_connection(self) -> sqlite3.Connection:
        """Establishes an SQLite connection with WAL mode and row factory."""
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        # WAL mode enables non-blocking concurrent readers while daemon writes
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_database(self):
        """Initializes the action_ledger table and indexes if not present."""
        with self._get_connection() as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS action_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                iso_time TEXT NOT NULL,
                prediction TEXT NOT NULL,
                threat_probability REAL NOT NULL,
                mitre_stage INTEGER NOT NULL,
                mitre_tactic TEXT NOT NULL,
                severity TEXT NOT NULL,
                shap_summary TEXT NOT NULL,
                shap_vector BLOB,
                prev_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL,
                source TEXT DEFAULT 'live_sniffer'
            );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_timestamp ON action_ledger (timestamp);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_hash ON action_ledger (record_hash);")
            # Migrate table if source column doesn't exist
            cursor = conn.execute("PRAGMA table_info(action_ledger);")
            cols = [col["name"] for col in cursor.fetchall()]
            if "source" not in cols:
                conn.execute("ALTER TABLE action_ledger ADD COLUMN source TEXT DEFAULT 'live_sniffer';")
            conn.commit()

    @staticmethod
    def compute_record_hash(
        prev_hash: str,
        timestamp: float,
        prediction: str,
        threat_probability: float,
        mitre_stage: int,
        shap_summary: str,
        source: str = "live_sniffer"
    ) -> str:
        """
        Computes deterministic SHA-256 hash chaining over canonical fields.
        """
        payload = (
            f"{prev_hash}|"
            f"{timestamp:.6f}|"
            f"{prediction}|"
            f"{threat_probability:.4f}|"
            f"{mitre_stage}|"
            f"{shap_summary}|"
            f"{source}"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def get_latest_record(self) -> Optional[LedgerRecord]:
        """Fetches the most recent record appended to the chain."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM action_ledger ORDER BY id DESC LIMIT 1;")
            row = cursor.fetchone()
            if row is None:
                return None
            return self._row_to_record(row)

    def append_record(
        self,
        prediction: str,
        threat_probability: float,
        mitre_stage: int,
        mitre_tactic: str,
        severity: str,
        shap_summary: str,
        shap_vector: Optional[np.ndarray] = None,
        timestamp: Optional[float] = None,
        source: str = "live_sniffer"
    ) -> LedgerRecord:
        """
        Appends a new event cryptographically linked to the preceding record.
        
        Returns:
            The newly inserted LedgerRecord.
        """
        if timestamp is None:
            timestamp = time.time()
        iso_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))

        # Serialize shap_vector to bytes if provided (float32 continuous array)
        shap_blob = shap_vector.astype(np.float32).tobytes() if shap_vector is not None else None

        with self._get_connection() as conn:
            # Query latest record hash to establish chain link
            cursor = conn.execute("SELECT record_hash FROM action_ledger ORDER BY id DESC LIMIT 1;")
            latest_row = cursor.fetchone()
            prev_hash = latest_row["record_hash"] if latest_row else GENESIS_HASH

            # Compute record hash
            rec_hash = self.compute_record_hash(
                prev_hash=prev_hash,
                timestamp=timestamp,
                prediction=prediction,
                threat_probability=threat_probability,
                mitre_stage=mitre_stage,
                shap_summary=shap_summary,
                source=source
            )

            cursor = conn.execute("""
                INSERT INTO action_ledger (
                    timestamp, iso_time, prediction, threat_probability,
                    mitre_stage, mitre_tactic, severity, shap_summary,
                    shap_vector, prev_hash, record_hash, source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                timestamp, iso_time, prediction, threat_probability,
                mitre_stage, mitre_tactic, severity, shap_summary,
                shap_blob, prev_hash, rec_hash, source
            ))
            conn.commit()
            new_id = cursor.lastrowid

        return LedgerRecord(
            id=new_id,
            timestamp=timestamp,
            iso_time=iso_time,
            prediction=prediction,
            threat_probability=threat_probability,
            mitre_stage=mitre_stage,
            mitre_tactic=mitre_tactic,
            severity=severity,
            shap_summary=shap_summary,
            shap_vector=shap_vector,
            prev_hash=prev_hash,
            record_hash=rec_hash,
            source=source
        )

    def get_records(self, limit: int = 100, offset: int = 0) -> List[LedgerRecord]:
        """Retrieves paginated records in chronological order."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM action_ledger ORDER BY id ASC LIMIT ? OFFSET ?;",
                (limit, offset)
            )
            return [self._row_to_record(row) for row in cursor.fetchall()]

    def count_records(self) -> int:
        """Returns total records stored in the ledger."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM action_ledger;")
            return cursor.fetchone()[0]

    def get_recent_records(self, limit: int = 10) -> List[LedgerRecord]:
        """Retrieves most recent records in reverse chronological order (latest first)."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM action_ledger ORDER BY id DESC LIMIT ?;",
                (limit,)
            )
            return [self._row_to_record(row) for row in cursor.fetchall()]

    def get_record_by_id(self, record_id: int) -> Optional[LedgerRecord]:
        """Retrieves a single record by its primary key ID."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM action_ledger WHERE id = ?;", (record_id,))
            row = cursor.fetchone()
            if row is None:
                return None
            return self._row_to_record(row)

    def get_ledger_stats(self) -> Dict[str, Any]:
        """Returns high-level statistics and cryptographic integrity summary of the ledger."""
        count = self.count_records()
        is_valid, verified_cnt, error = self.verify_integrity()
        latest = self.get_latest_record()
        return {
            "total_records": count,
            "chain_valid": is_valid,
            "verified_records": verified_cnt,
            "latest_record_id": latest.id if latest else None,
            "latest_record_hash": (latest.record_hash[:16] + "...") if latest else None,
            "integrity_error": error,
        }

    def verify_integrity(self) -> Tuple[bool, int, Optional[str]]:
        """
        Cryptographically verifies the entire hash chain from Genesis to latest.
        
        Returns:
            Tuple of (is_valid: bool, verified_count: int, error_details: Optional[str])
        """
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM action_ledger ORDER BY id ASC;")
            rows = cursor.fetchall()

        if not rows:
            return True, 0, None

        expected_prev_hash = GENESIS_HASH

        for idx, row in enumerate(rows):
            row_id = row["id"]
            stored_prev = row["prev_hash"]
            stored_hash = row["record_hash"]

            # 1. Verify previous hash pointer
            if stored_prev != expected_prev_hash:
                return False, idx, (
                    f"Hash-chain broken at record ID {row_id}! "
                    f"Expected prev_hash '{expected_prev_hash[:16]}...', "
                    f"but found '{stored_prev[:16]}...'"
                )

            # 2. Recompute hash over row payload
            row_keys = row.keys() if hasattr(row, "keys") else []
            row_source = row["source"] if "source" in row_keys else "live_sniffer"

            recomputed_hash = self.compute_record_hash(
                prev_hash=stored_prev,
                timestamp=row["timestamp"],
                prediction=row["prediction"],
                threat_probability=row["threat_probability"],
                mitre_stage=row["mitre_stage"],
                shap_summary=row["shap_summary"],
                source=row_source
            )

            if recomputed_hash != stored_hash:
                return False, idx, (
                    f"Data tampering detected at record ID {row_id}! "
                    f"Stored hash '{stored_hash[:16]}...' does not match "
                    f"recomputed hash '{recomputed_hash[:16]}...'"
                )

            expected_prev_hash = stored_hash

        return True, len(rows), None

    def _row_to_record(self, row: sqlite3.Row) -> LedgerRecord:
        """Converts an SQLite row to a LedgerRecord dataclass."""
        blob = row["shap_vector"]
        shap_arr = np.frombuffer(blob, dtype=np.float32) if blob is not None else None
        row_keys = row.keys() if hasattr(row, "keys") else []
        row_source = row["source"] if "source" in row_keys else "live_sniffer"
        return LedgerRecord(
            id=row["id"],
            timestamp=row["timestamp"],
            iso_time=row["iso_time"],
            prediction=row["prediction"],
            threat_probability=row["threat_probability"],
            mitre_stage=row["mitre_stage"],
            mitre_tactic=row["mitre_tactic"],
            severity=row["severity"],
            shap_summary=row["shap_summary"],
            shap_vector=shap_arr,
            prev_hash=row["prev_hash"],
            record_hash=row["record_hash"],
            source=row_source
        )
