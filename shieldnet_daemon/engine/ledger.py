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
    Supports row-capping and rolling checkpoint anchoring.
    """
    def __init__(self, db_path: Optional[Union[str, Path]] = None, max_records: Optional[int] = None):
        if db_path is None:
            default_dir = Path(__file__).resolve().parent.parent / "data"
            default_dir.mkdir(parents=True, exist_ok=True)
            db_path = default_dir / "ledger.db"
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._init_database()

        with self._get_connection() as conn:
            if max_records is not None:
                self.max_records = max_records
                conn.execute(
                    "INSERT INTO ledger_metadata (key, value) VALUES ('max_records', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
                    (str(max_records),),
                )
                conn.commit()
            else:
                cur = conn.execute("SELECT value FROM ledger_metadata WHERE key = 'max_records';")
                row = cur.fetchone()
                if row:
                    try:
                        self.max_records = int(row["value"])
                    except Exception:
                        self.max_records = 10000
                else:
                    self.max_records = 10000
                    conn.execute(
                        "INSERT INTO ledger_metadata (key, value) VALUES ('max_records', '10000');"
                    )
                    conn.commit()

    def _get_connection(self) -> sqlite3.Connection:
        """Establishes an SQLite connection with WAL mode and row factory."""
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        # WAL mode enables non-blocking concurrent readers while daemon writes
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_database(self):
        """Initializes the action_ledger and metadata tables and indexes if not present."""
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
            conn.execute("""
            CREATE TABLE IF NOT EXISTS ledger_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_timestamp ON action_ledger (timestamp);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_hash ON action_ledger (record_hash);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_prediction ON action_ledger (prediction);")
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

        # Auto-prune if max_records is configured
        if self.max_records is not None and self.max_records > 0:
            if new_id % 10 == 0 or self.count_records() > self.max_records:
                self.prune_records(self.max_records)

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

    def prune_records(self, keep_count: int) -> int:
        """
        Prunes older records to cap the ledger at keep_count rows while preserving
        cryptographic verification via a rolling checkpoint anchor.
        
        Returns:
            Number of pruned records.
        """
        if keep_count <= 0:
            return 0

        with self._get_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM action_ledger;")
            total = cursor.fetchone()[0]
            if total <= keep_count:
                return 0

            prune_count = total - keep_count

            # Find the cutoff row: the oldest row that WILL BE KEPT
            cursor = conn.execute(
                "SELECT id, prev_hash FROM action_ledger ORDER BY id DESC LIMIT 1 OFFSET ?;",
                (keep_count - 1,)
            )
            cutoff_row = cursor.fetchone()
            if cutoff_row is None:
                return 0

            cutoff_id = cutoff_row["id"]
            checkpoint_anchor = cutoff_row["prev_hash"]

            # Store the rolling checkpoint anchor
            conn.execute(
                "INSERT INTO ledger_metadata (key, value) VALUES ('checkpoint_anchor_hash', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
                (checkpoint_anchor,)
            )

            # Update cumulative pruned count
            cursor = conn.execute("SELECT value FROM ledger_metadata WHERE key = 'pruned_records_count';")
            pruned_meta = cursor.fetchone()
            old_pruned = int(pruned_meta["value"]) if pruned_meta else 0
            new_pruned = old_pruned + prune_count
            conn.execute(
                "INSERT INTO ledger_metadata (key, value) VALUES ('pruned_records_count', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
                (str(new_pruned),)
            )

            # Delete rows older than cutoff_id
            conn.execute("DELETE FROM action_ledger WHERE id < ?;", (cutoff_id,))
            conn.commit()

            # Passive WAL checkpoint
            try:
                conn.execute("PRAGMA wal_checkpoint(PASSIVE);")
            except Exception:
                pass

        return prune_count

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

        with self._get_connection() as conn:
            cur = conn.execute("SELECT value FROM ledger_metadata WHERE key = 'pruned_records_count';")
            p_row = cur.fetchone()
            pruned_count = int(p_row["value"]) if p_row else 0

        return {
            "total_records": count,
            "max_records": self.max_records,
            "pruned_records": pruned_count,
            "chain_valid": is_valid,
            "verified_records": verified_cnt,
            "latest_record_id": latest.id if latest else None,
            "latest_record_hash": (latest.record_hash[:16] + "...") if latest else None,
            "integrity_error": error,
        }

    def verify_integrity(self) -> Tuple[bool, int, Optional[str]]:
        """
        Cryptographically verifies the entire hash chain from Genesis/Checkpoint to latest.
        
        Returns:
            Tuple of (is_valid: bool, verified_count: int, error_details: Optional[str])
        """
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM action_ledger ORDER BY id ASC;")
            rows = cursor.fetchall()

            # Retrieve checkpoint anchor if ledger was previously pruned
            cursor = conn.execute("SELECT value FROM ledger_metadata WHERE key = 'checkpoint_anchor_hash';")
            meta_row = cursor.fetchone()
            checkpoint_anchor = meta_row["value"] if meta_row else None

        if not rows:
            return True, 0, None

        first_prev = rows[0]["prev_hash"]
        if first_prev == GENESIS_HASH:
            expected_prev_hash = GENESIS_HASH
        elif checkpoint_anchor is not None and first_prev == checkpoint_anchor:
            expected_prev_hash = checkpoint_anchor
        else:
            expected_prev_hash = checkpoint_anchor if checkpoint_anchor else GENESIS_HASH

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

    def export_threat_signature(self, record_id: int, node_id: str = "shieldnet-node-local") -> Optional[Dict[str, Any]]:
        """
        Exports a tamper-evident, zero-IP threat signature for a given ledger record.
        Strictly contains 84-dim SHAP attribution vector, MITRE classification, and SHA-256 hash.
        """
        record = self.get_record_by_id(record_id)
        if record is None:
            return None

        # Parse top_drivers from shap_summary if available
        top_drivers = []
        if record.shap_summary:
            try:
                summary_data = json.loads(record.shap_summary)
                top_drivers = summary_data.get("top_features", [])
            except Exception:
                top_drivers = []

        from engine.corroboration import CrossNodeCorroborator
        corroborator = CrossNodeCorroborator(node_id=node_id)
        shap_vec = record.shap_vector if record.shap_vector is not None else np.zeros(84, dtype=np.float32)
        sig = corroborator.export_signature(
            prediction=record.prediction,
            threat_probability=record.threat_probability,
            mitre_stage=record.mitre_stage,
            mitre_tactic=record.mitre_tactic,
            shap_vector=shap_vec,
            top_drivers=top_drivers,
            record_hash=record.record_hash,
            prev_hash=record.prev_hash,
            timestamp=record.timestamp,
        )
        return sig.to_dict()

    @staticmethod
    def verify_signature_payload(payload: Union[str, Dict[str, Any]]) -> Tuple[bool, str]:
        """
        Verifies cryptographic integrity and zero-IP privacy compliance of a threat signature payload.
        """
        from engine.corroboration import CrossNodeCorroborator
        corroborator = CrossNodeCorroborator()
        is_valid, msg, _ = corroborator.import_signature_payload(payload)
        return is_valid, msg

