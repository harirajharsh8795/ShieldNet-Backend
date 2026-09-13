"""
ShieldNet Persistent Database Storage (SQLAlchemy + SQLite).

Solves Weakness 2.1 from 1.pdf (In-memory deque & localStorage loss upon restart).
Maintains persistent records for all detected security incidents, evidence artifacts,
and ledger audit linkage. Fully offline-capable and ready for PostgreSQL in production.
"""

import os
import json
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session

Base = declarative_base()

class IncidentRecord(Base):
    """Persistent storage for security incidents."""
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(String(32), default=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    threat_type = Column(String(64), nullable=False)
    severity = Column(String(16), default="HIGH")
    confidence = Column(Float, default=0.0)
    evidence_name = Column(String(255), default="telemetry_stream.csv")
    evidence_hash = Column(String(64), index=True)
    mitre_stage = Column(Integer, default=0)
    mitre_tactic = Column(String(128), default="Unknown")
    status = Column(String(32), default="DETECTED")  # DETECTED, MITIGATED, REJECTED, AUTO_GATED
    mitigation_action = Column(String(128), default="Rate Limit & Monitor")
    target_ip = Column(String(64), default="192.168.1.100")
    ledger_block_index = Column(Integer, nullable=True)
    ledger_block_hash = Column(String(64), nullable=True)
    details_json = Column(Text, default="{}")

    def to_dict(self) -> Dict[str, Any]:
        details = {}
        if self.details_json:
            try:
                details = json.loads(self.details_json)
            except Exception:
                pass
        return {
            "incident_id": self.incident_id,
            "timestamp": self.timestamp,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence_name": self.evidence_name,
            "evidence_hash": self.evidence_hash,
            "mitre_stage": self.mitre_stage,
            "mitre_tactic": self.mitre_tactic,
            "status": self.status,
            "mitigation_action": self.mitigation_action,
            "target_ip": self.target_ip,
            "ledger_block_index": self.ledger_block_index,
            "ledger_block_hash": self.ledger_block_hash,
            "details": details
        }


class EvidenceRecord(Base):
    """Persistent storage for forensic evidence artifacts."""
    __tablename__ = "evidence_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    evidence_hash = Column(String(64), unique=True, index=True, nullable=False)
    filename = Column(String(255), nullable=False)
    file_type = Column(String(32), default="PCAP")
    size_bytes = Column(Integer, default=0)
    uploaded_at = Column(String(32), default=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    associated_incident_id = Column(String(64), nullable=True)
    ledger_block_hash = Column(String(64), nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_hash": self.evidence_hash,
            "filename": self.filename,
            "file_type": self.file_type,
            "size_bytes": self.size_bytes,
            "uploaded_at": self.uploaded_at,
            "associated_incident_id": self.associated_incident_id,
            "ledger_block_hash": self.ledger_block_hash
        }


class ThreatRecord(Base):
    """Persistent storage for detected flagged threat events."""
    __tablename__ = "threat_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(64), index=True, nullable=True)
    source_ip = Column(String(64), index=True, nullable=True)
    destination_ip = Column(String(64), index=True, nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(32), nullable=True)
    threat_probability = Column(Float, nullable=True)
    predicted_class = Column(String(128), index=True, nullable=True)
    severity = Column(String(32), nullable=True)
    mitre_stage = Column(String(128), nullable=True)
    timestamp = Column(String(64), default=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    shap_summary = Column(Text, default="{}")

    def to_dict(self) -> Dict[str, Any]:
        shap_data = {}
        if self.shap_summary:
            try:
                shap_data = json.loads(self.shap_summary)
            except Exception:
                shap_data = {"raw": self.shap_summary}
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "threat_probability": self.threat_probability,
            "predicted_class": self.predicted_class,
            "severity": self.severity,
            "mitre_stage": self.mitre_stage,
            "timestamp": self.timestamp,
            "shap_summary": shap_data,
        }


class DatabaseManager:
    """Manages persistent database sessions and transactions."""

    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            base_dir = Path(__file__).parent.parent.parent / "models" / "checkpoints"
            base_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = base_dir / "shieldnet_persistent.db"
        else:
            self.db_path = Path(db_path)

        # Allow connecting to custom DATABASE_URL (e.g. Postgres in production) or SQLite locally
        database_url = os.getenv("DATABASE_URL", f"sqlite:///{str(self.db_path).replace(chr(92), '/')}")
        self.engine = create_engine(database_url, echo=False)
        self.SessionFactory = scoped_session(sessionmaker(bind=self.engine))
        Base.metadata.create_all(self.engine)

    def get_session(self):
        return self.SessionFactory()

    def save_incident(
        self,
        incident_id: str,
        threat_type: str,
        severity: str,
        confidence: float,
        evidence_name: str,
        evidence_hash: str,
        mitre_stage: int = 0,
        mitre_tactic: str = "Unknown",
        status: str = "DETECTED",
        mitigation_action: str = "Rate Limit & Monitor",
        target_ip: str = "192.168.1.100",
        ledger_block_index: Optional[int] = None,
        ledger_block_hash: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        session = self.get_session()
        try:
            record = session.query(IncidentRecord).filter_by(incident_id=incident_id).first()
            if not record:
                record = IncidentRecord(incident_id=incident_id)
                session.add(record)

            record.threat_type = threat_type
            record.severity = severity
            record.confidence = round(float(confidence), 4)
            record.evidence_name = evidence_name
            record.evidence_hash = evidence_hash
            record.mitre_stage = mitre_stage
            record.mitre_tactic = mitre_tactic
            record.status = status
            record.mitigation_action = mitigation_action
            record.target_ip = target_ip
            if ledger_block_index is not None:
                record.ledger_block_index = ledger_block_index
            if ledger_block_hash is not None:
                record.ledger_block_hash = ledger_block_hash
            if details:
                record.details_json = json.dumps(details, default=str)

            session.commit()
            return record.to_dict()
        finally:
            session.close()

    def get_all_incidents(self, limit: int = 50) -> List[Dict[str, Any]]:
        session = self.get_session()
        try:
            records = session.query(IncidentRecord).order_by(IncidentRecord.id.desc()).limit(limit).all()
            return [r.to_dict() for r in records]
        finally:
            session.close()

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        session = self.get_session()
        try:
            record = session.query(IncidentRecord).filter_by(incident_id=incident_id).first()
            return record.to_dict() if record else None
        finally:
            session.close()

    def save_evidence_record(
        self,
        evidence_hash: str,
        filename: str,
        file_type: str = "PCAP",
        size_bytes: int = 0,
        associated_incident_id: Optional[str] = None,
        ledger_block_hash: Optional[str] = None
    ) -> Dict[str, Any]:
        session = self.get_session()
        try:
            record = session.query(EvidenceRecord).filter_by(evidence_hash=evidence_hash).first()
            if not record:
                record = EvidenceRecord(evidence_hash=evidence_hash)
                session.add(record)

            record.filename = filename
            record.file_type = file_type
            record.size_bytes = size_bytes
            if associated_incident_id:
                record.associated_incident_id = associated_incident_id
            if ledger_block_hash:
                record.ledger_block_hash = ledger_block_hash

            session.commit()
            return record.to_dict()
        finally:
            session.close()

    def save_threat(
        self,
        ip_address: Optional[str] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        source_port: Optional[int] = None,
        destination_port: Optional[int] = None,
        protocol: Optional[str] = None,
        threat_probability: Optional[float] = None,
        predicted_class: Optional[str] = None,
        severity: Optional[str] = None,
        mitre_stage: Optional[str] = None,
        timestamp: Optional[str] = None,
        shap_summary: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        session = self.get_session()
        try:
            record = ThreatRecord(
                ip_address=ip_address,
                source_ip=source_ip,
                destination_ip=destination_ip,
                source_port=source_port,
                destination_port=destination_port,
                protocol=protocol,
                threat_probability=round(float(threat_probability), 4) if threat_probability is not None else None,
                predicted_class=predicted_class,
                severity=severity,
                mitre_stage=mitre_stage,
                timestamp=timestamp or datetime.datetime.now(datetime.timezone.utc).isoformat(),
                shap_summary=json.dumps(shap_summary or {}, default=str),
            )
            session.add(record)
            session.commit()
            session.refresh(record)
            return record.to_dict()
        finally:
            session.close()

    def get_all_threats(self, limit: int = 50) -> List[Dict[str, Any]]:
        session = self.get_session()
        try:
            records = session.query(ThreatRecord).order_by(ThreatRecord.id.desc()).limit(limit).all()
            return [r.to_dict() for r in records]
        finally:
            session.close()


_DB_MANAGER_INSTANCE = None

def get_db_manager() -> DatabaseManager:
    global _DB_MANAGER_INSTANCE
    if _DB_MANAGER_INSTANCE is None:
        _DB_MANAGER_INSTANCE = DatabaseManager()
    return _DB_MANAGER_INSTANCE
