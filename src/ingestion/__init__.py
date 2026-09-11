"""
ShieldNet Ingestion Module.
Provides multi-source telemetry ingestion: PCAP streams, NetFlow CSVs,
and LANL enterprise authentication log fusion engine.
"""

from src.ingestion.auth_log_fuser import (
    AuthLogFuser,
    get_auth_log_fuser
)

__all__ = [
    "AuthLogFuser",
    "get_auth_log_fuser",
]
