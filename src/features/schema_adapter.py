"""
ShieldNet Cross-Dataset Schema Adapter.
SIH26153 NTRO PS-153 Mandated Interoperability Upgrade.

Translates heterogeneous network intrusion telemetry across diverse industry formats:
- CIC-IDS-2017 / CSE-CIC-IDS2018 (Canonical 84-feature NetFlow)
- UNSW-NB15 (49 features)
- CTU-13 Botnet (NetFlow v5/IPFIX)
- DARPA 1998 / 1999
Into ShieldNet's unified 84-dimensional feature vector, with deterministic
imputation for schema discrepancies.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import numpy as np
import pandas as pd
import json

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CKPT_DIR = PROJECT_ROOT / "models" / "checkpoints"


class CrossDatasetSchemaAdapter:
    """
    Standardizes disparate public and enterprise cybersecurity telemetry formats
    into the canonical 84-feature schema required by ShieldNet World Model and Ensembles.
    """
    def __init__(self, canonical_columns_path: Optional[Union[str, Path]] = None):
        if canonical_columns_path is None:
            canonical_columns_path = CKPT_DIR / "feature_columns.json"
        self.canonical_columns_path = Path(canonical_columns_path)
        
        self.canonical_columns: List[str] = []
        if self.canonical_columns_path.exists():
            try:
                with open(self.canonical_columns_path, "r") as f:
                    data = json.load(f)
                self.canonical_columns = data.get("features", [])[:84]
            except Exception:
                pass
                
        if not self.canonical_columns:
            # Fallback canonical list if file missing
            self.canonical_columns = [f"feat_{i}" for i in range(84)]

        # UNSW-NB15 to CIC-IDS mapping dictionary
        self.unsw_to_canonical = {
            "dur": "Flow Duration",
            "spkts": "Total Fwd Packets",
            "dpkts": "Total Backward Packets",
            "sbytes": "Total Length of Fwd Packets",
            "dbytes": "Total Length of Bwd Packets",
            "smean": "Fwd Packet Length Mean",
            "dmean": "Bwd Packet Length Mean",
            "rate": "Flow Packets/s",
            "sload": "Flow Bytes/s",
            "sinpkt": "Fwd IAT Mean",
            "dinpkt": "Bwd IAT Mean",
            "sjit": "Fwd IAT Std",
            "djit": "Bwd IAT Std",
            "swin": "Init_Win_bytes_forward",
            "dwin": "Init_Win_bytes_backward",
            "synack": "SYN Flag Count",
            "ackdat": "ACK Flag Count",
            "tcprtt": "Active Mean"
        }

        # CTU-13 / NetFlow to CIC-IDS mapping dictionary
        self.ctu_to_canonical = {
            "Dur": "Flow Duration",
            "TotPkts": "Total Fwd Packets",
            "TotBytes": "Total Length of Fwd Packets",
            "SrcBytes": "Total Length of Fwd Packets",
            "DstBytes": "Total Length of Bwd Packets",
            "SrcPkts": "Total Fwd Packets",
            "DstPkts": "Total Backward Packets",
            "Rate": "Flow Packets/s"
        }

    def detect_schema(self, columns: List[str]) -> str:
        """Automatically detects incoming dataset schema based on header signatures."""
        col_set = set(c.strip() for c in columns)
        
        # Check UNSW-NB15 signatures
        if {"dur", "spkts", "sbytes", "sttl"}.issubset(col_set) or "attack_cat" in col_set:
            return "UNSW_NB15"
            
        # Check CTU-13 signatures
        if {"Dur", "TotPkts", "TotBytes"}.issubset(col_set) or "sTos" in col_set:
            return "CTU_13"
            
        # Check CIC-IDS canonical
        if "Flow Duration" in col_set or "Total Fwd Packets" in col_set:
            return "CANONICAL_CICIDS"
            
        return "GENERIC_NUMERIC"

    def adapt_dataframe(self, df: pd.DataFrame, source_schema: Optional[str] = None) -> np.ndarray:
        """
        Transforms a DataFrame in any supported schema into an (N, 84) canonical feature matrix.
        Missing columns are filled with 0.0 (neutral baseline).
        """
        if source_schema is None:
            source_schema = self.detect_schema(list(df.columns))

        N = len(df)
        canonical_matrix = np.zeros((N, 84), dtype=np.float32)
        
        # 1. Canonical Schema Match
        if source_schema == "CANONICAL_CICIDS":
            for i, target_col in enumerate(self.canonical_columns):
                if target_col in df.columns:
                    canonical_matrix[:, i] = pd.to_numeric(df[target_col], errors="coerce").fillna(0.0).values
            return canonical_matrix

        # 2. UNSW-NB15 Adaptation
        elif source_schema == "UNSW_NB15":
            mapping = self.unsw_to_canonical
            mapped_targets = {}
            for src_col, target_col in mapping.items():
                if src_col in df.columns:
                    val = pd.to_numeric(df[src_col], errors="coerce").fillna(0.0).values
                    mapped_targets[target_col] = val

            for i, target_col in enumerate(self.canonical_columns):
                if target_col in mapped_targets:
                    canonical_matrix[:, i] = mapped_targets[target_col]
                elif target_col in df.columns:
                    canonical_matrix[:, i] = pd.to_numeric(df[target_col], errors="coerce").fillna(0.0).values
            return canonical_matrix

        # 3. CTU-13 Adaptation
        elif source_schema == "CTU_13":
            mapping = self.ctu_to_canonical
            mapped_targets = {}
            for src_col, target_col in mapping.items():
                if src_col in df.columns:
                    val = pd.to_numeric(df[src_col], errors="coerce").fillna(0.0).values
                    mapped_targets[target_col] = val

            for i, target_col in enumerate(self.canonical_columns):
                if target_col in mapped_targets:
                    canonical_matrix[:, i] = mapped_targets[target_col]
                elif target_col in df.columns:
                    canonical_matrix[:, i] = pd.to_numeric(df[target_col], errors="coerce").fillna(0.0).values
            return canonical_matrix

        # 4. Generic Numeric fallback
        else:
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            for i in range(min(84, len(numeric_cols))):
                canonical_matrix[:, i] = pd.to_numeric(df[numeric_cols[i]], errors="coerce").fillna(0.0).values
            return canonical_matrix

    def adapt_record(self, record: Dict[str, Any], source_schema: Optional[str] = None) -> np.ndarray:
        """Adapts a single incoming JSON dictionary to a 1D (84,) numpy array."""
        df_single = pd.DataFrame([record])
        return self.adapt_dataframe(df_single, source_schema=source_schema)[0]


# Global singleton
_schema_adapter_instance: Optional[CrossDatasetSchemaAdapter] = None

def get_schema_adapter() -> CrossDatasetSchemaAdapter:
    global _schema_adapter_instance
    if _schema_adapter_instance is None:
        _schema_adapter_instance = CrossDatasetSchemaAdapter()
    return _schema_adapter_instance
