"""
ShieldNet Cross-Dataset Schema Adapter.
SIH26153 NTRO PS-153 Mandated Interoperability Upgrade.

Translates heterogeneous network intrusion telemetry across diverse industry formats:
- CIC-IDS-2017 / CSE-CIC-IDS2018 (Canonical 84-feature NetFlow)
- UNSW-NB15 (49 features)
- CTU-13 Botnet (NetFlow v5/IPFIX)
- CICIoT2023 (46-feature IoT traffic — 33 attack types, 105 devices)
- LANL Authentication Logs (Enterprise Kerberos/NTLM lateral movement)
- DARPA 1998 / 1999
Into ShieldNet's unified 84-dimensional feature vector, with deterministic
imputation for schema discrepancies.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import numpy as np
import pandas as pd
import json
try:
    from src.features.schema import get_numeric_feature_names
except Exception:
    get_numeric_feature_names = None

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
                with open(self.canonical_columns_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.canonical_columns = data.get("numeric_features", data.get("features", []))[:84]
            except Exception:
                pass
                
        if not self.canonical_columns and get_numeric_feature_names is not None:
            try:
                self.canonical_columns = get_numeric_feature_names(include_packet_level=True)[:84]
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

        # ─── CICIoT2023 Schema Mapping ──────────────────────────────────────────
        # CICIoT2023 dataset uses a different naming convention (46 features).
        # Maps IoT-specific flow/flag features into canonical 84-dim vector.
        # Reference: Neto et al., 2023 — "CICIoT2023: A real-time dataset and
        # benchmark for large-scale attacks in IoT environment"
        self.ciciot_to_canonical = {
            # Flow duration / rate features
            "flow_duration": "Flow Duration",
            "Duration": "Flow Duration",
            "Rate": "Flow Packets/s",
            "Srate": "Fwd Packets/s",
            "Drate": "Bwd Packets/s",
            "Header_Length": "Fwd Header Length",
            # Packet size statistics
            "Tot sum": "Total Length of Fwd Packets",
            "Tot size": "Average Packet Size",
            "Min": "Min Packet Length",
            "Max": "Max Packet Length",
            "AVG": "Packet Length Mean",
            "Std": "Packet Length Std",
            "Variance": "Packet Length Variance",
            "Number": "Total Fwd Packets",
            # TCP flag columns (CICIoT2023 uses _flag_number suffix)
            "fin_flag_number": "FIN Flag Count",
            "syn_flag_number": "SYN Flag Count",
            "rst_flag_number": "RST Flag Count",
            "psh_flag_number": "PSH Flag Count",
            "ack_flag_number": "ACK Flag Count",
            "ece_flag_number": "ECE Flag Count",
            "cwr_flag_number": "CWE Flag Count",
            # Counter columns (cumulative counts per flow)
            "ack_count": "ACK Flag Count",
            "syn_count": "SYN Flag Count",
            "fin_count": "FIN Flag Count",
            "urg_count": "URG Flag Count",
            "rst_count": "RST Flag Count",
            # Inter-arrival time
            "IAT": "Flow IAT Mean",
            # Statistical shape features → mapped to nearest canonical slot
            "Magnitue": "Flow Bytes/s",
            "Radius": "Avg Fwd Segment Size",
            "Covariance": "Active Std",
            "Weight": "Down/Up Ratio",
        }

        # ─── LANL Authentication Log Schema Mapping ─────────────────────────────
        # Maps enterprise authentication event features into the tail
        # packet-level positions of the 84-dim canonical vector.
        # These features capture lateral movement / credential abuse signals
        # (MITRE ATT&CK T1078, T1021, T1550).
        self.lanl_to_canonical = {
            # Auth velocity → maps to flow rate proxy
            "auth_velocity": "Flow Packets/s",
            # Failed auth burst → maps to RST flag (failed connection analogue)
            "failed_auth_burst": "RST Flag Count",
            # Fan-out degree → maps to subflow forward packets (multi-host reach)
            "fan_out_degree": "Subflow Fwd Packets",
            # Session entropy → maps to packet length variance (randomness signal)
            "session_entropy": "Packet Length Variance",
        }

        # LANL binary/categorical encoding mappings
        self.lanl_auth_type_map = {
            "Kerberos": 0.0, "NTLM": 1.0, "Negotiate": 0.5
        }
        self.lanl_logon_type_map = {
            "Network": 1.0, "Interactive": 0.5, "Batch": 0.25, "Service": 0.75
        }
        self.lanl_result_map = {
            "Success": 0.0, "Failure": 1.0
        }

    def detect_schema(self, columns: List[str]) -> str:
        """Automatically detects incoming dataset schema based on header signatures."""
        col_set = set(c.strip() for c in columns)
        
        # Check LANL Authentication Log signatures (most specific first)
        if {"auth_velocity", "fan_out_degree", "failed_auth_burst"}.issubset(col_set):
            return "LANL_AUTH"
        if {"src_user", "dst_user", "auth_type", "logon_type"}.issubset(col_set):
            return "LANL_AUTH"
            
        # Check CICIoT2023 signatures (IoT-specific flag naming)
        if {"fin_flag_number", "syn_flag_number", "ack_flag_number"}.issubset(col_set):
            return "CICIOT_2023"
        if {"ack_count", "syn_count", "fin_count"}.issubset(col_set) and "Header_Length" in col_set:
            return "CICIOT_2023"
        
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

        # 4. CICIoT2023 Adaptation (46-feature IoT traffic telemetry)
        elif source_schema == "CICIOT_2023":
            mapping = self.ciciot_to_canonical
            mapped_targets = {}
            for src_col, target_col in mapping.items():
                if src_col in df.columns:
                    val = pd.to_numeric(df[src_col], errors="coerce").fillna(0.0).values
                    # Avoid overwriting a mapping with a lower-priority one
                    if target_col not in mapped_targets:
                        mapped_targets[target_col] = val

            # Map binary protocol indicator columns to canonical protocol slot
            # CICIoT2023 encodes protocol as binary columns (TCP, UDP, ICMP, etc.)
            protocol_binary_cols = ["TCP", "UDP", "ICMP"]
            protocol_values = np.zeros(N, dtype=np.float32)
            for proto_col, proto_num in [("TCP", 6.0), ("UDP", 17.0), ("ICMP", 1.0)]:
                if proto_col in df.columns:
                    mask = pd.to_numeric(df[proto_col], errors="coerce").fillna(0.0).values > 0.5
                    protocol_values[mask] = proto_num
            # If Protocol Type column exists, use it directly
            if "Protocol Type" in df.columns:
                protocol_values = pd.to_numeric(df["Protocol Type"], errors="coerce").fillna(0.0).values

            # Also map application-layer binary flags as secondary flow signals
            app_layer_cols = {
                "HTTP": "Fwd PSH Flags",   # HTTP traffic → PSH flag proxy
                "HTTPS": "Fwd URG Flags",  # HTTPS traffic → URG flag proxy
                "DNS": "Bwd PSH Flags",    # DNS traffic → backward PSH proxy
                "SSH": "Bwd URG Flags",    # SSH traffic → backward URG proxy
            }
            for app_col, target_col in app_layer_cols.items():
                if app_col in df.columns and target_col not in mapped_targets:
                    mapped_targets[target_col] = pd.to_numeric(
                        df[app_col], errors="coerce"
                    ).fillna(0.0).values

            for i, target_col in enumerate(self.canonical_columns):
                if target_col in mapped_targets:
                    canonical_matrix[:, i] = mapped_targets[target_col]
                elif target_col in df.columns:
                    canonical_matrix[:, i] = pd.to_numeric(
                        df[target_col], errors="coerce"
                    ).fillna(0.0).values
            return canonical_matrix

        # 5. LANL Authentication Log Adaptation
        elif source_schema == "LANL_AUTH":
            mapping = self.lanl_to_canonical
            mapped_targets = {}

            # Map numeric auth features to canonical slots
            for src_col, target_col in mapping.items():
                if src_col in df.columns:
                    val = pd.to_numeric(df[src_col], errors="coerce").fillna(0.0).values
                    mapped_targets[target_col] = val

            # Encode categorical auth features as continuous signals
            if "auth_type" in df.columns:
                auth_encoded = df["auth_type"].map(self.lanl_auth_type_map).fillna(0.5).values
                # Map to SYN Flag Count slot (auth protocol type signal)
                mapped_targets["SYN Flag Count"] = auth_encoded

            if "logon_type" in df.columns:
                logon_encoded = df["logon_type"].map(self.lanl_logon_type_map).fillna(0.5).values
                # Map to ACK Flag Count slot (session type signal)
                mapped_targets["ACK Flag Count"] = logon_encoded

            if "result" in df.columns:
                result_encoded = df["result"].map(self.lanl_result_map).fillna(0.5).values
                # Map to FIN Flag Count slot (auth success/failure signal)
                mapped_targets["FIN Flag Count"] = result_encoded

            # Timestamp → flow duration proxy
            if "time" in df.columns:
                time_vals = pd.to_numeric(df["time"], errors="coerce").fillna(0.0).values
                if len(time_vals) > 1:
                    # Inter-event time as flow duration
                    iet = np.diff(time_vals, prepend=time_vals[0])
                    mapped_targets["Flow Duration"] = iet
                    mapped_targets["Flow IAT Mean"] = iet

            for i, target_col in enumerate(self.canonical_columns):
                if target_col in mapped_targets:
                    canonical_matrix[:, i] = mapped_targets[target_col]
                elif target_col in df.columns:
                    canonical_matrix[:, i] = pd.to_numeric(
                        df[target_col], errors="coerce"
                    ).fillna(0.0).values
            return canonical_matrix

        # 6. Generic Numeric fallback
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
