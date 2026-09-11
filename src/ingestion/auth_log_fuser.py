"""
ShieldNet LANL Authentication Log Fusion Engine.

Integrates enterprise authentication event telemetry (Kerberos, NTLM, AD)
into the main ShieldNet prediction pipeline alongside network flow/packet data.

PS-153 Requirement: "May utilise flow records, packet captures, authentication
logs or other publicly available cybersecurity telemetry."

MITRE ATT&CK Coverage:
  - T1078: Valid Accounts (Credential Abuse Detection)
  - T1021: Remote Services (Lateral Movement via PsExec/WinRM)
  - T1550: Use Alternate Authentication Material (Pass-the-Hash)
  - T1098: Account Manipulation (Privilege Escalation)

Architecture:
  Auth logs are processed into 84-dim canonical feature vectors using the
  CrossDatasetSchemaAdapter (LANL_AUTH schema). This module provides:
  1. Raw LANL CSV ingestion with windowed temporal aggregation
  2. Auth-specific feature enrichment (velocity, fan-out, burst detection)
  3. Fusion with concurrent network telemetry via timestamp alignment
  4. Direct integration with the /api/predict-sequence pipeline
"""

import os
import sys
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.features.schema_adapter import get_schema_adapter


# ─── Constants ────────────────────────────────────────────────────────────────
AUTH_WINDOW_SECONDS = 10.0    # Sliding window for auth event aggregation
MAX_FAN_OUT_NORMAL = 5        # Normal user typically accesses <= 5 hosts
BRUTE_FORCE_THRESHOLD = 5    # >= 5 failed auths in window = suspicious
LATERAL_VELOCITY_THRESHOLD = 10.0  # Auth events/sec threshold for lateral movement


class AuthLogFuser:
    """
    Processes LANL-format authentication logs and produces 84-dimensional
    canonical feature vectors compatible with the ShieldNet World Model.
    
    Supports two fusion modes:
      1. Standalone: Auth logs only → 84-dim vectors (missing network slots = 0)
      2. Enriched: Auth features injected into concurrent network flow vectors
    """
    
    def __init__(self, window_seconds: float = AUTH_WINDOW_SECONDS):
        self.window_seconds = window_seconds
        self.schema_adapter = get_schema_adapter()
        self._auth_cache: Optional[pd.DataFrame] = None
    
    def load_auth_log(self, path: Union[str, Path]) -> pd.DataFrame:
        """Load and validate a LANL authentication log CSV.
        
        Expected columns (minimal): time, src_user, dst_user, src_host, 
        dst_host, auth_type, logon_type, result
        
        Optional pre-computed features: auth_velocity, failed_auth_burst,
        fan_out_degree, session_entropy
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Auth log file not found: {path}")
        
        df = pd.read_csv(path, low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        
        # Validate minimum schema
        required_cols = {"src_user", "dst_user", "auth_type", "result"}
        missing = required_cols - set(df.columns)
        if missing:
            raise ValueError(
                f"Auth log missing required columns: {missing}. "
                f"Available: {list(df.columns)}"
            )
        
        # Ensure time column exists (generate sequential if missing)
        if "time" not in df.columns:
            df["time"] = np.arange(len(df), dtype=np.float64)
        else:
            df["time"] = pd.to_numeric(df["time"], errors="coerce").fillna(0.0)
        
        # Sort by time for temporal windowing
        df = df.sort_values("time").reset_index(drop=True)
        
        # Compute derived features if not already present
        if "auth_velocity" not in df.columns:
            df = self._compute_auth_features(df)
        
        self._auth_cache = df
        return df
    
    def _compute_auth_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Compute temporal auth behavior features using sliding windows.
        
        Features computed:
          - auth_velocity: Authentication events per second in sliding window
          - failed_auth_burst: Count of failed auths in sliding window
          - fan_out_degree: Unique destination hosts accessed in window
          - session_entropy: Shannon entropy of auth type distribution in window
        """
        n = len(df)
        auth_velocity = np.zeros(n, dtype=np.float64)
        failed_auth_burst = np.zeros(n, dtype=np.float64)
        fan_out_degree = np.zeros(n, dtype=np.float64)
        session_entropy = np.zeros(n, dtype=np.float64)
        
        times = df["time"].values
        results = df["result"].values if "result" in df.columns else np.full(n, "Success")
        dst_hosts = df["dst_host"].values if "dst_host" in df.columns else np.full(n, "UNKNOWN")
        auth_types = df["auth_type"].values if "auth_type" in df.columns else np.full(n, "Kerberos")
        
        for i in range(n):
            t_current = times[i]
            t_start = t_current - self.window_seconds
            
            # Window mask: events within [t_start, t_current]
            window_mask = (times >= t_start) & (times <= t_current)
            window_size = np.sum(window_mask)
            
            # Auth velocity (events/second)
            if self.window_seconds > 0:
                auth_velocity[i] = float(window_size) / self.window_seconds
            
            # Failed auth burst count
            window_results = results[window_mask]
            failed_auth_burst[i] = float(np.sum(
                np.array([r == "Failure" for r in window_results])
            ))
            
            # Fan-out degree (unique destination hosts)
            window_dst = dst_hosts[window_mask]
            fan_out_degree[i] = float(len(set(window_dst)))
            
            # Session entropy (diversity of auth types in window)
            window_auth = auth_types[window_mask]
            if len(window_auth) > 0:
                _, counts = np.unique(window_auth, return_counts=True)
                probs = counts / counts.sum()
                entropy = -np.sum(probs * np.log2(probs + 1e-10))
                session_entropy[i] = entropy
        
        df["auth_velocity"] = auth_velocity
        df["failed_auth_burst"] = failed_auth_burst
        df["fan_out_degree"] = fan_out_degree
        df["session_entropy"] = session_entropy
        
        return df
    
    def to_canonical_matrix(self, df: Optional[pd.DataFrame] = None) -> np.ndarray:
        """Convert auth log DataFrame to (N, 84) canonical feature matrix.
        
        Uses the CrossDatasetSchemaAdapter with LANL_AUTH schema detection.
        
        Returns:
            np.ndarray of shape (N, 84) — canonical feature vectors
        """
        if df is None:
            if self._auth_cache is None:
                raise ValueError("No auth log loaded. Call load_auth_log() first.")
            df = self._auth_cache
        
        # Use schema adapter for standardized conversion
        return self.schema_adapter.adapt_dataframe(df, source_schema="LANL_AUTH")
    
    def extract_labels(self, df: Optional[pd.DataFrame] = None) -> np.ndarray:
        """Extract attack labels from auth log DataFrame.
        
        Returns:
            np.ndarray of string labels (e.g., 'Benign', 'Lateral_Movement_RedTeam')
        """
        if df is None:
            if self._auth_cache is None:
                raise ValueError("No auth log loaded. Call load_auth_log() first.")
            df = self._auth_cache
        
        if "label" in df.columns:
            return df["label"].values
        
        # Heuristic labeling based on computed features
        labels = np.full(len(df), "Benign", dtype=object)
        
        if "fan_out_degree" in df.columns and "failed_auth_burst" in df.columns:
            suspicious_mask = (
                (df["fan_out_degree"].values > MAX_FAN_OUT_NORMAL) |
                (df["failed_auth_burst"].values >= BRUTE_FORCE_THRESHOLD)
            )
            labels[suspicious_mask] = "Suspicious_Auth"
        
        if "auth_velocity" in df.columns:
            lateral_mask = df["auth_velocity"].values > LATERAL_VELOCITY_THRESHOLD
            labels[lateral_mask] = "Lateral_Movement"
        
        return labels
    
    def fuse_with_network_telemetry(
        self,
        network_matrix: np.ndarray,
        network_timestamps: np.ndarray,
        auth_df: Optional[pd.DataFrame] = None,
        alignment_tolerance_sec: float = 5.0
    ) -> np.ndarray:
        """Fuse auth log features into concurrent network telemetry vectors.
        
        For each network flow timestep, finds the nearest auth events within
        ±alignment_tolerance_sec and injects auth behavioral features into
        the network flow's feature vector.
        
        Args:
            network_matrix: (N, 84) network flow feature matrix
            network_timestamps: (N,) array of timestamps for each network flow
            auth_df: LANL auth DataFrame (uses cache if None)
            alignment_tolerance_sec: Max time difference for alignment
            
        Returns:
            (N, 84) enriched feature matrix with auth signals injected
        """
        if auth_df is None:
            if self._auth_cache is None:
                return network_matrix  # No auth data, return unchanged
            auth_df = self._auth_cache
        
        if len(auth_df) == 0:
            return network_matrix
        
        enriched = network_matrix.copy()
        auth_times = auth_df["time"].values
        
        # Pre-compute auth feature arrays
        auth_velocity = auth_df["auth_velocity"].values if "auth_velocity" in auth_df.columns else np.zeros(len(auth_df))
        failed_burst = auth_df["failed_auth_burst"].values if "failed_auth_burst" in auth_df.columns else np.zeros(len(auth_df))
        fan_out = auth_df["fan_out_degree"].values if "fan_out_degree" in auth_df.columns else np.zeros(len(auth_df))
        sess_entropy = auth_df["session_entropy"].values if "session_entropy" in auth_df.columns else np.zeros(len(auth_df))
        
        # Auth feature target indices in canonical 84-dim vector
        # These are the column indices where auth features get injected
        canonical_cols = self.schema_adapter.canonical_columns
        
        # Find indices for auth-mapped canonical columns
        auth_inject_map = {}
        for feat_name, canon_name in self.schema_adapter.lanl_to_canonical.items():
            if canon_name in canonical_cols:
                idx = canonical_cols.index(canon_name)
                auth_inject_map[feat_name] = idx
        
        for i in range(len(network_timestamps)):
            t_net = network_timestamps[i]
            
            # Find nearest auth event within tolerance
            time_diffs = np.abs(auth_times - t_net)
            nearest_idx = np.argmin(time_diffs)
            
            if time_diffs[nearest_idx] <= alignment_tolerance_sec:
                # Inject auth features (additive blending — network signal preserved)
                if "auth_velocity" in auth_inject_map:
                    enriched[i, auth_inject_map["auth_velocity"]] += auth_velocity[nearest_idx]
                if "failed_auth_burst" in auth_inject_map:
                    enriched[i, auth_inject_map["failed_auth_burst"]] += failed_burst[nearest_idx]
                if "fan_out_degree" in auth_inject_map:
                    enriched[i, auth_inject_map["fan_out_degree"]] += fan_out[nearest_idx]
                if "session_entropy" in auth_inject_map:
                    enriched[i, auth_inject_map["session_entropy"]] += sess_entropy[nearest_idx]
        
        return enriched
    
    def get_summary_stats(self, df: Optional[pd.DataFrame] = None) -> Dict:
        """Return summary statistics for the loaded auth log."""
        if df is None:
            if self._auth_cache is None:
                return {"status": "no_data_loaded"}
            df = self._auth_cache
        
        labels = self.extract_labels(df)
        unique_labels, counts = np.unique(labels, return_counts=True)
        
        stats = {
            "total_events": len(df),
            "time_range_seconds": float(df["time"].max() - df["time"].min()) if "time" in df.columns else 0,
            "unique_src_users": int(df["src_user"].nunique()) if "src_user" in df.columns else 0,
            "unique_dst_hosts": int(df["dst_host"].nunique()) if "dst_host" in df.columns else 0,
            "auth_types": dict(df["auth_type"].value_counts()) if "auth_type" in df.columns else {},
            "label_distribution": {str(l): int(c) for l, c in zip(unique_labels, counts)},
            "mean_auth_velocity": float(df["auth_velocity"].mean()) if "auth_velocity" in df.columns else 0,
            "max_fan_out_degree": float(df["fan_out_degree"].max()) if "fan_out_degree" in df.columns else 0,
            "max_failed_burst": float(df["failed_auth_burst"].max()) if "failed_auth_burst" in df.columns else 0,
            "schema_detected": "LANL_AUTH",
            "canonical_dim": 84
        }
        return stats


# ─── Module-Level Singleton ───────────────────────────────────────────────────
_auth_fuser_instance: Optional[AuthLogFuser] = None

def get_auth_log_fuser() -> AuthLogFuser:
    """Get or create the global AuthLogFuser singleton."""
    global _auth_fuser_instance
    if _auth_fuser_instance is None:
        _auth_fuser_instance = AuthLogFuser()
    return _auth_fuser_instance
