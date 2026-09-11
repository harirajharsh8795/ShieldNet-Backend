"""
Unit and Integration Tests for CICIoT2023 and LANL Auth Log Fusion.
NTRO PS-153 Mandated Heterogeneous Telemetry Verification.
"""

import sys
from pathlib import Path
import numpy as np
import pandas as pd
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.features.schema_adapter import CrossDatasetSchemaAdapter, get_schema_adapter
from src.ingestion.auth_log_fuser import AuthLogFuser, get_auth_log_fuser


class TestCICIoT2023SchemaAdapter:
    """Tests for the CICIoT2023 (46-feature IoT telemetry) adapter mapping."""

    @pytest.fixture
    def adapter(self):
        return CrossDatasetSchemaAdapter()

    @pytest.fixture
    def sample_ciciot_df(self):
        csv_path = PROJECT_ROOT / "demo_test_csvs" / "6_CICIoT2023_SmartGrid_IoT_Flood.csv"
        return pd.read_csv(csv_path)

    def test_ciciot_schema_detection(self, adapter, sample_ciciot_df):
        """Adapter must identify CICIoT2023 telemetry from IoT flag signatures."""
        detected = adapter.detect_schema(list(sample_ciciot_df.columns))
        assert detected == "CICIOT_2023", f"Expected CICIOT_2023, got {detected}"

    def test_ciciot_adaptation_output_shape(self, adapter, sample_ciciot_df):
        """Adapter must convert 46-feature IoT DataFrame to (N, 84) canonical matrix."""
        mat = adapter.adapt_dataframe(sample_ciciot_df, source_schema="CICIOT_2023")
        assert mat.shape == (len(sample_ciciot_df), 84), f"Shape mismatch: {mat.shape}"
        assert not np.isnan(mat).any(), "Adapted matrix contains NaNs"
        assert not np.isinf(mat).any(), "Adapted matrix contains Infs"

    def test_ciciot_feature_fidelity(self, adapter, sample_ciciot_df):
        """Key mapped features (duration, flags, rate) must preserve numerical integrity."""
        mat = adapter.adapt_dataframe(sample_ciciot_df, source_schema="CICIOT_2023")
        cols = adapter.canonical_columns
        
        # Verify Flow Duration
        if "Flow Duration" in cols:
            idx = cols.index("Flow Duration")
            expected_first = sample_ciciot_df["flow_duration"].iloc[0]
            assert np.isclose(mat[0, idx], expected_first, atol=1e-3)
            
        # Verify SYN Flag Count
        if "SYN Flag Count" in cols:
            idx = cols.index("SYN Flag Count")
            assert mat[0, idx] == 1.0 or mat[0, idx] == 50.0  # Syn flag or syn count

    def test_single_record_adaptation(self, adapter, sample_ciciot_df):
        """Single-record JSON adaptation must return 1D (84,) vector."""
        rec = sample_ciciot_df.iloc[0].to_dict()
        vec = adapter.adapt_record(rec)
        assert vec.shape == (84,), f"Expected (84,), got {vec.shape}"


class TestLANLAuthLogFusion:
    """Tests for the LANL Authentication Log Fusion Engine and schema adapter."""

    @pytest.fixture
    def fuser(self):
        return AuthLogFuser(window_seconds=10.0)

    @pytest.fixture
    def sample_lanl_csv(self):
        return PROJECT_ROOT / "demo_test_csvs" / "7_LANL_Enterprise_Kerberos_LateralMovement.csv"

    def test_lanl_schema_detection(self):
        """Adapter must detect LANL_AUTH schema from auth telemetry column signatures."""
        adapter = get_schema_adapter()
        lanl_cols = ["time", "src_user", "dst_user", "src_host", "dst_host", "auth_type", "logon_type", "result"]
        assert adapter.detect_schema(lanl_cols) == "LANL_AUTH"

    def test_lanl_load_and_window_computation(self, fuser, sample_lanl_csv):
        """Fuser must compute temporal sliding window features (velocity, fan-out, burst, entropy)."""
        df = fuser.load_auth_log(sample_lanl_csv)
        assert "auth_velocity" in df.columns
        assert "failed_auth_burst" in df.columns
        assert "fan_out_degree" in df.columns
        assert "session_entropy" in df.columns
        assert len(df) > 0

    def test_lanl_to_canonical_matrix(self, fuser, sample_lanl_csv):
        """Fuser must output (N, 84) matrix conforming to ShieldNet World Model state space."""
        df = fuser.load_auth_log(sample_lanl_csv)
        mat = fuser.to_canonical_matrix(df)
        assert mat.shape == (len(df), 84), f"Expected ({len(df)}, 84), got {mat.shape}"
        assert not np.isnan(mat).any()
        assert not np.isinf(mat).any()

    def test_lanl_attack_label_extraction(self, fuser, sample_lanl_csv):
        """Fuser must extract and detect lateral movement and brute-force behaviors."""
        df = fuser.load_auth_log(sample_lanl_csv)
        labels = fuser.extract_labels(df)
        assert len(labels) == len(df)
        assert "Lateral_Movement_RedTeam" in labels or "Lateral_Movement" in labels

    def test_network_telemetry_fusion(self, fuser, sample_lanl_csv):
        """Fuser must blend auth behavioral features into concurrent network flow state sequences."""
        auth_df = fuser.load_auth_log(sample_lanl_csv)
        
        # Create synthetic concurrent network flows around the auth timestamps
        n_net = 5
        net_matrix = np.zeros((n_net, 84), dtype=np.float32)
        net_times = np.array([100.0, 102.0, 108.1, 109.0, 120.0])
        
        fused = fuser.fuse_with_network_telemetry(
            network_matrix=net_matrix,
            network_timestamps=net_times,
            auth_df=auth_df,
            alignment_tolerance_sec=5.0
        )
        
        assert fused.shape == (n_net, 84)
        # Verify that index 2 (t=108.1s, coincident with lateral movement burst) received auth signals
        assert np.sum(fused[2, :]) > 0.0, "Auth features were not injected into aligned network sequence"

    def test_summary_statistics(self, fuser, sample_lanl_csv):
        """Summary stats must provide complete diagnostic telemetry for SecOps."""
        df = fuser.load_auth_log(sample_lanl_csv)
        stats = fuser.get_summary_stats(df)
        assert stats["total_events"] == len(df)
        assert "auth_types" in stats
        assert "label_distribution" in stats
        assert stats["canonical_dim"] == 84
