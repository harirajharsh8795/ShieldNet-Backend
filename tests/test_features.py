"""
Unit tests for ShieldNet Phase 1 Feature Engineering and Parsing.
Tests schema, sequencer, rare-class merging, stratified splitting, and scaling on sample data.
"""

import pytest
import numpy as np
import pandas as pd
import joblib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.features.schema import (
    get_config_a_feature_names, get_numeric_feature_names,
    get_schema_dataframe, generate_data_dictionary,
    FLOW_LEVEL, PACKET_LEVEL, META_LEVEL
)
from src.features.preprocessing import (
    clean_label_string, standardize_and_merge_rare_classes,
    stratified_split_dataset, fit_standard_scaler, transform_numeric_features,
    RARE_ATTACK_CLASSES
)
from src.features.sequencer import (
    create_time_windows, create_sequences, analyze_window_density,
    MITRE_STAGE_MAP, parse_timestamps
)


class TestSchema:
    """Tests for the unified 100/101-column feature schema."""
    
    def test_total_column_count(self):
        """Schema defines canonical features for Config A (including post-merge Label_Original)."""
        cols = get_config_a_feature_names()
        assert len(cols) == 101, f"Expected 101 columns (with Label_Original), got {len(cols)}"
        
    def test_flow_and_packet_feature_counts(self):
        """Schema must have 77 Flow features, 7 Packet features, and 17 Meta columns."""
        flow_cols = get_config_a_feature_names(FLOW_LEVEL)
        packet_cols = get_config_a_feature_names(PACKET_LEVEL)
        meta_cols = get_config_a_feature_names(META_LEVEL)
        
        assert len(flow_cols) == 77, f"Expected 77 flow features, got {len(flow_cols)}"
        assert len(packet_cols) == 7, f"Expected 7 packet features, got {len(packet_cols)}"
        assert len(meta_cols) == 17, f"Expected 17 meta features, got {len(meta_cols)}"
        
    def test_numeric_feature_names(self):
        """Numeric features must include flow and packet features."""
        all_numeric = get_numeric_feature_names(include_packet_level=True)
        flow_only_numeric = get_numeric_feature_names(include_packet_level=False)
        
        assert len(all_numeric) == 84
        assert len(flow_only_numeric) == 77
        assert "ttl_mean" in all_numeric
        assert "ttl_mean" not in flow_only_numeric
        
    def test_data_dictionary_generation(self, tmp_path):
        """Data dictionary markdown generation test."""
        out_path = tmp_path / "DATA_DICTIONARY.md"
        generate_data_dictionary(str(out_path))
        assert out_path.exists()
        content = out_path.read_text(encoding="utf-8")
        assert "Rare-Attack" in content
        assert "Packet-Level" in content
        assert "ttl_mean" in content


class TestPreprocessingAndRareClasses:
    """Tests for label standardization, Rare-Attack merging, and stratified splitting."""
    
    def test_clean_label_string(self):
        """Label cleaner should normalize mangled encodings."""
        assert clean_label_string("Web Attack \ufffd Brute Force") == "Web Attack - Brute Force"
        assert clean_label_string("Web Attack \ufffd XSS") == "Web Attack - XSS"
        assert clean_label_string("Web Attack \ufffd Sql Injection") == "Web Attack - SQL Injection"
        assert clean_label_string("Infilteration") == "Infiltration"
        assert clean_label_string("Heartbleed") == "Heartbleed"
        assert clean_label_string("BENIGN") == "BENIGN"
        
    def test_rare_attack_merging(self):
        """Ultra-rare classes (< 200 samples) must be merged into 'Rare-Attack'."""
        sample_df = pd.DataFrame({
            "Label": [
                "BENIGN", "DoS Hulk", "Heartbleed", 
                "Web Attack \ufffd Sql Injection", "Infilteration", "Bot"
            ]
        })
        processed = standardize_and_merge_rare_classes(sample_df, label_col="Label")
        
        assert "Label_Original" in processed.columns
        assert processed.loc[2, "Label"] == "Rare-Attack"
        assert processed.loc[2, "Label_Original"] == "Heartbleed"
        assert processed.loc[3, "Label"] == "Rare-Attack"
        assert processed.loc[3, "Label_Original"] == "Web Attack - SQL Injection"
        assert processed.loc[4, "Label"] == "Rare-Attack"
        assert processed.loc[4, "Label_Original"] == "Infiltration"
        assert processed.loc[0, "Label"] == "BENIGN"
        assert processed.loc[1, "Label"] == "DoS Hulk"
        
    def test_stratified_split(self):
        """Stratified split must maintain class balance across Train, Val, Test."""
        n_samples = 1000
        labels = (["BENIGN"] * 750) + (["DoS Hulk"] * 150) + (["PortScan"] * 80) + (["Rare-Attack"] * 20)
        df = pd.DataFrame({
            "feature_1": np.random.randn(n_samples),
            "feature_2": np.random.randn(n_samples),
            "Label": labels
        })
        
        train, val, test = stratified_split_dataset(
            df, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, random_seed=42
        )
        
        assert len(train) == 700
        assert len(val) == 150
        assert len(test) == 150
        
        # Check Rare-Attack representation
        assert (train["Label"] == "Rare-Attack").sum() == 14
        assert (val["Label"] == "Rare-Attack").sum() == 3
        assert (test["Label"] == "Rare-Attack").sum() == 3


class TestScaler:
    """Tests for StandardScaler fitting and transformation."""
    
    def test_standard_scaler_no_leakage(self):
        """Scaler fitted on train must transform train/val/test without error or NaN."""
        train_df = pd.DataFrame({"a": [10.0, 20.0, 30.0], "b": [100.0, 200.0, 300.0]})
        val_df = pd.DataFrame({"a": [15.0, 25.0], "b": [150.0, 250.0]})
        
        scaler = fit_standard_scaler(train_df, ["a", "b"])
        train_trans = transform_numeric_features(train_df, scaler, ["a", "b"])
        val_trans = transform_numeric_features(val_df, scaler, ["a", "b"])
        
        assert np.isclose(train_trans["a"].mean(), 0.0, atol=1e-6)
        assert np.isclose(train_trans["a"].std(ddof=0), 1.0, atol=1e-6)
        assert not val_trans.isna().any().any()


class TestSequencer:
    """Tests for the time-windowed sequencer and sequence generator."""
    
    def _create_synthetic_flow_stream(self, n=500):
        ts = pd.date_range(start="2017-07-06 09:00:00", periods=n, freq="500ms")
        half = n // 2
        benign_cnt = int(n * 0.8)
        attack_cnt = n - benign_cnt
        return pd.DataFrame({
            "Timestamp": ts,
            "session_group": ["Thursday-Morning"] * n,
            "Source IP": ["172.16.0.1"] * half + ["192.168.10.5"] * (n - half),
            "Flow Duration": np.random.uniform(100, 10000, n),
            "Total Fwd Packets": np.random.poisson(5, n) + 1,
            "ttl_mean": np.random.choice([64.0, 128.0], n),
            "retransmission_count": np.random.poisson(0.5, n),
            "Label": ["BENIGN"] * benign_cnt + ["Web Attack - Brute Force"] * attack_cnt
        })
        
    def test_analyze_window_density(self):
        """Density analyzer must compute valid metrics on 10s windows."""
        df = self._create_synthetic_flow_stream(300)
        stats = analyze_window_density(df, window_size_seconds=10, group_by="host")
        
        assert stats["total_windows"] > 0
        assert stats["total_flows_processed"] == 300
        assert stats["mean_flows_per_window"] > 0
        assert 0.0 <= stats["sparsity_ratio_1flow_pct"] <= 100.0
        
    def test_create_time_windows_and_sequences(self):
        """create_time_windows and create_sequences should output valid World Model input tensors."""
        df = self._create_synthetic_flow_stream(500)
        windows = create_time_windows(df, window_size_seconds=5, group_by="host", min_flows_per_window=1)
        
        assert len(windows) > 0
        assert "Flow Duration_mean" in windows.columns
        assert "ttl_mean_mean" in windows.columns
        assert "flow_count" in windows.columns
        
        if len(windows) >= 10:
            X, y_next, y_labels = create_sequences(windows, sequence_length=5, stride=1, group_column="group_key")
            if len(X) > 0:
                assert X.ndim == 3
                assert X.shape[1] == 5
                assert y_next.ndim == 2
                assert len(X) == len(y_next) == len(y_labels)


class TestSavedArtifacts:
    """Verify saved Phase 1 artifacts exist on disk and have valid structure."""
    
    def test_scaler_artifact_exists(self):
        scaler_file = Path("models/checkpoints/scaler.joblib")
        assert scaler_file.exists(), "Scaler checkpoint not found"
        scaler = joblib.load(scaler_file)
        assert hasattr(scaler, "mean_")
        assert len(scaler.mean_) == 84
        
    def test_feature_manifest_exists(self):
        manifest_file = Path("models/checkpoints/feature_columns.json")
        assert manifest_file.exists(), "Feature columns manifest not found"
        with open(manifest_file, "r") as f:
            data = json.load(f)
        assert "numeric_features" in data
        assert len(data["numeric_features"]) == 84
        assert len(data["classes"]) == 13
        assert "Rare-Attack" in data["classes"]
        
    def test_split_files_exist(self):
        for name in ["train_v1.parquet", "val_v1.parquet", "test_v1.parquet",
                     "train_flow_only.parquet", "val_flow_only.parquet", "test_flow_only.parquet"]:
            p = Path(f"data/processed/{name}")
            assert p.exists(), f"Split file missing: {name}"
