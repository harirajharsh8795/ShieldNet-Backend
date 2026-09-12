"""
ShieldNet Module 1 Verification Test Suite.

Validates the Shared Feature-Extraction Module:
1. Schema integrity & exact alignment with trained models (84 dimensions: 77 flow + 7 packet).
2. Direct packet-level and flow-level calculation on synthetic TCP/UDP packet streams.
3. Bidirectional flow matching and rolling time-window buffer (L=3 context length).
4. Frozen reference baseline scaler guard (clipping, zero leakage, no dynamic self-centering).
5. Cross-dataset schema adaptation (CIC-IDS-2018 and CTU-13 formats).
"""

import json
from pathlib import Path
import numpy as np
import pandas as pd
import pytest

from shared.schema import (
    CANONICAL_84_FEATURES,
    CANONICAL_FLOW_FEATURES,
    CANONICAL_PACKET_FEATURES,
    NUM_CANONICAL_FEATURES,
    NUM_FLOW_FEATURES,
    NUM_PACKET_FEATURES,
    CONTEXT_LENGTH,
    FEATURE_TO_IDX,
    validate_feature_vector,
)
from shared.feature_extractor import (
    PacketMetadata,
    compute_flow_features,
    adapt_dataframe_to_canonical,
)
from shared.scaler_guard import FrozenReferenceScalerGuard
from shared.rolling_buffer import RollingFlowBuffer


def test_canonical_schema_integrity():
    """Verify that canonical schema has exact 84 features and matches feature_columns.json."""
    assert len(CANONICAL_84_FEATURES) == 84
    assert NUM_FLOW_FEATURES == 77
    assert NUM_PACKET_FEATURES == 7
    assert CONTEXT_LENGTH == 3

    # Check against checkpoint feature_columns.json
    ckpt_path = Path(__file__).resolve().parent.parent / "models" / "checkpoints" / "feature_columns.json"
    if not ckpt_path.exists():
        ckpt_path = Path(__file__).resolve().parent.parent.parent / "models" / "checkpoints" / "feature_columns.json"
        
    assert ckpt_path.exists(), f"feature_columns.json not found at {ckpt_path}"
    with open(ckpt_path, "r") as f:
        data = json.load(f)
        
    expected_numeric = data["numeric_features"]
    assert len(expected_numeric) == 84, f"Expected 84 features, found {len(expected_numeric)}"
    assert CANONICAL_84_FEATURES == expected_numeric, "Canonical schema must match feature_columns.json exactly"


def test_packet_and_flow_feature_extraction():
    """Test feature extraction on a synthetic TCP communication stream."""
    t0 = 1000.0
    packets = [
        # Packet 1: SYN from Client (192.168.1.50:54321 -> 10.0.0.1:80)
        PacketMetadata(
            timestamp=t0,
            src_ip="192.168.1.50", dst_ip="10.0.0.1",
            src_port=54321, dst_port=80, protocol=6,
            total_length=60, payload_length=0, header_length=60,
            direction=0, tcp_flags=0x02, tcp_window=64240, seq_num=1000, ack_num=0,
            ttl=64, ip_flags=0x02, frag_offset=0
        ),
        # Packet 2: SYN-ACK from Server (10.0.0.1:80 -> 192.168.1.50:54321)
        PacketMetadata(
            timestamp=t0 + 0.015,  # 15 ms RTT
            src_ip="10.0.0.1", dst_ip="192.168.1.50",
            src_port=80, dst_port=54321, protocol=6,
            total_length=60, payload_length=0, header_length=60,
            direction=1, tcp_flags=0x12, tcp_window=65535, seq_num=5000, ack_num=1001,
            ttl=128, ip_flags=0x02, frag_offset=0
        ),
        # Packet 3: ACK from Client
        PacketMetadata(
            timestamp=t0 + 0.030,
            src_ip="192.168.1.50", dst_ip="10.0.0.1",
            src_port=54321, dst_port=80, protocol=6,
            total_length=52, payload_length=0, header_length=52,
            direction=0, tcp_flags=0x10, tcp_window=64240, seq_num=1001, ack_num=5001,
            ttl=64, ip_flags=0x02, frag_offset=0
        ),
        # Packet 4: HTTP Request (Client -> Server)
        PacketMetadata(
            timestamp=t0 + 0.045,
            src_ip="192.168.1.50", dst_ip="10.0.0.1",
            src_port=54321, dst_port=80, protocol=6,
            total_length=552, payload_length=500, header_length=52,
            direction=0, tcp_flags=0x18, tcp_window=64240, seq_num=1001, ack_num=5001,
            ttl=64, ip_flags=0x02, frag_offset=0
        ),
        # Packet 5: HTTP Response (Server -> Client)
        PacketMetadata(
            timestamp=t0 + 0.075,
            src_ip="10.0.0.1", dst_ip="192.168.1.50",
            src_port=80, dst_port=54321, protocol=6,
            total_length=1500, payload_length=1448, header_length=52,
            direction=1, tcp_flags=0x18, tcp_window=65535, seq_num=5001, ack_num=1501,
            ttl=128, ip_flags=0x02, frag_offset=0
        ),
    ]

    vector = compute_flow_features(packets)

    # Dimensionality & Validity
    assert vector.shape == (84,)
    assert validate_feature_vector(vector)
    assert not np.isnan(vector).any(), "Feature vector contains NaNs"
    assert not np.isinf(vector).any(), "Feature vector contains Infs"

    # Verify flow properties
    duration_us = (0.075) * 1e6
    assert abs(vector[FEATURE_TO_IDX["Flow Duration"]] - duration_us) < 1.0
    assert vector[FEATURE_TO_IDX["Total Fwd Packets"]] == 3.0
    assert vector[FEATURE_TO_IDX["Total Backward Packets"]] == 2.0
    assert vector[FEATURE_TO_IDX["Total Length of Fwd Packets"]] == 500.0
    assert vector[FEATURE_TO_IDX["Total Length of Bwd Packets"]] == 1448.0
    assert vector[FEATURE_TO_IDX["SYN Flag Count"]] == 2.0  # SYN and SYN-ACK
    assert vector[FEATURE_TO_IDX["ACK Flag Count"]] == 4.0  # SYN-ACK, ACK, PSH-ACK, PSH-ACK

    # Verify verified packet-level properties
    # TTLs: [64, 128, 64, 64, 128], mean = (64*3 + 128*2)/5 = 448/5 = 89.6
    assert abs(vector[FEATURE_TO_IDX["ttl_mean"]] - 89.6) < 1e-4
    assert vector[FEATURE_TO_IDX["ttl_variance"]] > 0.0
    assert vector[FEATURE_TO_IDX["tcp_window_min"]] == 64240.0
    assert vector[FEATURE_TO_IDX["tcp_window_max"]] == 65535.0


def test_rolling_flow_buffer_bidirectional():
    """Verify that bidirectional packets are grouped and rolling windows produce L=3 sequences."""
    buffer = RollingFlowBuffer(window_seconds=1.0, flow_timeout=10.0, context_length=3)
    t = 100.0

    # Ingest forward packet
    pkt_fwd = PacketMetadata(
        timestamp=t, src_ip="10.10.10.1", dst_ip="10.10.10.2",
        src_port=12345, dst_port=443, protocol=6,
        total_length=64, payload_length=0, header_length=64,
        tcp_flags=0x02, tcp_window=29200, seq_num=10, ack_num=0, ttl=64
    )
    key_fwd = buffer.ingest_packet(pkt_fwd)

    # Ingest reverse packet
    pkt_bwd = PacketMetadata(
        timestamp=t + 0.01, src_ip="10.10.10.2", dst_ip="10.10.10.1",
        src_port=443, dst_port=12345, protocol=6,
        total_length=64, payload_length=0, header_length=64,
        tcp_flags=0x12, tcp_window=29200, seq_num=100, ack_num=11, ttl=64
    )
    key_bwd = buffer.ingest_packet(pkt_bwd)

    # Must map to the exact same canonical key
    assert key_fwd == key_bwd
    assert len(buffer.active_flows) == 1

    flow = buffer.active_flows[key_fwd]
    assert len(flow.packets) == 2
    assert flow.packets[0].direction == 0  # Forward
    assert flow.packets[1].direction == 1  # Backward

    # Step window to generate temporal evaluation
    evals = buffer.step_window(current_time=t + 0.5)
    assert len(evals) == 1
    eval_item = evals[0]

    assert eval_item["raw_vector"].shape == (84,)
    assert eval_item["sequence"].shape == (3, 84), "Sequence shape must be (L=3, 84)"

    # Aggregate host sequence test
    agg_seq = buffer.get_aggregate_host_sequence()
    assert agg_seq.shape == (1, 3, 84), "Aggregate host sequence must be (1, 3, 84)"


def test_frozen_scaler_guard():
    """Verify frozen scaler standardization, clipping [-5.0, 5.0], and absence of NaNs."""
    scaler_guard = FrozenReferenceScalerGuard()
    assert scaler_guard.is_loaded, "Scaler guard must successfully load reference scaler parameters"
    assert len(scaler_guard.mean) == 84
    assert len(scaler_guard.scale) == 84

    # Create synthetic raw vector
    raw_vec = np.ones(84, dtype=np.float32) * 100.0
    norm_vec = scaler_guard.transform(raw_vec)

    assert norm_vec.shape == (84,)
    assert np.all(norm_vec >= -5.0) and np.all(norm_vec <= 5.0), "Normalized values must be clipped to [-5, 5]"
    assert not np.isnan(norm_vec).any()

    # Test 3D batch standardization (B, L, 84)
    batch_3d = np.ones((2, 3, 84), dtype=np.float32) * 50.0
    norm_batch = scaler_guard.guard_batch(batch_3d)
    assert norm_batch.shape == (2, 3, 84)
    assert np.all(norm_batch >= -5.0) and np.all(norm_batch <= 5.0)


def test_cross_dataset_schema_adapter():
    """Verify that CTU-13 NetFlow format and CIC-IDS format map into canonical 84 dimensions."""
    # Synthetic CTU-13 NetFlow record
    ctu_data = {
        "Dur": [1.5, 0.2],
        "TotPkts": [10, 4],
        "TotBytes": [1500, 240],
        "SrcBytes": [500, 100],
        "DstBytes": [1000, 140],
        "Rate": [6.67, 20.0],
    }
    ctu_df = pd.DataFrame(ctu_data)
    ctu_matrix = adapt_dataframe_to_canonical(ctu_df)

    assert ctu_matrix.shape == (2, 84)
    # Check that Dur is mapped to Flow Duration
    assert ctu_matrix[0, FEATURE_TO_IDX["Flow Duration"]] == 1.5
    assert ctu_matrix[0, FEATURE_TO_IDX["Total Fwd Packets"]] == 10.0
    assert ctu_matrix[0, FEATURE_TO_IDX["Flow Packets/s"]] == 6.67

    # Synthetic canonical CIC-IDS format record
    cic_data = {
        "Flow Duration": [1500000.0],
        "Total Fwd Packets": [25.0],
        "Total Backward Packets": [30.0],
        "ttl_mean": [64.0],
        "tcp_window_mean": [65535.0],
    }
    cic_df = pd.DataFrame(cic_data)
    cic_matrix = adapt_dataframe_to_canonical(cic_df)

    assert cic_matrix.shape == (1, 84)
    assert cic_matrix[0, FEATURE_TO_IDX["Flow Duration"]] == 1500000.0
    assert cic_matrix[0, FEATURE_TO_IDX["Total Fwd Packets"]] == 25.0
    assert cic_matrix[0, FEATURE_TO_IDX["ttl_mean"]] == 64.0
    assert cic_matrix[0, FEATURE_TO_IDX["tcp_window_mean"]] == 65535.0


if __name__ == "__main__":
    pytest.main(["-v", __file__])
