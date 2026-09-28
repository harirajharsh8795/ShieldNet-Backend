"""
Tests for RollingFlowBuffer capacity bounding, flow eviction, and packet parser crash immunity.
"""

import time
import pytest

from shared.feature_extractor import PacketMetadata, parse_scapy_packet
from shared.rolling_buffer import RollingFlowBuffer


def test_buffer_enforces_flow_ceiling_under_attack():
    """
    Simulates a high-volume attack with 50 distinct spoofed IP flows against a buffer
    with max_flows=10. Verifies active_flows is strictly bounded.
    """
    buffer = RollingFlowBuffer(
        window_seconds=1.0,
        flow_timeout=15.0,
        max_flows=10,
    )

    # Ingest packets across 50 distinct flows
    for i in range(50):
        pkt = PacketMetadata(
            timestamp=time.time() + (i * 0.01),
            src_ip=f"10.0.0.{i+1}",
            dst_ip="192.168.1.100",
            src_port=10000 + i,
            dst_port=80,
            protocol=6,
            total_length=60,
            payload_length=0,
            header_length=40,
            direction=0,
            tcp_flags=0x02,
            tcp_window=64240,
            ttl=64,
        )
        buffer.ingest_packet(pkt)

    # Buffer must never exceed max_flows
    assert len(buffer.active_flows) <= 10
    assert buffer.total_flows_evicted_overflow > 0
    assert buffer.total_packets_processed == 50


def test_parse_scapy_packet_malformed_immunity():
    """
    Verifies that malformed or non-standard objects do not raise unhandled exceptions
    when processed by parse_scapy_packet.
    """
    # None input
    assert parse_scapy_packet(None) is None

    # Object without haslayer
    class CorruptPkt:
        pass

    assert parse_scapy_packet(CorruptPkt()) is None

    # Object with broken haslayer raising exception
    class ExplodingPkt:
        def haslayer(self, layer):
            raise ValueError("Corrupt Ethernet Frame / Buffer Overflow Attempt")

    assert parse_scapy_packet(ExplodingPkt()) is None
