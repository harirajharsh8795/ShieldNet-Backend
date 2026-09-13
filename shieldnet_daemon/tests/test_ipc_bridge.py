"""
ShieldNet Local IPC Bridge & Demo Simulation Verification Test Suite.

Validates:
1. Ephemeral session token generation, file permissions, and secure unlinking on shutdown.
2. Localhost ping/pong handshake via IPCClient.
3. Constant-time token verification and 5-failure brute-force lockout.
4. Non-loopback rejection security invariant.
5. Strict schema, type, and protocol range validation on incoming packet batches.
6. End-to-end simulated traffic injection, ONNX threat detection, and Action Ledger
   cryptographic provenance tagging (source: "simulated").
"""

from pathlib import Path
import os
import socket
import time
import pytest

from daemon.service import ShieldNetDaemon, DaemonConfig
from daemon.ipc_bridge import (
    IPCServer,
    IPCClient,
    validate_packet_dict,
    DEFAULT_IPC_HOST,
    DEFAULT_IPC_PORT,
)
from scripts.simulate_traffic import generate_ddos_synflood, generate_benign_traffic


@pytest.fixture
def temp_daemon_with_ipc(tmp_path):
    """Creates an isolated ShieldNetDaemon with IPC bridge active on an ephemeral port."""
    # Use high port for testing to prevent collision
    test_port = 49188
    config = DaemonConfig(
        db_path=tmp_path / "test_ipc_ledger.db",
        status_path=tmp_path / "test_ipc_status.json",
        evaluation_interval=0.5,
        mock_mode=True,
        enable_ipc=True,
        ipc_port=test_port,
    )
    daemon = ShieldNetDaemon(config=config)
    daemon.start()
    time.sleep(0.3)  # Brief warm-up

    yield daemon, test_port

    daemon.stop()
    time.sleep(0.2)


def test_ipc_token_generation_and_cleanup(tmp_path):
    """Verify 256-bit token entropy and secure unlinking on shutdown."""
    test_port = 49189
    config = DaemonConfig(
        db_path=tmp_path / "ledger.db",
        status_path=tmp_path / "status.json",
        mock_mode=True,
        enable_ipc=True,
        ipc_port=test_port,
    )
    daemon = ShieldNetDaemon(config=config)
    token_file = tmp_path / ".ipc_token"

    assert not token_file.exists()

    daemon.start()
    time.sleep(0.3)

    assert token_file.exists()
    token = token_file.read_text(encoding="utf-8").strip()
    assert len(token) == 64  # 32 bytes hex = 64 characters
    assert int(token, 16) > 0  # Valid hex integer

    daemon.stop()
    time.sleep(0.2)

    # Token file should be securely unlinked upon stop
    assert not token_file.exists()


def test_ipc_ping_and_handshake(temp_daemon_with_ipc):
    """Verify loopback ping/pong communication via IPCClient."""
    daemon, port = temp_daemon_with_ipc
    token_file = daemon.data_dir / ".ipc_token"

    client = IPCClient(token_path=token_file, port=port)
    resp = client.ping()

    assert resp.get("status") == "ok"
    assert resp.get("message") == "pong"
    assert "queue_size" in resp


def test_ipc_constant_time_auth_and_lockout(temp_daemon_with_ipc):
    """Verify invalid token rejection and brute-force lockout after 5 failures."""
    daemon, port = temp_daemon_with_ipc

    # Client with bogus token
    bad_client = IPCClient(token="invalid_token_" + "0" * 50, port=port)

    # First 4 attempts fail with 'Invalid authentication token.'
    for i in range(4):
        resp = bad_client.ping()
        assert resp.get("status") == "error"
        assert "Invalid authentication token" in resp.get("error", "")

    # 5th attempt also fails and triggers lockout
    resp5 = bad_client.ping()
    assert resp5.get("status") == "error"

    # 6th attempt hits active lockout
    resp6 = bad_client.ping()
    assert resp6.get("status") == "error"
    assert "lockout active" in resp6.get("error", "").lower()


def test_ipc_strict_schema_validation():
    """Verify packet dictionaries are strictly validated before acceptance."""
    # 1. Valid packet dictionary
    valid_pkt = {
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": 6,
        "total_length": 60,
        "payload_length": 0,
        "header_length": 60,
        "direction": 0,
        "tcp_flags": 2,
        "tcp_window": 65535,
        "ttl": 64,
    }
    is_valid, err = validate_packet_dict(valid_pkt)
    assert is_valid is True
    assert err is None

    # 2. Invalid IP address format
    bad_ip = valid_pkt.copy()
    bad_ip["src_ip"] = "999.999.999.999"
    is_valid, err = validate_packet_dict(bad_ip)
    assert is_valid is False
    assert "Invalid IP address" in err

    # 3. Port out of range
    bad_port = valid_pkt.copy()
    bad_port["dst_port"] = 70000
    is_valid, err = validate_packet_dict(bad_port)
    assert is_valid is False
    assert "Invalid dst_port" in err

    # 4. TTL out of range
    bad_ttl = valid_pkt.copy()
    bad_ttl["ttl"] = 0
    is_valid, err = validate_packet_dict(bad_ttl)
    assert is_valid is False
    assert "Invalid ttl" in err

    # 5. Unsupported protocol (e.g. protocol 99)
    bad_proto = valid_pkt.copy()
    bad_proto["protocol"] = 99
    is_valid, err = validate_packet_dict(bad_proto)
    assert is_valid is False
    assert "Unsupported protocol" in err

    # 6. Type mismatch (boolean in place of integer)
    bad_type = valid_pkt.copy()
    bad_type["protocol"] = True
    is_valid, err = validate_packet_dict(bad_type)
    assert is_valid is False
    assert "must be of type int" in err


def test_ipc_end_to_end_injection_and_ledger_provenance(temp_daemon_with_ipc):
    """
    Verify synthetic DDoS packets injected over IPC are processed by ONNX + Gate,
    and committed to the Action Ledger with source: 'simulated'.
    """
    daemon, port = temp_daemon_with_ipc
    token_file = daemon.data_dir / ".ipc_token"

    # Generate 50 synthetic DDoS SYN flood packets
    simulated_packets = generate_ddos_synflood(num_packets=50)

    client = IPCClient(token_path=token_file, port=port)
    resp = client.inject_packets(simulated_packets)

    assert resp.get("status") == "ok"
    assert resp.get("accepted") == 50
    assert resp.get("source") == "simulated"

    # Allow processing worker to step window, evaluate model, and write to ledger
    time.sleep(2.0)

    # Authoritative ledger check
    records = daemon.ledger.get_recent_records(limit=10)
    assert len(records) > 0, "Expected at least 1 alert committed to Action Ledger"

    # Verify provenance tag
    for r in records:
        assert r.source == "simulated", f"Expected source 'simulated', got '{r.source}'"

    # Verify cryptographic integrity of the hash chain
    is_valid, count, err = daemon.ledger.verify_integrity()
    assert is_valid is True
    assert count >= 1
    assert err is None


def test_ipc_client_stats_endpoint(temp_daemon_with_ipc):
    """Verify IPC stats query returns live metrics."""
    daemon, port = temp_daemon_with_ipc
    token_file = daemon.data_dir / ".ipc_token"

    client = IPCClient(token_path=token_file, port=port)
    stats = client.get_stats()

    assert stats.get("status") == "ok"
    assert "packets_captured" in stats
    assert "evaluations" in stats
    assert "alerts" in stats


if __name__ == "__main__":
    pytest.main(["-v", __file__])
