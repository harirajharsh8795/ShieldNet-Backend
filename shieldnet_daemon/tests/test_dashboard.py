"""
Unit and Integration Tests for Module 7: ShieldNet Decoupled Dashboard.

Validates:
1. HTTP server lifecycle (clean startup, background thread execution, teardown).
2. Index SPA template delivery (HTML5, offline self-contained assets).
3. Live / offline daemon heartbeat reporting via /api/status.
4. Concurrent read-only WAL ledger querying via /api/ledger.
5. Single-record inspection and continuous 84-dim SHAP driver ranking via /api/ledger/record/<id>.
6. On-demand cryptographic hash-chain verification and tamper detection via /api/ledger/verify.
7. Aggregated attack classification and MITRE ATT&CK statistics via /api/stats.
"""

from pathlib import Path
from typing import Dict, List, Tuple, Any
import json
import os
import socket
import tempfile
import time
import urllib.request
import urllib.error
import pytest
import numpy as np

from dashboard.app import DashboardServer
from engine.ledger import ActionLedger
from shared.schema import CANONICAL_84_FEATURES


def get_free_port() -> int:
    """Finds a free TCP port on localhost for non-conflicting test binding."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def dashboard_env(tmp_path):
    """Sets up a clean isolated test environment with temporary DB, status file, and server."""
    db_path = tmp_path / "test_ledger.db"
    status_path = tmp_path / "test_daemon_status.json"
    port = get_free_port()

    # Pre-populate some records in test ledger
    ledger = ActionLedger(db_path)

    # 1. First record: PortScan
    shap_vec_1 = np.zeros(len(CANONICAL_84_FEATURES), dtype=np.float32)
    shap_vec_1[0] = 0.42   # Flow Duration
    shap_vec_1[15] = 0.88  # Flow IAT Mean
    shap_vec_1[58] = 0.65  # SYN Flag Count

    rec1 = ledger.append_record(
        prediction="PortScan",
        threat_probability=0.965,
        mitre_stage=1,
        mitre_tactic="Discovery / Reconnaissance",
        severity="HIGH",
        shap_summary="top_drivers: Flow IAT Mean, SYN Flag Count",
        shap_vector=shap_vec_1,
        timestamp=time.time() - 10.0,
    )

    # 2. Second record: DDoS SYN Flood
    shap_vec_2 = np.zeros(len(CANONICAL_84_FEATURES), dtype=np.float32)
    shap_vec_2[29] = 0.95  # Flow Packets/s
    shap_vec_2[44] = 0.72  # Fwd PSH Flags

    rec2 = ledger.append_record(
        prediction="DDoS",
        threat_probability=0.992,
        mitre_stage=5,
        mitre_tactic="Impact / Denial of Service",
        severity="CRITICAL",
        shap_summary="top_drivers: Flow Packets/s, Fwd PSH Flags",
        shap_vector=shap_vec_2,
        timestamp=time.time() - 2.0,
    )

    # Pre-populate daemon status file
    status_data = {
        "pid": os.getpid(),
        "status": "RUNNING",
        "mode": "MOCK_INJECTION",
        "uptime_seconds": 120.5,
        "uptime_formatted": "00:02:00",
        "total_packets_captured": 4500,
        "total_packets_dropped": 0,
        "active_flows": 12,
        "total_evaluations": 120,
        "total_alerts": 2,
        "memory_rss_mb": 185.4,
        "cpu_percent": 1.2,
    }
    with open(status_path, "w", encoding="utf-8") as f:
        json.dump(status_data, f)

    # Initialize dashboard server
    server = DashboardServer(
        host="127.0.0.1",
        port=port,
        db_path=db_path,
        status_path=status_path,
    )
    server.start(block=False)
    time.sleep(0.3)  # Allow server thread to bind

    base_url = f"http://127.0.0.1:{port}"

    yield {
        "server": server,
        "base_url": base_url,
        "db_path": db_path,
        "status_path": status_path,
        "ledger": ledger,
        "rec1": rec1,
        "rec2": rec2,
    }

    server.stop()


def fetch_url(url: str) -> Tuple[int, bytes, Dict[str, str]]:
    """Helper to perform HTTP GET using standard library urllib."""
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            headers = dict(resp.getheaders())
            return resp.status, resp.read(), headers
    except urllib.error.HTTPError as err:
        headers = dict(err.headers)
        return err.code, err.read(), headers


def test_dashboard_ping_endpoint(dashboard_env):
    """Verifies that the /api/ping health check works."""
    url = f"{dashboard_env['base_url']}/api/ping"
    status, body, _ = fetch_url(url)
    assert status == 200
    data = json.loads(body.decode("utf-8"))
    assert data.get("pong") is True
    assert "server_time" in data


def test_dashboard_index_html_serving(dashboard_env):
    """Verifies that the root endpoint serves the single page command center UI."""
    url = f"{dashboard_env['base_url']}/"
    status, body, headers = fetch_url(url)
    assert status == 200
    assert "text/html" in headers.get("Content-Type", "")
    html_text = body.decode("utf-8")
    assert "ShieldNet // AI Command Center" in html_text
    assert "AIR-GAP OFFLINE" in html_text
    assert "TAMPER-EVIDENT ACTION LEDGER" in html_text


def test_dashboard_api_status_live_and_offline(dashboard_env):
    """Verifies /api/status telemetry and offline graceful fallback."""
    url = f"{dashboard_env['base_url']}/api/status"
    status, body, _ = fetch_url(url)
    assert status == 200
    data = json.loads(body.decode("utf-8"))
    assert data["status"] == "RUNNING"
    assert data["process_alive"] is True
    assert data["total_packets_captured"] == 4500
    assert data["total_alerts"] == 2

    # Remove status file to test graceful offline fallback
    dashboard_env["status_path"].unlink()
    status, body, _ = fetch_url(url)
    assert status == 200
    offline_data = json.loads(body.decode("utf-8"))
    assert offline_data["status"] == "OFFLINE"
    assert offline_data["process_alive"] is False


def test_dashboard_api_ledger_querying(dashboard_env):
    """Verifies that /api/ledger returns recent records in reverse chronological order."""
    url = f"{dashboard_env['base_url']}/api/ledger?limit=10"
    status, body, _ = fetch_url(url)
    assert status == 200
    records = json.loads(body.decode("utf-8"))

    assert len(records) == 2
    # Latest record (ID 2 - DDoS) should be first
    assert records[0]["id"] == 2
    assert records[0]["prediction"] == "DDoS"
    assert records[0]["severity"] == "CRITICAL"
    assert records[0]["has_shap"] is True
    assert records[0]["shap_vector"] is None  # Omitted in summary to conserve bandwidth

    # Earlier record (ID 1 - PortScan)
    assert records[1]["id"] == 1
    assert records[1]["prediction"] == "PortScan"
    assert records[1]["severity"] == "HIGH"


def test_dashboard_api_record_detail_and_shap_ranking(dashboard_env):
    """Verifies /api/ledger/record/<id> returns full SHAP vector and ranked top drivers."""
    # Test valid ID 1
    url = f"{dashboard_env['base_url']}/api/ledger/record/1"
    status, body, _ = fetch_url(url)
    assert status == 200
    data = json.loads(body.decode("utf-8"))
    assert data["id"] == 1
    assert data["prediction"] == "PortScan"
    assert len(data["shap_vector"]) == len(CANONICAL_84_FEATURES)

    # Validate ranked top drivers
    drivers = data.get("top_drivers", [])
    assert len(drivers) > 0
    # Top driver should be Flow IAT Mean (val = 0.88)
    assert drivers[0]["feature"] == "Flow IAT Mean"
    assert abs(drivers[0]["value"] - 0.88) < 1e-4

    # Test non-existent ID
    url_404 = f"{dashboard_env['base_url']}/api/ledger/record/9999"
    status_404, _, _ = fetch_url(url_404)
    assert status_404 == 404


def test_dashboard_api_verify_cryptographic_chain(dashboard_env):
    """Verifies /api/ledger/verify returns mathematical chain proof and detects tampering."""
    url = f"{dashboard_env['base_url']}/api/ledger/verify"
    status, body, _ = fetch_url(url)
    assert status == 200
    audit = json.loads(body.decode("utf-8"))
    assert audit["is_valid"] is True
    assert audit["verified_count"] == 2
    assert audit["total_records"] == 2
    assert audit["error_details"] is None

    # Simulate unauthorized database tampering
    ledger = dashboard_env["ledger"]
    with ledger._get_connection() as conn:
        conn.execute("UPDATE action_ledger SET threat_probability = 0.1234 WHERE id = 1;")
        conn.commit()

    # Re-verify through API; tampering must be flagged immediately
    status, body, _ = fetch_url(url)
    assert status == 200
    audit_tampered = json.loads(body.decode("utf-8"))
    assert audit_tampered["is_valid"] is False
    assert "Data tampering detected at record ID 1" in audit_tampered["error_details"]


def test_dashboard_api_stats_aggregation(dashboard_env):
    """Verifies /api/stats accurately aggregates attack categories and MITRE stages."""
    url = f"{dashboard_env['base_url']}/api/stats"
    status, body, _ = fetch_url(url)
    assert status == 200
    stats = json.loads(body.decode("utf-8"))

    assert stats["total_records"] == 2
    assert stats["attack_distribution"] == {"DDoS": 1, "PortScan": 1}
    assert stats["severity_distribution"] == {"CRITICAL": 1, "HIGH": 1}
    assert "Stage 1: Discovery / Reconnaissance" in stats["mitre_distribution"]
    assert "Stage 5: Impact / Denial of Service" in stats["mitre_distribution"]
