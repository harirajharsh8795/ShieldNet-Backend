"""
Tests for Dashboard Web Security: Host Header DNS Rebinding Defense, Localhost CORS, and Security Headers.
"""

from pathlib import Path
import http.client
import json
import threading
import time
import pytest

from dashboard.app import DashboardServer


@pytest.fixture(scope="module")
def dashboard_test_server(tmp_path_factory):
    """Launches a test dashboard server on an ephemeral port."""
    temp_dir = tmp_path_factory.mktemp("dash_sec_test")
    db_path = temp_dir / "ledger.db"
    status_path = temp_dir / "status.json"

    server = DashboardServer(
        host="127.0.0.1",
        port=18081,
        db_path=db_path,
        status_path=status_path,
    )
    server.start(block=False)
    time.sleep(0.5)

    yield server

    server.stop()


def test_dns_rebinding_rejection(dashboard_test_server):
    """Verifies that an incoming HTTP request with a foreign Host header is rejected with 403 Forbidden."""
    conn = http.client.HTTPConnection("127.0.0.1", 18081, timeout=5)
    # Attacker attempting DNS rebinding by sending external Host
    conn.request("GET", "/api/ping", headers={"Host": "attacker-dns-rebind.com"})
    res = conn.getresponse()
    body = res.read().decode("utf-8")
    conn.close()

    assert res.status == 403
    assert "Forbidden" in body or "DNS Rebinding" in body


def test_valid_host_header_acceptance(dashboard_test_server):
    """Verifies that legitimate requests with loopback Host headers succeed."""
    conn = http.client.HTTPConnection("127.0.0.1", 18081, timeout=5)
    conn.request("GET", "/api/ping", headers={"Host": "127.0.0.1:18081"})
    res = conn.getresponse()
    body = res.read().decode("utf-8")
    conn.close()

    assert res.status == 200
    data = json.loads(body)
    assert data.get("pong") is True


def test_security_headers_present(dashboard_test_server):
    """Verifies defensive HTTP security headers are injected."""
    conn = http.client.HTTPConnection("127.0.0.1", 18081, timeout=5)
    conn.request("GET", "/api/ping", headers={"Host": "127.0.0.1:18081"})
    res = conn.getresponse()
    headers = dict(res.getheaders())
    res.read()
    conn.close()

    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert "Content-Security-Policy" in headers
    assert "no-store" in headers.get("Cache-Control", "")


def test_cors_rejects_external_origin(dashboard_test_server):
    """Verifies that requests from external web origins are NOT granted wildcard CORS access."""
    conn = http.client.HTTPConnection("127.0.0.1", 18081, timeout=5)
    conn.request("GET", "/api/ping", headers={
        "Host": "127.0.0.1:18081",
        "Origin": "https://malicious-website.com"
    })
    res = conn.getresponse()
    headers = dict(res.getheaders())
    res.read()
    conn.close()

    # Must NOT return Access-Control-Allow-Origin: * or https://malicious-website.com
    assert headers.get("Access-Control-Allow-Origin") != "*"
    assert headers.get("Access-Control-Allow-Origin") != "https://malicious-website.com"
