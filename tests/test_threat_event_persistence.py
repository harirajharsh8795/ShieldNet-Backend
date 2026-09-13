import json
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from src.api.server import app
from src.database.db import get_db_manager

client = TestClient(app)


def test_post_threat_event_persists_valid_payload():
    payload = {
        "ip_address": "10.10.10.10",
        "source_ip": "10.0.0.5",
        "destination_ip": "10.10.10.10",
        "source_port": 52341,
        "destination_port": 443,
        "protocol": "TCP",
        "threat_probability": 0.96,
        "predicted_class": "DDoS",
        "severity": "HIGH",
        "mitre_stage": "Impact",
        "shap_summary": {"top_risk_drivers": ["SYN Flag Count", "Flow IAT Mean"]},
        "timestamp": "2026-09-13T09:30:00"
    }

    response = client.post("/api/threats", json=payload)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["message"] == "Threat stored successfully"
    assert body["id"] > 0

    stored = get_db_manager().get_all_threats(limit=10)
    assert any(item["ip_address"] == "10.10.10.10" and item["predicted_class"] == "DDoS" for item in stored)


def test_post_threat_event_rejects_invalid_payload():
    response = client.post("/api/threats", json={
        "ip_address": "10.10.10.10",
        "threat_probability": -0.1,
        "predicted_class": "DDoS"
    })
    assert response.status_code == 422


def test_get_threat_events_returns_recent_records():
    response = client.get("/api/threats?limit=10")
    assert response.status_code == 200, response.text
    body = response.json()
    assert "threats" in body
    assert isinstance(body["threats"], list)


def test_send_threat_event_uses_api_and_handles_failure():
    with patch("src.api.server.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value.read.return_value = b'{"message":"Threat stored successfully","id":42}'
        mock_urlopen.return_value.__enter__.return_value.status = 200
        success = __import__("src.api.server", fromlist=["_send_threat_event"])._send_threat_event({"ip_address": "1.2.3.4", "threat_probability": 0.9, "predicted_class": "Bot"})
        assert success is True

    with patch("src.api.server.urllib.request.urlopen", side_effect=Exception("API down")):
        success = __import__("src.api.server", fromlist=["_send_threat_event"])._send_threat_event({"ip_address": "1.2.3.4", "threat_probability": 0.77, "predicted_class": "Bot"})
        assert success is False
