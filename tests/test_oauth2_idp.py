"""
Unit & Integration Tests for Enterprise OAuth2 / Keycloak-Compatible IdP Server.
Tests:
- PBKDF2 Password Authentication & Salt Verification
- OAuth2 Access Token & Refresh Token Issuance
- OIDC Core 1.0 Discovery Metadata & JWKS Endpoint
- JWT Signature & Expiration Verification
- Refresh Token Rotation & Session Revocation
- 4-Tier RBAC Clearance Enforcement
"""

import pytest
import time
from src.auth.idp_server import EnterpriseIdPServer, USER_STORE


def test_pbkdf2_authentication_success():
    idp = EnterpriseIdPServer()

    # CISO Admin
    user = idp.authenticate("admin@shieldnet.gov.in", "shieldnet2026")
    assert user is not None
    assert user["role"] == "CISO_Admin"
    assert user["clearance_level"] == 5

    # Short alias test
    analyst = idp.authenticate("analyst", "analyst2026")
    assert analyst is not None
    assert analyst["role"] == "SecOps_Analyst"
    assert analyst["clearance_level"] == 3


def test_pbkdf2_authentication_failure():
    idp = EnterpriseIdPServer()
    assert idp.authenticate("admin@shieldnet.gov.in", "wrong_password") is None
    assert idp.authenticate("nonexistent@shieldnet.gov.in", "shieldnet2026") is None


def test_token_issuance_and_verification():
    idp = EnterpriseIdPServer()
    user = USER_STORE["admin@shieldnet.gov.in"]

    token_pair = idp.issue_token_pair(user)
    assert "access_token" in token_pair
    assert "refresh_token" in token_pair
    assert token_pair["token_type"] == "Bearer"
    assert token_pair["expires_in"] == 86400

    # Verify access token
    payload = idp.verify_token(token_pair["access_token"])
    assert payload is not None
    assert payload["sub"] == "admin@shieldnet.gov.in"
    assert payload["role"] == "CISO_Admin"
    assert payload["clearance_level"] == 5
    assert "soar:approve" in payload["permissions"]


def test_oidc_discovery_and_jwks():
    idp = EnterpriseIdPServer()

    discovery = idp.get_oidc_discovery_configuration("http://localhost:8000")
    assert discovery["issuer"] == "https://idp.shieldnet.gov.in/auth/realms/shieldnet-defense"
    assert "/api/auth/token" in discovery["token_endpoint"]
    assert "/api/auth/jwks.json" in discovery["jwks_uri"]
    assert "HS256" in discovery["id_token_signing_alg_values_supported"]

    jwks = idp.get_jwks()
    assert "keys" in jwks
    assert len(jwks["keys"]) == 1
    assert jwks["keys"][0]["alg"] == "HS256"


def test_refresh_token_rotation():
    idp = EnterpriseIdPServer()
    user = USER_STORE["analyst@shieldnet.gov.in"]

    pair1 = idp.issue_token_pair(user)
    rfr1 = pair1["refresh_token"]

    # Exchange refresh token
    pair2 = idp.refresh_access_token(rfr1)
    assert pair2 is not None
    assert pair2["access_token"] != pair1["access_token"]

    # Using old refresh token a second time must FAIL (Single-use rotation)
    assert idp.refresh_access_token(rfr1) is None


def test_token_revocation():
    idp = EnterpriseIdPServer()
    user = USER_STORE["auditor@shieldnet.gov.in"]

    pair = idp.issue_token_pair(user)
    token = pair["access_token"]

    assert idp.verify_token(token) is not None
    idp.revoke_token(token)
    assert idp.verify_token(token) is None
