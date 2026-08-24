"""OAuth interoperability contract shared with the hosted Nimbus MCP."""

from __future__ import annotations

import asyncio
import base64
import hashlib

import jwt
from fastapi.testclient import TestClient

from src import main
from src.state import InMemoryStateStore


def _configure_oauth(monkeypatch) -> None:
    monkeypatch.setattr(main, "OAUTH_CLIENT_ID", "legacy-shared-client")
    monkeypatch.setattr(
        main,
        "OAUTH_CLIENT_SECRET",
        "test-secret-that-is-at-least-32-bytes",
    )
    monkeypatch.setattr(main, "PUBLIC_BASE_URL", "https://mcp.example.com")
    monkeypatch.setattr(main, "OAUTH_DYNAMIC_CLIENT_REGISTRATION_ENABLED", True)
    monkeypatch.setattr(
        main,
        "OAUTH_ALLOWED_REDIRECT_URIS",
        [
            "https://chatgpt.com/connector/oauth/callback-id",
            "https://claude.ai/api/oauth/callback",
        ],
    )
    monkeypatch.setattr(main, "_state_store", InMemoryStateStore())


def test_metadata_publishes_public_jwks(monkeypatch):
    _configure_oauth(monkeypatch)

    client = TestClient(main.app)
    metadata = client.get("/.well-known/oauth-authorization-server")
    canonical = client.get("/.well-known/jwks.json")
    compatible = client.get("/jwks.json")

    assert metadata.status_code == 200
    assert metadata.json()["jwks_uri"] == "https://mcp.example.com/.well-known/jwks.json"
    assert canonical.status_code == 200
    assert compatible.json() == canonical.json()
    [public_key] = canonical.json()["keys"]
    assert public_key["kty"] == "EC"
    assert public_key["crv"] == "P-256"
    assert public_key["alg"] == "ES256"
    assert public_key["kid"]
    assert "d" not in public_key


def test_dcr_issues_unique_public_clients(monkeypatch):
    _configure_oauth(monkeypatch)
    registration = {
        "client_name": "Claude",
        "redirect_uris": ["https://claude.ai/api/oauth/callback"],
        "token_endpoint_auth_method": "none",
    }

    client = TestClient(main.app)
    first = client.post("/oauth/register", json=registration)
    second = client.post("/oauth/register", json=registration)

    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["client_id"] != second.json()["client_id"]
    assert first.json()["client_id"] != "legacy-shared-client"


def test_dynamic_registration_is_rate_limited(monkeypatch):
    _configure_oauth(monkeypatch)
    monkeypatch.setattr(main, "check_http_rate_limit", lambda *_args, **_kwargs: True)

    response = TestClient(main.app).post(
        "/oauth/register",
        json={
            "client_name": "Claude",
            "redirect_uris": ["https://claude.ai/api/oauth/callback"],
            "token_endpoint_auth_method": "none",
        },
    )

    assert response.status_code == 429


def test_dynamic_registration_returns_controlled_storage_error(monkeypatch):
    _configure_oauth(monkeypatch)
    monkeypatch.setattr(main, "check_http_rate_limit", lambda *_args, **_kwargs: False)

    async def fail_to_store(_registration):
        raise RuntimeError("state store unavailable")

    monkeypatch.setattr(main, "_store_dynamic_client", fail_to_store)
    response = TestClient(main.app).post(
        "/oauth/register",
        json={
            "client_name": "Claude",
            "redirect_uris": ["https://claude.ai/api/oauth/callback"],
            "token_endpoint_auth_method": "none",
        },
    )

    assert response.status_code == 500
    assert response.json()["error"] == "server_error"


def test_dcr_client_can_authorize_exchange_and_use_access_token(monkeypatch):
    _configure_oauth(monkeypatch)
    verifier = "v" * 43
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    redirect_uri = "https://claude.ai/api/oauth/callback"
    resource = "https://mcp.example.com/mcp"
    client = TestClient(main.app)

    registration = client.post(
        "/oauth/register",
        json={
            "client_name": "Claude",
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": "none",
        },
    )
    client_id = registration.json()["client_id"]
    authorization = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "openid profile email offline_access",
        },
    )
    assert authorization.status_code == 200

    code = asyncio.run(
        main._store_auth_grant(
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": "openid profile email offline_access",
                "ho_profile": {},
            }
        )
    )
    token_response = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": redirect_uri,
        },
    )
    assert token_response.status_code == 200

    token = token_response.json()["access_token"]
    [public_key] = client.get("/.well-known/jwks.json").json()["keys"]
    claims = jwt.decode(
        token,
        jwt.PyJWK.from_dict(public_key).key,
        algorithms=["ES256"],
        audience=resource,
    )
    assert claims["sub"] == client_id

    protected = client.post(
        "/tools/search_providers",
        headers={"Authorization": f"Bearer {token}"},
        json={},
    )
    assert protected.status_code == 422


def test_unregistered_pkce_client_can_still_start_login(monkeypatch):
    _configure_oauth(monkeypatch)

    response = TestClient(main.app).get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client-generated-by-existing-agent",
            "redirect_uri": "https://chatgpt.com/connector/oauth/callback-id",
            "code_challenge": "challenge",
            "code_challenge_method": "S256",
            "scope": "mcp",
        },
    )

    assert response.status_code == 200
