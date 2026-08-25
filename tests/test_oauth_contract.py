"""OAuth interoperability contract shared with the hosted Nimbus MCP."""

from __future__ import annotations

import asyncio
import base64
import hashlib

import jwt
import httpx
from fastapi.testclient import TestClient

from src import main
from src import tools
from src.auth_context import current_ai_service, current_request_meta
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


def test_server_card_is_public_and_uses_configured_mcp_host(monkeypatch):
    _configure_oauth(monkeypatch)

    response = TestClient(main.app).get("/.well-known/mcp/server-card.json")

    assert response.status_code == 200
    card = response.json()
    assert card["transport"]["endpoint"] == "https://mcp.example.com/mcp"
    assert card["transports"] == [
        {
            "type": "streamable-http",
            "endpoint": "https://mcp.example.com/mcp",
        }
    ]
    assert card["authentication"]["metadata"] == (
        "https://mcp.example.com/.well-known/oauth-protected-resource"
    )


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


def test_dcr_accepts_native_loopback_redirect_with_ephemeral_port(monkeypatch):
    _configure_oauth(monkeypatch)

    response = TestClient(main.app).post(
        "/oauth/register",
        json={
            "client_name": "Native MCP client",
            "redirect_uris": ["http://localhost:54321/cb"],
            "token_endpoint_auth_method": "none",
        },
    )

    assert response.status_code == 201


def test_redirect_allowlist_accepts_only_valid_loopback_exceptions(monkeypatch):
    _configure_oauth(monkeypatch)

    for redirect_uri in (
        "http://localhost:54321/cb",
        "http://127.0.0.1:54322/oauth/callback",
        "http://[::1]:54323/callback?client=native",
    ):
        assert main._is_allowed_redirect_uri(redirect_uri)

    for redirect_uri in (
        "https://localhost:54321/cb",
        "http://localhost.evil.example:54321/cb",
        "http://127.0.0.1.evil.example:54321/cb",
        "http://user@localhost:54321/cb",
        "http://localhost/cb",
        "http://localhost:99999/cb",
        "vscode://unregistered-client/callback",
        "https://evil.example.com/cb",
    ):
        assert not main._is_allowed_redirect_uri(redirect_uri)


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
                "ai_service": "Claude",
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
    assert claims["ai_service"] == "Claude"

    protected = client.post(
        "/tools/search_providers",
        headers={"Authorization": f"Bearer {token}"},
        json={},
    )
    assert protected.status_code == 422


def test_booking_source_uses_signed_chatgpt_identity():
    service_token = current_ai_service.set("ChatGPT")
    try:
        assert tools._booking_source("AI Assistant") == "ChatGPT"
    finally:
        current_ai_service.reset(service_token)


def test_booking_source_rejects_spoofed_chatgpt_request_hint_and_argument():
    service_token = current_ai_service.set(None)
    meta_token = current_request_meta.set(
        {"origin": "https://chatgpt.com", "user_agent": "ChatGPT"}
    )
    try:
        assert tools._booking_source("OpenAI ChatGPT") == "AI Assistant"
    finally:
        current_request_meta.reset(meta_token)
        current_ai_service.reset(service_token)


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


def test_unregistered_localhost_pkce_client_cannot_claim_grok_bot(monkeypatch):
    _configure_oauth(monkeypatch)
    monkeypatch.setattr(
        main,
        "OAUTH_ALLOWED_REDIRECT_URIS",
        ["http://localhost:8787/callback"],
    )
    assert main._ai_service_for_oauth_redirect(
        "http://localhost:8787/callback"
    ) is None

    verifier = "v" * 43
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    client_id = "generic-local-pkce-client"
    redirect_uri = "http://localhost:8787/callback"
    client = TestClient(main.app)

    authorization = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "mcp",
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
                "scope": "mcp",
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
    claims = jwt.decode(
        token_response.json()["access_token"],
        options={"verify_signature": False},
    )
    assert "ai_service" not in claims


def test_new_tokens_keep_homeowner_pii_in_opaque_server_session(monkeypatch):
    _configure_oauth(monkeypatch)
    verifier = "v" * 43
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    profile = {
        "ho_name": "Alex Fontova",
        "ho_address": {"address1": "2000 Mason Hill Drive"},
        "phone": "+15551234567",
    }
    session_id = asyncio.run(main._store_ho_session(profile, "upstream-token"))
    code = asyncio.run(
        main._store_auth_grant(
            {
                "client_id": "legacy-shared-client",
                "redirect_uri": "https://chatgpt.com/connector/oauth/callback-id",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": "mcp offline_access",
                "ho_profile": profile,
                "ho_session": session_id,
                "phone_number": "+15551234567",
            }
        )
    )

    response = TestClient(main.app).post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "legacy-shared-client",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": "https://chatgpt.com/connector/oauth/callback-id",
        },
    )

    assert response.status_code == 200
    access_claims = jwt.decode(
        response.json()["access_token"],
        options={"verify_signature": False},
    )
    refresh_claims = jwt.decode(
        response.json()["refresh_token"],
        options={"verify_signature": False},
    )
    forbidden = {
        "ho_profile",
        "ho_phone",
        "phone_number",
        "ho_name",
        "ho_address",
        "enc_ho_token",
    }
    assert not forbidden & access_claims.keys()
    assert not forbidden & refresh_claims.keys()
    assert access_claims["ho_session"] == session_id
    assert refresh_claims["ho_session"] == session_id
    assert jwt.get_unverified_header(response.json()["refresh_token"])["alg"] == "ES256"


def test_legacy_hs256_refresh_without_upstream_session_requires_reconnect(monkeypatch):
    _configure_oauth(monkeypatch)
    now = main.time.time()
    legacy_refresh = jwt.encode(
        {
            "type": "refresh_token",
            "jti": "legacy-refresh-jti",
            "iat": now,
            "exp": now + 600,
            "client_id": "legacy-shared-client",
            "scope": "mcp offline_access",
            "resource": "https://mcp.example.com/mcp",
            "phone_number": "+15551234567",
            "ho_profile": {"ho_name": "Alex Fontova"},
        },
        main.OAUTH_CLIENT_SECRET,
        algorithm="HS256",
    )
    asyncio.run(
        main._get_state_store().put(
            "refresh:legacy-refresh-jti",
            {"status": "active"},
            int(now + 600),
        )
    )

    response = TestClient(main.app).post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "client_id": "legacy-shared-client",
            "refresh_token": legacy_refresh,
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"
    assert response.json()["error_code"] == "reauthentication_required"


def test_refresh_rotates_operator_homeowner_session(monkeypatch):
    _configure_oauth(monkeypatch)
    now = int(main.time.time())
    upstream_access = jwt.encode(
        {"sub": "homeowner", "exp": now + 7200},
        "upstream-test-secret-that-is-long-enough",
        algorithm="HS256",
    )
    session_id = asyncio.run(
        main._store_ho_session(
            {"ho_name": "Alex Fontova"},
            "expired-upstream-access",
            "upstream-refresh-before-rotation",
        )
    )
    refresh_token = asyncio.run(
        main._issue_refresh_token({
            "client_id": "legacy-shared-client",
            "scope": "mcp offline_access",
            "ho_session": session_id,
            "resource": "https://mcp.example.com/mcp",
        })
    )

    async def refresh_upstream(_client, method, url, **kwargs):
        assert kwargs["json"] == {
            "refresh_token": "upstream-refresh-before-rotation"
        }
        return httpx.Response(
            200,
            json={
                "access_token": upstream_access,
                "refresh_token": "upstream-refresh-after-rotation",
            },
            request=httpx.Request(method, url),
        )

    monkeypatch.setattr(main, "operator_request", refresh_upstream)
    response = TestClient(main.app).post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "client_id": "legacy-shared-client",
            "refresh_token": refresh_token,
        },
    )

    assert response.status_code == 200
    refreshed = asyncio.run(main._resolve_ho_session(session_id))
    assert refreshed["token"] == upstream_access
    assert refreshed["upstream_refresh_token"] == "upstream-refresh-after-rotation"
    assert response.json()["expires_in"] <= 7200


def test_bad_otp_returns_json_400_for_non_browser_client(monkeypatch):
    _configure_oauth(monkeypatch)

    async def reject_otp(client, method, url, **kwargs):
        return httpx.Response(
            400,
            json={
                "error": "invalid_grant",
                "error_code": "invalid_or_expired_otp",
                "error_description": "The verification code is incorrect or expired.",
            },
            request=httpx.Request(method, url),
        )

    monkeypatch.setattr(main, "operator_request", reject_otp)
    response = TestClient(main.app).post(
        "/oauth/authorize",
        data={
            "response_type": "code",
            "client_id": "legacy-shared-client",
            "redirect_uri": "https://chatgpt.com/connector/oauth/callback-id",
            "code_challenge": "challenge",
            "code_challenge_method": "S256",
            "scope": "mcp",
            "phone_number": "+15551234567",
            "verification_code": "000000",
            "step": "verify",
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"
    assert response.json()["error_code"] == "invalid_or_expired_otp"


def test_authorize_rejects_post_without_step_or_inferable_fields(monkeypatch):
    _configure_oauth(monkeypatch)

    response = TestClient(main.app).post(
        "/oauth/authorize",
        data={
            "response_type": "code",
            "client_id": "legacy-shared-client",
            "redirect_uri": "https://chatgpt.com/connector/oauth/callback-id",
            "code_challenge": "challenge",
            "code_challenge_method": "S256",
            "scope": "mcp",
        },
    )

    assert response.status_code == 400
    assert response.json()["error_code"] == "missing_form_step"
