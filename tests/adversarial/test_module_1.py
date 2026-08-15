"""Adversarial contract tests for the public distribution boundary."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from fastapi.testclient import TestClient

from src import config, main
from src.adapters import HttpOperatorRequestAdapter
from src.auth_context import current_is_authenticated
from src.mcp_server import _normalize_address, create_booking_mcp, get_my_profile_mcp
from src.security import ValidationError
from src.state import InMemoryStateStore
from src.tools import (
    _claim_booking_idempotency,
    _complete_booking_idempotency,
    _normalize_address_fields,
    _pick_best_address,
)


def test_public_configuration_has_no_private_defaults():
    assert config.configured_external_api_urls() == []
    assert not config.APP_LINK
    assert not config.SITE_BASE_URL
    assert not config.UPSTREAM_MCP_URL
    assert not config.UPSTREAM_MCP_AUTH_TOKEN


def test_address_normalization_handles_profile_shape():
    address = _normalize_address(
        {
            "street": "1 Main Street",
            "cityStateZip": "Example City, Example State, United States",
            "full": "1 Main Street, Example City, EX 12345, USA",
        }
    )

    assert address["address1"] == "1 Main Street"
    assert address["city"] == "Example City"
    assert address["region"] == "Example State"
    assert address["postalCode"] == "12345"
    assert address["formattedAddress"].startswith("1 Main Street")


def test_booking_address_normalization_enriches_formatted_address():
    address = _normalize_address_fields(
        {"address1": "1 Main Street", "formatted_address": "1 Main Street, Example City, EX 12345, USA"}
    )

    assert address["formattedAddress"] == "1 Main Street, Example City, EX 12345, USA"
    assert address["city"] == "Example City"
    assert address["region"] == "EX"
    assert address["postalCode"] == "12345"


def test_best_address_prefers_most_complete_candidate():
    selected = _pick_best_address(
        {"address1": "1 Main Street"},
        {"address1": "1 Main Street", "city": "Example City", "region": "EX", "postalCode": "12345"},
    )
    assert selected["postalCode"] == "12345"


def test_protected_tools_fail_closed_without_auth():
    token = current_is_authenticated.set(False)
    try:
        profile = asyncio.run(get_my_profile_mcp())
        booking = asyncio.run(create_booking_mcp("provider", "repair a leak"))
    finally:
        current_is_authenticated.reset(token)

    assert profile.status == "error"
    assert "connected" in (profile.message or "").lower()
    assert booking["status"] == "auth_required"


def test_http_adapter_rejects_unconfigured_integration():
    async def run():
        adapter = HttpOperatorRequestAdapter()
        async with httpx.AsyncClient() as client:
            with pytest.raises(ValidationError, match="not configured"):
                await adapter.request(
                    client,
                    "GET",
                    "",
                    allowed_hosts=set(),
                    endpoint_name="test:integration",
                    rate_limit=1,
                )

    asyncio.run(run())


def test_upstream_relay_uses_operator_token_only(monkeypatch):
    captured: dict = {}

    async def fake_operator_request(*args, **kwargs):
        captured.update(kwargs)
        return httpx.Response(200, headers={"content-type": "application/json"}, json={"ok": True})

    monkeypatch.setattr(main, "UPSTREAM_MCP_URL", "https://operator.example/mcp")
    monkeypatch.setattr(main, "UPSTREAM_MCP_AUTH_TOKEN", "operator-token")
    monkeypatch.setattr(main, "operator_request", fake_operator_request)

    with TestClient(main.app) as client:
        response = client.post(
            "/upstream/mcp",
            headers={"Authorization": "Bearer inbound-user-token", "Content-Type": "application/json"},
            content=b'{"jsonrpc":"2.0"}',
        )

    assert response.status_code == 200
    assert captured["headers"]["authorization"] == "Bearer operator-token"
    assert "inbound-user-token" not in str(captured["headers"])


def test_landing_page_renders_without_template_interpolation_errors():
    with TestClient(main.app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "Home Services MCP" in response.text
    assert "{ margin:" in response.text


def test_oauth_authorize_page_interpolates_operator_brand(monkeypatch):
    monkeypatch.setattr(main, "OAUTH_CLIENT_ID", "client")
    monkeypatch.setattr(main, "OAUTH_CLIENT_SECRET", "s" * 32)
    monkeypatch.setattr(main, "OAUTH_ALLOWED_REDIRECT_URIS", ["http://localhost:3000/callback"])

    with TestClient(main.app) as client:
        response = client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": "client",
                "redirect_uri": "http://localhost:3000/callback",
                "code_challenge": "challenge",
                "code_challenge_method": "S256",
            },
        )

    assert response.status_code == 200
    assert "Connect Home Services" in response.text
    assert "{form_body}" not in response.text


def test_auth_grants_are_opaque_and_single_use(monkeypatch):
    monkeypatch.setattr(main, "OAUTH_CLIENT_SECRET", "x" * 32)
    monkeypatch.setattr(main, "_state_store", InMemoryStateStore())

    async def run():
        code = await main._store_auth_grant(
            {
                "client_id": "client",
                "ho_profile": {"name": "Test User", "token": "upstream-secret"},
            }
        )
        first = await main._consume_auth_grant(code)
        second = await main._consume_auth_grant(code)
        return code, first, second

    code, first, second = asyncio.run(run())
    assert "upstream-secret" not in code
    assert first and "token" not in first["ho_profile"]
    assert second is None


def test_refresh_tokens_rotate_once(monkeypatch):
    monkeypatch.setattr(main, "OAUTH_CLIENT_SECRET", "y" * 32)
    monkeypatch.setattr(main, "_state_store", InMemoryStateStore())

    async def run():
        token = await main._issue_refresh_token({"client_id": "client"})
        decoded = main._decode_refresh_token(token)
        assert decoded is not None
        return await main._consume_refresh_token(decoded), await main._consume_refresh_token(decoded)

    assert asyncio.run(run()) == (True, False)


def test_booking_idempotency_claims_and_replays(monkeypatch):
    import src.tools as tools

    monkeypatch.setattr(tools, "_idempotency_store", InMemoryStateStore())

    async def run():
        key, first = await _claim_booking_idempotency("retry-1", "+15551234567")
        _, second = await _claim_booking_idempotency("retry-1", "+15551234567")
        await _complete_booking_idempotency(key, "job-123")
        _, completed = await _claim_booking_idempotency("retry-1", "+15551234567")
        return first, second, completed

    first, second, completed = asyncio.run(run())
    assert first is None
    assert second and second["status"] == "in_progress"
    assert completed == {"status": "completed", "job_id": "job-123"}
