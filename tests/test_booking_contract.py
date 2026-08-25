from __future__ import annotations

import asyncio

import httpx
from fastapi.testclient import TestClient

from src import main, mcp_server, tools
from src.auth_context import (
    current_ho_profile,
    current_ho_session_id,
)
from src.state import InMemoryStateStore


MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
    "Mcp-Protocol-Version": "2025-03-26",
}


def _mcp_call(client: TestClient, name: str, arguments: dict, token: str):
    return client.post(
        "/mcp",
        headers={**MCP_HEADERS, "Authorization": f"Bearer {token}"},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    )


def test_successful_booking_backfills_profile_and_geocodes_address(monkeypatch):
    captured: dict[str, object] = {}
    monkeypatch.setattr(tools, "BOOKING_API", "https://operator.example/book")
    monkeypatch.setattr(
        tools,
        "HOMEOWNER_PROFILE_API",
        "https://operator.example/profile",
    )
    monkeypatch.setattr(main, "_state_store", InMemoryStateStore())
    monkeypatch.setattr(tools, "GEOCODING_API", "https://operator.example/geocode")
    monkeypatch.setattr(tools, "GEOCODING_API_KEY", "test-key")

    async def operator_request(_client, method, url, **kwargs):
        if url == tools.GEOCODING_API:
            return httpx.Response(
                200,
                json={
                    "results": [{
                        "formatted_address": "2000 Mason Hill Drive, Alexandria, VA 22307, USA",
                        "geometry": {"location": {"lat": 38.7421, "lng": -77.0672}},
                        "address_components": [],
                    }]
                },
                request=httpx.Request(method, url),
            )
        if method == "PATCH":
            captured["profile_patch"] = kwargs["json"]
            return httpx.Response(200, json={}, request=httpx.Request(method, url))
        captured["booking_payload"] = kwargs["json"]
        return httpx.Response(
            200,
            json={"data": {"id": 3445}},
            request=httpx.Request(method, url),
        )

    monkeypatch.setattr(tools, "operator_request", operator_request)
    profile = {
        "name": None,
        "ho_name": None,
        "phone": "+15551234567",
        "address": None,
        "ho_address": None,
        "token": "upstream-token",
    }
    session_id = asyncio.run(main._store_ho_session(profile, "upstream-token"))
    profile_token = current_ho_profile.set(profile)
    session_token = current_ho_session_id.set(session_id)
    try:
        result = asyncio.run(
            tools.create_booking(
                {
                    "serviceProviderSlug": "test-provider",
                    "name": "Alex Fontova",
                    "phone": "+15551234567",
                    "address": {
                        "address1": "2000 Mason Hill Drive",
                        "city": "Alexandria",
                        "region": "VA",
                        "postalCode": "22307",
                    },
                    "job_description": "Mount a television in the living room.",
                }
            )
        )
    finally:
        current_ho_session_id.reset(session_token)
        current_ho_profile.reset(profile_token)

    assert result["status"] == "created"
    assert result["details"]["resolved_location"]["lat"] == 38.7421
    assert captured["booking_payload"]["address"]["lat"] == 38.7421
    assert captured["booking_payload"]["address"]["lng"] == -77.0672
    assert captured["profile_patch"] == {
        "ho_name": "Alex Fontova",
        "ho_address": captured["booking_payload"]["address"],
        "backfill_only": True,
    }
    restored = asyncio.run(main._resolve_ho_session(session_id))
    assert restored["name"] == "Alex Fontova"
    assert restored["address"]["address1"] == "2000 Mason Hill Drive"


def test_rebooking_uses_source_job_identity_when_profile_is_null(monkeypatch):
    source_job = {
        "id": 3408,
        "name": "Alex Fontova",
        "phone": "+15551234567",
        "address": {"address1": "2000 Mason Hill Drive"},
        "job_description": "Mount a television.",
        "service_provider": {"slug": "test-provider"},
    }
    captured: dict[str, object] = {}

    async def load_jobs():
        return {"data": [source_job]}

    async def create(args):
        captured.update(args)
        return {"status": "created"}

    monkeypatch.setattr(tools, "_load_homeowner_jobs_raw", load_jobs)
    monkeypatch.setattr(tools, "create_booking", create)
    profile_token = current_ho_profile.set(
        {"name": None, "phone": None, "address": None}
    )
    try:
        result = asyncio.run(tools.book_same_pro_again({"job_id": 3408}))
    finally:
        current_ho_profile.reset(profile_token)

    assert result["status"] == "created"
    assert captured["name"] == "Alex Fontova"
    assert captured["phone"] == "+15551234567"
    assert captured["address"]["address1"] == "2000 Mason Hill Drive"


def test_failed_confirmed_booking_sets_mcp_is_error(monkeypatch):
    monkeypatch.setattr(main, "OAUTH_CLIENT_ID", "")
    monkeypatch.setattr(main, "OAUTH_CLIENT_SECRET", "")
    monkeypatch.setattr(main, "MVP_STATIC_MCP_TOKEN", "test-static-token")

    with TestClient(main.app) as client:
        response = _mcp_call(
            client,
            "create_booking",
            {
                "serviceProviderSlug": "test-provider",
                "job_description": "Mount a television.",
                "confirm_booking": True,
            },
            "test-static-token",
        )

    assert response.status_code == 200
    assert response.json()["result"]["isError"] is True
    assert "VALIDATION_ERROR" in response.json()["result"]["content"][0]["text"]


def test_missing_rebooking_job_sets_mcp_is_error(monkeypatch):
    monkeypatch.setattr(main, "OAUTH_CLIENT_ID", "")
    monkeypatch.setattr(main, "OAUTH_CLIENT_SECRET", "")
    monkeypatch.setattr(main, "MVP_STATIC_MCP_TOKEN", "test-static-token")

    async def missing_job(_args):
        return {
            "status": "failed",
            "message": "Previous job not found",
            "error_code": "JOB_NOT_FOUND",
        }

    monkeypatch.setattr(mcp_server, "book_same_pro_again", missing_job)
    with TestClient(main.app) as client:
        response = _mcp_call(
            client,
            "book_same_pro_again",
            {"job_id": 999999, "confirm_booking": True},
            "test-static-token",
        )

    assert response.status_code == 200
    assert response.json()["result"]["isError"] is True
    assert "JOB_NOT_FOUND" in response.json()["result"]["content"][0]["text"]


def test_homeowner_session_validation_rejects_expired_upstream_token(monkeypatch):
    monkeypatch.setattr(
        tools,
        "HOMEOWNER_PROFILE_API",
        "https://operator.example/profile",
    )

    async def unauthorized(_client, method, url, **_kwargs):
        return httpx.Response(401, request=httpx.Request(method, url))

    monkeypatch.setattr(tools, "operator_request", unauthorized)
    profile_token = current_ho_profile.set({"token": "expired-upstream-token"})
    try:
        result = asyncio.run(tools.validate_homeowner_session())
    finally:
        current_ho_profile.reset(profile_token)

    assert result["status"] == "error"
    assert result["error_code"] == "UPSTREAM_SESSION_EXPIRED"


def test_numeric_rebooking_id_and_cancel_tool_are_exposed(monkeypatch):
    monkeypatch.setattr(main, "OAUTH_CLIENT_ID", "")
    monkeypatch.setattr(main, "OAUTH_CLIENT_SECRET", "")
    monkeypatch.setattr(main, "MVP_STATIC_MCP_TOKEN", "test-static-token")

    async def previous_jobs():
        return {
            "jobs": [
                {
                    "id": 3408,
                    "name": "Alex Fontova",
                    "phone": "+15551234567",
                    "address": {"address1": "2000 Mason Hill Drive"},
                    "job_description": "Mount a television.",
                    "service_provider": {"slug": "test-provider"},
                }
            ],
            "hasActiveJobs": False,
            "error": None,
        }

    monkeypatch.setattr(mcp_server, "get_previous_jobs", previous_jobs)
    with TestClient(main.app) as client:
        listed = client.post(
            "/mcp",
            headers={**MCP_HEADERS, "Authorization": "Bearer test-static-token"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
        preview = _mcp_call(
            client,
            "book_same_pro_again",
            {"job_id": 3408, "confirm_booking": False},
            "test-static-token",
        )

    names = {tool["name"] for tool in listed.json()["result"]["tools"]}
    assert "cancel_booking" in names
    assert preview.json()["result"].get("isError", False) is False
    assert '"homeowner_name": "Alex Fontova"' in preview.json()["result"]["content"][0]["text"]
