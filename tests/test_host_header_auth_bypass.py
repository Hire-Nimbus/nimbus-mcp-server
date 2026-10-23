"""CVE-2026-48710: a crafted Host header must not make a protected path look public."""
from fastapi.testclient import TestClient

from src import main


def test_crafted_host_header_does_not_bypass_auth(monkeypatch):
    monkeypatch.setattr(main, "OAUTH_CLIENT_ID", "test-client")
    monkeypatch.setattr(main, "OAUTH_CLIENT_SECRET", "test-secret")
    monkeypatch.setattr(main, "PUBLIC_BASE_URL", "https://mcp.hirenimbus.com")
    client = TestClient(main.app)
    assert client.post("/tools/create_booking", json={}).status_code == 401
    for host in ("evil.example/oauth/token?", "evil.example/.well-known/jwks.json#"):
        response = client.post("/tools/create_booking", json={}, headers={"Host": host})
        assert response.status_code == 401, (host, response.status_code, response.text)
