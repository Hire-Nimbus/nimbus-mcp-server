"""Environment-only configuration for the public MCP distribution.

The server ships without credentials, tenant data, or private API defaults.
It does include one documented public hosted MCP fallback for convenience;
operators can replace that relay with their own endpoint through the
deployment environment.
"""

from __future__ import annotations

import json
import os
from typing import Any

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover - dotenv is optional in minimal images
    pass


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _bool_env(name: str, default: bool = False) -> bool:
    value = _env(name, "true" if default else "false").lower()
    return value in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    raw = _env(name, str(default))
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc


def _csv_env(name: str) -> list[str]:
    return [value.strip() for value in _env(name).split(",") if value.strip()]


def _json_dict_env(name: str) -> dict[str, str]:
    raw = _env(name)
    if not raw:
        return {}
    try:
        value: Any = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{name} must contain a JSON object") from exc
    if not isinstance(value, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
        raise RuntimeError(f"{name} must contain a JSON object with string keys and values")
    return value


# Configurable presentation. Empty URLs intentionally omit optional handoffs.
BRAND_NAME = _env("BRAND_NAME", "Home Services")
MCP_SERVER_NAME = _env("MCP_SERVER_NAME", f"{BRAND_NAME} MCP")
MCP_SERVER_DESCRIPTION = _env(
    "MCP_SERVER_DESCRIPTION",
    "Search, review, and request home services through an operator-configured MCP server.",
)
APP_LINK = _env("APP_LINK")
SITE_BASE_URL = _env("SITE_BASE_URL")
UI_BASE_URL = _env("UI_BASE_URL")
SUPPORT_URL = _env("SUPPORT_URL")
LANDING_REDIRECT_URL = _env("LANDING_REDIRECT_URL")
ALLOWED_ORIGINS = _csv_env("ALLOWED_ORIGINS")

# Operator-owned service APIs. There are no public-service fallbacks.
PROVIDERS_API = _env("PROVIDERS_API")
COORDS_RESOLVE_API = _env("COORDS_RESOLVE_API")
ZIP_RESOLVE_API = _env("ZIP_RESOLVE_API")
GEOCODING_API = _env("GEOCODING_API")
GEOCODING_API_KEY = _env("GEOCODING_API_KEY")
BOOKING_API = _env("BOOKING_API")
SERVICE_REQUESTS_URL = _env("SERVICE_REQUESTS_URL") or BOOKING_API
SERVICE_REQUESTS_METADATA_URL = _env("SERVICE_REQUESTS_METADATA_URL")
REVIEWS_API = _env("REVIEWS_API")
SEND_BOOK_NOTIFICATION_API = _env("SEND_BOOK_NOTIFICATION_API")
SEND_JOB_TO_SLACK_API = _env("SEND_JOB_TO_SLACK_API")
CANCEL_BOOKING_API = _env("CANCEL_BOOKING_API")

# Optional monitoring is off by default and never points at a default webhook.
MCP_MONITOR_ENABLED = _bool_env("MCP_MONITOR_ENABLED", False)
MCP_MONITOR_SLACK_CHANNEL = _env("MCP_MONITOR_SLACK_CHANNEL", "mcp-monitor")
MCP_MONITOR_SLACK_API = _env("MCP_MONITOR_SLACK_API")

# Optional phone/OTP identity integration owned by the operator.
PROFILE_LOOKUP_API = _env("PROFILE_LOOKUP_API")
PROFILE_LOOKUP_METHOD = _env("PROFILE_LOOKUP_METHOD", "POST").upper()
AUTH_WEBHOOK_URL = _env("AUTH_WEBHOOK_URL")
HOMEOWNER_PROFILE_API = _env("HOMEOWNER_PROFILE_API")

# The public hosted relay is a convenience default, not a credential or data
# store. Operators can replace it with their own MCP endpoint and token.
DEFAULT_UPSTREAM_MCP_URL = "https://mcp.hirenimbus.com/mcp"


def _resolve_upstream_mcp_url() -> str:
    """Return the operator override, or the documented public fallback."""

    return _env("UPSTREAM_MCP_URL") or DEFAULT_UPSTREAM_MCP_URL


# The relay never forwards inbound Authorization headers implicitly.
UPSTREAM_MCP_URL = _resolve_upstream_mcp_url()
UPSTREAM_MCP_AUTH_TOKEN = _env("UPSTREAM_MCP_AUTH_TOKEN")
UPSTREAM_MCP_TIMEOUT_SECONDS = _int_env("UPSTREAM_MCP_TIMEOUT_SECONDS", 15)

# Search behavior.
SEARCH_PROVIDERS_FETCH_COUNT = _int_env("SEARCH_PROVIDERS_FETCH_COUNT", 10)
SEARCH_PROVIDERS_RETURN_COUNT = _int_env("SEARCH_PROVIDERS_RETURN_COUNT", 6)

# Security and operational limits.
RATE_LIMIT_RPM = _int_env("RATE_LIMIT_RPM", 60)
USER_RATE_LIMIT_RPM = _int_env("USER_RATE_LIMIT_RPM", 120)
TOOL_RATE_LIMIT_RPM = _int_env("TOOL_RATE_LIMIT_RPM", 30)
LOCATION_RESOLVE_RATE_LIMIT_RPM = _int_env("LOCATION_RESOLVE_RATE_LIMIT_RPM", 15)
BOOKING_RATE_LIMIT_RPM = _int_env("BOOKING_RATE_LIMIT_RPM", 10)

# OAuth and optional compatibility authentication.
OAUTH_CLIENT_ID = _env("OAUTH_CLIENT_ID")
OAUTH_CLIENT_SECRET = _env("OAUTH_CLIENT_SECRET")
OAUTH_TOKEN_TTL = _int_env("OAUTH_TOKEN_TTL", 604800)
PUBLIC_BASE_URL = _env("PUBLIC_BASE_URL")
OAUTH_ALLOWED_REDIRECT_URIS = _csv_env("OAUTH_ALLOWED_REDIRECT_URIS")
OAUTH_DYNAMIC_CLIENT_REGISTRATION_ENABLED = _bool_env(
    "OAUTH_DYNAMIC_CLIENT_REGISTRATION_ENABLED", False
)
MVP_STATIC_MCP_TOKEN = _env("MVP_STATIC_MCP_TOKEN")
OPENAI_APPS_CHALLENGE_TOKEN = _env("OPENAI_APPS_CHALLENGE_TOKEN")
AUTH_PHONE_ALIASES = _json_dict_env("AUTH_PHONE_ALIASES")

# Shared state is optional for local development but should be enabled for
# multi-instance production deployments. The SAM template provisions the
# operator-owned table and sets this value automatically.
AUTH_STATE_TABLE_NAME = _env("AUTH_STATE_TABLE_NAME")
REQUIRE_DURABLE_STATE = _bool_env("REQUIRE_DURABLE_STATE", False)
IDEMPOTENCY_TTL_SECONDS = _int_env("IDEMPOTENCY_TTL_SECONDS", 86400)
IDEMPOTENCY_KEY_MAX_LENGTH = _int_env("IDEMPOTENCY_KEY_MAX_LENGTH", 128)


def configured_external_api_urls() -> list[str]:
    """Return configured outbound URLs for the request host allowlist."""

    urls = [
        PROVIDERS_API,
        COORDS_RESOLVE_API,
        ZIP_RESOLVE_API,
        GEOCODING_API,
        BOOKING_API,
        SERVICE_REQUESTS_URL,
        SERVICE_REQUESTS_METADATA_URL,
        REVIEWS_API,
        SEND_BOOK_NOTIFICATION_API,
        SEND_JOB_TO_SLACK_API,
        CANCEL_BOOKING_API,
        MCP_MONITOR_SLACK_API,
        PROFILE_LOOKUP_API,
        AUTH_WEBHOOK_URL,
        HOMEOWNER_PROFILE_API,
        UPSTREAM_MCP_URL,
    ]
    return [url for url in urls if url]
