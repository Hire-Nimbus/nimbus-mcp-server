from __future__ import annotations

import base64
from pathlib import Path
import fnmatch
import hashlib
import html as html_mod
import logging
import secrets
import time
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlencode, urlparse

from cryptography.fernet import Fernet, InvalidToken
import httpx
import jwt
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from mangum import Mangum
from pydantic import BaseModel, Field

from src.config import (
    ALLOWED_ORIGINS,
    AUTH_STATE_TABLE_NAME,
    AUTH_PHONE_ALIASES,
    AUTH_WEBHOOK_URL,
    BRAND_NAME,
    HOMEOWNER_PROFILE_API,
    LANDING_REDIRECT_URL,
    MCP_SERVER_DESCRIPTION,
    MCP_SERVER_NAME,
    OAUTH_ALLOWED_REDIRECT_URIS,
    OAUTH_DYNAMIC_CLIENT_REGISTRATION_ENABLED,
    OAUTH_CLIENT_ID,
    OAUTH_CLIENT_SECRET,
    OAUTH_TOKEN_TTL,
    OPENAI_APPS_CHALLENGE_TOKEN,
    PUBLIC_BASE_URL,
    RATE_LIMIT_RPM,
    REQUIRE_DURABLE_STATE,
    USER_RATE_LIMIT_RPM,
    PROFILE_LOOKUP_API,
    PROFILE_LOOKUP_METHOD,
    MVP_STATIC_MCP_TOKEN,
    UPSTREAM_MCP_AUTH_TOKEN,
    UPSTREAM_MCP_TIMEOUT_SECONDS,
    UPSTREAM_MCP_URL,
    configured_external_api_urls,
)
from src.auth_context import (
    current_ho_profile,
    current_actor_id,
    current_ho_session_id,
    current_is_authenticated,
)
from src.adapters import operator_request
from src.mcp_server import mcp
from src.monitor import (
    notify_login_success,
    notify_token_issued,
    request_meta_from_request,
    set_request_meta,
)
from src.oauth_signing import access_token_jwk, decode_access_token, encode_access_token
from src.security import (
    build_allowed_hosts,
    check_http_rate_limit,
    install_pii_log_filter,
    mask_phone,
)
from src.state import InMemoryStateStore, StateStore, StateStoreError, build_state_store
from src.tools import create_booking, search_providers

logger = logging.getLogger("nimbus-mcp")
logger.setLevel(logging.INFO)
install_pii_log_filter()

_ALLOWED_API_HOSTS = build_allowed_hosts(configured_external_api_urls())

_http_client: httpx.AsyncClient | None = None


def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(timeout=httpx.Timeout(10, connect=5))
    return _http_client

# -----------  MCP sub-app (must be created before lifespan)  -----------

_mcp_app_raw = mcp.streamable_http_app()


class _RootToMcp:
    """Remap POST/DELETE/PUT on / to /mcp for MCP clients that use the server root URL."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("path") in ("/", ""):
            scope = dict(scope)
            scope["path"] = "/mcp"
            if "raw_path" in scope:
                scope["raw_path"] = b"/mcp"
        await self.app(scope, receive, send)


mcp_app = _RootToMcp(_mcp_app_raw)


@asynccontextmanager
async def lifespan(app):
    if REQUIRE_DURABLE_STATE:
        _get_state_store()
    mcp._session_manager._has_started = False
    async with mcp.session_manager.run():
        yield
    client = _http_client
    if client and not client.is_closed:
        await client.aclose()


app = FastAPI(redirect_slashes=False, lifespan=lifespan)

# -----------  CORS  -----------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Accept", "Authorization", "Mcp-Session-Id", "Mcp-Protocol-Version"],
    expose_headers=["Mcp-Session-Id"],
    allow_credentials=False,
)

# -----------  Helpers  -----------


def _get_base_url(request: Request) -> str:
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL.rstrip("/")
    return str(request.base_url).rstrip("/")


def _oauth_enabled() -> bool:
    return bool(OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET)


def _is_static_mvp_token(token: str) -> bool:
    """True when request bearer token matches configured MVP static token."""
    if not MVP_STATIC_MCP_TOKEN:
        return False
    return secrets.compare_digest(token or "", MVP_STATIC_MCP_TOKEN)


def _is_allowed_origin(origin: str) -> bool:
    """Allow approved AI clients, Google surfaces, and localhost origins."""
    normalized_origin = (origin or "").strip()
    if not normalized_origin:
        return False

    # Accept plain host values if a proxy strips scheme.
    if "://" not in normalized_origin:
        normalized_origin = f"https://{normalized_origin}"

    try:
        parsed = urlparse(normalized_origin)
    except Exception:
        return False

    if parsed.scheme not in {"http", "https"}:
        return False

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False

    if parsed.scheme == "https" and hostname == "claude.ai":
        return True

    if parsed.scheme == "https" and fnmatch.fnmatch(hostname, "*.anthropic.com"):
        return True

    if parsed.scheme == "https" and hostname == "chat.openai.com":
        return True

    if parsed.scheme == "https" and hostname == "chatgpt.com":
        return True

    if parsed.scheme == "https" and (hostname == "openai.com" or fnmatch.fnmatch(hostname, "*.openai.com")):
        return True

    if parsed.scheme == "https" and (
        hostname in {"cursor.com", "www.cursor.com"}
        or fnmatch.fnmatch(hostname, "*.cursor.com")
        or hostname in {"grok.com", "www.grok.com"}
        or fnmatch.fnmatch(hostname, "*.x.ai")
    ):
        return True

    if parsed.scheme == "https" and hostname == "gemini.google.com":
        return True

    if parsed.scheme == "https" and fnmatch.fnmatch(hostname, "*.google.com"):
        return True

    if hostname == "localhost":
        return True

    return normalized_origin in {origin.rstrip("/") for origin in ALLOWED_ORIGINS}


# -----------  Rate limiter (per-IP and per-user, in-memory)  -----------

AUTH_CODE_TTL = 600
REFRESH_TOKEN_TTL = 14 * 24 * 60 * 60  # 14 days
DYNAMIC_CLIENT_TTL = 10 * 365 * 24 * 60 * 60  # 10 years
_OAUTH_SCOPES_SUPPORTED = (
    "openid",
    "profile",
    "email",
    "offline_access",
    "mcp",
    "mcp:read",
    "mcp:write",
    "jobs:read",
    "jobs:write",
    "homeowner:read",
)

_state_store: StateStore | None = None


def _get_state_store() -> StateStore:
    """Return the configured shared store, with an explicit local fallback."""

    global _state_store
    if _state_store is not None:
        return _state_store
    try:
        _state_store = build_state_store(AUTH_STATE_TABLE_NAME)
    except StateStoreError:
        if REQUIRE_DURABLE_STATE:
            raise
        logger.warning("Shared state backend unavailable; using process-local state")
        _state_store = InMemoryStateStore()
    if REQUIRE_DURABLE_STATE and not _state_store.durable:
        raise RuntimeError("REQUIRE_DURABLE_STATE is enabled but AUTH_STATE_TABLE_NAME is not configured")
    return _state_store


def _fernet() -> Fernet:
    """Encrypt operator-issued upstream tokens before state persistence."""

    key_bytes = hashlib.sha256(OAUTH_CLIENT_SECRET.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(key_bytes))


def _encrypt_token(token: str) -> str:
    return _fernet().encrypt(token.encode("utf-8")).decode("ascii")


def _decrypt_token(encrypted: str) -> str:
    return _fernet().decrypt(encrypted.encode("ascii")).decode("utf-8")


def _encode_refresh_token(payload: dict[str, Any]) -> str:
    """Encode refresh token data as a signed JWT."""
    now = time.time()
    payload = {
        **payload,
        "type": "refresh_token",
        "iat": now,
        "exp": now + REFRESH_TOKEN_TTL,
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, OAUTH_CLIENT_SECRET, algorithm="HS256")


def _decode_refresh_token(token: str) -> dict[str, Any] | None:
    """Decode and validate a refresh token JWT. Returns None if invalid/expired."""
    try:
        payload = jwt.decode(
            token,
            OAUTH_CLIENT_SECRET,
            algorithms=["HS256"],
            options={"require": ["exp", "jti", "type"]},
        )
        if payload.get("type") != "refresh_token":
            return None
        return payload
    except jwt.InvalidTokenError:
        return None


async def _store_auth_grant(payload: dict[str, Any]) -> str:
    """Persist a short-lived opaque grant without putting profile data in a URL."""

    code = secrets.token_urlsafe(32)
    safe_payload = dict(payload)
    safe_payload["ho_profile"] = _trim_profile(dict(safe_payload.get("ho_profile") or {}))
    for secret_key in ("token", "ho_token", "access_token", "enc_ho_token"):
        safe_payload.pop(secret_key, None)
    await _get_state_store().put(
        f"grant:{code}",
        safe_payload,
        int(time.time()) + AUTH_CODE_TTL,
    )
    return code


async def _consume_auth_grant(code: str) -> dict[str, Any] | None:
    """Atomically consume an authorization grant exactly once."""

    return await _get_state_store().consume(f"grant:{code}")


async def _store_dynamic_client(registration: dict[str, Any]) -> None:
    """Persist an RFC 7591 public-client registration."""

    await _get_state_store().put(
        f"client:{registration['client_id']}",
        registration,
        int(time.time()) + DYNAMIC_CLIENT_TTL,
    )


async def _resolve_dynamic_client(client_id: str) -> dict[str, Any] | None:
    return await _get_state_store().get(f"client:{client_id}")


async def _store_ho_session(profile: dict[str, Any], upstream_token: str) -> str:
    """Persist profile context server-side; encrypt the operator bearer token."""

    session_id = secrets.token_urlsafe(32)
    safe_profile = _trim_profile(profile)
    if upstream_token:
        safe_profile["enc_ho_token"] = _encrypt_token(upstream_token)
    await _get_state_store().put(
        f"session:{session_id}",
        safe_profile,
        int(time.time()) + REFRESH_TOKEN_TTL,
    )
    return session_id


async def _resolve_ho_session(session_id: str) -> dict[str, Any] | None:
    """Resolve an opaque homeowner session for internal outbound calls only."""

    if not session_id:
        return None
    profile = await _get_state_store().get(f"session:{session_id}")
    if not profile:
        return None
    encrypted = profile.pop("enc_ho_token", None)
    if encrypted:
        try:
            profile["token"] = _decrypt_token(str(encrypted))
        except (InvalidToken, ValueError, TypeError):
            logger.warning("Unable to decrypt homeowner session token")
    return profile


async def _issue_refresh_token(payload: dict[str, Any]) -> str:
    """Issue a signed refresh token and register its JTI for rotation/revocation."""

    token = _encode_refresh_token(payload)
    decoded = _decode_refresh_token(token)
    if not decoded or not decoded.get("jti"):
        raise RuntimeError("Unable to issue refresh token")
    await _get_state_store().put(
        f"refresh:{decoded['jti']}",
        {"status": "active"},
        int(decoded["exp"]),
    )
    return token


async def _consume_refresh_token(decoded: dict[str, Any]) -> bool:
    """Consume a refresh JTI so every refresh operation rotates the token."""

    jti = str(decoded.get("jti") or "")
    if not jti:
        return False
    return await _get_state_store().consume(f"refresh:{jti}") is not None


def _normalize_phone(phone_number: str) -> str:
    """Normalize phone aliases to canonical auth destinations."""
    return AUTH_PHONE_ALIASES.get(phone_number, phone_number)


def _is_allowed_redirect_uri(redirect_uri: str) -> bool:
    if not redirect_uri:
        return False
    if not OAUTH_ALLOWED_REDIRECT_URIS:
        return False
    return redirect_uri in OAUTH_ALLOWED_REDIRECT_URIS


def _trim_profile(raw: dict[str, Any]) -> dict[str, Any]:
    """Keep only the fields used downstream to avoid bloating JWTs."""
    trimmed: dict[str, Any] = {}
    for name_key in ("ho_name", "name"):
        v = raw.get(name_key)
        if v:
            trimmed[name_key] = v
    for phone_key in ("ho_phone", "phone"):
        v = raw.get(phone_key)
        if v:
            trimmed[phone_key] = v
    for addr_key in ("ho_address", "address"):
        v = raw.get(addr_key)
        if v:
            trimmed[addr_key] = v
    return trimmed


async def _fetch_homeowner_profile(normalized_phone: str, upstream_access_token: str) -> dict[str, Any]:
    """Fetch homeowner profile after OTP verification.

    Preferred source is backsearch-by-phone. Falls back to ho_profile API.
    """
    client = _get_http_client()
    masked = mask_phone(normalized_phone)

    # 1) Preferred: phone-based backsearch profile lookup.
    if PROFILE_LOOKUP_API:
        try:
            lookup_kwargs: dict[str, Any] = {"json": {"phone": normalized_phone}}
            if PROFILE_LOOKUP_METHOD == "GET":
                lookup_kwargs = {"params": {"phone": normalized_phone}}
            r = await operator_request(
                client,
                PROFILE_LOOKUP_METHOD,
                PROFILE_LOOKUP_API,
                allowed_hosts=_ALLOWED_API_HOSTS,
                endpoint_name="ho:lookup",
                rate_limit=30,
                **lookup_kwargs,
                timeout=8,
            )
            if r.status_code != 404:
                r.raise_for_status()
                raw_lookup = r.json() or {}
                if raw_lookup.get("found", True):
                    lookup_profile = _trim_profile(raw_lookup)
                    if lookup_profile:
                        return lookup_profile
        except Exception as exc:
            logger.warning("Phone backsearch profile lookup failed for %s: %s", masked, exc)

    # 2) Backward-compatible fallback: profile via webhook access token.
    try:
        r2 = await operator_request(
            client,
            "GET",
            HOMEOWNER_PROFILE_API,
            allowed_hosts=_ALLOWED_API_HOSTS,
            endpoint_name="ho:profile",
            rate_limit=30,
            headers={"Authorization": f"Bearer {upstream_access_token}"},
            timeout=8,
        )
        r2.raise_for_status()
        raw_profile = r2.json() or {}
        return _trim_profile(raw_profile) if raw_profile else {}
    except Exception as exc:
        logger.warning("Fallback ho_profile fetch failed for %s: %s", masked, exc)
        return {}


async def _fetch_profile_by_upstream_token(upstream_access_token: str) -> dict[str, Any]:
    """Fetch homeowner profile using upstream bearer token."""
    if not upstream_access_token:
        return {}

    try:
        r = await operator_request(
            _get_http_client(),
            "GET",
            HOMEOWNER_PROFILE_API,
            allowed_hosts=_ALLOWED_API_HOSTS,
            endpoint_name="ho:profile",
            rate_limit=30,
            headers={"Authorization": f"Bearer {upstream_access_token}"},
            timeout=8,
        )
        r.raise_for_status()
        raw_profile = r.json() or {}
        return _trim_profile(raw_profile) if raw_profile else {}
    except Exception as exc:
        logger.warning("Profile-by-token fetch failed: %s", exc)
        return {}


def _safe_jwt_sub(token: str) -> str:
    """Extract 'sub' from a JWT without verification, for logging only."""
    try:
        payload = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
        return str(payload.get("sub", "?"))
    except Exception:
        return "?"


def _verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return computed == code_challenge
    return False


# -----------  Security middleware  -----------

_TOOL_ANNOTATIONS_PATH = Path(__file__).resolve().parent.parent / "docs" / "TOOL_ANNOTATIONS.md"

_PUBLIC_PATHS = {
    "/__ping",
    "/.well-known/mcp.json",
    "/.well-known/tool-annotations",
    "/.well-known/openai-apps-challenge",
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-authorization-server/mcp",
    "/.well-known/openid-configuration",
    "/.well-known/jwks.json",
    "/jwks.json",
    "/oauth/authorize",
    "/oauth/token",
    "/oauth/register",
    "/oauth/revoke",
}
_PUBLIC_GET_ONLY_PATHS = {"/"}  # GET / = landing page; POST / = MCP (needs auth)


@app.middleware("http")
async def security_middleware(request: Request, call_next) -> Response:
    path = request.url.path
    method = request.method

    logger.info(">> %s %s (host=%s)", method, path, request.headers.get("host", "?"))

    origin = request.headers.get("origin")
    if origin and not _is_allowed_origin(origin):
        logger.warning("Rejected request with disallowed origin=%s for %s %s", origin, method, path)
        return JSONResponse({"error": "forbidden_origin", "message": "Origin is not allowed"}, status_code=403)

    is_public = (
        path in _PUBLIC_PATHS
        or (path in _PUBLIC_GET_ONLY_PATHS and method == "GET")
        or method == "OPTIONS"
    )
    if is_public:
        response = await call_next(request)
        allow_frame = path.startswith("/oauth/") or path == "/"
        _add_security_headers(response, allow_frame=allow_frame)
        logger.info("<< %s %s -> %s", method, path, response.status_code)
        return response

    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    client_ip = client_ip.split(",")[0].strip()
    request_meta = request_meta_from_request(request)
    set_request_meta(request_meta)
    if check_http_rate_limit(f"ip:{client_ip}", limit=RATE_LIMIT_RPM):
        logger.warning("Rate limited (IP): %s", client_ip)
        return JSONResponse({"error": "rate_limited", "message": "Too many requests"}, status_code=429)

    if _oauth_enabled() or bool(MVP_STATIC_MCP_TOKEN):
        auth_header = request.headers.get("authorization", "")
        base = _get_base_url(request)
        if not auth_header.startswith("Bearer "):
            logger.warning("Missing Bearer token for %s %s", method, path)
            return JSONResponse(
                {"error": "unauthorized", "message": "Bearer token required"},
                status_code=401,
                headers={
                    "WWW-Authenticate": (
                        f'Bearer realm="nimbus-mcp", '
                        f'resource_metadata="{base}/.well-known/oauth-protected-resource"'
                    )
                },
            )
        token = auth_header[7:]
        if _is_static_mvp_token(token):
            # MVP bypass path: trust this integration token and provide a
            # minimal synthetic claim set so downstream code can proceed.
            request.state.jwt_claims = {  # type: ignore[attr-defined]
                "sub": "mvp-static-token",
                "scope": "mcp",
                "aud": f"{base}/mcp",
                "auth_type": "static_mvp_token",
            }
            current_actor_id.set("mvp-static-token")
            current_is_authenticated.set(True)
            current_ho_session_id.set(None)
            current_ho_profile.set(None)
            response = await call_next(request)
            _add_security_headers(response)
            logger.info("<< %s %s -> %s (mvp static token)", method, path, response.status_code)
            return response
        if not _oauth_enabled():
            logger.warning("Invalid MVP static token for %s %s", method, path)
            return JSONResponse(
                {"error": "invalid_token", "message": "Invalid access token"},
                status_code=401,
                headers={
                    "WWW-Authenticate": (
                        f'Bearer realm="nimbus-mcp", '
                        f'error="invalid_token", '
                        f'resource_metadata="{base}/.well-known/oauth-protected-resource"'
                    )
                },
            )
        try:
            claims = decode_access_token(
                token,
                OAUTH_CLIENT_SECRET,
                audience=f"{base}/mcp",
            )
            if "sub" not in claims:
                raise jwt.InvalidTokenError("sub missing")
            token_scope = str(claims.get("scope") or "")
            if token_scope and "mcp" not in token_scope.split():
                logger.info(
                    "Accepting token without explicit 'mcp' scope for %s %s (scope=%s)",
                    method,
                    path,
                    token_scope,
                )

            request.state.jwt_claims = claims  # type: ignore[attr-defined]
            actor_sub = str(claims.get("sub") or "unknown")
            current_actor_id.set(actor_sub)
            current_is_authenticated.set(True)
            ho_session = str(claims.get("ho_session") or "") or None
            current_ho_session_id.set(ho_session)
            if check_http_rate_limit(f"user:{actor_sub}:{path}", limit=USER_RATE_LIMIT_RPM):
                logger.warning("Rate limited (user): sub=%s path=%s", actor_sub, path)
                return JSONResponse({"error": "rate_limited", "message": "Too many requests"}, status_code=429)

            profile = await _resolve_ho_session(ho_session) if ho_session else None
            profile = profile or {}
            claim_profile = dict(claims.get("ho_profile") or {})
            for key, value in claim_profile.items():
                profile.setdefault(key, value)
            if claims.get("ho_phone"):
                profile.setdefault("phone", claims["ho_phone"])
            if claims.get("ho_name"):
                profile.setdefault("name", claims["ho_name"])
            if claims.get("ho_address"):
                profile.setdefault("address", claims["ho_address"])

            # If OAuth token payload lacks profile fields, refresh them via
            # upstream homeowner token (same token-based pattern tools use).
            if not profile.get("name") or not profile.get("address"):
                upstream_token = profile.get("token")
                if upstream_token:
                    enriched = await _fetch_profile_by_upstream_token(str(upstream_token))
                    if enriched:
                        profile.update(enriched)
            current_ho_profile.set(profile or None)
        except jwt.ExpiredSignatureError:
            logger.info("Expired token for %s %s (sub=%s)", method, path, _safe_jwt_sub(token))
            return JSONResponse(
                {"error": "token_expired", "message": "Access token has expired"},
                status_code=401,
                headers={
                    "WWW-Authenticate": (
                        f'Bearer realm="nimbus-mcp", '
                        f'error="invalid_token", error_description="expired", '
                        f'resource_metadata="{base}/.well-known/oauth-protected-resource"'
                    )
                },
            )
        except jwt.InvalidTokenError as exc:
            actual_aud = "?"
            try:
                unverified = jwt.decode(
                    token, options={"verify_signature": False, "verify_exp": False, "verify_aud": False},
                )
                actual_aud = unverified.get("aud", "missing")
            except Exception:
                pass
            logger.warning(
                "Invalid token for %s %s: %s (expected_aud=%s/mcp, actual_aud=%s, host=%s)",
                method, path, exc, base, actual_aud, request.headers.get("host", "?"),
            )
            return JSONResponse(
                {"error": "invalid_token", "message": "Invalid access token"},
                status_code=401,
                headers={
                    "WWW-Authenticate": (
                        f'Bearer realm="nimbus-mcp", '
                        f'error="invalid_token", '
                        f'resource_metadata="{base}/.well-known/oauth-protected-resource"'
                    )
                },
            )

    response = await call_next(request)
    _add_security_headers(response)
    logger.info("<< %s %s -> %s", method, path, response.status_code)
    return response


def _add_security_headers(response: Response, allow_frame: bool = False) -> None:
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    if not allow_frame:
        response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"


# -----------  OAuth discovery endpoints  -----------


@app.get("/.well-known/oauth-protected-resource")
@app.get("/.well-known/oauth-protected-resource/mcp")
async def protected_resource_metadata(request: Request):
    base = _get_base_url(request)
    return {
        "resource": f"{base}/mcp",
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "scopes_supported": list(_OAUTH_SCOPES_SUPPORTED),
    }


@app.get("/.well-known/oauth-authorization-server")
@app.get("/.well-known/oauth-authorization-server/mcp")
async def auth_server_metadata(request: Request):
    base = _get_base_url(request)
    out = {
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "revocation_endpoint": f"{base}/oauth/revoke",
        "jwks_uri": f"{base}/.well-known/jwks.json",
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "response_types_supported": ["code"],
        "scopes_supported": list(_OAUTH_SCOPES_SUPPORTED),
        "code_challenge_methods_supported": ["S256"],
    }
    if OAUTH_DYNAMIC_CLIENT_REGISTRATION_ENABLED:
        out["registration_endpoint"] = f"{base}/oauth/register"
    return out


@app.get("/.well-known/openid-configuration")
async def openid_compatible_metadata(request: Request):
    """Serve OAuth metadata at the OIDC compatibility URL probed by clients."""

    return await auth_server_metadata(request)


@app.get("/.well-known/jwks.json")
@app.get("/jwks.json")
async def oauth_jwks():
    """Publish the public key used to verify MCP access tokens."""

    if not _oauth_enabled():
        return {"keys": []}
    return {"keys": [access_token_jwk(OAUTH_CLIENT_SECRET)]}


# -----------  OAuth authorize (Authorization Code + PKCE + phone/OTP login)  -----------


@app.api_route("/oauth/authorize", methods=["GET", "POST"])
async def authorize_endpoint(request: Request):
    # Step 1: read OAuth params
    if request.method == "GET":
        params = dict(request.query_params)
        phone_number = ""
        step = "phone"
        error = ""
    else:
        form = await request.form()
        params = {
            "response_type": form.get("response_type"),
            "client_id": form.get("client_id"),
            "redirect_uri": form.get("redirect_uri"),
            "code_challenge": form.get("code_challenge"),
            "code_challenge_method": form.get("code_challenge_method") or "S256",
            "state": form.get("state"),
            "scope": form.get("scope") or "mcp",
        }
        phone_number = (form.get("phone_number") or "").strip()
        verification_code = (form.get("verification_code") or "").strip()
        step = form.get("step") or "phone"
        error = ""

    response_type = params.get("response_type")
    client_id = params.get("client_id")
    redirect_uri = params.get("redirect_uri")
    code_challenge = params.get("code_challenge")
    code_challenge_method = params.get("code_challenge_method") or "S256"
    state = params.get("state")
    scope = params.get("scope") or "mcp"

    # Basic OAuth validation
    if response_type != "code":
        return JSONResponse({"error": "unsupported_response_type"}, status_code=400)

    if not _oauth_enabled():
        return JSONResponse({"error": "server_error", "error_description": "OAuth not configured"}, status_code=500)

    if not client_id:
        return JSONResponse({"error": "invalid_request", "error_description": "client_id required"}, status_code=400)

    # Accept registered client_id OR any client_id when PKCE is present (public client).
    # PKCE prevents authorization code interception, making strict client_id validation
    # redundant. This supports Claude personal accounts that may use their own client_id
    # without calling /oauth/register.
    if client_id != OAUTH_CLIENT_ID and not code_challenge:
        logger.warning("Rejecting unregistered client_id=%s without PKCE", client_id)
        return JSONResponse({"error": "invalid_client"}, status_code=400)

    if not redirect_uri:
        return JSONResponse({"error": "invalid_request", "error_description": "redirect_uri required"}, status_code=400)
    if not _is_allowed_redirect_uri(str(redirect_uri)):
        return JSONResponse(
            {"error": "invalid_request", "error_description": "redirect_uri not allowed"},
            status_code=400,
        )

    if client_id != OAUTH_CLIENT_ID:
        registered_client = await _resolve_dynamic_client(str(client_id))
        if registered_client:
            registered_redirects = registered_client.get("redirect_uris") or []
            if redirect_uri not in registered_redirects:
                return JSONResponse(
                    {
                        "error": "invalid_request",
                        "error_description": "redirect_uri is not registered for this client",
                    },
                    status_code=400,
                )
        else:
            logger.info("Accepting unregistered client_id=%s (PKCE present)", client_id)

    if not code_challenge:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "code_challenge required (PKCE)"},
            status_code=400,
        )
    if code_challenge_method != "S256":
        return JSONResponse(
            {"error": "invalid_request", "error_description": "code_challenge_method must be S256"},
            status_code=400,
        )

    # Step 2: handle POST actions
    ho_profile: dict | None = None
    upstream_access_token = ""
    if request.method == "POST":
        if step == "send_code":
            if not phone_number:
                error = "Please enter your phone number."
                step = "phone"
            else:
                try:
                    normalized_phone = _normalize_phone(phone_number)
                    logger.info("Sending OTP to %s", mask_phone(normalized_phone))
                    client = _get_http_client()
                    r = await operator_request(
                        client,
                        "POST",
                        AUTH_WEBHOOK_URL,
                        allowed_hosts=_ALLOWED_API_HOSTS,
                        endpoint_name="auth:otp_send",
                        rate_limit=10,
                        json={"phone_number": normalized_phone},
                        timeout=8,
                    )
                    r.raise_for_status()
                    logger.info("OTP sent successfully to %s", mask_phone(normalized_phone))
                    step = "code"
                except Exception as exc:
                    logger.error("Failed to send OTP to %s: %s", mask_phone(phone_number), exc)
                    error = "Failed to send verification code. Please try again."
                    step = "phone"
        elif step == "verify":
            if not phone_number or not verification_code:
                error = "Please enter your verification code."
                step = "code"
            else:
                try:
                    normalized_phone = _normalize_phone(phone_number)
                    logger.info("Verifying OTP for %s", mask_phone(normalized_phone))
                    client = _get_http_client()

                    r = await operator_request(
                        client,
                        "POST",
                        AUTH_WEBHOOK_URL,
                        allowed_hosts=_ALLOWED_API_HOSTS,
                        endpoint_name="auth:otp_verify",
                        rate_limit=10,
                        json={
                            "phone_number": normalized_phone,
                            "verification_code": verification_code,
                            "source": "MCP",
                        },
                        timeout=8,
                    )
                    r.raise_for_status()
                    auth_payload = r.json() or {}
                    access_token = auth_payload.get("access_token")
                    if not access_token:
                        logger.error(
                            "Auth webhook returned no access_token for %s",
                            mask_phone(normalized_phone),
                        )
                        raise RuntimeError("access_token missing from auth webhook response")

                    logger.info("OTP verified for %s, fetching profile", mask_phone(normalized_phone))
                    upstream_access_token = str(access_token)
                    ho_profile = await _fetch_homeowner_profile(normalized_phone, access_token)
                    logger.info(
                        "Profile fetched for %s: has_profile=%s",
                        mask_phone(normalized_phone),
                        bool(ho_profile),
                    )
                except httpx.TimeoutException as exc:
                    logger.error("Timeout during OTP verify for %s: %s", mask_phone(phone_number), exc)
                    error = "Verification timed out. Please try again."
                    step = "code"
                except Exception as exc:
                    logger.error("OTP verification failed for %s: %s", mask_phone(phone_number), exc)
                    error = "Verification failed. Please check the code and try again."
                    step = "code"

            if ho_profile is not None and not error:
                ho_session = await _store_ho_session(ho_profile, upstream_access_token)
                code = await _store_auth_grant({
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "code_challenge": code_challenge,
                    "code_challenge_method": code_challenge_method,
                    "scope": scope,
                    "ho_profile": ho_profile,
                    "ho_session": ho_session,
                    "phone_number": phone_number,
                })

                callback_params = {"code": code}
                if state:
                    callback_params["state"] = state

                separator = "&" if "?" in redirect_uri else "?"
                final_url = f"{redirect_uri}{separator}{urlencode(callback_params)}"
                logger.info(
                    "OTP flow complete for %s, redirecting (url_len=%d, code_len=%d)",
                    mask_phone(phone_number), len(final_url), len(code),
                )
                try:
                    await notify_login_success(
                        phone=normalized_phone,
                        profile=ho_profile,
                        client_id=client_id,
                        meta=request_meta_from_request(request),
                    )
                except Exception as exc:
                    logger.warning("MCP monitor login event failed: %s", exc)
                return RedirectResponse(url=final_url, status_code=302)

    # Step 3: render UI (two-step)
    base = _get_base_url(request)
    error_escaped = html_mod.escape(error) if error else ""
    error_html = f"<p style='color:#f97373;margin-bottom:12px;'>{error_escaped}</p>" if error else ""
    phone_value = html_mod.escape(phone_number or "")

    if step == "code":
        form_body = f"""
      <p>We sent a one-time code to <strong>{phone_value}</strong>. Enter it below to finish connecting.</p>
      {error_html}
      <form method="post" action="{base}/oauth/authorize" novalidate>
        <input type="hidden" name="response_type" value="{html_mod.escape(response_type or '')}">
        <input type="hidden" name="client_id" value="{html_mod.escape(client_id or '')}">
        <input type="hidden" name="redirect_uri" value="{html_mod.escape(redirect_uri or '')}">
        <input type="hidden" name="code_challenge" value="{html_mod.escape(code_challenge or '')}">
        <input type="hidden" name="code_challenge_method" value="{html_mod.escape(code_challenge_method or '')}">
        <input type="hidden" name="state" value="{html_mod.escape(state or '')}">
        <input type="hidden" name="scope" value="{html_mod.escape(scope or '')}">
        <input type="hidden" name="phone_number" value="{phone_value}">
        <input type="hidden" id="step" name="step" value="verify">

        <label for="verification_code">Verification code</label>
        <input id="verification_code" name="verification_code" type="text" placeholder="123456" autofocus>

        <button type="submit" class="btn">
          Verify &amp; connect
        </button>
        <button type="submit" class="btn secondary" onclick="document.getElementById('step').value='send_code';">
          Resend code
        </button>
        <div class="hint">
          Didn't get a code? Check your number, then resend.
        </div>
      </form>
        """
    else:
        form_body = f"""
      <p>Enter your phone number to link your operator profile to this AI.</p>
      {error_html}
      <form method="post" action="{base}/oauth/authorize" novalidate>
        <input type="hidden" name="response_type" value="{html_mod.escape(response_type or '')}">
        <input type="hidden" name="client_id" value="{html_mod.escape(client_id or '')}">
        <input type="hidden" name="redirect_uri" value="{html_mod.escape(redirect_uri or '')}">
        <input type="hidden" name="code_challenge" value="{html_mod.escape(code_challenge or '')}">
        <input type="hidden" name="code_challenge_method" value="{html_mod.escape(code_challenge_method or '')}">
        <input type="hidden" name="state" value="{html_mod.escape(state or '')}">
        <input type="hidden" name="scope" value="{html_mod.escape(scope or '')}">
        <input type="hidden" id="step" name="step" value="send_code">

        <label for="phone_number">Phone number</label>
        <input id="phone_number" name="phone_number" type="tel" value="{phone_value}" placeholder="+1 (555) 123‑4567" autofocus>

        <button type="submit" class="btn">
          Send code
        </button>
        <div class="hint">
          We'll text a one-time code to your phone to verify it's you.
        </div>
      </form>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorize &ndash; {html_mod.escape(MCP_SERVER_NAME)}</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0a0a0a; color: #e5e5e5;
      display: flex; justify-content: center; align-items: center; min-height: 100vh;
    }}
    .card {{
      text-align: center; max-width: 420px; padding: 32px 24px;
      background: #171717; border: 1px solid #262626; border-radius: 16px;
    }}
    .logo {{ font-size: 40px; margin-bottom: 12px; }}
    h1 {{ font-size: 22px; font-weight: 700; color: #fff; margin-bottom: 8px; }}
    p {{ font-size: 14px; color: #a3a3a3; line-height: 1.5; margin-bottom: 16px; }}
    label {{ display: block; font-size: 13px; color: #d4d4d4; text-align: left; margin: 12px 0 4px; }}
    input {{
      width: 100%; padding: 10px 12px; border-radius: 8px;
      border: 1px solid #404040; background: #0a0a0a; color: #e5e5e5;
      font-size: 14px;
    }}
    .row {{ margin-bottom: 4px; }}
    .btn {{
      width: 100%; margin-top: 16px;
      background: #22c55e; color: #000; font-size: 15px; font-weight: 600;
      padding: 10px 16px; border-radius: 8px; border: none; cursor: pointer;
    }}
    .btn.secondary {{
      background: #262626; color: #e5e5e5; margin-top: 8px;
    }}
    .hint {{ margin-top: 8px; font-size: 12px; color: #737373; }}
    .btn:disabled {{
      opacity: 0.7;
      cursor: default;
    }}
    .btn.loading {{
      position: relative;
      color: transparent;
      pointer-events: none;
    }}
    .btn.loading::after {{
      content: "";
      position: absolute;
      top: 50%;
      left: 50%;
      width: 18px;
      height: 18px;
      margin-top: -9px;
      margin-left: -9px;
      border-radius: 999px;
      border: 2px solid rgba(0, 0, 0, 0.25);
      border-top-color: #000;
      animation: spin 0.7s linear infinite;
    }}
    .btn.secondary.loading::after {{
      border-color: rgba(212, 212, 212, 0.3);
      border-top-color: #e5e5e5;
    }}
    @keyframes spin {{
      to {{
        transform: rotate(360deg);
      }}
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">&#9889;</div>
    <h1>Connect {html_mod.escape(BRAND_NAME)}</h1>
    {form_body}
</div>
  <script>
    (function () {{
      var phoneInput = document.getElementById('phone_number');

      function formatUsPhone(digits) {{
        var cleaned = (digits || '').replace(/\\D/g, '').slice(0, 10);
        var p1 = cleaned.slice(0, 3);
        var p2 = cleaned.slice(3, 6);
        var p3 = cleaned.slice(6, 10);
        return [p1, p2, p3].filter(Boolean).join('.');
      }}

      if (phoneInput) {{
        var rawInitial = phoneInput.value || '';
        if (rawInitial.indexOf('+1') === 0) {{
          rawInitial = rawInitial.slice(2);
        }}
        var allDigits = rawInitial.replace(/\\D/g, '');
        var initialDigits = allDigits.length > 10 ? allDigits.slice(-10) : allDigits.slice(0, 10);
        phoneInput.value = '+1 ' + formatUsPhone(initialDigits);
        phoneInput.dataset.digits = initialDigits;

        phoneInput.addEventListener('input', function (event) {{
          var raw = event.target.value || '';
          if (raw.indexOf('+1') === 0) {{
            raw = raw.slice(2);
          }}
          var digits = raw.replace(/\\D/g, '').slice(0, 10);
          event.target.dataset.digits = digits;
          event.target.value = '+1 ' + formatUsPhone(digits);
        }});
      }}

      document.addEventListener('submit', function (event) {{
        var form = event.target;
        if (!form || !(form instanceof HTMLFormElement)) return;

        var phoneField = form.querySelector('#phone_number');
        if (phoneField) {{
          var digits = (phoneField.dataset.digits || '').replace(/\\D/g, '').slice(0, 10);
          if (!digits) {{
            var rawVal = phoneField.value || '';
            if (rawVal.indexOf('+1') === 0) {{
              rawVal = rawVal.slice(2);
            }}
            digits = rawVal.replace(/\\D/g, '').slice(0, 10);
          }}
          if (digits) {{
            phoneField.value = '+1' + digits;
          }}
        }}

        var activeButton = form.querySelector('button[type="submit"]:focus');
        if (!activeButton) {{
          activeButton = form.querySelector('button[type="submit"]');
        }}
        if (!activeButton) return;

        activeButton.classList.add('loading');
        activeButton.disabled = true;

        var buttons = form.querySelectorAll('button');
        buttons.forEach(function (button) {{
          if (button === activeButton) return;
          button.disabled = true;
        }});

        setTimeout(function () {{
          if (!activeButton) return;
          activeButton.classList.remove('loading');
          activeButton.disabled = false;
          buttons.forEach(function (button) {{ button.disabled = false; }});

          var existingErr = form.closest('.card');
          if (existingErr && !existingErr.querySelector('.timeout-msg')) {{
            var msg = document.createElement('p');
            msg.className = 'timeout-msg';
            msg.style.cssText = 'color:#f97373;margin-bottom:12px;font-size:14px;';
            msg.textContent = 'Request timed out. Please try again.';
            var firstForm = existingErr.querySelector('form');
            if (firstForm) firstForm.parentNode.insertBefore(msg, firstForm);
          }}
        }}, 20000);
      }}, true);
    }})();
  </script>
</body>
</html>"""
    return Response(content=html, media_type="text/html")


# -----------  OAuth token  -----------


@app.post("/oauth/token")
async def token_endpoint(request: Request):
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        data = await request.json()
    else:
        form = await request.form()
        data = dict(form)

    grant_type = data.get("grant_type")
    client_id = data.get("client_id", "")
    client_secret = data.get("client_secret", "")

    if not client_id or not client_secret:
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Basic "):
            decoded = base64.b64decode(auth_header[6:]).decode()
            parts = decoded.split(":", 1)
            if len(parts) == 2:
                client_id, client_secret = parts

    if not _oauth_enabled():
        return JSONResponse({"error": "server_error", "error_description": "OAuth not configured"}, status_code=500)

    base = _get_base_url(request)
    logger.info(
        "Token request: grant_type=%s client_id_present=%s secret_present=%s base=%s host=%s",
        grant_type, bool(client_id), bool(client_secret),
        base, request.headers.get("host", "?"),
    )

    # Validate credentials if provided, but don't require them for PKCE flows
    # (Claude personal accounts may use their own client_id without registering)
    if client_secret and client_id == OAUTH_CLIENT_ID and client_secret != OAUTH_CLIENT_SECRET:
        logger.warning("Token request with wrong client_secret for registered client_id=%s", client_id)
        return JSONResponse({"error": "invalid_client", "error_description": "Bad client_secret"}, status_code=401)

    # --- Authorization Code + PKCE ---
    if grant_type == "authorization_code":
        code = data.get("code", "")
        code_verifier = data.get("code_verifier", "")
        redirect_uri = data.get("redirect_uri", "")

        stored = await _consume_auth_grant(str(code))
        if not stored:
            logger.warning("Token exchange failed: invalid, expired, or already used auth code")
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Invalid or expired code"},
                status_code=400,
            )

        if stored.get("client_id") != client_id:
            return JSONResponse({"error": "invalid_grant", "error_description": "Client mismatch"}, status_code=400)

        if stored.get("redirect_uri") != redirect_uri:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "redirect_uri mismatch"},
                status_code=400,
            )

        if not _verify_pkce(
            code_verifier,
            stored.get("code_challenge", ""),
            stored.get("code_challenge_method", "S256"),
        ):
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "PKCE verification failed"},
                status_code=400,
            )

        now = time.time()
        resource = f"{base}/mcp"
        scope = stored.get("scope") or "mcp"
        claims: dict[str, Any] = {
            "sub": client_id,
            "scope": scope,
            "aud": resource,
            "iat": now,
            "exp": now + OAUTH_TOKEN_TTL,
        }

        ho_profile = _trim_profile(stored.get("ho_profile") or {})
        ho_session = str(stored.get("ho_session") or "")
        if ho_profile:
            claims["ho_profile"] = ho_profile
        if ho_session:
            claims["ho_session"] = ho_session
        if stored.get("phone_number"):
            claims["ho_phone"] = stored["phone_number"]
        if ho_profile.get("ho_name"):
            claims["ho_name"] = ho_profile.get("ho_name")
        if ho_profile.get("ho_address"):
            claims["ho_address"] = ho_profile.get("ho_address")

        access_token = encode_access_token(claims, OAUTH_CLIENT_SECRET)

        refresh_token = await _issue_refresh_token({
            "client_id": client_id,
            "scope": scope,
            "ho_profile": ho_profile,
            "ho_session": ho_session,
            "phone_number": stored.get("phone_number"),
            "resource": resource,
        })

        logger.info("Token exchange successful for client %s", client_id)

        if ho_profile:
            try:
                await notify_token_issued(
                    client_id=client_id,
                    profile=ho_profile,
                    phone=stored.get("phone_number"),
                    meta=request_meta_from_request(request),
                )
            except Exception as exc:
                logger.warning("MCP monitor token event failed: %s", exc)

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": OAUTH_TOKEN_TTL,
            "refresh_token": refresh_token,
            "scope": scope,
            "resource": resource,
        }

    # --- Refresh Token ---
    if grant_type == "refresh_token":
        rt = data.get("refresh_token", "")
        if not rt:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "refresh_token required"},
                status_code=400,
            )

        stored_rt = _decode_refresh_token(rt)
        if not stored_rt:
            logger.warning("Refresh token exchange failed: invalid or expired token")
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Invalid or expired refresh token"},
                status_code=400,
            )

        if stored_rt.get("client_id") != client_id:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Client mismatch for refresh token"},
                status_code=400,
            )

        if not await _consume_refresh_token(stored_rt):
            logger.warning("Refresh token exchange failed: token already rotated or revoked")
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Invalid or revoked refresh token"},
                status_code=400,
            )

        now = time.time()
        resource = stored_rt.get("resource") or f"{base}/mcp"
        scope = stored_rt.get("scope") or "mcp"
        ho_profile = _trim_profile(stored_rt.get("ho_profile") or {})
        ho_session = str(stored_rt.get("ho_session") or "")

        claims: dict[str, Any] = {
            "sub": client_id,
            "scope": scope,
            "aud": resource,
            "iat": now,
            "exp": now + OAUTH_TOKEN_TTL,
        }
        if ho_profile:
            claims["ho_profile"] = ho_profile
        if ho_session:
            claims["ho_session"] = ho_session
        if stored_rt.get("phone_number"):
            claims["ho_phone"] = stored_rt["phone_number"]
        if ho_profile.get("ho_name"):
            claims["ho_name"] = ho_profile.get("ho_name")
        if ho_profile.get("ho_address"):
            claims["ho_address"] = ho_profile.get("ho_address")

        access_token = encode_access_token(claims, OAUTH_CLIENT_SECRET)

        new_refresh_token = await _issue_refresh_token({
            "client_id": client_id,
            "scope": scope,
            "ho_profile": ho_profile,
            "ho_session": ho_session,
            "phone_number": stored_rt.get("phone_number"),
            "resource": resource,
        })

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": OAUTH_TOKEN_TTL,
            "refresh_token": new_refresh_token,
            "scope": scope,
            "resource": resource,
        }

    # --- Client Credentials ---
    if grant_type == "client_credentials":
        if client_id != OAUTH_CLIENT_ID or client_secret != OAUTH_CLIENT_SECRET:
            return JSONResponse({"error": "invalid_client"}, status_code=401)

        now = time.time()
        resource = f"{base}/mcp"
        access_token = encode_access_token(
            {"sub": client_id, "scope": "mcp", "aud": resource, "iat": now, "exp": now + OAUTH_TOKEN_TTL},
            OAUTH_CLIENT_SECRET,
        )
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": OAUTH_TOKEN_TTL,
            "scope": "mcp",
            "resource": resource,
        }

    return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)


# -----------  Dynamic client registration  -----------


@app.post("/oauth/register")
async def dynamic_registration(request: Request):
    if not _oauth_enabled() or not OAUTH_DYNAMIC_CLIENT_REGISTRATION_ENABLED:
        return JSONResponse({"error": "not_configured"}, status_code=404)

    body = await request.json()
    redirect_uris = body.get("redirect_uris") or []
    if not isinstance(redirect_uris, list) or not redirect_uris or not all(
        isinstance(uri, str) and _is_allowed_redirect_uri(uri)
        for uri in redirect_uris
    ):
        return JSONResponse(
            {"error": "invalid_redirect_uri", "error_description": "Unsupported redirect URI"},
            status_code=400,
        )

    token_auth_method = body.get("token_endpoint_auth_method") or "none"
    if token_auth_method != "none":
        return JSONResponse(
            {
                "error": "invalid_client_metadata",
                "error_description": "Only public clients are supported",
            },
            status_code=400,
        )

    requested_scope = body.get("scope") or "mcp"
    if isinstance(requested_scope, list):
        requested_scope = " ".join(str(item) for item in requested_scope)
    registration = {
        "client_id": f"nimbus_{secrets.token_urlsafe(24)}",
        "client_id_issued_at": int(time.time()),
        "client_name": body.get("client_name", "MCP Client"),
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": str(requested_scope),
    }
    await _store_dynamic_client(registration)
    logger.info(
        "Client registration: client_name=%s redirect_uris=%s host=%s",
        body.get("client_name", "?"),
        body.get("redirect_uris", []),
        request.headers.get("host", "?"),
    )
    return JSONResponse(registration, status_code=201)


# -----------  OAuth revocation (best-effort)  -----------


@app.post("/oauth/revoke")
async def revoke_token(request: Request):
    if not _oauth_enabled():
        return Response(status_code=200)

    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        data = await request.json()
    else:
        form = await request.form()
        data = dict(form)

    token = data.get("token", "")
    if not token:
        return Response(status_code=200)

    decoded = _decode_refresh_token(token)
    if decoded and decoded.get("jti"):
        await _get_state_store().consume(f"refresh:{decoded['jti']}")

    # RFC 7009 recommends 200 even if the token was unknown.
    return Response(status_code=200)


# -----------  Models  -----------


class Location(BaseModel):
    lat: float | None = None
    lng: float | None = None
    lon: float | None = None
    zip: str | None = None
    text: str | None = None


class SearchProvidersInput(BaseModel):
    query: str = Field(min_length=2)
    location: Location
    page: int = 1
    limit: int = Field(default=6, ge=1, le=10)


class Address(BaseModel):
    formattedAddress: str | None = None
    postalCode: str | None = None
    address1: str | None = None
    address2: str | None = None
    city: str | None = None
    region: str | None = None
    country: str | None = None


class CreateBookingInput(BaseModel):
    serviceProviderSlug: str = Field(min_length=1)
    name: str = Field(min_length=2)
    phone: str = Field(min_length=7)
    job_description: str = Field(min_length=5, max_length=2000)

    location: Location | None = None
    address: Address | None = None


# -----------  Routes  -----------


@app.get("/")
async def landing():
    escaped_name = html_mod.escape(MCP_SERVER_NAME)
    redirect_url = html_mod.escape(LANDING_REDIRECT_URL, quote=True)
    redirect_block = (
        f'<p><a href="{redirect_url}">Continue to the configured client</a></p>'
        if redirect_url
        else ""
    )
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>__MCP_NAME__</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a0a;
            color: #e5e5e5;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            text-align: center;
            max-width: 480px;
            padding: 48px 32px;
        }
        .logo { font-size: 48px; margin-bottom: 16px; }
        h1 { font-size: 28px; font-weight: 700; color: #fff; margin-bottom: 8px; }
        .subtitle { font-size: 16px; color: #a3a3a3; margin-bottom: 32px; line-height: 1.5; }
        .countdown-box {
            background: #171717;
            border: 1px solid #262626;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
        }
        .countdown-text { font-size: 14px; color: #a3a3a3; margin-bottom: 8px; }
        .countdown-number { font-size: 48px; font-weight: 700; color: #22c55e; }
        .btn {
            display: inline-block;
            background: #22c55e;
            color: #000;
            font-size: 16px;
            font-weight: 600;
            padding: 14px 32px;
            border-radius: 8px;
            text-decoration: none;
            transition: background 0.2s;
        }
        .btn:hover { background: #16a34a; }
        .status { margin-top: 24px; font-size: 13px; color: #525252; }
        .check { color: #22c55e; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">⚡</div>
        <h1>__MCP_NAME__</h1>
        <p class="subtitle">The MCP server is running.</p>
        __REDIRECT_BLOCK__
        <div class="status">
            <span class="check">&#10003;</span> MCP Server connected &nbsp;
            <span class="check">&#10003;</span> Tools available
        </div>
    </div>
</body>
</html>""".replace("__MCP_NAME__", escaped_name).replace("__REDIRECT_BLOCK__", redirect_block)
    return Response(content=html, media_type="text/html")


@app.api_route(
    "/upstream/mcp",
    methods=["GET", "POST", "DELETE", "OPTIONS"],
)
async def upstream_mcp_proxy(request: Request) -> Response:
    """Proxy MCP transport to an explicitly configured operator upstream.

    The inbound Authorization header is intentionally not forwarded. The
    upstream receives only the operator-configured token, when present.
    """

    if not UPSTREAM_MCP_URL:
        return JSONResponse(
            {"error": "upstream_not_configured", "message": "UPSTREAM_MCP_URL is not configured"},
            status_code=404,
        )

    forwarded_headers = {
        name: request.headers[name]
        for name in (
            "accept",
            "content-type",
            "mcp-protocol-version",
            "mcp-session-id",
            "last-event-id",
        )
        if name in request.headers
    }
    if UPSTREAM_MCP_AUTH_TOKEN:
        forwarded_headers["authorization"] = f"Bearer {UPSTREAM_MCP_AUTH_TOKEN}"

    try:
        upstream_response = await operator_request(
            _get_http_client(),
            request.method,
            UPSTREAM_MCP_URL,
            allowed_hosts=_ALLOWED_API_HOSTS,
            endpoint_name="upstream:mcp",
            rate_limit=RATE_LIMIT_RPM,
            headers=forwarded_headers,
            content=await request.body(),
            timeout=UPSTREAM_MCP_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        logger.warning("Configured upstream MCP request failed: %s", type(exc).__name__)
        return JSONResponse(
            {"error": "upstream_unavailable", "message": "Configured upstream MCP is unavailable"},
            status_code=502,
        )

    response_headers = {
        name: upstream_response.headers[name]
        for name in ("content-type", "cache-control", "mcp-session-id", "last-event-id")
        if name in upstream_response.headers
    }
    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=response_headers,
    )


@app.get("/__ping")
async def ping():
    return {"ok": True}


@app.get("/.well-known/mcp.json")
async def mcp_manifest(request: Request):
    base = _get_base_url(request)
    return {
        "name": MCP_SERVER_NAME,
        "description": MCP_SERVER_DESCRIPTION,
        "url": f"{base}/mcp",
        "transport": "streamable-http",
        "authentication": {
            "type": "oauth2",
            "authorization_endpoint": f"{base}/oauth/authorize",
            "token_endpoint": f"{base}/oauth/token",
        } if _oauth_enabled() else None,
        "capabilities": {"tools": True},
    }


@app.get("/.well-known/tool-annotations")
async def tool_annotations_well_known():
    """Long-form tool hint copy for humans and connector docs (not MCP JSON-RPC)."""
    try:
        body = _TOOL_ANNOTATIONS_PATH.read_text(encoding="utf-8")
    except OSError:
        return Response(
            status_code=404,
            content="tool annotations document not available",
            media_type="text/plain; charset=utf-8",
        )
    return Response(
        content=body,
        media_type="text/markdown; charset=utf-8",
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.api_route("/.well-known/openai-apps-challenge", methods=["GET", "HEAD", "POST"])
async def openai_apps_challenge():
    if not OPENAI_APPS_CHALLENGE_TOKEN:
        return Response(status_code=404, content="Not configured", media_type="text/plain")
    return Response(
        content=OPENAI_APPS_CHALLENGE_TOKEN,
        media_type="text/plain",
        headers={"Cache-Control": "no-store"},
    )


@app.post("/tools/search_providers")
async def handle_search(input: SearchProvidersInput):
    loc = input.location.model_dump(exclude_none=True)
    return await search_providers(
        query=input.query,
        location=loc,
        page=input.page,
        limit=input.limit,
    )


@app.post("/tools/create_booking")
async def handle_booking(input: CreateBookingInput):
    payload = input.model_dump(exclude_none=True)

    if input.location:
        payload["location"] = input.location.model_dump(exclude_none=True)
    if input.address:
        payload["address"] = input.address.model_dump(exclude_none=True)

    return await create_booking(payload)


# -----------  MCP mount  -----------

app.mount("", mcp_app)

handler = Mangum(app, lifespan="on")
