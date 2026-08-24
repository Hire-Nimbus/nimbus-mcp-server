from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx
from starlette.requests import Request

from src.auth_context import current_ho_profile, current_request_meta
from src.adapters import operator_request
from src.config import (
    MCP_MONITOR_ENABLED,
    MCP_MONITOR_SLACK_API,
    MCP_MONITOR_SLACK_CHANNEL,
    TOOL_RATE_LIMIT_RPM,
    configured_external_api_urls,
)
from src.security import build_allowed_hosts, mask_name, mask_phone, redact_for_log

logger = logging.getLogger("nimbus-mcp.monitor")

_monitor_http_client: httpx.AsyncClient | None = None
_ALLOWED_API_HOSTS = build_allowed_hosts(configured_external_api_urls())


def _get_client() -> httpx.AsyncClient:
    global _monitor_http_client
    if _monitor_http_client is None or _monitor_http_client.is_closed:
        _monitor_http_client = httpx.AsyncClient(timeout=httpx.Timeout(8, connect=3))
    return _monitor_http_client


def request_meta_from_request(request: Request) -> Dict[str, Any]:
    """Extract client IP, country, and client hints from proxy headers."""
    forwarded = (request.headers.get("x-forwarded-for") or "").strip()
    client_ip = forwarded.split(",")[0].strip() if forwarded else ""
    if not client_ip:
        client_ip = (request.headers.get("x-real-ip") or "").strip()
    if not client_ip and request.client:
        client_ip = request.client.host or ""

    country = (
        request.headers.get("cloudfront-viewer-country")
        or request.headers.get("cf-ipcountry")
        or request.headers.get("x-country-code")
        or ""
    ).strip().upper()

    return {
        "client_ip": client_ip or "unknown",
        "country": country or None,
        "user_agent": (request.headers.get("user-agent") or "").strip() or None,
        "origin": (request.headers.get("origin") or "").strip() or None,
        "host": (request.headers.get("host") or "").strip() or None,
    }


def set_request_meta(meta: Dict[str, Any]) -> None:
    current_request_meta.set(meta)


def _hostname_from_url(value: Optional[str]) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = f"https://{raw}"
    try:
        return (urlparse(raw).hostname or "").lower()
    except Exception:
        return ""


def identify_ai_service(
    *,
    redirect_uri: Optional[str] = None,
    origin: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> str:
    """Map trusted OAuth and request hints to a platform label."""
    redirect = (redirect_uri or "").lower()
    if (
        "cursor.com/agents/mcp/oauth/callback" in redirect
        or redirect.startswith("cursor://anysphere.cursor-mcp/")
        or "localhost:8787/callback" in redirect
        or "127.0.0.1:8787/callback" in redirect
    ):
        return "Grok Bot"

    for hint in (redirect_uri, origin):
        host = _hostname_from_url(hint)
        if host in {"chatgpt.com", "chat.openai.com", "openai.com"} or host.endswith(".openai.com"):
            return "ChatGPT"
        if host == "claude.ai" or host.endswith(".anthropic.com"):
            return "Claude"
        if host in {"cursor.com", "www.cursor.com"} or host.endswith(".cursor.com"):
            return "Grok Bot"
        if host in {"grok.com", "www.grok.com", "x.ai", "x.com", "www.x.com"} or host.endswith(".x.ai"):
            return "Grok"
        if host == "gemini.google.com":
            return "Gemini"

    ua = (user_agent or "").lower()
    if "chatgpt" in ua or "openai" in ua:
        return "ChatGPT"
    if "claude" in ua or "anthropic" in ua:
        return "Claude"
    if "grok bot" in ua or "cursor" in ua:
        return "Grok Bot"
    if "grok" in ua or "xai" in ua or "x.ai" in ua:
        return "Grok"
    if "gemini" in ua:
        return "Gemini"
    return "Unknown"


def _profile_name(profile: Dict[str, Any]) -> str:
    return str(profile.get("name") or profile.get("ho_name") or "").strip()


def _profile_phone(profile: Dict[str, Any]) -> str:
    return str(profile.get("phone") or profile.get("ho_phone") or "").strip()


def _profile_location(profile: Dict[str, Any]) -> Optional[str]:
    address = profile.get("address") or profile.get("ho_address") or {}
    if not isinstance(address, dict):
        return None
    city = str(address.get("city") or "").strip()
    region = str(address.get("region") or address.get("state") or "").strip()
    if city and region:
        return f"{city}, {region}"
    return city or region or None


def _user_block(profile: Optional[Dict[str, Any]] = None) -> str:
    profile = profile or current_ho_profile.get() or {}
    name = mask_name(_profile_name(profile) or "unknown")
    phone = _profile_phone(profile)
    phone_part = f" ({mask_phone(phone)})" if phone else ""
    location = _profile_location(profile)
    lines = [f"*User:* {name}{phone_part}"]
    if location:
        lines.append(f"*Profile location:* {location}")
    return "\n".join(lines)


def _request_block(meta: Optional[Dict[str, Any]] = None) -> str:
    meta = meta or current_request_meta.get() or {}
    lines = [f"*IP:* {meta.get('client_ip', 'unknown')}"]
    if meta.get("country"):
        lines.append(f"*Country:* {meta['country']}")
    if meta.get("origin"):
        lines.append(f"*Origin:* {meta['origin']}")
    if meta.get("user_agent"):
        ua = str(meta["user_agent"])
        if len(ua) > 120:
            ua = ua[:117] + "..."
        lines.append(f"*Client:* {ua}")
    return "\n".join(lines)


def _summarize_tool_args(tool_name: str, arguments: Dict[str, Any]) -> str:
    if not arguments:
        return "(no args)"

    safe = redact_for_log(dict(arguments))
    if tool_name == "create_booking" and safe.get("job_description"):
        desc = str(safe["job_description"])
        if len(desc) > 120:
            safe["job_description"] = desc[:117] + "..."

    parts = []
    for key, value in safe.items():
        if value is None:
            continue
        if isinstance(value, dict):
            parts.append(f"{key}={value!r}")
        else:
            parts.append(f"{key}={value!r}")
    return ", ".join(parts) if parts else "(no args)"


async def send_monitor_event(title: str, body: str, *, severity: str = "info") -> None:
    if not MCP_MONITOR_ENABLED:
        return
    if not MCP_MONITOR_SLACK_API:
        logger.warning("Monitoring is enabled but MCP_MONITOR_SLACK_API is not configured")
        return

    message = f"*{title}*\n{body}"
    payload = {
        "message": message,
        "type": severity,
        "channel": MCP_MONITOR_SLACK_CHANNEL,
    }

    try:
        r = await operator_request(
            _get_client(),
            "POST",
            MCP_MONITOR_SLACK_API,
            allowed_hosts=_ALLOWED_API_HOSTS,
            endpoint_name="monitor:event",
            rate_limit=TOOL_RATE_LIMIT_RPM,
            json=payload,
            timeout=8,
        )
        r.raise_for_status()
    except Exception as exc:
        logger.warning("Failed to send MCP monitor event to Slack: %s", exc)


def schedule_monitor_event(title: str, body: str, *, severity: str = "info") -> None:
    """Fire-and-forget monitor event (used for high-frequency tool calls)."""
    if not MCP_MONITOR_ENABLED:
        return
    asyncio.create_task(send_monitor_event(title, body, severity=severity))


async def notify_login_success(
    *,
    phone: str,
    profile: Dict[str, Any],
    client_id: str,
    meta: Optional[Dict[str, Any]] = None,
) -> None:
    body = "\n".join(
        [
            "*Event:* OAuth login (OTP verified)",
            f"*Phone:* {mask_phone(phone)}",
            _user_block(profile),
            f"*OAuth client:* {client_id or 'unknown'}",
            _request_block(meta),
        ]
    )
    await send_monitor_event("MCP login", body, severity="success")


async def notify_token_issued(
    *,
    client_id: str,
    profile: Dict[str, Any],
    phone: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> None:
    body = "\n".join(
        [
            "*Event:* Access token issued",
            f"*OAuth client:* {client_id or 'unknown'}",
            _user_block(profile),
            f"*Phone:* {mask_phone(phone or _profile_phone(profile))}" if (phone or _profile_phone(profile)) else "",
            _request_block(meta),
        ]
    )
    body = "\n".join(line for line in body.splitlines() if line.strip())
    await send_monitor_event("MCP session started", body, severity="success")


def install_tool_monitor(fastmcp_instance: Any) -> None:
    """Wrap FastMCP tool dispatch to emit monitor events."""
    tool_manager = fastmcp_instance._tool_manager
    original_call_tool = tool_manager.call_tool

    async def monitored_call_tool(
        name: str,
        arguments: dict[str, Any],
        context: Any = None,
        convert_result: bool = True,
    ):
        schedule_monitor_event(
            "MCP tool call",
            "\n".join(
                [
                    f"*Tool:* `{name}`",
                    f"*Args:* {_summarize_tool_args(name, arguments)}",
                    _user_block(),
                    _request_block(),
                ]
            ),
            severity="info",
        )
        return await original_call_tool(
            name,
            arguments,
            context=context,
            convert_result=convert_result,
        )

    tool_manager.call_tool = monitored_call_tool
